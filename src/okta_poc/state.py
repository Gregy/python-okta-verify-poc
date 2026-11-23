"""Local state: keys, enrollments and FCM device credentials in one file.

The file is either plaintext JSON (testing only) or the same JSON encrypted
with Fernet using a key derived from a passphrase with scrypt. It is always
written atomically with mode 0600.
"""

from __future__ import annotations

import base64
import fcntl
import json
import os
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import jwt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import PoCError

SCHEMA_VERSION = 2
# Only the last few responded transaction IDs are needed to ignore FCM redeliveries.
MAX_RESPONDED = 200


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


@dataclass
class Key:
    """RSA-2048 software key used to sign JWTs for Okta."""

    kid: str
    private_pem: str = field(repr=False)

    @classmethod
    def generate(cls) -> Key:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            # The state file as a whole is encrypted (unless --plaintext-state).
            serialization.NoEncryption(),
        ).decode("ascii")
        return cls(kid=str(uuid.uuid4()), private_pem=pem)

    def _private(self) -> rsa.RSAPrivateKey:
        return serialization.load_pem_private_key(self.private_pem.encode("ascii"), password=None)

    def public_jwk(self) -> dict[str, Any]:
        # Encoded like the Android app does it: java.math.BigInteger.toByteArray()
        # (signed, so the modulus gets a leading zero byte) and base64url *with*
        # padding. This is the profile proven against a live tenant.
        numbers = self._private().public_key().public_numbers()

        def java_bytes(value: int) -> bytes:
            return value.to_bytes(value.bit_length() // 8 + 1, "big")

        return {
            "kty": "RSA",
            "n": _b64url(java_bytes(numbers.n)),
            "e": _b64url(java_bytes(numbers.e)),
            "kid": self.kid,
            "alg": "RS256",
            "use": "sig",
            "okta:kpr": "SOFTWARE",
        }

    def sign(self, claims: dict[str, Any], typ: str) -> str:
        return jwt.encode(
            claims, self._private(), algorithm="RS256", headers={"kid": self.kid, "typ": typ}
        )


@dataclass
class Enrollment:
    """One completed Okta Verify enrollment and the keys bound to it."""

    enrollment_id: str
    authenticator_id: str
    org_id: str
    org_url: str
    user_id: str
    username: str | None
    device_id: str
    client_instance_id: str
    method_enrollment_id: str
    pending_challenge_uri: str
    # OAuth client ID that signed challenges must carry in `aud`. None means the
    # policy did not publish one (explicit --allow-missing-policy-audience).
    expected_audience: str | None
    policy_supports_ciba: bool
    display_name: str
    pop_key: Key
    client_instance_key: Key
    uv_key: Key | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Enrollment:
        value = dict(value)
        for name in ("pop_key", "client_instance_key", "uv_key"):
            if value.get(name) is not None:
                value[name] = Key(**value[name])
        return cls(**value)


@dataclass
class FcmDevice:
    """Credentials of the emulated Android device registered with Google FCM."""

    android_id: int
    security_token: int = field(repr=False)
    token: str = field(repr=False)


@dataclass
class State:
    enrollments: dict[str, Enrollment] = field(default_factory=dict)
    fcm: FcmDevice | None = None
    responded: list[str] = field(default_factory=list)

    def mark_responded(self, transaction_id: str) -> None:
        self.responded = [*self.responded, transaction_id][-MAX_RESPONDED:]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "enrollments": {key: asdict(value) for key, value in self.enrollments.items()},
            "fcm": asdict(self.fcm) if self.fcm else None,
            "responded": self.responded,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> State:
        if value.get("schema_version") != SCHEMA_VERSION:
            raise PoCError("Unsupported local state schema")
        try:
            return cls(
                enrollments={
                    key: Enrollment.from_dict(item)
                    for key, item in value.get("enrollments", {}).items()
                },
                fcm=FcmDevice(**value["fcm"]) if value.get("fcm") else None,
                responded=list(value.get("responded", [])),
            )
        except (TypeError, KeyError, AttributeError) as exc:
            raise PoCError("Malformed local state") from exc


def _fernet(password: str, salt: bytes) -> Fernet:
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


class Store:
    """Loads and atomically saves the state file.

    `password=None` means plaintext. Use `edit()` for read-modify-write; it
    holds an exclusive lock so `okta-poc fcm` and other commands can run
    side by side.
    """

    def __init__(self, path: Path, password: str | None) -> None:
        self.path = path.expanduser()
        self.password = password

    @staticmethod
    def is_encrypted(path: Path) -> bool:
        return "fernet" in json.loads(path.expanduser().read_text(encoding="utf-8"))

    @property
    def exists(self) -> bool:
        return self.path.exists()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = os.open(self.path.with_name(self.path.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield
        finally:
            os.close(lock)

    def _load(self) -> State:
        if not self.exists:
            return State()
        if self.path.stat().st_mode & 0o077:
            raise PoCError(f"State file permissions are too open; run chmod 600 {self.path}")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if "fernet" in data:
                if self.password is None:
                    raise PoCError("State file is encrypted; a passphrase is required")
                salt = base64.b64decode(data["salt"])
                data = json.loads(_fernet(self.password, salt).decrypt(data["fernet"].encode()))
        except InvalidToken as exc:
            raise PoCError("Wrong state passphrase or corrupted state") from exc
        except (OSError, ValueError, KeyError) as exc:
            raise PoCError(f"Cannot read state file {self.path}") from exc
        return State.from_dict(data)

    def _save(self, state: State) -> None:
        payload: dict[str, Any] = state.to_dict()
        if self.password is not None:
            salt = os.urandom(16)
            token = _fernet(self.password, salt).encrypt(json.dumps(payload).encode("utf-8"))
            payload = {"salt": base64.b64encode(salt).decode("ascii"), "fernet": token.decode("ascii")}
        descriptor, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)  # mkstemp already created it with mode 0600
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def read(self) -> State:
        with self._locked():
            return self._load()

    @contextmanager
    def edit(self) -> Iterator[State]:
        """Load the state, let the caller change it, then save it (even if the
        caller raises, so progress made before an error is not lost)."""

        with self._locked():
            state = self._load()
            try:
                yield state
            finally:
                self._save(state)
