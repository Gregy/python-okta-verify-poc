from __future__ import annotations

import base64
import fcntl
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import StateError
from .models import State

_AAD = b"okta-poc-state-v1"
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if not password:
        raise StateError("State passphrase must not be empty")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


class StateStore:
    def __init__(self, path: Path, *, plaintext: bool = False) -> None:
        self.path = path.expanduser().resolve()
        self._plaintext = plaintext

    @property
    def exists(self) -> bool:
        return self.path.exists()

    @property
    def plaintext(self) -> bool:
        if self._plaintext:
            return True
        if not self.exists:
            return False
        return "schema_version" in self._read_envelope()

    def _ensure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Serialize state-changing CLI operations on this host."""

        self._ensure_parent()
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path.with_suffix(self.path.suffix + ".lock"), flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read_envelope(self) -> dict:
        try:
            info = os.lstat(self.path)
            if not stat.S_ISREG(info.st_mode):
                raise StateError("State path is not a regular file")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise StateError("State file permissions are too open; chmod 600 the state file")
            if info.st_size > 4 * 1024 * 1024:
                raise StateError("State file is too large")
            with self.path.open("r", encoding="utf-8") as handle:
                envelope = json.load(handle)
            if not isinstance(envelope, dict):
                raise StateError("State envelope is invalid")
            return envelope
        except FileNotFoundError as exc:
            raise StateError(f"No local state exists at {self.path}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise StateError("Cannot read local state") from exc

    def load(self, password: str = "", *, create: bool = False) -> State:
        if not self.exists:
            if create:
                if not password and not self._plaintext:
                    raise StateError("State passphrase must not be empty")
                return State()
            raise StateError(f"No local state exists at {self.path}")
        envelope = self._read_envelope()
        if "schema_version" in envelope:
            self._plaintext = True
            return State.from_dict(envelope)
        if self._plaintext:
            raise StateError("The existing state is encrypted; do not use plaintext mode")
        try:
            if envelope.get("version") != 1:
                raise StateError("Unsupported state envelope version")
            kdf = envelope["kdf"]
            cipher = envelope["cipher"]
            if kdf["name"] != "scrypt" or cipher["name"] != "AES-256-GCM":
                raise StateError("Unsupported state encryption profile")
            salt = base64.b64decode(kdf["salt"], validate=True)
            nonce = base64.b64decode(cipher["nonce"], validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
            if len(salt) != 16 or len(nonce) != 12:
                raise StateError("State envelope parameters are invalid")
            n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
            if n != _SCRYPT_N or r != _SCRYPT_R or p != _SCRYPT_P:
                raise StateError("Unsupported state KDF parameters")
            key = _derive(password, salt, n, r, p)
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, _AAD)
            value = json.loads(plaintext.decode("utf-8"))
            if not isinstance(value, dict):
                raise StateError("Decrypted state is invalid")
            return State.from_dict(value)
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise StateError("Wrong state passphrase or corrupted state") from exc
        except StateError:
            raise
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise StateError("Malformed encrypted state envelope") from exc

    def save(self, state: State, password: str = "") -> None:
        if self.plaintext:
            encoded = json.dumps(
                state.to_dict(), ensure_ascii=False, indent=2, sort_keys=True
            ).encode("utf-8")
        else:
            if not password:
                raise StateError("State passphrase must not be empty")
            salt = os.urandom(16)
            nonce = os.urandom(12)
            key = _derive(password, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
            plaintext = json.dumps(
                state.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, _AAD)
            envelope = {
                "version": 1,
                "kdf": {
                    "name": "scrypt",
                    "salt": _b64(salt),
                    "n": _SCRYPT_N,
                    "r": _SCRYPT_R,
                    "p": _SCRYPT_P,
                    "length": 32,
                },
                "cipher": {"name": "AES-256-GCM", "nonce": _b64(nonce)},
                "ciphertext": _b64(ciphertext),
            }
            encoded = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self._ensure_parent()
        temporary: str | None = None
        try:
            descriptor, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.write(b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            temporary = None
            os.chmod(self.path, 0o600)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise StateError("Cannot atomically save state") from exc
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
