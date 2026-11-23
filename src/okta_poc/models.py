from __future__ import annotations

import socket
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from .errors import StateError


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class KeyRecord:
    kid: str
    algorithm: str
    private_pem: str = field(repr=False)
    public_jwk: dict[str, Any]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> KeyRecord:
        try:
            if value["algorithm"] != "RS256":
                raise StateError("Unsupported key algorithm in local state")
            if not isinstance(value["public_jwk"], dict):
                raise StateError("Invalid public JWK in local state")
            return cls(
                kid=str(value["kid"]),
                algorithm=value["algorithm"],
                private_pem=str(value["private_pem"]),
                public_jwk=value["public_jwk"],
            )
        except KeyError as exc:
            raise StateError("Incomplete key record in local state") from exc


@dataclass
class DeviceProfile:
    display_name: str
    platform: str
    os_version: str
    model: str | None
    client_instance_bundle_id: str
    client_instance_version: str
    client_instance_device_sdk_version: str

    @classmethod
    def android_compatibility(cls, display_name: str | None = None) -> DeviceProfile:
        """Declared Android protocol profile for disposable compatibility tests."""

        return cls(
            display_name=display_name or socket.gethostname() or "okta-poc-android-test",
            platform="ANDROID",
            os_version="32",
            # Do not invent a phone manufacturer/model or hardware signals.
            model=None,
            client_instance_bundle_id="com.okta.android.auth",
            client_instance_version="9.10.0",
            client_instance_device_sdk_version="9.10.0",
        )

    def enrollment_dict(self, client_instance_jwk: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "displayName": self.display_name,
            "platform": self.platform,
            "osVersion": self.os_version,
            "clientInstanceBundleId": self.client_instance_bundle_id,
            "clientInstanceVersion": self.client_instance_version,
            "clientInstanceDeviceSdkVersion": self.client_instance_device_sdk_version,
            "clientInstanceKey": client_instance_jwk,
            # Empty means that this independent PoC makes no attestation claim.
            "deviceAttestation": {},
        }
        if self.model:
            result["model"] = self.model
        return result

    def response_signals(
        self,
        requested: list[str],
        *,
        device_id: str,
        client_instance_id: str,
    ) -> tuple[dict[str, Any], list[str]]:
        available = {
            "displayName": self.display_name,
            "platform": self.platform,
            "osVersion": self.os_version,
            "model": self.model,
            "clientInstanceBundleId": self.client_instance_bundle_id,
            "clientInstanceVersion": self.client_instance_version,
            "clientInstanceDeviceSdkVersion": self.client_instance_device_sdk_version,
        }
        signals: dict[str, Any] = {
            "id": device_id,
            "clientInstanceId": client_instance_id,
        }
        omitted: list[str] = []
        for name in requested:
            if name in ("id", "clientInstanceId"):
                continue
            value = available.get(name)
            if value is None:
                omitted.append(name)
            else:
                signals[name] = value
        return signals, sorted(set(omitted))


@dataclass
class Preparation:
    org_id: str
    org_url: str
    authenticator_id: str
    enroll_uri: str
    expected_audience: str | None
    supported_transaction_types: list[str]
    policy_supports_ciba: bool
    pop_key: KeyRecord
    client_instance_key: KeyRecord
    device_profile: DeviceProfile
    jwk_profile: str
    uv_key: KeyRecord | None = None
    policy_user_verification: str = "PREFERRED"

    @property
    def key(self) -> str:
        return f"{self.org_id}:{self.authenticator_id}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Preparation:
        try:
            result = cls(
                org_id=str(value["org_id"]),
                org_url=str(value["org_url"]),
                authenticator_id=str(value["authenticator_id"]),
                enroll_uri=str(value["enroll_uri"]),
                expected_audience=value.get("expected_audience"),
                supported_transaction_types=list(value["supported_transaction_types"]),
                policy_supports_ciba=value["policy_supports_ciba"],
                pop_key=KeyRecord.from_dict(value["pop_key"]),
                client_instance_key=KeyRecord.from_dict(value["client_instance_key"]),
                device_profile=DeviceProfile(**value["device_profile"]),
                jwk_profile=str(value["jwk_profile"]),
                uv_key=(
                    KeyRecord.from_dict(value["uv_key"])
                    if value.get("uv_key") is not None
                    else None
                ),
                policy_user_verification=value.get("policy_user_verification", "PREFERRED"),
            )
        except (KeyError, TypeError) as exc:
            raise StateError("Incomplete enrollment preparation in local state") from exc
        if result.expected_audience is not None and (
            not isinstance(result.expected_audience, str) or not result.expected_audience.strip()
        ):
            raise StateError("Invalid expected audience in local state")
        if result.jwk_profile not in ("android", "canonical"):
            raise StateError("Unknown JWK profile in local state")
        return result


@dataclass
class EnrollmentRecord:
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
    expected_audience: str | None
    supported_transaction_types: list[str]
    pop_key: KeyRecord
    client_instance_key: KeyRecord
    device_profile: DeviceProfile
    jwk_profile: str
    uv_key: KeyRecord | None = None
    uv_enrolled: bool = False
    policy_supports_ciba: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EnrollmentRecord:
        try:
            result = cls(
                enrollment_id=str(value["enrollment_id"]),
                authenticator_id=str(value["authenticator_id"]),
                org_id=str(value["org_id"]),
                org_url=str(value["org_url"]),
                user_id=str(value["user_id"]),
                username=value.get("username"),
                device_id=str(value["device_id"]),
                client_instance_id=str(value["client_instance_id"]),
                method_enrollment_id=str(value["method_enrollment_id"]),
                pending_challenge_uri=str(value["pending_challenge_uri"]),
                expected_audience=value.get("expected_audience"),
                supported_transaction_types=list(value["supported_transaction_types"]),
                pop_key=KeyRecord.from_dict(value["pop_key"]),
                client_instance_key=KeyRecord.from_dict(value["client_instance_key"]),
                device_profile=DeviceProfile(**value["device_profile"]),
                jwk_profile=str(value["jwk_profile"]),
                uv_key=(
                    KeyRecord.from_dict(value["uv_key"])
                    if value.get("uv_key") is not None
                    else None
                ),
                uv_enrolled=value.get("uv_enrolled", False),
                policy_supports_ciba=value.get("policy_supports_ciba", False),
            )
        except (KeyError, TypeError) as exc:
            raise StateError("Incomplete enrollment in local state") from exc
        if result.expected_audience is not None and (
            not isinstance(result.expected_audience, str) or not result.expected_audience.strip()
        ):
            raise StateError("Invalid expected audience in local state")
        return result


@dataclass
class State:
    installation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    preparations: dict[str, Preparation] = field(default_factory=dict)
    enrollments: dict[str, EnrollmentRecord] = field(default_factory=dict)
    transactions: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "installation_id": self.installation_id,
            "preparations": {key: value.to_dict() for key, value in self.preparations.items()},
            "enrollments": {key: value.to_dict() for key, value in self.enrollments.items()},
            "transactions": self.transactions,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> State:
        if value.get("schema_version") != 1:
            raise StateError("Unsupported local state schema")
        try:
            state = cls(installation_id=str(value["installation_id"]))
            uuid.UUID(state.installation_id)
            state.preparations = {
                key: Preparation.from_dict(item)
                for key, item in value.get("preparations", {}).items()
            }
            state.enrollments = {
                key: EnrollmentRecord.from_dict(item)
                for key, item in value.get("enrollments", {}).items()
            }
            transactions = value.get("transactions", {})
            if not isinstance(transactions, dict):
                raise StateError("Invalid transaction state")
            state.transactions = transactions
            return state
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            if isinstance(exc, StateError):
                raise
            raise StateError("Malformed local state") from exc

    def transaction(self, enrollment_id: str, transaction_id: str) -> dict[str, Any] | None:
        return self.transactions.get(enrollment_id, {}).get(transaction_id)

    def set_transaction(
        self,
        enrollment_id: str,
        transaction_id: str,
        status: str,
        *,
        decision: str,
        http_status: int | None = None,
    ) -> None:
        self.transactions.setdefault(enrollment_id, {})[transaction_id] = {
            "state": status,
            "decision": decision,
            "http_status": http_status,
            "updated_at": utc_now(),
        }
