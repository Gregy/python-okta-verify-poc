from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from .crypto import generate_rsa_key, update_assertion
from .errors import ApiError, PolicyError, ValidationError
from .http import HttpClient
from .models import DeviceProfile, EnrollmentRecord, Preparation
from .qr import Activation
from .urls import canonical_org_url, org_endpoint, validate_org_link


@dataclass(frozen=True)
class Discovery:
    org_id: str
    org_url: str
    authenticator_id: str
    enroll_uri: str
    expected_audience: str | None
    supported_transaction_types: list[str]
    policy_supports_ciba: bool
    policy_user_verification: str = "PREFERRED"

    @property
    def preparation_key(self) -> str:
        return f"{self.org_id}:{self.authenticator_id}"

    def matches(self, preparation: Preparation) -> bool:
        return (
            self.org_id == preparation.org_id
            and self.org_url == preparation.org_url
            and self.authenticator_id == preparation.authenticator_id
            and self.enroll_uri == preparation.enroll_uri
            and self.expected_audience == preparation.expected_audience
            and self.supported_transaction_types == preparation.supported_transaction_types
            and self.policy_supports_ciba == preparation.policy_supports_ciba
            and self.policy_user_verification == preparation.policy_user_verification
        )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be a JSON object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"{label} must be a JSON array")
    return value


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{label} is missing or blank")
    return value


def discover(
    activation: Activation,
    http: HttpClient,
    *,
    allow_missing_audience: bool = False,
) -> Discovery:
    organization = _object(
        http.get_json(org_endpoint(activation.org_url, "/.well-known/okta-organization")),
        "Organization response",
    )
    org_id = _required_string(organization.get("id"), "Organization id")
    org_url = activation.org_url
    organization_link = organization.get("_links", {}).get("organization", {})
    if organization_link:
        href = _required_string(
            _object(organization_link, "Organization link").get("href"),
            "Organization href",
        )
        org_url = canonical_org_url(validate_org_link(
            href, activation.org_url, allow_query=False, label="Organization href"
        ))

    # The QR f value is an authenticator ID. The endpoint's key filter remains
    # okta_verify; do not put the ID into the key query parameter.
    query = urlencode({"key": "okta_verify", "expand": "methods"})
    policies = _array(
        http.get_json(
            org_endpoint(activation.org_url, f"/api/v1/authenticators?{query}"),
            headers={"Authorization": f"OTDT {activation.token}"},
        ),
        "Authenticator policy response",
    )
    if len(policies) != 1:
        raise PolicyError("Expected exactly one built-in Okta Verify policy")
    policy = _object(policies[0], "Authenticator policy")
    authenticator_id = _required_string(policy.get("id"), "Policy authenticator id")
    if activation.authenticator_id and authenticator_id != activation.authenticator_id:
        raise ValidationError("Policy authenticator id does not match the QR activation")
    if policy.get("key") != "okta_verify" or policy.get("status") != "ACTIVE":
        raise PolicyError("Policy is not an active okta_verify authenticator")

    settings = _object(policy.get("settings", {}), "Policy settings")
    policy_user_verification = settings.get("userVerification", "PREFERRED")
    if policy_user_verification not in ("NONE", "DISCOURAGED", "PREFERRED", "REQUIRED"):
        raise PolicyError("The policy uses an unknown user-verification requirement")
    raw_audience = settings.get("oauthClientId")
    if raw_audience is None or (isinstance(raw_audience, str) and not raw_audience.strip()):
        if not allow_missing_audience:
            raise PolicyError(
                "Policy settings.oauthClientId is missing; explicitly use "
                "--allow-missing-policy-audience for the Android-compatible unbound-audience experiment"
            )
        expected_audience = None
    else:
        expected_audience = _required_string(raw_audience, "Policy settings.oauthClientId")
    embedded = _object(policy.get("_embedded", {}), "Policy _embedded")
    methods = [
        _object(item, "Policy method")
        for item in _array(embedded.get("methods", []), "Policy methods")
        if isinstance(item, dict) and item.get("type") == "push"
    ]
    if len(methods) != 1:
        raise PolicyError("Expected exactly one push method in the policy")
    push = methods[0]
    push_status = push.get("status")
    if push_status not in ("ACTIVE", "INACTIVE"):
        raise PolicyError("The push policy method has an unknown status")
    if push_status == "INACTIVE":
        # Fresh built-in QR policies can expose push as INACTIVE with an
        # activation link. Enrollment through the policy enroll link activates
        # it; do not call the lifecycle link as a separate mutation.
        push_links = _object(push.get("_links", {}), "Push policy _links")
        activate = _object(push_links.get("activate"), "Push activation link")
        validate_org_link(
            _required_string(activate.get("href"), "Push activation href"),
            org_url,
            allow_query=True,
            label="Push activation href",
        )
    push_settings = _object(push.get("settings", {}), "Push policy settings")
    algorithms = _array(push_settings.get("algorithms", []), "Push algorithms")
    if "RS256" not in algorithms:
        raise PolicyError("The policy does not offer the PoC's RS256 algorithm")
    protection = push_settings.get("keyProtection", "ANY")
    if protection == "HARDWARE":
        raise PolicyError("The policy requires hardware keys; this software-key PoC cannot enroll")
    if protection not in ("ANY", "SOFTWARE"):
        raise PolicyError("The policy uses an unknown key-protection requirement")
    advertised = _array(push_settings.get("transactionTypes", []), "Push transaction types")
    if "LOGIN" not in advertised:
        raise PolicyError("The push policy does not advertise LOGIN transactions")

    enroll_uri = org_endpoint(org_url, "/idp/authenticators")
    links = _object(policy.get("_links", {}), "Policy _links")
    if links.get("enroll") is not None:
        enroll = _object(links["enroll"], "Policy enroll link")
        enroll_uri = validate_org_link(
            _required_string(enroll.get("href"), "Policy enroll href"),
            org_url,
            allow_query=True,
            label="Policy enroll href",
        )
    return Discovery(
        org_id=org_id,
        org_url=org_url,
        authenticator_id=authenticator_id,
        enroll_uri=enroll_uri,
        expected_audience=expected_audience,
        supported_transaction_types=["LOGIN"],
        policy_supports_ciba="CIBA" in advertised,
        policy_user_verification=policy_user_verification,
    )


def new_preparation(
    discovery: Discovery,
    *,
    jwk_profile: str,
    display_name: str | None,
    with_uv: bool = False,
) -> Preparation:
    return Preparation(
        org_id=discovery.org_id,
        org_url=discovery.org_url,
        authenticator_id=discovery.authenticator_id,
        enroll_uri=discovery.enroll_uri,
        expected_audience=discovery.expected_audience,
        supported_transaction_types=list(discovery.supported_transaction_types),
        policy_supports_ciba=discovery.policy_supports_ciba,
        pop_key=generate_rsa_key(profile=jwk_profile),
        client_instance_key=generate_rsa_key(profile=jwk_profile),
        device_profile=DeviceProfile.android_compatibility(display_name),
        jwk_profile=jwk_profile,
        uv_key=generate_rsa_key(profile=jwk_profile) if with_uv else None,
        policy_user_verification=discovery.policy_user_verification,
    )


def enrollment_body(
    preparation: Preparation | EnrollmentRecord,
    push_token: str | None,
) -> dict[str, Any]:
    keys = {"proofOfPossession": preparation.pop_key.public_jwk}
    if preparation.uv_key is not None:
        keys["userVerification"] = preparation.uv_key.public_jwk
    method: dict[str, Any] = {
        "type": "push",
        "keys": keys,
    }
    if push_token is not None:
        if not push_token or len(push_token) > 16384:
            raise ValidationError("FCM token is empty or too long")
        method["pushToken"] = push_token
    # CIBA itself is not requested. Android 9.10.0 emits capabilities only when
    # the policy advertises CIBA.
    if preparation.policy_supports_ciba:
        method["capabilities"] = {"transactionTypes": ["LOGIN"]}
    return {
        "key": "okta_verify",
        "authenticatorId": preparation.authenticator_id,
        "device": preparation.device_profile.enrollment_dict(
            preparation.client_instance_key.public_jwk
        ),
        "methods": [method],
    }


def parse_enrollment_response(
    value: Any,
    preparation: Preparation,
) -> EnrollmentRecord:
    response = _object(value, "Enrollment response")
    enrollment_id = _required_string(response.get("id"), "Enrollment id")
    if response.get("authenticatorId") != preparation.authenticator_id:
        raise ValidationError("Enrollment response has a different authenticator id")
    if response.get("key") != "okta_verify" or response.get("status") != "ACTIVE":
        raise ValidationError("Enrollment response is not an active okta_verify enrollment")
    device = _object(response.get("device"), "Enrolled device")
    device_id = _required_string(device.get("id"), "Enrolled device id")
    client_instance_id = _required_string(
        device.get("clientInstanceId"), "Enrolled client instance id"
    )
    user = _object(response.get("user"), "Enrolled user")
    user_id = _required_string(user.get("id"), "Enrolled user id")
    username = user.get("username")
    if username is not None and not isinstance(username, str):
        raise ValidationError("Enrolled username is not a string")
    methods = [
        _object(item, "Enrolled method")
        for item in _array(response.get("methods"), "Enrolled methods")
        if isinstance(item, dict) and item.get("type") == "push"
    ]
    if len(methods) != 1:
        raise ValidationError("Enrollment response does not contain exactly one push method")
    method = methods[0]
    method_status = method.get("status")
    # The current legacy response can omit method status even though the parent
    # enrollment is ACTIVE. Reject only an explicitly different status.
    if method_status is not None and method_status != "ACTIVE":
        raise ValidationError(f"Enrolled push method status is not ACTIVE: {method_status}")
    method_id = _required_string(method.get("id"), "Push method enrollment id")
    links = _object(method.get("links"), "Push method links")
    pending = _object(links.get("pending"), "Pending challenge link")
    pending_uri = validate_org_link(
        _required_string(pending.get("href"), "Pending challenge href"),
        preparation.org_url,
        allow_query=True,
        label="Pending challenge href",
    )
    return EnrollmentRecord(
        enrollment_id=enrollment_id,
        authenticator_id=preparation.authenticator_id,
        org_id=preparation.org_id,
        org_url=preparation.org_url,
        user_id=user_id,
        username=username,
        device_id=device_id,
        client_instance_id=client_instance_id,
        method_enrollment_id=method_id,
        pending_challenge_uri=pending_uri,
        expected_audience=preparation.expected_audience,
        supported_transaction_types=list(preparation.supported_transaction_types),
        pop_key=preparation.pop_key,
        client_instance_key=preparation.client_instance_key,
        device_profile=preparation.device_profile,
        jwk_profile=preparation.jwk_profile,
        uv_key=preparation.uv_key,
        uv_enrolled=preparation.uv_key is not None,
        policy_supports_ciba=preparation.policy_supports_ciba,
    )


def update_enrollment(
    enrollment: EnrollmentRecord,
    http: HttpClient,
    *,
    push_token: str,
    now: int,
) -> EnrollmentRecord:
    """Update the same enrollment without replacing its identity or keys."""

    body = enrollment_body(enrollment, push_token)
    if enrollment.uv_key is not None:
        # The dedicated Android UV update marks UV support explicitly and
        # reports FIPS state separately from key protection.
        body["methods"][0]["supportUserVerification"] = True
        body["methods"][0]["isFipsCompliant"] = False
    body["device"]["id"] = enrollment.device_id
    body["device"]["clientInstanceId"] = enrollment.client_instance_id
    authorization = f"SSWS {update_assertion(enrollment, now=now)}"
    url = org_endpoint(
        enrollment.org_url,
        f"/idp/authenticators/{quote(enrollment.enrollment_id, safe='')}",
    )
    value = http.request(
        "PUT",
        url,
        headers={
            "Authorization": authorization,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json_body=body,
        expected=(200, 201),
    ).json()
    updated = parse_enrollment_response(value, enrollment)
    if (
        updated.enrollment_id != enrollment.enrollment_id
        or updated.method_enrollment_id != enrollment.method_enrollment_id
        or updated.device_id != enrollment.device_id
        or updated.client_instance_id != enrollment.client_instance_id
        or updated.user_id != enrollment.user_id
    ):
        raise ValidationError("Enrollment update response changed a bound identity")
    return updated


def delete_enrollment(
    enrollment: EnrollmentRecord,
    http: HttpClient,
    *,
    now: int,
) -> str:
    """Delete one server enrollment, preserving local state on uncertain errors."""

    authorization = f"SSWS {update_assertion(enrollment, now=now)}"
    url = org_endpoint(
        enrollment.org_url,
        f"/idp/authenticators/{quote(enrollment.enrollment_id, safe='')}",
    )
    try:
        http.request(
            "DELETE",
            url,
            headers={
                "Authorization": authorization,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            expected=(200, 204),
        )
    except ApiError as exc:
        # Android treats its resource-not-found deletion result as success.
        # Restrict idempotency to Okta's known not-found code, not every 404.
        if exc.status == 404 and exc.error_code == "E0000007":
            return "already absent"
        raise
    return "deleted"
