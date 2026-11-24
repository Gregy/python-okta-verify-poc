"""Enrollment lifecycle: discover the policy, enroll, update the push token, delete.

We present ourselves as Okta Verify for Android 9.10.0 (the profile the
server accepts for software keys) but make no hardware or attestation claims.
"""

from __future__ import annotations

import socket
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from .errors import ApiError, PoCError
from .http import HttpClient, check_org_link, org_origin
from .qr import Activation
from .state import Enrollment, Key

DEVICE_PROFILE = {
    "platform": "ANDROID",
    "osVersion": "32",
    "clientInstanceBundleId": "com.okta.android.auth",
    "clientInstanceVersion": "9.10.0",
    "clientInstanceDeviceSdkVersion": "9.10.0",
}


@dataclass(frozen=True)
class Policy:
    """What the org's Okta Verify authenticator policy tells us before enrolling."""

    org_id: str
    org_url: str
    authenticator_id: str
    enroll_uri: str
    expected_audience: str | None
    supports_ciba: bool
    user_verification: str  # NONE / DISCOURAGED / PREFERRED / REQUIRED
    fips_required: bool = False


def _push_method(methods: list[Any]) -> dict[str, Any]:
    push = [item for item in methods if isinstance(item, dict) and item.get("type") == "push"]
    if len(push) != 1:
        raise PoCError("Expected exactly one push method")
    return push[0]


def discover(activation: Activation, http: HttpClient, *, allow_missing_audience: bool) -> Policy:
    org = http.get(activation.org_url + "/.well-known/okta-organization")
    org_url = activation.org_url
    if href := org.get("_links", {}).get("organization", {}).get("href"):
        org_url = org_origin(check_org_link(href, activation.org_url, "Organization link"))

    policies = http.get(
        org_url + "/api/v1/authenticators?key=okta_verify&expand=methods",
        auth=f"OTDT {activation.token}",
    )
    if not isinstance(policies, list) or len(policies) != 1:
        raise PoCError("Expected exactly one built-in Okta Verify policy")
    policy = policies[0]
    if activation.authenticator_id and policy.get("id") != activation.authenticator_id:
        raise PoCError("Policy authenticator ID does not match the QR code")
    if policy.get("key") != "okta_verify" or policy.get("status") != "ACTIVE":
        raise PoCError("Policy is not an active okta_verify authenticator")

    settings = policy.get("settings", {})
    audience = settings.get("oauthClientId") or None
    if audience is None and not allow_missing_audience:
        raise PoCError(
            "Policy has no settings.oauthClientId, so challenge audiences cannot be checked; "
            "rerun with --allow-missing-policy-audience to accept that"
        )

    push = _push_method(policy.get("_embedded", {}).get("methods", []))
    push_settings = push.get("settings", {})
    if "RS256" not in push_settings.get("algorithms", []):
        raise PoCError("The policy does not offer RS256 keys")
    if push_settings.get("keyProtection", "ANY") == "HARDWARE":
        raise PoCError("The policy requires hardware keys; software keys cannot enroll")
    transaction_types = push_settings.get("transactionTypes", [])
    if "LOGIN" not in transaction_types:
        raise PoCError("The push policy does not allow LOGIN transactions")

    enroll_uri = policy.get("_links", {}).get("enroll", {}).get("href") or org_url + "/idp/authenticators"
    return Policy(
        org_id=org["id"],
        org_url=org_url,
        authenticator_id=policy["id"],
        enroll_uri=check_org_link(enroll_uri, org_url, "Enroll link"),
        expected_audience=audience,
        supports_ciba="CIBA" in transaction_types,
        user_verification=settings.get("userVerification", "PREFERRED"),
        fips_required=settings.get("compliance", {}).get("fips") == "REQUIRED",
    )


def _request_body(
    authenticator_id: str,
    display_name: str,
    supports_ciba: bool,
    pop_key: Key,
    client_instance_key: Key,
    uv_key: Key | None,
    push_token: str | None,
    fips_required: bool = False,
) -> dict[str, Any]:
    keys = {"proofOfPossession": pop_key.public_jwk(fips_compliant=fips_required)}
    if uv_key:
        keys["userVerification"] = uv_key.public_jwk(fips_compliant=fips_required)
    method: dict[str, Any] = {"type": "push", "keys": keys}
    # Android's push method leaves supportUserVerification/isFipsCompliant unset at
    # enroll; FIPS compliance is declared per key ("okta:isFipsCompliant" in the JWK).
    if push_token:
        method["pushToken"] = push_token
    if supports_ciba:
        # Android sends capabilities only when the policy advertises CIBA.
        # We still only handle LOGIN.
        method["capabilities"] = {"transactionTypes": ["LOGIN"]}
    return {
        "key": "okta_verify",
        "authenticatorId": authenticator_id,
        "device": {
            "displayName": display_name,
            **DEVICE_PROFILE,
            "clientInstanceKey": client_instance_key.public_jwk(fips_compliant=fips_required),
            "deviceAttestation": {},  # empty: no attestation claim
        },
        "methods": [method],
    }


def enroll(
    policy: Policy,
    activation: Activation,
    http: HttpClient,
    *,
    push_token: str | None,
    with_uv: bool,
    display_name: str | None,
) -> Enrollment:
    """Generate keys and POST the enrollment once. A failed POST is never retried:
    the activation token is single-use, so get a fresh QR code instead."""

    pop_key, client_instance_key = Key.generate(), Key.generate()
    uv_key = Key.generate() if with_uv else None
    display_name = display_name or socket.gethostname() or "okta-poc"
    body = _request_body(
        policy.authenticator_id, display_name, policy.supports_ciba,
        pop_key, client_instance_key, uv_key, push_token, policy.fips_required,
    )
    response = http.request(
        "POST", policy.enroll_uri, auth=f"OTDT {activation.token}", json_body=body, expected=(200, 201)
    )
    if response.get("authenticatorId") != policy.authenticator_id:
        raise PoCError("Enrollment response is for a different authenticator")
    if response.get("key") != "okta_verify" or response.get("status") != "ACTIVE":
        raise PoCError("Enrollment response is not an active okta_verify enrollment")
    push = _push_method(response.get("methods", []))
    # The response may omit the method status; only reject an explicit non-ACTIVE one.
    if push.get("status", "ACTIVE") != "ACTIVE":
        raise PoCError(f"Enrolled push method is {push.get('status')}")
    try:
        return Enrollment(
            enrollment_id=response["id"],
            authenticator_id=policy.authenticator_id,
            org_id=policy.org_id,
            org_url=policy.org_url,
            user_id=response["user"]["id"],
            username=response["user"].get("username"),
            device_id=response["device"]["id"],
            client_instance_id=response["device"]["clientInstanceId"],
            method_enrollment_id=push["id"],
            pending_challenge_uri=check_org_link(
                push["links"]["pending"]["href"], policy.org_url, "Pending challenge link"
            ),
            expected_audience=policy.expected_audience,
            policy_supports_ciba=policy.supports_ciba,
            fips_required=policy.fips_required,
            display_name=display_name,
            pop_key=pop_key,
            client_instance_key=client_instance_key,
            uv_key=uv_key,
        )
    except (KeyError, TypeError) as exc:
        raise PoCError("Enrollment response is incomplete") from exc


def auth_assertion(enrollment: Enrollment, issuer: str) -> str:
    """Self-signed JWT that authenticates us to Okta as this enrollment.

    `issuer` is the enrollment ID for update/delete and the push method ID for
    fetching pending challenges.
    """

    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": enrollment.user_id,
        "aud": enrollment.org_url,
        "kid": enrollment.pop_key.kid,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 300,
        "nbf": now - 300,
    }
    return "SSWS " + enrollment.pop_key.sign(claims, typ="okta-enrollmentupdate+jwt")


def _enrollment_url(enrollment: Enrollment) -> str:
    return f"{enrollment.org_url}/idp/authenticators/{quote(enrollment.enrollment_id, safe='')}"


def update_push_token(enrollment: Enrollment, http: HttpClient, push_token: str) -> None:
    """Replace the FCM token of an existing enrollment, keeping its keys and IDs."""

    body = _request_body(
        enrollment.authenticator_id, enrollment.display_name, enrollment.policy_supports_ciba,
        enrollment.pop_key, enrollment.client_instance_key, enrollment.uv_key, push_token,
    )
    body["device"]["id"] = enrollment.device_id
    body["device"]["clientInstanceId"] = enrollment.client_instance_id
    if enrollment.uv_key:
        # Android's UV-capable update flags UV support explicitly.
        body["methods"][0]["supportUserVerification"] = True
        body["methods"][0]["isFipsCompliant"] = enrollment.fips_required
    response = http.request(
        "PUT", _enrollment_url(enrollment),
        auth=auth_assertion(enrollment, enrollment.enrollment_id),
        json_body=body, expected=(200, 201),
    )
    if (
        response.get("id") != enrollment.enrollment_id
        or _push_method(response.get("methods", [])).get("id") != enrollment.method_enrollment_id
    ):
        raise PoCError("Push token update response changed the enrollment identity")


def delete(enrollment: Enrollment, http: HttpClient) -> str:
    try:
        http.request(
            "DELETE", _enrollment_url(enrollment),
            auth=auth_assertion(enrollment, enrollment.enrollment_id), expected=(200, 204),
        )
    except ApiError as exc:
        # E0000007: not found; E0000154: no longer active (e.g. replaced by a newer enrollment).
        if (exc.status, exc.error_code) in ((404, "E0000007"), (410, "E0000154")):
            return "already absent"
        raise
    return "deleted"
