from __future__ import annotations

import time
from copy import deepcopy
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from okta_poc.enrollment import Policy
from okta_poc.qr import Activation
from okta_poc.state import Enrollment, Key

ORG = "https://org.example"
VERIFY_URI = ORG + "/idp/authenticators/enrollment-id/transactions/tx-1/verify"


class FakeHttp:
    """Stands in for HttpClient: returns queued responses in order, records calls."""

    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(self, method, url, *, auth=None, json_body=None, accept="application/json", expected=(200,)):
        self.calls.append({"method": method, "url": url, "auth": auth, "body": deepcopy(json_body), "accept": accept})
        if not self.responses:
            raise AssertionError(f"Unexpected {method} {url}")
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)

    def get(self, url, *, auth=None):
        return self.request("GET", url, auth=auth)


def activation() -> Activation:
    return Activation(token="TEST_ACTIVATION_TOKEN", org_url=ORG, authenticator_id="aut_example")


def policy(*, ciba: bool = False, audience: str | None = "0oa_client", uv: str = "PREFERRED", fips: bool = False) -> Policy:
    return Policy(
        org_id="00o_org",
        org_url=ORG,
        authenticator_id="aut_example",
        enroll_uri=ORG + "/idp/authenticators",
        expected_audience=audience,
        supports_ciba=ciba,
        user_verification=uv,
        fips_required=fips,
    )


def organization_response() -> dict[str, Any]:
    return {"id": "00o_org", "_links": {"organization": {"href": ORG}}}


def policy_response(*, ciba: bool = False, protection: str = "ANY", audience: str | None = "0oa_client", fips: bool = False) -> list[dict[str, Any]]:
    settings = {"oauthClientId": audience} if audience else {}
    settings["compliance"] = {"fips": "REQUIRED" if fips else "ANY"}
    return [
        {
            "id": "aut_example",
            "key": "okta_verify",
            "status": "ACTIVE",
            "settings": settings,
            "_links": {"enroll": {"href": ORG + "/idp/authenticators"}},
            "_embedded": {
                "methods": [
                    {
                        "type": "push",
                        "status": "INACTIVE",
                        "settings": {
                            "algorithms": ["RS256", "ES256"],
                            "keyProtection": protection,
                            "transactionTypes": ["LOGIN", "CIBA"] if ciba else ["LOGIN"],
                        },
                    }
                ]
            },
        }
    ]


def enrollment_response() -> dict[str, Any]:
    return {
        "id": "enrollment-id",
        "authenticatorId": "aut_example",
        "key": "okta_verify",
        "status": "ACTIVE",
        "device": {"id": "device-id", "clientInstanceId": "client-instance-id"},
        "user": {"id": "user-id", "username": "user@example.test"},
        "methods": [
            {
                "id": "push-method-id",
                "type": "push",
                "links": {"pending": {"href": ORG + "/api/v1/factors/device-id/lifecycle/pending"}},
            }
        ],
    }


def enrollment(*, audience: str | None = "0oa_client", with_uv: bool = False) -> Enrollment:
    return Enrollment(
        enrollment_id="enrollment-id",
        authenticator_id="aut_example",
        org_id="00o_org",
        org_url=ORG,
        user_id="user-id",
        username="user@example.test",
        device_id="device-id",
        client_instance_id="client-instance-id",
        method_enrollment_id="push-method-id",
        pending_challenge_uri=ORG + "/api/v1/factors/device-id/lifecycle/pending",
        expected_audience=audience,
        policy_supports_ciba=False,
        display_name="Test Host",
        pop_key=Key.generate(),
        client_instance_key=Key.generate(),
        uv_key=Key.generate() if with_uv else None,
    )


class Server:
    """The org's challenge-signing key and its JWKS."""

    def __init__(self, kid: str = "server-kid") -> None:
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        return {"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]}

    def sign(self, claims: dict[str, Any], *, typ: str = "okta-pushbind+jwt", kid: str | None = None) -> str:
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": kid or self.kid, "typ": typ})


def challenge_claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims = {
        "iss": ORG,
        "aud": "0oa_client",
        "exp": now + 300,
        "iat": now,
        "jti": "jti-1",
        "nonce": "SYNTHETIC_NONCE",
        "transactionId": "tx-1",
        "verificationUri": VERIFY_URI,
        "method": "push",
        "orgId": "00o_org",
        "userId": "user-id",
        "authenticatorEnrollmentId": "enrollment-id",
        "methodEnrollmentId": "push-method-id",
        "appInstanceName": "Example Dashboard",
        "userMediation": "REQUIRED",
        "userVerification": "NONE",
        "signals": ["id", "clientInstanceId", "platform", "clientInstanceVersion", "imei"],
        "challengeContext": {
            "clientOS": "Linux",
            "clientLocation": "Test Location",
            "transactionTime": "2026-11-23T10:00:00.000Z",
            "transactionType": "LOGIN",
        },
    }
    claims.update(overrides)
    return claims
