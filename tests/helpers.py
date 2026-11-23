from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from okta_poc.challenge import ValidatedChallenge
from okta_poc.crypto import sign_jws
from okta_poc.enrollment import Discovery, new_preparation, parse_enrollment_response
from okta_poc.http import HttpResponse
from okta_poc.models import EnrollmentRecord
from okta_poc.qr import Activation

NOW = 1763928000
ORG = "https://org.example"


def write_qr_image(path: Path, value: str) -> None:
    import cv2

    image = cv2.QRCodeEncoder_create().encode(value)
    # OpenCV emits one pixel per module; upscale with a quiet zone so its
    # detector sees the same geometry as a real rendered QR image.
    image = cv2.resize(image, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    image = cv2.copyMakeBorder(
        image, 32, 32, 32, 32, cv2.BORDER_CONSTANT, value=255
    )
    if image is None or not cv2.imwrite(str(path), image):
        raise AssertionError("Could not create synthetic QR test image")


def discovery(*, ciba: bool = False) -> Discovery:
    return Discovery(
        org_id="00o_org",
        org_url=ORG,
        authenticator_id="aut_example",
        enroll_uri=ORG + "/idp/authenticators",
        expected_audience="0oa_client",
        supported_transaction_types=["LOGIN"],
        policy_supports_ciba=ciba,
    )


def preparation(*, ciba: bool = False, profile: str = "canonical"):
    return new_preparation(
        discovery(ciba=ciba), jwk_profile=profile, display_name="Test Linux Host"
    )


def enrollment_response() -> dict[str, Any]:
    return {
        "id": "enrollment-id",
        "authenticatorId": "aut_example",
        "key": "okta_verify",
        "status": "ACTIVE",
        "type": "APP",
        "device": {"id": "device-id", "clientInstanceId": "client-instance-id"},
        "user": {"id": "user-id", "username": "user@example.test"},
        "methods": [
            {
                "id": "push-method-id",
                "type": "push",
                "status": "ACTIVE",
                "links": {"pending": {"href": ORG + "/api/v1/factors/device-id/lifecycle/pending"}},
            }
        ],
    }


def enrollment(*, ciba: bool = False, profile: str = "canonical") -> EnrollmentRecord:
    prep = preparation(ciba=ciba, profile=profile)
    return parse_enrollment_response(enrollment_response(), prep)


def activation() -> Activation:
    return Activation(
        token="TEST_ACTIVATION_TOKEN",
        authenticator_id="aut_example",
        org_url=ORG,
        account="test-account",
        issuer="Example",
    )


def policy_response(*, ciba: bool = False, protection: str = "ANY") -> list[dict[str, Any]]:
    transaction_types = ["LOGIN", "CIBA"] if ciba else ["LOGIN"]
    return [
        {
            "id": "aut_example",
            "key": "okta_verify",
            "type": "APP",
            "status": "ACTIVE",
            "settings": {"oauthClientId": "0oa_client"},
            "_links": {"enroll": {"href": ORG + "/idp/authenticators"}},
            "_embedded": {
                "methods": [
                    {
                        "type": "push",
                        "status": "ACTIVE",
                        "settings": {
                            "algorithms": ["RS256", "ES256"],
                            "keyProtection": protection,
                            "transactionTypes": transaction_types,
                        },
                    }
                ]
            },
        }
    ]


def organization_response() -> dict[str, Any]:
    return {"id": "00o_org", "_links": {"organization": {"href": ORG}}}


def challenge_claims() -> dict[str, Any]:
    return {
        "iss": ORG,
        "aud": "0oa_client",
        "exp": NOW + 300,
        "iat": NOW,
        "nbf": NOW - 30,
        "jti": "transaction-id",
        "nonce": "SYNTHETIC_NONCE",
        "transactionId": "transaction-id",
        "verificationUri": ORG + "/idp/authenticators/enrollment-id/transactions/transaction-id/verify",
        "method": "push",
        "orgId": "00o_org",
        "appInstanceName": "Example Dashboard",
        "userId": "user-id",
        "authenticatorEnrollmentId": "enrollment-id",
        "methodEnrollmentId": "push-method-id",
        "userMediation": "REQUIRED",
        "userVerification": "NONE",
        "ver": 0,
        "signals": ["id", "clientInstanceId", "platform", "clientInstanceVersion"],
        "challengeContext": {
            "clientOS": "LINUX",
            "clientLocation": "Test Location",
            "transactionTime": "2026-11-23T10:00:00.000Z",
            "transactionType": "LOGIN",
        },
    }


def validated_challenge(
    *,
    transaction_id: str = "transaction-id",
    user_verification: str = "NONE",
) -> ValidatedChallenge:
    claims = challenge_claims()
    claims["jti"] = transaction_id
    claims["transactionId"] = transaction_id
    claims["verificationUri"] = ORG + f"/idp/authenticators/enrollment-id/transactions/{transaction_id}/verify"
    claims["userVerification"] = user_verification
    return ValidatedChallenge(
        enrollment_id=claims["authenticatorEnrollmentId"],
        transaction_id=transaction_id,
        verification_uri=claims["verificationUri"],
        expires_at=claims["exp"],
        validated_at=claims["iat"],
        issuer=claims["iss"],
        nonce=claims["nonce"],
        transaction_type=claims["challengeContext"]["transactionType"],
        user_verification=user_verification,
        user_mediation=claims["userMediation"],
        requested_signals=list(claims["signals"]),
        legacy_v1=False,
        number_matching=False,
        audience_bound=True,
        claims=claims,
    )


def server_challenge(server_key, claims: dict[str, Any], *, typ: str = "okta-pushbind+jwt") -> str:
    return sign_jws(server_key, claims, typ=typ)


class FakeHttp:
    def __init__(
        self,
        *,
        gets: list[Any] | None = None,
        posts: list[Any] | None = None,
        puts: list[Any] | None = None,
        deletes: list[Any] | None = None,
    ) -> None:
        self.gets = list(gets or [])
        self.posts = list(posts or [])
        self.puts = list(puts or [])
        self.deletes = list(deletes or [])
        self.calls: list[dict[str, Any]] = []

    def get_json(self, url: str, *, headers=None, expected=(200,)):
        self.calls.append({"method": "GET", "url": url, "headers": deepcopy(headers or {}), "expected": tuple(expected)})
        if not self.gets:
            raise AssertionError("Unexpected GET " + url)
        value = self.gets.pop(0)
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)

    def post_json(self, url: str, body: Any, *, headers=None, expected=(200,)):
        self.calls.append({"method": "POST", "url": url, "headers": deepcopy(headers or {}), "body": deepcopy(body), "expected": tuple(expected)})
        if not self.posts:
            raise AssertionError("Unexpected POST " + url)
        value = self.posts.pop(0)
        if isinstance(value, Exception):
            raise value
        if isinstance(value, HttpResponse):
            return value
        return HttpResponse(200, {}, b"{}")

    def request(self, method: str, url: str, *, headers=None, json_body=None, expected=(200,)):
        self.calls.append({"method": method, "url": url, "headers": deepcopy(headers or {}), "body": deepcopy(json_body), "expected": tuple(expected)})
        values = self.puts if method == "PUT" else self.deletes if method == "DELETE" else []
        if not values:
            raise AssertionError("Unexpected " + method + " " + url)
        value = values.pop(0)
        if isinstance(value, Exception):
            raise value
        if isinstance(value, HttpResponse):
            return value
        raise TypeError(f"{method} fake must be HttpResponse")


class FakeResponse:
    def __init__(self, status: int = 200, body: bytes = b"{}", headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.closed = False

    def iter_content(self, size: int):
        yield self._body

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses
        self.requests: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs):
        self.requests.append({"method": method, "url": url, **kwargs})
        return self.responses.pop(0)
