from __future__ import annotations

import json

import jwt
import pytest

from okta_poc.challenge import ChallengeValidator, submit_response
from okta_poc.cli import _poll
from okta_poc.crypto import generate_rsa_key, private_key
from okta_poc.errors import ApiError, ValidationError
from okta_poc.http import HttpClient, HttpResponse
from tests.helpers import (
    NOW,
    FakeHttp,
    FakeResponse,
    FakeSession,
    challenge_claims,
    enrollment,
    server_challenge,
)


def test_pending_http_method_headers_and_ssws_claims():
    record = enrollment()
    session = FakeSession([FakeResponse(body=b"[]")])
    http = HttpClient(session)
    challenges, errors = _poll(record, http, now=NOW)
    assert challenges == [] and errors == []
    request = session.requests[0]
    assert request["method"] == "GET"
    assert request["url"] == record.pending_challenge_uri
    assert request["allow_redirects"] is False
    assert request["headers"]["Accept"] == "application/json"
    assert request["headers"]["Content-Type"] == "application/json"
    scheme, compact = request["headers"]["Authorization"].split(" ", 1)
    assert scheme == "SSWS"
    assert jwt.get_unverified_header(compact)["typ"] == "okta-enrollmentupdate+jwt"
    claims = jwt.decode(
        compact,
        private_key(record.pop_key).public_key(),
        algorithms=["RS256"],
        audience=record.org_url,
        issuer=record.method_enrollment_id,
        options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
    )
    assert claims["kid"] == record.pop_key.kid
    assert claims["exp"] == NOW + 300 and claims["nbf"] == NOW - 300


def test_verify_body_headers_and_200_204_success():
    record = enrollment()
    server = generate_rsa_key(profile="canonical")
    claims = challenge_claims()
    compact = server_challenge(server, claims)
    jwks = {"keys": [server.public_jwk]}
    for status in (200, 204):
        http = FakeHttp(gets=[jwks], posts=[HttpResponse(status, {}, b"")])
        challenge = ChallengeValidator(record, http).validate(compact, now=NOW)
        response = submit_response(http, record, challenge, "HEADER.PAYLOAD.SIGNATURE")
        assert response.status == status
        post = http.calls[-1]
        assert post["method"] == "POST"
        assert post["url"] == claims["verificationUri"]
        assert post["headers"] == {"Accept": "application/json; okta-version=1.0.0"}
        assert post["expected"] == (200, 204)
        assert post["body"] == {"method": "push", "challengeResponse": "HEADER.PAYLOAD.SIGNATURE"}
        assert "Authorization" not in post["headers"]


def test_redirect_is_not_followed_or_accepted():
    session = FakeSession([FakeResponse(status=302, headers={"Location": "https://attacker.example"})])
    with pytest.raises(ApiError) as caught:
        HttpClient(session).get_json("https://org.example/api/v1/test")
    assert caught.value.status == 302
    assert session.requests[0]["allow_redirects"] is False


def test_error_body_is_redacted_and_bounded():
    body = json.dumps({
        "errorCode": "E0000001",
        "errorSummary": "Bad OTDT SECRET_TOKEN abc.def.ghi",
    }).encode()
    session = FakeSession([FakeResponse(status=400, body=body)])
    with pytest.raises(ApiError) as caught:
        HttpClient(session).get_json("https://org.example/api/v1/test")
    message = str(caught.value)
    assert "E0000001" in message
    assert "SECRET_TOKEN" not in message
    assert "abc.def.ghi" not in message


def test_non_json_success_is_rejected():
    session = FakeSession([FakeResponse(body=b"not-json")])
    with pytest.raises(ValidationError, match="malformed JSON"):
        HttpClient(session).get_json("https://org.example/api/v1/test")
