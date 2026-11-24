from __future__ import annotations

import jwt
import pytest

from okta_poc.enrollment import auth_assertion, delete, discover, enroll, update_push_token
from okta_poc.errors import ApiError, PoCError
from tests.helpers import (
    ORG,
    FakeHttp,
    activation,
    enrollment,
    enrollment_response,
    organization_response,
    policy,
    policy_response,
)


def _claims(token: str, key) -> dict:
    return jwt.decode(token, key._private().public_key(), algorithms=["RS256"], audience=ORG)


def test_discover_requests_and_policy():
    http = FakeHttp(organization_response(), policy_response(ciba=True))
    result = discover(activation(), http, allow_missing_audience=False)
    assert result == policy(ciba=True)
    assert http.calls[0]["url"] == ORG + "/.well-known/okta-organization"
    assert http.calls[1]["url"] == ORG + "/api/v1/authenticators?key=okta_verify&expand=methods"
    assert http.calls[1]["auth"] == "OTDT TEST_ACTIVATION_TOKEN"


def test_missing_policy_audience_needs_explicit_opt_in():
    with pytest.raises(PoCError, match="oauthClientId"):
        discover(activation(), FakeHttp(organization_response(), policy_response(audience=None)), allow_missing_audience=False)
    result = discover(activation(), FakeHttp(organization_response(), policy_response(audience=None)), allow_missing_audience=True)
    assert result.expected_audience is None


def test_hardware_key_policy_is_refused():
    http = FakeHttp(organization_response(), policy_response(protection="HARDWARE"))
    with pytest.raises(PoCError, match="hardware"):
        discover(activation(), http, allow_missing_audience=False)


def test_enroll_request_body_and_record():
    http = FakeHttp(enrollment_response())
    record = enroll(policy(ciba=True), activation(), http, push_token="FCM_TOKEN", with_uv=True, display_name="Box")
    call = http.calls[0]
    assert (call["method"], call["url"], call["auth"]) == ("POST", ORG + "/idp/authenticators", "OTDT TEST_ACTIVATION_TOKEN")
    body = call["body"]
    assert body["key"] == "okta_verify" and body["authenticatorId"] == "aut_example"
    device = body["device"]
    assert device["platform"] == "ANDROID" and device["clientInstanceVersion"] == "9.10.0"
    assert device["displayName"] == "Box"
    assert device["deviceAttestation"] == {}
    assert device["clientInstanceKey"] == record.client_instance_key.public_jwk()
    assert "model" not in device
    method = body["methods"][0]
    assert method["pushToken"] == "FCM_TOKEN"
    assert method["capabilities"] == {"transactionTypes": ["LOGIN"]}
    assert method["keys"] == {
        "proofOfPossession": record.pop_key.public_jwk(),
        "userVerification": record.uv_key.public_jwk(),
    }
    assert record.enrollment_id == "enrollment-id"
    assert record.method_enrollment_id == "push-method-id"
    assert record.pending_challenge_uri == ORG + "/api/v1/factors/device-id/lifecycle/pending"


def test_fips_policy_declares_compliance_without_real_fips_crypto():
    http = FakeHttp(enrollment_response())
    record = enroll(policy(fips=True), activation(), http, push_token=None, with_uv=True, display_name="Box")
    assert http.calls[0]["body"]["methods"][0]["isFipsCompliant"] is True
    assert record.fips_required is True
    # Non-FIPS tenants keep the body unchanged (no declaration at enroll).
    http = FakeHttp(enrollment_response())
    enroll(policy(), activation(), http, push_token=None, with_uv=False, display_name="Box")
    assert "isFipsCompliant" not in http.calls[0]["body"]["methods"][0]


def test_enroll_without_push_or_ciba_omits_them():
    http = FakeHttp(enrollment_response())
    record = enroll(policy(), activation(), http, push_token=None, with_uv=False, display_name="Box")
    method = http.calls[0]["body"]["methods"][0]
    assert "pushToken" not in method and "capabilities" not in method
    assert record.uv_key is None


@pytest.mark.parametrize("change", [
    {"status": "INACTIVE"},
    {"authenticatorId": "other"},
    {"methods": []},
    {"methods": [{"type": "push", "id": "m", "status": "INACTIVE"}]},
    {"methods": [{"type": "push", "id": "m", "links": {"pending": {"href": "https://evil.example/p"}}}]},
])
def test_enroll_rejects_bad_responses(change):
    with pytest.raises(PoCError):
        enroll(policy(), activation(), FakeHttp({**enrollment_response(), **change}),
               push_token=None, with_uv=False, display_name="Box")


def test_auth_assertion_claims():
    record = enrollment()
    scheme, token = auth_assertion(record, record.method_enrollment_id).split(" ")
    assert scheme == "SSWS"
    assert jwt.get_unverified_header(token) == {"alg": "RS256", "kid": record.pop_key.kid, "typ": "okta-enrollmentupdate+jwt"}
    claims = _claims(token, record.pop_key)
    assert claims["iss"] == record.method_enrollment_id and claims["sub"] == "user-id"
    assert claims["kid"] == record.pop_key.kid
    assert claims["exp"] - claims["iat"] == 300 and claims["iat"] - claims["nbf"] == 300


def test_update_push_token_keeps_identity():
    record = enrollment(with_uv=True)
    http = FakeHttp(enrollment_response())
    update_push_token(record, http, "NEW_TOKEN")
    call = http.calls[0]
    assert (call["method"], call["url"]) == ("PUT", ORG + "/idp/authenticators/enrollment-id")
    assert _claims(call["auth"].split(" ")[1], record.pop_key)["iss"] == "enrollment-id"
    assert call["body"]["device"]["id"] == "device-id"
    assert call["body"]["device"]["clientInstanceId"] == "client-instance-id"
    method = call["body"]["methods"][0]
    assert method["pushToken"] == "NEW_TOKEN"
    assert method["supportUserVerification"] is True and method["isFipsCompliant"] is False
    assert method["keys"]["proofOfPossession"] == record.pop_key.public_jwk()

    changed = enrollment_response()
    changed["methods"][0]["id"] = "another-method"
    with pytest.raises(PoCError, match="identity"):
        update_push_token(record, FakeHttp(changed), "NEW_TOKEN")


def test_delete_and_already_absent():
    record = enrollment()
    http = FakeHttp(None)
    assert delete(record, http) == "deleted"
    assert http.calls[0]["method"] == "DELETE"
    assert delete(record, FakeHttp(ApiError(404, "gone", "E0000007"))) == "already absent"
    assert delete(record, FakeHttp(ApiError(410, "inactive", "E0000154"))) == "already absent"
    with pytest.raises(ApiError):
        delete(record, FakeHttp(ApiError(404, "other", "E0000001")))
