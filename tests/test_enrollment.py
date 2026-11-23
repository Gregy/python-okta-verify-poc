from __future__ import annotations

import json
from dataclasses import replace

import jwt
import pytest

from okta_poc.crypto import generate_rsa_key, private_key
from okta_poc.enrollment import (
    delete_enrollment,
    discover,
    enrollment_body,
    new_preparation,
    parse_enrollment_response,
    update_enrollment,
)
from okta_poc.errors import ApiError, PolicyError, ValidationError
from okta_poc.http import HttpResponse
from okta_poc.models import EnrollmentRecord
from tests.helpers import (
    NOW,
    ORG,
    FakeHttp,
    activation,
    discovery,
    enrollment,
    enrollment_response,
    organization_response,
    policy_response,
    preparation,
)


def test_discovery_exact_request_and_response_persistence():
    http = FakeHttp(gets=[organization_response(), policy_response(ciba=True)])
    result = discover(activation(), http)
    assert result.org_id == "00o_org"
    assert result.expected_audience == "0oa_client"
    assert result.policy_supports_ciba is True
    assert http.calls[0] == {
        "method": "GET",
        "url": ORG + "/.well-known/okta-organization",
        "headers": {},
        "expected": (200,),
    }
    assert http.calls[1]["url"] == ORG + "/api/v1/authenticators?key=okta_verify&expand=methods"
    assert http.calls[1]["headers"] == {"Authorization": "OTDT TEST_ACTIVATION_TOKEN"}

    prep = preparation(ciba=True)
    body = enrollment_body(prep, "REAL_FCM_TOKEN")
    assert body["key"] == "okta_verify"
    assert body["authenticatorId"] == "aut_example"
    assert isinstance(body["methods"], list)
    method = body["methods"][0]
    assert method["type"] == "push"
    assert method["pushToken"] == "REAL_FCM_TOKEN"
    assert method["capabilities"] == {"transactionTypes": ["LOGIN"]}
    assert method["keys"]["proofOfPossession"] == prep.pop_key.public_jwk
    assert "supportUserVerification" not in method
    assert body["device"]["clientInstanceKey"] == prep.client_instance_key.public_jwk
    assert body["device"]["deviceAttestation"] == {}
    assert "fullDiskEncryption" not in body["device"]
    assert "rootPrivileges" not in body["device"]

    record = parse_enrollment_response(enrollment_response(), prep)
    assert record.enrollment_id == "enrollment-id"
    assert record.method_enrollment_id == "push-method-id"
    assert record.pending_challenge_uri == ORG + "/api/v1/factors/device-id/lifecycle/pending"
    assert record.expected_audience == "0oa_client"


def test_no_ciba_omits_capabilities_and_missing_token_is_not_dummy():
    body = enrollment_body(preparation(ciba=False), None)
    method = body["methods"][0]
    assert "capabilities" not in method
    assert "pushToken" not in method


def test_missing_policy_audience_requires_explicit_opt_in():
    policy = policy_response()
    del policy[0]["settings"]["oauthClientId"]
    with pytest.raises(PolicyError, match="allow-missing-policy-audience"):
        discover(activation(), FakeHttp(gets=[organization_response(), policy]))
    result = discover(
        activation(),
        FakeHttp(gets=[organization_response(), policy]),
        allow_missing_audience=True,
    )
    assert result.expected_audience is None


def test_policy_requires_exactly_one_active_policy():
    http = FakeHttp(gets=[organization_response(), []])
    with pytest.raises(PolicyError, match="exactly one"):
        discover(activation(), http)


def test_pre_enrollment_inactive_push_requires_activation_link():
    policy = policy_response()
    push = policy[0]["_embedded"]["methods"][0]
    push["status"] = "INACTIVE"
    with pytest.raises(ValidationError, match="activation"):
        discover(
            activation(),
            FakeHttp(gets=[organization_response(), policy]),
        )
    push["_links"] = {"activate": {"href": ORG + "/api/v1/authenticators/aut_example/methods/push/lifecycle/activate"}}
    result = discover(
        activation(),
        FakeHttp(gets=[organization_response(), policy]),
    )
    assert result.authenticator_id == "aut_example"


def test_hardware_policy_is_not_bypassed():
    http = FakeHttp(gets=[organization_response(), policy_response(protection="HARDWARE")])
    with pytest.raises(PolicyError, match="hardware keys"):
        discover(activation(), http)


def test_enrollment_accepts_omitted_method_status_but_rejects_inactive():
    prep = preparation()
    response = enrollment_response()
    del response["methods"][0]["status"]
    record = parse_enrollment_response(response, prep)
    assert record.method_enrollment_id == "push-method-id"
    response["methods"][0]["status"] = "INACTIVE"
    with pytest.raises(ValidationError, match="INACTIVE"):
        parse_enrollment_response(response, prep)


def test_default_android_profile_has_no_hardware_or_attestation_claims():
    prep = new_preparation(
        discovery(),
        jwk_profile="canonical",
        display_name="Android Compatibility Test",
    )
    body = enrollment_body(prep, "REAL_FCM_TOKEN")
    device = body["device"]
    assert device["platform"] == "ANDROID"
    assert device["osVersion"] == "32"
    assert device["clientInstanceBundleId"] == "com.okta.android.auth"
    assert device["clientInstanceVersion"] == "9.10.0"
    assert device["clientInstanceDeviceSdkVersion"] == "9.10.0"
    assert "model" not in device
    assert "secureHardwarePresent" not in device
    assert "screenLockType" not in device
    assert "diskEncryptionType" not in device
    assert device["deviceAttestation"] == {}
    assert device["clientInstanceKey"]["okta:kpr"] == "SOFTWARE"


def test_initial_uv_enrollment_includes_stable_uv_key():
    policy = replace(discovery(), policy_user_verification="REQUIRED")
    prep = new_preparation(policy, jwk_profile="canonical", display_name="UV Host", with_uv=True)
    assert prep.uv_key is not None
    body = enrollment_body(prep, "REAL_FCM_TOKEN")
    keys = body["methods"][0]["keys"]
    assert keys["userVerification"] == prep.uv_key.public_jwk
    assert keys["proofOfPossession"] == prep.pop_key.public_jwk
    record = parse_enrollment_response(enrollment_response(), prep)
    assert record.uv_enrolled is True
    restored = EnrollmentRecord.from_dict(record.to_dict())
    assert restored.uv_key.kid == prep.uv_key.kid
    assert restored.uv_enrolled is True


def test_uv_enrollment_update_preserves_identity_and_exact_ssws_profile():
    record = enrollment()
    record.uv_key = generate_rsa_key(profile=record.jwk_profile)
    response_value = enrollment_response()
    del response_value["methods"][0]["status"]
    http = FakeHttp(puts=[HttpResponse(200, {}, json.dumps(response_value).encode())])
    updated = update_enrollment(record, http, push_token="REAL_FCM_TOKEN", now=NOW)
    call = http.calls[0]
    assert call["method"] == "PUT"
    assert call["url"] == ORG + "/idp/authenticators/enrollment-id"
    assert call["expected"] == (200, 201)
    assert call["body"]["device"]["id"] == record.device_id
    assert call["body"]["device"]["clientInstanceId"] == record.client_instance_id
    assert call["body"]["methods"][0]["supportUserVerification"] is True
    assert call["body"]["methods"][0]["isFipsCompliant"] is False
    keys = call["body"]["methods"][0]["keys"]
    assert keys["proofOfPossession"] == record.pop_key.public_jwk
    assert keys["userVerification"] == record.uv_key.public_jwk
    scheme, assertion = call["headers"]["Authorization"].split(" ", 1)
    assert scheme == "SSWS"
    claims = jwt.decode(
        assertion,
        private_key(record.pop_key).public_key(),
        algorithms=["RS256"],
        audience=record.org_url,
        issuer=record.enrollment_id,
        options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
    )
    assert claims["kid"] == record.pop_key.kid
    assert claims["exp"] == NOW + 300 and claims["nbf"] == NOW - 300
    assert updated.uv_enrolled is True
    assert updated.method_enrollment_id == record.method_enrollment_id


def test_delete_enrollment_exact_request_and_idempotent_not_found():
    record = enrollment()
    http = FakeHttp(deletes=[HttpResponse(204, {}, b"")])
    assert delete_enrollment(record, http, now=NOW) == "deleted"
    call = http.calls[0]
    assert call["method"] == "DELETE"
    assert call["url"] == ORG + "/idp/authenticators/enrollment-id"
    assert call["expected"] == (200, 204)
    assert call["body"] is None
    scheme, assertion = call["headers"]["Authorization"].split(" ", 1)
    assert scheme == "SSWS"
    claims = jwt.decode(
        assertion,
        private_key(record.pop_key).public_key(),
        algorithms=["RS256"],
        audience=record.org_url,
        issuer=record.enrollment_id,
        options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
    )
    assert claims["kid"] == record.pop_key.kid
    assert claims["exp"] == NOW + 300 and claims["nbf"] == NOW - 300

    absent = FakeHttp(deletes=[
        ApiError(404, "not found", error_code="E0000007")
    ])
    assert delete_enrollment(record, absent, now=NOW) == "already absent"
    rejected = FakeHttp(deletes=[ApiError(401, "unauthorized")])
    with pytest.raises(ApiError, match="unauthorized"):
        delete_enrollment(record, rejected, now=NOW)


def test_enrollment_rejects_incomplete_or_foreign_response():
    prep = preparation()
    incomplete = enrollment_response()
    del incomplete["device"]["clientInstanceId"]
    with pytest.raises(ValidationError):
        parse_enrollment_response(incomplete, prep)
    foreign = enrollment_response()
    foreign["methods"][0]["links"]["pending"]["href"] = "https://attacker.example/pending"
    with pytest.raises(ValidationError, match="organization host"):
        parse_enrollment_response(foreign, prep)
