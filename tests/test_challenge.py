from __future__ import annotations

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from okta_poc.challenge import (
    ChallengeValidator,
    build_response,
    parse_envelope,
    parse_pending_envelopes,
)
from okta_poc.crypto import generate_rsa_key, private_key
from okta_poc.errors import PolicyError, ValidationError
from tests.helpers import (
    NOW,
    ORG,
    FakeHttp,
    challenge_claims,
    enrollment,
    server_challenge,
)


@pytest.fixture(scope="module")
def record():
    return enrollment()


@pytest.fixture(scope="module")
def server():
    return generate_rsa_key(profile="canonical")


def validate(record, server, claims=None, *, compact=None):
    claims = claims or challenge_claims()
    compact = compact or server_challenge(server, claims)
    http = FakeHttp(gets=[{"keys": [server.public_jwk]}])
    return ChallengeValidator(record, http).validate(compact, now=NOW), http


def test_valid_challenge_binding_and_context(record, server):
    challenge, http = validate(record, server)
    assert challenge.transaction_id == "transaction-id"
    assert challenge.issuer == ORG
    assert challenge.context["clientLocation"] == "Test Location"
    assert challenge.legacy_v1 is False
    assert len(http.calls) == 1
    assert http.calls[0]["url"] == ORG + "/oauth2/v1/keys"


def test_android_padded_jwk_is_accepted_for_server_key(record):
    server = generate_rsa_key(profile="android")
    challenge, _ = validate(record, server)
    assert challenge.transaction_id == "transaction-id"


def test_explicit_unbound_audience_profile_still_requires_aud_claim(server):
    record = enrollment()
    record.expected_audience = None
    challenge, _ = validate(record, server)
    assert challenge.audience_bound is False
    claims = challenge_claims()
    del claims["aud"]
    with pytest.raises(ValidationError):
        validate(record, server, claims)


def test_missing_method_id_uses_explicit_legacy_v1_profile(record, server):
    claims = challenge_claims()
    del claims["methodEnrollmentId"]
    challenge, _ = validate(record, server, claims)
    assert challenge.legacy_v1 is True


@pytest.mark.parametrize(
    "claim,value",
    [
        ("aud", "another-client"),
        ("orgId", "another-org"),
        ("authenticatorEnrollmentId", "another-enrollment"),
        ("methodEnrollmentId", "another-method"),
        ("userId", "another-user"),
        ("method", "signed_nonce"),
        ("ver", 1),
    ],
)
def test_signed_binding_mutation_is_rejected(record, server, claim, value):
    claims = challenge_claims()
    claims[claim] = value
    with pytest.raises(ValidationError):
        validate(record, server, claims)


def test_wrong_signature_is_rejected(record, server):
    other = generate_rsa_key(profile="canonical")
    compact = jwt.encode(
        challenge_claims(),
        private_key(other),
        algorithm="RS256",
        headers={"kid": server.kid, "typ": "okta-pushbind+jwt"},
    )
    with pytest.raises(ValidationError, match="signature"):
        validate(record, server, compact=compact)


def test_wrong_type_and_hs256_are_rejected_before_key_fetch(record, server):
    wrong_typ = server_challenge(server, challenge_claims(), typ="JWT")
    http = FakeHttp()
    with pytest.raises(ValidationError, match="typ"):
        ChallengeValidator(record, http).validate(wrong_typ, now=NOW)
    assert http.calls == []
    hs256 = jwt.encode(
        challenge_claims(), "x" * 32, algorithm="HS256", headers={"kid": server.kid, "typ": "okta-pushbind+jwt"}
    )
    with pytest.raises(ValidationError, match="algorithm"):
        ChallengeValidator(record, http).validate(hs256, now=NOW)
    assert http.calls == []


def test_unknown_kid_refreshes_exactly_once(record, server):
    compact = jwt.encode(
        challenge_claims(),
        private_key(server),
        algorithm="RS256",
        headers={"kid": "unknown-kid", "typ": "okta-pushbind+jwt"},
    )
    http = FakeHttp(gets=[{"keys": [server.public_jwk]}, {"keys": [server.public_jwk]}])
    with pytest.raises(ValidationError, match="unknown or ambiguous"):
        ChallengeValidator(record, http).validate(compact, now=NOW)
    assert len(http.calls) == 2


def test_custom_authorization_server_issuer_and_jwks_path(record, server):
    claims = challenge_claims()
    claims["authorizationServerId"] = "default"
    claims["iss"] = ORG + "/oauth2/default"
    challenge, http = validate(record, server, claims)
    assert challenge.issuer == ORG + "/oauth2/default"
    assert http.calls[0]["url"] == ORG + "/oauth2/default/v1/keys"


def test_es256_server_challenge(record):
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = ECAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk.update({"kid": "ec-server", "alg": "ES256", "use": "sig"})
    compact = jwt.encode(
        challenge_claims(), key, algorithm="ES256", headers={"kid": "ec-server", "typ": "okta-pushbind+jwt"}
    )
    http = FakeHttp(gets=[{"keys": [jwk]}])
    challenge = ChallengeValidator(record, http).validate(compact, now=NOW)
    assert challenge.transaction_id == "transaction-id"


def test_expired_and_future_challenges_fail(record, server):
    claims = challenge_claims()
    claims.update({"iat": NOW - 400, "exp": NOW - 61, "nbf": NOW - 500})
    with pytest.raises(ValidationError, match="time"):
        validate(record, server, claims)
    claims = challenge_claims()
    claims["nbf"] = NOW + 61
    with pytest.raises(ValidationError, match="time"):
        validate(record, server, claims)


@pytest.mark.parametrize("uri", ["http://org.example/verify", "https://attacker.example/verify", "https://org.example/verify?redirect=x"])
def test_unsafe_verification_uri_is_rejected(record, server, uri):
    claims = challenge_claims()
    claims["verificationUri"] = uri
    with pytest.raises(ValidationError):
        validate(record, server, claims)


def test_envelope_compatibility_and_unknown_version():
    assert parse_envelope({"challenge": "a.b.c"}) == "a.b.c"
    assert parse_envelope({"okta.challenge": "a.b.c", "okta.payloadVersion": "IDXv1"}) == "a.b.c"
    assert parse_pending_envelopes([{"payloadVersion": "IDXv1", "challenge": "a.b.c"}]) == ["a.b.c"]
    with pytest.raises(ValidationError, match="version"):
        parse_envelope({"payloadVersion": "future", "challenge": "a.b.c"})
    with pytest.raises(PolicyError, match="non-JWS"):
        parse_envelope({"payloadVersion": "legacy", "challenge": "a.b.c"})
    with pytest.raises(ValidationError, match="ambiguous"):
        parse_envelope({"challenge": "a.b.c", "okta.challenge": "a.b.c"})


def test_response_accept_deny_and_unknown_signal_omission(record, server):
    challenge, _ = validate(record, server)
    for approve, consent in ((True, "APPROVED_CONSENT_PROMPT"), (False, "DENIED_CONSENT_PROMPT")):
        compact, omitted = build_response(record, challenge, approve=approve, now=NOW, response_id="response-id")
        claims = jwt.decode(
            compact,
            private_key(record.pop_key).public_key(),
            algorithms=["RS256"],
            audience=challenge.issuer,
            issuer=record.enrollment_id,
            options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
        )
        assert claims["challengeResponseContext"]["userConsent"] == consent
        assert claims["deviceSignals"]["platform"] == record.device_profile.platform
        assert claims["deviceSignals"]["id"] == record.device_id
        assert omitted == []
    challenge.requested_signals.append("secureHardwarePresent")
    _, omitted = build_response(record, challenge, approve=True, now=NOW)
    assert omitted == ["secureHardwarePresent"]


def test_uv_and_number_matching_never_get_regular_approval(record, server):
    claims = challenge_claims()
    claims["userVerification"] = "REQUIRED"
    challenge, _ = validate(record, server, claims)
    with pytest.raises(PolicyError, match="user verification"):
        build_response(record, challenge, approve=True, now=NOW)
    compact, _ = build_response(record, challenge, approve=False, now=NOW)
    denied = jwt.decode(compact, options={"verify_signature": False})
    assert denied["keyType"] == "proofOfPossession"
    assert denied["challengeResponseContext"]["userConsent"] == "DENIED_CONSENT_PROMPT"

    claims = challenge_claims()
    claims["challengeItems"] = ["1", "2", "3"]
    challenge, _ = validate(record, server, claims)
    with pytest.raises(PolicyError, match="Number matching"):
        build_response(record, challenge, approve=True, now=NOW)


def test_successful_external_uv_uses_uv_key_and_claims(record, server):
    record.uv_key = generate_rsa_key(profile=record.jwk_profile)
    record.uv_enrolled = True
    claims = challenge_claims()
    claims["userVerification"] = "REQUIRED"
    challenge, _ = validate(record, server, claims)
    compact, _ = build_response(
        record,
        challenge,
        approve=True,
        now=NOW,
        response_id="uv-response",
        use_uv=True,
        uv_verified=True,
    )
    header = jwt.get_unverified_header(compact)
    claims = jwt.decode(
        compact,
        private_key(record.uv_key).public_key(),
        algorithms=["RS256"],
        audience=challenge.issuer,
        issuer=record.enrollment_id,
        options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
    )
    assert header["kid"] == record.uv_key.kid
    assert header["kid"] != record.pop_key.kid
    assert claims["keyType"] == "userVerification"
    assert claims["amr"] == ["fpt"]
    assert claims["challengeResponseContext"]["userConsent"] == "APPROVED_USER_VERIFICATION"
    assert claims["iss"] == record.enrollment_id
    assert claims["methodEnrollmentId"] == record.method_enrollment_id
    assert claims["jti"] == "uv-response"
    with pytest.raises(PolicyError, match="did not succeed"):
        build_response(
            record,
            challenge,
            approve=True,
            now=NOW,
            use_uv=True,
            uv_verified=False,
        )


def test_ciba_is_not_downgraded_to_login(record, server):
    claims = challenge_claims()
    claims["challengeContext"]["transactionType"] = "CIBA"
    claims["challengeContext"]["bindingMessage"] = "TEST-BINDING"
    with pytest.raises(PolicyError, match="CIBA"):
        validate(record, server, claims)


def test_expired_within_skew_can_be_displayed_but_not_signed(record, server):
    claims = challenge_claims()
    claims.update({"iat": NOW - 320, "exp": NOW - 20, "nbf": NOW - 400})
    challenge, _ = validate(record, server, claims)
    assert challenge.is_expired(NOW)
    with pytest.raises(ValidationError, match="expired"):
        build_response(record, challenge, approve=False, now=NOW)
