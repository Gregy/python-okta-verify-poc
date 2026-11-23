from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from okta_poc.challenge import ChallengeValidator, challenge_from_envelope, poll, sign_response, submit_response
from okta_poc.errors import PoCError
from tests.helpers import ORG, VERIFY_URI, FakeHttp, Server, challenge_claims, enrollment


@pytest.fixture
def server():
    return Server()


def validate(server, claims, record=None, **sign_options):
    record = record or enrollment()
    http = FakeHttp(server.jwks(), server.jwks())
    return ChallengeValidator(record, http).validate(server.sign(claims, **sign_options)), http


def test_valid_challenge(server):
    challenge, http = validate(server, challenge_claims())
    assert challenge.transaction_id == "tx-1"
    assert challenge.verification_uri == VERIFY_URI
    assert challenge.summary()["clientLocation"] == "Test Location"
    assert not challenge.needs_uv and not challenge.number_matching
    assert http.calls[0]["url"] == ORG + "/oauth2/v1/keys"


@pytest.mark.parametrize("claim, value", [
    ("orgId", "other-org"),
    ("authenticatorEnrollmentId", "other"),
    ("methodEnrollmentId", "other"),
    ("userId", "other"),
    ("method", "totp"),
    ("aud", "other-client"),
    ("iss", "https://evil.example"),
    ("verificationUri", "https://evil.example/verify"),
    ("nonce", ""),
])
def test_binding_mismatch_is_rejected(server, claim, value):
    with pytest.raises(PoCError):
        validate(server, challenge_claims(**{claim: value}))


def test_missing_method_id_is_accepted_for_older_challenges(server):
    claims = challenge_claims()
    del claims["methodEnrollmentId"]
    assert validate(server, claims)[0].transaction_id == "tx-1"


def test_without_policy_audience_aud_must_still_exist(server):
    record = enrollment(audience=None)
    assert validate(server, challenge_claims(aud="anything"), record)[0]
    claims = challenge_claims()
    del claims["aud"]
    with pytest.raises(PoCError):
        validate(server, claims, record)


def test_wrong_signature_type_and_algorithm(server):
    with pytest.raises(PoCError):
        ChallengeValidator(enrollment(), FakeHttp(Server().jwks())).validate(server.sign(challenge_claims()))
    with pytest.raises(PoCError, match="type or algorithm"):
        validate(server, challenge_claims(), typ="JWT")
    hs256 = jwt.encode(challenge_claims(), "secret" * 8, algorithm="HS256", headers={"typ": "okta-pushbind+jwt"})
    with pytest.raises(PoCError, match="type or algorithm"):
        ChallengeValidator(enrollment(), FakeHttp()).validate(hs256)


def test_unknown_kid_refreshes_jwks_exactly_once(server):
    http = FakeHttp({"keys": []}, server.jwks())
    validator = ChallengeValidator(enrollment(), http)
    assert validator.validate(server.sign(challenge_claims())).transaction_id == "tx-1"
    assert len(http.calls) == 2
    with pytest.raises(PoCError, match="unknown server key"):
        ChallengeValidator(enrollment(), FakeHttp({"keys": []}, {"keys": []})).validate(server.sign(challenge_claims()))


def test_custom_authorization_server(server):
    claims = challenge_claims(authorizationServerId="aus_custom", iss=ORG + "/oauth2/aus_custom")
    challenge, http = validate(server, claims)
    assert challenge.issuer == ORG + "/oauth2/aus_custom"
    assert http.calls[0]["url"] == ORG + "/oauth2/aus_custom/v1/keys"
    with pytest.raises(PoCError, match="authorizationServerId"):
        validate(server, challenge_claims(authorizationServerId="../evil"))


def test_es256_challenge():
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = {**jwt.algorithms.ECAlgorithm.to_jwk(key.public_key(), as_dict=True), "kid": "ec"}
    compact = jwt.encode(challenge_claims(), key, algorithm="ES256", headers={"kid": "ec", "typ": "okta-pushbind+jwt"})
    assert ChallengeValidator(enrollment(), FakeHttp({"keys": [jwk]})).validate(compact).transaction_id == "tx-1"


def test_expired_future_and_ciba_challenges_fail(server):
    now = int(time.time())
    for claims in (
        challenge_claims(exp=now - 120),
        challenge_claims(iat=now + 600, exp=now + 900),
        challenge_claims(challengeContext={"transactionType": "CIBA"}),
    ):
        with pytest.raises(PoCError):
            validate(server, claims)


def test_envelopes():
    assert challenge_from_envelope({"challenge": "a.b.c"}) == "a.b.c"
    assert challenge_from_envelope({"okta.challenge": "a.b.c", "okta.payloadVersion": "IDXv1"}) == "a.b.c"
    for bad in ({"challenge": "a.b.c", "payloadVersion": "legacy"}, {"challenge": "nope"}, {}):
        with pytest.raises(PoCError):
            challenge_from_envelope(bad)


def test_poll_validates_each_pending_item(server):
    record = enrollment()
    http = FakeHttp([{"challenge": server.sign(challenge_claims())}, {"challenge": "x.y.z"}], server.jwks())
    challenges, errors = poll(record, http)
    assert [item.transaction_id for item in challenges] == ["tx-1"]
    assert len(errors) == 1
    assert http.calls[0]["url"] == record.pending_challenge_uri
    assert http.calls[0]["auth"].startswith("SSWS ")


def _response_claims(signed, key):
    return jwt.decode(signed, key._private().public_key(), algorithms=["RS256"], audience=ORG)


def test_sign_approve_and_deny(server):
    record = enrollment()
    challenge, _ = validate(server, challenge_claims(), record)
    signed, omitted = sign_response(record, challenge, approve=True)
    claims = _response_claims(signed, record.pop_key)
    assert jwt.get_unverified_header(signed)["typ"] == "okta-pushbind+jwt"
    assert claims["iss"] == "enrollment-id" and claims["methodEnrollmentId"] == "push-method-id"
    assert (claims["tx"], claims["nonce"], claims["keyType"]) == ("tx-1", "SYNTHETIC_NONCE", "proofOfPossession")
    assert claims["challengeResponseContext"] == {"userConsent": "APPROVED_CONSENT_PROMPT", "transactionType": "LOGIN"}
    assert claims["deviceSignals"] == {
        "id": "device-id", "clientInstanceId": "client-instance-id", "platform": "ANDROID", "clientInstanceVersion": "9.10.0",
    }
    assert omitted == ["imei"]
    denied, _ = sign_response(record, challenge, approve=False)
    assert _response_claims(denied, record.pop_key)["challengeResponseContext"]["userConsent"] == "DENIED_CONSENT_PROMPT"

    http = FakeHttp(None)
    submit_response(challenge, signed, http)
    assert http.calls[0]["url"] == VERIFY_URI
    assert http.calls[0]["body"] == {"method": "push", "challengeResponse": signed}
    assert http.calls[0]["accept"] == "application/json; okta-version=1.0.0"


def test_user_verification(server):
    record = enrollment(with_uv=True)
    challenge, _ = validate(server, challenge_claims(userVerification="REQUIRED"), record)
    with pytest.raises(PoCError, match="user verification"):
        sign_response(record, challenge, approve=True)
    with pytest.raises(PoCError, match="user verification"):
        sign_response(enrollment(), challenge, approve=True, uv_verified=True)
    signed, _ = sign_response(record, challenge, approve=True, uv_verified=True)
    claims = _response_claims(signed, record.uv_key)
    assert jwt.get_unverified_header(signed)["kid"] == record.uv_key.kid
    assert claims["keyType"] == "userVerification" and claims["amr"] == ["fpt"]
    assert claims["challengeResponseContext"]["userConsent"] == "APPROVED_USER_VERIFICATION"
    # Denying needs no UV and uses the PoP key.
    denied, _ = sign_response(record, challenge, approve=False)
    assert _response_claims(denied, record.pop_key)["keyType"] == "proofOfPossession"


def test_number_matching_and_expired_cannot_be_approved(server):
    record = enrollment()
    challenge, _ = validate(server, challenge_claims(challengeItems=["12", "34"]), record)
    assert challenge.number_matching
    with pytest.raises(PoCError, match="Number matching"):
        sign_response(record, challenge, approve=True)
    assert sign_response(record, challenge, approve=False)

    challenge, _ = validate(server, challenge_claims(exp=int(time.time()) - 30), record)  # within clock skew
    with pytest.raises(PoCError, match="expired"):
        sign_response(record, challenge, approve=False)
