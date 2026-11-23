from __future__ import annotations

import base64

import jwt

from okta_poc.crypto import (
    generate_rsa_key,
    pending_assertion,
    private_key,
    response_assertion,
)
from tests.helpers import NOW, enrollment


def decode_segment(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_android_and_canonical_jwk_profiles_are_explicit():
    android = generate_rsa_key(kid="stable-kid", profile="android")
    canonical = generate_rsa_key(kid="stable-kid", profile="canonical")
    android_n = decode_segment(android.public_jwk["n"])
    canonical_n = decode_segment(canonical.public_jwk["n"])
    assert len(android_n) == 257 and android_n[0] == 0
    assert len(canonical_n) == 256 and canonical_n[0] != 0
    assert android.public_jwk["n"].endswith("=")
    assert "=" not in canonical.public_jwk["n"]
    assert android.public_jwk["e"] == canonical.public_jwk["e"] == "AQAB"
    assert android.public_jwk["kid"] == canonical.public_jwk["kid"] == "stable-kid"
    assert android.public_jwk["okta:kpr"] == "SOFTWARE"
    assert not {"d", "p", "q", "dp", "dq", "qi"}.intersection(android.public_jwk)


def test_pending_assertion_exact_profile():
    record = enrollment()
    compact = pending_assertion(record, now=NOW, assertion_id="assertion-id")
    header = jwt.get_unverified_header(compact)
    claims = jwt.decode(
        compact,
        private_key(record.pop_key).public_key(),
        algorithms=["RS256"],
        audience=record.org_url,
        issuer=record.method_enrollment_id,
        options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
    )
    assert header == {"alg": "RS256", "kid": record.pop_key.kid, "typ": "okta-enrollmentupdate+jwt"}
    assert claims == {
        "iss": record.method_enrollment_id,
        "sub": record.user_id,
        "aud": record.org_url,
        "kid": record.pop_key.kid,
        "jti": "assertion-id",
        "iat": NOW,
        "exp": NOW + 300,
        "nbf": NOW - 300,
    }


def test_response_uses_authenticator_enrollment_id_and_fresh_jti():
    record = enrollment()
    kwargs = {
        "challenge_issuer": record.org_url,
        "transaction_id": "tx",
        "nonce": "nonce",
        "transaction_type": "LOGIN",
        "consent": "APPROVED_CONSENT_PROMPT",
        "device_signals": {"id": record.device_id},
        "now": NOW,
    }
    first = response_assertion(record, response_id="response-one", **kwargs)
    second = response_assertion(record, response_id="response-two", **kwargs)
    claims = jwt.decode(
        first,
        private_key(record.pop_key).public_key(),
        algorithms=["RS256"],
        audience=record.org_url,
        issuer=record.enrollment_id,
        options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
    )
    assert jwt.get_unverified_header(first)["typ"] == "okta-pushbind+jwt"
    assert claims["iss"] == record.enrollment_id
    assert claims["methodEnrollmentId"] == record.method_enrollment_id
    assert claims["sub"] == record.user_id
    assert claims["tx"] == "tx" and claims["nonce"] == "nonce"
    assert claims["keyType"] == "proofOfPossession"
    assert claims["challengeResponseContext"] == {
        "userConsent": "APPROVED_CONSENT_PROMPT",
        "transactionType": "LOGIN",
    }
    assert claims["jti"] == "response-one"
    assert claims["jti"] != jwt.decode(second, options={"verify_signature": False})["jti"]
    assert (claims["iat"], claims["exp"], claims["nbf"]) == (NOW, NOW + 300, NOW - 300)
