from __future__ import annotations

import base64
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from .errors import ValidationError
from .models import EnrollmentRecord, KeyRecord


def b64url(value: bytes, *, padded: bool = False) -> str:
    encoded = base64.urlsafe_b64encode(value).decode("ascii")
    return encoded if padded else encoded.rstrip("=")


def _unsigned_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _java_big_integer_bytes(value: int) -> bytes:
    # java.math.BigInteger.toByteArray() is signed, big-endian two's complement.
    return value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")


def generate_rsa_key(kid: str | None = None, *, profile: str = "android") -> KeyRecord:
    if profile not in ("android", "canonical"):
        raise ValidationError("JWK profile must be android or canonical")
    key_id = kid or str(uuid.uuid4())
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    if profile == "android":
        modulus = _java_big_integer_bytes(numbers.n)
        exponent = _java_big_integer_bytes(numbers.e)
    else:
        modulus = _unsigned_bytes(numbers.n)
        exponent = _unsigned_bytes(numbers.e)
    public_jwk = {
        "kty": "RSA",
        "n": b64url(modulus, padded=profile == "android"),
        "e": b64url(exponent, padded=profile == "android"),
        "kid": key_id,
        "alg": "RS256",
        "use": "sig",
        "okta:kpr": "SOFTWARE",
    }
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # The enclosing state file encrypts this with the operator's passphrase.
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return KeyRecord(
        kid=key_id,
        algorithm="RS256",
        private_pem=private_pem,
        public_jwk=public_jwk,
    )


def private_key(record: KeyRecord) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(record.private_pem.encode("ascii"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048:
        raise ValidationError("Local PoP key is not a 2048-bit RSA private key")
    return key


def public_key_from_jwk(jwk_value: dict[str, Any], algorithm: str) -> Any:
    try:
        if algorithm == "RS256":
            if jwk_value.get("kty") != "RSA":
                raise ValidationError("Server JWK does not match RS256")
            return RSAAlgorithm.from_jwk(jwk_value)
        if algorithm == "ES256":
            if jwk_value.get("kty") != "EC" or jwk_value.get("crv") != "P-256":
                raise ValidationError("Server JWK does not match ES256")
            return ECAlgorithm.from_jwk(jwk_value)
    except (ValueError, TypeError, jwt.exceptions.InvalidKeyError) as exc:
        raise ValidationError("Server JWK is malformed") from exc
    raise ValidationError("Unsupported server signing algorithm")


def sign_jws(record: KeyRecord, claims: dict[str, Any], *, typ: str) -> str:
    return jwt.encode(
        claims,
        private_key(record),
        algorithm="RS256",
        headers={"kid": record.kid, "typ": typ},
    )


def pending_assertion(
    enrollment: EnrollmentRecord,
    *,
    now: int,
    assertion_id: str | None = None,
) -> str:
    claims = {
        "iss": enrollment.method_enrollment_id,
        "sub": enrollment.user_id,
        "aud": enrollment.org_url,
        "kid": enrollment.pop_key.kid,
        "jti": assertion_id or str(uuid.uuid4()),
        "iat": now,
        "exp": now + 300,
        "nbf": now - 300,
    }
    return sign_jws(enrollment.pop_key, claims, typ="okta-enrollmentupdate+jwt")


def update_assertion(
    enrollment: EnrollmentRecord,
    *,
    now: int,
    assertion_id: str | None = None,
) -> str:
    claims = {
        "iss": enrollment.enrollment_id,
        "sub": enrollment.user_id,
        "aud": enrollment.org_url,
        "kid": enrollment.pop_key.kid,
        "jti": assertion_id or str(uuid.uuid4()),
        "iat": now,
        "exp": now + 300,
        "nbf": now - 300,
    }
    return sign_jws(enrollment.pop_key, claims, typ="okta-enrollmentupdate+jwt")


def response_assertion(
    enrollment: EnrollmentRecord,
    *,
    challenge_issuer: str,
    transaction_id: str,
    nonce: str,
    transaction_type: str,
    consent: str,
    device_signals: dict[str, Any],
    now: int,
    response_id: str | None = None,
    key_type: str = "proofOfPossession",
    amr: list[str] | None = None,
) -> str:
    if key_type == "userVerification":
        if enrollment.uv_key is None or not enrollment.uv_enrolled:
            raise ValidationError("No enrolled user-verification key is available")
        if consent != "APPROVED_USER_VERIFICATION":
            raise ValidationError("UV key cannot be used for a non-UV consent response")
        signing_record = enrollment.uv_key
        amr_values = amr or ["fpt"]
    elif key_type == "proofOfPossession":
        if consent == "APPROVED_USER_VERIFICATION":
            raise ValidationError("PoP key cannot claim user verification")
        signing_record = enrollment.pop_key
        amr_values = None
    else:
        raise ValidationError("Unsupported response key type")
    claims = {
        # Live tenant verify resolves the parent AuthenticatorEnrollment by iss.
        # Keep methodEnrollmentId separate below. (The static Android 9.10.0
        # builder instead used the method ID, so this is a live compatibility pin.)
        "iss": enrollment.enrollment_id,
        "aud": challenge_issuer,
        "sub": enrollment.user_id,
        "jti": response_id or str(uuid.uuid4()),
        "iat": now,
        "exp": now + 300,
        "nbf": now - 300,
        "methodEnrollmentId": enrollment.method_enrollment_id,
        "tx": transaction_id,
        "nonce": nonce,
        "keyType": key_type,
        "challengeResponseContext": {
            "userConsent": consent,
            "transactionType": transaction_type,
        },
        "deviceSignals": device_signals,
    }
    if amr_values is not None:
        claims["amr"] = amr_values
    return sign_jws(signing_record, claims, typ="okta-pushbind+jwt")
