from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import jwt

from .crypto import public_key_from_jwk, response_assertion
from .errors import PolicyError, ValidationError
from .http import HttpClient, HttpResponse
from .models import EnrollmentRecord
from .urls import org_endpoint, validate_org_link

_MAX_CHALLENGE = 64 * 1024


@dataclass
class ValidatedChallenge:
    enrollment_id: str
    transaction_id: str
    verification_uri: str
    expires_at: float
    validated_at: int
    issuer: str
    nonce: str = field(repr=False)
    transaction_type: str
    user_verification: str
    user_mediation: str
    requested_signals: list[str]
    legacy_v1: bool
    number_matching: bool
    audience_bound: bool
    claims: dict[str, Any] = field(repr=False)

    @property
    def context(self) -> dict[str, Any]:
        value = self.claims.get("challengeContext", {})
        return value if isinstance(value, dict) else {}

    def is_expired(self, now: int | None = None) -> bool:
        current = int(time.time()) if now is None else now
        return current >= self.expires_at


def _required_string(claims: dict[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"Challenge claim {name} is missing or blank")
    return value


def parse_envelope(value: Any) -> str:
    if not isinstance(value, dict):
        raise ValidationError("Pending challenge envelope must be an object")
    plain = value.get("challenge")
    historical = value.get("okta.challenge")
    if plain is not None and historical is not None:
        raise ValidationError("Envelope contains ambiguous challenge keys")
    compact = plain if plain is not None else historical
    version_plain = value.get("payloadVersion")
    version_historical = value.get("okta.payloadVersion")
    if version_plain is not None and version_historical is not None:
        raise ValidationError("Envelope contains ambiguous payload-version keys")
    version = version_plain if version_plain is not None else version_historical
    if version is None:
        version = "IDXv1"
    if version == "legacy":
        raise PolicyError("Legacy non-JWS pending challenges are outside this PoC")
    if version != "IDXv1":
        raise ValidationError("Unsupported pending challenge payload version")
    if not isinstance(compact, str) or not compact or len(compact) > _MAX_CHALLENGE:
        raise ValidationError("Challenge compact JWS is missing, empty, or too large")
    if compact.count(".") != 2 or any(not segment for segment in compact.split(".")):
        raise ValidationError("Challenge is not a three-part compact JWS")
    return compact


def parse_pending_envelopes(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValidationError("Pending challenge response must be a JSON array")
    if len(value) > 100:
        raise ValidationError("Too many pending challenges in one response")
    return [parse_envelope(item) for item in value]


class ChallengeValidator:
    def __init__(self, enrollment: EnrollmentRecord, http: HttpClient, *, clock_skew: int = 60) -> None:
        if not 0 <= clock_skew <= 300:
            raise ValidationError("Clock skew must be between 0 and 300 seconds")
        self.enrollment = enrollment
        self.http = http
        self.clock_skew = clock_skew
        self._jwks_cache: dict[str, list[dict[str, Any]]] = {}

    def _expected_issuer(self, claims: dict[str, Any]) -> str:
        authorization_server_id = claims.get("authorizationServerId")
        if authorization_server_id is None:
            return self.enrollment.org_url
        if (
            not isinstance(authorization_server_id, str)
            or not authorization_server_id
            or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in authorization_server_id)
        ):
            raise ValidationError("Challenge authorizationServerId is invalid")
        return org_endpoint(
            self.enrollment.org_url,
            f"/oauth2/{quote(authorization_server_id, safe='')}",
        )

    def _jwks_uri(self, issuer: str) -> str:
        # issuer was derived exclusively from the enrolled org origin and the
        # validated authorizationServerId character set, never from a remote URL.
        if issuer == self.enrollment.org_url:
            return org_endpoint(self.enrollment.org_url, "/oauth2/v1/keys")
        return issuer + "/v1/keys"

    def _fetch_jwks(self, issuer: str) -> list[dict[str, Any]]:
        value = self.http.get_json(
            validate_org_link(
                self._jwks_uri(issuer),
                self.enrollment.org_url,
                allow_query=False,
                label="JWKS URI",
            )
        )
        if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
            raise ValidationError("JWKS response has no keys array")
        if len(value["keys"]) > 100:
            raise ValidationError("JWKS response contains too many keys")
        if not all(isinstance(item, dict) for item in value["keys"]):
            raise ValidationError("JWKS response contains a non-object key")
        self._jwks_cache[issuer] = value["keys"]
        return value["keys"]

    @staticmethod
    def _matching_keys(keys: list[dict[str, Any]], kid: str, algorithm: str) -> list[dict[str, Any]]:
        matches = []
        for item in keys:
            if item.get("kid") != kid:
                continue
            if item.get("use") not in (None, "sig"):
                continue
            if item.get("alg") not in (None, algorithm):
                continue
            key_ops = item.get("key_ops")
            if key_ops is not None and (
                not isinstance(key_ops, list) or "verify" not in key_ops
            ):
                continue
            matches.append(item)
        return matches

    def _server_key(self, issuer: str, kid: str, algorithm: str) -> Any:
        keys = self._jwks_cache.get(issuer)
        if keys is None:
            keys = self._fetch_jwks(issuer)
        matches = self._matching_keys(keys, kid, algorithm)
        if not matches:
            # Unknown or rotated kid: exactly one refresh, then fail closed.
            keys = self._fetch_jwks(issuer)
            matches = self._matching_keys(keys, kid, algorithm)
        if len(matches) != 1:
            raise ValidationError("Server signing key is unknown or ambiguous")
        return public_key_from_jwk(matches[0], algorithm)

    def validate(self, compact: str, *, now: int | None = None) -> ValidatedChallenge:
        current = int(time.time()) if now is None else now
        if len(compact) > _MAX_CHALLENGE:
            raise ValidationError("Challenge compact JWS is too large")
        try:
            header = jwt.get_unverified_header(compact)
        except jwt.exceptions.PyJWTError as exc:
            raise ValidationError("Challenge JWS header is malformed") from exc
        if header.get("typ") != "okta-pushbind+jwt":
            raise ValidationError("Challenge JWS has an unexpected typ")
        algorithm = header.get("alg")
        if algorithm not in ("RS256", "ES256"):
            raise ValidationError("Challenge JWS uses a disallowed algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ValidationError("Challenge JWS has no server kid")
        if any(name in header for name in ("crit", "jwk", "jku", "x5u", "zip")):
            raise ValidationError("Challenge JWS uses unsupported header extensions")
        try:
            untrusted = jwt.decode(
                compact,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
                algorithms=[algorithm],
            )
        except jwt.exceptions.PyJWTError as exc:
            raise ValidationError("Challenge JWS payload is malformed") from exc
        issuer = self._expected_issuer(untrusted)
        key = self._server_key(issuer, kid, algorithm)
        try:
            claims = jwt.decode(
                compact,
                key=key,
                algorithms=[algorithm],
                issuer=issuer,
                audience=self.enrollment.expected_audience,
                leeway=self.clock_skew,
                options={
                    "require": ["exp", "iat", "iss", "aud"],
                    "verify_signature": True,
                    # Time is checked explicitly below against the injected
                    # clock. PyJWT versions differ in deterministic clock APIs.
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": self.enrollment.expected_audience is not None,
                    "verify_iss": True,
                },
            )
        except jwt.exceptions.PyJWTError as exc:
            raise ValidationError(
                "Challenge signature, issuer, audience, or time validation failed"
            ) from exc

        for name in ("exp", "iat"):
            if isinstance(claims.get(name), bool) or not isinstance(claims.get(name), (int, float)):
                raise ValidationError(f"Challenge {name} is not a NumericDate")
        if "nbf" in claims and (
            isinstance(claims["nbf"], bool) or not isinstance(claims["nbf"], (int, float))
        ):
            raise ValidationError("Challenge nbf is not a NumericDate")
        if claims["exp"] <= current - self.clock_skew:
            raise ValidationError("Challenge time validation failed: expiration is outside clock skew")
        if claims["iat"] > current + self.clock_skew or claims["iat"] > claims["exp"]:
            raise ValidationError("Challenge iat is in the future or after expiration")
        if "nbf" in claims and claims["nbf"] > current + self.clock_skew:
            raise ValidationError("Challenge time validation failed: not yet valid")

        audience = claims.get("aud")
        if isinstance(audience, str):
            if not audience:
                raise ValidationError("Challenge aud is blank")
        elif isinstance(audience, list):
            if not audience or not all(isinstance(item, str) and item for item in audience):
                raise ValidationError("Challenge aud contains an invalid audience")
        else:
            raise ValidationError("Challenge aud is missing or has an invalid type")

        transaction_id = _required_string(claims, "transactionId")
        nonce = _required_string(claims, "nonce")
        verification_uri = _required_string(claims, "verificationUri")
        _required_string(claims, "jti")
        if claims.get("method") != "push":
            raise ValidationError("Challenge method is not push")
        if claims.get("orgId") != self.enrollment.org_id:
            raise ValidationError("Challenge is bound to another organization")
        if claims.get("authenticatorEnrollmentId") != self.enrollment.enrollment_id:
            raise ValidationError("Challenge is bound to another authenticator enrollment")
        method_id = claims.get("methodEnrollmentId")
        legacy_v1 = method_id is None
        if not legacy_v1 and method_id != self.enrollment.method_enrollment_id:
            raise ValidationError("Challenge is bound to another push method")
        if "userId" in claims and claims["userId"] != self.enrollment.user_id:
            raise ValidationError("Challenge is bound to another user")
        if "ver" in claims and (isinstance(claims["ver"], bool) or claims["ver"] != 0):
            raise ValidationError("Challenge ver is unsupported")

        verification_uri = validate_org_link(
            verification_uri,
            self.enrollment.org_url,
            allow_query=False,
            label="Challenge verificationUri",
        )
        context = claims.get("challengeContext", {})
        if not isinstance(context, dict):
            raise ValidationError("Challenge challengeContext is not an object")
        transaction_type = context.get("transactionType", "LOGIN")
        if transaction_type != "LOGIN":
            raise PolicyError("Only LOGIN challenges are supported; CIBA is deferred")
        mediation = claims.get("userMediation", "REQUIRED")
        if mediation not in ("NONE", "OPTIONAL", "REQUIRED"):
            raise ValidationError("Challenge userMediation is unknown")
        user_verification = claims.get("userVerification", "NONE")
        if user_verification not in ("NONE", "DISCOURAGED", "PREFERRED", "REQUIRED"):
            raise ValidationError("Challenge userVerification is unknown")
        signals = claims.get("signals", [])
        if not isinstance(signals, list) or not all(isinstance(item, str) for item in signals):
            raise ValidationError("Challenge signals must be an array of strings")
        number_matching = any(
            container.get(name) is not None
            for container in (claims, context)
            for name in ("challengeItems", "challengeTextToVerify")
        )
        return ValidatedChallenge(
            enrollment_id=self.enrollment.enrollment_id,
            transaction_id=transaction_id,
            verification_uri=verification_uri,
            expires_at=claims["exp"],
            validated_at=current,
            issuer=claims["iss"],
            nonce=nonce,
            transaction_type=transaction_type,
            user_verification=user_verification,
            user_mediation=mediation,
            requested_signals=signals,
            legacy_v1=legacy_v1,
            number_matching=number_matching,
            audience_bound=self.enrollment.expected_audience is not None,
            claims=claims,
        )


def build_response(
    enrollment: EnrollmentRecord,
    challenge: ValidatedChallenge,
    *,
    approve: bool,
    now: int,
    response_id: str | None = None,
    use_uv: bool = False,
    uv_verified: bool = False,
) -> tuple[str, list[str]]:
    if challenge.enrollment_id != enrollment.enrollment_id:
        raise ValidationError("Validated challenge belongs to another enrollment")
    if challenge.is_expired(now):
        raise ValidationError("Challenge has expired; start a new sign-in and poll again")
    if approve and challenge.number_matching:
        raise PolicyError("Number matching is not implemented; approve in the official client")
    uv_requested = challenge.user_verification in ("PREFERRED", "REQUIRED")
    if approve and uv_requested and not use_uv:
        raise PolicyError("This challenge requires external user verification (UV)")
    if approve and use_uv and not uv_requested:
        raise PolicyError("UV approval was requested for a challenge that does not request UV")
    if approve and use_uv and not uv_verified:
        raise PolicyError("External user verification did not succeed; no approval will be signed")
    if approve and use_uv and (enrollment.uv_key is None or not enrollment.uv_enrolled):
        raise PolicyError("Enroll with --with-uv before attempting UV approval")
    signals, omitted = enrollment.device_profile.response_signals(
        challenge.requested_signals,
        device_id=enrollment.device_id,
        client_instance_id=enrollment.client_instance_id,
    )
    if approve and use_uv:
        consent = "APPROVED_USER_VERIFICATION"
        key_type = "userVerification"
    else:
        consent = "APPROVED_CONSENT_PROMPT" if approve else "DENIED_CONSENT_PROMPT"
        key_type = "proofOfPossession"
    compact = response_assertion(
        enrollment,
        challenge_issuer=challenge.issuer,
        transaction_id=challenge.transaction_id,
        nonce=challenge.nonce,
        transaction_type=challenge.transaction_type,
        consent=consent,
        device_signals=signals,
        now=now,
        response_id=response_id,
        key_type=key_type,
    )
    return compact, omitted


def submit_response(
    http: HttpClient,
    enrollment: EnrollmentRecord,
    challenge: ValidatedChallenge,
    compact_response: str,
) -> HttpResponse:
    uri = validate_org_link(
        challenge.verification_uri,
        enrollment.org_url,
        allow_query=False,
        label="Challenge verificationUri",
    )
    return http.post_json(
        uri,
        {"method": "push", "challengeResponse": compact_response},
        headers={"Accept": "application/json; okta-version=1.0.0"},
        expected=(200, 204),
    )
