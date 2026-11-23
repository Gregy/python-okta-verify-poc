"""Push challenges: fetch, validate the server's signed JWT, sign our answer.

A challenge is a JWT signed by the org (typ `okta-pushbind+jwt`). We only act
on one after checking its signature against the org's JWKS and checking that
it is bound to our org, enrollment, push method and user.
"""

from __future__ import annotations

import string
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import jwt

from .enrollment import DEVICE_PROFILE, auth_assertion
from .errors import PoCError
from .http import HttpClient, check_org_link
from .state import Enrollment

CLOCK_SKEW = 60
UV_LEVELS = ("PREFERRED", "REQUIRED")
_SERVER_ID_CHARS = set(string.ascii_letters + string.digits + "_-")


@dataclass
class Challenge:
    transaction_id: str
    nonce: str = field(repr=False)
    verification_uri: str
    issuer: str
    expires_at: float
    user_verification: str
    user_mediation: str
    requested_signals: list[str]
    number_matching: bool
    claims: dict[str, Any] = field(repr=False)

    @property
    def context(self) -> dict[str, Any]:
        return self.claims.get("challengeContext") or {}

    @property
    def needs_uv(self) -> bool:
        return self.user_verification in UV_LEVELS

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def summary(self) -> dict[str, Any]:
        """What a human (or decision program) needs to decide. No secrets."""

        return {
            "transactionId": self.transaction_id,
            "expiresAt": datetime.fromtimestamp(self.expires_at, UTC).isoformat(),
            "appInstanceName": self.claims.get("appInstanceName"),
            "clientOS": self.context.get("clientOS"),
            "clientLocation": self.context.get("clientLocation"),
            "transactionTime": self.context.get("transactionTime"),
            "userVerification": self.user_verification,
            "userMediation": self.user_mediation,
            "numberMatching": self.number_matching,
        }


def challenge_from_envelope(envelope: dict[str, Any]) -> str:
    """Extract the JWT from a pending-API item or an FCM data message."""

    version = envelope.get("payloadVersion") or envelope.get("okta.payloadVersion") or "IDXv1"
    if version != "IDXv1":
        raise PoCError(f"Unsupported challenge payload version {version!r}")
    compact = envelope.get("challenge") or envelope.get("okta.challenge")
    if not isinstance(compact, str) or compact.count(".") != 2:
        raise PoCError("Challenge is not a compact JWS")
    return compact


class ChallengeValidator:
    def __init__(self, enrollment: Enrollment, http: HttpClient) -> None:
        self.enrollment = enrollment
        self.http = http
        self._jwks: dict[str, list[dict[str, Any]]] = {}

    def _issuer(self, claims: dict[str, Any]) -> str:
        # The issuer is derived from *our* org URL, never taken from the token.
        server_id = claims.get("authorizationServerId")
        if server_id is None:
            return self.enrollment.org_url
        if not isinstance(server_id, str) or not server_id or set(server_id) - _SERVER_ID_CHARS:
            raise PoCError("Challenge authorizationServerId is invalid")
        return f"{self.enrollment.org_url}/oauth2/{server_id}"

    def _signing_key(self, issuer: str, kid: Any, algorithm: str) -> jwt.PyJWK:
        jwks_uri = issuer + ("/oauth2/v1/keys" if issuer == self.enrollment.org_url else "/v1/keys")
        for refresh in (False, True):  # unknown kid: refetch once (key rotation)
            if refresh or issuer not in self._jwks:
                self._jwks[issuer] = self.http.get(jwks_uri).get("keys", [])
            matches = [key for key in self._jwks[issuer] if key.get("kid") == kid]
            if len(matches) == 1:
                try:
                    return jwt.PyJWK(matches[0], algorithm)
                except jwt.PyJWTError as exc:
                    raise PoCError("Server signing key is malformed") from exc
        raise PoCError("Challenge is signed by an unknown server key")

    def validate(self, compact: str) -> Challenge:
        enrollment = self.enrollment
        try:
            header = jwt.get_unverified_header(compact)
            unverified = jwt.decode(compact, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise PoCError("Challenge JWS is malformed") from exc
        algorithm = header.get("alg")
        if header.get("typ") != "okta-pushbind+jwt" or algorithm not in ("RS256", "ES256"):
            raise PoCError("Challenge JWS has an unexpected type or algorithm")
        issuer = self._issuer(unverified)
        key = self._signing_key(issuer, header.get("kid"), algorithm)
        try:
            claims = jwt.decode(
                compact,
                key.key,
                algorithms=[algorithm],
                issuer=issuer,
                audience=enrollment.expected_audience,
                leeway=CLOCK_SKEW,
                options={
                    "require": ["exp", "iat", "iss", "aud"],
                    # Without a policy audience we can only require that aud exists.
                    "verify_aud": enrollment.expected_audience is not None,
                },
            )
        except jwt.PyJWTError as exc:
            raise PoCError(f"Challenge rejected: {exc}") from exc

        bindings = {
            "method": "push",
            "orgId": enrollment.org_id,
            "authenticatorEnrollmentId": enrollment.enrollment_id,
        }
        # Older challenges omit these; when present they must match.
        for name, expected in (("methodEnrollmentId", enrollment.method_enrollment_id), ("userId", enrollment.user_id)):
            if name in claims:
                bindings[name] = expected
        for name, expected in bindings.items():
            if claims.get(name) != expected:
                raise PoCError(f"Challenge {name} does not match this enrollment")
        for name in ("transactionId", "nonce", "verificationUri"):
            if not isinstance(claims.get(name), str) or not claims[name]:
                raise PoCError(f"Challenge claim {name} is missing")

        context = claims.get("challengeContext") or {}
        if context.get("transactionType", "LOGIN") != "LOGIN":
            raise PoCError("Only LOGIN challenges are supported (not CIBA)")
        return Challenge(
            transaction_id=claims["transactionId"],
            nonce=claims["nonce"],
            verification_uri=check_org_link(claims["verificationUri"], enrollment.org_url, "verificationUri"),
            issuer=claims["iss"],
            expires_at=claims["exp"],
            user_verification=claims.get("userVerification", "NONE"),
            user_mediation=claims.get("userMediation", "REQUIRED"),
            requested_signals=list(claims.get("signals", [])),
            number_matching=any(
                source.get(name) is not None
                for source in (claims, context)
                for name in ("challengeItems", "challengeTextToVerify")
            ),
            claims=claims,
        )


def poll(enrollment: Enrollment, http: HttpClient) -> tuple[list[Challenge], list[str]]:
    """Fetch pending challenges. Returns (valid challenges, rejection reasons)."""

    items = http.get(
        enrollment.pending_challenge_uri,
        auth=auth_assertion(enrollment, enrollment.method_enrollment_id),
    )
    validator = ChallengeValidator(enrollment, http)
    challenges: dict[str, Challenge] = {}
    errors = []
    for index, item in enumerate(items or []):
        try:
            challenge = validator.validate(challenge_from_envelope(item))
            challenges.setdefault(challenge.transaction_id, challenge)
        except PoCError as exc:
            errors.append(f"item {index + 1}: {exc}")
    return sorted(challenges.values(), key=lambda item: item.expires_at), errors


def _device_signals(enrollment: Enrollment, requested: list[str]) -> tuple[dict[str, Any], list[str]]:
    available = {"displayName": enrollment.display_name, **DEVICE_PROFILE}
    signals = {"id": enrollment.device_id, "clientInstanceId": enrollment.client_instance_id}
    omitted = []
    for name in requested:
        if name in available:
            signals[name] = available[name]
        elif name not in signals:
            omitted.append(name)
    return signals, sorted(set(omitted))


def sign_response(
    enrollment: Enrollment,
    challenge: Challenge,
    *,
    approve: bool,
    uv_verified: bool = False,
) -> tuple[str, list[str]]:
    """Build our signed approve/deny JWT. Returns (JWT, device signals we could not provide).

    Approving a challenge that asks for user verification requires the UV key
    and `uv_verified=True` (the caller ran the external UV provider).
    """

    if challenge.is_expired():
        raise PoCError("Challenge has expired; start a new sign-in")
    use_uv = approve and challenge.needs_uv
    if approve and challenge.number_matching:
        raise PoCError("Number matching is not implemented; approve in the official app")
    if use_uv and not (enrollment.uv_key and uv_verified):
        raise PoCError("This challenge requires user verification; enroll with --with-uv and pass --uv-executable")

    if use_uv:
        key, key_type, consent = enrollment.uv_key, "userVerification", "APPROVED_USER_VERIFICATION"
    else:
        key, key_type = enrollment.pop_key, "proofOfPossession"
        consent = "APPROVED_CONSENT_PROMPT" if approve else "DENIED_CONSENT_PROMPT"
    signals, omitted = _device_signals(enrollment, challenge.requested_signals)
    now = int(time.time())
    claims: dict[str, Any] = {
        # The live tenant resolves the enrollment by `iss` = authenticator
        # enrollment ID (Android 9.10.0 used the method ID; that is rejected).
        "iss": enrollment.enrollment_id,
        "aud": challenge.issuer,
        "sub": enrollment.user_id,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 300,
        "nbf": now - 300,
        "methodEnrollmentId": enrollment.method_enrollment_id,
        "tx": challenge.transaction_id,
        "nonce": challenge.nonce,
        "keyType": key_type,
        "challengeResponseContext": {
            "userConsent": consent,
            "transactionType": "LOGIN",
        },
        "deviceSignals": signals,
    }
    if use_uv:
        claims["amr"] = ["fpt"]
    return key.sign(claims, typ="okta-pushbind+jwt"), omitted


def submit_response(challenge: Challenge, signed: str, http: HttpClient) -> None:
    http.request(
        "POST",
        challenge.verification_uri,
        json_body={"method": "push", "challengeResponse": signed},
        accept="application/json; okta-version=1.0.0",
        expected=(200, 204),
    )
