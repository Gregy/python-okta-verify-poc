from __future__ import annotations

from urllib.parse import SplitResult, urlsplit, urlunsplit

from .errors import ValidationError


def _port(parts: SplitResult) -> int | None:
    try:
        return parts.port
    except ValueError as exc:
        raise ValidationError("URL contains an invalid port") from exc


def canonical_org_url(value: str) -> str:
    """Validate and canonicalize an Okta organization origin.

    The PoC deliberately supports organization origins only, not arbitrary path
    prefixes, non-HTTPS URLs, userinfo, query strings, or non-default ports.
    """

    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValidationError("Organization URL is missing or too long")
    parts = urlsplit(value)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ValidationError("Organization URL must be an absolute HTTPS URL")
    if parts.username is not None or parts.password is not None:
        raise ValidationError("Organization URL must not contain userinfo")
    if parts.query or parts.fragment:
        raise ValidationError("Organization URL must not contain a query or fragment")
    if parts.path not in ("", "/"):
        raise ValidationError("Organization URL must be an origin without a path")
    port = _port(parts)
    if port not in (None, 443):
        raise ValidationError("Organization URL uses a non-default HTTPS port")
    try:
        host = parts.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError("Organization URL contains an invalid host") from exc
    return urlunsplit(("https", host, "", "", ""))


def org_endpoint(org_url: str, path: str) -> str:
    base = canonical_org_url(org_url)
    if not path.startswith("/") or path.startswith("//"):
        raise ValidationError("Internal endpoint path is invalid")
    return base + path


def validate_org_link(
    value: str,
    org_url: str,
    *,
    allow_query: bool,
    label: str,
) -> str:
    """Validate a server-provided URL without following redirects or aliases."""

    base = canonical_org_url(org_url)
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise ValidationError(f"{label} is missing or too long")
    parts = urlsplit(value)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ValidationError(f"{label} must be an absolute HTTPS URL")
    if parts.username is not None or parts.password is not None:
        raise ValidationError(f"{label} must not contain userinfo")
    if parts.fragment:
        raise ValidationError(f"{label} must not contain a fragment")
    if parts.query and not allow_query:
        raise ValidationError(f"{label} must not contain a query")
    if _port(parts) not in (None, 443):
        raise ValidationError(f"{label} uses a non-default HTTPS port")
    base_parts = urlsplit(base)
    try:
        host = parts.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError(f"{label} contains an invalid host") from exc
    if host != base_parts.hostname:
        raise ValidationError(f"{label} is not on the enrolled organization host")
    # Preserve the server-provided path/query verbatim after validation.
    return value
