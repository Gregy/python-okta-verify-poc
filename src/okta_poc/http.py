"""HTTPS calls to Okta, plus the URL checks that keep them on the enrolled org."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import requests

from . import __version__
from .errors import ApiError, PoCError


def org_origin(url: str) -> str:
    """Return `https://host` for an Okta org URL, rejecting anything fancier."""

    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.port not in (None, 443)
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise PoCError("Organization URL must be a plain https://host origin")
    return "https://" + parts.hostname.lower()


def check_org_link(url: Any, org_url: str, label: str) -> str:
    """Ensure a server-provided link points at the enrolled org host.

    Every URL we call comes either from our own org origin or from a server
    response checked here, so nothing can redirect our signed requests elsewhere.
    """

    if not isinstance(url, str):
        raise PoCError(f"{label} is missing")
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.username
        or parts.port not in (None, 443)
        or parts.fragment
        or parts.hostname != urlsplit(org_url).hostname
    ):
        raise PoCError(f"{label} is not an https URL on the enrolled organization")
    return url


def _error(response: requests.Response) -> ApiError:
    code = summary = None
    try:
        body = response.json()
        code = body.get("errorCode") or body.get("error")
        summary = body.get("errorSummary") or body.get("error_description")
    except (ValueError, AttributeError):
        pass
    message = f"Okta returned HTTP {response.status_code}"
    if code:
        message += f" ({code})"
    if summary:
        message += f": {str(summary)[:300]}"
    return ApiError(response.status_code, message, code)


class HttpClient:
    """Thin wrapper around requests: no redirects, JSON in/out, safe errors."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()

    def request(
        self,
        method: str,
        url: str,
        *,
        auth: str | None = None,
        json_body: Any = None,
        accept: str = "application/json",
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        headers = {
            "Accept": accept,
            # The Android app sends this even on GET/DELETE; harmless without a body.
            "Content-Type": "application/json",
            "User-Agent": f"okta-poc/{__version__}",
        }
        if auth:
            headers["Authorization"] = auth
        try:
            response = self.session.request(
                method, url, headers=headers, json=json_body, timeout=(5, 20), allow_redirects=False
            )
        except requests.RequestException as exc:
            raise PoCError(
                f"{method} request failed without an HTTP answer; it may still have been processed"
            ) from exc
        if response.status_code not in expected:
            raise _error(response)
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise PoCError("Okta returned malformed JSON") from exc

    def get(self, url: str, *, auth: str | None = None) -> Any:
        return self.request("GET", url, auth=auth)
