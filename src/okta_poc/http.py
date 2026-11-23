from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import requests

from . import __version__
from .errors import ApiError, TransportError, ValidationError

_MAX_BODY = 1024 * 1024
_JWT_LIKE = re.compile(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_AUTH_LIKE = re.compile(r"\b(OTDT|SSWS|Bearer)\s+\S+", re.IGNORECASE)


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("Server returned malformed JSON") from exc


def _safe_summary(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = _JWT_LIKE.sub("[redacted-jws]", value)
    value = _AUTH_LIKE.sub(r"\1 [redacted]", value)
    value = " ".join(value.split())
    return value[:300] if value else None


def _api_error(status: int, headers: dict[str, str], body: bytes) -> ApiError:
    error_code: str | None = None
    summaries: list[str] = []
    try:
        value = json.loads(body.decode("utf-8"))
        if isinstance(value, dict):
            error_code = _safe_summary(value.get("errorCode") or value.get("error"))
            for candidate in (value.get("errorSummary"), value.get("error_description")):
                summary = _safe_summary(candidate)
                if summary:
                    summaries.append(summary)
            causes = value.get("errorCauses")
            if isinstance(causes, list):
                for cause in causes[:5]:
                    if isinstance(cause, dict):
                        summary = _safe_summary(cause.get("errorSummary"))
                        if summary:
                            summaries.append(summary)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    detail = "; ".join(dict.fromkeys(summaries))
    message = f"Okta returned HTTP {status}"
    if error_code:
        message += f" ({error_code})"
    if detail:
        message += f": {detail}"
    return ApiError(
        status,
        message,
        error_code=error_code,
        retry_after=headers.get("Retry-After"),
    )


class HttpClient:
    """Bounded, redirect-free HTTPS transport with no body/auth logging."""

    def __init__(self, session: Any | None = None, *, timeout: tuple[float, float] = (5.0, 20.0)) -> None:
        self.session = session or requests.Session()
        self.timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any | None = None,
        expected: Iterable[int] = (200,),
    ) -> HttpResponse:
        request_headers = {"User-Agent": f"okta-poc/{__version__}"}
        if headers:
            request_headers.update(headers)
        data = None
        if json_body is not None:
            data = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            response = self.session.request(
                method,
                url,
                headers=request_headers,
                data=data,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            )
            try:
                length = response.headers.get("Content-Length")
                if length and int(length) > _MAX_BODY:
                    raise ValidationError("Server response is too large")
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_content(16384):
                    size += len(chunk)
                    if size > _MAX_BODY:
                        raise ValidationError("Server response is too large")
                    chunks.append(chunk)
                body = b"".join(chunks)
                result = HttpResponse(response.status_code, dict(response.headers), body)
            finally:
                response.close()
        except ValidationError:
            raise
        except requests.RequestException as exc:
            raise TransportError(
                f"{method} request failed without a definitive HTTP result; do not assume it was not processed"
            ) from exc
        expected_statuses = tuple(expected)
        if result.status not in expected_statuses:
            raise _api_error(result.status, result.headers, result.body)
        return result

    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        expected: Iterable[int] = (200,),
    ) -> Any:
        response_headers = {"Accept": "application/json"}
        if headers:
            response_headers.update(headers)
        return self.request("GET", url, headers=response_headers, expected=expected).json()

    def post_json(
        self,
        url: str,
        body: Any,
        *,
        headers: dict[str, str] | None = None,
        expected: Iterable[int] = (200,),
    ) -> HttpResponse:
        response_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if headers:
            response_headers.update(headers)
        return self.request(
            "POST", url, headers=response_headers, json_body=body, expected=expected
        )
