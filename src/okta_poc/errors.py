"""Errors whose messages are safe to show to the operator."""

from __future__ import annotations


class PoCError(Exception):
    """Something failed; the message never contains secrets."""


class ApiError(PoCError):
    """Okta answered with an unexpected HTTP status."""

    def __init__(self, status: int, message: str, error_code: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.error_code = error_code
