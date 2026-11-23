from __future__ import annotations


class PoCError(Exception):
    """Base class for errors whose messages are safe to show to the operator."""


class ValidationError(PoCError):
    """Input, policy, or cryptographic validation failed."""


class PolicyError(ValidationError):
    """The requested operation is outside the supported/truthful client policy."""


class StateError(PoCError):
    """Local encrypted state is absent, invalid, or unusable."""


class TransportError(PoCError):
    """A network operation failed without a definitive HTTP result."""


class ApiError(PoCError):
    """The server returned an unexpected HTTP status."""

    def __init__(
        self,
        status: int,
        message: str,
        *,
        error_code: str | None = None,
        retry_after: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.error_code = error_code
        self.retry_after = retry_after
