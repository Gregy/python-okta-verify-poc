from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .errors import PolicyError, ValidationError
from .urls import canonical_org_url

_MAX_QR_IMAGE_BYTES = 16 * 1024 * 1024


def decode_activation_qr(path: Path) -> str:
    """Decode one activation URI from an image without logging its contents."""

    try:
        resolved = path.expanduser().resolve(strict=True)
        if not resolved.is_file():
            raise ValidationError("QR image path is not a regular file")
        if not 0 < resolved.stat().st_size <= _MAX_QR_IMAGE_BYTES:
            raise ValidationError("QR image is empty or exceeds the 16 MiB limit")
    except ValidationError:
        raise
    except OSError as exc:
        raise ValidationError("QR image does not exist or cannot be accessed") from exc

    try:
        import cv2
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise ValidationError(
            "QR image support requires opencv-python-headless; reinstall the project dependencies"
        ) from exc

    try:
        image = cv2.imread(str(resolved))
        if image is None or image.size == 0:
            raise ValidationError("QR image could not be read")
        # Avoid passing unexpectedly large decoded images to the detector.
        if image.shape[0] * image.shape[1] > 25_000_000:
            raise ValidationError("QR image exceeds the 25-megapixel limit")
        detector = cv2.QRCodeDetector()
        value, _, _ = detector.detectAndDecode(image)
        if not value:
            # Dense QR symbols rendered with small modules are sometimes more
            # reliable after resampling. Try bounded alternatives rather than
            # rejecting valid enrollment images based on one rasterization.
            for scale, interpolation in (
                (0.5, cv2.INTER_AREA),
                (2.0, cv2.INTER_NEAREST),
                (0.25, cv2.INTER_AREA),
            ):
                resized = cv2.resize(
                    image, None, fx=scale, fy=scale, interpolation=interpolation
                )
                value, _, _ = detector.detectAndDecode(resized)
                if value:
                    break
    except cv2.error as exc:
        raise ValidationError("QR image could not be decoded") from exc
    if not value:
        raise ValidationError("No QR code was found in the image")
    return value


@dataclass(frozen=True)
class Activation:
    token: str = field(repr=False)
    authenticator_id: str | None
    org_url: str
    account: str
    issuer: str | None
    hardware_keystore_required: bool = False


def _boolean(values: dict[str, list[str]], name: str) -> bool:
    if name not in values:
        return False
    value = values[name][0].lower()
    if value not in ("true", "false"):
        raise ValidationError(f"QR field {name} must be true or false")
    return value == "true"


def parse_activation_uri(uri: str) -> Activation:
    """Parse a built-in Okta Verify activation URI without logging its token."""

    if not isinstance(uri, str) or not uri or len(uri) > 16384:
        raise ValidationError("Activation URI is missing or too long")
    if any(ord(char) < 0x20 for char in uri):
        raise ValidationError("Activation URI contains control characters")
    parts = urlsplit(uri.strip())
    if parts.scheme.lower() != "oktaverify":
        raise ValidationError("Only oktaverify:// enrollment URIs are supported")
    if not parts.netloc:
        raise ValidationError("Activation URI has no account authority")
    if parts.fragment:
        raise ValidationError("Activation URI must not contain a fragment")
    try:
        query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise ValidationError("Activation URI query is malformed") from exc
    for name, items in query.items():
        if len(items) != 1:
            raise ValidationError(f"Activation URI repeats field {name}")
    token = query.get("t", [""])[0]
    if not token:
        raise ValidationError("Activation URI has no activation token")
    org_url = canonical_org_url(query.get("s", [""])[0])
    authenticator_id = query.get("f", [None])[0]
    if authenticator_id == "":
        raise ValidationError("Activation URI has an empty authenticator ID")
    hardware_required = _boolean(query, "hwKeystoreRequired")
    # Parse this even though the PoC has no alternative hardware backend.
    _boolean(query, "isIdxEnabled")
    if hardware_required:
        raise PolicyError(
            "This activation requires a hardware keystore; the software-key PoC cannot satisfy it"
        )
    return Activation(
        token=token,
        authenticator_id=authenticator_id,
        org_url=org_url,
        account=parts.netloc,
        issuer=query.get("issuer", [None])[0],
        hardware_keystore_required=hardware_required,
    )
