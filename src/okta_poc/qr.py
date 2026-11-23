"""Read the Okta Verify activation QR code (`oktaverify://...`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import cv2

from .errors import PoCError
from .http import org_origin


@dataclass(frozen=True)
class Activation:
    token: str = field(repr=False)  # single-use activation token ("t")
    org_url: str                   # "s"
    authenticator_id: str | None   # "f"


def decode_qr_image(path: Path) -> str:
    image = cv2.imread(str(path.expanduser()))
    if image is None:
        raise PoCError(f"Cannot read QR image {path}")
    detector = cv2.QRCodeDetector()
    # Dense QR codes in screenshots sometimes decode only after resampling.
    for scale, interpolation in ((1.0, None), (0.5, cv2.INTER_AREA), (2.0, cv2.INTER_NEAREST), (0.25, cv2.INTER_AREA)):
        candidate = image if interpolation is None else cv2.resize(
            image, None, fx=scale, fy=scale, interpolation=interpolation
        )
        value, _, _ = detector.detectAndDecode(candidate)
        if value:
            return value
    raise PoCError("No QR code was found in the image")


def parse_activation_uri(uri: str) -> Activation:
    parts = urlsplit(uri.strip())
    if parts.scheme.lower() != "oktaverify":
        raise PoCError("Only oktaverify:// enrollment URIs are supported")
    query = {name: values[0] for name, values in parse_qs(parts.query).items()}
    if not query.get("t"):
        raise PoCError("Activation URI has no activation token")
    if query.get("hwKeystoreRequired", "").lower() == "true":
        raise PoCError("This activation requires a hardware keystore; software keys cannot satisfy it")
    return Activation(
        token=query["t"],
        org_url=org_origin(query.get("s", "")),
        authenticator_id=query.get("f"),
    )
