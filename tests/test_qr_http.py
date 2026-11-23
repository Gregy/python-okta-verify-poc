from __future__ import annotations

import cv2
import pytest

from okta_poc.errors import PoCError
from okta_poc.http import check_org_link, org_origin
from okta_poc.qr import decode_qr_image, parse_activation_uri

URI = "oktaverify://user@example?t=SECRET_TOKEN&f=aut_example&s=https://ORG.example/&issuer=Example"


def test_parse_activation_hides_token_in_repr():
    activation = parse_activation_uri(URI)
    assert activation.token == "SECRET_TOKEN"
    assert activation.org_url == "https://org.example"
    assert activation.authenticator_id == "aut_example"
    assert "SECRET_TOKEN" not in repr(activation)


@pytest.mark.parametrize(
    "uri",
    [
        "https://example?t=x&s=https://org.example",
        "oktaverify://user?s=https://org.example",
        "oktaverify://user?t=x&s=http://org.example",
        "oktaverify://user?t=x&s=https://org.example/path",
        "oktaverify://user?t=x&s=https://org.example&hwKeystoreRequired=true",
    ],
)
def test_bad_activation_uris_are_rejected(uri):
    with pytest.raises(PoCError):
        parse_activation_uri(uri)


def test_decode_qr_image(tmp_path):
    image = cv2.QRCodeEncoder_create().encode(URI)
    image = cv2.resize(image, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    image = cv2.copyMakeBorder(image, 32, 32, 32, 32, cv2.BORDER_CONSTANT, value=255)
    path = tmp_path / "qr.png"
    cv2.imwrite(str(path), image)
    assert decode_qr_image(path) == URI


def test_decode_qr_image_failures(tmp_path):
    with pytest.raises(PoCError, match="Cannot read"):
        decode_qr_image(tmp_path / "missing.png")
    blank = tmp_path / "blank.png"
    cv2.imwrite(str(blank), cv2.resize(cv2.QRCodeEncoder_create().encode("x"), (10, 10)) * 0 + 255)
    with pytest.raises(PoCError, match="No QR code"):
        decode_qr_image(blank)


def test_org_links_must_stay_on_the_org_host():
    org = org_origin("https://Org.Example:443/")
    assert org == "https://org.example"
    assert check_org_link(org + "/a?b=c", org, "x") == org + "/a?b=c"
    for bad in ("http://org.example/a", "https://evil.example/a", "https://org.example.evil/a",
                "https://user@org.example/a", "https://org.example:8443/a", None):
        with pytest.raises(PoCError):
            check_org_link(bad, org, "x")
