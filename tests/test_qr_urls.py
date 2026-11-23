from __future__ import annotations

import pytest

from okta_poc.errors import PolicyError, ValidationError
from okta_poc.qr import decode_activation_qr, parse_activation_uri
from okta_poc.urls import canonical_org_url, validate_org_link
from tests.helpers import write_qr_image


def test_parse_activation_and_hide_token_in_repr():
    activation = parse_activation_uri(
        "oktaverify://account/?t=SECRET_TEST_TOKEN&f=aut_example&s=https%3A%2F%2Forg.example&issuer=Example&isIdxEnabled=true"
    )
    assert activation.token == "SECRET_TEST_TOKEN"
    assert activation.authenticator_id == "aut_example"
    assert activation.org_url == "https://org.example"
    assert "SECRET_TEST_TOKEN" not in repr(activation)


@pytest.mark.parametrize(
    "uri",
    [
        "https://account/?t=x&s=https%3A%2F%2Forg.example",
        "oktaverify://account/?s=https%3A%2F%2Forg.example",
        "oktaverify://account/?t=x&s=http%3A%2F%2Forg.example",
        "oktaverify://account/?t=x&t=y&s=https%3A%2F%2Forg.example",
        "oktaverify://account/?t=x&s=https%3A%2F%2Forg.example#fragment",
    ],
)
def test_reject_bad_activation(uri):
    with pytest.raises(ValidationError):
        parse_activation_uri(uri)


def test_hardware_requirement_fails_before_network():
    with pytest.raises(PolicyError, match="hardware keystore"):
        parse_activation_uri(
            "oktaverify://account/?t=x&s=https%3A%2F%2Forg.example&hwKeystoreRequired=true"
        )


def test_decode_activation_qr_without_exposing_token(tmp_path):
    path = tmp_path / "activation.png"
    value = (
        "oktaverify://account/?t=SECRET_IMAGE_TEST_TOKEN&f=aut_example"
        "&s=https%3A%2F%2Forg.example&issuer=Example&isIdxEnabled=true"
    )
    write_qr_image(path, value)
    decoded = decode_activation_qr(path)
    activation = parse_activation_uri(decoded)
    assert activation.token == "SECRET_IMAGE_TEST_TOKEN"
    assert activation.org_url == "https://org.example"


def test_decode_activation_qr_rejects_missing_or_invalid_images(tmp_path):
    with pytest.raises(ValidationError, match="does not exist"):
        decode_activation_qr(tmp_path / "missing.png")
    path = tmp_path / "invalid.png"
    path.write_bytes(b"not an image")
    with pytest.raises(ValidationError, match="could not be read"):
        decode_activation_qr(path)


def test_org_url_canonicalization_and_link_binding():
    assert canonical_org_url("HTTPS://ORG.EXAMPLE:443/") == "https://org.example"
    assert validate_org_link(
        "https://org.example/idp/authenticators", "https://org.example", allow_query=False, label="test"
    )
    with pytest.raises(ValidationError, match="organization host"):
        validate_org_link(
            "https://attacker.example/verify", "https://org.example", allow_query=False, label="test"
        )
    with pytest.raises(ValidationError, match="query"):
        validate_org_link(
            "https://org.example/verify?x=1", "https://org.example", allow_query=False, label="test"
        )
