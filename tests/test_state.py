from __future__ import annotations

import base64
import json

import pytest

from okta_poc.errors import PoCError
from okta_poc.state import Key, State, Store
from tests.helpers import enrollment


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value)


def test_public_jwk_uses_android_encoding():
    jwk = Key.generate().public_jwk()
    modulus = _unb64(jwk["n"])
    # Java BigInteger.toByteArray(): leading sign byte, base64url with padding.
    assert len(modulus) == 257 and modulus[0] == 0
    assert jwk["n"].endswith("=")
    assert jwk["e"] == "AQAB"
    assert jwk["okta:kpr"] == "SOFTWARE"
    assert not {"d", "p", "q"} & set(jwk)


def test_encrypted_roundtrip_hides_private_keys(tmp_path):
    path = tmp_path / "state.json"
    record = enrollment(with_uv=True)
    with Store(path, "correct horse battery").edit() as state:
        state.enrollments[record.enrollment_id] = record
        state.mark_responded("tx-1")
    raw = path.read_text()
    assert "PRIVATE KEY" not in raw and "enrollment-id" not in raw
    assert path.stat().st_mode & 0o777 == 0o600
    assert Store.is_encrypted(path)
    loaded = Store(path, "correct horse battery").read()
    assert loaded.enrollments["enrollment-id"] == record
    assert loaded.responded == ["tx-1"]


def test_wrong_passphrase_and_missing_passphrase_fail(tmp_path):
    path = tmp_path / "state.json"
    with Store(path, "correct horse battery").edit():
        pass
    with pytest.raises(PoCError, match="Wrong state passphrase"):
        Store(path, "wrong").read()
    with pytest.raises(PoCError, match="passphrase is required"):
        Store(path, None).read()


def test_plaintext_roundtrip_and_open_permissions_rejected(tmp_path):
    path = tmp_path / "state.json"
    with Store(path, None).edit() as state:
        state.enrollments["enrollment-id"] = enrollment()
    assert json.loads(path.read_text())["schema_version"] == 2
    assert not Store.is_encrypted(path)
    assert "enrollment-id" in Store(path, None).read().enrollments
    path.chmod(0o644)
    with pytest.raises(PoCError, match="too open"):
        Store(path, None).read()


def test_edit_saves_progress_even_when_the_caller_fails(tmp_path):
    path = tmp_path / "state.json"
    with pytest.raises(RuntimeError):
        with Store(path, None).edit() as state:
            state.mark_responded("tx-1")
            raise RuntimeError("network failed after sending")
    assert Store(path, None).read().responded == ["tx-1"]


def test_responded_list_is_bounded():
    state = State()
    for index in range(250):
        state.mark_responded(f"tx-{index}")
    assert len(state.responded) == 200 and state.responded[-1] == "tx-249"
