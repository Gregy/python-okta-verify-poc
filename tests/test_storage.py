from __future__ import annotations

import os

import pytest

from okta_poc.errors import StateError
from okta_poc.models import State
from okta_poc.storage import StateStore
from tests.helpers import preparation

PASSWORD = "correct horse battery staple"


def test_encrypted_state_roundtrip_and_no_plaintext_private_key(tmp_path):
    path = tmp_path / "nested" / "state.json"
    store = StateStore(path)
    state = State()
    prep = preparation()
    state.preparations[prep.key] = prep
    store.save(state, PASSWORD)
    raw = path.read_bytes()
    assert b"PRIVATE KEY" not in raw
    assert b"Test Linux Host" not in raw
    assert b"client-instance" not in raw
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    loaded = store.load(PASSWORD)
    assert loaded.installation_id == state.installation_id
    assert loaded.preparations[prep.key].pop_key.kid == prep.pop_key.kid
    assert loaded.preparations[prep.key].device_profile.display_name == "Test Linux Host"


def test_wrong_passphrase_and_open_permissions_fail(tmp_path):
    path = tmp_path / "state.json"
    store = StateStore(path)
    store.save(State(), PASSWORD)
    with pytest.raises(StateError, match="Wrong state passphrase"):
        store.load("definitely wrong passphrase")
    os.chmod(path, 0o644)
    with pytest.raises(StateError, match="permissions"):
        store.load(PASSWORD)


def test_plaintext_state_roundtrip_without_passphrase(tmp_path):
    path = tmp_path / "plain-state.json"
    state = State()
    prep = preparation()
    state.preparations[prep.key] = prep
    StateStore(path, plaintext=True).save(state)

    raw = path.read_bytes()
    assert b'"schema_version": 1' in raw
    assert b"PRIVATE KEY" in raw
    assert b"ciphertext" not in raw
    assert path.stat().st_mode & 0o777 == 0o600

    reopened = StateStore(path)
    assert reopened.plaintext is True
    loaded = reopened.load()
    assert loaded.preparations[prep.key].pop_key.kid == prep.pop_key.kid
    reopened.save(loaded)
    assert StateStore(path).load().installation_id == state.installation_id


def test_plaintext_mode_does_not_read_encrypted_state(tmp_path):
    path = tmp_path / "state.json"
    StateStore(path).save(State(), PASSWORD)
    with pytest.raises(StateError, match="existing state is encrypted"):
        StateStore(path, plaintext=True).load()


def test_new_state_requires_existing_file_unless_create(tmp_path):
    store = StateStore(tmp_path / "state.json")
    with pytest.raises(StateError, match="No local state"):
        store.load(PASSWORD)
    assert isinstance(store.load(PASSWORD, create=True), State)
