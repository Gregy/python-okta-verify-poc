from __future__ import annotations

import json

import pytest

from okta_poc.challenge import ChallengeValidator
from okta_poc.errors import PoCError
from okta_poc.external import external_decision, run_helper, verify_user
from tests.helpers import FakeHttp, Server, challenge_claims, enrollment


def script(tmp_path, body: str, name: str = "helper"):
    path = tmp_path / name
    path.write_text("#!/usr/bin/env python3\nimport json, os, sys\n" + body)
    path.chmod(0o700)
    return str(path)


def challenge():
    server = Server()
    return ChallengeValidator(enrollment(), FakeHttp(server.jwks())).validate(server.sign(challenge_claims()))


def test_decision_gets_summary_and_no_okta_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", "secret")
    out = tmp_path / "seen.json"
    helper = script(tmp_path, f"""
data = json.load(sys.stdin)
json.dump({{"data": data, "env": [k for k in os.environ if k.startswith("OKTA_")]}}, open({str(out)!r}, "w"))
sys.exit(0)
""")
    assert external_decision(helper, challenge()) == "approve"
    seen = json.loads(out.read_text())
    assert seen["env"] == []
    assert seen["data"]["transactionId"] == "tx-1"
    assert "nonce" not in json.dumps(seen["data"]).lower()


@pytest.mark.parametrize("status, expected", [(0, "approve"), (1, "deny"), (2, "skip")])
def test_decision_exit_statuses(tmp_path, status, expected):
    assert external_decision(script(tmp_path, f"sys.exit({status})"), challenge()) == expected


def test_unknown_decision_status_fails_closed(tmp_path):
    with pytest.raises(PoCError, match="exited with 7"):
        external_decision(script(tmp_path, "sys.exit(7)"), challenge())


def test_user_verification(tmp_path):
    verify_user(script(tmp_path, "sys.exit(0)"))
    with pytest.raises(PoCError, match="failed"):
        verify_user(script(tmp_path, "sys.exit(1)", "fail"))
    with pytest.raises(PoCError, match="--uv-executable"):
        verify_user(None)


def test_helper_must_be_absolute_and_not_world_writable(tmp_path):
    with pytest.raises(PoCError, match="absolute"):
        run_helper("relative/helper")
    helper = script(tmp_path, "sys.exit(0)")
    (tmp_path / "helper").chmod(0o777)
    with pytest.raises(PoCError, match="world-writable"):
        run_helper(helper)
