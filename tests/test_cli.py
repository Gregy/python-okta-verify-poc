from __future__ import annotations

import pytest

from okta_poc import cli
from okta_poc.state import FcmDevice, Store
from tests.helpers import (
    FakeHttp,
    Server,
    challenge_claims,
    enrollment,
    enrollment_response,
    organization_response,
    policy_response,
)

QR_URI = "oktaverify://user@example?t=SECRET_TOKEN&f=aut_example&s=https://org.example"
DEVICE = FcmDevice(android_id=1, security_token=2, token="SECRET_FCM_TOKEN")


@pytest.fixture
def http(monkeypatch):
    fake = FakeHttp()
    monkeypatch.setattr(cli, "HttpClient", lambda: fake)
    return fake


@pytest.fixture(autouse=True)
def no_terminal(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)


def plaintext_state(tmp_path, record=None):
    path = tmp_path / "state.json"
    with Store(path, None).edit() as state:
        state.fcm = DEVICE
        if record:
            state.enrollments[record.enrollment_id] = record
    return path


def test_enroll_registers_fcm_and_saves_encrypted_state(tmp_path, monkeypatch, http, capsys):
    monkeypatch.setenv("OKTA_QR_URI", QR_URI)
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", "correct horse battery")
    monkeypatch.setattr(cli, "register_device", lambda: DEVICE)
    http.responses = [organization_response(), policy_response(), enrollment_response()]
    path = tmp_path / "state.json"

    assert cli.main(["--state", str(path), "enroll", "--with-uv", "--yes"]) == 0
    assert http.calls[2]["body"]["methods"][0]["pushToken"] == "SECRET_FCM_TOKEN"
    output = capsys.readouterr()
    assert "SECRET" not in output.out + output.err
    state = Store(path, "correct horse battery").read()
    assert state.fcm == DEVICE
    assert state.enrollments["enrollment-id"].uv_key is not None


def test_enroll_refuses_when_policy_requires_uv(tmp_path, monkeypatch, http, capsys):
    monkeypatch.setenv("OKTA_QR_URI", QR_URI)
    policy = policy_response()
    policy[0]["settings"]["userVerification"] = "REQUIRED"
    http.responses = [organization_response(), policy]
    path = tmp_path / "state.json"
    assert cli.main(["--state", str(path), "enroll", "--plaintext-state", "--without-push", "--yes"]) == 2
    assert "--with-uv" in capsys.readouterr().err
    assert len(http.calls) == 2  # no enrollment POST


def test_commands_need_existing_state(tmp_path, capsys):
    assert cli.main(["--state", str(tmp_path / "none.json"), "list"]) == 2
    assert "enroll" in capsys.readouterr().err


def _run_fcm(monkeypatch, path, messages, *extra):
    monkeypatch.setattr(cli, "listen", lambda device: iter(messages))
    return cli.main(["--state", str(path), "fcm", *extra])


def test_fcm_approves_validated_push_once(tmp_path, monkeypatch, http, capsys):
    server = Server()
    path = plaintext_state(tmp_path, enrollment())
    push = {"challenge": server.sign(challenge_claims())}
    # The same push twice (FCM redelivery) and one forged push.
    forged = {"challenge": Server().sign(challenge_claims(transactionId="tx-forged"))}
    http.responses = [server.jwks(), None]
    decision = tmp_path / "approve"
    decision.write_text("#!/bin/sh\nexit 0\n")
    decision.chmod(0o700)

    assert _run_fcm(monkeypatch, path, [push, push, forged], "--decision-executable", str(decision)) == 0
    posts = [call for call in http.calls if call["method"] == "POST"]
    assert len(posts) == 1
    assert Store(path, None).read().responded == ["tx-1"]
    output = capsys.readouterr()
    assert "already handled" in output.out
    assert "Push not handled" in output.err


def test_fcm_uv_push_requires_uv_provider(tmp_path, monkeypatch, http, capsys):
    server = Server()
    path = plaintext_state(tmp_path, enrollment(with_uv=True))
    http.responses = [server.jwks()]
    approve = tmp_path / "approve"
    approve.write_text("#!/bin/sh\nexit 0\n")
    approve.chmod(0o700)
    push = {"challenge": server.sign(challenge_claims(userVerification="REQUIRED"))}

    assert _run_fcm(monkeypatch, path, [push], "--decision-executable", str(approve)) == 0
    assert "--uv-executable" in capsys.readouterr().err
    assert not [call for call in http.calls if call["method"] == "POST"]
    assert Store(path, None).read().responded == []

    http.responses = [server.jwks(), None]
    assert _run_fcm(monkeypatch, path, [push], "--decision-executable", str(approve), "--uv-executable", str(approve)) == 0
    assert Store(path, None).read().responded == ["tx-1"]


def test_deny_via_poll(tmp_path, http):
    server = Server()
    record = enrollment()
    path = plaintext_state(tmp_path, record)
    http.responses = [[{"challenge": server.sign(challenge_claims())}], server.jwks(), None]
    assert cli.main(["--state", str(path), "deny", "tx-1", "--yes"]) == 0
    assert http.calls[-1]["method"] == "POST"
    assert Store(path, None).read().responded == ["tx-1"]


def test_delete_all(tmp_path, http):
    path = plaintext_state(tmp_path, enrollment())
    http.responses = [None]
    assert cli.main(["--state", str(path), "delete-enrollment", "--all", "--yes"]) == 0
    assert http.calls[0]["method"] == "DELETE"
    assert Store(path, None).read().enrollments == {}


def test_fcm_register_updates_all_enrollments(tmp_path, monkeypatch, http):
    path = plaintext_state(tmp_path, enrollment())
    new_device = FcmDevice(android_id=5, security_token=6, token="NEW_TOKEN")
    monkeypatch.setattr(cli, "register_device", lambda: new_device)
    http.responses = [enrollment_response()]
    assert cli.main(["--state", str(path), "fcm-register"]) == 0
    assert http.calls[0]["body"]["methods"][0]["pushToken"] == "NEW_TOKEN"
    assert Store(path, None).read().fcm == new_device


def test_fcm_ignores_expired_redelivery_quietly(tmp_path, monkeypatch, http, capsys):
    import time

    server = Server()
    path = plaintext_state(tmp_path, enrollment())
    old = {"challenge": server.sign(challenge_claims(exp=int(time.time()) - 3600, iat=int(time.time()) - 3900)),
           "transactionId": "tx-old"}
    http.responses = [server.jwks()]
    assert _run_fcm(monkeypatch, path, [old], "--decision-executable", "/bin/false") == 0
    output = capsys.readouterr()
    assert "Ignoring expired push tx-old" in output.out
    assert output.err == ""
