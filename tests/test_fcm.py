from __future__ import annotations

import json
import sys
import time

import pytest

from okta_poc.cli import _submit_challenge_response, main
from okta_poc.crypto import generate_rsa_key
from okta_poc.errors import PolicyError, ValidationError
from okta_poc.fcm import (
    FcmReceiver,
    interactive_decision,
    register_fcm_device,
    run_external_decision,
)
from okta_poc.http import HttpResponse
from okta_poc.models import State
from okta_poc.storage import StateStore
from tests.helpers import (
    FakeHttp,
    challenge_claims,
    enrollment,
    enrollment_response,
    server_challenge,
    validated_challenge,
)


def executable(path, body: str):
    path.write_text("#!/usr/bin/env python3\n" + body)
    path.chmod(0o700)
    return path


def test_receiver_yields_once_deletes_challenge_and_scrubs_environment(tmp_path, monkeypatch):
    capture = tmp_path / "environment.json"
    device = tmp_path / "device.json"
    device.write_text("{}")
    device.chmod(0o600)
    receiver = executable(
        tmp_path / "receiver.py",
        "import json, os\n"
        "from pathlib import Path\n"
        f"capture = Path({str(capture)!r})\n"
        "capture.write_text(json.dumps({'device': os.environ.get('OKTA_POC_FCM_DEVICE'), 'secret': os.environ.get('OKTA_TEST_SECRET'), 'tokenOut': os.environ.get('OKTA_POC_FCM_TOKEN_OUT')}))\n"
        "challenge = Path(os.environ['OKTA_POC_FCM_CHALLENGE_OUT'])\n"
        "challenge.write_text('HEADER.PAYLOAD.SIGNATURE')\n"
        "challenge.chmod(0o600)\n"
        "print('OKTA_CHALLENGE_RECEIVED')\n",
    )
    monkeypatch.setenv("OKTA_TEST_SECRET", "must-not-reach-receiver")
    token_out = tmp_path / "custom-token"
    instance = FcmReceiver(receiver, device, token_out)
    result = instance.receive()
    assert result == "HEADER.PAYLOAD.SIGNATURE"
    metadata = json.loads(capture.read_text())
    assert metadata == {
        "device": str(device.resolve()),
        "secret": None,
        "tokenOut": str(token_out),
    }
    assert not instance.challenge_path.exists()


def test_receiver_requires_owner_only_device_credentials(tmp_path):
    device = tmp_path / "device.json"
    device.write_text("{}")
    device.chmod(0o644)
    receiver = executable(tmp_path / "receiver.py", "")
    with pytest.raises(ValidationError, match="mode 0600"):
        FcmReceiver(receiver, device)


def test_register_fcm_device_creates_secure_credentials_and_token(tmp_path, capsys):
    device = tmp_path / "device.json"
    token = tmp_path / "token"
    receiver = executable(
        tmp_path / "register.py",
        "import os\n"
        "from pathlib import Path\n"
        "Path(os.environ['OKTA_POC_FCM_DEVICE']).write_text('{}')\n"
        "Path(os.environ['OKTA_POC_FCM_DEVICE']).chmod(0o600)\n"
        "Path(os.environ['OKTA_POC_FCM_TOKEN_OUT']).write_text('SECRET_FCM_TOKEN')\n"
        "Path(os.environ['OKTA_POC_FCM_TOKEN_OUT']).chmod(0o600)\n"
        "print('FCM token written to /secure/path (mode 0600; not printed)')\n",
    )
    assert register_fcm_device(receiver, device, token) == "SECRET_FCM_TOKEN"
    assert token.read_text() == "SECRET_FCM_TOKEN"
    assert device.stat().st_mode & 0o777 == 0o600
    assert token.stat().st_mode & 0o777 == 0o600
    assert "SECRET_FCM_TOKEN" not in capsys.readouterr().out


def test_cli_fcm_register_attaches_token_to_existing_enrollment(tmp_path, monkeypatch, capsys):
    record = enrollment()
    path = tmp_path / "state.json"
    StateStore(path, plaintext=True).save(State(enrollments={record.enrollment_id: record}))
    device = tmp_path / "device.json"
    token = tmp_path / "token"
    receiver = executable(
        tmp_path / "register.py",
        "import os\n"
        "from pathlib import Path\n"
        "Path(os.environ['OKTA_POC_FCM_DEVICE']).write_text('{}')\n"
        "Path(os.environ['OKTA_POC_FCM_DEVICE']).chmod(0o600)\n"
        "Path(os.environ['OKTA_POC_FCM_TOKEN_OUT']).write_text('SECRET_FCM_TOKEN')\n"
        "Path(os.environ['OKTA_POC_FCM_TOKEN_OUT']).chmod(0o600)\n"
        "print('FCM token written to /secure/path (mode 0600; not printed)')\n",
    )
    http = FakeHttp(puts=[HttpResponse(200, {}, json.dumps(enrollment_response()).encode())])
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: http)
    result = main([
        "--state", str(path), "fcm-register",
        "--receiver", str(receiver),
        "--fcm-device", str(device),
        "--fcm-token-out", str(token),
    ])
    assert result == 0
    assert http.calls[0]["body"]["methods"][0]["pushToken"] == "SECRET_FCM_TOKEN"
    assert "SECRET_FCM_TOKEN" not in capsys.readouterr().out


def test_external_decision_receives_transaction_json_without_secrets(tmp_path, monkeypatch):
    output = tmp_path / "decision.json"
    provider = executable(
        tmp_path / "decision.py",
        "import json, os, sys\n"
        "payload = json.load(sys.stdin)\n"
        f"payload['secret'] = os.environ.get('OKTA_TEST_SECRET')\n"
        f"json.dump(payload, open({str(output)!r}, 'w'))\n"
        "raise SystemExit(0)\n",
    )
    monkeypatch.setenv("OKTA_TEST_SECRET", "must-not-reach-decision")
    challenge = validated_challenge(user_verification="REQUIRED")
    assert run_external_decision(provider, challenge) == "approve"
    payload = json.loads(output.read_text())
    assert payload["transactionId"] == "transaction-id"
    assert payload["enrollmentId"] == "enrollment-id"
    assert payload["clientOS"] == "LINUX"
    assert payload["userVerification"] == "REQUIRED"
    assert payload["secret"] is None
    assert "nonce" not in payload
    assert "challenge" not in payload


@pytest.mark.parametrize(("status", "expected"), [(1, "deny"), (2, "skip")])
def test_external_decision_statuses(tmp_path, status, expected):
    provider = executable(tmp_path / "decision.py", f"raise SystemExit({status})\n")
    assert run_external_decision(provider, validated_challenge()) == expected


def test_external_decision_rejects_other_status(tmp_path):
    provider = executable(tmp_path / "decision.py", "raise SystemExit(3)\n")
    with pytest.raises(PolicyError, match="unsupported exit status 3"):
        run_external_decision(provider, validated_challenge())


def test_interactive_decision_reprompts_and_supports_quit(monkeypatch):
    answers = iter(("invalid", "a"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert interactive_decision() == "approve"
    monkeypatch.setattr("builtins.input", lambda _: "q")
    assert interactive_decision() == "quit"


def test_interactive_decision_eof_quits_without_response(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError()))
    assert interactive_decision() == "quit"


@pytest.mark.parametrize("external", [False, True])
def test_cli_fcm_decides_validated_pushes(tmp_path, monkeypatch, external):
    record = enrollment()
    path = tmp_path / "state.json"
    StateStore(path, plaintext=True).save(State(enrollments={record.enrollment_id: record}))
    server = generate_rsa_key(profile="canonical")
    now = int(time.time())
    first_claims = challenge_claims()
    second_claims = challenge_claims()
    for claims in (first_claims, second_claims):
        claims.update({"iat": now, "exp": now + 300, "nbf": now - 30})
    second_claims.update({
        "jti": "second-transaction",
        "transactionId": "second-transaction",
        "verificationUri": second_claims["verificationUri"].replace("transaction-id", "second-transaction"),
    })
    compacts = [server_challenge(server, first_claims), server_challenge(server, second_claims)]

    class Receiver:
        def __init__(self, *_):
            pass

        def receive(self):
            return compacts.pop(0)

    decisions = iter(("deny", "quit"))
    submitted = []
    monkeypatch.setattr("okta_poc.cli.FcmReceiver", Receiver)
    monkeypatch.setattr(
        "okta_poc.cli.HttpClient",
        lambda: FakeHttp(gets=[{"keys": [server.public_jwk]}, {"keys": [server.public_jwk]}]),
    )
    if external:
        monkeypatch.setattr(
            "okta_poc.cli.run_external_decision",
            lambda *_: next(decisions),
        )
    else:
        monkeypatch.setattr("okta_poc.cli.interactive_decision", lambda: next(decisions))
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(
        "okta_poc.cli._submit_challenge_response",
        lambda *args, **kwargs: submitted.append(kwargs) or 0,
    )
    argv = ["--state", str(path), "fcm"]
    if external:
        argv += ["--decision-executable", "/unused/test-double"]
    assert main(argv) == 0
    assert len(submitted) == 1
    assert submitted[0]["approve"] is False
    assert submitted[0]["assume_yes"] is True
    assert submitted[0]["display_challenge"] is False


def test_cli_fcm_auto_registers_missing_device_before_listening(tmp_path, monkeypatch):
    record = enrollment()
    path = tmp_path / "state.json"
    StateStore(path, plaintext=True).save(State(enrollments={record.enrollment_id: record}))
    device = tmp_path / "device.json"
    token = tmp_path / "token"
    registration = executable(
        tmp_path / "register.py",
        "import os\n"
        "from pathlib import Path\n"
        "Path(os.environ['OKTA_POC_FCM_DEVICE']).write_text('{}')\n"
        "Path(os.environ['OKTA_POC_FCM_DEVICE']).chmod(0o600)\n"
        "Path(os.environ['OKTA_POC_FCM_TOKEN_OUT']).write_text('SECRET_FCM_TOKEN')\n"
        "Path(os.environ['OKTA_POC_FCM_TOKEN_OUT']).chmod(0o600)\n"
        "print('FCM token written to /secure/path (mode 0600; not printed)')\n",
    )
    server = generate_rsa_key(profile="canonical")
    now = int(time.time())
    claims = challenge_claims()
    claims.update({"iat": now, "exp": now + 300, "nbf": now - 30})
    compact = server_challenge(server, claims)

    class Receiver:
        def __init__(self, *_):
            pass

        def receive(self):
            return compact

    http = FakeHttp(
        gets=[{"keys": [server.public_jwk]}],
        puts=[HttpResponse(200, {}, json.dumps(enrollment_response()).encode())],
    )
    monkeypatch.setattr("okta_poc.cli.FcmReceiver", Receiver)
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: http)
    monkeypatch.setattr("okta_poc.cli.run_external_decision", lambda *_: "quit")
    result = main([
        "--state", str(path), "fcm",
        "--receiver", str(registration),
        "--fcm-device", str(device),
        "--fcm-token-out", str(token),
        "--decision-executable", "/unused/test-double",
    ])
    assert result == 0
    assert http.calls[0]["method"] == "PUT"
    assert http.calls[0]["body"]["methods"][0]["pushToken"] == "SECRET_FCM_TOKEN"
    assert token.read_text() == "SECRET_FCM_TOKEN"


def test_uv_still_required_after_external_approval(tmp_path):
    record = enrollment()
    path = tmp_path / "state.json"
    store = StateStore(path, plaintext=True)
    state = State(enrollments={record.enrollment_id: record})
    store.save(state)
    challenge = validated_challenge(user_verification="REQUIRED")
    challenge.expires_at = time.time() + 300
    with pytest.raises(PolicyError, match="requires user verification"):
        _submit_challenge_response(
            store,
            "",
            state,
            record,
            challenge,
            approve=True,
            uv_executable=None,
            retry_unknown=False,
            assume_yes=True,
            display_challenge=False,
        )
    assert state.transactions == {}
