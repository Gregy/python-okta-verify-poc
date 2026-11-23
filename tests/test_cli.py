from __future__ import annotations

import json

import pytest

from okta_poc.cli import _submission_error_state, main
from okta_poc.errors import ApiError, TransportError
from okta_poc.http import HttpResponse
from okta_poc.models import State
from okta_poc.storage import StateStore
from tests.helpers import (
    FakeHttp,
    enrollment,
    enrollment_response,
    organization_response,
    policy_response,
    write_qr_image,
)

PASSWORD = "correct horse battery staple"
QR = "oktaverify://account/?t=CLI_TEST_ACTIVATION_TOKEN&f=aut_example&s=https%3A%2F%2Forg.example"


def set_credentials(monkeypatch):
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", PASSWORD)
    monkeypatch.setenv("OKTA_QR_URI", QR)
    monkeypatch.delenv("OKTA_FCM_TOKEN", raising=False)


def successful_http():
    return FakeHttp(
        gets=[organization_response(), policy_response()],
        posts=[HttpResponse(200, {}, json.dumps(enrollment_response()).encode())],
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, "FAILED_FINAL"),
        (401, "FAILED_FINAL"),
        (404, "FAILED_FINAL"),
        (429, "UNKNOWN_RETRYABLE"),
        (500, "UNKNOWN_RETRYABLE"),
        (302, "UNKNOWN_RETRYABLE"),
        (202, "UNKNOWN_RETRYABLE"),
    ],
)
def test_submission_error_state_preserves_unknown_outcomes(status, expected):
    assert _submission_error_state(status) == expected


def test_cli_required_uv_policy_cannot_enroll_pop_only(tmp_path, monkeypatch, capsys):
    policy = policy_response()
    policy[0]["settings"]["userVerification"] = "REQUIRED"
    http = FakeHttp(gets=[organization_response(), policy])
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: http)
    set_credentials(monkeypatch)
    path = tmp_path / "state.json"
    result = main(["--state", str(path), "enroll", "--without-push-token", "--yes"])
    assert result == 2
    assert "--with-uv" in capsys.readouterr().err
    assert len(http.calls) == 2  # discovery only; no key generation or enrollment POST
    assert not path.exists()


def test_cli_enroll_persists_encrypted_record_without_secret_logs(tmp_path, monkeypatch, capsys):
    http = successful_http()
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: http)
    set_credentials(monkeypatch)
    path = tmp_path / "state.json"
    result = main(["--state", str(path), "enroll", "--without-push-token", "--yes"])
    assert result == 0
    output = capsys.readouterr()
    assert "CLI_TEST_ACTIVATION_TOKEN" not in output.out + output.err
    assert b"CLI_TEST_ACTIVATION_TOKEN" not in path.read_bytes()
    assert b"PRIVATE KEY" not in path.read_bytes()
    state = StateStore(path).load(PASSWORD)
    assert len(state.enrollments) == 1
    assert state.preparations == {}
    post = http.calls[-1]
    assert post["headers"]["Authorization"] == "OTDT CLI_TEST_ACTIVATION_TOKEN"
    assert "pushToken" not in post["body"]["methods"][0]
    assert "capabilities" not in post["body"]["methods"][0]


def test_cli_delete_enrollment_removes_server_and_local_records(
    tmp_path, monkeypatch
):
    path = tmp_path / "state.json"
    record = enrollment()
    state = State(enrollments={record.enrollment_id: record})
    state.set_transaction(
        record.enrollment_id, "old-transaction", "COMPLETED", decision="APPROVE"
    )
    StateStore(path).save(state, PASSWORD)
    http = FakeHttp(deletes=[HttpResponse(204, {}, b"")])
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: http)
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", PASSWORD)

    result = main([
        "--state", str(path), "delete-enrollment", "--all", "--yes",
    ])

    assert result == 0
    assert len(http.calls) == 1
    assert http.calls[0]["method"] == "DELETE"
    restored = StateStore(path).load(PASSWORD)
    assert restored.enrollments == {}
    assert restored.transactions == {}


def test_cli_delete_enrollment_preserves_local_keys_on_rejection(
    tmp_path, monkeypatch
):
    path = tmp_path / "state.json"
    record = enrollment()
    StateStore(path).save(
        State(enrollments={record.enrollment_id: record}), PASSWORD
    )
    http = FakeHttp(deletes=[ApiError(401, "synthetic rejection")])
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: http)
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", PASSWORD)

    result = main([
        "--state", str(path), "delete-enrollment", "--all", "--yes",
    ])

    assert result == 2
    restored = StateStore(path).load(PASSWORD)
    assert restored.enrollments[record.enrollment_id].pop_key.kid == record.pop_key.kid


def test_cli_update_push_token_preserves_enrollment_and_hides_token(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "state.json"
    record = enrollment()
    StateStore(path).save(
        State(enrollments={record.enrollment_id: record}), PASSWORD
    )
    http = FakeHttp(
        puts=[HttpResponse(200, {}, json.dumps(enrollment_response()).encode())]
    )
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: http)
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", PASSWORD)
    monkeypatch.setenv("OKTA_FCM_TOKEN", "OKTA_PROJECT_FCM_TOKEN")

    result = main([
        "--state", str(path), "update-push-token", "--yes",
        "--enrollment", record.enrollment_id,
    ])

    assert result == 0
    assert len(http.calls) == 1
    call = http.calls[0]
    assert call["method"] == "PUT"
    assert call["body"]["methods"][0]["pushToken"] == "OKTA_PROJECT_FCM_TOKEN"
    assert call["body"]["device"]["id"] == record.device_id
    output = capsys.readouterr()
    assert "OKTA_PROJECT_FCM_TOKEN" not in output.out + output.err
    restored = StateStore(path).load(PASSWORD)
    assert restored.enrollments[record.enrollment_id].pop_key.kid == record.pop_key.kid


def test_cli_update_push_token_from_file(tmp_path, monkeypatch, capsys):
    path = tmp_path / "state.json"
    token_path = tmp_path / "fcm-token"
    token_path.write_text("OKTA_PROJECT_FCM_TOKEN")
    token_path.chmod(0o600)
    record = enrollment()
    StateStore(path).save(
        State(enrollments={record.enrollment_id: record}), PASSWORD
    )
    http = FakeHttp(
        puts=[HttpResponse(200, {}, json.dumps(enrollment_response()).encode())]
    )
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: http)
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", PASSWORD)
    monkeypatch.delenv("OKTA_FCM_TOKEN", raising=False)

    result = main([
        "--state", str(path), "update-push-token", "--yes",
        "--fcm-token-file", str(token_path),
    ])

    assert result == 0
    assert http.calls[0]["body"]["methods"][0]["pushToken"] == "OKTA_PROJECT_FCM_TOKEN"
    assert "OKTA_PROJECT_FCM_TOKEN" not in capsys.readouterr().out


def test_cli_update_push_token_requires_real_token(tmp_path, monkeypatch, capsys):
    path = tmp_path / "state.json"
    record = enrollment()
    StateStore(path).save(
        State(enrollments={record.enrollment_id: record}), PASSWORD
    )
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", PASSWORD)
    monkeypatch.delenv("OKTA_FCM_TOKEN", raising=False)
    result = main(["--state", str(path), "update-push-token", "--yes"])
    assert result == 2
    assert "OKTA_FCM_TOKEN" in capsys.readouterr().err


def test_cli_enroll_decodes_qr_image_without_secret_logs(tmp_path, monkeypatch, capsys):
    qr_path = tmp_path / "activation.png"
    write_qr_image(qr_path, QR)
    state_path = tmp_path / "state.json"
    http = successful_http()
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: http)
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", PASSWORD)
    monkeypatch.delenv("OKTA_QR_URI", raising=False)
    monkeypatch.delenv("OKTA_FCM_TOKEN", raising=False)

    result = main([
        "--state", str(state_path),
        "enroll", "--qr-image", str(qr_path), "--without-push-token", "--yes",
    ])

    assert result == 0
    output = capsys.readouterr()
    assert "CLI_TEST_ACTIVATION_TOKEN" not in output.out + output.err
    assert http.calls[-1]["headers"]["Authorization"] == "OTDT CLI_TEST_ACTIVATION_TOKEN"
    assert len(StateStore(state_path).load(PASSWORD).enrollments) == 1


def test_cli_qr_image_conflicts_with_environment_uri(tmp_path, monkeypatch, capsys):
    qr_path = tmp_path / "activation.png"
    write_qr_image(qr_path, QR)
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", PASSWORD)
    monkeypatch.setenv("OKTA_QR_URI", QR)
    result = main([
        "--state", str(tmp_path / "state.json"),
        "enroll", "--qr-image", str(qr_path), "--without-push-token", "--yes",
    ])
    assert result == 2
    assert "conflicts" in capsys.readouterr().err


def test_cli_plaintext_enroll_needs_no_passphrase_and_reopens(tmp_path, monkeypatch, capsys):
    path = tmp_path / "state.json"
    http = successful_http()
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: http)
    monkeypatch.delenv("OKTA_POC_STATE_PASSWORD", raising=False)
    monkeypatch.setenv("OKTA_QR_URI", QR)
    monkeypatch.delenv("OKTA_FCM_TOKEN", raising=False)

    result = main([
        "--state", str(path),
        "enroll", "--plaintext-state", "--without-push-token", "--yes",
    ])

    assert result == 0
    raw = path.read_bytes()
    assert b'"schema_version": 1' in raw
    assert b"PRIVATE KEY" in raw
    assert b"ciphertext" not in raw
    assert path.stat().st_mode & 0o777 == 0o600
    assert "CLI_TEST_ACTIVATION_TOKEN" not in capsys.readouterr().out

    # The existing plaintext file is auto-detected by subsequent commands.
    assert main(["--state", str(path), "list"]) == 0


def test_cli_uncertain_enrollment_reuses_keys_and_never_auto_retries(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    first = FakeHttp(
        gets=[organization_response(), policy_response()],
        posts=[TransportError("synthetic uncertain result")],
    )
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: first)
    set_credentials(monkeypatch)
    result = main(["--state", str(path), "enroll", "--without-push-token", "--yes"])
    assert result == 2
    assert len(first.calls) == 3  # organization, policy, exactly one enrollment POST
    saved = StateStore(path).load(PASSWORD)
    assert saved.enrollments == {}
    preparation = next(iter(saved.preparations.values()))
    original_kid = preparation.pop_key.kid

    second = successful_http()
    monkeypatch.setattr("okta_poc.cli.HttpClient", lambda: second)
    set_credentials(monkeypatch)
    result = main(["--state", str(path), "enroll", "--without-push-token", "--yes"])
    assert result == 0
    assert len(second.calls) == 3
    assert second.calls[-1]["body"]["methods"][0]["keys"]["proofOfPossession"]["kid"] == original_kid
    completed = StateStore(path).load(PASSWORD)
    assert len(completed.enrollments) == 1
    assert completed.preparations == {}
