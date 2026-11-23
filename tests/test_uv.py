from __future__ import annotations

import json
from pathlib import Path

import pytest

from okta_poc.errors import PolicyError, ValidationError
from okta_poc.uv import run_external_uv


def helper(path: Path, body: str) -> Path:
    executable = path / "uv helper.py"
    executable.write_text("#!/usr/bin/env python3\n" + body)
    executable.chmod(0o700)
    return executable


def test_external_uv_success_and_secret_environment_scrubbing(tmp_path, monkeypatch):
    output = tmp_path / "result.json"
    monkeypatch.setenv("OKTA_TEST_SECRET", "must-not-reach-helper")
    monkeypatch.setenv("OKTA_POC_STATE_PASSWORD", "also-secret")
    executable = helper(
        tmp_path,
        "import json, os\n"
        f"json.dump({{'secret': os.environ.get('OKTA_TEST_SECRET'), 'password': os.environ.get('OKTA_POC_STATE_PASSWORD')}}, open({str(output)!r}, 'w'))\n",
    )
    assert run_external_uv(str(executable)) == 0
    result = json.loads(output.read_text())
    assert result == {"secret": None, "password": None}


def test_external_uv_failure_and_unsupported_status(tmp_path):
    failed = helper(tmp_path, "raise SystemExit(1)\n")
    assert run_external_uv(str(failed)) == 1
    failed.unlink()
    invalid = helper(tmp_path, "raise SystemExit(2)\n")
    with pytest.raises(PolicyError, match="unsupported exit status 2"):
        run_external_uv(str(invalid))


def test_external_uv_requires_safe_absolute_executable(tmp_path):
    with pytest.raises(PolicyError, match="uv-executable"):
        run_external_uv("")
    with pytest.raises(ValidationError, match="absolute path"):
        run_external_uv("relative/helper")
    missing = tmp_path / "missing"
    with pytest.raises(ValidationError, match="does not exist"):
        run_external_uv(str(missing))
    world_writable = helper(tmp_path, "raise SystemExit(0)\n")
    world_writable.chmod(0o777)
    with pytest.raises(ValidationError, match="world-writable"):
        run_external_uv(str(world_writable))
