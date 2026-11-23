#!/usr/bin/env python3
"""Interactive file-backed decision provider for live FCM testing."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

REQUEST = Path("/dev/shm/okta-poc-decision-request.json")
RESPONSE = Path("/dev/shm/okta-poc-decision-response")
TIMEOUT_SECONDS = 300


def write_request(value: dict) -> None:
    temporary = REQUEST.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, REQUEST)


def main() -> int:
    payload = json.load(sys.stdin)
    RESPONSE.unlink(missing_ok=True)
    REQUEST.unlink(missing_ok=True)
    write_request(payload)
    transaction = payload.get("transactionId", "<unknown>")
    print(f"DECISION_REQUEST transaction={transaction}", flush=True)
    for name in (
        "appInstanceName",
        "clientOS",
        "clientLocation",
        "transactionTime",
        "userVerification",
        "userMediation",
        "expiresAt",
    ):
        print(f"  {name}: {payload.get(name)}", flush=True)
    print("DECISION_WAITING approve/deny/skip (5 minute timeout)", flush=True)
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        while time.monotonic() < deadline:
            try:
                decision = RESPONSE.read_text(encoding="ascii").strip().lower()
            except FileNotFoundError:
                time.sleep(0.5)
                continue
            except (OSError, UnicodeDecodeError):
                decision = ""
            RESPONSE.unlink(missing_ok=True)
            if decision == "approve":
                return 0
            if decision == "deny":
                return 1
            if decision == "skip":
                return 2
            print("DECISION_INVALID expected approve/deny/skip", flush=True)
        print("DECISION_TIMEOUT skipping without a response", flush=True)
        return 2
    finally:
        REQUEST.unlink(missing_ok=True)
        RESPONSE.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(2)
