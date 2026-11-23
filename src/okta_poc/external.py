"""Run operator-supplied helper programs: push decisions and user verification.

Helpers run without a shell and without any OKTA_* environment variables, so
they never see activation tokens, passphrases or other secrets.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Literal

from .challenge import Challenge
from .errors import PoCError

Decision = Literal["approve", "deny", "skip", "quit"]


def run_helper(executable: str, stdin: str | None = None) -> int:
    path = Path(executable)
    if not path.is_absolute() or not os.access(path, os.X_OK) or not path.is_file():
        raise PoCError(f"{executable} must be an absolute path to an executable file")
    if path.stat().st_mode & 0o002:
        raise PoCError(f"{executable} is world-writable; refusing to run it")
    environment = {name: value for name, value in os.environ.items() if not name.startswith("OKTA_")}
    try:
        return subprocess.run([str(path)], input=stdin, text=True, env=environment, check=False).returncode
    except OSError as exc:
        raise PoCError(f"Cannot start {executable}") from exc


def external_decision(executable: str, challenge: Challenge) -> Decision:
    """The program gets the challenge summary as JSON on stdin.
    Exit 0 = approve, 1 = deny, 2 = skip; anything else fails closed."""

    status = run_helper(executable, json.dumps(challenge.summary(), ensure_ascii=False) + "\n")
    decisions: dict[int, Decision] = {0: "approve", 1: "deny", 2: "skip"}
    if status not in decisions:
        raise PoCError(f"Decision program exited with {status}; nothing was signed")
    return decisions[status]


def interactive_decision() -> Decision:
    choices: dict[str, Decision] = {"a": "approve", "d": "deny", "s": "skip", "q": "quit"}
    while True:
        try:
            answer = input("Decision [a]pprove/[d]eny/[s]kip/[q]uit: ").strip().lower()[:1]
        except EOFError:
            return "quit"
        if answer in choices:
            return choices[answer]
        print("Choose a, d, s, or q.")


def verify_user(executable: str | None) -> None:
    """Run the trusted UV provider (e.g. a biometric check). Exit 0 = verified."""

    if not executable:
        raise PoCError("This challenge requires user verification; pass --uv-executable")
    print("Running the user-verification provider; nothing is signed unless it succeeds.")
    status = run_helper(executable)
    if status != 0:
        raise PoCError(f"User verification failed (exit {status}); nothing was submitted")
