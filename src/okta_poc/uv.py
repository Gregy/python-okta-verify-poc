from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path

from .errors import PolicyError, ValidationError


def run_external_uv(executable: str) -> int:
    """Run the operator's trusted biometric verifier without a shell.

    Exit 0 means successful biometric user verification; exit 1 means failed.
    Other statuses are protocol errors. The helper never receives Okta secrets.
    """

    if not executable:
        raise PolicyError("UV challenge requires --uv-executable")
    path = Path(executable).expanduser()
    if not path.is_absolute():
        raise ValidationError("UV executable must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise ValidationError("UV executable is not a regular file")
        if resolved.stat().st_mode & 0o002:
            raise ValidationError("UV executable must not be world-writable")
    except OSError as exc:
        raise ValidationError("UV executable does not exist or cannot be accessed") from exc
    if not os.access(resolved, os.X_OK):
        raise ValidationError("UV executable is not executable")

    # Preserve desktop/biometric-session variables but never pass Okta
    # activation tokens, state passphrases, FCM tokens, or other Okta secrets.
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("OKTA_")
    }
    try:
        process = subprocess.Popen(
            [str(resolved)],
            stdin=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        )
    except OSError as exc:
        raise PolicyError("Cannot start external user verification") from exc
    try:
        result = process.wait()
    except KeyboardInterrupt:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        raise
    if result not in (0, 1):
        raise PolicyError(
            f"External user verification returned unsupported exit status {result}; no response was signed"
        )
    return result
