from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from .challenge import ValidatedChallenge
from .errors import PolicyError, TransportError, ValidationError

Decision = Literal["approve", "deny", "skip", "quit"]
_MAX_CHALLENGE = 64 * 1024
_JWT_LIKE = re.compile(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_LONG_SECRET_LIKE = re.compile(r"\b[A-Za-z0-9_-]{40,}\b")


def _executable(path_value: str | Path, label: str) -> Path:
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        raise ValidationError(f"{label} must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise ValidationError(f"{label} is not a regular file")
        if resolved.stat().st_mode & 0o002:
            raise ValidationError(f"{label} must not be world-writable")
    except OSError as exc:
        raise ValidationError(f"{label} does not exist or cannot be accessed") from exc
    if not os.access(resolved, os.X_OK):
        raise ValidationError(f"{label} is not executable")
    return resolved


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _safe_receiver_line(line: str) -> str:
    value = _JWT_LIKE.sub("[redacted-jws]", line.strip())
    value = _LONG_SECRET_LIKE.sub("[redacted]", value)
    return value[:300]


class FcmReceiver:
    """Run the Android FCM helper until it yields one securely saved JWS."""

    def __init__(
        self,
        executable: str | Path,
        device: str | Path,
        token_path: str | Path | None = None,
    ) -> None:
        self.executable = _executable(executable, "FCM receiver")
        try:
            self.device = Path(device).expanduser().resolve(strict=True)
            info = self.device.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValidationError("FCM device credential path is not a regular file")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise ValidationError("FCM device credentials must have mode 0600")
            if not 0 < info.st_size <= 65536:
                raise ValidationError("FCM device credentials are empty or too large")
        except OSError as exc:
            raise ValidationError("FCM device credentials cannot be accessed") from exc
        self.challenge_path = Path(f"/dev/shm/okta-poc-fcm-challenge-{os.getpid()}.jws")
        self.token_path = Path(token_path) if token_path is not None else Path(
            os.environ.get("OKTA_POC_FCM_TOKEN_OUT", "/dev/shm/okta-poc-okta-fcm-token")
        )
        self.seen_path = self.device.with_name(self.device.stem + "-seen.json")
        self._seen_logs: set[str] = set()

    def _environment(self) -> dict[str, str]:
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("OKTA_")
        }
        environment.update({
            "OKTA_POC_FCM_DEVICE": str(self.device),
            "OKTA_POC_FCM_CHALLENGE_OUT": str(self.challenge_path),
            "OKTA_POC_FCM_TOKEN_OUT": str(self.token_path),
            "OKTA_POC_FCM_SEEN": str(self.seen_path),
        })
        return environment

    def _read_and_remove_challenge(self) -> str:
        try:
            info = self.challenge_path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValidationError("FCM challenge path is not a regular file")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise ValidationError("FCM challenge file permissions are too open")
            if not 0 < info.st_size <= _MAX_CHALLENGE:
                raise ValidationError("FCM challenge is empty or too large")
            compact = self.challenge_path.read_text(encoding="ascii").strip()
        except FileNotFoundError as exc:
            raise TransportError("FCM receiver reported a challenge without writing it") from exc
        except (OSError, UnicodeDecodeError) as exc:
            raise ValidationError("FCM challenge could not be read") from exc
        finally:
            self.challenge_path.unlink(missing_ok=True)
        if not compact:
            raise ValidationError("FCM challenge is empty")
        return compact

    def receive(self) -> str:
        self.challenge_path.unlink(missing_ok=True)
        try:
            process = subprocess.Popen(
                [str(self.executable)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=self._environment(),
                text=True,
                bufsize=1,
                start_new_session=True,
            )
        except OSError as exc:
            raise TransportError("Cannot start FCM receiver") from exc
        received = False
        try:
            assert process.stdout is not None
            for line in process.stdout:
                if line.startswith("OKTA_CHALLENGE_RECEIVED"):
                    received = True
                    print("FCM challenge received; validating before any decision", flush=True)
                    break
                safe = _safe_receiver_line(line)
                if safe and safe not in self._seen_logs:
                    self._seen_logs.add(safe)
                    print(f"FCM receiver: {safe}", flush=True)
            if not received:
                status = process.wait()
                raise TransportError(
                    f"FCM receiver exited before delivering a challenge (status {status})"
                )
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                _terminate(process)
                raise TransportError("FCM receiver did not exit after delivering a challenge")
            return self._read_and_remove_challenge()
        except KeyboardInterrupt:
            _terminate(process)
            self.challenge_path.unlink(missing_ok=True)
            raise
        except Exception:
            _terminate(process)
            self.challenge_path.unlink(missing_ok=True)
            raise
        finally:
            if process.stdout is not None:
                process.stdout.close()


def register_fcm_device(
    executable: str | Path,
    device: str | Path,
    token_path: str | Path,
) -> str:
    """Create/load Android FCM credentials and return their token securely."""

    resolved = _executable(executable, "FCM receiver")
    device_path = Path(device).expanduser().resolve()
    device_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if device_path.exists():
        info = device_path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValidationError("Existing FCM device credentials must be a regular mode-0600 file")
    token = Path(token_path).expanduser().resolve()
    if not token.parent.is_dir():
        raise ValidationError("FCM token output directory does not exist")
    token.unlink(missing_ok=True)
    seen = device_path.with_name(device_path.stem + "-seen.json")
    challenge = Path(f"/dev/shm/okta-poc-fcm-register-{os.getpid()}.jws")
    challenge.unlink(missing_ok=True)
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("OKTA_")
    }
    environment.update({
        "OKTA_POC_FCM_DEVICE": str(device_path),
        "OKTA_POC_FCM_CHALLENGE_OUT": str(challenge),
        "OKTA_POC_FCM_TOKEN_OUT": str(token),
        "OKTA_POC_FCM_SEEN": str(seen),
    })
    try:
        process = subprocess.Popen(
            [str(resolved)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
    except OSError as exc:
        raise TransportError("Cannot start FCM registration") from exc
    try:
        assert process.stdout is not None
        for line in process.stdout:
            if line.startswith("FCM token written to"):
                _terminate(process)
                try:
                    info = token.lstat()
                    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                        raise ValidationError("FCM token must be a regular mode-0600 file")
                    if not 0 < info.st_size <= 16384:
                        raise ValidationError("FCM token is empty or too large")
                    value = token.read_text(encoding="ascii").strip()
                except OSError as exc:
                    raise TransportError("FCM registration did not create a readable token") from exc
                if not value:
                    raise ValidationError("FCM token is empty")
                return value
            safe = _safe_receiver_line(line)
            if safe:
                print(f"FCM registration: {safe}", flush=True)
        status = process.wait()
        raise TransportError(f"FCM registration exited before returning a token (status {status})")
    except KeyboardInterrupt:
        _terminate(process)
        raise
    except Exception:
        _terminate(process)
        raise
    finally:
        challenge.unlink(missing_ok=True)
        if process.stdout is not None:
            process.stdout.close()


def transaction_info(challenge: ValidatedChallenge) -> dict[str, object]:
    context = challenge.context
    return {
        "transactionId": challenge.transaction_id,
        "enrollmentId": challenge.enrollment_id,
        "issuer": challenge.issuer,
        "verificationUri": challenge.verification_uri,
        "expiresAt": datetime.fromtimestamp(challenge.expires_at, UTC).isoformat(),
        "transactionType": challenge.transaction_type,
        "userVerification": challenge.user_verification,
        "userMediation": challenge.user_mediation,
        "appInstanceName": challenge.claims.get("appInstanceName"),
        "clientOS": context.get("clientOS"),
        "clientLocation": context.get("clientLocation"),
        "transactionTime": context.get("transactionTime"),
        "numberMatching": challenge.number_matching,
        "audienceBound": challenge.audience_bound,
    }


def run_external_decision(
    executable: str | Path,
    challenge: ValidatedChallenge,
) -> Decision:
    """Return approve/deny/skip from a trusted decision program.

    The program receives one JSON object on stdin. Exit 0 approves, 1 denies,
    and 2 skips without a response. All other statuses fail closed.
    """

    resolved = _executable(executable, "Decision executable")
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("OKTA_")
    }
    payload = json.dumps(transaction_info(challenge), ensure_ascii=False) + "\n"
    try:
        process = subprocess.Popen(
            [str(resolved)],
            stdin=subprocess.PIPE,
            env=environment,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise PolicyError("Cannot start external decision provider") from exc
    try:
        process.communicate(payload)
    except KeyboardInterrupt:
        _terminate(process)
        raise
    except OSError as exc:
        _terminate(process)
        raise PolicyError("External decision provider closed unexpectedly") from exc
    result = process.returncode
    if result == 0:
        return "approve"
    if result == 1:
        return "deny"
    if result == 2:
        return "skip"
    raise PolicyError(
        f"External decision provider returned unsupported exit status {result}; no response was signed"
    )


def interactive_decision() -> Decision:
    while True:
        try:
            answer = input("Decision [a]pprove/[d]eny/[s]kip/[q]uit: ").strip().lower()
        except EOFError:
            return "quit"
        if answer in ("a", "approve"):
            return "approve"
        if answer in ("d", "deny"):
            return "deny"
        if answer in ("s", "skip"):
            return "skip"
        if answer in ("q", "quit"):
            return "quit"
        print("Choose a, d, s, or q.")
