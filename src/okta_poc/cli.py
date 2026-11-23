from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import stat
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .challenge import (
    ChallengeValidator,
    ValidatedChallenge,
    build_response,
    parse_pending_envelopes,
    submit_response,
)
from .crypto import pending_assertion
from .enrollment import (
    delete_enrollment,
    discover,
    enrollment_body,
    new_preparation,
    parse_enrollment_response,
    update_enrollment,
)
from .errors import (
    ApiError,
    PoCError,
    PolicyError,
    StateError,
    TransportError,
    ValidationError,
)
from .fcm import (
    FcmReceiver,
    interactive_decision,
    register_fcm_device,
    run_external_decision,
)
from .http import HttpClient
from .models import EnrollmentRecord, State
from .qr import decode_activation_qr, parse_activation_uri
from .storage import StateStore
from .uv import run_external_uv

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_STATE = Path(os.environ.get("OKTA_POC_STATE", "~/.local/share/okta-poc/state.json"))
_DEFAULT_FCM_RECEIVER = Path(os.environ.get(
    "OKTA_POC_FCM_RECEIVER",
    str(_PROJECT_ROOT / "fcm-receiver/example/target/debug/example"),
))
_DEFAULT_FCM_DEVICE = Path(os.environ.get(
    "OKTA_POC_FCM_DEVICE",
    str(_PROJECT_ROOT / "live-captures/okta-fcm-device-android.json"),
))
_DEFAULT_FCM_TOKEN_OUT = Path(os.environ.get(
    "OKTA_POC_FCM_TOKEN_OUT", "/dev/shm/okta-poc-okta-fcm-token"
))


def _state_password(store: StateStore, *, creating: bool = False) -> str:
    if store.plaintext:
        return ""
    password = os.environ.pop("OKTA_POC_STATE_PASSWORD", None)
    if password is None:
        if not sys.stdin.isatty():
            raise StateError(
                "Set OKTA_POC_STATE_PASSWORD for non-interactive use; never pass it as a CLI argument"
            )
        password = getpass.getpass("New state passphrase: " if creating else "State passphrase: ")
        if creating:
            confirmation = getpass.getpass("Confirm new state passphrase: ")
            if password != confirmation:
                raise StateError("State passphrases do not match")
    if creating and len(password) < 12:
        raise StateError("New state passphrase must contain at least 12 characters")
    if not password:
        raise StateError("State passphrase must not be empty")
    return password


def _read_push_token(args: argparse.Namespace) -> str | None:
    environment_token = os.environ.pop("OKTA_FCM_TOKEN", None)
    token_path = getattr(args, "fcm_token_file", None)
    if token_path is None:
        return environment_token
    if environment_token is not None:
        raise ValidationError("--fcm-token-file conflicts with OKTA_FCM_TOKEN")
    try:
        resolved = token_path.expanduser().resolve(strict=True)
        info = os.lstat(resolved)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError("FCM token file is not a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValidationError("FCM token file must have mode 0600")
        if not 0 < info.st_size <= 16384:
            raise ValidationError("FCM token file is empty or too large")
        value = resolved.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError("FCM token file cannot be read") from exc
    if not value:
        raise ValidationError("FCM token file is empty")
    return value


def _select_enrollment(state: State, enrollment_id: str | None) -> EnrollmentRecord:
    if enrollment_id:
        try:
            return state.enrollments[enrollment_id]
        except KeyError as exc:
            raise StateError("No local enrollment has the requested ID") from exc
    if len(state.enrollments) != 1:
        raise StateError(
            "Select an enrollment with --enrollment; use the list command to see local IDs"
        )
    return next(iter(state.enrollments.values()))


def _confirm(prompt: str, *, assume_yes: bool) -> None:
    if assume_yes:
        return
    if not sys.stdin.isatty():
        raise PolicyError("Confirmation required; use --yes only after reviewing the request")
    answer = input(prompt)
    if answer.strip().lower() not in ("y", "yes"):
        raise PolicyError("Operation cancelled; no signed response was submitted")


def _print_challenge(challenge: ValidatedChallenge, state: State) -> None:
    expires = datetime.fromtimestamp(challenge.expires_at, UTC).isoformat()
    print(f"Transaction: {challenge.transaction_id}")
    print(f"  Status: cryptographically validated; expires {expires}")
    if challenge.is_expired():
        print("  Expired: yes; a response will not be submitted")
    app_name = challenge.claims.get("appInstanceName")
    if isinstance(app_name, str):
        print(f"  Application: {app_name}")
    labels = (
        ("clientOS", "Client OS"),
        ("clientLocation", "Client location"),
        ("transactionTime", "Transaction time"),
    )
    for key, label in labels:
        value = challenge.context.get(key)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            print(f"  {label}: {value}")
    print(f"  User verification: {challenge.user_verification}")
    print(f"  User mediation: {challenge.user_mediation}")
    if not challenge.audience_bound:
        print("  Audience: present but NOT policy-bound (explicit compatibility mode)")
    if challenge.legacy_v1:
        print("  Profile: legacy-v1 (request omitted methodEnrollmentId; local method binding used)")
    if challenge.number_matching:
        print("  Number matching: present; approval is unsupported in this PoC")
    previous = state.transaction(challenge.enrollment_id, challenge.transaction_id)
    if previous:
        print(f"  Local response state: {previous.get('state', 'UNKNOWN')}")


def _poll(
    enrollment: EnrollmentRecord,
    http: HttpClient,
    *,
    now: int | None = None,
) -> tuple[list[ValidatedChallenge], list[str]]:
    assertion = pending_assertion(enrollment, now=int(time.time()) if now is None else now)
    value = http.get_json(
        enrollment.pending_challenge_uri,
        headers={
            "Authorization": f"SSWS {assertion}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    compact_values = parse_pending_envelopes(value)
    validator = ChallengeValidator(enrollment, http)
    challenges: dict[str, ValidatedChallenge] = {}
    errors: list[str] = []
    for index, compact in enumerate(compact_values):
        try:
            challenge = validator.validate(compact, now=now)
            challenges.setdefault(challenge.transaction_id, challenge)
        except PoCError as exc:
            errors.append(f"item {index + 1}: {exc}")
    return sorted(challenges.values(), key=lambda item: item.expires_at), errors


def cmd_enroll(args: argparse.Namespace) -> int:
    store = StateStore(args.state, plaintext=args.plaintext_state)
    creating = not store.exists
    password = _state_password(store, creating=creating)
    environment_uri = os.environ.pop("OKTA_QR_URI", None)
    if args.qr_image is not None:
        if environment_uri is not None:
            raise ValidationError("--qr-image conflicts with OKTA_QR_URI")
        uri = decode_activation_qr(args.qr_image)
    else:
        uri = environment_uri
        if uri is None:
            if not sys.stdin.isatty():
                raise ValidationError(
                    "Provide --qr-image or set OKTA_QR_URI for non-interactive enrollment; "
                    "do not put the QR URI in shell arguments"
                )
            uri = getpass.getpass("Okta Verify activation URI (hidden): ")
    activation = parse_activation_uri(uri)
    push_token = _read_push_token(args)
    if push_token is not None and not push_token:
        push_token = None
    if push_token is not None and args.without_push_token:
        raise ValidationError("A supplied FCM token conflicts with --without-push-token")
    if push_token is None and not args.without_push_token:
        raise ValidationError(
            "Provide a real token in OKTA_FCM_TOKEN or explicitly choose --without-push-token for polling-only testing"
        )

    http = HttpClient()
    with store.locked():
        state = store.load(password, create=True)
        if any(
            item.org_id and item.authenticator_id == activation.authenticator_id
            and item.org_url == activation.org_url
            for item in state.enrollments.values()
        ):
            raise PolicyError("This authenticator already has a local enrollment in the state file")
        discovery = discover(
            activation,
            http,
            allow_missing_audience=args.allow_missing_policy_audience,
        )
        if discovery.policy_user_verification == "REQUIRED" and not args.with_uv:
            raise PolicyError("The policy requires UV; retry this fresh enrollment with --with-uv")
        preparation = state.preparations.get(discovery.preparation_key)
        if preparation is not None and not discovery.matches(preparation):
            raise StateError(
                "Saved enrollment keys belong to a different policy; use a separate --state file rather than replacing them"
            )
        if preparation is not None and preparation.jwk_profile != args.jwk_profile:
            raise StateError(
                "Saved enrollment keys use another JWK profile; retry with the original profile or a separate state file"
            )
        if preparation is not None and (preparation.uv_key is not None) != args.with_uv:
            raise StateError(
                "Saved enrollment keys use another UV mode; retry with the original mode or a separate state file"
            )
        reused = preparation is not None
        if preparation is None:
            preparation = new_preparation(
                discovery,
                jwk_profile=args.jwk_profile,
                display_name=args.display_name,
                with_uv=args.with_uv,
            )
        profile = preparation.device_profile
        print("Experimental independent client; this is not official Okta Verify.")
        print(f"Organization: {discovery.org_url}")
        print(f"Host platform: {profile.platform}; OS version: {profile.os_version}")
        print(f"Display name sent to Okta: {profile.display_name}")
        print(f"JWK compatibility profile: {preparation.jwk_profile}")
        print(f"UV key: {'included in enrollment' if preparation.uv_key else 'not included'}")
        print("Device profile: Android compatibility (default; no hardware/attestation claims)")
        if discovery.expected_audience is None:
            print("WARNING: policy has no OAuth audience; signed challenge aud cannot be policy-bound")
        print(f"Push token: {'real token supplied via environment' if push_token else 'omitted (polling-only experiment)'}")
        print(f"Keys: {'reusing saved pre-enrollment keys' if reused else 'new RSA-2048 software keys'}")
        _confirm("Continue with one enrollment POST? [y/N] ", assume_yes=args.yes)
        # Persist keys before the only enrollment POST. A timeout never causes an
        # automatic retry or key regeneration.
        state.preparations[discovery.preparation_key] = preparation
        store.save(state, password)
        response = http.post_json(
            preparation.enroll_uri,
            enrollment_body(preparation, push_token),
            headers={"Authorization": f"OTDT {activation.token}"},
            expected=(200, 201),
        ).json()
        enrollment = parse_enrollment_response(response, preparation)
        state.enrollments[enrollment.enrollment_id] = enrollment
        del state.preparations[discovery.preparation_key]
        store.save(state, password)
        if store.plaintext:
            print("Enrollment response validated and saved in PLAINTEXT TEST state (mode 0600).")
        else:
            print("Enrollment response validated and saved in encrypted state.")
        print(f"Enrollment ID: {enrollment.enrollment_id}")
        print(f"Push method ID: {enrollment.method_enrollment_id}")
        print("Next: start a sign-in for this test user, then run okta-poc poll.")
        return 0


def cmd_delete_enrollment(args: argparse.Namespace) -> int:
    store = StateStore(args.state)
    password = _state_password(store)
    with store.locked():
        state = store.load(password)
        if args.all:
            targets = list(state.enrollments.values())
        else:
            targets = [_select_enrollment(state, args.enrollment)]
        if not targets:
            print("No completed enrollments require server cleanup.")
            return 0
        print(f"Server-side enrollments selected for deletion: {len(targets)}")
        for enrollment in targets:
            print(f"  {enrollment.enrollment_id} at {enrollment.org_url}")
        _confirm(
            "Permanently delete the selected server enrollments and their local records? [y/N] ",
            assume_yes=args.yes,
        )
        http = HttpClient()
        for enrollment in targets:
            result = delete_enrollment(enrollment, http, now=int(time.time()))
            # Save after every definitive result. A later failure must not roll
            # back cleanup progress or discard keys for records still present.
            state.enrollments.pop(enrollment.enrollment_id, None)
            state.transactions.pop(enrollment.enrollment_id, None)
            store.save(state, password)
            print(f"{enrollment.enrollment_id}: {result}; local record removed")
    return 0


def cmd_update_push_token(args: argparse.Namespace) -> int:
    push_token = _read_push_token(args)
    if not push_token:
        raise ValidationError("Provide a real token with OKTA_FCM_TOKEN or --fcm-token-file")
    store = StateStore(args.state)
    password = _state_password(store)
    with store.locked():
        state = store.load(password)
        enrollment = _select_enrollment(state, args.enrollment)
        print(f"Enrollment: {enrollment.enrollment_id}")
        print(f"Push method: {enrollment.method_enrollment_id}")
        print("Replacement FCM token supplied; its value will not be logged or persisted in Okta state.")
        _confirm("Continue with the enrollment update? [y/N] ", assume_yes=args.yes)
        updated = update_enrollment(
            enrollment,
            HttpClient(),
            push_token=push_token,
            now=int(time.time()),
        )
        state.enrollments[updated.enrollment_id] = updated
        store.save(state, password)
        print("Enrollment update validated; trigger a sign-in to test actual FCM delivery.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    store = StateStore(args.state)
    password = _state_password(store)
    with store.locked():
        state = store.load(password)
        if not state.enrollments:
            print("No completed enrollments.")
        for enrollment in state.enrollments.values():
            print(f"Enrollment: {enrollment.enrollment_id}")
            print(f"  Organization: {enrollment.org_url}")
            print(f"  Authenticator: {enrollment.authenticator_id}")
            print(f"  Push method: {enrollment.method_enrollment_id}")
            if enrollment.uv_key:
                print(f"  UV key: {'enrolled' if enrollment.uv_enrolled else 'pending update'}")
            if enrollment.username:
                print(f"  User: {enrollment.username}")
        if state.preparations:
            print(f"Unresolved pre-enrollment key sets: {len(state.preparations)}")
    return 0


def cmd_poll(args: argparse.Namespace) -> int:
    store = StateStore(args.state)
    password = _state_password(store)
    with store.locked():
        state = store.load(password)
        enrollment = _select_enrollment(state, args.enrollment)
        challenges, errors = _poll(enrollment, HttpClient())
        for challenge in challenges:
            _print_challenge(challenge, state)
        for error in errors:
            print(f"Rejected pending {error}", file=sys.stderr)
        if not challenges and not errors:
            print("No pending challenges.")
        elif not challenges and errors:
            return 1
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    store = StateStore(args.state)
    password = _state_password(store)
    seen: set[str] = set()
    print(f"Polling every {args.interval} seconds; press Ctrl+C to stop. No automatic approval is performed.")
    while True:
        wait_for = args.interval
        try:
            with store.locked():
                state = store.load(password)
                enrollment = _select_enrollment(state, args.enrollment)
                challenges, errors = _poll(enrollment, HttpClient())
                for challenge in challenges:
                    if challenge.transaction_id not in seen:
                        _print_challenge(challenge, state)
                        seen.add(challenge.transaction_id)
                for error in errors:
                    print(f"Rejected pending {error}", file=sys.stderr)
        except ApiError as exc:
            print(f"Polling error: {exc}", file=sys.stderr)
            if exc.status == 429 and exc.retry_after and exc.retry_after.isdigit():
                wait_for = max(wait_for, min(int(exc.retry_after), 300))
        except PoCError as exc:
            print(f"Polling error: {exc}", file=sys.stderr)
        time.sleep(wait_for)


def _check_decision(
    challenge: ValidatedChallenge,
    *,
    approve: bool,
    now: int,
    uv_available: bool,
) -> None:
    if challenge.is_expired(now):
        raise ValidationError("Challenge has expired; start a new sign-in and poll again")
    if approve and challenge.number_matching:
        raise PolicyError("Number matching is not implemented; approve in the official client")
    if (
        approve
        and challenge.user_verification in ("PREFERRED", "REQUIRED")
        and not uv_available
    ):
        raise PolicyError(
            "This challenge requires user verification; enroll with --with-uv and provide --uv-executable"
        )


def _submission_error_state(status: int) -> str:
    # Only deterministic client/policy rejections are final. Redirects,
    # unexpected 2xx, rate limits, and server errors may have processed the JWS.
    if 400 <= status < 500 and status != 429:
        return "FAILED_FINAL"
    return "UNKNOWN_RETRYABLE"


def _submit_challenge_response(
    store: StateStore,
    password: str,
    state: State,
    enrollment: EnrollmentRecord,
    challenge: ValidatedChallenge,
    *,
    approve: bool,
    uv_executable: str | None,
    retry_unknown: bool,
    assume_yes: bool,
    display_challenge: bool = True,
) -> int:
    """Sign and submit one validated challenge while the state lock is held."""

    decision = "APPROVE" if approve else "DENY"
    previous = state.transaction(enrollment.enrollment_id, challenge.transaction_id)
    if previous:
        previous_state = previous.get("state")
        if previous_state == "COMPLETED":
            raise PolicyError("This transaction already has a submitted response")
        if previous_state == "FAILED_FINAL":
            raise PolicyError("This transaction previously received a final server rejection")
        if previous_state in ("SUBMITTING", "UNKNOWN_RETRYABLE") and not retry_unknown:
            raise PolicyError(
                "The previous submission outcome is unknown; poll to reconcile, then explicitly use --retry-unknown to try again"
            )
    now = int(time.time())
    use_uv = approve and challenge.user_verification in ("PREFERRED", "REQUIRED")
    uv_available = not use_uv or (
        enrollment.uv_key is not None
        and enrollment.uv_enrolled
        and bool(uv_executable)
    )
    _check_decision(
        challenge,
        approve=approve,
        now=now,
        uv_available=uv_available,
    )
    if display_challenge:
        _print_challenge(challenge, state)
    uv_verified = False
    if use_uv:
        print("Calling the external UV provider; no response will be signed unless it exits 0.")
        result = run_external_uv(uv_executable)
        if result == 1:
            raise PolicyError("External user verification failed; no response was submitted")
        uv_verified = True
    else:
        _confirm(
            f"Type yes to {decision.lower()} this validated transaction: ",
            assume_yes=assume_yes,
        )
    compact, omitted = build_response(
        enrollment,
        challenge,
        approve=approve,
        now=now,
        use_uv=use_uv,
        uv_verified=uv_verified,
    )
    if omitted:
        print(
            "Warning: requested signals unavailable on this host and omitted: " + ", ".join(omitted),
            file=sys.stderr,
        )
    state.set_transaction(
        enrollment.enrollment_id, challenge.transaction_id, "SUBMITTING", decision=decision
    )
    store.save(state, password)
    try:
        response = submit_response(HttpClient(), enrollment, challenge, compact)
    except ApiError as exc:
        state.set_transaction(
            enrollment.enrollment_id,
            challenge.transaction_id,
            _submission_error_state(exc.status),
            decision=decision,
            http_status=exc.status,
        )
        store.save(state, password)
        raise
    except TransportError:
        state.set_transaction(
            enrollment.enrollment_id,
            challenge.transaction_id,
            "UNKNOWN_RETRYABLE",
            decision=decision,
        )
        store.save(state, password)
        raise
    state.set_transaction(
        enrollment.enrollment_id,
        challenge.transaction_id,
        "COMPLETED",
        decision=decision,
        http_status=response.status,
    )
    store.save(state, password)
    print(f"Response submitted (HTTP {response.status}); this does not guarantee completed sign-in.")
    return 0


def cmd_respond(args: argparse.Namespace, *, approve: bool) -> int:
    store = StateStore(args.state)
    password = _state_password(store)
    with store.locked():
        state = store.load(password)
        enrollment = _select_enrollment(state, args.enrollment)
        challenges, errors = _poll(enrollment, HttpClient())
        challenge = next(
            (item for item in challenges if item.transaction_id == args.transaction_id), None
        )
        if challenge is None:
            for error in errors:
                print(f"Rejected pending {error}", file=sys.stderr)
            raise ValidationError(
                "No valid pending challenge has that transaction ID; start a new sign-in and poll"
            )
        return _submit_challenge_response(
            store,
            password,
            state,
            enrollment,
            challenge,
            approve=approve,
            uv_executable=args.uv_executable,
            retry_unknown=args.retry_unknown,
            assume_yes=args.yes,
        )


def _register_and_maybe_update(
    args: argparse.Namespace,
    store: StateStore,
    password: str,
) -> tuple[str, bool]:
    token = register_fcm_device(args.receiver, args.fcm_device, args.fcm_token_out)
    if not store.exists:
        return token, False
    with store.locked():
        state = store.load(password)
        if not state.enrollments:
            return token, False
        enrollment = _select_enrollment(state, args.enrollment)
        updated = update_enrollment(
            enrollment,
            HttpClient(),
            push_token=token,
            now=int(time.time()),
        )
        state.enrollments[updated.enrollment_id] = updated
        store.save(state, password)
        print(f"FCM token attached to enrollment {updated.enrollment_id}", flush=True)
        return token, True


def cmd_fcm_register(args: argparse.Namespace) -> int:
    store = StateStore(args.state)
    password = _state_password(store) if store.exists else ""
    _, updated = _register_and_maybe_update(args, store, password)
    if not updated:
        print(f"FCM credentials registered; token stored at {args.fcm_token_out} (not printed)")
        print("Use that token file as OKTA_FCM_TOKEN when creating an enrollment.")
    return 0


def cmd_fcm(args: argparse.Namespace) -> int:
    if not args.decision_executable and not sys.stdin.isatty():
        raise PolicyError(
            "Interactive FCM decisions require a terminal; non-interactive use requires --decision-executable"
        )
    store = StateStore(args.state)
    password = _state_password(store)
    with store.locked():
        state = store.load(password)
        _select_enrollment(state, args.enrollment)
    if not args.fcm_device.exists():
        _register_and_maybe_update(args, store, password)
    receiver = FcmReceiver(args.receiver, args.fcm_device, args.fcm_token_out)
    seen: set[str] = set()
    rejected: set[str] = set()
    print("Waiting for Okta FCM challenges; each will be validated before a decision.")
    while True:
        try:
            compact = receiver.receive()
        except PoCError as exc:
            print(f"FCM receive error: {exc}; reconnecting in 5 seconds", file=sys.stderr)
            time.sleep(5)
            continue
        digest = hashlib.sha256(compact.encode("ascii")).hexdigest()
        if digest in rejected:
            time.sleep(30)
            continue
        try:
            with store.locked():
                state = store.load(password)
                enrollment = _select_enrollment(state, args.enrollment)
            try:
                challenge = ChallengeValidator(enrollment, HttpClient()).validate(compact)
            except (ApiError, ValidationError, TransportError) as exc:
                rejected.add(digest)
                print(f"Rejected FCM challenge: {exc}; suppressing identical replays", file=sys.stderr)
                time.sleep(1)
                continue
            if challenge.transaction_id in seen:
                print(f"Ignoring duplicate FCM transaction: {challenge.transaction_id}", flush=True)
                time.sleep(5)
                continue
            seen.add(challenge.transaction_id)
            previous = state.transaction(enrollment.enrollment_id, challenge.transaction_id)
            if previous:
                print(
                    f"Transaction {challenge.transaction_id} already has local state "
                    f"{previous.get('state', 'UNKNOWN')}; no automatic retry",
                    flush=True,
                )
                time.sleep(5)
                continue
            _print_challenge(challenge, state)
            if args.decision_executable:
                decision = run_external_decision(args.decision_executable, challenge)
            else:
                decision = interactive_decision()
            print(f"Decision for transaction {challenge.transaction_id}: {decision}", flush=True)
            if decision == "quit":
                print("Leaving FCM mode; no response was submitted for the last transaction.", flush=True)
                return 0
            if decision == "skip":
                print(f"Skipped transaction {challenge.transaction_id}; no response was submitted", flush=True)
                time.sleep(1)
                continue
            with store.locked():
                state = store.load(password)
                enrollment = _select_enrollment(state, args.enrollment)
                _submit_challenge_response(
                    store,
                    password,
                    state,
                    enrollment,
                    challenge,
                    approve=decision == "approve",
                    uv_executable=args.uv_executable,
                    retry_unknown=False,
                    assume_yes=True,
                    display_challenge=False,
                )
        except StateError:
            raise
        except PoCError as exc:
            # Never turn a pushed decision or an uncertain submission into an
            # unattended retry. The next distinct push can still be handled.
            print(f"FCM transaction error: {exc}", file=sys.stderr)
            continue




def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="okta-poc",
        description="Experimental independent built-in Okta Verify push PoC (variant B only)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--state",
        type=Path,
        default=_DEFAULT_STATE,
        help="state file (encrypted by default; plaintext test files are auto-detected)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    enroll = commands.add_parser("enroll", help="discover policy and enroll once from a fresh QR")
    enroll.add_argument(
        "--qr-image",
        type=Path,
        help="decode the activation URI from a QR image without logging or persisting it",
    )
    enroll.add_argument(
        "--plaintext-state",
        action="store_true",
        help="TESTING ONLY: store private keys and identifiers unencrypted (file remains mode 0600)",
    )
    enroll.add_argument(
        "--fcm-token-file",
        type=Path,
        help="read the FCM token from a mode-0600 file instead of OKTA_FCM_TOKEN",
    )
    enroll.add_argument("--without-push-token", action="store_true", help="explicit polling-only experiment; omit pushToken")
    enroll.add_argument("--allow-missing-policy-audience", action="store_true", help="explicit Android-compatible experiment when settings.oauthClientId is absent")
    enroll.add_argument("--with-uv", action="store_true", help="include a UV key from initial enrollment")
    enroll.add_argument("--jwk-profile", choices=("android", "canonical"), default="android")
    enroll.add_argument("--display-name", help="truthful device display name (default: hostname)")
    enroll.add_argument("--yes", action="store_true", help="skip enrollment confirmation after review")
    enroll.set_defaults(handler=cmd_enroll)

    delete_command = commands.add_parser(
        "delete-enrollment",
        help="delete server-side PoC enrollment(s) before removing local records",
    )
    delete_target = delete_command.add_mutually_exclusive_group()
    delete_target.add_argument("--enrollment")
    delete_target.add_argument(
        "--all",
        action="store_true",
        help="delete every completed enrollment in this state file",
    )
    delete_command.add_argument(
        "--yes", action="store_true", help="skip deletion confirmation after review"
    )
    delete_command.set_defaults(handler=cmd_delete_enrollment)

    update_token = commands.add_parser(
        "update-push-token",
        help="replace an existing enrollment's FCM token without changing its keys",
    )
    update_token.add_argument("--enrollment")
    update_token.add_argument(
        "--fcm-token-file",
        type=Path,
        help="read the replacement FCM token from a mode-0600 file",
    )
    update_token.add_argument("--yes", action="store_true", help="skip update confirmation after review")
    update_token.set_defaults(handler=cmd_update_push_token)

    fcm_register = commands.add_parser(
        "fcm-register",
        help="create/load Android FCM credentials and attach the token when enrolled",
    )
    fcm_register.add_argument("--enrollment")
    fcm_register.add_argument(
        "--receiver",
        type=Path,
        default=_DEFAULT_FCM_RECEIVER,
        help="absolute path to the Android FCM receiver helper",
    )
    fcm_register.add_argument(
        "--fcm-device",
        type=Path,
        default=_DEFAULT_FCM_DEVICE,
        help="Android-check-in FCM credential file to create or reuse (mode 0600)",
    )
    fcm_register.add_argument(
        "--fcm-token-out",
        type=Path,
        default=_DEFAULT_FCM_TOKEN_OUT,
        help="secure token output file (mode 0600; value is not printed)",
    )
    fcm_register.set_defaults(handler=cmd_fcm_register)

    fcm = commands.add_parser(
        "fcm",
        help="wait for push challenges and decide each interactively or externally",
    )
    fcm.add_argument("--enrollment")
    fcm.add_argument(
        "--receiver",
        type=Path,
        default=_DEFAULT_FCM_RECEIVER,
        help="absolute path to the Android FCM receiver helper",
    )
    fcm.add_argument(
        "--fcm-device",
        type=Path,
        default=_DEFAULT_FCM_DEVICE,
        help="Android-check-in FCM credential file (mode 0600)",
    )
    fcm.add_argument(
        "--fcm-token-out",
        type=Path,
        default=_DEFAULT_FCM_TOKEN_OUT,
        help="secure token output file used during registration (mode 0600)",
    )
    fcm.add_argument(
        "--decision-executable",
        help="external decision program: JSON on stdin; exit 0=approve, 1=deny, 2=skip",
    )
    fcm.add_argument(
        "--uv-executable",
        help="absolute path to the trusted UV provider required for UV approvals",
    )
    fcm.set_defaults(handler=cmd_fcm)

    list_command = commands.add_parser("list", help="list local enrollments")
    list_command.set_defaults(handler=cmd_list)

    poll = commands.add_parser("poll", help="retrieve and validate pending challenges")
    poll.add_argument("--enrollment")
    poll.set_defaults(handler=cmd_poll)

    watch = commands.add_parser("watch", help="poll repeatedly without automatic approval")
    watch.add_argument("--enrollment")
    watch.add_argument("--interval", type=int, default=15, help="seconds between polls (5-300)")
    watch.set_defaults(handler=cmd_watch)

    for name, approve in (("approve", True), ("deny", False)):
        respond = commands.add_parser(name, help=f"re-poll, validate, confirm, and {name} one transaction")
        respond.add_argument("transaction_id")
        respond.add_argument("--enrollment")
        respond.add_argument("--retry-unknown", action="store_true", help="explicitly retry after an uncertain submission")
        respond.add_argument("--uv-executable", help="absolute path to the trusted external UV provider")
        respond.add_argument("--yes", action="store_true", help="skip response confirmation after reviewing context")
        respond.set_defaults(handler=cmd_respond, approve=approve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "watch" and not 5 <= args.interval <= 300:
        parser.error("watch --interval must be between 5 and 300 seconds")
    try:
        if args.command in ("approve", "deny"):
            return cmd_respond(args, approve=args.approve)
        return args.handler(args)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except PoCError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
