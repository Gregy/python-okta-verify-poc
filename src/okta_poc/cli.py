"""Command line interface: `okta-poc <command>`."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__
from .challenge import (
    Challenge,
    ChallengeExpired,
    ChallengeValidator,
    challenge_from_envelope,
    poll,
    sign_response,
    submit_response,
)
from .enrollment import delete, discover, enroll, update_push_token
from .errors import PoCError
from .external import external_decision, interactive_decision, verify_user
from .fcm import listen, register_device
from .http import HttpClient
from .qr import decode_qr_image, parse_activation_uri
from .state import Enrollment, State, Store

DEFAULT_STATE = Path(os.environ.get("OKTA_POC_STATE", "~/.local/share/okta-poc/state.json"))


# --- helpers -------------------------------------------------------------------


def _open_store(path: Path, *, create: bool = False, plaintext: bool = False) -> Store:
    """Plaintext only if asked for when creating, or if the file already is."""

    path = path.expanduser()
    if path.exists():
        plaintext = not Store.is_encrypted(path)
    elif not create:
        raise PoCError(f"No state file at {path}; run `okta-poc enroll` first")
    if plaintext:
        return Store(path, password=None)
    password = os.environ.pop("OKTA_POC_STATE_PASSWORD", None)
    if password is None:
        if not sys.stdin.isatty():
            raise PoCError("Set OKTA_POC_STATE_PASSWORD (or use a terminal) to unlock the state file")
        password = getpass.getpass("State passphrase: ")
        if not path.exists() and getpass.getpass("Repeat passphrase: ") != password:
            raise PoCError("Passphrases do not match")
    if not password:
        raise PoCError("State passphrase must not be empty")
    return Store(path, password)


def _select(state: State, enrollment_id: str | None) -> Enrollment:
    if enrollment_id:
        if enrollment_id not in state.enrollments:
            raise PoCError(f"No local enrollment {enrollment_id}; see `okta-poc list`")
        return state.enrollments[enrollment_id]
    if len(state.enrollments) != 1:
        raise PoCError("Choose an enrollment with --enrollment; see `okta-poc list`")
    return next(iter(state.enrollments.values()))


def _confirm(prompt: str, assume_yes: bool) -> None:
    if assume_yes:
        return
    if not sys.stdin.isatty():
        raise PoCError("Confirmation needed; rerun with --yes")
    if input(prompt + " [y/N] ").strip().lower() not in ("y", "yes"):
        raise PoCError("Cancelled")


def _print_challenge(challenge: Challenge, enrollment: Enrollment) -> None:
    info = challenge.summary()
    print(f"Transaction: {challenge.transaction_id}")
    print(f"  Validated; expires {info['expiresAt']}")
    for key, label in (
        ("appInstanceName", "Application"),
        ("clientOS", "Client OS"),
        ("clientLocation", "Client location"),
        ("transactionTime", "Transaction time"),
        ("userVerification", "User verification"),
    ):
        if info[key] is not None:
            print(f"  {label}: {info[key]}")
    if enrollment.expected_audience is None:
        print("  Audience: not checked (policy has no OAuth client ID)")
    if challenge.number_matching:
        print("  Number matching: not supported; approve in the official app")
    sys.stdout.flush()


def _respond(
    state: State,
    enrollment: Enrollment,
    challenge: Challenge,
    *,
    approve: bool,
    uv_executable: str | None,
) -> None:
    if challenge.transaction_id in state.responded:
        raise PoCError("Already responded to this transaction")
    uv_verified = False
    if approve and challenge.needs_uv:
        verify_user(uv_executable)
        uv_verified = True
    signed, omitted = sign_response(enrollment, challenge, approve=approve, uv_verified=uv_verified)
    # Recorded before sending (and saved even if sending fails): an answer whose
    # fate is unknown is never followed by a second, possibly different, one.
    state.mark_responded(challenge.transaction_id)
    submit_response(challenge, signed, HttpClient())
    if omitted:
        print("Requested device signals we cannot provide (omitted): " + ", ".join(omitted))
    print(f"{'Approval' if approve else 'Denial'} submitted; check that the sign-in completed.")


def _set_push_token(state: State, token: str) -> None:
    http = HttpClient()
    for enrollment in state.enrollments.values():
        update_push_token(enrollment, http, token)
        print(f"FCM token attached to enrollment {enrollment.enrollment_id}")


# --- commands --------------------------------------------------------------------


def cmd_enroll(args: argparse.Namespace) -> None:
    if args.qr_image:
        uri = decode_qr_image(args.qr_image)
    elif "OKTA_QR_URI" in os.environ:
        uri = os.environ.pop("OKTA_QR_URI")
    elif sys.stdin.isatty():
        uri = getpass.getpass("Activation URI from the QR code (hidden): ")
    else:
        raise PoCError("Pass --qr-image or set OKTA_QR_URI")
    activation = parse_activation_uri(uri)

    store = _open_store(args.state, create=True, plaintext=args.plaintext_state)
    with store.edit() as state:
        if any(item.authenticator_id == activation.authenticator_id and item.org_url == activation.org_url
               for item in state.enrollments.values()):
            raise PoCError("This state file already has an enrollment for this authenticator")
        http = HttpClient()
        policy = discover(activation, http, allow_missing_audience=args.allow_missing_policy_audience)
        if policy.user_verification == "REQUIRED" and not args.with_uv:
            raise PoCError("The policy requires user verification; rerun with --with-uv")
        if not args.without_push and state.fcm is None:
            print("Registering an FCM device for push delivery...")
            state.fcm = register_device()

        print("Experimental independent client; this is not the official Okta Verify.")
        print(f"Organization: {policy.org_url}")
        print(f"Device: Android profile, display name {args.display_name or 'from hostname'}")
        print(f"User-verification key: {'yes' if args.with_uv else 'no'}")
        print(f"Push: {'polling only' if args.without_push else 'FCM'}")
        if policy.expected_audience is None:
            print("WARNING: the policy has no OAuth client ID, so challenge audiences cannot be checked")
        _confirm("Enroll now?", args.yes)

        enrollment = enroll(
            policy, activation, http,
            push_token=None if args.without_push else state.fcm.token,
            with_uv=args.with_uv,
            display_name=args.display_name,
        )
        state.enrollments[enrollment.enrollment_id] = enrollment
    print(f"Enrolled {enrollment.enrollment_id} ({'plaintext' if store.password is None else 'encrypted'} state)")
    print("Next: run `okta-poc fcm` and start a sign-in.")


def cmd_fcm_register(args: argparse.Namespace) -> None:
    with _open_store(args.state).edit() as state:
        if not state.enrollments:
            raise PoCError("Nothing to register for; enroll first (enroll registers FCM itself)")
        state.fcm = register_device()
        _set_push_token(state, state.fcm.token)


def cmd_fcm(args: argparse.Namespace) -> None:
    if not args.decision_executable and not sys.stdin.isatty():
        raise PoCError("Without a terminal, pass --decision-executable")
    store = _open_store(args.state)
    state = store.read()
    enrollment = _select(state, args.enrollment)
    if state.fcm is None:
        with store.edit() as state:
            state.fcm = register_device()
            _set_push_token(state, state.fcm.token)
    validator = ChallengeValidator(enrollment, HttpClient())
    handled: set[str] = set()  # this session, including skipped ones
    for message in listen(state.fcm):
        try:
            if _handle_push(args, store, enrollment, validator, handled, message) == "quit":
                return
        except PoCError as exc:
            # Only this push is dropped; we never retry it automatically.
            print(f"Push not handled: {exc}", file=sys.stderr)


def _handle_push(
    args: argparse.Namespace,
    store: Store,
    enrollment: Enrollment,
    validator: ChallengeValidator,
    handled: set[str],
    message: dict[str, str],
) -> str:
    """Validate one FCM message, ask for a decision and answer it. Returns the decision."""

    try:
        challenge = validator.validate(challenge_from_envelope(message))
    except ChallengeExpired:
        print(f"Ignoring expired push {message.get('transactionId', '')}".rstrip(), flush=True)
        return "ignored"
    if challenge.transaction_id in handled or challenge.transaction_id in store.read().responded:
        print(f"Ignoring already handled transaction {challenge.transaction_id}", flush=True)
        return "ignored"
    if challenge.is_expired():
        print(f"Ignoring expired transaction {challenge.transaction_id}", flush=True)
        return "ignored"
    handled.add(challenge.transaction_id)
    _print_challenge(challenge, enrollment)
    if args.decision_executable:
        decision = external_decision(args.decision_executable, challenge)
    else:
        decision = interactive_decision()
    print(f"Decision: {decision}", flush=True)
    if decision in ("approve", "deny"):
        with store.edit() as state:
            _respond(state, enrollment, challenge, approve=decision == "approve",
                     uv_executable=args.uv_executable)
    return decision


def cmd_list(args: argparse.Namespace) -> None:
    state = _open_store(args.state).read()
    if not state.enrollments:
        print("No enrollments.")
    for enrollment in state.enrollments.values():
        print(f"Enrollment: {enrollment.enrollment_id}")
        print(f"  Organization: {enrollment.org_url}")
        print(f"  User: {enrollment.username or enrollment.user_id}")
        print(f"  Push method: {enrollment.method_enrollment_id}")
        print(f"  User-verification key: {'yes' if enrollment.uv_key else 'no'}")
    print(f"FCM device: {'registered' if state.fcm else 'none'}")


def cmd_poll(args: argparse.Namespace) -> None:
    state = _open_store(args.state).read()
    enrollment = _select(state, args.enrollment)
    challenges, errors = poll(enrollment, HttpClient())
    for challenge in challenges:
        _print_challenge(challenge, enrollment)
    for error in errors:
        print(f"Rejected pending {error}", file=sys.stderr)
    if not challenges and not errors:
        print("No pending challenges.")


def cmd_respond(args: argparse.Namespace) -> None:
    approve = args.command == "approve"
    with _open_store(args.state).edit() as state:
        enrollment = _select(state, args.enrollment)
        challenges, _ = poll(enrollment, HttpClient())
        challenge = next((item for item in challenges if item.transaction_id == args.transaction_id), None)
        if challenge is None:
            raise PoCError("No valid pending challenge has that transaction ID; run `okta-poc poll`")
        _print_challenge(challenge, enrollment)
        if not (approve and challenge.needs_uv):  # UV itself is the confirmation
            _confirm(f"{args.command.capitalize()} this sign-in?", args.yes)
        _respond(state, enrollment, challenge, approve=approve,
                 uv_executable=getattr(args, "uv_executable", None))


def cmd_delete(args: argparse.Namespace) -> None:
    with _open_store(args.state).edit() as state:
        targets = list(state.enrollments.values()) if args.all else [_select(state, args.enrollment)]
        for enrollment in targets:
            print(f"Will delete {enrollment.enrollment_id} at {enrollment.org_url}")
        _confirm("Delete these enrollments in Okta and locally?", args.yes)
        http = HttpClient()
        for enrollment in targets:
            result = delete(enrollment, http)
            del state.enrollments[enrollment.enrollment_id]  # saved even if a later one fails
            print(f"{enrollment.enrollment_id}: {result}")


# --- argument parsing --------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="okta-poc", description="Experimental independent Okta Verify push client"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE, help="state file (default: %(default)s)")
    commands = parser.add_subparsers(dest="command", required=True)

    which = argparse.ArgumentParser(add_help=False)
    which.add_argument("--enrollment", help="enrollment ID (needed only if the state has several)")
    yes = argparse.ArgumentParser(add_help=False)
    yes.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    uv = argparse.ArgumentParser(add_help=False)
    uv.add_argument("--uv-executable", help="absolute path of the user-verification provider (exit 0 = verified)")

    command = commands.add_parser("enroll", parents=[yes], help="enroll from an activation QR code")
    command.add_argument("--qr-image", type=Path, help="screenshot of the QR code (or set OKTA_QR_URI)")
    command.add_argument("--plaintext-state", action="store_true", help="TESTING ONLY: do not encrypt a new state file")
    command.add_argument("--with-uv", action="store_true", help="also enroll a user-verification key")
    command.add_argument("--without-push", action="store_true", help="no FCM; use poll/approve/deny only")
    command.add_argument("--allow-missing-policy-audience", action="store_true",
                         help="accept a policy without settings.oauthClientId (challenge aud cannot be checked)")
    command.add_argument("--display-name", help="device name shown in Okta (default: hostname)")
    command.set_defaults(handler=cmd_enroll)

    command = commands.add_parser("fcm", parents=[which, uv], help="wait for pushes and decide each one")
    command.add_argument("--decision-executable",
                         help="program that gets the challenge as JSON on stdin; exit 0=approve 1=deny 2=skip")
    command.set_defaults(handler=cmd_fcm)

    command = commands.add_parser("fcm-register", help="register a new FCM device and attach its token to all enrollments")
    command.set_defaults(handler=cmd_fcm_register)

    command = commands.add_parser("list", help="show local enrollments")
    command.set_defaults(handler=cmd_list)

    command = commands.add_parser("poll", parents=[which], help="fetch and validate pending challenges")
    command.set_defaults(handler=cmd_poll)

    for name, parents in (("approve", [which, yes, uv]), ("deny", [which, yes])):
        command = commands.add_parser(name, parents=parents, help=f"{name} one pending challenge")
        command.add_argument("transaction_id")
        command.set_defaults(handler=cmd_respond)

    command = commands.add_parser("delete-enrollment", parents=[which, yes], help="delete enrollment(s) in Okta and locally")
    command.add_argument("--all", action="store_true", help="delete every enrollment in the state file")
    command.set_defaults(handler=cmd_delete)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.handler(args)
        return 0
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except PoCError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
