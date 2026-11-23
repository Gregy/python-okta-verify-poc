# Okta Verify push PoC

An independent, experimental Okta Verify client written in Python. It enrolls from an activation QR code, receives push challenges over Firebase Cloud Messaging (FCM) the way the Android app does, and approves or denies them with signed responses, optionally with user verification (UV).

**This is not official Okta Verify and not a production MFA replacement.** Use it only with an authorized test tenant and keep a recovery method. It presents the Android app's protocol profile (no hardware or attestation claims). The bundled UV helpers are mocks for protocol tests; real biometric UV needs a trusted provider.

## How it works

| Module | What it does |
|---|---|
| `qr.py` | Reads the `oktaverify://` activation URI from a QR screenshot |
| `enrollment.py` | Reads the org's Okta Verify policy, enrolls, updates the push token, deletes |
| `fcm.py` | Registers an emulated Android device with Google FCM and keeps a connection open to receive pushes |
| `challenge.py` | Validates the org-signed challenge JWT, then signs our approve/deny answer |
| `external.py` | Runs your decision and UV helper programs |
| `state.py` | Keys, enrollments and FCM credentials in one state file (encrypted by default) |
| `cli.py` | The `okta-poc` commands |

## Docker

```bash
docker build -t okta-poc .

# Enroll: start Okta Verify setup in the tenant, save the QR code as QR.png.
docker run --rm -it -v okta-poc-data:/data -v "$PWD/QR.png:/tmp/qr.png:ro" \
  okta-poc enroll --qr-image /tmp/qr.png --with-uv --allow-missing-policy-audience

# Listen for pushes and decide each one interactively.
docker run --rm -it -v okta-poc-data:/data okta-poc fcm \
  --uv-executable /opt/okta-poc/examples/uv-mock-accept.py
```

The state lives in the `okta-poc-data` volume. You are asked for a passphrase when the state file is created and each time it is opened. Set `OKTA_POC_STATE_PASSWORD` for non-interactive runs, or pass `--plaintext-state` at enrollment to store a disposable test state unencrypted (mode 0600).

Use `--allow-missing-policy-audience` only if `enroll` asks for it. It means the policy publishes no OAuth client ID, so the challenge audience cannot be checked.

## Local setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/okta-poc --state live-captures/state.json enroll --qr-image QR.png --with-uv
```

## Commands

| Command | Purpose |
|---|---|
| `enroll` | Enroll from `--qr-image` (or `OKTA_QR_URI`); registers an FCM device first unless `--without-push` |
| `fcm` | Wait for pushes; validate each one, then ask `[a]pprove/[d]eny/[s]kip/[q]uit` |
| `poll` | Fetch and show pending challenges without FCM |
| `approve TX` / `deny TX` | Answer one pending challenge from `poll` |
| `list` | Show local enrollments |
| `fcm-register` | Register a new FCM device and attach its token to every enrollment |
| `delete-enrollment` | Delete the enrollment in Okta and locally (`--all` for every one) |

Use the global `--state PATH` option (or `OKTA_POC_STATE`) to choose the state file. When the state holds several enrollments, pick one with `--enrollment ID`.

### Decisions and user verification

`fcm --decision-executable /abs/path` replaces the interactive prompt. The program gets the challenge summary as JSON on stdin and exits **0 = approve, 1 = deny, 2 = skip**. Any other exit status fails closed. `examples/decision-file.py` waits for `approve`/`deny`/`skip` to be written to `/dev/shm/okta-poc-decision-response`, so you can decide from another shell:

```bash
docker exec CONTAINER sh -c 'echo approve > /dev/shm/okta-poc-decision-response'
```

When a challenge asks for user verification, approving it runs `--uv-executable` first, and nothing is signed unless that program exits 0. Helper programs never get `OKTA_*` environment variables.

### Safety rules built in

- A challenge is only shown after its signature checks out against the org's JWKS, and only if it is bound to this org, enrollment, push method and user.
- Every URL we call is on the enrolled org's host. Redirects are never followed.
- Each transaction is answered at most once. It is recorded before sending, so an uncertain send is never followed by a second answer.
- Number-matching challenges cannot be approved (not implemented), and CIBA challenges are rejected.
