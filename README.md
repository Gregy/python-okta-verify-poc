# Okta Verify independent push PoC

Self-contained experimental Okta Verify client with QR enrollment, pending polling, native FCM delivery, interactive/external decisions, PoP/UV response signing, and enrollment lifecycle commands.

**Not official Okta Verify and not a production MFA replacement.** Use only an authorized test tenant and recovery method. The Android enrollment profile and public Okta Firebase client configuration are compatibility-test declarations, not proof of Android hardware or attestation. Real biometric user verification requires a trusted provider; the example UV helpers are mocks for protocol tests only.

## Included

- `src/okta_poc/` — Python package and `okta-poc` entry point
- `tests/` — hermetic protocol and FCM tests
- `fcm-receiver/` — Android FCM/MCS receiver source (Rust)
- `examples/` — interactive/skip decision providers and mock UV helpers
- `Dockerfile` — multi-stage receiver + Python build, non-root runtime
- `compose.yaml` — optional named-volume workflow

Live credentials and enrollment state belong in `live-captures/` locally or `/data` in Docker. They are excluded by `.gitignore` and `.dockerignore` and are never copied into the image.

## Local setup

Requirements: Python 3.11+, `uv` or pip, Rust/Cargo for the receiver.

```bash
cd okta-poc
uv venv .venv
uv pip install --python .venv/bin/python -e '.[dev]'
cargo build --locked --manifest-path fcm-receiver/example/Cargo.toml
.venv/bin/pytest
```

Without `uv`:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cargo build --locked --manifest-path fcm-receiver/example/Cargo.toml
```

## First run

### 1. Register Android FCM credentials

```bash
.venv/bin/okta-poc fcm-register
```

This creates or reuses:

- `live-captures/okta-fcm-device-android.json`
- `/dev/shm/okta-poc-okta-fcm-token`

The token is not printed. If an enrollment already exists, `fcm-register` also attaches the current token to it.

### 2. Enroll from a QR image

```bash
.venv/bin/okta-poc \
  --state live-captures/okta-poc-state.json \
  enroll \
    --qr-image QR.png \
    --plaintext-state \
    --with-uv \
    --fcm-token-file /dev/shm/okta-poc-okta-fcm-token \
    --allow-missing-policy-audience
```

Android compatibility is always enabled; no separate flag is needed. `--plaintext-state` is only for disposable testing and stores private keys unencrypted with mode `0600`. Omit it to use the default encrypted state and passphrase.

### 3. Listen and decide

```bash
.venv/bin/okta-poc \
  --state live-captures/okta-poc-state.json \
  fcm
```

For each validated push, choose `[a]pprove`, `[d]eny`, `[s]kip`, or `[q]uit`. Approval still requires successful UV when requested:

```bash
.venv/bin/okta-poc \
  --state live-captures/okta-poc-state.json \
  fcm \
    --decision-executable "$PWD/examples/decision-file.py" \
    --uv-executable /absolute/path/to/trusted-uv-provider
```

External decision protocol: one JSON transaction object on stdin; exit **0=approve**, **1=deny**, **2=skip**. Other statuses fail closed. The provider receives no nonce, JWS, private keys, FCM token, or `OKTA_*` environment secrets.

### Polling and lifecycle

```bash
.venv/bin/okta-poc --state live-captures/okta-poc-state.json list
.venv/bin/okta-poc --state live-captures/okta-poc-state.json poll
.venv/bin/okta-poc --state live-captures/okta-poc-state.json watch --interval 15
.venv/bin/okta-poc --state live-captures/okta-poc-state.json approve TRANSACTION_ID --uv-executable /absolute/path/to/uv-provider
.venv/bin/okta-poc --state live-captures/okta-poc-state.json deny TRANSACTION_ID
.venv/bin/okta-poc --state live-captures/okta-poc-state.json update-push-token --fcm-token-file /dev/shm/okta-poc-okta-fcm-token --yes
.venv/bin/okta-poc --state live-captures/okta-poc-state.json delete-enrollment --all --yes
```

## Docker

The image compiles the Rust receiver and Python package, then runs as UID `10001`. `/data` is the only persistent state volume.

### Build and register

```bash
docker build -t okta-poc .
docker run --rm -it -v okta-poc-data:/data okta-poc fcm-register
```

### Enroll with a mounted QR image

```bash
docker run --rm -it \
  -v okta-poc-data:/data \
  -v "$PWD/QR.png:/tmp/qr.png:ro" \
  okta-poc enroll \
    --qr-image /tmp/qr.png \
    --plaintext-state \
    --with-uv \
    --fcm-token-file /data/okta-fcm-token \
    --allow-missing-policy-audience
```

### Listen in FCM mode

```bash
docker run --rm -it -v okta-poc-data:/data okta-poc fcm
```

Other commands work the same way:

```bash
docker run --rm -it -v okta-poc-data:/data okta-poc list
docker run --rm -it -v okta-poc-data:/data okta-poc poll
docker run --rm -it -v okta-poc-data:/data okta-poc approve TRANSACTION_ID --uv-executable /path/to/provider
```

If `/data` has an enrollment but no FCM credential file, `fcm` registers credentials and attaches the token automatically before listening.

### Docker Compose

```bash
docker compose build
docker compose run --rm okta-poc fcm-register
docker compose run --rm \
  -v "$PWD/QR.png:/tmp/qr.png:ro" \
  okta-poc enroll \
    --qr-image /tmp/qr.png \
    --plaintext-state \
    --with-uv \
    --fcm-token-file /data/okta-fcm-token \
    --allow-missing-policy-audience
docker compose run --rm okta-poc fcm
```

## Environment variables

| Variable | Purpose |
|---|---|
| `OKTA_QR_URI` | Activation URI alternative to `--qr-image` |
| `OKTA_FCM_TOKEN` | FCM token alternative to `--fcm-token-file` |
| `OKTA_POC_STATE` | Override the default state path |
| `OKTA_POC_STATE_PASSWORD` | Passphrase for encrypted state only |
| `OKTA_POC_FCM_RECEIVER` | Override receiver binary path |
| `OKTA_POC_FCM_DEVICE` | Override Android FCM credential path |
| `OKTA_POC_FCM_TOKEN_OUT` | Override secure token output path |

