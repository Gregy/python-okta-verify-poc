FROM rust:1.100-bookworm AS fcm-builder

WORKDIR /src
COPY fcm-receiver/ ./fcm-receiver/

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && cargo build --locked --release --manifest-path fcm-receiver/example/Cargo.toml

FROM python:3.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OKTA_POC_STATE=/data/okta-poc-state.json \
    OKTA_POC_FCM_DEVICE=/data/okta-fcm-device-android.json \
    OKTA_POC_FCM_TOKEN_OUT=/data/okta-fcm-token \
    OKTA_POC_FCM_RECEIVER=/usr/local/bin/okta-poc-fcm-receiver

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates tini libssl3 libglib2.0-0 libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --create-home okta \
    && mkdir -p /data \
    && chown -R okta:okta /data

WORKDIR /opt/okta-poc
COPY pyproject.toml ./
COPY src/ ./src/
COPY README.md ./
RUN python -m pip install .

COPY --from=fcm-builder /src/fcm-receiver/example/target/release/example /usr/local/bin/okta-poc-fcm-receiver

USER 10001:10001
VOLUME ["/data"]
WORKDIR /home/okta

ENTRYPOINT ["tini", "--", "okta-poc"]
CMD ["--help"]
