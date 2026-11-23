FROM python:3.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OKTA_POC_STATE=/data/okta-poc-state.json

# libglib/libgomp are needed by OpenCV (QR decoding); tini forwards Ctrl+C.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini libglib2.0-0 libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --create-home okta \
    && mkdir -p /data \
    && chown okta:okta /data

WORKDIR /opt/okta-poc
COPY pyproject.toml README.md ./
COPY src/ ./src/
# Example decision/UV helpers (the UV ones are mocks for protocol tests).
COPY --chmod=755 examples/ /opt/okta-poc/examples/
RUN python -m pip install .

USER 10001:10001
VOLUME ["/data"]
WORKDIR /home/okta
ENTRYPOINT ["tini", "--", "okta-poc"]
CMD ["--help"]
