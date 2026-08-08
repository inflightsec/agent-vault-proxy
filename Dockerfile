# syntax=docker/dockerfile:1.7

# ============================================================
# agent-vault-proxy — hardened multi-stage build
# ============================================================
#
# Base image pin: regenerate before each release with
#   docker manifest inspect python:3.12-slim-bookworm | jq -r '.manifests[0].digest'
# Last verified: 2026-05-20.
#
# Distroless was rejected: argon2-cffi-bindings, bcrypt, bitwarden-sdk and
# aioquic need libffi + libssl3 at runtime. Alpine breaks because cffi needs
# glibc. python:3.12-slim-bookworm is the smallest viable base.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:93ab4b7fa528b25124c97bcc755415e60eb671a86b4dbe0328df2fe2d1c1193d

# ------------------------------------------------------------
# Builder stage — compiles the wheel, installs runtime venv.
# Compilers and -dev headers stay HERE; never reach runtime.
# ------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Layer cache: copy pyproject + lockfile + LICENSE + README first.
# Editing files under src/ shouldn't invalidate the dep-install layer.
COPY pyproject.toml requirements.lock README.md LICENSE ./

# Create the runtime venv (ships to runtime stage). Put the `build` tool
# itself in a SEPARATE throwaway venv so build tooling doesn't leak into
# the runtime image.
RUN python -m venv /opt/avp/.venv \
 && /opt/avp/.venv/bin/pip install --upgrade --no-cache-dir pip \
 && python -m venv /tmp/build-venv \
 && /tmp/build-venv/bin/pip install --no-cache-dir --only-binary :all: build

# Install runtime dependencies from the hash-pinned lockfile FIRST,
# before the project wheel. This matches the CI install posture
# (`--require-hashes` refuses any package whose SHA-256 doesn't match
# requirements.lock) and closes the gap where installing the project
# wheel directly would resolve dependency lower-bound ranges
# (mitmproxy>=11, pydantic>=2.7, …) against live PyPI at build time.
# With deps already pinned in the venv, the wheel install below uses
# `--no-deps` and cannot pull anything fresh. `--only-binary :all:`
# refuses sdists, blocking install-time script execution from a
# compromised dependency.
RUN /opt/avp/.venv/bin/pip install \
        --no-cache-dir \
        --require-hashes \
        --only-binary :all: \
        -r requirements.lock

# Source change invalidates only from here forward.
COPY src/ ./src/

# Build the project wheel and install it with `--no-deps` — runtime
# dependencies are already pinned in the venv from the locked install
# above, so nothing should be resolved here. `--only-binary :all:` is
# redundant given `--no-deps` but kept for defense-in-depth in case
# anyone refactors this step later.
RUN /tmp/build-venv/bin/python -m build --wheel --outdir /build/dist . \
 && /opt/avp/.venv/bin/pip install \
        --no-cache-dir \
        --no-deps \
        --only-binary :all: \
        /build/dist/*.whl

# ------------------------------------------------------------
# Runtime stage — minimal. No compilers, no -dev packages.
# ------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libffi8 \
        libssl3 \
        ca-certificates \
        tini \
 && rm -rf /var/lib/apt/lists/*

# UID 65532 is the well-known distroless convention. Picked over 1000 to
# avoid collision with typical host operator UIDs.
RUN groupadd --system --gid 65532 avp \
 && useradd  --system --uid 65532 --gid 65532 \
             --home-dir /var/lib/agent-vault-proxy \
             --shell /usr/sbin/nologin avp \
 && install -d -o avp  -g avp  -m 0750 /var/lib/agent-vault-proxy \
 && install -d -o avp  -g avp  -m 0750 /var/log/agent-vault-proxy \
 && install -d -o root -g avp  -m 0750 /etc/agent-vault-proxy

COPY --from=builder --chown=root:root /opt/avp/.venv /opt/avp/.venv

# HOME drives where mitmproxy writes $HOME/.mitmproxy/ on first request.
# Aligning HOME with /var/lib/agent-vault-proxy puts the CA on the named
# volume mounted there, so it survives container restarts.
ENV HOME=/var/lib/agent-vault-proxy \
    PATH="/opt/avp/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

USER avp:avp
WORKDIR /var/lib/agent-vault-proxy

# tini reaps zombies and forwards SIGTERM, so `docker stop` doesn't SIGKILL
# mid-write and truncate the audit log.
ENTRYPOINT ["/usr/bin/tini", "--"]

# Override the proxy's hardcoded --listen-host 127.0.0.1 with 0.0.0.0 so
# the container's published port is reachable from the host. Host-side,
# compose publishes 127.0.0.1:14322 so the listener is still loopback-only
# from outside the host.
CMD ["python", "-m", "kow", \
     "--listen-host", "0.0.0.0", \
     "--set", "avp_config=/etc/agent-vault-proxy/bindings.yaml"]

# Pure-Python liveness/readiness probe — no shell, no curl/nc dep, no external
# network. Sends a plain-HTTP request THROUGH the proxy to the reserved
# `/healthz` sentinel host; the addon answers 200 only once config, backend
# client, and audit writer are all live (503 "starting" before that). Stronger
# than the old bare-TCP probe, which only proved the socket was open — not that
# AVP could actually broker. 30s start_period covers first-run CA generation.
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import http.client,sys; c=http.client.HTTPConnection('127.0.0.1',14322,timeout=2); c.request('GET','http://healthz.agent-vault-proxy.invalid/healthz',headers={'Host':'healthz.agent-vault-proxy.invalid'}); sys.exit(0 if c.getresponse().status==200 else 1)"]
