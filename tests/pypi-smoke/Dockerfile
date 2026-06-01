# PyPI smoke-test image.
#
# Installs the published `agent-vault-proxy` wheel from PyPI (NOT from
# the local source tree) and runs it the same way the production image
# does. Used by:
#
#   - release.yml `pypi-install-smoke` job: post-publish, with
#     PACKAGE_VERSION = the tag being released, against pypi.org.
#   - pypi-canary.yml: daily, with PACKAGE_VERSION = latest released,
#     against pypi.org.
#   - tests/pypi-smoke/run.sh: locally, against any PACKAGE_VERSION /
#     PACKAGE_INDEX_URL the operator chooses.
#
# The point is to exercise the actual PyPI artifact (not a wheel built
# fresh from this commit). If something silently drifts between
# `python -m build` and `pip install agent-vault-proxy==X` from PyPI,
# this harness catches it.

# syntax=docker/dockerfile:1.7

ARG PACKAGE_VERSION
ARG PACKAGE_INDEX_URL=https://pypi.org/simple/
# INSTALL_SOURCE: `pypi` (default) installs the published version from
# PACKAGE_INDEX_URL; `local` installs a wheel file the operator has
# staged into ./wheels/ before running compose. The `local` mode is the
# dry-run path — validate the smoke harness against a locally-built
# wheel BEFORE pushing the tag that publishes to PyPI.
ARG INSTALL_SOURCE=pypi

# Pinned-by-digest in the production Dockerfile. The smoke image is
# transient (built fresh per CI run, never published), so pinning to
# the slim tag is acceptable here — drift in the base image would just
# be caught by the next run. Operator overrides via --build-arg if a
# specific digest is required.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE}

ARG PACKAGE_VERSION
ARG PACKAGE_INDEX_URL
ARG INSTALL_SOURCE

# Match the avp UID:GID used by the production Dockerfile so volumes
# mounted from docker-compose use the same ownership semantics. If these
# diverge the static-backend's world-readable check or audit-log perms
# will flag differently between this smoke and prod — defeating the point.
RUN groupadd --system --gid 65532 avp && \
    useradd  --system --uid 65532 --gid avp \
        --home-dir /var/lib/agent-vault-proxy \
        --shell /usr/sbin/nologin avp

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Stage the local wheel dir into the image (always — `pypi` mode just
# means it's empty). run.sh guarantees ./wheels/ exists before compose
# build runs, so the COPY succeeds in both modes.
COPY wheels/ /wheels/

# `--only-binary :all:` refuses source distributions — a compromised
# sdist could execute arbitrary code at `pip install` time. Same
# discipline as the production install path. `--no-cache-dir` keeps
# the image small (smoke runs build per-job).
#
# Branch on INSTALL_SOURCE:
#   pypi  → resolve from PACKAGE_INDEX_URL at PACKAGE_VERSION
#   local → install the single .whl staged into /wheels/
RUN set -eu; \
    if [ "${INSTALL_SOURCE}" = "local" ]; then \
        WHEEL=$(ls /wheels/agent_vault_proxy-*.whl 2>/dev/null | head -1); \
        if [ -z "$WHEEL" ]; then \
            echo "ERROR: INSTALL_SOURCE=local but no agent_vault_proxy-*.whl in /wheels/" >&2; \
            exit 1; \
        fi; \
        echo "Installing from local wheel: $WHEEL"; \
        pip install --no-cache-dir --only-binary :all: "$WHEEL"; \
    else \
        echo "Installing from index ${PACKAGE_INDEX_URL}: agent-vault-proxy==${PACKAGE_VERSION}"; \
        pip install --no-cache-dir --only-binary :all: \
            --index-url "${PACKAGE_INDEX_URL}" \
            "agent-vault-proxy==${PACKAGE_VERSION}"; \
    fi

# Bake the installed version into an image label for diagnostics on
# canary failures ("which version did this run actually test?").
RUN echo "${PACKAGE_VERSION}" > /etc/agent-vault-proxy-version
LABEL org.opencontainers.image.title="agent-vault-proxy-pypi-smoke"
LABEL org.opencontainers.image.description="Post-publish smoke test image for agent-vault-proxy ${PACKAGE_VERSION}"

# Stage the directory layout the proxy expects. The compose stack mounts
# named volumes on top of /etc/agent-vault-proxy and /var/lib & /var/log
# — these mkdirs just ensure the mount points exist with the right
# ownership before the volumes land on top.
RUN install -d -o avp -g avp -m 0750 /etc/agent-vault-proxy && \
    install -d -o avp -g avp -m 0750 /var/lib/agent-vault-proxy && \
    install -d -o avp -g avp -m 0750 /var/log/agent-vault-proxy && \
    touch /var/log/agent-vault-proxy/audit.jsonl && \
    chown avp:avp /var/log/agent-vault-proxy/audit.jsonl && \
    chmod 0640 /var/log/agent-vault-proxy/audit.jsonl

USER avp:avp
WORKDIR /var/lib/agent-vault-proxy
ENV HOME=/var/lib/agent-vault-proxy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 14322

# Identical CLI to the production Dockerfile. If this diverges, the
# smoke is testing something other than what ships, which defeats the
# point of the exercise.
CMD ["python", "-m", "agent_vault_proxy", \
     "--listen-host", "0.0.0.0", \
     "--set", "avp_config=/etc/agent-vault-proxy/bindings.yaml"]

HEALTHCHECK --interval=5s --timeout=2s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 14322), timeout=2).close()"]
