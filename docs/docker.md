# Docker install (alternative to bare-metal)

Cross-platform install path that runs on Linux, macOS (Docker Desktop), and Windows (Docker Desktop / WSL2). Different security primitives than the systemd path; **comparable for most threat models but not identical**. The trade-offs are in [§ Threat model](#threat-model) below - read them before deciding.

> ## ⚠️  Before you copy-paste anything below
>
> The proxy provides **zero isolation** if either of these is true on your host. Each takes 30 seconds to verify:
>
> 1. **Your AI agent's UID has docker daemon access** (member of `docker` group, or can reach `/var/run/docker.sock`). The agent can then extract the BWS token + CA private key directly via `docker exec` / `docker cp` - full detail in [§ Hard prerequisite: docker access boundary](#hard-prerequisite-docker-access-boundary).
> 2. **Another container is on the `avp-net` network.** It can reach the proxy directly via container DNS, bypassing the host's loopback constraint: full detail in [§ Hard prerequisite: do NOT add other containers to avp-net](#hard-prerequisite-do-not-add-other-containers-to-avp-net).
>
> If either applies, stop and use the [bare-metal systemd install](../README.md#installation) instead. The setup below assumes neither does.

---

## Prerequisites

- Docker Engine 24+ or Docker Desktop 4.30+
- A Bitwarden Secrets Manager subscription with at least one project + machine-account access token (see the main README's Prerequisites section)
- `~5 minutes` for first-time setup

---

## Setup

### 1. Clone the repo and prepare host files

```bash
git clone https://github.com/inflightsec/agent-vault-proxy.git
cd agent-vault-proxy

# Drop your BWS access token into a host file. `read -rs` keeps the token
# out of shell history; `umask 077` makes the file 0600. We wrap the
# whole thing in `bash -c '...'` so it runs the same regardless of your
# login shell — zsh interprets `read -p` differently than bash and errors
# with `no coprocess` on the bare form.
mkdir -p secrets
bash -c '( umask 077 && read -rsp "BWS access token: " TOKEN && printf "%s" "$TOKEN" > secrets/bws-token && echo )'

# Copy the example config and edit. bindings.example.yaml already references
# /etc/agent-vault-proxy/bws-token and /var/log/agent-vault-proxy/audit.jsonl,
# which match the container's bind-mount and named volume — no path edits needed.
cp bindings.example.yaml bindings.yaml
$EDITOR bindings.yaml
```

### 2. Build the image

```bash
docker compose build
```

Multi-stage: a builder stage compiles the wheel; a runtime stage carries only Python + glibc + libssl3 + libffi + tini + the venv. The base image pin is verified with:

```bash
docker manifest inspect python:3.12-slim-bookworm | jq -r '.manifests[0].digest'
```

If the digest in the Dockerfile is stale, edit the `ARG PYTHON_IMAGE` line. Don't pass `--build-arg PYTHON_IMAGE=...` on the CLI in production builds: the digest pin is meaningful only if the default isn't overridden.

### 3. Start the proxy

```bash
docker compose up -d
docker compose ps
docker compose logs --tail 50 avp
```

First start takes a few seconds for mitmproxy to initialize. The named volume `agent-vault-proxy-state` is initialized empty; mitmproxy will write its CA there on the first proxied request.

### 4. Apply append-only to the audit log

The audit log lives inside `agent-vault-proxy-logs`. To get the same `chattr +a` defense the bare-metal install applies, run a short-lived privileged container that holds `LINUX_IMMUTABLE` (the main proxy does not - `cap_drop: [ALL]`):

```bash
docker run --rm \
  --cap-add LINUX_IMMUTABLE \
  --user 0:0 \
  --network none \
  -v agent-vault-proxy-logs:/var/log/agent-vault-proxy \
  debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb \
  bash -c "touch /var/log/agent-vault-proxy/audit.jsonl \
        && chown 65532:65532 /var/log/agent-vault-proxy/audit.jsonl \
        && chmod 0640        /var/log/agent-vault-proxy/audit.jsonl \
        && chattr +a         /var/log/agent-vault-proxy/audit.jsonl \
        && lsattr            /var/log/agent-vault-proxy/audit.jsonl"
```

Pin the init container's digest for the same supply-chain reasons as the proxy image. Update the `sha256:...` above periodically by checking `docker manifest inspect debian:bookworm-slim`.

This is a one-shot per volume - re-run after `docker volume rm agent-vault-proxy-logs`. Without it, the audit log is still `O_APPEND`-only from the proxy's perspective; the `chattr +a` adds filesystem-level enforcement against an attacker with shell access inside the container. On filesystems that don't support extended attributes (very rare, Docker Desktop's Linux VM does), `chattr` is a no-op.

**Tamper window:** between first `docker compose up` and the init container completing, the audit log has no filesystem-level append-only enforcement. Run the init container immediately after the first `up`, ideally before the proxy serves real traffic.

### 5. Extract the CA so host callers can trust it

mitmproxy generates its own CA on the first proxied request. Trigger that once, then copy the **public** cert to the host:

```bash
# Trigger CA generation. The curl will TLS-fail — that's fine; the cert gets written.
curl -x http://127.0.0.1:14322 -sS https://example.com -o /dev/null || true

# Copy the PUBLIC CA cert (-ca-cert.pem) to the host.
docker cp agent-vault-proxy:/var/lib/agent-vault-proxy/.mitmproxy/mitmproxy-ca-cert.pem ca.pem
sudo install -m 0644 -o root -g root ca.pem /etc/agent-vault-proxy/ca.pem
rm ca.pem
```

> 🛑 **Never copy `mitmproxy-ca.pem` (no -cert suffix) or `mitmproxy-ca.p12`.** Those files contain the **private key** for the CA. Anyone with the private key can mint TLS certificates for any upstream and MITM the proxy. The private key MUST stay inside the named volume.

### 6. Point your agent at the proxy

Same as the bare-metal install. In the calling shell:

```bash
export HTTPS_PROXY="http://127.0.0.1:14322"
export HTTP_PROXY="http://127.0.0.1:14322"
export NODE_EXTRA_CA_CERTS="/etc/agent-vault-proxy/ca.pem"
export SSL_CERT_FILE="/etc/agent-vault-proxy/ca.pem"
export REQUESTS_CA_BUNDLE="/etc/agent-vault-proxy/ca.pem"
export CURL_CA_BUNDLE="/etc/agent-vault-proxy/ca.pem"

export OPENAI_API_KEY="sk-PLACEHOLDER-..."

curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

### 7. Verify the install

Three quick checks to confirm everything's wired up.

**Watch for the startup preflight banner** (silent on the documented happy path; loud if anything's off):

```bash
docker compose logs avp | grep -E "(preflight|insecure-configuration|proxy_restart)"
```

You should see `proxy_restart` in the audit lifecycle and either NO preflight banner (good: your config is on the happy path) or a clearly-marked `INSECURE:` block telling you exactly what to fix.

**Trigger a preflight warning intentionally** (sanity-checks the preflight pipeline without changing your real config):

```bash
docker compose run --rm -e BWS_ACCESS_TOKEN=dummy-trigger-the-warning avp \
    python -c "from agent_vault_proxy._preflight import emit_preflight; \
               from agent_vault_proxy.config import load_config; \
               emit_preflight(load_config('/etc/agent-vault-proxy/bindings.yaml'))"
```

Expected output: a banner like `INSECURE: BWS_ACCESS_TOKEN is set as an environment variable inside a container...`. If you don't see it, the preflight isn't running: check that your image actually contains `agent_vault_proxy/_preflight.py`.

**End-to-end substitution smoke test** (proves the wire-format path works, not just the listener):

```bash
# Pick a real binding from your bindings.yaml. Replace the placeholder
# string with the EXACT value of `placeholder:` for that secret.
HTTPS_PROXY=http://127.0.0.1:14322 \
  SSL_CERT_FILE=/etc/agent-vault-proxy/ca.pem \
  CURL_CA_BUNDLE=/etc/agent-vault-proxy/ca.pem \
  curl -H "Authorization: Bearer sk-ant-PLACEHOLDER-01HXY1234567890ABCDEFGH" \
       https://api.anthropic.com/v1/messages -d '{}'
```

If substitution worked, you get the upstream's normal response (likely a `400 invalid request` because the body is empty, that's success: the request reached Anthropic with a valid auth header). If substitution did NOT happen, you get a `401` saying the API key is invalid - the placeholder went out verbatim.

Cross-check by tailing the audit log:

```bash
docker compose exec avp tail -3 /var/log/agent-vault-proxy/audit.jsonl
```

You should see an `inject_decision: allowed` event matching your request.

### 8. Teardown

```bash
docker compose down                    # stop + remove container
docker volume rm agent-vault-proxy-state agent-vault-proxy-logs   # delete CA + audit log
```

⚠️  Removing `agent-vault-proxy-state` wipes the mitmproxy CA: every caller that trusted the old `ca.pem` will get TLS errors on next start until you re-extract the new one (step 5). Removing `agent-vault-proxy-logs` destroys the audit history: back it up first if you need it for forensics.

---

## Hard prerequisite: docker access boundary

**The proxy's whole isolation claim assumes the AI agent process cannot read the BWS token or the mitmproxy CA private key.** Under Docker, that holds only if the agent's host UID does **NOT** have access to the docker daemon. If the agent's UID is in the `docker` group, or can reach the docker socket, the agent can:

```bash
docker exec agent-vault-proxy cat /etc/agent-vault-proxy/bws-token
docker cp agent-vault-proxy:/var/lib/agent-vault-proxy/.mitmproxy/mitmproxy-ca.pem ./ca-key.pem
```

…and the proxy provides **zero** isolation from the agent. Docker group membership is equivalent to root on the host.

**The CA private key matters beyond BWS.** Once an attacker has `mitmproxy-ca.pem`, they can mint TLS certs for **any** host the agent trusts the proxy CA against. For as long as that CA is installed in the agent's trust store, the attacker can MITM the agent's traffic to every upstream API, not just credential-injection points. Rotating the BWS token after a suspected compromise doesn't help here; the CA root has to be regenerated and the agent's `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` updated to the new one.

**If the agent runs on the same host as the docker daemon and shares any user with docker access, use one of:**

- The bare-metal systemd install ([main README](../README.md#installation)), separate UNIX users with no shared privilege escalation path.
- Rootless docker (see [§ Rootless docker](#rootless-docker-optional)) running under a UID the agent doesn't have.
- A separate VM dedicated to the proxy, with no agent process on it.

Continue with this Docker install only if the docker daemon is reachable **only** by an operator UID the agent never assumes.

---

## Hard prerequisite: do NOT add other containers to `avp-net`

The proxy binds `0.0.0.0:14322` *inside* its container so Docker can port-publish it to the host. Any other container on the same docker network can reach the proxy directly via container DNS (`http://avp:14322`), bypassing the host's `127.0.0.1` loopback constraint and the binding-scope checks the operator may believe are protecting them.

The compose file declares a dedicated `avp-net` bridge specifically so no other service joins it by default. **Do not** add `networks: [avp-net]` to any other service in your own compose files. If another service needs the proxy, expose it on the host loopback and have that service reach it via `host.docker.internal:14322` (or the host gateway IP on Linux).

---

## What's enforced

| Concern | How |
|---|---|
| Non-root container UID, distinct from host operator | `USER 65532` (distroless convention) |
| Read-only rootfs, explicit writable paths | `read_only: true` + named volumes + 16M tmpfs at /tmp |
| Zero capabilities | `cap_drop: [ALL]`, no `cap_add` anywhere |
| No privilege escalation | `security_opt: no-new-privileges:true` |
| Default seccomp profile | applied implicitly, not overridden |
| Host-side port binding loopback-only | `127.0.0.1:14322:14322` (NOT `0.0.0.0`) |
| Isolated single-tenant network | dedicated `agent-vault-proxy-net` bridge |
| Resource bounds (DoS / fork-bomb / runaway) | `pids_limit: 256`, `mem_limit: 512m`, `cpus: 1.0`, no swap |
| BWS token never visible in env / `docker inspect` | bind-mount as file, never `environment:` |
| Append-only audit log | named volume + manual `chattr +a` init (see §4) |
| Clean shutdown without truncating audit log | `tini` as PID 1, `restart: unless-stopped` |
| Bounded docker JSON logs | `max-size: 10m`, `max-file: 3` |
| Pinned base image | `python:3.12-slim-bookworm@sha256:...` (Dockerfile ARG) |
| No install-time script execution from deps | `pip install --only-binary :all:` |
| Startup security preflight | warns to stderr + audit log on known footguns: `BWS_ACCESS_TOKEN` env var in container, root UID inside container, audit log missing `chattr +a`, unscoped binding on known-laundering hosts (`api.github.com` etc.). Silent on the documented happy paths. |

vs the bare-metal systemd install: systemd's `SystemCallFilter=@system-service` is more granular than the default Docker seccomp profile, and the bare-metal path doesn't have the docker-daemon-as-root attack surface. For most threat models the difference is academic; for high-value hosts, prefer bare-metal.

---

## What's NOT enforced (and why)

| Not done | Why |
|---|---|
| **Egress restriction** | The proxy MUST forward to arbitrary upstream APIs. The binding-scope check in `bindings.yaml` is what controls which destinations get the real secret vs the placeholder; Docker-level egress controls would either be no-ops or break the proxy. |
| **Image signature verification** | The image isn't published to a registry yet. v0.5.0 will ship cosign-signed images via `cosign verify ghcr.io/inflightsec/agent-vault-proxy@<digest>`. For now, build locally from the pinned-base Dockerfile. |
| **SBOM at build time** | Deferred to v0.5.0 (syft / CycloneDX in `release.yml`). |
| **Auto-applied `chattr +a`** | The proxy can't apply it itself (no `LINUX_IMMUTABLE`). Auto-init via depends_on/init container being evaluated for v0.5.0; in v0.4.1 it's a documented manual step. |
| **Hash-pinned pip install** | **Landed in v0.4.1.** The Dockerfile now installs runtime deps from `requirements.lock` with `--require-hashes --only-binary :all:`, then installs the project wheel with `--no-deps`. Matches the CI install posture. |
| **Rootless docker as default** | Works (see below) but adds setup friction. Documented as an option, not the default. |
| **Replicas / horizontal scaling** | Not applicable. Each container generates its own CA; replicas would break host trust. Single-instance only. |

---

## Threat model

These are residual risks the Docker hardening does NOT eliminate. Decide per host whether they matter.

1. **Docker daemon runs as root.** Compromise of the docker daemon (or root on the host) bypasses every container-level boundary. Use rootless docker on high-value hosts.

2. **Docker group ≈ host root.** Already flagged at the top of this doc, restating because it's the single most common misconfiguration: anyone with `docker exec` access can extract the CA private key + BWS token. Restrict docker group membership accordingly.

3. **Initial image pull queries Docker Hub.** The `python:3.12-slim-bookworm@sha256:...` pull is one outbound trip to docker.io. The sha256 pin guarantees you get the same bits regardless, but the request itself is unavoidable.

4. **CA private key in named volume.** Anyone with `docker exec` access, or read access to the named volume's host backing path (`/var/lib/docker/volumes/agent-vault-proxy-state/_data` on Linux), can read the key. See #2 above.

5. **`docker exec --user 0` bypasses `USER` and `no-new-privileges`.** The `--user` flag on `docker exec` is not constrained by the image's USER or the no-new-privileges security_opt. Only grant `docker exec` access to operators trusted to root the host.

6. **Bind-mount permissions are host-side.** `chmod 0600 secrets/bws-token` matters even though the container runs as UID 65532, the host-side mode is what's enforced when the file is mounted in.

   **Operator-UID compromise leaks the BWS token.** The token at `./secrets/bws-token` is owned by the operator's UID and readable by anything else running at that UID - malware in a browser, an unrelated package's postinstall, a misconfigured backup tool. The architecture defends against agent-UID compromise (the agent doesn't share the operator's UID), not operator-UID compromise. For stronger separation, use the systemd install where the token is `0440 root:avp` and the operator's interactive shell cannot read it.

7. **Audit log tamper window.** Between first `docker compose up` and step 4's chattr-init, the audit log is rewritable from inside the container. Window closes after step 4 runs.

8. **macOS Docker Desktop / Windows WSL2 network model.** On Linux, the container's published `127.0.0.1:14322` is the host's own loopback. On macOS Docker Desktop the Linux VM publishes through `vpnkit` to the macOS host's loopback (transparent for this use case). On **Windows + WSL2**, `127.0.0.1:14322` on the Windows host is NOT automatically reachable from inside a WSL2 distro: there's a vEthernet layer. Agents inside a WSL2 distro should target the Windows host's WSL2 gateway IP (typically `<distro IP>`'s default gateway) instead.

---

## Rootless docker (optional)

For high-value hosts, run docker rootless so the daemon runs as your UID, not root:

```bash
# One-time setup (Linux)
dockerd-rootless-setuptool.sh install
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock

# `docker compose up` now runs without root on the host.
```

Trade-off: file performance is worse on rootless, some volume drivers aren't available, host networking isn't supported. None of those matter for this proxy.

---

## Troubleshooting

**`docker compose up` says `bindings.yaml: no such file`:**
You haven't run step 1 (`cp bindings.example.yaml bindings.yaml`). The compose bind-mounts `./bindings.yaml`; it must exist.

**`docker compose up` says `secrets/bws-token: no such file`:**
You haven't created `./secrets/bws-token`. Re-run step 1's `read -rs` block.

**Container starts, logs show `BackendUnavailableError`:**
Either the BWS token is wrong, or `bindings.yaml`'s `backend.config.access_token_path` doesn't point at `/etc/agent-vault-proxy/bws-token` (the in-container path matching the bind-mount). `bindings.example.yaml` already has the correct path.

**Healthcheck fails with no useful error:**
`docker compose logs avp` shows mitmproxy's startup output. Most common: YAML syntax error in `bindings.yaml`, or a binding that references a secret name BWS doesn't have.

**Host can't reach `127.0.0.1:14322`:**
Check the compose `ports:` line says `"127.0.0.1:14322:14322"` (with the IP prefix). If it says `"14322:14322"`, it publishes to every interface - wrong, AND it shadows the loopback you actually want.

**Audit log is not append-only:**
You skipped step 4 (chattr init). Run it. If you're on a filesystem without extended attributes (rare), the proxy still opens the file `O_APPEND`-only - just without filesystem-level enforcement.

**`docker exec` complains about /bin/sh:**
Future Dockerfile revisions may strip the shell for additional hardening. If/when that happens, use `docker compose exec avp python -c "..."` or `docker cp` instead.

