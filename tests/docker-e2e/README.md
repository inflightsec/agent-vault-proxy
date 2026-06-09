# Docker end-to-end harness

A scripted integration test that builds the `agent-vault-proxy` Docker image, stands it up next to an HTTP echo upstream on an isolated bridge network, and proves the substitution path works end-to-end on the wire.

What it actually tests:

- The image **builds** with the hash-pinned `requirements.lock` install path. Regression coverage for v0.4.1's Dockerfile hardening.
- The container **starts** and the proxy listens on port 14322.
- A client request through the proxy with a configured **placeholder** in the `Authorization` header gets the real secret substituted before the upstream sees it.
- The **upstream's echoed headers** contain the real secret string and do NOT contain the placeholder string. This is the on-the-wire assertion.
- The **audit log** on the named volume contains an `inject_decision: allowed` entry with the right `secret_name`.
- A request to an **unbound destination** is denied with 403 and audited as `deny: unmatched_destination`. Covers the `unmatched_destination_policy: deny` posture the example config now ships with.

## Backend

The harness uses the `static` backend, not real BWS. The static backend is for **dev / integration testing / this harness only**: it reads plaintext from a file and emits a clear startup warning when active. Do not point it at real credentials.

`secrets.yml` is **not committed**. It's generated inside a one-shot `avp-init` busybox container from the `TEST_SECRET` env var that `run.sh` exports, written into a named volume with avp-owned (UID 65532) modes (0600). This avoids the host-UID mismatch class — on a Docker daemon with userns-remap enabled, the container's "root" maps to a non-root host UID and can't read a host-side 0600 file owned by whichever operator (or CI runner) checked out the tree.

## How to run locally

```bash
# Once
cd tests/docker-e2e

# Run the full positive + negative suite, then tear down.
bash run.sh

# Or invoke through pytest with the `docker` marker.
.venv/bin/pytest -m docker tests/docker-e2e/
```

If something fails and you want to poke at the running stack:

```bash
bash run.sh --keep              # leaves containers + volumes alive
docker compose logs avp         # mitmproxy + addon logs
docker exec -it avp-e2e bash    # not really — distroless-ish, no shell
docker compose down -v          # tear down when done
```

## How CI runs it

`.github/workflows/test.yml` has an `e2e-docker` job that runs `bash tests/docker-e2e/run.sh` on every PR. It runs alongside the unit-test matrix (not gating, since Docker setup time would slow the existing pytest jobs), and surfaces failures in the same Actions tab.

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Three-service stack: `avp-init` (one-shot config staging), `avp`, `upstream` echo. |
| `bindings.yaml` | Test config: one binding for `upstream.test`, `unmatched_destination_policy: deny`, `static` backend. |
| `run.sh` | Exports `TEST_SECRET`, builds, starts, exercises, asserts, tears down. Exit 0 = pass. |
| `test_docker_e2e.py` | pytest entry point, marked `@pytest.mark.docker` — skipped by default. |

## Why HTTP, not HTTPS, to the upstream

The wire-substitution logic the addon performs is identical for HTTP and HTTPS once mitmproxy hands the flow to the addon's `requestheaders` hook. Driving plain HTTP to the upstream avoids the cert-trust dance that an HTTPS upstream with a self-signed cert would require. The HTTPS interception path is exercised by `tests/smoke/layer3_proxy_anthropic.py` against the real `api.anthropic.com`.

## What this does NOT test

- HTTPS interception against an upstream that's not on the public CA trust path. (See note above.)
- Real BWS auth. (See `tests/smoke/layer2_bws_read.py`.)
- The systemd install path. The Docker harness covers the Docker install; systemd has its own smoke runbook in `docs/install-systemd.md`.
- The composite-secret / Jinja-template path. Covered by `tests/test_template.py` at the unit level.
- High-volume / concurrent-request behavior.

If you add a scenario to the harness, keep the contract simple: the script's exit code is the test result. Either both the positive and negative assertions pass, or `run.sh` exits non-zero with a clearly labeled red error message.
