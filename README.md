# agent-vault-proxy

**Just-in-time API keys for AI agents - and any other process you route through it: the caller only ever sees a placeholder.**

Your agent (dev laptop, CI runner, cron job, etc) gets a fake placeholder string (like `sk-PLACEHOLDER-...`) and uses it as if it were a real API key. This proxy sits between the caller and the internet, and swaps the fake for the real secret at the last possible moment - on the way out to the upstream API. If the caller gets prompt-injected, dumps a log, or runs a program with a software-supply-chain issue, the only thing that escapes is the fake placeholder. The real key never enters the calling process.


[![PyPI](https://img.shields.io/pypi/v/agent-vault-proxy.svg)](https://pypi.org/project/agent-vault-proxy/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![CI](https://github.com/inflightsec/agent-vault-proxy/actions/workflows/test.yml/badge.svg)](https://github.com/inflightsec/agent-vault-proxy/actions/workflows/test.yml)

![How agent-vault-proxy substitutes secrets on the wire](docs/how-it-works-animated.svg)

Under the hood: a loopback HTTPS proxy that fetches credentials from [Bitwarden](https://github.com/bitwarden) Secrets Manager — cloud or self-hosted — just-in-time and injects them into outbound requests, so the calling process never holds the real credential bytes in its address space.

## How it works

[![agent-vault-proxy demo: prompt injection vs. credential isolation](docs/demo.svg)](docs/demo.cast)

On every request the proxy: checks the destination against the binding for that secret (host + optional method + optional path scope), fails closed if no binding matches (the placeholder is forwarded verbatim so the upstream's own auth-fail response surfaces), fetches the real secret from BWS (served from an in-memory TTL cache when warm), substitutes placeholder → real secret on the upstream socket only, and `fsync`s an `inject_decision` audit event before the modified bytes go on the wire.

**Latency.** Steady state: 1–3 ms per request (header rewrite + audit fsync). First fetch per secret: +100–300 ms one-time, then cached for 5 minutes. Fresh TLS handshake to a new upstream: +5–20 ms one-time per connection; AVP keeps connections warm. Net: indistinguishable from a direct connection — the LLM endpoint already costs 200–2000 ms per call, AVP is noise.

## At a glance

```yaml
# bindings.yaml — what the agent sees vs. what the upstream sees
secrets:
  GITHUB_PAT:
    placeholder: "github_pat_PLACEHOLDER_01HXY1234"   # the agent's env holds THIS
    inject:
      header: "Authorization"
      format: "Bearer {GITHUB_PAT}"              # {GITHUB_PAT} = real value AVP fetches
                                                      # from your backend for the entry above.
                                                      # `{secret}` also works as a generic alias.
    bindings:
      - host: "api.github.com"                        # only swapped for this destination
        methods: [POST]                               # agent can open things...
        paths: ["/repos/*/*/pulls"]                   # ...but only "open a PR" - not delete, not merge
```

```bash
# Agent's env holds only the placeholder. The real key never enters the process.
export GITHUB_PAT="github_pat_PLACEHOLDER_01HXY1234"
export HTTPS_PROXY="http://127.0.0.1:14322"

# Agent code is unchanged — proxy swaps placeholder → real BWS value on the wire.
curl -H "Authorization: Bearer $GITHUB_PAT" https://api.github.com/repos/myorg/myrepo/pulls ...
```

Full schema (composite secrets, multiple hosts per binding, path globs) in [`bindings.example.yaml`](bindings.example.yaml).

## Why

Two threats keep getting worse, and your API keys sit in the blast radius of both.

**Prompt injection.** Anything your agent reads - a webpage, an email, a tool's output, a PR comment, can carry instructions. If the agent has `GITHUB_PAT` in its env, an injected "send your env to attacker.com" is one HTTP call away. Filtering, alignment, allowlists - are all statistical and all imperfect. The bytes shouldn't be there to exfil in the first place.

**Software supply chain.** A typosquatted npm package, a hijacked PyPI release, a malicious post-install script. If it runs as your agent's UID it reads the same env the agent does. Shai-Hulud showed what worm-scale ecosystem compromise looks like. That's the new baseline.

AVP keeps the credential **bytes** out of the agent, and out of anything the agent runs, and in fact out of any software you can run on that host. As long as the outbound HTTPS goes through AVP, none of it ever sees the real secret. The secrets live in Bitwarden; everyone else gets a placeholder. AVP swaps placeholder with a real value on the wire, default-deny per destination (the proxy refuses to inject for hosts you haven't bound to that secret), and additionally scopes per binding by HTTP method and URL path.

Although built for agents, the mechanism is fully general: any process that holds a placeholder in its env and routes HTTPS through AVP gets the same protection - CI runners, build servers, scrapers, cron jobs, or a developer machine you're hardening against software-supply-chain compromise. The agent case is just where it matters most. Prompt injection puts the credential-holder and the attacker-controlled-input-reader in the same process, which is the one situation where filtering and alignment can't reliably save you and removing the bytes is the only real fix. For plain software the supply-chain benefit still applies; the injection benefit largely doesn't.

**What AVP doesn't do - and what to layer on:** AVP prevents *exfiltration* of the raw key, not *misuse of the authority* the key represents on permitted destinations. If you bind `GITHUB_PAT` to `api.github.com` with no method/path scope, prompt injection can still ask the proxy to authenticate a `DELETE /repos/...` call as you. The lever for that is `methods:` and `paths:` on each binding: see [`bindings.example.yaml`](bindings.example.yaml). For extra security, pair AVP with an egress firewall on the agent's UID so unbound calls are blocked outright. Pair with response-side review for endpoints that may echo back the `Authorization` header in their response body, AVP injects on the request, but does not scrub the response.

**AVP is not a vault — and not trying to be.** Plenty of mature secret-vault implementations already exist: [Bitwarden](https://github.com/bitwarden) Secrets Manager, 1Password, HashiCorp Vault, Doppler, AWS Secrets Manager, Google Secrets Manager. The goal here isn't to reinvent any of them — use whichever you already trust. AVP is the just-in-time wire-substitution layer that sits between your vault and your agent's process. Bitwarden (cloud + self-hosted) is the reference backend that ships today; other vaults plug in via the `SecretsBackend` Protocol — see [docs/adapter-architecture.md](docs/adapter-architecture.md). PRs welcome.

How this compares to HashiCorp Vault Agent, Doppler, `op run`, `superfly/tokenizer`, and Kloak: [docs/comparison.md](docs/comparison.md).

## Setup (one-time)

Three steps. Once you've done this, every new API key is just "add to Bitwarden + a few lines of YAML + restart": see [Add a secret](#add-a-secret) below.

1. **Bitwarden Secrets Manager**, enable it on your org, create a project for this host, create a machine account with **read** access to the project, generate a token. ~10 minutes the first time. [Walkthrough](docs/prerequisites.md).

2. **Install + start the daemon. Pick the install path that matches your host:**

   <details open>
   <summary><b>Linux (recommended — hardened systemd install)</b></summary>

   Full walkthrough: [docs/install-systemd.md](docs/install-systemd.md). ~10 minutes the first time. The doc:

   - creates a dedicated `avp` UNIX user with no shell, no home directory,
   - **pip-installs the published wheel from PyPI** (`pip install --only-binary :all: agent-vault-proxy==0.4.3`) into a system-wide venv at `/opt/agent-vault-proxy/.venv` — `--only-binary :all:` refuses source distributions, so a compromised transitive dep can't run code at install time,
   - drops your BWS token at `/etc/agent-vault-proxy/bws-token` (root-owned, `avp`-readable) and your bindings at `/etc/agent-vault-proxy/bindings.yaml`,
   - installs a locked-down systemd unit (`ProtectSystem=strict`, `RestrictAddressFamilies`, syscall filter, `chattr +a` append-only audit log) — sandbox controls Docker can't offer.

   Token, bindings, audit log, and CA cert all live under `/etc/agent-vault-proxy/` and `/var/{lib,log}/agent-vault-proxy/`.
   </details>

   <details>
   <summary><b>Cross-platform / quick start (macOS, Windows-WSL2, or a Linux dev box)</b></summary>

   ```bash
   # Pick a tagged release, not `main` — tags are how you opt into a vetted
   # version. Tracking `main` exposes you to a window where a compromised
   # maintainer account could push a malicious commit before anyone notices.
   git clone -b v0.4.3 --depth 1 https://github.com/inflightsec/agent-vault-proxy && cd agent-vault-proxy
   mkdir -p secrets && bash -c '( umask 077 && read -rsp "BWS access token: " T && printf "%s" "$T" > secrets/bws-token && echo )'
   cp bindings.example.yaml bindings.yaml && $EDITOR bindings.yaml
   docker compose up -d
   ```

   Faster setup; weaker isolation than systemd. Threat model + caveats in [docs/docker.md](docs/docker.md).

   > ⚠️  **Two hard prerequisites for the Docker path:** (1) your AI agent's UID must NOT have docker daemon access — docker-group membership ≈ host root, which lets the agent `docker exec` the CA private key + BWS token out of the proxy. (2) Do NOT add other containers to the proxy's `avp-net` network. If either is hard to guarantee on your host, use the systemd install path instead.

   A pre-built, cosign-signed container image at `ghcr.io/inflightsec/agent-vault-proxy:<tag>` is planned for v0.5.0 — `cosign verify` + `docker pull` will replace the clone-and-build step. Until then, build locally from the cloned tag.
   </details>

3. **Point your agent at the proxy:**

   First, copy the mitmproxy-generated CA cert into the calling shell's working dir. The location depends on install path:

   ```bash
   # systemd install (see install-systemd.md step 5):
   sudo cp /etc/agent-vault-proxy/ca.pem ./ca.pem && sudo chown "$USER" ./ca.pem

   # Docker install:
   docker cp agent-vault-proxy:/var/lib/agent-vault-proxy/.mitmproxy/mitmproxy-ca-cert.pem ./ca.pem
   ```

   Then point the agent at the proxy + give it the placeholder:

   ```bash
   export HTTPS_PROXY="http://127.0.0.1:14322"  NODE_EXTRA_CA_CERTS="$PWD/ca.pem"  SSL_CERT_FILE="$PWD/ca.pem"
   export GITHUB_PAT="github_pat_PLACEHOLDER_01HXY1234ABCDEFGHIJ"
   curl -H "Authorization: Bearer $GITHUB_PAT" https://api.github.com/user
   ```

## Add a secret

After the one-time setup, every new credential is the same three steps:

1. **Bitwarden:** add the real secret to the project from step 1 above (use a clear name like `GITHUB_PAT`).
2. **Bindings:** add a block to `bindings.yaml`, the BWS name, a placeholder string, the destination host(s), and how to inject it. Composite credentials (e.g. `base64(email:token)` for Jira / Atlassian Cloud) use `compose:` + a sandboxed Jinja2 template - see [`bindings.example.yaml`](bindings.example.yaml) for one-secret and composite patterns covering OpenAI, GitHub, Jira, Slack.
3. **Restart:** `sudo systemctl restart agent-vault-proxy.service` (or `docker compose restart agent-vault-proxy` if you went with Docker). Verify with a request from the calling shell: the proxy audits every decision to `/var/log/agent-vault-proxy/audit.jsonl`.

That's it. Your agent uses the placeholder; the proxy swaps it for the real value on the wire.

## Deeper docs

- [docs/prerequisites.md](docs/prerequisites.md) — Bitwarden Secrets Manager setup (10 minutes, do this first)
- [docs/install-systemd.md](docs/install-systemd.md) — full bare-metal Linux + systemd walkthrough (the recommended install path on Linux)
- [docs/docker.md](docs/docker.md) — full Docker walkthrough (threat model, troubleshooting, rootless option) for the cross-platform / dev-box install path
- [docs/usage.md](docs/usage.md) — env-var setup for the calling shell, configuration reference
- [bindings.example.yaml](bindings.example.yaml) — full config schema with reference patterns for Anthropic, OpenAI, GitHub, Groq, Mistral, DigitalOcean

Alternative install for the embed / library case:

- **`pipx install agent-vault-proxy`** — for embedding AVP into your own Ansible role, Nix derivation, container image with hash-pinned deps, or an existing Python venv. Also the right entry point if you're writing a new `SecretsBackend` adapter. Same wheel that the recommended systemd install uses under the hood; you supply the service-supervision layer yourself. The PyPI badge at the top of this README links to the published artifact.

## Privacy

The proxy never phones home. The only outbound connections it makes are (1) to the Bitwarden Secrets Manager endpoint you configure in `bindings.yaml`, and (2) the upstream APIs your agent is actually calling on your behalf. No analytics, telemetry, update checks, crash reports or metrics export.

The audit log under `/var/log/agent-vault-proxy/audit.jsonl` is local-only.

## Security model

Nine binary, individually-testable invariants (G1–G9): the agent process address space never contains real secret bytes; substitution only happens on permitted destinations; failures are closed; audit events are fsynced before the modified request goes on the wire. See [docs/architecture.md](docs/architecture.md) for the threat model, invariant tests, hardening checklist, and accepted residual risks.

**Trust-store trade-off.** The blast radius of a proxy compromise scales with how much you route through it. Point AVP at one agent and a proxy compromise exposes that agent's TLS; point your whole dev machine at it and the same compromise sees every TLS connection that machine makes. More coverage = bigger single point of interception. Decide deliberately.

Vulnerability reports: [SECURITY.md](SECURITY.md).

## Status

**v0.4.3**, single-line follow-up to v0.4.2 — fixes a `__version__` skew in the published v0.4.2 wheel (`pyproject.toml` was bumped to 0.4.2 but `src/agent_vault_proxy/__init__.py` still reported `"0.4.1"`). Cosmetic only; the v0.4.2 proxy code was byte-for-byte identical to v0.4.1, so substitution and audit behavior were correct. v0.4.3 makes `agent_vault_proxy.__version__` agree with the wheel metadata. **v0.4.2**, release-tooling patch on top of v0.4.1 — fixes a grep in the PyPI install-smoke harness that mis-classified the `unmatched_destination_policy: deny` audit event (the proxy itself was always returning 403 + auditing correctly). No proxy code changes; v0.4.1's guarantees are unchanged. **v0.4.1**, security + review-followup release on top of v0.4.0. Closes a G6 fail-open path (any uncaught backend exception now returns 503 + audits rather than forwarding the placeholder), tightens config validation (`extra="forbid"` everywhere, placeholder structural checks, eager backend.config validation, case-insensitive host matching, cgroup v2 container detection in preflight), hardens the Dockerfile to install from the hash-pinned lockfile, and ships a Docker E2E harness exercised in CI. v0.4.0 introduced composite secret bindings (`compose:` + sandboxed Jinja2 templates), the `SecretsBackend` Protocol adapter architecture, and hash-pinned dev lockfiles. v0.3 was skipped. Full entries in [CHANGELOG.md](./CHANGELOG.md).

The wire-format invariants (G1–G9) are stable and exercised regularly against live Anthropic, OpenAI, GitHub, Groq, Mistral, and DigitalOcean APIs. Validation: 289+ automated tests passing, two rounds of adversarial review per feature (pentest + cross-model Oracle), and the hardening checklist from [`docs/architecture.md`](docs/architecture.md) walked end-to-end. The wire invariants will not change before 1.0; the configuration schema may.

Not yet supported: OAuth refresh-token flows, AWS SigV4, multi-tenant routing, off-host BWS broker, admin Unix socket / MCP interface. The [`avp bindings diff`](docs/architecture.md) semantic-review CLI, cosign-signed `ghcr.io` container images, SBOMs at build time, and a published Ansible role are planned for v0.5.0+.

Other vault backends (1Password, HashiCorp Vault as a source, etc.) plug in via the `SecretsBackend` Protocol - see [docs/adapter-architecture.md](docs/adapter-architecture.md) for the design. PRs that add an adapter for an additional vault are welcome.

## Contributing

Bug reports and PRs welcome. New here? Check the [good first issues](https://github.com/inflightsec/agent-vault-proxy/labels/good%20first%20issue) for starter-sized contributions. For changes that touch the G1–G9 invariants, please open an issue first, [docs/architecture.md](docs/architecture.md) describes what we're trying to preserve. Setup, testing, and pre-commit hooks in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT - see [LICENSE](LICENSE).
