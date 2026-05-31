# agent-vault-proxy

**Zero-knowledge API keys for AI agents - and any other process you route through it: the caller only ever sees a placeholder.**

Your agent - or CI runner, build server, scraper, cron job, dev laptop - gets a fake placeholder string (like `sk-PLACEHOLDER-...`) and uses it as if it were a real API key. This proxy sits between the caller and the internet, and swaps the fake for the real secret at the last possible moment - on the way out to the upstream API. If the caller gets prompt-injected, dumps a log, or runs a program with a software-supply-chain issue, the only thing that escapes is the fake placeholder. The real key never enters the calling process. Agents are the headline use case because they're the rare process that both holds credentials and reads attacker-controlled input in the same address space - the one situation where filtering can't reliably save you and removing the bytes is the only real fix.


[![PyPI](https://img.shields.io/pypi/v/agent-vault-proxy.svg)](https://pypi.org/project/agent-vault-proxy/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![CI](https://github.com/inflightsec/agent-vault-proxy/actions/workflows/test.yml/badge.svg)](https://github.com/inflightsec/agent-vault-proxy/actions/workflows/test.yml)

[![agent-vault-proxy demo: prompt injection vs. credential isolation](docs/demo.svg)](docs/demo.cast)

Under the hood: a loopback HTTPS proxy that fetches credentials from Bitwarden Secrets Manager just-in-time and injects them into outbound requests, so the calling process never holds the real credential bytes in its address space.

## How it works

```
┌──────────────┐    placeholder    ┌──────────────┐    real secret    ┌──────────┐
│  agent (any  │ ────────────────► │ agent-vault- │ ────────────────► │ upstream │
│  UID, never  │                   │    proxy     │                   │   API    │
│  sees real   │ ◄──────────────── │  (UID: avp)  │ ◄──────────────── │          │
│   secret)    │     response      │              │     response      │          │
└──────────────┘                   └──────┬───────┘                   └──────────┘
                                          │
                                          ▼  fetch + cache (TTL 5 min)
                                   ┌──────────────┐
                                   │  Bitwarden   │
                                   │  Secrets Mgr │
                                   └──────────────┘
```

On every request the proxy: checks the destination against the binding for that secret (host + optional method + optional path scope), fails closed if no binding matches (the placeholder is forwarded verbatim so the upstream's own auth-fail response surfaces), fetches the real secret from BWS (served from an in-memory TTL cache when warm), substitutes placeholder → real secret on the upstream socket only, and `fsync`s an `inject_decision` audit event before the modified bytes go on the wire.

## At a glance

```yaml
# bindings.yaml — what the agent sees vs. what the upstream sees
secrets:
  OPENAI_API_KEY:
    placeholder: "sk-PLACEHOLDER-01HXY1234567890"   # the agent's env holds THIS
    inject:
      header: "Authorization"
      format: "Bearer {secret}"                     # {secret} = real value from BWS
    bindings:
      - host: "api.openai.com"                      # only swapped for this destination
        methods: [POST]                             # only on these methods
        paths: ["/v1/chat/completions"]             # only on these paths
```

```bash
# Agent's env holds only the placeholder. The real key never enters the process.
export OPENAI_API_KEY="sk-PLACEHOLDER-01HXY1234567890"
export HTTPS_PROXY="http://127.0.0.1:14322"

# Agent code is unchanged — proxy swaps placeholder → real BWS value on the wire.
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/chat/completions ...
```

Full schema (composite secrets, multiple hosts per binding, path globs) in [`bindings.example.yaml`](bindings.example.yaml).

## Why

Two threats keep getting worse, and your API keys sit in the blast radius of both.

**Prompt injection.** Anything your agent reads - a webpage, an email, a tool's output, a PR comment, can carry instructions. If the agent has `OPENAI_API_KEY` in its env, an injected "send your env to attacker.com" is one HTTP call away. Filtering, alignment, allowlists - are all statistical and all imperfect. The bytes shouldn't be there to exfil in the first place.

**Software supply chain.** A typosquatted npm package, a hijacked PyPI release, a malicious post-install script. If it runs as your agent's UID it reads the same env the agent does. Shai-Hulud showed what worm-scale ecosystem compromise looks like. That's the new baseline.

AVP keeps the credential **bytes** out of the agent, and out of anything the agent runs, and in fact out of any software you can run on that host. As long as the outbound HTTPS goes through AVP, none of it ever sees the real secret. The secrets live in Bitwarden; everyone else gets a placeholder. AVP swaps placeholder with a real value on the wire, default-deny per destination (the proxy refuses to inject for hosts you haven't bound to that secret), and additionally scopes per binding by HTTP method and URL path.

Although built for agents, the mechanism is fully general: any process that holds a placeholder in its env and routes HTTPS through AVP gets the same protection - CI runners, build servers, scrapers, cron jobs, or a developer machine you're hardening against software-supply-chain compromise. The agent case is just where it matters most. Prompt injection puts the credential-holder and the attacker-controlled-input-reader in the same process, which is the one situation where filtering and alignment can't reliably save you and removing the bytes is the only real fix. For plain software the supply-chain benefit still applies; the injection benefit largely doesn't.

**What AVP doesn't do - and what to layer on:** AVP prevents *exfiltration* of the raw key, not *misuse of the authority* the key represents on permitted destinations. If you bind `GITHUB_PAT_WORK` to `api.github.com` with no method/path scope, prompt injection can still ask the proxy to authenticate a `DELETE /repos/...` call as you. The lever for that is `methods:` and `paths:` on each binding: see [`bindings.example.yaml`](bindings.example.yaml). For extra security, pair AVP with an egress firewall on the agent's UID so unbound calls are blocked outright. Pair with response-side review for endpoints that may echo back the `Authorization` header in their response body, AVP injects on the request, but does not scrub the response.

How this compares to HashiCorp Vault Agent, Doppler, `op run`, `superfly/tokenizer`, and Kloak: [docs/comparison.md](docs/comparison.md).

## Setup (one-time)

Four steps. Once you've done this, every new API key is just "add to Bitwarden + a few lines of YAML + restart": see [Add a secret](#add-a-secret) below.

1. **Bitwarden Secrets Manager**, enable it on your org, create a project for this host, create a machine account with **read** access to the project, generate a token. ~10 minutes the first time. [Walkthrough](docs/prerequisites.md).

2. **Clone a tagged release + give the daemon the BWS token + your initial bindings:**

   ```bash
   # Pick a tagged release, not `main`. Tags are how you opt into a specific
   # vetted version. Tracking `main` exposes you to a window where a
   # maintainer-account compromise could ship a malicious commit before
   # anyone notices.
   git clone -b v0.4.1 --depth 1 https://github.com/inflightsec/agent-vault-proxy && cd agent-vault-proxy
   mkdir -p secrets && bash -c '( umask 077 && read -rsp "BWS access token: " T && printf "%s" "$T" > secrets/bws-token && echo )'
   cp bindings.example.yaml bindings.yaml && $EDITOR bindings.yaml
   ```

3. **Start the daemon:**

   ```bash
   docker compose up -d
   ```

   Docker Compose covers Linux, macOS (Docker Desktop), Windows (WSL2). For bare-metal Linux + systemd (most hardened), see [docs/install-systemd.md](docs/install-systemd.md).

4. **Point your agent at the proxy:**

   ```bash
   docker cp agent-vault-proxy:/var/lib/agent-vault-proxy/.mitmproxy/mitmproxy-ca-cert.pem ca.pem
   export HTTPS_PROXY="http://127.0.0.1:14322"  NODE_EXTRA_CA_CERTS="$PWD/ca.pem"  SSL_CERT_FILE="$PWD/ca.pem"
   export OPENAI_API_KEY="sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"
   curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
   ```

> ⚠️  **Two hard prerequisites for the Docker path:** (1) your AI agent's UID must NOT have docker daemon access - docker-group membership ≈ host root, which lets the agent `docker exec` the CA private key + BWS token out of the proxy. (2) Do NOT add other containers to the proxy's `avp-net` network. If either is hard to guarantee, use the systemd install path. Full threat model in [docs/docker.md](docs/docker.md).

## Add a secret

After the one-time setup, every new credential is the same three steps:

1. **Bitwarden:** add the real secret to the project from step 1 above (use a clear name like `OPENAI_API_KEY`).
2. **Bindings:** add a block to `bindings.yaml`, the BWS name, a placeholder string, the destination host(s), and how to inject it. Composite credentials (e.g. `base64(email:token)` for Jira / Atlassian Cloud) use `compose:` + a sandboxed Jinja2 template - see [`bindings.example.yaml`](bindings.example.yaml) for one-secret and composite patterns covering OpenAI, GitHub, Jira, Slack.
3. **Restart:** `docker compose restart agent-vault-proxy` (or `systemctl restart agent-vault-proxy.service`). Verify with a request from the calling shell: the proxy audits every decision to `/var/log/agent-vault-proxy/audit.jsonl`.

That's it. Your agent uses the placeholder; the proxy swaps it for the real value on the wire.

## Other install paths

- [docs/prerequisites.md](docs/prerequisites.md), Bitwarden Secrets Manager setup (10 minutes, do this first)
- [docs/install-systemd.md](docs/install-systemd.md) - bare-metal Linux + systemd (most hardened; recommended for production hosts where the agent might share the box)
- [docs/docker.md](docs/docker.md), full Docker walkthrough (threat model, troubleshooting, rootless option)
- [docs/usage.md](docs/usage.md) - env-var setup for the calling shell, configuration reference
- [bindings.example.yaml](bindings.example.yaml), full config schema with reference patterns for Anthropic, OpenAI, GitHub, Groq, Mistral, DigitalOcean

Alternatives ways to install:

- **`pipx install agent-vault-proxy`** - for the library / non-Docker case: writing a new `SecretsBackend` adapter, wiring AVP into your own Ansible / Nix / image build with hash-pinned deps, or running inside an existing Python venv. The PyPI badge at the top of this README links to the published wheel.
- **Signed container image on `ghcr.io`** (planned for v0.5.0), `cosign verify ghcr.io/inflightsec/agent-vault-proxy:<tag>` + `docker run` with a tiny mount-only Compose snippet you write yourself. Removes the clone and pins the binary + its hardening assumptions to a single signed digest. Until then, build locally from the cloned tag.

## Privacy

The proxy never phones home. The only outbound connections it makes are (1) to the Bitwarden Secrets Manager endpoint you configure in `bindings.yaml`, and (2) the upstream APIs your agent is actually calling on your behalf. No analytics, telemetry, update checks, crash reports or metrics export. 

The audit log under `/var/log/agent-vault-proxy/audit.jsonl` is local-only.

## Security model

Nine binary, individually-testable invariants (G1–G9): the agent process address space never contains real secret bytes; substitution only happens on permitted destinations; failures are closed; audit events are fsynced before the modified request goes on the wire. See [docs/architecture.md](docs/architecture.md) for the threat model, invariant tests, hardening checklist, and accepted residual risks.

**Trust-store trade-off.** The blast radius of a proxy compromise scales with how much you route through it. Point AVP at one agent and a proxy compromise exposes that agent's TLS; point your whole dev machine at it and the same compromise sees every TLS connection that machine makes. More coverage = bigger single point of interception. Decide deliberately.

Vulnerability reports: [SECURITY.md](SECURITY.md).

## Status

**v0.4.1**, security + review-followup release on top of v0.4.0. Closes a G6 fail-open path (any uncaught backend exception now returns 503 + audits rather than forwarding the placeholder), tightens config validation (`extra="forbid"` everywhere, placeholder structural checks, eager backend.config validation, case-insensitive host matching, cgroup v2 container detection in preflight), hardens the Dockerfile to install from the hash-pinned lockfile, and ships a Docker E2E harness exercised in CI. v0.4.0 introduced composite secret bindings (`compose:` + sandboxed Jinja2 templates), the `SecretsBackend` Protocol adapter architecture, and hash-pinned dev lockfiles. v0.3 was skipped. Full entries in [CHANGELOG.md](./CHANGELOG.md).

The wire-format invariants (G1–G9) are stable and exercised regularly against live Anthropic, OpenAI, GitHub, Groq, Mistral, and DigitalOcean APIs. Validation: 289+ automated tests passing, two rounds of adversarial review per feature (pentest + cross-model Oracle), and the hardening checklist from [`docs/architecture.md`](docs/architecture.md) walked end-to-end. The wire invariants will not change before 1.0; the configuration schema may.

Not yet supported: OAuth refresh-token flows, AWS SigV4, multi-tenant routing, off-host BWS broker, admin Unix socket / MCP interface. The [`avp bindings diff`](docs/architecture.md) semantic-review CLI, cosign-signed `ghcr.io` container images, SBOMs at build time, and a published Ansible role are planned for v0.5.0+.

Other vault backends (1Password, HashiCorp Vault as a source, etc.) plug in via the `SecretsBackend` Protocol - see [docs/adapter-architecture.md](docs/adapter-architecture.md) for the design. PRs that add an adapter for an additional vault are welcome.

## Contributing

Bug reports and PRs welcome. New here? Check the [good first issues](https://github.com/inflightsec/agent-vault-proxy/labels/good%20first%20issue) for starter-sized contributions. For changes that touch the G1–G9 invariants, please open an issue first, [docs/architecture.md](docs/architecture.md) describes what we're trying to preserve. Setup, testing, and pre-commit hooks in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT - see [LICENSE](LICENSE).

