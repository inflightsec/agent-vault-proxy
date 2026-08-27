# Keys on the Wire

**Your AI agent never holds your API keys. It sends a placeholder; the real secret is swapped in on the wire.**

Stops credential stealers (Shai-Hulud and similar) and prompt-injected agents from leaking your secrets. A compromised agent has nothing to take.

[![PyPI](https://img.shields.io/pypi/v/keys-on-the-wire.svg)](https://pypi.org/project/keys-on-the-wire/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![CI](https://github.com/inflightsec/keys-on-the-wire/actions/workflows/test.yml/badge.svg)](https://github.com/inflightsec/keys-on-the-wire/actions/workflows/test.yml)

## How it works

1. Your agent sends a request with a *placeholder*, not the key.
2. Keys on the Wire swaps in the real secret from your vault, in transit.
3. The agent never sees the key. Nothing to leak, nothing to steal.

![How Keys on the Wire substitutes secrets on the wire](docs/how-it-works-animated.svg)

Under the hood it's a loopback HTTPS proxy. It fetches each credential from your vault just in time and injects it into the outbound request, so the calling process (your agent, or anything else you route through it) never holds the real bytes.

Vault backends: **macOS Keychain**, Bitwarden Secrets Manager, Google Secret Manager, AWS Secrets Manager, `static` (no vault, for trying it out) and `env`. On a Mac the Keychain backend needs no cloud vault account and no extra dependency: your secrets stay where they already are. (`kow setup` still defaults to Bitwarden; pass the backend you want.) See [Adapter architecture](docs/adapter-architecture.md).

## See it in action

[![Keys on the Wire demo: prompt injection vs. credential isolation](docs/demo.svg)](docs/demo.cast)

## Quickstart

**1. Install** (Linux `pipx`, macOS `brew`):

```bash
pipx install 'keys-on-the-wire[bitwarden]'
# macOS: brew install inflightsec/keys-on-the-wire/keys-on-the-wire
sudo kow setup --bws
```

**2. Install the skill** so your agent writes the binding for you:

```
/plugin marketplace add inflightsec/keys-on-the-wire
/plugin install kow@keys-on-the-wire
```

**3. Broker a service.** Say *"route the Stripe API through Keys on the Wire."* The skill mints the placeholder and prints the exact note to paste into your vault. It never sees your key.

**4. Add the real key** to your vault with that note, then route your agent through the proxy:

```bash
kow env && kow run claude
```

Done. The agent only ever sends the placeholder; Keys on the Wire swaps in the real key on the wire.

New to this? The [Quickstart guide](docs/quickstart.md) walks the first run in full, and [Prerequisites](docs/prerequisites.md) covers vault setup. Prefer shell env vars over `kow run`? See [Usage](docs/usage.md).

## Before you point it at production keys

Fair questions if the credentials in question move money. Short answers here, detail behind the links.

**Trial it behind one process, not your whole machine.** `kow run -- <command>` sets the proxy and CA variables in the spawned process only; your login shell never inherits them. No global `HTTPS_PROXY`, no system-wide CA trust, nothing to unpick afterwards. See [Scoping to a single process](docs/single-process.md).

**When the proxy is down, calls fail.** Traffic routed through kow cannot reach upstream if kow is not there, and a binding that denies returns 503 rather than passing the request through bare. Fail-closed is the default and the only mode. [Concepts](docs/concepts.md) covers the reasoning.

**It does not stop an agent being talked into using a key.** kow removes the key from the agent's context. It does not read the agent's mind about *why* it is calling an API, so a prompt-injected agent can still make calls the placeholder is bound to. Narrow each binding with `methods:` and `paths:` and you cut most of the accident case; that is enforced, not advisory. The bundled skill now writes `methods:` explicitly on every new binding, so new bindings are scoped by construction ([ADR-0047](docs/adrs/ADR-0047-destination-policy-defaults.md)). The engine default for a binding that omits `methods:` is still permissive, and such a binding logs a one-time advisory rather than being blocked. kow does not rate-limit or inspect payloads: it is a credential proxy, not an API gateway. The honest boundary is in [Architecture](docs/architecture.md).

**Auth that is not a static header is supported.** OAuth2 refresh and client-credentials, JWT bearer, GitHub App, HMAC signing and AWS SigV4 all ship as injectors. Amazon SP-API is buildable from the LWA refresh plus signing pieces, but there is no ready-made Amazon preset yet; presets exist for Google, Microsoft, Auth0, Slack, Atlassian and Okta.

**There is an audit log**, local-only, recording which binding was used for which request. It never records secret values.

**Versions are tagged.** The published version is whatever the [PyPI badge](https://pypi.org/project/keys-on-the-wire/) at the top of this page reports; per-release changes are in the [CHANGELOG](./CHANGELOG.md).

## Broker an MCP server

Each MCP server holds a long-lived upstream token (a GitHub PAT, a Slack or Brave key) in cleartext in your client config, where every server the client loads can read it. `kow mcp install` replaces that standing secret with a placeholder and routes the server's egress through the proxy:

```
kow mcp install github --host api.github.com --env-var GITHUB_PERSONAL_ACCESS_TOKEN \
  --server-cmd "npx -y @modelcontextprotocol/server-github"
```

It prints the vault note to paste and the exact `claude mcp add --env` / `codex mcp add --env` command. Propose-only for the vault; the secret value is never touched. Design and threat model: [ADR-0040](docs/adrs/ADR-0040-mcp-server-credential-broker.md).

## The binding is one line

Onboarding a credential is not hand-written YAML. The bundled [kow skill](skills/kow/) asks the auth shape and host, then tells you exactly what to paste into your secret's Notes field:

```
# kow-binding
api.acme.com
```

The marker line is what makes it a binding. A note whose first line isn't `# kow-binding` (or the still-accepted `# avp-binding`) stays a plain human description, never parsed ([ADR-0025](docs/adrs/ADR-0025-notes-binding-marker.md)). The assistant proposes; you apply. It never sees or stores the secret.

## Docs

**Start here**
- [Is Keys on the Wire for you?](docs/is-it-for-you.md) covers what it does, what it deliberately does not, and when to reach for it. Start here if you're evaluating.
- [Quickstart](docs/quickstart.md) is a 10-minute first run ending in a visible substitution.
- [Prerequisites](docs/prerequisites.md) sets up your vault. Do this first.

**Understand**
- [Concepts](docs/concepts.md) explains placeholder, binding, the CA, and fail-closed in plain terms.
- [Architecture](docs/architecture.md) is the threat model, the G1 to G9 invariants, hardening, and residual risks.

**Install and operate**
- Install: [Linux](docs/install-systemd.md) · [Docker](docs/docker.md) · [macOS](https://github.com/inflightsec/homebrew-keys-on-the-wire)
- [Usage](docs/usage.md) points your agent at the proxy.
- [Scoping to a single process](docs/single-process.md) wraps one command instead of your whole machine. Start here for a low-commitment trial.
- [Linux isolation](docs/linux-isolation.md) composes Keys on the Wire with `bubblewrap` for filesystem sandboxing.
- [macOS isolation](docs/macos-isolation.md) explains the deployment that makes the boundary real — the agent in a separate account (SandVault), kow as a LaunchAgent in yours — and exactly what the Keychain does and does not buy when both run as the same user.
- [Google Secret Manager](docs/gcp-secret-manager.md) covers keyless auth and end-to-end testing.

**Reference**
- [bindings.example.yaml](bindings.example.yaml) is the full config schema.
- [Adapter architecture](docs/adapter-architecture.md) covers the vault backends and how to add one.
- [Comparison](docs/comparison.md) weighs Keys on the Wire against Vault Agent, Doppler, `op run`, `superfly/tokenizer`, OneCLI, and others.
- [CHANGELOG](./CHANGELOG.md) · [SECURITY](./SECURITY.md) · [CONTRIBUTING](./CONTRIBUTING.md) · [CREDITS](./CREDITS.md)

## Open source, no lock-in

Every feature is in this repo under Apache-2.0. No paywalled tier, enterprise edition, hosted service, or telemetry. You can read the whole thing end to end (a few thousand lines) and run it forever. The goal is fewer real keys inside AI agents everywhere; if an [alternative](docs/comparison.md) fits your setup better, use that.

The proxy never phones home. Its only outbound connections are to the vault endpoint you configure and the upstream APIs your agent calls. The audit log is local-only by default; optional [off-box shipping](docs/adrs/ADR-0019-off-box-audit-shipping.md) forwards it, from a separate sidecar and never the proxy, only to a collector you run and control.

The patent grant is deliberate for a security tool ([ADR-0037](docs/adrs/ADR-0037-relicense-apache-2.0.md)). One optional dependency is not open source: the Bitwarden backend pulls [`bitwarden-sdk`](https://pypi.org/project/bitwarden-sdk/) under Bitwarden's proprietary [SDK license](https://github.com/bitwarden/sdk). You install it yourself only if you use that backend (`[bitwarden]`); the AWS Secrets Manager, Google Secret Manager, and env backends are 100% open source. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Releases up to 0.9.0 remain available under their original MIT terms and the `kow` name.

---

\* Formerly `kow`. The CLI is now `kow`; the old `avp` command still works this release and is removed in the next major. The note marker now defaults to `# kow-binding` (the old `# avp-binding` is still accepted); the on-disk paths keep their names this release for backward compatibility. See [ADR-0045](docs/adrs/ADR-0045-rename-keys-on-the-wire.md).
