# keys-on-the-wire

**Just-in-time API keys for AI agents and any other process you route through it: the caller only ever sees a placeholder.**

*Formerly `agent-vault-proxy`. The CLI is now `kow`; the old `avp` command still works this release and is removed in the next major ([ADR-0045](docs/adrs/ADR-0045-rename-keys-on-the-wire.md)).*

Keys on the Wire protects you from credential stealers (Shai-Hulud and similar) and prompt-injected agents leaking your secrets. It's a local proxy that injects real secrets into requests in-flight, so a compromised or prompt-injected agent has nothing to steal.

[![PyPI](https://img.shields.io/pypi/v/keys-on-the-wire.svg)](https://pypi.org/project/keys-on-the-wire/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![CI](https://github.com/inflightsec/keys-on-the-wire/actions/workflows/test.yml/badge.svg)](https://github.com/inflightsec/keys-on-the-wire/actions/workflows/test.yml)

![How keys-on-the-wire substitutes secrets on the wire](docs/how-it-works-animated.svg)

Under the hood: a loopback HTTPS proxy that fetches credentials from [Bitwarden Secrets Manager](https://github.com/bitwarden) (cloud or self-hosted) just-in-time and injects them into outbound requests, so the calling process never holds the real credential bytes in its address space.

## Fully open source, deliberately simple

Every feature is in this repo under Apache-2.0, with no paywalled tier, enterprise edition, trusted cloud, or telemetry. You can read the whole thing end to end (a few thousand lines) and run it forever.

The whole workflow is one move: ask the bundled skill to route a service, it tells you the single line to paste into Bitwarden (or your vault), you paste it, and the agent is brokered. Done. Because every brokered credential is one binding, the config **is** the complete, auditable list of exactly which secrets each agent can reach: nothing implicit or hidden.

The goal is fewer real keys inside AI agents everywhere, not lock-in. If Keys on the Wire fits, use it; if one of the [alternatives](docs/comparison.md) fits your setup better, use that. Any tool that keeps the real secret out of the agent's memory is a win.

## Try it. 10 seconds.

**1. Install** - Linux `pipx`, macOS `brew`:

```bash
pipx install 'keys-on-the-wire[bitwarden]'   # [bitwarden] adds the Bitwarden backend SDK; drop it for AWS/GSM/env only
# macOS: brew install inflightsec/kow/keys-on-the-wire
sudo kow setup --bws        # paste your Bitwarden token — generates the CA, starts the daemon
```

**2. Install the skill** so your agent writes the binding for you:

```
/plugin marketplace add inflightsec/agent-vault-proxy
/plugin install avp@agent-vault-proxy
```

**3. Ask the skill to broker a service** - say *"route the Stripe API through Keys on the Wire."* It mints the placeholder and prints the exact note to paste into BitWarden; it never sees your key.

**4. Put the secret in your vault** - add the real key to Bitwarden Secrets Manager (or Google Secret Manager) with that note, then route your agent through the proxy:

```bash
kow env && kow run claude
```

Done: the agent only ever sends the placeholder; Keys on the Wire swaps in the real key on the wire.

*Rather than `kow run`, you can export the proxy + CA vars in your agent's `~/.zshrc` (or any shell rc) - see [Usage](docs/usage.md) for the canonical block. It's persistent, but it routes your whole shell through Keys on the Wire, not just the agent it launches.*

## See it in action

[![keys-on-the-wire demo: prompt injection vs. credential isolation](docs/demo.svg)](docs/demo.cast)

## Add a secret with your AI agent: no config editing

Onboarding a new brokered credential shouldn't mean hand-writing binding YAML. The bundled **[avp skill](skills/avp/)** lets an AI assistant (Claude Code, or any agent that loads skills) walk you through it: you say *"route the Acme API through Keys on the Wire,"* it asks the auth shape and host, then tells you **exactly** what to add: the secret name plus the annotation to paste into the **Bitwarden Secrets Manager Notes field** (or the **Google Secret Manager `avp-binding` annotation**, or a future backend's per-secret metadata). No config edit or redeploy, and the assistant **never sees or stores the secret**; it proposes, you apply.

The note itself is two lines pasted into the secret's Notes field:

```
# avp-binding
api.acme.com
```

The marker line is what makes it a binding: a note whose first line isn't `# avp-binding` stays what it is, a human description, never parsed ([ADR-0025](docs/adrs/ADR-0025-notes-binding-marker.md)). *(The `avp-binding` marker and on-disk paths keep their names this release for backward compatibility; they move to `kow` in the next major - see [ADR-0045](docs/adrs/ADR-0045-rename-keys-on-the-wire.md).)*

### Install the skill

**Claude Code (recommended)** - install it as a plugin, so it's available in every project and updates with `/plugin marketplace update`:

```
/plugin marketplace add inflightsec/agent-vault-proxy
/plugin install avp@agent-vault-proxy
```

Invoke it as `/avp:avp`, or just say *"route the Acme API through Keys on the Wire"* and it triggers on its own. *(The bundled plugin keeps the `avp` name for now; it is renamed with the marketplace migration.)*

**Manual (any agent that loads Anthropic-format skills)** - copy or symlink `skills/avp/` into your agent's skills directory; Claude Code reads `~/.claude/skills/`. A symlink keeps it current on `git pull`:

```
ln -s "$PWD/skills/avp" ~/.claude/skills/avp
```

## Broker an MCP server

MCP servers are a fast-growing credential-leak surface: each holds a long-lived upstream token (a GitHub PAT, a Slack/Brave/Perplexity key) **in cleartext in your client config**, where every server the client loads can read it. `kow mcp install` replaces that standing secret with a placeholder and routes the server's egress through the proxy, so the real value never lives in the config:

```
kow mcp install github --host api.github.com --env-var GITHUB_PERSONAL_ACCESS_TOKEN \
  --server-cmd "npx -y @modelcontextprotocol/server-github"
```

It prints the vault note to paste **and** the exact `claude mcp add --env` / `codex mcp add --env` command (proxy + per-runtime CA-trust + placeholder env): propose-only for the vault, the secret value is never touched. The bundled **[avp skill](skills/avp/)** can derive the host/header/format from the server's docs and confirm the host with you first. Design + threat model: **[ADR-0040](docs/adrs/ADR-0040-mcp-server-credential-broker.md)**.

## Docs

- **[Is Keys on the Wire for you?](docs/is-it-for-you.md)** - what it does, what it deliberately does not do, why, and when to reach for it (start here if you're evaluating)
- **[Quickstart](docs/quickstart.md)** - 10-minute first run ending in a visible substitution
- **[Concepts](docs/concepts.md)** - placeholder, binding, the CA, fail-closed, in plain terms
- **[Prerequisites](docs/prerequisites.md)** - Bitwarden Secrets Manager setup (do this first)
- **[Linux install](docs/install-systemd.md)** · **[Docker](docs/docker.md)** · **[macOS](https://github.com/inflightsec/homebrew-kow)**
- **[Usage](docs/usage.md)** - pointing your agent at the proxy
- **[Linux isolation](docs/linux-isolation.md)** - composing Keys on the Wire with `bubblewrap` for filesystem sandboxing
- **[bindings.example.yaml](bindings.example.yaml)** - full config schema
- **[avp skill](skills/avp/)** - let an AI assistant author your notes/annotation bindings (propose-only, no config edit, no redeploy)
- **[Broker an MCP server](docs/adrs/ADR-0040-mcp-server-credential-broker.md)** - run Claude Code / Codex MCP servers with no plaintext credential (`kow mcp install`)
- **[Architecture](docs/architecture.md)** - threat model, G1–G9 invariants, hardening, residual risks
- **[Adapter architecture](docs/adapter-architecture.md)** - vault backends (Bitwarden, Google Secret Manager, and AWS Secrets Manager ship today, `static` for dev) and how to add another
- **[Google Secret Manager](docs/gcp-secret-manager.md)** - keep secrets in GSM: setup, keyless auth, and end-to-end testing
- **[Comparison](docs/comparison.md)** - vs. Vault Agent, Doppler, `op run`, `superfly/tokenizer`, OneCLI, and other agent credential tools (use whichever fits: the point is more agents protected, not lock-in)
- **[CHANGELOG](./CHANGELOG.md)** · **[SECURITY](./SECURITY.md)** · **[CONTRIBUTING](./CONTRIBUTING.md)** · **[CREDITS](./CREDITS.md)**

The proxy never phones home. The only outbound connections it makes are to the BWS endpoint you configure and the upstream APIs your agent is calling. No telemetry. The audit log under `/var/log/agent-vault-proxy/audit.jsonl` is local-only by default; optional [off-box shipping](docs/adrs/ADR-0019-off-box-audit-shipping.md) forwards it (from a separate sidecar, never the proxy) only to a collector you run and control.

## License

Apache-2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE); the explicit patent grant is deliberate for a security tool ([ADR-0037](docs/adrs/ADR-0037-relicense-apache-2.0.md)). Every feature ships here, with no open-core, enterprise tier, or hosted service. Fork it, read it end to end, run it forever. Releases up to 0.9.0 remain available under their original MIT terms and the `agent-vault-proxy` name. Prior art acknowledged in [`CREDITS.md`](./CREDITS.md).

**One dependency is not open source, and it's opt-in.** The optional Bitwarden backend pulls [`bitwarden-sdk`](https://pypi.org/project/bitwarden-sdk/), which is under Bitwarden's own [proprietary SDK license](https://github.com/bitwarden/sdk), not Apache-2.0. Keys on the Wire never bundles it; you install it yourself (`pip install 'keys-on-the-wire[bitwarden]'`) only if you use that backend. The default install and the AWS Secrets Manager, Google Secret Manager, and env backends are 100% open source.
