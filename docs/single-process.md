# Scoping to a single process

The fastest way to trial Keys on the Wire is to put it behind one command, not your whole machine. `kow run` exists for exactly this.

```bash
kow run -- ./scraper.py
```

That sets `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` and `NODE_USE_ENV_PROXY` **in the spawned process only**. Your login shell never inherits them. Nothing is written to your shell profile, and there is nothing to unpick if you decide against it. Placeholder exports written by `kow env` are loaded into that child too, so the host shell stays clean of those as well.

## Why start here

Two reasons, and the second is the interesting one.

**Onboarding cost.** Setting a global `HTTPS_PROXY` and getting CA trust working across Bun, Python, `launchd` jobs and MCP servers is a weekend of work. Wrapping one command is an afternoon, and it tells you whether the tool earns its place before you pay the larger cost.

**A smaller blast radius, honestly described.** Be clear about what wrapping does and does not buy. It does **not** make the proxy inescapable: the child inherits `HTTPS_PROXY` as an ordinary environment variable, and anything that can run code can unset it, or open a socket directly, and bypass kow entirely. No proxy-based design survives an agent that is actively trying to leave.

What it does buy is containment of *scope*. Only the wrapped process is routed, so the rest of your machine is untouched, no system-wide CA trust is installed, and nothing persists in your shell profile after the trial. If the untrusted input reaches only one component, routing only that component keeps the credential surface as small as the problem.

This is why the recommended trial is "put the scraper behind kow", not "put my machine behind kow". For a boundary an agent genuinely cannot step over, you need OS-level separation, not an environment variable: see [macOS isolation](macos-isolation.md) for the separate-account deployment, and [Linux isolation](linux-isolation.md) for `bubblewrap`.

## Picking the right process

Wrap the component that touches untrusted text, since that is where prompt injection enters:

| Setup | Wrap this |
|-------|-----------|
| Agent that scrapes or reads web pages | the scraper or fetch tool |
| Agent with MCP servers holding upstream tokens | use `kow mcp install` per server instead |
| Scheduled job moving orders or payments | the job itself, in the `launchd`/systemd unit |
| Full interactive agent session | `kow run -- claude` |

## Scheduled jobs

Put `kow run --` inside the unit's command rather than exporting variables in the surrounding environment. If kow is not running, the wrapped command's outbound calls fail rather than proceeding without credentials. For anything touching orders or payments that is the behaviour you want: loud failure over silent success with no auth.

## Going further on macOS

`kow run --sandvault` (or `kow sandvault`) additionally wraps the launch in the SandVault sandbox, adding filesystem confinement on top of the credential boundary. For the stronger deployment, where the agent runs in a separate macOS account entirely, see [macOS isolation](macos-isolation.md). On Linux, [linux isolation](linux-isolation.md) composes kow with `bubblewrap`.

## When to graduate to global routing

Once the wrapped trial has been running for a while and you want every process covered, move to the shell-environment approach in [Usage](usage.md). The trade is convenience against the fact that a global variable is a variable any process can unset.
