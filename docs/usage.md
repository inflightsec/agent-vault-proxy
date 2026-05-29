# Usage: pointing your agent at the proxy

With the daemon running (either install path), any HTTPS client can route through the proxy. In the calling shell - typically the shell that launches your agent:

```bash
# 1. Route through the proxy and trust its CA
export HTTPS_PROXY="http://127.0.0.1:14322"
export HTTP_PROXY="http://127.0.0.1:14322"
export NODE_EXTRA_CA_CERTS="/etc/agent-vault-proxy/ca.pem"
export SSL_CERT_FILE="/etc/agent-vault-proxy/ca.pem"
export REQUESTS_CA_BUNDLE="/etc/agent-vault-proxy/ca.pem"
export CURL_CA_BUNDLE="/etc/agent-vault-proxy/ca.pem"

# 2. Export the PLACEHOLDER — never the real value
export OPENAI_API_KEY="sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"

# 3. Use any HTTPS client. The proxy substitutes the placeholder for the real
#    secret on the way out, matching by binding scope (host + method + path).
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

The proxy records every substitution decision in an append-only JSONL audit log at `/var/log/agent-vault-proxy/audit.jsonl`.

## Configuration

YAML at `/etc/agent-vault-proxy/bindings.yaml`. Re-read on service restart. Minimal example:

```yaml
version: 1

secrets:
  GITHUB_PAT_WORK:
    placeholder: "ghp_PLACEHOLDER_WORK_01HXY1234567890"
    inject:
      header: "Authorization"
      format: "token {secret}"
    bindings:
      # Read-only on the REST API — POSTs and PATCHes forward the placeholder
      # verbatim, so a prompt-injected agent cannot create gists or open issues.
      - host: "api.github.com"
        methods: [GET]
      - host: "uploads.github.com"
```

Path globs: `*` matches one URL segment, `**` matches any number. Empty `methods: []` is rejected (deny-all-methods must be intentional: remove the binding instead). See [`bindings.example.yaml`](../bindings.example.yaml) for the full grammar and reference patterns for Anthropic, OpenAI, GitHub, Groq, Mistral, DigitalOcean, and others.

## Recommended layout for ongoing changes

After install, every new credential is "add to BWS + a few lines of YAML + restart." If you're using an AI coding agent (Claude Code, Codex, Cursor) to help write those bindings, you want a `git diff` review window between the agent's edit and your restart - that diff is what stops a prompt-injected edit from going live. (Threat: a single added `host:` entry under an existing binding can route a real secret to an attacker-controlled destination. See [`CLAUDE.md`](../CLAUDE.md) for the operating envelope.)

**Recommended: a small private git repo containing just your bindings.**

The repo itself is operational hygiene: version history, multi-host scale-out, a place for `git diff` to live. **It is not a security control.** The security control is (a) the operator reading the diff before restart and (b) only the operator being able to restart. The private-repo recommendation just makes both of those easier.

- **One repo, separate from this one.** Do not fork the AVP source repo for your config - your bindings have nothing to do with the upstream code and you'd inherit fork-maintenance for no benefit.
- **Path matters.** Put the repo where `npm` / `pip` / build tools don't traverse - typically not `~/projects/` and not the agent's CWD. Something like `~/.config/avp-bindings/` is fine. `chmod 0700` the directory so non-AVP-UID processes (like a postinstall hook from an unrelated `npm install`) can't read it.
- **Diff review is mandatory.** The agent edits `bindings.yaml` in your repo; you read the diff before restarting. Restart is your job, never the agent's. Treat `.gitignore`, any deploy script, and any `bindings.*` file as part of the diff review surface, the daemon reads exactly one file (`bindings.yaml`), so if your deploy script reads more than that, you've widened the gate.
- **No auto-restart.** Don't reach for `fswatch`, `inotify`, a `Makefile restart` target Claude can shell into, a post-commit hook, or a CI auto-deploy. All of them collapse the diff-review window to zero - exactly what the credential-isolation model relies on. If diff review feels tedious, the fix is better diff tooling, not automation around the restart.
- **`.gitignore` always:** `secrets/bws-token`, `ca.pem`, anything containing real values. Real values stay in Bitwarden Secrets Manager: the whole point of this proxy.
- **Multi-host:** branches or directories per host (e.g., `laptop/bindings.yaml`, `ci-runner/bindings.yaml`). Make sure your deploy command binds explicitly to the host it's targeting: accidentally shipping `laptop/bindings.yaml` to `ci-runner` cross-contaminates two hosts that were supposed to stay isolated.
- **Deploy step:** whatever fits your setup - `scp` + `systemctl restart` for systemd, `docker compose restart` for Docker, `ansible-playbook` for fleet. Keep it a one-line script you run by hand. The manual step IS the review gate.

