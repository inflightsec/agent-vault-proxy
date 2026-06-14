# Linux: composing AVP with a filesystem sandbox

AVP keeps real API keys out of the agent's environment. A filesystem sandbox keeps the agent out of `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc`, `~/.npmrc`, browser cookies, and other places worms scan even when they can't reach env vars. Use both.

macOS has [SandVault](https://github.com/webcoyote/sandvault) — one well-maintained Apache 2.0 wrapper that "just works". Linux has no single equivalent. This page covers the option we recommend (`bubblewrap`) and short notes on the alternatives.

## Recommended: bubblewrap

[`bubblewrap`](https://github.com/containers/bubblewrap) is what Flatpak is built on. It uses Linux user namespaces — not setuid root — so a sandbox compromise doesn't become a privilege escalation. Install via your distro: `apt install bubblewrap`, `dnf install bubblewrap`, `pacman -S bubblewrap`.

### Starter recipe

```bash
mkdir -p ~/.cache/avp-sandbox-home ~/.claude

bwrap \
  --ro-bind /usr /usr \
  --ro-bind /etc /etc \
  --symlink usr/lib   /lib   \
  --symlink usr/lib64 /lib64 \
  --symlink usr/bin   /bin   \
  --symlink usr/sbin  /sbin  \
  --proc /proc --dev /dev --tmpfs /tmp \
  --tmpfs /home \
  --bind ~/.cache/avp-sandbox-home "$HOME" \
  --bind ~/.claude                 "$HOME/.claude" \
  --bind "$PWD" "$PWD" --chdir "$PWD" \
  --die-with-parent \
  --setenv HOME "$HOME" \
  --setenv HTTPS_PROXY        http://127.0.0.1:14322 \
  --setenv NODE_EXTRA_CA_CERTS /etc/agent-vault-proxy/ca.pem \
  --setenv SSL_CERT_FILE       /etc/agent-vault-proxy/ca.pem \
  --setenv NODE_USE_ENV_PROXY  1 \
  -- claude
```

What this gets you:

- `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc`, `~/.npmrc`, browser cookies, GPG agent sockets — all invisible to the agent.
- The current project dir is writable; everything else under `$HOME` is a fresh tmpfs except `~/.claude` (so session state survives).
- Network is shared (bwrap's default) so the agent can reach the local AVP proxy on `127.0.0.1:14322`. **Do not add `--unshare-net`** — AVP needs network.
- `--die-with-parent` kills the agent if you `Ctrl-C` the shell.

Tune as you go: if the agent complains about a missing path, RW-bind it; if it shouldn't see something under `$HOME` you're currently bind-mounting, drop the bind.

If you'd rather not set `HTTPS_PROXY` etc. in the sandbox launch directly, replace the trailing `-- claude` with `-- avp run claude` — `avp run` does the env-var work and exec-replaces itself with claude inside the sandbox.

## Dedicated Unix user (simpler, weaker)

If `bwrap` is too much, a separate user (`useradd -m _claude`, `su -l _claude -c "avp run claude"`) gives you basic process-table and file-permission isolation: `~/.ssh` etc. of your main user are unreadable to `_claude` by default. Less defense-in-depth than `bwrap`, but two lines of setup.

## Why not firejail

[`firejail`](https://github.com/netblue30/firejail) is popular and easier to invoke, but it ships setuid root and has had recurring local-privilege-escalation CVEs over the years. For a tool whose entire point is reducing attack surface, recommending a setuid binary as the default Linux story is hard to justify. If you already use firejail with a tuned profile, AVP works inside it fine — we just don't recommend it as the entry point.

## systemd-run for daemon-style use

For non-interactive agents running as a service, `systemd-run --user --scope -p ProtectHome=tmpfs -p PrivateTmp=yes -p ProtectSystem=strict ... -- avp run …` gets you similar isolation with no extra dep. Awkward for interactive shells; reasonable for scheduled tasks or CI.
