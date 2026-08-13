# Bare-metal install (Linux + systemd)

Requires Linux, systemd, and `sudo`. Allow ~10 minutes for first-time setup. The proxy runs as a dedicated UNIX user (`avp`), never as root, and never as the same user as your AI agent.

**The separation matters.** If the proxy and the agent share a UID, the agent can `ptrace` the proxy, read its memory, and read its BWS token - and the whole isolation model collapses. The steps below set this up correctly.

Prerequisite: complete [prerequisites.md](prerequisites.md) (BWS account + token + organization UUID).

## 1. Create the user, directories, and append-only audit log

Pick your platform.

**Linux:**

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin avp

sudo install -d -o root -g avp  -m 0750 /etc/agent-vault-proxy
sudo install -d -o avp  -g avp  -m 0750 /var/lib/agent-vault-proxy
sudo install -d -o avp  -g avp  -m 0750 /var/log/agent-vault-proxy
sudo install -d -o root -g root -m 0755 /opt/agent-vault-proxy

sudo touch  /var/log/agent-vault-proxy/audit.jsonl
sudo chown  avp:avp /var/log/agent-vault-proxy/audit.jsonl
sudo chmod  0640    /var/log/agent-vault-proxy/audit.jsonl
sudo chattr +a      /var/log/agent-vault-proxy/audit.jsonl
```

**macOS:**

```bash
# Pick an unused UID/GID below 500. Check what's in use:
#   dscl . -list /Users UniqueID | sort -k2 -n
sudo dscl . -create /Groups/_avp PrimaryGroupID 250
sudo dscl . -create /Users/_avp  UniqueID 250
sudo dscl . -create /Users/_avp  PrimaryGroupID 250
sudo dscl . -create /Users/_avp  UserShell /usr/bin/false
sudo dscl . -create /Users/_avp  NFSHomeDirectory /var/empty

sudo install -d -o root -g _avp  -m 0750 /usr/local/etc/agent-vault-proxy
sudo install -d -o _avp -g _avp  -m 0750 /usr/local/var/lib/agent-vault-proxy
sudo install -d -o _avp -g _avp  -m 0750 /usr/local/var/log/agent-vault-proxy

sudo touch   /usr/local/var/log/agent-vault-proxy/audit.jsonl
sudo chown   _avp:_avp /usr/local/var/log/agent-vault-proxy/audit.jsonl
sudo chmod   0640      /usr/local/var/log/agent-vault-proxy/audit.jsonl
sudo chflags sappnd    /usr/local/var/log/agent-vault-proxy/audit.jsonl   # BSD append-only
```

The append-only flag (`chattr +a` on Linux, `chflags sappnd` on macOS) makes the audit log unrewritable without first explicitly stripping it. That strip is a visible, auditable event. The proxy refuses to start if the audit log is unwritable, so this step has to happen before the unit is enabled.

> **Platform notes for macOS:** The proxy itself runs (mitmproxy is cross-platform), but the hardening story is meaningfully weaker, `launchd` is service supervision, not a sandbox, and there's no equivalent to systemd's `ProtectSystem`, `RestrictAddressFamilies`, or syscall filter. If the host is a credible target, run the proxy inside Docker or a Linux VM. Steps 2-5 reference Linux paths; on macOS, prefix `/etc/` and `/var/{lib,log}/` with `/usr/local/` and use `launchctl load -w /Library/LaunchDaemons/io.inflightsec.agent-vault-proxy.plist` in place of systemd commands.

## 2. Install the package into a system-wide venv

```bash
sudo python -m venv /opt/agent-vault-proxy/.venv
sudo /opt/agent-vault-proxy/.venv/bin/pip install --only-binary :all: keys-on-the-wire
```

`--only-binary :all:` refuses source distributions. Wheels can't run scripts at install time by format spec, so this is the strongest install-time defense against a compromised transitive dependency.

## 3. Drop your BWS token and binding config into place

```bash
# Token from Prerequisites step 3 — root-owned, avp-readable, no world access
sudo install -o root -g avp -m 0440 your-bws-token /etc/agent-vault-proxy/bws-token

# Fetch the example config and edit for your secrets
sudo curl -fsSL -o /etc/agent-vault-proxy/bindings.yaml \
  https://raw.githubusercontent.com/inflightsec/keys-on-the-wire/main/bindings.example.yaml
sudo chown root:avp /etc/agent-vault-proxy/bindings.yaml
sudo chmod 0640     /etc/agent-vault-proxy/bindings.yaml
sudoedit /etc/agent-vault-proxy/bindings.yaml
```

## 4. Install the systemd unit and start the daemon

Copy the hardened unit from [systemd-unit.md](systemd-unit.md) to `/etc/systemd/system/agent-vault-proxy.service`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now keys-on-the-wire
systemctl is-active keys-on-the-wire          # expect: active
ss -tln | grep 127.0.0.1:14322                 # expect: LISTEN
```

## 5. Trust the CA

mitmproxy generates its own CA on the first proxied request - no need for manual keypair generation or `openssl req`:

```bash
# Trigger CA generation. The curl will TLS-fail; the cert gets written either way.
curl -x http://127.0.0.1:14322 -sS https://example.com -o /dev/null || true

sudo install -m 0644 -o root -g root \
  /var/lib/agent-vault-proxy/.mitmproxy/mitmproxy-ca-cert.pem \
  /etc/agent-vault-proxy/ca.pem
```

The CA private key stays inside `/var/lib/agent-vault-proxy/.mitmproxy/`, owned by `avp` mode `0700`. Do not regenerate the CA on subsequent deploys: anything pinned to `/etc/agent-vault-proxy/ca.pem` will break. Rotation procedure in [systemd-unit.md](systemd-unit.md#ca-rotation).

Continue to [usage.md](usage.md) to point your agent at the proxy.
