# Bare-metal install (Linux + systemd)

Requires Linux, systemd, and `sudo`. Allow ~10 minutes for first-time setup. The proxy runs as a dedicated UNIX user (`avp`), never as root, and never as the same user as your AI agent.

**The separation matters.** If the proxy and the agent share a UID, the agent can `ptrace` the proxy, read its memory, and read its BWS token - and the whole isolation model collapses. The steps below set this up correctly.

Prerequisite: complete [prerequisites.md](prerequisites.md) (BWS account + token + organization UUID).

## 1. Create the user, directories, and append-only audit log

Pick your platform.

**Linux:**

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin kow

sudo install -d -o root -g kow  -m 0750 /etc/kow
sudo install -d -o kow  -g kow  -m 0750 /var/lib/kow
sudo install -d -o kow  -g kow  -m 0750 /var/log/kow
sudo install -d -o root -g root -m 0755 /opt/kow

sudo touch  /var/log/kow/audit.jsonl
sudo chown  kow:kow /var/log/kow/audit.jsonl
sudo chmod  0640    /var/log/kow/audit.jsonl
sudo chattr +a      /var/log/kow/audit.jsonl
```

**macOS:**

```bash
# DERIVE a free id — do NOT hardcode one. 250 in particular is taken by the
# stock `_analyticsusers` group on every Mac; reusing it leaves you with a group
# that has no PrimaryGroupID, and the `install -d -g _kow` below then fails with
# "illegal group name".
ID=$(for i in $(seq 450 550); do \
       dscl . -list /Groups PrimaryGroupID | awk -v G=$i '$2==G' | grep -q . || \
       { echo $i; break; }; done)
echo "using uid/gid $ID"
sudo dseditgroup -o create -i "$ID" _kow
sudo dscl . -create /Users/_kow  UniqueID "$ID"
sudo dscl . -create /Users/_kow  PrimaryGroupID "$ID"
sudo dscl . -create /Users/_kow  UserShell /usr/bin/false
sudo dscl . -create /Users/_kow  NFSHomeDirectory /var/empty

sudo install -d -o root -g _kow  -m 0750 /usr/local/etc/kow
sudo install -d -o _kow -g _kow  -m 0750 /usr/local/var/lib/kow
sudo install -d -o _kow -g _kow  -m 0750 /usr/local/var/log/kow

sudo touch   /usr/local/var/log/kow/audit.jsonl
sudo chown   _kow:_kow /usr/local/var/log/kow/audit.jsonl
sudo chmod   0640      /usr/local/var/log/kow/audit.jsonl
sudo chflags sappnd    /usr/local/var/log/kow/audit.jsonl   # BSD append-only
```

The append-only flag (`chattr +a` on Linux, `chflags sappnd` on macOS) makes the audit log unrewritable without first explicitly stripping it. That strip is a visible, auditable event. The proxy refuses to start if the audit log is unwritable, so this step has to happen before the unit is enabled.

> **Platform notes for macOS:** The proxy itself runs (mitmproxy is cross-platform), but the hardening story is meaningfully weaker, `launchd` is service supervision, not a sandbox, and there's no equivalent to systemd's `ProtectSystem`, `RestrictAddressFamilies`, or syscall filter. If the host is a credible target, run the proxy inside Docker or a Linux VM. Steps 2-5 reference Linux paths; on macOS, prefix `/etc/` and `/var/{lib,log}/` with the Homebrew prefix — `$(brew --prefix)`, which is `/usr/local` on Intel and `/opt/homebrew` on Apple Silicon and use `launchctl load -w /Library/LaunchDaemons/io.inflightsec.kow.plist` in place of systemd commands.

## 2. Install the package into a system-wide venv

```bash
sudo python -m venv /opt/kow/.venv
sudo /opt/kow/.venv/bin/pip install --only-binary :all: keys-on-the-wire
```

`--only-binary :all:` refuses source distributions. Wheels can't run scripts at install time by format spec, so this is the strongest install-time defense against a compromised transitive dependency.

## 3. Drop your BWS token and binding config into place

```bash
# Token from Prerequisites step 3 — root-owned, avp-readable, no world access
sudo install -o root -g kow -m 0440 your-bws-token /etc/kow/bws-token

# Fetch the example config and edit for your secrets
sudo curl -fsSL -o /etc/kow/bindings.yaml \
  https://raw.githubusercontent.com/inflightsec/keys-on-the-wire/main/bindings.example.yaml
sudo chown root:kow /etc/kow/bindings.yaml
sudo chmod 0640     /etc/kow/bindings.yaml
sudoedit /etc/kow/bindings.yaml
```

## 4. Install the systemd unit and start the daemon

Copy the hardened unit from [systemd-unit.md](systemd-unit.md) to `/etc/systemd/system/kow.service`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kow
systemctl is-active kow          # expect: active
ss -tln | grep 127.0.0.1:14322                 # expect: LISTEN
```

## 5. Trust the CA

mitmproxy generates its own CA on the first proxied request - no need for manual keypair generation or `openssl req`:

```bash
# Trigger CA generation. The curl will TLS-fail; the cert gets written either way.
curl -x http://127.0.0.1:14322 -sS https://example.com -o /dev/null || true

# mitmproxy creates .mitmproxy/ as 0755. The CA PRIVATE key lives there, so
# tighten it to owner-only (ADR-0012) — `kow doctor` fails the install otherwise.
sudo chmod 0700 /var/lib/kow/.mitmproxy

sudo install -m 0644 -o root -g root \
  /var/lib/kow/.mitmproxy/mitmproxy-ca-cert.pem \
  /etc/kow/ca.pem
```

The CA private key stays inside `/var/lib/kow/.mitmproxy/`, owned by `kow` mode `0700`. Do not regenerate the CA on subsequent deploys: anything pinned to `/etc/kow/ca.pem` will break. Rotation procedure in [systemd-unit.md](systemd-unit.md#ca-rotation).


## Upgrading from an `agent-vault-proxy` install

`kow` is the canonical name everywhere; a pre-rename install keeps working
untouched until 2.0.0. Nothing below is required — it is what still resolves if
you do nothing:

| Canonical | Still accepted |
|---|---|
| `/etc/kow/`, `/var/lib/kow/`, `/var/log/kow/` | the same paths under `agent-vault-proxy/` |
| `kow.service` | an existing `agent-vault-proxy.service` unit |
| `--set kow_config=` | `--set avp_config=` (logs a deprecation warning) |
| `~/.config/kow/env` | `~/.config/avp/env` |
| `healthz.kow.invalid` | `healthz.agent-vault-proxy.invalid` |
| `KOW_CONFDIR` | `AVP_CONFDIR` (warns) |
| `kow` / `keys-on-the-wire` commands | `avp` / `agent-vault-proxy` |

Resolution prefers the `kow` path and falls back only when the pre-rename one is
the one that exists (`src/kow/_paths.py`). Re-running `kow setup` on a pre-rename
host adopts its existing directories rather than laying a second tree beside them.
Vault-side markers (`avp-binding` notes/tags/annotations, `avp-PLACEHOLDER-`
prefixes) are unchanged — do not rewrite them.

Continue to [usage.md](usage.md) to point your agent at the proxy.
