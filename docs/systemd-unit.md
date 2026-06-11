# Systemd unit (hardened)

Drop the unit below at `/etc/systemd/system/agent-vault-proxy.service`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now agent-vault-proxy
```

The rationale for each directive is in [`architecture.md`](./architecture.md) §5 (Hardening checklist).

```ini
[Unit]
Description=agent-vault-proxy — BWS-backed egress credential injector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=avp
Group=avp
ExecStart=/opt/agent-vault-proxy/.venv/bin/python -m agent_vault_proxy --set avp_config=/etc/agent-vault-proxy/bindings.yaml

# HOME must point inside ReadWritePaths so mitmproxy can write its CA at
# $HOME/.mitmproxy/. ProtectHome=yes still hides /home, /root, /run/user.
Environment=HOME=/var/lib/agent-vault-proxy

# Filesystem hardening
ReadWritePaths=/var/log/agent-vault-proxy /var/lib/agent-vault-proxy
ReadOnlyPaths=/etc/agent-vault-proxy /opt/agent-vault-proxy
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
ProtectHostname=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
NoNewPrivileges=yes

# MemoryDenyWriteExecute is intentionally OFF: cffi (used by mitmproxy and
# bitwarden-sdk) needs W+X for callback trampolines. Other hardening
# (ProtectSystem=strict, syscall filter, address-family restrict, etc.)
# is still in force.
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## First-boot CA generation

The CA is generated and installed during the install procedure: see [install-systemd.md](install-systemd.md#5-trust-the-ca) step 5. Unit-specific detail: with `HOME=/var/lib/agent-vault-proxy` (set above), mitmproxy writes the CA under `/var/lib/agent-vault-proxy/.mitmproxy/`. Do not regenerate it on later deploys, any caller that pinned the old `ca.pem` would break. To rotate it deliberately, see below.

## CA rotation

Plan for a CA rotation every 6–12 months, or immediately if you suspect the proxy host has been compromised. The procedure:

```bash
# 1. Stop the proxy and back up the old CA dir + installed cert.
sudo systemctl stop agent-vault-proxy
sudo cp -a /var/lib/agent-vault-proxy/.mitmproxy /var/lib/agent-vault-proxy/.mitmproxy.bak.$(date +%Y%m%d)
sudo cp -a /etc/agent-vault-proxy/ca.pem /etc/agent-vault-proxy/ca.pem.bak.$(date +%Y%m%d)

# 2. Remove the old CA material so mitmproxy regenerates on next start.
sudo rm /var/lib/agent-vault-proxy/.mitmproxy/mitmproxy-ca-cert.pem \
        /var/lib/agent-vault-proxy/.mitmproxy/mitmproxy-ca.pem
sudo systemctl start agent-vault-proxy

# 3. Make any request through the proxy to trigger CA generation, then install
#    the new cert in place. Callers will fail TLS verification until they're
#    updated to the new CA, so do this in a maintenance window.
sudo install -m 0644 -o root -g root \
  /var/lib/agent-vault-proxy/.mitmproxy/mitmproxy-ca-cert.pem \
  /etc/agent-vault-proxy/ca.pem
```

Audit the rotation in the operator log (this is a manual ritual, not yet a runbook the daemon emits).

## Append-only audit log

Created during install: see [install-systemd.md](install-systemd.md#1-create-the-user-directories-and-append-only-audit-log) step 1. `chattr +a` makes the file append-only at the filesystem level, so root itself cannot rewrite history without first stripping the attribute (a visible, auditable event). The proxy refuses to start if the audit log is unwritable (`fail_on_unwritable: true`).

## Verifying the install

```bash
# Service running?
systemctl is-active agent-vault-proxy

# Listening on loopback?
ss -tln | grep 127.0.0.1:14322

# Recent decisions?
sudo tail /var/log/agent-vault-proxy/audit.jsonl

# Round-trip test (placeholder must be in your shell env as documented in README)
curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" \
  https://api.openai.com/v1/models -o /dev/null -w "%{http_code}\n"
# Expect 200 + a fresh inject_decision in the audit log.
```
