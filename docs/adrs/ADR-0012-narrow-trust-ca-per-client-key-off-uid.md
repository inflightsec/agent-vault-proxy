---
status: accepted
date: 2026-06-12
relates_to: ADR-0011 (BWS-notes bindings)
---

# ADR-0012: Narrow-trust CA via per-client bundle, key off-UID

## Context

AVP is a loopback HTTPS-intercepting proxy; clients must trust its CA to let it terminate+re-originate TLS. Simple mode targets **agents and simple proxy-honoring apps** on the operator's own machine, whose dominant threat model is **supply-chain compromise** (a poisoned dependency running at the agent's UID — Shai-Hulud class).

An adversarial red-team and cross-model review warned that the *common* way to deploy a MITM CA — adding it to the **OS / browser system trust store**, with its **private key readable at the user's UID** — can make such a proxy **net-negative vs. not installing it**: same-UID malware reads the CA key and forges a valid cert for *any* site (bank, email, the Bitwarden vault), and can impersonate bound hosts to harvest the very secrets the proxy injects. It is also irreversible (you cannot un-trust a CA from thousands of already-trusting clients).

**Verification (2026-06-12) — AVP already avoids this.** The shipped install does NOT use the OS/browser trust store and already isolates the key:
- README setup and `usage.md` trust the CA **per-client** via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` (env-var bundle), never `security add-trusted-cert` / `update-ca-certificates`.
- The systemd install keeps the CA **private key in `/var/lib/agent-vault-proxy/.mitmproxy/`, owned by `avp` mode `0700`** — off the agent's UID.
- The README "Security model" already documents the trust-store blast-radius trade-off ("route deliberately").

So this ADR is **largely a ratification of existing design**, not a migration. Its job is to make narrow-trust a **hard invariant** (so a future doc/install never regresses to OS-store trust) and to close the small remaining gaps.

## Decision

For simple mode, **do not add the AVP CA to any OS or browser trust store.** Instead:

1. **Per-client trust via CA-bundle env vars.** Clients trust the AVP CA through `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `CURL_CA_BUNDLE`, set **ambiently** in the shell profile alongside `HTTPS_PROXY`. Trust is scoped to exactly the clients AVP serves; blast radius of a stolen CA key drops from "all of this user's TLS" to "the agent clients pointed at AVP."

2. **CA private key off the agent's UID.** The proxy runs as a dedicated service user (`avp` — already created by the systemd install). The CA **private key** is `0600`, owned by `avp`; the public CA cert is world-readable so clients can trust it. A poisoned dependency running as the operator's UID **cannot read the CA key** — it can still abuse the proxy's authority (already documented out-of-scope in `concepts.md`), but cannot forge certs to steal injected secrets.

3. **No macOS keychain trust step.** A consequence, not a side quest: removing OS-store trust removes the unavoidable macOS admin-password prompt. Install gets simpler *because* it got safer.

### Status of each point (verified 2026-06-12)

1. Per-client CA-bundle trust — **already shipped** (README/usage.md). This ADR adds: make it the canonical/only documented simple-mode path; ensure all four vars (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`) appear in the primary docs, not just usage.md; have `avp setup` write them ambiently alongside `HTTPS_PROXY`.
2. CA key off-UID — **already shipped** (`avp`-owned `0700`). This ADR: ratify as invariant; nothing to change on systemd. (Docker/macOS dev paths get a doctor check.)
3. No OS-store trust / no macOS prompt — **already true** (no `add-trusted-cert` in any recommended path). This ADR: add an `avp doctor` check that **warns if the AVP CA is found in any OS/browser trust store** (regression guard), and document "never add to the system store" as a hard rule.

**Genuine remaining deltas (the only new work):**
- `avp doctor` regression check (CA not in OS store; CA key perms `0700`/`avp`).
- Four-var bundle in primary docs + `avp setup` writing them ambiently (overlaps the `avp env`/setup follow-up).
- Per-install `install_salt` generated at `avp setup` (shared with the placeholder spec in ADR-0011's amendment).

## Consequences

**Positive**
- AVP is net-positive under its own supply-chain threat model: the CA key is not stealable by same-UID malware, and a narrow CA can't MITM the whole machine.
- Simpler install (no keychain prompt, no `update-ca-trust`).
- Reversible: per-client env-var trust is removed by unsetting four vars.

**Negative / accepted**
- Clients that consult **only** the OS trust store and ignore the CA-bundle env vars are not covered — notably **Go on macOS** (native verifier ignores `SSL_CERT_FILE`). Accepted: out of the "agents + simple apps" scope.
- Per-client env vars must be present in the client's environment — fine under the ambient model; GUI desktop apps that don't inherit the profile are out of scope.
- The hardened systemd file-mode install may still offer OS-store trust for operators who want it; simple mode does not.

**Neutral**
- mitmproxy supports bring-your-own-CA via `--set confdir=`; the `avp`-owned key lives there with `0600`.
