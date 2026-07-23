---
status: accepted
date: 2026-07-19
relates_to: docs/ROADMAP.md (Security posture — "Scope TLS termination to bound hosts"), ADR-0012 (narrow-trust CA), ADR-0019 (off-box audit / honeytoken shipping), ADR-0023 (closed audit event-type set), docs/architecture.md §4.4
---

# ADR-0026: Scope TLS termination to bound hosts; passthrough for everything else

> **Status: ACCEPTED (2026-07-20).** Passthrough (not deny) chosen for unbound hosts — see
> "Rejected: deny / egress allow-list". Numbers below reference the 0.8.0 behavior.

## Context

AVP is a mitmproxy-based forward proxy. Today it **TLS-terminates every host** that transits it,
bound or not: the client pins the AVP CA, AVP mints a leaf cert per host, decrypts, (maybe)
injects, re-encrypts upstream. For the ~14 bound hosts that is the product. For every *unbound*
host it is pure downside:

- **Privacy/attack surface** — AVP holds plaintext of traffic it will never touch (agent chatter
  to package registries, docs sites, telemetry endpoints). A compromised AVP reads *everything*,
  not just brokered flows.
- **Trust posture** — the AVP CA is a universal MITM credential for its clients. Scoping
  termination means unbound TLS is verified by the client against the **real web PKI**,
  end-to-end — AVP physically cannot read it. This shrinks what a stolen AVP CA key is worth.
- **Compatibility/perf** — cert-pinning clients break today on unbound hosts they should never
  have been intercepted for; double-crypto on bulk downloads (model weights via `HF_TOKEN`'s CDN
  fan-out is bound by *suffix* — see Open questions) costs real CPU.

## Decision (proposed)

Terminate TLS **only** for hosts the live config binds; every other CONNECT is tunneled as an
opaque byte stream (no CA cert minted, no decryption).

Mechanics — mitmproxy's `tls_clienthello` hook, **dynamic per-connection**:

1. On `tls_clienthello`, resolve the connection's authority (CONNECT host, falling back to SNI)
   against the **current config snapshot**: exact host index + `*.suffix` wildcard entries — the
   same matcher as request-time binding lookup (`secrets_for_host`).
2. Match → proceed with termination (today's path, unchanged: injection, scope checks, audit,
   honeytokens).
3. No match → `data.ignore_connection = True`: raw TCP passthrough. No leaf cert, no plaintext.
4. The decision is per-connection at handshake time, so **config hot-reload keeps working**: a
   host bound mid-flight applies to new connections (existing tunnels stay tunnels — document).
5. The `/healthz` sentinel is plain HTTP (no CONNECT/TLS) — unaffected.
6. A config knob `tls_termination: bound | all` (default **`bound`**). `all` preserves today's
   full-termination behavior (max observability) and is the escape hatch if a passthrough edge
   case bites.
7. **Passthrough is logged, not silent.** Each tunneled (unbound) connection emits a lightweight
   `tls_passthrough` audit event carrying only the destination host and the decision reason — no
   secret material, no plaintext (there is none to leak; the connection was never decrypted). This
   keeps exfil *visibility* in the passthrough model: an operator sees *where* the agent is
   tunneling even though AVP does not read or block it. Added to the ADR-0023 closed event set.

## Rejected: deny / egress allow-list

The stronger alternative — **deny** every unbound host, making AVP an egress allow-list that blocks
the agent from reaching anywhere it lacks a secret — was considered and **rejected** (2026-07-20).
Deny is the better *blast-radius* story (a hijacked agent cannot use AVP as an exfil conduit at
all), and it flips the honeytoken trade-off favorably (a denied host is a visible, audited refusal,
so no signal is lost). But it breaks AVP's operating model: the agent legitimately reaches many
no-secret hosts (PyPI, npm, docs, un-tokenised GitHub endpoints), so deny requires a second,
per-deployment `allow_unbound` list maintained *alongside* the vault — and that list differs per
process/experiment. That is exactly the "drop a secret in the vault and you're done" North Star
this project exists to protect: the operator should not have to do egress surgery every time they
point an agent at a new host. Blocking, where wanted, stays with the host's existing egress layer
(nftables / OpenSnitch), which already owns that concern and does not couple it to the vault.
The `tls_passthrough` event (point 7) recovers the *visibility* half of deny's value without its
maintenance cost. If a future deployment genuinely wants AVP-as-egress-gate, it is a separate
opt-in mode (`tls_termination: allowlist` + `allow_unbound`), not the default — out of scope here.

## Consequences

**Good**
- Unbound traffic becomes cryptographically invisible to AVP — the broker can only read what it
  brokers. Strong story for the threat model (T-1.x: compromised-proxy blast radius).
- Pinned-cert clients and gRPC/TLS-fingerprinting SDKs stop breaking on unbound hosts.
- Less CPU on bulk unbound transfers; smaller audit log (see the trade-off below).

**Trade-offs (the real costs — review these)**
1. **Honeytoken coverage narrows.** Today a honeytoken placeholder aimed at *any* host —
   including unbound ones — is visible in plaintext and trips the `honeytoken_triggered` wire.
   With passthrough, the "placeholder walked toward a random unbound host" signal disappears
   inside the tunnel. Retained: honeytoken *trap hosts are bound by definition*, so the
   designed-for signal (the decoy being *used* at its trap) survives; what is lost is incidental
   detection of the placeholder leaking toward unrelated TLS destinations. (Plain-HTTP unbound
   traffic remains visible.) Mitigation: `tls_termination: all` for max-observability installs.
2. **Audit visibility shrinks.** `upstream_response` events for unbound HTTPS hosts vanish
   (CONNECT-level metadata could be audited instead — host, byte counts, duration — a new
   lightweight `tls_passthrough` event; keeps the closed event-type set honest, ADR-0023).
3. **Scope-violation observability.** A bound secret's placeholder sent toward an *unbound* host
   today produces an audited pass-through-unsubstituted decision; under passthrough AVP cannot
   see it. The *security* invariant is unchanged (no injection happens either way — injection
   requires a binding); what is lost is the audit breadcrumb.

## Resolved decisions (were open questions)

- **`forward_unmodified` bindings → keep terminating.** The binding's existence declares "I want
  AVP watching this host", so a bound host is always in the terminate set regardless of injector.
- **IP-literal CONNECTs → passthrough.** Never bindable today (bindings are hostnames), so they
  fall to the tunnel path like any other unmatched authority. Emit `tls_passthrough` with the IP.
- **Wildcard fan-out** — `*.suffix` bindings (the HF CDN case) pull every matching subdomain into
  termination, correct by construction (the same matcher as request-time lookup).
- **Authority resolution → SNI first, CONNECT host fallback.** mitmproxy's `tls_clienthello`
  exposes the SNI; use it, falling back to the CONNECT/server-address host when SNI is absent. A
  mismatching SNI on a *terminated* connection still hits today's SNI-mismatch handling, unchanged;
  passthrough tunnels are not decrypted so no further inspection applies.

## Test strategy (sketch)

- docker-e2e adds: unbound HTTPS host → client verifies the **upstream's real certificate**
  (proof AVP did not mint); bound host unchanged; host added via hot-reload terminates on a new
  connection; `tls_termination: all` reproduces today's full-termination suite verbatim.
- Unit: authority-resolution matcher (CONNECT host, SNI fallback, IP literal, wildcard) against
  the live snapshot.
