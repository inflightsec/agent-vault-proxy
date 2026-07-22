---
status: proposed
date: 2026-07-22
relates_to: docs/ROADMAP.md (Security posture — response-side echo defense), ADR-0011 (salt-derived placeholders), ADR-0019 (off-box audit / honeytoken tripwire — the prior-art tripwire pattern), ADR-0023 (closed audit event-type set), ADR-0025 (warn-don't-break config posture), ADR-0026 (TLS termination scoping — the scan set == the terminated set), docs/architecture.md §4.4
references:
  - RFC 7230 §3.3 (message body / Content-Length — response buffering + size cap)
  - RFC 7231 §3.1.2 (Content-Encoding — gzip/br must be decoded before scanning)
  - Reflected-input credential exfiltration (general web-security class; see Context)
---

# ADR-0031: Response-side secret echo scrubbing

> **Status: PROPOSED.** Design for a 0.10 security feature. Six decisions resolved with the
> principal (see "Resolved decisions"); not yet implemented. Supersedes nothing.

## Context

AVP replaces a placeholder with the real secret on **outbound** agent requests — in headers and,
for `type: body`, in the request body (streaming). The upstream therefore only ever receives the
**real secret value**; the placeholder never leaves AVP. That outbound substitution is the product.
It also opens a response-side exfiltration class we do not currently defend against:

- **Immediate reflection.** A hostile (or prompt-injected) agent plants the placeholder in a request
  field an upstream reflects back — an error message (`invalid token: <value>`), a debug echo, a
  "describe what you sent" endpoint. AVP substitutes the real secret outbound; the upstream echoes
  the real secret into the **response body/headers**, where the agent reads it.
- **Create-then-read (persistent).** The agent `POST`s `{"field": "<placeholder>"}` to *create* a
  resource. AVP substitutes → the resource now **stores the real secret**. A later plain `GET`
  returns it. Note: **on that GET, AVP injected nothing** — so a defense that only inspects requests
  where a substitution happened is blind to this variant.

Today AVP's `response` hook emits only `upstream_response` (status code); it neither retains the
injected secret nor inspects the response. The whole placeholder-injection category shares this hole:
because the outbound substitution is the point, the value that comes back is the real secret, not a
sentinel we can cheaply recognise.

**Why not just scan for the placeholder?** The placeholder is gone by response time — AVP replaced it
with the real value on the way out. The only time a placeholder appears in a response is when AVP
*declined* to substitute (off-scope forward), which is harmless. Catching the leak therefore requires
matching the **real injected value** in the response — which is what forces every decision below.

## Decision (proposed)

Add an **opt-in, per-binding response scan** that exact-matches the real injected secret value(s) in
responses from bound hosts and, on a hit, **redacts** by default. Paired with a cheap injection-time
first line. Six decisions:

1. **Two layers (both).** Response-scan is the backstop; injection-time surface reduction is the cheap
   first line. Neither alone suffices — headers rarely echo, bodies/query params do, and the scan is
   the only thing that catches create-then-read.

2. **Action on a hit → redact by default.** Replace only the secret's occurrences in the response
   body/headers with a fixed marker (`[avp-redacted]`); pass the rest through. Per-binding
   `on_echo: redact | block | tripwire` overrides — `block` returns a 502 (whole-response), `tripwire`
   passes the response untouched but audits. Redaction is the default because it stops the exfil with
   the smallest blast radius; a false hit costs a few bytes, not the whole response.
   **Honest limit (documented, not fixable here):** this catches *naive* reflection only. An upstream
   that base64-encodes, splits, or otherwise transforms the secret before echoing it defeats an exact
   substring scan. This is a strong tripwire for the common case, not a cryptographic guarantee.

3. **Scan scope → host-bound, opted-in secrets.** On a response from a bound host, scan for the values
   of that host's secrets **that set `echo_scan: true`** — regardless of whether this particular
   request injected anything (this is what closes create-then-read). Not "this request's injections
   only" (blind to create-then-read), not "all vault secrets on all traffic" (does not scale, holds
   the whole vault in the response path). Matching is against the **cached** secret value; a secret
   not currently in cache is a **documented gap** (audited `echo_scan_secret_not_cached`), not a
   silent miss — it is not fetched from the vault on the response path.

4. **Cost + oversized → fail closed past a cap.** Responses already buffer in mitmproxy; the scan is a
   single-pass multi-pattern match (see Performance). Scan scannable content-types up to a
   configurable size cap (default 2 MiB, on the decompressed length). **Past the cap AVP fails
   closed** — blocks with an audited `response_too_large_to_scan` — because a size-based pass-through
   is a one-line bypass (pad the response past the cap). Per-binding escape hatch
   `oversize_response: scan_ends | block` where `scan_ends` best-effort-scans the first+last N KiB and
   passes (for hosts that legitimately return large payloads). Known-binary content-types
   (`image/*`, `video/*`, `application/octet-stream`) are **skipped but audited**
   (`response_unscanned_binary`) so the blind spot is visible.

5. **Injection-time posture → graded.** Body injection (established, needed — webhooks, HMAC payloads,
   TOTP form fields) stays allowed but emits a `body_injection_echo_risk` **load-time warning** naming
   the secret + host (matches the ADR-0025 warn-don't-break posture). Query-param injection, when it
   ships (ADR-003x), is **born opt-in** (`allow_query_injection: true`) — URL params are logged
   everywhere and are the most echo-prone surface, so they must not be on by default.

6. **Matching precision → exact value-match, operator-gated, no entropy heuristic in the hot path.**
   The match is a plain exact substring search for the injected value. `echo_scan` is **per-binding
   opt-in**; at config-load AVP **warns** (`secret_too_weak_to_echo_scan`) if an opted-in secret's
   value is short/low-entropy enough that exact-searching it would collide with ordinary response text
   — it does not silently skip and runs no entropy math per request. Scan **response headers as well as
   the body** (headers are tiny; `Location`/`Set-Cookie` reflect input). **Decompress** `gzip`/`br`
   bound-host responses before scanning (skipping compressed responses is a trivial bypass); on an
   undecodable body, fail closed (`response_undecodable`).

## Performance requirements (first-class — the feature must be near-free on the hot path)

- **Gate before any work.** In order: (a) is the response's host bound and does it have ≥1
  `echo_scan` secret? if not → **zero work**; (b) content-type scannable? (c) size within cap? Only
  then scan. The overwhelmingly common case (host with no echo-scan secrets) short-circuits before
  touching the body.
- **Single-pass multi-pattern.** Build one Aho-Corasick automaton over the host's opted-in secret
  values **once per config (re)load**, not per request, not per secret. One linear pass over the
  buffered body finds all secrets simultaneously — no per-secret `in` scans, no regex.
- **Zero-copy scan; copy only to redact.** Scan the existing buffer in place; allocate a new body only
  when there is an actual hit to redact.
- **Bounded work.** The size cap + fail-closed ceiling bound worst-case scan time; decompression only
  runs when the host has something to scan for.

## Rejected / alternatives considered

- **Scan for the placeholder, not the value.** Rejected — the placeholder is substituted out before
  the request leaves AVP; the response carries the real value. Placeholder scanning finds only the
  harmless off-scope-forward case. (This was the principal's first instinct; the substitution
  direction rules it out — see Context.)
- **Automatic entropy floor as a scanning gate.** Rejected in favour of per-binding opt-in + a
  load-time weak-value warning (decision 6). No entropy math in the hot path; the operator owns the
  call, consistent with `allow_wildcard_hosts` / honeytoken opt-ins.
- **Scan all vault secrets on all responses.** Rejected (decision 3) — does not scale and holds the
  whole vault in the response path.
- **Block (whole-response) as the default action.** Rejected as default (decision 2) — too high a
  blast radius for a false hit; available per-binding via `on_echo: block`.
- **Pass-and-audit past the size cap.** Rejected (decision 4) — a size bypass defeats the feature;
  available per-binding via `oversize_response: scan_ends`.
- **Deny body injection by default.** Rejected (decision 5) — breaks shipped, legitimate bindings;
  the response scan is the enforcement, a load-time warning is the signal.
- **Punt entirely to network egress controls.** Egress controls (nftables/OpenSnitch) cannot see
  *inside* a TLS-terminated response body, and cannot distinguish a secret echo from ordinary traffic.
  This defense lives where the plaintext + the secret-to-value mapping already are: in AVP.

## Consequences

**Good**
- Closes the category's biggest hole: the real secret can no longer round-trip back to the agent via
  naive reflection or create-then-read, for opted-in bindings.
- Reuses the tripwire pattern operators already understand (honeytoken, ADR-0019) and the closed
  audit event-type discipline (ADR-0023).
- No new TLS blind spot: **the scan set == the inject set == the terminated set** (ADR-0026). You can
  only echo a secret that was injected; injection only happens on bound hosts; bound hosts are already
  decrypted. Unbound (passthrough) hosts hold no secret to echo.

**Trade-offs (review these)**
- **Naive-only.** Transform-then-echo defeats it (decision 2) — documented, not solved.
- **Cache dependence.** A create-then-read where the create fell out of cache before the read is a
  documented gap (decision 3), audited, not silent.
- **False-hit redaction.** A high-entropy secret value colliding with legitimate response content is
  astronomically unlikely, but a weak opted-in secret can; the load-time warning (decision 6) is the
  mitigation, `tripwire` mode the escape hatch.
- **Latency on opted-in large responses.** Decompress + scan adds cost on bound hosts with echo_scan
  secrets; bounded by the cap and gated so non-participating hosts pay nothing.

## New audit events (added to the ADR-0023 closed set)

`secret_echo_detected` (with `action: redacted|blocked|tripwire`, `secret_name`, `destination`, and
**never** the value), `response_too_large_to_scan`, `response_unscanned_binary`, `response_undecodable`,
`echo_scan_secret_not_cached`. Config-load: `body_injection_echo_risk`, `secret_too_weak_to_echo_scan`
(warnings, not events).

## Test strategy (sketch)

- **Immediate reflection:** bound host with `echo_scan: true`, upstream echoes the injected value in a
  JSON body and in a header → response redacted, `secret_echo_detected` audited, value absent from the
  wire and the audit log.
- **Create-then-read:** POST (inject) then GET (no inject) of the same value → the GET response is
  redacted (proves scope decision 3).
- **Per-binding modes:** `on_echo: block` → 502; `tripwire` → passthrough + audit only.
- **Oversized:** response > cap with default → blocked; with `scan_ends` → head/tail scanned + passed.
- **Compressed:** gzip'd echo → decoded, scanned, redacted; undecodable → fail closed.
- **Gate/perf:** host with no echo_scan secret → body never read (assert zero scan); automaton built
  once per reload (assert not per-request).
- **Weak-value warning:** opt-in a short secret → `secret_too_weak_to_echo_scan` at load.
