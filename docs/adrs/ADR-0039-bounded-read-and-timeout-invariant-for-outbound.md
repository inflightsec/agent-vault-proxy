---
status: superseded
date: 2026-07-27
relates_to: ADR-0035, ADR-0017
priority: P2
---

# ADR-0039: Bounded-read + timeout invariant for AVP-owned outbound calls

> **Disposition — downscoped 2026-07-29.** The standalone form (a shared
> bounded-read helper across all outbound call sites + a mandatory-timeout CI
> invariant) is **not adopted**. Threat review found the value out of proportion
> to the cost: the AWS/GSM backends hit fixed vendor SaaS over verified TLS (a
> hostile multi-GB body there requires the hyperscaler itself to be malicious or
> a valid-cert MITM), and the timeout half only CI-enforces a convention every
> call site already follows. The one non-theoretical vector is the
> operator-controlled `token_url` — already SSRF-pinned and 3xx-refusing via
> ADR-0035. **Surviving slice:** fold a small read cap into ADR-0035's
> `_token_transport` (`_PinnedHTTPSConnection`) the next time that code is
> touched — a few lines on the one seam, no new helper, no backend changes, no
> CI guard. No separate ADR ships for this; that is why the status is
> `superseded` (the residual decision lives in ADR-0035). The analysis below is
> retained as the record of *why* the broader invariant was declined.

> **Number confirmed 2026-07-28.** 0039 is unique in the sequence (0037 skipped;
> 0038 and 0040 exist, no collision). Cross-references corrected in the same pass:
> the "SSRF-pinned token egress" seam this composes with is **ADR-0035** (accepted
> and implemented), not ADR-0033 (which is git smart-HTTP scoping) — the draft was
> written against a pre-renumber number.

## Context

Harvested from gbrain (MIT): two outbound-hardening ideas — a **default request
timeout** (a raw client with no timeout hangs forever on a stalled socket) and a
**response-body size cap** (`Content-Length` precheck + a decoded-size ceiling,
so a lying or hostile server cannot OOM the process).

Audit of AVP's own outbound HTTP against those two ideas:

- **Timeouts: already present, by convention.** Every raw-`urllib` outbound call
  sets an explicit timeout — `injectors/_token_transport.py` (`timeout=10.0`),
  `injectors/oauth2_refresh.py` (`timeout_seconds=10.0`), `backends/aws.py`
  (`urlopen(req, timeout=10)`), `backends/gsm.py` (`timeout=10`). So the first
  idea is largely satisfied — the gap is only that nothing *enforces* it, so a
  future backend can silently omit it (the same drift class ADR-0035 closed for
  the SSRF check). (`_preflight.py`'s `timeout=2` is a `subprocess.run` timeout
  on `lsattr`, not an HTTP call — `_preflight` makes no outbound requests and is
  out of scope.)
- **Response-body size: unbounded everywhere.** Every one of those call sites
  does `resp.read()` / `e.read()` with **no cap** (e.g. `json.loads(resp.read()
  or b"null")` in `aws.py:671` and `gsm.py:703`; `resp.read()` in both token
  transports; `_safe_read`/`err.read()` on the error path). A compromised or
  misconfigured `token_url`, STS endpoint, or Secret-Manager host can return a
  multi-gigabyte body and OOM the proxy. AVP is a **long-lived process on the
  agent's egress path** — an OOM there is a denial of service against every
  flow, not a single failed request.

Two facts bound the scope:

1. **The proxied agent↔upstream flow is already streamed.** Body injection uses
   `flow.request.stream = replacer` (chunked, constant memory —
   `handlers.py`), so the *proxied* path does not materialize whole bodies.
   The gap is strictly AVP's **own** outbound calls (token minting, SDK-less
   backend fetches), not the proxied traffic.
2. **SDK backends are not in scope.** `backends/bws.py` calls through the
   `bitwarden_sdk` `BitwardenClient` (its own transport); vendor SDKs own their
   timeouts/limits. This ADR covers only the raw-`urllib` call sites AVP
   controls directly.

## Decision

Add a **single bounded-read outbound helper** that every raw-`urllib` AVP call
routes through, and make its guarantees a **CI-enforced invariant**.

**The helper.** A small wrapper (`_http_read` / fold into the ADR-0035 shared
transport) that:

- **Requires an explicit timeout** — no `timeout=None` path; the parameter is
  mandatory, not defaulted-away.
- **Prechecks `Content-Length`** — if present and over the cap, refuse before
  reading a byte.
- **Caps the actual read** — read at most `cap + 1` bytes; if the body reaches
  `cap + 1`, fail closed (catches an absent or lying `Content-Length`). Never
  `.read()` unbounded.
- **Fails closed with a categorised error** on oversize (a new
  `outcome`/exception label, mirroring the existing token-exchange vocabulary),
  so an oversize response is a clean failed exchange, not a crash.
- Applies to the **error body path too** (`_safe_read`/`err.read()`), which is
  equally attacker-influenced.

**Cap size.** Token/STS/Secret-Manager responses are JSON in the kilobyte range;
the cap is set to "unambiguously not a legitimate response" (a few MB), generous
enough never to trip on real traffic. Exact value is an open question below.

**Route all raw-`urllib` outbound through it:** `_token_transport.post`,
`oauth2_refresh` transport, `backends/aws.py`, and `backends/gsm.py`. (These are
AVP's only outbound-HTTP call sites; `_preflight.py` is not one.)

**Chokepoint CI check** — extend ADR-0035's existing guard
(`scripts/check-token-egress-chokepoint.sh`) rather than adding a parallel one:
fail if any source opens a raw `urllib`/`http.client` outbound call that (a)
lacks an explicit `timeout=` or (b) bypasses the bounded-read helper. This turns
both guarantees into invariants a new backend cannot forget.

**Composition with ADR-0035.** ADR-0035 is accepted and implemented: outbound
operator-controlled token egress already routes through one shared, SSRF-pinned
transport (`injectors/_token_transport.py`), guarded by
`check-token-egress-chokepoint.sh`. For the **token-endpoint** call sites this
ADR extends that landed transport in place — same seam, add mandatory-timeout +
bounded-read to it. But 0039's scope is strictly larger than 0035's: the
**backend** call sites (`backends/aws.py`, `backends/gsm.py`) are NOT
operator-controlled token URLs, do not go through the pinned transport (they hit
fixed vendor SaaS endpoints under a different trust model), and still need
bounded-read. So bounded-read + mandatory-timeout is a **lower-level primitive**
than SSRF-pin: 0035's transport calls it, and the backends call it directly.
That is the substance of open question 2 below. Sequence after 0035
(landed) — this is an increment on existing code, not a coordinated double
refactor.

## Consequences

**Good**
- A hostile or broken upstream can no longer OOM the proxy — the DoS on the
  whole egress path is closed.
- The timeout stops being a convention a new backend can drop; it becomes a
  CI-checked invariant.
- Collapses into ADR-0035's single hardened outbound seam instead of scattering
  hardening across call sites.
- Cheap: a small helper + a grep guard, no new dependency.

**Bad**
- A cap can, in principle, truncate a legitimately-huge response — mitigated by
  a generous ceiling + a categorised error (never a silent truncation).
- One more shared helper to keep call sites routed through (the chokepoint check
  is exactly what prevents that from rotting).
- Marginally more code on each outbound path (bounded read vs `resp.read()`).

**Out of scope**
- SDK backends (`bitwarden_sdk`, and any future vendor SDK) — they own their
  transport; verify their timeout config separately, do not wrap.
- The proxied agent↔upstream flow — already streamed; not materialised by AVP.
- Streaming/entropy parsing of oversize bodies — we refuse them, we don't try to
  parse them incrementally.

## Open questions (for the grilling session)

1. **Cap value** — a fixed few-MB ceiling for all outbound, or per-surface
   (token vs STS vs GSM)? Token/secret responses are KB-scale, so a single low
   cap may be cleaner than per-call tuning.
2. **One helper or two** — fold bounded-read + timeout into ADR-0035's shared
   pinned-connect transport (one seam, but couples the two ADRs), or a thin
   standalone `_http_read` that 0035's transport also calls?
3. ~~**`_preflight.py`**~~ — RESOLVED 2026-07-28: `_preflight` makes no outbound
   HTTP call (its `timeout=2` is a `subprocess.run` on `lsattr`). Out of scope;
   no cap needed.
4. **Proxied upstream *response* buffering** — mitmproxy buffers non-streamed
   response bodies by default. Do we force `flow.response.stream` above a size
   threshold to bound that too, or is that a separate ADR? (Leaning separate —
   it's the proxied path, not AVP's own calls.)
5. **Error-path parity** — confirm the bounded read also wraps every
   `err.read()` / `_safe_read`, since the error body is equally attacker-shaped.

## References

- ADR-0035 — SSRF pin-vetted-address for token egress (the shared outbound seam this composes with).
- ADR-0017 §5 — the token-exchange transport.
- Call sites: `injectors/_token_transport.py`, `injectors/oauth2_refresh.py`, `backends/aws.py`, `backends/gsm.py`.
- Bounded-read + mandatory-timeout is standard outbound hardening: precheck `Content-Length`, cap the read, fail closed.
