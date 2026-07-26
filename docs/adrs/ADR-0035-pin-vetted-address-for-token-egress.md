---
status: accepted
date: 2026-07-26
relates_to: ADR-0017
priority: P2
---

# ADR-0035: Pin the vetted address for operator-controlled token egress

## Context

AVP's only operator-controlled outbound HTTP surface is token minting: the
`oauth2_refresh`, `oauth2_client_credentials`, and `github_app` injectors POST
to a `token_url` taken from `bindings.yaml`. Everything else that leaves the
box is fixed — backend reads go through vendor SDKs (BWS, GCP Secret Manager)
to pinned SaaS endpoints, and audit records are written to a local file
(`audit.py`, `os.fsync`) with off-box shipping delegated to a sidecar
(ADR-0019), not an AVP-owned HTTP call. So `token_url` is the whole surface.

That surface is already guarded by `_ssrf_guard.check_url_not_internal`
(ADR-0017 §5), which is good and stays:

- stdlib `ipaddress` classification of loopback / link-local (incl. IMDS
  `169.254.169.254`) / unspecified / multicast / reserved / RFC1918-private /
  CGNAT `100.64/10` / IPv6 ULA;
- resolve-then-check **every** `getaddrinfo` record (any internal ⇒ block);
- direct-IP-literal short-circuit;
- **fail-closed** on DNS error or empty answer;
- run at config-load **and** re-run request-time;
- `_token_transport` refuses **all** 3xx (`_NoRedirectHandler`) — a redirect
  off a token endpoint is a misconfig / SSRF pivot, so we never follow it.

The residual weakness is a **time-of-check / time-of-use gap**. `post()` calls
`check_url_not_internal(url)` — which resolves the host via `getaddrinfo` and
vets the answers — then hands the **hostname** URL to `urllib`, which performs
its **own, independent** DNS resolution at connect time. The address we vetted
and the address we connect to come from two separate lookups. They can differ:

1. **Adversarially** — a low-TTL name for an operator-trusted domain whose DNS
   is compromised or rebinding answers public on the guard's lookup and private
   (a control-plane IP, `169.254.169.254`) on `urllib`'s.
2. **Benignly** — round-robin / short-TTL records legitimately rotate between
   the two lookups, so we vet one record set and connect to another we never
   checked.

Severity is medium-low — `token_url` is operator-supplied and the threat model
(ADR-0017) already treats the operator as semi-trusted, and request-time
re-resolution shrinks the window. But "check and connect resolve
independently" is a real correctness defect, not only a theoretical one, in a
tool whose entire value proposition is careful handling of credential egress.

## Decision

Adopt **resolve-once, then connect to the pinned vetted address** for every
operator-controlled token exchange. One resolution feeds both the block-check
and the socket connect, so check and use are provably the same address.

**Transport (stdlib, no new dependency).** Add a minimal
`http.client.HTTPSConnection` subclass that connects to a caller-supplied
**vetted IP** while carrying the original hostname for identity:

- **TLS SNI** (`server_hostname`) and the **`Host:` header** = original
  hostname.
- Certificate verification runs against the **original hostname**, never the
  IP, and is **never disabled**. Pinning the transport address must not weaken
  TLS identity.

`httpx` was rejected: it adds a dependency chain (httpcore / anyio / sniffio)
to a credential proxy, against the supply-chain posture. The subclass is code
we fully control.

**Single seam.** `check_url_not_internal` grows a sibling (e.g.
`resolve_and_vet(url) -> list[vetted records]`) that returns the vetted
addresses instead of `None`; the block-check semantics are shared. The
pre-existing `oauth2_refresh` transport is **consolidated onto the shared
`_token_transport`** so pinned-connect exists in exactly one place.

**Failover (we now own it).** Pinning discards `urllib`'s free multi-record
failover, which matters for the load-balanced endpoints we call (Google,
GitHub, Okta). So iterate the vetted records **in order**, connecting to each
until one succeeds — every candidate is pre-vetted, so this is safe. On the
existing 5xx / transport retry, perform a **fresh** resolve-and-vet; never
reuse a stale pin (that would reintroduce the TOCTOU on retry).

**Adjuncts landed in the same change.**

- **Reject credentials-in-URL** (`user:pass@host`) at config-load. A credential
  proxy has no business carrying secrets in a `token_url`, and the userinfo is
  silently dropped today.
- **Chokepoint check** (`scripts/check-*.sh`): CI fails if any injector opens a
  raw `urllib` / `http.client` connection to an operator-supplied URL outside
  the shared transport, so a future injector cannot quietly reintroduce the
  hostname-connect path. Loose-positive bias — a review comment is cheaper than
  a silent egress hole.

**Test strategy.** Pragmatic-hermetic plus one real handshake:

- Resolver-stub (module-level `getaddrinfo` swap) tests for: rebinding
  prevented (check public, connect private ⇒ we still dial only the vetted IP);
  sequential failover (first vetted IP refuses, second succeeds); retry
  re-vets fresh; credentials-in-URL rejected at config-load.
- Assert on the connection object that `server_hostname` = original hostname
  and verification is not disabled (trust stdlib `ssl` to enforce it — do not
  re-test the stdlib).
- **One** real-handshake smoke to a local TLS server over the pinned IP, to
  catch the specific "SNI set but cert silently checked against the IP" wiring
  bug that parameter assertions would miss.

**Sequencing.** P2. Ships **post-0.9.0 as its own PR** — it touches the
sensitive token-transport path and merges two transports; it must not perturb
the gated 0.9.0 release. Transport surgery + consolidation + chokepoint guard
soak together as one reviewable unit.

## Consequences

**Good**
- Eliminates the check→connect TOCTOU: the address we vet is the address we
  connect to, deterministically.
- Kills benign round-robin skew as a side effect — no more "vetted A,
  connected B".
- Tightens the surface the threat model already names (ADR-0017 §5) without
  touching the parts already ahead of the field (fail-closed, no redirects,
  request-time re-resolution).
- The chokepoint check makes resolve-and-pin a structural invariant, not a
  convention a new injector can forget — directly closing the class of drift
  that left `oauth2_refresh` on its own transport.

**Bad**
- We now own multi-record failover (a manual connect loop) instead of the OS,
  and lose IPv6 Happy-Eyeballs parallelism — connections are attempted
  sequentially.
- Connect-by-IP with correct SNI / `Host` / cert-against-hostname is fiddly in
  Python; it is a code path that must stay in lockstep with the classifier's
  semantics.
- The chokepoint grep-guard needs occasional false-positive tuning.
- Connecting by pinned IP **bypasses `HTTPS_PROXY` / `ALL_PROXY` for token
  egress** — inherent to pinning, since an outer forward proxy would re-resolve
  the hostname and reopen the very gap this closes. Token exchanges go direct to
  the vetted address; an operator who must proxy that egress fronts AVP at the
  network layer instead. The IP pin is the address, not the full sockaddr: IPv6
  `scopeid` is dropped, which is harmless because link-local IPv6 — the only
  case where scopeid is load-bearing — is already blocked by the guard.

**Out of scope**
- General agent egress filtering — policing the agent's arbitrary outbound
  traffic is the network-layer agent-firewall model, deliberately not AVP's job
  (see `docs/comparison.md`).
- Audit shipping egress — local file-write, sidecar off-box (ADR-0019).
- Backend SDK endpoints — fixed vendor hosts, not operator-arbitrary.

## References

- ADR-0017 §5 — the original `token_url` SSRF guard this hardens.
- `src/agent_vault_proxy/_ssrf_guard.py`, `injectors/_token_transport.py`,
  `injectors/oauth2_refresh.py`, `config_models.py`.
- Resolve-and-pin is the standard SSRF-safe fetch pattern: vet the resolved
  address set, then connect to a vetted member rather than re-resolving the
  name at connect time.
