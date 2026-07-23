---
status: accepted
date: 2026-07-20
relates_to: ADR-0017 (oauth2-refresh injector — the computed-injector analog this mirrors), docs/architecture.md §4.2 (request path), docs/ROADMAP.md (Injector types — sigv4)
references:
  - AWS Signature Version 4 signing process (AWS4-HMAC-SHA256), AWS documentation
  - AWS SigV4 test suite (get-vanilla and related conformance vectors)
---

# ADR-0027: `sigv4` injector — AWS Signature Version 4 request signing

> **Status: ACCEPTED (2026-07-20).** Both slices implemented + tested end to end.

## Context

Every injector shipped so far *substitutes* a placeholder with a value: header, body, multi,
composite, and `oauth2_refresh` (which substitutes an exchanged token). AWS APIs cannot be brokered
that way. AWS does not accept a static bearer credential — it requires each request to be **signed**:
a per-request `AWS4-HMAC-SHA256` signature computed over the method, canonical URI + query, a chosen
header set, and a SHA-256 of the body, keyed by a date/region/service-scoped derivation of the secret
access key. Without a signing injector, an operator holding AWS credentials in the vault cannot route
an AWS API call through AVP at all — the credential must leave the vault and be handed to an SDK in
the agent's process, which is exactly the exposure AVP exists to remove.

SigV4 is the first *signing* injector (the reserved `hmac`, `jwt_bearer` types are the same shape).

## Decision

Ship `inject.type: sigv4`. Config surface:

```yaml
secrets:
  AWS_S3:
    placeholder: "aws_PLACEHOLDER_…"          # planted in Authorization = DETECTION trigger only
    inject:
      type: sigv4
      region: us-east-1
      service: s3
      access_key_id_secret: AWS_ACCESS_KEY_ID       # vault secret NAMES, resolved at request time
      secret_access_key_secret: AWS_SECRET_ACCESS_KEY
      session_token_secret: AWS_SESSION_TOKEN        # optional — temporary/STS credentials
    bindings:
      - host: s3.us-east-1.amazonaws.com
```

Design decisions:

1. **The `placeholder` is a detection trigger, not a substituted value.** SigV4 renders no value; it
   computes a signature. The operator plants the secret's `placeholder` in the `Authorization` header
   so the request-path detector fires exactly as it does for `oauth2_refresh` (which also injects a
   *computed* value into a header the operator seeded with the placeholder). This reuses the whole
   detect → decide → fail-closed pipeline; no new detection mechanism.
2. **Multi-secret via named references, not `compose:`.** `access_key_id_secret` /
   `secret_access_key_secret` / optional `session_token_secret` are vault-secret *names*, resolved to
   values at request time with independent backend fetches (the `oauth2_refresh` pattern). `compose:`
   (single-value assembly) is rejected for `sigv4` at config-load — the credentials are distinct
   inputs to a signing function, not fragments of one value.
3. **Signer is pure and deterministic.** `injectors/sigv4.py::sign(...)` takes the request parts +
   credentials + `region`/`service` + the `amz_date` timestamp (passed in, never read from a clock)
   and returns the header values to set. Purity makes it testable against fixed vectors; the addon
   stamps the real `X-Amz-Date` from the request clock and calls it. Implemented strictly from the
   published AWS SigV4 specification.
4. **Minimal signed-header set.** Signs `host` + `x-amz-date` (+ `x-amz-security-token` for temporary
   credentials) — the set a broker controls and the minimum the service requires. The default port is
   stripped from the signed `Host` value so it matches the service's own canonicalisation.
5. **Not a `multi` child.** Like `oauth2_refresh`, a computed/whole-request injector needs single-bind
   semantics; `sigv4` is excluded from `LeafInjectorSpec`.
6. **Audit reuses `inject_decision`.** Allowed path emits `inject_decision` / `binding_matched` (no
   new event type, no audit-contract bump). Failure modes (credential fetch failure, empty required
   field) emit `inject_decision` denials with descriptive `reason` strings (`secret_unavailable:…`,
   `sigv4_signing_error:…`) — free-form reasons, like the oauth path.

## Runtime seam (Slice 2 — the body-hash problem)

SigV4 must hash the **entire request body** (`SHA256(body)` is part of the canonical request). This
is the one structural difference from every prior injector, all of which act at `requestheaders`,
before the body arrives — and the body injector deliberately *streams* the body in constant memory and
never buffers it.

Therefore SigV4 cannot complete at `requestheaders`. The seam:

1. **`requestheaders`** — detection + deny gates + `decide()` run as today; a matched `sigv4` decision
   is *stashed* on `flow.metadata` (the resolved injector + fetched credential values). The request's
   body is left **buffered** (streaming is NOT enabled for a sigv4-bound request).
2. **A new addon `request(self, flow)` hook** (AVP has none today) fires once the full body is
   received: it reads `flow.request.content`, computes the canonical request + signature via the pure
   signer, sets `Authorization` + `X-Amz-Date` (+ `X-Amz-Security-Token`), and emits the G6-ordered
   `inject_decision` audit before returning.
3. **Conflict guard:** a host bound to both a `sigv4` injector and a `body` injector is **rejected at
   config-load** — the body streamer would mutate/stream bytes the signer must hash intact. (A future
   ADR could sign post-substitution in-buffer; out of scope here.)

## Consequences

**Good** — AWS APIs (S3, execute-api, STS, …) become brokerable: the AWS credential never enters the
agent's address space, same guarantee as every other AVP binding. Opens the door to the sibling
signing injectors (`hmac`, `jwt_bearer`) on the same seam.

**Cost / accepted** — SigV4-bound requests buffer the body (no streaming) — bounded by the request
size, acceptable for API calls (not bulk uploads; an unsigned-payload / streaming-SigV4 mode is a
later ADR). One new addon hook (`request`) enters the hot path.

## Delivery slices

- **Slice 1 (done):** pure signer (`injectors/sigv4.py`), verified against the AWS SigV4 test-suite
  `get-vanilla` vector; config schema (`Sigv4Injector`, un-reserved, union + guards). Tests:
  `tests/test_sigv4_signer.py`.
- **Slice 2 (done):** runtime wiring — `policy.py` detection + `Decision.sigv4_injector` + routing;
  `handlers.py` dispatch stashes the verdict on `flow.metadata`; `addon.py` `Sigv4Resolver` + the new
  `request` hook signs over `raw_content` (the wire bytes) once buffered; the config-load conflict
  guard (`reject_sigv4_body_host_conflict`). End-to-end tests (`tests/test_sigv4_addon_e2e.py`) prove
  a placeholder-seeded request to a bound AWS host emerges with a valid `AWS4-HMAC-SHA256` signature
  and no placeholder, temporary-credential session tokens are signed, a missing credential fails
  closed with 503, and the credential values never reach the audit log.

## Test strategy

- **Signer (done):** the AWS `get-vanilla` conformance vector pins the full pipeline byte-for-byte;
  structural tests cover query canonicalisation, body hashing, session-token signing, default-port
  handling.
- **Runtime (Slice 2):** end-to-end through the addon — a request whose `Authorization` carries the
  placeholder toward a bound host emerges with a spec-valid `Authorization: AWS4-HMAC-SHA256 …` and
  `X-Amz-Date`, the placeholder gone; the credential secrets never appear in the audit log
  (no-leak); the sigv4 + body-injector combination fails config-load.
