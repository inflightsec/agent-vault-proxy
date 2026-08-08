---
status: accepted
date: 2026-06-30
implemented: 2026-07-02
relates_to: docs/architecture.md (G1-G10), CHANGELOG.md (v0.5.0 discriminated-union taxonomy)
---

# ADR-0017: OAuth2 refresh-token injector (`inject.type: oauth2_refresh`)

> **Implemented 2026-07-02.** Landed in the working tree as `inject.type: oauth2_refresh`:
> `injectors/oauth2_refresh.py` (RFC 6749 §6 grant + transport), `_derived_token_cache.py`
> (per-entry TTL from `expires_in`, inflight dedup), `_ssrf_guard.py` (config-load + request-time
> re-resolution), `oauth_providers.py` (google / microsoft / auth0 / slack / atlassian / okta
> presets), `backends.update_secret` + `BitwardenBackend.update` (refresh-token write-back with
> the five audited outcomes of §8), and `avp doctor --probe-oauth`. Covered by the oauth2 test
> suite; full unit suite green (766 passed) plus the docker-e2e wire harness.
>
> **Delta from the plan below:** `target: header` only — `target: body` remains deferred
> (see §1 and Out of scope). Multi-AVP-instance rotation coordination remains out of scope.
> The design sections that follow are preserved verbatim as the record of the decision; they
> read in the future tense they were written in.
>
> **Hardening series closed 2026-07-18** — the five deferred post-review items are done; see
> the Amendment at the end of this document.

## Context

AVP today ships three injector types — `header`, `body`, `multi` — verified at v0.6.0 (Unreleased). The discriminated-union table in `src/kow/config.py` already names `oauth2_refresh` as `"planned: P1"`; the schema rejects it at config-load with a precise message. `docs/architecture.md` §22 lists OAuth refresh-token flows as out-of-scope. README "Not yet supported" lists the same.

The gap matters because every modern SaaS that issues short-lived access tokens (Google, Microsoft Graph, Atlassian, Slack OAuth, Okta-fronted apps, the entire OIDC-aware estate) uses the OAuth2 refresh-token grant defined in RFC 6749 §6. Without this injector, an agent calling those APIs through AVP must either hold the refresh token itself (defeats the proxy) or hold a pre-exchanged access token that expires within the hour (also defeats it).

The injector is the headline gap closing this round. It is also the first AVP injector type that makes outbound HTTP calls on its own — every prior type substitutes a vault-held value, this one exchanges one credential for another at request time. That shift earns a careful ADR.

**Verified current state (2026-06-30):**

- `config.py` ships `HeaderInjector` / `BodyInjector` / `MultiInjector` as a Pydantic discriminated union on `inject.type`. Adding a new type is one line in `_INJECTOR_TYPES`, one new class, one `LeafInjectorSpec` extension — the existing comment in `config.py` is verbatim.
- `caching.py` has a generation-counter / inflight-future cache with single TTL across all entries. Per-entry TTL does not exist today.
- `backends/__init__.py` defines `SecretsBackend` Protocol with `fetch` / `fetch_with_meta` / `list_secret_names` / `flush_name_map` — **read-only**. No `update(name, value)` method.
- `audit.py` schema v2 ships `inject_decision` and `deny` event shapes. No `token_exchange` event type.
- `injectors/body.py` ships streaming chunk-boundary-correct substitution via `_build_body_replacer`.
- Outbound HTTP deps: `h11`, `h2`, `tornado`, `certifi`, `cryptography`. **No `httpx`, no `requests`, no `urllib3`.**

## Decision

Land `inject.type: oauth2_refresh` as the fourth injector type in the v0.5.0-established discriminated-union taxonomy. Ship in v0.7.0.

### 1. Scope

- **In v0.7**: `target: header` only. The full RFC 6749 §6 refresh-token grant. Refresh-token write-back on rotation. Bundled provider catalog (Google, Microsoft, Auth0, Slack, Atlassian, Okta). `avp doctor --binding X --probe-oauth` operator verification.
- **Deferred**: `target: body` (separate ADR; needs content-type-aware escaping done properly, not retrofitted). PKCE / auth-code grant. Token introspection (RFC 7662). DPoP (RFC 9449). Multi-AVP-instance coordination locks.

### 2. Schema (Pydantic 2)

```python
class Oauth2RefreshInjector(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    type: Literal["oauth2_refresh"] = "oauth2_refresh"

    # Provider preset OR explicit fields (XOR validated at load time)
    provider: Literal["google", "microsoft", "auth0", "slack", "atlassian", "okta"] | None = None

    # Explicit fields — required unless `provider:` set, fills from preset
    token_url: HttpUrl | None = None
    client_auth_method: Literal["body_post", "basic"] | None = None

    # BWS secret references (always required)
    client_id_secret: str
    client_secret_secret: str
    refresh_token_secret: str

    # Target injection (header only in v0.7)
    header: str = "Authorization"
    format: str = "Bearer {access_token}"

    # Optional
    scopes: str | None = None

    # Cache control
    cache_ttl_safety_seconds: int = 60
    cache_ttl_max_seconds: int = 3600

    # Refresh-token rotation handling
    refresh_token_write_back: bool = True
```

XOR validator: `provider` set ⇒ `token_url` / `client_auth_method` optional and fall back to the preset; `provider` unset ⇒ `token_url` and `client_auth_method` both required. The provider preset catalog ships as a frozen Python dict in `src/kow/oauth_providers.py`, one entry per supported provider, no external file load.

`extra="forbid"` matches every other AVP config class since v0.4.1. Operator typos fail at config-load.

### 3. Token cache — separate from the secrets cache

Build `_DerivedTokenCache` as a sibling of `CachingSecretsClient`, not as a namespace inside it. The cache holds access tokens, not vault secrets; mixing them in one client makes `flush(name=None)` / `list_secret_names` / audit-reason semantics ambiguous, and the existing surface was not designed for mutable derived credentials.

Cache key is the SHA-256 HMAC (keyed by a process-local random salt at startup) of `(binding_name, token_url, scopes, client_id_value, refresh_token_value)`. Any input change — config reload, BWS secret rotation, scope edit, provider preset switch — produces a different key, so a stale token cannot be served after the inputs that minted it have changed.

Per-entry expiry: `effective_ttl = max(0, min(expires_in - safety, cache_ttl_max))`. If `effective_ttl < 5 seconds`, do not cache; log a warning. If `expires_in` is absent (RFC 6749 §5.1 calls it OPTIONAL), default to `cache_ttl_max`; emit an audit warning so the operator can spot under-spec providers.

Inflight dedup uses the same Future-per-key pattern as `CachingSecretsClient` — two concurrent requests for the same token trigger exactly one upstream exchange.

G10 (cache hardening) carries from the secrets cache: `mlock` the cache pages, `RLIMIT_CORE=0`, zero-on-`SIGTERM` via atexit handler, UNIX-user isolation via systemd sandbox. Identical invariants; new code path is held to the same bar.

### 4. Token exchange transport

Python stdlib `urllib.request` + `ssl.create_default_context()`. No new runtime dependency. The exchange is one POST (form-encoded), one JSON parse, one cache write — ~80 lines including error mapping.

- **HTTPS only** — `token_url` validator rejects `http://`.
- **Timeout**: `urllib.request.urlopen(timeout=N)` provides a total-deadline only (no native connect-timeout split). Documented as such; default `token_exchange_timeout_seconds: int = 10`. If real workloads need connect-timeout granularity, follow-up ADR introduces `httpx`.
- **Off-thread**: the call is dispatched via `asyncio.get_event_loop().run_in_executor()` so a slow token endpoint does not block mitmproxy's request loop for other in-flight flows. `mitmproxy.utils.asyncio_utils` already exposes the loop.
- **No proxy.** Token endpoint calls go direct, never recursively through AVP itself.
- **TLS verify**: system trust store via `ssl.create_default_context()`. Operators behind corporate TLS-MITM add their CA to the system trust store — same posture as every other AVP outbound call.
- **One retry on 5xx with 1 s backoff. No retry on 4xx.** 4xx is credential / scope, not transient.

### 5. SSRF defense

The token URL is operator-controlled, but a paste-error or a compromised `bindings.yaml` pointing at `https://169.254.169.254/` (cloud metadata) or an internal control-plane URL turns AVP into an SSRF vector. HTTPS-validation alone is not an egress policy.

Two layers:

1. **Config-load**: resolve `token_url`'s host via `socket.getaddrinfo`; reject if any resolved address is in RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`), link-local (`169.254/16`, `fe80::/10`), or carrier-grade NAT (`100.64/10`). Reject IMDS endpoints explicitly: `169.254.169.254`, `fd00:ec2::254`.
2. **Request-time**: re-resolve and re-check before each token exchange. DNS rebinding defense — a public DNS name that resolved to a public IP at config-load may resolve to a private IP later.

Both checks share one helper in `src/kow/_ssrf_guard.py`.

### 6. OAuth error response parsing

RFC 6749 §5.2 specifies error responses as JSON with `error`, optional `error_description`, optional `error_uri`. The injector parses the JSON body when present and surfaces `error` in the audit outcome as `token_endpoint_error:invalid_grant`, `:invalid_client`, `:invalid_scope`, `:unauthorized_client`, etc. Status-code-only fallback when the body is not valid JSON. Operators see actionable categorisation in audit, not just status codes.

### 7. Audit events

Two new event types; `inject_decision` semantics unchanged.

**`token_exchange`** — emitted AFTER the upstream token call returns (the outcome is unknowable before), fsynced before the proxied request bytes leave AVP. G6 invariant scope is clarified: G6 applies to `inject_decision`; the new `token_exchange` event has its own ordering — emitted-after-upstream-returns and before-bytes-leave-proxy. Both ordering rules are commented "do not reorder" in `addon.py`.

```json
{
  "type": "token_exchange",
  "request_id": "...",
  "binding_name": "GOOGLE_OAUTH",
  "token_url_host": "oauth2.googleapis.com",
  "outcome": "success",
  "expires_in_seconds": 3599,
  "cache_ttl_effective_seconds": 3539
}
```

Outcome taxonomy: `success`, `token_endpoint_error:<error_code>`, `token_endpoint_unreachable`, `token_endpoint_status:<code>`, `response_parse_failed`, `expires_in_missing`, `ssrf_blocked`.

**`refresh_token_rotated`** — emitted when the upstream response includes a new `refresh_token` value differing from the one fetched from BWS. Carries `binding_name` and `secret_name`. No token values in either field. Driven by the write-back path (next section).

The audit contract — "no header values, no bodies, no query strings, no secret material" — is preserved verbatim. Only `token_url_host` (not full URL with query) and lifetime metadata (not the token) are recorded.

### 8. Refresh-token write-back

Modern providers rotate the refresh token on each grant; the old one is revoked. Deferring write-back makes the injector unusable for those providers. Ship it in v0.7.

Extend `SecretsBackend` Protocol with an optional `update(name, value, ctx)` method. Backends that don't implement it raise `BackendNotWritableError` and the injector falls back to logging a `refresh_token_rotated:write_back_unavailable` audit event. `BitwardenBackend` implements `update` via the BWS SDK's secret-update endpoint. `StaticBackend` raises `BackendNotWritableError` (test fixture; never used in production).

Race handling: two concurrent agent requests can both trigger refresh, but the inflight dedup ensures exactly one upstream exchange per binding. The write-back is sequenced after the cache write, before the audit fsync, so a crash between cache and audit leaves the new refresh token in BWS but un-audited (operator sees the rotation on next request). The reverse (audit without write-back) is worse — would claim rotation that didn't happen — and is structurally prevented by the ordering.

**Anti-criterion**: in v0.7, two AVP processes sharing the same `refresh_token_secret` is **unsupported**. Documented in operator README. Multi-instance coordination is a follow-up ADR — likely a BWS-side optimistic lock via the secret's version metadata.

### 9. Provider-aware presets

Frozen Python dict shipped at `src/kow/oauth_providers.py`. One entry per supported provider:

```python
PROVIDER_PRESETS = {
    "google": ProviderPreset(
        token_url="https://oauth2.googleapis.com/token",
        client_auth_method="body_post",
        rotates_refresh_token=False,  # Google does not rotate by default
        error_codes={"invalid_grant": "refresh_token expired or revoked"},
    ),
    "microsoft": ProviderPreset(
        token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        client_auth_method="body_post",
        rotates_refresh_token=True,
        error_codes={...},
    ),
    "auth0": ProviderPreset(
        token_url=None,  # tenant-specific, operator must supply
        client_auth_method="basic",
        rotates_refresh_token=True,  # configurable, default rotate
        error_codes={...},
    ),
    "slack": ProviderPreset(
        token_url="https://slack.com/api/oauth.v2.access",
        client_auth_method="basic",
        rotates_refresh_token=True,
        error_codes={...},
    ),
    "atlassian": ProviderPreset(...),
    "okta": ProviderPreset(token_url=None, ...),  # tenant-specific
}
```

Operator writes `provider: google` and the catalog fills in token_url, auth method, and the operator's known-rotation-behaviour expectation. Tenant-specific providers (Auth0, Okta) still require explicit `token_url`; the preset supplies the auth method and rotation defaults.

Backfill discipline: a provider is added to the catalog when there is a concrete operator binding for it. Speculative provider entries get rejected at PR review.

### 10. `avp doctor --binding X --probe-oauth`

New `doctor` subcommand verb. For a binding of type `oauth2_refresh`, the CLI:

1. Resolves the three secrets from the configured backend.
2. Issues a live token exchange via the same code path the runtime uses.
3. Reports outcome with provider-specific remediation hints (from the preset catalog):

```
$ avp doctor --binding GOOGLE_OAUTH --probe-oauth
Resolving secrets...                           [OK]
Resolving token_url DNS (SSRF guard)...        [OK]
Exchanging refresh_token at oauth2.googleapis.com [OK]
Access token received, expires in 3599 s.
Refresh-token rotation: not detected.
Binding is healthy.

$ avp doctor --binding AUTH0_OAUTH --probe-oauth
Resolving secrets...                           [OK]
Resolving token_url DNS (SSRF guard)...        [OK]
Exchanging refresh_token at tenant.auth0.com   [FAIL]
  HTTP 400: error=invalid_grant
  Hint: the refresh token is expired or revoked. Issue a new one
        in the Auth0 dashboard and update the BWS secret named
        REFRESH_TOKEN_SECRET in the Bitwarden vault.
```

Pure read-side; never writes anything. Safe to run against production secrets.

### 11. Addon dispatch

`addon.requestheaders` is a 3-stage pipeline (CHANGELOG v0.5.0). OAuth refresh slots in as a **resolution step** between deny gates and injection:

1. Deny gates (unchanged).
2. **NEW:** For each eligible binding with `inject.type == "oauth2_refresh"`, resolve the access token via the derived-token cache (hit OR run-in-executor exchange OR fail-closed deny).
3. Header injection (unchanged surface; the resolved access token is the value the header path injects).
4. Body streaming setup (unchanged; OAuth `target: body` deferred).

The resolution step is the only genuinely new code. Header injection reuses `HeaderInjector` machinery verbatim.

### 12. Preflight

- `oauth2_refresh.token_url` HTTPS (or `provider:` set so token_url comes from preset).
- SSRF guard runs at config-load (per §5).
- Three referenced BWS secrets resolve at startup IF `preflight_resolve: bool = True` (default). Operators with lazy-load deployments set `preflight_resolve: false` per-binding; runtime resolution still fail-closed at first request.
- `cache_ttl_safety_seconds` ∈ [0, 600].
- `cache_ttl_max_seconds` ∈ [60, 86400].

## Beyond the baseline

Three commitments that put AVP's OAuth refresh ahead of the loopback-credential-broker baseline:

- **Provider-aware presets (§9).** Operator writes `provider: google` and gets a working binding. Most credential brokers in this space require hand-coding every URL, auth method, and error-parsing rule.
- **Write-back from day one (§8).** Rotation-tolerant by design. The read-only-backend pattern most brokers ship with cannot support modern OAuth providers without operator intervention every refresh cycle.
- **Live verification CLI (§10).** `avp doctor --probe-oauth` does what would otherwise be a manual curl-based ritual, with provider-specific hints. Operators verify binding health before production traffic without leaving the proxy.

These are scoped to v0.7. Each adds ~0.5-1 day. Total v0.7 estimate: ~8 days across 10 vertical slices.

## Consequences

### Good

- Closes the headline `docs/architecture.md` §22 out-of-scope item.
- Schema discipline preserved — one line in `_INJECTOR_TYPES`, one new class, one union extension.
- Cache machinery reused conceptually but isolated structurally (separate `_DerivedTokenCache`); no cross-contamination.
- Body machinery untouched in v0.7; `target: body` lands in its own ADR with content-type-aware escaping done right.
- Audit contract preserved — two new event types, both fsynced before bytes leave AVP, no secret material.
- Zero new runtime dependencies.
- Write-back makes the injector usable against providers the rest of the credential-broker landscape struggles with.

### Bad

- **Plaintext access tokens in RAM** for up to `cache_ttl_max_seconds` (capped 1 h default). Documented threat-model delta — mitigated by G10 invariants, not eliminated.
- Token-endpoint outage = AVP-side failure for OAuth bindings. Operators need alerting; `avp doctor --probe-oauth` is the human-readable check, the audit log carries the machine signal.
- New code path = new bug surface. ~600 LoC across schema, cache, transport, audit, dispatch, write-back, presets, doctor CLI. Held to AVP's existing OSV / Semgrep / TruffleHog / Bandit gate.
- One more failure axis per binding to test. Estimated 60-80 new test cases across unit + e2e.

### Out of scope (deferred, each its own future ADR)

- `target: body` — content-type-aware escaping (JSON quote-escape, form-encoded URL-escape, multipart rejection).
- PKCE / authorization-code grant.
- Token introspection (RFC 7662).
- DPoP (RFC 9449) — token binding to a client-held key; natural fit for AVP's loopback model but substantial cryptographic surface.
- Multi-AVP-instance coordination via a BWS-side rotation lock.
- OAuth2 client-credentials grant (RFC 6749 §4.4) and JWT bearer assertion (RFC 7523) — separate injector types, separate ADRs.
- `httpx` runtime dependency — only if operators need connect-timeout granularity.

## References

- RFC 6749 §2.3 (Client Authentication), §4.4 (Client Credentials), §5.1 (Successful Response), §5.2 (Error Response), §6 (Refreshing an Access Token), §10 (Security Considerations).
- `docs/architecture.md` §22 (out-of-scope flip), G1-G9 (invariants this ADR extends with G10), §8 (test plan extension).
- `src/kow/config.py:23` — `_INJECTOR_TYPES` table.
- `src/kow/caching.py:39` — `CacheEntry`, `CachingSecretsClient`.
- `src/kow/audit.py` — schema v2 → v3 (this ADR adds two event types).
- ADR-0011 (BWS-notes bindings — this injector type also honours both binding sources).
- ADR-0013 (declarative policy fixtures — this ADR's tests use the same fixture format).

## Amendment (2026-07-18) — deferred hardening series closed

The five items the v0.7.0 CHANGELOG tracked as "hardening patch series remaining" are
closed; each shipped with tests in the same change:

1. **SsrfBlockedError swallow.** The IP-literal short-circuit in
   `_ssrf_guard.check_url_not_internal` now parses first and block-checks second, so the
   `except ValueError` can no longer swallow a block verdict. Pinned by tests asserting a
   blocked literal raises with NO DNS consultation. The `ValueError` inheritance itself is
   retained deliberately — Pydantic needs it to surface config-load rejections as
   validation errors rather than crashes; the swallow site was the bug, not the hierarchy.
2. **Pending-before-write (Oracle F2).** `refresh_token_rotated:pending` is fsynced BEFORE
   the backend PUT; exactly one final outcome follows. A crash inside the write window
   leaves a pending-with-no-final pair — "attempted, outcome unknown" is now
   distinguishable from "never attempted". The reverse (a final event for a write that
   never happened) stays structurally impossible.
3. **Revision precondition (Oracle F3) — implemented as a VALUE precondition.** The BWS
   SDK has no conditional-PUT primitive, and `revisionDate` also moves on note/metadata
   edits (false conflicts). Instead, `update(..., expected_current_value=)` compares the
   vault's CURRENT value against the refresh token the exchange actually consumed; on
   mismatch the new `BackendWriteConflictError` is raised, the write is refused, and the
   audit reads `write_back_conflict` — an operator's manual mid-flight rotation survives.
   Residual: the compare happens at the adapter's GET, so the TOCTOU window shrinks to the
   GET→PUT gap rather than vanishing (a true conditional PUT needs SDK support).
4. **Per-binding write-back rate limit (Oracle F4).** `write_back_min_interval_seconds`
   (default 60, `0` disables) floors the interval between PUTs per binding; excess
   rotations audit `write_back_rate_limited` and are not persisted, bounding vault write
   pressure under a forced-rotation storm.
5. **Redirects disabled, not post-checked.** The exchange transport is a no-redirect
   opener (`_NoRedirectHandler`): ANY 3xx surfaces as `token_endpoint_status:<code>`, is
   never retried, and the Location target is never contacted. Replaces the `resp.geturl()`
   post-check, which could only distrust a redirect AFTER the redirected host had been
   visited on the wire. Pinned by an on-the-wire test against a live local server.

New audit outcome VALUES on `refresh_token_rotated`: `pending`, `write_back_rate_limited`,
`write_back_conflict` — additions to §7's outcome taxonomy, not new event types; no audit
contract-version bump (same precedent as `write_back_rejected_malformed`).
