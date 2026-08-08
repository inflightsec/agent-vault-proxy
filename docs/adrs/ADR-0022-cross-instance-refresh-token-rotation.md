---
status: proposed
date: 2026-07-13
relates_to: docs/adrs/ADR-0017-oauth2-refresh-injector.md (§8 write-back, deferred multi-instance item), docs/architecture.md (G6, G10)
supersedes_scope: ADR-0017 §8 anti-criterion ("two AVP processes sharing the same refresh_token_secret is unsupported")
---

# ADR-0022: Cross-instance refresh-token rotation coordination (`multi_instance_coordination`)

> **Applicability — read first.** This ADR matters ONLY for deployments that run
> **two or more AVP proxy *processes* against the same `refresh_token_secret`
> concurrently** (an HA pair, or the same OAuth binding live on two hosts). A
> single AVP process — regardless of how many agents or sandboxes route through
> it — is already fully covered by ADR-0017's in-process single-flight and needs
> nothing here; "many agents" is not "many instances". If you run one AVP
> process, treat this as a deferred boundary-marker, not a gap: **do not
> implement it until a second instance actually shares a binding.**

> **Revisions from adversarial design review (2026-07-13).** This draft was
> hardened against a skeptical second-opinion pass. Five changes: (1) BWS's
> optimistic re-read is NOT a true atomic CAS — the "CAS alone keeps the vault
> consistent" claim was overstated and is corrected; BWS multi-instance is
> marked **experimental**, and true safety requires a fencing-capable primitive
> (§4). (2) The lease TTL default (was 15s) was shorter than the worst-case
> token exchange (~25s: 10s timeout + 1s backoff + 10s retry), which would let a
> follower steal mid-refresh and double-exchange — TTL raised and lease renewal
> added (§1, §3). (3) On any write conflict / post-write mismatch / peer-rotation
> `invalid_grant`, the just-minted access token MUST be discarded and the resolve
> re-run **before** header mutation, or the request is denied — not best-effort
> served (§4). (4) "Vault version moved" is treated as **ambiguous**, not benign;
> one bounded retry then a terminal `needs_reauth` / `coordination_ambiguous` (§5).
> (5) Explicit `cas`/`lease` against a backend that can't provide the primitive
> is a **hard config-load failure**, not a silent downgrade (§2).

## Context

ADR-0017 shipped `inject.type: oauth2_refresh` with a complete single-process
broker: derived-token cache with per-key inflight dedup (`_derived_token_cache.py`),
a refresh safety margin (`cache_ttl_safety_seconds`, default 60), rotation-tolerant
write-back with a malformed-token shape guard, and categorised `token_exchange` /
`refresh_token_rotated` audit outcomes. Within one AVP process, concurrent requests
for the same binding trigger exactly one upstream exchange, and a rotated refresh
token is written back to the vault and the stale access token flushed.

ADR-0017 §8 drew one line explicitly and left it as an anti-criterion:

> *"in v0.7, two AVP processes sharing the same `refresh_token_secret` is
> **unsupported**. Multi-instance coordination is a follow-up ADR — likely a
> vault-side optimistic lock via the secret's version metadata."*

This ADR closes that item. The gap matters as soon as AVP runs as more than one
process against the same binding — an HA pair behind a single egress, or the same
OAuth binding served from two hosts in a fleet. The failure is not theoretical: it
is a direct, silent binding lockout.

### The two races

The inflight dedup in `_derived_token_cache.dedup_or_fetch` and the generation
counter in `CachingSecretsClient` serialise **within a process** (a `threading.Lock`
+ per-key `Future`). Neither is visible to a second process. With a provider that
rotates the refresh token on every grant (`rotates_refresh_token: true` — Microsoft,
Auth0, Slack, Atlassian, Okta in the current preset table), two instances that both
observe access-token expiry inside the same rotation window produce:

1. **Concurrent-exchange race.** Both instances present the *same* refresh token
   `RT0` to the provider. The provider rotates: instance A receives `RT1` and the
   provider revokes `RT0`. Instance B's exchange, already in flight with `RT0`, now
   either (a) also succeeds and receives a *different* `RT2` (some providers issue
   per-request), or (b) fails `invalid_grant` because `RT0` was just revoked. Either
   way the two instances now disagree about the live refresh token.

2. **Write-back lost-update race.** Both instances write back to the vault. Last
   writer wins. If A writes `RT1` then B writes `RT2`, the vault holds `RT2` but
   instance A's derived-token cache and any subsequent exchange from A will fetch
   `RT2` on next read — fine — *unless* the provider already revoked `RT2` in favour
   of `RT1` on a later grant. The general symptom: the vault can come to hold a
   refresh token that the provider no longer honours, and the binding is bricked
   until an operator manually re-issues a token and rewrites the secret.

Both collapse to the same operator-visible outcome: `token_endpoint_error:invalid_grant`
on every subsequent request, with no automatic recovery. Today AVP's only defence is
the ADR-0017 documentation telling operators not to do this.

### Verified current state (2026-07-13)

- `_derived_token_cache.DerivedTokenCache.dedup_or_fetch` — per-key `Future` dedup,
  process-local salt, no cross-process awareness.
- `caching.CachingSecretsClient.update_secret` → `backends.update_secret` → `flush(name)`
  — write-through + generation bump, process-local.
- `SecretsBackend` protocol (`backends/__init__.py`): `fetch` / `fetch_with_meta` /
  `list_secret_names` / `flush_name_map` / `update`. **No conditional/compare-and-swap
  write.** BWS `update` is an unconditional PUT.
- `injectors/oauth2_refresh.OauthResolver._handle_rotation` — best-effort write-back,
  five audited outcomes, no coordination.

## Decision

Add an **opt-in, vault-backed rotation lease with a compare-and-swap (CAS) write-back**,
keyed by the `refresh_token_secret`. Reuse the secret store both instances already
share as the coordination point — **no new infrastructure** (no external lock service,
no database, no message bus) and no new runtime dependency.

The load-bearing correctness primitive is **CAS on write-back**; the lease is an
efficiency layer on top of it that prevents the wasted double-exchange. The design
degrades safely: with CAS alone, the vault can never suffer a lost update; the lease
additionally avoids two instances hitting the token endpoint at all.

### 1. Config surface

```python
class Oauth2RefreshInjector(BaseModel):
    ...
    # OFF preserves today's single-process behaviour exactly (zero overhead,
    # zero new vault calls). Operators running >1 AVP against one binding opt in.
    multi_instance_coordination: Literal["off", "cas", "lease"] = "off"

    # Lease/lock tuning — only consulted when coordination == "lease".
    # TTL MUST exceed the worst-case exchange (token_exchange_timeout +
    # retry + backoff ≈ 25s today) or a follower could steal the lease
    # mid-refresh and double-exchange — the exact race the lease removes.
    # The leader RENEWS (heartbeats) the lease every rotation_lease_renew_seconds
    # while an exchange is in flight; a steal is permitted ONLY after the TTL
    # lapses with no renewal (genuine crash recovery), never during a live refresh.
    rotation_lease_ttl_seconds: int = 30
    rotation_lease_renew_seconds: int = 10    # heartbeat cadence while leader in-flight
    rotation_lease_wait_seconds: float = 5.0  # how long a follower waits before re-read
```

`extra="forbid"` unchanged — an operator typo fails at config load, as with every
other AVP field. `off` is the default so existing deployments are byte-for-byte
unaffected and incur no extra vault round-trips.

### 2. Backend capability extension (optional, capability-probed)

Extend `SecretsBackend` with two OPTIONAL methods. Capability is probed at
config-load. **If coordination is explicitly set to `cas`/`lease` and the backend
cannot provide the primitive, config load FAILS HARD** — a silent downgrade to
`off` would hand the operator a false sense of multi-instance safety while running
the old lockout-prone path, which is a worse footgun than a loud refusal. An
operator who genuinely wants best-effort-then-fallback sets
`allow_coordination_downgrade: true` to opt into the `multi_instance_unsupported`
startup-audit downgrade explicitly. (With `coordination: "off"` — the default —
no probe runs and nothing changes.)

```python
class SupportsConditionalWrite(Protocol):
    def fetch_with_version(self, name: str, ctx: FetchContext | None = None) -> tuple[str, str]:
        """Return (value, version_token). version_token is an opaque backend
        revision handle (BWS revisionDate/etag; GSM version name)."""

    def update_if_version(
        self, name: str, value: str, expected_version: str, ctx: FetchContext | None = None
    ) -> str:
        """CAS write. Persist value IFF the backend's current version still
        equals expected_version; return the new version_token. Raise
        VersionConflictError if it moved (a peer wrote first)."""
```

Per-backend mapping (spelled out because CAS semantics differ and honesty about
that is the point):

- **Bitwarden Secrets Manager**: secrets carry a `revisionDate`. `fetch_with_version`
  returns it; `update_if_version` re-reads the revision immediately before PUT and
  refuses if it advanced. This is *optimistic* (a TOCTOU window remains between
  re-read and PUT); the lease (§3) closes that window for the common path, and the
  post-write read-back verification (§4) catches the residual race. BWS has no true
  atomic CAS today — documented as a known limitation, mitigated in layers, not
  eliminated.
- **Google Secret Manager**: `addSecretVersion` is append-only; `fetch_with_version`
  returns the version name of `latest`. CAS maps to "add version, then confirm
  `latest` is the one we added"; concurrent adds are detected by the read-back and
  resolved by the lease. GSM's native versioning makes the lost-update *recoverable*
  (both writes survive as versions) which is strictly safer than BWS's overwrite.
- **StaticBackend** (test only): no conditional write → capability absent → `off`.

### 3. Rotation lease (`coordination: "lease"`)

Before an instance performs a refresh exchange for a binding, it acquires a lease on
a companion lock key `"<refresh_token_secret>.rotation-lock"`:

1. **Acquire.** CAS-write the lock key with `{holder: <instance-id>, expires_at:
   now + rotation_lease_ttl_seconds}`, conditional on the lock being absent or
   expired. The instance-id is a process-local random token (never a secret, never
   logged as anything but presence). Acquisition uses the same `update_if_version`
   primitive; a lost CAS means a peer holds a live lease.
2. **Leader path.** Lease acquired → perform the exchange, CAS write-back the rotated
   refresh token (§4), release the lease (best-effort delete; expiry is the backstop).
3. **Follower path.** Live lease held by a peer → wait up to `rotation_lease_wait_seconds`,
   then **re-read** the refresh token and the derived-access-token cache. The leader's
   fresh access token should now be resolvable from the vault-held rotated RT; the
   follower serves it without its own exchange. This turns cross-instance contention
   into *follow-the-leader*, not *both-refresh*.
4. **Steal.** Lease present but `expires_at` in the past (leader crashed mid-rotation)
   → CAS-steal and become leader. The TTL bounds how long a crash wedges the binding.

The lease is NEVER held across anything but the exchange+write-back. A request that
cannot obtain a usable token within the wait bound fails **closed** with the existing
`503` + `token_exchange_failed:*` audit — it never serves a stale, guessed, or
peer-uncoordinated token. (Preserves G6 and the fail-closed posture.)

### 4. CAS write-back + read-back verification (`coordination: "cas"` and `"lease"`)

Write-back changes from an unconditional PUT to:

1. `fetch_with_version(refresh_token_secret)` captured *before* the exchange →
   `expected_version`.
2. After a successful exchange yields `new_refresh_token`, `update_if_version(
   refresh_token_secret, new_refresh_token, expected_version)`.
3. **Conflict** (`VersionConflictError`) → a peer rotated first. Do **not** overwrite.
   **Discard the access token this instance just minted** (it was derived from a
   refresh token the peer has now superseded), flush the derived-token cache for this
   binding, re-read the vault RT, and re-run the resolve **before any header mutation**.
   If the re-resolve cannot complete safely within the request budget, **deny** (503) —
   never inject the discarded token. Emit `write_back_conflict_retried`.
4. **Post-write read-back** (BWS optimistic path): re-read the RT after PUT; if it is
   not the value we wrote, a peer raced inside the TOCTOU window — same recovery as (3),
   including the discard-before-inject rule.

**Honest limits of CAS on BWS.** BWS exposes only a `revisionDate`, not an atomic
compare-and-set, so `update_if_version` is a re-read-then-PUT: two writers that both
pass the pre-PUT re-read can still last-writer-wins inside the TOCTOU window. CAS on
BWS therefore *reduces* but does not *eliminate* lost updates, and post-write read-back
can prove a race happened but cannot tell which rotated token the IdP actually honours.
**BWS multi-instance coordination is `experimental`**; the lease (§3), with its
renewal and fencing discipline, is what provides real mutual exclusion, and the
discard-before-inject rule above is what prevents a lost race from ever injecting a
superseded token. GSM's native versioning makes the loser's write *recoverable* (both
survive as versions) and is the recommended backend for production multi-instance.
Deployments needing a hard guarantee should front the binding with a single writer or a
fencing-capable coordinator; that is called out in Consequences → Bad.

### 5. `invalid_grant` disambiguation (NeedsReauth vs benign lost race)

Today every `invalid_grant` is a terminal `token_endpoint_error:invalid_grant`. Under
coordination this is split by evidence:

- On `invalid_grant`, re-read the vault refresh token. A version advance since the
  `expected_version` captured pre-exchange proves only that *some* write happened — NOT
  that the new RT is valid (a peer or operator could have written another dead token).
  So version-moved is **ambiguous, not benign**: retry the resolve **exactly once**
  under the freshly-read RT. On success → audit `rotation_deferred_to_peer`, done.
- If the retry also returns `invalid_grant`, or the version was unchanged to begin with,
  stop — do not loop. Emit a terminal outcome: `needs_reauth` when the version never
  moved (genuine expiry/revocation), `coordination_ambiguous` when it moved but the
  retry still failed (the vault holds a token the IdP rejects). Both are distinct and
  greppable so the operator alert fires on real re-auth need, never on transient
  contention. `avp doctor --probe-oauth` surfaces the same distinction.

The per-request retry is capped at one — there is no unbounded per-request refresh
loop. This is the "transient vs terminal" boundary drawn on evidence (version movement
plus a bounded retry), not on a guess.

### 6. Audit additions

New outcome labels on the existing `token_exchange` / `refresh_token_rotated` events —
**no new event types, no secret material, contract-minimal** (see §7 below and the
audit no-secret invariant): `rotation_lease_acquired`, `rotation_lease_wait_timeout`,
`rotation_deferred_to_peer`, `write_back_conflict_retried`, `needs_reauth`,
`multi_instance_unsupported`. Each carries only `binding_name` / `refresh_token_secret`
(the vault reference name, never the value) and the outcome. Lock holder ids are never
written; only "lease held by peer" as a boolean-equivalent outcome.

### 7. Anti-criteria (must hold)

- **Anti**: coordination MUST NOT introduce a hard dependency on a lock being
  acquirable. Backend without conditional write → downgrade to `off` with a startup
  audit, never a crash, never a request failure that a single instance wouldn't have
  had.
- **Anti**: a lease MUST NOT be held longer than the exchange+write-back; TTL-bounded,
  crash-recoverable. No request blocks on a lease past `rotation_lease_wait_seconds`.
- **Anti**: no new audit outcome, log line, or lock payload may contain a refresh-token,
  access-token, or client-secret value — old or new. (Inherits the ADR-0017 §7 / audit
  no-secret contract verbatim.)
- **Anti**: `coordination: "off"` MUST be behaviourally identical to pre-ADR-0022 —
  zero extra vault calls, zero new code on the hot path (guard on the config literal).

## Consequences

### Good

- Closes ADR-0017's one deferred multi-instance item; AVP becomes safe to run as an
  HA pair or fleet-shared binding without silent lockout.
- No new infrastructure or runtime dependency — the shared vault is the coordinator.
- CAS is the correctness floor; the lease is a pure efficiency layer; the two degrade
  independently, so partial backend support still improves safety.
- The `invalid_grant` split removes the biggest false-alarm class from operator alerting.
- Opt-in and off-by-default: existing single-instance deployments are untouched and
  pay nothing.

### Bad

- BWS has no true atomic CAS; the optimistic re-read leaves a narrow TOCTOU window,
  mitigated (lease + read-back) but not eliminated. Documented threat-model delta, in
  the spirit of ADR-0017's "plaintext access tokens in RAM" honesty.
- New code path = new bug surface across cache, backend protocol, and the resolver
  rotation chain. Estimated ~250-350 LoC + a two-instance Hypothesis state machine.
- One companion lock key per coordinated binding — a small, documented increase in the
  vault namespace; must respect GSM `secret_prefix` scoping.
- Two extra vault round-trips per rotation window when `lease` is on (acquire + release);
  amortised to near-zero by the derived-token cache TTL between rotations.

### Out of scope (each its own future ADR if needed)

- N-way (>2 instance) consensus and fairness — the target is a small fleet / HA pair,
  not a large cluster. The lease is mutual-exclusion, not leader election.
- A dedicated external lock service (Redis/etcd) — deliberately avoided; the vault is
  sufficient and dependency-free.
- Coordinating the *access-token* cache across instances (each instance keeping its own
  derived-token cache is fine; they converge through the shared RT).
- `target: body`, PKCE/auth-code, DPoP — unchanged from ADR-0017 Out of scope.

## Test strategy

Extend the existing `test_addon_oauth2_noleak_stateful.py` Hypothesis state machine to
**two `AgentVaultProxyAddon` instances sharing one versioned `FakeBackend`**. Rules:
per-instance `request`, `rotate` (provider issues new RT + revokes old), `reload`,
plus adversarial interleaving. Invariants:

- **Vault convergence**: the vault RT is always the most-recent successfully-exchanged
  RT from exactly one instance; never a value the provider has revoked.
- **No lost update**: with `cas`, no write overwrites a newer peer write undetected.
- **No double-exchange**: with `lease`, the token endpoint is called at most once per
  rotation window across both instances (assert on a shared exchange counter).
- **No stale serve**: neither instance injects an access token minted from a
  revoked RT.
- **NeedsReauth precision**: `needs_reauth` is emitted only when the vault RT version
  did not move; a peer-rotation `invalid_grant` never surfaces as `needs_reauth`.
- **No-leak carries**: the existing `no_secret_bytes_in_audit` invariant extends over
  both instances' shared audit stream and the new lock key.

## References

- ADR-0017 (OAuth2 refresh-token injector) — §7 audit contract, §8 write-back +
  deferred multi-instance anti-criterion this ADR closes.
- ADR-0013 (declarative policy fixtures) — test fixture format reused.
- RFC 6749 §6 (Refreshing an Access Token), §10.4 (refresh-token security).
- `src/kow/_derived_token_cache.py` — process-local dedup this ADR
  extends across processes.
- `src/kow/backends/__init__.py` — `SecretsBackend` protocol the
  `SupportsConditionalWrite` capability extends.
