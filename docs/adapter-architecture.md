# Adapter architecture

**Status:** **shipped in v0.4.0** (v0.3 was skipped, this refactor was bundled with composite secrets in one release). The Protocol, the registry, and the discriminated `backend: {type, config}` form in `bindings.yaml` match what ships today.

**Note on the body below:** this doc was originally written as a design proposal that included a deprecation shim from a private v0.2.0 schema to the new `backend:` form. **v0.4.0 is the first public release, so the deprecation shim was dropped**, there are no public v0.2.0 users to migrate. References to "the top-level `bws:` block", "deprecation timeline", and "byte-for-byte equivalent shim" below are historical proposal text; the shipped code has no such shim. Treat the protocol, registry, and config-block shape sections below as accurate; treat the migration-plan sections as design-history-only.

## Motivation

`agent-vault-proxy` v0.2.0 is hard-wired to Bitwarden Secrets Manager via `BwsClient`. That's fine for a project that explicitly chose "BWS is the vault you already have", but it forecloses the obvious extension: let users plug in 1Password Connect, HashiCorp Vault, Doppler, AWS Secrets Manager, etc. without forking the project.

This doc proposes the abstraction that makes adding a backend a drop-in operation rather than a refactor. The goal is that the contributor-facing answer to "how do I add support for [vault]?" becomes "implement one Protocol with one method, register it in one dict, write the config schema for your auth model" - not "study the addon, the caching layer, the audit pipeline, and figure out where to wedge yourself in."

## Interface: the entire protocol

```python
class SecretsBackend(Protocol):
    """A secrets backend fetches one named secret. Implementations handle
    their own auth lifecycle, identifier translation, and transient retries.
    Caching is wrapped around the backend by the caller, not by the backend."""

    def fetch(self, name: str) -> str:
        """Return the current value of the secret named `name` as a string.

        Raises:
            SecretNotFoundError: if the backend has no secret by that name.
            BackendUnavailableError: for transient failures (network, auth
                expired and re-auth also failed, vault sealed, etc.).
        """
        ...
```

That's it. Two exceptions, one method, return-type str. The narrow surface is the point.

What the protocol deliberately does NOT include:
- `fetch(name, field=...)` - field selection is per-backend config, not API
- `fetch(name, version=...)` - version pinning is per-backend config
- `list_names()`, addon doesn't enumerate, doesn't need it
- `refresh()` / `invalidate()`, caching wrapper owns this, backends don't
- Async: current addon is sync; protocol stays sync to match. Async backends should use `asgiref.sync.async_to_sync` (which reuses a single per-thread event loop) rather than `asyncio.run()` per call (which creates a fresh loop every fetch and serializes them)

### Forward-compatible second arg: `FetchContext`

To avoid a breaking-change requirement later if a future backend needs request context (vault policies that condition on client IP, AWS `aws:SourceIp` IAM conditions, etc.), the protocol is defined with a forward-compatible optional second arg from day one:

```python
@dataclass(frozen=True)
class FetchContext:
    """Optional per-request context. Backends ignore fields they don't use."""
    destination_host: str | None = None      # the upstream the secret is bound for
    destination_method: str | None = None    # GET, POST, etc.
    destination_path: str | None = None      # request URL path
    request_id: str | None = None            # for backend-side audit log correlation

class SecretsBackend(Protocol):
    def fetch(self, name: str, ctx: FetchContext | None = None) -> str: ...
```

For v0.3.0 every backend can ignore `ctx` (default `None`). Adding it now while there's one consumer (the addon) is free; adding it after 3rd-party adapters exist would force them all to update their signatures.

### Why `str` and not `bytes`

Every binding format in `bindings.yaml` is a string-template substitution (`Authorization: Bearer {SECRET_NAME}` or the generic `{secret}` alias). The protocol returns the type the addon needs. Binary secrets aren't a current use case; if they become one, a sibling `BinarySecretsBackend` protocol can be added without breaking the existing one.

### Why no field parameter

The biggest temptation when staring at HashiCorp Vault (KV secrets are maps) or AWS Secrets Manager (SecretString is often a JSON blob) is to extend the protocol to `fetch(name, field)`. This pushes the per-backend complexity onto the caller (the addon, eventually 3rd-party callers if anyone embeds this), and contaminates the simple backends (BWS, Doppler, Azure) with a parameter they ignore.

The cleaner approach: each adapter's config maps a logical NAME to a backend-specific ADDRESS (which may include a field/JSON-pointer/path). The protocol stays at one parameter; the adapter does the resolution internally.

## Generic caching wrapper

The current `BwsClient` mixes BWS calls with caching. The refactor extracts the cache:

```python
class CachingSecretsClient:
    """TTL + jitter + LRU cache wrapping any SecretsBackend.
    Generic. Used by the addon. Adapters never see this class."""

    def __init__(self, backend: SecretsBackend, ttl_seconds: int = 300,
                 jitter_seconds: int = 30, max_entries: int = 100) -> None: ...

    def get(self, name: str) -> str:
        # Cache hit (within TTL ± jitter) → return cached.
        # Miss / stale → call backend.fetch(name), insert, return.
        # On overflow: LRU evict.
        ...

    def flush(self, name: str | None = None) -> None: ...
```

The addon's `requestheaders` call site changes from `self.bws.get(secret_name)` to `self.client.get(secret_name)` - the cache wrapper has the same shape as the old `BwsClient.get`. One-line diff.

## Config schema

### New `backend:` block (v0.3+)

```yaml
backend:
  type: bws    # discriminator: which adapter to instantiate
  config:      # type-specific block, validated by the adapter's pydantic model
    organization_id: "..."
    access_token_path: /etc/agent-vault-proxy/bws-token
    state_path: /var/lib/agent-vault-proxy/bws-state.json
    # api_url + identity_url for EU cloud or self-hosted, as today
```

Validation rules:
- `backend.type` must match a registered backend name **case-sensitively** (registration normalizes to lowercase + rejects duplicates loudly, so registry collisions like `bws` + `BWS` can't sneak through in a PR)
- `backend.config` is parsed by the adapter's own pydantic model with `model_config['extra'] = 'forbid'` and `hide_input_in_errors = True` (so a malformed config rejects foreign fields AND validation errors don't include the bad input in their stringified form - protects against pydantic leaking `SecretStr` values into logs)
- Exactly one `backend:` block. (v0.2.0's top-level `bws:` block stays valid as a deprecation shim, see "Migration" below.)
- **If both `bws:` (top-level) AND `backend:` are present, the proxy refuses to start.** This is a CONFIGURATION ERROR, not a merge. Without this rule, a PR reviewer who reads only the `backend:` block could miss that the running proxy honors `bws:` instead: classic split-brain config exploit. The shim only synthesizes `backend:` when `backend:` is absent.

### Backend coverage matrix

| `backend.type` | `config:` fields (sketch) | Notes |
|---|---|---|
| `bws` | `organization_id`, `access_token_path`, `state_path`, `api_url`, `identity_url` | Current v0.2.0 schema, lifted verbatim |
| `doppler` | `service_token_path`, `project`, `config` | HTTP-only, no SDK dep, simplest adapter (~50 LOC) |
| `onepassword-sa` | `service_account_token_path`, `vault`, `secrets: {NAME: {item_uuid, field}}` | Uses 1Password's **Service Accounts SDK** (`onepassword-sdk-python`, the actively-invested path). Address items by UUID (not title: `get_item_by_title` raises on count != 1) and require per-secret field name because field IDs vary by category (`API_CREDENTIAL` uses `credential`, `LOGIN`/`PASSWORD` use `password`, `SSH_KEY` uses `private_key`, etc.). Rate limits are tight (1000-10000/day per token depending on plan) - caching is a correctness requirement, not an optimization. |
| `hashicorp-vault` | `url`, `namespace?`, `auth: {type: approle, role_id_path, secret_id_path \| wrapping_token_path, token_type: batch}`, `secrets: {NAME: {path, field}}` OR `prefix: <path>` | Per-secret explicit map, OR prefix+convention shorthand (more idiomatic for Vault users). Uses **batch tokens** (current HashiCorp recommendation), so no renewal thread - adapter re-logs-in on each token expiry. Supports wrapped `secret_id` delivery via `wrapping_token_path` + `sys.unwrap()`. |
| `aws-secrets-manager` | `region`, `secrets: {NAME: {secret_id, json_pointer?}}` | Uses ambient AWS creds (IAM role / env). `json_pointer` handles SecretString JSON blobs |
| `azure-key-vault` | `vault_url`, `auth: {type: default-credential\|service-principal, ...}` | Bare names; uses Azure SDK credential chain |
| `gcp-secret-manager` | `project_id`, `version_alias` (default: `latest`) | Adapter formats the full resource path internally |

The matrix is the design-validation artifact: 7 backends, all expressible through the same protocol + per-backend config block. The pattern holds across substantially different auth models (machine-account tokens, AppRole, IAM role chains, AAD credential chain, ADC).

### Backends explicitly excluded

**LastPass**, evaluated and rejected. LastPass provides no programmatic vault-fetch API (the "Enterprise API" covers provisioning/SCIM only). The de facto integration path is `lastpass-cli`, which has had no release since 2019 and depends on master-password + 2FA-bypass authentication, unsuitable for a long-running daemon. Combined with the unresolved blast radius of the 2022 vault exfiltration (£1.2M ICO fine, traced downstream theft in the hundreds of millions), LastPass fails both the *abstraction-fit* gate (would require subprocess to a dead CLI) and the *trust-posture* gate (master-password auth model is hostile to daemons). Adapter cost is high; user demand is net-negative as enterprises migrate off the platform.

**1Password Connect (legacy)** - Connect is 1Password's older self-hosted product. As of 2026, 1Password's investment is in **Service Accounts** (the `onepassword-sa` row above), and the company explicitly positions Connect for air-gap / on-prem-only use cases. Connect's token rotation is also entirely manual (no programmatic rotation API), while Service Accounts supports it natively. We may add a `onepassword-connect` row in v0.4+ if a real air-gap deployment surfaces; until then, supporting both adds maintenance burden against a vendor-deprecated path.

**Dynamic secrets engines (Vault AWS, Vault DB, Vault PKI, etc.)** - these return `{access_key, secret_key, session_token, lease_id, lease_duration}` payloads with leases that must be renewed/revoked. The `fetch(name) -> str` protocol returns one field; lease lifecycle is lost. Future enhancement: a sibling `LeasedSecretsBackend` protocol with `fetch_lease(name) -> Lease` + explicit revocation. Out of v0.3 scope.

### Operator security model for `backend.config`

The per-backend config block is a security-sensitive surface that operators must treat with the same review discipline as a code change. Specifically:

- Whoever can modify `bindings.yaml` can remap `OPENAI_API_KEY` → fetch `path: secret/data/aws/root-creds` (Vault) or `secret_id: production-rds-password` (AWS). The proxy will happily inject whatever the backend returns into the bound destination.
- The **vault-side** auth principal (BWS machine account, AppRole policy, IAM role, etc.) is what bounds the actual blast radius. Scope it to the path-prefix / project / secret-name-pattern the proxy is *expected* to read, never grant the proxy broader read access "for convenience".
- The `secrets:` block in `bindings.yaml` enforces **destination** scoping (host + method + path). The `backend.config` block determines **source** mapping. Both surfaces are equally important; both deserve PR review when modified.

### Per-secret name mapping (where it lives)

Three backends have a name→address mapping that's richer than "the name IS the address":

- **HashiCorp Vault**: `{NAME: {path: "secret/data/openai/api-key", field: "value"}}`
- **AWS Secrets Manager**: `{NAME: {secret_id: "prod/openai", json_pointer: "/api_key"}}` for JSON blobs; just `{secret_id: "..."}` for scalar SecretStrings
- **1Password Connect**: optionally per-secret field override; otherwise the global `field` default applies

The other backends use the name as-is (BWS uses it to look up the BWS-side secret name; Doppler uses it as the query param; Azure uses it directly; GCP templates it into the resource path).

## Backend registration

```python
# src/agent_vault_proxy/backends/__init__.py
from agent_vault_proxy.backends.bws import BitwardenBackend, BwsConfig
from agent_vault_proxy.backends.doppler import DopplerBackend, DopplerConfig
# ... etc

BACKEND_REGISTRY: dict[str, tuple[type[SecretsBackend], type[BaseModel]]] = {
    "bws": (BitwardenBackend, BwsConfig),
    "doppler": (DopplerBackend, DopplerConfig),
    "onepassword-connect": (OnePasswordConnectBackend, OnePasswordConnectConfig),
    # ...
}
```

Adding a new backend is a one-line registry entry + one new file under `src/agent_vault_proxy/backends/<vault>.py`.

We are NOT using Python entry-point plugin discovery for v0.3. Explicit registration is auditable, makes the install boundary inspectable (a malicious package can't sneak a backend into our registry), and matches the "small project, transparent design" stance.

## Migration path

### File-by-file changes

| File | Change | LOC delta |
|---|---|---|
| `src/agent_vault_proxy/bws.py` | Extract caching into new `caching.py`. Rename `BwsClient` → `BitwardenBackend`, move to `backends/bws.py`. Drop the cache machinery (now in `CachingSecretsClient`). | -100 |
| `src/agent_vault_proxy/caching.py` | **New.** `CachingSecretsClient` (~80 lines). Direct lift of TTL+jitter+LRU code from `BwsClient`. | +80 |
| `src/agent_vault_proxy/backends/__init__.py` | **New.** Protocol definition (`SecretsBackend`), exceptions (`SecretNotFoundError`, `BackendUnavailableError`), `BACKEND_REGISTRY`. | +40 |
| `src/agent_vault_proxy/backends/bws.py` | **New.** `BitwardenBackend` + `BwsConfig` pydantic model. Mostly a move of existing code. | +120 |
| `src/agent_vault_proxy/config.py` | Add `BackendBlock` discriminated-union model. Keep `BwsSpec` (used by the deprecation shim). Add the shim: if top-level `bws:` is present, synthesize a `backend: {type: bws, config: <bws-spec>}` + emit warning. | +60 |
| `src/agent_vault_proxy/addon.py` | Two lines change: instantiate via `BACKEND_REGISTRY[cfg.backend.type]` instead of `BwsClient.from_config()`. Wrap in `CachingSecretsClient`. The `requestheaders` call site is unchanged. | +5 |
| `tests/test_bws.py` → `tests/test_caching.py` + `tests/backends/test_bws.py` | Split: caching tests get the cache class, backend tests get the BWS-specific tests. Add a `FakeBackend` fixture for caching-layer tests. | ±0 |
| `tests/backends/test_protocol.py` | **New.** Contract test that every registered backend implements the protocol correctly (uses recorded fixtures, no live API calls). | +60 |
| `bindings.example.yaml` | Add a `backend:` block as the new canonical form; keep the `bws:` block in a comment marked deprecated-but-supported. | ±20 |
| `docs/architecture.md` | Update §2 (component diagram) + §6.1 (supply chain: now references multi-backend possibility). | ±15 |

**Total: ~360 LOC of change, mostly moves/renames. ~200 LOC genuinely new.**

### Effort estimate

For a developer comfortable with the codebase: **3-5 hours** of focused work for the refactor itself + the test split. Adding the first non-BWS backend (probably Doppler as the simplest validator) is another **1-2 hours**. A 1Password Connect or HashiCorp Vault adapter is another **2-4 hours each**, mostly because of auth lifecycle handling.

If the user wants me to do the refactor: one Algorithm-mode session, ~6 hours of work, ships as v0.3.0-rc1.

### Deprecation timeline

| Version | `bws:` top-level block | `backend:` block | Behavior |
|---|---|---|---|
| v0.2.0 (today) | required | n/a | Single-backend, BWS only |
| v0.3.0 | **deprecated, still works** + startup-log warning | preferred | Shim translates old to new |
| v0.4.0 | warning escalates to a one-line `DeprecationWarning` print to stderr | required | Shim still works |
| v1.0.0 | **removed** | required | Bindings.yaml MUST use `backend:` |

Each step gives operators ~1 minor-version's worth of warning. The shim is ~15 lines of code in `config.py`; it stays around until v1.0 to avoid breaking anyone's first-public-release deployments.

### Optional-deps pinning

Adding `1Password`, `hvac`, `boto3`, `azure-keyvault-secrets`, `google-cloud-secret-manager` etc. as optional extras under `pyproject.toml`'s `[project.optional-dependencies]` would re-introduce the supply-chain weakness that `--require-hashes` closes for production deps. `pip install agent-vault-proxy[vault]` resolves the extras tree at install time against an unconstrained dependency graph.

Solution: ship one hash-pinned lockfile per backend extra.

```
requirements.lock              # always installed (BWS — the canonical backend)
requirements-1password.lock    # only installed if you want 1Password Connect
requirements-vault.lock        # only installed if you want HashiCorp Vault
requirements-aws.lock          # only installed if you want AWS Secrets Manager
…
```

Each backend extra's install command is `pip install --require-hashes -r requirements-<vault>.lock` rather than `pip install .[<vault>]`. CI's `verify-lockfile` job validates each one against the 7-day cooldown gate the same way it validates `requirements.lock` today. The README install snippet for "I want backend X" becomes one extra line, not a downgrade in security posture.

### What stays the same

The user-visible bits that DON'T change:
- The `secrets:` section of `bindings.yaml` (the placeholder/inject/bindings declaration) is unchanged
- The placeholder format, the audit log schema, the systemd unit, the Docker compose
- The `requestheaders` addon hook, the `inject_decision` audit event format
- The `--require-hashes` + 7-day cooldown supply-chain controls (the new backend's deps go through the same gate)
- The G1–G9 invariants, the refactor preserves every wire-format guarantee

This is a back-of-the-stack refactor; the user-facing surface only grows (new backend choices), it doesn't shift.

## Pre-mortem

### Failure modes of the refactor itself

1. **The deprecation shim has a subtle behavior delta.** Someone using `bws:` top-level + relying on a quirk of `BwsClient.from_config()` finds their v0.3 install fetches differently. **Mitigation:** the shim is byte-for-byte equivalent (synthesizes the exact same `BwsConfig` instance the new path uses). Add a regression test that runs the v0.2.0 bindings.yaml through v0.3 loader and asserts identical `BwsConfig` dataclass output.

2. **`CachingSecretsClient` extraction introduces a thread-safety regression.** The original `BwsClient` uses a single `threading.Lock`. If I split the cache from the backend, the lock split could allow a race where two threads both fetch the same secret. **Mitigation:** lock stays in the cache class (where it logically belongs); backend's `fetch()` is called outside the lock to avoid blocking the cache during slow network I/O - same pattern as `BwsClient.get()` today. Regression test: spawn 50 threads all calling `get("same_name")`, assert backend.fetch was called once.

3. **Pydantic discriminated-union schema parsing breaks for `backend.config`.** Each backend's config is a different pydantic model; the discriminator (`type:`) needs to dispatch correctly. **Mitigation:** use pydantic's `discriminator="type"` on the union (supported since pydantic 2.x). Unit test each backend's config rejects another backend's fields.

4. **Adapter authors put network I/O in `__init__` and break test ergonomics.** A backend that opens a session/auths in its constructor can't be unit-tested without a real vault. **Mitigation:** document the protocol contract: "no I/O in `__init__`; first I/O is on first `fetch()` call". Add this to the protocol docstring. Contract test catches I/O at construction by using a `responses`/`pytest-httpx` mock that asserts zero requests during `Backend(config)`.

5. **A backend leaks its config (incl. token) into log records on error.** `repr(self)` or an unhandled exception that includes `self.access_token` in its traceback. **Mitigation:** protocol guideline says backends MUST mark token fields with `pydantic.SecretStr`. Contract test verifies `repr(backend)` doesn't include the secret-typed fields.

6. **Caching layer caches `BackendUnavailableError` results.** A transient failure becomes a sticky bad cache entry. **Mitigation:** cache only inserts on successful fetch (the existing `BwsClient.get` pattern). Cache class catches `BackendUnavailableError` from backend.fetch and re-raises without inserting. Regression test.

### Failure modes of the cache + backend interaction

7. **Re-auth stampede on simultaneous token expiry.** 50 concurrent `fetch()` calls all observe "token expired" at the same moment, each triggers its own re-auth POST against the vault, potentially hitting vault-side rate limits and *causing* the auth failure they're trying to recover from. **Mitigation:** the cache wrapper implements singleflight per name - at most one in-flight fetch per name; concurrent callers wait on the same future. Backends MAY ALSO lock around their re-auth path defensively. Documented in the protocol-contract test.

8. **Operator revokes vault auth mid-incident; cached secrets keep flowing for up to TTL+jitter.** Cache doesn't know auth was lost. For 300s+jitter, the agent can still send the revoked secret to upstreams. **Mitigation:** introduce `BackendAuthLostError` as a subclass of `BackendUnavailableError`. When the cache catches it, it flushes its full map for that backend (not just the one name) before re-raising. Backends are expected to raise this distinct subclass when they detect token revocation, not generic `BackendUnavailableError`. Operators also get a documented `kill -USR1 <pid>` → `CachingSecretsClient.flush(None)` escape hatch.

### Failure modes of 3rd-party adapter authors

1. **Author thinks `fetch()` is called once per request.** Adds expensive operations (full vault list, audit log read) per call. **Mitigation:** docstring says "may be called frequently; cache adapter-side state where appropriate". Provide a reference impl (Doppler) showing the right pattern.

2. **Author handles auth errors by raising the SDK's native exception class.** Caller can't catch it without depending on the backend's SDK. **Mitigation:** protocol explicitly requires `SecretNotFoundError` and `BackendUnavailableError`. Add a contract test that runs every registered backend through a fuzzer-style "make X fail, assert protocol exception is raised" check.

3. **Author hard-codes `print()` for logging.** Pollutes operator stdout. **Mitigation:** docstring says "use `logging.getLogger(__name__)`; no stdout/stderr writes".

4. **Author writes a sync backend wrapping an async SDK via `asyncio.run()`, works in tests, breaks under threading.** `asyncio.run()` creates a new event loop per call, mitmproxy is threaded. **Mitigation:** document the threading model in a "Backend author's guide". Recommend `asgiref.sync.async_to_sync` for adapters wrapping async SDKs.

### Failure modes where the abstraction LEAKS (some vault needs something we didn't expose)

1. **OAuth refresh-token backends (Vault Agent w/ JWT, Azure with managed identity rotation) need a background renewal thread.** Our protocol has no "start"/"stop" lifecycle hook. **Mitigation:** adapter spawns its own daemon thread in `__init__` and uses `atexit` for cleanup. Acceptable but ugly. If we see this pattern in 2+ backends, add `def start(self): ...` and `def stop(self): ...` lifecycle hooks to the protocol (currently default no-ops).

2. **Backends that return binary secrets (e.g., a TLS private key) don't fit `-> str`.** **Mitigation:** out of scope for v0.3. If a real use case appears, add `BinarySecretsBackend(Protocol)` as a sibling protocol; addon's `requestheaders` only consumes string secrets, so this is naturally additive.

3. **Backends that need to know REQUEST CONTEXT (the destination host, the agent's IP, etc.) for policy decisions.** Some vaults support conditional access. **Mitigation:** out of scope. If real, the addon already enforces destination/method/path scoping in `bindings.yaml`, that's where access policy lives, not in the backend.

### Accepted residual risks

- **Schema validation only at startup.** If a backend's pydantic config has a runtime-discovered constraint (e.g., "this field is required only if `auth.type == approle`"), violations surface at startup, not at first `fetch()`. Standard pydantic idiom; not worth special handling.
- **No backend hot-swap.** Config changes require service restart. v0.2.0 has this constraint; v0.3 keeps it.
- **No multi-backend.** Each instance serves from one vault. Multi-backend ("BWS for these secrets, AWS for those") would require a backend-routing layer above the cache; deferred.

## FAQ

**Q: Why not entry-point plugin discovery?**
Explicit registration is auditable. A malicious pip package shouldn't be able to inject a backend that quietly handles `bws://` URIs and exfiltrates tokens. Registration in `BACKEND_REGISTRY` is a code change reviewable in PR. We can revisit if/when external contributors actually maintain out-of-tree backends.

**Q: Why not async?**
mitmproxy addons are sync. The whole proxy is one async event loop (mitmproxy's), and addons run in the loop. Wrapping a sync backend.fetch is trivial; wrapping an async one in a sync protocol is what the adapter would do internally. Keeping the protocol sync matches the consumer.

**Q: Why does the protocol have only two exception types?**
Caller code handles exactly two states: "this secret is gone" (404-like, log-and-skip) and "the backend is hosed" (5xx-like, fail-closed). Finer-grained distinctions (token-expired vs network-down vs vault-sealed) belong in the audit-log message, not in caller branching.

**Q: How do I write a contract test for my new backend?**
Subclass `tests/backends/protocol_contract.py:ProtocolContractTests` (TBD in implementation), supply a `make_backend(...)` fixture that returns a configured instance, and the suite runs the 12-ish assertions every backend must pass: no I/O in init, idempotent fetch, error-type mapping, no secrets in repr, etc.

**Q: Will v0.3 break my existing v0.2.0 deployment?**
No. The deprecation shim translates your `bws:` top-level block to the new `backend.type=bws` form transparently. You'll see a log warning on startup; nothing else changes. Migrate at your own pace; full removal isn't until v1.0.

## Adversarial review applied

This design has been through TWO review passes:
1. An opus-model Pentester agent red-teaming the abstraction itself
2. Three parallel research agents validating the design against current 1Password, LastPass, and HashiCorp Vault documentation

### Round 1 (Pentester) findings - incorporated:

- **CRITICAL** dual-block `bws:` + `backend:` precedence is undefined → now an explicit startup error (§Config schema)
- **HIGH** per-secret address remapping has no operator-side allowlist → added §Operator security model
- **HIGH** case-insensitive discriminator can collide → now case-sensitive with collision-rejecting registration (§Config schema)
- **HIGH** cache has no auth-loss invalidation path → added `BackendAuthLostError` + cache-wide flush + SIGUSR1 escape hatch (§Pre-mortem failure mode 8)
- **MED** pydantic `ValidationError` can leak `SecretStr` → `hide_input_in_errors = True` required on backend configs (§Config schema)
- **MED** re-auth stampede across concurrent callers → singleflight per name in cache wrapper (§Pre-mortem failure mode 7)
- **MED** optional-deps install bypasses `--require-hashes` → per-extra lockfiles documented (§Optional-deps pinning)
- **FOOTGUN** `asyncio.run()` advice was wrong for mitmproxy's threading model → corrected to `asgiref.sync.async_to_sync`
- **FOOTGUN** request-context would be a breaking-change to add post-hoc → added `FetchContext | None` second arg in v0.3.0 (§Interface)

Findings deferred or accepted as residual risk: backend lifecycle hooks (start/stop), recorded-fixture rot (operational, not architectural), binary secrets out of scope.

A cross-model Oracle review was attempted; the OpenAI provider returned shell-command-shaped `suggested_check` fields that failed the Oracle skill's JSON schema validation (twice). Substantive cross-model review is deferred until either (a) the Oracle skill's schema tolerates command-style suggestions, or (b) an alternate provider is wired.

### Round 2 (vendor-docs verification) - incorporated:

- **1Password**: pivoted from Connect to Service Accounts SDK as the v0.3 target, Connect is in vendor-acknowledged maintenance mode; Service Accounts is where 1Password is investing and is the only path with programmatic token rotation. Connect remains deferred to v0.4+ behind explicit air-gap demand.
- **1Password**: `field: "password"` is NOT a stable default across item categories, `API_CREDENTIAL` uses `credential`, `SSH_KEY` uses `private_key`, etc. Config now requires per-secret field name. Previous research's "warn-on-duplicate-titles" mitigation removed (SDK already raises on count != 1).
- **1Password**: rate limits are 1000-10000/day per token depending on plan: `CachingSecretsClient` is a CORRECTNESS requirement at sustained throughput, not just a latency win. Documented in the matrix row.
- **HashiCorp Vault**: switched from periodic-token-with-renewal-thread to **batch tokens with re-login per expiry**. HashiCorp's current recommendation. Eliminates an entire failure class (renewal thread dies silently, token lapses, sparse fetches don't notice until too late).
- **HashiCorp Vault**: added `prefix:` convention shorthand alongside the explicit `secrets:` map - more idiomatic for Vault users who already organize secrets by path.
- **HashiCorp Vault**: response-wrapped `secret_id` delivery (`wrapping_token_path` config + `sys.unwrap()`) supported as a first-class auth-onboarding option.
- **Vault dynamic secrets engines** (AWS/DB/PKI): formally excluded from v0.3 - lease lifecycle doesn't fit `fetch() -> str`. Added to "Explicitly excluded" with a path forward (sibling `LeasedSecretsBackend` protocol later).
- **LastPass**: formally excluded from the design. Added "Explicitly excluded" section documenting why (no fetch API, dead CLI, hostile auth model, post-breach brand posture).
- **Vault CVEs (HCSEC-2025-30 AWS auth bypass, HCSEC-2025-33 LDAP null-bind)**, flagged in implementation TODO: if a future contributor adds AWS auth method or LDAP auth method support, the adapter must require Vault >= 1.21.0.

## Next steps (for the user reviewing this doc)

If this design holds up to scrutiny:
1. Approve as-is → I implement the refactor as v0.3.0-rc1 (one Algorithm session, ~6 hours)
2. Approve with changes → tell me which sections to revise; I revise this doc, you re-review
3. Reject and want a different shape → tell me why; alternatives are: keep v0.2.0 BWS-only forever, OR adopt a fully async protocol, OR use entry-point plugins, OR something else

The refactor doesn't have to ship before v0.3.0, it could be a v0.4 thing if you want to soak v0.2.0 in the wild first. The design above is forward-compatible either way.
