# Adapter architecture

How `agent-vault-proxy` talks to a secrets vault, and how to add a new one.

**What ships today:** three backends. `bws` (Bitwarden Secrets Manager) and `gsm` (Google Secret Manager) are the production backends; `static` reads `{name: value}` pairs from a plaintext YAML file and exists only for development, testing, and the docker-e2e harness (it refuses world-readable files and warns loudly when selected, never use it in production). The `SecretsBackend` protocol, the registry, and the discriminated `backend: {type, config}` form in `bindings.yaml` are all live as of v0.4.0. The remaining vault backends in the coverage matrix below are the design target, not yet shipped: the matrix exists to prove the protocol holds across substantially different vaults, and to give a contributor the map for adding one.

## Why an adapter layer

The proxy was originally hard-wired to Bitwarden Secrets Manager via `BwsClient`. That is fine for a project that chose "BWS is the vault you already have", but it forecloses the obvious extension: plugging in 1Password, HashiCorp Vault, Doppler, AWS Secrets Manager, and so on without forking.

The adapter layer makes adding a backend a drop-in operation. The contributor-facing answer to "how do I add support for [vault]?" is "implement one protocol with one method, register it in one dict, write the config schema for your auth model", not "study the addon, the caching layer, and the audit pipeline and figure out where to wedge yourself in".

## The protocol

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

Two exceptions, one method, return-type `str`. The narrow surface is the point.

What the protocol deliberately does NOT include:
- `fetch(name, field=...)` : field selection is per-backend config, not API.
- `fetch(name, version=...)` : version pinning is per-backend config.
- `list_names()` : the addon doesn't enumerate, doesn't need it.
- `refresh()` / `invalidate()` : the caching wrapper owns this, backends don't.
- Async: the addon is sync; the protocol stays sync to match. Async backends use `asgiref.sync.async_to_sync` (which reuses a single per-thread event loop) rather than `asyncio.run()` per call (which creates a fresh loop every fetch and serializes them).

### The forward-compatible second arg: `FetchContext`

A future backend may need request context (vault policies that condition on client IP, AWS `aws:SourceIp` IAM conditions, etc.). To avoid forcing a breaking signature change later, the protocol carries an optional second arg from day one:

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

Every backend can ignore `ctx` (default `None`). Carrying it now, while the addon is the only consumer, is free; adding it after third-party adapters exist would force them all to update their signatures.

### Why `str` and not `bytes`

Every binding format in `bindings.yaml` is a string-template substitution (`Authorization: Bearer {SECRET_NAME}`). The protocol returns the type the addon needs. (The legacy generic `{secret}` alias was removed in v0.5.0: only the named form `{<SECRET_NAME>}` matching each entry's YAML key is accepted.) Binary secrets are not a current use case; if they become one, a sibling `BinarySecretsBackend` protocol can be added without breaking this one.

### Why no field parameter

The temptation when staring at HashiCorp Vault (KV secrets are maps) or AWS Secrets Manager (SecretString is often a JSON blob) is to extend the protocol to `fetch(name, field)`. That pushes per-backend complexity onto the caller and contaminates the simple backends (BWS, Doppler, Azure) with a parameter they ignore.

The cleaner approach: each adapter's config maps a logical NAME to a backend-specific ADDRESS (which may include a field / JSON-pointer / path). The protocol stays at one parameter; the adapter does the resolution internally.

## The caching wrapper

Caching is generic and lives outside the backend, so every adapter inherits it for free:

```python
class CachingSecretsClient:
    """TTL + jitter + LRU cache wrapping any SecretsBackend.
    Generic. Used by the addon. Adapters never see this class."""

    def __init__(self, backend: SecretsBackend, ttl_seconds: int = 300,
                 jitter_seconds: int = 30, max_entries: int = 100) -> None: ...

    def get(self, name: str) -> str:
        # Cache hit (within TTL ± jitter) -> return cached.
        # Miss / stale -> call backend.fetch(name), insert, return.
        # On overflow: LRU evict.
        ...

    def flush(self, name: str | None = None) -> None: ...
```

The addon calls `self.client.get(secret_name)`; the backend only ever sees `fetch()`.

## Config schema

The `backend:` block in `bindings.yaml` selects and configures the vault:

```yaml
backend:
  type: bws    # discriminator: which adapter to instantiate
  config:
    type: bws  # the adapter's own pydantic model, validated separately
    organization_id: "..."
    access_token_path: /etc/agent-vault-proxy/bws-token
    state_path: /var/lib/agent-vault-proxy/bws-state.json
    # api_url + identity_url for EU cloud or self-hosted
```

Validation rules:
- `backend.type` is matched **case-insensitively**: the name is NFKC-normalized and casefolded before the registry lookup, so `bws`, `BWS`, and full-width variants all resolve to the one backend. Registration rejects duplicates loudly, so a registry collision can't sneak through in a PR.
- `backend.config` is parsed by the adapter's own pydantic model with `model_config['extra'] = 'forbid'` and `hide_input_in_errors = True`, so a malformed config rejects foreign fields AND validation errors never include the bad input in their stringified form (protects against pydantic leaking `SecretStr` values into logs).
- Exactly one `backend:` block.

### Backend coverage matrix

Of the vaults, `bws` and `gsm` ship today (the `static` test backend aside). The rest are the design target: the matrix is the proof that one protocol plus a per-backend config block spans substantially different auth models (machine-account tokens, AppRole, IAM role chains, AAD credential chain, ADC).

| `backend.type` | `config:` fields (sketch) | Notes |
|---|---|---|
| `bws` | `organization_id`, `access_token_path`, `state_path`, `api_url`, `identity_url` | The shipped backend. |
| `doppler` | `service_token_path`, `project`, `config` | HTTP-only, no SDK dep, simplest adapter (~50 LOC). |
| `onepassword-sa` | `service_account_token_path`, `vault`, `secrets: {NAME: {item_uuid, field}}` | Uses 1Password's **Service Accounts SDK** (`onepassword-sdk-python`). Address items by UUID (not title: `get_item_by_title` raises on count != 1) and require per-secret field name, because field IDs vary by category (`API_CREDENTIAL` uses `credential`, `LOGIN`/`PASSWORD` use `password`, `SSH_KEY` uses `private_key`). Rate limits are tight (1000-10000/day per token by plan), so caching is a correctness requirement, not an optimization. |
| `hashicorp-vault` | `url`, `namespace?`, `auth: {type: approle, role_id_path, secret_id_path \| wrapping_token_path, token_type: batch}`, `secrets: {NAME: {path, field}}` OR `prefix: <path>` | Per-secret explicit map, OR prefix+convention shorthand (more idiomatic for Vault users). Uses **batch tokens** (current HashiCorp recommendation), so no renewal thread: the adapter re-logs-in on each token expiry. Supports wrapped `secret_id` delivery via `wrapping_token_path` + `sys.unwrap()`. |
| `aws-secrets-manager` | `region`, `secrets: {NAME: {secret_id, json_pointer?}}` | Uses ambient AWS creds (IAM role / env). `json_pointer` handles SecretString JSON blobs. |
| `azure-key-vault` | `vault_url`, `auth: {type: default-credential\|service-principal, ...}` | Bare names; uses Azure SDK credential chain. |
| `gsm` **(shipped)** | `project_id`, `version_alias`, `secret_prefix?`, `impersonate_service_account?`, `credential_config_path?`, `self_check`, `reject_ambient_key` | **Google Secret Manager.** Keyless auth only — ADC / SA-impersonation / Workload Identity Federation (**no key-file field**); boot-time deny-if-broad `self_check` (refuses to start under a broad identity); host binding via each secret's `avp-binding` annotation (bare host or flat-YAML) under `binding_source: notes`. REST over `google-auth`, not the gRPC SDK. See [ADR-0018](adrs/ADR-0018-gcp-secret-manager-backend.md). |

### The `gsm` backend's `avp-binding` annotation (host binding at the vault)

With `backend.type: gsm` and `binding_source: notes`, each secret is bound to a destination host **by the secret itself** — no `secrets:` block needed. Put an `avp-binding` annotation on the GSM secret:

- **Bare hostname** (the common case): `avp-binding: api.openai.com`. For a known provider the built-in exception table supplies a tight method/path scope; for an unknown host the default is `Authorization: Bearer <secret>`, any method.
- **Flat-YAML** (when you need more): a small block with `host` (required) plus optional `header`, `format`, `methods`, `paths`:
  ```yaml
  host: api.internal.acme.com
  methods: [POST]
  paths: [/v1/ingest]
  ```

A secret with no `avp-binding` annotation resolves to *no binding* and is never injected — fail-closed by omission. Set it with `gcloud secrets update NAME --update-annotations="avp-binding=api.openai.com"`.

### Backends explicitly excluded

**LastPass** : evaluated and rejected. LastPass provides no programmatic vault-fetch API (the "Enterprise API" covers provisioning/SCIM only). The de facto integration path is `lastpass-cli`, which has had no release since 2019 and depends on master-password + 2FA-bypass auth, unsuitable for a long-running daemon. Combined with the unresolved blast radius of the 2022 vault exfiltration, LastPass fails both the abstraction-fit gate (would require subprocess to a dead CLI) and the trust-posture gate (master-password auth is hostile to daemons).

**1Password Connect (legacy)** : Connect is 1Password's older self-hosted product. 1Password's investment is in **Service Accounts** (the `onepassword-sa` row), and the vendor positions Connect for air-gap / on-prem-only use. Connect's token rotation is also entirely manual. A `onepassword-connect` backend may follow if a real air-gap deployment surfaces.

**Dynamic secrets engines (Vault AWS, Vault DB, Vault PKI, etc.)** : these return `{access_key, secret_key, session_token, lease_id, lease_duration}` payloads with leases that must be renewed/revoked. The `fetch(name) -> str` protocol returns one field; lease lifecycle is lost. A future sibling `LeasedSecretsBackend` protocol with explicit revocation could cover this.

### Operator security model for `backend.config`

The per-backend config block is a security-sensitive surface. Treat edits to it with the same review discipline as a code change:

- Whoever can modify `bindings.yaml` can remap `OPENAI_API_KEY` to fetch `path: secret/data/aws/root-creds` (Vault) or `secret_id: production-rds-password` (AWS). The proxy injects whatever the backend returns into the bound destination.
- The **vault-side** auth principal (BWS machine account, AppRole policy, IAM role) bounds the actual blast radius. Scope it to the path-prefix / project / secret-name-pattern the proxy is expected to read; never grant broader read access "for convenience".
- The `secrets:` block enforces **destination** scoping (host + method + path). The `backend.config` block determines **source** mapping. Both deserve PR review when modified.

### Per-secret name mapping (where it lives)

Three backends have a name-to-address mapping richer than "the name IS the address":

- **HashiCorp Vault**: `{NAME: {path: "secret/data/openai/api-key", field: "value"}}`
- **AWS Secrets Manager**: `{NAME: {secret_id: "prod/openai", json_pointer: "/api_key"}}` for JSON blobs; just `{secret_id: "..."}` for scalar SecretStrings
- **1Password**: optionally a per-secret field override; otherwise the global `field` default applies

The other backends use the name as-is (BWS looks it up by secret name; Doppler uses it as the query param; Azure uses it directly; GCP templates it into the resource path).

## Backend registration

```python
# src/agent_vault_proxy/backends/__init__.py
def _register_builtins() -> None:
    from agent_vault_proxy.backends.bws import BitwardenBackend, BwsConfig
    from agent_vault_proxy.backends.static import StaticSecretsBackend, StaticSecretsConfig

    register_backend("bws", BitwardenBackend, BwsConfig)
    register_backend("static", StaticSecretsBackend, StaticSecretsConfig)
    # future: register_backend("doppler", ...), ("hashicorp-vault", ...), ...
```

`BACKEND_REGISTRY` is exposed read-only (a `MappingProxyType`); all writes go through `register_backend()`, which NFKC-normalizes + casefolds the name and rejects duplicates. Adding a backend is one `register_backend(...)` call plus one new file under `src/agent_vault_proxy/backends/<vault>.py`.

The proxy does **not** use Python entry-point plugin discovery. Explicit registration is auditable, keeps the install boundary inspectable (a malicious package can't sneak a backend into the registry), and matches the small-project, transparent-design stance.

## Backend author's guide

Guidance for anyone writing a new adapter. Each item is a real failure mode the protocol is shaped to prevent.

- **`fetch()` may be called frequently.** It sits behind the cache, but don't add per-call expensive operations (full vault list, audit-log read). Cache adapter-side state where appropriate; the Doppler reference impl shows the pattern.
- **Map errors to the two protocol exceptions.** Raise `SecretNotFoundError` (404-like, log-and-skip) and `BackendUnavailableError` (5xx-like, fail-closed), never the SDK's native exception class: the caller can't catch what it can't import.
- **No I/O in `__init__`.** First I/O is on first `fetch()`, so the adapter is unit-testable without a live vault. The contract test asserts zero requests during construction.
- **Never leak the token.** Mark token fields with `pydantic.SecretStr`; don't put secrets in `repr(self)` or in an exception traceback. The contract test verifies `repr(backend)` excludes secret-typed fields.
- **Use `logging.getLogger(__name__)`.** No `print()`, no stdout/stderr writes.
- **Wrap async SDKs with `asgiref.sync.async_to_sync`, not `asyncio.run()`.** mitmproxy is threaded; a fresh event loop per call breaks under threading.

The cache wrapper handles two interaction hazards on the adapter's behalf:

- **Re-auth stampede.** On simultaneous token expiry, the wrapper enforces singleflight per name (at most one in-flight `fetch()` per name; concurrent callers wait on the same result), so 50 callers don't each fire a re-auth POST and trip the vault's rate limit.
- **Auth revoked mid-flight.** A backend that detects token revocation should raise `BackendAuthLostError` (a subclass of `BackendUnavailableError`), which signals the cache to drop affected entries rather than keep serving a revoked secret for up to TTL+jitter. Raising the plain `BackendUnavailableError` instead would be treated as a transient outage.

### Accepted residual risks

- **Schema validation only at startup.** A runtime-discovered constraint (e.g. "this field is required only if `auth.type == approle`") surfaces at startup, not at first `fetch()`. Standard pydantic idiom.
- **No backend hot-swap.** Config changes require a service restart.
- **No multi-backend.** Each instance serves from one vault. Multi-backend ("BWS for these, AWS for those") would need a backend-routing layer above the cache; deferred.

## FAQ

**Q: Why not entry-point plugin discovery?**
Explicit registration is auditable. A malicious pip package shouldn't be able to inject a backend that quietly handles `bws://` URIs and exfiltrates tokens. Registration in `BACKEND_REGISTRY` is a code change reviewable in PR.

**Q: Why not async?**
mitmproxy addons are sync. Wrapping a sync `backend.fetch` is trivial; wrapping an async SDK in a sync protocol is what the adapter does internally. A sync protocol matches the consumer.

**Q: Why does the protocol have only two exception types?**
Caller code handles exactly two states: "this secret is gone" (404-like, log-and-skip) and "the backend is hosed" (5xx-like, fail-closed). Finer distinctions (token-expired vs network-down vs vault-sealed) belong in the audit-log message, not in caller branching.

**Q: How do I write a contract test for my new backend?**
Subclass the protocol contract test, supply a `make_backend(...)` fixture returning a configured instance, and the suite runs the assertions every backend must pass: no I/O in init, idempotent fetch, error-type mapping, no secrets in repr.
