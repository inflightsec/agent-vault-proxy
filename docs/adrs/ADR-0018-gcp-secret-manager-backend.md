---
status: accepted
date: 2026-07-02
implemented: 2026-07-03
relates_to: docs/adapter-architecture.md (backend coverage matrix), docs/architecture.md (G1-G10), ADR-0011 (BWS-notes bindings)
---

# ADR-0018: Google Secret Manager backend (`backend.type: gsm`)

> **Status: accepted — implemented 2026-07-03** with the draft defaults for the §0 forks
> (see "Implementation status" below). Design sections retain their original future tense.

## Context

`docs/adapter-architecture.md` already names `gcp-secret-manager` (`config: project_id, version_alias`)
in the backend coverage matrix as a design target. This ADR turns that row into a shipped backend.

Three forces make it worth doing now rather than later:

1. **Cost.** Google Secret Manager (GSM) bills `$0.06` per active secret version per month and `$0.03`
   per 10,000 `AccessSecretVersion` operations, with a monthly free tier of 6 versions + 10k accesses
   per billing account. Because AVP's `CachingSecretsClient` already collapses reads to ~1 per secret
   per TTL per instance, access-operation cost is effectively zero and the bill is dominated by *active
   version count*. For a 50-engineer org this lands at **~$8-10/month if secrets are shared org-wide**
   and **~$60/month (~$1.20/engineer) if every engineer holds their own set** — cheap enough that GSM is
   a credible *replacement* for the BWS backend, not merely an addition.

2. **The pattern is now vendor-validated, and the GSM slice is unserved.** "Never let the agent hold the
   raw secret; inject it at an egress proxy bound to an allow-listed destination" is documented as the
   reference pattern by Anthropic (Claude Code "proxy pattern"), SANS, Infisical, TRM Labs, and NIST
   NCCoE. The competitive field is real — CyberArk Secretless Broker is the architectural twin;
   **Infisical's "Agent Vault"** (MIT, ~1.8k★) is a near-identical HTTP credential proxy and a naming
   collision worth noting — but **none of them read from Google Secret Manager**. GSM shows up in that
   ecosystem only as a one-way *sync target* (Doppler/Infisical push *to* GSM), or via Vault's GCP
   *secrets engine* (which mints GCP creds, not reads arbitrary secrets). A request-injecting proxy that
   reads natively from GSM is an open quadrant.

3. **A hard security requirement from the operator: the backend's identity must reach ONLY its own
   secrets — nothing else in Secret Manager, nothing else in the GCP project.** The failure mode this
   design exists to prevent is the sloppy install: an engineer pastes a broad admin credential (or a
   downloadable service-account key with project-wide `secretAccessor`) and AVP silently becomes a
   read-any-secret oracle. **Secure-by-default is a schema-and-boot invariant here, not a doc note.**

**Verified current state (2026-07-02):**

- `backends/__init__.py` defines the `SecretsBackend` Protocol (`fetch` required; `fetch_with_meta` /
  `list_secret_names` / `update` optional-by-dispatch) plus `register_backend()` with NFKC-casefold
  dedup. Adding a backend is one new file + one `register_backend()` call + one import line.
- `bws_notes.parse_notes_binding` is **backend-agnostic**: it turns a flat-YAML "note" string into
  `NoBinding` / `InvalidBinding` / `ParsedBinding`, fails closed on missing `host`, and validates
  through the same `SecretSpec` the file path uses. Any backend that can surface a per-secret metadata
  string inherits host-binding for free.
- `binding_source` (ADR-0011) is `Literal["file","bws_notes","both"]` and — per an open bug on the
  a production deployment — the `both`/notes activation path (`_activate_bws_notes`) currently *replaces* rather than
  *unions* the file map, silently dropping file-only bindings. That path is also BWS-named. Both are
  addressed in §4.
- Outbound HTTP deps today: `h11`, `h2`, `tornado`, `certifi`, `cryptography`. No `httpx`/`requests`,
  and no `google-*` libraries.

## 0. Operator forks (resolve before `accepted`)

| # | Fork | Options | Draft default |
|---|------|---------|---------------|
| F1 | **BWS relationship** | peer backend / full replacement / per-engineer choice | **Peer backend** (non-destructive; multi-backend is a separate, later concern) |
| F2 | **Per-engineer isolation** | project-per-engineer / shared project + name-prefix + IAM condition | **Shared project + `avp-<owner>-` prefix + per-secret IAM condition** |
| F3 | **Where the host binding lives** | file (`bindings.yaml`) first / annotation-notes first | **Annotation-notes** — one `avp-binding` annotation per secret (bare host, or flat-YAML for extras); `binding_source: gsm_notes` makes "every secret is host-bound at the vault" a hard invariant (see §4) |
| F4 | **Over-broad-identity boot check** | hard refuse-to-start / warn-only | **Hard refuse-to-start** (`self_check: deny`) |

## Decision

Land `backend.type: gsm` as the third built-in backend (after `bws`, `static`), in two phases.
**Phase 1** ships value resolution + file bindings + the keyless-auth + least-privilege security model.
**Phase 2** ships annotation-carried host binding (`binding_source: gsm_notes`) once the notes-activation
path is generalised.

### 1. Scope

- **Phase 1**: `GsmBackend.fetch` + `list_secret_names`; `GsmConfig`; keyless ADC/impersonation/WIF auth
  with **no key-file field**; boot-time deny-if-broad self-check; `avp doctor --probe-gcp`; file-mode
  host bindings via existing `bindings.yaml`.
- **Phase 2**: `GsmBackend.fetch_with_meta` reading the `avp-binding` secret annotation; generalise
  `_activate_bws_notes` → `_activate_notes_bindings(backend)` for any notes-aware backend; add
  `binding_source: gsm_notes`; **fix the replace-not-union bug** while in that code.
- **Deferred** (each its own ADR): `update()` write-back for GSM (only needed if OAuth2 refresh-token
  rotation is proxied against a GSM-held refresh token — §8); CMEK-encrypted secrets; user-managed
  multi-region replication; regional (non-`latest`) version pinning UX beyond the config field.

### 2. Config schema (Pydantic 2)

```python
class GsmConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    type: Literal["gsm"] = "gsm"

    project_id: str                              # project NUMBER preferred (IAM-condition parity, §6)
    version_alias: str = "latest"                # or a pinned integer version
    secret_prefix: str | None = None             # namespace: only secrets under this prefix are in scope

    # --- Auth: KEYLESS BY DESIGN. There is deliberately NO service_account_key_path field. ---
    impersonate_service_account: str | None = None   # ADC user creds impersonate this low-priv SA
    credential_config_path: str | None = None        # WIF *no-secret* cred-config JSON (NOT a key file)

    # --- Secure-by-default guardrails ---
    # deny REQUIRES secret_prefix (model_validator) so the guard has a namespace
    # to bound — a prefix-less deny would silently no-op. Org SA-key policy is
    # asserted by `avp doctor` / the installer, not this runtime identity.
    self_check: Literal["deny", "warn", "off"] = "deny"   # boot deny-if-broad probe (§6)
    reject_ambient_key: bool = True                       # refuse if ADC resolves to a downloaded SA key
```

`extra="forbid"` + `hide_input_in_errors` match every AVP config class. The two design-load-bearing
choices: (a) **no key-path field exists**, so an operator *cannot* wire a downloadable key through
config; (b) `reject_ambient_key` catches the back door — a `GOOGLE_APPLICATION_CREDENTIALS` pointing at
a `*.json` service-account key is detected and refused (the credential type is inspectable before any
network call).

### 3. Value resolution

One REST call per cache miss:

```
GET https://secretmanager.googleapis.com/v1/projects/{project_id}/secrets/{name}/versions/{version_alias}:access
Authorization: Bearer <ADC access token>
```

`name` is templated into the resource path (with `secret_prefix` prepended when set); the response
`payload.data` is base64-decoded and returned as `str` (UTF-8; a decode error → `BackendUnavailableError`
with no bytes logged). Error mapping: `404` → `SecretNotFoundError`; `403` → `BackendAuthLostError`
(subclass of `BackendUnavailableError`, so the cache drops the entry rather than serving a revoked
value); `429`/`5xx`/timeout → `BackendUnavailableError` (one retry on 5xx, none on 4xx). No I/O in
`__init__`; first token mint + first `access` happen on first `fetch()`. `repr()` excludes the config.

### 4. Host binding — carried IN the secret: annotation, not label (Phase 2)

**Why not a label.** GSM *labels* are constrained to `[a-z0-9_-]` (lowercase, ≤63 chars, no dots, no
slashes) — they literally cannot hold `api.openai.com` (dots) or `/v1/**` (slashes). Labels are a filter
key, not a config carrier. **Annotations** are the right home: a `map<string,string>` of client metadata,
16 KiB total, arbitrary values, documented by Google as "custom metadata for client tools to store their
own state without requiring a database." Read via the *free* `GetSecret`/`ListSecrets` metadata calls,
never a billed `access` op.

One annotation key — **`avp-binding`** — carries the whole binding, and its value scales from trivial to
full so the common case is one field and the rare case is still one key:

- **Tier 0 — the North Star (just the hostname).** The value is a bare host string:
  `avp-binding: api.openai.com` → parsed as `{host: api.openai.com}`. Everything else is defaulted
  in-program — the per-host exception table supplies tight `methods`/`paths` for known providers, and
  `Authorization: Bearer {SECRET}` is the fallback. Add the secret, tag it with the host, done.
- **Tier 1 — a few extra params.** The value is the same flat-YAML grammar BWS notes use — `host`
  (required) plus optional `header`, `format`, `methods`, `paths`:
  ```
  avp-binding: |
    host: api.internal.acme.com
    methods: [POST]
    paths: [/v1/ingest]
  ```
- **Precedence** per field: `avp-binding` value > per-host exception-table default > bare-Bearer default.

`GsmBackend.fetch_with_meta(name)` returns `(value, annotations.get("avp-binding"))`; that string flows
into `bws_notes.parse_notes_binding` with **one small extension** — a bare non-empty scalar is wrapped as
`{host: <scalar>}` before the existing shape/key/`SecretSpec` pipeline. Same
`NoBinding`/`InvalidBinding`/`ParsedBinding` outcomes, same exception table, same fail-closed-on-missing-
host. Both backends now speak one binding grammar. `list_secret_names` (via `ListSecrets`, filtered to
`secret_prefix`) caches the annotation map in the same pass, so the placeholder-map build is one list
call, not one-get-per-secret.

**gcloud ergonomics (usability matters here).** gcloud treats commas as the annotation *separator*, so
list-valued YAML must be **block style (newlines), never inline `[a, b]`**:
```
printf '%s' "$KEY" | gcloud secrets create OPENAI_API_KEY \
  --annotations="avp-binding=api.openai.com" --data-file=-          # Tier 0
gcloud secrets update OPENAI_API_KEY \
  --update-annotations="avp-binding=api.openai.com"                 # adjust later
```

**Secure default vs usability.** An unknown host (a typical internal name) with no `methods`/`paths`
defaults to all-methods/all-paths — deliberately usable for a trusted internal endpoint, per the
North-Star intent. A new `preflight` advisory `binding_unscoped` flags any binding left unscoped against a
*public* host, so an over-broad public binding is visible without blocking the trusted-internal case.

**Forward-compat.** Unknown keys fail closed today (`extra=forbid`). Future capabilities (body / composite
/ oauth-shaped bindings) extend the grammar behind an optional reserved `v:` marker in a later ADR; the
annotation key `avp-binding` stays stable.

Running `binding_source: gsm_notes` makes the invariant hard: a secret with no `avp-binding` annotation
parses to `NoBinding` → **never injected**. There is no way to store an in-scope secret that isn't bound
to a host.

Running `binding_source: gsm_notes` makes the operator's hard requirement structural: a secret with no
`avp-binding` annotation parses to `NoBinding` → **never injected**. There is no way to store a secret in
scope that isn't bound to a host.

Two required fixes in the shared activation path, done here because Phase 2 lives in that code:

- **Generalise** `_activate_bws_notes()` → `_activate_notes_bindings(backend)` keyed on
  `fetch_with_meta`/`list_secret_names` support, not on "is BWS".
- **Fix the union bug**: notes bindings must *union* with (and override, per-name) file bindings, never
  *replace* the map. This is the observed silent-drop bug; ship the fix with a regression test that
  asserts a file-only binding survives `configure_from_path()` under `both`.

### 5. Auth model — keyless, three ordered options

No service-account key files. In preference order:

1. **ADC + impersonation** (best for engineer laptops): `gcloud auth application-default login
   --impersonate-service-account=avp-ro@PROJECT.iam.gserviceaccount.com`. The human's SSO identity mints
   short-lived tokens for a low-priv SA; nothing sensitive on disk. Requires
   `roles/iam.serviceAccountTokenCreator` on that SA.
2. **Workload Identity Federation** (best for CI / non-Google hosts): a no-secret cred-config JSON
   (`credential_config_path`) exchanges an external OIDC token for a 1-hour GCP token via STS. Provider
   constrained by attribute conditions (lock to subject/repo/tenant).
3. **Plain user ADC** for pure local dev where the human's own IAM is already least-privilege.

Token minting uses **`google-auth`** (§10). Endpoints are fixed and pinned
(`secretmanager.googleapis.com`, `sts.googleapis.com`, `iamcredentials.googleapis.com`) — there is no
operator-controlled URL, so the SSRF surface of ADR-0017 does not recur here.

### 6. Least privilege — secure by default (the core of this ADR)

Five layers, defence-in-depth, so a single sloppy step still fails safe:

1. **Schema can't express a key** (§2): no key-path field; `reject_ambient_key` refuses a downloaded key
   surfaced via ADC env.
2. **Grant only per-secret `secretAccessor`.** The bundled `avp gcp-setup` helper runs
   `gcloud secrets add-iam-policy-binding <secret> --member=<sa> --role=roles/secretmanager.secretAccessor`
   per secret and **hard-fails if asked to bind at project/folder/org level**. `secretAccessor` grants
   exactly `secretmanager.versions.access` — no list, no other secret, no other API.
3. **Name-prefix IAM condition** as a belt to the per-secret braces: any accessor binding carries
   `resource.name.startsWith("projects/<NUMBER>/secrets/avp-<owner>-")`, so even a mistaken broader grant
   is narrowed to the owner's namespace. (Project *number*, not ID, per GCP condition semantics.)
4. **Boot-time deny-if-broad self-check** (`self_check: deny`, default). At startup the daemon calls
   `secretmanager…:testIamPermissions` for `secretmanager.secrets.list` and `…versions.access` against a
   resource **outside** its allow-list (the project, or a canary out-of-prefix name). If the permission
   comes back *present*, the identity is broader than intended → **exit non-zero, refuse to start.** This
   direction is safe precisely because `testIamPermissions` may fail *open*: a false-positive over-reports
   permission → over-cautious refusal. (Never invert this into a "proceed only if I *can* read X" gate —
   that direction is unsafe.)
5. **Org-policy assertion** (`assert_org_key_policy`, default on): check that
   `iam.disableServiceAccountKeyCreation` (+ `…KeyUpload`) are enforced; warn loudly (or deny on prod).
   Orgs created on/after 2024-05-03 enforce these by default.

`avp doctor --probe-gcp` runs 1/3/4/5 read-only and prints what the identity can and cannot reach, with
remediation hints — the human-readable form of the boot check, safe against production secrets.

### 7. Cost model (50 engineers)

| Driver | Price | Free/mo | AVP effect |
|--------|-------|---------|-----------|
| Active secret version | $0.06 / ver / mo (automatic replication = 1 location) | 6 | none — set by secret *design* |
| `AccessSecretVersion` | $0.03 / 10k | 10k | cache collapses to ~1/secret/TTL/instance → ~free |
| Metadata get/list (incl. annotations), create/enable/disable | $0 | — | binding reads are free |
| Rotation notification | $0.05 | 3 | optional → skip |

| Model | Active versions | Est. monthly | /engineer |
|-------|-----------------|--------------|-----------|
| Shared org secrets (~40 shared + ~2 personal each) | ~140 | **~$8-10** | ~$0.18 |
| Per-engineer, 20 each, rotate + destroy old | ~1,000 | **~$60-67** | ~$1.20 |
| Per-engineer + version accumulation (anti-pattern) | ~10,000 | ~$600 ⚠️ | avoid |

Frugal levers, ranked: (1) share secrets org-wide; (2) **destroy superseded versions on rotate** (the one
real trap — a rotating CI secret once reached 84 billable versions); (3) automatic replication, not
user-managed multi-region (1× vs 3×); (4) lean on the cache, optionally raise TTL 300s→3600s; (5) skip
rotation notifications + CMEK.

### 8. Audit + write-back

Reuse `inject_decision` / `deny` unchanged. Backend errors surface through the existing audit path
(backend type + operation + outcome, no secret material). `update()` (refresh-token write-back, ADR-0017
§8) is **not** implemented for GSM in this ADR — a GSM binding used as an `oauth2_refresh`
`refresh_token_secret` against a rotating provider would audit `write_back_unavailable`; add
`GsmBackend.update` (via `AddSecretVersion` + disable-old) in a follow-up if that combination is needed.

### 9. Dependencies

One new runtime dependency: **`google-auth`** (first-party, for ADC / impersonation / WIF token minting +
refresh). REST calls use stdlib `urllib.request` + `ssl.create_default_context()`, mirroring ADR-0017's
"no heavy transport dep" posture. We **do not** take `google-cloud-secret-manager` (the gRPC SDK pulls
`grpcio` + `protobuf` + a large transitive tree); a fixed REST endpoint plus `google-auth` is the smaller,
more auditable supply-chain surface — consistent with the Doppler adapter's HTTP-only precedent and with
the repo's OSV/Semgrep/TruffleHog gate.

## Beyond the baseline

Three things that put AVP's GSM backend ahead of the crowded credential-broker field (Infisical Agent
Vault, Secretless Broker, Arcade, Aembit), none of which read from GSM:

- **Least-privilege enforced, not documented.** The schema can't express a key; the daemon refuses to
  start under a broad identity. The competitors' "one vault of keys" model is exactly the concentration
  risk this inverts.
- **Host binding lives at the vault** (`gsm_notes`): the secret is self-describing and can't exist
  in-scope without a destination host. Stronger than a generic env/proxy injector.
- **Frugal by construction**: ~$0.06/secret/month, reads free behind the cache — a credible BWS
  replacement at org scale, not just another backend.

## Consequences

### Good

- Fills the unserved "GSM-as-read-backend for an injecting proxy" quadrant; opens a ~$1/engineer/month
  path to replace BWS.
- Host binding is zero-new-code (reuses `parse_notes_binding`); the backend seam is one file + one
  registration.
- Secure-by-default is structural: no key-path field, deny-if-broad boot check, per-secret IAM only.
- Fixes the ADR-0011 `both`-replace-not-union bug as a side effect of generalising the notes path.
- One new dep, first-party, REST not gRPC.

### Bad

- **`google-auth`** is a new runtime dependency (pulls `rsa`, `pyasn1`, `cachetools`). Held to the OSV
  gate; pinned in the lockfile.
- **Trust-the-proxy model unchanged.** Proxy compromise = every in-scope secret readable; hostname
  allow-listing is bypassable by domain-fronting unless TLS-terminated. State it in the operator README.
- Two-phase ship means Phase 1 relies on `bindings.yaml` for host binding; the vault-enforced invariant
  only lands in Phase 2.
- IAM propagation lag (~2-7 min) means `avp gcp-setup` grants may not be live at the immediately-following
  first fetch; `avp doctor --probe-gcp` accounts for this with a retry hint.
- Name collision with Infisical "Agent Vault" is a positioning problem for any public release (out of
  scope for this ADR, flagged for the roadmap).

### Out of scope (each its own future ADR)

- `GsmBackend.update` write-back (OAuth2-refresh-against-GSM).
- CMEK-encrypted secrets and user-managed multi-region replication.
- A backend-routing layer for true multi-backend (BWS for some names, GSM for others) — today one
  instance serves one backend.
- Project-per-engineer automation (Terraform module) if F2 chooses hard isolation.

## Implementation status (2026-07-03)

Shipped and green — 830 tests pass, mypy + ruff clean (uncommitted; `google-auth` added to a `gsm`
extra, so `scripts/regen-lockfiles.sh` must run before commit): `backends/gsm.py` (`fetch` /
`list_secret_names` / `fetch_with_meta` / `list_secret_notes`, keyless auth, self_check), the
bare-hostname note shorthand, and `gsm_notes` as a first-class `binding_source`. **Follow-ups since
shipped** (see "Follow-ups shipped" below): `avp gcp-setup`, `avp doctor --probe-gcp`, the docs
(README / adapter-architecture / bindings.example / quickstart / usage), the notes-layer refactor, and the
project-level access probe. Still deferred: the `preflight binding_unscoped` advisory.

The "fix the union bug" item in §1/§4 was found **unnecessary**: `handlers.py` already unions file+notes
correctly in `both` mode. Locked with regression coverage instead.

### Cross-vendor audit (Cato / GPT-5.4) — findings resolved

| # | Finding | Resolution |
|---|---------|-----------|
| F1 (HIGH) | A `*.suffix` host arriving via a notes/annotation **bypassed** `allow_wildcard_hosts` — the Config validator runs at load, before notes merge (affects BWS notes too). | The activator re-enforces the wildcard opt-in over merged notes specs; a wildcard with the opt-in off is dropped and attributed `invalid_binding_metadata` (fail closed). §4 |
| F2 | `self_check` treated ANY list error incl. transient 5xx as "scoped → pass" (fail **open**). | Distinguish 401/403 (denied → scoped → pass) from transient (deny → refuse to start; warn → continue). Documented as ENUMERATION-scoped. |
| F3 | `self_check: deny` silently no-opped when `secret_prefix` was unset (the default). | `deny` now REQUIRES `secret_prefix` (config validator). Minimal secure config = `project_id` + `secret_prefix`. |
| F4 | `assert_org_key_policy` was a declared-but-unenforced no-op (false assurance). | Field removed. Org SA-key policy belongs to `avp doctor` / the installer. |
| F5 | Notes activation fetched every secret VALUE just to read its annotation (cost + all plaintext transits memory on reload + one disabled version bricked reload). | New `list_secret_notes` dispatch: GSM reads annotations from the free ListSecrets pass, no value fetch at configure; bws/static fall back unchanged. |

**Residual:** self_check now runs BOTH an enumeration check AND a project-level `testIamPermissions`
access probe (catches a project-wide `versions.access` grant even when list is denied) — so the
enumeration-vs-access gap is closed for the common broad-grant case. A per-secret grant on a *foreign*
secret still evades detection and stays an IAM-least-privilege duty. `reject_ambient_key` keys off
`isinstance(creds, service_account.Credentials)` and fails safe (returns False) only on `ImportError`.

### Second cross-vendor pass (Oracle / codex) — findings resolved

An independent second review (different provider) after the Cato fixes raised 9 concerns; the actionable ones are fixed and tested:

| # | Finding | Resolution |
|---|---------|-----------|
| C4 (HIGH) | Token acquisition (`_token_provider()`) ran OUTSIDE the try in `_request` — a google-auth refresh/impersonation error escaped raw, bypassing the fail-closed handling the addon/cache rely on. | Wrapped: any non-protocol exception → `BackendUnavailableError`. |
| C2 | self_check treated any `BackendAuthLostError` (401 OR 403) as "enumeration denied → scoped → pass"; a 401 is broken auth, not proof of scope. | `_request` tags the error with `http_status`; self_check passes only on 403, treats 401 as inconclusive (deny → refuse). |
| C5 | Provenance `source_label` came from the `binding_source` string, so `both` mode mislabeled GSM annotations `bws_notes`. | Derived from the backend TYPE (`NOTES_SOURCE_LABEL` class attr) — honest in every mode. |
| C6 | `base64.b64decode` without `validate=True` silently dropped non-alphabet bytes. | `validate=True` — a mangled payload is rejected, not accepted. |
| C7 | First-use init (provider build + self_check) was unsynchronized; concurrent first requests could double-run it. | `threading.Lock` + double-checked `_ready`. |
| C8 | `project_id` was interpolated raw into every authenticated URL. | `field_validator` restricts it to a GCP project ID / numeric number (no slash/query/fragment/whitespace). |
| C9 | Configless construction (token_provider only) crashed with `AssertionError` at first use. | `_ensure_ready` requires config, raises a protocol-shaped error. |

C3 (keyless "configurable away") is handled by default — `reject_ambient_key` (default on) catches a
service-account key loaded via EITHER `credential_config_path` or ADC; `false` is an explicit opt-out. C1
restates the enumeration-vs-access residual above.

### Third pass (Oracle codex + Grok, incl. the local-e2e harness) — resolved

Two more independent models reviewed the post-fix backend + the new `tests/local-e2e/` harness. Both
confirmed gsm.py is leak-clean and injection-safe; the incremental hardening:

- **Access-boundary prefix enforcement** — `_assert_in_scope` refuses to *fetch* any name outside
  `secret_prefix`, so a stray broad IAM grant still can't pull an out-of-namespace secret through the
  backend (belt to the self_check braces).
- **Malformed-response guards** — annotation / secret-list entries that aren't dicts are skipped, not
  raised as raw `AttributeError`.
- **self_check 404** — a ListSecrets 404 (wrong `project_id`) fails closed with a clear message.
- **Honest wording** — the docstring now states self_check bounds *enumeration* breadth, not
  `versions.access` breadth; a per-secret grant on a foreign secret is not detected, and the
  `testIamPermissions` access-probe remains the tracked follow-up.
- **Harness security** (test infra): the pytest wrapper owns the temp dir (removed on every path
  including a timeout SIGKILL) and reaps the proxy via a process-group kill; secrets are redacted from any
  failure output; the leak-scan covers the rendered composite credential; render is delimiter-safe.
  Accepted-LOW residuals: annotation cache is lock-free (CPython/GIL-safe), self_check has no list
  page-cap, port-pick is TOCTOU.

### Fourth pass (Oracle codex) — resolved

- **Annotation-write is a binding-control primitive (confused-deputy).** On GCP,
  `secretmanager.secrets.update` (edit annotations) and `secretmanager.versions.access`
  (read the value) are *independently grantable* permissions. Under `binding_source:
  notes`/`both`, a principal who can edit the `avp-binding` annotation but **cannot read
  the secret** can point it at a host they control; AVP then reads the value with its own
  identity and injects it there — exfiltrating a secret the attacker could never read
  directly. `_assert_in_scope` does not mitigate this (it bounds the secret *name*, not the
  destination host). **Decision:** the annotation channel is a **trust boundary** — whoever
  can write `avp-binding` must be as trusted as whoever can read the secret. Operators MUST
  restrict `secretmanager.secrets.update` to the value-read trust tier; `avp doctor
  --probe-gcp` now emits an `annotation-trust` WARN whenever annotations are load-bearing.
  A structural file-side host allowlist (annotations may only *narrow* scope, never add a
  host) is the stronger fix, tracked as a follow-up for split-IAM / multi-tenant deployments.
  (Not exploitable on BWS, which does not separate note-write from value-read; moot in a
  single-operator project where one identity holds both perms.)
- **Read-only enforcement (`self_check` write/admin guard).** AVP is a read-only broker, so
  it must not hold `secretmanager.secrets.update` / `versions.add` / `secrets.delete`. The
  boot self-check now runs a third `testIamPermissions` probe for these and refuses to start
  (`deny`) / warns when the identity holds any — bounding a *compromised proxy's* ability to
  tamper with the vault or rewrite the routing annotations. Same best-effort posture as the
  access probe: an inconclusive probe (API disabled / denied / transient) never hard-blocks.
  Defence-in-depth; it does **not** close the confused-deputy above (that abuses AVP's
  *legitimate read* access, not any write grant).

### Notes-layer generalization (de-BWS-ify refactor)

The notes-binding layer is backend-agnostic (it serves BWS `notes` AND GSM
`avp-binding` annotations), so its BWS naming was retired: module `bws_notes.py`
→ `notes_binding.py` (with a back-compat re-export shim), classes
`BwsNotesSource` / `BwsNotesActivator` → `NotesSource` / `NotesActivator`, and the
`binding_source` enum collapses `bws_notes` / `gsm_notes` into one generic
`notes` value. The legacy values are accepted as **deprecated aliases** at
config-load (normalized to `notes` with a `DeprecationWarning`), so existing
`bindings.yaml` keeps working unchanged. Per-spec audit **provenance stays
backend-typed** via `NOTES_SOURCE_LABEL` (`bws_notes` / `gsm_notes`) — the config
*mode* generalized; the audit label did not.

### Follow-ups shipped (docs · refactor · security feature)

- **Docs.** GSM is now documented end-to-end: the README backend line, the `docs/adapter-architecture.md`
  coverage matrix (flipped `gcp-secret-manager` → the shipped `gsm` row with full config + an `avp-binding`
  annotation guide), a commented `gsm` block in `bindings.example.yaml`, and `quickstart.md` / `usage.md`.
- **Refactor.** The notes-binding layer was de-BWS-ified (see above); `binding_source` collapses to a
  generic `notes` with `bws_notes` / `gsm_notes` accepted as deprecated aliases.
- **Security feature.** `self_check` gained a project-level `testIamPermissions` access probe (closes the
  enumeration-vs-access gap for project-wide grants). New operator CLIs: `avp gcp-setup` (grants per-secret
  `secretAccessor`, **refuses** project/folder/org binds) and `avp doctor --probe-gcp` (read-only identity
  scope report via `GsmBackend.diagnose()`).

## References

- `docs/adapter-architecture.md` — backend coverage matrix (`gcp-secret-manager` row), author's guide.
- ADR-0011 — BWS-notes bindings; `binding_source`; the notes parser this backend reuses.
- ADR-0017 — no-heavy-transport-dep + SSRF posture this backend follows.
- GSM pricing: https://cloud.google.com/secret-manager/pricing · quotas (annotations 16 KiB): https://cloud.google.com/secret-manager/quotas
- Per-secret IAM + conditions: https://docs.cloud.google.com/secret-manager/docs/manage-access-to-secrets · https://docs.cloud.google.com/secret-manager/docs/access-control
- Keyless auth: https://docs.cloud.google.com/docs/authentication/use-service-account-impersonation · https://docs.cloud.google.com/iam/docs/workload-identity-federation
- `testIamPermissions` (self-check): https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/testIamPermissions
- Org policy (kill SA keys): https://docs.cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts
- Pattern validation: Anthropic proxy pattern https://code.claude.com/docs/en/agent-sdk/secure-deployment · MCP leaves server→downstream creds out of scope https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- Closest prior art: CyberArk Secretless Broker https://github.com/cyberark/secretless-broker · Infisical Agent Vault https://github.com/Infisical/agent-vault
