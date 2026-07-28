---
status: accepted
date: 2026-07-26
implemented: 2026-07-27
relates_to: ADR-0018 (GSM backend — the design this mirrors), ADR-0036 (AWS SigV4 signing — the signer this reuses for the read call, and the AWS-identity bootstrap question it shares), ADR-0024 (notes-host-allowlist — the confused-deputy defence), ADR-0025 (notes-binding marker)
references:
  - AWS Secrets Manager pricing, https://aws.amazon.com/secrets-manager/pricing/
  - SSM Parameter Store pricing, https://aws.amazon.com/systems-manager/pricing/
  - GetSecretValue / staging labels, https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
  - IAM Roles Anywhere, https://aws.amazon.com/iam/roles-anywhere/ ; credential helper, https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html
  - iam:SimulatePrincipalPolicy, https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html
  - Secrets Manager resource-tag character set, https://docs.aws.amazon.com/secretsmanager/latest/userguide/managing-secrets_tagging.html
  - External Secrets Operator AWS auth (prior art), https://external-secrets.io/latest/provider/aws-access/
---

# ADR-0038: AWS Secrets Manager / SSM Parameter Store backend

> **Status: ACCEPTED (2026-07-26), Slice 1 implemented (2026-07-27).** Radek greenlit the
> implementation with the §0 draft defaults. This is the "fetch secrets *from* AWS" axis —
> the D3 deferred in ADR-0036 — mirroring the GSM backend (ADR-0018), not the AWS *signing*
> axis (ADR-0027/0036). See **Implementation status** at the end for what shipped vs the
> follow-up slices.

## Context

AVP has three backends today (`bws`, `gsm`, `static`) — a "backend" is a source AVP fetches
secret *values* from at request time. GSM (ADR-0018) established the pattern for a cloud
secret store: keyless auth, a per-secret least-privilege grant, a startup self-check that
refuses to run under an over-broad identity, per-prefix scoping, and host-binding stored *in
the vault* on the secret itself. AWS is the obvious fourth backend — AWS-native teams keep
credentials in Secrets Manager or SSM, and `docs/adapter-architecture.md` already sketches an
`aws-secrets-manager` row.

Three forces, same shape as ADR-0018:

1. **Demand** — AWS Secrets Manager / SSM is where a large share of the target market already
   stores credentials; without this backend they must copy secrets into BWS/GSM to use AVP.
2. **Pattern is validated** — reading an existing cloud secret store as a broker source is
   exactly what External Secrets Operator, Infisical, and Vault's import source do (§ prior art).
3. **The hard requirement (security)** — AVP's identity must reach ONLY the secrets it brokers,
   hold NO long-lived key at rest, and never gain write/admin/enumerate on the vault.

**Two structural differences from GSM to design around:**

- **AWS has two candidate stores, not one.** Secrets Manager (rotation + staging labels,
  ~$0.40/secret/mo) vs SSM Parameter Store SecureString (no rotation, standard tier free).
- **AWS auth is signature-based.** "Keyless" means "no *static* key at rest," not "no signer."
  We already have a spec-correct SigV4 signer (ADR-0027/0036) — the read call reuses it.

### Verified current state (what already exists)

- **Backend seam is ready.** `backends/__init__.py` exposes a `SecretsBackend` Protocol
  (required `fetch`; optional-by-dispatch `fetch_with_meta` / `list_secret_names` /
  `list_secret_notes` / `update` / `diagnose`), a typed exception set
  (`SecretNotFoundError`, `BackendUnavailableError`, `BackendAuthLostError`, …), and a
  duplicate-rejecting registry. A new backend = one `backends/aws.py` + a `register_backend`
  call + an import line + a `_reset_registry_for_tests` entry.
- **Host-binding is already backend-agnostic.** `notes_binding.py` parses a host string
  (bare hostname or flat-YAML) gated on the `# avp-binding` marker (ADR-0025); the
  `binding_source: notes` path activates any backend that surfaces `fetch_with_meta` +
  `list_secret_notes`. `notes_host_allowlist` (ADR-0024) already guards the confused-deputy.
  So the AWS backend inherits host-binding *for free* by surfacing a routing string.
- **The SigV4 signer exists** (`injectors/sigv4.py`) and can sign a `GetSecretValue` POST.

## §0 Operator forks (the decisions to resolve)

| # | Fork | Draft default | Why |
|---|------|---------------|-----|
| **F1** | Which store(s)? SM only, SSM only, or both behind one interface? | **Both, one interface — SM primary, SSM SecureString opt-in** | Read shapes differ only in verb + envelope; auth/signing/binding/self-check are shared. SSM standard tier is free → cheap static keys; SM staging labels → rotation-aware reads. |
| **F2** | Keyless bootstrap for a NON-AWS host? | **IAM Roles Anywhere (X.509 → STS, TPM/PKCS#11-backed key) primary; `credential_process` seam; refuse permanent keys** | Fleet (mainframe/SecOps VPS/Martian) isn't AWS-hosted → no instance profile. Roles Anywhere leaves no static key at rest; the AWS analog of GSM `reject_ambient_key` = require the resolved creds to be session-token-bearing (temporary). |
| **F3** | Share the AWS identity with the sigv4 *signer* (ADR-0036 D2 chose a rotated vaulted key)? | **Unify — one AWS identity bootstrap for read + sign** | Two AWS identity stories is twice the ops surface. But ADR-0036 deferred Roles Anywhere ("no CA until real users") and picked a rotated vaulted key. F2/F3 must agree. |
| **F4** | Where does the host binding live on an AWS secret? | **Tag `avp-host` (authoritative, hostname-safe) + Description freeform `# avp-binding` marker (fallback)** | Tag values are restricted to alnum + space + `+ - = . _ : / @` — a hostname fits, arbitrary YAML does NOT. Description (SM 2048 / SSM 1024 chars) is freeform for the rich case. |
| **F5** | Dependency posture? | **`botocore` for credential *resolution only* + our SigV4 signer + stdlib `urllib` for the call** | Exact GSM split (`google-auth` mints, `urllib` calls). Hand-rolling STS/Roles-Anywhere refresh is the dangerous part — use the maintained lib there; keep the data-plane call minimal. Full `boto3` is rejected as bloat. |
| **F6** | self_check mechanism? | **`SimulatePrincipalPolicy` (advisory, catches wildcard grants) + live narrow-call 403/200 probe (authoritative gate); `self_check: deny` default, requires `secret_prefix`** | Simulation can't see resource/KMS policies for *roles* (our case), so the live scoped call is the real gate. Fail closed on any write/admin/enumerate capability. |

## Decision (draft — pending §0)

Ship `backend.type: aws-secrets-manager` in a new `backends/aws.py`, mirroring `gsm.py`.

**§1 Scope.** One backend, two drivers behind a `resolve(ref) -> (value, note)` seam: SM
(`GetSecretValue`) primary, SSM SecureString (`GetParameter WithDecryption`) opt-in via a
`store: secretsmanager | ssm` field. Read-only — no `update` method (no write-back to AWS).

**§2 Config schema** (`AwsConfig`, Pydantic 2, `extra="forbid"`, `hide_input_in_errors=True`):
`type`, `region` (validated — interpolated into the endpoint), `store` (default
`secretsmanager`), `secret_prefix` / `path_prefix`, `version_stage` (default `AWSCURRENT`),
`self_check: deny|warn|off` (default `deny`), `require_temporary_credentials: bool = True`
(the `reject_ambient_key` analog). **No static-key field** — no `aws_access_key_id` /
`aws_secret_access_key` in the schema; a test pins its absence. `_deny_requires_prefix`
model-validator: `deny` requires a prefix (a deny-guard with no namespace no-ops).

**§3 Value resolution.** One signed POST per cache miss. SM: `GetSecretValue` for
`version_stage` (always `AWSCURRENT` for a read-only broker — `AWSPENDING` is untested/may be
empty). SSM: `GetParameter` `WithDecryption=true`. Decode defensively; bad payload →
`BackendUnavailableError` carrying only the failure class, never secret bytes.

**§4 Host binding.** `fetch_with_meta` / `list_secret_notes` read the routing hint from the
`avp-host` **tag** first (queryable, ABAC-usable, character-safe for a hostname), falling back
to the `# avp-binding` marker in the **Description**. `list_secret_notes` reads tags from the
free `ListSecrets`/`DescribeSecret` (SM) or `DescribeParameters` (SSM) metadata pass — **no
value fetch at configure time** (GSM finding F5). The parsed string flows through the existing
`notes_binding.py` + `notes_host_allowlist` (ADR-0024) unchanged.

**§5 Auth (keyless).** Lazy-import the credential resolver only when the backend is built.
Primary: IAM Roles Anywhere via `credential_process` (X.509 key in TPM/PKCS#11/OS keystore).
`require_temporary_credentials`: at startup, refuse resolved credentials that are *permanent*
— reject if `AWS_ACCESS_KEY_ID` is present without `AWS_SESSION_TOKEN`, and reject a static-key
`~/.aws/credentials` profile with no `credential_process` / `sso` / role source. This is the
mirror of GSM refusing an ambient downloaded service-account key.

**§6 Least privilege + self_check.** Grant only resource-ARN-scoped
`secretsmanager:GetSecretValue` (`…:secret:PREFIX*-*`) + `kms:Decrypt` on the one CMK (SSM:
`ssm:GetParameter` on `…:parameter/PREFIX/*`). `avp aws-setup` emits exactly that policy and
**refuses an account-wide / `*` grant**. Boot self_check: `SimulatePrincipalPolicy` (advisory —
catches a wildcard identity grant) **plus** a live narrow-call 403/200 probe (authoritative,
reflects resource + KMS policy). Fail closed on any write/admin (`PutSecretValue`,
`UpdateSecret`, `DeleteSecret`, `secretsmanager:*`) or enumerate (`ListSecrets`) capability.
`_assert_in_scope` at the fetch boundary refuses any name outside the prefix (defence in depth).

**§7 Cost.** SM $0.40/secret/mo + $0.05/10k reads; SSM standard tier free storage, KMS
`Decrypt` billed. Cache the resolved `AWSCURRENT` value with TTL ≤ rotation interval, plus a
**refresh-on-403** fast path (a rejected credential downstream ⇒ likely rotated) — caching
routinely cuts `GetSecretValue` calls 90–99%.

**§8 Dependencies.** New `aws` optional extra: `botocore` (credential resolution only). The
data-plane call is stdlib `urllib` + `injectors/sigv4.py`. Rejected: full `boto3` (bloat);
hand-rolled STS/Roles-Anywhere refresh (security-critical, use the maintained lib).

**§9 CLIs.** `avp aws-setup` (per-secret least-privilege policy, refuses broad scope),
`avp doctor --probe-aws` (read-only `diagnose()` scope report), `avp setup --aws`
(keyless secure-by-default starter config).

## Consequences

**Good** — AWS-native teams broker their existing SM/SSM secrets without copying them into
BWS/GSM. Reuses the SigV4 signer, the backend seam, and the whole host-binding + allowlist
machinery. Same five-layer security posture as GSM (no key at rest, per-secret grant,
prefix-scoped, deny-if-broad boot, read-only).

**Bad / cost** — a fourth backend to maintain and audit; `botocore` (even creds-only) is a
non-trivial dependency in a security-sensitive daemon; the AWS identity bootstrap (Roles
Anywhere ⇒ a CA) is real ops the fleet doesn't have yet (F2/F3); two stores double the
driver-level test matrix.

**Out of scope** — dynamic AWS credential *generation* (Vault's AWS secrets engine — that's
minting, not brokering an existing secret); write-back to AWS; SSM Advanced-tier envelope
features; cross-account assume-role fan-out.

## Implementation status

**Slice 1 — AWS Secrets Manager backend (shipped 2026-07-27).**
`backends/aws.py`: `AwsConfig` (no static-key field; `region` SSRF-validated; `self_check:
deny` default requiring `secret_prefix`; `require_temporary_credentials` default on) +
`AwsSecretsManagerBackend` implementing the full protocol surface — `fetch` (SigV4-signed
`GetSecretValue`, reads `AWSCURRENT`), `fetch_with_meta`, `list_secret_names`,
`list_secret_notes` (tags/description from `ListSecrets` metadata, no value fetch), `diagnose`.
Auth is keyless via `botocore` credential *resolution only* (lazy import, `aws` extra); the
call itself is stdlib `urllib` signed by the ADR-0027/0036 signer, reusing its
`signed_headers_extra` path so `x-amz-target` is signed (AWS rejects an unsigned `x-amz-*`).
Host binding: `avp-binding` **tag** (bare host) with a `# avp-binding`-marked **Description**
fallback, surfaced through the existing `notes_binding` parser + `notes_host_allowlist`
(ADR-0024). Registered as `aws-secrets-manager`. **37 hermetic tests** (injected
credential-provider + transport — no botocore, no network); full suite green, ruff + mypy
clean. Test-injection + no-I/O-in-`__init__` mirror GSM exactly.

**Follow-up slices (not yet built):**
- **SSM Parameter Store driver** behind the same interface (fork F1) — `GetParameter
  WithDecryption`, `path_prefix`, parameter tags/description.
- **`iam:SimulatePrincipalPolicy` self_check for WRITE/admin breadth** (fork F6) — the
  remaining gap. Slice 1's boot guard now validates **enumeration AND read scope**: a
  `ListSecrets` breadth probe *plus* a `GetSecretValue` probe on a non-existent out-of-prefix
  name (ResourceNotFound instead of AccessDenied proves broad `GetSecretValue` → refuse).
  Write/admin breadth (`PutSecretValue` / `DeleteSecret` / `TagResource`) is NOT yet checked —
  `SimulatePrincipalPolicy` is the follow-up. self_check keys "cannot enumerate/read → scoped"
  on the AWS error *type* (`AccessDenied` is HTTP 400 on Secrets Manager, not 403), so the
  recommended least-priv identity boots correctly.

**Review (before landing):** a Claude-family adversarial audit + an Oracle (GPT-family, codex)
cross-model review were applied. Fixed: the 400-vs-403 self_check boot-blocker; per-call
temporary-credential re-validation (not just at boot); the read-scope probe above; rejecting
`version_stage: AWSPENDING`; capital-`Code` error-body tolerance; a prefix-without-delimiter
boot warning. Dismissed with reasons: the signer already signs `x-amz-security-token` +
`x-amz-content-sha256` (verified in `sigv4.py`); secret *names* in local operator logs are
GSM-parity and never enter the audit stream; metadata-cache staleness is handled by the
caching layer + ADR-0032 notes-refresh.
- **CLIs** `avp aws-setup` (per-secret least-priv policy, refuse broad scope),
  `avp doctor --probe-aws`, `avp setup --aws` (fork §9).
- **Docs**: `docs/aws-secrets-manager.md` dedicated guide; `avp-binding` tag/Description
  onboarding in the `avp` skill.
- **STS-scoped signing identity coherence** with ADR-0036 D2 (fork F3) — the read-identity
  and the sigv4 signer-identity should share one keyless bootstrap; unify when either grows a
  concrete AWS deployment.

## References

See front-matter. Prior art: External Secrets Operator (IRSA/AssumeRole, path scoping),
Infisical (cross-account AssumeRole), Vault AWS import source. Mirrors `docs/adrs/ADR-0018`.
