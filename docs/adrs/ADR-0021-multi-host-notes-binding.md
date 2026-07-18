---
status: accepted
date: 2026-07-11
implemented: 2026-07-13
security_review: "Cato (cross-vendor) + Silas (red-team) + Oracle (cross-model) 2026-07-11 — v1 FAIL (C1 critical); v3 below folds all findings"
relates_to: ADR-0011-bws-notes-bindings, ADR-0017-oauth2-refresh-injector, ADR-0018-gcp-secret-manager-backend, ADR-0020-service-templates-zero-config-onboarding
---

# ADR-0021: Notes bindings reach `secrets:` parity — bounded by a note trust profile

> **Implemented in v0.8.0.** Multi-host `host:` lists (and the `hosts:` alias) land in
> `notes_binding.py`; behaviour pinned by `tests/test_bws_notes_multihost.py`.

## Context

A notes/annotation binding (ADR-0011 BWS notes, ADR-0018 GSM `avp-binding`) is today a
**flat, curated subset** of the file schema (`_ALLOWED_NOTE_KEYS = {host, header, format,
methods, paths}`, `host` a single string). The file `secrets:` schema is the full nested
`SecretSpec`: `inject:` (header / body / multi / oauth2_refresh), `bindings:` (a list),
`compose:`, `honeytoken:`.

**Operator principle (Radek, 2026-07-11):** a note should offer *as much flexibility as the file
config — ideally the same schema* — so an operator never learns two dialects; the `host`-only form
stays as a simplified option on top. The trigger is HuggingFace (one token, three hosts).

**The load-bearing correction (adversarial review, 2026-07-11).** A first draft granted notes the
*full* `SecretSpec* shape and reused the file validators as the safety net. A cross-vendor audit
(Cato) and an offensive red-team (Silas) independently found this **re-opens the confused-deputy
holes the broker exists to prevent** (see the Security Review section). The root cause is a single
sentence worth internalizing:

> **The file validators are not a trust boundary. They were written assuming `bindings.yaml` is
> operator-authored and fully trusted.** A vault note / GSM annotation is *partially trusted* —
> writable by anyone with vault-note access or a supply-chained tool. Granting a note the file's
> full expressive power hands a low-trust author the file's full authority.

**Stated assumption (verify before implementation — Oracle C10):** the note trust profile presumes a
real privilege split in the backend — that an actor can hold note/annotation write **without**
equivalent authority over the secret *value* or the trusted `bindings.yaml`. Confirm this holds for
BWS (secret-note write vs value write) and GSM (annotation write vs version-add) IAM. If note-write
implies value-write on a given backend, the profile is defence-in-depth there, not a hard boundary;
the supply-chained-tool threat (a compromised tool that can plant a note) still justifies it either
way.

So this ADR keeps parity of **schema** (one dialect: a note is written like a `secrets:` entry) but
**bounds the capability** a note may yield behind an explicit **note trust profile**, enforced in
code at the notes→config merge point — never asserted in prose and left to the file validators to
not-enforce.

Structural facts (verified against v0.7.0):

1. `SecretSpec.bindings` is already `list[BindingSpec]`; the host index iterates all bindings and
   `secrets_for_host` dedups by name — N hosts per secret is native.
2. A note is parsed straight into a `SecretSpec` (`parse_notes_binding` → `SecretSpec.model_validate`).
3. In notes mode the placeholder is **daemon-derived** (`derive_placeholder_map(names, install_salt)`),
   uniqueness/marker-validated by `validate_placeholder_invariants`, and surfaced via
   `placeholder_to_name`. That is why `placeholder` is absent from `_ALLOWED_NOTE_KEYS`.
4. The notes→config merge (`handlers.py` `NotesActivator.activate`) is where notes specs enter the
   live config. It today re-enforces only two guards post-merge: the wildcard opt-in (drops a spec
   whose `spec.bindings` include a `*.suffix` host when `allow_wildcard_hosts:false`) and
   `validate_placeholder_invariants` over the merged set. It does **not** re-run the full `Config`
   validator suite, and it drops a file spec when a same-named note is invalid.

## Decision

### 1. The note *schema* is the file `secrets:` schema, with simplified shorthands

Same keys, nesting, validators as `bindings.yaml`, at three tiers: **T0** bare hostname string;
**T1** flat `{host,header,format,methods,paths}` (exception-table defaults + `{secret}` rewrite);
**T2** the nested shape (`inject:`, `bindings:` list, …). `host: str | list[str]` and a `hosts:`
alias are added to the **shared `BindingSpec`** so file and note stay identical. `_ALLOWED_NOTE_KEYS`
expands to the `SecretSpec` field set minus `placeholder` (§3), **filtered by the note trust profile
(§2)**. Unknown keys still fail closed.

### 2. The note trust profile — the load-bearing security boundary (NEW, enforced at the merge)

Notes-sourced specs are validated against a **low-trust profile at `NotesActivator.activate`**, in
the same place the wildcard opt-in already runs. Each rule is **fail-closed: drop the offending spec
and attribute its placeholder `invalid_binding_metadata`** (never a silent widen, never a daemon
abort). Schema parity is preserved — a note may *use* these keys — but the profile rejects the
capabilities a partially-trusted author must not wield:

- **(P1) No cross-secret reach — capability-gated, deny-by-default (not a type-name denylist).** A
  note may inject only *its own* secret value. Reject any notes-sourced spec whose injector, by
  *capability*, (i) references another vault secret name (`oauth2_refresh`'s
  `client_id_secret`/`client_secret_secret`/`refresh_token_secret` — `oauth2_refresh.py:407-409`;
  `compose:`; `inject.template`), (ii) performs an outbound network exchange (`oauth2_refresh` POST
  to `token_url`), or (iii) resolves a dynamic template/lookup. **Enforce via a normative allow-list
  of note-safe injectors — a new or `multi`-wrapped injector is rejected until explicitly classified
  note-safe** (Oracle C1/C2/C8: a type-name denylist is fragile; `multi` can wrap a dangerous child).
  **This is the fix for the CRITICAL finding (C1/F1): without P1, one note exfiltrates and overwrites
  arbitrary sibling secrets.**
- **(P2) Exception-table minimums apply to ALL note bindings (T1 and T2), under a formal partial
  order.** A note binding to a curated host (`EXCEPTION_TABLE`: `api.github.com` GET-only, Anthropic
  `x-api-key` + companion, Linear raw, …) must declare scope **equal-or-tighter** than the curated
  default, defined precisely (Oracle C3): `methods` ⊆ curated set (case-normalized); every note
  `path` is glob-contained by a curated path; a curated field the note omits is treated as the
  curated default (not "unbounded"); comparison uses the canonical forms of §4(d). A scope not
  provably ⊆ the curated default is rejected. The table applies regardless of tier — T2 no longer
  bypasses it. (Fix for C2/F2 — a T2 GitHub note is no longer a silently-unscoped PAT.)
- **(P3) The multi-host safety invariant (§4) applies to ALL note bindings — including explicit
  `bindings:` entries, not just the `host:`-list sugar.** The trust boundary is note-vs-file, so the
  companion-header exclusion and least-privilege checks fire on every note-sourced binding. (Fix for
  C2/C3/F3 — the explicit-`bindings:` exemption is removed.)
- **(P4) `honeytoken:` is file-only — a note setting `honeytoken:true` is REJECTED** (drop-and-
  attribute, preserving file fallback), never silently stripped (Oracle C6 disambiguation). Arming a
  canary from a note weaponises the alert channel (detection DoS); `_preserve_file_flags` already
  prevents *disarming*. (Fix for C5/F7.)
- **(P5) Body / multi injectors gated by *effective sink*, not type string** (Oracle C8), behind a
  per-install opt-in (`allow_notes_body_injectors: false` by default, same pattern as
  `allow_wildcard_hosts`): any injector whose effective sink writes into a request body — directly or
  via a `multi` child — is off by default for a low-trust author. Header injection (the common path)
  stays default-on.
- **(P6) Resource limits on notes-sourced metadata** (Oracle C9): cap note size, binding count,
  path-pattern count, and template length, and reject over-limit **before** the full (potentially
  expensive) validation — drop-on-invalid is not a DoS control if validation itself is the DoS.

**Enforcement precision.** Host canonicalization (case, trailing dot, IDNA/punycode, port,
whitespace) happens in `BindingSpec.normalize_and_validate_host` *before* both the wildcard gate and
the `EXCEPTION_TABLE` match, so a lookalike host can't dodge a curated tight scope (Oracle C4). Every
profile rejection writes `invalid_binding_metadata` with source + reason + secret name, and repeated
invalid-note fallback is operator-visible — so a downgrade attack (forcing file-fallback, or probing
the profile) is detectable, not silent (Oracle C7).

**Normative capability table — "parity" is of *syntax*, not *capability* (Oracle C12):**

| Capability | In a note? |
|---|---|
| `host` (scalar/list/`hosts:`), `methods`, `paths`, `header`, `format` — header injection | **Accepted** |
| `bindings:` list / T2 nested shape | Accepted (bounded by P2, P3, P6) |
| `honeytoken` inherit-from-file / `false` | Accepted (inherit only) |
| Body / `multi` injectors | **Gated** — `allow_notes_body_injectors` (P5) |
| `oauth2_refresh`, `compose:`, `inject.template` (cross-secret / network) | **Rejected — file-only** (P1) |
| `honeytoken: true` (arm) | **Rejected — file-only** (P4) |
| explicit `placeholder:` | **Rejected — out of scope** (§3) |

One dialect to *write* (syntax parity); the table is the *capability* boundary. What the parser
accepts ≠ what the profile grants.

### 3. Placeholder — daemon-derived by default; policy reaches parity, plumbing stays managed

The placeholder is infrastructure plumbing, not policy. **Omit `placeholder:` in a note → derived**
from `(secret_name, install_salt)`, uniqueness/marker-validated, discoverable via a new
`avp placeholder <NAME>` + the ADR-0020 §8 effective-bindings print. `format`/`template` accept both
`{secret}` and the literal `{<SECRET_NAME>}` so a file entry pastes in — **but see F4 (§6): the
literal token requires re-running `validate_format_placeholders` over the merged config**, or a
mistyped `{WRONG_NAME}` becomes a silent non-injecting binding. **Explicit `placeholder:` in a note
stays out of scope** (§7): a colliding/malformed one hard-raises at the merged
`validate_placeholder_invariants` (`handlers.py:718`) → daemon DoS; enabling it requires the
raise→drop change first, and even then a gate.

### 4. Multi-host safety invariant (applies to all note bindings per P3)

For any note binding set that reaches multiple hosts with one `inject`: **(a) self-describing** —
explicit `format` (no silent bare-Bearer fan-out); **(b) companion-header hosts excluded** — a host
with non-empty exception-table `companion_headers` (Anthropic, Notion) cannot share a note; **(c)
least-privilege** — a curated-tight-scope host requires uniform `methods`/`paths` equal-or-tighter;
**(d) canonical comparison** — header case-folded, format exact, methods upper-cased set, paths
order-normalized, companion_headers key-sorted (spurious divergence fails closed; never spuriously
converge). Per P3 these fire on explicit `bindings:` too.

### 5. Multi-host normalization — the implementation seam the guards depend on

`host: str|list[str]` / `hosts:` on `BindingSpec` **must normalize to N scalar-host `BindingSpec`
objects in a `SecretSpec` before-validator — ahead of index build and BOTH wildcard gates**
(`handlers.py:699` `b.host.startswith("*.")`, `config.py:528`, `config.py:568`). Those sites do
scalar string ops on `b.host`; a residual list `.startswith` either raises (reload DoS) or coerces
to a false negative (wildcard opt-in bypass). This is **new code with a mandatory regression test**
(a `*.evil.com` element inside a `host:` list is still dropped at the merge) — the earlier "no new
code" claim was wrong (C4/F5).

### 6. Merge-point enforcement — reuse where sound, fix where not

The full note flows through `NotesActivator.activate`. Required changes there:

- **Re-run the full `Config` validator suite over the merged config** (not just wildcard +
  placeholder-invariants), so cross-secret Config validators — notably `validate_format_placeholders`
  — see notes specs. (Fix for F4; makes §3's `{SECRET_NAME}` literal safe.)
- **Enforce the note trust profile (§2 P1-P5)** at the merge: drop-and-attribute, never abort.
- **An invalid note for a name that also has a file spec falls back to the file binding**, never
  drops it (`handlers.py:676-679` currently excludes the file spec on `resolved.invalid`). Low-trust
  input must not disable trusted config. (Fix for F6.)
- **Wildcard opt-in** stays (correct once §5 normalization runs first).

### 7. Backward compatibility & out of scope

T0/T1/scalar `host:` unchanged; `model_dump()`, matcher, audit `binding_source` untouched;
single-element `host:[x]` ≡ `host:x`. **Note (Oracle C5):** `host: str|list`/`hosts:` on the *shared*
`BindingSpec` also changes the **file** schema — a `bindings.yaml` may now use a host list too. §5
normalization must preserve `model_dump()`, error locations, duplicate handling, and source
attribution for scalar-host entries (only list-host entries change shape); a golden-output test on an
unchanged scalar file config is required. **Out of scope / file-only:** `compose:`/`inject.template`
and `oauth2_refresh` (P1), `honeytoken:` arming (P4), explicit note placeholders (§3), per-host
scope in a fan-out, note-authored `token_url` allow-lists.

## Consequences

### Good
- One schema to learn (parity of syntax); the dangerous *capabilities* are bounded by an explicit,
  code-enforced trust profile rather than left to file validators that never enforced it.
- The confused-deputy chains the review found (sibling-secret exfil, unscoped curated hosts, wildcard
  bypass, honeytoken-arm DoS) are closed at one place — the merge — where the trust boundary belongs.

### Bad / risks
- **Not full literal parity:** a low-trust note cannot express oauth2_refresh / compose / honeytoken /
  (by default) body injectors. This is a deliberate, necessary deviation from "exactly the same" —
  schema is identical, capability is bounded. Operators needing those use the file (operator-trusted).
- New code (§5 normalization, §6 merged-config validation, §2 profile) — each carries a mandatory
  regression test; "additive, no new code" was false.

### Out of scope (future ADRs)
- Notes-sourced oauth2_refresh with a `token_url` allow-list + self-secret-only `*_secret` references.
- Explicit operator placeholders in notes (needs raise→drop first).

## Security Review (2026-07-11) — findings and resolution

Two independent adversarial reviews of ADR-0021 v1 (Cato cross-vendor audit; Silas offensive
red-team). Both returned **FAIL** on v1 and converged on C1.

| ID | Sev | Finding (v1) | Resolved by |
|----|-----|--------------|-------------|
| C1/F1 | **CRITICAL** | `oauth2_refresh` in a note → read/overwrite arbitrary sibling secrets, exfil to attacker `token_url` | §2 P1 (file-only) |
| C2/F2 | HIGH | T2 notes bypass `EXCEPTION_TABLE` tight scopes → unscoped GitHub PAT | §2 P2 |
| C2/C3/F3 | HIGH | §3 invariant exempted explicit `bindings:` → trivially bypassed | §2 P3 (applies to all note bindings) |
| C4/F5 | MED | `host: str|list` breaks scalar wildcard guards → crash / opt-in bypass | §5 (normalize before gates) |
| F4 | MED | Config validators (`validate_format_placeholders`) not re-run on merged specs | §6 (re-run full suite) |
| F6 | MED | invalid note drops same-named file binding | §6 (fall back to file) |
| C5/F7 | LOW-MED | note can *arm* honeytoken → alert DoS | §2 P4 (file-only) |
| C6 | LOW | oauth2 `token_url` DNS-resolved at reload → beacon/stall | mooted by §2 P1 |
| C7 | LOW | explicit-placeholder DoS/hijack | already deferred (§3/§7) — reviewers concur |

Reviewers **confirmed correct**: derived-placeholder recommendation; raise-vs-drop DoS analysis;
honeytoken disarm-prevention (`_preserve_file_flags`); structural facts 1-2.

**Oracle cross-model pass (design-review, 2026-07-11) on v2** — verdict *"directionally better than the
failed design; agreement partial"*; raised 12 refinements to the enforcement semantics. Material ones
folded into v3:

| ID | Sev | Refinement | Folded into |
|----|-----|-----------|-------------|
| C1/C2/C8 | HIGH | gate injectors by *capability* (deny-by-default allow-list), not type-name; `multi` can wrap a dangerous child | §2 P1, P5 |
| C3 | HIGH | define `equal-or-tighter` as a formal partial order (method-subset, path-glob-containment, absent=curated-default) | §2 P2 |
| C9 | MED | resource limits (note size, binding/path/template counts) — validation itself is a DoS vector | §2 P6 |
| C6 | MED | honeytoken reject-vs-strip ambiguity → **reject** | §2 P4 |
| C4 | MED | host canonicalization (IDNA/trailing-dot/port) before wildcard + table match | §2 Enforcement precision |
| C5 | MED | shared-`BindingSpec` change also alters file schema — golden-output test required | §7 |
| C7 | MED | invalid-note fallback needs an audit signal (downgrade-attack visibility) | §2 Enforcement precision |
| C10 | LOW | pin the note-vs-value privilege split assumption; verify per backend | Context (stated assumption) |
| C12 | LOW | distinguish accepted-syntax / rejected / gated in a normative table | §2 capability table |
| C11 | LOW | literal `{SECRET_NAME}` may leak secret names into effective-binding output | note only — check display/audit surface at impl |

**Status: v3 — signable as a DESIGN once you confirm the trust-profile deviation from "exactly the
same" (schema parity, bounded capability).** Implementation is E4 and gated on that confirm; a
post-implementation code review (Cato + Silas re-run against the actual diff) is still owed before
"done".

## References
- ADR-0011 / ADR-0017 (oauth2-refresh) / ADR-0018 / ADR-0020.
- Change/enforcement sites: `notes_binding.py`, `config.py` (`BindingSpec`, `SecretSpec`),
  `handlers.py` (`NotesActivator` — trust-profile enforcement), `config_models.py`
  (`validate_placeholder_invariants`, injector taxonomy), `oauth2_refresh.py` (C1 primitive),
  `runtime_bindings.py` / `placeholders.py` (derivation).
