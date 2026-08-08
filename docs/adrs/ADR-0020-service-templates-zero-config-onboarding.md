---
status: proposed
date: 2026-07-03
relates_to: ADR-0011-bws-notes-bindings, ADR-0017-oauth2-refresh-injector, ADR-0018-gcp-secret-manager-backend
---

# ADR-0020: Service templates — zero-config, secure-by-default secret onboarding

## Context

The North Star for AVP: an operator drops a secret into a backend vault (BWS, GSM,
future backends) and does nothing else. AVP recognises the service, applies a curated
template that supplies the upstream host(s), the injection method, and a tight default
scope. No hand-written bindings for well-known services. Critically, the operator
*cannot accidentally under-secure a known service* — the secure scope is the default,
not an opt-in.

Two structural facts about the current schema motivate this:

1. **Injection method is misfiled.** `inject:` (header / body / multi / oauth2_refresh /
   composite) lives on the per-secret entry today. But *how* a credential is presented on
   the wire — GitHub is always `Authorization: token <x>`, Slack webhook is always a body
   field — is a property of the **service**, not of the operator's particular token. It is
   duplicated across every secret and every operator who ever wires GitHub.
2. **Scope is duplicated too.** `bindings:` (host / methods / paths) is retyped per secret;
   two GitHub tokens get two identical scope blocks.

We already ship exactly one curated catalog and it works: `oauth_providers.py`
`PROVIDER_PRESETS` (ADR-0017) lets an operator write `provider: google` instead of
hand-copying token URLs and RFC 6749 §2.3 auth-method nuances. **This ADR generalises that
proven pattern from OAuth-only to all injection types.**

We also already resolve bindings from vault metadata: ADR-0011 (BWS notes), ADR-0018
(`avp-binding` GSM annotation + `binding_source`). This ADR adds `template` as a binding
source and pins the precedence.

Footgun on record to respect: `binding_source: both` previously *replaced* rather than
*unioned* file-only bindings (fixed in HEAD). Any merge semantics introduced here must be
explicit about union vs. replace.

## Decision

### 1. The Service Template is the enriched endpoint

A template is a curated, versioned object keyed by a service id, owning the three things
intrinsic to the *service* rather than the operator's token:

- `hosts:` — one or more upstream hosts.
- `inject:` — the injection method, reusing the existing **closed injector taxonomy**
  (`_INJECTOR_TYPES`). No new injector machinery.
- `default_scope:` — the tightest `methods` + `paths` that is still useful (least privilege).

Ships in-package (`kow/service_templates/…`) under the same **backfill
discipline** as the OAuth presets (ADR-0017 §9): an entry lands when a concrete operator
binding needs it, never on speculation. The catalog is the open-source credentialing
surface (S8) — a well-curated set of "here is how to safely scope GitHub / Stripe / Slack"
templates is a community asset.

### 2. The secret shrinks to {value, service, optional overrides}

Ideal operator action: put the value in the vault, tag it `service: github`. AVP expands
that into concrete bindings via the template. The per-secret `inject:` and `bindings:`
become **optional overrides**, not the main road.

### 3. Resolution is load-time expansion → the matcher never changes

Templates resolve at config/secret **load time** into the exact binding structures the pure
decision function already consumes. Request-time matching is byte-for-byte unchanged. This
is the same "load-time dereference, zero runtime change" property endpoint-extraction would
have had — the template *is* the endpoint, enriched with injection semantics.

### 4. Secure-by-default fallback ladder — the load-bearing security decision

Deterministic and fail-closed:

1. **Service tagged + template exists** → template hosts + inject + tight `default_scope`.
   Best case, zero operator config.
2. **Service tagged but no template**, or **host explicitly named but no template** →
   inject via the default method (`Authorization: Bearer {value}`), scoped to the
   *operator-named host*, all paths/methods. This is the weaker posture; `avp doctor` and
   preflight **warn**. This is the operator's "just allow all traffic on that hostname" —
   but bounded to a host the operator explicitly named.
3. **No host and no template** → **DENY. Fail closed.** (`unmatched_destination_policy: deny`
   already exists — this reuses it.)

**The host is NEVER inferred.** A credential is only ever injected toward a host that was
explicitly named by the operator or provided by a template. Injecting a bearer token toward
an unverified host is credential exfiltration, so tier 3 must fail closed, always.

### 5. Service identification = explicit tag, never value-sniffing

- **Primary:** an explicit `service:` tag — a vault annotation/note field, or a naming
  convention on the secret key.
- **Fingerprinting is suggestion-only.** Token-prefix shape (`ghp_`, `github_pat_`, `sk-`,
  `xoxb-`) MAY surface a "did you mean service: github?" hint at `avp doctor` time. It MUST
  NOT silently drive injection. Guessing a credential's *destination* from its *shape* is a
  security failure mode: a mislabelled or attacker-planted secret could be auto-injected
  against a permissive template. The operator asserts the service; AVP never guesses it into
  the injection path.

### 6. Overrides + precedence — respecting the `both` footgun

Vault-note / file overrides layer onto the template deterministically:

- An override may **tighten** scope freely — silent, encouraged.
- An override may **add hosts / widen scope / change the inject method** — allowed, but
  **audited and preflight-warned**. This is the powerful, attacker-interesting direction and
  must be visible.
- Merge is a **union with explicit precedence**, never a silent replace. `binding_source`
  extends to `{template, notes, file, all}` and MUST union its layers. This is exactly the
  place the old `both`-replaces-file bug lived; §8 is its regression guard.

### 7. Vault-as-source-of-truth for *which* secrets exist (North Star mode, staged)

Ultimately the backend enumerates the vault; each secret self-describes via its `service:`
tag, and `bindings.yaml` shrinks to global config only (cache / audit / backend / policy).
Staged (see §9): templates + explicit-tag resolution first, backend auto-enumeration second.

### 8. Verification — maximally simplified (per operator, 2026-07-03)

**No fixture corpus. No golden-file / recorded-request replay framework.** One dry-run
subcommand:

```
avp validate [config.yaml]
```

It loads the config, resolves templates + overrides, and **prints the effective bindings** —
what each secret expanded to and where it came from — then exits non-zero on any error:

```
GITHUB_PAT   -> api.github.com      header Authorization   GET /repos/** /user   [template:github]
SLACK_HOOK   -> hooks.slack.com     body  application/json POST                  [template:slack]
INTERNAL_X   -> intranet.example    header Authorization   * (host-wide)         [fallback: named-host]  ⚠ widen-warn
```

The operator edits a YAML line or a vault tag, runs it, and *sees* what resolution produced.
That is the entire test. It doubles as the union/precedence regression guard for §6.
Recorded-request replay / drift detection is **out of scope** — resurrect only if a concrete
drift bug ever demands it.

### 9. Staged rollout

1. Template object + `service_templates/` catalog (seed: github, slack, openai, anthropic,
   stripe) + `service:` tag resolution + `avp validate` dry-run.
2. `binding_source: template` union into the existing notes/file precedence.
3. Backend auto-enumeration (§7) — vault becomes the secret inventory.
4. (Maybe, later) `avp doctor` fingerprint *hints*.

## Consequences

### Good

- North Star UX: drop a token in the vault, it is secured correctly by default.
- Secure-by-default: operators cannot under-scope a *known* service; an unknown host fails
  closed rather than leaking a bearer.
- Injection method lives where it belongs — on the service, de-duplicated across operators.
- Generalises a pattern already shipped and trusted (OAuth presets); the template catalog is
  a natural open-source contribution surface (S8 credentialing).
- Verification is a single dry-run command with zero fixture maintenance.

### Bad

- The template catalog becomes a **supply-chain + freshness surface**: AVP now asserts "this
  is how GitHub auth works." Needs review discipline, template versioning, and a widening
  guard on template PRs (a malicious PR that loosens a `default_scope` is the threat).
- Fallback tier 2 (host-wide scope) is a genuinely weaker posture. It must be *visibly*
  warned every time, never silent, or the "secure by default" promise erodes quietly.
- Auto-enumeration (§7) broadens what a compromised vault can express. The vault is already
  the trust root, but destination-*widening* via notes is why §6 audits that direction.

### Out of scope (each its own future ADR if pursued)

- Recorded-request replay / policy drift testing (deliberately dropped per operator).
- Fingerprint-driven *automatic* onboarding (stays a doctor-time suggestion only).
- Rule / verdict layer + approval chains (LLM judge, human approval) — action-gating is a
  separate concern from credential onboarding and gets its own ADR.

## References

- ADR-0011 BWS-notes bindings · ADR-0017 oauth2-refresh presets (the catalog precedent) ·
  ADR-0018 GSM backend + `binding_source`.
