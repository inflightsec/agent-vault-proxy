---
status: proposed
date: 2026-08-03
relates_to: docs/paper/threat-model.md §2.2 (T-1, T-1.5), ADR-0031 (response-side echo scrubbing — the defense several gallery entries block on), ADR-0035 (pin vetted address for token egress — SSRF-to-vault surface), ADR-0023 (closed audit event-type set — assertions read the audit stream), ADR-0026 (TLS termination scoping — the inject path the gallery drives), ADR-0013 (declarative policy fixtures — the fixture pattern the exploits reuse)
references:
  - tests/test_addon_noleak_stateful.py, tests/test_addon_body_noleak_stateful.py (scope + audit-log no-leak assertions the gallery re-homes)
  - tests/test_scheme_gate_noleak.py, tests/test_confinement_and_audit_completeness.py (exploit-shaped coverage folded into the catalog)
---

# ADR-0043: Adversarial attack gallery as a CI-gated exfil regression suite

> **Status: PROPOSED.** A test-and-CI artifact, not a runtime feature. Adds no new
> injector, backend, or audit event. Implements no new *defense* — it makes the
> guarantee falsifiable and gates it. Supersedes nothing.

## Context

kow's product is outbound secret substitution; the guarantee is **G1 — the real secret never
enters the agent's address space, so it cannot be exfiltrated.** Today that guarantee is
asserted *piecemeal*: `test_addon_noleak_stateful.py` and its body/oauth siblings prove the
secret injects only in-scope and never lands in the audit log; `test_scheme_gate_noleak.py` and
`test_confinement_and_audit_completeness.py` cover adjacent slices; the rest of the attack
surface lives as prose in threat-model §2.2. There is no single artifact that

1. **enumerates** the concrete exfiltration exploits we claim to defeat,
2. **proves** each one fails-to-exfil against the *real* addon inject path, and
3. **fails the build** the instant a regression re-opens one.

Scattered no-leak tests cannot be read as a **guarantee ledger**: coverage gaps are invisible,
and classes we do *not* yet defend are undocumented in code. Verified 2026-08-03: there is no
`echo_scan` / `on_echo` / `redact` code in `src/` — response-side echo scrubbing (ADR-0031) is
**proposed, not shipped**. So **naive reflection** (upstream echoes a submitted field into an
error/response) and **create-then-read** (agent `POST`s the placeholder to create a resource;
kow injects the real secret into stored state; a later plain `GET` returns it) **leak today** and
are recorded nowhere executable.

## Decision (proposed)

Create **`tests/attacks/`** — a curated adversarial gallery. Five decisions:

1. **One file, one exploit, one threat.** Each file is a single named working exploit that drives
   the real addon pipeline (`http_connect` → `requestheaders`/`requestbody` → `response`), not a
   mock. Its docstring carries a `THREAT: <id>` marker mapping it 1:1 to a threat-model §2.2 entry
   (T-1 prompt-injection exfil, T-1.5 laundering-through-bound-host, etc.). The assertion is
   **fail-to-exfil**: the real secret value never appears anywhere the agent can read it — response
   headers, response body, error text, the audit log, or a *subsequent* request's response.

2. **Two verdict states, both build-gated.**
   - `defended` — asserts the secret does **not** exfil. A regression that re-opens it → **red**.
   - `expected-leak` — asserts the **current undefended** behavior (the secret *does* leak) for a
     class we have not yet closed. Every `expected-leak` file **must** carry `BLOCKED-BY: ADR-00NN`
     (or an issue) in its marker. When the defense ships, the entry flips to `defended` in the same
     PR. Crucially the state is **strict-xfail**: an `expected-leak` that *stops* leaking (the
     defense landed but nobody flipped it) also fails the build as an **unexpected pass**. There is
     no silent "we leak here forever," and no forgotten flip.

3. **Seed set** (each mapped to a threat entry; `defended` unless noted):
   - `scope_bypass` — off-scope method/path/host request; assert no injection (re-homes scheme-gate
     + confinement intent). **T-1.5.**
   - `audit_exfil` — assert the real secret is never written to the audit stream (re-homes the
     existing stateful assertion). **T-1.**
   - `injection_confinement` — agent smuggles the placeholder into a non-target header; assert
     substitution stays confined to the declared injection target. **T-1.5.**
   - `ssrf_to_vault` — agent coerces kow into fetching the backend/vault or a non-bound host; assert
     refusal. **T-1 / ADR-0035 surface.**
   - `reflection` — upstream echoes a submitted field into an error/response body; assert secret not
     in response. **`expected-leak`, BLOCKED-BY: ADR-0031.**
   - `create_then_read` — `POST` placeholder to create a resource, later `GET` returns it; assert
     secret not in the GET body. **`expected-leak`, BLOCKED-BY: ADR-0031.**

4. **CI gate.** A dedicated `attacks` job (`pytest -m attacks`) that MUST pass; `expected-leak`
   entries are part of the pass contract (strict-xfail — they must leak *exactly* as documented).
   Wired into the existing GitHub Actions workflow. A tiny meta-test enforces the convention: every
   file under `tests/attacks/` has a `THREAT:` marker, and every `expected-leak` has a `BLOCKED-BY:`.

5. **Re-home, do not duplicate.** Exploit-shaped assertions already living in `noleak`/gate/
   confinement tests **move** under `tests/attacks/` (or are referenced) so there is exactly one
   catalog; fine-grained unit tests (matcher, resolver) stay where they are. A moved test is not a
   new test — net test-count growth is only the genuinely-new exploits.

## Consequences

**Good**
- One readable **guarantee ledger**: the attack surface and our current coverage are visible in a
  single directory, keyed to the threat model.
- Known gaps become **pending acceptance tests** — `create_then_read` *is* ADR-0031's acceptance
  test — instead of prose. The gallery drives the roadmap.
- Both failure directions are caught: `defended → leak` is red (regression); `expected-leak → pass`
  is red (forgot to flip). The guarantee is now **falsifiable and gated**, not asserted.

**Bad / cost**
- Discipline burden: the `THREAT:` / `BLOCKED-BY:` convention must hold, enforced by the meta-test.
- **Honest limit** (same one ADR-0031 documents): exact-substring exfil checks miss *transformed*
  echoes (base64, split, re-encoded). The gallery proves the naive case is defeated, not a
  cryptographic guarantee. Transformed-echo exploits are a documented future entry, not a claim.
- Migration overlap risk while re-homing; mitigated by moving, not copying.

**Documented future exploits** (named so their absence is not mistaken for coverage)
- **Query-string echo** — a secret laundered into a URL query parameter and reflected back
  (same class as `reflection`, different channel).
- **Transfer-encoded / compressed body echo** — gzip/br or chunked responses defeat an
  exact-substring scan; `agent_visible` inspects decoded UTF-8 only. This is the honest limit
  ADR-0031 already documents, surfaced here as a pending exploit.
- **Streaming response path** — `simulate_upstream` attaches a complete response; leaks that
  appear only across streamed chunks are not yet exercised.

**Out of scope**
- Implementing the reflection / create-then-read **defense** — that is ADR-0031.
- Property-based / fuzzed attack generation (future).
- Any runtime, in-production attack *detection* — the gallery is CI-only.
