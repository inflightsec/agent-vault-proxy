---
status: accepted
date: 2026-06-12
relates_to: ADR-0011 (BWS-notes bindings), ADR-0012 (narrow-trust CA)
---

# ADR-0013: `avp test` — declarative fixture-based policy regression testing

## Context

Edits to `bindings.yaml` and to the injector logic are security-critical: a silent
regression either leaks a secret (placeholder injected where it shouldn't be) or breaks
auth (placeholder withheld where it should fire). The current pytest suite covers units
(`test_matching`, `test_bindings_resolver`, `test_body_injector`, `test_multi_injector`,
…) but there is **no declarative regression net over the full `(config, request) ->
decision` matrix** keyed to the audit verdict taxonomy.

The pattern we want is a self-contained fixture runner: replay a set of `(config, request)`
cases against a *candidate* policy and report **verdict drift**, with no gateway, DB, or auth
in the loop, exiting `0`/`1`/`2`. That shape fits AVP's needs directly.

**Constraint discovered while reviewing the design against our own docs.** AVP's audit log
**deliberately omits header values, bodies, and query strings** (architecture §4.4, "Vault-style
audit minimization"). A record-replay approach that exports fixtures *from the audit log* is
therefore not available to AVP — the raw request isn't recorded, by design. Record-replay would
force either weakening audit minimization or building a new full-request capture surface. Both
are rejected. AVP's request input space is small and enumerable (host, SNI, method, path, which
placeholder in which header), so **declarative, spec-derived fixtures** fit better and avoid the
dominant golden-master failure mode (capturing buggy behavior as "correct").

## Decision

1. **One decision path, run headless** (refined 2026-06-12 during implementation — see note below). The fixture
   runner drives the **real `addon`** decision path against a static in-memory backend, reading the
   observed verdict off the `inject_decision` / `deny` audit events
   (`decision: allowed|denied`, `reason`, `secret_name`, slot, `injected`). No separate
   `decide()` engine is extracted: `mitmproxy.test.tflow` + a fake backend already make the live
   addon callable in-process (the existing `test_addon.py` harness proves it), so there is exactly
   one decision path and nothing to keep in sync.

2. **Two entry points off one engine.** A `pytest` suite globs the fixtures (developer
   regression net) **and** an `avp test <dir>` subcommand runs the identical engine (operator
   safety net for editing their own `bindings.yaml`). Companion `avp validate` loads config and
   runs the existing config-load invariants to catch typos. Exit `0`=match, `1`=drift,
   `2`=config/usage error.

3. **Declarative, spec-derived fixtures.** One YAML per case under `tests/fixtures/policy/`,
   each `pins:` a `T-`/`G-` id from the architecture doc so a fixture *is* an executable
   threat-model assertion. Assert `{decision, reason, secret_name, injected}`; composite / multi
   / body injectors additionally snapshot `rendered:` output computed from **fixed fake
   static-backend values** (catches the Jinja `b64(email:token)` and multi-leaf assembly — the
   highest-logic, highest-risk paths — with human-reviewable diffs).

4. **Hard safety invariants for test mode.** Static backend only — the BWS backend is
   **uninstantiable** under `avp test` (no real credential ever enters the process). Clock pinned,
   TTL jitter off, and `ts` / `request_id` excluded from the compared record (determinism).

5. **Two entry points, no swap.** Both the `pytest` glob and the future `avp test <dir>` CLI lift
   the same `run_policy_fixture()` helper, which runs the live addon headless. Because nothing is
   extracted or rewired, there is no parity test and no migration step to guard — the drift risk
   that an extracted parallel engine would carry simply does not exist.

> **Implementation refinement (2026-06-12).** The original draft of points 1 & 5 called for extracting a pure
> `decide()` and guarding the addon→`decide()` swap with a parity test. Wiring it showed that
> unnecessary: the `tflow` + fake-backend harness runs the *real* addon in-process against a static
> backend, so the fixtures exercise the one true decision path directly. Dropping the extraction is
> strictly less code and removes the only drift risk in the design.

## Consequences

**Positive**
- Operators (and anyone editing bindings across a fleet) can edit `bindings.yaml` with a regression net;
  developers get the same net over refactors.
- Fixtures double as executable `T-`/`G-` assertions; the §4.2 host-matching semantics list is
  the ready-made backlog.
- Net test LoC may *shrink* as imperative matching tests become declarative fixtures.
- Audit minimization is untouched — no new capture surface, no record-replay.

**Negative / accepted**
- Fixtures own **policy correctness only**, not transport. The on-the-wire substitution and
  `inject_decision` fsync ordering (G2/G6) stay covered by the existing docker-e2e + smoke layers;
  one e2e smoke per injector type (header/body/composite/multi) is retained for the seam.
- Declarative fixtures are hand-authored (acceptable — tiny input space; and spec-derived is the
  point, not a cost).
- The `avp test` CLI imports `mitmproxy` to run the addon headless (it's already a hard dependency),
  rather than running a lighter standalone engine. Accepted: it buys a single decision path and
  zero drift risk, which is worth more than a leaner import graph for a test command.

**Neutral**
- Rendered snapshots require fixed fake-secret constants so diffs stay readable and reviewable.
