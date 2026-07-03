# Architecture Decision Records

ADRs (MADR-lite frontmatter + `Context` / `Decision` / `Consequences`) live here so that the rationale for non-trivial design choices is versioned alongside the code it governs. `git log docs/adrs/` is the decision history.

## Convention

- Filename: `ADR-NNNN-short-kebab-title.md` (zero-padded four-digit sequence).
- Frontmatter: `status: proposed | accepted | superseded`, `date: YYYY-MM-DD`, optional `relates_to:`, optional `amended:` and `amends:`.
- Body sections: `Context`, `Decision`, `Consequences` (Good / Bad / Out of scope). Additional sections (`References`, `Beyond the baseline`, `Amendment`) when they earn their existence.
- New ADRs start `status: proposed`; flip to `accepted` once the operator signs off. Never delete — supersede with a new ADR.

## When an ADR is required

- Anything touching the G1-G9 binary invariants in `docs/architecture.md`.
- New injector type, new backend type, new audit event shape.
- New external-call surface (token endpoints, write paths to backends).
- Schema change that breaks `apiVersion: v1` bindings.

## Backfill policy

Pre-existing AVP-relevant ADRs (0011 BWS-notes bindings, 0012 narrow-trust CA, 0013 declarative policy fixtures) currently live outside the repo for historical reasons. They get backfilled here as we touch the affected code paths — no big-bang migration.
