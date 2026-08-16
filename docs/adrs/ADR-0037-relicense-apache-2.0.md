---
status: accepted
date: 2026-07-26
---

# ADR-0037: Relicense from MIT to Apache-2.0

- **Status:** Accepted
- **Date:** 2026-07-26

## Context

AVP launched under MIT. MIT is silent on patents — it grants copyright permissions only. For a security tool whose adoption path runs through enterprise environments, that silence is a real cost: corporate OSS-intake reviews treat the absence of an explicit patent grant as an open question, while Apache-2.0 is the settled default for infrastructure and security tooling (Envoy, the CNCF landscape, Kubernetes). The project is at the right moment to fix this: a single copyright holder (git history: one author; dependabot manifest bumps carry no copyrightable expression), no external contributors to chase for consent, and a product rename on the horizon that this change can ship alongside.

## Decision

1. **Relicense to Apache-2.0** effective the next release. `LICENSE` is replaced with the canonical Apache-2.0 text; a `NOTICE` file names the product and copyright holder.
2. **Git history is left untouched.** No history rewrite, no retroactive relabeling. Every release up to and including 0.9.0 was distributed under MIT and remains so — MIT grants are irrevocable for the code already published. The relicense applies from this change forward. This is the standard, cleanest handling (same shape as countless MIT→Apache moves); anyone who pinned ≤0.9.0 keeps exactly the terms they received.
3. **Historical documents are not edited.** ADR-0018 and ADR-0019 mention "AVP's MIT license" as a dated fact and stay as written; `docs/comparison.md` mentions MIT only for third-party projects. This ADR supersedes them on licensing.
4. **DCO instead of a CLA.** `CONTRIBUTING.md` now requires `Signed-off-by` (`git commit -s`). Inbound = outbound under Apache-2.0 §5; the DCO preserves clean provenance (and future licensing optionality) without CLA bureaucracy, and matters to establish *before* the first external contributor arrives.
5. **No per-file license headers.** Apache-2.0 recommends but does not require them. A ~200-file boilerplate diff buys nothing for a single-repo project with a root `LICENSE`; skipped deliberately.
6. **Vendoring rule updated** (`AGENTS.md` rule 9): single-license Apache-2.0; only Apache-2.0-compatible sources (MIT/BSD/Apache) may ever be vendored; GPL-family and SSPL are not.

## Out of scope (considered, explicitly not decided here)

- **Product rename (InflightSec).** The GitHub org is already `inflightsec`; the product rename ships separately once the name is final, so the license flip is not blocked on naming. `NOTICE` will be updated then.
- **Donation to the Apache Software Foundation (or CNCF).** Assessed and declined for now: foundation donation transfers copyright and trademark into vendor-neutral governance, and Incubator entry requires a multi-affiliation committer community that a single-maintainer project does not have. Revisit only if the project ever has sustained independent committers and the commercial strategy no longer depends on owning the mark. Using the Apache *license* carries no relationship to, or obligation toward, the ASF.

## Consequences

- Downstream users gain an explicit patent grant and patent-retaliation protection; enterprise intake friction drops.
- Redistributors must now preserve the `NOTICE` file (Apache-2.0 §4(d)) — a trivially met obligation that also gives the product name light attribution protection.
- Apache-2.0 is incompatible with GPLv2-*only* downstream combination; no known downstream is affected.
- Contributors must sign off commits; PRs without `Signed-off-by` are asked to amend.
- Packaging metadata (`pyproject.toml` license + trove classifier, `.claude-plugin/plugin.json`) declares `Apache-2.0`; PyPI and the plugin marketplace will show the new license from the next publish.
