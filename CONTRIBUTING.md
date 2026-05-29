# Contributing to agent-vault-proxy

Thanks for the interest. `agent-vault-proxy` is a small, security-sensitive project - the contributing rules reflect that.

## Before you open a PR

For **non-trivial changes**, please open an issue first. The architecture in [`docs/architecture.md`](./docs/architecture.md) describes nine atomic guarantees (G1–G9) that the design preserves. Changes that affect those guarantees need agreement on approach before code review.

For **bug fixes, doc improvements, and small refactors**, a direct PR is fine, no issue needed.

For **security vulnerabilities**, do not open a public issue or PR. Follow the [`SECURITY.md`](./SECURITY.md) disclosure policy.

## Dev setup

```bash
git clone https://github.com/inflightsec/agent-vault-proxy
cd agent-vault-proxy
python3 -m venv .venv
.venv/bin/pip install --only-binary :all: -e '.[dev]'
```

`--only-binary :all:` refuses source distributions - the Python equivalent of `npm install --ignore-scripts`. Mirrors what CI does.

## Pre-commit hooks (install once, then automatic)

```bash
pipx install pre-commit
pre-commit install
```

From then on, every `git commit` runs ruff (lint + format), bandit (Python SAST), TruffleHog (secret scan), Semgrep (pattern SAST), OSV-Scanner (CVE check on lockfiles), zizmor (workflow audit), pinact (action SHA-pinning), pytest, and a set of hygiene hooks. The three Docker-based hooks (TruffleHog, OSV, Semgrep) gracefully skip if Docker isn't running locally, CI is the authoritative gate. Passing pre-commit locally guarantees the matching CI jobs won't fail on the same things.

To run the full set against the whole tree (not just staged files):

```bash
pre-commit run --all-files
```

To bump hook versions periodically:

```bash
pre-commit autoupdate
```

## The loop

```bash
# Tests
.venv/bin/pytest -q

# Lint + format check (CI runs the same; pre-commit runs this too)
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests

# Apply formatting
.venv/bin/ruff format src tests
```

## Dependency updates

If your change adds, removes, or version-bumps a dependency (production OR dev), regenerate BOTH lockfiles with the 7-day supply-chain cooldown applied:

```bash
CUTOFF=$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)
uv pip compile --generate-hashes --exclude-newer "$CUTOFF" \
  pyproject.toml -o requirements.lock
uv pip compile --generate-hashes --exclude-newer "$CUTOFF" --extra dev \
  pyproject.toml -o requirements-dev.lock
```

`requirements.lock` is production-only. `requirements-dev.lock` is a superset that also includes the `[project.optional-dependencies.dev]` tools (pytest, ruff). Both are hash-pinned. CI runs in install via `pip install --require-hashes -r requirements-dev.lock` plus `pip install --no-deps -e .` to add the package itself.

`--exclude-newer` refuses any package version released in the last 7 days. CI re-runs the same compile with the same cutoff and fails if either committed lockfile doesn't match - the cooldown gate cannot be bypassed without an explicit change to the workflow.

If you genuinely need a newer dep (e.g. a fresh CVE fix), say so in the PR description and we'll talk about it.

## Testing philosophy

- **Behavior, not implementation.** Tests use the public interface (`load_config`, `BindingSpec.matches_scope`, addon hooks). Internal helpers are exercised through that surface, not tested directly.
- **No real BWS calls in tests.** The BWS client is exercised against a fake. Integration runs that actually hit BWS are documented in `tests/smoke/` and gated behind explicit env vars.
- **No real mitmproxy CA in tests.** Anything that needs a CA uses a fixture.
- **One behavior per test.** If a test description has "and" in it, it probably wants to be two tests.

If a bug surfaces and there's no failing test that catches it, the PR should add one before - or alongside: the fix.

## Code style

`ruff` is the formatter and linter. CI enforces both. Run `ruff format src tests` before pushing and you'll be aligned.

A few project-specific conventions:

- **No silent except.** `except Exception: pass` is forbidden. If you genuinely need to swallow an error, narrow the exception type, log the swallow, and add a comment explaining the rationale.
- **Audit events use structured fields, not f-strings.** The audit format is a stable JSON contract; treat it as such.
- **Don't log header values or request bodies, ever.** The audit log records *decisions*, not *contents*.
- **Comments explain `why`, not `what`.** Code that needs a comment to explain what it does usually needs a clearer name instead.

## Commit messages

We don't require Conventional Commits. We do appreciate messages that explain motivation:

- Bad: `fix bug`
- Bad: `update addon.py`
- Good: `addon: forward placeholder verbatim on scope violation (G5)`
- Good: `tests: cover path glob across multiple segments`

The first line is a summary (≤72 chars). The body explains *why* the change was made if non-obvious.

## Scope

This project is intentionally narrow. We're unlikely to merge:

- OAuth refresh-token flows (a different threat model and a separate injector type: happy to discuss in an issue if you have a concrete need)
- AWS SigV4 signing (same)
- Egress firewall features (out of scope - that's the operator's host firewall)
- Multi-tenant routing (single-host design)
- Storage backends other than BWS (BWS-specific is the design constraint; abstracting it adds complexity without a concrete second backend in mind)

We're happy to merge:

- New injection formats (header patterns, query-param injection for APIs like Wolfram Alpha that auth via URL)
- Better deployment automation for popular distros / orchestrators
- Documentation improvements, especially around threat-model clarifications
- Test coverage improvements
- Performance improvements with measurements

## Code of Conduct

Be respectful. Disagree on technical substance, not on identity. Maintainers reserve the right to lock or close discussions that go sideways.

