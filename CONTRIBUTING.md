# Contributing to agent-vault-proxy

Thanks for the interest. `agent-vault-proxy` is a small, security-sensitive project - the contributing rules reflect that.

## Before you open a PR

For **non-trivial changes**, please open an issue first. The architecture in [`docs/architecture.md`](./docs/architecture.md) describes nine atomic guarantees (G1–G9) that the design preserves. Changes that affect those guarantees need agreement on approach before code review.

For **bug fixes, doc improvements, and small refactors**, a direct PR is fine, no issue needed.

For **security vulnerabilities**, do not open a public issue or PR. Follow the [`SECURITY.md`](./SECURITY.md) disclosure policy.

## Dev setup

Recommended path — mirrors CI exactly (Python 3.12, hash-pinned deps from the committed lockfile):

```bash
git clone https://github.com/inflightsec/agent-vault-proxy
cd agent-vault-proxy
bash scripts/bootstrap-venv.sh
```

Requires [`uv`](https://docs.astral.sh/uv/) on PATH (`curl -LsSf https://astral.sh/uv/install.sh | sh`). The script:

1. wipes any existing `.venv` and creates a fresh one with Python 3.12 (uv will fetch a managed copy if your system doesn't have one — works on Arch where `python3` is 3.14),
2. installs every dependency from `requirements-dev.lock` under `--require-hashes` (every package verified against an upstream sha256),
3. adds the project itself in editable mode.

Re-run any time you want a clean slate. `PY=python3.13 bash scripts/bootstrap-venv.sh` overrides the interpreter.

Fallback if you don't want uv:

```bash
python3 -m venv .venv
.venv/bin/pip install --only-binary :all: -e '.[dev]'
```

`--only-binary :all:` refuses source distributions — the Python equivalent of `npm install --ignore-scripts`. This path resolves deps fresh from PyPI (no hash verification against the committed lockfile), so it's a quicker setup but doesn't reproduce CI's exact pin set.

## Pre-commit hooks (install once, then automatic)

```bash
pipx install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push
```

From then on, every `git commit` runs ruff (lint + format), bandit (Python SAST), TruffleHog (secret scan), Semgrep (pattern SAST), OSV-Scanner (CVE check on lockfiles), zizmor (workflow audit), pinact (action SHA-pinning), pytest, and a set of hygiene hooks. The three Docker-based hooks (TruffleHog, OSV, Semgrep) gracefully skip if Docker isn't running locally, CI is the authoritative gate. Passing pre-commit locally guarantees the matching CI jobs won't fail on the same things.

`git push` additionally runs an unconditional lockfile-drift check — the commit-stage variant is scoped to dep-file changes for fast feedback, but the 7-day supply-chain cooldown rolls forward at midnight UTC, so a clean commit today can hit CI drift tomorrow. The pre-push hook catches that before it leaves your machine.

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

## Releasing

The release loop is three commands + one editor session. Do not bump version literals by hand — use the script, which writes every mechanical reference at once.

```bash
# 1. Bump every mechanical version reference (pyproject.toml,
#    src/kow/__init__.py, README install + clone tag,
#    docker-compose.yml image tag, smoke-test usage examples).
#    Reads the current version from pyproject.toml and rewrites
#    every known location to the target.
bash scripts/bump-version.sh 0.5.0

# 2. Edit CHANGELOG.md — add the new ## [0.5.0], YYYY-MM-DD entry
#    with release notes, advance [Unreleased] compare base to v0.5.0,
#    add a [0.5.0] footer link. Edit README.md "Status" prose to lead
#    with the v0.5.0 framing. These are content changes, not mechanical
#    bumps — the script deliberately does not touch them.
$EDITOR CHANGELOG.md README.md

# 3. Stage everything and run the pre-release gauntlet. Section 3
#    of pre-release.sh validates that every tracked version literal
#    agrees with pyproject.toml — the safety net for the class of
#    skew that broke v0.4.2. Other sections run lint, mypy, pytest,
#    lockfile pinning, zizmor, the wheel smoke, and the e2e harness.
git add -A
bash scripts/pre-release.sh

# 4. If green: commit, tag, push. Tag push triggers release.yml,
#    which builds + publishes to PyPI + runs the post-publish smoke
#    + creates the GitHub Release page. Approve the `pypi` environment
#    when GitHub prompts.
git commit -m "release: v0.5.0"
git tag -a v0.5.0 -m "AVP v0.5.0"
git push origin main
git push origin v0.5.0
```

**Rules of the road:**

- **`pyproject.toml` is the source of truth for the version.** Every other location must agree. `pre-release.sh` section 3 enforces this — if it goes red, run `bash scripts/bump-version.sh <version>` again rather than editing files by hand.
- **`pre-release.sh` runs on a clean tree.** Its first check is `git status --porcelain`. Commit first, then run pre-release; if pre-release fails after commit, `git reset --soft HEAD~1` restores staging without losing edits, fix the problem, retry.
- **The local `--local-wheel` smoke and the CI post-publish PyPI smoke exercise different code paths in `tests/pypi-smoke/Dockerfile`** (the `INSTALL_SOURCE=local` branch vs. the `INSTALL_SOURCE=pypi` branch). The local dry-run before tagging cannot fully validate the PyPI branch — that's what the daily `pypi-canary` workflow is for. If the post-publish smoke fails on PyPI propagation, re-run the failed job in the GitHub UI; the published wheel is unaffected.
- **`git push origin main` first, then `git push origin <tag>`.** The tag push is what triggers `release.yml`.

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

## License and sign-off (DCO)

Contributions are accepted under the project license, [Apache-2.0](./LICENSE) — inbound = outbound, per Section 5 of the license. There is no CLA. Instead, every commit must carry a `Signed-off-by:` line certifying the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s
```

The sign-off certifies that you wrote the change (or otherwise have the right to submit it) under the project license.

## Scope

This project is intentionally narrow. The injector taxonomy is complete and shipped (static `header`/`body`/`multi`, `oauth2_refresh`, `oauth2_client_credentials`, `github_app`, `sigv4`, `hmac`, `jwt_bearer`) and backends are BWS + GSM + static. We're unlikely to merge:

- Egress firewall features (out of scope - that's the operator's host firewall)
- Multi-tenant routing (single-host design)
- New storage backends beyond BWS / GSM / static (open an issue with a concrete need first)
- AWS SigV4 streaming/chunked payloads, presigned URLs, or SigV4a (core SigV4 signing already ships; these modes are held back to keep the agent from ever holding an AWS credential — see ADR-0036)

We're happy to merge:

- New injection formats (header patterns, query-param injection for APIs like Wolfram Alpha that auth via URL)
- Better deployment automation for popular distros / orchestrators
- Documentation improvements, especially around threat-model clarifications
- Test coverage improvements
- Performance improvements with measurements

## Code of Conduct

Be respectful. Disagree on technical substance, not on identity. Maintainers reserve the right to lock or close discussions that go sideways.
