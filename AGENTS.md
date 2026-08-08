# AGENTS.md

Instructions for AI coding assistants (Claude Code, Codex, Cursor, Cline, Aider, etc.) working in this repository. This file follows the [AGENTS.md convention](https://agents.md/). Vendor-specific files (e.g., `CLAUDE.md`) point here.

Human contributors: [`CONTRIBUTING.md`](./CONTRIBUTING.md) is the right doc.

## What this project is

`agent-vault-proxy` is a credential broker - a loopback HTTPS proxy that fetches API credentials from Bitwarden Secrets Manager just-in-time and substitutes them into outbound requests, so the calling agent's address space never contains the real secret bytes.

Read [`docs/architecture.md`](./docs/architecture.md) before making non-trivial changes. The whole design hangs on nine binary invariants (G1–G9); changes that affect those need explicit human discussion, not just a passing test.

## Hard constraints

These are non-negotiable. Violating any of them turns a PR into a security incident.

1. **Never log real secret values.** Not in `print()`, not in exception messages, not in audit events. The audit log records *decisions* (which secret name, which destination), never *contents*.
2. **Never silent-swallow exceptions.** `except Exception: pass` is forbidden. If you genuinely need to ignore an error, narrow the exception type, add a comment explaining what's being swallowed and why, and emit something observable.
3. **Never change the audit event schema** without bumping the JSON contract version and updating `docs/architecture.md` §4.4. Operators parse this log.
4. **Never weaken the G1–G9 invariants.** If a refactor moves substitution earlier, eliminates an fsync, or relaxes the SNI/Host consistency check, it's a security-affecting change that needs explicit human sign-off.
5. **Never replace `pip install --require-hashes --only-binary :all:`** with looser variants. Both flags exist for a reason. **`pip --require-hashes` at install time is the actual supply-chain enforcement mechanism** (CI runs it in the `test` workflow; pip itself refuses any install where a requirement lacks a matching hash). The structural pre-commit/CI check `scripts/check-lockfile-hashes.py` is a *fast guard* that the lockfile is shaped correctly - it complements but does not replace the install-time check. Every package in `requirements.lock` and `requirements-dev.lock` must carry at least one `--hash=sha256:` line.
6. **Never modify `.github/workflows/*.yml` without re-running `zizmor` and `pinact`.** Specifically: every third-party action reference must be pinned to a 40-character commit SHA (not `@v1` or other mutable tag); every checkout must set `persist-credentials: false`; every job needs an explicit `permissions:` block scoped to least privilege; downloaded artifacts must extract to `/tmp/`, never the workspace. Use `pull_request`, never `pull_request_target`. The existing workflows in this repo are the reference shape, match them.
7. **Never use `pull_request_target`** in any workflow. Forks would get secret access.
8. **Never commit or push.** Open a PR and let the human merge.
9. **Keep AVP single-license Apache-2.0.** Don't vendor code from sources that aren't Apache-2.0-compatible (MIT/BSD/Apache are fine; GPL/LGPL/AGPL/SSPL are not). Designs from prior art may be referenced — see [`CREDITS.md`](./CREDITS.md) — but code is original Python written from the underlying public specs (RFC / vendor docs / standard).

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install --only-binary :all: -e '.[dev]'
.venv/bin/pre-commit install --hook-type pre-commit --hook-type pre-push   # mandatory; CI runs the same checks
```

## The loop

```bash
.venv/bin/pytest -q                                  # tests
.venv/bin/ruff check src tests                       # lint
.venv/bin/ruff format src tests                      # apply formatting
.venv/bin/python -m bandit -c pyproject.toml -r src  # Python SAST
.venv/bin/pre-commit run --all-files                 # full pre-commit pass
```

Pre-commit runs ruff, bandit, TruffleHog (secret scan), Semgrep (pattern SAST), OSV-Scanner (CVE), zizmor, pinact, pytest, and basic hygiene hooks. The three Docker-based hooks gracefully skip if Docker isn't running locally, CI is the authoritative gate. Passing pre-commit locally means CI will pass on the same checks.

## Dependency changes

If your change adds, removes, or version-bumps a dependency in `pyproject.toml`, regenerate **both** lockfiles with the 7-day supply-chain cooldown applied:

```bash
CUTOFF=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00Z"))')
uv pip compile --generate-hashes --exclude-newer "$CUTOFF" \
  pyproject.toml -o requirements.lock
uv pip compile --generate-hashes --exclude-newer "$CUTOFF" --extra dev \
  pyproject.toml -o requirements-dev.lock
```

Two layers enforce this:

- **Pre-commit** (`scripts/check-lockfile-hashes.py` + `scripts/check-lockfile-drift.sh`) - the first script always runs and verifies every pinned package has a `--hash=sha256:` continuation; the second re-compiles with the cooldown and diffs whenever `pyproject.toml` or a lockfile changed. Drift check silently skips if `uv` isn't installed (CI catches it).
- **CI** (`verify-lockfile` job in `.github/workflows/test.yml`) - runs the same hash check and the same `uv pip compile` diff; refuses to merge if either lockfile drifts.

The cooldown is not bypassable without changing the workflow.

## Testing philosophy

- **Behavior, not implementation.** Tests use the public interface (`load_config`, `BindingSpec.matches_scope`, addon hooks). Don't test private helpers directly.
- **No real BWS calls in unit tests.** The BWS client is exercised against a fake. The `tests/smoke/` directory has end-to-end runs gated behind explicit env vars.
- **No real mitmproxy CA in unit tests.** Fixtures only.
- **One behavior per test.** If a test name has "and" in it, it probably wants to be two tests.
- **Add a test before the fix.** If a bug surfaces and no failing test catches it, the PR should add one alongside the change.

## Sensitive files, extra care required

Any change here needs human review and most likely an issue first:

| Path | Why it's sensitive |
|---|---|
| `src/kow/addon.py` | The substitution path. G1, G3, G5, G6 all enforced here. |
| `src/kow/bws.py` | Secret fetch + cache. Misorder = secret leak to wrong destination. |
| `src/kow/audit.py` | The integrity backstop. Do not reorder the fsync - see the "do not reorder" comment in `addon.py`. |
| `src/kow/config.py` | Pydantic validators enforce the invariants. Don't relax them. |
| `.github/workflows/*.yml` | Compromising these compromises the publish path to PyPI. |
| `pyproject.toml` / `requirements.lock` | Supply chain. Regenerate with cooldown if you touch deps. |
| `bindings.example.yaml` | A bad default here would mislead operators into an insecure config. |
| `SECURITY.md` / `docs/architecture.md` | Public threat-model surface. Don't claim invariants we don't actually uphold. |

## Things that are explicitly out of scope

Do not propose changes in these directions without a concrete issue and approval first:

- Egress firewall features - the operator's host firewall handles that
- Multi-tenant routing: single-host design
- Storage backends beyond BWS / GSM / static - the shipped set; a new backend needs an issue first
- Replacing `mitmproxy` with a different proxy engine: the backend integration model assumes mitmproxy's addon API
- AWS SigV4 streaming/chunked payloads, presigned URLs, and SigV4a (ECDSA) - core SigV4 signing shipped (`sigv4`, ADR-0027/ADR-0036); these modes are held back to keep the "agent never holds any AWS credential" invariant

The injector taxonomy is **complete and shipped** — do not treat these as out of scope: static `header`/`body`/`multi`, `oauth2_refresh` (ADR-0017), `oauth2_client_credentials` + `github_app` (ADR-0030), `sigv4` (ADR-0027, S3-hardened ADR-0036), `hmac` + `jwt_bearer` (ADR-0028).

## Commit message style

Imperative, area-prefixed, explain the *why* if non-obvious:

- `addon: forward placeholder verbatim on scope violation (G5)`
- `bws: clamp jitter to ttl/2 to avoid negative effective TTL`
- `tests: cover path glob across multiple segments`
- `docs: correct G7 wording - CA trust is operator-distributed, not enforced by the daemon`

72 chars max on the summary line. Body explains *why* if the diff doesn't.

## Documentation: minimal, in-tree, no bloat

Keep repo docs tight. `README.md` is for users running the proxy. `docs/architecture.md` is the single architectural source of truth, extend existing sections rather than adding new top-level docs. `docs/adapter-architecture.md` covers backend protocol only. `docs/docker.md` covers the container path. Do **not** create new `docs/foo.md` pages for features that fit in an existing section.

When adding feature reference material (filter tables, config examples, etc.):
- Add to the existing architecture section that already mentions the feature.
- Prefer a small table + one worked example over prose.
- Don't duplicate content across `README.md`, `docs/`, and `CHANGELOG.md`: pick one home, link from the others.
- Longer-form rationale (threat model, design alternatives, premortems) lives outside the repo in the maintainer's design-doc archive; the repo carries the result, not the deliberation.

## When in doubt

Default to opening an issue rather than a PR. The maintainer would rather discuss approach for 15 minutes than review a 500-line PR that takes a direction the project won't merge.
