# Changelog

All notable changes to `agent-vault-proxy` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`inject.format` accepts a named placeholder matching the entry key.** Previously the format string had to contain the literal sentinel `{secret}`; now `{<SECRET_NAME>}` works too, where `<SECRET_NAME>` is the entry's YAML key (e.g. `format: "Bearer {ANTHROPIC_API_KEY}"` under a `secrets.ANTHROPIC_API_KEY:` block). The generic `{secret}` form continues to work — operators can pick whichever they prefer. `bindings.example.yaml` and the README "At a glance" snippet now use the named form for readability. Config validation rejects a named placeholder that doesn't match the parent entry's key (catches typos like `{ANTHROPIC_API_KEY}` under a `secrets.ANTHROPIC:` block, which would otherwise inject literal `{ANTHROPIC_API_KEY}` bytes onto the wire).

## [0.4.3], 2026-06-02

Single-line follow-up to v0.4.2. **No proxy code changes** — v0.4.2's proxy runtime was already byte-for-byte identical to v0.4.1 (all v0.4.2 diffs were in `tests/`, `pyproject.toml`, `README.md`, and `CHANGELOG.md`).

### Fixed

- **`src/agent_vault_proxy/__init__.py` `__version__` now agrees with `pyproject.toml`.** The v0.4.2 release bumped `pyproject.toml` to `0.4.2` but left `__version__ = "0.4.1"` in `src/agent_vault_proxy/__init__.py`. The published v0.4.2 wheel installed correctly via `pip` (PyPI metadata = 0.4.2) but reported `agent_vault_proxy.__version__ == "0.4.1"` at runtime. The `wheel-smoke` job in `.github/workflows/test.yml` is designed to catch exactly this skew (its comment lists it as the canonical failure mode) and went red on `main` after the v0.4.2 push.
- **`scripts/smoke-test-wheel.sh` entry-point check switched from `python -m agent_vault_proxy --help` to an import-only check** matching `.github/workflows/test.yml`'s `wheel-smoke` job. mitmdump's argparse behavior on `--help` with a `-s addon` flag is fragile across versions and returns exit 1 in some environments, masking real wheel issues as entry-point failures. The CI job already learned this lesson and switched to importing `agent_vault_proxy`, `agent_vault_proxy.__main__.main`, `agent_vault_proxy.addon`, `agent_vault_proxy.config`, and `agent_vault_proxy.backends.BACKEND_REGISTRY`; the local pre-release tool now does the same. Without this, `scripts/pre-release.sh` step 11 (which invokes `smoke-test-wheel.sh`) couldn't go green.
- **Release-tooling fixes from v0.4.2 are preserved unchanged in v0.4.3** (`tests/pypi-smoke/run.sh` NEGATIVE assertion accepting `"type":"deny"`, `tests/pypi-smoke/docker-compose.yml` empty-default for `TEST_SECRET`).
- **Release handoff now gates on `scripts/pre-release.sh`** between commit and tag — that script's section 3 (Version constants agree?) does the exact pyproject vs `__init__.py` comparison that would have caught the v0.4.2 skew. Order matters: `pre-release.sh`'s first check is `git status --porcelain` for a clean working tree, so it runs AFTER `git commit`, not before. This is a process fix, not a code fix; recorded here for traceability.

### Changed

- Version pointers in `README.md`, `tests/pypi-smoke/README.md`, `tests/pypi-smoke/run.sh` usage examples, `docker-compose.yml` image tag, and `scripts/smoke-test-wheel.sh` usage examples bumped to `0.4.3`. The historical reference to "v0.4.2 changelog" in `tests/pypi-smoke/run.sh:324` is preserved — the harness fix is documented in the v0.4.2 entry.

## [0.4.2], 2026-06-02

Release-tooling-only patch on top of v0.4.1. **No proxy code changes** — v0.4.1's substitution and audit guarantees are unchanged. v0.4.1 was correctly published to PyPI and the core wire-format behavior was verified by the smoke harness's positive test on the published wheel. The release.yml `pypi-install-smoke` gate did its job: it caught a real signal mismatch and held back the GitHub Release until investigation was complete. The investigation found the proxy was behaving correctly; the harness's negative-assertion grep needed updating.

### Fixed (release tooling)

- **`tests/pypi-smoke/run.sh` NEGATIVE assertion** now accepts the `"type":"deny"` audit event in addition to the `"decision":"denied"` / `"decision":"forwarded_unmodified"` shapes. The addon has two distinct deny paths for an unbound destination: (1) the `unmatched_destination_policy: deny` policy gate fires BEFORE placeholder analysis when the request's host is in no binding at all and emits `{"type":"deny","reason":"unmatched_destination",...}`; (2) the `destination_not_in_binding` check inside the inject path fires when a placeholder IS present but the matched secret's bindings don't cover the request host and emits `{"type":"inject_decision","decision":"denied",...}`. The pypi-smoke negative test aims at `example.invalid` (in no binding at all), so the policy gate fires first. The previous grep only knew path (2) and the smoke went red despite the proxy correctly returning 403 + auditing the deny. `tests/docker-e2e/run.sh:236` already greps the `"type":"deny"` shape, so this was a pypi-smoke-only regression introduced when the pypi-smoke harness was first added in v0.4.1.
- **`tests/pypi-smoke/docker-compose.yml`** uses `${TEST_SECRET:-}` instead of the strict `${TEST_SECRET:?...}` for the `avp-init` env reference. The strict form blocked `docker compose down -v` teardown when `TEST_SECRET` wasn't exported, because compose interpolates all referenced vars at parse time even for `down`. The empty default unblocks teardown without weakening the test: `run.sh` still exports the real value before `compose up`, and a manual `compose up` without `TEST_SECRET` produces a broken `secrets.yml` that fails the positive assertion at run time rather than at compose time.

### Changed

- README.md and tests/pypi-smoke/README.md version pointers bumped from `0.4.1` to `0.4.2`. The "Status" prose now leads with the v0.4.2 framing (release-tooling patch only; v0.4.1 guarantees unchanged) before recapping v0.4.1 and v0.4.0.

## [0.4.1], 2026-05-30

External security review of the v0.4.0 release surface flagged a handful of items as "must fix before high-value credentials." This release lands those.

### Changed

- **Dockerfile installs runtime dependencies from the hash-pinned lockfile.** Previous Docker builds installed the project wheel directly, which resolved dependency lower-bound ranges (`mitmproxy>=11`, `pydantic>=2.7`, etc.) against live PyPI at build time and produced an image whose deps were unpinned even though `requirements.lock` exists. The Dockerfile now runs `pip install --require-hashes --only-binary :all: -r requirements.lock` first, then installs the project wheel with `--no-deps`. Matches the CI install posture.
- **`bindings.example.yaml` defaults to `unmatched_destination_policy: deny`.** New operators copying the example get fail-closed unbound-destination behavior; the schema default in `Config` stays `forward_unmodified` for backward compatibility.

### Added (security hardening)

- **`extra="forbid"` on every config model** (`InjectSpec`, `BindingSpec`, `SecretSpec`, `CacheSpec`, `AuditSpec`, `PreflightSpec`, `BackendBlock`, `Config`). Operator typos like `method:` for `methods:` are now rejected at config load instead of silently producing an unscoped binding. `BwsConfig` already had this guard from v0.4.0.
- **Structural placeholder validation.** Each `secrets[].placeholder` must be non-empty, at least 24 characters, contain the literal marker `PLACEHOLDER`, be printable, be unique across the file, and not be a substring of any other placeholder. The substring check matters because the addon detects placeholders via `in` matching on the request header: an overlap would route the wrong real secret onto the wire.
- **Ambiguous multi-placeholder match denial.** If a single header value contains placeholders for two distinct configured secrets, the addon now refuses to inject, returns 400, and audits `inject_decision: denied, reason: ambiguous_placeholder_match` with `matched_secret_names: [...]`. Belt-and-suspenders on top of the config-load substring check: a request constructed by a buggy or hostile caller could embed two distinct placeholders even when the config itself is clean.
- **Tighter scopes throughout `bindings.example.yaml`.** Every binding in the example now declares `methods:`; nine of twelve also declare `paths:`. The two remaining bindings without `paths:` (Anthropic MCP gateway, `*.claude.com`) have documented reasons. GitHub PAT bindings gained `/repos/**`, `/user`, `/users/**`, `/orgs/**`, `/search/**` path scope and `uploads.github.com` is now `methods: [POST, PUT]` with `paths: ["/repos/**/releases/**"]`. Jira composite binding gained `methods: [GET]` + `paths: ["/rest/**"]`.

### Added (tooling)

- **`static` secrets backend** (`backend: {type: static, config: {path: ...}}`). Reads `{name: value}` pairs from a YAML file on disk, refuses world-readable files, emits a clear startup warning that this backend is for dev / integration testing only. Drives the new Docker E2E harness; available for anyone who needs a plaintext-file backend during local development.
- **`tests/docker-e2e/`** — scripted end-to-end integration test. Builds the production Dockerfile, stands the proxy up next to an HTTP echo upstream on an isolated bridge network, and asserts that (a) the upstream's echoed `Authorization` header contains the real secret and not the placeholder, (b) the audit log records `inject_decision: allowed`, (c) an unbound destination is denied with 403 and audited. Runs as a CI job (`e2e-docker` in `.github/workflows/test.yml`) on every PR; runnable locally via `bash tests/docker-e2e/run.sh` or `pytest -m docker`. The compose stack uses a one-shot `avp-init` busybox container running as root to copy `bindings.yaml` + `secrets.yml` into a named `avp-e2e-config` volume with `chown 65532:65532` + correct modes (0644/0600); the avp service then `depends_on: avp-init: condition: service_completed_successfully` and mounts the volume read-only. This sidesteps the bind-mount UID mismatch that would otherwise prevent the avp process (UID 65532) from reading host-UID-owned config files.

### Added (release tooling)

- **`pypi-install-smoke` release gate.** A new job in `.github/workflows/release.yml` runs after `publish-pypi` and before `github-release`: waits 120s for PyPI CDN propagation, then runs the smoke harness against the freshly-published wheel pulled from real PyPI in a clean container. Asserts the proxy starts and substitutes a placeholder end-to-end against an HTTP echo upstream. If the smoke fails, the GitHub Release isn't created — the published PyPI version is irreversible at that point, so the operator yanks it manually rather than shipping a broken Release page.
- **`pypi-canary` daily workflow** (`.github/workflows/pypi-canary.yml`). Runs the same smoke harness at 03:00 UTC against the latest PyPI release. Catches issues a one-shot post-publish smoke can't surface: transitive deps yanked weeks after release, Python point-version regressions, PyPI CDN inconsistencies, breaking `mitmproxy` releases against our wheel. Failures open (or reuse) a GitHub issue tagged `pypi-canary` so the operator sees it without watching the Actions tab.
- **`scripts/build-and-smoke-wheel.sh`** — pre-tag dry-run. Builds the wheel locally via `uvx --from build pyproject-build` (no project .venv pollution) and runs the smoke harness in `--local-wheel` mode against it. Same code path as the post-publish smoke; the only variable between local and CI is the install source (local file vs PyPI URL). Run before every tag push: if green locally, the published smoke is green.
- **`tests/pypi-smoke/`** — the harness itself: `Dockerfile` + `docker-compose.yml` stand up the proxy against an HTTP echo upstream on an isolated network, `bindings.yaml` declares a single test binding, `run.sh` orchestrates positive (substitution-happened) and negative (fail-closed-on-unbound-destination) assertions, accepts either `--local-wheel <path>` for the pre-tag dry-run or a bare version for PyPI-mode.

### Fixed (security)

- **G6 regression: addon now fails closed on any uncaught backend exception.** Previously the addon caught only `(BackendUnavailableError, SecretNotFoundError)` around `client.get(...)`. A backend that raised any other exception type — for example, the static backend hitting `PermissionError` on a misconfigured bind mount — would let the exception bubble to mitmproxy, which logged the traceback and **forwarded the request unmodified** with the placeholder bytes intact. The single-secret and composite paths now both catch `Exception` as a final clause, return 503, and emit `inject_decision: denied, reason: secret_fetch_error:<ExceptionType>` (or `composite_fetch_error:` on the composite path) with the exception class in the audit reason. Discovered via the docker-e2e diagnostic dump 2026-05-30 — the harness's mount-permission gap surfaced the silent fail-open class.
- **`StaticSecretsBackend` now converts `OSError` on the secrets-file read to `BackendUnavailableError`.** Previously `path.read_text()` was outside the `try` block, so `PermissionError` / read-time `OSError` propagated unwrapped. With the addon's broadened catch above this would already be safe, but converting at the backend layer keeps the audit reason consistent (`secret_unavailable:BackendUnavailableError`) regardless of which backend produced the failure.
- **E2E `dump_diagnostics` no longer `cat`s `secrets.yml`.** The harness uses a fake test value, but the pattern would leak real credentials if copied into a production diagnostic path. The diagnostic now prints `stat` only (mode + UID:GID + size) — enough to confirm the file is present, owned, and at the expected mode without surfacing the value. The standalone `avp-e2e-diagnose.sh` handoff script got the same treatment.
- **`tests/docker-e2e/run.sh` input-validates `REAL_SECRET`** against `^[A-Za-z0-9_-]+$` before exporting `TEST_SECRET`. The avp-init heredoc embeds the value into a YAML string literal, and a value containing `"`, `\n`, or `\\` could break the YAML or inject extra keys. The hardcoded harness value satisfies the constraint; this guard exists to keep future edits from regressing into a YAML-injection-shaped path.
- **`_filter_b64decode` also catches `UnicodeEncodeError`** from `v.encode("ascii")`. Previously, a composite secret containing any non-ASCII character would have raised an uncaught exception in the template path and bypassed the addon's `render_failed` audit boundary. The catch tuple is now `(binascii.Error, ValueError, UnicodeEncodeError, UnicodeDecodeError)` — covers all four documented failure modes of the single `b64decode(v.encode("ascii"), validate=True).decode("utf-8")` chain.
- **`pip-audit` install pinned to exact version (`==2.9.0`)** rather than the broader `>=2.7,<3` range. Closes the bootstrap loop where a malicious pip-audit release in the version range could silently report "no CVEs" against the lockfile it audits. Bump this pin when Dependabot opens its PR.

### Fixed (follow-up review)

A second-pass code review of the v0.4.0 surface raised four landable items. Three deferred items (a perf tweak, a perf bound to document, and a composite-fetch availability edge case) are noted below the fixed list.

- **Host matching is case-insensitive.** `host_matches_pattern` lowercases both inputs, and the `BindingSpec.host` field validator normalises at config-load with a clear log warning when the input was mixed case. DNS is case-insensitive but the previous string compare was not, so an operator who pasted `API.OpenAI.com` from a vendor doc got a silent miss at request time instead of a binding-match. Now: load-time warning + match-time normalisation.
- **`base64.b64decode` catches `ValueError` as well as `binascii.Error`.** Python 3.12's `b64decode(validate=True)` raises `ValueError` (not `binascii.Error`) on some malformed inputs. The previous `except (binascii.Error, UnicodeDecodeError)` tuple would have let the `ValueError` propagate out of the composite-render path and bypass the addon's `render_failed` audit boundary.
- **Backend config validated eagerly at config-load.** `BackendBlock` runs an after-validator that validates `backend.config` against the per-backend pydantic model (e.g., `BwsConfig`) from `BACKEND_REGISTRY[type]`. Typos under `backend.config` (e.g., `organization_iddd`) now fail at `Config.model_validate` rather than at the first secret fetch. `build_backend()` reuses the eagerly-validated instance.
- **Container detection covers cgroup v2.** `_in_container()` now recognises the cgroup v2 + cgroup-namespace signature (PID 1's cgroup is bare `0::/` rather than `0::/init.scope` on a bare-metal systemd host). Previously the `BWS_ACCESS_TOKEN`-via-env and root-UID-in-container preflight warnings were silently muted on modern runtimes that didn't drop a `/.dockerenv` stub.

### Deferred from the same review

- **`audit.AuditWriter` uses `os.fsync` rather than `os.fdatasync`.** For an append-only JSONL log, `fdatasync` would be sufficient and lower latency. Correctness is unaffected; throughput tweak parked for a future release if anyone reports the fsync bound is hurting them.
- **O(N×M) header scan in `_find_placeholder_matches`.** Fine for N ≤ 20 in practice (typical credential count per proxy). Worth indexing once someone runs a proxy with O(100) bindings; for the current scale it would be premature optimisation.
- **`composite_fetch` discards-and-retries the whole assembly on a flush between component fetches.** Correctness is preserved (fail-closed via `_StaleAfterFlushError`); under frequent secret rotation, composites will retry more often than single-secret fetches. Reordering the fetch loop to hold the flush lock across all component reads would touch the flush-invariant and isn't worth the risk for an availability-under-rotation edge case.

## [0.4.0], 2026-05-29

First public release.

The adapter refactor (originally proposed for v0.3.0 in `docs/adapter-architecture.md`) is bundled with composite secrets and shipped together as v0.4.0.

### Added

- **Composite secret bindings (`inject.template` + `compose:`).** Bindings can now assemble a credential from 1-4 atomic BWS values at fetch time, instead of requiring the operator to pre-concatenate values in BWS (which made single-key rotation silently stale). Templates use Jinja2 syntax evaluated through `ImmutableSandboxedEnvironment` with a strict filter/function whitelist (`b64encode`, `b64decode`, `sha256`, `urlencode`, `hmac_sha256`, `hmac_sha512`). An AST-level deny-by-default validator at config-load rejects every Jinja2 construct outside the small set the proxy supports, class-walk escapes, control flow, attribute traversal, subscript, arithmetic are all structurally impossible. See `bindings.example.yaml` for a Jira / Atlassian Cloud example and `docs/architecture.md` §4.2 for the reference table and architectural sketch.
- `CachingSecretsClient.composite_fetch(names)`: atomically fetches multiple secrets under a single generation snapshot; empty BWS values raise `BackendUnavailableError` (never compose partial credentials); flush during assembly raises `_StaleAfterFlushError` so the caller restarts.
- Same-UUID heuristic: when two distinctly-named compose entries resolve to the same value (suggesting an operator typo pointing both names at one BWS secret), the addon logs a one-shot WARNING to its own logger. The warning never includes the actual secret value.
- `jinja2 >= 3.1` is now a declared direct dependency (previously transitive via mitmproxy).
- **`SecretsBackend` protocol + adapter architecture.** `bindings.yaml` uses a discriminated `backend: {type: bws, config: {...}}` block. `agent_vault_proxy.backends.bws.BitwardenBackend` is the reference implementation; new backends (1Password Service Accounts, HashiCorp Vault, Doppler, etc.) plug in by registering a `type` discriminator. `agent_vault_proxy.caching.CachingSecretsClient` provides generic TTL+jitter+LRU+singleflight caching on top of any backend. Protocol design in [`docs/adapter-architecture.md`](docs/adapter-architecture.md).
- **mypy in CI + pre-commit.** Strict-ish config (`warn_return_any`, `warn_unused_ignores`, `no_implicit_optional`, `check_untyped_defs`); third-party libs without stubs (`mitmproxy`, `bitwarden_sdk`, `yaml`) explicitly silenced.
- **Ruff C90 cyclomatic-complexity gate** (`max-complexity = 10`). Three pre-existing functions carry `# noqa: C901` with one-line provenance justifications.
- **Hash-pinned dev dependencies.** `requirements-dev.lock` is now hash-pinned alongside `requirements.lock`. New helper scripts: `scripts/check-lockfile-hashes.py` (zero-dep structural check - every pinned package must carry a `--hash=sha256:` continuation) and `scripts/check-lockfile-drift.sh` (re-runs `uv pip compile` with the 7-day cooldown and diffs against committed). Both wired into pre-commit; the CI `verify-lockfile` job runs the same hash check before the drift diff.

### Changed

- Config: `InjectSpec.format` is now `Optional[str]` and a peer of the new `InjectSpec.template: Optional[str]`. Exactly one of the two must be set per binding (validator-enforced). Existing `inject.format` bindings continue to work unchanged.
- Addon: request handlers now capture `(config, client, audit)` at handler entry, preventing a mid-request `configure()` reload from producing a torn state (Silas F3).
- Dependency advances captured by the 7-day-cooldown regen: `bitwarden-sdk` 2.0.0 → 2.1.0, `certifi` 2026.4.22 → 2026.5.20, `click` 8.4.0 → 8.4.1, `ruff` 0.15.13 → 0.15.14.
- **Security CI stack refactored to drop GitHub Advanced Security dependency.** CodeQL (Python SAST) replaced with **Bandit + Semgrep** (community rulesets: `p/security-audit` + `p/python` + `p/secrets`). Gitleaks (which required a paid license for org-owned repos as of Aug 2022) replaced with **TruffleHog** (AGPL-3, free for everyone). OSV-Scanner switched from the action wrapper to direct binary install (the wrapper passes `scan-args` as a single positional arg, breaking multi-flag invocation). All security jobs now gate the merge via job-fail instead of SARIF-upload to the Security tab, workflows portable to any git host, no GHAS settings to babysit. The same three Docker-based scanners (TruffleHog, OSV-Scanner, Semgrep) also run in pre-commit so most commits hit the same gates locally before push.

### Removed

- `agent_vault_proxy.bws` module (the `BwsClient` facade) and the top-level `bws:` config block deprecation shim in `config.py`. v0.4.0 is the first public release; there are no public v0.2.0 users to migrate. New `bindings.yaml` files must use the `backend: {type: bws, config: {...}}` form (shown in `bindings.example.yaml`).
- CodeQL job from `.github/workflows/security.yml` (replaced by Bandit + Semgrep: see above).
- Gitleaks pre-commit hook + CI job (replaced by TruffleHog - see above).

## [0.2.0], 2026-05-27

### Added

- Per-binding HTTP method and URL path scope. Bindings can declare `methods: [GET, …]` and `paths: ["/repos/*"]`. Out-of-scope requests have their placeholder forwarded verbatim (G5 preserved) and emit a `binding_scope_violation` audit event.
- Custom path glob grammar: `*` matches one URL segment, `**` matches any number of segments.
- `proxy_restart` audit event emitted on daemon startup, completing the G9 "restart itself is audited" guarantee.
- LRU cache eviction in `BwsClient` driven by the `cache.max_entries` setting (was previously validated in config but unenforced).
- Per-entry expiry jitter (`cache.jitter_seconds`, clamped to `ttl/2`) so cached secrets don't all expire at the same wall-clock tick and stampede BWS at once.
- Hash-pinned production dependencies in `requirements.lock` (generated via `uv pip compile --generate-hashes`).
- Public architecture documentation in `docs/architecture.md` covering threat model, atomic guarantees, request lifecycle, hardening checklist, supply-chain controls, premortem, and accepted residual risks.
- Hardened systemd unit example and CA rotation runbook in `docs/systemd-unit.md`.
- Security disclosure policy in `SECURITY.md` with explicit in/out-of-scope and a coordinated-disclosure example timeline.
- CI workflows:
  - `test.yml`: pytest on Python 3.12 + 3.13, ruff lint, ruff format check, lockfile drift detection with 7-day cooldown enforcement.
  - `security.yml`, OSV-Scanner (SCA), CodeQL (Python SAST), Gitleaks (secret scan), Zizmor (workflow-security self-audit), `actions/dependency-review-action` on PRs.
  - `release.yml` - OIDC publish to PyPI (no long-lived API token); tag-triggered, with version-tag-matches-pyproject check.
- Pre-commit hook chain mirroring CI: ruff, bandit, gitleaks, zizmor, pinact, pytest, plus file hygiene hooks.

### Changed

- Secret substitution in `addon.py` now uses `str.replace()` instead of `str.format()`. `str.format()` accepts attribute access (`{secret.__class__.…}`), which a buggy or hostile `bindings.yaml` could exploit to traverse internals of the substituted string. `str.replace()` is a literal substitution, full stop.
- Audit log: synchronous `fsync()` is now applied to **every** event (the previous documentation incorrectly suggested asynchronous batching for `upstream_response`: that path was never implemented, and we now describe what actually ships).
- `bindings.example.yaml` placeholders generalized to `GITHUB_PAT` instead of operator-specific names.
- EU and US BWS regions are now both shown in `bindings.example.yaml`, with EU URLs as commented-out overrides rather than defaults.
- All GitHub Actions workflows pin every action to a commit SHA (not a version tag) and use `persist-credentials: false` on every checkout.

### Security

- Both example GitHub PAT bindings now declare `methods: [GET]` on `api.github.com`, closing the laundering-via-public-gist surface (T-1.5) for either identity.
- CI install step now uses `pip install --require-hashes --only-binary :all:`, wheels-only, no source distributions, no install-time script execution.
- Lockfile regeneration uses `uv pip compile --exclude-newer "<7d ago>"` to enforce a 7-day supply-chain cooldown on every dependency. CI re-validates this on every PR.

### Removed

- "Hot-reload of `bindings.yaml` on file mtime change" documentation. The feature was never implemented (the addon's `configure()` hook only fires when the option name changes, not when the file content changes). Re-loading currently requires a service restart; auto-reload is on the v0.3.0 list.

## [0.1.0], 2026-05-17

Initial single-operator deployment. Not published publicly.

### Added

- mitmproxy addon with config loader, BWS in-process fetch + cache, header injection.
- `User=avp` systemd unit with full sandboxing.
- Audit log with `chattr +a`.
- Per-host CA installed at `/etc/agent-vault-proxy/ca.pem`.
- Pilot bindings: `ANTHROPIC_API_KEY` + `mcp-proxy.anthropic.com` + `*.claude.com`, plus `OPENAI_API_KEY` and per-identity GitHub PATs.

[Unreleased]: https://github.com/inflightsec/agent-vault-proxy/compare/v0.4.3...HEAD
[0.4.3]: https://github.com/inflightsec/agent-vault-proxy/releases/tag/v0.4.3
[0.4.2]: https://github.com/inflightsec/agent-vault-proxy/releases/tag/v0.4.2
[0.4.1]: https://github.com/inflightsec/agent-vault-proxy/releases/tag/v0.4.1
[0.4.0]: https://github.com/inflightsec/agent-vault-proxy/releases/tag/v0.4.0
[0.2.0]: https://github.com/inflightsec/agent-vault-proxy/releases/tag/v0.2.0
[0.1.0]: https://github.com/inflightsec/agent-vault-proxy/releases/tag/v0.1.0
