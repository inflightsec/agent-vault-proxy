# Changelog

All notable changes to `agent-vault-proxy` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No changes pending._

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
- `bindings.example.yaml` placeholders generalized to `GITHUB_PAT_WORK` / `GITHUB_PAT_PERSONAL` instead of operator-specific names.
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

[Unreleased]: https://github.com/inflightsec/agent-vault-proxy/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/inflightsec/agent-vault-proxy/releases/tag/v0.4.0
[0.2.0]: https://github.com/inflightsec/agent-vault-proxy/releases/tag/v0.2.0
[0.1.0]: https://github.com/inflightsec/agent-vault-proxy/releases/tag/v0.1.0

