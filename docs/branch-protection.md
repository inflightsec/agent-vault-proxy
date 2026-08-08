# Branch protection: recommended GitHub settings

The CI workflows are only one half of the supply-chain story. The other half is making sure nothing reaches `main` (or a release tag) without passing them. The settings below are what we use on `inflightsec/agent-vault-proxy`; treat them as a defensible baseline rather than a fixed policy.

Apply via **Settings → Branches → Branch protection rules** and **Settings → Tags → Tag protection rules**.

## `main` branch ruleset

| Setting | Value | Reason |
|---|---|---|
| Require a pull request before merging | ✓ | No direct pushes to main, even from maintainers. |
| Require approvals | 1 | One reviewer minimum. For a solo project, this means the maintainer's own PRs need their own self-approval before merge: slight friction is the point. |
| Dismiss stale approvals when new commits are pushed | ✓ | Force re-review after rebase/fixup. |
| Require review from Code Owners | ✓ (when `CODEOWNERS` is added) | Routes security-sensitive areas (`src/kow/`, `.github/workflows/`) to the right reviewer. |
| Require status checks to pass before merging | ✓ | The CI must be green; see "Required checks" below. |
| Require branches to be up to date before merging | ✓ | Forces rebase against the latest `main` so the checks ran against the actual merge state. |
| Require conversation resolution before merging | ✓ | No unresolved review comments. |
| Require signed commits | ✓ | GPG or SSH signed commits only. |
| Require linear history | ✓ | No merge commits: keep `git log` readable. |
| Require deployments to succeed before merging | (off) | We don't gate merge on deploy. |
| Lock branch | ✗ | Keep merges possible. |
| Do not allow bypassing the above settings | ✓ | Including for admins. The maintainer can self-disable in an emergency, but it leaves an audit trail. |
| Restrict who can push to matching branches | ✓ - empty list | Combined with "Require a PR before merging", this blocks direct push. |
| Allow force pushes | ✗ | Never. |
| Allow deletions | ✗ | Never. |

### Required status checks

The set below maps 1:1 to the jobs in `.github/workflows/`. Names match exactly.

- `test / test (3.12)`: pytest + ruff on Python 3.12
- `test / test (3.13)`, pytest + ruff on Python 3.13
- `test / verify-lockfile` - lockfile-drift detection with 7-day cooldown
- `security / osv-scan` - CVE check against both lockfiles
- `security / trufflehog`: verified-only secret scan over full history
- `security / bandit`: Python-specific SAST
- `security / semgrep`, pattern SAST (security-audit + python + secrets rulesets)
- `security / zizmor` - workflow self-audit
- `security / dependency-review` (PR-only - required for PR merge, not for direct push since direct push is blocked anyway)

## Tag protection: `v*`

Releases are tag-driven. A maliciously-pushed tag would publish a malicious version to PyPI via the trusted-publisher OIDC flow.

| Setting | Value |
|---|---|
| Pattern | `v*` |
| Restricted | ✓ |
| Allowed actors | the maintainer(s) authorized to cut releases |

## PyPI trusted publisher

The release workflow uses PyPI's OIDC trusted-publishing flow. There is no long-lived API token in repo secrets to steal. Configure on PyPI at <https://pypi.org/manage/account/publishing/>:

| Field | Value |
|---|---|
| PyPI project name | `agent-vault-proxy` |
| Owner | `inflightsec` |
| Repository | `agent-vault-proxy` |
| Workflow | `release.yml` |
| Environment | `pypi` |

Pair with the `pypi` environment on the GitHub side (**Settings → Environments → New environment**) and add a deployment branch rule restricting it to tags matching `v*`.

## Secrets posture

- **Zero** repo secrets for the publish path (OIDC handles it).
- The default `GITHUB_TOKEN` is read-only at the top level; only the publish job gets `id-token: write`, only the release job gets `contents: write`.
- Forks cannot access secrets - the workflows use `pull_request` (not `pull_request_target`).

## Dependabot (recommended)

Enable Dependabot for `pip` and `github-actions` ecosystems via `.github/dependabot.yml`. Dependabot PRs go through the same CI as any other PR, including the 7-day cooldown gate, so you cannot accidentally merge a same-day dependency bump even if Dependabot opens one.

## Periodic review

Schedule a quarterly review of:

- Pre-commit hook versions (`pre-commit autoupdate`)
- Workflow action SHAs (`pinact run .github/workflows/*.yml`)
- The maintainer list on the PyPI trusted publisher and tag-protection allow-list
- The supported-versions table in `SECURITY.md`
