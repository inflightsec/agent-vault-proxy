#!/usr/bin/env bash
#
# Bump every mechanical version reference in the repo from the current
# pyproject.toml value to a new value, in a single command.
#
# Why this exists: agent-vault-proxy carries the version literal in
# multiple files that all need to agree at release time. v0.4.2 shipped
# with src/agent_vault_proxy/__init__.py stuck at "0.4.1" because the
# bumper only edited pyproject.toml. This script makes that class of
# bug structurally impossible: one command updates every known location,
# and scripts/pre-release.sh section 3 then validates the result.
#
# Usage:
#   bash scripts/bump-version.sh <new-version>      # e.g. 0.5.0 (no leading v)
#
# What gets bumped (the STRICT set, pre-release.sh section 3 verifies):
#   1. pyproject.toml                              version = "X.Y.Z"
#   2. src/agent_vault_proxy/__init__.py           __version__ = "X.Y.Z"
#   3. README.md                                   pip install agent-vault-proxy==X.Y.Z
#                                                  git clone -b vX.Y.Z
#   4. docker-compose.yml                          image: ...:X.Y.Z
#
# What also gets bumped (the SOFT set — usage examples in docs):
#   5. tests/pypi-smoke/README.md                  example commands
#   6. tests/pypi-smoke/run.sh                     header usage block
#   7. scripts/smoke-test-wheel.sh                 --pypi <version> example
#
# What this script does NOT touch (operator must edit manually):
#   - CHANGELOG.md                                 add the new [X.Y.Z] entry
#                                                  with release notes; update the
#                                                  footer link table and the
#                                                  [Unreleased] compare base
#   - README.md "Status" section prose             the leading paragraph that
#                                                  describes what the new release
#                                                  is — prose changes meaning
#                                                  between versions, not a
#                                                  mechanical bump
#
# After this script: edit CHANGELOG.md + README.md Status prose, then
# run scripts/pre-release.sh, then commit + tag + push. The CONTRIBUTING.md
# "Releasing" section documents the full loop.

set -euo pipefail

# --- Validate args ---------------------------------------------------
if [ $# -ne 1 ]; then
    echo "Usage: $0 <new-version>" >&2
    echo "  e.g. $0 0.5.0   (no leading v)" >&2
    exit 2
fi

NEW="$1"
if ! echo "$NEW" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "FAIL: version must be X.Y.Z (no leading v, no suffix). Got: $NEW" >&2
    exit 2
fi

# --- Cwd: repo root --------------------------------------------------
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# --- Read current version from pyproject.toml (source of truth) ------
if [ ! -f pyproject.toml ]; then
    echo "FAIL: pyproject.toml not found at $REPO_ROOT" >&2
    exit 1
fi
CURRENT=$(grep -E '^version[[:space:]]*=' pyproject.toml | head -1 | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')

if [ -z "$CURRENT" ]; then
    echo "FAIL: could not parse current version from pyproject.toml" >&2
    exit 1
fi

if [ "$CURRENT" = "$NEW" ]; then
    echo "Already at $NEW — nothing to do."
    exit 0
fi

echo "Bumping $CURRENT -> $NEW"
echo ""

# --- portable in-place sed (BSD vs GNU) ------------------------------
# macOS sed requires `sed -i '' ...`; GNU sed accepts `sed -i ...`.
sed_inplace() {
    if sed --version >/dev/null 2>&1; then
        sed -i "$@"
    else
        sed -i '' "$@"
    fi
}

# --- bump (STRICT set — pre-release.sh section 3 enforces these) -----

# 1. pyproject.toml -- only the project version line, not [tool.*]
#    version refs.
sed_inplace -E "0,/^version[[:space:]]*=/s|^version[[:space:]]*=[[:space:]]*\"$CURRENT\"|version = \"$NEW\"|" pyproject.toml
echo "  [strict] pyproject.toml                  version = \"$NEW\""

# 2. __init__.py
sed_inplace -E "s|^__version__[[:space:]]*=[[:space:]]*\"$CURRENT\"|__version__ = \"$NEW\"|" \
    src/agent_vault_proxy/__init__.py
echo "  [strict] src/agent_vault_proxy/__init__.py  __version__ = \"$NEW\""

# 3a. README.md install line: agent-vault-proxy==X.Y.Z
sed_inplace -E "s|agent-vault-proxy==$CURRENT|agent-vault-proxy==$NEW|g" README.md
echo "  [strict] README.md                       agent-vault-proxy==$NEW"

# 3b. README.md clone tag: git clone -b vX.Y.Z
sed_inplace -E "s|git clone -b v$CURRENT|git clone -b v$NEW|g" README.md
echo "  [strict] README.md                       git clone -b v$NEW"

# 4. docker-compose.yml image: inflightsec/agent-vault-proxy:X.Y.Z
sed_inplace -E "s|inflightsec/agent-vault-proxy:$CURRENT|inflightsec/agent-vault-proxy:$NEW|g" \
    docker-compose.yml
echo "  [strict] docker-compose.yml              image: ...:$NEW"

# --- bump (SOFT set — usage examples in docs) ------------------------

# 5. tests/pypi-smoke/README.md (every occurrence of CURRENT)
if [ -f tests/pypi-smoke/README.md ]; then
    sed_inplace "s|$CURRENT|$NEW|g" tests/pypi-smoke/README.md
    echo "  [soft]   tests/pypi-smoke/README.md       usage examples -> $NEW"
fi

# 6. tests/pypi-smoke/run.sh — header usage block only (lines 24-35).
#    Other refs inside the script may be historical (e.g., "v0.4.2
#    changelog" in the negative-assertion comment) and must NOT be
#    touched. Scope sed to the header lines.
if [ -f tests/pypi-smoke/run.sh ]; then
    sed_inplace -E "24,35s|$CURRENT|$NEW|g" tests/pypi-smoke/run.sh
    echo "  [soft]   tests/pypi-smoke/run.sh          header usage -> $NEW"
fi

# 7. scripts/smoke-test-wheel.sh — `--pypi <version>` example.
if [ -f scripts/smoke-test-wheel.sh ]; then
    sed_inplace -E "s|--pypi $CURRENT|--pypi $NEW|g" scripts/smoke-test-wheel.sh
    sed_inplace -E "s|--pypi requires a version, e\.g\. --pypi $CURRENT|--pypi requires a version, e.g. --pypi $NEW|g" \
        scripts/smoke-test-wheel.sh
    echo "  [soft]   scripts/smoke-test-wheel.sh     --pypi $NEW example"
fi

echo ""
echo "Done. Now:"
echo ""
echo "  1. Edit CHANGELOG.md — add a new ## [$NEW], $(date +%Y-%m-%d) entry,"
echo "     update [Unreleased] compare to v$NEW, add [$NEW] footer link."
echo "  2. Edit README.md Status section prose — lead with the v$NEW framing,"
echo "     recap previous releases."
echo "  3. git add -A and run scripts/pre-release.sh to validate."
echo "  4. If green: git commit + git tag -a v$NEW + git push origin main + git push origin v$NEW."
echo ""
echo "See CONTRIBUTING.md \"Releasing\" for the full loop."
