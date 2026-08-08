#!/usr/bin/env bash
# Verify every mechanical version literal in the repo agrees with the single
# source of truth (pyproject.toml [project].version).
#
# Why this exists: v0.4.2 shipped with __init__.py stuck at "0.1.0", and 0.9.0
# nearly shipped with docker-compose.yml stuck at "0.8.0" — both because a
# manual edit bumped pyproject.toml but missed a sibling literal. bump-version.sh
# is the WRITE side (updates all literals at once); this is the READ side that
# FAILS a commit / release when they drift. Wired two ways:
#   1. pre-commit hook (fast feedback whenever a version-bearing file changes);
#   2. scripts/pre-release.sh section 3 calls this so there is ONE definition.
#
# The STRICT set (must equal pyproject) mirrors bump-version.sh's strict set:
#   - src/kow/__init__.py   __version__ = "X.Y.Z"
#   - docker-compose.yml                  image: inflightsec/agent-vault-proxy:X.Y.Z
# The OPTIONAL set (verified only if present — the README intentionally uses an
# unpinned `pipx install agent-vault-proxy`, so absence is legitimate; a STALE
# pin is not):
#   - README.md                           agent-vault-proxy==X.Y.Z
#   - README.md                           git clone -b vX.Y.Z
#
# Exit 0 = aligned. Exit 1 = drift (prints each offender + the fix command).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

TAG_VER=$(python3 -c "import tomllib, pathlib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])")
if [ -z "$TAG_VER" ]; then
    echo "FAIL: could not read [project].version from pyproject.toml" >&2
    exit 1
fi

INIT_VER=$(grep -Eo '__version__[[:space:]]*=[[:space:]]*"[^"]+"' src/kow/__init__.py 2>/dev/null | head -1 | awk -F '"' '{print $2}' || true)
README_INSTALL_VER=$(grep -Eo 'agent-vault-proxy==[0-9]+\.[0-9]+\.[0-9]+' README.md 2>/dev/null | head -1 | awk -F= '{print $NF}' || true)
README_CLONE_VER=$(grep -Eo 'git clone -b v[0-9]+\.[0-9]+\.[0-9]+' README.md 2>/dev/null | head -1 | awk '{print $NF}' | sed 's/^v//' || true)
COMPOSE_VER=$(grep -Eo 'inflightsec/agent-vault-proxy:[0-9]+\.[0-9]+\.[0-9]+' docker-compose.yml 2>/dev/null | head -1 | awk -F: '{print $NF}' || true)

skew=0

# Required: absence OR mismatch is a failure.
check_required() {
    local label="$1" found="$2"
    if [ -z "$found" ]; then
        echo "  ✗ $label: no version literal found (expected $TAG_VER)"
        skew=1
    elif [ "$found" != "$TAG_VER" ]; then
        echo "  ✗ $label: $found  (pyproject.toml says $TAG_VER)"
        skew=1
    fi
}

# Optional: only a present-but-stale literal fails; absence is fine.
check_optional() {
    local label="$1" found="$2"
    if [ -n "$found" ] && [ "$found" != "$TAG_VER" ]; then
        echo "  ✗ $label: $found  (pyproject.toml says $TAG_VER)"
        skew=1
    fi
}

check_required "src/kow/__init__.py   __version__" "$INIT_VER"
check_required "docker-compose.yml                  image tag"   "$COMPOSE_VER"
check_optional "README.md                           install pin" "$README_INSTALL_VER"
check_optional "README.md                           clone tag"   "$README_CLONE_VER"

if [ "$skew" -ne 0 ]; then
    cat >&2 <<EOF

Version literals disagree with pyproject.toml ($TAG_VER).
Fix — never hand-edit one file; bump them all from the source of truth:

  bash scripts/bump-version.sh $TAG_VER

EOF
    exit 1
fi

echo "Version literals aligned == pyproject.toml == $TAG_VER"
