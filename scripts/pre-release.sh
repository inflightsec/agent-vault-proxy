#!/usr/bin/env bash
#
# Release-time gate for kow.
#
# Run before any `git tag v0.x.y && git push --tags`. Mirrors what CI
# runs but in one local pass, plus a few release-specific checks that
# CI doesn't gate on (version alignment, CHANGELOG section presence,
# wheel install in a clean container).
#
# Why a separate script (not a pre-commit hook): the cost is too high
# for per-commit (wheel build + e2e harness = ~2-3 min). A pre-tag gate
# is the right pace — runs maybe once a week, blocks the high-stakes
# action (a public PyPI publish that's hard to undo).
#
# Designed to be runnable from a fresh terminal — no assumed venv,
# everything explicit. Uses the repo's .venv if it exists; falls back
# to system Python otherwise.
#
# Usage:
#
#   bash scripts/pre-release.sh                  # run everything
#   SKIP_E2E=1 bash scripts/pre-release.sh       # skip the Docker e2e (~90s)
#   SKIP_WHEEL=1 bash scripts/pre-release.sh     # skip the wheel smoke (~30s)
#   SKIP_HEAVY=1 bash scripts/pre-release.sh     # skip both
#
# Exit 0 = ready to tag. Non-zero = something to fix first.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ── Output helpers ────────────────────────────────────────────────────────
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
header() { printf '\033[1;36m── %s ──\033[0m\n' "$*"; }

# ── venv selection ────────────────────────────────────────────────────────
if [ -x "$REPO_ROOT/.venv/bin/python" ]; then
    PY="$REPO_ROOT/.venv/bin/python"
    PYTEST="$REPO_ROOT/.venv/bin/pytest"
    RUFF="$REPO_ROOT/.venv/bin/ruff"
    MYPY="$REPO_ROOT/.venv/bin/mypy"
else
    yellow "no .venv found at $REPO_ROOT/.venv — using system Python"
    PY=python3
    PYTEST=pytest
    RUFF=ruff
    MYPY=mypy
fi

# ── Track failures and report at the end ─────────────────────────────────
FAILED=()
fail() {
    FAILED+=("$1")
    red "✗ $1"
}
pass() {
    green "✓ $1"
}

# ============================================================================
# 1. Working tree is clean
# ============================================================================
header "1. Working tree clean?"
if [ -n "$(git status --porcelain)" ]; then
    red "Uncommitted changes:"
    git status --short >&2
    fail "working tree has uncommitted changes — commit or stash before tagging"
else
    pass "working tree clean"
fi

# ============================================================================
# 2. No staged files match .gitignore
#    (Catches the tests/docker-e2e/bindings.yaml-class trap — a file that
#    LOOKS staged but won't actually land on the remote.)
# ============================================================================
header "2. No tracked files matched by .gitignore?"
# Iterate tracked files; check-ignore exits 0 when a file IS ignored.
# A tracked-but-ignored file means .gitignore added a rule after the file
# was tracked; the rule has no effect locally but trips up fresh clones.
TRACKED=$(git ls-files)
ignored_tracked=()
while IFS= read -r f; do
    if git check-ignore -q "$f" 2>/dev/null; then
        ignored_tracked+=("$f")
    fi
done <<< "$TRACKED"
if [ ${#ignored_tracked[@]} -ne 0 ]; then
    red "These tracked files match a .gitignore rule:"
    printf '  %s\n' "${ignored_tracked[@]}" >&2
    fail "tracked files match .gitignore — scope the rule or untrack the files"
else
    pass "no tracked files matched by .gitignore"
fi

# ============================================================================
# 3. Version alignment: pyproject.toml is the source of truth — every
#    other version-tracking location in the repo must agree.
#    (Catches the silent skew where pyproject went 0.4.0 but __init__
#    stayed "0.1.0" through multiple releases — v0.4.2 shipped with
#    exactly this kind of skew. The check below is wider than just
#    __init__.py: it covers every mechanical version reference that
#    bump-version.sh writes to.)
# ============================================================================
header "3. Version constants agree?"
TAG_VER=$("$PY" -c "
import tomllib, pathlib
print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])
")

# Delegated to scripts/check-version-alignment.sh so the pre-commit hook
# (id: version-alignment) and this release gate share ONE definition of
# "aligned" — the two literal lists can't drift apart, which would itself be a
# source of the skew this section exists to catch.
if VA_OUT=$(bash scripts/check-version-alignment.sh 2>&1); then
    pass "every tracked version literal == pyproject.toml == $TAG_VER"
else
    echo "$VA_OUT" | grep -E '✗|disagree' || echo "$VA_OUT"
    fail "one or more version literals disagree with pyproject.toml — run \`scripts/bump-version.sh $TAG_VER\` to align them"
fi

# ============================================================================
# 4. CHANGELOG has an entry for the current version
# ============================================================================
header "4. CHANGELOG entry for $TAG_VER present?"
if grep -qE "^## \[$TAG_VER\]" CHANGELOG.md; then
    pass "CHANGELOG.md has a ## [$TAG_VER] section"
else
    fail "CHANGELOG.md has no ## [$TAG_VER] section — write release notes before tagging"
fi

# ============================================================================
# 5. Lint + type-check + unit tests (mirrors CI `test` job)
# ============================================================================
header "5. Ruff lint"
if "$RUFF" check src tests; then
    pass "ruff clean"
else
    fail "ruff lint failures"
fi

header "6. Ruff format check"
if "$RUFF" format --check src tests; then
    pass "ruff format clean"
else
    fail "ruff format would change files — run \`ruff format src tests\` and commit"
fi

header "7. mypy"
if "$MYPY" --config-file pyproject.toml src; then
    pass "mypy clean"
else
    fail "mypy errors"
fi

header "8. pytest"
if "$PYTEST" -q --strict-markers --strict-config; then
    pass "pytest green"
else
    fail "pytest failures"
fi

# ============================================================================
# 6. Lockfile hash structure (mirrors `check-lockfile-hashes` pre-commit)
# ============================================================================
header "9. Lockfile hash-pinning"
if "$PY" scripts/check-lockfile-hashes.py; then
    pass "every package hash-pinned"
else
    fail "lockfile has unpinned packages"
fi

# ============================================================================
# 7. Zizmor on workflows (mirrors security.yml zizmor + pre-commit hook)
# ============================================================================
header "10. Zizmor (workflow security)"
if command -v zizmor >/dev/null 2>&1; then
    if zizmor .github/workflows/ >/dev/null; then
        pass "zizmor clean"
    else
        fail "zizmor findings — fix the workflow templates"
    fi
else
    yellow "skip — zizmor not on PATH (\`pre-commit run zizmor --all-files\` works too)"
fi

# ============================================================================
# 8. Wheel smoke test (mirrors `wheel-smoke` CI job)
# ============================================================================
if [ "${SKIP_WHEEL:-0}${SKIP_HEAVY:-0}" != "00" ]; then
    yellow "skip — SKIP_WHEEL or SKIP_HEAVY set"
else
    header "11. Wheel smoke test (build + install + import + entry point)"
    if bash scripts/smoke-test-wheel.sh; then
        pass "wheel installs cleanly in fresh container, version $TAG_VER reported"
    else
        fail "wheel smoke failed — wheel won't work for PyPI users"
    fi
fi

# ============================================================================
# 9. Docker E2E harness (mirrors `e2e-docker` CI job)
# ============================================================================
if [ "${SKIP_E2E:-0}${SKIP_HEAVY:-0}" != "00" ]; then
    yellow "skip — SKIP_E2E or SKIP_HEAVY set"
else
    header "12. Docker E2E harness (substitution + deny on the wire)"
    if bash tests/docker-e2e/run.sh; then
        pass "e2e positive + negative assertions green"
    else
        fail "e2e harness failed"
    fi
fi

# ============================================================================
# Final report
# ============================================================================
echo
if [ ${#FAILED[@]} -eq 0 ]; then
    green "════════════════════════════════════════════════════════════════════"
    green "✓ All pre-release checks passed for v$TAG_VER"
    green "════════════════════════════════════════════════════════════════════"
    green ""
    green "Ready to tag + push:"
    green "  git tag -s v$TAG_VER -m \"v$TAG_VER — <one-line summary>\""
    green "  git push origin v$TAG_VER         # triggers PyPI publish via release.yml"
    green "  # if you keep a backup remote, push the tag there too"
    exit 0
else
    red "════════════════════════════════════════════════════════════════════"
    red "✗ Pre-release checks FAILED — do NOT tag yet"
    red "════════════════════════════════════════════════════════════════════"
    red ""
    red "Failures:"
    for f in "${FAILED[@]}"; do
        red "  - $f"
    done
    exit 1
fi
