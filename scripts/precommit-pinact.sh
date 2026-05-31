#!/usr/bin/env bash
# Pinact SHA-pinning check on workflow files. Belt-and-suspenders on top
# of zizmor's `unpinned-uses` audit rule — pinact has independent action-
# reference parsing, so a regression in either tool is caught by the
# other.
#
# Pinact doesn't ship a Docker image (single static Go binary, no
# containerized release), and its pre-commit integration repo doesn't
# expose .pre-commit-hooks.yaml. So we treat it like a system tool:
# use it if installed, skip gracefully if not.
#
# Install pinact:
#   - aqua (suzuki-shunsuke's own tool, recommended):
#       aqua install pinact
#   - Go toolchain:
#       go install github.com/suzuki-shunsuke/pinact/v3/cmd/pinact@latest
#   - Direct binary:
#       https://github.com/suzuki-shunsuke/pinact/releases
#
# When pinact IS installed, this script runs `pinact run --check` which
# fails non-zero if any workflow action reference is not pinned to a
# 40-char commit SHA. To auto-fix, run `pinact run` (without --check)
# manually — that command rewrites the workflow files in place, so it
# belongs in a manual maintenance pass, not in a commit hook.
set -euo pipefail

if ! command -v pinact >/dev/null 2>&1; then
    echo "pinact not installed — skipping (zizmor's unpinned-uses rule covers the same check)."
    echo "Install: aqua install pinact   OR   go install github.com/suzuki-shunsuke/pinact/v3/cmd/pinact@latest"
    exit 0
fi

# --check fails non-zero on unpinned refs without modifying files —
# safe to run inside a commit hook.
pinact run --check
