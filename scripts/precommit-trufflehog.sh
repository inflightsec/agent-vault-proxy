#!/usr/bin/env bash
# TruffleHog secret scan over the unpushed diff, using a NATIVE trufflehog
# binary (no Docker). Mirrors the CI security job's flags so a pre-commit-clean
# repo passes CI secret-scanning. --since-commit HEAD limits the scan to the
# staged change (fast local feedback; CI scans full history); --only-verified
# filters unverified matches by confirming each candidate against its issuer.
#
# Why native instead of Docker: the `docker run` container-start tax dominated
# commit time (multiple seconds every commit). The native binary removes it.
# Tradeoff, eyes open: trufflehog now runs with the operator's full host access
# and network egress instead of inside a scoped container. Mitigate by
# installing a CHECKSUM-VERIFIED, version-pinned release (NOT `curl | sh`), and
# we pass --no-update below so the binary can't self-modify at runtime.
#
# Graceful degradation: if trufflehog isn't installed, skip with install
# guidance. CI (SHA-pinned trufflehog action) remains the enforcement gate, so
# a missing local binary never lets a secret through — it only loses fast local
# feedback.
set -euo pipefail

# Keep in lockstep with the version CI's pinned action resolves to
# (.github/workflows/security.yml → trufflesecurity/trufflehog). Bump both
# together. The soft check below warns if the local binary drifts from this.
EXPECTED_VERSION="3.95.5"

if ! command -v trufflehog >/dev/null 2>&1; then
    cat >&2 <<EOF
trufflehog not on PATH — skipping local secret scan (CI will catch it).

Install the checksum-verified, version-pinned binary (do NOT pipe install.sh to sh):
  1. Download from https://github.com/trufflesecurity/trufflehog/releases/tag/v${EXPECTED_VERSION}
     trufflehog_${EXPECTED_VERSION}_<os>_<arch>.tar.gz  +  trufflehog_${EXPECTED_VERSION}_checksums.txt
  2. Verify:  sha256sum -c --ignore-missing trufflehog_${EXPECTED_VERSION}_checksums.txt
  3. Extract 'trufflehog' onto your PATH (e.g. ~/.local/bin or /usr/local/bin).
EOF
    exit 0
fi

# Soft version-parity check: warn (don't fail) if the local binary drifts from
# the pin CI uses, so a stale local trufflehog can't silently diverge from CI.
have_version="$(trufflehog --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
if [ -n "$have_version" ] && [ "$have_version" != "$EXPECTED_VERSION" ]; then
    echo "warning: local trufflehog ${have_version} != pinned ${EXPECTED_VERSION} (CI uses the pin)." >&2
fi

# file://<path> scans this repo's git history; --since-commit HEAD narrows to
# the staged diff. --no-update blocks trufflehog's runtime self-update check
# (supply-chain hygiene + skips a startup network round-trip).
exec trufflehog git "file://$(pwd)" \
    --since-commit HEAD \
    --only-verified \
    --no-update \
    --fail
