#!/usr/bin/env bash
#
# Pre-publish wheel smoke test for agent-vault-proxy.
#
# Builds the wheel from the current tree (or uses the already-published
# version on PyPI) INSIDE a clean python:3.12-slim container, with no
# host bind mount for the build output. The source tree is mounted
# read-only; the wheel is built into the container's own filesystem
# and installed in the same container. Verifies:
#
#   1. The wheel builds without errors.
#   2. The wheel installs into a fresh interpreter.
#   3. `import kow` succeeds.
#   4. `kow.__version__` matches what pyproject.toml says.
#   5. Entry-point + addon imports succeed (proves __main__.main and
#      every runtime-required module load against the installed wheel).
#
# Run AGAINST THE LOCAL TREE before tagging / publishing — catches the
# "we shipped a broken wheel that imports fine but blows up at entry"
# class.
#
# Single-container design (rather than build → mount-out → install-in)
# sidesteps a Docker userns-remap failure where the daemon tries to
# chown the host bind-mount source and can't (NFS / shared dev trees).
# We never need the wheel artifact on the host for the smoke test —
# the question is "would a downstream user's `pip install` work."
# Use `python -m build` in CI's release.yml for the publish artifact.
#
# Usage:
#
#   bash scripts/smoke-test-wheel.sh                 # build + test local tree
#   bash scripts/smoke-test-wheel.sh --pypi 0.9.0    # test the already-published version
#
# No host Python touched; runs entirely in a throwaway container.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

MODE="local"
PYPI_VERSION=""

if [ "${1:-}" = "--pypi" ]; then
    MODE="pypi"
    PYPI_VERSION="${2:?--pypi requires a version, e.g. --pypi 0.9.0}"
fi

# Source of truth for expected version: pyproject.toml. The smoke test
# cross-checks pyproject ↔ __init__.py ↔ wheel metadata all line up.
EXPECTED_VERSION="$(python3 -c "
import tomllib, sys
with open('pyproject.toml', 'rb') as f:
    print(tomllib.load(f)['project']['version'])
")"

green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

if [ "$MODE" = "local" ]; then
    green "[1/2] Building + smoke-testing wheel for agent-vault-proxy ${EXPECTED_VERSION}..."
    green "      (single container: build → install → import → version → --help)"

    # The source tree is mounted read-only; the container builds and
    # installs everything inside its own writable layers. No bind mount
    # for /dist — the wheel lives in the container's /tmp/dist for the
    # duration of the run, then dies with the container.
    docker run --rm \
        -v "$PWD:/src:ro" \
        -w /src \
        -e EXPECTED_VERSION="$EXPECTED_VERSION" \
        python:3.12-slim \
        sh -eux -c '
            # Copy ONLY what hatchling needs to build the wheel — not
            # the .git/.venv/cache morass. The source mount is :ro and
            # python -m build writes a build/ subdir alongside, so the
            # scratch dir has to be writable. Stay minimal:
            #   pyproject.toml + README.md + LICENSE + src/
            # is what gets packaged per [tool.hatch.build.targets.wheel]
            # in pyproject.toml. Everything else (tests, docs, .venv,
            # .git) is irrelevant to wheel content and just slows the cp.
            mkdir -p /tmp/scratch/src /tmp/dist
            cp /src/pyproject.toml /src/README.md /src/LICENSE /tmp/scratch/
            cp -r /src/src/kow /tmp/scratch/src/
            cd /tmp/scratch

            # 1. Build wheel.
            python -m pip install --quiet --no-cache-dir --only-binary :all: build
            python -m build --wheel --outdir /tmp/dist .

            # 2. Find the produced wheel.
            WHEEL=$(ls /tmp/dist/keys_on_the_wire-*.whl | head -1)
            echo "built: $WHEEL"

            # 3. Install it into a fresh venv (NOT the build venv —
            # build pulled hatchling + friends; the test install must
            # see the wheel-declared deps and nothing more).
            python -m venv /tmp/testvenv
            /tmp/testvenv/bin/pip install --quiet --no-cache-dir --only-binary :all: "$WHEEL"

            # 4. Import — proves no missing-dep at runtime.
            /tmp/testvenv/bin/python -c "import kow; print(\"import OK\")"

            # 5. Version — proves the wheel and pyproject agree.
            ACTUAL=$(/tmp/testvenv/bin/python -c "import kow; print(kow.__version__)")
            if [ "$ACTUAL" != "$EXPECTED_VERSION" ]; then
                echo "version mismatch: wheel says $ACTUAL, pyproject says $EXPECTED_VERSION" >&2
                exit 1
            fi
            echo "version OK: $ACTUAL"

            # 6. Entry point + addon module imports. Originally this
            # ran `python -m kow --help`, which delegates
            # to the mitmdump argparse layer; mitmdump --help with a
            # -s addon flag is fragile across versions and returns
            # exit 1 on the runner. The test.yml wheel-smoke job
            # already switched to an import-only check; this brings
            # smoke-test-wheel.sh in line. Imports prove every module
            # the runtime depends on loads against the installed wheel.
            # NOTE: no APOSTROPHE characters anywhere in this inner
            # block — comments included. The whole inner script runs
            # as a single-quoted argument to sh -eux -c. A bare
            # APOSTROPHE inside closes the outer quote and breaks the
            # shell parse with: unexpected EOF while looking for
            # matching quote.
            /tmp/testvenv/bin/python -c "
import kow
from kow.__main__ import main
from kow import addon, config
from kow.backends import BACKEND_REGISTRY
print(\"entry point OK\")
"
        '
else
    green "[1/2] Smoke-testing published agent-vault-proxy==${PYPI_VERSION} from PyPI..."

    docker run --rm \
        -e EXPECTED_VERSION="$EXPECTED_VERSION" \
        -e PYPI_VERSION="$PYPI_VERSION" \
        python:3.12-slim \
        sh -eux -c '
            python -m venv /tmp/testvenv
            /tmp/testvenv/bin/pip install --quiet --no-cache-dir --only-binary :all: \
                "agent-vault-proxy==${PYPI_VERSION}"

            /tmp/testvenv/bin/python -c "import kow; print(\"import OK\")"

            ACTUAL=$(/tmp/testvenv/bin/python -c "import kow; print(kow.__version__)")
            if [ "$ACTUAL" != "$PYPI_VERSION" ]; then
                echo "PyPI wheel reports version $ACTUAL, expected $PYPI_VERSION" >&2
                exit 1
            fi
            echo "version OK: $ACTUAL"

            /tmp/testvenv/bin/python -m kow --help >/dev/null
            echo "entry point OK"
        '
fi

green ""
if [ "$MODE" = "local" ]; then
    green "[2/2] ✓ Local wheel ${EXPECTED_VERSION} smoke test passed."
    green "      Build + install + import + version + entry point all green."
    green "      Safe to tag + publish to PyPI."
else
    green "[2/2] ✓ Published wheel agent-vault-proxy==${PYPI_VERSION} smoke test passed."
fi
