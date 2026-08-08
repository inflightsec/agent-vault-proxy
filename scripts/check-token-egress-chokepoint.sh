#!/usr/bin/env bash
# ADR-0035 chokepoint guard: operator-controlled token-endpoint egress must go
# through the ONE shared, SSRF-pinned transport (injectors/_token_transport.py).
#
# A new injector that opens its own raw urllib / http.client / socket connection
# to an operator-supplied URL would silently reintroduce the check->connect
# TOCTOU that ADR-0035 closed (resolve-once, connect-to-the-vetted-IP). This
# guard fails if any injector OTHER than the shared transport reaches for a
# connection-opening primitive.
#
# Loose-positive by design (ADR-0035 "Adjuncts"): a review comment is cheaper
# than a silent egress hole. ``urllib.request.Request`` is deliberately NOT
# flagged — it builds a request object and opens nothing. If a match is a
# genuine false positive, route the call through _token_transport, or narrow
# the pattern below with a comment explaining why.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

INJECTORS="src/kow/injectors"

# Connection-OPENING primitives only, matched as CALLS (trailing "(") so a
# prose mention in a comment/docstring doesn't false-positive. The single
# legitimate egress site, _token_transport.py, is excluded — it IS the shared
# pinned transport.
PATTERN='(build_opener|urlopen|HTTPSConnection|HTTPConnection|create_connection|socket\.socket)\('

hits="$(grep -rnE "$PATTERN" "$INJECTORS" \
          --include='*.py' \
          --exclude='_token_transport.py' || true)"

if [ -n "$hits" ]; then
    {
        echo "ADR-0035 chokepoint violation: an injector opens a raw connection"
        echo "outside the shared SSRF-pinned transport (injectors/_token_transport.py):"
        echo ""
        echo "$hits"
        echo ""
        echo "Route token-endpoint egress through _token_transport.post /"
        echo "transport_open so resolve-and-pin (ADR-0035) applies. If this is a"
        echo "genuine false positive, narrow the pattern in"
        echo "scripts/check-token-egress-chokepoint.sh."
    } >&2
    exit 1
fi

echo "ADR-0035 chokepoint OK: no injector opens a raw connection outside the shared transport."
