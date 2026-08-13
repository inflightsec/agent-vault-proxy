"""``kow moo`` — an undocumented easter egg.

``kow`` sounds like "cow", so ``kow moo`` prints a ``cowsay``-style cow with
an on-theme one-liner. It's intercepted in :func:`kow.cli.main.main` *before*
argparse runs, so it never appears in ``kow --help`` — not even in the
subcommand choices metavar (``help=argparse.SUPPRESS`` alone would still leak
the name there). You only find it if you go looking, which is the whole point.

Deliberately trivial and side-effect-free: it prints to stdout and returns 0.
Nothing here touches config, the vault, the CA, or the network. Keep it that
way — the joke lives at the edges, never near anything that establishes trust.
"""

from __future__ import annotations

import random

# On-theme quips. Keep them about keys/secrets staying put — the product
# promise, told with a straight face by a cow. The tagline earns a slot.
_LINES = (
    "Keys on the wire, never in your code.",
    "Your secrets never left the pasture.",
    "Real credential's grazing safely. You get a placeholder.",
    "Secrets in, placeholders out. Moo.",
    "Nothing to see here. That's the idea.",
)

_COW = r"""        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||"""


def cowsay(text: str) -> str:
    """Render ``text`` in a speech bubble above an ASCII cow."""
    width = len(text)
    return "\n".join(
        (
            " " + "_" * (width + 2),
            f"< {text} >",
            " " + "-" * (width + 2),
            _COW,
        )
    )


def run_moo() -> int:
    """Print the cow. Always succeeds."""
    print(cowsay(random.choice(_LINES)))  # noqa: S311  # nosec B311 - a cow, not crypto
    return 0
