"""CLI verbs for keys-on-the-wire.

This package hosts the ``kow`` subcommands (``kow doctor``,
``kow bindings ...``, etc.). The actual proxy daemon entry point lives at
``kow.__main__:main`` — see ``pyproject.toml``'s
``[project.scripts]`` block.

Subcommands ship across subsequent phases — ``kow doctor``,
``kow bindings list``, ``kow bindings show``, ``kow bindings diff``,
``kow template <service>``, and friends — see the brew side at
``homebrew-keys-on-the-wire/ISA.md`` for the full operator-facing surface.
"""

from __future__ import annotations
