"""CLI verbs for agent-vault-proxy.

This package hosts the ``avp`` subcommands (``avp doctor``,
``avp bindings ...``, etc.). The actual proxy daemon entry point lives at
``agent_vault_proxy.__main__:main`` — see ``pyproject.toml``'s
``[project.scripts]`` block.

Subcommands ship across subsequent phases — ``avp doctor``,
``avp bindings list``, ``avp bindings show``, ``avp bindings diff``,
``avp template <service>``, and friends — see the brew side at
``agent-vault-proxy-brew/ISA.md`` for the full operator-facing surface.
"""

from __future__ import annotations
