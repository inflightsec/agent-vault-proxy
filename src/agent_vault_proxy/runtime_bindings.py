"""Daemon-side activation of BWS-notes bindings (ADR-0011 item 3).

Where :mod:`agent_vault_proxy.bindings_resolver` is the pure merge logic and
:mod:`agent_vault_proxy.notes_binding` is the pure note parser, THIS module is
the glue that runs at daemon configure() time: it lists the BWS secrets,
derives each one's salted placeholder, fetches+parses each note, and merges
the result (honouring BWS-notes-over-file precedence) into a single resolved
view the request path can consume.

Crucially it also returns, for EVERY listed secret, a ``placeholder ->
secret_name`` entry — including secrets whose note carried NO binding or a
MALFORMED one. The request path needs that so a placeholder belonging to an
unbound/typo'd secret fails CLOSED with the correct audit reason
(``no_binding_in_notes`` / ``invalid_binding_metadata``) instead of being
forwarded as an unrecognised string.

Fetch/refresh boundary: notes are fetched here, at configure() time (config
reload). That is the binding-policy refresh boundary, exactly analogous to
re-reading bindings.yaml in file mode. The per-REQUEST credential VALUE
fetch still goes through the caching client and respects ``cache.ttl_seconds``
unchanged — this module never caches or holds secret values, only notes
(policy metadata) and the placeholder map.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from agent_vault_proxy.backends import list_secret_notes
from agent_vault_proxy.bindings_resolver import (
    BindingsResolver,
    BindingsSource,
    FileSource,
    NotesSource,
    ResolvedSpec,
)
from agent_vault_proxy.config import Config
from agent_vault_proxy.placeholders import derive_placeholder_map


@dataclass
class ResolvedRuntimeBindings:
    """Outcome of runtime binding resolution.

    * ``specs``               — {secret_name: (SecretSpec, source, companion_headers)}
      for secrets that resolved to an actual binding.
    * ``placeholder_to_name`` — derived placeholder -> secret_name for EVERY
      listed BWS secret (bound, no-binding, or invalid). Lets the request
      path attribute a placeholder even when it has no spec.
    * ``no_binding``          — names whose note carried no binding.
    * ``invalid``             — name -> diagnostic for malformed notes.
    """

    specs: dict[str, ResolvedSpec]
    placeholder_to_name: dict[str, str]
    no_binding: set[str] = field(default_factory=set)
    invalid: dict[str, str] = field(default_factory=dict)


def resolve_runtime_bindings(
    *,
    backend: object,
    binding_source: Literal["file", "notes", "both"],
    install_salt: bytes,
    file_config: Config | None,
) -> ResolvedRuntimeBindings:
    """Resolve bindings for the daemon at configure() time.

    ``backend`` must be listable (bws/static) for notes/both modes.
    ``file_config`` carries the file-source bindings (used in `both` mode;
    ignored in `notes`). ``file`` mode should not call this function —
    the addon keeps its existing file-only path for that.

    Raises:
        PlaceholderCollisionError: two BWS secret names derive the same
            placeholder (hard startup failure — see placeholders.py).
        BackendCannotListError: the backend can't enumerate names.
    """
    if binding_source == "file":  # pragma: no cover - addon never calls in file mode
        raise ValueError("resolve_runtime_bindings is for notes/both modes only")

    # Notes (policy metadata) for every enumerable secret. Where the backend
    # supports it (GSM: annotations from the free ListSecrets pass), NO secret
    # value is fetched here — so a config reload never pulls every plaintext,
    # and a disabled/denied secret VERSION does not brick the reload. Backends
    # without a note-only path fall back to list + fetch_with_meta. A backend
    # failure propagates so configure() fails closed rather than serving a
    # partial binding view.
    notes: dict[str, str | None] = list_secret_notes(backend)  # type: ignore[arg-type]
    names = list(notes.keys())
    # Derive ALL placeholders up front so a collision fails before any note
    # is parsed (collision is a config-wide invariant, not a per-secret one).
    placeholders = derive_placeholder_map(names, install_salt)

    notes_source = NotesSource(
        placeholders=placeholders,
        notes=notes,
        # Label specs by the backend TYPE, not the binding_source string, so the
        # inject_decision audit is honest even in `both` mode: GSM annotations
        # read gsm_notes, BWS notes read bws_notes. Same mechanism either way.
        source_label=getattr(type(backend), "NOTES_SOURCE_LABEL", "bws_notes"),
    )

    sources: list[BindingsSource] = [notes_source]
    if binding_source == "both" and file_config is not None:
        sources.append(FileSource(config=file_config))

    resolver = BindingsResolver(sources=sources)
    specs = resolver.resolve()

    # placeholder -> name for EVERY listed secret (so unbound/invalid
    # placeholders are still attributable at request time).
    placeholder_to_name = {ph: name for name, ph in placeholders.items()}

    return ResolvedRuntimeBindings(
        specs=specs,
        placeholder_to_name=placeholder_to_name,
        no_binding=set(notes_source.no_binding),
        invalid=dict(notes_source.invalid),
    )
