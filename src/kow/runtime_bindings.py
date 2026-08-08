"""Daemon-side activation of BWS-notes bindings (ADR-0011 item 3).

Where :mod:`kow.bindings_resolver` is the pure merge logic and
:mod:`kow.notes_binding` is the pure note parser, THIS module is
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

from kow.backends import list_secret_notes
from kow.bindings_resolver import (
    BindingsResolver,
    BindingsSource,
    FileSource,
    NotesSource,
    ResolvedSpec,
)
from kow.config import Config
from kow.placeholders import derive_placeholder_map


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

    # ADR-0029: a note may pin a STORED placeholder (spec.placeholder then
    # differs from the salt-derived one). Uniqueness across the whole
    # resolved view is a fail-closed invariant — enforced here, where every
    # secret is visible, never guessed per-note.
    invalid = dict(notes_source.invalid)
    dropped = _enforce_placeholder_uniqueness(specs, placeholders, invalid)

    # placeholder -> name for EVERY listed secret (so unbound/invalid
    # placeholders are still attributable at request time). Stored
    # placeholders are added on top: the DERIVED entry stays too, so a
    # consumer still wired to the old derived placeholder fails closed with
    # an attributable audit line instead of an anonymous passthrough.
    placeholder_to_name = {ph: name for name, ph in placeholders.items()}
    for name, (spec, _src, _comp) in specs.items():
        if spec.placeholder != placeholders.get(name):
            placeholder_to_name[spec.placeholder] = name
    # Dropped stored claims stay attributable too (never injectable — their
    # specs are gone — but a request carrying one audits with a named secret
    # instead of forwarding as an anonymous string). Surviving claims win.
    for ph, name in dropped.items():
        placeholder_to_name.setdefault(ph, name)

    return ResolvedRuntimeBindings(
        specs=specs,
        placeholder_to_name=placeholder_to_name,
        no_binding=set(notes_source.no_binding),
        invalid=invalid,
    )


def _enforce_placeholder_uniqueness(
    specs: dict[str, ResolvedSpec],
    derived: dict[str, str],
    invalid: dict[str, str],
) -> dict[str, str]:
    """Drop (fail closed) every spec whose placeholder is ambiguous (ADR-0029).

    Three ambiguity classes, all resolved by REMOVING the affected specs and
    recording a diagnostic (they surface through the same
    ``invalid_binding_metadata`` audit/doctor path as a malformed note):

    * the same placeholder claimed by >1 resolved spec (stored/stored, or
      stored colliding with a file-source operator placeholder in ``both``
      mode);
    * a stored placeholder equal to ANOTHER secret's derived placeholder;
    * a stored placeholder that is a SUBSTRING/SUPERSTRING of another spec's
      placeholder. This one is load-bearing: the merge-level
      ``validate_placeholder_invariants`` refuses substring overlaps by
      RAISING, which would fail the whole configure()/reload — a crafted
      overlapping note would then be a metadata-write DoS against every
      secret. Dropping the illegitimate claimant here keeps the failure
      per-secret.

    Thief-loses: a claimant is legitimate when the claim is its own derived
    placeholder or comes from the file source; illegitimate claimants drop
    alone when a single legitimate one exists. Between a file-source and a
    derived claimant (both legitimate — a pre-existing configuration
    condition, not creatable from a note), the merge validator retains
    arbitration.

    Mutates ``specs`` and ``invalid`` in place. Returns ``{placeholder:
    secret_name}`` for every dropped claim so the caller can keep them
    attributable in the request path.
    """
    dropped_ph: dict[str, str] = {}
    # Sequential: the overlap pass runs over the exact pass's survivors.
    for finder in (_exact_collision_drops, _overlap_drops):
        for name, diagnostic in finder(specs, derived).items():
            dropped_ph.setdefault(specs[name][0].placeholder, name)
            specs.pop(name, None)
            invalid[name] = diagnostic
    return dropped_ph


def _is_legitimate(name: str, ph: str, source: str, derived: dict[str, str]) -> bool:
    """A claim is LEGITIMATE when it is the claimant's own derived
    placeholder, or comes from the file source (root-owned config — higher
    trust than vault-writable notes)."""
    return derived.get(name) == ph or source == "file"


def _exact_collision_drops(
    specs: dict[str, ResolvedSpec], derived: dict[str, str]
) -> dict[str, str]:
    """Equal-placeholder contests -> {name: diagnostic} to drop."""
    claimed: dict[str, list[str]] = {}
    for name, (spec, _src, _comp) in specs.items():
        claimed.setdefault(spec.placeholder, []).append(name)

    derived_owner = {ph: name for name, ph in derived.items()}
    to_drop: dict[str, str] = {}
    for ph, names in claimed.items():
        legitimate = [n for n in names if _is_legitimate(n, ph, specs[n][1], derived)]
        owner = derived_owner.get(ph)
        if len(names) > 1:
            if len(legitimate) == 1:
                for name in (n for n in names if n != legitimate[0]):
                    to_drop[name] = (
                        f"stored placeholder {ph!r} on secret {name!r} collides "
                        f"with the placeholder of secret {legitimate[0]!r}. Mint "
                        "a fresh placeholder (`avp binding new`) for it."
                    )
            else:
                diagnostic = (
                    f"placeholder {ph!r} is claimed by multiple secrets "
                    f"{sorted(names)}; injection would be ambiguous. Mint a "
                    "fresh placeholder (`avp binding new`) for all but one."
                )
                for name in names:
                    to_drop[name] = diagnostic
        elif owner is not None and owner != names[0] and not legitimate:
            to_drop[names[0]] = (
                f"stored placeholder {ph!r} on secret {names[0]!r} collides "
                f"with the derived placeholder of secret {owner!r}. Mint a "
                "fresh placeholder (`avp binding new`) for it."
            )
    return to_drop


def _overlap_drops(specs: dict[str, ResolvedSpec], derived: dict[str, str]) -> dict[str, str]:
    """Substring/superstring contests -> {name: diagnostic} to drop (see
    _enforce_placeholder_uniqueness docstring: keeps a crafted overlap a
    per-secret drop instead of a global raise in the merge validator).
    O(n^2) over BOUND secrets — dozens, not thousands; deterministic order
    for stable diagnostics."""
    remaining = sorted(specs.items())
    to_drop: dict[str, str] = {}
    for i, (name_a, (spec_a, src_a, _ca)) in enumerate(remaining):
        for name_b, (spec_b, src_b, _cb) in remaining[i + 1 :]:
            pa, pb = spec_a.placeholder, spec_b.placeholder
            if pa == pb or (pa not in pb and pb not in pa):
                continue
            a_legit = _is_legitimate(name_a, pa, src_a, derived)
            b_legit = _is_legitimate(name_b, pb, src_b, derived)
            if a_legit and b_legit:
                continue  # pre-existing config condition; merge validator arbitrates
            for name, legit, ph, other in (
                (name_a, a_legit, pa, name_b),
                (name_b, b_legit, pb, name_a),
            ):
                if not legit:
                    to_drop[name] = (
                        f"stored placeholder {ph!r} on secret {name!r} is a "
                        f"substring/superstring of the placeholder of secret "
                        f"{other!r}; `in`-matching would be ambiguous. Mint a "
                        "fresh placeholder (`avp binding new`)."
                    )
    return to_drop
