"""Resolve binding policy from one or more sources (ADR-0011 item 3).

Two sources today:

  * :class:`NotesSource` — builds SecretSpecs from each BWS secret's
    ``notes`` field (via :func:`bws_notes.parse_notes_binding`).
  * :class:`FileSource`     — the existing ``bindings.yaml`` Config.

Both produce the SAME structural shape ({secret_name: (SecretSpec, source,
companion_headers)}) and run the SAME validation (config.py's SecretSpec /
BindingSpec) — they differ ONLY in where the YAML comes from. That parity
is the whole point: migrating a secret from file to notes must not change
its enforced scope.

Precedence (ADR): **BWS-notes WINS over file** for the same secret. The
resolver merges sources in list order, FIRST source winning; callers pass
``[notes_source, file_source]`` so notes take precedence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from kow.config import Config, SecretSpec
from kow.notes_binding import InvalidBinding, ParsedBinding, parse_notes_binding

# (spec, source_label, companion_headers) — what each source yields per secret.
ResolvedSpec = tuple[SecretSpec, str, dict[str, str]]


class BindingsSource(Protocol):
    """A binding source yields {secret_name: ResolvedSpec}."""

    def resolve(self) -> dict[str, ResolvedSpec]: ...


@dataclass
class FileSource:
    """Bindings from a loaded ``bindings.yaml`` Config. Each spec is tagged
    binding_source='file' (the field's default, asserted here for clarity).
    File bindings carry no companion headers (that concept is BWS-notes-only,
    sourced from the exception table)."""

    config: Config

    def resolve(self) -> dict[str, ResolvedSpec]:
        out: dict[str, ResolvedSpec] = {}
        for name, spec in self.config.secrets.items():
            spec.binding_source = "file"
            out[name] = (spec, "file", {})
        return out


@dataclass
class NotesSource:
    """Bindings from BWS secret notes.

    Inputs (assembled by the daemon from the BWS secret list — see ADR
    "placeholder origin"):
      * ``placeholders``: secret_name -> assigned placeholder string.
      * ``notes``:        secret_name -> raw notes field (str | None).

    Malformed notes are recorded in :attr:`invalid` (name -> diagnostic)
    and produce NO binding — fail closed, never a silent unscoped binding.
    No-binding notes are silently skipped (they are a normal state, not an
    error). Both behaviours mirror the ADR's audit distinction.
    """

    placeholders: dict[str, str]
    notes: dict[str, str | None]
    # Provenance label stamped onto each resolved spec + its audit event.
    # "bws_notes" for BWS notes, "gsm_notes" for GSM `avp-binding` annotations.
    source_label: str = "bws_notes"
    # name -> diagnostic, for malformed notes (audit `invalid_binding_metadata`).
    invalid: dict[str, str] = field(default_factory=dict)
    # names whose note carried no binding (audit `no_binding_in_notes`). A
    # normal state, tracked separately from `invalid` so a diagnostic surface
    # (e.g. `avp doctor`) can report the two distinctly.
    no_binding: set[str] = field(default_factory=set)

    def resolve(self) -> dict[str, ResolvedSpec]:
        out: dict[str, ResolvedSpec] = {}
        self.invalid = {}
        self.no_binding = set()
        for name, placeholder in self.placeholders.items():
            note = self.notes.get(name)
            result = parse_notes_binding(secret_name=name, placeholder=placeholder, note=note)
            if isinstance(result, ParsedBinding):
                result.spec.binding_source = self.source_label
                out[name] = (result.spec, self.source_label, result.companion_headers)
            elif isinstance(result, InvalidBinding):
                # Record diagnostic, emit no binding (fail closed).
                self.invalid[name] = result.diagnostic
            else:
                # NoBinding -> no injection anywhere, but tracked so the
                # diagnostic surface can distinguish it from malformed.
                self.no_binding.add(name)
        return out


@dataclass
class BindingsResolver:
    """Merge multiple sources with first-source-wins precedence.

    Callers order sources so the higher-precedence one comes first; per the
    ADR that is ``[NotesSource, FileSource]`` (BWS-notes wins over file
    for the same secret).
    """

    sources: list[BindingsSource]

    def resolve(self) -> dict[str, ResolvedSpec]:
        merged: dict[str, ResolvedSpec] = {}
        invalid_names: set[str] = set()
        for source in self.sources:
            resolved_map = source.resolve()
            source_invalid = getattr(source, "invalid", None)
            if isinstance(source_invalid, dict) and source_invalid:
                invalid_names.update(source_invalid)
                for name in source_invalid:
                    merged.pop(name, None)
            for name, resolved in resolved_map.items():
                if name in invalid_names:
                    continue
                # First source to claim a name wins; later sources do not
                # override it. This is the precedence guarantee.
                if name not in merged:
                    merged[name] = resolved
        return merged
