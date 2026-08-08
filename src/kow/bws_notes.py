"""Deprecated module path — renamed to :mod:`kow.notes_binding`.

The note/annotation parser is backend-agnostic (BWS ``notes`` AND GSM
``avp-binding`` annotations), so the ``bws_`` prefix was misleading. Import from
``kow.notes_binding`` instead. This shim re-exports the full
surface (including the private helpers the tests reach for) for back-compat.
"""

from __future__ import annotations

import warnings

from kow.notes_binding import (  # noqa: F401
    _ALLOWED_NOTE_KEYS,
    _DEFAULT_FORMAT,
    _DEFAULT_HEADER,
    _NOTE_SECRET_TOKEN,
    EXCEPTION_TABLE,
    InvalidBinding,
    NoBinding,
    ParsedBinding,
    _ExceptionRow,
    _first_error,
    _load_note_mapping,
    _rewrite_token,
    parse_notes_binding,
)

warnings.warn(
    "kow.bws_notes is deprecated and will be removed in a future "
    "release; import from kow.notes_binding instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "EXCEPTION_TABLE",
    "InvalidBinding",
    "NoBinding",
    "ParsedBinding",
    "parse_notes_binding",
]
