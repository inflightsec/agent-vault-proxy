"""Secret must never render its value — on any path that produces text."""

from __future__ import annotations

import copy
import logging
import pickle
import traceback

import pytest

from kow.secret import REDACTED, Secret, reveal

VALUE = "sk-live-DEADBEEF-must-never-appear"


def test_reveal_returns_the_value() -> None:
    assert Secret(VALUE).reveal() == VALUE


def test_rejects_non_str() -> None:
    with pytest.raises(TypeError, match="takes str"):
        Secret(b"bytes")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "render",
    [
        repr,
        str,
        lambda s: f"{s}",
        lambda s: f"{s!s}",
        lambda s: f"{s!r}",
        lambda s: f"{s:>80}",
        lambda s: "{}".format(s),  # noqa: UP032 — .format() is a distinct path
        lambda s: "%s" % (s,),  # noqa: UP031 — %-format is a distinct path
        lambda s: "".join([str(s)]),
    ],
    ids=[
        "repr",
        "str",
        "fstring",
        "fstring_str",
        "fstring_repr",
        "fstring_padded",
        "format_method",
        "percent",
        "join",
    ],
)
def test_no_render_path_leaks(render) -> None:
    out = render(Secret(VALUE))
    assert VALUE not in out
    assert REDACTED in out


def test_exception_message_does_not_leak() -> None:
    """The phase-2 requirement: a Secret inside a raised exception stays opaque."""
    secret = Secret(VALUE)
    with pytest.raises(RuntimeError) as exc:
        raise RuntimeError(f"backend failed for {secret}")
    assert VALUE not in str(exc.value)
    assert VALUE not in repr(exc.value)


def test_traceback_render_does_not_leak() -> None:
    """A traceback formats every frame's locals repr in some handlers."""
    secret = Secret(VALUE)  # noqa: F841 — deliberately a live local in the frame
    try:
        raise ValueError(f"{Secret(VALUE)}")
    except ValueError:
        text = traceback.format_exc()
    assert VALUE not in text


def test_log_record_does_not_leak(caplog) -> None:
    log = logging.getLogger("kow.test_secret")
    with caplog.at_level(logging.WARNING, logger=log.name):
        log.warning("value=%s repr=%r", Secret(VALUE), Secret(VALUE))
    assert VALUE not in caplog.text
    assert REDACTED in caplog.text


def test_not_picklable() -> None:
    """Pickling would move the bytes across a process boundary."""
    with pytest.raises(TypeError, match="not picklable"):
        pickle.dumps(Secret(VALUE))


def test_not_copyable() -> None:
    with pytest.raises(TypeError, match="not copyable"):
        copy.copy(Secret(VALUE))
    with pytest.raises(TypeError, match="not copyable"):
        copy.deepcopy(Secret(VALUE))


def test_equality_is_secret_to_secret_only() -> None:
    assert Secret(VALUE) == Secret(VALUE)
    assert Secret(VALUE) != Secret("other")
    # Comparing against a bare str is refused, not silently False-by-value.
    assert Secret(VALUE) != VALUE


def test_bool_and_len_reflect_the_value() -> None:
    assert bool(Secret("x")) is True
    assert bool(Secret("")) is False
    assert len(Secret("abcd")) == 4


def test_no_attribute_injection() -> None:
    """__slots__ keeps a Secret from carrying an extra unredacted copy."""
    with pytest.raises(AttributeError):
        Secret(VALUE).plaintext = VALUE  # type: ignore[attr-defined]


def test_reveal_helper_passes_str_through() -> None:
    assert reveal(Secret(VALUE)) == VALUE
    assert reveal(VALUE) == VALUE


def test_derived_token_cache_key_repr_omits_credentials() -> None:
    """KeyInputs lands in tracebacks; its repr must not carry the token."""
    from kow._derived_token_cache import KeyInputs

    k = KeyInputs(
        binding_name="B",
        token_url="https://example.invalid/token",
        scopes=None,
        client_id_value="client-abc",
        refresh_token_value=VALUE,
    )
    rep = repr(k)
    assert VALUE not in rep
    assert "client-abc" not in rep
    assert "B" in rep  # non-secret identity fields still visible for debugging


# --------------------------------------------- non-ASCII comparison (2026-08-16)


@pytest.mark.parametrize(
    "value",
    ["żółć", "naïve-key", "密码-token", "emoji-🔑-key", "Ω≈ç√"],
    ids=["polish", "diaeresis", "cjk", "emoji", "symbols"],
)
def test_equality_works_for_non_ascii_secrets(value: str) -> None:
    """`hmac.compare_digest` accepts `str` only when BOTH sides are ASCII-only
    and raises TypeError otherwise, so comparing two perfectly legal non-ASCII
    credentials used to crash rather than answer. Every backend that
    read-back-compares a write depends on this."""
    assert Secret(value) == Secret(value)
    assert Secret(value) != Secret(value + "x")


def test_non_ascii_comparison_does_not_raise_type_error() -> None:
    try:
        equal = Secret("żółć") == Secret("żółć")
    except TypeError as exc:  # pragma: no cover — the regression itself
        raise AssertionError(f"non-ASCII Secret comparison raised: {exc}") from exc
    assert equal


def test_mixed_ascii_and_non_ascii_compare_unequal() -> None:
    assert Secret("plain") != Secret("żółć")


def test_equal_length_different_bytes_still_unequal() -> None:
    assert Secret("ąą") != Secret("ćć")
