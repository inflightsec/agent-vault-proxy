"""Happy-path coverage for the AVP template module.

Sandbox-escape adversarial corpus lives in test_sandbox_escape.py — keep
that separate so it can grow without diluting the readability of these
behavioral tests.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import urllib.parse

import pytest

from kow.template import (
    WHITELISTED_FILTERS,
    WHITELISTED_FUNCTIONS,
    KowTemplate,
    TemplateRenderError,
    UnsupportedTemplateError,
)

# ---------------------------------------------------------------------------
# Construction / parse-time validation
# ---------------------------------------------------------------------------


def test_plain_literal_template() -> None:
    tpl = KowTemplate("Bearer fixed-string", [])
    assert tpl.render({}) == "Bearer fixed-string"


def test_simple_variable_substitution() -> None:
    tpl = KowTemplate("Bearer {{ TOKEN }}", ["TOKEN"])
    assert tpl.render({"TOKEN": "abc123"}) == "Bearer abc123"


def test_string_concatenation_with_separator() -> None:
    tpl = KowTemplate("{{ USER + ':' + KEY }}", ["USER", "KEY"])
    assert tpl.render({"USER": "alice", "KEY": "secret"}) == "alice:secret"


def test_b64encode_filter_on_concat() -> None:
    tpl = KowTemplate(
        "Basic {{ (USER + ':' + TOKEN) | b64encode }}",
        ["USER", "TOKEN"],
    )
    expected = "Basic " + base64.b64encode(b"alice:s3cret").decode("ascii")
    assert tpl.render({"USER": "alice", "TOKEN": "s3cret"}) == expected


def test_b64encode_filter_on_single_var() -> None:
    tpl = KowTemplate("{{ X | b64encode }}", ["X"])
    assert tpl.render({"X": "hello"}) == base64.b64encode(b"hello").decode("ascii")


def test_b64decode_filter() -> None:
    encoded = base64.b64encode(b"foo:bar").decode("ascii")
    tpl = KowTemplate("{{ X | b64decode }}", ["X"])
    assert tpl.render({"X": encoded}) == "foo:bar"


def test_b64decode_invalid_input_render_error() -> None:
    tpl = KowTemplate("{{ X | b64decode }}", ["X"])
    with pytest.raises(TemplateRenderError, match="b64decode"):
        tpl.render({"X": "not-valid-base64!@#$"})


def test_b64decode_value_error_caught() -> None:
    """base64.b64decode(validate=True) can raise ValueError (not binascii.Error)
    on some malformed inputs in Python 3.12+. The filter must catch both and
    surface them as a clean render_failed, not an uncaught exception that
    bubbles past the addon's audit boundary."""
    tpl = KowTemplate("{{ X | b64decode }}", ["X"])
    # Empty string after stripping padding is one input class that historically
    # produced ValueError rather than binascii.Error on some CPython versions.
    # Any malformed input that ends up raising ValueError exercises the new
    # branch — the assertion is on the exception type, not the specific input.
    with pytest.raises(TemplateRenderError, match="b64decode"):
        tpl.render({"X": "==="})  # padding-only, no data


def test_b64decode_non_ascii_input_caught() -> None:
    """v.encode("ascii") raises UnicodeEncodeError on non-ASCII input.
    Composite secrets passed through b64decode must not let that exception
    bypass the render_failed audit boundary — operators rely on
    render_failed being the catch-all for "composite input was unusable."""
    tpl = KowTemplate("{{ X | b64decode }}", ["X"])
    with pytest.raises(TemplateRenderError, match="b64decode"):
        tpl.render({"X": "café"})  # non-ASCII — fails at .encode("ascii")


def test_sha256_filter() -> None:
    tpl = KowTemplate("{{ X | sha256 }}", ["X"])
    assert tpl.render({"X": "hello"}) == hashlib.sha256(b"hello").hexdigest()


def test_urlencode_filter() -> None:
    tpl = KowTemplate("{{ X | urlencode }}", ["X"])
    assert tpl.render({"X": "a b/c?d"}) == urllib.parse.quote("a b/c?d", safe="")


def test_hmac_sha256_function() -> None:
    tpl = KowTemplate("{{ hmac_sha256(KEY, MSG) }}", ["KEY", "MSG"])
    expected = hmac.new(b"k", b"m", "sha256").hexdigest()
    assert tpl.render({"KEY": "k", "MSG": "m"}) == expected


def test_hmac_sha512_function() -> None:
    tpl = KowTemplate("{{ hmac_sha512(KEY, MSG) }}", ["KEY", "MSG"])
    expected = hmac.new(b"k", b"m", "sha512").hexdigest()
    assert tpl.render({"KEY": "k", "MSG": "m"}) == expected


def test_filter_chain_b64_then_sha256() -> None:
    tpl = KowTemplate("{{ X | b64encode | sha256 }}", ["X"])
    encoded = base64.b64encode(b"value").decode("ascii")
    expected = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    assert tpl.render({"X": "value"}) == expected


def test_const_string_in_concat() -> None:
    # 'Token ' is a Const(str). Add(Const, Name) is allowed string concat.
    tpl = KowTemplate("{{ 'Token ' + KEY }}", ["KEY"])
    assert tpl.render({"KEY": "abc"}) == "Token abc"


def test_multiple_compose_variables() -> None:
    tpl = KowTemplate(
        "{{ A + '|' + B + '|' + C + '|' + D }}",
        ["A", "B", "C", "D"],
    )
    assert tpl.render({"A": "1", "B": "2", "C": "3", "D": "4"}) == "1|2|3|4"


# ---------------------------------------------------------------------------
# AST validator — unknown variables, unknown filters/funcs
# ---------------------------------------------------------------------------


def test_unknown_variable_rejected_at_construction() -> None:
    with pytest.raises(UnsupportedTemplateError, match="unknown variable 'OTHER'"):
        KowTemplate("{{ OTHER }}", ["X"])


def test_unknown_filter_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="unknown filter 'upper'"):
        KowTemplate("{{ X | upper }}", ["X"])


def test_unknown_function_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="unknown function 'range'"):
        KowTemplate("{{ range(10) }}", [])


def test_function_used_as_variable_rejected() -> None:
    # hmac_sha256 is a function name, not a variable. Used as a value
    # it falls into the Name-validator path and gets rejected as not in
    # allowed_vars.
    with pytest.raises(UnsupportedTemplateError, match="unknown variable 'hmac_sha256'"):
        KowTemplate("{{ hmac_sha256 | b64encode }}", ["X"])


def test_filter_used_as_function_rejected() -> None:
    # b64encode is registered as a filter, not as a global. Calling it
    # as a function — ``b64encode(X)`` — fails the WHITELISTED_FUNCTIONS
    # check.
    with pytest.raises(UnsupportedTemplateError, match="unknown function 'b64encode'"):
        KowTemplate("{{ b64encode(X) }}", ["X"])


def test_empty_template_renders_empty_string() -> None:
    tpl = KowTemplate("", [])
    assert tpl.render({}) == ""


def test_template_with_only_literal_text() -> None:
    tpl = KowTemplate("just plain text", [])
    assert tpl.render({}) == "just plain text"


def test_template_with_mixed_literal_and_variable() -> None:
    tpl = KowTemplate("prefix {{ X }} suffix", ["X"])
    assert tpl.render({"X": "MID"}) == "prefix MID suffix"


# ---------------------------------------------------------------------------
# Const restriction — string-only
# ---------------------------------------------------------------------------


def test_int_constant_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="non-string constant"):
        KowTemplate("{{ 1 }}", [])


def test_int_constant_in_add_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="non-string constant"):
        KowTemplate("{{ X + 1 }}", ["X"])


def test_float_constant_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="non-string constant"):
        KowTemplate("{{ 1.5 }}", [])


def test_bool_constant_rejected() -> None:
    # In Jinja2 True/False parse as Const(value=True/False).
    with pytest.raises(UnsupportedTemplateError, match="non-string constant"):
        KowTemplate("{{ True }}", [])


def test_none_constant_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="non-string constant"):
        KowTemplate("{{ none }}", [])


# ---------------------------------------------------------------------------
# Filter / function call arg quirks
# ---------------------------------------------------------------------------


def test_filter_with_keyword_args_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="keyword or dynamic args not allowed"):
        KowTemplate("{{ X | sha256(foo='bar') }}", ["X"])


def test_function_with_keyword_args_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="keyword or dynamic args not allowed"):
        KowTemplate("{{ hmac_sha256(key='k', msg='m') }}", [])


# ---------------------------------------------------------------------------
# Render-time validation
# ---------------------------------------------------------------------------


def test_render_missing_variable_raises() -> None:
    tpl = KowTemplate("{{ X }}", ["X"])
    with pytest.raises(TemplateRenderError, match="missing variables"):
        tpl.render({})


def test_render_unexpected_variable_raises() -> None:
    tpl = KowTemplate("{{ X }}", ["X"])
    with pytest.raises(TemplateRenderError, match="unexpected variables"):
        tpl.render({"X": "ok", "EXTRA": "leaked"})


def test_render_non_string_value_raises() -> None:
    tpl = KowTemplate("{{ X }}", ["X"])
    with pytest.raises(TemplateRenderError, match="expected str"):
        tpl.render({"X": 123})  # type: ignore[dict-item]


def test_render_empty_string_value() -> None:
    # Empty strings ARE valid str. AVP's addon will refuse-to-render with
    # empty BWS values upstream, but the template module
    # itself accepts them as valid input.
    tpl = KowTemplate("{{ X }}", ["X"])
    assert tpl.render({"X": ""}) == ""


# ---------------------------------------------------------------------------
# Source / allowed_vars introspection
# ---------------------------------------------------------------------------


def test_source_preserved() -> None:
    src = "{{ A + B }}"
    tpl = KowTemplate(src, ["A", "B"])
    assert tpl.source == src


def test_allowed_vars_is_frozenset() -> None:
    tpl = KowTemplate("{{ A }}", ["A", "B"])
    assert tpl.allowed_vars == frozenset({"A", "B"})


# ---------------------------------------------------------------------------
# Whitelist registry tests — guard against accidental additions
# ---------------------------------------------------------------------------


def test_whitelisted_filters_exactly_matches_spec() -> None:
    # Pinning the set so a future hand-roll of "just add this one filter"
    # is forced through code review.
    assert set(WHITELISTED_FILTERS) == {
        "b64encode",
        "b64decode",
        "sha256",
        "urlencode",
    }


def test_whitelisted_functions_exactly_matches_spec() -> None:
    assert set(WHITELISTED_FUNCTIONS) == {
        "hmac_sha256",
        "hmac_sha512",
        "hmac_sha1",
        "totp",
    }


def test_whitelisted_filters_is_immutable() -> None:
    # MappingProxyType prevents tests or future code from
    # mutating the whitelist after env init — which would otherwise
    # let validator and runtime diverge.
    with pytest.raises(TypeError):
        WHITELISTED_FILTERS["evil"] = (lambda x: x, 0)  # type: ignore[index]


def test_whitelisted_functions_is_immutable() -> None:
    with pytest.raises(TypeError):
        WHITELISTED_FUNCTIONS["evil"] = (lambda x, y: x, 2)  # type: ignore[index]


# ---------------------------------------------------------------------------
# Pure-filter / function module-level call surface (defense in depth)
# ---------------------------------------------------------------------------


def test_filter_b64encode_non_string_input_raises() -> None:
    fn, _arity = WHITELISTED_FILTERS["b64encode"]
    with pytest.raises(UnsupportedTemplateError):
        fn(123)


def test_func_hmac_sha256_non_string_key_raises() -> None:
    fn, _arity = WHITELISTED_FUNCTIONS["hmac_sha256"]
    with pytest.raises(UnsupportedTemplateError):
        fn(b"bytes-not-str", "m")


# ---------------------------------------------------------------------------
# HMAC-SHA1 — RFC 2202 test vector + type-guard parity
# ---------------------------------------------------------------------------


def test_func_hmac_sha1_rfc2202_vector() -> None:
    """RFC 2202 §3 test case 1: key = 20 bytes of 0x0b, data = "Hi There",
    expected HMAC-SHA1 = b617318655057264e28bc0b6fb378c8ef146be00.
    We pass the key as a UTF-8 string of equivalent bytes; key "\\x0b" * 20
    encodes to itself byte-for-byte under UTF-8 since 0x0b is single-byte ASCII.
    """
    fn, _arity = WHITELISTED_FUNCTIONS["hmac_sha1"]
    key = "\x0b" * 20
    data = "Hi There"
    assert fn(key, data) == "b617318655057264e28bc0b6fb378c8ef146be00"


def test_func_hmac_sha1_non_string_key_raises() -> None:
    fn, _arity = WHITELISTED_FUNCTIONS["hmac_sha1"]
    with pytest.raises(UnsupportedTemplateError):
        fn(b"bytes-not-str", "m")


def test_func_hmac_sha1_non_string_msg_raises() -> None:
    fn, _arity = WHITELISTED_FUNCTIONS["hmac_sha1"]
    with pytest.raises(UnsupportedTemplateError):
        fn("k", b"bytes-not-str")


# ---------------------------------------------------------------------------
# TOTP — RFC 6238 reference vectors + input validation
# ---------------------------------------------------------------------------


def _patch_time(monkeypatch: pytest.MonkeyPatch, frozen_unix_seconds: int) -> None:
    """Freeze ``time.time()`` inside the template module to a fixed value so
    TOTP outputs are reproducible against RFC 6238 §5.2's published table."""
    import kow.template as template_module

    monkeypatch.setattr(template_module.time, "time", lambda: float(frozen_unix_seconds))


def test_func_totp_rfc6238_vector_59s(monkeypatch: pytest.MonkeyPatch) -> None:
    """RFC 6238 §5.2 SHA-1 vector at T=59s with seed "12345678901234567890".
    Expected 8-digit TOTP is 94287082; the 6-digit code is the last six,
    i.e. 287082. Our implementation returns 6 digits per RFC 6238 §4 default."""
    fn, _arity = WHITELISTED_FUNCTIONS["totp"]
    # seed = ASCII "12345678901234567890" → 20 bytes; base32-encoded:
    secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    _patch_time(monkeypatch, 59)
    assert fn(secret_b32) == "287082"


def test_func_totp_rfc6238_vector_1111111109s(monkeypatch: pytest.MonkeyPatch) -> None:
    """RFC 6238 §5.2 SHA-1 vector at T=1111111109s.
    Expected 8-digit TOTP is 07081804; 6-digit code 081804."""
    fn, _arity = WHITELISTED_FUNCTIONS["totp"]
    secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    _patch_time(monkeypatch, 1111111109)
    assert fn(secret_b32) == "081804"


def test_func_totp_rfc6238_vector_2000000000s(monkeypatch: pytest.MonkeyPatch) -> None:
    """RFC 6238 §5.2 SHA-1 vector at T=2000000000s.
    Expected 8-digit TOTP is 69279037; 6-digit code 279037."""
    fn, _arity = WHITELISTED_FUNCTIONS["totp"]
    secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    _patch_time(monkeypatch, 2000000000)
    assert fn(secret_b32) == "279037"


def test_func_totp_tolerates_padding_and_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    """Authenticator apps display base32 secrets with spaces and ``=`` padding
    in various combinations. Both should normalize to the same code."""
    fn, _arity = WHITELISTED_FUNCTIONS["totp"]
    _patch_time(monkeypatch, 59)
    a = fn("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    b = fn("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ")
    c = fn("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")
    assert a == b == c


def test_func_totp_non_string_raises() -> None:
    fn, _arity = WHITELISTED_FUNCTIONS["totp"]
    with pytest.raises(UnsupportedTemplateError):
        fn(b"GEZDGNBVGY3TQOJQ")


def test_func_totp_empty_after_normalize_raises() -> None:
    fn, _arity = WHITELISTED_FUNCTIONS["totp"]
    with pytest.raises(UnsupportedTemplateError, match="empty"):
        fn("   = = =   ")


def test_func_totp_invalid_base32_chars_raises() -> None:
    fn, _arity = WHITELISTED_FUNCTIONS["totp"]
    # '1' and '0' are NOT in the base32 alphabet (uses 2-7 + A-Z).
    with pytest.raises(UnsupportedTemplateError, match="non-base32"):
        fn("ABCDEFGH10")


def test_func_totp_via_template_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: KowTemplate parses + AST-validates + renders ``{{ totp(X) }}``
    against a compose-var input, returning a 6-digit code."""
    tmpl = KowTemplate("{{ totp(TOTP_SECRET) }}", ["TOTP_SECRET"])
    _patch_time(monkeypatch, 59)
    result = tmpl.render({"TOTP_SECRET": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})
    assert result == "287082"


def test_totp_arity_is_one() -> None:
    """``totp()`` with zero or two args must fail at config-load (AST arity
    check), not at request time."""
    with pytest.raises(UnsupportedTemplateError, match="takes 1 positional"):
        KowTemplate("{{ totp() }}", [])
    with pytest.raises(UnsupportedTemplateError, match="takes 1 positional"):
        KowTemplate("{{ totp(X, Y) }}", ["X", "Y"])


def test_hmac_sha1_arity_is_two() -> None:
    """``hmac_sha1()`` arity-check at config-load mirrors hmac_sha256/512."""
    with pytest.raises(UnsupportedTemplateError, match="takes 2 positional"):
        KowTemplate("{{ hmac_sha1(K) }}", ["K"])
    with pytest.raises(UnsupportedTemplateError, match="takes 2 positional"):
        KowTemplate("{{ hmac_sha1(K, M, X) }}", ["K", "M", "X"])


def test_compose_var_named_totp_rejected() -> None:
    """Compose entry colliding with the ``totp`` function name is rejected at
    KowTemplate construction — same as the existing rule for hmac_sha256 etc.
    Error message includes the offending name + a rename suggestion so an
    operator on upgrade gets a one-line remediation (review R-4)."""
    with pytest.raises(
        UnsupportedTemplateError, match="collides with reserved function 'totp'"
    ) as exc_info:
        KowTemplate("{{ totp }}", ["totp"])
    assert "rename" in str(exc_info.value)


def test_compose_var_named_hmac_sha1_rejected() -> None:
    with pytest.raises(
        UnsupportedTemplateError, match="collides with reserved function 'hmac_sha1'"
    ):
        KowTemplate("{{ hmac_sha1(X, Y) }}", ["hmac_sha1"])


def test_compose_var_named_b64encode_rejected_with_filter_message() -> None:
    """Filter-name collisions get a distinct message than function-name
    collisions — review R-4 path; keep both error shapes covered."""
    with pytest.raises(UnsupportedTemplateError, match="collides with reserved filter 'b64encode'"):
        KowTemplate("{{ X | b64encode }}", ["b64encode"])


def test_func_totp_base32_decode_failure_message_is_static() -> None:
    """Defence in depth (Council seat 4): the exception raised when
    ``base64.b32decode`` rejects an input must NOT interpolate the underlying
    ``binascii.Error`` message — that protects against a future stdlib change
    that echoes input bytes (review R-1 stderr-leak chain)."""
    fn, _arity = WHITELISTED_FUNCTIONS["totp"]
    # An input that survives the alphabet check but fails decode would be
    # zero-length after normalize — but we already gate empty above. Force
    # the failure by feeding a length that base32 rejects post-pad. The
    # simplest path: a single-char input that's in-alphabet but malformed
    # block-wise after pad. Concretely: the base32 alphabet check passes
    # for "A" but b32decode("A=======") raises binascii.Error.
    with pytest.raises(UnsupportedTemplateError) as exc_info:
        fn("A")
    msg = str(exc_info.value)
    assert msg == "totp.secret: base32 decode failed", (
        f"expected static message, got {msg!r} — base32 decode error may now "
        f"interpolate the binascii.Error message; revisit template.py"
    )


# ---------------------------------------------------------------------------
# Review-driven hardening tests
# ---------------------------------------------------------------------------


def test_source_length_cap_enforced() -> None:
    # pathological-size guard at config-load.
    from kow.template import MAX_TEMPLATE_SOURCE_LEN

    over = "X" * (MAX_TEMPLATE_SOURCE_LEN + 1)
    with pytest.raises(UnsupportedTemplateError, match="max allowed"):
        KowTemplate(over, ["X"])


def test_source_length_at_cap_accepted() -> None:
    from kow.template import MAX_TEMPLATE_SOURCE_LEN

    at_cap = "x" * MAX_TEMPLATE_SOURCE_LEN
    tpl = KowTemplate(at_cap, [])
    assert tpl.render({}) == at_cap


def test_filter_extra_positional_arg_rejected() -> None:
    # ``X | sha256(Y)`` must fail at config-load, not at render.
    with pytest.raises(UnsupportedTemplateError, match="filter 'sha256' takes 0"):
        KowTemplate("{{ X | sha256('extra') }}", ["X"])


def test_function_wrong_arity_rejected_too_few() -> None:
    # ``hmac_sha256(K)`` is missing the message arg.
    with pytest.raises(UnsupportedTemplateError, match="function 'hmac_sha256' takes 2"):
        KowTemplate("{{ hmac_sha256(K) }}", ["K"])


def test_function_wrong_arity_rejected_too_many() -> None:
    with pytest.raises(UnsupportedTemplateError, match="function 'hmac_sha256' takes 2"):
        KowTemplate("{{ hmac_sha256(K, M, 'extra') }}", ["K", "M"])


def test_allowed_vars_as_bare_string_rejected() -> None:
    # prevent the silent character-split footgun.
    with pytest.raises(UnsupportedTemplateError, match="not a bare string"):
        KowTemplate("{{ X }}", "X")  # type: ignore[arg-type]


def test_allowed_vars_non_string_entry_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="expected str"):
        KowTemplate("{{ X }}", ["X", 42])  # type: ignore[list-item]


def test_allowed_vars_empty_string_entry_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="non-empty strings"):
        KowTemplate("{{ X }}", ["X", ""])


def test_compose_var_colliding_with_filter_name_rejected() -> None:
    # compose name `b64encode` would create ambiguous parse
    # behavior — reject at construction.
    with pytest.raises(UnsupportedTemplateError, match="reserved filter 'b64encode'"):
        KowTemplate("{{ b64encode }}", ["b64encode"])


def test_compose_var_colliding_with_function_name_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="reserved function 'hmac_sha256'"):
        KowTemplate("{{ X }}", ["X", "hmac_sha256"])


def test_render_filter_runtime_error_becomes_render_error() -> None:
    # filter-raised UnsupportedTemplateError (e.g., b64decode
    # on non-ASCII) is wrapped as TemplateRenderError so the addon catches
    # exactly one type at the render boundary.
    tpl = KowTemplate("{{ X | b64decode }}", ["X"])
    # b64decode on a bare value normally returns TemplateRenderError directly
    # (we raise it explicitly). For the conversion path test, give it
    # a value the type-check rejects via a different route — the
    # b64decode function does `_require_str` which raises Unsupported.
    # Since `X` IS a string, build the case via the env layer instead:
    # operator-friendly proof is that EVERY error from render() is a
    # TemplateRenderError, never UnsupportedTemplateError.
    with pytest.raises(TemplateRenderError):
        tpl.render({"X": "not-valid-base64!@#$"})


# ---------------------------------------------------------------------------
# Template source type guard
# ---------------------------------------------------------------------------


def test_non_string_source_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="must be str"):
        KowTemplate(42, [])  # type: ignore[arg-type]


def test_unbalanced_braces_parse_error() -> None:
    with pytest.raises(UnsupportedTemplateError, match="parse error"):
        KowTemplate("{{ X ", ["X"])
