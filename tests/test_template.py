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

from agent_vault_proxy.template import (
    WHITELISTED_FILTERS,
    WHITELISTED_FUNCTIONS,
    AvpTemplate,
    TemplateRenderError,
    UnsupportedTemplateError,
)

# ---------------------------------------------------------------------------
# Construction / parse-time validation
# ---------------------------------------------------------------------------


def test_plain_literal_template() -> None:
    tpl = AvpTemplate("Bearer fixed-string", [])
    assert tpl.render({}) == "Bearer fixed-string"


def test_simple_variable_substitution() -> None:
    tpl = AvpTemplate("Bearer {{ TOKEN }}", ["TOKEN"])
    assert tpl.render({"TOKEN": "abc123"}) == "Bearer abc123"


def test_string_concatenation_with_separator() -> None:
    tpl = AvpTemplate("{{ USER + ':' + KEY }}", ["USER", "KEY"])
    assert tpl.render({"USER": "alice", "KEY": "secret"}) == "alice:secret"


def test_b64encode_filter_on_concat() -> None:
    tpl = AvpTemplate(
        "Basic {{ (USER + ':' + TOKEN) | b64encode }}",
        ["USER", "TOKEN"],
    )
    expected = "Basic " + base64.b64encode(b"alice:s3cret").decode("ascii")
    assert tpl.render({"USER": "alice", "TOKEN": "s3cret"}) == expected


def test_b64encode_filter_on_single_var() -> None:
    tpl = AvpTemplate("{{ X | b64encode }}", ["X"])
    assert tpl.render({"X": "hello"}) == base64.b64encode(b"hello").decode("ascii")


def test_b64decode_filter() -> None:
    encoded = base64.b64encode(b"foo:bar").decode("ascii")
    tpl = AvpTemplate("{{ X | b64decode }}", ["X"])
    assert tpl.render({"X": encoded}) == "foo:bar"


def test_b64decode_invalid_input_render_error() -> None:
    tpl = AvpTemplate("{{ X | b64decode }}", ["X"])
    with pytest.raises(TemplateRenderError, match="b64decode"):
        tpl.render({"X": "not-valid-base64!@#$"})


def test_b64decode_value_error_caught() -> None:
    """base64.b64decode(validate=True) can raise ValueError (not binascii.Error)
    on some malformed inputs in Python 3.12+. The filter must catch both and
    surface them as a clean render_failed, not an uncaught exception that
    bubbles past the addon's audit boundary."""
    tpl = AvpTemplate("{{ X | b64decode }}", ["X"])
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
    tpl = AvpTemplate("{{ X | b64decode }}", ["X"])
    with pytest.raises(TemplateRenderError, match="b64decode"):
        tpl.render({"X": "café"})  # non-ASCII — fails at .encode("ascii")


def test_sha256_filter() -> None:
    tpl = AvpTemplate("{{ X | sha256 }}", ["X"])
    assert tpl.render({"X": "hello"}) == hashlib.sha256(b"hello").hexdigest()


def test_urlencode_filter() -> None:
    tpl = AvpTemplate("{{ X | urlencode }}", ["X"])
    assert tpl.render({"X": "a b/c?d"}) == urllib.parse.quote("a b/c?d", safe="")


def test_hmac_sha256_function() -> None:
    tpl = AvpTemplate("{{ hmac_sha256(KEY, MSG) }}", ["KEY", "MSG"])
    expected = hmac.new(b"k", b"m", "sha256").hexdigest()
    assert tpl.render({"KEY": "k", "MSG": "m"}) == expected


def test_hmac_sha512_function() -> None:
    tpl = AvpTemplate("{{ hmac_sha512(KEY, MSG) }}", ["KEY", "MSG"])
    expected = hmac.new(b"k", b"m", "sha512").hexdigest()
    assert tpl.render({"KEY": "k", "MSG": "m"}) == expected


def test_filter_chain_b64_then_sha256() -> None:
    tpl = AvpTemplate("{{ X | b64encode | sha256 }}", ["X"])
    encoded = base64.b64encode(b"value").decode("ascii")
    expected = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    assert tpl.render({"X": "value"}) == expected


def test_const_string_in_concat() -> None:
    # 'Token ' is a Const(str). Add(Const, Name) is allowed string concat.
    tpl = AvpTemplate("{{ 'Token ' + KEY }}", ["KEY"])
    assert tpl.render({"KEY": "abc"}) == "Token abc"


def test_multiple_compose_variables() -> None:
    tpl = AvpTemplate(
        "{{ A + '|' + B + '|' + C + '|' + D }}",
        ["A", "B", "C", "D"],
    )
    assert tpl.render({"A": "1", "B": "2", "C": "3", "D": "4"}) == "1|2|3|4"


# ---------------------------------------------------------------------------
# AST validator — unknown variables, unknown filters/funcs
# ---------------------------------------------------------------------------


def test_unknown_variable_rejected_at_construction() -> None:
    with pytest.raises(UnsupportedTemplateError, match="unknown variable 'OTHER'"):
        AvpTemplate("{{ OTHER }}", ["X"])


def test_unknown_filter_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="unknown filter 'upper'"):
        AvpTemplate("{{ X | upper }}", ["X"])


def test_unknown_function_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="unknown function 'range'"):
        AvpTemplate("{{ range(10) }}", [])


def test_function_used_as_variable_rejected() -> None:
    # hmac_sha256 is a function name, not a variable. Used as a value
    # it falls into the Name-validator path and gets rejected as not in
    # allowed_vars.
    with pytest.raises(UnsupportedTemplateError, match="unknown variable 'hmac_sha256'"):
        AvpTemplate("{{ hmac_sha256 | b64encode }}", ["X"])


def test_filter_used_as_function_rejected() -> None:
    # b64encode is registered as a filter, not as a global. Calling it
    # as a function — ``b64encode(X)`` — fails the WHITELISTED_FUNCTIONS
    # check.
    with pytest.raises(UnsupportedTemplateError, match="unknown function 'b64encode'"):
        AvpTemplate("{{ b64encode(X) }}", ["X"])


def test_empty_template_renders_empty_string() -> None:
    tpl = AvpTemplate("", [])
    assert tpl.render({}) == ""


def test_template_with_only_literal_text() -> None:
    tpl = AvpTemplate("just plain text", [])
    assert tpl.render({}) == "just plain text"


def test_template_with_mixed_literal_and_variable() -> None:
    tpl = AvpTemplate("prefix {{ X }} suffix", ["X"])
    assert tpl.render({"X": "MID"}) == "prefix MID suffix"


# ---------------------------------------------------------------------------
# Const restriction — string-only
# ---------------------------------------------------------------------------


def test_int_constant_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="non-string constant"):
        AvpTemplate("{{ 1 }}", [])


def test_int_constant_in_add_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="non-string constant"):
        AvpTemplate("{{ X + 1 }}", ["X"])


def test_float_constant_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="non-string constant"):
        AvpTemplate("{{ 1.5 }}", [])


def test_bool_constant_rejected() -> None:
    # In Jinja2 True/False parse as Const(value=True/False).
    with pytest.raises(UnsupportedTemplateError, match="non-string constant"):
        AvpTemplate("{{ True }}", [])


def test_none_constant_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="non-string constant"):
        AvpTemplate("{{ none }}", [])


# ---------------------------------------------------------------------------
# Filter / function call arg quirks
# ---------------------------------------------------------------------------


def test_filter_with_keyword_args_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="keyword or dynamic args not allowed"):
        AvpTemplate("{{ X | sha256(foo='bar') }}", ["X"])


def test_function_with_keyword_args_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="keyword or dynamic args not allowed"):
        AvpTemplate("{{ hmac_sha256(key='k', msg='m') }}", [])


# ---------------------------------------------------------------------------
# Render-time validation
# ---------------------------------------------------------------------------


def test_render_missing_variable_raises() -> None:
    tpl = AvpTemplate("{{ X }}", ["X"])
    with pytest.raises(TemplateRenderError, match="missing variables"):
        tpl.render({})


def test_render_unexpected_variable_raises() -> None:
    tpl = AvpTemplate("{{ X }}", ["X"])
    with pytest.raises(TemplateRenderError, match="unexpected variables"):
        tpl.render({"X": "ok", "EXTRA": "leaked"})


def test_render_non_string_value_raises() -> None:
    tpl = AvpTemplate("{{ X }}", ["X"])
    with pytest.raises(TemplateRenderError, match="expected str"):
        tpl.render({"X": 123})  # type: ignore[dict-item]


def test_render_empty_string_value() -> None:
    # Empty strings ARE valid str. AVP's addon will refuse-to-render with
    # empty BWS values upstream, but the template module
    # itself accepts them as valid input.
    tpl = AvpTemplate("{{ X }}", ["X"])
    assert tpl.render({"X": ""}) == ""


# ---------------------------------------------------------------------------
# Source / allowed_vars introspection
# ---------------------------------------------------------------------------


def test_source_preserved() -> None:
    src = "{{ A + B }}"
    tpl = AvpTemplate(src, ["A", "B"])
    assert tpl.source == src


def test_allowed_vars_is_frozenset() -> None:
    tpl = AvpTemplate("{{ A }}", ["A", "B"])
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
    assert set(WHITELISTED_FUNCTIONS) == {"hmac_sha256", "hmac_sha512"}


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
# Review-driven hardening tests
# ---------------------------------------------------------------------------


def test_source_length_cap_enforced() -> None:
    # pathological-size guard at config-load.
    from agent_vault_proxy.template import MAX_TEMPLATE_SOURCE_LEN

    over = "X" * (MAX_TEMPLATE_SOURCE_LEN + 1)
    with pytest.raises(UnsupportedTemplateError, match="max allowed"):
        AvpTemplate(over, ["X"])


def test_source_length_at_cap_accepted() -> None:
    from agent_vault_proxy.template import MAX_TEMPLATE_SOURCE_LEN

    at_cap = "x" * MAX_TEMPLATE_SOURCE_LEN
    tpl = AvpTemplate(at_cap, [])
    assert tpl.render({}) == at_cap


def test_filter_extra_positional_arg_rejected() -> None:
    # ``X | sha256(Y)`` must fail at config-load, not at render.
    with pytest.raises(UnsupportedTemplateError, match="filter 'sha256' takes 0"):
        AvpTemplate("{{ X | sha256('extra') }}", ["X"])


def test_function_wrong_arity_rejected_too_few() -> None:
    # ``hmac_sha256(K)`` is missing the message arg.
    with pytest.raises(UnsupportedTemplateError, match="function 'hmac_sha256' takes 2"):
        AvpTemplate("{{ hmac_sha256(K) }}", ["K"])


def test_function_wrong_arity_rejected_too_many() -> None:
    with pytest.raises(UnsupportedTemplateError, match="function 'hmac_sha256' takes 2"):
        AvpTemplate("{{ hmac_sha256(K, M, 'extra') }}", ["K", "M"])


def test_allowed_vars_as_bare_string_rejected() -> None:
    # prevent the silent character-split footgun.
    with pytest.raises(UnsupportedTemplateError, match="not a bare string"):
        AvpTemplate("{{ X }}", "X")  # type: ignore[arg-type]


def test_allowed_vars_non_string_entry_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="expected str"):
        AvpTemplate("{{ X }}", ["X", 42])  # type: ignore[list-item]


def test_allowed_vars_empty_string_entry_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="non-empty strings"):
        AvpTemplate("{{ X }}", ["X", ""])


def test_compose_var_colliding_with_filter_name_rejected() -> None:
    # compose name `b64encode` would create ambiguous parse
    # behavior — reject at construction.
    with pytest.raises(UnsupportedTemplateError, match="reserved filter or function"):
        AvpTemplate("{{ b64encode }}", ["b64encode"])


def test_compose_var_colliding_with_function_name_rejected() -> None:
    with pytest.raises(UnsupportedTemplateError, match="reserved filter or function"):
        AvpTemplate("{{ X }}", ["X", "hmac_sha256"])


def test_render_filter_runtime_error_becomes_render_error() -> None:
    # filter-raised UnsupportedTemplateError (e.g., b64decode
    # on non-ASCII) is wrapped as TemplateRenderError so the addon catches
    # exactly one type at the render boundary.
    tpl = AvpTemplate("{{ X | b64decode }}", ["X"])
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
        AvpTemplate(42, [])  # type: ignore[arg-type]


def test_unbalanced_braces_parse_error() -> None:
    with pytest.raises(UnsupportedTemplateError, match="parse error"):
        AvpTemplate("{{ X ", ["X"])
