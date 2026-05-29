"""Adversarial corpus for the AVP template sandbox.

Every test here is a real Jinja2 sandbox-escape pattern, a known historical
CVE shape, or a feature we deliberately disabled. They MUST all raise
UnsupportedTemplateError at construction — failure at render-time is too
late (a malicious binding would already be loaded).

If a test in here starts passing where it used to fail, the sandbox has a
new hole. Treat that as a release blocker.
"""

from __future__ import annotations

import pytest

from agent_vault_proxy.template import AvpTemplate, UnsupportedTemplateError


def _assert_rejected(source: str, allowed: list[str] | None = None) -> None:
    with pytest.raises(UnsupportedTemplateError):
        AvpTemplate(source, allowed or ["X", "Y"])


# ---------------------------------------------------------------------------
# Class-walk escapes — the canonical Jinja2 sandbox attack
# ---------------------------------------------------------------------------


def test_class_walk_via_empty_string_rejected() -> None:
    _assert_rejected("{{ ''.__class__.__mro__[1].__subclasses__() }}")


def test_class_walk_via_variable_rejected() -> None:
    _assert_rejected("{{ X.__class__.__mro__[1].__subclasses__() }}")


def test_class_walk_via_attr_filter_rejected() -> None:
    # CVE-style: attr filter would walk attributes if it were whitelisted.
    _assert_rejected("{{ X | attr('__class__') }}")


def test_getattr_via_subscript_rejected() -> None:
    _assert_rejected("{{ X['__class__'] }}")


def test_globals_dunder_rejected() -> None:
    _assert_rejected("{{ X.__globals__ }}")


def test_builtins_traversal_rejected() -> None:
    _assert_rejected("{{ X.__init__.__globals__['__builtins__'] }}")


# ---------------------------------------------------------------------------
# Historical Jinja2 CVE shapes — even though we don't whitelist these
# filters, prove they're rejected so a future "just enable format for
# debugging" PR fails the corpus.
# ---------------------------------------------------------------------------


def test_format_filter_rejected_cve_2019_10906() -> None:
    # CVE-2019-10906: str.format access to internals.
    _assert_rejected("{{ X | format('y') }}")


def test_format_map_rejected_cve_2024_56326() -> None:
    # str.format_map() escape family. Method call → Getattr → rejected.
    _assert_rejected("{{ X.format_map({}) }}")


def test_xmlattr_filter_rejected_cve_2024_22195() -> None:
    _assert_rejected("{{ X | xmlattr }}")


# ---------------------------------------------------------------------------
# Control flow — none of For/If/Macro/Block/Include/Extends/Import is allowed
# ---------------------------------------------------------------------------


def test_for_loop_rejected() -> None:
    _assert_rejected("{% for i in [X, Y] %}{{ i }}{% endfor %}")


def test_if_statement_rejected() -> None:
    _assert_rejected("{% if X %}{{ X }}{% endif %}")


def test_ternary_if_expression_rejected() -> None:
    _assert_rejected("{{ X if Y else Y }}")


def test_set_statement_rejected() -> None:
    _assert_rejected("{% set tmp = X %}{{ tmp }}")


def test_macro_rejected() -> None:
    _assert_rejected("{% macro f(a) %}{{ a }}{% endmacro %}{{ f(X) }}")


def test_block_rejected() -> None:
    _assert_rejected("{% block b %}{{ X }}{% endblock %}")


def test_include_rejected() -> None:
    _assert_rejected("{% include 'other' %}")


def test_extends_rejected() -> None:
    _assert_rejected("{% extends 'base' %}")


def test_import_rejected() -> None:
    _assert_rejected("{% import 'foo' as foo %}{{ foo.bar }}")


def test_from_import_rejected() -> None:
    _assert_rejected("{% from 'foo' import bar %}{{ bar }}")


# ---------------------------------------------------------------------------
# Arithmetic and comparison — string-only model, so anything numeric or
# logical must be rejected
# ---------------------------------------------------------------------------


def test_multiplication_rejected() -> None:
    # String * int IS legal Python but a great DoS vector — disabled.
    _assert_rejected("{{ X * 100 }}")


def test_division_rejected() -> None:
    _assert_rejected("{{ X / Y }}")


def test_modulo_rejected() -> None:
    # ``"%s" % X`` — string formatting escape vector in Python.
    _assert_rejected("{{ X % Y }}")


def test_power_rejected() -> None:
    _assert_rejected("{{ X ** Y }}")


def test_subtraction_rejected() -> None:
    _assert_rejected("{{ X - Y }}")


def test_floor_division_rejected() -> None:
    _assert_rejected("{{ X // Y }}")


def test_unary_minus_rejected() -> None:
    _assert_rejected("{{ -X }}")


def test_unary_plus_rejected() -> None:
    _assert_rejected("{{ +X }}")


def test_unary_not_rejected() -> None:
    _assert_rejected("{{ not X }}")


def test_comparison_eq_rejected() -> None:
    _assert_rejected("{{ X == Y }}")


def test_comparison_lt_rejected() -> None:
    _assert_rejected("{{ X < Y }}")


def test_logical_and_rejected() -> None:
    _assert_rejected("{{ X and Y }}")


def test_logical_or_rejected() -> None:
    _assert_rejected("{{ X or Y }}")


def test_is_test_rejected() -> None:
    # ``{{ X is defined }}`` — Test node. We disabled all tests via empty
    # env.tests dict, AND the Test AST node is not in our allow list.
    _assert_rejected("{{ X is defined }}")


# ---------------------------------------------------------------------------
# Subscript / attribute / collection literals — anything that could read
# from the BWS dict via a non-literal key
# ---------------------------------------------------------------------------


def test_subscript_with_const_rejected() -> None:
    _assert_rejected("{{ X[0] }}")


def test_subscript_with_string_rejected() -> None:
    _assert_rejected("{{ X['username'] }}")


def test_attribute_access_rejected() -> None:
    _assert_rejected("{{ X.upper }}")


def test_method_call_rejected() -> None:
    _assert_rejected("{{ X.upper() }}")


def test_slice_rejected() -> None:
    _assert_rejected("{{ X[0:2] }}")


def test_list_literal_rejected() -> None:
    _assert_rejected("{{ [X, Y] }}")


def test_tuple_literal_rejected() -> None:
    _assert_rejected("{{ (X, Y) }}")


def test_dict_literal_rejected() -> None:
    _assert_rejected("{{ {'k': X} }}")


# ---------------------------------------------------------------------------
# Jinja2 implicit identifiers — namespace, range, lipsum, dict, cycler, etc.
# None of these are in our globals; they should fall to Name lookup and
# fail because they're not in compose.
# ---------------------------------------------------------------------------


def test_namespace_rejected() -> None:
    _assert_rejected("{{ namespace(x=X) }}")


def test_range_rejected() -> None:
    _assert_rejected("{{ range(10) }}")


def test_lipsum_rejected() -> None:
    _assert_rejected("{{ lipsum() }}")


def test_cycler_rejected() -> None:
    _assert_rejected("{{ cycler('a', 'b') }}")


def test_dict_func_rejected() -> None:
    _assert_rejected("{{ dict(x=X) }}")


def test_self_rejected() -> None:
    _assert_rejected("{{ self }}")


def test_loop_rejected() -> None:
    # ``loop`` is only valid inside a for, but writing it standalone
    # parses as a Name and falls through to unknown-variable.
    _assert_rejected("{{ loop }}")


# ---------------------------------------------------------------------------
# Filter-shape edge cases
# ---------------------------------------------------------------------------


def test_dynamic_filter_args_rejected() -> None:
    # ``X | sha256(*Y)`` — splat the var as args.
    _assert_rejected("{{ X | sha256(*Y) }}")


def test_dynamic_filter_kwargs_rejected() -> None:
    _assert_rejected("{{ X | sha256(**Y) }}")


def test_chained_unknown_filter_rejected() -> None:
    # First filter is whitelisted, second isn't — must reject.
    _assert_rejected("{{ X | b64encode | format('y') }}")


def test_chained_unknown_then_whitelisted_filter_rejected() -> None:
    _assert_rejected("{{ X | format('y') | b64encode }}")


def test_indirect_function_via_filter_rejected() -> None:
    # ``X | hmac_sha256`` — hmac_sha256 is a function, not a filter; the
    # Filter visitor checks the filters whitelist.
    _assert_rejected("{{ X | hmac_sha256 }}")


# ---------------------------------------------------------------------------
# Variable scope — only compose vars are reachable
# ---------------------------------------------------------------------------


def test_undefined_variable_at_compile_rejected() -> None:
    _assert_rejected("{{ NOT_IN_COMPOSE }}", ["X"])


def test_partial_compose_unknown_in_concat_rejected() -> None:
    _assert_rejected("{{ X + UNKNOWN }}", ["X"])


# ---------------------------------------------------------------------------
# Parsing pathology — these must NOT crash the validator, they must raise
# a clean UnsupportedTemplateError.
# ---------------------------------------------------------------------------


def test_deeply_nested_addition_rejected_or_accepted_cleanly() -> None:
    # 100-deep nested Add chain — accept (it's structurally legal string
    # concatenation). The validator should not stack-overflow.
    deep = " + ".join(["X"] * 100)
    tpl = AvpTemplate("{{ " + deep + " }}", ["X"])
    assert tpl.render({"X": "a"}) == "a" * 100


def test_template_with_jinja2_comment_accepted() -> None:
    # Comments are stripped by the parser, leave no AST artifact.
    tpl = AvpTemplate("{# comment #}{{ X }}", ["X"])
    assert tpl.render({"X": "val"}) == "val"


def test_raw_block_emits_literal_text_no_escape() -> None:
    # ``{% raw %}...{% endraw %}`` is a parser-level construct that emits
    # its body as a single TemplateData node — i.e. operator-controlled
    # literal text. Not an escape: the body is never evaluated, just
    # streamed as bytes. The operator already controls bindings.yaml, so
    # putting raw text in the template is no worse than putting it in
    # ``inject.header``. Documented here to lock that intuition.
    tpl = AvpTemplate("{% raw %}{{ X }}{% endraw %}", ["X"])
    assert tpl.render({"X": "ignored"}) == "{{ X }}"


# ---------------------------------------------------------------------------
# Output / autoescape sanity — we autoescape=False, so make sure the
# output isn't accidentally HTML-escaped (header values are not HTML).
# ---------------------------------------------------------------------------


def test_special_chars_not_html_escaped() -> None:
    tpl = AvpTemplate("{{ X }}", ["X"])
    # If autoescape were True, `<` would become `&lt;`. Verify raw.
    assert tpl.render({"X": "<a&b>"}) == "<a&b>"
