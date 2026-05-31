"""Sandboxed Jinja2 templating for composite-secret bindings.

See ``docs/architecture.md`` §4.2 for the threat model and the rationale
behind the AST-level deny-by-default validator below.

What this module enforces:
 * Templates parse via Jinja2's ImmutableSandboxedEnvironment but the
   environment is wiped of every default filter, global, and test, and
   re-populated with our whitelist only.
 * The parsed AST is walked with a deny-by-default visitor. Only the AST
   nodes we explicitly allow survive — every other node type raises
   UnsupportedTemplateError at config-load (before any secret value
   ever flows through Jinja2).
 * String-only model: Const literals must be str; arithmetic, comparison,
   subscript, attribute access, control flow are all structurally
   impossible. The classic class-walk escape
   (``{{ ''.__class__.__mro__[1].__subclasses__() }}``) is blocked twice:
   once by the AST validator rejecting Getattr/Subscript nodes, once by
   the SandboxedEnvironment's own is_safe_attribute defaults.
 * Variables are restricted to the binding's compose list at AST time;
   render-time also validates the dict passed in.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import urllib.parse
from types import MappingProxyType
from typing import Any

import jinja2
from jinja2 import nodes
from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2.visitor import NodeVisitor

__all__ = [
    "MAX_TEMPLATE_SOURCE_LEN",
    "AvpTemplate",
    "TemplateRenderError",
    "UnsupportedTemplateError",
    "WHITELISTED_FILTERS",
    "WHITELISTED_FUNCTIONS",
]


# Resource bound on operator-supplied template source. 4 KiB is far above
# any realistic auth header template (Jira/Slack/GitHub composites fit in
# ~100 bytes). Caps pathological depth/length at config-load before any
# AST walk runs. Operator-side guardrail; not a defense against an
# adversarial bindings.yaml (which is already game over per threat model).
MAX_TEMPLATE_SOURCE_LEN = 4096


class UnsupportedTemplateError(ValueError):
    """Raised at config-load when an inject_template uses a feature the
    sandbox doesn't allow (unsupported AST node, unknown filter/function,
    non-string constant, unknown variable, etc.). Inherits from ValueError
    so pydantic surfaces it cleanly inside ValidationError."""


class TemplateRenderError(Exception):
    """Raised at request time when rendering a previously-validated template
    fails (e.g., a filter function raises). The addon catches this and
    returns 503 + audits inject_decision=denied,reason=render_failed."""


# ---------------------------------------------------------------------------
# Whitelisted filters and functions.
#
# Filters: ``{{ X | name }}`` — value-transforming, single-input.
# Functions: ``{{ name(arg1, arg2) }}`` — multi-input.
#
# Every callable here MUST accept and return ``str``. Type-check inputs and
# raise UnsupportedTemplateError if a caller violates it — this is defense
# in depth; the AST validator and render-time variable-dict check should
# already have caught non-string inputs.
# ---------------------------------------------------------------------------


def _require_str(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise UnsupportedTemplateError(f"{name}: expected str, got {type(value).__name__}")
    return value


def _filter_b64encode(value: Any) -> str:
    """Standard RFC 4648 §4 base64 of UTF-8 bytes of ``value``. ASCII output."""
    v = _require_str("b64encode", value)
    return base64.b64encode(v.encode("utf-8")).decode("ascii")


def _filter_b64decode(value: Any) -> str:
    """Strict RFC 4648 base64 decode. Raises on invalid padding or characters."""
    v = _require_str("b64decode", value)
    try:
        return base64.b64decode(v.encode("ascii"), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeEncodeError, UnicodeDecodeError) as e:
        # The except tuple covers four distinct failure modes on the single
        # expression above:
        #   - binascii.Error / ValueError — base64.b64decode(validate=True)
        #     surfaces malformed input as either, depending on CPython
        #     version + which validation rule fails first.
        #   - UnicodeEncodeError — v.encode("ascii") raises this if the
        #     composite value contains any non-ASCII character. Without
        #     this in the tuple, a composite secret with e.g. 'é' would
        #     surface as an uncaught exception in the addon and bypass the
        #     render_failed audit boundary.
        #   - UnicodeDecodeError — the final .decode("utf-8") on the
        #     decoded bytes; covers binary payloads that aren't valid UTF-8.
        raise TemplateRenderError(f"b64decode: invalid input: {e}") from None


def _filter_sha256(value: Any) -> str:
    """Lowercase hex SHA-256 digest of UTF-8 bytes of ``value``."""
    v = _require_str("sha256", value)
    return hashlib.sha256(v.encode("utf-8")).hexdigest()


def _filter_urlencode(value: Any) -> str:
    """Percent-encode per RFC 3986, no safe characters."""
    v = _require_str("urlencode", value)
    return urllib.parse.quote(v, safe="")


def _func_hmac_sha256(key: Any, msg: Any) -> str:
    """Lowercase hex HMAC-SHA256(key, msg) over UTF-8 bytes."""
    k = _require_str("hmac_sha256.key", key)
    m = _require_str("hmac_sha256.msg", msg)
    return hmac.new(k.encode("utf-8"), m.encode("utf-8"), "sha256").hexdigest()


def _func_hmac_sha512(key: Any, msg: Any) -> str:
    """Lowercase hex HMAC-SHA512(key, msg) over UTF-8 bytes."""
    k = _require_str("hmac_sha512.key", key)
    m = _require_str("hmac_sha512.msg", msg)
    return hmac.new(k.encode("utf-8"), m.encode("utf-8"), "sha512").hexdigest()


# Whitelists are immutable read-only views (Oracle C8). Each entry maps to
# (callable, expected_positional_arg_count). Arity is enforced at AST-walk
# time so a wrong-arg-count template fails AT CONFIG-LOAD, not at the first
# request that hits it (Oracle C3 + C4).
#
# Filters: positional-arg count EXCLUDES the implicit `value` (the input to
# the | operator). E.g. ``X | sha256`` is arity 0; ``X | foo(a, b)`` is
# arity 2. Today every filter is arity 0.
#
# Functions: positional-arg count is the total argument list. hmac_sha256
# is arity 2 (key, msg).
_FILTERS_RAW: dict[str, tuple[Any, int]] = {
    "b64encode": (_filter_b64encode, 0),
    "b64decode": (_filter_b64decode, 0),
    "sha256": (_filter_sha256, 0),
    "urlencode": (_filter_urlencode, 0),
}

_FUNCTIONS_RAW: dict[str, tuple[Any, int]] = {
    "hmac_sha256": (_func_hmac_sha256, 2),
    "hmac_sha512": (_func_hmac_sha512, 2),
}

# Public, read-only views. Mutation attempts raise TypeError. Prevents tests
# or future code from monkeypatching the whitelist after env init, which
# would otherwise let validator and runtime diverge.
WHITELISTED_FILTERS: MappingProxyType[str, tuple[Any, int]] = MappingProxyType(_FILTERS_RAW)
WHITELISTED_FUNCTIONS: MappingProxyType[str, tuple[Any, int]] = MappingProxyType(_FUNCTIONS_RAW)


# ---------------------------------------------------------------------------
# Sandboxed environment.
#
# Single module-level instance, reused across all bindings. The env's
# filters/globals/tests are set ONCE at module import and never mutated.
# Threadsafe under that contract.
# ---------------------------------------------------------------------------


class _AvpTemplateEnvironment(ImmutableSandboxedEnvironment):
    pass


def _make_environment() -> _AvpTemplateEnvironment:
    env = _AvpTemplateEnvironment(
        autoescape=False,
        keep_trailing_newline=False,
    )
    # Strip just the callables (drop arity metadata) for the env dicts.
    env.filters = {name: fn for name, (fn, _arity) in _FILTERS_RAW.items()}
    env.globals = {name: fn for name, (fn, _arity) in _FUNCTIONS_RAW.items()}
    env.tests = {}
    return env


_SHARED_ENV = _make_environment()


# ---------------------------------------------------------------------------
# AST validator.
#
# Deny-by-default: generic_visit raises. Only nodes with explicit visitors
# pass. This is the single most important security boundary in this module
# — every escape attempt (class walk, subscript, control flow, attribute
# access) lands on generic_visit because we never wrote a visitor for it.
# ---------------------------------------------------------------------------


class _AstValidator(NodeVisitor):
    def __init__(self, allowed_vars: frozenset[str]) -> None:
        self.allowed_vars = allowed_vars

    def generic_visit(self, node: nodes.Node, *args: Any, **kwargs: Any) -> None:
        raise UnsupportedTemplateError(
            f"unsupported template construct: {type(node).__name__}; "
            f"allowed nodes: Template, Output, TemplateData, Name, Const, "
            f"Filter, Call, Add(string-concat)"
        )

    # NodeVisitor dispatch uses the AST class name (e.g. visit_Template).
    # That collides with PEP 8 lowercase-method naming; suppress N802 on
    # these specific methods only.

    def visit_Template(self, node: nodes.Template) -> None:  # noqa: N802
        for child in node.body:
            self.visit(child)

    def visit_Output(self, node: nodes.Output) -> None:  # noqa: N802
        for child in node.nodes:
            self.visit(child)

    def visit_TemplateData(self, node: nodes.TemplateData) -> None:  # noqa: ARG002, N802
        # Literal text outside {{ }} expressions (e.g., "Basic " in
        # "Basic {{ ... }}"). Fixed bytes from bindings.yaml; safe.
        return

    def visit_Const(self, node: nodes.Const) -> None:  # noqa: N802
        if not isinstance(node.value, str):
            raise UnsupportedTemplateError(
                f"non-string constant {node.value!r} "
                f"({type(node.value).__name__}) not allowed; "
                f"templates work on strings only"
            )

    def visit_Name(self, node: nodes.Name) -> None:  # noqa: N802
        if node.name not in self.allowed_vars:
            raise UnsupportedTemplateError(
                f"template references unknown variable {node.name!r}; "
                f"must be one of compose: {sorted(self.allowed_vars)}"
            )
        if node.ctx != "load":
            # 'store' / 'param' contexts would mean an assignment or
            # macro parameter — both are reachable only through nodes we
            # already reject (Assign, Macro), but guard explicitly.
            raise UnsupportedTemplateError(
                f"variable {node.name!r} used in non-load context {node.ctx!r}"
            )

    def visit_Add(self, node: nodes.Add) -> None:  # noqa: N802
        # String concatenation only. At render time we'll receive str
        # values (validated by render()) and str Const literals (validated
        # above). Add on two strs is concat; Jinja2 has no separate
        # string-concat operator, so we have to allow Add to support
        # ``{{ A + ':' + B }}`` patterns.
        self.visit(node.left)
        self.visit(node.right)

    def visit_Filter(self, node: nodes.Filter) -> None:  # noqa: N802
        entry = WHITELISTED_FILTERS.get(node.name)
        if entry is None:
            raise UnsupportedTemplateError(
                f"unknown filter {node.name!r}; allowed: {sorted(WHITELISTED_FILTERS)}"
            )
        _fn, expected_arity = entry
        # Reject kwargs / splat first — those are syntactic violations
        # that should win the error message over arity.
        if node.kwargs or node.dyn_args or node.dyn_kwargs:
            raise UnsupportedTemplateError(
                f"filter {node.name!r}: keyword or dynamic args not allowed"
            )
        # The value being filtered (left side of the |) — implicit, not
        # counted in arity. Validate it recursively. Jinja2 types
        # ``Filter.node`` as Optional, but a filter without an input is
        # not syntactically reachable here (parser would have rejected
        # ``{{ | sha256 }}``); the assert documents the invariant.
        assert node.node is not None
        self.visit(node.node)
        # Arity check (Oracle C3): wrong positional arg count must fail
        # at config-load, not silently pass to render where Python raises
        # TypeError. Today every filter is arity 0.
        if len(node.args) != expected_arity:
            raise UnsupportedTemplateError(
                f"filter {node.name!r} takes {expected_arity} positional "
                f"argument(s) (excluding the | input); got {len(node.args)}"
            )
        for arg in node.args:
            self.visit(arg)

    def visit_Call(self, node: nodes.Call) -> None:  # noqa: N802
        # The callable must be a bare Name (function reference), not an
        # attribute access or another expression. ``X.upper()`` parses as
        # Call(node=Getattr(Name(X), 'upper')) — Getattr is not in our
        # allowed set, but we check the call target explicitly for a
        # clearer error message.
        if not isinstance(node.node, nodes.Name):
            raise UnsupportedTemplateError(
                f"only direct function calls allowed; got call on {type(node.node).__name__}"
            )
        entry = WHITELISTED_FUNCTIONS.get(node.node.name)
        if entry is None:
            raise UnsupportedTemplateError(
                f"unknown function {node.node.name!r}; allowed: {sorted(WHITELISTED_FUNCTIONS)}"
            )
        _fn, expected_arity = entry
        # Reject kwargs / splat first — syntactic violation outranks arity.
        if node.kwargs or node.dyn_args or node.dyn_kwargs:
            raise UnsupportedTemplateError(
                f"function {node.node.name!r}: keyword or dynamic args not allowed"
            )
        # Arity check (Oracle C4): operator writing hmac_sha256(K) or
        # hmac_sha256(K, M, EXTRA) must fail at config-load. Without this
        # the template compiles and only fails when an actual request
        # tries to render it — turning an operator typo into a runtime
        # 503 instead of a refused-to-start signal.
        if len(node.args) != expected_arity:
            raise UnsupportedTemplateError(
                f"function {node.node.name!r} takes {expected_arity} "
                f"positional argument(s); got {len(node.args)}"
            )
        # Validate args (Name lookups, Const checks, nested Filter/Call).
        # We deliberately do NOT visit node.node — that Name is the
        # function reference, not a variable load.
        for arg in node.args:
            self.visit(arg)


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


class AvpTemplate:
    """A pre-validated, pre-compiled inject_template.

    Construction is the validation pass — every operator-supplied template
    is parsed, AST-walked, and compiled at config-load. A successful
    construction means the template uses only whitelisted features and
    references only compose variables.

    Renders are thread-safe (Jinja2 Template objects are immutable after
    compile; our shared env is also immutable post-init).
    """

    __slots__ = ("_source", "_allowed_vars", "_template")

    def __init__(self, source: str, allowed_vars: list[str] | tuple[str, ...]) -> None:  # noqa: C901
        # Linear precondition chain: source-type, length cap, allowed_vars
        # shape, collision check, AST walk, compile. One rule per branch
        # (Oracle C2/C5/C6); helper extraction would obscure rule provenance.
        if not isinstance(source, str):
            raise UnsupportedTemplateError(
                f"template source must be str, got {type(source).__name__}"
            )
        # Oracle C2: resource bound on operator-supplied source. 4 KiB is far
        # above any realistic auth header template; catches pathological depth
        # (e.g., 10k Add nodes) at the cheapest possible check.
        if len(source) > MAX_TEMPLATE_SOURCE_LEN:
            raise UnsupportedTemplateError(
                f"template source is {len(source)} bytes; max allowed is {MAX_TEMPLATE_SOURCE_LEN}"
            )
        # Oracle C5: allowed_vars must be a sequence of non-empty strings.
        # Accepting a bare string would make frozenset() split it into
        # characters (`"X"` → `{'X'}` is fine but `"XY"` → `{'X','Y'}` —
        # silent multi-variable scope).
        if isinstance(allowed_vars, str):
            raise UnsupportedTemplateError(
                "allowed_vars must be a list or tuple of strings, "
                "not a bare string (would silently split into characters)"
            )
        names: list[str] = []
        for entry in allowed_vars:
            if not isinstance(entry, str):
                raise UnsupportedTemplateError(
                    f"allowed_vars entry {entry!r} is {type(entry).__name__}; expected str"
                )
            if not entry:
                raise UnsupportedTemplateError("allowed_vars entries must be non-empty strings")
            names.append(entry)
        # Oracle C6: forbid compose-variable names that collide with
        # whitelist filter/function names. The AST validator binds
        # ``{{ hmac_sha256(K, M) }}`` to the function unconditionally,
        # but ``{{ hmac_sha256 }}`` standalone would try to look up a
        # variable — leaving operators with a subtly broken template
        # depending on whether they happen to call it. Resolve the
        # ambiguity at construction.
        for entry in names:
            if entry in WHITELISTED_FILTERS or entry in WHITELISTED_FUNCTIONS:
                raise UnsupportedTemplateError(
                    f"allowed_vars entry {entry!r} collides with a reserved filter or function name"
                )
        self._source = source
        self._allowed_vars = frozenset(names)

        try:
            ast = _SHARED_ENV.parse(source)
        except jinja2.TemplateSyntaxError as e:
            # Re-raise as our own type so pydantic surfaces it through
            # ValidationError without leaking Jinja2-specific class names
            # into operator-facing error output.
            raise UnsupportedTemplateError(
                f"template parse error at line {e.lineno}: {e.message}"
            ) from None

        _AstValidator(self._allowed_vars).visit(ast)

        # Compile to a runnable Template. We use the same env (so filters
        # and globals are resolved against our whitelist).
        try:
            self._template = _SHARED_ENV.from_string(source)
        except jinja2.TemplateSyntaxError as e:
            # Should be unreachable — parse() above would have caught it —
            # but defensive.
            raise UnsupportedTemplateError(f"template compile error: {e.message}") from None

    @property
    def source(self) -> str:
        return self._source

    @property
    def allowed_vars(self) -> frozenset[str]:
        return self._allowed_vars

    def render(self, variables: dict[str, str]) -> str:
        """Render with the given variable dict.

        ``variables`` MUST contain exactly the allowed_vars set and every
        value MUST be a string. Mismatches raise TemplateRenderError
        BEFORE Jinja2 sees the dict — keeps the failure mode on our side
        of the boundary and avoids leaking Jinja2 UndefinedError messages
        through audit lines.

        NOTE for callers (addon.py audit code, Oracle C7): render errors
        include compose variable names and value type names. Those are
        operationally useful for the operator who reads the proxy log,
        but the addon MUST NOT pass these messages verbatim into the
        ``inject_decision`` audit event that the agent boundary could
        eventually observe. Use a generic ``reason: "render_failed"``
        in the audit record; keep the detailed message in proxy
        stdout/stderr only.
        """
        provided = set(variables)
        unexpected = provided - self._allowed_vars
        missing = self._allowed_vars - provided
        if unexpected:
            raise TemplateRenderError(
                f"unexpected variables passed to render: {sorted(unexpected)}"
            )
        if missing:
            raise TemplateRenderError(f"missing variables required by template: {sorted(missing)}")
        for name, value in variables.items():
            if not isinstance(value, str):
                raise TemplateRenderError(
                    f"variable {name!r}: expected str, got {type(value).__name__}"
                )

        try:
            return self._template.render(**variables)
        except UnsupportedTemplateError as e:
            # Oracle C1: filter/function impls raise UnsupportedTemplateError
            # for type/shape violations at render time. Convert here so the
            # addon catches exactly ONE exception type at the render
            # boundary (TemplateRenderError). Without this conversion the
            # addon would need to catch both — easy to forget.
            raise TemplateRenderError(
                f"render failed: filter/function rejected input: {e}"
            ) from None
        except TemplateRenderError:
            raise
        except jinja2.TemplateError as e:
            raise TemplateRenderError(f"render failed: {type(e).__name__}: {e}") from None
        except Exception as e:
            # Catch-all so a buggy filter doesn't crash the proxy worker.
            raise TemplateRenderError(f"render failed: {type(e).__name__}: {e}") from None
