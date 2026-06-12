from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

from agent_vault_proxy.matching import host_matches_pattern, path_glob_matches
from agent_vault_proxy.template import AvpTemplate, UnsupportedTemplateError

# Known injector types — closed enumeration. Maps each type name to the
# phase that ships it; entries whose value starts with "planned:" are in
# the v0.5.0 taxonomy but raise a "not yet implemented" error at config
# load until their phase lands. Single source of truth: adding a new
# type means one line here plus the matching class + InjectorSpec union
# extension, never a parallel edit to two tuples.
_INJECTOR_TYPES: dict[str, str] = {
    "header": "P0",
    "body": "P0.6",
    "multi": "P0.7",
    "oauth2_refresh": "planned: P1",
    "github_app": "planned: P1",
    "sigv4": "planned: P2/P3",
    "oauth2_client_credentials": "planned: P2",
    "jwt_bearer": "planned: P2",
    "hmac": "planned: P4",
}


def _validate_inject_block(name: str, inject: dict) -> None:
    """Validate the ``type`` field of one ``inject:`` block (and, for
    ``multi``, of each declared child). Raises ``ValueError`` with an
    operator-friendly message on unknown / unimplemented / malformed
    types. ``name`` is the parent secret's YAML key, interpolated into
    error messages so operators can locate the entry.

    Pre-condition: ``inject["type"]`` is set (the default-injection
    pass upstream guarantees this for v0.4.x-shape inputs).
    """
    t = inject.get("type")
    if t is None:
        return  # already defaulted upstream; defensive
    _check_injector_type(t, type_path=f"secret {name!r}: inject.type")
    if t != "multi":
        return
    children = inject.get("injectors")
    if not isinstance(children, list):
        return  # let standard validator raise (wrong shape)
    for i, child in enumerate(children):
        if not isinstance(child, dict):
            continue
        ct = child.get("type")
        if ct is None:
            # Multi is v0.5.0 P0.7 — no backward-compat reason to default
            # child types. Be explicit to avoid ambiguity ("which leaf
            # did the operator mean?") and keep errors tight.
            raise ValueError(
                f"secret {name!r}: inject.injectors[{i}] is missing the "
                "required ``type:`` field. Multi injector children must "
                "specify their leaf type explicitly; valid leaf types in "
                "v0.5.0: 'header', 'body'."
            )
        _check_injector_type(ct, type_path=f"secret {name!r}: inject.injectors[{i}].type")
        # ``multi`` inside ``multi`` is rejected at the MultiInjector
        # schema level (LeafInjectorSpec excludes "multi"), but catch
        # it here too with a tighter message — same operator-facing UX
        # as the other type checks.
        if ct == "multi":
            raise ValueError(
                f"secret {name!r}: inject.injectors[{i}].type is 'multi'; "
                "nested multi-injectors are not supported (use a single "
                "multi with all leaf children flat)."
            )


def _check_injector_type(t: object, *, type_path: str) -> None:
    """Validate a single ``inject.type`` value against the closed taxonomy.

    Raises ``ValueError`` with an operator-friendly message on:

    * type not a string / not in :data:`_INJECTOR_TYPES`
      ("unknown type"; lists every valid alternative)
    * type known but not yet implemented in this version
      ("planned for phase X"; points at the CHANGELOG)

    ``type_path`` is the dotted location of the offending ``type`` field —
    e.g. ``"secret 'FOO': inject.type"`` or
    ``"secret 'FOO': inject.injectors[2].type"``. Interpolated verbatim so
    the operator can locate the entry without guesswork.
    """
    if not isinstance(t, str) or t not in _INJECTOR_TYPES:
        raise ValueError(f"{type_path} {t!r} is unknown; valid types: {sorted(_INJECTOR_TYPES)}")
    phase = _INJECTOR_TYPES[t]
    if phase.startswith("planned:"):
        implemented = sorted(k for k, v in _INJECTOR_TYPES.items() if not v.startswith("planned:"))
        raise ValueError(
            f"{type_path} {t!r} is in the planned v0.5.0 taxonomy ({phase}) but "
            "not yet implemented in this version. Currently implemented: "
            f"{implemented}. See CHANGELOG.md for the per-phase ship order."
        )


# `extra="forbid"` everywhere: a `method:` typo for `methods:` would
# otherwise silently produce an unscoped binding.
_STRICT_MODEL = ConfigDict(extra="forbid")

# Placeholders must be ≥24 chars, contain the marker, be unique, and not
# substring-overlap (addon detects via `in` matching).
_PLACEHOLDER_MIN_LEN = 24
_PLACEHOLDER_MARKER = "PLACEHOLDER"

# Permissive at the injector layer; the strict name-match runs at Config
# level in `validate_format_placeholders`.
_FORMAT_PLACEHOLDER_RE = re.compile(r"\{[^{}]+\}")


def validate_placeholder_invariants(placeholders: dict[str, str]) -> None:
    """Assert the placeholder invariants over a ``{secret_name: placeholder}``
    map: each is non-empty, >= the min length, contains the PLACEHOLDER
    marker, printable, unique, and no placeholder is a substring of another
    (the addon's ``in`` matching would otherwise pick the wrong secret).

    Raised as ``ValueError`` so it surfaces identically whether invoked by
    the Config load-time validator or by the daemon's BWS-notes activation
    (which merges file + derived placeholders into one set that must ALSO
    satisfy these invariants — a derived placeholder colliding/overlapping
    with a file one is a hard, fail-closed startup error).
    """
    seen: dict[str, str] = {}
    for name, ph in placeholders.items():
        if not ph:
            raise ValueError(f"secret {name!r}: placeholder is empty")
        if len(ph) < _PLACEHOLDER_MIN_LEN:
            raise ValueError(
                f"secret {name!r}: placeholder must be at least "
                f"{_PLACEHOLDER_MIN_LEN} characters (got {len(ph)})"
            )
        if _PLACEHOLDER_MARKER not in ph:
            raise ValueError(
                f"secret {name!r}: placeholder must contain the "
                f"literal marker {_PLACEHOLDER_MARKER!r}"
            )
        if not ph.isprintable():
            raise ValueError(f"secret {name!r}: placeholder must be printable")
        if ph in seen:
            raise ValueError(f"secret {name!r}: placeholder is identical to secret {seen[ph]!r}")
        seen[ph] = name
    # Pairwise substring check — a placeholder that's a substring of another
    # would let the addon's `in` matching pick the wrong secret.
    for ph_a, name_a in seen.items():
        for ph_b, name_b in seen.items():
            if name_a != name_b and ph_a in ph_b:
                raise ValueError(
                    f"secret {name_a!r}: placeholder is a substring "
                    f"of secret {name_b!r}'s placeholder"
                )


def _assert_format_has_placeholder(format_str: str, *, context_label: str) -> None:
    """Require ``format_str`` to contain some ``{NAME}``-shaped placeholder."""
    if not _FORMAT_PLACEHOLDER_RE.search(format_str):
        raise ValueError(
            f"{context_label} must contain a `{{<SECRET_NAME>}}` "
            "placeholder for the value to substitute"
        )


def _render_substitution(format_str: str, *, real_secret: str, secret_name: str) -> str:
    """Substitute ``{<secret_name>}`` -> ``real_secret``. Uses ``str.replace``
    (not ``str.format``) so an operator-provided format can't traverse
    attributes via Python's format-mini-language."""
    return format_str.replace("{" + secret_name + "}", real_secret)


class HeaderInjector(BaseModel):
    """Header-injection rule. Exactly one of ``format`` (literal substitution)
    or ``template`` (Jinja2-sandboxed, requires ``compose:`` on the parent)
    must be set."""

    model_config = _STRICT_MODEL

    type: Literal["header"] = "header"
    header: str
    format: str | None = None
    template: str | None = None

    def render_value(self, *, real_secret: str, secret_name: str) -> str:
        """Substituted header value for a single-secret binding. Composite
        bindings go through ``SecretSpec.compiled_template``."""
        assert self.format is not None, (
            "render_value() expects inject.format; use compiled_template for composite bindings"
        )
        return _render_substitution(
            self.format,
            real_secret=real_secret,
            secret_name=secret_name,
        )

    @model_validator(mode="after")
    def exactly_one_of_format_or_template(self) -> HeaderInjector:
        has_format = self.format is not None
        has_template = self.template is not None
        if has_format and has_template:
            raise ValueError(
                "inject.format and inject.template are mutually exclusive; "
                "use format for literal substitution or template for Jinja2-syntax assembly"
            )
        if not has_format and not has_template:
            raise ValueError("inject requires either 'format' or 'template'")
        if has_format:
            assert self.format is not None
            _assert_format_has_placeholder(self.format, context_label="inject.format")
        return self


class BodyInjector(BaseModel):
    """Body-injection rule. The secret's ``placeholder`` (inherited from the
    parent :class:`SecretSpec`) is substituted in the request body via
    streaming replacement (constant memory, chunked transfer).

    ``format`` / ``template`` semantics mirror :class:`HeaderInjector` —
    the result is the bytes each placeholder occurrence gets replaced WITH.

    ``content_type`` (optional): when set, the request's Content-Type must
    match (parameters stripped, case-insensitive) or the body forwards
    unmodified. Default None = any content-type eligible.
    """

    model_config = _STRICT_MODEL

    type: Literal["body"] = "body"
    content_type: str | None = None
    format: str | None = None
    template: str | None = None

    def render_value(self, *, real_secret: str, secret_name: str) -> str:
        """Bytes each in-body placeholder occurrence is replaced with."""
        assert self.format is not None, (
            "render_value() expects inject.format; composite body bindings would "
            "use compiled_template (not yet supported for body)"
        )
        return _render_substitution(
            self.format,
            real_secret=real_secret,
            secret_name=secret_name,
        )

    @model_validator(mode="after")
    def exactly_one_of_format_or_template(self) -> BodyInjector:
        has_format = self.format is not None
        has_template = self.template is not None
        if has_format and has_template:
            raise ValueError("body inject.format and inject.template are mutually exclusive")
        if not has_format and not has_template:
            raise ValueError("body inject requires either 'format' or 'template'")
        if has_template:
            raise ValueError(
                "body inject.template (composite/Jinja) is not yet supported; "
                "use inject.format for single-secret substitution"
            )
        if has_format:
            assert self.format is not None
            _assert_format_has_placeholder(self.format, context_label="body inject.format")
        return self

    @field_validator("content_type")
    @classmethod
    def normalize_content_type(cls, v: str | None) -> str | None:
        # Normalise at config-load so the runtime gate is a single
        # case-insensitive compare against the wire's Content-Type.
        if v is None:
            return None
        v = v.strip().lower()
        if not v:
            raise ValueError("content_type must be a non-empty string, or omit the field")
        if ";" in v:
            raise ValueError(
                f"content_type {v!r} contains parameters; specify only the media-type "
                "(e.g. 'application/json')."
            )
        if "/" not in v:
            raise ValueError(
                f"content_type {v!r} is not a media-type (expected 'type/subtype' form)"
            )
        return v


# Leaf injectors permitted inside MultiInjector. Nested multi is rejected
# at config-load.
LeafInjectorSpec = Annotated[HeaderInjector | BodyInjector, Field(discriminator="type")]


_MULTI_MIN_CHILDREN = 2
_MULTI_MAX_CHILDREN = 4  # mirrors compose: cap


class MultiInjector(BaseModel):
    """One secret's placeholder feeds multiple injection sites in one request
    (e.g. an Authorization header AND a JSON body field). 2-4 leaf children.
    Nested multi rejected; ``compose:`` cannot wrap a multi."""

    model_config = _STRICT_MODEL

    type: Literal["multi"] = "multi"
    injectors: list[LeafInjectorSpec]

    @model_validator(mode="after")
    def validate_children(self) -> MultiInjector:
        n = len(self.injectors)
        if n < _MULTI_MIN_CHILDREN or n > _MULTI_MAX_CHILDREN:
            raise ValueError(
                f"multi inject.injectors must contain "
                f"{_MULTI_MIN_CHILDREN}-{_MULTI_MAX_CHILDREN} children; got {n}. "
                "Single-injector secrets should use the leaf type directly."
            )
        # Header names compared case-insensitively per RFC 7230 §3.2 —
        # otherwise `Authorization` + `authorization` would silently
        # overwrite on the wire.
        header_names_lower: set[str] = set()
        body_count = 0
        for child in self.injectors:
            if isinstance(child, HeaderInjector):
                lowered = child.header.lower()
                if lowered in header_names_lower:
                    raise ValueError(
                        f"multi inject.injectors contains two header children "
                        f"targeting the same header {child.header!r} "
                        "(HTTP header names are case-insensitive). Pick one."
                    )
                header_names_lower.add(lowered)
            elif isinstance(child, BodyInjector):
                body_count += 1
        # One body child per multi — multiple would race on the same
        # placeholder occurrence in the body bytes.
        if body_count > 1:
            raise ValueError(
                "multi inject.injectors contains more than one body child; "
                "use one body child per multi (or split into separate secrets)."
            )
        return self


# Discriminated union of all injector specs. Default-type injection at
# `Config.normalize_and_validate_injector_types` keeps v0.4.x configs
# parsing without a `type:` field.
InjectorSpec = Annotated[
    HeaderInjector | BodyInjector | MultiInjector,
    Field(discriminator="type"),
]


def iter_leaf_injectors(spec: InjectorSpec) -> list[HeaderInjector | BodyInjector]:
    """Flatten ``spec`` to its ordered leaf injectors. Single-leaf bindings
    yield ``[spec]``; multi yields ``spec.injectors``."""
    if isinstance(spec, MultiInjector):
        return list(spec.injectors)
    return [spec]


_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


class BindingSpec(BaseModel):
    model_config = _STRICT_MODEL

    host: str
    methods: list[str] | None = None
    paths: list[str] | None = None

    @field_validator("host")
    @classmethod
    def normalize_and_validate_host(cls, v: str) -> str:
        # DNS is case-insensitive; lowercase at load + warn on uppercase
        # so silent rewrites don't lose audit value.
        if v != v.lower():
            import logging

            logging.getLogger("agent_vault_proxy.config").warning(
                "binding host %r contains uppercase; normalising to %r.",
                v,
                v.lower(),
            )
            v = v.lower()
        if v.startswith("*.") and v.count(".") < 2:
            raise ValueError(f"wildcard '{v}' is too broad; require at least two DNS labels")
        return v

    @field_validator("methods")
    @classmethod
    def normalize_and_validate_methods(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        if not v:
            raise ValueError(
                "empty methods = deny-all-methods; omit the field for any-method instead"
            )
        normalized: list[str] = []
        for m in v:
            up = m.upper()
            if up == "*":
                raise ValueError(
                    "methods cannot contain '*'; omit the field entirely for any-method"
                )
            if up not in _HTTP_METHODS:
                raise ValueError(f"unknown HTTP method '{m}'; allowed: {sorted(_HTTP_METHODS)}")
            normalized.append(up)
        return normalized

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        if not v:
            raise ValueError("empty paths = deny-all-paths; omit the field for any-path instead")
        for p in v:
            if not p.startswith("/"):
                raise ValueError(f"path '{p}' must start with '/'")
        return v

    def matches_scope(self, method: str, path: str) -> bool:
        """True if this binding's optional method/path scope allows the
        request. Bindings with both fields omitted always allow. Caller
        passes the uppercased method and the query-stripped path."""
        if self.methods is not None and method not in self.methods:
            return False
        if self.paths is None:
            return True
        return any(path_glob_matches(p, path) for p in self.paths)


_COMPOSE_MIN = 1
_COMPOSE_MAX = 4  # covers tenant_id-style patterns


class SecretSpec(BaseModel):
    model_config = _STRICT_MODEL

    placeholder: str
    inject: InjectorSpec
    compose: list[str] | None = None
    bindings: list[BindingSpec]

    # Populated when inject.template is set; None for inject.format.
    _compiled_template: AvpTemplate | None = PrivateAttr(default=None)
    # Which source produced this spec (ADR-0011 item 6). Defaults to "file":
    # a spec loaded from bindings.yaml is file-sourced. The BindingsResolver
    # sets "bws_notes" on specs built from a BWS secret's notes. The addon
    # reads this onto the inject_decision audit event's `binding_source`.
    # exclude=True keeps it OUT of model_dump()/JSON so the file-loaded
    # schema and the parity dumps are byte-unchanged; it's a settable runtime
    # attribute, not part of the serialised contract.
    binding_source: str = Field(default="file", exclude=True)

    @field_validator("bindings")
    @classmethod
    def reject_empty_bindings(cls, v: list[BindingSpec]) -> list[BindingSpec]:
        if not v:
            raise ValueError("empty bindings = deny-all; add explicit bindings or remove the entry")
        return v

    @model_validator(mode="after")
    def validate_compose_and_template(self) -> SecretSpec:  # noqa: C901
        # Multi-injector bindings carry format/template on each child, not
        # the parent spec; `compose:` cannot combine with multi.
        if isinstance(self.inject, MultiInjector):
            if self.compose is not None:
                raise ValueError("compose: cannot be used with inject.type: multi")
            return self
        has_compose = self.compose is not None
        has_template = self.inject.template is not None

        # compose: ↔ inject.template are co-required.
        if has_compose and not has_template:
            raise ValueError("compose: requires inject.template")
        if has_template and not has_compose:
            raise ValueError("inject.template requires compose: list of BWS secret names")

        if has_compose:
            assert self.compose is not None
            n = len(self.compose)
            if n < _COMPOSE_MIN or n > _COMPOSE_MAX:
                raise ValueError(
                    f"compose must contain {_COMPOSE_MIN}-{_COMPOSE_MAX} secret names; got {n}"
                )
            # Reject duplicates rather than silently coalesce.
            seen: set[str] = set()
            duplicates: list[str] = []
            for name in self.compose:
                if not isinstance(name, str):
                    raise ValueError(f"compose entry {name!r} must be a string")
                if not name:
                    raise ValueError("compose entries must be non-empty strings")
                if name in seen:
                    duplicates.append(name)
                seen.add(name)
            if duplicates:
                raise ValueError(
                    f"compose secret names must be unique; got duplicates: "
                    f"{sorted(set(duplicates))}"
                )
            assert self.inject.template is not None
            try:
                self._compiled_template = AvpTemplate(self.inject.template, self.compose)
            except UnsupportedTemplateError as e:
                raise ValueError(f"inject.template invalid: {e}") from None

        return self

    @property
    def compiled_template(self) -> AvpTemplate | None:
        return self._compiled_template


class CacheSpec(BaseModel):
    model_config = _STRICT_MODEL

    ttl_seconds: int = Field(default=300, ge=10, le=3600)
    max_entries: int = Field(default=100, ge=1)
    jitter_seconds: int = Field(default=30, ge=0)


class AuditSpec(BaseModel):
    model_config = _STRICT_MODEL

    path: str
    fail_on_unwritable: bool = True


class PreflightSpec(BaseModel):
    """Startup security preflight (src/agent_vault_proxy/_preflight.py).

    Default is advisory: warnings emit to stderr + logger but the proxy
    still starts. Set fail_on_warning to convert any warning into a
    startup abort — useful for hardened environments that want hard-fail
    over advisory output.
    """

    model_config = _STRICT_MODEL

    fail_on_warning: bool = False


class BackendBlock(BaseModel):
    """Backend selector. `type` is the discriminator; `config` is the
    per-backend pydantic model from BACKEND_REGISTRY[type]."""

    model_config = _STRICT_MODEL

    type: str
    config: dict

    # Populated by the after-validator below. Holds the per-backend pydantic
    # model instance so build_backend() doesn't re-validate. Not serialised.
    _validated_config: BaseModel | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def validate_inner_config(self) -> BackendBlock:
        """Eagerly validate ``config`` against the per-backend pydantic model.

        A typo under ``backend.config`` (e.g., ``organization_iddd`` for
        ``organization_id``) would otherwise only surface at first secret
        fetch, when the addon calls ``build_backend()``. Validating at
        config-load makes ``avp bindings diff`` and ``--check`` honest about
        backend-block correctness instead of deferring it to runtime.
        """
        from agent_vault_proxy.backends import BACKEND_REGISTRY, _normalize_name

        type_name = _normalize_name(self.type)
        if type_name not in BACKEND_REGISTRY:
            raise ValueError(
                f"unknown backend type {self.type!r}; "
                f"available types: {sorted(BACKEND_REGISTRY.keys())}"
            )
        _backend_cls, config_cls = BACKEND_REGISTRY[type_name]
        # Let pydantic's ValidationError surface as-is — it carries the
        # field-level detail (which key was unknown / what type was wrong).
        self._validated_config = config_cls.model_validate(self.config)
        return self


class ConfigError(Exception):
    """Raised at config-load time for structural errors that pydantic
    can't express."""


class Config(BaseModel):
    model_config = _STRICT_MODEL

    # Schema version. Optional, pinned to 1; reserved for future
    # schema-breaking changes.
    version: Literal[1] = 1
    secrets: dict[str, SecretSpec]
    # Default `forward_unmodified`: AVP is a credential broker, not an
    # egress firewall. Operators opt into allow-listing with `deny`.
    unmatched_destination_policy: Literal["deny", "forward_unmodified"] = "forward_unmodified"
    # Where binding policy comes from (ADR-0011). Default `both`: bindings
    # resolve from BWS secret notes AND `secrets:` in this file, BWS-notes
    # winning for the same secret. `bws_notes` = notes only; `file` = the
    # pre-ADR-0011 file-only behaviour. Anything other than `file` requires
    # a listable backend (bws/static).
    binding_source: Literal["file", "bws_notes", "both"] = "both"
    # Path to the per-install salt used to derive placeholders in
    # bws_notes/both mode. Defaults to install-salt next to this file's
    # directory; overridable for non-systemd layouts. Ignored in file mode.
    install_salt_path: str | None = None
    cache: CacheSpec = Field(default_factory=CacheSpec)
    audit: AuditSpec
    preflight: PreflightSpec = Field(default_factory=PreflightSpec)
    backend: BackendBlock | None = None

    @model_validator(mode="before")
    @classmethod
    def normalize_and_validate_injector_types(cls, data: object) -> object:
        """Before the ``InjectorSpec`` union dispatch: (1) default-inject
        ``type: "header"`` so v0.4.x configs without a ``type:`` field still
        parse; (2) reject unknown / unimplemented types with a one-line
        error (instead of Pydantic's verbose ``union_tag_invalid`` dump).
        No-ops on non-dict input."""
        if not isinstance(data, dict):
            return data
        secrets = data.get("secrets")
        if not isinstance(secrets, dict):
            return data

        # Shallow-copy only if some inject block actually needs a default.
        needs_default_injection = any(
            isinstance(spec, dict)
            and isinstance(spec.get("inject"), dict)
            and "type" not in spec["inject"]
            for spec in secrets.values()
        )

        if needs_default_injection:
            new_secrets: dict[str, object] = {}
            for name, spec in secrets.items():
                if isinstance(spec, dict):
                    inject = spec.get("inject")
                    if isinstance(inject, dict) and "type" not in inject:
                        new_secrets[name] = {**spec, "inject": {**inject, "type": "header"}}
                        continue
                new_secrets[name] = spec
            data = {**data, "secrets": new_secrets}
            secrets = new_secrets

        for name, spec in secrets.items():
            if not isinstance(spec, dict):
                continue
            inject = spec.get("inject")
            if isinstance(inject, dict):
                _validate_inject_block(name, inject)
        return data

    @model_validator(mode="after")
    def validate_placeholders(self) -> Config:
        validate_placeholder_invariants(
            {name: spec.placeholder for name, spec in self.secrets.items()}
        )
        return self

    @model_validator(mode="after")
    def validate_format_placeholders(self) -> Config:
        """Every leaf ``inject.format`` must contain ``{<entry_name>}``
        matching the parent secret's YAML key. Catches typos and the
        legacy ``{secret}`` alias."""
        for name, spec in self.secrets.items():
            for child in iter_leaf_injectors(spec.inject):
                fmt = child.format
                if fmt is None:
                    continue
                named = "{" + name + "}"
                if named not in fmt:
                    raise ValueError(
                        f"secret {name!r}: inject.format must contain "
                        f"'{named}' as the substitution placeholder; got {fmt!r}"
                    )
        return self

    # Host-keyed indices: exact-host dict + linear wildcard list.
    _exact_host_index: dict[str, list[tuple[str, SecretSpec]]] = PrivateAttr(default_factory=dict)
    _wildcard_host_entries: list[tuple[str, str, SecretSpec]] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def build_host_index(self) -> Config:
        """Populate the host-keyed indices used by ``secrets_for_host``.
        O(total bindings) at load; O(1) exact + O(wildcards) per request.
        Body and Aho-Corasick injectors need the narrowing so the body
        scan stays bounded.
        """
        self.rebuild_host_index()
        return self

    def rebuild_host_index(self) -> None:
        """(Re)build the host-keyed indices from the current ``secrets`` map.

        Idempotent: clears then repopulates, so it is safe to call again
        after ``secrets`` is mutated at runtime (the BWS-notes activation
        merges resolved specs into ``secrets`` at configure() time and must
        rebuild the index for the merged set). Separate from the load-time
        ``build_host_index`` validator because pydantic wraps validators in a
        descriptor that isn't directly callable post-construction.
        """
        self._exact_host_index = {}
        self._wildcard_host_entries = []
        for name, spec in self.secrets.items():
            for binding in spec.bindings:
                if binding.host.startswith("*."):
                    self._wildcard_host_entries.append((binding.host, name, spec))
                else:
                    self._exact_host_index.setdefault(binding.host, []).append((name, spec))

    def secrets_for_host(self, host: str) -> list[tuple[str, SecretSpec]]:
        """``(secret_name, spec)`` pairs whose bindings include ``host``.
        Exact matches first, then ``*.suffix`` wildcards. Each secret
        appears at most once; config-load order preserved within each class.
        """
        host = host.lower()
        seen_names: set[str] = set()
        result: list[tuple[str, SecretSpec]] = []
        for name, spec in self._exact_host_index.get(host, ()):
            if name not in seen_names:
                seen_names.add(name)
                result.append((name, spec))
        for pattern, name, spec in self._wildcard_host_entries:
            if name in seen_names:
                continue
            if host_matches_pattern(host, pattern):
                seen_names.add(name)
                result.append((name, spec))
        return result

    @model_validator(mode="after")
    def reject_nested_composition(self) -> Config:
        """``compose:`` entries must point at leaf BWS secret names, never
        at another binding that itself has ``compose:`` set. Leaf-check
        only — same name may legitimately be both a standalone binding
        AND a compose entry."""
        for binding_name, spec in self.secrets.items():
            if spec.compose is None:
                continue
            for entry in spec.compose:
                referenced = self.secrets.get(entry)
                if referenced is not None and referenced.compose is not None:
                    raise ValueError(
                        f"binding {binding_name!r}: compose entry {entry!r} "
                        "is itself a composite binding; point compose at "
                        "leaf BWS secret names only."
                    )
        return self


# Back-compat alias for v0.4.x importers. Removed in v0.6.0.
InjectSpec = HeaderInjector


def load_config(path: str | Path) -> Config:
    with open(path) as f:
        raw = yaml.safe_load(f)
    return Config.model_validate(raw)


def build_backend(config: Config):
    """Instantiate the configured backend.

    Returns (backend_instance, backend_config_instance). Caller is
    responsible for wrapping the backend in CachingSecretsClient.
    """
    from agent_vault_proxy.backends import BACKEND_REGISTRY, _normalize_name

    if config.backend is None:
        raise ConfigError(
            "no backend configured. Add a `backend: {type: ..., config: {...}}` "
            "block to bindings.yaml. Available types: "
            f"{sorted(BACKEND_REGISTRY.keys())}"
        )
    # Use the same NFKC+casefold normalization as register_backend so the
    # operator can't sneak past the dedup check via compat variants.
    type_name = _normalize_name(config.backend.type)
    if type_name not in BACKEND_REGISTRY:
        raise ConfigError(
            f"unknown backend type '{config.backend.type}'. "
            f"Available types: {sorted(BACKEND_REGISTRY.keys())}"
        )
    backend_cls, config_cls = BACKEND_REGISTRY[type_name]
    # BackendBlock's after-validator already validated this at config-load;
    # reuse the result so we don't double-validate (and so the model_validate
    # call here can't surface a different error than load_config did).
    backend_config = config.backend._validated_config
    if backend_config is None:  # pragma: no cover — defensive
        backend_config = config_cls.model_validate(config.backend.config)
    # SecretsBackend is a Protocol — it cannot statically express that every
    # concrete backend's __init__ takes a `config=` kwarg. The registry is
    # what enforces the convention at runtime (see backends/__init__.py
    # register_backend signature check).
    backend_instance = backend_cls(config=backend_config)  # type: ignore[call-arg]
    return backend_instance, backend_config
