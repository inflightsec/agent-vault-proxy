from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator

from agent_vault_proxy.matching import path_glob_matches
from agent_vault_proxy.template import AvpTemplate, UnsupportedTemplateError


class InjectSpec(BaseModel):
    """Injection rule for a binding. Exactly one of ``format`` or ``template``
    must be set.

    - ``format`` (legacy single-secret path): literal ``.replace("{secret}",
      value)``. Backward compatible.
    - ``template`` (composite or single-secret with encoding): Jinja2-syntax
      sandboxed expression with strict whitelist (see ``template.py``).
      Requires the parent SecretSpec to declare a ``compose:`` list.
    """

    header: str
    format: str | None = None
    template: str | None = None

    @model_validator(mode="after")
    def exactly_one_of_format_or_template(self) -> InjectSpec:
        has_format = self.format is not None
        has_template = self.template is not None
        if has_format and has_template:
            raise ValueError(
                "inject.format and inject.template are mutually exclusive; "
                "use format for literal '{secret}' substitution or template "
                "for Jinja2-syntax assembly"
            )
        if not has_format and not has_template:
            raise ValueError(
                "inject requires either 'format' (literal) or 'template' "
                "(Jinja2-syntax) — neither was set"
            )
        if has_format and "{secret}" not in self.format:  # type: ignore[operator]
            raise ValueError("inject.format must contain '{secret}'")
        return self


_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


class BindingSpec(BaseModel):
    host: str
    methods: list[str] | None = None
    paths: list[str] | None = None

    @field_validator("host")
    @classmethod
    def reject_overbroad_wildcard(cls, v: str) -> str:
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
        """Return True if this binding's optional method/path scope allows
        the request. Bindings with both fields omitted always allow (legacy
        behavior). Caller passes the uppercased method and the
        query-stripped path."""
        if self.methods is not None and method not in self.methods:
            return False
        if self.paths is None:
            return True
        return any(path_glob_matches(p, path) for p in self.paths)


_COMPOSE_MIN = 1
_COMPOSE_MAX = 4  # raised from 3 during grill — covers tenant_id-style patterns


class SecretSpec(BaseModel):
    placeholder: str
    inject: InjectSpec
    compose: list[str] | None = None
    bindings: list[BindingSpec]

    # Compiled, pre-validated template — populated by the after-validator
    # below when inject.template is set. None for legacy inject.format bindings.
    # Not part of the serialized model.
    _compiled_template: AvpTemplate | None = PrivateAttr(default=None)

    @field_validator("bindings")
    @classmethod
    def reject_empty_bindings(cls, v: list[BindingSpec]) -> list[BindingSpec]:
        if not v:
            raise ValueError(
                "empty bindings = deny-all; either add explicit bindings or remove the secret entry"
            )
        return v

    @model_validator(mode="after")
    def validate_compose_and_template(self) -> SecretSpec:  # noqa: C901
        # Linear precondition chain: each branch enforces one distinct
        # binding-spec rule from the design doc (§4.6). Refactoring into
        # helpers would obscure the rule-per-branch one-to-one mapping.
        has_compose = self.compose is not None
        has_template = self.inject.template is not None

        # 1. Compose ↔ inject.template are co-required. Single-secret
        # bindings using legacy ``inject.format`` MUST NOT set compose.
        if has_compose and not has_template:
            raise ValueError(
                "compose: requires inject.template; use inject.format for "
                "literal '{secret}' substitution on a single secret"
            )
        if has_template and not has_compose:
            raise ValueError("inject.template requires compose: list of BWS secret names")

        if has_compose:
            assert self.compose is not None  # for type narrowing
            # 2. RAW list length cap (Silas F5 — never coalesce).
            n = len(self.compose)
            if n < _COMPOSE_MIN or n > _COMPOSE_MAX:
                raise ValueError(
                    f"compose must contain {_COMPOSE_MIN}-{_COMPOSE_MAX} secret names; got {n}"
                )
            # 3. Each entry non-empty string; raw-list dedup check
            # (reject, never silently shorten).
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
            # 4. Compile the template via AvpTemplate. This catches:
            #    - syntax errors
            #    - unsupported AST nodes (Getattr, Subscript, control flow…)
            #    - unknown variables (must be in compose)
            #    - unknown filters/functions
            #    - wrong filter/function arity
            #    - non-string Const values
            #    - source length > MAX_TEMPLATE_SOURCE_LEN
            #    - allowed_vars collisions with reserved filter/function names
            assert self.inject.template is not None
            try:
                self._compiled_template = AvpTemplate(self.inject.template, self.compose)
            except UnsupportedTemplateError as e:
                raise ValueError(f"inject.template invalid: {e}") from None

        return self

    @property
    def compiled_template(self) -> AvpTemplate | None:
        """The compiled AvpTemplate (composite/templated bindings) or None
        (legacy inject.format bindings)."""
        return self._compiled_template


class CacheSpec(BaseModel):
    ttl_seconds: int = Field(default=300, ge=10, le=3600)
    max_entries: int = Field(default=100, ge=1)
    jitter_seconds: int = Field(default=30, ge=0)


class AuditSpec(BaseModel):
    path: str
    fail_on_unwritable: bool = True


class PreflightSpec(BaseModel):
    """Startup security preflight (src/agent_vault_proxy/_preflight.py).

    Default is advisory: warnings emit to stderr + logger but the proxy
    still starts. Set fail_on_warning to convert any warning into a
    startup abort — useful for hardened environments that want hard-fail
    over advisory output.
    """

    fail_on_warning: bool = False


class BackendBlock(BaseModel):
    """Backend selector. `type` is the discriminator; `config` is the
    per-backend pydantic model from BACKEND_REGISTRY[type]."""

    type: str
    config: dict  # validated against the backend's own config model in build_backend()


class ConfigError(Exception):
    """Raised at config-load time for structural errors that pydantic
    can't express."""


class Config(BaseModel):
    version: Literal[1]
    secrets: dict[str, SecretSpec]
    # Default is forward_unmodified: the proxy is a credential broker, not
    # an egress firewall. Requests to destinations without a matching binding
    # pass through unmodified. Users who want strict allow-listing can set
    # `unmatched_destination_policy: deny` in their bindings.yaml — that is
    # an explicit opt-in to firewall-like behavior, not the default.
    unmatched_destination_policy: Literal["deny", "forward_unmodified"] = "forward_unmodified"
    cache: CacheSpec = Field(default_factory=CacheSpec)
    audit: AuditSpec
    preflight: PreflightSpec = Field(default_factory=PreflightSpec)
    backend: BackendBlock | None = None

    @model_validator(mode="after")
    def reject_nested_composition(self) -> Config:
        """Silas F6: a composite binding's ``compose:`` entries must reference
        LEAF BWS secret names, never another binding that itself has
        ``compose:`` set. Composite-of-composite is structurally banned —
        but the test must be a leaf-check ("does the named binding itself
        have compose?"), NOT a name-blacklist ("is this name a binding
        key?"). The latter would over-block legitimate sharing where the
        same name is both a standalone single-secret binding AND used as
        an underlying value inside a composite.
        """
        for binding_name, spec in self.secrets.items():
            if spec.compose is None:
                continue
            for entry in spec.compose:
                referenced = self.secrets.get(entry)
                if referenced is not None and referenced.compose is not None:
                    raise ValueError(
                        f"binding {binding_name!r}: compose entry "
                        f"{entry!r} is itself a composite binding "
                        f"(has its own compose: list). Nested composition "
                        f"is not supported — point compose at leaf BWS "
                        f"secret names only."
                    )
        return self


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
    backend_config = config_cls.model_validate(config.backend.config)
    # SecretsBackend is a Protocol — it cannot statically express that every
    # concrete backend's __init__ takes a `config=` kwarg. The registry is
    # what enforces the convention at runtime (see backends/__init__.py
    # register_backend signature check).
    backend_instance = backend_cls(config=backend_config)  # type: ignore[call-arg]
    return backend_instance, backend_config
