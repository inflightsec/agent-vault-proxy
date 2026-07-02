from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)

from agent_vault_proxy.oauth_providers import PROVIDER_PRESETS, ProviderName

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
    "oauth2_refresh": "P1",
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
    Single-secret bindings use ``format`` (literal ``{<SECRET_NAME>}``
    substitution); composite bindings use ``template`` (sandboxed Jinja2)
    together with ``compose:`` on the parent ``SecretSpec``. The render
    path is identical to headers — only the substitution target differs.

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
        """Bytes each in-body placeholder occurrence is replaced with (single-
        secret path only). Composite body bindings go through
        ``SecretSpec.compiled_template`` — same as composite header bindings."""
        assert self.format is not None, (
            "render_value() expects inject.format; use compiled_template for composite bindings"
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


class Oauth2RefreshInjector(BaseModel):
    """OAuth2 refresh-token grant (RFC 6749 §6) — exchanges a vault-held
    refresh token for a short-lived access token at request time and
    injects the result.

    The schema captures the planning surface (ADR-0017 §2); runtime
    resolution (cache, off-thread exchange, audit emission, write-back)
    lands in subsequent slices and lives in
    :mod:`agent_vault_proxy.injectors.oauth2_refresh`.

    Either ``provider:`` is set — the bundled preset supplies
    ``token_url`` and ``client_auth_method`` — or both fields are
    declared explicitly. XOR validated at load time so the operator
    intent is unambiguous.
    """

    model_config = _STRICT_MODEL

    type: Literal["oauth2_refresh"] = "oauth2_refresh"

    # Either preset, or explicit fields, never both. Tenant-specific
    # presets (auth0, okta) supply auth_method but require an explicit
    # token_url — handled in the model_validator.
    provider: ProviderName | None = None
    token_url: HttpUrl | None = None
    client_auth_method: Literal["body_post", "basic"] | None = None

    # BWS secret references — always required regardless of preset usage.
    # The preset supplies URLs, not credentials.
    client_id_secret: str
    client_secret_secret: str
    refresh_token_secret: str

    # Target — header only in v0.7 (ADR-0017 §1). Body target lands in a
    # separate ADR with content-type-aware escaping.
    header: str = "Authorization"
    format: str = "Bearer {access_token}"

    # Optional scope override on refresh — RFC 6749 §6 allows narrowing
    # (not widening) the scopes against the refresh token's mint.
    scopes: str | None = None

    # Cache control — per-binding overrides on the derived-token cache
    # (ADR-0017 §3). ``safety`` is subtracted from upstream ``expires_in``;
    # ``max`` is the absolute ceiling regardless of upstream lifetime.
    cache_ttl_safety_seconds: int = Field(default=60, ge=0, le=600)
    cache_ttl_max_seconds: int = Field(default=3600, ge=60, le=86400)

    # Write-back on rotation — ADR-0017 §8. True (default) extends
    # ``SecretsBackend`` with ``update()``; backends that don't implement
    # it audit ``refresh_token_rotated:write_back_unavailable`` and the
    # operator must rotate manually.
    refresh_token_write_back: bool = True

    def render_value(self, *, access_token: str) -> str:
        """Substitute ``{access_token}`` in :attr:`format` with the
        exchanged token. Mirrors :meth:`HeaderInjector.render_value`'s
        ``str.replace``-not-``str.format`` posture so an operator-
        controlled format cannot traverse attributes via Python's
        format-mini-language. The placeholder name is literal — the
        XOR/schema layer pinned the format default to ``Bearer
        {access_token}`` and any operator override is still constrained
        to that single placeholder name."""
        return self.format.replace("{access_token}", access_token)

    @model_validator(mode="after")
    def resolve_preset_xor(self) -> Oauth2RefreshInjector:
        """Enforce the preset/explicit semantics and apply the preset.

        Three valid shapes; everything else is rejected at load:

        - **Non-tenant preset only** (``provider: google|microsoft|
          slack|atlassian``): the catalog supplies BOTH ``token_url``
          and ``client_auth_method``. Operator MUST NOT supply either
          field — silent override of vetted defaults is a surprise.
        - **Tenant-specific preset + URL** (``provider: auth0|okta``,
          + explicit ``token_url``): tenant URL is operator-supplied;
          the preset supplies ``client_auth_method`` only. Operator
          MUST supply ``token_url``, MUST NOT override the auth
          method.
        - **Fully explicit** (no ``provider:``): operator supplies
          both ``token_url`` and ``client_auth_method``.

        After this runs, ``token_url`` and ``client_auth_method`` are
        populated regardless of which path the operator chose — so the
        runtime never needs to consult ``PROVIDER_PRESETS`` again.
        SSRF check runs on every operator-supplied URL (both the
        fully-explicit and the tenant-explicit paths)."""
        from agent_vault_proxy._ssrf_guard import check_url_not_internal

        has_provider = self.provider is not None
        has_explicit_url = self.token_url is not None
        has_explicit_method = self.client_auth_method is not None

        if has_provider:
            preset = PROVIDER_PRESETS[self.provider]  # type: ignore[index]

            if has_explicit_method:
                raise ValueError(
                    f"oauth2_refresh: provider {self.provider!r} supplies "
                    "client_auth_method from the bundled preset; remove the "
                    "explicit value. Override is rejected to keep the schema "
                    "intent unambiguous."
                )

            if preset.token_url is None:
                # Tenant-specific: operator MUST supply token_url, preset
                # contributes auth method only.
                if not has_explicit_url:
                    raise ValueError(
                        f"oauth2_refresh: provider {self.provider!r} is tenant-"
                        "specific; supply token_url explicitly (e.g. "
                        "https://<tenant>.auth0.com/oauth/token). The preset "
                        "only contributes the auth method."
                    )
                # Operator-supplied URL → must pass SSRF guard.
                assert self.token_url is not None
                check_url_not_internal(self.token_url)
                object.__setattr__(self, "client_auth_method", preset.client_auth_method)
                return self

            # Non-tenant preset: catalog supplies everything; operator
            # must not duplicate.
            if has_explicit_url:
                raise ValueError(
                    f"oauth2_refresh: provider {self.provider!r} supplies "
                    "token_url from the bundled preset; remove the explicit "
                    "value (the preset URL was vetted at PR review)."
                )
            object.__setattr__(self, "token_url", HttpUrl(preset.token_url))
            object.__setattr__(self, "client_auth_method", preset.client_auth_method)
            return self

        # No provider — both explicit fields required.
        if not has_explicit_url:
            raise ValueError(
                "oauth2_refresh: either set provider: <name> for a bundled "
                "preset, or supply token_url explicitly. Neither was given."
            )
        if not has_explicit_method:
            raise ValueError(
                "oauth2_refresh: when token_url is supplied explicitly, "
                "client_auth_method ('body_post' or 'basic') is also "
                "required. RFC 6749 §2.3 — provider preference matters."
            )
        assert self.token_url is not None
        check_url_not_internal(self.token_url)
        return self

    @field_validator("token_url")
    @classmethod
    def require_https(cls, v: HttpUrl | None) -> HttpUrl | None:
        """HTTPS-only. A cleartext token endpoint would expose the
        refresh token on the very first exchange."""
        if v is None:
            return None
        if v.scheme != "https":
            raise ValueError(
                f"oauth2_refresh.token_url must use the https scheme; "
                f"got {v.scheme!r}. RFC 6749 §3.1 — token endpoint MUST "
                "use TLS."
            )
        return v


# Leaf injectors permitted inside MultiInjector. Nested multi is rejected
# at config-load. ``oauth2_refresh`` is NOT a permitted child in v0.7 —
# the resolution-step semantics inside a multi (which child triggers
# exchange, sibling sharing, audit ordering) need their own ADR.
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
    HeaderInjector | BodyInjector | MultiInjector | Oauth2RefreshInjector,
    Field(discriminator="type"),
]


def iter_leaf_injectors(
    spec: InjectorSpec,
) -> list[HeaderInjector | BodyInjector | Oauth2RefreshInjector]:
    """Flatten ``spec`` to its ordered leaf injectors. Single-leaf bindings
    yield ``[spec]``; multi yields ``spec.injectors``. ``oauth2_refresh``
    is a leaf — its runtime resolution step is single-bind by design."""
    if isinstance(spec, MultiInjector):
        return list(spec.injectors)
    return [spec]
