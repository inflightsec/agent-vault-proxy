"""AWS Secrets Manager backend (ADR-0038).

Mirror of :mod:`kow.backends.gsm` for AWS. Fetches secret *values*
from AWS Secrets Manager and surfaces a per-secret host binding stored on the
secret itself. Caching is layered on top by ``CachingSecretsClient``.

Design mirrors GSM point for point:

* **No I/O in __init__.** First credential resolution + first signed call happen
  on first use.
* **Lazy ``botocore`` import.** Importing this module (registration + config
  validation) never needs ``botocore`` — only a live fetch does. ``botocore`` is
  an optional dependency (extra ``aws``) used ONLY to resolve credentials; the
  data-plane call is stdlib ``urllib`` signed by :mod:`kow.injectors.sigv4`
  (the exact GSM split: ``google-auth`` mints, ``urllib`` calls → ``botocore``
  resolves creds, our signer + ``urllib`` call).
* **Test-injection path.** ``AwsSecretsManagerBackend(config=..., credential_provider=fn, http=fn)``
  bypasses ``botocore`` and the network entirely, so the contract suite and unit
  tests need neither the dependency nor a live AWS account.

Host binding (ADR-0038 §4): notes-aware. A secret carries its host in the
``avp-binding`` **tag** (character-safe for a hostname — the North-Star case,
``avp-binding: api.openai.com``) or, for the richer flat-YAML case that a tag's
character set can't hold, in the secret's **Description** as a ``# avp-binding``
marker block. ``fetch_with_meta`` surfaces that string verbatim;
:func:`kow.notes_binding.parse_notes_binding` turns it into a
fail-closed binding — the same path GSM annotations take. A secret with neither
resolves to ``NoBinding`` and is never injected.

Least privilege (ADR-0038 §6): the config has **no static-key field** — an
operator cannot wire an ``aws_access_key_id`` / ``aws_secret_access_key`` through
it. ``require_temporary_credentials`` additionally refuses permanent IAM-user
credentials (creds with no session token), the AWS analog of GSM's
``reject_ambient_key``. When ``self_check`` is ``deny`` (default), the backend
refuses to start if its identity can ENUMERATE (``ListSecrets``) OR READ
(``GetSecretValue`` on an out-of-prefix probe — ResourceNotFound instead of
AccessDenied proves broad read) secrets outside ``secret_prefix``. WRITE/admin
breadth is not checked — the ``iam:SimulatePrincipalPolicy`` probe for it (GSM's
``testIamPermissions`` analog) is the documented next slice (ADR-0038 §6).
``_assert_in_scope`` also refuses to *fetch* any name outside the prefix at the
access boundary.

Scope of this slice: AWS Secrets Manager only. SSM Parameter Store (a second
driver behind the same interface) is the documented next slice per ADR-0038 §1.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from kow.injectors.sigv4 import sign

_log = logging.getLogger("kow.backends.aws")

_SERVICE = "secretsmanager"
# AWS JSON-1.1 protocol content type + the X-Amz-Target operations we call.
_JSON_CONTENT_TYPE = "application/x-amz-json-1.1"
_TARGET_GET = "secretsmanager.GetSecretValue"
_TARGET_LIST = "secretsmanager.ListSecrets"
_TARGET_DESCRIBE = "secretsmanager.DescribeSecret"
# Tag key that carries the AVP binding (bare host; same key name as the GSM
# annotation for cross-backend least-surprise). Richer flat-YAML bindings live
# in the secret Description as a `# avp-binding` marker block (a tag value's
# character set — alnum + space + `+ - = . _ : / @` — can't hold YAML).
_BINDING_TAG = "avp-binding"
_LIST_PAGE_SIZE = 100

# AWS ``__type`` discriminators meaning "this principal is DENIED this action"
# (distinct from a broken/expired credential). Secrets Manager returns these with
# HTTP **400**, not 403 — so "can this identity enumerate?" must be inferred from
# the error TYPE, not the status. A ListSecrets that fails access-denied means the
# identity cannot enumerate others → scoped (GOOD for self_check).
_ACCESS_DENIED_TYPES = frozenset({"AccessDeniedException", "AccessDenied", "NotAuthorized"})

# Transport callable injected in tests: (method, url, headers, body) ->
# (status_code, parsed_json_or_None). Production builds one from urllib.
HttpFn = Callable[[str, str, "dict[str, str]", "bytes | None"], "tuple[int, dict[str, Any] | None]"]


@dataclass(frozen=True)
class AwsCredentials:
    """A resolved AWS credential set. ``session_token`` is present for temporary
    (STS / Roles Anywhere / SSO) credentials and absent for a permanent IAM-user
    key — whose *absence* is what ``require_temporary_credentials`` refuses."""

    access_key_id: str
    secret_access_key: str
    session_token: str | None = None


CredentialFn = Callable[[], AwsCredentials]


class AwsConfig(BaseModel):
    """``backend.config`` schema for ``type: aws-secrets-manager`` (ADR-0038 §2).

    Two design-load-bearing choices, mirroring GSM: (a) there is deliberately
    **no static-key field**, so long-lived ``AKIA…`` credentials cannot be wired
    through config; (b) ``require_temporary_credentials`` catches the back door —
    resolved credentials with no session token (a permanent IAM-user key) are
    refused before any call.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    type: Literal["aws-secrets-manager"] = "aws-secrets-manager"
    region: str
    # Namespace: only secrets whose name starts with this prefix are in scope
    # (client-side list filter + the self_check boundary + fetch boundary).
    secret_prefix: str | None = None
    # A read-only broker always reads the promoted version; AWSPENDING is
    # untested and may be an empty version on a failed rotation.
    version_stage: str = "AWSCURRENT"

    # --- Secure-by-default guardrails ---
    self_check: Literal["deny", "warn", "off"] = "deny"
    # Refuse resolved credentials that are permanent (no STS session token) —
    # the AWS analog of GSM reject_ambient_key. Keeps a long-lived AKIA key out
    # of the daemon; forces Roles Anywhere / SSO / instance-profile temp creds.
    require_temporary_credentials: bool = True

    @model_validator(mode="after")
    def _deny_requires_prefix(self) -> AwsConfig:
        # A deny-if-broad guard with no namespace to bound silently no-ops.
        if self.self_check == "deny" and not self.secret_prefix:
            raise ValueError(
                "self_check: deny requires secret_prefix to bound the namespace it "
                "guards (e.g. secret_prefix: 'avp/<owner>/'). Set it, or choose "
                "self_check: warn|off to opt out of the boot guard."
            )
        return self

    @field_validator("region")
    @classmethod
    def _validate_region(cls, v: str) -> str:
        # region is interpolated into the endpoint host that also carries the
        # signed request; a value with a slash / dot / whitespace could redirect
        # that authenticated call. AWS regions are lowercase letters, digits, and
        # hyphens only (e.g. us-east-1, eu-central-1).
        v = v.strip()
        if not re.fullmatch(r"[a-z0-9-]{1,32}", v):
            raise ValueError(
                "region must be an AWS region code (lowercase letters, digits, "
                "hyphens — e.g. 'us-east-1'); no slashes, dots, or whitespace."
            )
        return v

    @field_validator("version_stage")
    @classmethod
    def _reject_pending_stage(cls, v: str) -> str:
        # A read-only broker serves the promoted version. AWSPENDING is the
        # unpromoted, untested rotation version (may be empty on a failed
        # rotation) — refusing it keeps the config from contradicting the
        # "reads AWSCURRENT only" contract (ADR-0038 §3).
        v = v.strip()
        if v.upper() == "AWSPENDING":
            raise ValueError(
                "version_stage 'AWSPENDING' is refused — it is the unpromoted, "
                "untested rotation version. Use 'AWSCURRENT' (default) or a "
                "custom promoted staging label."
            )
        return v


class _HttpError(Exception):
    """Internal: a non-2xx HTTP response. Carries the code + parsed body so the
    caller maps it to a protocol exception."""

    def __init__(self, status: int, body: dict[str, Any] | None) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


class AwsSecretsManagerBackend:
    """AWS Secrets Manager backend implementing the ``SecretsBackend`` protocol.

    Construction is cheap (no I/O). First use triggers credential resolution +
    a one-shot self_check, then the signed REST call.
    """

    # Provenance label stamped onto notes-derived specs + their audit events,
    # read off the backend TYPE (not the binding_source string) so `both` mode
    # labels AWS tags honestly.
    NOTES_SOURCE_LABEL = "aws_tags"

    def __init__(
        self,
        config: AwsConfig | None = None,
        *,
        credential_provider: CredentialFn | None = None,
        http: HttpFn | None = None,
    ) -> None:
        # Two construction paths:
        #   1. Production: AwsSecretsManagerBackend(config=AwsConfig(...)) —
        #      credential provider built lazily from botocore on first use; http
        #      from urllib.
        #   2. Tests: (config=..., credential_provider=fn, http=fn) — bypasses
        #      botocore and the network entirely.
        self._config = config
        self._credential_provider = credential_provider
        self._http = http
        self._ready = False
        import threading

        self._ready_lock = threading.Lock()
        # secret_name -> {"tags": {k: v}, "description": str|None}, populated by
        # list_secret_names so fetch_with_meta serves the binding without a
        # second call.
        self._meta: dict[str, dict[str, Any]] = {}

    def __repr__(self) -> str:
        # No config in repr (would leak region via a traceback). Plain class name.
        return f"<{self.__class__.__name__}>"

    # ---- protocol surface -------------------------------------------------

    def _assert_in_scope(self, name: str) -> None:
        """Defence-in-depth: refuse to touch a name outside ``secret_prefix``."""
        prefix = self._config.secret_prefix if self._config is not None else None
        if prefix and not name.startswith(prefix):
            from kow.backends import SecretNotFoundError

            raise SecretNotFoundError(
                f"secret {name!r} is outside secret_prefix {prefix!r}; refusing to "
                "fetch out-of-namespace (defence-in-depth)"
            )

    def fetch(self, name: str, ctx: Any = None) -> str:  # noqa: ARG002 — ctx unused
        self._ensure_ready()
        self._assert_in_scope(name)
        _status, body = self._call(
            _TARGET_GET,
            {"SecretId": name, "VersionStage": self._version_stage},
        )
        body = body or {}
        secret_string = body.get("SecretString")
        if isinstance(secret_string, str):
            return secret_string
        # SecretBinary is a base64 blob; a broker injecting text credentials
        # doesn't handle it — fail closed rather than guess an encoding.
        from kow.backends import BackendUnavailableError

        if body.get("SecretBinary") is not None:
            raise BackendUnavailableError(
                f"AWS secret {name!r} is a SecretBinary; only SecretString is supported"
            )
        raise BackendUnavailableError(f"AWS GetSecretValue for {name!r} returned no SecretString")

    def fetch_with_meta(self, name: str, ctx: Any = None) -> tuple[str, str | None]:
        """Return ``(value, note)``. The note is the secret's ``avp-binding`` tag
        (bare host) or, failing that, a ``# avp-binding`` marker block in the
        Description — surfaced verbatim for the notes parser, ``None`` when
        neither is present."""
        value = self.fetch(name, ctx)
        return value, self._binding_note(name)

    def list_secret_names(self) -> list[str]:
        """Every in-scope secret name. Filtered client-side to ``secret_prefix``;
        caches each secret's tags + description so ``fetch_with_meta`` needs no
        second call."""
        self._ensure_ready()
        return self._list_names(scope_to_prefix=True)

    def list_secret_notes(self) -> dict[str, str | None]:
        """``{secret_name: binding | None}`` for every in-scope secret, WITHOUT
        fetching any secret VALUE. Tags + Description come from the free
        ``ListSecrets`` metadata pass, so notes activation never pulls plaintext
        at configure time."""
        self._ensure_ready()
        names = self._list_names(scope_to_prefix=True)  # populates self._meta
        return {n: self._note_from_meta(self._meta.get(n) or {}) for n in names}

    def flush_name_map(self) -> None:
        """Invalidate the cached metadata map; next list re-reads."""
        self._meta = {}

    # ---- readiness / auth / self-check -----------------------------------

    @property
    def _region(self) -> str:
        assert self._config is not None
        return self._config.region

    @property
    def _version_stage(self) -> str:
        return self._config.version_stage if self._config is not None else "AWSCURRENT"

    @property
    def _endpoint(self) -> str:
        return f"https://{_SERVICE}.{self._region}.amazonaws.com/"

    def _ensure_ready(self) -> None:
        if self._ready:
            return
        with self._ready_lock:
            if self._ready:
                return
            if self._config is None:
                raise NotImplementedError(
                    "AwsSecretsManagerBackend requires an AwsConfig; pass config=AwsConfig(...). "
                    "credential_provider/http are optional test overrides."
                )
            if self._credential_provider is None:
                self._credential_provider = self._build_credential_provider()
            self._enforce_temporary_credentials()
            self._run_self_check()
            self._ready = True

    def _build_credential_provider(self) -> CredentialFn:
        """Build a credential provider from botocore's credential resolution
        chain (Roles Anywhere via credential_process, SSO, STS, env, instance
        profile). Lazy botocore import: only on first live use, so module import
        and injected-provider unit tests never need the dependency.

        botocore is used ONLY to RESOLVE + refresh credentials; the actual
        GetSecretValue call is signed by our own SigV4 signer over urllib.
        """
        from kow.backends import BackendUnavailableError, require

        with require("aws", "botocore", "aws"):
            import botocore.session

        session = botocore.session.get_session()
        resolved = session.get_credentials()
        if resolved is None:
            raise BackendUnavailableError(
                "no AWS credentials resolved (env / SSO / Roles Anywhere / instance "
                "profile all empty); configure a keyless source"
            )

        def provider() -> AwsCredentials:
            # get_frozen_credentials() re-resolves through botocore's refresh
            # logic, so STS / Roles-Anywhere creds stay fresh across expiry.
            frozen = resolved.get_frozen_credentials()
            return AwsCredentials(
                access_key_id=frozen.access_key,
                secret_access_key=frozen.secret_key,
                session_token=frozen.token,
            )

        return provider

    def _enforce_temporary_credentials(self) -> None:
        """Refuse permanent IAM-user credentials (no session token) when
        ``require_temporary_credentials`` is set — the AWS analog of GSM
        ``reject_ambient_key``. A resolved key with no ``session_token`` is a
        long-lived ``AKIA…`` user key, exactly the material this design keeps out
        of the daemon."""
        assert self._config is not None
        if not self._config.require_temporary_credentials:
            return
        from kow.backends import BackendAuthLostError, BackendUnavailableError

        try:
            creds = self._credential_provider() if self._credential_provider else None
        except BackendAuthLostError:
            raise
        except Exception as e:  # noqa: BLE001 — provider errors map to protocol
            raise BackendUnavailableError(
                f"AWS credential resolution failed: {type(e).__name__}"
            ) from None
        if creds is not None and not creds.session_token:
            raise BackendAuthLostError(
                "aws backend resolved PERMANENT credentials (no STS session token); "
                "long-lived IAM-user keys are refused (require_temporary_credentials). "
                "Use IAM Roles Anywhere / SSO / an instance profile for temporary creds."
            )

    def _run_self_check(self) -> None:
        """Deny-if-broad boot guard (ADR-0038 §6) — ENUMERATION SCOPE ONLY.

        If ``secret_prefix`` is set and the identity can enumerate secrets
        OUTSIDE that prefix, it is broader than intended → refuse to start
        (``deny``) or warn. A ``ListSecrets`` that fails **access-denied** is GOOD
        — the identity cannot enumerate others — so it passes. (Secrets Manager
        returns AccessDenied with HTTP **400**, not 403, so we key on the error
        TYPE, not the status.) With no prefix the scope is undeterminable and the
        check is skipped with a warning.

        Two probes run: (1) ENUMERATION breadth via ``ListSecrets`` (access-denied
        is GOOD — the identity cannot enumerate others; ``ListSecrets`` has no
        resource-level IAM scoping, so denial is the expected shape for a
        least-priv identity), and (2) READ breadth via a ``GetSecretValue`` probe
        on a non-existent OUT-OF-PREFIX name (AccessDenied = cannot read outside =
        GOOD; ResourceNotFound = the identity *could* read there = broad → refuse).
        WRITE/admin breadth (``PutSecretValue`` / ``DeleteSecret`` / ``TagResource``)
        is NOT checked — the ``iam:SimulatePrincipalPolicy`` probe for it is the
        documented follow-up (ADR-0038 §6).
        """
        assert self._config is not None
        mode = self._config.self_check
        if mode == "off":
            return
        prefix = self._config.secret_prefix
        if not prefix:
            _log.warning(
                "aws self_check=%s but no secret_prefix set; cannot bound scope — skipping.",
                mode,
            )
            return
        # A prefix with no trailing delimiter matches as a SUBSTRING, not a
        # namespace segment (e.g. 'avp/prod' also admits 'avp/production'). Nudge
        # — don't hard-fail (operator-controlled, GSM-parity).
        if not prefix.endswith(("/", "-", "_", ".", ":")):
            _log.warning(
                "aws self_check: secret_prefix %r has no trailing delimiter, so it matches "
                "as a substring (it also admits e.g. %r); prefer a delimiter-terminated "
                "namespace like %r.",
                prefix,
                prefix + "-other",
                prefix + "/",
            )
        self._check_enumeration_scope(mode, prefix)
        self._check_read_scope(mode, prefix)

    def _check_enumeration_scope(self, mode: str, prefix: str) -> None:
        """Refuse/warn if the identity can ENUMERATE secrets outside ``prefix``. An
        access-denied ``ListSecrets`` is GOOD (cannot enumerate) and returns
        normally so the read-scope probe still runs."""
        from kow.backends import BackendAuthLostError, BackendUnavailableError

        try:
            all_names = self._list_names(scope_to_prefix=False)
        except BackendAuthLostError as e:
            if getattr(e, "aws_error_type", "") in _ACCESS_DENIED_TYPES:
                _log.debug("aws self_check: ListSecrets access-denied — enumeration scoped")
                return
            # A broken/expired credential (InvalidClientTokenId, ExpiredToken) is
            # NOT proof of scope — inconclusive, fail closed under deny.
            self._refuse_or_warn(mode, f"aws self_check inconclusive ({e})")
            return
        except BackendUnavailableError as e:
            # Transient — do NOT treat as scoped (would fail open).
            self._refuse_or_warn(mode, f"aws self_check could not complete: {type(e).__name__}")
            return
        out_of_scope = [n for n in all_names if not n.startswith(prefix)]
        if out_of_scope:
            self._refuse_or_warn(
                mode,
                f"aws self_check: identity can enumerate {len(out_of_scope)} secret(s) outside "
                f"prefix {prefix!r} (e.g. {out_of_scope[0]!r}) — broader Secrets Manager access "
                "than its own namespace; scope GetSecretValue/ListSecrets to the prefix ARN",
            )

    def _check_read_scope(self, mode: str, prefix: str) -> None:
        """Refuse/warn if the identity can READ secrets outside ``prefix`` (ADR-0038
        §6 read-breadth). Probes ``GetSecretValue`` on a non-existent
        out-of-prefix name: AccessDenied = cannot read outside = GOOD;
        ResourceNotFound = read WOULD be allowed there (broad ``GetSecretValue``) →
        refuse; a 200 (probe name somehow exists) → refuse. Any inconclusive result
        (broken cred / transient) does NOT refuse — never fail-open a hard block on
        an unrelated error (GSM's probe posture)."""
        from kow.backends import (
            BackendAuthLostError,
            BackendUnavailableError,
            SecretNotFoundError,
        )

        probe = self._out_of_scope_probe_name(prefix)
        try:
            self._call(_TARGET_GET, {"SecretId": probe, "VersionStage": self._version_stage})
        except SecretNotFoundError:
            self._refuse_or_warn(
                mode,
                f"aws self_check: identity can GetSecretValue OUTSIDE prefix {prefix!r} "
                "(a non-existent out-of-namespace probe returned ResourceNotFound, not "
                "AccessDenied) — scope GetSecretValue to the prefix ARN so it cannot read "
                "the rest of the account",
            )
            return
        except BackendAuthLostError as e:
            if getattr(e, "aws_error_type", "") in _ACCESS_DENIED_TYPES:
                _log.debug("aws self_check: GetSecretValue out-of-prefix denied — read scoped")
                return
            _log.debug("aws self_check: read-scope probe inconclusive (%s)", e)
            return
        except BackendUnavailableError as e:
            _log.debug("aws self_check: read-scope probe inconclusive (%s)", type(e).__name__)
            return
        # 200 — the out-of-prefix probe secret exists AND is readable ⇒ broad read.
        self._refuse_or_warn(
            mode,
            f"aws self_check: identity can READ a secret outside prefix {prefix!r} "
            "(out-of-namespace probe returned a value) — scope GetSecretValue to the prefix ARN",
        )

    @staticmethod
    def _out_of_scope_probe_name(prefix: str) -> str:
        """A secret name guaranteed OUTSIDE ``prefix`` and overwhelmingly unlikely
        to exist — for the read-scope probe. Prepends ``z`` until it no longer
        starts with the prefix."""
        name = "avp-selfcheck-out-of-scope-probe-DO-NOT-CREATE"
        while name.startswith(prefix):
            name = "z" + name
        return name

    def _refuse_or_warn(self, mode: str, msg: str) -> None:
        from kow.backends import BackendUnavailableError

        if mode == "deny":
            raise BackendUnavailableError(f"{msg} [self_check=deny → refusing to start]")
        _log.warning("%s [self_check=warn → continuing]", msg)

    def diagnose(self) -> list[tuple[str, str, str]]:
        """Read-only scope report for ``avp doctor --probe-aws`` — a list of
        ``(status, check, message)`` rows. NEVER raises: every probe failure
        becomes a row. Makes only credential-resolve + ListSecrets calls."""
        from kow.backends import BackendAuthLostError, BackendUnavailableError

        assert self._config is not None
        prefix = self._config.secret_prefix
        rows: list[tuple[str, str, str]] = []

        try:
            if self._credential_provider is None:
                self._credential_provider = self._build_credential_provider()
            creds = self._credential_provider()
            temp = "temporary (session-token)" if creds.session_token else "PERMANENT (no token)"
            status = "OK" if creds.session_token else "WARN"
            rows.append((status, "auth", f"credentials resolved: {temp}"))
        except (BackendAuthLostError, BackendUnavailableError) as e:
            rows.append(("FAIL", "auth", f"could not resolve credentials: {e}"))
            return rows

        try:
            all_names = self._list_names(scope_to_prefix=False)
            if not prefix:
                rows.append(
                    ("WARN", "enumeration", f"no secret_prefix set — {len(all_names)} visible")
                )
            else:
                out = [n for n in all_names if not n.startswith(prefix)]
                rows.append(
                    (
                        "WARN",
                        "enumeration",
                        f"can list {len(out)} outside {prefix!r} (e.g. {out[0]!r})",
                    )
                    if out
                    else ("OK", "enumeration", f"all listable secrets are within {prefix!r}")
                )
        except BackendAuthLostError as e:
            scoped = getattr(e, "aws_error_type", "") in _ACCESS_DENIED_TYPES
            rows.append(
                ("OK", "enumeration", "list access-denied — cannot enumerate others")
                if scoped
                else ("WARN", "enumeration", f"list inconclusive: {e}")
            )
        except BackendUnavailableError as e:
            rows.append(("WARN", "enumeration", f"list inconclusive: {type(e).__name__}"))
        return rows

    # ---- binding-note extraction -----------------------------------------

    def _note_from_meta(self, meta: dict[str, Any]) -> str | None:
        """Derive the binding string from a secret's cached metadata: the
        ``avp-binding`` tag (bare host) wins; else a Description carrying the
        ``# avp-binding`` marker; else ``None``. Blank/whitespace → ``None``."""
        tags = meta.get("tags") or {}
        raw = tags.get(_BINDING_TAG)
        if isinstance(raw, str) and raw.strip():
            return raw
        desc = meta.get("description")
        if isinstance(desc, str) and desc.strip():
            # Only treat a Description as a binding when it opts in with the
            # marker (ADR-0025); ordinary human descriptions are not bindings.
            from kow.notes_binding import NOTES_MARKER

            first = next((ln for ln in desc.splitlines() if ln.strip()), "")
            if first.strip() == NOTES_MARKER:
                return desc
        return None

    def _binding_note(self, name: str) -> str | None:
        """The binding note for ``name``: cache (from list) first, else a
        DescribeSecret metadata call."""
        meta = self._meta.get(name)
        if meta is None:
            _status, body = self._call(_TARGET_DESCRIBE, {"SecretId": name})
            meta = self._meta_from_describe(body or {})
            self._meta[name] = meta
        return self._note_from_meta(meta)

    @staticmethod
    def _meta_from_describe(body: dict[str, Any]) -> dict[str, Any]:
        tags = {
            t["Key"]: t["Value"]
            for t in body.get("Tags") or []
            if isinstance(t, dict)
            and isinstance(t.get("Key"), str)
            and isinstance(t.get("Value"), str)
        }
        desc = body.get("Description")
        return {"tags": tags, "description": desc if isinstance(desc, str) else None}

    # ---- REST helpers -----------------------------------------------------

    def _list_names(self, *, scope_to_prefix: bool) -> list[str]:
        """Enumerate secret names, paginating ``ListSecrets``. ``scope_to_prefix``
        filters to ``secret_prefix``; False returns everything the identity can
        see (self_check). Caches tags + description on the scoped pass."""
        assert self._config is not None
        prefix = self._config.secret_prefix
        names: list[str] = []
        next_token: str | None = None
        while True:
            req: dict[str, Any] = {"MaxResults": _LIST_PAGE_SIZE}
            if next_token:
                req["NextToken"] = next_token
            _status, body = self._call(_TARGET_LIST, req)
            body = body if isinstance(body, dict) else {}
            for entry in body.get("SecretList") or []:
                if not isinstance(entry, dict):
                    continue  # malformed entry — skip rather than raise
                name = entry.get("Name")
                if not isinstance(name, str) or not name:
                    continue
                if scope_to_prefix and prefix and not name.startswith(prefix):
                    continue
                names.append(name)
                if scope_to_prefix:
                    self._meta[name] = self._meta_from_describe(entry)
            next_token = body.get("NextToken") or None
            if not next_token:
                break
        return names

    def _call(self, target: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
        """One signed AWS JSON-1.1 call. Signs with our SigV4 signer (reusing the
        ADR-0036 ``signed_headers_extra`` path — AWS rejects an unsigned
        ``x-amz-*`` header, and we send ``x-amz-target``). Maps non-2xx to
        protocol exceptions off the AWS ``__type`` discriminator."""
        from kow.backends import (
            BackendAuthLostError,
            BackendUnavailableError,
            SecretNotFoundError,
        )

        body_bytes = json.dumps(payload).encode("utf-8")
        try:
            creds = self._credential_provider() if self._credential_provider is not None else None
        except (BackendAuthLostError, BackendUnavailableError, SecretNotFoundError):
            raise
        except Exception as e:  # provider errors must map into the protocol
            raise BackendUnavailableError(
                f"AWS credential resolution failed: {type(e).__name__}"
            ) from None
        if creds is None:
            raise BackendUnavailableError("AWS credentials unavailable")
        # Re-validate on EVERY call, not just at boot: a provider that returned
        # temporary creds at _ensure_ready could later refresh into a permanent
        # key. require_temporary_credentials must hold for every signed request.
        if (
            self._config is not None
            and self._config.require_temporary_credentials
            and not creds.session_token
        ):
            raise BackendAuthLostError(
                "aws backend resolved PERMANENT credentials on a request (no STS "
                "session token); require_temporary_credentials refuses them"
            )

        amz_date = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        result = sign(
            method="POST",
            url=self._endpoint,
            body=body_bytes,
            access_key_id=creds.access_key_id,
            secret_access_key=creds.secret_access_key,
            region=self._region,
            service=_SERVICE,
            amz_date=amz_date,
            session_token=creds.session_token,
            sign_content_sha256=True,
            # x-amz-target is an x-amz-* header we send, so it MUST be signed.
            signed_headers_extra={"x-amz-target": target},
        )
        headers = {
            "Authorization": result.authorization,
            "X-Amz-Date": result.amz_date,
            "X-Amz-Content-Sha256": result.content_sha256,
            "X-Amz-Target": target,
            "Content-Type": _JSON_CONTENT_TYPE,
            "Accept": "application/json",
        }
        if result.security_token is not None:
            headers["X-Amz-Security-Token"] = result.security_token

        try:
            status, resp = self._do_http("POST", self._endpoint, headers, body_bytes)
        except _HttpError as e:
            status, resp = e.status, e.body
        except Exception as e:  # network / DNS / TLS
            raise BackendUnavailableError(f"AWS request failed: {type(e).__name__}") from None

        if 200 <= status < 300:
            return status, resp
        raise self._make_aws_error(status, resp)

    @staticmethod
    def _make_aws_error(status: int, body: dict[str, Any] | None) -> Exception:
        """Map an AWS error response to a protocol exception off the ``__type``
        discriminator (AWS returns 400 for most modeled errors, 403 for auth)."""
        from kow.backends import (
            BackendAuthLostError,
            BackendUnavailableError,
            SecretNotFoundError,
        )

        err_type = ""
        if isinstance(body, dict):
            # JSON-1.1 (secretsmanager) uses `__type`; tolerate `Code`/`code`
            # from an intervening SDK/proxy layer defensively.
            raw = body.get("__type") or body.get("Code") or body.get("code") or ""
            err_type = raw.rsplit("#", 1)[-1] if isinstance(raw, str) else ""

        if err_type == "ResourceNotFoundException":
            return SecretNotFoundError("AWS: no such secret")
        # Auth / denial / signature errors → BackendAuthLostError. Names match the
        # AWS common-errors + Secrets Manager reference (denials are HTTP 400;
        # bad-credential / signature ones vary 400/403). ThrottlingException is
        # deliberately NOT here — it's retryable → BackendUnavailableError below.
        auth_types = _ACCESS_DENIED_TYPES | {
            "UnrecognizedClientException",
            "InvalidClientTokenId",
            "ExpiredTokenException",
            "MissingAuthenticationTokenException",
            "InvalidSignatureException",
            "SignatureDoesNotMatch",
            "IncompleteSignature",
        }
        if status in (401, 403) or err_type in auth_types:
            err = BackendAuthLostError(
                f"AWS denied access (HTTP {status}, {err_type or 'unknown'})"
            )
            err.http_status = status  # type: ignore[attr-defined]
            err.aws_error_type = err_type  # type: ignore[attr-defined]
            return err
        return BackendUnavailableError(
            f"AWS request failed: HTTP {status} ({err_type or 'unknown'})"
        )

    def _do_http(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None = None
    ) -> tuple[int, dict[str, Any] | None]:
        """Injected transport in tests; urllib in production."""
        if self._http is not None:
            return self._http(method, url, headers, body)
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))  # noqa: S310  # nosec B310 — fixed https host
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310  # nosec B310 — fixed https host  # nosemgrep
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            try:
                parsed = json.loads(e.read() or b"null")
            except (ValueError, OSError):
                parsed = None
            raise _HttpError(e.code, parsed) from None


# Self-register at import time. backends/__init__.py imports this module.
def _register() -> None:
    from kow.backends import register_backend

    register_backend("aws-secrets-manager", AwsSecretsManagerBackend, AwsConfig)


_register()
