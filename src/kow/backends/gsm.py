"""Google Secret Manager backend.

GSM-specific concerns only: keyless ADC / impersonation / Workload-Identity
auth, the REST calls to ``secretmanager.googleapis.com``, and the
least-privilege boot guard. Caching is layered on top by
``kow.caching.CachingSecretsClient``.

Design mirrors :mod:`kow.backends.bws`:

* **No I/O in __init__.** First auth + first REST call happen on first use.
* **Lazy ``google-auth`` import.** Importing this module (for registration and
  config validation) never requires ``google-auth`` — only a live fetch does.
  ``google-auth`` is an optional dependency (extra ``gsm``); the two protocol
  helpers (``fetch_with_meta`` / ``list_secret_names``) and the parser reuse
  work without it installed.
* **Test-injection path.** ``GsmBackend(config=..., token_provider=fn, http=fn)``
  bypasses ``google-auth`` and the network entirely, so the contract suite and
  unit tests need neither the dependency nor a live GCP project.

Host binding (ADR-0018 §4): this backend is notes-aware. A secret may carry an
``avp-binding`` annotation whose value is either a **bare hostname** (the
North-Star case — ``avp-binding: api.openai.com``) or the same flat-YAML
binding blob the BWS notes path uses. ``fetch_with_meta`` surfaces that
annotation verbatim; ``kow.notes_binding.parse_notes_binding`` turns
it into a fail-closed binding. A secret with no ``avp-binding`` annotation
resolves to ``NoBinding`` and is never injected.

Least privilege (ADR-0018 §6): the config has **no key-file field** — an
operator cannot wire a downloadable service-account key through it.
``reject_ambient_key`` additionally refuses a key surfaced via ADC. When
``self_check`` is ``deny`` (default), the backend refuses to start if its
identity can ENUMERATE secrets outside ``secret_prefix``. This bounds
enumeration breadth. A project-level ``testIamPermissions`` access-probe ALSO
runs — it catches a project-wide ``versions.access`` grant even when list is
denied. (A per-secret grant on a *foreign* secret still evades detection; that
stays an IAM-least-privilege duty.) Belt-and-suspenders: ``_assert_in_scope``
also refuses to *fetch* any name outside ``secret_prefix`` at the access
boundary, so a stray broad grant still cannot pull an out-of-namespace secret
through this backend.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import threading
from collections.abc import Callable
from typing import Any, Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

_log = logging.getLogger("kow.backends.gsm")

_API_ROOT = "https://secretmanager.googleapis.com/v1"
# Annotation key that carries the AVP binding (bare host or flat-YAML blob).
_BINDING_ANNOTATION = "avp-binding"
# cloud-platform is the scope AccessSecretVersion + ListSecrets require; the
# IAM role bounds the ACTUAL reach, the scope only gates which APIs the token
# may address.
_SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)
_LIST_PAGE_SIZE = 500
# Cloud Resource Manager — used by the self_check project-level access probe.
_RESOURCEMANAGER_ROOT = "https://cloudresourcemanager.googleapis.com/v1"
_ACCESS_PERM = "secretmanager.versions.access"
# Write/admin perms AVP must never hold — it only ever reads. A keyless read
# broker granted any of these is over-privileged: a compromised proxy could
# tamper with, add, or destroy vault contents (and rewrite the very
# `avp-binding` annotations that drive routing). self_check refuses to start
# under them (deny), the same deny-if-broad posture as _ACCESS_PERM.
_WRITE_PERMS = (
    "secretmanager.secrets.update",
    "secretmanager.versions.add",
    "secretmanager.secrets.delete",
)

# Transport callable injected in tests: (method, url, headers, body) ->
# (status_code, parsed_json_or_None). Production builds one from urllib.
HttpFn = Callable[[str, str, "dict[str, str]", "bytes | None"], "tuple[int, dict[str, Any] | None]"]
TokenFn = Callable[[], str]


class GsmConfig(BaseModel):
    """``backend.config`` schema for ``type: gsm`` (ADR-0018 §2).

    Two design-load-bearing choices: (a) there is deliberately **no
    key-file field**, so a downloadable service-account key cannot be wired
    through config; (b) ``reject_ambient_key`` catches the back door — a
    ``GOOGLE_APPLICATION_CREDENTIALS`` pointing at a ``*.json`` key is
    detected and refused before any network call.
    """

    # extra=forbid: bindings.yaml typos rejected at startup, not silently
    # ignored. hide_input_in_errors: ValidationError reprs never echo config.
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    type: Literal["gsm"] = "gsm"
    project_id: str
    version_alias: str = "latest"
    # Namespace: only secrets whose id starts with this prefix are in scope
    # (client-side list filter + the self_check boundary). Optional.
    secret_prefix: str | None = None

    # --- Auth: KEYLESS BY DESIGN. No service_account_key_path field exists. ---
    # ADC user creds impersonate this low-priv SA (short-lived tokens).
    impersonate_service_account: str | None = None
    # Workload Identity Federation *no-secret* cred-config JSON. WIF is the
    # intended use; a path pointed at a service-account KEY is still caught by
    # reject_ambient_key (default on) — _is_service_account_key runs on whatever
    # this loads, whichever branch produced it.
    credential_config_path: str | None = None

    # --- Secure-by-default guardrails ---
    # deny: refuse to start if the identity is over-broad. Requires
    # secret_prefix (validated below). Two checks: (1) enumeration — can it LIST
    # secrets outside the prefix; (2) access — does it hold project-wide
    # versions.access (a project-level testIamPermissions probe, caught even when
    # list is denied). A per-secret foreign grant still evades detection.
    # Org service-account-key policy is checked by `avp doctor` / the installer.
    self_check: Literal["deny", "warn", "off"] = "deny"
    # Refuse if ADC resolves to a downloaded service-account key file.
    reject_ambient_key: bool = True

    @model_validator(mode="after")
    def _deny_requires_prefix(self) -> GsmConfig:
        # A deny-if-broad guard with no namespace to bound silently no-ops —
        # not secure-by-default. Force an explicit prefix, or an explicit
        # opt-out to warn/off.
        if self.self_check == "deny" and not self.secret_prefix:
            raise ValueError(
                "self_check: deny requires secret_prefix to bound the namespace it "
                "guards (e.g. secret_prefix: 'avp-<owner>-'). Set it, or choose "
                "self_check: warn|off to opt out of the boot guard."
            )
        return self

    @field_validator("project_id")
    @classmethod
    def _validate_project_id(cls, v: str) -> str:
        # project_id is interpolated into every REST URL that also carries the
        # bearer token; a value with a slash / query / fragment / whitespace
        # could redirect that authenticated request. Accept only a GCP project
        # ID (6-30 chars, lowercase letter start) or a numeric project number.
        v = v.strip()
        if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,30}", v):
            raise ValueError(
                "project_id must be a GCP project ID (6-30 lowercase "
                "letters/digits/hyphens, letter-first) or a numeric project "
                "number — no slashes, query, fragment, or whitespace."
            )
        return v


class _HttpError(Exception):
    """Internal: an HTTP response with a non-2xx status. Carries the code and
    parsed body so the caller maps it to a protocol exception."""

    def __init__(self, status: int, body: dict[str, Any] | None) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


class GsmBackend:
    """GSM backend implementing the ``SecretsBackend`` protocol.

    Construction is cheap (no I/O). First use triggers auth (token provider
    build + one-shot self_check) then the REST call.
    """

    # Provenance label stamped onto notes-derived specs + their audit events.
    # Read by runtime_bindings off the backend TYPE (not the binding_source
    # string) so `both` mode labels GSM annotations honestly as gsm_notes.
    NOTES_SOURCE_LABEL = "gsm_notes"

    def __init__(
        self,
        config: GsmConfig | None = None,
        *,
        token_provider: TokenFn | None = None,
        http: HttpFn | None = None,
    ) -> None:
        # Two construction paths:
        #   1. Production: GsmBackend(config=GsmConfig(...)) — token provider is
        #      built lazily from google-auth on first use; http from urllib.
        #   2. Tests: GsmBackend(config=..., token_provider=fn, http=fn) —
        #      bypasses google-auth and the network entirely.
        self._config = config
        self._token_provider = token_provider
        self._http = http
        self._ready = False
        # Serialises first-use init (provider build + self_check) so concurrent
        # first requests don't double-run them (mitmproxy is threaded).
        self._ready_lock = threading.Lock()
        # secret_id -> annotations map, populated by list_secret_names so
        # fetch_with_meta serves the binding annotation without a second GET.
        self._annotations: dict[str, dict[str, str]] = {}

    def __repr__(self) -> str:
        # No config in repr (would leak project id / impersonation target via
        # a traceback or log). Plain class name only.
        return f"<{self.__class__.__name__}>"

    # ---- protocol surface -------------------------------------------------

    def _assert_in_scope(self, name: str) -> None:
        """Defence-in-depth: even if IAM is broader than intended, refuse to
        touch a name outside the configured ``secret_prefix`` namespace — the
        same deny-if-broad posture as self_check, at the access boundary."""
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
        status, body = self._request(
            "GET",
            f"{_API_ROOT}/projects/{self._project}/secrets/{quote(name, safe='')}"
            f"/versions/{quote(self._version_alias, safe='')}:access",
        )
        payload = (body or {}).get("payload") or {}
        data = payload.get("data")
        if not isinstance(data, str):
            from kow.backends import BackendUnavailableError

            raise BackendUnavailableError(f"GSM access for '{name}' returned no payload data")
        try:
            # validate=True rejects non-alphabet bytes instead of silently
            # discarding them — a credential proxy must not accept mangled bytes.
            return base64.b64decode(data, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as e:
            from kow.backends import BackendUnavailableError

            # No secret bytes in the message — only the failure class.
            raise BackendUnavailableError(
                f"GSM secret '{name}' payload is not valid base64/UTF-8: {type(e).__name__}"
            ) from None

    def fetch_with_meta(self, name: str, ctx: Any = None) -> tuple[str, str | None]:
        """Return ``(value, note)``. The note is the secret's ``avp-binding``
        annotation (bare host or flat-YAML blob) or ``None`` when absent/blank.
        Served from the list cache when present, else via a metadata GET."""
        value = self.fetch(name, ctx)
        note = self._binding_annotation(name)
        return value, note

    def list_secret_names(self) -> list[str]:
        """Every in-scope secret id (drives ``avp env`` + notes activation).
        Filtered client-side to ``secret_prefix``; caches each secret's
        annotation map so ``fetch_with_meta`` needs no second call."""
        self._ensure_ready()
        return self._list_ids(scope_to_prefix=True)

    def list_secret_notes(self) -> dict[str, str | None]:
        """``{secret_id: avp-binding annotation | None}`` for every in-scope
        secret, WITHOUT fetching any secret VALUE. Annotations come from the
        free ListSecrets metadata pass, so notes activation never pulls
        plaintext at configure time — and a disabled/denied secret VERSION no
        longer bricks a config reload (only its request-time value fetch fails,
        which fail-closes correctly)."""
        self._ensure_ready()
        ids = self._list_ids(scope_to_prefix=True)  # populates self._annotations
        out: dict[str, str | None] = {}
        for sid in ids:
            raw = (self._annotations.get(sid) or {}).get(_BINDING_ANNOTATION)
            out[sid] = None if raw is None or not str(raw).strip() else str(raw)
        return out

    def flush_name_map(self) -> None:
        """Invalidate the cached annotation map; next list re-reads."""
        self._annotations = {}

    # ---- readiness / auth / self-check -----------------------------------

    @property
    def _project(self) -> str:
        assert self._config is not None
        return self._config.project_id

    @property
    def _version_alias(self) -> str:
        return self._config.version_alias if self._config is not None else "latest"

    def _ensure_ready(self) -> None:
        if self._ready:
            return
        with self._ready_lock:
            if self._ready:  # another thread finished while we waited on the lock
                return
            if self._config is None:
                # config carries project_id / version / prefix that every code
                # path asserts on; token_provider/http are overrides layered ON
                # TOP of config, not a substitute for it.
                raise NotImplementedError(
                    "GsmBackend requires a GsmConfig; pass config=GsmConfig(...). "
                    "token_provider/http are optional test overrides."
                )
            if self._token_provider is None:
                self._token_provider = self._build_token_provider()
            self._run_self_check()
            self._ready = True

    def _build_token_provider(self) -> TokenFn:
        """Build a keyless token provider from ADC / impersonation / WIF.

        Lazy google-auth import: this runs only on first live use, so the
        module imports (and unit tests with an injected provider) never need
        the dependency installed.
        """
        assert self._config is not None
        from kow.backends import (
            BackendAuthLostError,
            BackendUnavailableError,
            require,
        )

        with require("gsm", "google-auth", "gsm"):
            import google.auth
            from google.auth.transport.requests import Request as GoogleAuthRequest

        cfg = self._config
        try:
            if cfg.credential_config_path:
                # WIF / external-account cred-config JSON (no secret material).
                creds, _ = google.auth.load_credentials_from_file(
                    cfg.credential_config_path, scopes=list(_SCOPES)
                )
            else:
                creds, _ = google.auth.default(scopes=list(_SCOPES))
        except Exception as e:  # google.auth.exceptions.DefaultCredentialsError etc.
            raise BackendUnavailableError(
                f"no GCP application-default credentials: {type(e).__name__}"
            ) from None

        if cfg.reject_ambient_key and _is_service_account_key(creds):
            # The whole point of the design: a pasted / mounted SA key is the
            # footgun this refuses. Impersonation and WIF are not key-based.
            raise BackendAuthLostError(
                "gsm backend resolved a downloaded service-account key via ADC; "
                "keys are refused (reject_ambient_key). Use ADC + "
                "impersonate_service_account or a Workload-Identity cred-config."
            )

        if cfg.impersonate_service_account:
            from google.auth import impersonated_credentials

            creds = impersonated_credentials.Credentials(
                source_credentials=creds,
                target_principal=cfg.impersonate_service_account,
                target_scopes=list(_SCOPES),
            )

        request = GoogleAuthRequest()

        def provider() -> str:
            if not creds.valid:
                creds.refresh(request)
            token = creds.token
            if not token:
                raise BackendUnavailableError("google-auth returned an empty access token")
            return str(token)

        return provider

    def _run_self_check(self) -> None:  # noqa: C901 — multi-branch fail-closed boot guard
        """Deny-if-broad boot guard (ADR-0018 §6).

        If ``secret_prefix`` is set and the identity can enumerate secrets
        OUTSIDE that prefix, it is broader than intended → refuse to start
        (``deny``) or warn. A list that is itself denied (403) is GOOD — the
        identity cannot enumerate others — so it passes. With no prefix the
        scope is undeterminable and the check is skipped with a warning.
        """
        assert self._config is not None
        mode = self._config.self_check
        if mode == "off":
            return
        prefix = self._config.secret_prefix
        if not prefix:
            _log.warning(
                "gsm self_check=%s but no secret_prefix set; cannot bound scope — skipping. "
                "Set secret_prefix to enable the deny-if-broad guard.",
                mode,
            )
            return
        from kow.backends import (
            BackendAuthLostError,
            BackendUnavailableError,
            SecretNotFoundError,
        )

        # 1. ENUMERATION breadth — can the identity LIST secrets outside prefix?
        try:
            all_ids = self._list_ids(scope_to_prefix=False)
        except SecretNotFoundError:
            # 404 on ListSecrets = wrong project_id — a config error, fail closed.
            self._refuse_or_warn(mode, "gsm self_check: ListSecrets 404 — check project_id")
            return
        except BackendAuthLostError as e:
            if getattr(e, "http_status", None) == 403:
                # Forbidden to LIST = scoped for enumeration; still probe ACCESS below.
                _log.debug("gsm self_check: list forbidden (403) — enumeration scoped")
                all_ids = []
            else:
                # 401 (broken auth) is not proof of scope — inconclusive.
                self._refuse_or_warn(mode, f"gsm self_check inconclusive ({e})")
                return
        except BackendUnavailableError as e:
            # Transient (5xx / network) — do NOT treat as scoped (would fail open).
            self._refuse_or_warn(mode, f"gsm self_check could not complete: {type(e).__name__}")
            return
        out_of_scope = [n for n in all_ids if not n.startswith(prefix)]
        if out_of_scope:
            self._refuse_or_warn(
                mode,
                f"gsm self_check: identity can enumerate {len(out_of_scope)} secret(s) outside "
                f"prefix {prefix!r} (e.g. {out_of_scope[0]!r}) — broader Secret Manager access "
                "than its own namespace; scope to per-secret secretAccessor",
            )

        # 2. ACCESS breadth — a project-wide versions.access grant is caught here
        # even when list is denied. (A per-secret grant on a foreign secret still
        # evades detection — that stays an IAM-least-privilege duty; ADR-0018 §6.)
        if self._project_has_broad_access():
            self._refuse_or_warn(
                mode,
                f"gsm self_check: identity holds project-wide {_ACCESS_PERM!r} — it can read "
                "EVERY secret in the project; scope to per-secret secretAccessor",
            )

        # 3. WRITE breadth — AVP only reads; any write/admin grant is
        # over-privileged (a compromised proxy could tamper with the vault or
        # rewrite the annotations that drive routing). Best-effort, same
        # inconclusive-is-not-a-block posture as the access probe.
        held_write = self._project_has_write_access()
        if held_write:
            self._refuse_or_warn(
                mode,
                f"gsm self_check: identity holds write/admin permission(s) {held_write} — AVP "
                "is a read-only broker; scope to secretAccessor so a compromised proxy cannot "
                "tamper with the vault",
            )

    def _refuse_or_warn(self, mode: str, msg: str) -> None:
        """Shared self_check failure branch: deny → raise (refuse to start);
        warn → log and continue. ``mode`` is never ``off`` here."""
        from kow.backends import BackendUnavailableError

        if mode == "deny":
            raise BackendUnavailableError(f"{msg} [self_check=deny → refusing to start]")
        _log.warning("%s [self_check=warn → continuing]", msg)

    def _project_has_broad_access(self) -> bool:
        """True iff the identity holds ``secretmanager.versions.access`` at the
        PROJECT level (project-wide read of every secret), via a
        cloudresourcemanager ``testIamPermissions`` self-test (a caller may
        always test its OWN permissions). Any probe failure — API disabled,
        denied, transient — is inconclusive and returns False: the enumeration
        check above stays the primary guard, and this must never fail-open into
        a hard block on an unrelated error."""
        from kow.backends import (
            BackendAuthLostError,
            BackendUnavailableError,
            SecretNotFoundError,
        )

        url = f"{_RESOURCEMANAGER_ROOT}/projects/{quote(self._project, safe='')}:testIamPermissions"
        try:
            _status, body = self._request("POST", url, req_body={"permissions": [_ACCESS_PERM]})
        except (SecretNotFoundError, BackendAuthLostError, BackendUnavailableError):
            _log.debug("gsm self_check: access-breadth probe inconclusive (skipped)")
            return False
        granted = (body or {}).get("permissions")
        return _ACCESS_PERM in granted if isinstance(granted, list) else False

    def _project_has_write_access(self) -> list[str]:
        """The subset of ``_WRITE_PERMS`` the identity holds at PROJECT level,
        via the same self-testable ``testIamPermissions`` probe (a caller may
        always test its OWN permissions). AVP only ever reads; any write/admin
        grant is over-privileged. Probe failure — API disabled, denied,
        transient — is inconclusive and returns ``[]``: defence-in-depth, never
        a hard block on an unrelated error (mirrors ``_project_has_broad_access``)."""
        from kow.backends import (
            BackendAuthLostError,
            BackendUnavailableError,
            SecretNotFoundError,
        )

        url = f"{_RESOURCEMANAGER_ROOT}/projects/{quote(self._project, safe='')}:testIamPermissions"
        try:
            _status, body = self._request("POST", url, req_body={"permissions": list(_WRITE_PERMS)})
        except (SecretNotFoundError, BackendAuthLostError, BackendUnavailableError):
            _log.debug("gsm self_check: write-access probe inconclusive (skipped)")
            return []
        granted = (body or {}).get("permissions")
        if not isinstance(granted, list):
            return []
        return [p for p in _WRITE_PERMS if p in granted]

    def diagnose(self) -> list[tuple[str, str, str]]:  # noqa: C901 — linear report, many branches
        """Read-only scope report for ``avp doctor --probe-gcp`` — a list of
        ``(status, check, message)`` rows. NEVER raises: every probe failure
        becomes a row so the operator always gets a report. Makes only
        read / list / testIamPermissions calls, never a write."""
        from kow.backends import (
            BackendAuthLostError,
            BackendUnavailableError,
            SecretNotFoundError,
        )

        assert self._config is not None
        prefix = self._config.secret_prefix
        rows: list[tuple[str, str, str]] = []

        try:
            if self._token_provider is None:
                self._token_provider = self._build_token_provider()
            self._token_provider()
            rows.append(("OK", "auth", "keyless credentials resolved; access token minted"))
        except (BackendAuthLostError, BackendUnavailableError) as e:
            rows.append(("FAIL", "auth", f"could not authenticate: {e}"))
            return rows  # nothing else is probeable without a token

        try:
            all_ids = self._list_ids(scope_to_prefix=False)
            if not prefix:
                rows.append(
                    (
                        "WARN",
                        "enumeration",
                        f"no secret_prefix set — {len(all_ids)} secret(s) visible",
                    )
                )
            else:
                out = [n for n in all_ids if not n.startswith(prefix)]
                if out:
                    rows.append(
                        (
                            "WARN",
                            "enumeration",
                            f"can list {len(out)} outside {prefix!r} (e.g. {out[0]!r})",
                        )
                    )
                else:
                    rows.append(
                        ("OK", "enumeration", f"all listable secrets are within {prefix!r}")
                    )
        except BackendAuthLostError as e:
            scoped = getattr(e, "http_status", None) == 403
            rows.append(
                ("OK", "enumeration", "list forbidden (403) — cannot enumerate others")
                if scoped
                else ("WARN", "enumeration", f"list inconclusive: {e}")
            )
        except (BackendUnavailableError, SecretNotFoundError) as e:
            rows.append(("WARN", "enumeration", f"list inconclusive: {type(e).__name__}"))

        if self._project_has_broad_access():
            rows.append(
                ("WARN", "access", f"holds PROJECT-WIDE {_ACCESS_PERM!r} — can read EVERY secret")
            )
        else:
            rows.append(("OK", "access", "no project-wide versions.access (or probe inconclusive)"))

        held_write = self._project_has_write_access()
        if held_write:
            rows.append(
                ("WARN", "write", f"holds write/admin {held_write} — AVP should be read-only")
            )
        else:
            rows.append(("OK", "write", "no project-wide write/admin (or probe inconclusive)"))

        try:
            rows.append(
                (
                    "OK",
                    "in-scope",
                    f"{len(self._list_ids(scope_to_prefix=True))} secret(s) in scope",
                )
            )
        except (BackendAuthLostError, BackendUnavailableError, SecretNotFoundError) as e:
            rows.append(("WARN", "in-scope", f"could not enumerate: {type(e).__name__}"))
        return rows

    # ---- REST helpers -----------------------------------------------------

    def _binding_annotation(self, name: str) -> str | None:
        """The ``avp-binding`` annotation for ``name``: cache (from list) first,
        else a metadata GET. Blank/whitespace normalises to ``None`` (absent,
        not malformed — the distinction is the notes parser's job)."""
        annotations = self._annotations.get(name)
        if annotations is None:
            _status, body = self._request(
                "GET", f"{_API_ROOT}/projects/{self._project}/secrets/{quote(name, safe='')}"
            )
            raw_ann = (body or {}).get("annotations")
            annotations = raw_ann if isinstance(raw_ann, dict) else {}
            self._annotations[name] = annotations
        raw = annotations.get(_BINDING_ANNOTATION)
        return None if raw is None or not str(raw).strip() else str(raw)

    def _list_ids(self, *, scope_to_prefix: bool) -> list[str]:
        """Enumerate secret ids, paginating. ``scope_to_prefix`` filters to
        ``secret_prefix`` (functional list); False returns everything the
        identity can see (self_check). Caches annotations on the scoped pass."""
        assert self._config is not None
        prefix = self._config.secret_prefix
        ids: list[str] = []
        page_token: str | None = None
        while True:
            url = f"{_API_ROOT}/projects/{self._project}/secrets?pageSize={_LIST_PAGE_SIZE}"
            if page_token:
                url += f"&pageToken={quote(page_token, safe='')}"
            _status, body = self._request("GET", url)
            body = body if isinstance(body, dict) else {}
            for secret in body.get("secrets") or []:
                if not isinstance(secret, dict):
                    continue  # malformed entry — skip rather than raise AttributeError
                resource = secret.get("name", "")
                secret_id = resource.split("/secrets/", 1)[-1] if isinstance(resource, str) else ""
                if not secret_id:
                    continue
                if scope_to_prefix and prefix and not secret_id.startswith(prefix):
                    continue
                ids.append(secret_id)
                if scope_to_prefix:
                    ann = secret.get("annotations")
                    self._annotations[secret_id] = ann if isinstance(ann, dict) else {}
            page_token = body.get("nextPageToken") or None
            if not page_token:
                break
        return ids

    def _request(
        self, method: str, url: str, req_body: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any] | None]:
        """One authorised REST call. Returns (status, parsed_json). Maps
        non-2xx to the two protocol exceptions."""
        from kow.backends import (
            BackendAuthLostError,
            BackendUnavailableError,
            SecretNotFoundError,
        )

        try:
            token = self._token_provider() if self._token_provider is not None else ""
        except (BackendAuthLostError, BackendUnavailableError, SecretNotFoundError):
            raise  # already a protocol exception
        except Exception as e:
            # Token acquisition (google-auth refresh / impersonation / an
            # injected provider) MUST map into the protocol, not escape raw —
            # the addon and cache only catch BackendUnavailableError /
            # SecretNotFoundError; a raw exception bypasses fail-closed handling.
            raise BackendUnavailableError(
                f"GSM token acquisition failed: {type(e).__name__}"
            ) from None
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        try:
            status, body = self._do_http(method, url, headers, req_body)
        except _HttpError as e:
            status, body = e.status, e.body
        except Exception as e:  # network / DNS / TLS
            raise BackendUnavailableError(f"GSM request failed: {type(e).__name__}") from None

        if 200 <= status < 300:
            return status, body
        if status == 404:
            raise SecretNotFoundError(f"GSM: no such secret/version ({url.rsplit('/', 2)[-1]})")
        if status in (401, 403):
            # Credential invalid / lacking access — flush cached values. Carry
            # the code so self_check can tell 403 (forbidden-to-list → scoped)
            # from 401 (broken auth → inconclusive).
            err = BackendAuthLostError(f"GSM denied access (HTTP {status})")
            err.http_status = status  # type: ignore[attr-defined]
            raise err
        raise BackendUnavailableError(f"GSM request failed: HTTP {status}")

    def _do_http(
        self, method: str, url: str, headers: dict[str, str], body: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any] | None]:
        """Injected transport in tests; urllib in production."""
        payload = json.dumps(body).encode() if body is not None else None
        if self._http is not None:
            return self._http(method, url, headers, payload)
        import urllib.error
        import urllib.request

        h = dict(headers)
        if payload is not None:
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=payload, method=method, headers=h)  # noqa: S310  # nosec B310 — fixed https host
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310  # nosec B310 — fixed https host  # nosemgrep
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            try:
                parsed = json.loads(e.read() or b"null")
            except (ValueError, OSError):
                parsed = None
            raise _HttpError(e.code, parsed) from None


def _is_service_account_key(creds: object) -> bool:
    """True iff ``creds`` is a service-account key loaded from a JSON key file
    (``google.oauth2.service_account.Credentials``). Impersonated credentials,
    external-account (WIF) credentials, and user credentials are all keyless
    and return False."""
    try:
        from google.oauth2 import service_account
    except ImportError:  # pragma: no cover
        return False
    return isinstance(creds, service_account.Credentials)


# Self-register at import time. backends/__init__.py imports this module,
# which triggers this call.
def _register() -> None:
    from kow.backends import register_backend

    register_backend("gsm", GsmBackend, GsmConfig)


_register()
