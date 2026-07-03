"""Bitwarden Secrets Manager backend.

BWS-specific concerns only: auth, name→id resolution, the SDK calls.
Caching is layered on top by ``agent_vault_proxy.caching.CachingSecretsClient``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class BwsConfig(BaseModel):
    """`backend.config` schema for `type: bws`.

    Access token precedence: if BWS_ACCESS_TOKEN
    is set in the process environment, it wins over `access_token_path`
    unconditionally. Documented footgun — an operator who sets the path
    expecting it to be authoritative will get a silent override. When
    both are set, _ensure_authed() emits a DeprecationWarning so the
    divergence surfaces in logs.
    """

    # extra=forbid: bindings.yaml typos rejected at startup, not silently ignored.
    # hide_input_in_errors: pydantic ValidationError reprs don't include the
    # input dict (which could include token paths or other sensitive bits).
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    type: Literal["bws"] = "bws"
    organization_id: str
    access_token_path: str | None = None
    state_path: str | None = None
    api_url: str = "https://api.bitwarden.com"
    identity_url: str = "https://identity.bitwarden.com"


class BitwardenBackend:
    """BWS backend implementing SecretsBackend.

    Instantiation is cheap (no I/O). First fetch() triggers auth + a list
    call to populate the name→id map. Subsequent fetches reuse the map
    until flush_name_map() is called.
    """

    def __init__(
        self,
        config: BwsConfig | None = None,
        *,
        sdk_client: Any = None,
        organization_id: str | None = None,
    ) -> None:
        # Two construction paths:
        #   1. Production: `BitwardenBackend(config=BwsConfig(...))` — defers
        #      auth to first fetch() so __init__ does no I/O.
        #   2. Tests: `BitwardenBackend(sdk_client=mock, organization_id=...)`
        #      — bypasses the real SDK + auth path entirely.
        self._config = config
        self._sdk_client = sdk_client
        self._organization_id = organization_id or (
            config.organization_id if config is not None else None
        )
        # Lazy: populated on first fetch via _ensure_authed() / _ensure_name_map().
        self._name_to_id: dict[str, str] | None = None

    def __repr__(self) -> str:
        # Do not include the config object (could leak token path / org ID
        # via repr in a traceback or log). Plain class name + identity.
        return f"<{self.__class__.__name__}>"

    def fetch(self, name: str, ctx: Any = None) -> str:
        value, _note = self._fetch_data(name)
        return value

    def fetch_with_meta(self, name: str, ctx: Any = None) -> tuple[str, str | None]:
        """Return ``(value, note)`` for ``name`` (ADR-0011 item 1).

        The note is the BWS secret's ``notes`` field, carrying the binding
        metadata blob. Normalisation: an absent field, an empty string, or a
        whitespace-only string all collapse to ``None`` — i.e. "no binding",
        NOT a malformed one. The malformed-vs-no-binding distinction is made
        downstream by the notes parser; here we only decide present-vs-absent.
        """
        return self._fetch_data(name)

    def _fetch_data(self, name: str) -> tuple[str, str | None]:
        """Shared resolve+get for fetch / fetch_with_meta. Returns the
        secret value and its normalised note (None when absent/blank)."""
        from agent_vault_proxy.backends import (
            BackendUnavailableError,
            SecretNotFoundError,
        )

        self._ensure_authed()
        name_to_id = self._ensure_name_map()
        secret_id = name_to_id.get(name)
        if secret_id is None:
            raise SecretNotFoundError(f"secret '{name}' not in BWS organization")
        try:
            response = self._sdk_client.secrets().get(secret_id)
        except Exception as e:
            raise BackendUnavailableError(f"BWS get failed: {e}") from e
        # bws-sdk has no type stubs; .value / .note are Any. Cast at the
        # boundary so the rest of the codebase keeps the Protocol's `str`
        # contract intact.
        value: str = response.data.value
        # .note may be absent on older SDK objects / mocks; getattr-default
        # to None. Empty/whitespace -> None (no binding, not malformed).
        raw_note = getattr(response.data, "note", None)
        note = None if raw_note is None or not str(raw_note).strip() else str(raw_note)
        return value, note

    def update(self, name: str, value: str, ctx: Any = None) -> None:  # noqa: ARG002
        """Persist ``value`` under ``name`` (ADR-0017 slice 3).

        Reads the current secret to capture ``note`` and ``project_ids``,
        then PUTs the new value with the same metadata. Blanking the
        note would lose binding-yaml-blob metadata on every refresh-
        token rotation — that's not acceptable behaviour for a write
        the operator never asked about.

        The SDK's ``secrets().update`` is the BWS PUT-by-id endpoint.
        Org id and secret id are looked up identically to the fetch
        path (cached name→id map; refreshed via ``flush_name_map``).

        ``ctx`` is accepted to match the Protocol signature but is
        intentionally unused — BWS update has no per-request context
        to honour beyond what the secret id carries.

        **Known limitations:**

        * **No ETag/version preconditions.** The BWS SDK exposes no
          conditional-PUT primitive. A concurrent edit to ``note`` or
          ``project_ids`` between this method's GET and PUT is
          silently overwritten. Single-host single-instance AVP keeps
          this rare; multi-instance coordination is its own ADR.
        * **No retry on stale name→id map.** ``_ensure_name_map`` is
          populated lazily and only refreshed via ``flush_name_map``;
          a secret deleted and re-created with the same key between
          map populations will fail with ``BackendUnavailableError``
          via the SDK's not-found path. Operator action: invoke
          ``avp doctor`` (which flushes) and retry.
        """
        from agent_vault_proxy.backends import (
            BackendUnavailableError,
            SecretNotFoundError,
        )

        self._ensure_authed()
        name_to_id = self._ensure_name_map()
        secret_id = name_to_id.get(name)
        if secret_id is None:
            raise SecretNotFoundError(f"secret '{name}' not in BWS organization")
        try:
            current = self._sdk_client.secrets().get(secret_id)
            note = getattr(current.data, "note", None)
            project_ids = getattr(current.data, "project_ids", None)
            self._sdk_client.secrets().update(
                self._organization_id,
                secret_id,
                name,
                value,
                note,
                project_ids,
            )
        except (SecretNotFoundError, BackendUnavailableError):
            raise
        except Exception as e:
            raise BackendUnavailableError(f"BWS update failed: {e}") from e

    def list_secret_names(self) -> list[str]:
        """Return every secret NAME (BWS ``.key``) in the configured org/project
        (ADR-0011 amendment — drives ``avp env`` and the daemon's BWS-notes
        placeholder map). Triggers auth + the list call on first use, reusing
        the cached name→id map thereafter. Returns names only — no values, no
        ids — so the projection that builds the env file never pulls secret
        bytes it doesn't need."""
        self._ensure_authed()
        return list(self._ensure_name_map().keys())

    def flush_name_map(self) -> None:
        """Invalidate the cached name→id map. Called when the caching
        layer is told to flush — forces a fresh list on next fetch."""
        self._name_to_id = None

    def _ensure_authed(self) -> None:
        if self._sdk_client is not None:
            return
        if self._config is None:
            raise NotImplementedError(
                "BitwardenBackend was constructed without sdk_client AND without "
                "config; use BitwardenBackend(config=BwsConfig(...)) or pass a "
                "test-double sdk_client"
            )
        from agent_vault_proxy.backends import BackendUnavailableError

        access_token = os.environ.get("BWS_ACCESS_TOKEN")
        if access_token is not None and self._config.access_token_path:
            # surface the env-vs-path divergence. The env
            # var wins, but the operator who set the path expected it to
            # be authoritative.
            import warnings

            warnings.warn(
                "both BWS_ACCESS_TOKEN env var and access_token_path are "
                f"configured ({self._config.access_token_path!r}); env wins. "
                "If you intended the path to be authoritative, unset "
                "BWS_ACCESS_TOKEN in this process's environment.",
                DeprecationWarning,
                stacklevel=2,
            )
        if access_token is None and self._config.access_token_path:
            token_path = Path(self._config.access_token_path)
            if token_path.exists():
                access_token = token_path.read_text().strip()
        if not access_token:
            raise BackendUnavailableError(
                "no BWS access token (set BWS_ACCESS_TOKEN env or configure bws.access_token_path)"
            )

        from bitwarden_sdk import BitwardenClient, client_settings_from_dict

        sdk_client = BitwardenClient(
            client_settings_from_dict(
                {
                    "apiUrl": self._config.api_url,
                    "identityUrl": self._config.identity_url,
                    "userAgent": "agent-vault-proxy",
                }
            )
        )
        try:
            sdk_client.auth().login_access_token(access_token, self._config.state_path)
        except Exception as e:
            # SDK exception bodies may include the
            # Authorization header, request body, or token bytes. Emit
            # only the exception type, and use `from None` to drop the
            # cause chain so the original exception (still containing the
            # token) doesn't surface in tracebacks/logs.
            #
            # this DOES lose diagnostic detail. If you need
            # to debug auth failures, the addon's audit log
            # (`agent_vault_proxy.addon`) records the backend type +
            # operation + outcome with no PII. Combine that with the
            # exception class name surfaced here. Do NOT re-add the
            # original `{e}` interpolation here without first proving the
            # SDK never echoes the Authorization header in its repr.
            raise BackendUnavailableError(f"BWS auth failed: {type(e).__name__}") from None
        self._sdk_client = sdk_client

    def _ensure_name_map(self) -> dict[str, str]:
        if self._name_to_id is not None:
            return self._name_to_id
        from agent_vault_proxy.backends import BackendUnavailableError

        try:
            response = self._sdk_client.secrets().list(self._organization_id)
        except Exception as e:
            raise BackendUnavailableError(f"BWS list failed: {e}") from e
        self._name_to_id = {item.key: item.id for item in response.data.data}
        return self._name_to_id


# Self-register at import time. The agent_vault_proxy.backends package
# __init__.py imports this module, which triggers this call.
def _register() -> None:
    # Local import to avoid circular import at module load time
    # (this module is imported FROM backends/__init__.py).
    from agent_vault_proxy.backends import register_backend

    register_backend("bws", BitwardenBackend, BwsConfig)


_register()
