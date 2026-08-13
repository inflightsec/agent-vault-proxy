"""``kow doctor --probe-oauth`` — operator self-service for OAuth2 bindings (ADR-0017 slice 8).

Answers "is this binding wired correctly?" without driving a proxied
request through an agent. Each probe is READ-ONLY by default — the
``--exchange`` opt-in is the only path that actually contacts the
upstream token endpoint, and most providers will rotate the refresh
token on a successful exchange (so it is state-mutating on the
upstream side; the probe reports rotations distinctly so the operator
knows the old token is now invalid).

Per-binding checks:

* **ssrf** — re-runs the SSRF guard on ``token_url`` at probe time;
  config-load already passed but DNS could rebind between then and now.
* **input:<role>** — fetches each of the three vault inputs
  (``client_id_secret``, ``client_secret_secret``,
  ``refresh_token_secret``) through the configured backend. Empty
  value or fetch failure is a ``FAIL``.
* **writable** — checks whether the backend has an ``update`` method so
  the slice-7 write-back path could persist a rotated refresh token.
  Read-only backend with ``refresh_token_write_back: true`` is a
  ``FAIL`` (a rotation would lock the binding out); with
  ``refresh_token_write_back: false`` it is a ``WARN`` (operator opted
  in to the lockout risk).
* **exchange** (opt-in, ``--exchange``) — actually calls the token
  endpoint; ``OK`` on success without rotation, ``WARN`` on success
  WITH rotation (the probe consumed the old refresh token), ``FAIL``
  on any upstream error, ``SKIP`` if a prior input check already
  failed.

Status semantics: ``FAIL`` rolls up to exit code 1; ``WARN`` and
``OK`` do not. ``SKIP`` is a non-finding (the prerequisite for the
check wasn't met).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from kow._ssrf_guard import SsrfBlockedError, check_url_not_internal
from kow.backends import (
    BackendUnavailableError,
    SecretNotFoundError,
    SecretsBackend,
)
from kow.config import Config, Oauth2RefreshInjector

Status = Literal["OK", "WARN", "FAIL", "SKIP"]


@dataclass(frozen=True)
class ProbeResult:
    """One probe's outcome.

    ``binding_name`` is the secret key from ``bindings.yaml``;
    ``check`` is a stable machine label (``ssrf`` / ``input:<role>`` /
    ``writable`` / ``exchange`` / ``binding-exists`` / ``binding-type``
    / ``discovery``); ``status`` is the rolled-up severity;
    ``message`` is the operator-readable line printed under the
    binding's header.
    """

    binding_name: str
    check: str
    status: Status
    message: str


def probe_oauth_binding(
    config: Config,
    binding_name: str,
    backend: SecretsBackend,
    *,
    do_exchange: bool = False,
) -> list[ProbeResult]:
    """Probe one OAuth2 binding's preconditions without proxying a request."""
    secret_spec = config.secrets.get(binding_name)
    if secret_spec is None:
        return [
            ProbeResult(
                binding_name,
                "binding-exists",
                "FAIL",
                f"no secret named {binding_name!r} in config",
            )
        ]
    if not isinstance(secret_spec.inject, Oauth2RefreshInjector):
        return [
            ProbeResult(
                binding_name,
                "binding-type",
                "FAIL",
                f"binding {binding_name!r} is not type oauth2_refresh "
                f"(found: {type(secret_spec.inject).__name__})",
            )
        ]
    injector = secret_spec.inject
    results: list[ProbeResult] = []
    results.append(_probe_ssrf(binding_name, injector))
    input_results = _probe_inputs(binding_name, injector, backend)
    results.extend(input_results)
    results.append(_probe_writable(binding_name, injector, backend))
    if do_exchange:
        results.append(_probe_exchange(binding_name, injector, backend, input_results))
    return results


def probe_all_oauth_bindings(
    config: Config,
    backend: SecretsBackend,
    *,
    binding_filter: str | None = None,
    do_exchange: bool = False,
) -> tuple[list[ProbeResult], bool]:
    """Probe every ``oauth2_refresh`` binding (or just the named one).

    Returns ``(results, any_fail)``. ``any_fail`` is the bit ``run_doctor``
    folds into its exit code.
    """
    if binding_filter is not None:
        candidates = [binding_filter]
    else:
        candidates = [
            name
            for name, spec in config.secrets.items()
            if isinstance(spec.inject, Oauth2RefreshInjector)
        ]
    if not candidates:
        return (
            [
                ProbeResult(
                    "(none)",
                    "discovery",
                    "WARN",
                    "no oauth2_refresh bindings configured — nothing to probe",
                )
            ],
            False,
        )
    results: list[ProbeResult] = []
    any_fail = False
    for name in candidates:
        binding_results = probe_oauth_binding(config, name, backend, do_exchange=do_exchange)
        results.extend(binding_results)
        if any(r.status == "FAIL" for r in binding_results):
            any_fail = True
    return (results, any_fail)


# --- per-check helpers ------------------------------------------------------


def _probe_ssrf(binding_name: str, injector: Oauth2RefreshInjector) -> ProbeResult:
    token_url = str(injector.token_url)
    try:
        check_url_not_internal(token_url)
    except SsrfBlockedError as e:
        return ProbeResult(
            binding_name,
            "ssrf",
            "FAIL",
            f"token_url SSRF check failed: {e}",
        )
    # Show the host only (not the full URL) — query params would be a
    # contract leak under the same audit hygiene the daemon enforces.
    from urllib.parse import urlparse

    host = urlparse(token_url).hostname or "(unknown)"
    return ProbeResult(
        binding_name,
        "ssrf",
        "OK",
        f"token_url host {host} resolved and passed the SSRF guard",
    )


def _probe_inputs(
    binding_name: str,
    injector: Oauth2RefreshInjector,
    backend: SecretsBackend,
) -> list[ProbeResult]:
    out: list[ProbeResult] = []
    for label, ref in (
        ("client_id", injector.client_id_secret),
        ("client_secret", injector.client_secret_secret),
        ("refresh_token", injector.refresh_token_secret),
    ):
        out.append(_probe_one_input(binding_name, label, ref, backend))
    return out


def _probe_one_input(
    binding_name: str,
    label: str,
    ref: str,
    backend: SecretsBackend,
) -> ProbeResult:
    check = f"input:{label}"
    try:
        value = backend.fetch(ref)
    except SecretNotFoundError:
        return ProbeResult(
            binding_name,
            check,
            "FAIL",
            f"vault secret {ref!r} not found",
        )
    except BackendUnavailableError as e:
        return ProbeResult(
            binding_name,
            check,
            "FAIL",
            f"backend unavailable fetching {ref!r}: {type(e).__name__}",
        )
    except Exception as e:  # noqa: BLE001 - any backend exception is a fetch failure
        return ProbeResult(
            binding_name,
            check,
            "FAIL",
            f"backend error fetching {ref!r}: {type(e).__name__}",
        )
    if not value:
        return ProbeResult(
            binding_name,
            check,
            "FAIL",
            f"vault secret {ref!r} is empty",
        )
    # Report length only — never the value itself.
    return ProbeResult(
        binding_name,
        check,
        "OK",
        f"vault secret {ref!r} fetched ({len(value)} bytes)",
    )


def _probe_writable(
    binding_name: str,
    injector: Oauth2RefreshInjector,
    backend: SecretsBackend,
) -> ProbeResult:
    backend_supports_update = callable(getattr(type(backend), "update", None))
    if not injector.refresh_token_write_back:
        # Operator explicitly opted out. Not a FAIL — they chose this —
        # but always a WARN so the consequence is visible: the next
        # rotation will lock the binding out until they rotate
        # manually in the vault.
        return ProbeResult(
            binding_name,
            "writable",
            "WARN",
            "refresh_token_write_back: false — a future upstream rotation "
            "will lock this binding out until you manually update the "
            "refresh token in the vault",
        )
    if not backend_supports_update:
        backend_name = type(backend).__name__
        msg = (
            f"backend {backend_name} has no write method (read-only adapter); "
            "the next upstream rotation will fail with "
            "write_back_unavailable. Either use a writable backend "
            "(BWS) or set refresh_token_write_back: false to accept "
            "the lockout risk explicitly."
        )
        return ProbeResult(binding_name, "writable", "FAIL", msg)
    return ProbeResult(
        binding_name,
        "writable",
        "OK",
        f"backend {type(backend).__name__} supports update — "
        "rotated refresh tokens will be persisted",
    )


def _probe_exchange(
    binding_name: str,
    injector: Oauth2RefreshInjector,
    backend: SecretsBackend,
    input_results: list[ProbeResult],
) -> ProbeResult:
    # If any input failed, the live exchange can't run. Distinct SKIP
    # status so the operator sees the actual failure (the input) rather
    # than a secondary symptom (a confusing 'invalid_client' from
    # exchanging with empty creds).
    if any(r.status == "FAIL" for r in input_results):
        return ProbeResult(
            binding_name,
            "exchange",
            "SKIP",
            "skipping live exchange because one or more input fetches failed",
        )
    # Local import: only pull the urllib + exchange machinery into the
    # process when the operator explicitly asked to probe live.
    from kow.injectors.oauth2_refresh import exchange

    try:
        client_id_value = backend.fetch(injector.client_id_secret)
        client_secret_value = backend.fetch(injector.client_secret_secret)
        refresh_token_value = backend.fetch(injector.refresh_token_secret)
    except Exception as e:  # noqa: BLE001 - covered by the input checks already
        return ProbeResult(
            binding_name,
            "exchange",
            "SKIP",
            f"skipping live exchange (input re-fetch failed: {type(e).__name__})",
        )
    result = exchange(injector, client_id_value, client_secret_value, refresh_token_value)
    if result.outcome != "success":
        msg = f"token endpoint outcome: {result.outcome}"
        if result.error_description is not None:
            msg += f" — {result.error_description}"
        return ProbeResult(binding_name, "exchange", "FAIL", msg)
    if result.new_refresh_token is not None:
        # The probe consumed the old refresh token — the upstream
        # rotated. Operator MUST know: the prior value in the vault
        # would no longer work for an exchange. Slice 7's write-back
        # path doesn't run for the probe (we deliberately don't
        # mutate the vault from doctor), so the operator must
        # manually rotate in the vault now.
        return ProbeResult(
            binding_name,
            "exchange",
            "WARN",
            "token endpoint returned success AND ROTATED the refresh token. "
            "Probe did NOT write-back; the vault now holds the OLD token, "
            "which the upstream will reject on the next exchange. "
            "Update the vault secret manually with the rotated value.",
        )
    return ProbeResult(
        binding_name,
        "exchange",
        "OK",
        "token endpoint returned a fresh access token; refresh token unchanged",
    )
