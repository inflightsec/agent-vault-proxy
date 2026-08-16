"""GSM backend: protocol contract + unit tests (ADR-0018).

All tests use an injected transport (``http``) and token provider, so they
need neither the optional ``google-auth`` dependency nor a live GCP project.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
from pydantic import ValidationError

from kow.backends import (
    BACKEND_REGISTRY,
    BackendAuthLostError,
    BackendUnavailableError,
    SecretNotFoundError,
)
from kow.backends.gsm import GsmBackend, GsmConfig, _is_service_account_key
from kow.runtime_bindings import resolve_runtime_bindings
from kow.secret import Secret
from tests.backends.test_protocol_contract import ProtocolContract


def _access_body(value: str) -> dict[str, Any]:
    return {"payload": {"data": base64.b64encode(value.encode()).decode()}}


def _router(routes: list[tuple[str, tuple[int, dict[str, Any] | None]]]):
    """Fake HttpFn: first route whose needle is in the url wins. Order the
    routes so the more specific needle (``:access``) precedes ``/secrets/``."""

    def http(method: str, url: str, headers: dict[str, str], body: bytes | None):
        assert headers.get("Authorization", "").startswith("Bearer ")
        for needle, resp in routes:
            if needle in url:
                return resp
        return (404, {"error": {"message": f"no route for {url}"}})

    return http


def _backend(http, **cfg) -> GsmBackend:
    cfg.setdefault("project_id", "test-proj")
    cfg.setdefault("self_check", "off")
    return GsmBackend(config=GsmConfig(**cfg), token_provider=lambda: "fake-token", http=http)


# ---------------------------------------------------------------------------
# Contract suite
# ---------------------------------------------------------------------------


class TestGsmContract(ProtocolContract):
    @pytest.fixture
    def backend(self):
        return _backend(_router([(":access", (200, _access_body("v")))]))


def test_registry_has_gsm() -> None:
    assert "gsm" in BACKEND_REGISTRY
    backend_cls, config_cls = BACKEND_REGISTRY["gsm"]
    assert backend_cls.__name__ == "GsmBackend"
    assert config_cls.__name__ == "GsmConfig"


# ---------------------------------------------------------------------------
# Config — secure-by-default schema
# ---------------------------------------------------------------------------


def test_config_has_no_key_file_field() -> None:
    """The 'no downloadable key' invariant (ADR-0018 §2): a service-account
    key path cannot be wired through config — extra=forbid rejects it."""
    with pytest.raises(ValidationError):
        GsmConfig(project_id="myproj", service_account_key_path="/etc/key.json")  # type: ignore[call-arg]


def test_config_defaults_are_secure() -> None:
    # self_check defaults to deny, which REQUIRES a namespace to bound (F3):
    # a deny guard with nothing to bound would silently no-op.
    with pytest.raises(ValidationError):
        GsmConfig(project_id="myproj")
    cfg = GsmConfig(project_id="myproj", secret_prefix="avp-")
    assert cfg.self_check == "deny"
    assert cfg.reject_ambient_key is True
    assert cfg.version_alias == "latest"


def test_self_check_deny_requires_prefix() -> None:
    with pytest.raises(ValidationError, match="secret_prefix"):
        GsmConfig(project_id="myproj", self_check="deny")
    # warn / off do not require a prefix
    assert GsmConfig(project_id="myproj", self_check="warn").self_check == "warn"
    assert GsmConfig(project_id="myproj", self_check="off").self_check == "off"


# ---------------------------------------------------------------------------
# fetch — value resolution + error mapping
# ---------------------------------------------------------------------------


def test_fetch_returns_decoded_value() -> None:
    b = _backend(_router([(":access", (200, _access_body("sk-secret-123")))]))
    assert b.fetch("OPENAI_API_KEY").reveal() == "sk-secret-123"


def test_fetch_missing_secret_raises_not_found() -> None:
    b = _backend(_router([(":access", (404, {"error": {"message": "nope"}}))]))
    with pytest.raises(SecretNotFoundError):
        b.fetch("MISSING")


def test_fetch_denied_raises_auth_lost() -> None:
    b = _backend(_router([(":access", (403, {"error": {"status": "PERMISSION_DENIED"}}))]))
    with pytest.raises(BackendAuthLostError):
        b.fetch("FORBIDDEN")


def test_fetch_5xx_raises_unavailable() -> None:
    b = _backend(_router([(":access", (503, None))]))
    with pytest.raises(BackendUnavailableError):
        b.fetch("X")


def test_fetch_bad_base64_raises_unavailable_without_leaking() -> None:
    b = _backend(_router([(":access", (200, {"payload": {"data": "!!!not-base64!!!"}}))]))
    with pytest.raises(BackendUnavailableError):
        b.fetch("X")


# ---------------------------------------------------------------------------
# list_secret_names — prefix scoping + annotation cache
# ---------------------------------------------------------------------------


def _list_body(*entries: tuple[str, dict[str, str]]) -> dict[str, Any]:
    return {
        "secrets": [
            {"name": f"projects/test-proj/secrets/{sid}", "annotations": ann}
            for sid, ann in entries
        ]
    }


def test_list_scopes_to_prefix() -> None:
    body = _list_body(
        ("avp-OPENAI", {"avp-binding": "api.openai.com"}),
        ("other-team-DB", {}),
    )
    b = _backend(_router([("/secrets?", (200, body))]), secret_prefix="avp-")
    assert b.list_secret_names() == ["avp-OPENAI"]


def test_fetch_with_meta_serves_annotation_from_list_cache() -> None:
    body = _list_body(("avp-OPENAI", {"avp-binding": "api.openai.com"}))
    b = _backend(
        _router([("/secrets?", (200, body)), (":access", (200, _access_body("sk-1")))]),
        secret_prefix="avp-",
    )
    b.list_secret_names()  # populates the annotation cache
    value, note = b.fetch_with_meta("avp-OPENAI")
    assert value.reveal() == "sk-1"
    assert note == "api.openai.com"


def test_fetch_with_meta_falls_back_to_metadata_get() -> None:
    # No prior list() -> annotation comes from a metadata GET.
    b = _backend(
        _router(
            [
                (":access", (200, _access_body("sk-2"))),
                ("/secrets/", (200, {"annotations": {"avp-binding": "api.internal.acme.com"}})),
            ]
        )
    )
    value, note = b.fetch_with_meta("SOME_KEY")
    assert value.reveal() == "sk-2"
    assert note == "api.internal.acme.com"


def test_fetch_with_meta_blank_annotation_is_none() -> None:
    b = _backend(
        _router(
            [
                (":access", (200, _access_body("sk-3"))),
                ("/secrets/", (200, {"annotations": {"avp-binding": "   "}})),
            ]
        )
    )
    _value, note = b.fetch_with_meta("SOME_KEY")
    assert note is None


# ---------------------------------------------------------------------------
# self_check — deny-if-broad boot guard (ADR-0018 §6)
# ---------------------------------------------------------------------------


def test_self_check_deny_refuses_when_identity_sees_out_of_prefix_secrets() -> None:
    body = _list_body(("avp-A", {}), ("prod-db-root-password", {}))
    b = _backend(
        _router([("/secrets?", (200, body))]),
        secret_prefix="avp-",
        self_check="deny",
    )
    with pytest.raises(BackendUnavailableError, match="broader Secret Manager access"):
        b.list_secret_names()


def test_self_check_warn_continues(caplog) -> None:
    body = _list_body(("avp-A", {"avp-binding": "api.openai.com"}), ("prod-secret", {}))
    b = _backend(
        _router([("/secrets?", (200, body))]),
        secret_prefix="avp-",
        self_check="warn",
    )
    names = b.list_secret_names()
    # scoped result still filtered to prefix; warn did not raise
    assert names == ["avp-A"]


def test_self_check_passes_when_listing_is_denied() -> None:
    # A tightly-scoped identity cannot enumerate others -> 403 on the broad
    # list -> self_check treats that as scoped/OK, then the real fetch works.
    b = _backend(
        _router([("/secrets?", (403, {})), (":access", (200, _access_body("v")))]),
        secret_prefix="avp-",
        self_check="deny",
    )
    assert b.fetch("avp-x").reveal() == "v"


def test_self_check_off_skips_probe() -> None:
    # self_check=off -> no list on first fetch even without a list route.
    b = _backend(_router([(":access", (200, _access_body("v")))]), self_check="off")
    assert b.fetch("anything").reveal() == "v"


def test_self_check_deny_fails_closed_on_transient_list_error() -> None:
    # A 5xx on the broad list is inconclusive (NOT "denied => scoped"); deny
    # mode must refuse to start rather than fail open (F2).
    b = _backend(
        _router([("/secrets?", (503, None))]),
        secret_prefix="avp-",
        self_check="deny",
    )
    with pytest.raises(BackendUnavailableError, match="refusing to start"):
        b.fetch("avp-x")


def test_self_check_warn_continues_on_transient() -> None:
    b = _backend(
        _router([("/secrets?", (503, None)), (":access", (200, _access_body("v")))]),
        secret_prefix="avp-",
        self_check="warn",
    )
    assert b.fetch("avp-x").reveal() == "v"


def test_list_secret_notes_reads_annotations_without_fetching_values() -> None:
    # Notes activation must read the binding annotation from the free list
    # metadata, never pull the plaintext value (F5).
    body = _list_body(
        ("avp-a", {"avp-binding": "api.openai.com"}),
        ("avp-b", {}),
    )

    def http(method: str, url: str, headers: dict[str, str], body_: bytes | None):
        if ":access" in url:
            raise AssertionError("list_secret_notes must not fetch secret values")
        if "/secrets?" in url:
            return (200, body)
        return (404, None)

    b = GsmBackend(
        config=GsmConfig(project_id="myproj", secret_prefix="avp-", self_check="off"),
        token_provider=lambda: "t",
        http=http,
    )
    assert b.list_secret_notes() == {"avp-a": "api.openai.com", "avp-b": None}


def test_is_service_account_key_false_without_google_auth() -> None:
    # Dep-not-installed path: helper must not crash, just return False.
    assert _is_service_account_key(object()) is False


# ---------------------------------------------------------------------------
# Oracle audit hardening (C2/C4/C6/C8/C9)
# ---------------------------------------------------------------------------


def test_self_check_deny_fails_closed_on_401() -> None:
    # A 401 (broken/expired auth) is NOT proof of narrow scope; deny must
    # refuse, not treat it as "enumeration denied → scoped" (C2).
    b = _backend(_router([("/secrets?", (401, {}))]), secret_prefix="avp-", self_check="deny")
    with pytest.raises(BackendUnavailableError, match="refusing to start"):
        b.fetch("avp-x")


def test_token_acquisition_failure_maps_to_protocol_exception() -> None:
    # A raising token provider must surface as BackendUnavailableError, not a
    # raw exception escaping the SecretsBackend protocol (C4).
    def boom() -> str:
        raise RuntimeError("network down during refresh")

    b = GsmBackend(
        config=GsmConfig(project_id="myproj", self_check="off"),
        token_provider=boom,
        http=_router([(":access", (200, _access_body("v")))]),
    )
    with pytest.raises(BackendUnavailableError, match="token acquisition failed"):
        b.fetch("x")


def test_fetch_base64_with_stray_char_rejected_with_validate() -> None:
    # "YWJj" is valid ("abc"); the stray "!" would be silently dropped without
    # validate=True. With it, the mangled payload is rejected, not accepted (C6).
    b = _backend(_router([(":access", (200, {"payload": {"data": "YWJj!"}}))]))
    with pytest.raises(BackendUnavailableError):
        b.fetch("x")


def test_config_rejects_unsafe_project_id() -> None:
    # project_id lands in every authenticated URL; reject anything that could
    # redirect the request (C8).
    for bad in ["p", "proj/../etc", "proj?x=1", "MyProj", "proj id"]:
        with pytest.raises(ValidationError):
            GsmConfig(project_id=bad, self_check="off")
    assert GsmConfig(project_id="my-proj-1", self_check="off").project_id == "my-proj-1"
    assert GsmConfig(project_id="123456789012", self_check="off").project_id == "123456789012"


def test_config_required_even_with_token_provider() -> None:
    # Injecting token_provider/http does not substitute for config (C9) — it
    # layers on top; without config first use raises a protocol-shaped error.
    b = GsmBackend(
        token_provider=lambda: "t", http=_router([(":access", (200, _access_body("v")))])
    )
    with pytest.raises(NotImplementedError, match="requires a GsmConfig"):
        b.fetch("x")


def test_fetch_out_of_prefix_refused_at_access_boundary() -> None:
    # Defence-in-depth: a name outside secret_prefix is refused BEFORE any GSM
    # call, even if the transport would have succeeded (Oracle-2 C2).
    def http(method, url, headers, body):  # noqa: ARG001
        raise AssertionError("must not reach GSM for an out-of-prefix name")

    b = GsmBackend(
        config=GsmConfig(project_id="myproj", secret_prefix="avp-", self_check="off"),
        token_provider=lambda: "t",
        http=http,
    )
    with pytest.raises(SecretNotFoundError):
        b.fetch("other-team-KEY")


def test_malformed_annotation_does_not_crash() -> None:
    # A non-dict annotations field must not raise AttributeError (Oracle-2 C6).
    b = _backend(
        _router([(":access", (200, _access_body("v"))), ("/secrets/", (200, {"annotations": "x"}))])
    )
    value, note = b.fetch_with_meta("SOME_KEY")
    assert value.reveal() == "v"
    assert note is None


def test_malformed_list_entry_skipped() -> None:
    body = {
        "secrets": [
            "not-a-dict",
            {
                "name": "projects/test-proj/secrets/avp-a",
                "annotations": {"avp-binding": "api.openai.com"},
            },
        ]
    }
    b = _backend(_router([("/secrets?", (200, body))]), secret_prefix="avp-")
    assert b.list_secret_names() == ["avp-a"]


def test_self_check_deny_fails_closed_on_404_list() -> None:
    # A 404 on the broad list (wrong project_id) is a config error, not a scope
    # signal — deny must refuse to start, not proceed (Grok A4).
    b = _backend(
        _router([("/secrets?", (404, {"error": {"message": "no project"}}))]),
        secret_prefix="avp-",
        self_check="deny",
    )
    with pytest.raises(BackendUnavailableError, match="refusing to start"):
        b.fetch("avp-x")


def test_self_check_deny_on_project_wide_access() -> None:
    # Enumeration is scoped (403 on list), but the identity holds project-wide
    # secretmanager.versions.access — the access-probe catches it and deny
    # refuses (Grok A1 / access-breadth probe).
    b = _backend(
        _router(
            [
                ("/secrets?", (403, {})),
                (":testIamPermissions", (200, {"permissions": ["secretmanager.versions.access"]})),
            ]
        ),
        secret_prefix="avp-",
        self_check="deny",
    )
    with pytest.raises(BackendUnavailableError, match="project-wide"):
        b.list_secret_names()


def test_self_check_passes_when_access_probe_shows_scoped() -> None:
    # List denied AND the access-probe reports no project-wide access → scoped
    # on both axes → the backend starts and fetch works.
    b = _backend(
        _router(
            [
                ("/secrets?", (403, {})),
                (":testIamPermissions", (200, {"permissions": []})),
                (":access", (200, _access_body("v"))),
            ]
        ),
        secret_prefix="avp-",
        self_check="deny",
    )
    assert b.fetch("avp-x").reveal() == "v"


# ---------------------------------------------------------------------------
# North-Star acceptance: a secret with ONLY a hostname annotation, no file
# entry, produces a working host binding under gsm_notes mode.
# ---------------------------------------------------------------------------


class _FakeListableBackend:
    """Minimal notes-aware backend for the runtime-bindings acceptance test."""

    NOTES_SOURCE_LABEL = "gsm_notes"

    def __init__(self, data: dict[str, tuple[str, str | None]]) -> None:
        self._data = data  # name -> (value, note)

    def fetch(self, name: str, ctx: Any = None) -> Secret:
        return Secret(self._data[name][0])

    def fetch_with_meta(self, name: str, ctx: Any = None) -> tuple[Secret, str | None]:
        return self._data[name]

    def list_secret_names(self) -> list[str]:
        return list(self._data)


def test_gsm_notes_bare_hostname_needs_no_file_entry() -> None:
    """Radek's North-Star: add a secret to GSM, tag it `avp-binding:
    api.openai.com`, nothing in bindings.yaml — and it binds."""
    backend = _FakeListableBackend(
        {"OPENAI_API_KEY": ("sk-live-value", "# avp-binding\napi.openai.com")}
    )
    resolved = resolve_runtime_bindings(
        backend=backend,
        binding_source="gsm_notes",
        install_salt=b"\x00" * 32,
        file_config=None,
    )
    assert "OPENAI_API_KEY" in resolved.specs
    spec, source, _companion = resolved.specs["OPENAI_API_KEY"]
    assert source == "gsm_notes"
    assert spec.binding_source == "gsm_notes"
    assert spec.bindings[0].host == "api.openai.com"


def test_gsm_notes_secret_without_annotation_is_unbound() -> None:
    """No avp-binding annotation -> NoBinding -> never injected (fail closed)."""
    backend = _FakeListableBackend({"STRAY_KEY": ("value", None)})
    resolved = resolve_runtime_bindings(
        backend=backend,
        binding_source="gsm_notes",
        install_salt=b"\x00" * 32,
        file_config=None,
    )
    assert "STRAY_KEY" not in resolved.specs
    assert "STRAY_KEY" in resolved.no_binding


# ---------------------------------------------------------------------------
# self_check — read-only enforcement (AVP must not hold write/admin)
# ---------------------------------------------------------------------------


def test_self_check_deny_refuses_when_identity_holds_write() -> None:
    # Enumeration is scoped (403), but testIamPermissions shows the identity
    # holds a write/admin permission -> AVP is a read-only broker, refuse start.
    b = _backend(
        _router(
            [
                ("/secrets?", (403, {})),
                (":testIamPermissions", (200, {"permissions": ["secretmanager.secrets.update"]})),
            ]
        ),
        secret_prefix="avp-",
        self_check="deny",
    )
    with pytest.raises(BackendUnavailableError, match="write/admin"):
        b.fetch("avp-x")


def test_self_check_write_probe_inconclusive_does_not_block() -> None:
    # A denied/disabled testIamPermissions probe is inconclusive -> must NOT
    # fail-open into a hard block; the fetch still works (defence-in-depth only).
    b = _backend(
        _router(
            [
                ("/secrets?", (403, {})),
                (":testIamPermissions", (403, {})),
                (":access", (200, _access_body("v"))),
            ]
        ),
        secret_prefix="avp-",
        self_check="deny",
    )
    assert b.fetch("avp-x").reveal() == "v"


def test_diagnose_flags_project_write_access() -> None:
    b = _backend(
        _router(
            [
                ("/secrets?", (200, _list_body(("avp-A", {})))),
                (":testIamPermissions", (200, {"permissions": ["secretmanager.versions.add"]})),
            ]
        ),
        secret_prefix="avp-",
    )
    rows = b.diagnose()
    assert any(check == "write" and status == "WARN" for status, check, _ in rows)
