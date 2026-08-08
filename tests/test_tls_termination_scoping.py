"""ADR-0026: TLS termination scoped to bound hosts; opaque passthrough for the rest.

The `tls_clienthello` hook decides, per connection at handshake time, whether AVP
MITM-terminates (bound host) or tunnels the connection un-decrypted (unbound host,
`tls_termination: bound`). Passthrough is logged via a `tls_passthrough` audit event
(destination host only — the connection was never decrypted, so no secret to leak).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from kow.addon import AgentVaultProxyAddon
from kow.audit import AuditWriter
from kow.config import Config

_FOO_PH = "foo_PLACEHOLDER_01HXY1234567890"


def _config(tls_termination: str, audit_path: Path) -> Config:
    return Config.model_validate(
        {
            "version": 1,
            "secrets": {
                "FOO": {
                    "placeholder": _FOO_PH,
                    "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
                    "bindings": [{"host": "api.example.com"}],
                }
            },
            "audit": {"path": str(audit_path)},
            "tls_termination": tls_termination,
        }
    )


def _addon(tls_termination: str, tmp_path: Path) -> tuple[AgentVaultProxyAddon, Path]:
    audit_path = tmp_path / "audit.jsonl"
    addon = AgentVaultProxyAddon()
    addon.config = _config(tls_termination, audit_path)
    addon.audit = AuditWriter(path=str(audit_path), fail_on_unwritable=True)
    return addon, audit_path


def _clienthello(sni: str | None = None, server_host: str | None = None) -> SimpleNamespace:
    # Minimal stand-in for mitmproxy tls.ClientHelloData — the hook only touches
    # .client_hello.sni, .context.server.address and sets .ignore_connection.
    return SimpleNamespace(
        client_hello=SimpleNamespace(sni=sni),
        context=SimpleNamespace(
            server=SimpleNamespace(address=(server_host, 443) if server_host else None)
        ),
        ignore_connection=False,
        establish_server_tls_first=False,
    )


def _last_audit(path: Path) -> dict:
    lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
    return json.loads(lines[-1])


def test_schema_default_is_bound() -> None:
    c = Config.model_validate(
        {
            "version": 1,
            "secrets": {
                "FOO": {
                    "placeholder": _FOO_PH,
                    "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
                    "bindings": [{"host": "api.example.com"}],
                }
            },
            "audit": {"path": "/tmp/x.jsonl"},
        }
    )
    assert c.tls_termination == "bound"


def test_unbound_host_is_passed_through_and_audited(tmp_path: Path) -> None:
    addon, audit_path = _addon("bound", tmp_path)
    ch = _clienthello(sni="exfil.attacker.example")
    addon.tls_clienthello(ch)
    assert ch.ignore_connection is True  # opaque tunnel — AVP never decrypts it
    ev = _last_audit(audit_path)
    assert ev["type"] == "tls_passthrough"
    assert ev["reason"] == "unbound_destination"
    assert ev["destination"]["host"] == "exfil.attacker.example"
    # metadata only — never a secret value (connection was never decrypted)
    assert set(ev) <= {"type", "reason", "destination", "ts", "v"}


def test_bound_host_is_terminated(tmp_path: Path) -> None:
    addon, audit_path = _addon("bound", tmp_path)
    ch = _clienthello(sni="api.example.com")
    addon.tls_clienthello(ch)
    assert ch.ignore_connection is False  # terminate + inject (unchanged path)
    assert not audit_path.exists() or audit_path.read_text().strip() == ""


def test_wildcard_bound_host_is_terminated(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    addon = AgentVaultProxyAddon()
    addon.config = Config.model_validate(
        {
            "version": 1,
            "allow_wildcard_hosts": True,
            "secrets": {
                "FOO": {
                    "placeholder": _FOO_PH,
                    "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
                    "bindings": [{"host": "*.hf.co"}],
                }
            },
            "audit": {"path": str(audit_path)},
        }
    )
    addon.audit = AuditWriter(path=str(audit_path), fail_on_unwritable=True)
    ch = _clienthello(sni="cdn-lfs.hf.co")
    addon.tls_clienthello(ch)
    assert ch.ignore_connection is False  # wildcard match -> terminate


def test_all_mode_terminates_even_unbound(tmp_path: Path) -> None:
    addon, audit_path = _addon("all", tmp_path)
    ch = _clienthello(sni="exfil.attacker.example")
    addon.tls_clienthello(ch)
    assert ch.ignore_connection is False  # full termination restored
    assert not audit_path.exists() or audit_path.read_text().strip() == ""


def test_no_sni_falls_back_to_server_address(tmp_path: Path) -> None:
    addon, _ = _addon("bound", tmp_path)
    ch = _clienthello(sni=None, server_host="api.example.com")
    addon.tls_clienthello(ch)
    assert ch.ignore_connection is False  # resolved bound via CONNECT host fallback


def test_no_sni_and_unbound_fallback_passes_through(tmp_path: Path) -> None:
    addon, audit_path = _addon("bound", tmp_path)
    ch = _clienthello(sni=None, server_host="other.example.net")
    addon.tls_clienthello(ch)
    assert ch.ignore_connection is True
    assert _last_audit(audit_path)["destination"]["host"] == "other.example.net"


def test_config_none_is_noop() -> None:
    addon = AgentVaultProxyAddon()  # config stays None (pre-configure)
    ch = _clienthello(sni="whatever.example.com")
    addon.tls_clienthello(ch)  # must not raise
    assert ch.ignore_connection is False
