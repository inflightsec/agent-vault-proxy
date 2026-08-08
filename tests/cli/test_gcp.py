"""`avp gcp-setup` + `avp doctor --probe-gcp` (ADR-0018 §6 operator tooling)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kow.backends.gsm import GsmBackend, GsmConfig
from kow.cli.doctor_gcp import run_gcp_probe
from kow.cli.gcp_setup import run_gcp_setup
from kow.cli.main import main

# ── gcp-setup ────────────────────────────────────────────────────────────────


def test_gcp_setup_refuses_broad_scope(capsys) -> None:
    rc = run_gcp_setup(
        project="myproj", member="serviceAccount:x@myproj.iam", secrets=["s"], scope="project"
    )
    assert rc == 2
    assert "refusing scope" in capsys.readouterr().err


def test_gcp_setup_requires_secrets() -> None:
    assert run_gcp_setup(project="myproj", member="serviceAccount:x", secrets=[]) == 2


def test_gcp_setup_dry_run_is_per_secret_and_never_project_level(capsys) -> None:
    rc = run_gcp_setup(
        project="myproj",
        member="serviceAccount:avp@myproj.iam",
        secrets=["alpha", "beta"],
        dry_run=True,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert out.count("secrets add-iam-policy-binding") == 2  # one PER SECRET
    assert "roles/secretmanager.secretAccessor" in out
    assert "--project=myproj" in out
    assert "projects add-iam-policy-binding" not in out  # never a project-level bind


def test_main_parses_gcp_setup_dry_run(capsys) -> None:
    rc = main(
        [
            "gcp-setup",
            "--project",
            "myproj",
            "--member",
            "serviceAccount:x@myproj.iam",
            "--secret",
            "a",
            "--dry-run",
        ]
    )
    assert rc == 0
    assert "add-iam-policy-binding" in capsys.readouterr().out


# ── doctor --probe-gcp / diagnose() (injected transport, no live GCP) ─────────


def _router(routes: list[tuple[str, tuple[int, dict[str, Any] | None]]]):
    def http(method: str, url: str, headers: dict[str, str], body: bytes | None):
        for needle, resp in routes:
            if needle in url:
                return resp
        return (404, {"error": {}})

    return http


def _backend(http, **cfg) -> GsmBackend:
    cfg.setdefault("project_id", "myproj")
    cfg.setdefault("self_check", "off")
    return GsmBackend(config=GsmConfig(**cfg), token_provider=lambda: "t", http=http)


def test_diagnose_reports_scoped_identity() -> None:
    body = {"secrets": [{"name": "projects/myproj/secrets/avp-a", "annotations": {}}]}
    b = _backend(
        _router([("/secrets?", (200, body)), (":testIamPermissions", (200, {"permissions": []}))]),
        secret_prefix="avp-",
    )
    d = {check: status for status, check, _msg in b.diagnose()}
    assert d["auth"] == "OK"
    assert d["enumeration"] == "OK"
    assert d["access"] == "OK"


def test_diagnose_flags_project_wide_access_without_raising() -> None:
    # self_check(deny) would REFUSE here; diagnose only reports.
    b = _backend(
        _router(
            [
                ("/secrets?", (403, {})),
                (":testIamPermissions", (200, {"permissions": ["secretmanager.versions.access"]})),
            ]
        ),
        secret_prefix="avp-",
    )
    d = {check: status for status, check, _msg in b.diagnose()}
    assert d["access"] == "WARN"


def test_probe_gcp_rejects_non_gsm_backend(tmp_path: Path, capsys) -> None:
    p = tmp_path / "bindings.yaml"
    p.write_text(
        "version: 1\nsecrets: {}\nbinding_source: file\n"
        f"audit:\n  path: {tmp_path / 'audit.jsonl'}\n"
        "backend:\n  type: static\n  config:\n    type: static\n"
        f"    path: {tmp_path / 'secrets.yaml'}\n"
    )
    assert run_gcp_probe(config_path=str(p)) is True
    assert "not 'gsm'" in capsys.readouterr().err


def test_probe_gcp_warns_on_annotation_trust_when_notes(tmp_path, capsys, monkeypatch) -> None:
    # When bindings come from annotations (notes/both), the probe must warn
    # that annotation-write == binding-control (confused-deputy trust boundary).
    salt = tmp_path / "salt"
    salt.write_bytes(b"\x11" * 32)
    salt.chmod(0o600)
    p = tmp_path / "bindings.yaml"
    p.write_text(
        "version: 1\n"
        "secrets: {}\n"
        "binding_source: both\n"
        f"install_salt_path: {salt}\n"
        f"audit:\n  path: {tmp_path / 'a.jsonl'}\n"
        "backend:\n"
        "  type: gsm\n"
        "  config:\n"
        "    type: gsm\n"
        "    project_id: myproj\n"
        "    secret_prefix: avp-\n"
        '    self_check: "off"\n'
    )

    class _Stub:
        def diagnose(self):
            return [("OK", "auth", "ok")]

    monkeypatch.setattr("kow.cli.doctor_gcp.build_backend", lambda cfg: (_Stub(), None))
    run_gcp_probe(config_path=str(p))
    assert "annotation-trust" in capsys.readouterr().out


def test_probe_gcp_no_annotation_warn_in_file_mode(tmp_path, capsys, monkeypatch) -> None:
    p = tmp_path / "bindings.yaml"
    p.write_text(
        "version: 1\n"
        "secrets: {}\n"
        "binding_source: file\n"
        f"audit:\n  path: {tmp_path / 'a.jsonl'}\n"
        "backend:\n"
        "  type: gsm\n"
        "  config:\n"
        "    type: gsm\n"
        "    project_id: myproj\n"
        "    secret_prefix: avp-\n"
        '    self_check: "off"\n'
    )

    class _Stub:
        def diagnose(self):
            return [("OK", "auth", "ok")]

    monkeypatch.setattr("kow.cli.doctor_gcp.build_backend", lambda cfg: (_Stub(), None))
    run_gcp_probe(config_path=str(p))
    assert "annotation-trust" not in capsys.readouterr().out


def test_probe_gcp_annotation_trust_downgrades_with_allowlist(
    tmp_path, capsys, monkeypatch
) -> None:
    # ADR-0024: with notes_host_allowlist set, annotation-write can only
    # NARROW scope — the confused-deputy advisory downgrades WARN -> OK.
    salt = tmp_path / "salt"
    salt.write_bytes(b"\x11" * 32)
    salt.chmod(0o600)
    p = tmp_path / "bindings.yaml"
    p.write_text(
        "version: 1\n"
        "secrets: {}\n"
        "binding_source: both\n"
        'notes_host_allowlist: ["api.example.com"]\n'
        f"install_salt_path: {salt}\n"
        f"audit:\n  path: {tmp_path / 'a.jsonl'}\n"
        "backend:\n"
        "  type: gsm\n"
        "  config:\n"
        "    type: gsm\n"
        "    project_id: myproj\n"
        "    secret_prefix: avp-\n"
        '    self_check: "off"\n'
    )

    class _Stub:
        def diagnose(self):
            return [("OK", "auth", "ok")]

    monkeypatch.setattr("kow.cli.doctor_gcp.build_backend", lambda cfg: (_Stub(), None))
    run_gcp_probe(config_path=str(p))
    out = capsys.readouterr().out
    assert "annotations can only narrow scope" in out
    assert "WARN  annotation-trust" not in out
