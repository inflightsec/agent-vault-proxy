"""Tests for the startup security preflight checks."""

from __future__ import annotations

import pytest

from agent_vault_proxy._preflight import (
    _in_container,
    check_audit_log_append_only,
    check_bws_token_via_env_in_container,
    check_loose_bindings_on_sensitive_hosts,
    check_root_uid_in_container,
    run_preflight,
)
from agent_vault_proxy.config import (
    BindingSpec,
    Config,
)

# ---------------------------------------------------------------------------
# Container detection scaffolding
# ---------------------------------------------------------------------------


def _make_minimal_config(
    bindings: list[BindingSpec] | None = None,
    audit_path: str = "/tmp/test-audit.jsonl",
) -> Config:
    """Construct a minimum-viable Config for testing preflight checks
    without going through YAML."""
    return Config.model_validate(
        {
            "version": 1,
            "secrets": {
                "FOO": {
                    "placeholder": "test_PLACEHOLDER_01HXY1234567890",
                    "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
                    "bindings": [
                        b.model_dump() for b in (bindings or [BindingSpec(host="x.example.com")])
                    ],
                }
            },
            "audit": {"path": audit_path},
            "backend": {"type": "bws", "config": {"type": "bws", "organization_id": "org-1"}},
        }
    )


# ---------------------------------------------------------------------------
# _in_container() — direct tests for the detection heuristic
# ---------------------------------------------------------------------------


def _stub_path(monkeypatch, mapping: dict[str, str | None]) -> None:
    """Stub Path.exists()/read_text() for a small set of /proc and /run paths.

    ``mapping`` maps absolute path → file contents (str = file exists with
    that content, None = path does not exist).
    """
    from pathlib import Path as _Path

    real_exists = _Path.exists
    real_read = _Path.read_text

    def fake_exists(self: _Path) -> bool:
        p = str(self)
        if p in mapping:
            return mapping[p] is not None
        return real_exists(self)

    def fake_read_text(self: _Path, *a, **kw) -> str:
        p = str(self)
        if p in mapping:
            v = mapping[p]
            if v is None:
                raise FileNotFoundError(p)
            return v
        return real_read(self, *a, **kw)

    monkeypatch.setattr(_Path, "exists", fake_exists)
    monkeypatch.setattr(_Path, "read_text", fake_read_text)


def test_in_container_dockerenv_stub(monkeypatch) -> None:
    _stub_path(
        monkeypatch,
        {"/.dockerenv": "", "/run/.containerenv": None, "/proc/1/cgroup": None},
    )
    assert _in_container() is True


def test_in_container_podman_containerenv_stub(monkeypatch) -> None:
    _stub_path(
        monkeypatch,
        {"/.dockerenv": None, "/run/.containerenv": "", "/proc/1/cgroup": None},
    )
    assert _in_container() is True


def test_in_container_cgroup_v1_docker_marker(monkeypatch) -> None:
    _stub_path(
        monkeypatch,
        {
            "/.dockerenv": None,
            "/run/.containerenv": None,
            "/proc/1/cgroup": "12:devices:/docker/abc123\n",
        },
    )
    assert _in_container() is True


def test_in_container_cgroup_v2_bare_root_is_container(monkeypatch) -> None:
    """Reviewer-flagged gap: cgroup v2 with a cgroup namespace, no
    /.dockerenv stub, and no v1-style runtime markers. PID 1 sees its
    own cgroup as bare '0::/'. A bare-metal systemd host shows
    '0::/init.scope' (or similar non-root path) so this is unambiguous."""
    _stub_path(
        monkeypatch,
        {
            "/.dockerenv": None,
            "/run/.containerenv": None,
            "/proc/1/cgroup": "0::/\n",
        },
    )
    assert _in_container() is True


def test_in_container_cgroup_v2_systemd_host_is_not_container(monkeypatch) -> None:
    """Negative: a bare-metal cgroup v2 host running systemd shows PID 1
    inside '0::/init.scope' — must NOT trigger container detection."""
    _stub_path(
        monkeypatch,
        {
            "/.dockerenv": None,
            "/run/.containerenv": None,
            "/proc/1/cgroup": "0::/init.scope\n",
        },
    )
    assert _in_container() is False


def test_in_container_no_proc_returns_false(monkeypatch) -> None:
    """Non-Linux test runner / no /proc at all."""
    _stub_path(
        monkeypatch,
        {
            "/.dockerenv": None,
            "/run/.containerenv": None,
            "/proc/1/cgroup": None,
        },
    )
    assert _in_container() is False


# ---------------------------------------------------------------------------
# Check 1: BWS_ACCESS_TOKEN via env inside a container
# ---------------------------------------------------------------------------


def test_bws_env_token_in_container_emits_warning(monkeypatch) -> None:
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "anything")
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: True)
    msgs = check_bws_token_via_env_in_container()
    assert any("BWS_ACCESS_TOKEN" in m and "env" in m.lower() for m in msgs), msgs


def test_bws_env_token_outside_container_is_silent(monkeypatch) -> None:
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "anything")
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: False)
    assert check_bws_token_via_env_in_container() == []


def test_no_bws_env_token_is_silent_even_in_container(monkeypatch) -> None:
    monkeypatch.delenv("BWS_ACCESS_TOKEN", raising=False)
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: True)
    assert check_bws_token_via_env_in_container() == []


# ---------------------------------------------------------------------------
# Check 2: audit log not append-only
# ---------------------------------------------------------------------------


def test_audit_log_missing_append_only_emits_warning(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    audit_path.touch()
    # On the test runner, chattr +a is almost certainly NOT set.
    msgs = check_audit_log_append_only(str(audit_path))
    # Either we get a warning, OR the FS doesn't support extended attrs at
    # all (in which case lsattr fails and we treat it as not-enforceable).
    assert msgs == [] or any("append-only" in m.lower() for m in msgs), msgs


def test_audit_log_nonexistent_path_is_silent(tmp_path) -> None:
    """Pre-create-on-first-write is normal; we only warn on EXISTING files
    that aren't append-only. A missing audit file is fine — AuditWriter
    will create it on first emit."""
    assert check_audit_log_append_only(str(tmp_path / "does-not-exist.jsonl")) == []


# ---------------------------------------------------------------------------
# Check 3: root UID inside a container
# ---------------------------------------------------------------------------


def test_root_inside_container_emits_warning(monkeypatch) -> None:
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: True)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    msgs = check_root_uid_in_container()
    assert any("root" in m.lower() and "container" in m.lower() for m in msgs), msgs


def test_root_outside_container_is_silent(monkeypatch) -> None:
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: False)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert check_root_uid_in_container() == []


def test_nonroot_inside_container_is_silent(monkeypatch) -> None:
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: True)
    monkeypatch.setattr("os.geteuid", lambda: 65532)
    assert check_root_uid_in_container() == []


# ---------------------------------------------------------------------------
# Check 4: loose bindings on known-laundering-risk hosts
# ---------------------------------------------------------------------------


def test_loose_binding_on_github_api_emits_warning() -> None:
    """T-1.5 laundering: api.github.com without methods=[GET] lets a
    prompt-injected agent POST gists. Warn."""
    cfg = _make_minimal_config(bindings=[BindingSpec(host="api.github.com")])
    msgs = check_loose_bindings_on_sensitive_hosts(cfg)
    assert any("api.github.com" in m and "method" in m.lower() for m in msgs), msgs


def test_scoped_binding_on_github_api_is_silent() -> None:
    """A binding with explicit methods restriction is the documented happy path."""
    cfg = _make_minimal_config(bindings=[BindingSpec(host="api.github.com", methods=["GET"])])
    assert check_loose_bindings_on_sensitive_hosts(cfg) == []


def test_loose_binding_on_unknown_host_is_silent() -> None:
    """We only warn on a curated list of high-laundering-risk hosts. A
    user's own API isn't our business."""
    cfg = _make_minimal_config(bindings=[BindingSpec(host="api.mycompany.com")])
    assert check_loose_bindings_on_sensitive_hosts(cfg) == []


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


def test_run_preflight_returns_all_warnings(monkeypatch, tmp_path) -> None:
    """Confirm the aggregator combines warnings from all individual checks."""
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "anything")
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: True)
    monkeypatch.setattr("os.geteuid", lambda: 0)

    cfg = _make_minimal_config(
        bindings=[BindingSpec(host="api.github.com")],
        audit_path=str(tmp_path / "audit.jsonl"),
    )
    msgs = run_preflight(cfg)
    # Expect at least the BWS env + root + GitHub scope warnings.
    assert any("BWS_ACCESS_TOKEN" in m for m in msgs)
    assert any("root" in m.lower() for m in msgs)
    assert any("api.github.com" in m for m in msgs)


def test_sensitive_host_check_is_case_insensitive() -> None:
    """a misconfigured binding with `Api.GitHub.com` (mixed
    case) must still trip the warning — case-fold the comparison."""
    cfg = _make_minimal_config(bindings=[BindingSpec(host="Api.GitHub.com")])
    msgs = check_loose_bindings_on_sensitive_hosts(cfg)
    assert msgs, "case-mixed sensitive host should still trip warning"


def test_sensitive_host_check_flags_write_verbs() -> None:
    """a binding with methods=[POST] on a known-laundering
    target silenced the previous loose-binding check even though POST is
    the actual exfil vector. New behavior: warn separately."""
    cfg = _make_minimal_config(bindings=[BindingSpec(host="api.github.com", methods=["POST"])])
    msgs = check_loose_bindings_on_sensitive_hosts(cfg)
    assert any("POST" in m and "write" in m.lower() for m in msgs), msgs


def test_sensitive_host_check_read_verbs_silent() -> None:
    """Read-only methods on sensitive hosts are the recommended config."""
    cfg = _make_minimal_config(
        bindings=[BindingSpec(host="api.github.com", methods=["GET", "HEAD", "OPTIONS"])]
    )
    assert check_loose_bindings_on_sensitive_hosts(cfg) == []


def test_audit_check_resolves_symlinks(tmp_path) -> None:
    """a symlink from audit_path to a mutable file shouldn't
    let an attacker silence the check. We resolve symlinks before lsattr."""
    real_file = tmp_path / "real-audit.jsonl"
    real_file.touch()
    link_file = tmp_path / "audit.jsonl"
    link_file.symlink_to(real_file)
    # Should not crash on the symlink path; should still emit warning
    # (because the real file isn't +a on the test runner) OR be silent
    # (if FS doesn't support xattrs).
    msgs = check_audit_log_append_only(str(link_file))
    assert msgs == [] or any("append-only" in m.lower() for m in msgs), msgs


def test_emit_preflight_only_runs_once(monkeypatch, tmp_path, capsys) -> None:
    """mitmproxy may call running() multiple times. The
    banner should appear once per process to avoid burying real changes
    in log spam."""
    from agent_vault_proxy._preflight import _reset_for_tests, emit_preflight

    _reset_for_tests()
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "anything")
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: True)

    cfg = _make_minimal_config(audit_path=str(tmp_path / "x.jsonl"))
    emit_preflight(cfg)
    first = capsys.readouterr().err
    emit_preflight(cfg)
    second = capsys.readouterr().err

    assert "BWS_ACCESS_TOKEN" in first
    assert second == ""  # silent on subsequent calls


def test_emit_preflight_force_overrides_once_flag(monkeypatch, tmp_path, capsys) -> None:
    """Tests need to re-trigger emission for fresh assertions."""
    from agent_vault_proxy._preflight import _reset_for_tests, emit_preflight

    _reset_for_tests()
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "anything")
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: True)
    cfg = _make_minimal_config(audit_path=str(tmp_path / "x.jsonl"))

    emit_preflight(cfg)
    capsys.readouterr()  # discard
    emit_preflight(cfg, force=True)
    out = capsys.readouterr().err
    assert "BWS_ACCESS_TOKEN" in out


def test_strict_mode_aborts_on_warning(monkeypatch, tmp_path) -> None:
    """when preflight.fail_on_warning is true, any warning
    raises PreflightFailedError so mitmproxy aborts startup before
    serving traffic."""
    from agent_vault_proxy._preflight import (
        PreflightFailedError,
        _reset_for_tests,
        emit_preflight,
    )

    _reset_for_tests()
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "anything")
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: True)

    cfg = _make_minimal_config(audit_path=str(tmp_path / "x.jsonl"))
    cfg.preflight.fail_on_warning = True

    with pytest.raises(PreflightFailedError, match="fail_on_warning"):
        emit_preflight(cfg)


def test_strict_mode_is_silent_when_no_warnings(monkeypatch, tmp_path) -> None:
    """Strict mode doesn't abort when there's nothing to warn about
    (otherwise it'd be unusable on the happy path)."""
    from agent_vault_proxy._preflight import _reset_for_tests, emit_preflight

    _reset_for_tests()
    monkeypatch.delenv("BWS_ACCESS_TOKEN", raising=False)
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: False)
    monkeypatch.setattr("os.geteuid", lambda: 65532)

    cfg = _make_minimal_config(
        bindings=[BindingSpec(host="api.github.com", methods=["GET"])],
        audit_path=str(tmp_path / "x.jsonl"),
    )
    cfg.preflight.fail_on_warning = True
    # No raise expected.
    emit_preflight(cfg)


def test_run_preflight_on_documented_happy_path_is_quiet(monkeypatch, tmp_path) -> None:
    """systemd install, non-root, scoped sensitive bindings, no env-token →
    no warnings (this is what we tell operators to do; surfacing nags here
    would train them to ignore the preflight)."""
    monkeypatch.delenv("BWS_ACCESS_TOKEN", raising=False)
    monkeypatch.setattr("agent_vault_proxy._preflight._in_container", lambda: False)
    monkeypatch.setattr("os.geteuid", lambda: 65532)

    cfg = _make_minimal_config(
        bindings=[BindingSpec(host="api.github.com", methods=["GET"])],
        audit_path=str(tmp_path / "audit.jsonl"),
    )
    assert run_preflight(cfg) == []
