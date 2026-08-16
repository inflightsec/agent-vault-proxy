"""secret_prefix boundary warning — advisory, never fatal by default."""

from __future__ import annotations

from pathlib import Path

import pytest

from kow._preflight import check_secret_prefix_boundary, run_preflight
from kow.config import load_config


def _config(tmp_path: Path, prefix: str | None, backend: str = "aws") -> object:
    block = (
        '  type: aws-secrets-manager\n  config:\n    region: "us-east-1"\n    self_check: "off"\n'
        if backend == "aws"
        else '  type: gsm\n  config:\n    project_id: "myproj"\n    self_check: "off"\n'
    )
    if prefix is not None:
        block += f'    secret_prefix: "{prefix}"\n'
    p = tmp_path / "b.yaml"
    p.write_text(f"""
version: 1
secrets:
  OPENAI_API_KEY:
    placeholder: "sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"
    inject:
      header: "Authorization"
      format: "Bearer {{OPENAI_API_KEY}}"
    bindings:
      - host: "api.openai.com"
backend:
{block}
audit:
  path: {tmp_path / "audit.jsonl"}
""")
    return load_config(p)


@pytest.mark.parametrize("prefix", ["app", "avp", "prod1"])
def test_separator_less_prefix_warns(tmp_path, prefix) -> None:
    msgs = check_secret_prefix_boundary(_config(tmp_path, prefix))
    assert len(msgs) == 1
    assert "WIDE SCOPE" in msgs[0]
    assert prefix in msgs[0]


@pytest.mark.parametrize("prefix", ["avp/", "avp-", "avp_", "avp.", "avp:"])
def test_separator_terminated_prefix_is_silent(tmp_path, prefix) -> None:
    assert check_secret_prefix_boundary(_config(tmp_path, prefix)) == []


def test_no_prefix_is_silent(tmp_path) -> None:
    assert check_secret_prefix_boundary(_config(tmp_path, None)) == []


def test_backend_without_secret_prefix_field_is_silent(tmp_path) -> None:
    """bws and static have no secret_prefix at all — must not crash."""
    p = tmp_path / "b.yaml"
    secrets = tmp_path / "s.yaml"
    secrets.write_text("secrets:\n  OPENAI_API_KEY: v\n")
    secrets.chmod(0o600)
    p.write_text(f"""
version: 1
secrets:
  OPENAI_API_KEY:
    placeholder: "sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"
    inject:
      header: "Authorization"
      format: "Bearer {{OPENAI_API_KEY}}"
    bindings:
      - host: "api.openai.com"
backend:
  type: static
  config:
    path: {secrets}
audit:
  path: {tmp_path / "audit.jsonl"}
""")
    assert check_secret_prefix_boundary(load_config(p)) == []


def test_gsm_backend_also_covered(tmp_path) -> None:
    assert len(check_secret_prefix_boundary(_config(tmp_path, "app", "gsm"))) == 1


def test_warning_is_advisory_not_fatal(tmp_path) -> None:
    """The whole point: a wide prefix must never stop the proxy starting."""
    cfg = _config(tmp_path, "app")
    assert cfg.preflight.fail_on_warning is False
    msgs = run_preflight(cfg)  # does not raise
    assert any("WIDE SCOPE" in m for m in msgs)
