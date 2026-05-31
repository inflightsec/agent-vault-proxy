from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_vault_proxy.config import Config, load_config

EXAMPLE_PATH = Path(__file__).parent.parent / "bindings.example.yaml"

# Test placeholders: ≥ 24 chars, contain PLACEHOLDER marker, disjoint.
_FOO_PH = "foo_PLACEHOLDER_01HXY1234567890"
_BAR_PH = "bar_PLACEHOLDER_01HXY1234567890"


def test_example_yaml_validates() -> None:
    config = load_config(EXAMPLE_PATH)
    assert config.version == 1
    assert "ANTHROPIC_API_KEY" in config.secrets


def test_unmatched_destination_policy_code_default_is_forward_unmodified() -> None:
    """The Config schema default stays `forward_unmodified` for backward
    compatibility — the proxy is a credential broker by design, not a
    firewall. The example file is allowed to opt into the stricter
    `deny` posture; this test pins the SCHEMA default."""
    minimal: dict = {
        "version": 1,
        "secrets": {
            "FOO": {
                "placeholder": _FOO_PH,
                "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                "bindings": [{"host": "api.example.com"}],
            }
        },
        "audit": {"path": "/tmp/x.jsonl"},
    }
    config = Config.model_validate(minimal)
    assert config.unmatched_destination_policy == "forward_unmodified"


def test_example_file_opts_into_deny_for_hardened_default() -> None:
    """The example config opts into `deny` so a new operator copying it
    gets fail-closed unbound-destination behavior by default."""
    config = load_config(EXAMPLE_PATH)
    assert config.unmatched_destination_policy == "deny"


def test_empty_bindings_rejected() -> None:
    with pytest.raises(ValidationError, match="empty bindings"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                        "bindings": [],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_overbroad_wildcard_rejected() -> None:
    with pytest.raises(ValidationError, match="too broad"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                        "bindings": [{"host": "*.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_mixed_case_host_is_lowercased_with_warning(caplog) -> None:
    """DNS is case-insensitive; binding hosts written in mixed case
    (e.g., a vendor doc paste) get normalised at config-load and the
    operator gets a visible log warning. Silent rewrites lose audit value."""
    import logging

    with caplog.at_level(logging.WARNING, logger="agent_vault_proxy.config"):
        cfg = Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                        "bindings": [{"host": "API.OpenAI.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )
    assert cfg.secrets["FOO"].bindings[0].host == "api.openai.com"
    assert any("uppercase" in r.message for r in caplog.records)


def test_lowercase_host_does_not_warn(caplog) -> None:
    import logging

    with caplog.at_level(logging.WARNING, logger="agent_vault_proxy.config"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                        "bindings": [{"host": "api.openai.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )
    assert not any("uppercase" in r.message for r in caplog.records)


def _minimal_secret(extra_binding: dict) -> dict:
    return {
        "version": 1,
        "secrets": {
            "FOO": {
                "placeholder": _FOO_PH,
                "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                "bindings": [{"host": "api.example.com", **extra_binding}],
            }
        },
        "audit": {"path": "/tmp/x.jsonl"},
    }


# ---------------------------------------------------------------------------
# Strict-models: extra fields rejected
# ---------------------------------------------------------------------------


def test_binding_unknown_field_rejected() -> None:
    """A `method:` typo for `methods:` would otherwise produce a binding
    with no method scope, silently widening the credential's authority."""
    with pytest.raises(ValidationError, match="[Ee]xtra"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                        "bindings": [
                            {"host": "api.example.com", "method": ["GET"]},  # typo
                        ],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_inject_unknown_field_rejected() -> None:
    with pytest.raises(ValidationError, match="[Ee]xtra"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "header": "Authorization",
                            "format": "Bearer {secret}",
                            "headers": "Authorization",
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_config_unknown_top_level_field_rejected() -> None:
    with pytest.raises(ValidationError, match="[Ee]xtra"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
                "unmatchd_destination_policy": "deny",  # typo
            }
        )


# ---------------------------------------------------------------------------
# Placeholder validation
# ---------------------------------------------------------------------------


def _two_secrets(ph_a: str, ph_b: str) -> dict:
    return {
        "version": 1,
        "secrets": {
            "FOO": {
                "placeholder": ph_a,
                "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                "bindings": [{"host": "api.example.com"}],
            },
            "BAR": {
                "placeholder": ph_b,
                "inject": {"header": "X-Other", "format": "{secret}"},
                "bindings": [{"host": "other.example.com"}],
            },
        },
        "audit": {"path": "/tmp/x.jsonl"},
    }


def test_placeholder_too_short_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 24"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": "short_PLACEHOLDER",
                        "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_placeholder_missing_marker_rejected() -> None:
    with pytest.raises(ValidationError, match="must contain the literal marker"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": "x" * 40,
                        "inject": {"header": "Authorization", "format": "Bearer {secret}"},
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_placeholder_duplicate_across_secrets_rejected() -> None:
    with pytest.raises(ValidationError, match="identical"):
        Config.model_validate(_two_secrets(_FOO_PH, _FOO_PH))


def test_placeholder_substring_of_another_rejected() -> None:
    short = "ghp_PLACEHOLDER_01HXY12345"
    longer = short + "_EXTENDED"
    with pytest.raises(ValidationError, match="substring"):
        Config.model_validate(_two_secrets(short, longer))


def test_placeholder_disjoint_pair_accepted() -> None:
    Config.model_validate(_two_secrets(_FOO_PH, _BAR_PH))


def test_empty_methods_rejected() -> None:
    with pytest.raises(ValidationError, match="empty methods"):
        Config.model_validate(_minimal_secret({"methods": []}))


def test_empty_paths_rejected() -> None:
    with pytest.raises(ValidationError, match="empty paths"):
        Config.model_validate(_minimal_secret({"paths": []}))


def test_methods_wildcard_rejected() -> None:
    with pytest.raises(ValidationError, match=r"cannot contain '\*'"):
        Config.model_validate(_minimal_secret({"methods": ["*"]}))


def test_unknown_http_method_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown HTTP method"):
        Config.model_validate(_minimal_secret({"methods": ["FOO"]}))


def test_methods_normalized_to_uppercase() -> None:
    config = Config.model_validate(_minimal_secret({"methods": ["get", "post"]}))
    assert config.secrets["FOO"].bindings[0].methods == ["GET", "POST"]


def test_path_without_leading_slash_rejected() -> None:
    with pytest.raises(ValidationError, match="must start with '/'"):
        Config.model_validate(_minimal_secret({"paths": ["repos/foo"]}))


def test_inject_format_must_contain_secret_placeholder() -> None:
    with pytest.raises(ValidationError, match=r"\{secret\}"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {"header": "Authorization", "format": "Bearer hardcoded"},
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


# ---------------------------------------------------------------------------
# Composite secrets — inject.template + compose validators
# ---------------------------------------------------------------------------


def _composite_secret(
    *,
    template: str | None = None,
    fmt: str | None = None,
    compose: list[str] | None = None,
) -> dict:
    inject: dict = {"header": "Authorization"}
    if template is not None:
        inject["template"] = template
    if fmt is not None:
        inject["format"] = fmt
    secret: dict = {
        "placeholder": "x_PLACEHOLDER_01234567890",
        "inject": inject,
        "bindings": [{"host": "api.example.com"}],
    }
    if compose is not None:
        secret["compose"] = compose
    return {
        "version": 1,
        "secrets": {"FOO": secret},
        "audit": {"path": "/tmp/x.jsonl"},
    }


def test_composite_secret_validates() -> None:
    config = Config.model_validate(
        _composite_secret(
            template="Basic {{ (USER + ':' + TOKEN) | b64encode }}",
            compose=["USER", "TOKEN"],
        )
    )
    spec = config.secrets["FOO"]
    assert spec.compose == ["USER", "TOKEN"]
    assert spec.compiled_template is not None
    rendered = spec.compiled_template.render({"USER": "alice", "TOKEN": "s3cret"})
    assert rendered.startswith("Basic ")


def test_inject_format_and_template_both_set_rejected() -> None:
    with pytest.raises(ValidationError, match="mutually exclusive"):
        Config.model_validate(
            _composite_secret(
                fmt="Bearer {secret}",
                template="Bearer {{ X }}",
                compose=["X"],
            )
        )


def test_inject_neither_format_nor_template_rejected() -> None:
    with pytest.raises(ValidationError, match="either 'format' .* or 'template'"):
        Config.model_validate(_composite_secret())


def test_compose_without_template_rejected() -> None:
    with pytest.raises(ValidationError, match="compose: requires inject.template"):
        Config.model_validate(_composite_secret(fmt="Bearer {secret}", compose=["X"]))


def test_template_without_compose_rejected() -> None:
    with pytest.raises(ValidationError, match="requires compose"):
        Config.model_validate(_composite_secret(template="Bearer {{ X }}"))


def test_compose_too_many_entries_rejected() -> None:
    with pytest.raises(ValidationError, match="1-4 secret names"):
        Config.model_validate(
            _composite_secret(
                template="{{ A + B + C + D + E }}",
                compose=["A", "B", "C", "D", "E"],
            )
        )


def test_compose_zero_entries_rejected() -> None:
    with pytest.raises(ValidationError, match="1-4 secret names"):
        Config.model_validate(_composite_secret(template="Bearer {{ X }}", compose=[]))


def test_compose_duplicate_entries_rejected() -> None:
    # Silas F5: raw-list dedupe rejection, never silently coalesce.
    with pytest.raises(ValidationError, match="duplicates"):
        Config.model_validate(
            _composite_secret(
                template="{{ X + ':' + X }}",
                compose=["X", "X"],
            )
        )


def test_compose_yaml_alias_duplicate_rejected() -> None:
    # Silas F5 (anchor variant): YAML aliases produce the same parsed
    # list as repeated entries — must still reject.
    raw_yaml = """
version: 1
secrets:
  FOO:
    placeholder: x_PLACEHOLDER_0123456789
    inject:
      header: Authorization
      template: "Basic {{ X + ':' + Y }}"
    compose:
      - &shared X
      - *shared
    bindings:
      - host: api.example.com
audit:
  path: /tmp/x.jsonl
"""
    import yaml

    raw = yaml.safe_load(raw_yaml)
    with pytest.raises(ValidationError, match="duplicates"):
        Config.model_validate(raw)


def test_compose_empty_entry_rejected() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        Config.model_validate(_composite_secret(template="Bearer {{ X }}", compose=["X", ""]))


def test_template_syntax_error_rejected() -> None:
    with pytest.raises(ValidationError, match="invalid"):
        Config.model_validate(_composite_secret(template="{{ X ", compose=["X"]))


def test_template_unknown_variable_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown variable"):
        Config.model_validate(_composite_secret(template="{{ NOT_IN_COMPOSE }}", compose=["X"]))


def test_template_unknown_filter_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown filter"):
        Config.model_validate(_composite_secret(template="{{ X | upper }}", compose=["X"]))


def test_template_class_walk_escape_rejected_at_config() -> None:
    # End-to-end proof: a malicious template lands on the AST validator
    # via the config-load path and gets rejected before AVP starts.
    # ``X.__class__.__mro__[1].__subclasses__()`` parses as
    # Call(Getattr(...)) — Call validator hits first and rejects because
    # the call target isn't a bare Name.
    with pytest.raises(ValidationError, match="only direct function calls"):
        Config.model_validate(
            _composite_secret(
                template="{{ X.__class__.__mro__[1].__subclasses__() }}",
                compose=["X"],
            )
        )


def test_single_secret_with_inject_template_legal() -> None:
    # Design doc §4.1: single-secret bindings can opt-in to inject.template
    # if they want filter-based encoding (e.g., sha256 of a token).
    config = Config.model_validate(
        _composite_secret(
            template="{{ KEY | sha256 }}",
            compose=["KEY"],
        )
    )
    spec = config.secrets["FOO"]
    assert spec.compose == ["KEY"]
    assert spec.compiled_template is not None


def test_legacy_inject_format_still_works() -> None:
    # Backward compatibility: existing single-secret bindings with the
    # original inject.format flow are untouched.
    config = Config.model_validate(_composite_secret(fmt="Bearer {secret}"))
    spec = config.secrets["FOO"]
    assert spec.compose is None
    assert spec.compiled_template is None
    assert spec.inject.format == "Bearer {secret}"


def test_nested_composition_rejected_silas_f6() -> None:
    # Silas F6: composite-of-composite must be rejected via leaf-check.
    raw = {
        "version": 1,
        "secrets": {
            "INNER": {
                "placeholder": "inner_PLACEHOLDER_01HXY12345",
                "inject": {
                    "header": "X-Inner",
                    "template": "{{ A + B }}",
                },
                "compose": ["A", "B"],
                "bindings": [{"host": "inner.example.com"}],
            },
            "OUTER": {
                "placeholder": "outer_PLACEHOLDER_01HXY12345",
                "inject": {
                    "header": "Authorization",
                    "template": "Bearer {{ INNER }}",
                },
                "compose": ["INNER"],  # references the INNER composite — illegal
                "bindings": [{"host": "outer.example.com"}],
            },
        },
        "audit": {"path": "/tmp/x.jsonl"},
    }
    with pytest.raises(ValidationError, match="[Nn]ested composition is not supported"):
        Config.model_validate(raw)


def test_compose_can_share_name_with_single_secret_binding_silas_f6() -> None:
    # Silas F6 corollary: it's legal for a compose entry to share its name
    # with a SINGLE-secret binding. Only nesting (composite-in-composite)
    # is banned. ``JIRA_API_TOKEN`` can be both a standalone single-secret
    # binding AND used inside a JIRA_API_BASIC composite.
    raw = {
        "version": 1,
        "secrets": {
            "JIRA_API_TOKEN": {
                "placeholder": "jira_tok_PLACEHOLDER_01HXY12345",
                "inject": {"header": "X-Jira-Token", "format": "{secret}"},
                "bindings": [{"host": "jira.example.com"}],
            },
            "JIRA_API_BASIC": {
                "placeholder": "jira_basic_PLACEHOLDER_01HXY12345",
                "inject": {
                    "header": "Authorization",
                    "template": "Basic {{ (JIRA_EMAIL + ':' + JIRA_API_TOKEN) | b64encode }}",
                },
                "compose": ["JIRA_EMAIL", "JIRA_API_TOKEN"],
                "bindings": [{"host": "jira.example.com"}],
            },
        },
        "audit": {"path": "/tmp/x.jsonl"},
    }
    config = Config.model_validate(raw)
    assert config.secrets["JIRA_API_BASIC"].compose == ["JIRA_EMAIL", "JIRA_API_TOKEN"]


def test_4_secret_composite_at_cap_accepted() -> None:
    # Cap raised to 4 during grill (tenant_id-style patterns).
    config = Config.model_validate(
        _composite_secret(
            template="{{ A + B + C + D }}",
            compose=["A", "B", "C", "D"],
        )
    )
    assert config.secrets["FOO"].compose == ["A", "B", "C", "D"]
