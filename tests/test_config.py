from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from kow.config import Config, load_config

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
                "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
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
                        "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
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
                        "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
                        "bindings": [{"host": "*.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


@pytest.mark.parametrize(
    "bad_host",
    ["", "   ", "\t", "*", "*bad.com", "a*b.com", "evil_*", "api .github.com", "foo..bar"],
)
def test_host_without_real_hostname_rejected(bad_host: str) -> None:
    """A secret must name a concrete destination host. Empty, whitespace,
    bare/embedded '*', and malformed hosts are rejected at config-load — so it
    is structurally impossible to define a secret with an unbounded (or a
    silently dead, in the bare-'*' case) destination. Combined with `host`
    being required and reject_empty_bindings, every secret is pinned to at
    least one real hostname."""
    with pytest.raises(ValidationError):
        Config.model_validate(_minimal_secret({"host": bad_host}))


@pytest.mark.parametrize(
    "good_host",
    ["api.github.com", "postman-echo.com", "internal-host", "api.example.net"],
)
def test_valid_exact_hosts_accepted(good_host: str) -> None:
    """Real exact hosts (including a single-label internal name) load cleanly —
    the enforcement rejects junk, not intent."""
    cfg = Config.model_validate(_minimal_secret({"host": good_host}))
    assert cfg.secrets["FOO"].bindings[0].host == good_host.lower()


@pytest.mark.parametrize(
    "tld_wildcard",
    [
        "*.com",
        "*.io",
        "*.co.uk",
        "*.com.au",
        "*.co.jp",
        "*.github.io",
        "*.herokuapp.com",
        "*.vercel.app",
    ],
)
def test_public_suffix_wildcard_rejected_even_when_wildcards_enabled(tld_wildcard: str) -> None:
    """A wildcard must never span a public suffix / registry TLD: `*.co.uk` or
    `*.github.io` would broker the secret to every registrant under that suffix.
    This is a FIELD-level rule — rejected even with `allow_wildcard_hosts: true`."""
    cfg = _minimal_secret({"host": tld_wildcard})
    cfg["allow_wildcard_hosts"] = True
    with pytest.raises(ValidationError, match="too broad|public suffix"):
        Config.model_validate(cfg)


@pytest.mark.parametrize(
    "registrable_wildcard",
    ["*.github.com", "*.googleapis.com", "*.your-tenant.atlassian.net", "*.internal.example.com"],
)
def test_registrable_wildcard_requires_opt_in(registrable_wildcard: str) -> None:
    """Wildcards on a real registrable domain are a deliberate opt-in: rejected
    by default (blast-radius footgun), accepted only when the operator sets
    `allow_wildcard_hosts: true`."""
    off = _minimal_secret({"host": registrable_wildcard})
    with pytest.raises(ValidationError, match="wildcard host"):
        Config.model_validate(off)

    on = _minimal_secret({"host": registrable_wildcard})
    on["allow_wildcard_hosts"] = True
    cfg = Config.model_validate(on)
    assert cfg.secrets["FOO"].bindings[0].host == registrable_wildcard


def test_mixed_case_host_is_lowercased_with_warning(caplog) -> None:
    """DNS is case-insensitive; binding hosts written in mixed case
    (e.g., a vendor doc paste) get normalised at config-load and the
    operator gets a visible log warning. Silent rewrites lose audit value."""
    import logging

    with caplog.at_level(logging.WARNING, logger="kow.config"):
        cfg = Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
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

    with caplog.at_level(logging.WARNING, logger="kow.config"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
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
                "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
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
                        "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
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
                            "format": "Bearer {FOO}",
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
                        "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
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
                "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
                "bindings": [{"host": "api.example.com"}],
            },
            "BAR": {
                "placeholder": ph_b,
                "inject": {"header": "X-Other", "format": "{BAR}"},
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
                        "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
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
                        "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
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
    # The HeaderInjector-level validator fires when inject.format has no
    # `{...}`-shaped placeholder at all. The message is generic — it doesn't
    # know the parent SecretSpec's name, so it can only point at the shape.
    # (The Config-level validator catches the name-mismatch case where a
    # `{...}` is present but doesn't match the YAML key — see
    # test_named_inject_format_rejects_mismatched_name.)
    with pytest.raises(ValidationError, match=r"must contain a"):
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


def test_body_composite_secret_validates() -> None:
    """Body injector + compose: + inject.template compiles the template at
    config-load — same machinery as the header composite path. The deferral
    that previously blocked this at the BodyInjector validator is now lifted."""
    config = Config.model_validate(
        {
            "version": 1,
            "secrets": {
                "WEBHOOK_HMAC": {
                    "placeholder": "wh_PLACEHOLDER_01HXY1234567890ABC",
                    "inject": {
                        "type": "body",
                        "content_type": "application/json",
                        "template": "{{ (KEY + ':' + MSG) | b64encode }}",
                    },
                    "compose": ["KEY", "MSG"],
                    "bindings": [{"host": "hooks.example.com", "methods": ["POST"]}],
                }
            },
            "audit": {"path": "/tmp/x.jsonl"},
        }
    )
    spec = config.secrets["WEBHOOK_HMAC"]
    assert spec.compose == ["KEY", "MSG"]
    assert spec.compiled_template is not None
    rendered = spec.compiled_template.render({"KEY": "alice", "MSG": "ping"})
    assert rendered == "YWxpY2U6cGluZw=="


def test_body_composite_without_compose_rejected() -> None:
    """Body inject.template alone (no compose:) must fail at config-load
    with the same message as the header case — co-required."""
    with pytest.raises(ValidationError, match="requires compose"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "WH": {
                        "placeholder": "wh_PLACEHOLDER_01HXY1234567890ABC",
                        "inject": {
                            "type": "body",
                            "template": "{{ X }}",
                        },
                        "bindings": [{"host": "hooks.example.com", "methods": ["POST"]}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_body_composite_with_format_too_rejected() -> None:
    """Body inject.format AND inject.template are mutually exclusive — the
    BodyInjector validator surfaces the same error as the header path."""
    with pytest.raises(ValidationError, match="mutually exclusive"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "WH": {
                        "placeholder": "wh_PLACEHOLDER_01HXY1234567890ABC",
                        "inject": {
                            "type": "body",
                            "format": "{WH}",
                            "template": "{{ X }}",
                        },
                        "compose": ["X"],
                        "bindings": [{"host": "hooks.example.com", "methods": ["POST"]}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_inject_format_and_template_both_set_rejected() -> None:
    with pytest.raises(ValidationError, match="mutually exclusive"):
        Config.model_validate(
            _composite_secret(
                fmt="Bearer {FOO}",
                template="Bearer {{ X }}",
                compose=["X"],
            )
        )


def test_inject_neither_format_nor_template_rejected() -> None:
    with pytest.raises(ValidationError, match=r"either 'format'.*'template'"):
        Config.model_validate(_composite_secret())


def test_compose_without_template_rejected() -> None:
    with pytest.raises(ValidationError, match="compose: requires inject.template"):
        Config.model_validate(_composite_secret(fmt="Bearer {FOO}", compose=["X"]))


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
    # raw-list dedupe rejection, never silently coalesce.
    with pytest.raises(ValidationError, match="duplicates"):
        Config.model_validate(
            _composite_secret(
                template="{{ X + ':' + X }}",
                compose=["X", "X"],
            )
        )


def test_compose_yaml_alias_duplicate_rejected() -> None:
    # anchor variant: YAML aliases produce the same parsed
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
    # named-form inject.format flow are untouched.
    config = Config.model_validate(_composite_secret(fmt="Bearer {FOO}"))
    spec = config.secrets["FOO"]
    assert spec.compose is None
    assert spec.compiled_template is None
    assert spec.inject.format == "Bearer {FOO}"


def test_named_inject_format_accepted() -> None:
    # The named form `{<entry_name>}` is the canonical (and only) placeholder
    # accepted from v0.5.0 onward — see test_generic_secret_placeholder_rejected.
    config = Config.model_validate(_composite_secret(fmt="Bearer {FOO}"))
    spec = config.secrets["FOO"]
    assert spec.inject.format == "Bearer {FOO}"


def test_named_inject_format_rejects_mismatched_name() -> None:
    # The named placeholder must match the parent entry's YAML key. A typo
    # like `{FOO_API_KEY}` under a secrets entry actually named `FOO` would
    # silently inject literal `{FOO_API_KEY}` bytes onto the wire — caught
    # at config load instead.
    with pytest.raises(ValidationError, match=r"must contain"):
        Config.model_validate(_composite_secret(fmt="Bearer {WRONG_NAME}"))


def test_nested_composition_rejected() -> None:
    # composite-of-composite must be rejected via leaf-check.
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
    with pytest.raises(ValidationError, match="is itself a composite binding"):
        Config.model_validate(raw)


def test_compose_can_share_name_with_single_secret_binding() -> None:
    # it's legal for a compose entry to share its name
    # with a SINGLE-secret binding. Only nesting (composite-in-composite)
    # is banned. ``JIRA_API_TOKEN`` can be both a standalone single-secret
    # binding AND used inside a JIRA_API_BASIC composite.
    raw = {
        "version": 1,
        "secrets": {
            "JIRA_API_TOKEN": {
                "placeholder": "jira_tok_PLACEHOLDER_01HXY12345",
                "inject": {"header": "X-Jira-Token", "format": "{JIRA_API_TOKEN}"},
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


# ---------------------------------------------------------------------------
# v0.5.0 injector-strategy port: discriminator + named-placeholder rules
# (P0.1 of the superfly-tokenizer-inspired refactor — see ISA.md at repo
# root, decisions Q1+Q12+Q14)
# ---------------------------------------------------------------------------


def test_unknown_inject_type_clean_error() -> None:
    # Operator typos `type: oauth_refresh_` (note the underscore) instead
    # of `oauth2_refresh`. The pre-discriminator short-circuit catches it
    # with a single-line error listing the valid types, rather than
    # spilling Pydantic-internal-repr across hundreds of lines.
    with pytest.raises(ValidationError, match=r"inject\.type 'oauth_refresh_' is unknown"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "oauth_refresh_",
                            "header": "Authorization",
                            "format": "Bearer {FOO}",
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_known_but_unimplemented_inject_type_clean_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # All shipped injector types are now implemented, so to exercise the
    # planned-but-unimplemented guard (kept for future reserved types) we
    # temporarily mark one planned. An operator writing an unimplemented type
    # gets a clear "not yet implemented" error pointing at the CHANGELOG,
    # rather than a Pydantic validation error about missing fields.
    from kow import config_models

    monkeypatch.setitem(config_models._INJECTOR_TYPES, "github_app", "planned: P9")
    with pytest.raises(ValidationError, match=r"not yet implemented in this version"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "github_app",
                            "header": "Authorization",
                            "format": "Bearer {FOO}",
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_generic_secret_placeholder_rejected() -> None:
    # The legacy `{secret}` alias was removed in v0.5.0 — only the named
    # form `{<SECRET_NAME>}` is accepted. A binding still using the
    # generic alias fails the named-form check at config load.
    with pytest.raises(ValidationError, match=r"must contain '\{FOO\}'"):
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
            }
        )


def test_version_field_is_optional_and_defaults_to_one() -> None:
    # `version:` may be omitted from bindings.yaml; the schema defaults
    # to 1. Operators can write it for explicitness or drop it.
    config = Config.model_validate(
        {
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
    assert config.version == 1


def test_implicit_inject_type_defaults_to_header() -> None:
    # An `inject:` block omitting `type:` parses as HeaderInjector by
    # default — this is the backward-compat path for every v0.4.x
    # bindings.yaml in existence.
    config = Config.model_validate(
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
    assert config.secrets["FOO"].inject.type == "header"


def test_explicit_inject_type_header_accepted() -> None:
    # Operators may opt to write `type: header` explicitly. The
    # discriminator round-trips cleanly.
    config = Config.model_validate(
        {
            "version": 1,
            "secrets": {
                "FOO": {
                    "placeholder": _FOO_PH,
                    "inject": {
                        "type": "header",
                        "header": "Authorization",
                        "format": "Bearer {FOO}",
                    },
                    "bindings": [{"host": "api.example.com"}],
                }
            },
            "audit": {"path": "/tmp/x.jsonl"},
        }
    )
    assert config.secrets["FOO"].inject.type == "header"


def test_inject_spec_backcompat_alias() -> None:
    # Third-party code (and AVP's own pre-v0.5.0 tests) imports `InjectSpec`
    # directly. The alias keeps `InjectSpec` valid through v0.6.0; new code
    # should use `HeaderInjector`.
    from kow.config import HeaderInjector, InjectSpec

    assert InjectSpec is HeaderInjector


def test_discriminator_default_injection_with_real_multi_variant_union() -> None:
    # Pydantic 2 does NOT apply per-model field defaults before reading the
    # discriminator tag. The moment ``InjectorSpec`` gains a second variant
    # (P0.6 adds BodyInjector), an input lacking ``type:`` would fail with
    # ``union_tag_not_found`` unless the parent default-injects ``type:
    # "header"`` first. This test simulates that future state by building a
    # programmatic two-variant union and verifying both the default-injection
    # and the union dispatch behave correctly.
    from typing import Annotated, Literal

    from pydantic import BaseModel, ConfigDict, Field, model_validator

    class _Header(BaseModel):
        model_config = ConfigDict(extra="forbid")
        type: Literal["header"] = "header"
        value: str

    class _Body(BaseModel):
        model_config = ConfigDict(extra="forbid")
        type: Literal["body"]
        value: str

    _Spec = Annotated[_Header | _Body, Field(discriminator="type")]  # noqa: N806

    class _Parent(BaseModel):
        model_config = ConfigDict(extra="forbid")
        items: dict[str, _Spec]

        @model_validator(mode="before")
        @classmethod
        def default_type(cls, data: object) -> object:
            if not isinstance(data, dict):
                return data
            items = data.get("items")
            if not isinstance(items, dict):
                return data
            new_items: dict[str, object] = {}
            mutated = False
            for k, v in items.items():
                if isinstance(v, dict) and "type" not in v:
                    new_items[k] = {**v, "type": "header"}
                    mutated = True
                else:
                    new_items[k] = v
            if mutated:
                return {**data, "items": new_items}
            return data

    # Implicit type: defaults to header.
    p1 = _Parent.model_validate({"items": {"a": {"value": "x"}}})
    assert isinstance(p1.items["a"], _Header)

    # Explicit type=body dispatches to the body variant.
    p2 = _Parent.model_validate({"items": {"a": {"type": "body", "value": "y"}}})
    assert isinstance(p2.items["a"], _Body)

    # Mixed: defaulted + explicit non-default coexist.
    p3 = _Parent.model_validate(
        {"items": {"a": {"value": "x"}, "b": {"type": "body", "value": "y"}}}
    )
    assert isinstance(p3.items["a"], _Header)
    assert isinstance(p3.items["b"], _Body)
