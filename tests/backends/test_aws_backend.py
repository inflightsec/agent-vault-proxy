"""AWS Secrets Manager backend: protocol contract + unit tests (ADR-0038).

All tests use an injected transport (``http``) and credential provider, so they
need neither the optional ``botocore`` dependency nor a live AWS account. The
router dispatches on the ``X-Amz-Target`` header (every AWS JSON call hits the
same endpoint), and asserts each request is SigV4-signed.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from agent_vault_proxy.backends import (
    BACKEND_REGISTRY,
    BackendAuthLostError,
    BackendUnavailableError,
    SecretNotFoundError,
)
from agent_vault_proxy.backends.aws import (
    AwsConfig,
    AwsCredentials,
    AwsSecretsManagerBackend,
)
from tests.backends.test_protocol_contract import ProtocolContract

_GET = "secretsmanager.GetSecretValue"
_LIST = "secretsmanager.ListSecrets"
_DESCRIBE = "secretsmanager.DescribeSecret"

# Default self_check read-scope-probe response: AccessDenied = "cannot read
# outside prefix" = the healthy, scoped case.
_PROBE_SCOPED = (400, {"__type": "AccessDeniedException"})


def _router(
    routes: dict[str, tuple[int, dict[str, Any] | None]],
    *,
    probe: tuple[int, dict[str, Any] | None] = _PROBE_SCOPED,
):
    """Fake HttpFn keyed on X-Amz-Target. Asserts the request is SigV4-signed.
    A GetSecretValue whose SecretId is the self_check read-scope PROBE routes to
    ``probe`` (default AccessDenied = scoped); real GetSecretValue uses routes."""

    def http(method: str, url: str, headers: dict[str, str], body: bytes | None):
        assert method == "POST"
        assert headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 ")
        target = headers.get("X-Amz-Target", "")
        if target == _GET and body:
            sid = json.loads(body).get("SecretId", "")
            if "selfcheck-out-of-scope-probe" in sid:
                return probe
        if target in routes:
            return routes[target]
        return (400, {"__type": "ResourceNotFoundException"})

    return http


def _creds(*, temporary: bool = True) -> Any:
    tok = "FQoG-SESSION-TOKEN" if temporary else None
    return lambda: AwsCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", tok)


def _backend(http, *, temporary: bool = True, **cfg) -> AwsSecretsManagerBackend:
    cfg.setdefault("region", "us-east-1")
    cfg.setdefault("self_check", "off")
    return AwsSecretsManagerBackend(
        config=AwsConfig(**cfg), credential_provider=_creds(temporary=temporary), http=http
    )


# ---------------------------------------------------------------------------
# Contract suite + registry
# ---------------------------------------------------------------------------


class TestAwsContract(ProtocolContract):
    @pytest.fixture
    def backend(self):
        return _backend(_router({_GET: (200, {"SecretString": "v"})}))


def test_registry_has_aws() -> None:
    assert "aws-secrets-manager" in BACKEND_REGISTRY
    backend_cls, config_cls = BACKEND_REGISTRY["aws-secrets-manager"]
    assert backend_cls.__name__ == "AwsSecretsManagerBackend"
    assert config_cls.__name__ == "AwsConfig"


# ---------------------------------------------------------------------------
# Config — secure-by-default schema
# ---------------------------------------------------------------------------


def test_config_has_no_static_key_field() -> None:
    """The 'no long-lived key' invariant (ADR-0038 §2): a static access key
    cannot be wired through config — extra=forbid rejects it."""
    with pytest.raises(ValidationError):
        AwsConfig(  # type: ignore[call-arg]
            region="us-east-1",
            secret_prefix="avp/",
            aws_access_key_id="AKIA",
            aws_secret_access_key="x",
        )


def test_config_defaults_are_secure() -> None:
    with pytest.raises(ValidationError):  # deny requires a prefix
        AwsConfig(region="us-east-1")
    cfg = AwsConfig(region="us-east-1", secret_prefix="avp/")
    assert cfg.self_check == "deny"
    assert cfg.require_temporary_credentials is True
    assert cfg.version_stage == "AWSCURRENT"


def test_self_check_deny_requires_prefix() -> None:
    with pytest.raises(ValidationError, match="secret_prefix"):
        AwsConfig(region="us-east-1", self_check="deny")
    assert AwsConfig(region="us-east-1", self_check="warn").self_check == "warn"
    assert AwsConfig(region="us-east-1", self_check="off").self_check == "off"


@pytest.mark.parametrize("bad", ["us_east_1", "us east 1", "us-east-1/x", "US-EAST-1", "a.b"])
def test_region_rejects_unsafe_values(bad: str) -> None:
    with pytest.raises(ValidationError):
        AwsConfig(region=bad, secret_prefix="avp/")


def test_version_stage_rejects_awspending() -> None:
    # A read-only broker serves the promoted version; AWSPENDING is unpromoted
    # (Oracle C5) — refused so config can't contradict the "AWSCURRENT only" claim.
    with pytest.raises(ValidationError, match="AWSPENDING"):
        AwsConfig(region="us-east-1", secret_prefix="avp/", version_stage="AWSPENDING")
    # AWSCURRENT (default) and a custom promoted label are fine.
    assert AwsConfig(region="us-east-1", secret_prefix="avp/", version_stage="prod").version_stage


# ---------------------------------------------------------------------------
# fetch — value resolution + AWS error mapping
# ---------------------------------------------------------------------------


def test_fetch_returns_secret_string() -> None:
    b = _backend(_router({_GET: (200, {"SecretString": "sk-secret-123"})}))
    assert b.fetch("avp/OPENAI_API_KEY") == "sk-secret-123"


def test_fetch_missing_raises_not_found() -> None:
    b = _backend(_router({_GET: (400, {"__type": "com.amazon.coral#ResourceNotFoundException"})}))
    with pytest.raises(SecretNotFoundError):
        b.fetch("avp/MISSING")


@pytest.mark.parametrize(
    "resp",
    [
        (403, {"__type": "AccessDeniedException"}),
        (400, {"__type": "UnrecognizedClientException"}),
        (403, {"__type": "ExpiredTokenException"}),
    ],
)
def test_fetch_denied_raises_auth_lost(resp) -> None:
    b = _backend(_router({_GET: resp}))
    with pytest.raises(BackendAuthLostError):
        b.fetch("avp/FORBIDDEN")


def test_fetch_5xx_raises_unavailable() -> None:
    b = _backend(_router({_GET: (500, {"__type": "InternalServiceError"})}))
    with pytest.raises(BackendUnavailableError):
        b.fetch("avp/X")


def test_fetch_secret_binary_raises_unavailable_without_leaking() -> None:
    b = _backend(_router({_GET: (200, {"SecretBinary": "AAECAwQ="})}))
    with pytest.raises(BackendUnavailableError) as ei:
        b.fetch("avp/BIN")
    assert "AAECAwQ=" not in str(ei.value)


def test_fetch_no_secret_string_raises_unavailable() -> None:
    b = _backend(_router({_GET: (200, {"ARN": "arn:..."})}))
    with pytest.raises(BackendUnavailableError):
        b.fetch("avp/EMPTY")


# ---------------------------------------------------------------------------
# Signing — the request is SigV4-signed with x-amz-target in the signed set
# ---------------------------------------------------------------------------


def test_request_is_sigv4_signed_with_target_and_content_hash() -> None:
    seen: dict[str, str] = {}

    def http(method, url, headers, body):
        seen.update(headers)
        return (200, {"SecretString": "v"})

    b = _backend(http)
    assert b.fetch("avp/K") == "v"
    auth = seen["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 ")
    assert "/us-east-1/secretsmanager/aws4_request" in auth
    # x-amz-target is sent, so AWS requires it signed; content-sha256 too.
    assert "x-amz-content-sha256" in auth  # in SignedHeaders
    assert "x-amz-target" in auth
    assert seen["X-Amz-Target"] == _GET
    assert seen["X-Amz-Content-Sha256"]
    # temporary creds carry the session token, signed + sent.
    assert seen["X-Amz-Security-Token"] == "FQoG-SESSION-TOKEN"
    assert "x-amz-security-token" in auth


# ---------------------------------------------------------------------------
# Scope — fetch + list bounded by secret_prefix
# ---------------------------------------------------------------------------


def test_fetch_out_of_prefix_refused() -> None:
    b = _backend(_router({_GET: (200, {"SecretString": "v"})}), secret_prefix="avp/")
    with pytest.raises(SecretNotFoundError, match="outside secret_prefix"):
        b.fetch("other/SECRET")


def test_list_filters_to_prefix() -> None:
    routes = {
        _LIST: (
            200,
            {"SecretList": [{"Name": "avp/A"}, {"Name": "avp/B"}, {"Name": "other/C"}]},
        )
    }
    b = _backend(_router(routes), secret_prefix="avp/")
    assert sorted(b.list_secret_names()) == ["avp/A", "avp/B"]


# ---------------------------------------------------------------------------
# Host binding — tag + Description marker, WITHOUT fetching values
# ---------------------------------------------------------------------------


def test_list_secret_notes_reads_tag_without_fetching_values() -> None:
    routes = {
        _LIST: (
            200,
            {
                "SecretList": [
                    {
                        "Name": "avp/OPENAI",
                        "Tags": [{"Key": "avp-binding", "Value": "api.openai.com"}],
                    },
                    {"Name": "avp/PLAIN"},
                ]
            },
        ),
        # GetSecretValue must NOT be called by list_secret_notes.
        _GET: (500, {"__type": "ShouldNotBeCalled"}),
    }
    b = _backend(_router(routes), secret_prefix="avp/")
    notes = b.list_secret_notes()
    assert notes == {"avp/OPENAI": "api.openai.com", "avp/PLAIN": None}


def test_description_marker_is_a_binding_but_plain_text_is_not() -> None:
    marked = "# avp-binding\nhost: api.stripe.com\nmethods: [POST]"
    routes = {
        _LIST: (
            200,
            {
                "SecretList": [
                    {"Name": "avp/RICH", "Description": marked},
                    {"Name": "avp/HUMAN", "Description": "just a human note about this key"},
                ]
            },
        )
    }
    b = _backend(_router(routes), secret_prefix="avp/")
    notes = b.list_secret_notes()
    assert notes["avp/RICH"] == marked
    assert notes["avp/HUMAN"] is None  # no marker → not a binding


def test_tag_wins_over_description() -> None:
    routes = {
        _LIST: (
            200,
            {
                "SecretList": [
                    {
                        "Name": "avp/BOTH",
                        "Tags": [{"Key": "avp-binding", "Value": "api.tag.com"}],
                        "Description": "# avp-binding\nhost: api.desc.com",
                    }
                ]
            },
        )
    }
    b = _backend(_router(routes), secret_prefix="avp/")
    assert b.list_secret_notes()["avp/BOTH"] == "api.tag.com"


def test_fetch_with_meta_returns_value_and_note_via_describe() -> None:
    routes = {
        _GET: (200, {"SecretString": "sk-x"}),
        _DESCRIBE: (200, {"Tags": [{"Key": "avp-binding", "Value": "api.openai.com"}]}),
    }
    b = _backend(_router(routes), secret_prefix="avp/")
    value, note = b.fetch_with_meta("avp/OPENAI")
    assert value == "sk-x"
    assert note == "api.openai.com"


# ---------------------------------------------------------------------------
# self_check — deny-if-broad boot guard
# ---------------------------------------------------------------------------


def test_self_check_deny_refuses_when_can_list_outside_prefix() -> None:
    routes = {_LIST: (200, {"SecretList": [{"Name": "avp/A"}, {"Name": "prod/DB_PASSWORD"}]})}
    b = _backend(_router(routes), secret_prefix="avp/", self_check="deny")
    with pytest.raises(BackendUnavailableError, match="refusing to start"):
        b.fetch("avp/A")


def test_self_check_deny_passes_when_scoped() -> None:
    routes = {_LIST: (200, {"SecretList": [{"Name": "avp/A"}]}), _GET: (200, {"SecretString": "v"})}
    b = _backend(_router(routes), secret_prefix="avp/", self_check="deny")
    assert b.fetch("avp/A") == "v"


def test_self_check_deny_passes_when_list_access_denied_400() -> None:
    # AWS Secrets Manager returns AccessDeniedException with HTTP 400 (NOT 403).
    # The recommended least-priv identity (GetSecretValue on prefix, no
    # ListSecrets) hits exactly this — it MUST boot. Keyed on error TYPE, not
    # status, so a 400 access-denial is correctly read as "cannot enumerate".
    routes = {
        _LIST: (400, {"__type": "AccessDeniedException"}),
        _GET: (200, {"SecretString": "v"}),
    }
    b = _backend(_router(routes), secret_prefix="avp/", self_check="deny")
    assert b.fetch("avp/A") == "v"  # can't enumerate others → scoped → OK


def test_self_check_deny_refuses_on_broken_credential_403() -> None:
    # A 403 InvalidClientTokenId is a BROKEN credential, not proof of scope —
    # inconclusive → deny refuses (must not be mistaken for "scoped").
    routes = {_LIST: (403, {"__type": "InvalidClientTokenId"})}
    b = _backend(_router(routes), secret_prefix="avp/", self_check="deny")
    with pytest.raises(BackendUnavailableError, match="refusing to start"):
        b.fetch("avp/A")


def test_self_check_deny_refuses_on_transient_list_error() -> None:
    routes = {_LIST: (500, {"__type": "InternalServiceError"})}
    b = _backend(_router(routes), secret_prefix="avp/", self_check="deny")
    with pytest.raises(BackendUnavailableError):
        b.fetch("avp/A")  # transient is NOT treated as scoped (no fail-open)


def test_self_check_warn_does_not_refuse() -> None:
    routes = {
        _LIST: (200, {"SecretList": [{"Name": "avp/A"}, {"Name": "prod/X"}]}),
        _GET: (200, {"SecretString": "v"}),
    }
    b = _backend(_router(routes), secret_prefix="avp/", self_check="warn")
    assert b.fetch("avp/A") == "v"


def test_self_check_deny_refuses_on_broad_read() -> None:
    # Oracle C3: enumeration-scoped (ListSecrets denied) but the read-scope probe
    # gets ResourceNotFound on an OUT-OF-PREFIX name → identity could read there
    # → broad GetSecretValue → refuse.
    routes = {_LIST: (400, {"__type": "AccessDeniedException"}), _GET: (200, {"SecretString": "v"})}
    b = _backend(
        _router(routes, probe=(400, {"__type": "ResourceNotFoundException"})),
        secret_prefix="avp/",
        self_check="deny",
    )
    with pytest.raises(BackendUnavailableError, match="GetSecretValue OUTSIDE prefix"):
        b.fetch("avp/A")


def test_self_check_deny_passes_when_read_scoped() -> None:
    # ListSecrets denied (enum scoped) + probe AccessDenied (read scoped) → boots.
    routes = {_LIST: (400, {"__type": "AccessDeniedException"}), _GET: (200, {"SecretString": "v"})}
    b = _backend(_router(routes), secret_prefix="avp/", self_check="deny")  # probe defaults scoped
    assert b.fetch("avp/A") == "v"


# ---------------------------------------------------------------------------
# require_temporary_credentials — the reject_ambient_key analog
# ---------------------------------------------------------------------------


def test_permanent_credentials_refused_by_default() -> None:
    b = _backend(_router({_GET: (200, {"SecretString": "v"})}), temporary=False)
    with pytest.raises(BackendAuthLostError, match="PERMANENT"):
        b.fetch("avp/A")


def test_permanent_credentials_allowed_when_opted_out() -> None:
    b = _backend(
        _router({_GET: (200, {"SecretString": "v"})}),
        temporary=False,
        require_temporary_credentials=False,
    )
    assert b.fetch("avp/A") == "v"


def test_permanent_credentials_refused_on_a_later_call() -> None:
    # Oracle C2: a provider that returns temporary creds at boot but permanent
    # creds on a later request must be refused per-call, not just at _ensure_ready.
    tokens = iter(["SESSION-1", None, None])  # ready check ok; later calls permanent

    def provider() -> AwsCredentials:
        return AwsCredentials(
            "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", next(tokens)
        )

    b = AwsSecretsManagerBackend(
        config=AwsConfig(region="us-east-1", self_check="off"),
        credential_provider=provider,
        http=_router({_GET: (200, {"SecretString": "v"})}),
    )
    with pytest.raises(BackendAuthLostError, match="PERMANENT credentials on a request"):
        b.fetch("avp/A")


# ---------------------------------------------------------------------------
# diagnose — read-only report, never raises
# ---------------------------------------------------------------------------


def test_diagnose_reports_temp_creds_and_scope() -> None:
    routes = {_LIST: (200, {"SecretList": [{"Name": "avp/A"}]})}
    b = _backend(_router(routes), secret_prefix="avp/")
    rows = b.diagnose()
    checks = {check: (status, msg) for status, check, msg in rows}
    assert checks["auth"][0] == "OK"  # temporary creds
    assert checks["enumeration"][0] == "OK"  # all within prefix


def test_repr_does_not_leak_config() -> None:
    b = _backend(_router({}), secret_prefix="avp/")
    assert repr(b) == "<AwsSecretsManagerBackend>"
