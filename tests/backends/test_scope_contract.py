"""Characterization contract for the duplicated secret_prefix scoping predicate.

`_assert_in_scope`, `_refuse_or_warn` and `_HttpError` are currently implemented
twice — once in backends/aws.py, once in backends/gsm.py. This suite runs one
table against BOTH copies so any behavioural divergence is a test failure rather
than a silent scope bypass, and pins the shared behaviour before it is extracted
to a single implementation.

Rows marked PINS-SHARP-EDGE record what the predicate does today, not what it
ought to do. Changing any of them is a security-affecting behaviour change and
needs its own commit, not a refactor.
"""

from __future__ import annotations

import logging

import pytest

from kow.backends import BackendUnavailableError, SecretNotFoundError
from kow.backends import aws as aws_mod
from kow.backends import gsm as gsm_mod
from kow.backends.aws import AwsConfig, AwsSecretsManagerBackend
from kow.backends.gsm import GsmBackend, GsmConfig


def _aws(prefix: str | None):
    return AwsSecretsManagerBackend(
        config=AwsConfig(region="us-east-1", secret_prefix=prefix, self_check="off")
    )


def _gsm(prefix: str | None):
    return GsmBackend(config=GsmConfig(project_id="myproj", secret_prefix=prefix, self_check="off"))


# (id, prefix, name, in_scope)
SCOPE_ROWS = [
    ("none_prefix_admits_all", None, "anything/at/all", True),
    ("empty_prefix_admits_all", "", "anything/at/all", True),
    ("exact_match", "avp/", "avp/key", True),
    ("name_equals_prefix", "avp/", "avp/", True),
    ("outside_namespace", "avp/", "other/key", False),
    ("separator_missing", "avp/", "avpkey", False),
    ("case_differs", "avp/", "AVP/key", False),
    ("fullwidth_unicode_not_folded", "avp/", "ａｖｐ/key", False),
    ("leading_space", "avp/", " avp/key", False),
    # PINS-SHARP-EDGE: startswith has no segment boundary, so a prefix without a
    # trailing separator admits a longer sibling namespace.
    ("segment_boundary_admits_sibling", "app", "application-prod", True),
    ("segment_boundary_admits_child", "app", "app/prod", True),
    # PINS-SHARP-EDGE: the predicate is a prefix test only — it does not
    # normalise the remainder of the name.
    ("traversal_in_name_admitted", "avp/", "avp/../dev/key", True),
    ("nul_byte_in_name_admitted", "avp/", "avp/\x00evil", True),
]

BACKENDS = [("aws", _aws), ("gsm", _gsm)]


def _in_scope(backend, name: str) -> bool:
    try:
        backend._assert_in_scope(name)
    except SecretNotFoundError:
        return False
    return True


@pytest.mark.parametrize("backend_id,build", BACKENDS, ids=[b[0] for b in BACKENDS])
@pytest.mark.parametrize(
    "prefix,name,expected", [r[1:] for r in SCOPE_ROWS], ids=[r[0] for r in SCOPE_ROWS]
)
def test_scope_predicate(backend_id: str, build, prefix: str | None, name: str, expected: bool):
    """Every backend's scope predicate agrees with the pinned table."""
    assert _in_scope(build(prefix), name) is expected


@pytest.mark.parametrize(
    "prefix,name,expected", [r[1:] for r in SCOPE_ROWS], ids=[r[0] for r in SCOPE_ROWS]
)
def test_copies_agree(prefix: str | None, name: str, expected: bool):
    """The two copies must not diverge — divergence is a scope bypass, not drift."""
    assert _in_scope(_aws(prefix), name) == _in_scope(_gsm(prefix), name)


@pytest.mark.parametrize("backend_id,build", BACKENDS, ids=[b[0] for b in BACKENDS])
def test_out_of_scope_message_does_not_echo_the_secret(backend_id: str, build):
    """The refusal names the requested name and prefix only — no value bytes."""
    with pytest.raises(SecretNotFoundError) as exc:
        build("avp/")._assert_in_scope("other/key")
    msg = str(exc.value)
    assert "other/key" in msg
    assert "outside secret_prefix" in msg


@pytest.mark.parametrize("backend_id,build", BACKENDS, ids=[b[0] for b in BACKENDS])
def test_refuse_or_warn_deny_raises(backend_id: str, build):
    with pytest.raises(BackendUnavailableError, match=r"self_check=deny → refusing to start"):
        build("avp/")._refuse_or_warn("deny", "boom")


@pytest.mark.parametrize(
    "backend_id,build,module",
    [("aws", _aws, aws_mod), ("gsm", _gsm, gsm_mod)],
    ids=["aws", "gsm"],
)
def test_refuse_or_warn_warn_logs_and_continues(backend_id: str, build, module, caplog):
    with caplog.at_level(logging.WARNING, logger=module._log.name):
        build("avp/")._refuse_or_warn("warn", "boom")
    assert "boom [self_check=warn → continuing]" in caplog.text


@pytest.mark.parametrize(
    "make",
    [
        lambda: AwsConfig(region="us-east-1", self_check="deny"),
        lambda: GsmConfig(project_id="myproj", self_check="deny"),
    ],
    ids=["aws", "gsm"],
)
def test_deny_without_prefix_is_rejected(make):
    """A deny-if-broad guard with no namespace to bound would silently no-op."""
    with pytest.raises(ValueError, match="deny requires secret_prefix"):
        make()


@pytest.mark.parametrize("module", [aws_mod, gsm_mod], ids=["aws", "gsm"])
def test_http_error_shape(module):
    """Both copies carry status + parsed body and stringify identically."""
    err = module._HttpError(404, {"x": 1})
    assert (err.status, err.body) == (404, {"x": 1})
    assert str(err) == "HTTP 404"
