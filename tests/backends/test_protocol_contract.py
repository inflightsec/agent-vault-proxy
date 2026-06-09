"""Protocol contract test — every registered SecretsBackend must pass these.

Adding a new backend means: (1) implement SecretsBackend, (2) register it,
(3) provide a `make_backend()` fixture parameter for the backend's test
file that subclasses the contract test class below.

These tests pin the invariants the addon + caching layer rely on.
"""

from __future__ import annotations

import pytest

from agent_vault_proxy.backends import (
    BACKEND_REGISTRY,
    BackendAuthLostError,
    BackendUnavailableError,
    FetchContext,
    SecretsBackend,
)


def test_registry_has_at_least_bws() -> None:
    assert "bws" in BACKEND_REGISTRY


def test_backend_auth_lost_is_unavailable_subclass() -> None:
    """Cache logic catches BackendUnavailableError; the more specific
    BackendAuthLostError MUST be catchable by that handler."""
    assert issubclass(BackendAuthLostError, BackendUnavailableError)


@pytest.fixture
def isolated_registry():
    """snapshot the registry at fixture entry, reset for the
    test body, and ALWAYS restore the canonical state on teardown — even
    if the test body raises mid-way. Without this, a failed assertion
    between `register_backend(fake)` and a manual `_reset_registry_for_tests()`
    call leaked the fake backend into the registry, contaminating
    subsequent tests."""
    from agent_vault_proxy.backends import _reset_registry_for_tests

    _reset_registry_for_tests()
    try:
        yield
    finally:
        _reset_registry_for_tests()


def test_register_backend_rejects_duplicate() -> None:
    """Registering the same name twice raises — prevents silent
    registry-collision attacks."""
    from agent_vault_proxy.backends import register_backend

    # The 'bws' backend is already registered at module import time.
    class FakeBackend:
        def fetch(self, name: str, ctx=None) -> str:
            return "x"

    class FakeConfig:
        pass

    with pytest.raises(ValueError, match="already registered"):
        register_backend("bws", FakeBackend, FakeConfig)  # type: ignore[arg-type]


def test_register_backend_normalizes_case(isolated_registry) -> None:
    from agent_vault_proxy.backends import register_backend

    class FakeBackend:
        def fetch(self, name: str, ctx=None) -> str:
            return "x"

    class FakeConfig:
        pass

    register_backend("CapsBackend", FakeBackend, FakeConfig)  # type: ignore[arg-type]
    assert "capsbackend" in BACKEND_REGISTRY
    assert "CapsBackend" not in BACKEND_REGISTRY  # case-folded


def test_register_backend_nfkc_normalizes_unicode(isolated_registry) -> None:
    """bare .lower() lets full-width Unicode (e.g., ＢＷＳ)
    and other compatibility variants bypass the case-folding dedup check.
    Use NFKC normalization + casefold so visually-identical names collide
    in the registry."""
    from agent_vault_proxy.backends import register_backend

    class FakeBackend:
        def fetch(self, name: str, ctx=None) -> str:
            return "x"

    class FakeConfig:
        pass

    register_backend("bws-alt", FakeBackend, FakeConfig)  # type: ignore[arg-type]
    # Full-width "ＢＷＳ-ＡＬＴ" should NFKC-normalize to "bws-alt"
    with pytest.raises(ValueError, match="already registered"):
        register_backend("ＢＷＳ-ＡＬＴ", FakeBackend, FakeConfig)  # type: ignore[arg-type]


def test_backend_registry_is_read_only_externally() -> None:
    """BACKEND_REGISTRY exposes a read-only Mapping view.
    External code MUST go through register_backend() (which enforces the
    duplicate check) rather than mutating the dict directly."""
    with pytest.raises(TypeError):
        BACKEND_REGISTRY["evil"] = ("x", "y")  # type: ignore[index, assignment]
    with pytest.raises((TypeError, AttributeError)):
        BACKEND_REGISTRY.clear()  # type: ignore[attr-defined]
    with pytest.raises((TypeError, AttributeError)):
        BACKEND_REGISTRY.pop("bws")  # type: ignore[attr-defined]
    with pytest.raises((TypeError, AttributeError)):
        BACKEND_REGISTRY.update({"evil": ("x", "y")})  # type: ignore[attr-defined]


def test_register_backend_rejects_empty_name(isolated_registry) -> None:
    """empty / whitespace-only names silently register an
    unreachable backend. Reject explicitly."""
    from agent_vault_proxy.backends import register_backend

    class FakeBackend:
        def fetch(self, name, ctx=None):
            return "x"

    class FakeConfig:
        pass

    with pytest.raises(ValueError, match="empty"):
        register_backend("", FakeBackend, FakeConfig)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="empty"):
        register_backend("   ", FakeBackend, FakeConfig)  # type: ignore[arg-type]


def test_register_backend_rejects_non_string_name(isolated_registry) -> None:
    """non-string names (a TypeError-prone footgun
    for plugin authors that might pass an enum or path) must surface
    immediately, not crash later in build_backend."""
    from agent_vault_proxy.backends import register_backend

    class FakeBackend:
        def fetch(self, name, ctx=None):
            return "x"

    class FakeConfig:
        pass

    with pytest.raises(TypeError, match="must be str"):
        register_backend(123, FakeBackend, FakeConfig)  # type: ignore[arg-type]


def test_backend_registry_still_readable() -> None:
    """The read-only wrapper must still support .get / .keys / __getitem__
    / __contains__ — all the read paths the addon and tests use."""
    assert "bws" in BACKEND_REGISTRY
    assert BACKEND_REGISTRY.get("nonexistent") is None
    assert "bws" in list(BACKEND_REGISTRY.keys())
    backend_cls, config_cls = BACKEND_REGISTRY["bws"]
    assert backend_cls.__name__ == "BitwardenBackend"
    assert config_cls.__name__ == "BwsConfig"


def test_fetch_context_dataclass_shape() -> None:
    """FetchContext is forward-compat; default-all-None construction works."""
    ctx = FetchContext()
    assert ctx.destination_host is None
    assert ctx.destination_method is None
    assert ctx.destination_path is None
    assert ctx.request_id is None


def test_fetch_context_is_frozen() -> None:
    """Backends must not mutate the context they receive (shared object
    semantics — would race across threads)."""
    ctx = FetchContext(destination_host="api.example.com")
    with pytest.raises(Exception):  # noqa: B017 — pydantic/dataclass raises different types
        ctx.destination_host = "evil.example.com"  # type: ignore[misc]


# ----------------------------------------------------------------------------
# Contract assertions — what every backend MUST satisfy.
#
# To add a new backend's contract suite, create
# tests/backends/test_<name>_contract.py with:
#
#     import pytest
#     from agent_vault_proxy.backends.<name> import <Name>Backend, <Name>Config
#     from tests.backends.test_protocol_contract import ProtocolContract
#
#     class TestMyBackendContract(ProtocolContract):
#         @pytest.fixture
#         def backend(self):
#             return <Name>Backend(...)  # mocked/in-process — no live API
# ----------------------------------------------------------------------------


class ProtocolContract:
    """Base contract suite. Subclass and provide a `backend` fixture."""

    @pytest.fixture
    def backend(self):
        raise NotImplementedError("subclass must provide `backend` fixture")

    def test_backend_is_runtime_protocol_instance(self, backend) -> None:
        assert isinstance(backend, SecretsBackend)

    def test_init_does_no_io(self, backend) -> None:
        """If construction triggered I/O, the fixture wouldn't have been
        able to construct a backend with mocked transport. This test
        documents the requirement — actual enforcement is by the fixture
        construction not failing under network isolation."""
        assert backend is not None

    def test_repr_does_not_include_token(self, backend) -> None:
        """repr() goes into tracebacks + logs. Token bytes must not."""
        rep = repr(backend)
        # Spot-check: no obvious token shapes. (Real defense lies in
        # SecretStr usage; this is a coarse sanity assertion.)
        forbidden = ["BWS_ACCESS_TOKEN", "access_token", "0.eyJ"]
        for needle in forbidden:
            assert needle not in rep, f"repr() leaked '{needle}': {rep}"

    def test_fetch_signature(self, backend) -> None:
        """fetch must accept (name) and (name, ctx) — forward-compat."""
        import inspect

        sig = inspect.signature(backend.fetch)
        params = list(sig.parameters.values())
        # First param: name (positional)
        assert params[0].name == "name"
        # Second param (if present): ctx with default None
        if len(params) > 1:
            assert params[1].default is None
