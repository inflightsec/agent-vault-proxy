"""Synthetic-config builders for the hot-path benchmarks."""

from __future__ import annotations

from kow.config import Config

# Fixed-width ids so no placeholder can be a substring of another
# (validate_placeholder_invariants rejects that).
_PH = "sk-PLACEHOLDER-{i:05d}-benchmarkpad"


def build_config(n_secrets: int, *, shared_header_ratio: float = 0.5) -> Config:
    """A config with ``n_secrets`` header-injecting secrets.

    ``shared_header_ratio`` of them target ``Authorization`` (the common real
    shape — every Bearer key lands there); the rest get distinct headers.
    """
    shared = int(n_secrets * shared_header_ratio)
    secrets: dict[str, dict] = {}
    for i in range(n_secrets):
        name = f"SECRET_{i:05d}"
        header = "Authorization" if i < shared else f"X-Api-Key-{i:05d}"
        secrets[name] = {
            "placeholder": _PH.format(i=i),
            "inject": {"header": header, "format": "Bearer {" + name + "}"},
            "bindings": [{"host": f"api{i % 16}.example.com"}],
        }
    return Config.model_validate(
        {
            "version": 1,
            "secrets": secrets,
            "audit": {"path": "/dev/null"},
        }
    )


def header_getter(headers: dict[str, str]):
    """mitmproxy-style case-insensitive accessor."""
    lowered = {k.lower(): v for k, v in headers.items()}
    return lambda name: lowered.get(name.lower())
