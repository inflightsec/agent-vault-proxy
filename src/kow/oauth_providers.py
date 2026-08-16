"""Bundled OAuth2 provider presets for the ``oauth2_refresh`` injector.

Each entry supplies the well-known token endpoint and client-auth method
for one provider so operators can write ``provider: <name>`` instead of
hand-copying URLs and RFC 6749 §2.3 nuances. The catalog is small on
purpose — a new entry lands when a concrete operator binding needs it,
not on speculation (see ADR-0017 §9, "Backfill discipline").

The single source of truth for the closed list of provider names is the
``Literal[...]`` annotation on
``kow.config.Oauth2RefreshInjector.provider``. The keys in
:data:`PROVIDER_PRESETS` must be a superset of that literal — enforced
at module load.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# When provider is tenant-specific (Auth0, Okta), token_url is None and the
# operator MUST supply it explicitly alongside `provider:`. The preset
# still contributes the auth method.
ProviderName = Literal["google", "microsoft", "auth0", "slack", "atlassian", "okta"]


@dataclass(frozen=True)
class ProviderPreset:
    """One provider's known-good defaults.

    ``token_url`` is None for tenant-specific providers; in that case the
    operator supplies it. ``client_auth_method`` reflects the provider's
    documented preference under RFC 6749 §2.3.
    """

    token_url: str | None
    client_auth_method: Literal["body_post", "basic"]
    # ``rotates_refresh_token`` is consulted by ``kow doctor --probe-oauth``
    # to set operator expectations. False = the provider re-issues the
    # same refresh token on each grant by default; True = a new one each
    # time and the write-back path is the load-bearing surface.
    rotates_refresh_token: bool
    # ADR-0042: the ``kow oauth login`` bootstrap reads these. Optional so existing
    # oauth2_refresh presets are untouched; backfilled per concrete binding, never speculatively.
    authorization_endpoint: str | None = None
    device_authorization_endpoint: str | None = None
    default_scopes: str | None = None


# The Bandit/Ruff S106 rule treats the kwarg name ``token_url`` as a
# password-like assignment. These are public OAuth2 token endpoint URLs,
# not secrets. Suppressed inline rather than excluding the rule globally.
PROVIDER_PRESETS: dict[ProviderName, ProviderPreset] = {
    "google": ProviderPreset(
        token_url="https://oauth2.googleapis.com/token",  # noqa: S106  # nosec B106
        client_auth_method="body_post",
        authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",  # noqa: S106  # nosec B106
        device_authorization_endpoint="https://oauth2.googleapis.com/device/code",  # noqa: S106  # nosec B106
        rotates_refresh_token=False,
    ),
    "microsoft": ProviderPreset(
        token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",  # noqa: S106  # nosec B106
        client_auth_method="body_post",
        rotates_refresh_token=True,
    ),
    "auth0": ProviderPreset(
        token_url=None,  # tenant-specific: https://<tenant>.auth0.com/oauth/token
        client_auth_method="basic",
        rotates_refresh_token=True,
    ),
    "slack": ProviderPreset(
        token_url="https://slack.com/api/oauth.v2.access",  # noqa: S106  # nosec B106
        client_auth_method="basic",
        rotates_refresh_token=True,
    ),
    "atlassian": ProviderPreset(
        token_url="https://auth.atlassian.com/oauth/token",  # noqa: S106  # nosec B106
        client_auth_method="body_post",
        rotates_refresh_token=True,
    ),
    "okta": ProviderPreset(
        token_url=None,  # tenant-specific: https://<tenant>.okta.com/oauth2/v1/token
        client_auth_method="basic",
        rotates_refresh_token=True,
    ),
}
