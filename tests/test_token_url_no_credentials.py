"""ADR-0035: credentials-in-URL (``user:pass@host``) rejected at config-load.

The three token-minting injectors carry an operator-controlled egress URL
(``token_url`` for the oauth2 injectors, ``api_base_url`` for github_app). A
URL that embeds userinfo has it silently dropped on the wire; we reject it
loudly at config-load instead. Hermetic — the rejection fires in the
field_validator before any DNS / model-level SSRF resolution, so no network.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_vault_proxy.config_models import (
    GithubAppInjector,
    Oauth2ClientCredentialsInjector,
    Oauth2RefreshInjector,
)

_CREDS_URL = "https://user:pass@auth.example.com/token"


def test_oauth2_refresh_rejects_credentials_in_token_url() -> None:
    with pytest.raises(ValidationError, match="must not embed credentials"):
        Oauth2RefreshInjector(
            token_url=_CREDS_URL,
            client_auth_method="body_post",
            client_id_secret="CID",
            client_secret_secret="CSEC",
            refresh_token_secret="RT",
        )


def test_oauth2_client_credentials_rejects_credentials_in_token_url() -> None:
    with pytest.raises(ValidationError, match="must not embed credentials"):
        Oauth2ClientCredentialsInjector(
            token_url=_CREDS_URL,
            client_id_secret="CID",
            client_secret_secret="CSEC",
        )


def test_github_app_rejects_credentials_in_api_base_url() -> None:
    with pytest.raises(ValidationError, match="must not embed credentials"):
        GithubAppInjector(
            app_id="123",
            installation_id="456",
            private_key_secret="PK",
            api_base_url="https://user:pass@ghe.example.com",
        )


def test_username_only_credentials_rejected() -> None:
    # ``user@host`` (username, no password) is still userinfo — reject it.
    with pytest.raises(ValidationError, match="must not embed credentials"):
        Oauth2ClientCredentialsInjector(
            token_url="https://user@auth.example.com/token",
            client_id_secret="CID",
            client_secret_secret="CSEC",
        )


def test_clean_url_accepted() -> None:
    # No userinfo → passes config-load. oauth2_client_credentials does not run
    # the model-level SSRF resolution at load, so this stays hermetic.
    inj = Oauth2ClientCredentialsInjector(
        token_url="https://auth.example.com/token",
        client_id_secret="CID",
        client_secret_secret="CSEC",
    )
    assert str(inj.token_url).startswith("https://auth.example.com")
