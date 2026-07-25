"""Unit tests for the wildcard-host `subdomains:` discriminator on BindingSpec
(ADR-0033): validation rules + the matches_host host gate."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_vault_proxy.config import BindingSpec


def test_matches_host_allows_listed_label() -> None:
    b = BindingSpec(host="*.jfrog.io", subdomains=["mycompany"])
    assert b.matches_host("mycompany.jfrog.io")


def test_matches_host_denies_unlisted_label() -> None:
    b = BindingSpec(host="*.jfrog.io", subdomains=["mycompany"])
    assert not b.matches_host("evil.jfrog.io")


def test_matches_host_denies_non_matching_suffix() -> None:
    b = BindingSpec(host="*.jfrog.io", subdomains=["mycompany"])
    assert not b.matches_host("mycompany.example.com")


def test_matches_host_case_insensitive_label() -> None:
    b = BindingSpec(host="*.jfrog.io", subdomains=["mycompany"])
    assert b.matches_host("MyCompany.JFrog.io")


def test_no_subdomains_matches_any_label() -> None:
    b = BindingSpec(host="*.jfrog.io")
    assert b.matches_host("anything.jfrog.io")


def test_subdomains_on_exact_host_rejected() -> None:
    with pytest.raises(ValidationError, match="only valid on a '\\*.' wildcard host"):
        BindingSpec(host="api.jfrog.io", subdomains=["mycompany"])


def test_empty_subdomains_rejected() -> None:
    with pytest.raises(ValidationError, match="deny-all-subdomains"):
        BindingSpec(host="*.jfrog.io", subdomains=[])


def test_subdomain_with_dot_rejected() -> None:
    with pytest.raises(ValidationError, match="single DNS label"):
        BindingSpec(host="*.jfrog.io", subdomains=["a.b"])


def test_subdomain_wildcard_label_rejected() -> None:
    with pytest.raises(ValidationError, match="single DNS label"):
        BindingSpec(host="*.jfrog.io", subdomains=["*"])


def test_subdomains_normalised_lowercase() -> None:
    b = BindingSpec(host="*.jfrog.io", subdomains=["MyCompany"])
    assert b.subdomains == ["mycompany"]
