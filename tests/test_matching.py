from __future__ import annotations

from agent_vault_proxy.matching import host_matches_pattern, path_glob_matches


def test_host_exact_match() -> None:
    assert host_matches_pattern("api.openai.com", "api.openai.com")


def test_host_case_insensitive_request_side() -> None:
    """DNS is case-insensitive: a mixed-case request host must match a
    lowercase binding. Reviewer-flagged operator footgun otherwise."""
    assert host_matches_pattern("API.OpenAI.com", "api.openai.com")


def test_host_case_insensitive_pattern_side() -> None:
    """Belt and suspenders: even if config-load somehow let an uppercase
    pattern through, match-time normalisation still works."""
    assert host_matches_pattern("api.openai.com", "API.OPENAI.COM")


def test_host_wildcard_case_insensitive() -> None:
    assert host_matches_pattern("API.Claude.com", "*.claude.com")


def test_host_wildcard_no_match_root() -> None:
    assert not host_matches_pattern("claude.com", "*.claude.com")


def test_host_wildcard_single_label_only() -> None:
    assert host_matches_pattern("api.claude.com", "*.claude.com")
    assert not host_matches_pattern("a.b.claude.com", "*.claude.com")


def test_exact_match() -> None:
    assert path_glob_matches("/repos/foo", "/repos/foo")


def test_no_match_different_path() -> None:
    assert not path_glob_matches("/repos/foo", "/repos/bar")


def test_single_star_matches_one_segment() -> None:
    assert path_glob_matches("/repos/*", "/repos/foo")


def test_single_star_does_not_cross_slash() -> None:
    """Critical anti-footgun: `/repos/*` must NOT match `/repos/foo/bar`,
    otherwise an operator scoping to `/repos/*` would silently allow nested
    paths they didn't intend (e.g., `/repos/owner/name/contents/secrets`)."""
    assert not path_glob_matches("/repos/*", "/repos/foo/bar")


def test_double_star_crosses_slashes() -> None:
    assert path_glob_matches("/repos/**", "/repos/foo/bar/baz")


def test_double_star_matches_zero_segments() -> None:
    assert path_glob_matches("/repos/**", "/repos/")


def test_star_in_middle() -> None:
    assert path_glob_matches("/repos/*/issues", "/repos/foo/issues")
    assert not path_glob_matches("/repos/*/issues", "/repos/foo/bar/issues")


def test_double_star_in_middle() -> None:
    assert path_glob_matches("/repos/**/issues", "/repos/foo/bar/issues")
