from __future__ import annotations

from agent_vault_proxy.matching import path_glob_matches


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
