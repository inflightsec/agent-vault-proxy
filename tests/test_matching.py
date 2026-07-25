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


# --- git smart-HTTP two-phase canonicalisation ---------------------------

from agent_vault_proxy.matching import git_smart_http_effective_path  # noqa: E402


def test_git_receive_pack_discovery_canonicalised_to_data_path() -> None:
    # A push discovery GET is rewritten to the data-phase path so a `paths:`
    # scope can tell it apart from a clone discovery.
    assert (
        git_smart_http_effective_path("/owner/repo.git/info/refs", "service=git-receive-pack")
        == "/owner/repo.git/git-receive-pack"
    )


def test_git_upload_pack_discovery_canonicalised() -> None:
    assert (
        git_smart_http_effective_path("/owner/repo.git/info/refs", "service=git-upload-pack")
        == "/owner/repo.git/git-upload-pack"
    )


def test_git_service_param_among_others() -> None:
    assert (
        git_smart_http_effective_path("/r.git/info/refs", "foo=bar&service=git-receive-pack")
        == "/r.git/git-receive-pack"
    )


def test_git_no_service_param_unchanged() -> None:
    # Dumb-HTTP / plain info/refs fetch: nothing to canonicalise.
    assert git_smart_http_effective_path("/r.git/info/refs", None) == "/r.git/info/refs"
    assert git_smart_http_effective_path("/r.git/info/refs", "") == "/r.git/info/refs"


def test_git_unknown_service_unchanged() -> None:
    # Only the two real git services are folded; anything else is left alone.
    assert git_smart_http_effective_path("/r.git/info/refs", "service=evil") == "/r.git/info/refs"


def test_git_duplicate_service_param_unchanged() -> None:
    # Ambiguous (two service values) → do not guess; leave unchanged.
    assert (
        git_smart_http_effective_path(
            "/r.git/info/refs", "service=git-upload-pack&service=git-receive-pack"
        )
        == "/r.git/info/refs"
    )


def test_non_git_path_unchanged() -> None:
    assert (
        git_smart_http_effective_path("/v1/chat/completions", "service=git-receive-pack")
        == "/v1/chat/completions"
    )
