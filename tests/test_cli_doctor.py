"""``avp doctor`` CA regression checks (ADR-0012 delta).

Two read-only checks guard the narrow-trust CA invariants ADR-0012 makes
hard:

1. **CA must NOT be in any OS/browser trust store.** Adding the AVP CA to
   the system store turns the proxy net-negative (same-UID malware can mint
   certs for any host). ``avp doctor`` WARNs if the CA cert appears in a
   known trust-store location — a regression guard so a future install can
   never silently re-add it.
2. **CA private key perms.** The key must be owner-only (0600) inside a
   0700 confdir, owned by the service user. ``avp doctor`` WARNs on any
   group/other-readable key or a loose confdir.

Both are advisory, read-only, and never mutate the trust store.
"""

from __future__ import annotations

import os

from agent_vault_proxy.cli.doctor import (
    check_ca_key_perms,
    check_ca_not_in_trust_store,
    run_doctor,
)


def _make_ca_files(tmp_path, *, key_mode=0o600, dir_mode=0o700):
    confdir = tmp_path / ".mitmproxy"
    confdir.mkdir(mode=dir_mode)
    cert = confdir / "mitmproxy-ca-cert.pem"
    key = confdir / "mitmproxy-ca.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----\nDEADBEEF\n-----END CERTIFICATE-----\n")
    key.write_text("-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n")
    os.chmod(key, key_mode)
    os.chmod(confdir, dir_mode)
    return confdir, cert, key


# --------------------------------------------------------------------------
# CA key perms
# --------------------------------------------------------------------------


def test_ca_key_perms_clean_when_0600_in_0700_dir(tmp_path) -> None:
    confdir, _cert, key = _make_ca_files(tmp_path)
    warnings = check_ca_key_perms(str(key))
    assert warnings == []


def test_ca_key_perms_warns_on_group_readable_key(tmp_path) -> None:
    confdir, _cert, key = _make_ca_files(tmp_path, key_mode=0o640)
    warnings = check_ca_key_perms(str(key))
    assert warnings
    assert any("0600" in w or "perm" in w.lower() for w in warnings)


def test_ca_key_perms_warns_on_world_readable_key(tmp_path) -> None:
    confdir, _cert, key = _make_ca_files(tmp_path, key_mode=0o644)
    warnings = check_ca_key_perms(str(key))
    assert warnings


def test_ca_key_perms_warns_on_loose_confdir(tmp_path) -> None:
    confdir, _cert, key = _make_ca_files(tmp_path, dir_mode=0o755)
    warnings = check_ca_key_perms(str(key))
    assert warnings
    assert any("0700" in w or "directory" in w.lower() for w in warnings)


def test_ca_key_perms_silent_when_key_absent(tmp_path) -> None:
    """A not-yet-generated CA (key file absent) is not an error — mitmproxy
    creates it on first proxied request. Silent skip."""
    key = tmp_path / ".mitmproxy" / "mitmproxy-ca.pem"
    assert check_ca_key_perms(str(key)) == []


# --------------------------------------------------------------------------
# CA not in trust store
# --------------------------------------------------------------------------


def test_ca_not_in_trust_store_clean_when_absent(tmp_path) -> None:
    _confdir, cert, _key = _make_ca_files(tmp_path)
    # No trust-store dirs supplied -> nothing to find -> clean.
    warnings = check_ca_not_in_trust_store(str(cert), trust_store_paths=[])
    assert warnings == []


def test_ca_not_in_trust_store_warns_when_cert_present(tmp_path) -> None:
    """If the CA cert bytes appear in a scanned trust-store file, warn."""
    _confdir, cert, _key = _make_ca_files(tmp_path)
    store_dir = tmp_path / "ca-trust"
    store_dir.mkdir()
    # Simulate the CA having been added to a system store: a file containing
    # the same PEM bytes.
    (store_dir / "anchors.pem").write_text(cert.read_text())
    warnings = check_ca_not_in_trust_store(str(cert), trust_store_paths=[str(store_dir)])
    assert warnings
    assert any("trust store" in w.lower() for w in warnings)


def test_ca_not_in_trust_store_clean_when_other_certs_present(tmp_path) -> None:
    """An unrelated cert in the store must NOT trigger a false positive."""
    _confdir, cert, _key = _make_ca_files(tmp_path)
    store_dir = tmp_path / "ca-trust"
    store_dir.mkdir()
    (store_dir / "other.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nUNRELATED\n-----END CERTIFICATE-----\n"
    )
    warnings = check_ca_not_in_trust_store(str(cert), trust_store_paths=[str(store_dir)])
    assert warnings == []


def test_ca_not_in_trust_store_silent_when_ca_cert_absent(tmp_path) -> None:
    """No AVP CA cert generated yet -> nothing to match -> silent."""
    cert = tmp_path / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    warnings = check_ca_not_in_trust_store(str(cert), trust_store_paths=[str(tmp_path)])
    assert warnings == []


def test_ca_cert_unreadable_is_treated_as_absent(tmp_path) -> None:
    """An unreadable CA cert path (here: a directory) is skipped, not a
    traceback — same contract as a missing cert."""
    # Passing a directory makes read_text raise IsADirectoryError (OSError).
    warnings = check_ca_not_in_trust_store(str(tmp_path), trust_store_paths=[str(tmp_path)])
    assert warnings == []


def test_trust_store_scan_skips_missing_dirs_and_unreadable_files(tmp_path) -> None:
    """A non-existent store path is skipped; an unreadable file in a real
    store dir is skipped rather than crashing the scan."""
    _confdir, cert, _key = _make_ca_files(tmp_path)
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    unreadable = store_dir / "locked.pem"
    unreadable.write_text("whatever")
    os.chmod(unreadable, 0o000)
    try:
        warnings = check_ca_not_in_trust_store(
            str(cert),
            trust_store_paths=[str(tmp_path / "does-not-exist"), str(store_dir)],
        )
        assert warnings == []
    finally:
        os.chmod(unreadable, 0o600)  # let tmp cleanup remove it


# --------------------------------------------------------------------------
# run_doctor (exit-code + output contract)
# --------------------------------------------------------------------------


def test_run_doctor_returns_0_and_prints_pass_when_clean(tmp_path, capsys) -> None:
    absent_cert = tmp_path / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    absent_key = tmp_path / ".mitmproxy" / "mitmproxy-ca.pem"
    rc = run_doctor(ca_cert_path=str(absent_cert), ca_key_path=str(absent_key))
    assert rc == 0
    assert "passed" in capsys.readouterr().out


def test_run_doctor_returns_1_and_reports_warnings(tmp_path, capsys) -> None:
    _confdir, _cert, key = _make_ca_files(tmp_path, key_mode=0o640)
    absent_cert = tmp_path / "nope-cert.pem"
    rc = run_doctor(ca_cert_path=str(absent_cert), ca_key_path=str(key))
    assert rc == 1
    err = capsys.readouterr().err
    assert "warning" in err.lower()
