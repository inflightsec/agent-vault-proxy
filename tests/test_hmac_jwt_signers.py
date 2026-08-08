"""HMAC + JWT-bearer signer cores — verified against public vectors.

HMAC-SHA256 is pinned to the well-known ``key`` / "quick brown fox" vector; JWT
HS256 to the canonical jwt.io example (byte-for-byte). RS256 / ES256 are mint +
verify round-trips against the matching public key (the only correctness proof
that doesn't depend on a fixed key pair).
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from kow.injectors.hmac_signer import build_signing_string, hmac_sign
from kow.injectors.jwt_bearer import encode


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def test_hmac_sha256_public_vector() -> None:
    # Wikipedia HMAC-SHA256 test vector.
    out = hmac_sign(
        key="key",
        signing_string="The quick brown fox jumps over the lazy dog",
        algorithm="sha256",
        encoding="hex",
    )
    assert out == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"


def test_hmac_base64_encoding_differs_from_hex() -> None:
    hexed = hmac_sign(key="k", signing_string="m", algorithm="sha256", encoding="hex")
    b64 = hmac_sign(key="k", signing_string="m", algorithm="sha256", encoding="base64")
    assert bytes.fromhex(hexed) == base64.b64decode(b64)


def test_build_signing_string_substitutes_request_tokens() -> None:
    s = build_signing_string(
        "{method}\n{path}\n{query}\n{host}\n{timestamp}\n{body_sha256}",
        method="POST",
        path="/v1/x",
        query="a=1",
        host="api.example.com",
        body=b"",
        timestamp="1700000000",
    )
    lines = s.split("\n")
    assert lines[:5] == ["POST", "/v1/x", "a=1", "api.example.com", "1700000000"]
    # empty-body sha256
    assert lines[5] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_jwt_hs256_matches_jwt_io_vector() -> None:
    jwt = encode(
        payload={"sub": "1234567890", "name": "John Doe", "iat": 1516239022},
        key="your-256-bit-secret",
        algorithm="HS256",
    )
    assert jwt == (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )


def test_jwt_rs256_round_trip() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    jwt = encode(
        payload={"iss": "avp", "sub": "svc", "exp": 9999999999}, key=pem, algorithm="RS256"
    )
    header, payload, sig = jwt.split(".")
    key.public_key().verify(
        _b64url_decode(sig), f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()
    )


def test_jwt_es256_round_trip_raw_rs() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    jwt = encode(payload={"iss": "avp"}, key=pem, algorithm="ES256")
    header, payload, sig = jwt.split(".")
    raw = _b64url_decode(sig)
    assert len(raw) == 64  # P-256 raw R||S, not DER
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    key.public_key().verify(
        encode_dss_signature(r, s), f"{header}.{payload}".encode(), ec.ECDSA(hashes.SHA256())
    )


def test_jwt_unknown_algorithm_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported jwt_bearer algorithm"):
        encode(payload={"iss": "x"}, key="k", algorithm="none")
