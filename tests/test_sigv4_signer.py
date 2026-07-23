"""AWS SigV4 signer — verified against the AWS SigV4 test-suite vectors.

The `get-vanilla` case is AWS's own published conformance vector (credentials
AKIDEXAMPLE / us-east-1 / service / 20150830T123600Z); reproducing its exact
Signature proves the whole pipeline — canonical request, string-to-sign, signing
key derivation, and HMAC — is spec-correct. The remaining tests pin structural
behaviour (query canonicalisation, body hashing, session-token header).
"""

from __future__ import annotations

import hashlib

from agent_vault_proxy.injectors.sigv4 import EMPTY_PAYLOAD_HASH, sign

_AK = "AKIDEXAMPLE"
_SK = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
_DATE = "20150830T123600Z"


def test_get_vanilla_matches_aws_test_suite_vector() -> None:
    r = sign(
        method="GET",
        url="https://example.amazonaws.com/",
        body=b"",
        access_key_id=_AK,
        secret_access_key=_SK,
        region="us-east-1",
        service="service",
        amz_date=_DATE,
    )
    assert r.authorization == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    )
    assert r.amz_date == _DATE
    assert r.content_sha256 == EMPTY_PAYLOAD_HASH
    assert r.security_token is None


def test_empty_body_uses_the_empty_sha256_constant() -> None:
    assert hashlib.sha256(b"").hexdigest() == EMPTY_PAYLOAD_HASH


def test_body_changes_signature_and_content_hash() -> None:
    common = {
        "method": "POST",
        "url": "https://example.amazonaws.com/",
        "access_key_id": _AK,
        "secret_access_key": _SK,
        "region": "us-east-1",
        "service": "service",
        "amz_date": _DATE,
    }
    empty = sign(body=b"", **common)
    full = sign(body=b'{"k":"v"}', **common)
    assert full.content_sha256 == hashlib.sha256(b'{"k":"v"}').hexdigest()
    assert full.content_sha256 != empty.content_sha256
    # Body is part of the canonical request, so the signature must differ.
    assert full.authorization != empty.authorization


def test_query_is_canonicalised_order_independent() -> None:
    # Same query, different textual order -> identical signature (AWS sorts).
    common = {
        "method": "GET",
        "body": b"",
        "access_key_id": _AK,
        "secret_access_key": _SK,
        "region": "us-east-1",
        "service": "service",
        "amz_date": _DATE,
    }
    a = sign(url="https://example.amazonaws.com/?Param1=v1&Param2=v2", **common)
    b = sign(url="https://example.amazonaws.com/?Param2=v2&Param1=v1", **common)
    assert a.authorization == b.authorization
    # ...but a different query value must change the signature.
    c = sign(url="https://example.amazonaws.com/?Param1=vX&Param2=v2", **common)
    assert c.authorization != a.authorization


def test_session_token_is_signed() -> None:
    r = sign(
        method="GET",
        url="https://example.amazonaws.com/",
        body=b"",
        access_key_id=_AK,
        secret_access_key=_SK,
        region="us-east-1",
        service="service",
        amz_date=_DATE,
        session_token="FQoGZ...SESSION",
    )
    # temp creds add x-amz-security-token to the SIGNED header set.
    assert "x-amz-security-token" in r.authorization
    assert "SignedHeaders=host;x-amz-date;x-amz-security-token" in r.authorization
    assert r.security_token == "FQoGZ...SESSION"


def test_default_ports_are_omitted_from_host() -> None:
    # Host header used in the signature must not carry the default port, or the
    # service's own canonicalisation won't match.
    r = sign(
        method="GET",
        url="https://example.amazonaws.com:443/",
        body=b"",
        access_key_id=_AK,
        secret_access_key=_SK,
        region="us-east-1",
        service="service",
        amz_date=_DATE,
    )
    # identical to the no-port get-vanilla signature
    assert r.authorization.endswith(
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    )
