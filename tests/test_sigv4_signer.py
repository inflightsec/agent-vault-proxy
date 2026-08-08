"""AWS SigV4 signer — verified against the AWS SigV4 test-suite vectors.

The `get-vanilla` case is AWS's own published conformance vector (credentials
AKIDEXAMPLE / us-east-1 / service / 20150830T123600Z); reproducing its exact
Signature proves the whole pipeline — canonical request, string-to-sign, signing
key derivation, and HMAC — is spec-correct. The remaining tests pin structural
behaviour (query canonicalisation, body hashing, session-token header).
"""

from __future__ import annotations

import hashlib

from kow.injectors.sigv4 import EMPTY_PAYLOAD_HASH, sign

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


def test_s3_get_matches_aws_published_header_auth_vector() -> None:
    # AWS's own worked S3 example from "Authenticating Requests: Using the
    # Authorization Header (AWS Signature Version 4)". Credentials
    # AKIAIOSFODNN7EXAMPLE / us-east-1 / s3, GET /test.txt with a Range header,
    # empty-body payload hash, x-amz-content-sha256 SIGNED. Reproducing its exact
    # Signature proves S3-shaped signing (content-sha256 in the signed set +
    # a client x-amz/other header folded in) is spec-correct.
    r = sign(
        method="GET",
        url="https://examplebucket.s3.amazonaws.com/test.txt",
        body=b"",
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="s3",
        amz_date="20130524T000000Z",
        sign_content_sha256=True,
        signed_headers_extra={"range": "bytes=0-9"},
    )
    assert r.content_sha256 == EMPTY_PAYLOAD_HASH
    assert r.authorization == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    )


def test_content_sha256_signed_only_when_requested() -> None:
    # Default off keeps the minimal (get-vanilla) set; opt-in adds it to the
    # signed header list and changes the signature.
    common = {
        "method": "PUT",
        "url": "https://examplebucket.s3.amazonaws.com/obj",
        "body": b"payload",
        "access_key_id": _AK,
        "secret_access_key": _SK,
        "region": "us-east-1",
        "service": "s3",
        "amz_date": _DATE,
    }
    off = sign(**common)
    on = sign(sign_content_sha256=True, **common)
    assert "x-amz-content-sha256" not in off.authorization
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in on.authorization
    assert on.authorization != off.authorization


def test_client_amz_headers_are_folded_into_the_signed_set() -> None:
    # An x-amz-* header the client set (e.g. x-amz-acl) MUST be signed, or AWS
    # rejects the request. AVP-computed headers still win on collision.
    r = sign(
        method="PUT",
        url="https://examplebucket.s3.amazonaws.com/obj",
        body=b"data",
        access_key_id=_AK,
        secret_access_key=_SK,
        region="us-east-1",
        service="s3",
        amz_date=_DATE,
        sign_content_sha256=True,
        signed_headers_extra={"x-amz-acl": "private", "x-amz-date": "SPOOFED"},
    )
    assert "SignedHeaders=host;x-amz-acl;x-amz-content-sha256;x-amz-date" in r.authorization
    # The client's attempt to pre-seed x-amz-date is overwritten, not signed.
    assert "SPOOFED" not in r.authorization


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
