"""Loopback TLS test helpers for pinned-transport coverage (ADR-0035).

Mints a throwaway CA + leaf cert (SAN = a DNS hostname, deliberately NO IP SAN)
and runs a real HTTPS server on ``127.0.0.1``. Tests point the pinned transport
at the loopback IP with ``server_hostname`` = the hostname, so a real TLS
handshake exercises the "dial the IP, verify the cert against the hostname" wiring.
Loopback only — no external network.
"""

from __future__ import annotations

import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class LoopbackTLSServer:
    """A running loopback HTTPS server plus a client context that trusts its
    self-signed CA. ``port`` + ``client_context`` are everything a test needs to
    point the pinned transport at ``127.0.0.1`` under hostname verification."""

    port: int
    client_context: ssl.SSLContext


def make_trusting_context(ca_pem: str) -> ssl.SSLContext:
    """A default client context (``check_hostname=True``, ``CERT_REQUIRED``) that
    trusts ONLY the supplied CA PEM."""
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cadata=ca_pem)
    return ctx


def _issue_ca_and_leaf(tmp_path: Path, hostname: str) -> tuple[str, Path, Path]:
    """Mint a throwaway CA and a leaf cert whose ONLY SAN is ``DNS:hostname`` (no
    IP SAN — so a cert-checked-against-the-IP wiring bug is guaranteed to fail)."""
    now = datetime.now(UTC)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AVP Test CA")])
    # KeyUsage(keyCertSign) + SubjectKeyIdentifier are required for RFC 5280
    # compliance. Python 3.13's ssl.create_default_context() enables
    # VERIFY_X509_STRICT by default, which rejects a CA that omits them
    # ("Missing Authority Key Identifier" at the leaf); 3.12 tolerated it.
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        # BasicConstraints(CA:FALSE) + KeyUsage + EKU(serverAuth) +
        # Subject/Authority KeyIdentifier: RFC 5280 essentials the leaf needs so
        # Python 3.13's default VERIFY_X509_STRICT accepts the chain. The AKID
        # (from the CA's public key) is the specific extension whose absence
        # broke the 3.13 CI job.
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    cert_path = tmp_path / f"{hostname}.crt.pem"
    key_path = tmp_path / f"{hostname}.key.pem"
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_pem, cert_path, key_path


@contextmanager
def run_loopback_tls_http_server(
    tmp_path: Path,
    handler: type[BaseHTTPRequestHandler],
    *,
    hostname: str = "pinned.test",
) -> Iterator[LoopbackTLSServer]:
    """Start an HTTPS server on ``127.0.0.1:0`` with a self-signed cert whose SAN
    is ``hostname``. Yields the bound port and a CA-trusting client context, then
    tears the server down on exit."""
    ca_pem, cert_path, key_path = _issue_ca_and_leaf(tmp_path, hostname)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    server = HTTPServer(("127.0.0.1", 0), handler)
    server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield LoopbackTLSServer(
            port=server.server_port,
            client_context=make_trusting_context(ca_pem),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
