---
status: accepted
date: 2026-07-20
relates_to: ADR-0027 (sigv4 injector — established the computed-signing request-hook seam these reuse), docs/architecture.md §4.2 (request path), docs/ROADMAP.md (Injector types — hmac, jwt_bearer)
references:
  - RFC 2104 (HMAC)
  - RFC 7519 (JWT), RFC 7515 (JWS), RFC 7518 (JWA — ES256 raw R||S), RFC 7523 (JWT bearer)
---

# ADR-0028: `hmac` and `jwt_bearer` signing injectors

> **Status: ACCEPTED (2026-07-20).** Implemented + tested end to end.

## Context

ADR-0027 (SigV4) introduced the *signing* injector and the request-hook seam it needs (a computed
value that may cover the request body, resolved after the body buffers). Two more of the common
authentication mechanisms sit on that same seam:

- **HMAC request signing (RFC 2104).** Many APIs and webhook schemes authenticate a request with an
  `HMAC-<hash>` of some canonical string over request parts, in a header. The *what-is-signed* differs
  per service, so this is a generic primitive, not one algorithm.
- **JWT bearer (RFC 7519/7515).** APIs and RFC 7523 flows that accept a self-signed JWT need a signed
  token minted from a vault-held key and injected as a bearer credential.

With these plus SigV4, OAuth2-refresh, and static header/body, AVP covers the major mechanisms an
autonomous agent hits — none of which require the real credential to enter the agent's process.

## Decision

Ship `inject.type: hmac` and `inject.type: jwt_bearer`, both reusing the ADR-0027 request-hook seam
(detected + stashed at `requestheaders`, resolved in the addon `request` hook; the `Decision` carries
`hmac_injector` / `jwt_injector`).

**`hmac`.** Config: `secret_key_secret` (vault HMAC key), `signing_string` (a template over the fixed
token set `{method}` `{path}` `{query}` `{host}` `{body_sha256}` `{timestamp}`, substituted by literal
`str.replace` — never a format language), `header` (output), `algorithm` (`sha256` default / sha1 /
sha384 / sha512), `encoding` (`hex` default / base64), optional `timestamp_header` (emits the unix
timestamp used, so the server can bound request age). The signer does **no** service-specific
canonicalisation beyond the token substitution — the operator owns the scheme. Body-hashing when the
template uses `{body_sha256}`, so it signs in the request hook over the raw wire bytes.

**`jwt_bearer`.** Config: `signing_key_secret` (an HMAC secret for `HS256`, a PEM private key for
`RS256`/`ES256`), `algorithm`, `issuer`/`subject`/`audience` (iss/sub/aud), `ttl_seconds`
(iat = request time, exp = iat + ttl), optional `extra_claims`, `header` + `format` (`Bearer {jwt}`).
Mints a compact JWS; `ES256` emits the raw fixed-width R||S signature (RFC 7518 §3.4), not the DER the
crypto library returns. JWT does not read the body but rides the same request-hook seam for a single
computed-injector dispatch.

Shared design:

1. **Placeholder = detection trigger.** As with sigv4/oauth2, the operator plants the secret's
   `placeholder` in the target header; the value is computed, not substituted. `compose:` is rejected.
2. **Fail-closed.** A key-fetch failure (or a JWT signing error — bad key / algorithm mismatch) denies
   with 503 and audits `inject_decision` / `secret_unavailable` / `jwt_signing_error`. No new event
   type — the happy path reuses `inject_decision` / `binding_matched`.
3. **Body-conflict guard extends to hmac.** A host bound to both a body-hashing signer (sigv4 **or**
   hmac) and a `body` injector is rejected at config-load — the body streamer would corrupt the bytes
   the signer must hash. `jwt_bearer` does not read the body and is exempt.
4. **Pure signers, verifiable.** The signing cores are pure and pinned to public vectors (see below);
   the RSA/EC signing uses the `cryptography` library the daemon already requires — no new dependency.

## Consequences

**Good** — covers HMAC-signed APIs/webhooks and self-signed-JWT APIs, keeping their keys in the vault.
The request-hook seam now hosts three signing injectors with one dispatch; `oauth2_client_credentials`
and `github_app` (the remaining reserved types) can follow.

**Cost / accepted** — a `{body_sha256}` HMAC and any request-hook signer buffer the body (bounded by
request size; fine for API calls). JWT buffers the body it does not use, the price of one seam. The
HMAC `signing_string` is operator-owned — a wrong template produces a signature the service rejects
(the operator's responsibility, like any credential scope).

## Test strategy

- **Signers (pinned to public vectors):** HMAC-SHA256 against the well-known `key` / "quick brown fox"
  vector; JWT `HS256` against the canonical jwt.io example, byte-for-byte; `RS256`/`ES256` as
  mint-and-verify round-trips against the matching public key (`ES256` asserts the 64-byte raw R||S).
- **End to end through the addon:** a placeholder in the target header toward a bound host emerges
  HMAC-signed (exact signature recomputed) or carrying a verifiable `Bearer <jwt>` (claims + signature
  checked); the timestamp header is emitted; a missing key fails closed with 503; the signing key
  never appears in the audit log.
