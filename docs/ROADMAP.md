# Roadmap

Forward-looking work. Design records live in [`docs/adrs/`](adrs/); an entry
here means "intended, not yet shipped." No dates — priorities, not promises.

## Shipped

- `header`, `body`, `multi` injectors; composite `template + compose`.
- `oauth2_refresh` injector — RFC 6749 §6 refresh-token grant, per-token TTL
  cache, SSRF-guarded token endpoint, refresh-token rotation + write-back
  ([ADR-0017](adrs/ADR-0017-oauth2-refresh-injector.md)).
- Host-validation hardening — reject empty / bare-`*` / public-suffix
  wildcards; wildcard hosts opt-in (`allow_wildcard_hosts`).
- Config hot-reload — atomic snapshot/publish on `configure()`; in-flight
  requests keep their captured state, no restart needed.
- Supply-chain gates — hash-pinned lockfiles, TruffleHog secret scan,
  `pip-audit`, and a pre-release checklist.
- Honeytoken tripwire — a per-secret `honeytoken` flag emits a
  `honeytoken_triggered` audit event on any use of a planted placeholder
  ([ADR-0019](adrs/ADR-0019-off-box-audit-shipping.md), `accepted`). The
  off-box shipping half (Fluent Bit sidecar → central collector) lives in
  separate repos, not here.

## Planned

### Backends
- **Google Secret Manager backend** — second first-class backend alongside
  BWS ([ADR-0018](adrs/ADR-0018-gcp-secret-manager-backend.md), `proposed`).

### Security posture
- **Scope TLS termination to bound hosts** — today AVP TLS-terminates *every*
  destination the agent routes through it and injects only on bound hosts, so
  it decrypts traffic to hosts it never touches. Add a mitmproxy `next_layer`
  hook that does **TLS passthrough** for unbound destinations (intercept only
  what has a binding), shrinking the decryption surface to what injection
  actually needs. Warrants its own ADR.

### Supply chain
- **Artifact signing + SBOM** — the gates above cover *inputs*; still to add
  on *outputs*: sign released wheels/images (e.g. Sigstore/cosign) and publish
  an SBOM (CycloneDX/SPDX) so downstream consumers can verify provenance.

### Observability
- **Metrics endpoint** — the `/healthz` liveness/readiness probe has shipped
  (a request through the proxy to the reserved
  `healthz.agent-vault-proxy.invalid/healthz` sentinel returns `200` once AVP
  is fully configured, `503` while starting; the Docker healthcheck uses it).
  Still missing a Prometheus-style metrics surface (exchange counts, cache hit
  rate, deny reasons).

### Injector types (schema-reserved, not yet implemented)

These parse but fail config-load with a "not yet implemented" error until they ship.

| Type | Purpose |
|---|---|
| `github_app` | GitHub App installation-token minting |
| `oauth2_client_credentials` | RFC 6749 §4.4 client-credentials grant |
| `jwt_bearer` | RFC 7523 JWT bearer assertion |
| `sigv4` | AWS SigV4 request signing |
| `hmac` | Generic HMAC request signing |
