---
status: accepted
date: 2026-07-26
relates_to: ADR-0027 (sigv4 injector — what this hardens), ADR-0028 (sibling hmac/jwt signers on the same seam), ADR-0018 (GSM backend — the "fetch-from-cloud" precedent an AWS backend would follow)
references:
  - AWS SigV4 signing spec (AWS4-HMAC-SHA256), https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
  - AWS S3 header-auth worked example (the ground-truth vector), https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
  - STS AssumeRole, https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
  - IAM Roles Anywhere, https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html
  - Container credential provider (ECS-style vending), https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html
  - Prior art: cyberark/secretless-broker AWS connector, awslabs/aws-sigv4-proxy, NVIDIA OpenShell aws-sigv4 provider
---

# ADR-0036: AWS auth hardening — content-sha256 correctness, STS-scoped signing credentials, and the vending escape hatch

> **Status: ACCEPTED (2026-07-26).** Phase 1 (S3 correctness) is **implemented and
> tested**. Decisions D1–D5 are resolved (Radek, 2026-07-26): STS-scoped signing
> is the next slice, bootstrapped from a rotated vaulted key (not Roles Anywhere
> yet); the vending escape hatch is rejected to keep AVP's core invariant absolute.
> ADR-0027 shipped the signer; this ADR closes the gap between "spec-correct
> signature" and "secure, real-world AWS support."

## Context

ADR-0027 shipped `inject.type: sigv4`: a pure `AWS4-HMAC-SHA256` signer plus a
`request`-hook resolver that re-signs a placeholder-seeded request so the AWS
credential never enters the agent's address space. It is spec-correct — pinned
byte-for-byte against AWS's own `get-vanilla` conformance vector — fail-closed
(503 on missing credential), no-leak (credentials never hit the audit log), and
STS-session-token aware.

That is the **right architecture**. Independent research confirms it is the same
pattern the strongest brokers use: CyberArk Secretless (its AWS connector strips
the client's `Authorization`, reads region+service from the credential scope, and
re-signs with the real key), Teleport's app-access proxy, NVIDIA OpenShell's
`aws-sigv4` provider ("the sandbox never sees the real credentials"), and
awslabs/aws-sigv4-proxy. By contrast, the 1Password shell-plugin model injects
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` straight into the agent's subprocess
env — the exposure AVP exists to remove. We are on the correct side of that line.

But "spec-correct signature" is not yet "secure AWS support for the services an
operator will actually reach." Three gaps remain:

### Gap 1 — S3 does not work (correctness bug in the flagship example) — FIXED

Before this ADR the signer signed the **minimal** header set `host;x-amz-date`.
It computed the payload hash and returned it as `Sigv4Result.content_sha256` — but
the resolver set only `Authorization`, `x-amz-date`, and optionally
`x-amz-security-token`. **It never emitted `x-amz-content-sha256`, and that header
was not in the signed set.**

AWS S3 (and several other services) **require** `x-amz-content-sha256` to be
present *and* signed. So `service: s3` — the headline example in ADR-0027,
`bindings.example.yaml`, and the tests — would have been rejected by real S3. The
e2e test used a `FakeBackend`, so this was never exercised against AWS.

**Fixed in Phase 1 (this ADR):** `sign()` gained `sign_content_sha256` (adds
`x-amz-content-sha256` to the signed set) and `signed_headers_extra` (folds in any
`x-amz-*` header the client's SDK already set — AWS rejects an *unsigned* `x-amz-*`
header, so a plain content-sha256 fix alone would still break `x-amz-acl` /
`x-amz-storage-class` uploads). The resolver now always signs and emits
`x-amz-content-sha256` and passes through the client's `x-amz-*` headers.
Correctness is pinned against **AWS's own published S3 header-auth worked example**
(`GET /test.txt`, `Range: bytes=0-9`, signature
`f0e8bdb8…6036bdb41`) — reproducing it byte-for-byte proves S3-shaped signing is
spec-correct, not merely internally consistent. (`test_sigv4_signer.py`,
`test_sigv4_addon_e2e.py`; full suite green.)

### Gap 2 — the proxy holds a static long-lived AWS key (weakest secure variant)

Today the operator stores `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` in BWS or
GSM, and AVP fetches those *long-lived* `AKIA…` values at signing time. Agent
isolation is intact, but the **proxy** now warehouses a non-expiring credential.
One proxy compromise leaks a forever-key. In the research ranking this is
option D ("sign-at-proxy with a static long-lived key") — acceptable as a v1
stepping stone, but strictly dominated by option A: the proxy signs with **STS
short-lived** credentials it refreshes itself (AssumeRole → 15 min–1 h creds,
downscoped per agent via session policies, `SourceIdentity` = agent id for
CloudTrail attribution), bootstrapped from IAM Roles Anywhere (X.509 key in
TPM/HSM — no static secret at rest anywhere) or a vaulted key it rotates.

### Gap 3 — no escape hatch for flows re-signing can't handle

Re-signing at the proxy structurally cannot cover: S3 **streaming/chunked**
uploads (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`), **presigned URLs**, and
**SigV4a** (multi-region, ECDSA). ADR-0027 already accepts the no-streaming
limitation (body is buffered; sigv4+body on one host is rejected at config-load).
The industry answer for these is a second mechanism: vend STS temp credentials to
the agent via the ECS-style container-credential endpoint
(`AWS_CONTAINER_CREDENTIALS_FULL_URI` + bearer token — honored natively by every
AWS SDK, auto-refreshing). That *does* put a short-lived credential in the agent,
so it is a deliberate, weaker fallback — but for presigned URLs and bulk uploads
there is no re-sign option.

### Non-gap, tracked separately — AWS as a *secrets backend*

AVP cannot fetch secrets *from* AWS Secrets Manager or SSM (only `bws`, `gsm`,
`static` are registered). `docs/adapter-architecture.md` already sketches an
`aws-secrets-manager` backend. This is a different axis (where credentials are
stored) from AWS *auth* (how AWS API calls are signed) and is out of scope here
except where Decision D3 makes it a dependency.

### Doc debt

`docs/architecture.md`, `CLAUDE.md`, and `AGENTS.md` still list AWS SigV4 as
out-of-scope / deferred — they predate the v0.9.0 ship and now contradict
`docs/ROADMAP.md` and the shipped code. This ADR's acceptance must reconcile them.

## Decision

Adopt a phased hardening. Phase 1 shipped with this ADR; Phases 2–3 are governed
by the resolved decisions below.

### Phase 1 — make signed AWS requests actually work — DONE

1. **Sign and emit `x-amz-content-sha256` on the request path, unconditionally.**
   Not per-service profiles — sending it is spec-valid for *every* service, so the
   resolver always sets it (`sign_content_sha256=True`). This is simpler than a
   service matrix and can't silently miss a service that needs it.
2. **Fold the client's `x-amz-*` headers into the signed set** (`signed_headers_extra`).
   AWS rejects a request that carries an unsigned `x-amz-*` header, so a
   content-sha256 fix alone would still break real S3 writes (`x-amz-acl`,
   `x-amz-storage-class`, …). AVP-computed headers win on collision (a client can't
   pre-seed a spoofed `x-amz-date`).
3. **Ground-truth test.** Pinned against AWS's published S3 header-auth worked
   example, not a self-generated vector — botocore was unavailable offline, and an
   external authoritative signature is stronger evidence than internal consistency.

### Phase 2 — the signing-credential source — ACCEPTED, next slice

- **D1 [RESOLVED: yes].** Move from static-key signing (option D) to STS-scoped
  signing (option A): AVP calls `sts:AssumeRole` itself, caches the short-lived
  creds, signs with those, and refreshes before expiry — so the material at rest in
  the proxy is short-lived and downscoped, not a forever-key. Downscope per agent
  with session policies; set `SourceIdentity` = agent id for CloudTrail attribution.
- **D2 [RESOLVED: (c) rotated vaulted key, for now].** Bootstrap the proxy's AWS
  identity from a vaulted static key AVP rotates on a schedule (Vault `rotate-root`
  pattern) — *not* IAM Roles Anywhere yet. Rationale: Radek's fleet (mainframe /
  SecOps VPS / Martian) is not AWS-hosted, so no instance profile; standing up a CA
  for Roles Anywhere is not justified until AVP has real users. Roles Anywhere stays
  the documented upgrade path (revisit at first AWS-heavy customer).

### Phase 3 — the vending escape hatch — REJECTED

- **D4 [RESOLVED: no].** Do **not** add an ECS-style credential-vending endpoint.
  It would hand the agent a short-lived credential, breaking the invariant AVP is
  built on ("the agent never holds any AWS credential"). Keep the invariant
  absolute. Presigned URLs, streaming/chunked S3 uploads, and SigV4a are documented
  as **unsupported** rather than served by weakening the model. Revisit only if a
  concrete need outweighs the invariant.

### Cross-cutting

- **D3 [RESOLVED: deferred].** Do not ship the AWS Secrets Manager / SSM *backend*
  now. AWS credentials live in BWS or GSM and are referenced by name; a fetch-from-
  AWS backend is a separate axis with no current demand. Reopen if a customer needs
  AWS-native storage, or if Phase 2's rotation logic ends up wanting to read the
  vaulted key from AWS.
- **D5 [RESOLVED: Phase 1 now; Phase 2 as a follow-up slice].** Ship the S3
  correctness fix immediately (done); STS-scoped signing lands as its own release
  once the AssumeRole config surface + session cache are built and tested.

## Consequences

**Good**
- Phase 1 turns the flagship S3 example from aspirational to working, and is a
  self-contained correctness fix with a conformance vector.
- Phase 2 (if adopted) moves us from the weakest secure variant to the strongest:
  no long-lived AWS secret at rest, per-agent downscoping, per-call CloudTrail
  attribution — and the proxy becomes a per-request AWS policy enforcement point,
  which is impossible once credentials leave a broker.
- Keeps AVP on the correct side of the 1Password line: the agent still holds no
  long-lived credential in every path except the deliberate D4 escape hatch.

**Bad / cost**
- Phase 2 is real engineering: an STS session cache, refresh-before-expiry,
  AssumeRole config surface (role ARN, session policy, duration, external id),
  and a bootstrap mechanism. Roles Anywhere additionally means running a CA.
- Per-service header profiles are a maintenance surface — each AWS service's
  signing quirks (S3 content-sha256, some services signing the security token,
  etc.) is a small compatibility matrix we now own.
- D4, if adopted, reintroduces a (short-lived, scoped) credential into the agent
  for specific flows — a deliberate, documented weakening of the core invariant.

**Out of scope**
- SigV4a (ECDSA multi-region) signing at the proxy — vend-only (D4) if ever.
- General agent egress filtering — network-layer agent-firewall model, not AVP's
  job (`docs/comparison.md`).

## References

- ADR-0027 (the signer), ADR-0028 (sibling signers), ADR-0018 (GSM backend).
- `src/agent_vault_proxy/injectors/sigv4.py`, `backends/__init__.py`,
  `docs/adapter-architecture.md`.
- AWS SigV4 / STS AssumeRole / Roles Anywhere / container-credential-provider
  docs (front-matter). Prior art: cyberark/secretless-broker AWS connector,
  awslabs/aws-sigv4-proxy, NVIDIA OpenShell aws-sigv4 provider.
