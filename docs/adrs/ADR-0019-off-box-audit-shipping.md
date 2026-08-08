---
status: accepted
date: 2026-07-02
implemented: 2026-07-03
relates_to: docs/architecture.md (§4.1 process layout, §4.4 audit log, G4/G5/G6), ADR-0017 (audit event addition precedent), ADR-0011 (BWS-notes bindings)
---

# ADR-0019: Off-box audit shipping + honeytoken tripwire

> **Accepted + implemented 2026-07-03.** This ADR records the decision to forward AVP's audit
> stream off each host to a central collector, and to add a first-class honeytoken binding flag
> so a planted credential's use lights up fleet-wide. The design sections below are written in
> the future tense of the original proposal; the implementation is in the tree.
>
> **Built 2026-07-03.** Landed: audit contract v3 + the `honeytoken_triggered` event
> (`audit.py`), the per-secret `honeytoken` flag (`config.py`), the Fluent Bit shipper via the
> `kow_shipper` selector — with an `kow_shipper_extra_outputs`
> passthrough for hosted log services (Datadog, Splunk, Elasticsearch, …) and first-class GCP
> Cloud Logging — in the Ansible role, and the `avp-audit-collector` service
> (`src/avp-audit-collector`). **Deltas from the plan:** (1) the `honeytoken` flag lives on the
> **secret** (`SecretSpec`), not the inner host-scope `BindingSpec` — it is the AVP "binding"
> the audit `binding_name` names, and matches ADR-0011's binding object; (2) the follow-up
> event is emitted centrally inside `AuditWriter.emit()` rather than at each handler call site,
> so it covers every `inject_decision` path (allowed, all denies, fail-closed 503s) with no
> site missed and G6 preserved per record; (3) the Fluent Bit binary is pinned + checksum-
> verified via role vars and **fails closed** if the sha256 is unset. The collector read-access
> + retention policy (§Consequences → Bad) is enforced by restrictive file perms (0700/0600)
> and the `AVP_COLLECTOR_RETENTION_DAYS` knob. Deployment (the pinned binary sha256, the
> Ansible run, the tailnet collector, docker-e2e) remains an operator handoff.

## Context

AVP runs per-engineer, one instance per developer laptop. Each instance keeps a **local**
audit log (`audit.py` → `AuditWriter`): append-only JSONL, one `os.fsync()` per event,
`fail_on_unwritable: true`, made tamper-evident at the filesystem level with `chattr +a`
by the Ansible role. The record is deliberately minimized — timestamp, contract version `v`,
`request_id`, secret name, destination host, outcome, reason. It **never** carries header
values, request/response bodies, query strings, or secret material.

That log is excellent as a *local* black box and useless as a *fleet* signal, because it
never leaves the box. `docs/architecture.md` §4.4 already names the gap in its own words:
*"Future direction: off-host shipping (rsyslog TLS or similar)."* A recent posture review
scored the same row: audit is structured, correlation-ID'd, fsync'd and `chattr +a`
tamper-resistant **locally**; forwarding is **absent**.

The value of centralizing is not "collect all the logs." It is a **fleet-wide tripwire**:

- A **honeytoken** — a placeholder bound to a trap host the operator controls, planted
  somewhere tempting on disk (a decoy `.env`, a decoy `~/.aws/credentials`). Because the
  agent only ever holds *placeholders* (G1), the honeytoken's real value is never in the
  agent's address space; but the moment anything steers that placeholder anywhere, AVP
  emits an audit event. Any such event, anywhere in the fleet, means that machine is being
  walked for credentials.
- An **exfiltration attempt** shows up not as a secret-in-traffic sighting — audit
  minimization and G1 make that impossible — but as a placeholder aimed at a destination
  that isn't its binding: AVP already emits `destination_not_in_binding` and forwards the
  placeholder verbatim without injecting the real value (G5). Aggregated across the fleet,
  a burst of `denied` / `destination_not_in_binding` / `binding_scope_violation` on one
  engineer's box is an anomaly worth paging on.

The design tension is that AVP's local audit is its crown jewel: fail-closed, fsynced
before bytes leave the proxy (G6), minimal-surface, one-daemon/one-config/one-log. Off-box
shipping is a fundamentally *different* reliability class — best-effort, network-dependent,
must never be allowed to stall or fail a credential decision. The whole decision below is
about keeping those two classes from contaminating each other.

**Verified current state (2026-07-02):**

- `audit.py` ships `AuditWriter.emit()`: `json.dumps` one line, `write` + `flush` +
  `os.fsync()`, under a `threading.Lock`. `AUDIT_CONTRACT_VERSION = 2` stamped on every
  record as `v`. `fail_on_unwritable` re-raises `OSError` (G4 startup/persistent failure).
- No network egress anywhere in `audit.py`. The proxy's only outbound calls are upstream
  TLS, BWS, and (ADR-0017) OAuth token endpoints — all SSRF-guarded.
- Ansible role `roles/agent-vault-proxy/tasks/bootstrap.yml` initializes
  `/var/log/agent-vault-proxy/audit.jsonl` and applies `chattr +a` (idempotent
  `-a` then `+a`; warns-and-continues where the filesystem doesn't support it).
- systemd unit sandbox is tight: `ProtectSystem=strict`, `ProtectHome=yes`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service`
  minus `@privileged @resources @mount`, `ReadWritePaths` = log dir + state dir only,
  `ReadOnlyPaths` = etc + install dirs, `NoNewPrivileges=yes`.
- No log-shipping stack exists in the Ansible tree (no Vector, rsyslog-forward, Loki,
  promtail, or Fluent* role). This is greenfield.
- All fleet machines are on a single Tailscale mesh (tailnet) with ACLs.
- The operator already runs a local notification endpoint.
- Honeytoken / canary is a new concept — the only "canary" in the repo today is the
  unrelated `pypi-canary` CI workflow.

## Decision

Ship off-box audit forwarding as a **separate sibling process**, never from inside the
proxy, transported over the existing Tailscale mesh; and add a first-class **honeytoken**
binding flag with its own audit event. Target v1 of the shipping capability.

### 1. Scope

- **In v1**: forward the existing local JSONL, best-effort, from a process that is not the
  proxy — a pluggable shipper, **Fluent Bit** by default (§4). Node-identity transport over
  Tailscale. A per-binding `honeytoken: true` flag and a `honeytoken_triggered` audit event.
  A minimal central collector that appends per-host and runs a cheap alert rule.
- **Deferred**: guaranteed / at-least-once delivery with broker semantics; multi-collector
  HA; a retention / rotation policy engine on the collector; deep-packet inspection of any
  kind; collector authn beyond the tailnet ACL; SIEM-grade correlation and dashboards.

### 2. The shipper lives outside the proxy process — the load-bearing decision

`audit.py`, the local log, `chattr +a`, and the G6 fsync ordering are **unchanged**. The
local log remains the fail-closed source of truth. A **separate tailer** reads that file
read-only and forwards it. Rationale:

- **Egress surface.** A persistent connection to a log collector inside the
  credential-broker process is a new outbound path in exactly the process whose surface we
  most want frozen. A sibling process keeps AVP's blast radius identical to today.
- **Reliability class isolation.** The local write is fail-closed and synchronous (G4/G6).
  Network shipping is best-effort and asynchronous. Entangling them means a slow or dead
  collector could stall a credential decision — a self-inflicted DoS on the proxy. The two
  must not share a failure domain.
- **Sandbox integrity.** The proxy's systemd sandbox stays exactly as verified above. The
  shipper runs as its **own systemd unit**, as a **different, unprivileged user**, with
  **read-only** access to the log directory and its own (network-permitting but otherwise
  restricted) sandbox. AVP's `SystemCallFilter` / `ReadWritePaths` do not widen.

Consequence for config: shipping configuration does **not** enter `bindings.yaml`. The
proxy keeps its one-config-file property; the shipper reads its own role-managed env /
unit config. `bindings.yaml`'s `audit:` block stays `path` + `fail_on_unwritable` only.

### 3. Transport — HTTP POST over Tailscale, node identity as client identity

The collector is a **tailnet-only** service on a designated collector host, reachable only over
the tailnet and gated by a Tailscale ACL that admits authorized nodes to that one
port. **The Tailscale node identity IS the client identity** — WireGuard already
authenticates every peer, so there is no per-engineer mTLS certificate to mint, distribute,
rotate, or revoke. This is the single decision that makes the feature "super easy to
integrate": deployment is one more systemd unit added by the same Ansible role, one env var
pointing at the collector's tailnet address, and an ACL line. Zero manual per-engineer
steps.

Records cross the wire exactly as they sit in the JSONL — no enrichment on the client that
could reintroduce sensitive fields. The collector may add *its own* envelope metadata
(receive time, source node name from the tailnet) around the untouched record.

### 4. The tailer — a pluggable shipper, Fluent Bit as the default

The shipper is defined by a **contract**, not a specific binary, so the implementation can be
changed per host or over time without reopening this decision. Every implementation obeys the
same contract:

- **Input.** Read `audit.jsonl` **read-only**, from a persisted `(inode, byte-offset)`
  **checkpoint** in the shipper's own state dir — resume across restarts with no gap and no
  re-send (the G9 spirit applied to shipping). Handle rotation by inode change (§7).
- **Output.** Deliver each record to one or more sinks, best-effort, with a disk-backed spool
  and retry/backoff when a sink is unreachable. Records cross the wire exactly as they sit in
  the JSONL (§3) — no client-side enrichment that could reintroduce a sensitive field.
- **Constraints (non-negotiable, identical for every implementation).** Its **own systemd
  unit**, a **separate unprivileged user**, `ReadOnlyPaths` on the audit dir, `ReadWritePaths`
  limited to its spool/state dir, network permitted. **Never blocks, never fails the proxy,
  never writes the proxy's log.** The local `chattr +a` log stays authoritative; the worst
  case of a catastrophic shipper loss is "central view is behind," not "audit lost."

The Ansible role selects the implementation per host via
`kow_shipper: fluentbit | vector | native` (default `fluentbit`). Adding Vector
later is flipping that variable on the hosts that need it — no schema change, no ADR reopen.

**Default — Fluent Bit (Apache-2.0).** Chosen for this workload: small (~15 MB binary,
~20–30 MB RAM — roughly a **10% add** on top of AVP's ~130–150 MB mitmproxy-heavy footprint),
CNCF-standard, and it does every piece with nothing left idle — a `tail` input with a SQLite
checkpoint DB, `stackdriver` / `http` / `splunk` / `es` outputs to fan out to a cloud log
store and/or a SIEM at once, and a Prometheus metrics endpoint for the trackable-delivery
requirement. AVP's records are already minimized JSON, so no transform stage is needed.

**Opt-in alternative — Vector (MPL-2.0).** Same contract, richer at a cost. Reach for it on a
host that needs Vector-only sinks (native Chronicle / Google SecOps), VRL transforms, or its
live-inspection ergonomics (`vector tap` / `vector top`). The trade is size (~100 MB binary,
~50–100 MB RAM — roughly a **two-thirds add**) and a transform engine that sits idle on an
already-minimized stream. Because it satisfies the same contract, it is a per-host swap, not a
redesign — this is the seam left open on purpose.

**Fallback — native `avp audit-ship`.** A ~120-line stdlib subcommand (checkpointed tail →
batched `http` POST → disk-backed spool) for hosts that must carry **zero third-party shipping
binary** at all. Most control, least reliability-for-free; matches AVP's stdlib-only transport
posture (§4.4, ADR-0017).

**Licensing / supply-chain (applies to both third-party shippers).** They run as **separate
processes invoked by the role**, never linked into AVP — MPL-2.0 (Vector) and Apache-2.0
(Fluent Bit) create no obligation on AVP's MIT license. Whichever is used is **pinned to an
exact version and checksum-verified at provision time** (never fetched at runtime), and is
**not an AVP package dependency**: it never enters `pyproject.toml`, the wheel, the Docker
image, or `requirements.lock`, so AVP's own supply-chain audit surface (OSV / pip-audit) is
unchanged. It is installed only on hosts where shipping is enabled.

### 5. Honeytoken — the first-class tripwire

Add an optional per-binding boolean `honeytoken: true` (default `false`). Semantics:

- A honeytoken binding behaves exactly like any other binding for injection/decision — no
  special network behavior — so an attacker cannot distinguish it by probing.
- When any decision fires on a honeytoken binding (injected, denied, scope-violated, or
  aimed at the wrong destination), AVP emits a distinct **`honeytoken_triggered`** audit
  event in addition to the normal `inject_decision`, so the collector can alert on a single
  unambiguous event type with zero false positives — rather than inferring intent from
  binding names.

```json
{
  "type": "honeytoken_triggered",
  "request_id": "...",
  "binding_name": "DECOY_AWS_PROD",
  "dest_host": "s3.amazonaws.com",
  "underlying_reason": "destination_not_in_binding",
  "v": 3
}
```

No secret material, no header/body/query content — the same minimization contract as every
other event, stated verbatim. `dest_host` and the categorical `underlying_reason` are the
only additions, both already present in the record set today.

This is a **new audit event shape**, which is exactly the trigger `docs/adrs/README.md`
names as ADR-required, and it bumps `AUDIT_CONTRACT_VERSION` (2 in the working tree today)
by one, with the matching update to `docs/architecture.md` §4.4 per the audit-contract
hard constraint.

### 6. Invariant preservation (stated by name)

- **G6 unchanged.** Shipping is strictly downstream of the local fsynced write. The proxy's
  fsync-before-bytes-leave ordering is not observed, extended, or coupled to the network.
- **Audit minimization preserved.** The shipper forwards the JSONL verbatim; it performs no
  enrichment that could reintroduce a header, body, query string, or secret value. The
  `honeytoken_triggered` event adds only fields already in the minimized set.
- **Fail-closed asymmetry, on purpose.** The *local* log stays fail-closed (`fail_on_unwritable`,
  G4). *Shipping* is best-effort by design; its failure must never affect a credential
  decision or the proxy's availability. A dead collector degrades the fleet view, nothing
  else.

### 7. Log rotation interaction

The role's `chattr +a` and the architecture's logrotate-with-`copytruncate` + privileged
`chattr -a`/`+a` orchestration are unchanged. The shipper must tolerate rotation: detect
inode change, finish the old inode to EOF, then continue on the new file from offset zero.
`copytruncate` (rather than rename) is the operator's current posture; the tailer handles
both by tracking `(inode, offset)`.

### 8. Central collector (v1)

Deliberately minimal — **no SIEM**:

- A tailnet-only HTTP endpoint on a designated collector host that accepts the NDJSON batches.
- Appends to a per-source-node JSONL file (source node from the tailnet identity, §3).
- A cheap rule pass over incoming records: fire on `honeytoken_triggered`, and on
  configurable thresholds of `denied` / `destination_not_in_binding` /
  `binding_scope_violation` per node per window.
- Alerts reuse the existing local notification endpoint — no new
  alerting stack.

A heavier query/dashboard layer (Loki + LogQL, or Grafana) is a later, optional upgrade
that consumes the same on-disk JSONL; it is out of scope for v1.

## Beyond the baseline

- **Honeytoken fleet tripwire (§5).** Intent-based and pre-exfiltration: it fires when a
  planted credential is *touched*, before any real secret moves, across every laptop at
  once. Most credential brokers ship no equivalent — they log usage, they don't plant bait.
- **Node-identity transport (§3).** The mesh authenticates peers, so there is no client
  PKI to operate. Off-box audit with none of the certificate lifecycle most log-forwarding
  designs carry.
- **Best-effort-by-design contract (§6).** The shipper is structurally incapable of harming
  the proxy — a property asserted in the ADR and enforced by process/user/sandbox
  separation, not by careful coding alone.

## Consequences

### Good

- Closes the `docs/architecture.md` §4.4 "off-host shipping" future-direction item and the
  posture-review row.
- The proxy process, its sandbox, its egress surface, and G4/G5/G6 are untouched.
- Pluggable shipper behind one contract: **Fluent Bit** by default (~15 MB, Apache-2.0,
  ~10% footprint add), with **Vector** or the native stdlib subcommand as per-host swaps —
  no redesign to change. Whichever is chosen is an optional sidecar, never an AVP package
  dependency.
- Turns the fleet into a single tripwire surface: one honeytoken event = one compromised
  machine, named.
- Leverages infrastructure the operator already runs (a mesh VPN, an existing notification path);
  integration is one Ansible unit, not a new platform.

### Bad

- **The central collector is a new aggregation of who-used-which-credential-where across
  the whole team — it is now itself a target.** The ADR must fix, before `accepted`: who
  may read it, how long records are retained, and the guarantee that the collector never
  becomes a softer path to the same intent-intelligence the proxy exists to protect. It
  holds no secret *values*, but the metadata graph is sensitive on its own.
- Best-effort shipping can drop events under catastrophic shipper/collector loss. Mitigated,
  not eliminated: the local `chattr +a` log remains authoritative for forensics.
- A second systemd unit per host to deploy, monitor, and keep alive — real operational
  surface, even if small.
- Honeytokens demand discipline: they must be planted convincingly, kept current, and never
  accidentally bound to a real destination, or they become noise or a self-inflicted alert.
- New audit event shape = contract bump = a coordinated edit across `audit.py`,
  `docs/architecture.md` §4.4, and any operator parsers.

### Out of scope (deferred, each its own future ADR if pursued)

- Guaranteed / at-least-once delivery with broker semantics.
- Multi-collector HA and failover.
- Retention / rotation / lifecycle policy engine on the collector.
- Deep-packet or response-body inspection of any kind (precluded by minimization + G1).
- Collector authentication beyond the tailnet ACL (e.g. per-node mTLS on top of Tailscale).
- SIEM-grade correlation, long-term search, and dashboards (Loki/Grafana layer).
- Shipping the OAuth `token_exchange` / `refresh_token_rotated` events differently from the
  rest — they ride the same stream with no special handling.

## References

- `docs/architecture.md` §4.1 (process layout — the shipper is a new sibling process),
  §4.4 (audit log, minimization contract, "off-host shipping" future direction),
  G4 (fail-closed classes), G5 (enforcement by omission — the exfil-attempt signal),
  G6 (fsync-before-bytes-leave, preserved), G9 (restart loses no audit history — the
  checkpoint mirrors this for shipping).
- `src/kow/audit.py` — `AuditWriter`, `AUDIT_CONTRACT_VERSION` (2 → 3 with
  the new event type).
- `roles/agent-vault-proxy/tasks/bootstrap.yml` — `chattr +a` initialization; the new
  shipper unit is added alongside.
- ADR-0017 (OAuth2 refresh injector) — precedent for adding audit event types and for
  stdlib-only transport with no new runtime dependency.
- ADR-0011 (BWS-notes bindings) — `honeytoken` is a per-binding flag on the same binding
  object, honored regardless of binding source.
- Shipper implementations behind the §4 contract: Fluent Bit (Apache-2.0, default), Vector
  (MPL-2.0, opt-in), native `avp audit-ship` (fallback) — all run as separate processes,
  none linked into AVP's MIT code; selected per host via `kow_shipper`.
