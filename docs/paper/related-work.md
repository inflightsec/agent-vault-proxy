# Related Work (annotated, draft)

> Draft related-work section for the kow paper. Every arXiv ID below was resolved
> against arxiv.org before inclusion; industry URLs were fetched. The one-line
> **How kow differs** under each entry is the sentence that should survive into the
> final paper's prose. Positioning thesis in one line: *kow is the only member of
> this space that is simultaneously (i) transparent to the upstream, (ii) sources
> just-in-time from an existing vault without becoming a second store, (iii) keeps
> the real secret out of the agent's address space as a physical invariant, and
> (iv) states its guarantees as individually falsifiable tests.*

## 1. The threat: credential exfiltration from untrusted agents

The problem kow addresses is empirically established, so the paper argues from
evidence rather than assertion.

- **Prompt-injection data leakage during task execution** — Simple injection
  attacks leak data an agent handles mid-task; the authors fold data-flow attacks
  into the AgentDojo benchmark and report non-trivial attack success even against
  built-in defenses. arXiv:2506.01055.
- **The emerged security and privacy of LLM agents** (survey with case studies),
  arXiv:2407.19354; **Trustworthy LLM Agents: threats and countermeasures**,
  arXiv:2503.09648 — establish the attack surface: an agent reads untrusted text
  all day and runs third-party code, so any secret in its process can leave it.
- **Real, disclosed incidents.** The Balkanization SoK (below) confirms against the
  NIST NVD **CVE-2026-21852** — Claude Code data exfiltration allowing *API-key
  leakage before trust confirmation* (CVSS 7.5) — and **CVE-2025-53773** (Copilot
  command injection). These are the "this already happened in production" hooks for
  the introduction.

**How kow relates:** this cluster is motivation, not competition. kow's contract
begins exactly where these attacks succeed — the moment a secret would otherwise be
readable inside the agent — and removes the secret from that location entirely.

## 2. Substitution proxies — the direct-mechanism class

The on-the-wire-placeholder mechanism is now a small **product** category, almost
entirely outside peer review. This is the cluster that kills any "new mechanism"
claim, so the paper must name it plainly and compete on rigor, not novelty.

- **superfly/tokenizer** — substitution-on-the-wire with header/HMAC/SigV4/JWT
  processors; does **not** terminate TLS for the client (assumes a separate secure
  transport such as a VPN). Apache-2.0.
- **nono — the "phantom token" pattern** (https://nono.sh/blog/blog-credential-injection)
  — the agent gets a per-session 256-bit token that only works against a localhost
  proxy; the proxy constant-time-validates it, strips inbound auth headers, swaps in
  the real credential, and holds values in zeroized memory.
- **SecretProxy** (https://secretproxy.io/) — egress-time header/body injection,
  onboarding by changing the base URL.
- **Riptides** (https://riptides.io/blog/vault-credentials-on-the-wire-riptides/) —
  the sharp one: injects **in kernel space**, so no user-space proxy process exists
  to attach a debugger to. Directly attacks kow's residual risk R1 (proxy-UID
  compromise = all bound secrets). Must be addressed head-on, not sidestepped.
- **Envoy `credential_injector` filter** — the same wire-injection built into a
  general L7 proxy, but for **workload** auth (one workload behind the sidecar),
  `Authorization`-only, no per-destination agent-secret scoping, no JIT vault source.
- **Kloak** — eBPF substitution at `SSL_write`; Kubernetes-only (admission webhook +
  DaemonSet), AGPL-3.0. **OneCLI / Deno Claw Patrol** — fuller products that ship
  their **own** secret store and return an explicit error on a blocked destination.

**How kow differs:** it is the single-host layer that (a) *terminates TLS for a local
agent* (unlike tokenizer), (b) *sources just-in-time from an existing vault instead of
introducing a second store* (unlike nono/OneCLI/Claw Patrol), and (c) refuses to be a
destination oracle — on a policy miss it forwards the placeholder verbatim rather than
erroring, so it never signals which destinations are bound (§G5, unique in this list).
On Riptides' kernel argument the paper concedes the point as accepted residual risk R1
and scopes to the portable, no-kernel-dependency, any-host case.

## 3. Delegation protocols and capability tokens — the closest *academic* neighbor

This is the nearest peer-reviewed neighborhood and the honest "we are not first in the
building" citation.

- **SUDP — Secret-Use Delegation Protocol for Agentic Systems** (Yu, Geng, Zeng,
  Knottenbelt), arXiv:2604.24920. A three-party requester/user/custodian model: the
  user issues a fresh authenticator-backed grant, a custodian redeems it to perform a
  **bounded** use, so the agent never holds reusable authority. Threat model
  explicitly covers a compromised agent runtime, replay, and confused-deputy.
- **Delegation Capability Tokens / macaroons** — Birgisson et al.'s macaroons
  (attenuable, caveat-chained capabilities) extended to agent-to-agent delegation;
  **Biscuit** tokens (arXiv:2603.24775) add an offline-verifiable logic language;
  older capability-based distributed authorization, arXiv:2211.04980.

**How kow differs (the key wedge):** every scheme here **requires the upstream to
cooperate** — the resource server must accept and validate a new grant/token format,
and SUDP explicitly is *not transparent to the upstream* and adds a custodian round
trip (and latency) per access. kow is **transparent to the upstream**: it protects the
overwhelming majority of real APIs that only speak a plain bearer token or API key and
will never adopt a capability format. kow and SUDP are complementary — where an upstream
*does* speak grants, use SUDP; for everything else, kow keeps the static key out of the
agent. Note also the naming collision to avoid: Narajala & Narayan (below) also use a
"nine risks" framing; kow's G1–G9 are *guarantees*, not risks — rename if it reads
ambiguously.

## 3b. Object-capability systems and the powerbox — the architectural ancestor

Distinct from the bearer/token capability work above is the *object-capability* (ocap)
systems tradition, where authority is an unforgeable, non-transferable **reference** a
program holds but cannot forge or name out of thin air, and every access is mediated by a
reference monitor. This lineage is arguably kow's closest *architectural* ancestor, even
though it predates the agent framing and is largely systems-and-industry rather than
recent arXiv.

- **KeyKOS / EROS / seL4-style capability kernels** (Shapiro et al. and successors) — the
  foundational ocap systems: no ambient authority, access only through a held capability.
- **Sandstorm and Cap'n Proto** (Varda; sandstorm.io, capnproto.org) — an ocap
  application platform where each app runs confined and receives resources only through
  capabilities the *platform* grants, never by naming them itself. Its **powerbox**
  pattern has the system, not the app, mediate the user's grant of a specific resource,
  which structurally defeats the confused deputy: the app can only *ask*, the user picks.
- **Cloudflare OS** (Varda, 2026; blog.cloudflare.com/cloudflare-os) — a current,
  large-scale revival of the Sandstorm model for AI agents: sandboxed "Gadget" instances
  whose **Gatekeeper** verifies, on any share, that the recipient already holds direct
  permission to each connected resource. Evidence the ocap model is moving from research
  into mainstream agent infrastructure.

**How kow relates (kinship, not difference):** kow *is* an object-capability treatment of
credentials. The placeholder is an unforgeable, non-dereferenceable reference the agent
holds but cannot redeem; only the reference monitor (the proxy) exchanges it for the real
secret, and only toward a bound destination. This is the ocap discipline applied to the
one resource the token, information-flow, and TEE lines all leave in the agent's hands:
the secret bytes. Where kow advances past the classical ocap platforms is transparency and
reach — Sandstorm and Cloudflare OS require apps to be *written for* the platform's
capability API, whereas kow retrofits the discipline onto unmodified agents talking plain
HTTP to unmodified upstreams. ADR-0024's "annotations may only narrow, never add a host"
is the powerbox instinct in miniature: the note-writer can attenuate authority but never
widen it.

## 4. Information-flow and privilege control — orthogonal, composable

These gate *what an agent may do or where data may flow*; kow gates *what an agent may
hold*. The paper should frame them as complements it stacks under, not rivals.

- **Fides — Securing AI Agents with Information-Flow Control** (Costa, Köpf, Paverd,
  Russinovich, Salem, Tople, Wutschitz, Zanella-Béguelin), arXiv:2505.23643. A planner
  that carries confidentiality/integrity labels and deterministically enforces flow
  policies via taint tracking. Crucially, by its own account Fides *assumes secrets are
  already available as labeled values* and **does not address where secrets physically
  live in process memory**.
- **Progent — Securing AI Agents with Privilege Control** (Shi, He, Wang, Li, Wu, Guo,
  Song), arXiv:2504.11703. SMT-checked symbolic policies that restrict which tools an
  agent may invoke, auto-updated during execution.

**How kow differs:** kow occupies the exact layer Fides punts on — the physical location
of the secret bytes. A Fides deployment still needs the real credential to reach the
upstream; kow is what keeps that credential out of the labeled computation in the first
place. The natural composite (worth one sentence in the paper): Progent decides *whether*
a tool call is allowed, Fides tracks *whether data may flow* to it, kow guarantees the
*credential never enters the agent* to be flowed in the first place.

## 5. Systematizations and the confidential-computing frame

- **The Balkanization of Execution-Security Research for AI Coding Agents** (Rashidi),
  arXiv:2607.05743 — an SoK of 39 papers (2023–2026) across 17 categories. Two facts
  make it load-bearing for us: (i) **none of its 17 categories systematizes
  credential-isolation proxies or on-the-wire injection** — its "Identity and credential
  delegation" category is OAuth/OIDC extension and cryptographic capability binding,
  not secret-substitution infrastructure; and (ii) its **Gap 1** is that "isolation
  architectures and capability models are never evaluated against each other on shared
  benchmarks," and **Gap 2** is that defenses are not re-evaluated against measured
  real-world failure rates. Gaps 1–2 are precisely the hole kow's empirical
  test-battery (companion section) fills.
- **Securing Agentic AI: a comprehensive threat model** (Narajala & Narayan),
  arXiv:2504.19956 — nine risks across five domains (ATFAA/SHIELD); a threat-model
  citation, and the naming-collision note above.
- **When Agents Handle Secrets: a survey of confidential computing for agentic AI**
  (Forough, Kogias, Haddadi), arXiv:2605.03213 — maps TEEs against agent threats and
  concludes no unified production framework exists. Positions kow as the pragmatic,
  no-special-hardware point on the same spectrum whose ceiling is R1.

**How kow differs:** it is not another survey. kow contributes the artifact plus the
falsifiable-invariant methodology these SoKs call for — and, if we run §b, the first
cross-tool empirical evaluation of the substitution-proxy class against a shared battery,
answering the Balkanization SoK's Gap 1 for at least this sub-field.

---

### One-paragraph synthesis (drop-in for the paper)

Prior work on protecting credentials in autonomous agents falls into four lines:
information-flow and privilege control that govern *what an agent may do* but assume the
secret is already in hand (Fides, Progent); delegation protocols and capability tokens
that issue bounded, non-reusable authority but **require the upstream to accept a new
token format** (SUDP, macaroons/DCT, Biscuit); confidential-computing approaches that
lean on special hardware (TEE survey); and a nascent, largely non-peer-reviewed class of
substitution proxies that swap a placeholder for the real secret on the wire (tokenizer,
nono, Riptides, Envoy's filter, Kloak). kow sits in the last line but is distinguished by
being transparent to the upstream, sourcing just-in-time from an existing vault without
becoming a second store, keeping the secret out of the agent's address space as a tested
physical invariant, and — uniquely — declining to act as a destination oracle on a policy
miss. Architecturally it is best read as an *object-capability* treatment of the credential
itself — the placeholder is an unforgeable reference redeemed only by the proxy — a
discipline the Sandstorm and Cloudflare OS lineage applies to whole applications and kow
narrows to the secret bytes, retrofitted onto unmodified agents and upstreams. No existing
systematization evaluates this class against a shared, falsifiable battery; we do.
