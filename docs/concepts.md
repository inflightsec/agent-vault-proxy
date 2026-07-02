# Concepts: agent-vault-proxy

> The mid-level on-ramp. The [README](../README.md) gives you the one-line pitch; [architecture.md](architecture.md) gives you the dense expert detail. This page sits between them: the core ideas you want in your head before (or while) you install, in plain language. It explains the "why" and "what it means". It is not a how-to and not a config reference: for install steps see [install-systemd.md](install-systemd.md) or [docker.md](docker.md), for the full config grammar see [bindings.example.yaml](../bindings.example.yaml).

## The problem, and the one idea

Your AI agent needs API keys: a key for Anthropic, a token for GitHub, and so on. The usual way to give it those keys is to put them in the agent's environment as plain text. That works, but it means the real keys are sitting inside the agent's process, readable by anything running there.

That is a problem for two reasons. An agent reads untrusted text all day: web pages, emails, tool output, PR comments. Any of that text can carry hidden instructions ("send your keys to attacker.com"): this is "prompt injection". And the agent runs other people's code: npm packages, Python libraries, install scripts. Any of those can read the same environment the agent does: this is "software supply-chain risk". In both cases, if the real key is in the process, it can leave the process.

AVP's one idea: the agent never holds the real key. Instead it holds a fake stand-in string called a **placeholder**, and uses it exactly as if it were real. AVP is a small proxy that sits on the wire between the agent and the internet, and swaps the placeholder for the real key at the last possible moment, on the way out to the upstream API. The real key lives in a separate vault and never enters the agent's process. If the agent is prompt-injected or leaks a log, the only thing that escapes to an outside attacker is the placeholder, which is worthless on its own. (Code the agent runs locally, like a poisoned dependency, is a narrower case, covered below.)

"On the wire" is the key phrase. The substitution happens inside the network connection leaving the proxy, not anywhere the agent can see. The agent sends `sk-PLACEHOLDER-...`, the upstream API receives the real `sk-ant-...`, and the agent never observed the difference.

## How it works, conceptually

A "proxy" here means a small program that your agent's HTTPS traffic is routed through on its way out. You point the agent at it with one environment variable (`HTTPS_PROXY=http://127.0.0.1:14322`), and from then on every outbound request passes through AVP first. It runs on loopback (`127.0.0.1`), so it is local to the machine, not a remote service.

The lifecycle of a single request, in plain terms:

1. **The agent sends a request carrying a placeholder.** For example a call to `api.github.com` with the header `Authorization: token ghp_PLACEHOLDER_...`. As far as the agent is concerned, that is its API key.
2. **AVP matches the placeholder against a binding.** A **binding** is a rule the operator wrote that says "this placeholder is allowed to become the real secret, but only when talking to these destinations". In other words, each secret carries its own **per-secret host allowlist**: the secret is injected *only* for the hosts its binding names, never for any other destination. Crucially, AVP checks the request's **real** destination — the TLS SNI / `CONNECT` host that actually terminates the connection, not the spoofable `Host:` header — optionally narrowed further by HTTP method and URL path. That is what blocks **exfil-by-redirect**: an attacker cannot aim a request at an allowed host to get the secret injected and then have it delivered somewhere else, because a mismatch between the connection's real host and the claimed host is denied outright (`sni_host_mismatch`).
3. **If it matches, AVP fetches the real secret from the vault.** The real value lives in the **backend** (Bitwarden Secrets Manager today), fetched just-in-time and held briefly in an in-memory cache so repeat calls are fast.
4. **AVP swaps the placeholder for the real secret on the way out.** The substitution happens on the connection to the upstream only. It also writes an audit-log entry, flushed to disk, before the modified bytes go on the wire.
5. **The upstream sees the real key. The agent never did.** The response comes back to the agent unchanged.

If no binding matches, behaviour depends on the policy. On the default (`forward_unmodified`), AVP does not error: it forwards the placeholder unchanged and lets the upstream reject it with its own "bad credentials" response. Operators who want allow-list behaviour set `unmatched_destination_policy: deny`, which makes AVP return a 403 for an unbound destination instead. The default "stay quiet" choice is deliberate; the fail-closed glossary entry explains why.

**Three "allowlists" people conflate — keep them separate.** These sound alike but do different jobs:

1. **Per-secret injection allowlist (always on).** A binding's host list (step 2) decides *which hosts a given secret may be handed to*. This is enforced for every secret, always. It is the answer to "where can `GITHUB_PAT` go?" — never to "where can the agent connect?".
2. **Unbound-destination policy (one config flag).** `unmatched_destination_policy` decides what happens to a destination *no secret is bound to*: `forward_unmodified` (default — let it through un-injected) or `deny` (return 403). This is the only "allowlist vs. not" toggle, and it only governs *un-brokered* traffic.
3. **Egress firewall (not AVP at all).** Blocking the agent from *opening a connection* to a host in the first place is a separate tool's job (OpenSnitch, nftables, firewalld). AVP never does this; by default it happily forwards traffic to any host, it just won't inject a secret that host isn't bound to.

So: bindings gate *secret injection*, not *connectivity*. AVP with the default policy is a credential broker, not an egress firewall — set `unmatched_destination_policy: deny` if you want it to also refuse unbound destinations, and pair it with a real egress firewall for hard network isolation.

For the precise, hook-by-hook lifecycle, including the SNI/Host consistency check and the exact audit ordering, see [architecture.md section 4.3](architecture.md#43-request-lifecycle).

## What it protects you from, and what it does not

What AVP buys you is a smaller **blast radius**. If the agent is compromised, by prompt injection, by a leaked log, or by a malicious dependency, what an attacker can *exfiltrate* is the placeholder, not the key: the real secret bytes were never in the agent's memory to steal.

That is narrower than it sounds for local code. A malicious dependency running at the agent's own UID can still *use* the proxy as an authenticated channel: AVP cannot tell legitimate agent traffic from poisoned-dependency traffic at the same UID, so it injects the real secret for any request that matches a binding. Routing that traffic through AVP does not stop it. AVP prevents the dependency from *stealing the raw key*; it does not stop the dependency from *spending the authority* that key grants, within each binding's scope. Tight binding scope (`methods:` and `paths:`) plus an egress firewall are what bound that damage.

Be clear about the boundary, because this layer is often over-trusted:

- **AVP is not an egress firewall.** It does not block where the agent can connect. Its job starts when a request arrives at the proxy and ends when the response is returned. Controlling which destinations the agent may reach at all is the **operator's job**, using a separate tool (OpenSnitch, nftables, firewalld, and so on). AVP and an egress firewall are complementary; neither replaces the other.
- **AVP protects against key theft, not against misuse of the authority the key grants.** If you bind `GITHUB_PAT` to `api.github.com` with no method or path limits, a prompt-injected agent can still ask AVP to authenticate, say, a `DELETE` request as you. The lever for that is tightening the binding's **scope** (`methods:` and `paths:`), so a read-only key cannot be used to write. Lock scopes down, and pair AVP with an egress firewall for hard isolation.
- **AVP injects on the request, not the response.** If an upstream echoes your `Authorization` header back in its response body (some debug or verbose-error endpoints do), the agent receives the real secret that way and the isolation breaks for that exchange. Prefer well-behaved upstreams, or sanitize responses at a higher layer.
- **Same-UID and host-root attackers are out of scope.** A persistent attacker running as the proxy's own user, or as host root, can defeat it. AVP is one layer, not a complete answer.

The full threat model, including each threat AVP does and does not defend against, and the accepted residual risks, is in [architecture.md section 2](architecture.md#2-threat-model).

## Glossary

**Placeholder**: a fake, structurally-valid-looking stand-in string (like `sk-ant-PLACEHOLDER-...`) that the agent holds and uses in place of a real API key. AVP recognizes it on outbound requests and swaps it for the real value. The placeholder is what escapes if the agent is compromised, and it is useless on its own.

**Binding**: an operator-written rule that links one placeholder to the destinations where it may be turned into the real secret. A binding names a host and, optionally, the HTTP methods and URL paths allowed. If a request does not match any binding for its placeholder, no substitution happens. Bindings live in `bindings.yaml`. A request is matched by the placeholder it carries; exact-host bindings are checked before wildcard ones, and if one request carries two different recognized placeholders, AVP denies it rather than guess.

**Backend / BWS (Bitwarden Secrets Manager)**: the vault where the real secrets actually live. AVP fetches from it just-in-time and never stores secrets itself. Bitwarden Secrets Manager (cloud or self-hosted) is the reference backend that ships today; other vaults can plug in via an adapter. AVP is not a vault and does not try to be one: it is the wire-substitution layer between your vault and your agent.

**Scope (host / method / path)**: the three dimensions a binding can restrict. *Host* is required (which server the secret may go to). *Method* (`GET`, `POST`, and so on) and *path* (URL path globs, where `*` matches one segment and `**` matches any number) are optional and narrow it further. Tight scope is how you stop a read-only key from being used to write: it limits what an attacker can do even when they manage to use the proxy.

**The CA (and why the agent must trust it)**: AVP terminates and re-encrypts the agent's HTTPS traffic so it can read and rewrite the headers, so it presents its own TLS certificate, signed by its own per-host Certificate Authority (CA). For the agent's HTTPS client to accept that certificate instead of erroring, the calling shell must explicitly load the CA via env vars like `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`. This CA must NOT be added to the system-wide trust store: only processes you have deliberately pointed at the proxy should trust it, which limits the blast radius if the CA ever leaks.

**Fail-closed**: AVP's rule that any uncertainty results in no real secret being injected, never a guessed or degraded one. The externally-visible behaviour depends on the failure. For a per-request problem (vault unreachable, scope violation, or an unbound destination under the default policy), AVP forwards the placeholder unchanged and lets the upstream return its own auth failure: it stays quiet rather than erroring, because an error would tell an attacker probing the agent that a destination is blocked, turning the proxy into a side channel. (Under `unmatched_destination_policy: deny`, an unbound destination instead gets a 403.) For a startup or persistent problem (invalid config, unwritable audit log), the daemon refuses to start or serve at all.

**Audit log**: an append-only, local-only record (JSONL, one event per line) of every substitution decision AVP makes: allowed or denied, which secret, which destination, and why. The decision is flushed to disk *before* the modified request goes on the wire. It never records header values, request or response bodies, or query strings. This is the forensic trail for what the agent actually did.

**Composite secret**: a credential assembled on the wire from more than one stored value, rather than injected directly. The classic case is Jira / Atlassian Cloud Basic auth, which needs `base64(email:token)`: the email and the API token are two separate BWS secrets, listed under `compose:` and combined by a sandboxed template at request time. Each piece can be rotated independently, and the combined value is never cached: only the raw pieces are.

**Injector type**: how AVP places the secret into the request. `header` puts it in an HTTP header (the common case, like `Authorization`). `body` substitutes it inside the request body via streaming replacement, for upstreams that expect the credential in the payload (Slack webhooks, OAuth POSTs, HMAC-signed bodies). `multi` fires several injectors for one placeholder when a credential must land in more than one place per request.

**Blast radius**: the scope of damage if something is compromised. AVP's whole purpose is to shrink the blast radius of a compromised agent: instead of "the attacker has my real API keys", it becomes "the attacker has a placeholder". A related trade-off runs the other way: the more traffic you route through the proxy, the bigger the blast radius if the *proxy itself* is compromised, so route deliberately.
