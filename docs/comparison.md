# Why this and not the alternatives

`agent-vault-proxy` is for the single-host case where you already run Bitwarden Secrets Manager, prefer not to stand up a second vault, and want the credential bytes to literally never enter the agent's process.

Other tools in this space:

- **HashiCorp Vault Agent / Infisical Agent**: render templates with real secrets to files the agent reads. Excellent at reducing blast radius for the vault token itself, but the per-API secrets still land in the agent's filesystem (and from there easily in its memory). Not zero-knowledge for the per-API secrets.

- **Doppler / `op run` / `aws-vault exec`**: inject secrets into the agent's process environment at start time. Same exposure: real secret bytes live in the agent's address space for the duration of the run.

- **`superfly/tokenizer`** - same substitution-on-the-wire idea, different deployment story. Supports header injection plus HMAC, SigV4, and JWT processors. Does not terminate TLS for clients (it speaks plain HTTP to the proxy and assumes a separate secure transport like a VPN protects that hop). Apache-2.0. Useful primitive, not a drop-in for the local-host case where you don't have that secure-transport assumption.

- **Kloak**, the project that sparked this design. eBPF substitution at `SSL_write` (and similar TLS write functions) for any OpenSSL/BoringSSL/Go-`crypto/tls` runtime in a Pod. Architecturally the cleanest version of the pattern, but Kubernetes-only - mutating admission webhook, DaemonSet, Pod-label opt-in, no documented standalone single-host install path, and AGPL-3.0. AVP applies the same substitution-on-the-wire idea to any process on any host, not just Pods in a cluster.

`agent-vault-proxy` is a thin substitution layer that terminates TLS for the local agent, fetches secrets from BWS just-in-time, and substitutes them on the upstream socket. It is not a vault, key manager or a rotation system: it's the missing piece between the existing vault and an autonomous agent.

