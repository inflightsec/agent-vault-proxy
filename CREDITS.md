# Acknowledgments

`agent-vault-proxy` is original work licensed under MIT (see [`LICENSE`](./LICENSE)). A few projects influenced the design:

- **[Kloak](https://www.getkloak.com)** — sparked the idea of substituting credentials on the wire instead of handing them to the agent.
- **[`superfly/tokenizer`](https://github.com/superfly/tokenizer)** — the injector-strategy taxonomy introduced in v0.5.0 (`type: header`, `body`, `hmac`, `sigv4`, `oauth2_*`, `jwt_bearer`, `github_app`, `multi`) was informed by its processor catalog. Implementations are written from the underlying public specs (RFC 6749, RFC 7523, AWS SigV4, GitHub Apps docs, etc.).
- **[mitmproxy](https://github.com/mitmproxy/mitmproxy)** — the addon framework AVP runs as.
- **Bitwarden Secrets Manager** — the reference vault backend AVP ships against.

Thanks to all four for the prior art.
