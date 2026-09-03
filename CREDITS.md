# Acknowledgments

`kow` is original work licensed under Apache-2.0 (see [`LICENSE`](./LICENSE)). A few projects influenced the design:

- **[Kloak](https://www.getkloak.com)** — sparked the idea of substituting credentials on the wire instead of handing them to the agent.
- **[`superfly/tokenizer`](https://github.com/superfly/tokenizer)** — the injector-strategy taxonomy introduced in v0.5.0 (`type: header`, `body`, `hmac`, `sigv4`, `oauth2_refresh`, `oauth2_client_credentials`, `jwt_bearer`, `github_app`, `multi`) was informed by its processor catalog. All of them now ship. Implementations are written from the underlying public specs (RFC 6749, RFC 7523, AWS SigV4, GitHub Apps docs, etc.).
- **[mitmproxy](https://github.com/mitmproxy/mitmproxy)** — the addon framework keys-on-the-wire runs as.
- **Bitwarden Secrets Manager** — the first vault backend keys-on-the-wire shipped against. Its client, [`bitwarden-sdk`](https://pypi.org/project/bitwarden-sdk/), is under Bitwarden's proprietary SDK license (not Apache-2.0); it stays an opt-in extra (`keys-on-the-wire[bitwarden]`) so the default install is fully open source.

Thanks to all four for the prior art.
