# Acknowledgments

`kow` is original work licensed under Apache-2.0 (see [`LICENSE`](./LICENSE)). A few projects influenced the design:

- **[Kloak](https://www.getkloak.com)** — sparked the idea of substituting credentials on the wire instead of handing them to the agent.
- **[`superfly/tokenizer`](https://github.com/superfly/tokenizer)** — the injector-strategy taxonomy introduced in v0.5.0 (`type: header`, `body`, `hmac`, `sigv4`, `oauth2_*`, `jwt_bearer`, `github_app`, `multi`) was informed by its processor catalog. v0.5.0 implements `header`, `body`, and `multi`; the rest are in the schema as planned and fail config-load with a one-line "not yet implemented" error until they ship. Implementations are written from the underlying public specs (RFC 6749, RFC 7523, AWS SigV4, GitHub Apps docs, etc.).
- **[mitmproxy](https://github.com/mitmproxy/mitmproxy)** — the addon framework AVP runs as.
- **Bitwarden Secrets Manager** — the reference vault backend AVP ships against. Its client, [`bitwarden-sdk`](https://pypi.org/project/bitwarden-sdk/), is under Bitwarden's proprietary SDK license (not Apache-2.0); AVP keeps it an opt-in extra (`kow[bitwarden]`) so the default install stays fully open source.

Thanks to all four for the prior art.
