# NoteSchema — the annotation format + auth-pattern catalog

The binding lives in a secret's per-backend metadata: BWS **Notes** field, GSM **`avp-binding`** annotation, or the equivalent on a future backend. The parser is backend-agnostic.

## Allowed keys (flat YAML)

Exactly these, any others are a typo and fail closed:

| Key | Meaning | Default |
|-----|---------|---------|
| `host` | hostname the credential is sent to — a single string **or a list** (`hosts:` alias also accepted) | required |
| `header` | HTTP header to inject into | `Authorization` |
| `format` | header value template; MUST contain `{secret}` | `Bearer {secret}` |
| `methods` | list of HTTP methods to bind (scope) | all |
| `paths` | list of URL path globs to bind (scope) | all |

`{secret}` is the only substitution token — the note has no name key because the secret *is* the value. Bare-host shorthand: a note of just `host: api.example.com` uses the header/format defaults.

## Auth-pattern catalog

**Bearer** (most APIs):
```yaml
host: api.example.com
header: Authorization
format: "Bearer {secret}"
```

**`token` scheme** (some git/forge APIs):
```yaml
host: api.example.com
format: "token {secret}"
```

**Custom header / X-API-Key**:
```yaml
host: api.example.com
header: X-API-Key
format: "{secret}"
```

**Basic (single pre-encoded secret)** — store `base64("user:pass")` as the secret value:
```yaml
host: api.example.com
header: Authorization
format: "Basic {secret}"
```

**Composite Basic (`email:token` from two secrets)** — NOT expressible in a note (a note holds one secret). Use the AVP **config file source** with `compose:` + `inject_template`, e.g.:
```yaml
# config file source only — not a note
EXAMPLE_API_BASIC:
  placeholder: "ex_PLACEHOLDER_0000000000"
  inject_header: "Authorization"
  inject_template: "Basic {{ (EXAMPLE_EMAIL + ':' + EXAMPLE_TOKEN) | b64encode }}"
  compose: [EXAMPLE_EMAIL, EXAMPLE_TOKEN]
  bindings:
    - host: api.example.com
```

**Scoped (narrow blast radius)**:
```yaml
host: api.example.com
header: Authorization
format: "Bearer {secret}"
methods: [GET, POST]
paths: ["/v1/**"]
```

## Multi-host credentials

`host` accepts a single hostname **or a list** (a `hosts:` alias also works); a list fans out to
one binding per host under a single injector. Use it for a token that spans several hosts:

```yaml
host:
  - api.example.com
  - cdn.example.com
format: "Bearer {secret}"     # REQUIRED for a multi-host list — see rules
```

A list of **>1 host fails closed unless**:
- **explicit `format`** — the bare-Bearer default is never applied silently across hosts;
- **no curated host** in the list — a host with built-in defaults (`api.github.com` GET-only,
  Anthropic `x-api-key` + version header, Linear, etc.) must bind in its own single-host note;
- **no wildcard element** — a `*.suffix` inside a list is rejected (bind a wildcard on its own).

`methods`/`paths` apply **uniformly** to every host. For per-host scope, or to mix in a curated
host, use the **file source** (its `bindings:` list is per-host) or separate notes:
```yaml
# file source only — per-host scope / curated hosts
EXAMPLE_TOKEN:
  placeholder: "ex_PLACEHOLDER_0000000000"
  inject_header: "Authorization"
  inject_format: "Bearer {EXAMPLE_TOKEN}"
  bindings:
    - host: api.example.com
    - host: cdn.example.com
```

**Note the download-host caveat:** for model/file *downloads* (e.g. HuggingFace), the bytes flow
over the LFS/CDN hosts (`cdn-lfs.huggingface.co`, `cas-bridge.xethub.hf.co`) — NOT
`api-inference` / `datasets-server`. Bind the hosts the traffic actually uses.

## Gotchas (detail)

- **Fail-closed:** no annotation ⇒ never injected. Silent "auth didn't happen" almost always means the note didn't parse (wrong key, bad YAML).
- **Salt-derived placeholder (notes/both):** AVP derives the placeholder from a per-install salt + secret key; a consuming app must discover it, not assume `sk-...`-style literals. The file source is the only place an operator picks the placeholder.
- **`both` precedence:** notes win over file for the same secret; file-only bindings may be dropped under `both` unless pinned `:file`.
- **Wildcard hosts** require `allow_wildcard_hosts` opt-in; keep hosts exact otherwise.
- **Annotation-trust (ADR-0018):** metadata-write must be locked to the value-read trust tier — a metadata-only writer can redirect the credential (confused-deputy). `avp doctor` warns.
- **Deployed vs repo version:** notes support and schema evolve; if a note won't activate, check the running daemon version, not just the docs.
