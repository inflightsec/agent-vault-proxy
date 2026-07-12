# Container-free end-to-end test

A real `mitmdump` proxy process (static backend, file bindings) plus a local
HTTP echo upstream, driving live traffic through the proxy. It asserts the same
behaviour as [`../docker-e2e`](../docker-e2e/) — **without a container runtime** —
so it runs in the **main CI pytest job** and on any dev box (Docker not
required).

## What it proves (on the wire)

| Case | Assertion |
|------|-----------|
| POS-HDR | Bearer header gets the real secret; placeholder never leaves |
| POS-BODY | placeholder in the JSON body is substituted in-stream |
| POS-MULTI | one placeholder lands in a header AND the body on one request |
| POS-COMPOSITE-HEADER | `inject.template` renders `Basic base64(user:pass)` |
| POS-COMPOSITE-BODY | same compose machinery rendered into the JSON body |
| FAILCLOSED | a bound secret missing from the store → `503`, never forwarded |
| NEG | an unbound destination → `403` deny |
| AUDIT | allowed `inject_decision` + `deny` recorded; **no secret bytes in any log** |

(oauth2_refresh is covered by unit tests; it needs a mock HTTPS token endpoint
and is left to the docker harness.)

## Run it

Via pytest (the normal suite already includes it):

```bash
pytest tests/local-e2e -q
```

By hand:

```bash
bash tests/local-e2e/run.sh   # exit 0 = all assertions passed
```

## Security posture

- Everything lives in a per-run `mktemp` dir (mode `0700`), removed on exit.
- The static secrets file is generated with **random** values, `chmod 0600`, and
  is **never committed** — only placeholders live in `bindings.template.yaml`.
- Proxy and echo bind `127.0.0.1` only; mitmproxy's `confdir` is inside the temp
  dir; no external network is contacted.
- The proxy runs in its own process group and is always reaped; the client
  asserts no real secret bytes appear in the audit log or the proxy log.
