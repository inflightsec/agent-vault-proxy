# Attack gallery — the exfil-regression guarantee ledger

Per [ADR-0043](../../docs/adrs/ADR-0043-adversarial-attack-gallery.md). Each file
here is **one working exploit** that drives the real addon inject path
(`http_connect` → `requestheaders` → `request` → `response`, no mock of the
inject path) and asserts **fail-to-exfil**: the real secret value never reaches
anywhere the agent can read — request it launders, response body/headers, error
text, the audit log, or a later request's response.

This directory is the single readable answer to "what does keys-on-the-wire
claim to defend, and is it still true?"

## Verdict states — both build-gated

- **defended** — asserts the secret does *not* exfil. A regression that re-opens
  it turns the build red.
- **expected-leak** — a `@pytest.mark.xfail(strict=True)` that asserts the
  *desired* end state for a class we have not yet closed. It fails today (xfail),
  and the day the defense lands it starts passing → `strict=True` turns that
  **unexpected pass** red, forcing the entry to flip. No silent "we leak here
  forever," no forgotten flip. Every expected-leak names a `BLOCKED-BY: ADR-NNNN`.

`test_meta_markers.py` enforces both conventions (`THREAT:` on every file,
`BLOCKED-BY:` on every expected-leak).

## The catalog

| Exploit | Threat | State | Blocked by |
|---------|--------|-------|-----------|
| `test_scope_bypass` | T-1.5 laundering a bound token onto an off-scope request | defended | — |
| `test_ssrf_to_vault` | T-1 point a request at the credential backend host | defended | — |
| `test_audit_exfil` | T-1 read the secret out of kow's own audit log | defended | — |
| `test_injection_confinement` | T-1.5 smuggle a placeholder into a non-target header | defended | — |
| `test_cross_binding` | T-1.5 spend secret A's value under secret B's binding | defended | — |
| `test_inject_precondition` | T-1 guards that injection works (so xfails can't prove nothing) | defended | — |
| `test_reflection` | T-1 upstream reflects the injected secret into its response body | **expected-leak** | ADR-0031 |
| `test_header_reflection` | T-1 upstream reflects the secret into a response header | **expected-leak** | ADR-0031 |
| `test_create_then_read` | T-1 store the placeholder, read the real secret back later | **expected-leak** | ADR-0031 |

`expected-leak` tests carry **no** sanity `assert` of their own — a failing
precondition inside a strict-xfail would be masked as an expected failure
(Oracle C1). `test_inject_precondition` is the standalone guard that injection
actually happens. Known-but-unwritten channels (query-string echo, compressed /
chunked body echo, streaming responses) are named in the ADR's "Documented
future exploits" so their absence is not read as coverage.

Threat IDs map to [`docs/paper/threat-model.md` §2.2](../../docs/paper/threat-model.md).

## Run

```sh
pytest -m attacks
```

The expected-leak entries are part of the pass contract — they must leak
*exactly* as documented (strict xfail).
