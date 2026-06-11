# Quickstart: your first substitution

By the end of this walkthrough you will have AVP running and a single audit-log line proving it swapped a placeholder for a real API key on the way to the upstream. It runs entirely in your own user account, against one throwaway key. This is the demo, not the production setup: the hardened install is linked at the end. For why any of this works, read [concepts.md](concepts.md).

## What you need

- Python 3.12 or newer (`python3 --version`): AVP requires 3.12+.
- A Bitwarden Secrets Manager project and a machine-account token. First-time BWS setup is about 10 minutes: do [prerequisites.md](prerequisites.md) first, then come back here.
- A **throwaway** API key to broker. Use a free, revocable test token, never a production key. A free [Groq](https://console.groq.com/keys) key works well: free to mint, scoped to one service, and you can revoke it the moment you finish. This guide uses Groq.

## Store the throwaway key in BWS

In the BWS project from prerequisites, add the throwaway Groq key as a secret named `GROQ_API_KEY` (the same name you will use in the binding below). If you skip this, the proxy fails closed and the proof step shows `denied / secret_unavailable` instead of a substitution.

## Install AVP

```bash
python3.12 -m venv .venv
.venv/bin/pip install --only-binary :all: agent-vault-proxy
```

`--only-binary :all:` refuses source builds. If pip says it cannot find a binary distribution, the Rust-backed dependencies (`bitwarden-sdk`, `pydantic-core`) do not yet publish wheels for your Python version: use the newest Python that has them (3.12 is the safe floor) and recreate the venv.

## Write a local bindings file

Save this as `bindings.yaml` in the current directory. It brokers the one Groq key and writes its audit log right next to you, so the whole demo stays in your user account, no `sudo`. Set `organization_id` to your BWS organization UUID:

```yaml
version: 1

secrets:
  GROQ_API_KEY:
    placeholder: "gsk_PLACEHOLDER_01HXY1234567890ABCDEF"
    inject:
      header: "Authorization"
      format: "Bearer {GROQ_API_KEY}"
    bindings:
      - host: "api.groq.com"
        methods: [POST]
        paths: ["/openai/v1/chat/completions"]

audit:
  path: ./audit.jsonl
  fail_on_unwritable: true

backend:
  type: bws
  config:
    type: bws
    organization_id: "REPLACE-WITH-YOUR-BWS-ORGANIZATION-UUID"
    access_token_path: ./bws-token
    state_path: ./bws-state.json
```

Drop your machine-account token into the file `access_token_path` points at:

```bash
( umask 077 && printf '%s' 'YOUR-BWS-TOKEN' > bws-token )
```

No `unmatched_destination_policy` is set, so AVP uses its default (`forward_unmodified`): anything not bound is forwarded unchanged. That keeps the demo simple.

## Run the proxy

In one terminal, start AVP in the foreground:

```bash
.venv/bin/agent-vault-proxy --set avp_config=./bindings.yaml
```

It listens on `127.0.0.1:14322` and prints to this terminal. Leave it running. On first start it generates its CA at `~/.mitmproxy/mitmproxy-ca-cert.pem`.

## Run your first substitution

In a SECOND terminal, route through the proxy, trust its CA, export the PLACEHOLDER (never the real key), and call Groq:

```bash
export HTTPS_PROXY="http://127.0.0.1:14322"
export CURL_CA_BUNDLE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
export GROQ_API_KEY="gsk_PLACEHOLDER_01HXY1234567890ABCDEF"

curl -sS https://api.groq.com/openai/v1/chat/completions \
  -H "Authorization: Bearer $GROQ_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"llama-3.1-8b-instant","messages":[{"role":"user","content":"ping"}]}'
```

Your shell only ever held `gsk_PLACEHOLDER_...`. Groq received your real key, so you get a normal chat-completion response, not a 401.

## See the proof

Read the audit log AVP wrote next to your bindings file (run this from the same directory):

```bash
tail -n 1 audit.jsonl
```

You should see an `inject_decision` event like this:

```json
{"ts":"2026-06-10T14:32:11.123456+00:00","type":"inject_decision","request_id":"01HXY...","decision":"allowed","reason":"binding_matched","secret_name":"GROQ_API_KEY","destination":{"host":"api.groq.com","port":443,"path_prefix":"/openai/v1/chat/completions"}}
```

`"decision":"allowed"` with `"reason":"binding_matched"` is the substitution: the placeholder matched the `GROQ_API_KEY` binding, and the real key went on the wire to `api.groq.com`. The log records the decision, the secret name, and the destination, never the key value or the request body. That line is what this tutorial set out to show.

If you instead see `"decision":"denied"` with `"reason":"secret_unavailable:..."`, the key is not in BWS under `GROQ_API_KEY`, or the organization UUID or token in `bindings.yaml` is wrong. Fix that and retry.

## Next steps

This was the demo. It skipped the supply-chain controls (hash-pinned dependencies, release cooldown) and the systemd sandboxing that make the in-memory-isolation guarantee trustworthy in production, so do not point a real key at this setup. From here:

- Harden it for real use: [install-systemd.md](install-systemd.md) or [docker.md](docker.md).
- Point a real agent at the proxy, with the full client env-var block: [usage.md](usage.md).
- Add more secrets: one BWS entry plus a few lines under `secrets:` in `bindings.yaml`, then restart. The full grammar (path globs, body injection, composite secrets) is in [bindings.example.yaml](../bindings.example.yaml).

Revoke the throwaway Groq key when you are done.
