# Google Secret Manager backend — setup & testing

How to keep your secrets in Google Secret Manager (GSM) and have `agent-vault-proxy`
inject them just-in-time. This is the GSM equivalent of [prerequisites.md](prerequisites.md)
(which covers Bitwarden). Config reference: [adapter-architecture.md](adapter-architecture.md);
design: [ADR-0018](adrs/ADR-0018-gcp-secret-manager-backend.md).

The idea in one line: **each secret carries its own destination host in an
`avp-binding` annotation**, so `binding_source: notes` needs no `secrets:` block —
you just add the secret to GSM and tag it with the host it's allowed to reach.

## 0. Prerequisites

- A GCP project (`gcloud config get-value project` to see your current one).
- `gcloud` installed and logged in (`gcloud auth login`).
- `agent-vault-proxy` installed **with the `gsm` extra**:
  ```bash
  pip install 'agent-vault-proxy[gsm]'      # adds google-auth
  ```
- Enable the Secret Manager API once:
  ```bash
  gcloud services enable secretmanager.googleapis.com --project=YOUR_PROJECT
  ```

## 1. Add a secret — tagged with the host it's for

The whole trick is the `avp-binding` annotation. Prefix the secret name with a
namespace (here `avp-<you>-`) so the proxy's identity can be scoped to just your
secrets later.

```bash
printf '%s' 'sk-your-real-openai-key' | gcloud secrets create avp-OPENAI_API_KEY \
  --project=YOUR_PROJECT \
  --annotations="avp-binding=api.openai.com" \
  --data-file=-
```

That's it — the bare hostname is the common case. Need more control? Use a small
YAML block instead (block style, no inline commas — gcloud treats commas as the
annotation separator):

```bash
gcloud secrets update avp-OPENAI_API_KEY --update-annotations=$'avp-binding=host: api.openai.com\nmethods:\n- POST\npaths:\n- /v1/**'
```

A secret **with no `avp-binding` annotation is never injected** (fail-closed).

## 2. Authenticate — keyless, no key files

Two options. There is deliberately **no key-file field** — downloadable
service-account keys are refused.

**a) Quickest (your own login) — for a first test.**
```bash
gcloud auth application-default login
```

**b) Production (a scoped, low-privilege service account).** Create it, grant it
access to *only* your secrets with `avp gcp-setup` (which **refuses** any
project-level grant), then impersonate it:
```bash
gcloud iam service-accounts create avp-ro --project=YOUR_PROJECT

avp gcp-setup --project=YOUR_PROJECT \
  --member=serviceAccount:avp-ro@YOUR_PROJECT.iam.gserviceaccount.com \
  --secret=avp-OPENAI_API_KEY          # repeat --secret per secret

# let your login impersonate it (needs roles/iam.serviceAccountTokenCreator on the SA)
gcloud auth application-default login \
  --impersonate-service-account=avp-ro@YOUR_PROJECT.iam.gserviceaccount.com
```

> **Heads-up (the security feature working):** if you authenticate as a broad
> identity (e.g. project **Owner**) with `self_check: deny`, the proxy will
> **refuse to start** — it detected that the identity can read *every* secret in
> the project, not just its own. That's correct. For a quick test set
> `self_check: warn`; for real use, use the scoped SA above and keep `deny`.

## 3. Point AVP at GSM

A minimal `bindings.yaml` — no `secrets:` block, because the bindings live on the
secrets themselves:

```yaml
version: 1
secrets: {}
binding_source: notes            # bindings come from the avp-binding annotations
unmatched_destination_policy: deny
audit:
  path: ./audit.jsonl
backend:
  type: gsm
  config:
    type: gsm
    project_id: "123456789012"   # project NUMBER (gcloud projects describe YOUR_PROJECT --format='value(projectNumber)')
    secret_prefix: "avp-"  # only secrets under this prefix are in scope
    self_check: warn             # use `deny` once you're on a scoped SA
    # impersonate_service_account: avp-ro@YOUR_PROJECT.iam.gserviceaccount.com
```

## 4. Verify the connection (read-only)

```bash
avp doctor --probe-gcp --config ./bindings.yaml
```

You'll get a scope report — auth, whether you can enumerate outside your prefix,
whether you hold project-wide access, and how many secrets are in scope. This
proves AVP can reach GSM and see your secret, without sending any traffic.

### The annotation trust boundary (and how to close it)

Because the host lives in the `avp-binding` annotation, whoever can **edit** a
secret's annotations controls where it's sent — and on GCP,
`secretmanager.secrets.update` (edit annotations) and `secretmanager.versions.access`
(read the value) are **independently grantable**. So a principal who can write
annotations but not read a secret could point it at a host they control and let
AVP inject it there (a confused deputy). `avp doctor --probe-gcp` flags this with an
`annotation-trust` warning.

Two ways to close it, ideally both:

1. **IAM (primary):** restrict `secretmanager.secrets.update` on these secrets to
   the same principals trusted to read them.
2. **`notes_host_allowlist` (structural backstop, ADR-0024):** set a top-level list
   of trusted hosts in `bindings.yaml`. An annotation host outside the list is
   rejected fail-closed (audit reason `host_not_in_allowlist`); annotations can then
   only **narrow** scope, never add a host. With it set, the doctor `annotation-trust`
   check flips from WARN to OK.
   ```yaml
   notes_host_allowlist:
     - api.openai.com
     - api.internal.acme.com
   ```

## 5. Test injection end-to-end

Start the proxy (listens on `127.0.0.1:14322`):
```bash
python -m agent_vault_proxy --set avp_config=./bindings.yaml
```

In another terminal, get the **placeholder** the agent should use (AVP never lets
the agent hold the real key):
```bash
avp env --config ./bindings.yaml --print
# -> export avp-OPENAI_API_KEY='sk-PLACEHOLDER-…'
```

Now send a request **through the proxy** with the placeholder. AVP matches the
placeholder, confirms the destination is `api.openai.com` (from the annotation),
swaps in the real key, and forwards it. The proxy MITMs TLS, so trust its CA:
```bash
curl -x http://127.0.0.1:14322 \
  --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer sk-PLACEHOLDER-…"
```

**Success looks like:** OpenAI returns `200` (the real key was injected), and the
`avp-binding` audit line in `./audit.jsonl` shows `"decision":"allowed"` — with
**no secret bytes** in the log. Point the same request at a host you did *not*
bind and it's denied with `403`.

## Troubleshooting

- **Proxy refuses to start with "project-wide access":** working as intended —
  your identity is too broad. Use a scoped SA (step 2b) or `self_check: warn`.
- **`403` on your bound host:** the secret has no `avp-binding` annotation, or its
  host doesn't match — check with `gcloud secrets describe NAME --format='value(annotations)'`.
- **`google-auth` not found:** install the extra — `pip install 'agent-vault-proxy[gsm]'`.
- **Curl TLS error:** pass `--cacert ~/.mitmproxy/mitmproxy-ca-cert.pem` (generated on the proxy's first request).
