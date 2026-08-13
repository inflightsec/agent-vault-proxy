# Workflow: OauthLogin

Guide a non-engineer through connecting an **OAuth** service through kow end to end. The agent
**never sees the client secret or the refresh token** — the secret goes into the vault by the
user's own paste, and the refresh token is minted by the browser/phone consent and written
straight to the vault by `avp oauth login`.

> **Honesty up front — OAuth is not yet as simple as a static key.** A static key is one vault
> entry + a note (`AddSecret`). OAuth today needs **three vault secrets + one config-file binding
> + a one-time consent**, because the `oauth2_refresh` runtime is config-source only (a note can't
> express it yet) and it requires a client secret. Guide it patiently; do the mechanical parts
> for the user. The North-Star simplifications (note-based OAuth binding, client-id-in-note,
> public-client/no-secret) are tracked in SKILL Gotchas → "OAuth North Star".

## 0. Say this first (plain language, no jargon)

> "OAuth is how you let a tool use one of your accounts *without giving it your password*. Three
> one-time things: (1) you register the tool with the provider and copy an **ID** (and usually a
> **secret**) — think of it as a name badge for the tool; (2) you click **Allow** once in a
> browser (or type a code on your phone) and that mints a long-lived pass; (3) the long-lived
> pass lives in your vault, and the tool only ever gets a fresh pass that expires in an hour. I'll
> do all the mechanical parts; you just click Allow and paste two values into your vault."

## 1. Interview (choose the simplest working path; recommend a default each time)

1. **Provider** — google / github / microsoft / slack / atlassian / auth0 / okta. If it's on the
   preset list, we pass `--provider <name>` and the user never touches an endpoint URL. If not,
   we'll need its authorization + token endpoints from its API docs (uncatalogued path).
2. **Which host does the API live on?** (e.g. `www.googleapis.com`) — needed for the binding scope.
3. **Is the machine headless?** SSH'd mainframe / VPS with no browser → **device flow** ("type a
   code on your phone"). A laptop with a browser → **loopback** (a browser tab opens). It
   auto-detects, but tell the user which to expect.
4. **Scopes** — the narrowest permission that does the job (e.g. Google Calendar read-only
   `https://www.googleapis.com/auth/calendar.readonly`). Narrow = smaller blast radius.

## 2. Register the app at the provider (the one irreducible human step)

There is no way to skip this — the user must create an app registration in the provider's console
to get a client id/secret. Give the **exact click-path** and tell them precisely what to copy.
Two rules to state every time:
- **Choose the "Desktop app" / "Native" / "CLI" application type** when offered — it's the right
  fit for a local tool. (Note: most providers still hand you a client *secret* even for a desktop
  app; that's expected — vault it in §3. Truly secretless public clients aren't runtime-supported
  yet — see Gotchas.)
- **Redirect URI:** set it to **`http://127.0.0.1`** (loopback needs it; the exact ephemeral port
  is accepted per RFC 8252). For device flow, enable the **device authorization** grant instead.

**Google (Cloud Console):** APIs & Services → Credentials → *Create Credentials* → *OAuth client
ID* → Application type *Desktop app* → Create → copy the **Client ID** and **Client secret**. Then
enable the specific API (e.g. Google Calendar API) under *Enabled APIs*.

**GitHub:** Settings → Developer settings → *OAuth Apps* → *New OAuth App* → set the callback URL
to `http://127.0.0.1` → Register → copy the **Client ID**, then *Generate a new client secret* and
copy it.

**Other providers:** Developer/API settings → "Create OAuth app / client" → native/desktop type →
`http://127.0.0.1` callback (or enable device flow) → copy client id + secret. If it isn't a preset
provider, also copy its **authorization endpoint** and **token endpoint** URLs from the API docs.

## 3. Put the values in the vault (the user pastes; the agent never sees them)

Pick a provider prefix in `SCREAMING_SNAKE_CASE` (e.g. `GCAL`). Have the user create **three**
Bitwarden Secrets Manager entries:

> 1. **`GCAL_CLIENT_ID`** — value = the Client ID you copied.
> 2. **`GCAL_CLIENT_SECRET`** — value = the Client secret you copied.
> 3. **`GCAL_REFRESH_TOKEN`** — create it **empty**. If your vault UI won't accept a truly empty
>    value, use a real placeholder string that starts with `avp-PLACEHOLDER-` — **not** a bare
>    character or word: `avp oauth login` treats any non-empty, non-placeholder value as an
>    already-live token and refuses to overwrite it without `--force`. The next step fills it.

State plainly: "I never see these — you paste them into your vault, same as an API key."

## 4. Add the OAuth binding (the one config exception — flag it)

A note can't express `oauth2_refresh` yet, so this binding lives in the kow **config file** and
needs a daemon reload. Emit this block for the operator to add under `secrets:` in
`bindings.yaml`, then have them reload kow:

```yaml
secrets:
  GCAL_API:                       # the consumer emits THIS secret's placeholder
    inject:
      type: oauth2_refresh
      provider: google            # or: token_url + client_auth_method for an uncatalogued provider
      client_id_secret: GCAL_CLIENT_ID
      client_secret_secret: GCAL_CLIENT_SECRET
      refresh_token_secret: GCAL_REFRESH_TOKEN
      scopes: "https://www.googleapis.com/auth/calendar.readonly"
    bindings:
      - host: www.googleapis.com
        methods: [GET]            # scope down: read-only can't POST/DELETE
```

Reload the daemon after adding it (notes/config are read at startup). This is the single step that
still touches the config — call it out honestly, and see Gotchas → "OAuth North Star" for the
follow-up that removes it.

## 5. Run the consent — `avp oauth login` (the agent runs this; the user just approves)

This is the magic step: it drives the browser/phone consent and writes the refresh token straight
into `GCAL_REFRESH_TOKEN`. **The token value never appears in the terminal, a log, or this chat.**

```bash
avp oauth login GCAL \
  --provider google \
  --client-id-secret GCAL_CLIENT_ID \
  --client-secret-secret GCAL_CLIENT_SECRET \
  --refresh-token-secret GCAL_REFRESH_TOKEN \
  --scopes "https://www.googleapis.com/auth/calendar.readonly"
#   laptop  → a browser tab opens; the user clicks Allow.
#   headless→ it prints "visit <url> and enter code: XXXX"; the user approves on their phone.
#   add --device / --loopback to force a flow; --callback-port for a firewalled loopback.
#   uncatalogued provider (no --provider): pass --authorization-endpoint / --token-endpoint
#     / --device-authorization-endpoint instead (do NOT combine those with --provider).
```

On success it prints only the secret name it populated. If it fails, it prints a clear reason
(consent denied, provider needs an offline scope, device flow not enabled for this client) — relay
it; nothing sensitive is in the message.

## 6. Wire the consumer + reload (BLOCKING — same as AddSecret §5)

The binding injects nothing until the consuming app **emits `GCAL_API`'s placeholder**. Get the
placeholder (`kow env --print | grep GCAL_API` on the kow host), put that `export GCAL_API='…'`
line into the app's `.env`, and reload the daemon. A binding whose placeholder never reaches the
consumer is the #1 "kow isn't working" cause.

## 7. Verify (user runs)

- `kow doctor --binding GCAL_API --probe-oauth` — resolves the three secrets and checks the SSRF
  guard, read-only. Add `--exchange` to do one live refresh (it reports whether the provider
  **rotated** the refresh token — if it did, note that write-back must be enabled/working).
- Confirm the consumer emits the exact `GCAL_API` placeholder and the daemon was reloaded.

## 8. Security recap (state briefly)

- The agent never saw the client secret or the refresh token — the secret was pasted into the
  vault by the user; the refresh token was minted by consent and written to the vault by the CLI.
- **One refresh secret per host.** Don't point two machines at the same `*_REFRESH_TOKEN` — if the
  provider rotates, the second machine gets locked out.
- Scope tightly (read-only, narrow host/methods) — it caps what a compromised binding can do.
- Rotating providers (Microsoft, Slack, Atlassian, Auth0) need kow **write** on the refresh
  secret; non-rotating (Google) can run read-only if you seed the token by hand and set
  `refresh_token_write_back: false`.
