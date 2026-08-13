# Quickstart

kow is a local proxy that swaps a placeholder for the real secret in-flight, so your agent never holds the credential. Five steps — no config file to hand-write.

## 1. Install

Mac:

```bash
brew install inflightsec/keys-on-the-wire/keys-on-the-wire
```

Anywhere with Python 3.12+:

```bash
pipx install keys-on-the-wire
```

## 2. Set it up

```bash
sudo kow setup --bws
```

Installs the service and prompts for your **Bitwarden Secrets Manager machine-account token**. (Create the machine account in the BWS console first and copy its access token.)

## 3. Install the skill

In Claude Code:

```
/plugin marketplace add inflightsec/keys-on-the-wire
/plugin install kow@keys-on-the-wire
```

## 4. Ask the skill for the binding

Just ask, in plain English:

> Add my `GROQ_API_KEY` to kow

The skill hands you the exact `# kow-binding` note — which host, which header — for that secret. No YAML, no redeploy.

## 5. Add the secret

In Bitwarden Secrets Manager, create the secret (`GROQ_API_KEY` = your key) and paste the skill's `# kow-binding` note into its **Notes** field.

That's it. kow re-reads the vault on a timer (default every 60s) and starts brokering the new key automatically — no restart, no redeploy. (Tune or disable with `notes_refresh_seconds`.)

---

Point your agent at the proxy (`HTTPS_PROXY=http://127.0.0.1:14322`) and export the **placeholder** instead of the real key: the real secret goes on the wire, your process never holds it. `kow doctor` confirms the setup.

Going deeper — hardening, how it works, and the full binding grammar: [install-systemd.md](install-systemd.md) · [concepts.md](concepts.md) · [bindings.example.yaml](../bindings.example.yaml).
