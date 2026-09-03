# Prerequisites: Bitwarden Secrets Manager setup

The proxy needs a Bitwarden Secrets Manager project and a machine-account access token. If you don't have them yet (~10 minutes the first time):

1. **Enable Secrets Manager on your Bitwarden organization**: [bitwarden.com/help/secrets-manager-overview](https://bitwarden.com/help/secrets-manager-overview/). The free tier covers personal use; team/enterprise plans cover production.

2. **Create a project** for this host (e.g. `claude-laptop`, `ci-runner-prod`), then add the secrets you want to broker as project-scoped entries - one per API (`OPENAI_API_KEY`, `GITHUB_PAT`, `ANTHROPIC_API_KEY`, …). Use the same name in BWS as you'll declare in `bindings.yaml`.

3. **Create a machine account**, grant it **read** access to the project from step 2, and generate an access token. The token lives in:
   - `/etc/kow/bws-token` (mode `0440 root:kow`) for the bare-metal install, or
   - `./secrets/bws-token` (mode `0600`) for the Docker install.

   The project's organization UUID goes into `bindings.yaml` under `backend.config.organization_id`. See `bindings.example.yaml` for the shape.

**Project and machine-account scoping (please read this).** What a compromised BWS token exposes is exactly the secrets in the projects that machine account can read. Two rules:

- **One BWS project per kow instance.** Don't pool unrelated services into one shared project so they can all reach each other's secrets - that turns one bad binding into a multi-service leak.
- **Separate machine accounts per environment.** Staging laptop's kow, CI runner's kow, and prod host's kow each get their own machine account with read access to a single project scoped to that environment. Don't reuse one token across hosts; if one leaks, you only burn one environment.

If you already keep, say, Stripe + AWS + Datadog in one combined "production" project for human use, create *separate* BWS projects for kow brokerage and put only the per-environment subset in each.

The proxy needs nothing else from Bitwarden, no master key, no user account, no API beyond the read-scoped machine token.

Once you have the token and organization UUID, pick an install path:
- [install-systemd.md](install-systemd.md): bare-metal Linux + systemd (most hardened)
- [docker.md](docker.md): Docker (cross-platform, comparable hardening with trade-offs)

## Self-hosted Bitwarden

The proxy works against any deployment that exposes the BWS Secrets Manager API. Defaults assume Bitwarden cloud (US region). To point at a different deployment, set `api_url` and `identity_url` under `backend.config` in `bindings.yaml`:

| Deployment | `api_url` | `identity_url` |
|---|---|---|
| Bitwarden cloud, US | `https://api.bitwarden.com` (default) | `https://identity.bitwarden.com` (default) |
| Bitwarden cloud, EU | `https://api.bitwarden.eu` | `https://identity.bitwarden.eu` |
| Self-hosted Bitwarden | `https://vault.example.com/api` | `https://vault.example.com/identity` |

**Private CA on self-hosted:** If your self-hosted Bitwarden uses a TLS cert signed by a private CA, the proxy needs to trust that CA: separately from the host's CA trust:

- **Bare-metal install:** install the CA into the system trust store using your distro's normal procedure (Debian/Ubuntu: drop the PEM in `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`; RHEL/Fedora: `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust`). The proxy uses the system trust store via `ca-certificates`.

- **Docker install:** either bake the CA into a custom image layer (`COPY your-private-ca.pem /usr/local/share/ca-certificates/private-ca.crt` + `RUN update-ca-certificates`), or extend `docker-compose.yml` with a bind-mount of the CA file under `/usr/local/share/ca-certificates/` and an entrypoint that runs `update-ca-certificates` before the proxy starts.

**Vaultwarden is NOT supported.** Vaultwarden is a community Rust reimplementation of the Bitwarden password-manager API only - it does not implement the BWS Secrets Manager API that this proxy depends on. If you're running Vaultwarden today, you'd need to switch to the official self-hosted Bitwarden distribution (which does include Secrets Manager) for this proxy to work.
