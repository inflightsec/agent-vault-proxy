# setup-e2e

Real `avp setup --no-service` in a disposable Ubuntu container, end state
asserted with bats: service user, every mode/owner, append-only audit log,
service file written but never activated, idempotent rerun, mutation-free
dry-run. Run `bash tests/setup-e2e/run.sh`; CI job: `e2e-setup`.

On a real Mac, `bash tests/setup-e2e/run-macos.sh` runs the whole thing —
builds a throwaway `/tmp` venv (world-traversable, so `_avp` can reach the
interpreter `avp setup` bakes in), runs `setup.bats`, and tears the host state back down.
`brew install bats-core` first; you're prompted once for a throwaway token, and
macOS asks to "administer your computer" because real provisioning needs admin.

`--static` does the same real install backed by a file-based static secrets
backend instead of Bitwarden — no machine account, no token prompt. The suite
runs identically for either backend (`AVP_BACKEND=bws|static`); only the
secret-source assertion differs.

`--dry-run` is the lightweight smoke: it runs `avp setup --no-service --dry-run`
as your normal user and checks the plan renders — no `sudo` (no admin prompt),
no Bitwarden, no token, nothing provisioned.
