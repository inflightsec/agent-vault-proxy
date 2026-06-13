# setup-e2e

Real `avp setup --no-service` in a disposable Ubuntu container, end state
asserted with bats: service user, every mode/owner, append-only audit log,
service file written but never activated, idempotent rerun, mutation-free
dry-run. Run `bash tests/setup-e2e/run.sh`; CI job: `e2e-setup`.

On a real Mac, `bash tests/setup-e2e/run-macos.sh` runs the whole thing —
builds a throwaway `/tmp` venv (world-traversable, so `_avp` can reach the
interpreter `avp setup` bakes in), runs `setup.bats`, and tears the host state back down.
`brew install bats-core` first; you're prompted once for a throwaway token.
