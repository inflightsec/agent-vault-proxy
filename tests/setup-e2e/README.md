# setup-e2e

Real `avp setup --no-service` in a disposable Ubuntu container, end state
asserted with bats: service user, every mode/owner, append-only audit log,
service file written but never activated, idempotent rerun, mutation-free
dry-run. Run `bash tests/setup-e2e/run.sh`; CI job: `e2e-setup`.

Same `setup.bats` validates the macOS executor on a real Mac (provisions
the host; token prompt is interactive). Install `avp` somewhere `_avp` can
execute first — setup bakes `sys.executable` into the service definition.

```sh
brew install bats-core && sudo bats tests/setup-e2e/setup.bats
```
