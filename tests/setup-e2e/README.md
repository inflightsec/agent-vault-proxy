# setup-e2e — `avp setup --no-service` integration suite

`run.sh` builds the wheel and runs a real `avp setup --no-service` as root
inside a disposable Ubuntu container (`--cap-add LINUX_IMMUTABLE` for the
append-only audit lock). `setup.bats` asserts the provisioned end state:
service user, every directory/file mode and owner, append-only audit log,
service file written but never activated, idempotent rerun,
tighten-never-widen, and a mutation-free `--dry-run`.

The same `setup.bats` validates the macOS executor on a real Mac
(provisions the host for real; the token prompt is interactive there):

```sh
brew install bats-core
sudo bats tests/setup-e2e/setup.bats
```

Install `avp` somewhere the `_avp` service user can traverse and execute
first (system Python or a `/usr/local` venv, not a user-home venv): setup
bakes `sys.executable` into the `sudo -u _avp` steps and the service
definition.

CI: the `e2e-setup` job in `.github/workflows/test.yml`.
