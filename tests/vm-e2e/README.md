# VM end-to-end

Boots a throwaway Debian VM under QEMU/KVM with **real systemd** and follows
`docs/install-systemd.md` step by step for the static backend, then asserts the
whole chain on the wire.

```bash
bash tests/vm-e2e/run.sh                 # Linux, systemd leg (default), ~4 min
bash tests/vm-e2e/run.sh all             # all six Linux legs, ~25 min
bash tests/vm-e2e/run.sh pypi            # build + install from a mock PyPI index
bash tests/vm-e2e/run.sh readme          # walk the README quickstart
bash tests/vm-e2e/run.sh tls             # TLS interception only
bash tests/vm-e2e/run.sh docker          # container path only
bash tests/vm-e2e/run.sh rootless        # unprivileged install only
bash tests/vm-e2e/run.sh --keep all      # leave it up: ssh -F /dev/null -p 2222 debian@127.0.0.1
bash tests/vm-e2e/run-macos.sh           # macOS launchd leg (default), ~8 min
bash tests/vm-e2e/run-macos.sh brew      # the tap formula, built from source, ~15 min
bash tests/vm-e2e/run-macos.sh all       # both macOS legs
```

## The four legs

| Leg | Script | Asserts |
|---|---|---|
| systemd | `guest-install.sh` | the documented bare-metal install: service user, `chattr +a`, real unit, journald |
| docker | `guest-docker.sh` | the repo `Dockerfile` builds, runs as unprivileged `kow`, brokers through a published port |
| tls | `guest-tls.sh` | **the core capability**: a real TLS connection intercepted, the credential swapped *inside* the encrypted request, upstream chain genuinely verified |
| rootless | `guest-rootless.sh` | no sudo, no `/etc`, no service account — venv in `$HOME`, config in `$KOW_CONFDIR` |
| pypi | `guest-pypi.sh` | builds sdist+wheel from this tree, serves a PEP 503 index, installs from it — packaging, console scripts, extras |
| readme | `guest-readme.sh` | walks the README quickstart command by command, ending in the README's own end-to-end promise |
| brew | `guest-brew.sh` | the REAL tap formula, repointed at a locally built sdist: `brew install --build-from-source` |
| macOS | `guest-install-macos.sh` | `dscl` account, `/usr/local` prefix, `chflags sappnd`, launchd |

Every leg ends with the same four wire assertions: healthz 200, a real placeholder
swapped for a real secret upstream, an unbound destination refused 403, and **no
secret bytes in any log**.

### Why the tls leg matters

Every other harness here — and `tests/local-e2e` — asserts substitution over
plain HTTP. The tls leg is the only proof that kow does the thing it exists for.
It stands up an HTTPS upstream behind a real CA, points kow at that CA with
`ssl_verify_upstream_trusted_ca` (**not** `--ssl-insecure`, so the upstream hop
is genuinely verified), and then proves interception actually happened: a client
trusting *only* the upstream CA must FAIL, because kow re-signs with its own.

### Rootless is a convenience, not the hardened deployment

The rootless leg runs kow as the calling user — no root anywhere. That is useful
where you have no admin rights, but it puts the proxy and the agent at the **same
UID**, which dissolves the boundary the design rests on (`docs/architecture.md`:
anything at the agent's UID can use the proxy as its own authenticated channel,
and can also just read the config). Use the system install for a real deployment.

The legs share one VM and are independent: docker publishes on its own host port
so it cannot collide with a running systemd unit, and the rootless leg snapshots
`/etc` first so a system install from another leg is never mistaken for its own.

The macOS leg drives the Sequoia VM that already exists on the mainframe for the
Laima iOS gate (`~/ios-gate-dev`, ADR-0036). It is a **shared resource**: the
harness reverts to the golden snapshot before and after every run and never
writes a new one.

## Why a VM and not a container

These cannot be exercised anywhere else:

| Needs a real VM | Why |
|---|---|
| `chattr +a` on the audit log | overlayfs/tmpfs reject the attribute |
| `systemctl enable --now kow` | no PID 1 in a container |
| the hardened unit's sandboxing | `ProtectSystem`, `ReadWritePaths`, `User=avp` |
| `journalctl` secret-leak check | no journald in a container |
| a real service user + 0700 CA confdir | uid separation is the ADR-0012 boundary |

## The documentation is the test

The systemd unit is **extracted from `docs/systemd-unit.md`** at run time, not
copied into the harness, and the install follows the documented commands rather
than calling `kow setup`. A doc that drifts from reality fails here.

`extract_doc_steps.py` dumps the runnable blocks from an install doc
(`python3 tests/vm-e2e/extract_doc_steps.py docs/install-systemd.md --list`).

## Findings this harness has already caught

- `systemctl enable --now keys-on-the-wire` — the documented unit name never
  existed (real unit: `kow.service`); the install could not be followed.
- `kow --version` was documented in `_healthz.py` but the flag did not exist.
- The documented macOS account recipe hardcodes uid/gid **250**, which is the
  stock `_analyticsusers` group on every Mac. `dscl` then leaves the group with
  no `PrimaryGroupID` and `install -d -g _kow` dies with "illegal group name" —
  the macOS install could not be followed on any machine.
- The Python >= 3.12 requirement was documented nowhere; macOS ships 3.9.
- The documented install left `/var/lib/kow/.mitmproxy` at 0755, exposing the CA
  private key directory to other UIDs and failing `kow doctor` (ADR-0012).

## Not yet covered

- Docker / compose path (needs a reachable docker daemon).
- Non-root / rootless install.


## Prerequisites

| Leg | Needs |
|---|---|
| all Linux legs | `qemu-system-x86_64` + `/dev/kvm`; the Debian cloud image is fetched once into `/tmp/kow-vm` (override with `KOW_VM_WORK`) |
| macOS legs | the Sequoia VM at `~/ios-gate-dev` (override with `KOW_MACOS_GATE`) |
| brew leg | a checkout of the tap at `/home/shared/nfs/src/homebrew-keys-on-the-wire` (override with `KOW_TAP`) — it tests the REAL formula |

Both harnesses are safe to re-run: the Linux legs boot a throwaway overlay and
delete it, and the macOS legs revert the shared VM to its golden snapshot before
**and** after, never writing a new one.

Known host gotcha: if `ssh` refuses to start with *"Bad owner or permissions on
/etc/ssh/ssh_config.d/…"*, that is the host's config, not the VM — both runners
already pass `-F /dev/null`.
