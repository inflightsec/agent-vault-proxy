# ADR-0046 — macOS Keychain secrets backend

**Status:** Accepted
**Date:** 2026-08-16
**Supersedes:** none
**Related:** ADR-0038 (AWS Secrets Manager backend — the driver structure this mirrors)

## Context

kow ships four backends. Three of them (`bws`, `gsm`, `aws-secrets-manager`) need a cloud vault account; the fourth, `static`, keeps secrets in plaintext YAML and says so loudly because it exists for development and the docker e2e harness, not for production.

That leaves a Mac user with two bad options on first contact: sign up for a vault before they have decided whether kow is useful, or put their real API keys in a plaintext file. Neither is a reasonable first five minutes, and the second one is the thing kow exists to prevent.

macOS already ships a credential store. The question was which one, and what it actually buys.

## Decision

Add a `keychain` backend that reads and writes generic-password items in a **file-based** macOS keychain — the login keychain by default — by shelling out to `/usr/bin/security`.

Configuration:

```yaml
backend:
  type: keychain
  config:
    type: keychain
    service: kow                    # generic-password "service" attribute
    keychain: null                  # optional path; null = default (login) keychain
    secret_prefix: null             # optional namespace bound
    self_check: deny                # deny | warn | off
    timeout_seconds: 10.0
```

Six fields, no more. `kow secret add | list | remove | rotate` manage it, alongside the `static` backend they already managed.

### What this buys

- No plaintext credential on disk. The keychain is encrypted with a key derived from the account's login password.
- A view the operator already knows: Keychain Access, filtered on the `service` string.
- No vault account, no token file, no network round trip — the zero-friction onboarding path.

### What it does not buy, stated plainly

**Access is scoped to the user account, not to kow.** Keychain ACLs bind to a signing identity. Distributed through PyPI and Homebrew, kow is not a Developer-ID-signed application, and shelling out makes the ACL identity `/usr/bin/security` itself — so anything running as the same user can read the same items. In practice the boundary is the same as a `0400` file, plus at-rest encryption, plus a GUI view, minus the plaintext.

That is a real improvement and an honest one. The docs say it in the same breath as the feature, because a credential store that hides its own boundary is worse than one that states it.

The topology that makes the boundary hold: run kow as a **LaunchAgent in the operator's account**, and keep agent workloads in a **separate macOS account**. Per-user keychain encryption is the wall; the ACL is not.

## Two implementation decisions worth the ink

**Writes never touch `argv`.** The macOS process table is world-readable, so `security add-generic-password -w <value>` publishes the credential to every local user for the duration of the call. The backend uses `security -i` instead, handing the command line to the child on **stdin**. The interactive parser needs the value quoted, and a quoting bug would store a mangled credential while looking like success — so `update()` reads the value back and refuses the write unless it compares equal. Correctness of the quoting is verified, not assumed.

**The `security` binary is addressed absolutely.** No `PATH` lookup, no config field, no environment override. A configurable path to a security-critical binary is a hijack surface handed to anything that can edit config or environment. Tests substitute the binary by monkeypatching the module attribute, which requires already being inside the process.

## Alternatives rejected

| Alternative | Why not |
|---|---|
| **The macOS Passwords app** | No read API — not via CLI, AppleScript, Shortcuts, or any public framework, through macOS 26. Apple DTS is explicit: there is no command-line tool access to the data-protection keychain. Passwords reads *only* that keychain; `security` writes *only* the file-based one. kow items can never appear in Passwords, and Passwords items can never be read by kow. This is by design and is not going to change. |
| **Credential Exchange (CXP/CXF)** | User-initiated migration between *entitled, registered* credential managers. Sealed blob, biometric-gated, and no working macOS receivers as of mid-2026. Not an access API. |
| **Python `keyring`** | Its ACL identity is the whole interpreter: any script run under the same Python reads kow's secrets silently. That is the worst possible shape for a credential proxy — and it is a dependency, which this backend does not need. |
| **Data-protection keychain with `SecAccessControl` / Touch ID** | Requires validated `keychain-access-groups` entitlements, i.e. a Developer-ID-signed binary with a Team Identifier ($99/yr). Also structurally unavailable to LaunchDaemons (TN3137). This is the L2 tier and gets its own ADR if we take it. |
| **`kSecAttrSynchronizable` (iCloud sync)** | Forces the data-protection keychain, same entitlement wall, and synced items still do not surface usefully in Passwords. The login keychain never syncs; for a fleet, use a networked backend. |
| **`-T` ACLs for real app-scoping** | Ad-hoc and linker-signed binaries are cdhash-bound, so every upgrade re-prompts (a well-documented failure in comparable tools). Under Homebrew/PyPI distribution `-T` buys friction, not a boundary. |

## What the write path defends against

Storing a *silently shortened* credential is the worst outcome available here, because everything downstream still looks fine. Four defences, in order of when they fire:

1. **Untransmittable bytes are refused before a child is spawned.** A newline ends the interactive command line; a NUL ends the C string on the far side of the pipe. Either one stores a prefix. Both are rejected at the API boundary for the value, the name, **and the configured keychain path** — which rides the same command line and was the one input originally left unchecked. `service` is additionally constrained to `^[A-Za-z0-9._-]+$` at config-load, because it travels through the command line *and* back out of `dump-keychain`'s escaped text format; one conservative charset removes both problems at the boundary rather than defending them at two runtime sites.

1b. **The subprocess's own report is not treated as evidence.** `security -i` exits 0 even when a command inside the session failed, and it can write to stderr on a write that landed perfectly well. So the invocation result is *recorded*, and verification runs either way. A noisy-but-correct write is accepted (with a warning); a write that errored *after* creating an item still reaches its own cleanup, carrying the original `security` error alongside the mismatch rather than in place of it.
2. **Duplicate `(service, account)` pairs abort the write.** `add -U`, `find`, and `delete` all act on an unspecified *first match*. With a duplicate present the read-back can verify a different item than the one written, and pass or fail for the wrong reason. The backend refuses to reason about it and says which pair to clean up.
3. **The read-back compares in constant time.** Not via `Secret.__eq__` — that calls `hmac.compare_digest` on `str`, which raises `TypeError` on any non-ASCII character. A credential with a non-ASCII byte is unusual but legal, and a write path that crashes on one is worse than one that compares it.
4. **Failure compensates according to what it broke.** A failed *create* deletes the partial item — nobody depended on it, and a readable mangled credential is worse than none. A failed *update* does **not** delete: the prior value is already gone, and deleting would take the consumer from a wrong credential to no credential. The cleanup is itself verified, and a cleanup failure is reported *alongside* the original mismatch, never instead of it.

The failure log carries lengths and a single boolean — "stored value is a proper prefix of what was written" — which distinguishes tokenizer truncation from every other cause and leaks nothing. Not the values, and not a hash of them: a hash of a low-entropy secret in a log file is a cracking target.

## Consequences

- Multi-line values are refused. `security -i` is line-oriented, and truncating a credential silently is worse than declining to store it. PEM-shaped secrets need a networked backend.
- **Session domain matters, and is the likeliest production surprise.** A LaunchAgent bootstrapped into `gui/$UID` inherits the login-unlocked keychain. One bootstrapped into `user/$UID` without a GUI login — or reached over SSH — does not, and has no SecurityAgent to prompt, so every fetch fails with interaction-not-allowed. This is a deployment-documentation issue as much as a code one.
- **A locked keychain must not become a prompt storm.** Every `security` call carries a timeout, so a modal unlock dialog nobody can answer produces an error rather than a permanently blocked child. If a locked keychain were allowed to reach process exit under launchd `KeepAlive`, the restart loop would raise a dialog every few seconds; locked has to mean in-process backoff, not exit. The live leg asserts fail-closed-without-hang against a genuinely locked keychain.
- `self_check` runs once, at first I/O. For a long-lived agent that is a startup diagnostic, not a standing guarantee — lock state is system-wide in `securityd` and any process can lock the keychain afterwards. Nothing in the request path is gated on the self-check having passed.
- Enumeration reads the *whole* keychain's attribute metadata into the process. It is filtered to the configured service immediately and never logged, but the `dump-keychain` output format is not a stable interface across OS versions. Change here is a plausible future break.
## The `security(1)` vs `Security.framework` question — verdict

Reviewed cross-model on 2026-08-16. **Verdict: the CLI is the right thing to have shipped, and it is the wrong thing to keep.** The migration to `SecItemAdd` / `SecItemCopyMatching` / `SecItemDelete` via `ctypes` against `/System/Library/Frameworks/Security.framework` should happen, under its own ADR.

The deciding argument is **not** robustness. It is this: `security(1)` offers **no way to suppress the interactive unlock prompt.** If the keychain locks while kow is running as a LaunchAgent, the next fetch raises a modal dialog in the operator's GUI session. A timeout bounds kow's wait; it does not remove the dialog. That means a prompt-injected agent can *induce a credential dialog on the operator's screen at a time of the attacker's choosing* — and the operator, mid-task, may well click Allow, or worse, Always Allow, which permanently widens the item's ACL.

`kSecUseAuthenticationUI = kSecUseAuthenticationUIFail` closes that. There is no CLI equivalent. For a tool whose entire premise is defence against prompt injection, "the attacker can make a credential prompt appear" is a design defect, not a papercut.

Four more defects fall out at the same time: the hand-rolled `security -i` tokenizer disappears (values become `CFData`, so the single-line and NUL restrictions lift, and PEM-shaped secrets become storable); `dump-keychain`'s unstable text format stops being a parsing dependency; exit-code plus stderr-string matching is replaced by real `OSStatus` values; and there is no subprocess per fetch.

Against: roughly 250 lines of `ctypes` `CFDictionary` / `CFRelease` work, in which a mistake **segfaults a running credential proxy** where a subprocess could only have failed. That risk is why this is a separate, separately-verified change rather than an amendment here — but it is a reason to sequence the work, not to skip it.

Until then, the shipped CLI implementation stands, with every defect above either guarded (read-back, timeouts, charset validation) or documented.
- The backend is macOS-only and says so on first use rather than at config-load, so a macOS config still validates on a Linux CI box.
- `self_check: deny` (the default) refuses to start when the keychain cannot be opened — a locked keychain fails at startup with the `security unlock-keychain` fix named, instead of at the first request.
- `list_secret_names` works (via attribute-only `dump-keychain`, which never reads or decrypts password data), so `kow env` and notes-mode binding activation are available on this backend.

## Verification

- `tests/backends/test_keychain_backend.py` — runs against a real fake-`security` executable, so the subprocess boundary itself is crossed: argv contents, stdin protocol, exit codes, quoting round-trips for shell-hostile values.
- `tests/vm-e2e/macos-e2e.sh --keychain` — the live proof on a real Mac against the real `/usr/bin/security`: a throwaway keychain, `kow secret add` through the CLI, a shell-hostile value round-tripping byte-identical, enumeration without a prompt, no secret bytes on disk, and the four wire assertions showing the real secret substituted onto the wire and absent from every log. The leg is unprivileged by construction, which is the LaunchAgent constraint demonstrated rather than asserted.
