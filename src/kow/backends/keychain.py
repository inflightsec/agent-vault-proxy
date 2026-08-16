"""macOS Keychain secrets backend (ADR-0046).

Reads and writes generic-password items in a **file-based** macOS keychain —
the login keychain by default — through ``/usr/bin/security``. Zero third-party
dependencies: the tool ships with the OS.

What this buys, stated plainly:

    * no plaintext secret on disk (the keychain is encrypted with a key derived
      from the account's login password),
    * a GUI view: Keychain Access, filtered on the configured ``service``,
    * no vault account, no token, no network round trip.

What it does **not** buy: access scoping to kow alone. Under PyPI/Homebrew
distribution kow is not a Developer-ID-signed application, so the keychain ACL
identity is ``/usr/bin/security`` itself — anything running as the same user can
read the same items. **The access boundary is the user account.** Run kow as a
LaunchAgent in the operator's account and keep agent workloads in a *separate*
macOS account; per-user keychain encryption is the wall that actually holds.
Making "only kow can read" enforceable needs a signed helper against the
data-protection keychain, which is a separate (L2) decision.

Two more consequences of the file-based keychain, both deliberate:

    * items here can never appear in the macOS **Passwords** app, and Passwords
      items can never be read from here — Passwords speaks only to the
      data-protection keychain, and there is no command-line access to that one.
    * the login keychain never syncs between Macs. For a fleet, use a networked
      backend (bws, gsm, aws-secrets-manager).

Config::

    backend:
      type: keychain
      config:
        type: keychain
        service: kow                     # the generic-password "service" attr
        keychain: ~/Library/Keychains/login.keychain-db   # optional; default keychain when unset
        secret_prefix: null              # optional namespace bound
        self_check: deny                 # deny | warn | off
        timeout_seconds: 10.0
"""

from __future__ import annotations

import logging
import os
import re
import subprocess  # noqa: S404 — the whole backend is a wrapper around /usr/bin/security
import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from kow.backends._scope import assert_in_scope, refuse_or_warn
from kow.secret import Secret

_log = logging.getLogger("kow.backends.keychain")

# Absolute, never resolved through PATH: a backend that finds its
# security-critical binary by searching $PATH is one writable directory away
# from executing somebody else's "security". Module-level so tests can
# monkeypatch it with a stub; deliberately NOT a config field or an env var,
# which would put the same hijack back in the hands of anything that can edit
# config or environment.
SECURITY_BIN = "/usr/bin/security"

# `security dump-keychain` prints one `"attr"<blob>="value"` line per attribute.
# Non-representable values come out as `<blob>=0x68656C6C6F  "hello"`, which this
# pattern deliberately does not match — see _parse_dump.
_ATTR_RE = re.compile(r'^\s*"(?P<key>[a-zA-Z0-9_]{4})"<blob>="(?P<value>.*)"\s*$')
_ITEM_BOUNDARY_RE = re.compile(r"^keychain: ")

# `service` is constrained at config-load to this set so it survives both the
# interactive command line and the dump-keychain text format unambiguously.
_SAFE_SERVICE_RE = re.compile(r"[A-Za-z0-9._-]+")

# errSecItemNotFound. `security` surfaces the OSStatus as its exit code for the
# find/delete verbs, so 44 is "the keychain answered: no such item" — a
# different fact from "the keychain would not answer", and the protocol demands
# they raise different exceptions.
_EXIT_ITEM_NOT_FOUND = 44

_NOT_FOUND_MARKERS = ("could not be found", "The specified item could not be found")
_LOCKED_MARKERS = (
    "User interaction is not allowed",
    "interaction is not allowed",
    "The user name or passphrase you entered is not correct",
    "is locked",
)


class KeychainConfig(BaseModel):
    """``backend.config`` schema for ``type: keychain``."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    type: Literal["keychain"] = "keychain"

    # The generic-password `service` attribute every kow item carries. Also the
    # string to type into Keychain Access's search box to see them all.
    service: str = "kow"

    # Which keychain file. Unset = the user's default (login) keychain, which is
    # what an operator wants. Setting it is how CI, the VM e2e leg, and anyone
    # who wants a dedicated kow keychain stay out of the login keychain.
    keychain: str | None = None

    # Defence-in-depth namespace bound, identical in meaning to the aws/gsm
    # field of the same name.
    secret_prefix: str | None = None

    # Startup reachability check: platform, binary, keychain openable.
    self_check: Literal["deny", "warn", "off"] = "deny"

    timeout_seconds: float = 10.0

    @field_validator("service")
    @classmethod
    def _service_is_safe(cls, v: str) -> str:
        # `service` travels twice: quoted into the `security -i` command line
        # (where a newline truncates the command), and back out through
        # `dump-keychain`'s text format (where a quote or backslash would need
        # unescaping to match). A conservative charset removes both problems at
        # the config boundary instead of defending them at two runtime sites.
        if not v.strip():
            raise ValueError("service must not be empty")
        if not _SAFE_SERVICE_RE.fullmatch(v):
            raise ValueError(
                "service must match ^[A-Za-z0-9._-]+$ (it is quoted into a "
                "command line and parsed back out of dump-keychain text)"
            )
        return v

    @field_validator("keychain")
    @classmethod
    def _keychain_path_is_transmittable(cls, v: str | None) -> str | None:
        # The keychain path is appended to the SAME interactive command line as
        # the value, and is quoted by the same helper. It was the one input not
        # checked for line-protocol-hostile bytes — a newline in it would split
        # the command stream and the write would land somewhere unintended.
        if v is not None and any(c in v for c in ("\n", "\r", "\0")):
            raise ValueError("keychain path must not contain a newline or NUL byte")
        return v

    @field_validator("timeout_seconds")
    @classmethod
    def _timeout_positive(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("timeout_seconds must be > 0")
        return v


class KeychainError(Exception):
    """Internal: a non-zero ``security`` exit. Carries the exit code and the
    child's stderr — never its stdout, which on the read path IS the secret."""

    def __init__(self, code: int, stderr: str) -> None:
        super().__init__(f"security exited {code}")
        self.code = code
        self.stderr = stderr


class KeychainBackend:
    """``SecretsBackend`` over ``/usr/bin/security``.

    Thread-safety: every operation is a self-contained subprocess call with no
    shared mutable state beyond the one-shot ``_checked`` flag, so concurrent
    fetches are safe.
    """

    def __init__(self, config: KeychainConfig | None = None) -> None:
        self._config = config or KeychainConfig()
        # No I/O in __init__ (protocol contract). The first fetch/update/list
        # runs the self-check.
        self._checked = False

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} service={self._config.service!r}>"

    # ------------------------------------------------------------------ reads

    def fetch(self, name: str, ctx: Any = None) -> Secret:  # noqa: ARG002 — ctx unused
        from kow.backends import SecretNotFoundError

        assert_in_scope(name, self._config.secret_prefix)
        self._ensure_ready()
        try:
            out = self._run(["find-generic-password", "-a", name, "-s", self._config.service, "-w"])
        except KeychainError as e:
            if _is_not_found(e):
                raise SecretNotFoundError(
                    f"secret {name!r} not in keychain (service {self._config.service!r})"
                ) from None
            raise self._unavailable(e, f"reading {name!r}") from None
        # `security -w` writes the password followed by exactly one newline.
        # Strip that one and nothing else: trailing whitespace can be part of a
        # secret, and .strip() would silently corrupt it.
        return Secret(out[:-1] if out.endswith("\n") else out)

    def list_secret_names(self) -> list[str]:
        """Every ``acct`` whose ``svce`` matches the configured service.

        Attribute-only dump: ``dump-keychain`` without ``-d`` never reads
        password data, so this neither prompts nor decrypts anything.
        """
        self._ensure_ready()
        try:
            out = self._run(["dump-keychain"])
        except KeychainError as e:
            raise self._unavailable(e, "enumerating the keychain") from None
        prefix = self._config.secret_prefix
        names = _parse_dump(out, self._config.service)
        return sorted(n for n in names if not prefix or n.startswith(prefix))

    # ----------------------------------------------------------------- writes

    def update(
        self,
        name: str,
        value: str,
        ctx: Any = None,  # noqa: ARG002 — ctx unused
        *,
        expected_current_value: str | None = None,
    ) -> None:
        """Store ``value`` under ``name``, replacing any existing item.

        The value is handed to ``security`` over **stdin** (`security -i`
        interactive mode), never as an argv element: argv is world-readable
        through the process table on macOS, so ``-w <value>`` on a command line
        publishes the credential to every local user for the life of the call.
        """
        from kow.backends import BackendUnavailableError, BackendWriteConflictError

        assert_in_scope(name, self._config.secret_prefix)
        self._ensure_ready()

        _reject_untransmittable(name, "name", name)
        _reject_untransmittable(value, "value", name)

        # Whether the item already exists decides what a failed write is allowed
        # to do about it: a botched CREATE can be cleaned up, a botched UPDATE
        # cannot (the prior value is already gone, and deleting would take the
        # consumer from "wrong credential" to "no credential").
        current = self._current_or_none(name)
        existed = current is not None

        if expected_current_value is not None and (
            current is None or current.reveal() != expected_current_value
        ):
            raise BackendWriteConflictError(
                f"secret {name!r} changed in the keychain since it was read; "
                "refusing to overwrite (operator rotation in flight?)"
            )

        cmd = [
            "add-generic-password",
            "-a",
            name,
            "-s",
            self._config.service,
            "-U",
            "-w",
            value,
        ]
        # The invocation's own report is NOT evidence either way, in either
        # direction: `security -i` exits 0 even when a command inside the session
        # failed, and it can emit stderr on a write that landed perfectly well.
        # So the error is recorded and verification runs REGARDLESS — otherwise a
        # noisy-but-successful write is reported as a failure with no read-back,
        # and a failed write that already created an item skips its own cleanup.
        # The keychain is the authority; the subprocess is only a messenger.
        write_error: Exception | None = None
        try:
            self._run_interactive(cmd)
        except KeychainError as e:
            write_error = self._unavailable(e, f"writing {name!r}")

        # `add -U`, `find` and `delete` all act on the FIRST match, in an order
        # `security` does not specify. With a duplicate (service, account) pair —
        # created out of band, or by an earlier partial write — the read-back
        # below can read a different item than the one just written, and then
        # pass or fail for the wrong reason. Refuse to reason about it.
        duplicates = self._count_items(name)
        if duplicates > 1:
            raise BackendUnavailableError(
                f"keychain holds {duplicates} items for ({self._config.service!r}, "
                f"{name!r}); `security` operates on an unspecified first match, so "
                "the write cannot be verified. Remove the duplicates in Keychain "
                "Access and retry."
            )

        # Read back and compare. The interactive protocol requires quoting the
        # value, and a quoting bug is exactly the class of failure that stores a
        # mangled credential while looking like success.
        stored = self._current_or_none(name)
        if stored is None or stored != Secret(value):
            # Log the ONE bit that distinguishes tokenizer truncation from every
            # other cause. Never the values, and never a hash of them: a hash of
            # a low-entropy secret in a log file is a cracking target.
            truncated = stored is not None and value.startswith(stored.reveal())
            _log.error(
                "keychain write of %r did not round-trip (stored %s bytes, wrote %s, "
                "stored-is-prefix=%s)",
                name,
                len(stored) if stored is not None else "none",
                len(value),
                truncated,
            )
            detail = ""
            if not existed:
                # We created this item, so nobody depended on it: removing the
                # mangled value is strictly better than leaving it readable. The
                # compensating action is itself verified, and its own failure is
                # reported ALONGSIDE the mismatch rather than replacing it.
                try:
                    self.delete(name)
                    detail = " The partial item was removed."
                except Exception as cleanup_exc:  # noqa: BLE001 — reported, never swallowed
                    detail = f" Removing the partial item ALSO failed: {cleanup_exc}"
            else:
                detail = (
                    " The previous value is gone and the item now holds untrusted "
                    "bytes — re-set it with `kow secret add`."
                )
            cause = f" `security` also reported: {write_error}" if write_error else ""
            raise BackendUnavailableError(
                f"keychain write of {name!r} did not round-trip; the stored value "
                f"differs from what was written (value withheld).{detail}{cause}"
            )

        if write_error is not None:
            # Verified good despite the noise. Say so rather than either failing a
            # correct write or hiding that the tool complained.
            _log.warning(
                "`security` reported an error writing %r but the stored value "
                "verifies; treating the write as successful. Reported: %s",
                name,
                write_error,
            )

    def _count_items(self, name: str) -> int:
        """How many items carry this (service, account) pair. Duplicates make
        every first-match verb ambiguous."""
        try:
            out = self._run(["dump-keychain"])
        except KeychainError:
            # Fails OPEN, deliberately, and it is worth being precise about why:
            # the read-back that follows is the actual guarantee. If duplicates
            # exist and the read lands on a different item than the write, the
            # values differ and the read-back rejects the write anyway; the only
            # case this misses is a duplicate whose value already equals what we
            # wrote, which is indistinguishable from success. Failing the write
            # here would trade that non-problem for an outage whenever
            # enumeration is unavailable. Logged so it is never silent.
            _log.warning(
                "could not enumerate the keychain to check for duplicate items; "
                "the write is verified by read-back alone"
            )
            return 1
        return _parse_dump(out, self._config.service, dedupe=False).count(name)

    def delete(self, name: str) -> None:
        """Remove ``name``. Absent item is a no-op, so delete is idempotent."""
        assert_in_scope(name, self._config.secret_prefix)
        self._ensure_ready()
        try:
            self._run(["delete-generic-password", "-a", name, "-s", self._config.service])
        except KeychainError as e:
            if _is_not_found(e):
                return
            raise self._unavailable(e, f"deleting {name!r}") from None

    # ------------------------------------------------------------- internals

    def _current_or_none(self, name: str) -> Secret | None:
        from kow.backends import SecretNotFoundError

        try:
            return self.fetch(name)
        except SecretNotFoundError:
            return None

    def _keychain_arg(self) -> list[str]:
        """The trailing ``[keychain]`` positional, expanded. Empty when unset,
        which lets ``security`` use the default (login) keychain."""
        raw = self._config.keychain
        if not raw:
            return []
        return [str(Path(raw).expanduser())]

    def _ensure_ready(self) -> None:
        if self._checked:
            return
        # Set first: a `warn`-mode failure must not re-run the probe on every
        # single fetch.
        self._checked = True
        mode = self._config.self_check
        if mode == "off":
            return

        if not _is_macos():
            refuse_or_warn(
                mode,
                f"the keychain backend needs macOS; this host is {sys.platform!r}",
                _log,
            )
            return
        if not os.access(SECURITY_BIN, os.X_OK):
            refuse_or_warn(mode, f"{SECURITY_BIN} is missing or not executable", _log)
            return
        try:
            self._run(["show-keychain-info"])
        except KeychainError as e:
            target = self._config.keychain or "the default (login) keychain"
            hint = (
                f"unlock it with `security unlock-keychain {self._config.keychain or ''}`".rstrip()
                if _is_locked(e)
                else f"security said: {_sanitise(e.stderr)}"
            )
            refuse_or_warn(mode, f"cannot open {target}: {hint}", _log)

    def _argv(self, cmd: list[str]) -> list[str]:
        return [SECURITY_BIN, *cmd, *self._keychain_arg()]

    def _run(self, cmd: list[str]) -> str:
        """Run ``security <cmd> [keychain]`` and return stdout.

        No shell. Callers must never put a secret in ``cmd`` — use
        :meth:`_run_interactive` for that.
        """
        from kow.backends import BackendUnavailableError

        argv = self._argv(cmd)
        try:
            proc = subprocess.run(  # noqa: S603 — absolute binary, list argv, no shell
                argv,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise BackendUnavailableError(
                f"`security {cmd[0]}` timed out after {self._config.timeout_seconds}s "
                "(a GUI unlock prompt with nobody to answer it looks exactly like this)"
            ) from None
        except OSError as e:
            raise BackendUnavailableError(
                f"could not execute {SECURITY_BIN}: {type(e).__name__}"
            ) from None
        if proc.returncode != 0:
            raise KeychainError(proc.returncode, proc.stderr or "")
        return proc.stdout

    def _run_interactive(self, cmd: list[str]) -> str:
        """Run one command through ``security -i``, so the command line — and
        therefore any secret in it — reaches the child on stdin instead of argv.

        Only the interactive line is built here; the argv is the constant
        ``[security, -i]``.
        """
        from kow.backends import BackendUnavailableError

        line = " ".join(_quote(a) for a in [*cmd, *self._keychain_arg()]) + "\n"
        try:
            proc = subprocess.run(  # noqa: S603 — absolute binary, list argv, no shell
                [SECURITY_BIN, "-i"],
                input=line,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise BackendUnavailableError(
                f"`security {cmd[0]}` timed out after {self._config.timeout_seconds}s"
            ) from None
        except OSError as e:
            raise BackendUnavailableError(
                f"could not execute {SECURITY_BIN}: {type(e).__name__}"
            ) from None
        # `security -i` exits 0 even when a command inside the session failed,
        # so the exit code alone is not evidence of success. The write path does
        # not rely on it: update() re-reads and compares. stderr is still
        # surfaced when it is non-empty so the failure has a cause attached.
        if proc.returncode != 0 or proc.stderr.strip():
            raise KeychainError(proc.returncode, proc.stderr or "")
        return proc.stdout

    def _unavailable(self, e: KeychainError, doing: str) -> Exception:
        from kow.backends import BackendUnavailableError

        if _is_locked(e):
            kc = self._config.keychain or ""
            return BackendUnavailableError(
                f"keychain is locked or needs interaction while {doing}; unlock it "
                f"with `security unlock-keychain {kc}`".rstrip()
                + " and retry"
            )
        return BackendUnavailableError(
            f"`security` failed while {doing} (exit {e.code}): {_sanitise(e.stderr)}"
        )


# ------------------------------------------------------------------ helpers


def _reject_untransmittable(text: str, what: str, name: str) -> None:
    """Refuse bytes the ``security -i`` line protocol cannot carry intact.

    A newline ends the command line, so it would truncate the write and store a
    prefix of the credential. A NUL terminates the C string on the far side of
    the pipe, with the same result. Both are refused at the API boundary, before
    a child is ever spawned — storing a silently-shortened credential is the
    worst outcome available here, because everything downstream looks fine.
    """
    from kow.backends import BackendUnavailableError

    for bad, label in (("\n", "newline"), ("\r", "carriage return"), ("\0", "NUL byte")):
        if bad in text:
            raise BackendUnavailableError(
                f"secret {name!r} has a {label} in its {what}; the keychain backend "
                "stores single-line, NUL-free values only (a multi-line credential "
                "such as a PEM key needs a networked backend)"
            )


def _unescape_blob(value: str) -> str:
    """Undo `dump-keychain`'s backslash escaping of a quoted blob value.

    Without this a stored name containing a quote or backslash comes back with
    the escapes still in it and silently fails to match the name it was written
    under, so enumeration and the duplicate check would both miss a real item."""
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _is_macos() -> bool:
    """Platform seam. A function rather than an inline comparison so the test
    suite can exercise the macOS paths against a fake ``security`` on Linux CI —
    the alternative is macOS-only tests, i.e. no coverage on the machine where
    the code is actually written."""
    return sys.platform == "darwin"


def _quote(arg: str) -> str:
    """Quote one token for ``security -i``'s line parser.

    The parser understands double quotes and backslash escapes, so escaping
    backslash and double-quote and wrapping in quotes covers every byte a
    single-line value can hold. Correctness here is not taken on faith:
    :meth:`KeychainBackend.update` reads the value back and refuses the write if
    it does not match.
    """
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sanitise(stderr: str) -> str:
    """One line of the child's stderr, bounded. ``security`` never echoes the
    password on stderr; the bound is belt-and-braces against a future verb that
    does, and against a multi-megabyte error flooding the audit log."""
    first = stderr.strip().splitlines()[0] if stderr.strip() else "no error output"
    return first[:200]


def _is_not_found(e: KeychainError) -> bool:
    return e.code == _EXIT_ITEM_NOT_FOUND or any(m in e.stderr for m in _NOT_FOUND_MARKERS)


def _is_locked(e: KeychainError) -> bool:
    return any(m in e.stderr for m in _LOCKED_MARKERS)


def _parse_dump(text: str, service: str, *, dedupe: bool = True) -> list[str]:
    """Extract account names for ``service`` from ``security dump-keychain``.

    Output is a run of per-item blocks, each opening with a ``keychain: "..."``
    line and carrying ``"attr"<blob>="value"`` lines. Attributes whose bytes are
    not printable come out in a hex form this parser does not match — such an
    entry is skipped rather than guessed at, which is safe because kow secret
    names are ``^[A-Z][A-Z0-9_]*$``.
    """
    names: list[str] = []
    acct: str | None = None
    svce: str | None = None

    def flush() -> None:
        if acct and svce == service:
            names.append(acct)

    for line in text.splitlines():
        if _ITEM_BOUNDARY_RE.match(line):
            flush()
            acct = svce = None
            continue
        m = _ATTR_RE.match(line)
        if not m:
            continue
        key, value = m.group("key"), _unescape_blob(m.group("value"))
        if key == "acct":
            acct = value
        elif key == "svce":
            svce = value
    flush()
    # Enumeration wants a name list; the write path's duplicate check wants a
    # tally, and passes dedupe=False to get one.
    return list(dict.fromkeys(names)) if dedupe else names


def _register() -> None:
    from kow.backends import register_backend

    register_backend("keychain", KeychainBackend, KeychainConfig)


_register()
