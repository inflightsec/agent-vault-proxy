#!/usr/bin/env bats
# End-state assertions for `avp setup --no-service` (ADR-0011/0012).
#
# Provisions THE CURRENT HOST for real — run it only inside the disposable
# container (tests/setup-e2e/run.sh) or on a Mac you actually intend to
# provision:
#
#   brew install bats-core && sudo bats tests/setup-e2e/setup.bats
#
# On macOS the BWS token prompt is interactive (getpass reads /dev/tty):
# paste any throwaway value. On Linux the harness feeds a fake token via
# stdin. Tests run in file order and build on each other's state.

setup_file() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "must run as root (sudo bats)" >&2
        return 1
    fi
    if [ "$(uname -s)" = "Darwin" ]; then
        export AVP_OS=macos AVP_USER=_avp AVP_GID0=wheel
        export AVP_CONF=/usr/local/etc/agent-vault-proxy
        export AVP_STATE=/usr/local/var/lib/agent-vault-proxy
        export AVP_LOG=/usr/local/var/log/agent-vault-proxy
        export AVP_SERVICE=/Library/LaunchDaemons/io.inflightsec.agent-vault-proxy.plist
    else
        export AVP_OS=linux AVP_USER=avp AVP_GID0=root
        export AVP_CONF=/etc/agent-vault-proxy
        export AVP_STATE=/var/lib/agent-vault-proxy
        export AVP_LOG=/var/log/agent-vault-proxy
        export AVP_SERVICE=/etc/systemd/system/agent-vault-proxy.service
    fi
    # Clearly fake — never put real credential material in this suite.
    export AVP_FAKE_TOKEN="avp-setup-e2e-FAKE-TOKEN-not-a-secret"
}

# mode owner group of a path, GNU/BSD portable.
mog() {
    if [ "$AVP_OS" = macos ]; then stat -f '%Lp %Su %Sg' "$1"; else stat -c '%a %U %G' "$1"; fi
}

# path + mode/owner/group/size for everything setup provisions; mtimes
# excluded on purpose (reruns atomically rewrite the unit file with
# identical bytes).
fingerprint() {
    local root p
    for root in "$AVP_CONF" "$AVP_STATE" "$AVP_LOG" "$AVP_SERVICE"; do
        [ -e "$root" ] || continue
        find "$root" 2>/dev/null | while IFS= read -r p; do
            if [ "$AVP_OS" = macos ]; then
                stat -f '%N %Lp %Su %Sg %z' "$p"
            else
                stat -c '%n %a %U %G %s' "$p"
            fi
        done
    done | sort
}

# Group/other permission bits of a path must be zero (key material).
assert_owner_only() {
    local mode
    mode="$(mog "$1" | cut -d' ' -f1)"
    [ $((8#$mode & 8#077)) -eq 0 ]
}

run_setup() {
    if [ "$AVP_OS" = linux ]; then
        printf '%s\n' "$AVP_FAKE_TOKEN" | avp setup --no-service "$@"
    else
        avp setup --no-service "$@"
    fi
}

@test "dry-run on a pristine host creates nothing" {
    if [ -e "$AVP_CONF" ] || id "$AVP_USER" >/dev/null 2>&1; then
        skip "host already provisioned"
    fi
    # Exit code deliberately not asserted: on a pristine host the trailing
    # doctor pass reports the not-yet-generated CA. Mutation is the claim.
    avp setup --no-service --dry-run || true
    [ ! -e "$AVP_CONF" ]
    [ ! -e "$AVP_STATE" ]
    [ ! -e "$AVP_SERVICE" ]
    # The log dir may pre-exist as a harness mount point — then it must be empty.
    if [ -e "$AVP_LOG" ]; then [ -z "$(ls -A "$AVP_LOG")" ]; fi
    ! id "$AVP_USER" >/dev/null 2>&1
}

@test "first provisioning run exits 0" {
    run_setup
}

@test "service user exists: system account, no login shell" {
    id "$AVP_USER"
    if [ "$AVP_OS" = linux ]; then
        [ "$(getent passwd "$AVP_USER" | cut -d: -f7)" = "/usr/sbin/nologin" ]
        [ "$(id -u "$AVP_USER")" -lt 1000 ]
    else
        [ "$(dscl . -read "/Users/$AVP_USER" UserShell | awk '{print $2}')" = "/usr/bin/false" ]
        [ "$(dscl . -read "/Users/$AVP_USER" IsHidden | awk '{print $2}')" = "1" ]
        [ "$(dscl . -read "/Users/$AVP_USER" UniqueID | awk '{print $2}')" -lt 500 ]
    fi
}

@test "config dir 0750 root:$AVP_USER" {
    [ "$(mog "$AVP_CONF")" = "750 root $AVP_USER" ]
}

@test "state dir 0750 $AVP_USER:$AVP_USER" {
    [ "$(mog "$AVP_STATE")" = "750 $AVP_USER $AVP_USER" ]
}

@test "log dir 0750 $AVP_USER:$AVP_USER" {
    [ "$(mog "$AVP_LOG")" = "750 $AVP_USER $AVP_USER" ]
}

@test "mitmproxy CA dir 0700 $AVP_USER:$AVP_USER" {
    [ "$(mog "$AVP_STATE/.mitmproxy")" = "700 $AVP_USER $AVP_USER" ]
}

@test "BWS token 0440 root:$AVP_USER, fake value landed" {
    [ "$(mog "$AVP_CONF/bws-token")" = "440 root $AVP_USER" ]
    if [ "$AVP_OS" = linux ]; then
        grep -qF "$AVP_FAKE_TOKEN" "$AVP_CONF/bws-token"
    fi
}

@test "CA private key owned by $AVP_USER, zero group/other bits" {
    local key="$AVP_STATE/.mitmproxy/mitmproxy-ca.pem"
    [ "$(mog "$key" | cut -d' ' -f2)" = "$AVP_USER" ]
    assert_owner_only "$key"
}

@test "install salt 0600 $AVP_USER in the statedir (daemon-HOME parity)" {
    [ "$(mog "$AVP_STATE/install-salt" | cut -d' ' -f1-2)" = "600 $AVP_USER" ]
    grep -q "^install_salt_path: $AVP_STATE/install-salt$" "$AVP_CONF/bindings.yaml"
}

@test "bindings.yaml 0640 root:$AVP_USER" {
    [ "$(mog "$AVP_CONF/bindings.yaml")" = "640 root $AVP_USER" ]
}

@test "public CA cert 0644 root:$AVP_GID0" {
    [ "$(mog "$AVP_CONF/ca.pem")" = "644 root $AVP_GID0" ]
}

@test "audit log 0640 $AVP_USER:$AVP_USER and append-only" {
    [ "$(mog "$AVP_LOG/audit.jsonl")" = "640 $AVP_USER $AVP_USER" ]
    if [ "$AVP_OS" = linux ]; then
        case "$(lsattr "$AVP_LOG/audit.jsonl" | awk '{print $1}')" in
            *a*) ;;
            *) echo "append-only attr missing" >&2; return 1 ;;
        esac
    else
        ls -lO "$AVP_LOG/audit.jsonl" | grep -q sappnd
    fi
}

@test "service definition FILE written; service NOT activated" {
    if [ "$AVP_OS" = linux ]; then
        [ "$(mog "$AVP_SERVICE")" = "644 root root" ]
        grep -q "^User=$AVP_USER$" "$AVP_SERVICE"
        grep -q "^ProtectSystem=strict$" "$AVP_SERVICE"
        [ ! -e /etc/systemd/system/multi-user.target.wants/agent-vault-proxy.service ]
    else
        [ "$(mog "$AVP_SERVICE")" = "644 root wheel" ]
        grep -q "io.inflightsec.agent-vault-proxy" "$AVP_SERVICE"
        ! launchctl print system/io.inflightsec.agent-vault-proxy >/dev/null 2>&1
    fi
}

@test "second run is idempotent: exit 0, state fingerprint unchanged" {
    local before after
    before="$(fingerprint)"
    run_setup
    after="$(fingerprint)"
    [ "$before" = "$after" ]
}

@test "tighten-never-widen: operator chmod 0600 on bindings survives rerun" {
    chmod 0600 "$AVP_CONF/bindings.yaml"
    run_setup
    [ "$(mog "$AVP_CONF/bindings.yaml" | cut -d' ' -f1)" = "600" ]
    # Restore the canonical mode so later runs assert from a clean slate.
    chmod 0640 "$AVP_CONF/bindings.yaml"
}

@test "dry-run after provisioning: exit 0, mutates nothing" {
    local before after
    before="$(fingerprint)"
    avp setup --no-service --dry-run
    after="$(fingerprint)"
    [ "$before" = "$after" ]
}
