#!/bin/bash
# Run with the trial ssh-blocker in $PATH
# (or set SSH_BLOCKER to the binary path).

set -e -u

fail() {
    echo "FAIL: $1" >&2
    exit 1
}
warn() {
    echo "WARN: $1" >&2
}


log_systemd() {
    systemd-run --no-ask-password --quiet \
        --unit=$systemd_logger_unit echo "$1" ||
        fail "Failed to create systemd log entry"
}

log_pipe() {
    echo "$1" > "$logfifo"
}


# Check for sane environment
precheck() {
    ipset --version >/dev/null || fail "ipset binary unavailable"
    ipset list -name 2>/dev/null || fail "Cannot query ipset"
    if ipset list -name | grep -qxE "ssh-whitelist|ssh-blocklist"; then
        fail "ipsets already exist, try to run in a clean netns!"
    fi

    SSH_BLOCKER="$(which "${SSH_BLOCKER:-ssh-blocker}")" ||
        fail "Cannot find ssh-blocker binary"
    if grep -q 'Log file must be a FIFO' "$SSH_BLOCKER"; then
        logmode=pipe
    elif grep -q log-systemd: "$SSH_BLOCKER"; then
        logmode=systemd
    else
        fail "Cannot determine log type of $SSH_BLOCKER"
    fi
    echo "Testing using log source \"$logmode\""
}

setup() {
    tmpdir=$(mktemp -d)
    pid=
    needsCleanup=true
    trap 'cleanup; rm -rf "$tmpdir"' EXIT

    # Run as unprivileged user
    user=$(id -un)
    [[ "$user" != root ]] || user=nobody

    # Prepare logger
    log() { log_$logmode "$@"; }
    case $logmode in
    pipe)
        logfifo="$tmpdir/logpipe"
        mkfifo -m770 "$logfifo"
        [[ $(id -un) != root ]] || chown "$user" "$logfifo"
        ;;
    systemd)
        # Hopefully one of the services "ssh" or "sshd" do not exist so we can
        # attempt to inject logging messages using either service name.
        for systemd_logger_unit in ssh sshd ''; do
            systemctl show "$systemd_logger_unit" &>/dev/null || break
        done
        [ -n "$systemd_logger_unit" ] || fail "Cannot find a free systemd unit"
        echo "Using systemd unit name $systemd_logger_unit for logging"
        ;;
    esac

    # Part of TEST-NET-2 so should not conflict in real world.
    TESTIP1=198.51.100.1
    TESTIP2=198.51.100.2

}

start_ipset() {
    case $logmode in
    pipe)
        "$SSH_BLOCKER" "$user" "$logfifo" & pid=$!
        ;;
    systemd)
        "$SSH_BLOCKER" "$user" & pid=$!
        ;;
    esac

    echo "Started daemon as $pid"
}

stop_ipset() {
    if [ -n "$pid" ]; then
        kill $pid || warn "Cannot kill daemon $pid"
        pid=
    fi
}

destroy_ipsets() {
    ipset destroy ssh-whitelist || warn "Cannot destroy ssh-whitelist"
    ipset destroy ssh-blocklist || warn "Cannot destroy ssh-blocklist"
}

ipset_test() {
    for ((i=0; i<10; i++)); do
        ipset test "$@" 2>/dev/null && return || sleep .1
    done
    return 1
}

# Test a simple setup and expect IPs to be blocked.
test_block() {
    start_ipset

    log "Invalid user ssh-blocker-test from $TESTIP1"
    ipset_test ssh-blocklist $TESTIP1 && fail "Should not be blocked yet" || :

    log "Invalid user ssh-blocker-test from $TESTIP1"
    ipset_test ssh-blocklist $TESTIP1 || fail "Should be blocked"

    log "Invalid user ssh-blocker-test from $TESTIP1"
    ipset_test ssh-blocklist $TESTIP1 || fail "Should still be blocked"

    stop_ipset
    destroy_ipsets
}

# Test that pre-created ipsets are accepted and that whitelisting works
test_whitelist() {
    ipset create ssh-whitelist hash:ip timeout 0 ||
        fail "Cannot create ssh-whitelist"
    ipset create ssh-blocklist hash:ip timeout 0 ||
        fail "Cannot create ssh-blocklist"
    ipset add ssh-whitelist $TESTIP2 ||
        fail "Cannot add $TESTIP2 to ssh-whitelist"

    start_ipset

    log "Invalid user ssh-blocker-test from $TESTIP2"
    log "Invalid user ssh-blocker-test from $TESTIP2"
    log "Invalid user ssh-blocker-test from $TESTIP1"
    log "Invalid user ssh-blocker-test from $TESTIP1"
    ipset_test ssh-blocklist $TESTIP2 && fail "$TESTIP1 should not be blocked" || :
    ipset_test ssh-blocklist $TESTIP1 || fail "$TESTIP1 should be blocked"

    stop_ipset
    destroy_ipsets
}

cleanup() {
    $needsCleanup || return
    needsCleanup=false

    echo "(cleaning up)" >&2
    stop_ipset
    destroy_ipsets
}

do_test() {
    echo "Testing $1..."
    test_$1
    printf 'OK\n\n'
}

precheck
setup
do_test block
do_test whitelist
needsCleanup=false
echo "PASSED"
