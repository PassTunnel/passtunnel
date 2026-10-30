#!/bin/bash
# A real Cisco AnyConnect tunnel through passtunneld against the test server of Tests/ocserv: the one
# test that changes the network of the machine it runs on (Tests/ocserv/README.md). TEST ONLY, and only
# on a throwaway machine: a CI runner VM or a container with NET_ADMIN and /dev/net/tun.
#
#   PASSTUNNEL_TEST_OCSERV=1 OCSERV_PIN=pin-sha256:… DNS_BACKEND=resolved|resolvconf|file \
#     Tests/ocserv/tunnel-test.sh BIN_DIR
#
# BIN_DIR holds passtunnel and passtunneld (built with the Swift standard library linked statically
# where Swift is not installed). As root: it installs them in /usr/local, adds the group passtunnel and
# the user alice, starts passtunneld, and, as alice, adds the profile (vpn.example.com, which must
# resolve to the server) and connects it with the `passtunnel` command. Then: the tunnel's address,
# routes (included, excluded), reachability and DNS (on the backend DNS_BACKEND names) set; all of it
# reverted by a disconnect; set again by a second connect (after a fresh code); openconnect's own
# reconnect after its connection was cut (with RECONNECT=1: `ss -K` needs the kernel's sock_destroy);
# and, after openconnect is killed with SIGKILL, everything reverted by passtunneld. Every step's
# output is in OUT (default: a new temporary directory), printed when a step fails.
set -euo pipefail

[[ "${PASSTUNNEL_TEST_OCSERV:-}" == 1 ]] || { echo "set PASSTUNNEL_TEST_OCSERV=1 to run (it changes this machine's network)" >&2; exit 2; }
[[ "$(id -u)" == 0 ]] || { echo "run as root" >&2; exit 2; }
BIN="${1:?the directory with passtunnel and passtunneld}"
PIN="${OCSERV_PIN:?OCSERV_PIN: the pin of the server key (/etc/ocserv/pin.txt)}"
BACKEND="${DNS_BACKEND:?DNS_BACKEND: resolved, resolvconf or file}"
OUT="${OUT:-$(mktemp -d)}"
SERVER=vpn.example.com
USER_NAME=alice
SOCK=/run/passtunnel/daemon.sock

step() { printf '\n=== %s\n' "$*"; }
fail() {
    echo "FAILED: $*" >&2
    exit 1
}

# Installed as the release tarball's README says.
install -m 0755 "$BIN/passtunneld" /usr/local/sbin/passtunneld
install -m 0755 "$BIN/passtunnel" /usr/local/bin/passtunnel
getent group passtunnel >/dev/null || groupadd --system passtunnel
id "$USER_NAME" >/dev/null 2>&1 || useradd --create-home --groups passtunnel "$USER_NAME"
home="$(getent passwd "$USER_NAME" | cut -d: -f6)"
# The secret store is detected (`auto`): with no session bus, and systemd-creds unusable for alice (not
# installed, older than 256, or systemd not running as init), it is the file, with its passphrase file.
pt() { runuser -u "$USER_NAME" -- env -i HOME="$home" PATH=/usr/bin:/bin PASSTUNNEL_PASSPHRASE_FILE="$home/passphrase" \
    LANG=C.UTF-8 /usr/local/bin/passtunnel "$@"; }

/usr/local/sbin/passtunneld >>"$OUT/daemon.log" 2>&1 &
daemon=$!
cleanup() {
    status=$?
    if ((daemon)); then
        pt disconnect acme --json >/dev/null 2>&1 || true
        kill -TERM "$daemon" 2>/dev/null || true
        wait "$daemon" 2>/dev/null || true
    fi
    if ((status != 0)); then
        echo "--- daemon log"
        cat "$OUT/daemon.log"
        echo "--- session log"
        cat "$home/.local/share/passtunnel/profiles/acme/vpn.log" 2>/dev/null || true
        echo "--- activity"
        pt log acme --activity 2>/dev/null | tail -n 30 || true
    fi
    exit "$status"
}
trap cleanup EXIT
for _ in $(seq 100); do
    [[ -S "$SOCK" ]] && break
    sleep 0.1
done
[[ -S "$SOCK" ]] || fail "passtunneld did not start"

step "the profile"
getent ahostsv4 "$SERVER" | sed -n 1p
install -m 0600 -o "$USER_NAME" /dev/null "$home/passphrase"
printf '%s\n' 'a passphrase for this test only' >"$home/passphrase"
pt secret-store --json >"$OUT/secret-store.json" || { cat "$OUT/secret-store.json"; fail "no usable secret store"; }
jq -c . "$OUT/secret-store.json"
if [[ ! -d /run/systemd/system ]]; then
    # Without systemd as init, auto must not take systemd-creds (#213), and must say why when it is installed.
    jq -e '.name == "file" and .chosen_by == "auto"' "$OUT/secret-store.json" >/dev/null || fail "auto did not take the file"
    if [[ -x /usr/bin/systemd-creds ]]; then
        jq -e '[.skipped[]? | select(.name == "systemd-creds")] | length == 1' "$OUT/secret-store.json" >/dev/null \
            || fail "secret-store does not say why systemd-creds is not used"
    fi
fi
pt add Acme --type anyconnect --server "https://$SERVER/" --json | jq -e '.id == "acme"' >/dev/null
pt set acme username="$USER_NAME" server_cert="$PIN" otp_mode=totp tls_only=true set_dns=true set_routes=true --json >/dev/null
printf '%s' 'example-password' | pt secret acme password --json | jq -e .saved >/dev/null
printf '%s' 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' | pt secret acme totp --json | jq -e .saved >/dev/null
pt show acme --json | jq -c '.profile | {host, port, username, server_cert, tls_only, set_dns, set_routes}'

# What the machine has before: the default gateway, the routes and the DNS, to compare with after.
read -r gateway gateway_dev < <(ip -4 route show default | awk '{for (i = 1; i < NF; i++) { if ($i == "via") g = $(i + 1); if ($i == "dev") d = $(i + 1) } print g, d; exit}')
echo "default gateway: $gateway dev $gateway_dev"
ip -4 route show | sort >"$OUT/routes4.before"
ip -6 route show 2>/dev/null | sort >"$OUT/routes6.before" || true
cp /etc/resolv.conf "$OUT/resolv.before"
dns_state() {
    case "$BACKEND" in
        resolved) resolvectl dns; resolvectl domain ;;
        resolvconf) cat /etc/resolv.conf; resolvconf -l ;;
        file) cat /etc/resolv.conf ;;
    esac
}
dns_state >"$OUT/dns.before"
ipv6=0
if [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" == 0 ]]; then ipv6=1; fi

connect() {
    pt connect acme --json --timeout 120 --no-input >"$OUT/connect.json" || { cat "$OUT/connect.json"; fail "connect"; }
    jq -c '{state, ip, warning}' "$OUT/connect.json"
    jq -e '.state == "connected" and (.ip | startswith("10.211.0.")) and .warning == null' "$OUT/connect.json" >/dev/null \
        || fail "not connected as expected"
}

# The tunnel's interface: the one with the address ocserv gave.
tunnel() { ip -o -4 addr show | awk '$4 ~ /^10\.211\.0\./ {print $2; exit}'; }

check_up() {
    local tun
    tun="$(tunnel)"
    [[ "$tun" =~ ^tun[0-9]+$ ]] || fail "no tunnel interface: '$tun'"
    echo "tunnel interface $tun"
    ip addr show dev "$tun"
    ip -4 route show | grep -E "dev $tun( |$)" | tee "$OUT/routes4.tun"
    grep -q "^10\.212\.0\.0/16 dev $tun" "$OUT/routes4.tun" || fail "no route to 10.212.0.0/16 through $tun"
    ip -4 route show 10.212.99.0/24 | tee "$OUT/exclude"
    grep -q "via $gateway dev $gateway_dev" "$OUT/exclude" || fail "10.212.99.0/24 not routed around the tunnel"
    if ! ip -4 route show default | grep -q "via $gateway dev $gateway_dev"; then fail "the default route changed"; fi
    ping -c 2 -W 3 10.212.0.80 >/dev/null || fail "10.212.0.80 not reachable through the tunnel"
    if ((ipv6)); then
        ip -6 addr show dev "$tun" | grep -q 'inet6 fd42:211:' || fail "no IPv6 address on $tun"
        ip -6 route show | grep -E "^fd42:212::/48 dev $tun" || fail "no route to fd42:212::/48 through $tun"
        ping -6 -c 2 -W 3 fd42:212::80 >/dev/null || fail "fd42:212::80 not reachable through the tunnel"
    fi
    case "$BACKEND" in
        resolved)
            resolvectl dns "$tun" | tee "$OUT/dns.tun"
            grep -q '10\.212\.0\.53' "$OUT/dns.tun" || fail "no DNS server on $tun"
            resolvectl domain "$tun" | tee "$OUT/domains.tun"
            grep -q 'corp\.example\.com' "$OUT/domains.tun" || fail "no corp.example.com on $tun"
            resolvectl default-route "$tun" | tee "$OUT/default-route.tun"
            grep -q ': no$' "$OUT/default-route.tun" || fail "split DNS, yet $tun takes every name"
            ;;
        resolvconf)
            cat /etc/resolv.conf
            grep -q '^nameserver 10\.212\.0\.53' /etc/resolv.conf || fail "resolv.conf lacks the tunnel's DNS"
            grep -Eq '^search .*corp\.example\.com' /etc/resolv.conf || fail "resolv.conf lacks the default domain"
            ;;
        file)
            cat /etc/resolv.conf
            head -n 1 /etc/resolv.conf | grep -q "^# PassTunnel $tun begin" || fail "no PassTunnel block in resolv.conf"
            test "$(grep '^nameserver ' /etc/resolv.conf)" = "nameserver 10.212.0.53" || fail "resolv.conf's servers"
            grep -q '^search corp\.example\.com' /etc/resolv.conf || fail "resolv.conf lacks the default domain"
            ;;
    esac
    # The split DNS domain goes to the tunnel's server, which knows the name.
    getent ahostsv4 intranet.corp.example.com | tee "$OUT/getent"
    grep -q '^10\.212\.0\.80 ' "$OUT/getent" || fail "intranet.corp.example.com not resolved through the tunnel"
}

check_reverted() {
    local what="$1"
    ip -o link show type tun | grep -q . && { ip -o link show type tun; fail "$what: a tun interface is left"; }
    ip -4 route show | sort | diff "$OUT/routes4.before" - || fail "$what: the IPv4 routes differ from before"
    if ((ipv6)); then
        ip -6 route show | sort | diff "$OUT/routes6.before" - || fail "$what: the IPv6 routes differ from before"
    fi
    dns_state | diff "$OUT/dns.before" - || fail "$what: the DNS differs from before"
    if [[ "$BACKEND" != resolved ]]; then
        cmp "$OUT/resolv.before" /etc/resolv.conf || fail "$what: resolv.conf differs from before"
    fi
    if pt status acme --json >"$OUT/status.json"; then cat "$OUT/status.json"; fail "$what: still connected"; fi
}

wait_reverted() {
    for _ in $(seq 60); do
        if ! ip -o link show type tun | grep -q . && ip -4 route show | sort | cmp -s "$OUT/routes4.before" - \
            && dns_state | cmp -s "$OUT/dns.before" -; then
            break
        fi
        sleep 0.5
    done
    check_reverted "$1"
}

step "connect"
connect
check_up
grep 'passtunnel vpn-hook: ' "$home/.local/share/passtunnel/profiles/acme/vpn.log"

if [[ "${RECONNECT:-0}" == 1 ]]; then
    step "openconnect's own reconnect, after its connection to the server was cut"
    log="$home/.local/share/passtunnel/profiles/acme/vpn.log"
    ups="$(grep -c "^passtunnel vpn-hook: tun[0-9]* up: " "$log")"
    # CUT_COMMAND cuts the connection some other way (from the server's side, say).
    if [[ -n "${CUT_COMMAND:-}" ]]; then
        eval "$CUT_COMMAND"
    else
        ss -tn dst 172.31.211.10 dport = 443 | tee "$OUT/ss.before"
        ss -K dst 172.31.211.10 dport = 443 >/dev/null
        if ss -tn dst 172.31.211.10 dport = 443 | cmp -s "$OUT/ss.before" -; then
            fail "ss -K closed nothing (a kernel without CONFIG_INET_DIAG_DESTROY?)"
        fi
    fi
    for _ in $(seq 120); do
        (($(grep -c "^passtunnel vpn-hook: tun[0-9]* up: " "$log") > ups)) && break
        sleep 0.5
    done
    tail -n 12 "$log"
    (($(grep -c "^passtunnel vpn-hook: tun[0-9]* up: " "$log") > ups)) || fail "no reconnect reported up by the hook"
    if grep -q 'passtunnel vpn-hook: .*failed' "$log"; then fail "the hook failed"; fi
    pt status acme --json | jq -e '.state == "connected"' >/dev/null || fail "not connected after the reconnect"
    check_up
fi

step "disconnect"
pt disconnect acme --json --wait | jq -c '{state}'
wait_reverted "after disconnect"

step "connect again (a fresh code)"
connect
check_up

step "openconnect killed: passtunneld reverts"
pid="$(pgrep -x openconnect)"
[[ "$pid" =~ ^[0-9]+$ ]] || fail "no single openconnect: '$pid'"
kill -KILL "$pid"
wait_reverted "after SIGKILL of openconnect"
grep -E 'acme' "$OUT/daemon.log" | tail -n 5

step "done"
kill -TERM "$daemon"
wait "$daemon"
daemon=0
if [[ -d /run/passtunnel ]] && find /run/passtunnel -mindepth 2 -name state | grep -q .; then
    find /run/passtunnel -ls
    fail "a session directory is left"
fi
echo "Cisco AnyConnect tunnel against ocserv ($BACKEND): passed"
