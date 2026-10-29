#!/bin/bash
# Runs tunnel-test.sh against the test server on each Linux DNS backend, each client in a container of
# its own (Tests/ocserv/README.md). TEST ONLY. Needs Docker (with NET_ADMIN, /dev/net/tun and privileged
# containers: a CI runner VM, Linux, or Docker Desktop) and changes nothing outside its containers and
# the network it makes.
#
#   PASSTUNNEL_TEST_OCSERV=1 Tests/ocserv/run-tunnel-tests.sh BIN_DIR [BACKEND...]
#
# BIN_DIR: passtunnel and passtunneld for Linux on this architecture, with the Swift standard library
# linked statically (swift build --static-swift-stdlib). BACKEND: file, resolvconf, resolved (default:
# all three). The containers and the network are removed at the end; the logs are in OUT (default: a
# new temporary directory).
set -euo pipefail

[[ "${PASSTUNNEL_TEST_OCSERV:-}" == 1 ]] || { echo "set PASSTUNNEL_TEST_OCSERV=1 to run (it starts VPN tunnels)" >&2; exit 2; }
BIN="$(cd "${1:?the directory with passtunnel and passtunneld}" && pwd)"
shift
backends=("$@")
((${#backends[@]})) || backends=(file resolvconf resolved)
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$(mktemp -d)}"
mkdir -p "$OUT"
NET=passtunnel-ocserv-test
SERVER=passtunnel-ocserv-test
CLIENT=passtunnel-ocserv-client

cleanup() {
    docker rm -f "$SERVER" "$CLIENT" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker build -q -t passtunnel-ocserv "$HERE" >/dev/null
docker network create --subnet 172.31.211.0/24 "$NET" >/dev/null

failed=0
for backend in "${backends[@]}"; do
    case "$backend" in
        file) target=client-ubuntu extra="" ;;
        resolvconf) target=client-debian extra="openresolv" ;;
        resolved) target=client-ubuntu extra="systemd systemd-sysv systemd-resolved dbus" ;;
        *) echo "unknown backend: $backend" >&2; exit 2 ;;
    esac
    echo "::group::Cisco AnyConnect tunnel, DNS: $backend"
    # A server of its own for each client: ocserv refuses a code it accepted from the previous one.
    docker rm -f "$SERVER" >/dev/null 2>&1 || true
    docker run -d --name "$SERVER" --network "$NET" --ip 172.31.211.10 --cap-add NET_ADMIN --device /dev/net/tun \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 passtunnel-ocserv >/dev/null
    pin="$(docker exec "$SERVER" cat /etc/ocserv/pin.txt)"
    docker build -q -t "passtunnel-ocserv-client:$backend" --target "$target" --build-arg EXTRA="$extra" \
        -f "$HERE/client.Dockerfile" "$HERE" >/dev/null
    shared="$(mktemp -d)"
    run=(docker run -d --name "$CLIENT" --network "$NET" --add-host vpn.example.com:172.31.211.10 --cap-add NET_ADMIN
        --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 -v "$BIN:/bin-under-test:ro" -v "$HERE:/test:ro"
        -v "$shared:/shared")
    if [[ "$backend" == resolved ]]; then
        # systemd as init, with systemd-resolved managing /etc/resolv.conf (Docker's bind mount replaced by
        # the usual link to its stub).
        "${run[@]}" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
            "passtunnel-ocserv-client:$backend" /sbin/init >/dev/null
        for _ in $(seq 60); do
            docker exec "$CLIENT" systemctl is-active --quiet systemd-resolved 2>/dev/null && break
            sleep 0.5
        done
        docker exec "$CLIENT" sh -c 'umount /etc/resolv.conf && ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf'
    else
        "${run[@]}" "passtunnel-ocserv-client:$backend" sleep infinity >/dev/null
    fi
    # The reconnect step asks for its connection to be cut from the server's side.
    (
        until [[ -e "$shared/cut" ]] || ! docker inspect "$CLIENT" >/dev/null 2>&1; do sleep 0.5; done
        if [[ -e "$shared/cut" ]]; then docker exec "$SERVER" ocserv-test-cut; fi
    ) &
    cutter=$!
    if docker exec -e PASSTUNNEL_TEST_OCSERV=1 -e OCSERV_PIN="$pin" -e DNS_BACKEND="$backend" -e RECONNECT=1 \
        -e CUT_COMMAND="touch /shared/cut" "$CLIENT" /test/tunnel-test.sh /bin-under-test >"$OUT/$backend.log" 2>&1; then
        tail -n 1 "$OUT/$backend.log"
    else
        cat "$OUT/$backend.log"
        echo "--- ocserv"
        docker logs "$SERVER" 2>&1 | tail -n 40
        failed=1
    fi
    docker rm -f "$CLIENT" >/dev/null
    wait "$cutter" || true
    rm -rf "$shared"
    echo "::endgroup::"
done
exit "$failed"
