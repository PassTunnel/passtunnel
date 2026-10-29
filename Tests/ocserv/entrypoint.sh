#!/bin/sh
# Starts the test server (Tests/ocserv/README.md). TEST ONLY.
#
# With NET_ADMIN (the tunnel tests), the addresses inside the tunnel are added to the container's own
# loopback first, and dnsmasq answers on them: 10.212.0.53 and fd42:212::53 (DNS), 10.212.0.80 and
# fd42:212::80 (a host to reach). Without it (the sign-in tests) ocserv runs alone: it allocates a tun
# device only once a client asks for the tunnel, which sign-ins never do.
set -eu

if ip addr add 10.212.0.53/32 dev lo 2>/dev/null; then
    ip addr add 10.212.0.80/32 dev lo
    if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = 0 ]; then
        ip -6 addr add fd42:212::53/128 dev lo
        ip -6 addr add fd42:212::80/128 dev lo
    else
        sed -i 's/,fd42:212::53$//' /etc/ocserv/dnsmasq.conf
    fi
    dnsmasq --conf-file=/etc/ocserv/dnsmasq.conf --keep-in-foreground &
    echo "ocserv-test: tunnel addresses and DNS set up"
else
    echo "ocserv-test: no NET_ADMIN, sign-in only"
fi

exec ocserv --foreground --config /etc/ocserv/ocserv.conf "$@"
