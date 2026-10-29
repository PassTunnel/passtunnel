#!/bin/sh
# Cuts every client's connection from the server's side (Tests/ocserv/README.md). TEST ONLY: kills
# ocserv's workers (one per connection) with SIGKILL, so the client sees its TLS connection end and
# reconnects with its cookie, which ocserv's main process still holds.
set -eu
killed=0
for dir in /proc/[0-9]*; do
    # The command line, which a worker running as another user still shows (its exe link does not).
    name="$(tr '\0' '\n' <"$dir/cmdline" 2>/dev/null | head -n 1 || true)"
    if [ "$name" = /usr/sbin/ocserv-worker ]; then
        kill -KILL "${dir#/proc/}" && killed=$((killed + 1))
    fi
done
echo "ocserv-test-cut: $killed connection(s) cut"
[ "$killed" -gt 0 ]
