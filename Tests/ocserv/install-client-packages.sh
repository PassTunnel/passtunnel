#!/bin/sh
# Installs what the test client needs, plus the packages given as arguments (client.Dockerfile). TEST ONLY.
set -eu
# Three tries: the mirrors fail now and then.
for try in 1 2 3; do
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        openconnect ca-certificates jq iproute2 iputils-ping procps "$@" >/dev/null && break
    [ "$try" -lt 3 ] || exit 1
    sleep 10
done
rm -rf /var/lib/apt/lists/*
