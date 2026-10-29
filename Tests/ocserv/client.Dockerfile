# A client machine for tunnel-test.sh (Tests/ocserv/README.md). TEST ONLY. BASE is pinned by digest by
# the caller (run-tunnel-tests.sh); EXTRA adds the DNS backend's packages (openresolv, or systemd with
# systemd-resolved, which then runs as the container's init).
ARG BASE
FROM ${BASE}
ARG EXTRA=""
# Three tries: the mirrors fail now and then.
RUN for try in 1 2 3; do \
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            openconnect ca-certificates jq iproute2 iputils-ping procps ${EXTRA} >/dev/null && break; \
        [ "$try" -lt 3 ] || exit 1; sleep 10; \
    done; rm -rf /var/lib/apt/lists/*
