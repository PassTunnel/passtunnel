# A Palo Alto GlobalProtect test portal and gateway: openconnect's own tests/fake-gp-server.py, run unchanged
# with Debian's Python 3 and Flask, for the sign-in tests of PassTunnel's GlobalProtect support
# (Tests/globalprotect/README.md). TEST ONLY: every secret in it (the CA and server keys made at build time) is
# a throwaway that protects nothing, and the server accepts any password and code. Never expose it beyond the
# machine that runs the tests.
#
# fake-gp-server.py is not in this repository: start-server.sh takes it from the openconnect release tarball
# after checking the tarball's SHA-256 (fake-gp-server.sha256) and passes it in as the build context
# `fake-gp`:
#
#   Tests/globalprotect/start-server.sh DOWNLOADS OUT         # fetches, checks, builds and starts it
#
# The script is openconnect's (LGPL-2.1 or later); it is only run here, never copied into this repository or
# shipped (README.md, "License").

# debian:trixie-slim (Debian 13: Python 3.13, Flask 3.1), pinned by the digest of its multi-arch index, the
# image of Tests/ocserv; Dependabot updates the digest (.github/dependabot.yml).
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

# Three tries: the mirrors fail now and then.
RUN for try in 1 2 3; do \
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            python3 python3-flask openssl curl ca-certificates >/dev/null && break; \
        [ "$try" -lt 3 ] || exit 1; sleep 10; \
    done; \
    rm -rf /var/lib/apt/lists/*

COPY --from=fake-gp fake-gp-server.py /opt/fake-gp/fake-gp-server.py
COPY entrypoint.sh /usr/local/sbin/fake-gp-test

# A test CA and one server key with two certificates, made fresh for each build (no key is ever committed):
# server-cert.pem for vpn.example.com, 127.0.0.1 and 172.31.212.10 (the address the CI job gives the
# container), and name-cert.pem for vpn.example.com alone, so a gateway the portal lists by its address fails
# the CA check (README.md). ca.pem and pin.txt (the key's pin-sha256, as openconnect prints it) are read by the
# tests.
RUN set -eu; mkdir -p /etc/fake-gp; cd /etc/fake-gp; \
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
        -subj "/CN=PassTunnel test CA (test only)" -keyout ca-key.pem -out ca.pem \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null; \
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=vpn.example.com" -keyout server-key.pem -out server.csr 2>/dev/null; \
    for cert in server name; do \
        if [ "$cert" = server ]; then san='DNS:vpn.example.com,IP:127.0.0.1,IP:172.31.212.10'; else san='DNS:vpn.example.com'; fi; \
        printf '%s\n' "subjectAltName=$san" 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
            'extendedKeyUsage=serverAuth' >server.ext; \
        openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 30 \
            -extfile server.ext -out "$cert-cert.pem" 2>/dev/null; \
    done; \
    rm ca-key.pem server.csr server.ext ca.srl; \
    printf 'pin-sha256:%s\n' "$(openssl x509 -in server-cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary | base64)" >pin.txt; \
    chmod 0600 server-key.pem; chmod 0755 /usr/local/sbin/fake-gp-test

EXPOSE 443/tcp 4432-4438/tcp
ENTRYPOINT ["/usr/local/sbin/fake-gp-test"]
