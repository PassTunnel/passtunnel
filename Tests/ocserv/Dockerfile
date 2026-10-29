# A Cisco AnyConnect-compatible test server: Debian's ocserv with a password and a TOTP code (two forms),
# for the end-to-end tests of PassTunnel's Cisco AnyConnect support (Tests/ocserv/README.md). TEST ONLY:
# every secret in it (the CA and server keys made at build time, the password, the TOTP secret) is a
# throwaway that protects nothing. Never expose it beyond the machine that runs the tests.
#
#   docker build -t passtunnel-ocserv Tests/ocserv
#   docker run -d --name ocserv -p 127.0.0.1:8443:443 passtunnel-ocserv                 # sign-in only
#   docker run -d --name ocserv --cap-add NET_ADMIN --device /dev/net/tun \
#     --sysctl net.ipv6.conf.all.disable_ipv6=0 -p 8443:443 passtunnel-ocserv          # with tunnels

# debian:trixie-slim (Debian 13: ocserv 1.3.0 built with liboath, openconnect 9.12), pinned by the
# digest of its multi-arch index; Dependabot updates the digest (.github/dependabot.yml).
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        ocserv dnsmasq-base iproute2 openssl ca-certificates >/dev/null \
    && rm -rf /var/lib/apt/lists/*

COPY ocserv.conf /etc/ocserv/ocserv.conf
COPY users.oath /var/lib/ocserv/users.oath
COPY dnsmasq.conf /etc/ocserv/dnsmasq.conf
COPY entrypoint.sh /usr/local/sbin/ocserv-test
COPY cut.sh /usr/local/sbin/ocserv-test-cut

# A test CA and a server certificate for vpn.example.com, 127.0.0.1 and the address the tunnel job gives
# the container (Tests/ocserv/README.md), made fresh for each build: no key is ever committed. ca.pem and
# pin.txt (the server key's pin-sha256, as openconnect prints it) are read by the tests.
RUN set -eu; cd /etc/ocserv; \
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
        -subj "/CN=PassTunnel test CA (test only)" -keyout ca-key.pem -out ca.pem \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null; \
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=vpn.example.com" -keyout server-key.pem -out server.csr 2>/dev/null; \
    printf '%s\n' 'subjectAltName=DNS:vpn.example.com,IP:127.0.0.1,IP:172.31.211.10' \
        'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' >server.ext; \
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 30 \
        -extfile server.ext -out server-cert.pem 2>/dev/null; \
    rm ca-key.pem server.csr server.ext ca.srl; \
    printf 'pin-sha256:%s\n' "$(openssl x509 -in server-cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary | base64)" >pin.txt; \
    chmod 0600 server-key.pem; \
    # alice's and bob's password (test only); ocpasswd asks twice.
    for user in alice bob; do \
        printf '%s\n%s\n' 'example-password' 'example-password' | ocpasswd -c /etc/ocserv/ocpasswd "$user"; \
    done; \
    chmod 0755 /usr/local/sbin/ocserv-test /usr/local/sbin/ocserv-test-cut; chmod 0600 /var/lib/ocserv/users.oath

EXPOSE 443/tcp 443/udp
ENTRYPOINT ["/usr/local/sbin/ocserv-test"]
