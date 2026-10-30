#!/bin/bash
# Starts openconnect's fake-gp-server.py once per test configuration, each on a port of its own, at the
# container's address (Tests/globalprotect/README.md, "What it offers"). TEST ONLY.
#
# The script takes the address it listens on as the host of the gateways its portal lists, so it runs at the
# container's own address (FAKE_GP_ADDRESS, by default the first of `hostname -i`), never 0.0.0.0. Each
# server's configuration is set through its /CONFIGURE endpoint once it answers; then /run/fake-gp-ready is
# made. The container ends when any server does.
set -euo pipefail

ADDRESS="${FAKE_GP_ADDRESS:-$(hostname -i | cut -d ' ' -f 1)}"
CERTS=/etc/fake-gp
mkdir -p /var/log/fake-gp
rm -f /run/fake-gp-ready

# PORT|CERT[|FIELD=VALUE...]: the form fields posted to /CONFIGURE.
servers=(
    "443|server"
    "4432|server|gateways=US East,US West"
    "4433|server|portal_2fa=js|portal_cookie=portal-userauthcookie"
    "4434|server|gw_2fa=xml"
    "4435|server|portal_2fa=html|gw_2fa=html"
    "4436|server|portal_saml=prelogin-cookie"
    "4437|server|portal_2fa=xml|gateway_saml=prelogin-cookie"
    "4438|name"
)

# The certificates name vpn.example.com: ask the server under that name at its address, against the test CA.
ask() {
    local port="$1"
    shift
    curl -fsS --max-time 5 --cacert "$CERTS/ca.pem" --resolve "vpn.example.com:$port:$ADDRESS" \
        "https://vpn.example.com:$port/CONFIGURE" "$@"
}

for entry in "${servers[@]}"; do
    IFS='|' read -r port cert _ <<<"$entry"
    python3 -u /opt/fake-gp/fake-gp-server.py "$ADDRESS" "$port" "$CERTS/$cert-cert.pem" "$CERTS/server-key.pem" \
        >"/var/log/fake-gp/$port.log" 2>&1 &
done

for entry in "${servers[@]}"; do
    IFS='|' read -r -a parts <<<"$entry"
    port="${parts[0]}"
    for try in $(seq 60); do
        ask "$port" -o /dev/null 2>/dev/null && break
        if [[ "$try" -eq 60 ]]; then
            echo "fake-gp-test: the server on port $port did not answer" >&2
            cat "/var/log/fake-gp/$port.log" >&2
            exit 1
        fi
        sleep 0.5
    done
    fields=()
    for field in "${parts[@]:2}"; do fields+=(--data-urlencode "$field"); done
    if ((${#fields[@]})); then
        ask "$port" -o /dev/null "${fields[@]}"
    fi
    echo "fake-gp-test: port $port: $(ask "$port" | tail -n 1)"
done

touch /run/fake-gp-ready
echo "fake-gp-test: ready at $ADDRESS"
wait -n
echo "fake-gp-test: a server ended" >&2
exit 1
