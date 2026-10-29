# ocserv: a Cisco AnyConnect test server

TEST ONLY. A container with Debian's [ocserv](https://ocserv.openconnect-vpn.net/) (an AnyConnect-compatible
server) for PassTunnel's end-to-end tests of Cisco AnyConnect (issue #188; docs/ARCHITECTURE.md, "Tests (#188)").
Every secret in it is a throwaway: the CA and server keys are made when the image is built (never committed),
and the password and the TOTP secret below protect nothing. Never publish it beyond the machine that runs the
tests.

## What it offers

| | |
|---|---|
| Sign-in | `auth = "plain[passwd=…,otp=…]"`: a form for the user name, one for the password, then a separate form "Please enter your OTP password." for the code (`otp_delivery` `separate`). ocserv has no combined password-and-code field |
| Users | `alice` and `bob`, password `example-password`, TOTP secret `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` (RFC 6238's test key "12345678901234567890"; 30 s, 6 digits, SHA-1) |
| Codes | ocserv records each user's last accepted code in the oath users file and refuses it and anything older, as real servers do |
| Server | `vpn.example.com`, `127.0.0.1` and `172.31.211.10` in the certificate, signed by a test CA: `/etc/ocserv/ca.pem`; the key's pin: `/etc/ocserv/pin.txt` |
| Tunnel | IPv4 `10.211.0.0/24`, IPv6 `fd42:211::/48` (a /64 each); routes into the tunnel `10.212.0.0/16`, `fd42:212::/48`; around it `10.212.99.0/24`; DNS `10.212.0.53`, split DNS and default domain `corp.example.com` |
| Inside | `10.212.0.80` / `fd42:212::80` answer ping; `intranet.corp.example.com` resolves to them (dnsmasq, only for `corp.example.com`) |
| Not here | A host scan (CSD) or group list: ocserv asks for neither, so those paths stay with the unit tests (`AnyConnectConnectTests`) |

Without `NET_ADMIN` ocserv runs alone and only signs in: it allocates a tun device once a client asks for the
tunnel (CSTP CONNECT), which `openconnect --authenticate` never does.

## The tests

- **Sign-in, every CI run** (job "Cisco AnyConnect against ocserv" in `.github/workflows/ci.yml`, x86_64): the
  image on a Docker network, and `OcservSignInTests` (Tests/PassTunnelCoreTests) in the Swift container with
  Ubuntu's openconnect, run only with `PASSTUNNEL_TEST_OCSERV_SERVER` set. They connect through
  `ConnectionManager` with the real openconnect and clock and a fake helper: the password and code accepted
  with the pin and in CA mode (the test CA given to the sign-in in the test only; the product always passes
  the system bundle), what reaches the helper accepted by its own checks; a second connect in the same window
  waiting for the next code; ocserv refusing a spent code; a wrong code; a wrong password answered by ocserv's
  retry form (refused, the code counted as sent); `combined` delivery against these separate forms; the system
  CAs refusing the test CA (with the pin to offer); another pin; and a tunnel run with a cookie ocserv does not
  know, which ends at the CSTP CONNECT.
- **Tunnel, opt-in** (workflow `.github/workflows/ocserv-tunnel.yml`, not a required check):
  `run-tunnel-tests.sh` starts the image with `NET_ADMIN` and `/dev/net/tun`, and for each Linux DNS backend
  a client container of its own (`client.Dockerfile`: Ubuntu with a plain `/etc/resolv.conf`, Debian with
  openresolv, Ubuntu with systemd-resolved as a privileged container's init), in which `tunnel-test.sh`
  runs, only with `PASSTUNNEL_TEST_OCSERV=1`, as root. It is the one test that starts a tunnel (an
  exception to "tests never start a tunnel", docs/LINUX.md, Rules), and it changes nothing outside its
  containers. passtunneld and the `passtunnel` command connect; the test checks the address, the routes
  into and around the tunnel, the default route, reachability (ping) and DNS (the backend's own state, and
  `intranet.corp.example.com` resolved through the tunnel); disconnects and checks that routes and DNS are
  as before; has the server cut the connection (`ocserv-test-cut`) and checks openconnect's own reconnect
  (the hook reports the tunnel up again after its checks); connects again with a fresh code; and kills
  openconnect with SIGKILL for passtunneld to revert everything.

Locally, with Docker (Linux, or Docker Desktop on a Mac):

```sh
docker build -t passtunnel-ocserv Tests/ocserv
docker run -d --name ocserv -p 127.0.0.1:8443:443 passtunnel-ocserv
docker cp ocserv:/etc/ocserv/ca.pem /tmp/ocserv-ca.pem
PASSTUNNEL_TEST_OCSERV_SERVER=127.0.0.1:8443 PASSTUNNEL_TEST_OCSERV_CA=/tmp/ocserv-ca.pem \
  PASSTUNNEL_TEST_OCSERV_PIN="$(docker exec ocserv cat /etc/ocserv/pin.txt)" \
  PASSTUNNEL_TEST_OCSERV_OPENCONNECT=/opt/homebrew/bin/openconnect \
  swift test --filter OcservSignInTests       # PASSTUNNEL_TEST_OCSERV_OPENCONNECT: on a Mac only
docker rm -f ocserv
```

A successful sign-in takes a TOTP window of its own per user, so the tests take about a minute.

The tunnels (Linux or Docker Desktop; the binaries for Linux with the Swift standard library linked in):

```sh
docker run --rm -v "$PWD:/src" -w /src swift:6.4.1-noble bash -c \
  'swift build --static-swift-stdlib --product passtunnel && swift build --static-swift-stdlib --product passtunneld \
   && install -D -m 0755 -t ocserv-bin "$(swift build --static-swift-stdlib --show-bin-path)"/passtunnel{,d}'
PASSTUNNEL_TEST_OCSERV=1 Tests/ocserv/run-tunnel-tests.sh ocserv-bin            # or: … ocserv-bin resolved
```

## A tunnel from a Mac (manual)

GitHub's macOS runners have no Docker, so the Mac's tunnel (the helper and its `vpn-hook`, routes with
`route`, DNS with `SCDynamicStore`) is checked by hand on a developer Mac with Docker Desktop and a build
of the app with its helper installed. It changes the Mac's routes and DNS for the duration of the test,
with nothing but this container behind them.

1. Start the server with tunnels allowed, published on the Mac's own address:

   ```sh
   docker build -t passtunnel-ocserv Tests/ocserv
   docker run -d --name ocserv --cap-add NET_ADMIN --device /dev/net/tun \
     --sysctl net.ipv6.conf.all.disable_ipv6=0 -p 127.0.0.1:8443:443 passtunnel-ocserv
   docker exec ocserv cat /etc/ocserv/pin.txt
   ```

2. Add the profile (the app's editor, or the command; the user name, password and code as above):

   ```sh
   passtunnel add "ocserv test" --type anyconnect --server https://127.0.0.1:8443/
   passtunnel set ocserv-test username=alice otp_mode=totp set_dns=true set_routes=true tls_only=true \
     server_cert="$(docker exec ocserv cat /etc/ocserv/pin.txt)"
   passtunnel secret ocserv-test password        # example-password
   passtunnel secret ocserv-test totp            # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
   ```

3. Connect (`passtunnel connect ocserv-test --json`, or from the menu bar) and check:
   - `passtunnel status ocserv-test --json`: `connected`, an address in `10.211.0.0/24`;
   - `netstat -rn -f inet | grep -E '10\.212|utun'`: `10.212/16` through the `utun`, `10.212.99/24` through
     the previous default gateway; the default route unchanged;
   - `ping -c 2 10.212.0.80`;
   - `scutil --dns`: a resolver for `corp.example.com` with `10.212.0.53`; `dscacheutil -q host -a name
     intranet.corp.example.com` answers `10.212.0.80`.
4. Disconnect and check that the routes and `scutil --dns` are as before. Connect again, then
   `sudo pkill -KILL -x openconnect`: the helper reverts the same way within a few seconds.
5. Without a pin (`server_cert=`) the connect fails with the server's pin offered ("Trust this server"),
   since the test CA is not in the system's trust store; with a wrong password the log shows ocserv's
   "Login failed." and the connect fails as refused.
6. `docker rm -f ocserv`, and delete the profile (`passtunnel rm ocserv-test`).

The server at `127.0.0.1` never gets a host route (the hook leaves a server on this machine alone), and
`10.212.0.0/16` must not overlap a network the Mac is on.
