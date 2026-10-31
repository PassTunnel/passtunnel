# fake-gp-server: a Palo Alto GlobalProtect test portal and gateway

TEST ONLY. openconnect's own GlobalProtect test server, `tests/fake-gp-server.py`, run unchanged in a container
for PassTunnel's sign-in tests of Palo Alto GlobalProtect (issue #235; docs/ARCHITECTURE.md, "Tests (G8)"). No
open-source server speaks GlobalProtect's tunnel, so this checks the sign-in only; that is one reason the type is
labelled experimental. Every secret in the image is a throwaway: the CA and server key are made when the image is
built (never committed), and the server accepts any password and code. Never publish it beyond the machine that
runs the tests.

## Where it comes from

The script is not in this repository. `start-server.sh` downloads the openconnect release tarball
`https://www.infradead.org/openconnect/download/openconnect-<version>.tar.gz` of the version
`scripts/release.env` pins as `OPENCONNECT_VERSION` (the bundled openconnect's), checks it against
`fake-gp-server.sha256` (the value Homebrew's formula pins for the same tarball) before anything is read from it,
takes only `tests/fake-gp-server.py` out of it into a temporary directory, and builds the image with that file as
its build context `fake-gp` (`Dockerfile`: Debian 13 by digest, its `python3` and `python3-flask`). A hash file for
another version than the pin, or a tarball with another hash, stops it. When the pin moves, the same pull request
updates `fake-gp-server.sha256`.

**License.** `fake-gp-server.py` is part of openconnect and licensed under the GNU Lesser General Public
License 2.1 or later (its header). It is only downloaded and run, in CI and by hand on a test machine: never copied
into this repository, never modified, never part of the app, the Linux tarball, PassTunnel's Docker image (the root
Dockerfile) or any release; only this test image holds it while it runs. So
it adds nothing to `THIRD_PARTY_NOTICES.md`.

## What it offers

`entrypoint.sh` starts the script once per configuration, each on a port of its own at the container's address
(`172.31.212.10` in CI; the script lists its gateways at the address it listens on, so it never listens on
`0.0.0.0`), and sets each one through the script's `/CONFIGURE` endpoint:

| Port | Configuration |
|---|---|
| 443 | One gateway, "Default gateway"; the password alone |
| 4432 | Two gateways, "US East" and "US West" |
| 4433 | A challenge at the portal (the JavaScript form) and the portal's `portal-userauthcookie` |
| 4434 | A challenge at the gateway (the XML form) |
| 4435 | A challenge at the portal and at the gateway (the HTML-wrapped form), no override cookie |
| 4436 | SAML at the portal |
| 4437 | A challenge at the portal (XML), SAML at the gateway |
| 4438 | As 443, with a certificate for `vpn.example.com` only, not the address its gateway is listed at |
| 4439 | Nothing (no server) |

Every other port has the certificate for `vpn.example.com`, `127.0.0.1` and `172.31.212.10`, signed by the image's
test CA (`/etc/fake-gp/ca.pem`); one key for all, its pin in `/etc/fake-gp/pin.txt`. Each portal lists its gateways at
its own address and port. The server accepts any user name, password and challenge answer (only the challenge's
`inputStr` must come back, and it clears it after use, so a blind replay of a challenge fails as at a real gateway),
remembers no code, answers every HIP check "not needed", and keeps its state in an HTTP cookie of the sign-in run,
so a later tunnel run (another openconnect) is refused at the gateway's configuration ("errors getting SSL/VPN
config").

## The tests

`FakeGPServerSignInTests` (Tests/PassTunnelCoreTests), run only with `PASSTUNNEL_TEST_GP_SERVER` set, through
`ConnectionManager` with the real openconnect (Ubuntu's 9.12 in CI, so `disable-ipv6` is rendered), the real clock
and a fake helper (no tunnel):

- the password alone at the portal and openconnect's replay to its gateway: the start request (the gateway's address
  and port, `connect_url`, the key the sign-in accepted, the profile's pins, the cookie in GlobalProtect's shape with
  `preferred-ipv6` only without `disable-ipv6`) through the helper's wire format, its protocol-5 checks and the root
  file it renders; nothing of the password, the codes or the cookie in the log, the errors or the activity;
- the portal by name and its gateway by address (another host, the two-server rule), in CA mode with the test CA;
- two pins, the gateway's matching;
- a code at the portal with its override cookie (one code, no second sign-in, the cookie's value masked); a code at
  the gateway after the replay; `skip_portal` with the code at the gateway;
- a code at both: the second part (the password and a code of a later window) written at the gateway's prompt after
  the first code's window ended;
- two gateways: the profile's chosen; none named (the labels for `gateway`, the code spent and masked); one the portal
  does not list, then one it does through `chooseGateway`;
- SAML at the portal (the code given back), at the gateway after the portal (spent), at the gateway with
  `skip_portal` (given back);
- the system CAs refusing the test CA, then "Trust this server"; another pin; the gateway's certificate failing after
  the portal, then "Trust This Gateway…" with the portal's pin; no server at a port;
- the root file the helper renders, run with the real cookie: openconnect takes every option and asks the gateway for
  its configuration, where the run ends.

**What stays with the unit tests** (`GlobalProtectConnectTests`, `GlobalProtectConfigTests`,
`GlobalProtectHelperTests`, with openconnect 9.21's output written from its sources), because the server cannot do
it unmodified: a refused password or code (HTTP 512, standard input closed early, two attempts only); a spent code
and the second code's wait when another process used the window, or none comes in time (the server remembers no
code); a gateway with another key than the portal's ("None of the N fingerprint(s)"), and the two-server rule's
refusals (a third server, the gateway before the portal's configuration), since its gateways are always itself; the
HIP request and the `hip_report_not_sent` notice (it never asks); "Server is neither a GlobalProtect portal nor a
gateway"; `portal-prelogonuserauthcookie` and unexpected `<jnlp>` arguments in the log masks; server text that looks
like openconnect's lines; a third prompt, the time limits and cancelling; `combined` delivery; and the tunnel itself
(ESP or HTTPS, rekey and reconnect, logout, the hook), which no open-source server offers. openconnect 9.21's own
output (the Mac's: gateway priorities, the SAML line without `:`) is in those fixtures; CI runs 9.12.

## In CI

The job "Palo Alto GlobalProtect against openconnect's test server" (`.github/workflows/ci.yml`) runs on every pull
request and push: `start-server.sh` (the tarball cached by its hash, checked on every run), then the tests in the
Swift container on the same Docker network, which knows `172.31.212.10` as `vpn.example.com`. It takes a few minutes,
mostly the build; one case waits for the next TOTP window (up to 30 s).

It is **not a required check**, as "Cisco AnyConnect against ocserv" is not: it depends on infradead.org (on a cache
miss), Docker Hub and Debian's mirrors, which can fail for reasons that are not the change's, and a required check
that fails that way blocks every pull request, docs included. Review it on the pull requests that touch the sign-in
(`GlobalProtectSignIn`, `VPNLog+GlobalProtect`, `ConnectionManager`, VPNConfig's openconnect files) before merging.

## Locally

With Docker (Linux, or Docker Desktop on a Mac): the tests reach the container's address, so they run in the Swift
container on its network, as in CI.

```sh
Tests/globalprotect/start-server.sh /tmp/fake-gp-downloads /tmp/fake-gp
docker run --rm --network passtunnel-fake-gp --add-host vpn.example.com:172.31.212.10 -v "$PWD:/src" -w /src \
  -v /tmp/fake-gp:/fake-gp:ro swift:6.4.1-noble bash -c '
  apt-get update -qq && apt-get install -y -qq --no-install-recommends openconnect ca-certificates >/dev/null
  PASSTUNNEL_TEST_GP_SERVER=172.31.212.10 PASSTUNNEL_TEST_GP_NAME=vpn.example.com PASSTUNNEL_TEST_GP_CA=/fake-gp/ca.pem \
    PASSTUNNEL_TEST_GP_PIN="$(cat /fake-gp/pin.txt)" swift test --filter FakeGPServerSignInTests'
docker rm -f passtunnel-fake-gp; docker network rm passtunnel-fake-gp
```

`PASSTUNNEL_TEST_GP_OPENCONNECT` names another openconnect to run instead of the distribution's.

## Against a real gateway (manual)

What the test server cannot show (a real gateway's forms, HIP, ESP, the tunnel) is checked by hand, by anyone with
an account on a GlobalProtect portal they may use, with a password and a code (or the password alone) and no single
sign-on. Write down the portal's address and the gateway names the GlobalProtect app shows.

1. Make the profile (the app: File → New Palo Alto GlobalProtect Profile (Experimental)…; or the command):

   ```sh
   passtunnel add "Acme GP" --type globalprotect --server https://vpn.example.com
   passtunnel set acme-gp username=alice otp_mode=totp
   passtunnel secret acme-gp password
   passtunnel secret acme-gp totp                 # when the codes come from an authenticator app
   ```

2. Connect (`passtunnel connect acme-gp --json`, or from the menu bar). A portal with several gateways fails with
   their labels (`failure.gateways`, or the app's list): `passtunnel set acme-gp gateway="US East"` and connect again.
   A server certificate the system does not trust is offered for trust (the portal's, then a gateway's): compare
   the pin with one obtained another way before accepting it.
3. Connected: `passtunnel status acme-gp --json` shows `connected` and an address, and `notices` holds
   `hip_report_not_sent` when the gateway asked for a HIP report. An internal host answers and an internal name
   resolves; the routes and DNS are as for Cisco AnyConnect (Mac: `netstat -rn -f inet`, `scutil --dns`; Linux:
   `ip route`, `resolvectl status` or `/etc/resolv.conf`).
4. `passtunnel log acme-gp`: the portal's and the gateway's requests; `Challenge:` where a code was asked; an
   `ssl-vpn/prelogin.esp` after the portal's `getconfig.esp` is a second sign-in (that connect waits for the next
   code's window); "ESP session established" or "using HTTPS instead" (try `tls_only=true` when ESP fails). No
   password, code, `authcookie` or portal cookie value may appear (they show as `<redacted>`).
5. Stay connected past the gateway's rekey interval (often an hour): the log shows the reconnect and the tunnel stays
   up. Disconnect: "Logout successful.", routes and DNS as before. Connect again and `sudo pkill -KILL -x openconnect`:
   everything is reverted within a few seconds.
6. Report the result with the GlobalProtect report issue template (`globalprotect_report.md`), with host names, user
   names and addresses replaced (examples as in this repository).
