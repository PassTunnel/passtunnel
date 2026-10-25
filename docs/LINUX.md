# PassTunnel for Linux

This is the spec for the Linux version: what runs where, how the root daemon is built and secured,
where secrets live, and the order it is built in. [ARCHITECTURE.md](ARCHITECTURE.md),
[APP.md](APP.md) and [CLI-JSON.md](CLI-JSON.md) remain the source of truth for everything Linux
shares with the Mac: profiles, code formats, the fresh-code rule, share files, the `--json` objects,
error codes and the MCP tools. Background and the decisions behind this spec: issue #5.

## What it is

| | |
|---|---|
| First release | `passtunnel` (the CLI and the stdio MCP server) and `passtunneld` (the root daemon). No GUI |
| Later | A desktop app with tray, notifications and live codes, built from the new interface design for macOS, Windows and Linux; a password prompt for protected profiles |
| VPN types | OpenVPN and FortiGate SSL VPN, with the distribution's `openvpn` (2.6 or later) and `openfortivpn` (1.21 or later) |
| Targets | systemd distributions on x86_64 and aarch64. Tested: Ubuntu 24.04 and 26.04, Debian 13, the current two Fedora releases. Best effort: Ubuntu 22.04, Debian 12, RHEL 9 and 10 |
| Language | Swift (6.4 toolchain, language mode 5), the same packages as the Mac; English only at first |

## Process model

```
passtunnel …          ─┐
passtunnel mcp (stdio) ┴─▶ PassTunnelCore (as on the Mac: ProfileStore, ConnectionManager, TOTP,
                           AutomationService, MCPServer), secrets from a SecretStore
                                │  HelperRequest / HelperResponse JSON (unchanged)
                                │  /run/passtunnel/daemon.sock
                                ▼
                           passtunneld (root; links only PassTunnelShared + PassTunnelVPNConfig)
                                │  spawns, supervises, stops
                                ▼
                           openvpn / openfortivpn (+ pppd), from the distribution
```

- `passtunnel` runs as the user. It keeps the Mac's split exactly: profiles, secrets, TOTP and the
  credentials sent are worked out in the user's process; the daemon never sees a TOTP secret, only
  what is sent to the server, as the macOS helper does.
- `passtunneld` is a separate executable target, Linux only. Like `PassTunnelHelper` it links
  `PassTunnelShared` and `PassTunnelVPNConfig` and nothing else.
- The OpenVPN management socket is handed to the user as on the Mac (`--management-client-user`),
  so status and the static-challenge reply go from the user's process straight to OpenVPN.

## Paths

| What | Path |
|---|---|
| Profiles, preferences, logs | `~/.local/share/passtunnel/` (same layout as the Mac's support dir: `config.json`, `profiles/<id>/…`); `PASSTUNNEL_HOME` overrides it for tests. `XDG_DATA_HOME` is not followed, because the daemon checks that profile directories are under the caller's home at this fixed subpath |
| Run root | `/run/passtunnel/` (0711, root): `<uid>/<id>/` per session as on the Mac (`config.ovpn` or `openfortivpn.conf`, `auth`, `state`, `mgmt.sock`; for DNS the `dns-hook` link and the record `dns`, with `dns.resolv.conf`), and `daemon.lock` (one daemon per run root) |
| Daemon socket | `/run/passtunnel/daemon.sock` (0666, root; access is decided per request, below) |
| Binaries | `/usr/bin/passtunnel`, `/usr/sbin/passtunneld` from the packages; `/usr/local/…` from the tarball |

`PT.profilesSubpath`, `PT.helperRunRoot`, the `sun_path` limit (108 bytes on Linux) and the CA bundle
become platform values. The CA bundle is the first of `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem` that exists (`FortiConfig` takes it as a
parameter), resolved and checked as the tools are (below).

## The daemon protocol

One request per connection, one JSON object per line, at most 64 KiB:

- `{"op":"hello"}` → `{"protocol":3,"build":"<hex SHA-256 of passtunneld>","build_number":N}`. The
  client's `ensureCompatible()` uses it as the `version` and `build` XPC calls are used on the Mac.
  The daemon hashes `/proc/self/exe` once at start. `build_number` (and `helper_build` in every
  reply) is left out until release builds compile one in (2d).
- `{"op":"perform","request":<HelperRequest>}` → `<HelperResponse>`. Request decoding is
  `HelperCore.decodeRequest`, unchanged, and so are the request types and `PT.helperProtocolVersion`.
  The daemon hands it the bytes of the `request` member exactly as sent (`DaemonCall.parse`).

A client has 5 s to send its line and 5 s to take the reply; each connection is served on a thread
of its own, at most 64 at once and 8 per uid (more are answered "busy" at once). Anything else on
the line (bad JSON, an unknown `op`, a repeated key, more than 64 KiB) gets a `HelperResponse`
failure.

On the client side this is a second `HelperClienting` (`UnixSocketHelperClient`); `ConnectionManager`
needs nothing else from the transport. A Linux `HelperInspecting` reports the daemon as not
installed (no socket), unavailable (no answer within 5 s) or current/outdated (from `hello`).
"Current" means the build of the daemon installed with the running `passtunnel` (`HelperBuild.installedDaemon`:
`<prefix>/sbin/passtunneld` for `<prefix>/bin/passtunnel`, else `passtunneld` next to it, as in a
development build), not the client's own binary: a different build means the daemon still runs an
earlier binary after an update (restart it) or comes from another installation. Without an
installed daemon there, builds are not compared.

## Daemon security rules

The macOS rules apply where they make sense; these replace the ones built on code signing.

- **Who is calling.** `SO_PEERCRED` on the accepted socket gives the uid (and `SO_PEERPIDFD` the
  process, where the kernel has it). Every request acts for that uid only: `SessionPolicy` is keyed by
  (uid, profile ID) as on the Mac, so users never see or stop each other's sessions.
- **Who may connect.** Phase 2: root, and members of the group `passtunnel` (supplementary groups of
  the uid from the user database, `getgrouplist`, not the caller's current groups: adding or removing
  a user takes effect at once, without a new login). Anyone may ask for `hello`. Phase 3 adds polkit: the action
  `com.furkanprlk.passtunnel.connect` (`allow_active` yes by default), checked with the caller's pidfd
  as the subject; the group stays for machines without polkit. `status` and `stop` of one's own
  sessions need no authorization. The daemon cannot tell `passtunnel` from another process of the same
  user (there is no code signature to check); this is documented, as it is for comparable Linux VPN
  daemons.
- **Profiles.** `profileDir` must be the caller's `<home>/.local/share/passtunnel/profiles/<id>`
  (home from the user database, symlinks resolved), with the Mac's owner, mode and link-count checks
  on the directory and on `config.ovpn`, and `config_sha256` compared as on the Mac.
- **Tools.** Only fixed paths are run: the first existing of `/usr/sbin/openvpn`, `/usr/bin/openvpn`;
  `/usr/bin/openfortivpn`; `/usr/sbin/pppd` (checked, run by openfortivpn). Each is resolved with
  `realpath` once, then every component of the real path must be root-owned and not group- or
  world-writable, and the file a regular file. Nothing is pinned by hash: distribution binaries
  change with every security update, so trust rests on the package manager. Versions below
  openvpn 2.6.0, openfortivpn 1.21 or pppd 2.4.7 are refused with a clear message. The checks run
  before every start; the version is read by running the checked file (`openvpn --version`,
  `openfortivpn --version`, `pppd --version`, killed after 5 s). pppd is run by openfortivpn from
  the path compiled into it, `/usr/sbin/pppd`, so it is checked before every FortiGate start too.
- **The daemon itself** refuses to start unless its own executable (`/proc/self/exe`, resolved) passes
  the same path checks, since OpenVPN runs it as root for DNS (below).
- **Spawning.** `posix_spawn` of the checked path (no suspended start: there is no signature to
  verify), new process group, stdin `/dev/null`, output to the session log, every other descriptor
  closed (`posix_spawn_file_actions_addclosefrom_np`), default signals and an empty mask, a fixed
  environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`). Unlike the Mac, `OPENSSL_CONF` and
  the CA variables are **not** overridden: the distribution's OpenSSL configuration (for example
  system-wide crypto policies) applies.
- **OpenVPN** runs with the Mac's fixed flags (`--management <run>/mgmt.sock unix`,
  `--management-client-user`, `--auth-nocache`, `--remap-usr1 SIGTERM`, `--connect-retry-max 3`,
  capped `--verb`), the sanitized config (`OVPNSanitizer`, unchanged) and `--script-security 2` with
  the DNS hook below, the only script it can run (the sanitizer removes every other). The management
  socket goes to the caller as on the Mac, its mode set before its owner (no `CAP_FOWNER` needed).
- **FortiGate** runs openfortivpn as the Mac's helper does: `openfortivpn -c <run>/openfortivpn.conf`
  and nothing else on its command line, the config written by `FortiConfig.render` (typed fields
  only, `checkRendered` as on the Mac) into the session's run directory (0600, root), with the
  password and the one-time code in it, never in an argument or the environment. On Linux the config
  names the distribution's CA bundle (`ca-file`, checked) and keeps the profile's `set-routes`, but
  `set-dns` and `pppd-use-peerdns` are always 0, so neither openfortivpn nor pppd (nor the
  distribution's ppp scripts) touch resolv.conf; the daemon applies DNS (below). Profile directory,
  log, supervision, stop and the cleanup of a previous instance are those of OpenVPN; there is no
  management socket. pppd runs in a session of its own on openfortivpn's pseudo-terminal: openfortivpn
  stops it on its way out, and if openfortivpn is killed, pppd ends when the terminal goes.
- **Supervision.** One waiter per child (a thread in `waitid(WNOWAIT)`, so the child is reaped only
  on the supervisor's queue and its pid cannot be reused while it is listed); `stop` sends SIGTERM,
  then SIGKILL after 5 s; at most `SessionPolicy.maxSessionsPerUser` sessions per user; the session
  log is capped with `HelperCore.capLog`. On exit the DNS the session recorded is reverted (when its
  hook did not) and the run directory removed.
  There is no adoption: a starting daemon stops tools recorded by a previous instance (when the pid
  still runs the recorded executable, `/proc/<pid>/exe`), reverts the DNS their sessions recorded and
  cleans up (under systemd `KillMode=control-group` has already stopped them).
- **Sandbox** (`packaging/linux/passtunnel.service`, a first version that nothing installs yet):
  `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID
  CAP_CHOWN CAP_DAC_OVERRIDE CAP_KILL` (trimmed to what testing shows openvpn and pppd need),
  `DevicePolicy=closed` with `DeviceAllow=/dev/net/tun` and `/dev/ppp` (the pseudo-terminal between
  openfortivpn and pppd is among the standard devices `closed` allows), `ProtectSystem=strict` with
  `/run/passtunnel` and what the DNS hook writes (it runs inside the unit, a child of OpenVPN)
  writable: `-/etc/resolv.conf` and `-/run/resolvconf` (`-`: skipped when missing at start), never
  all of `/etc`, which would let every tool the daemon runs as root change the system's
  configuration. `/etc/resolv.conf` is then a bind mount of its own in a read-only `/etc`, so the
  file backend rewrites it in place (as openresolv does by default; set to rename a file over it,
  `resolv_conf_mv`, it cannot work there, and the set-up fails saying so). The bind mount holds the
  file there was when the unit started: one renamed over it later (a network manager without
  systemd-resolved) is out of the daemon's reach until it restarts, which a set-up says ("restart
  passtunnel.service"). systemd follows a link at `/etc/resolv.conf` and applies the entry to its
  target: into `/run/resolvconf` (Debian's resolvconf) it is redundant beside `-/run/resolvconf` and
  dropped (so resolvconf can still rename its `resolv.conf` there); into `/run/systemd/resolve` the
  file there becomes writable inside the unit and is never written (systemd-resolved is told over
  D-Bus and lets `CAP_NET_ADMIN` through; the daemon's own view of the stub file may keep old search
  domains until it restarts). `PrivateTmp`. FortiGate adds no path: pppd needs `CAP_NET_ADMIN` and
  `/dev/ppp`, its pid file and database under `/run` stay unwritable (it only warns about them), and
  the daemon applies the FortiGate DNS with the same code and paths as the hook. Not set, unlike the first
  plan: `ProtectHome=read-only`, because the daemon creates the session log in the user's profile
  directory (possible once the client opens the log, or it moves out of the home directory);
  `RuntimeDirectory=passtunnel`, because systemd would remove it, and the socket of
  `passtunnel.socket` in it, whenever the service stops (the socket unit creates the directory,
  `DirectoryMode=0711`). `NoNewPrivileges` is not set either: it adds nothing to a root service
  within a bounding set, and it would block SELinux domain transitions to `openvpn_t` or `pppd_t`
  unless the policy allows them; it waits for testing on Fedora and RHEL.

## DNS

Profiles never run scripts (the sanitizer removes them); DNS comes from what the server pushes, and
every value of it is treated as hostile: it ends up in the hands of root.

- **The hook.** `passtunneld dns-hook`: the daemon's own executable, which, like the daemon, refuses
  to run unless it is root's and writable by root only. OpenVPN runs it as root through `dns-hook` in
  the session directory, a link to the daemon's executable (`HelperCore.dnsHook`), because OpenVPN
  2.7's `--dns-updown` runs a path without arguments; the executable started under that name is the
  hook too. 2.7 runs it as `--dns-updown`; 2.6 as `--route-up`, whose failure OpenVPN logs without
  exiting (as 2.7 does for `--dns-updown`), and as `--down` with `--down-pre`, before the device
  closes. The hook never starts a daemon, takes its lock or touches its socket, and ignores the
  arguments `--down` appends.
- **Its own session only.** The hook works in OpenVPN's working directory, which must be a session
  directory `<run root>/<uid>/<id>` (root's) whose `state` names the hook's parent process as the
  session's tool (its pid, running the recorded executable); anything else is refused. It acts on the
  interface OpenVPN names (`dev`: 1 to 15 letters, digits, `_`, `-` and `.`, and it must exist) and
  notes its index, so that a revert never reaches another interface of that name.
- **What it reads.** The `dns_*` variables when there are any (`--dns`: all of OpenVPN 2.7's, which
  turns pushed `dhcp-option`s into them for `--dns-updown`, and 2.6's for pushed `dns` options), else
  2.6's `foreign_option_N` with `dhcp-option DNS`, `DNS6`, `DOMAIN`, `DOMAIN-SEARCH` and
  `ADAPTER-DOMAIN-SUFFIX`. Addresses must parse (`inet_pton`, after a check for hex digits, dots and
  colons only; never the unspecified address) and are written as `inet_ntop` gives them back; domains
  must be plain host names (at most 253 bytes, labels of letters, digits, `-` and `_`, nothing that
  starts like an option or a `~`); at most 8 servers and 16 domains of each kind, indexes up to 64.
  One bad value fails the set-up. Of several `--dns` servers the first that plain DNS on port 53
  reaches is used (DNS over TLS or HTTPS is not set up). Every name is resolved through the tunnel
  unless the server names the domains its server is for (`dns server N resolve-domains`: split DNS),
  as OpenVPN's own scripts and the Mac do. OpenVPN profiles have no setting for the VPN's DNS (on the
  Mac it is FortiGate's, `set_dns`): a config that wants none says `pull-filter ignore "dhcp-option"`
  (and `"dns"`).
- **Applying** (`DNSApplier`: `apply(settings, interface:, in: session)` and `revert(in: session)`,
  independent of OpenVPN; `DNSSettings` holds the checked values), one change at a time on the
  machine (the run root is locked with `flock`), in this order of preference:
  - systemd-resolved, when `/etc/resolv.conf` is a link into `/run/systemd/resolve/` (or to its
    static `resolv.conf`): `resolvectl dns`, `domain` (the search domains, `~domain` for routing-only
    ones, and `~.` when every name goes through the tunnel) and `default-route` (yes only then) for
    the link. `resolvectl revert` undoes it while the link (with that index) exists; once it is gone,
    systemd-resolved has dropped its settings.
  - else `resolvconf` (Debian's or openresolv, not systemd's stand-in, which is resolvectl):
    `resolvconf -a <dev>.passtunnel` with up to three `nameserver` lines and a `search` line on
    standard input, `-d` to revert. Debian's writes `/run/resolvconf/resolv.conf` (renamed into
    place), openresolv `/etc/resolv.conf` in place; openresolv set to rename a file over it instead
    (`resolv_conf_mv` in `/etc/resolvconf.conf`) is refused where `/etc` is read-only (inside the
    unit), before it runs.
  - else `/etc/resolv.conf` itself when it is a regular file of root (a link anywhere else is never
    followed, and fails the set-up): a block at the top (`# PassTunnel <dev> begin: …` to
    `# PassTunnel <dev> end`) with up to three servers and the search domains, and the file's own
    `nameserver` lines (and `search` and `domain`, when the tunnel brings domains) disabled with the
    mark `#PassTunnel <dev># `. A resolv.conf cannot route names, so every name goes through the
    tunnel here. Written atomically where it can be: a new file next to it, synced, renamed over it.
    Inside the unit (`/etc` read-only, the file a bind mount) and where a container runtime
    bind-mounts it (rename fails with `EBUSY`) it is rewritten in place instead: the whole content
    in one write from the start, cut to its length, synced; what it replaces is in the session
    directory first. A file that lost its name (replaced after the unit started) fails the set-up.
    The revert writes back the previous content when the file is still what was written; one changed
    meanwhile loses only the block and the marks; one replaced since is left alone.
  - The tools run only from fixed paths (`/usr/bin/resolvectl`, `/bin/resolvectl`;
    `/usr/sbin/resolvconf`, `/sbin/resolvconf`), checked as the VPN tools are (`TrustedPath`), with
    the fixed environment and argument lists of `Sys.spawn` (never a shell), 10 s each.
- **Recorded and reverted.** Before it changes anything, the hook records in the session directory
  what it is about to change (`dns`: the backend, the interface and its index, a digest of the
  resolv.conf it writes; `dns.resolv.conf`: the content that one replaces; root's, 0600). A failed
  set-up reverts what it did, removes the record and prints "setting DNS failed: …" to the session
  log, which the client turns into `PTError.setupFailed`, as on the Mac. OpenVPN goes on after it on
  2.6 (`--route-up`; a failed `--up` would end OpenVPN with a fatal error, which the client reports
  as `connectFailed` before it looks for a failed set-up) and on 2.7 (`--dns-updown`). The hook
  reverts when OpenVPN takes the tunnel down; the daemon reverts whatever is still recorded when it
  reaps the tool (killed, crashed, or the daemon stopping), and a starting daemon what the sessions
  of a previous instance recorded.
- **FortiGate**: the daemon reads the servers and search domains openfortivpn logs once the tunnel
  is up and applies them for the `ppp` interface through the same `DNSApplier`, when the profile has
  `set_dns`.

## Client side

- **Routes.** The "another VPN already takes all traffic" check (`RoutingTable.trafficRoutes`) reads
  the links, the routes of every table and the policy rules, IPv4 and IPv6, from rtnetlink dumps (no
  privileges, no external commands). It follows the rules in priority order as the kernel does for a
  packet of a local program (no mark, any destination, the caller's uid): a rule applies when its
  selectors match such a packet (none, `iif lo`, a mark of 0, a uid range holding the caller's uid)
  or, for a `not` rule, when they do not. Each applying rule that looks up a table adds that table's
  `default`, `0/1` and `128/1` routes (IPv6: `::/0`, `::/1`, `8000::/1`, and `2000::/3` or its halves,
  which OpenVPN's `redirect-gateway ipv6` adds), less those the rule suppresses
  (`suppress_prefixlength`, as wg-quick sets it); the walk ends at the first table whose routes cover
  every destination and at a rule that drops all traffic. One of these routes through a VPN-type
  interface that is not one of PassTunnel's sessions refuses the connect (`other_vpn_active`;
  `--force` skips it). VPN-type: by the kernel's kind of device (`IFLA_INFO_KIND` `tun`, which tap
  devices have too, `ppp`, `wireguard`, `ovpn-dco`, `ovpn`, `xfrm`, `vti`, `vti6`), or by name (the Mac's
  `utun`, `ppp`, `ipsec`, `tun`, `tap`, and `wg`, `tailscale`, with a number); a modem (`wwan`) is not. PassTunnel's sessions are
  the devices their logs name. So another OpenVPN client (`0/1` and `128/1` in the main table),
  wg-quick (a default route in table 51820 behind a `not fwmark` rule) and Tailscale with an exit node
  (table 52) are found, and a VPN for some destinations only is not.
- **Log parsing.** `VPNLog` reads OpenVPN 2.6 and 2.7 on Linux: the device ("TUN/TAP device tun0
  opened", with data channel offload "DCO device tun0 opened"), the address (`net_addr_v4_add`,
  `net_addr_ptp_v4_add`; `ip addr add` in builds that run iproute2), each route it adds through
  rtnetlink ("net_route_v4_add: 0.0.0.0/1 via 10.8.0.1 dev [NULL] table 0 metric -1", or
  `net_route_v6_add`) and its failure, which follows it ("sitnl_send: rtnl: generic error (-17): File
  exists", "NOTE: Linux route add command failed because route exists", "ERROR: Linux route add command
  failed"; with iproute2 "/sbin/ip route add …" and "RTNETLINK answers: …"), and a DNS hook that
  failed: its own "setting DNS failed: …", or OpenVPN's line for it (2.6, which runs it as
  `--route-up` and `--down`: "WARNING: Failed running command (--route-up): …", "(--up/--down)"; 2.7
  as on the Mac). A route followed by any other line was added. So `setupProblem` (a failed all-traffic route or DNS hook stops the
  session, another failed route is a warning, "File exists" for a route the session added already or
  for the leftover host route to the server is not counted), the address in `status` and the warnings
  behave as on the Mac; the reason shown is the route's line with the error. openfortivpn writes the
  same lines as on the Mac ("Got addresses: […]", "Interface ppp0 is UP", "Tunnel is up and running").
  The tests use log lines in the formats of OpenVPN 2.6/2.7 and openfortivpn with example hosts and
  documentation addresses, and rtnetlink messages for the tables; they run on the Mac and in the
  Linux jobs, which also read the container's own tables.
- **Combine.** Linux has none. A small stand-in in Core (`ObservableObject`, `@Published` with
  `sink`/`compactMap`, `PassthroughSubject`, `AnyCancellable`), compiled only where Combine is
  missing; the Mac keeps Combine and macOS 13.
- **MCP input.** JSON-RPC parameters are decoded into a small `JSONValue` enum on every platform
  instead of telling booleans from numbers with CoreFoundation (`MCPTools.isBool`); the MCP fuzzer
  covers the new decoder.
- **Version.** Compiled in from a file the build script generates (`BuildVersion+Generated.swift`
  with `-DPASSTUNNEL_BUILD_VERSION`, like `PinnedTools+Generated.swift`, never committed); development
  builds report `0.0.0-dev`. `AppInfo` reads it on Linux instead of `Info.plist`.
- **Language.** English: the `String(localized:)` stand-in of PassTunnelKit is used by Core and the
  CLI on Linux. Turkish follows by turning `Localizable.xcstrings` into a lookup table at build time.
- **Commands that differ.** `helper install`/`uninstall` explain that the package installs and
  removes the daemon, and fail with `invalid_argument`. `code --copy` uses `wl-copy` (Wayland) or
  `xclip` (X11) when present and fails with `invalid_argument` otherwise. As on the Mac, the code is
  cleared after `clear_clipboard_after` in `config.json` (30, 60 or 120 s, default 60) if PassTunnel
  still owns the clipboard: a process left behind runs the tool in the foreground, where it serves
  the clipboard until another program takes it, and stops it only if it still does.
- **Not used on Linux:** the Mac's file watcher, login item, helper installer and auto-update, QR
  decoding, reading TLS certificates (the fingerprint formats are shared) and distributed
  notifications (all app-side or macOS-only).

## Secrets

The same accounts (`<id>/password`, `<id>/totp`, `<id>/sekey`) and values (plain, `ptpl1:…` or
`ptse1:…`, byte for byte) as the Keychain items, behind the `SecretStore` protocol (the Keychain is
the Mac's implementation; the Linux tests use an in-memory store, which exists in debug builds only,
and fakes for the system tools; the Mac's tests a Keychain service of their own):

| Store | Where | Used by default when |
|---|---|---|
| `secret-service` | The desktop keyring (GNOME Keyring, KDE Wallet, KeePassXC) through `secret-tool` (libsecret's command-line tool): attributes `service=PassTunnel`, `account=<id>/<kind>`, label `PassTunnel (<id>/<kind>)`, values over stdin/stdout as they are, never in arguments or the environment | A user (not root) whose session bus answers (the default on desktops; the design names it in the import review) |
| `systemd-creds` | `~/.local/share/passtunnel/secrets/<account>.cred` (folder 0700, files 0600), sealed with `systemd-creds encrypt/decrypt` (host key and TPM2): the system's scope for root, `--user` for other users (systemd 256 or later) | root; other users without a Secret Service, when their systemd is new enough |
| `file` | `~/.local/share/passtunnel/secrets.enc` (0600): scrypt from swift-crypto (N = 2^17, r = 8, p = 1) and AES-256-GCM; passphrase from `PASSTUNNEL_PASSPHRASE_FILE` or the terminal | The fallback |

- **Choosing.** The setting `secret_store` in config.json (`auto`, the default, or a store's name;
  `passtunnel secret-store [STORE]` shows and sets it) or `PASSTUNNEL_SECRET_STORE`, which overrides
  it (`memory`, the tests' store, only in debug builds; release builds refuse it as unknown). `auto`
  uses the store recorded in config.json (`secret_store_used`): the store of the first secret saved,
  or the one last named in `passtunnel secret-store`. With nothing recorded it takes, for root,
  systemd-creds if available, else the file; for other users secret-service, then systemd-creds,
  then the file. So a profile set up in a desktop session is still looked for in the keyring over
  SSH, which then says it cannot reach it rather than reporting the secret missing. Secrets are
  never moved between stores: after changing the store, save them again with `passtunnel secret`.
  `diagnose` (`secret_store`) and `passtunnel secret-store` name the store, how it was chosen and
  whether it can be used from that process.
- **Errors.** Any store failure is `keychain_error` (`SecretStoreUnavailable`) with the store's own
  message: no `secret-tool` or `systemd-creds`, no session bus, a locked keyring that did not answer,
  systemd older than 256 for `--user`, no passphrase, a file that does not decrypt.
- **secret-service.** `secret-tool` is taken from `/usr/bin`, `/bin` or `/usr/local/bin`, never
  `PATH`, and gets only `DBUS_SESSION_BUS_ADDRESS` (or `unix:path=$XDG_RUNTIME_DIR/bus` when that
  socket exists), `XDG_RUNTIME_DIR`, `HOME` and `LANG=C`. It stores what it reads on standard input
  unchanged (UTF-8 text up to 8 KiB; longer values are refused before it runs) and `lookup` writes it
  back unchanged when its output is not a terminal, so values need no encoding; `lookup` and `clear`
  exit 1 without a message when nothing matches. Available when a lookup of an account no item has
  answers found or not found within 5 s. A locked keyring asks for its password on the desktop:
  commands on a terminal wait up to 120 s for it, everything else (MCP, `--no-input`, scripts) 15 s,
  then fail. Unlike the Keychain, a Secret Service gives no per-application protection: any process
  of the user can read an unlocked keyring.
- **systemd-creds.** File and credential name are the account with every byte outside `a-z0-9-_` as
  `%XX` (`acme%2Fpassword.cred`); `--name` seals the name in, so a renamed file does not decrypt.
  Values go over standard input and output (`encrypt|decrypt --name=… [--user] - -`, `--newline=no`),
  the result is written atomically. The version comes from `systemd-creds --version`; 30 s timeout.
- **file.** `"PTSF"`, version 1, KDF 1 (scrypt), log2 N, r, p, a 32-byte salt and a 12-byte nonce (53
  bytes, all of it the AES-GCM additional data), then the ciphertext of the JSON object account →
  value (Base64) and the 16-byte tag. The salt and parameters are fixed when the file is made (files
  name at most 1 GiB of scrypt memory), the nonce is new on every write; writes are atomic and
  serialized with `flock` on `.secrets.lock` (10 s, then an error). The passphrase comes from
  `PASSTUNNEL_PASSPHRASE_FILE` (a regular file of the user that group and others cannot access, final
  line breaks dropped), else from a no-echo prompt when the CLI runs on a terminal without
  `--no-input` (twice for a new file; three tries for a wrong one); otherwise the command fails at
  once. A process derives the key once and keeps it (a failed passphrase is not tried again); the
  passphrase and the decrypted items are overwritten after use, as far as Swift allows. Commands
  that touch a profile's secrets ask, including `add` and `import`, which clear what an earlier
  profile with the same id left behind. Wrong passphrase and a changed file give the same error.
- **Protected profiles** (`require_auth`): refused with `auth_unavailable` until Phase 3. Then
  `connect` asks for the user's password through polkit before the daemon starts the session (the
  design's "Ask for my password before connecting", the desktop's own authentication dialog). That is
  a check the root daemon enforces, not encryption, and the setting is worded so; showing and copying
  codes are not protected by it. A key that releases secrets only on a security-key touch (FIDO2) or
  a TPM PIN can come later.

## Distribution

- **Phase 2:** a release tarball (`passtunnel`, `passtunneld`, the unit files, a README) per
  architecture, and a `Dockerfile` at the repository root that builds the CLI and runs
  `passtunnel mcp` (what MCP directories build and introspect; inside a container it can only manage
  a VPN of that container).
- **Phase 3:** `.deb` and `.rpm` built with nfpm, holding the binaries, `passtunnel.service` and
  `passtunnel.socket`, the polkit policy and the `passtunnel` group; a signed apt and dnf repository
  on GitHub Pages; updates through the package manager (the daemon is restarted only when no session
  is active). Release assets get the same checksums and provenance attestations as the Mac's, plus an
  SBOM.
- Built once per architecture in the oldest supported Ubuntu container with the Swift standard
  library linked statically (`--static-swift-stdlib`); the Static Linux SDK (musl) only for the
  tarball's CLI if it proves useful.

## Phases

1. **Done (#64, #66):** PassTunnelKit builds and its tests, the golden fixtures included, run on Linux
   in CI on both architectures.
2. **CLI and MCP on Linux**
   - 2a (#70): Core, Shared (the parts Core uses) and the CLI build on Linux: the CLI is the library
     `PassTunnelCLI`, which the Mac app runs in CLI mode and the Linux-only `passtunnel` executable
     wraps. The seams above are in place (Combine stand-in, `SecretStore`, `JSONValue`, compiled-in
     version, Glibc and ping differences) with placeholders for the later steps: no secret store,
     the daemon reported as not installed, no routes, protected profiles refused. The portable Core
     tests run in the Linux CI jobs, which also try the binary (`--version`, `list --json`, an MCP
     session); `passtunnel` lists, shows, adds and imports profiles and serves MCP.
   - 2b (#78): the secret stores (secret-service, systemd-creds, file), chosen and recorded as above,
     `passtunnel secret-store`, and the store in `diagnose`.
   - 2c: `passtunneld` with group-based access, the DNS hook, Linux routes and log parsing: connect
     and disconnect work.
     - Part 1 (#79): the daemon (`PassTunnelDaemon`, wrapped by the executable `passtunneld`) with
       the protocol, access, profile and tool checks, OpenVPN start, supervision and stop without
       touching DNS, the cleanup of a previous instance; `UnixSocketHelperClient` and the Linux
       `SystemHelperInspector`; the unit files in `packaging/linux/`. The Linux CI jobs start the
       daemon as root in the container and run an OpenVPN session against it (no tunnel).
     - Part 2: the DNS hook, FortiGate (openfortivpn and pppd), Linux routes and log parsing. Done so
       far (#90): `passtunneld dns-hook` for OpenVPN 2.6 and 2.7, with the systemd-resolved,
       resolvconf and file backends (`DNSApplier`, which FortiGate reuses), recorded in the session
       directory and reverted by the hook, the daemon or the next daemon; the unit's writable paths
       for it. The Linux CI jobs run the hook as root on the container's resolv.conf (set and
       reverted in both forms, the refusals, the revert by a starting daemon).
   - 2d: the release tarball and the `Dockerfile`.
3. **Packages:** polkit, systemd units, nfpm packages, the apt/dnf repository, release automation
   (with it, how commits with the scope `linux` count: until then they are left out of the app's
   releases, see [RELEASING.md](RELEASING.md#how-a-release-happens)), install tests on the target
   distributions.
4. **Desktop app:** from the new design: main window with live codes, profile editor, import review,
   tray where the desktop has one (KDE, Ubuntu) and background app with notifications on stock
   GNOME, the polkit prompt for protected profiles.

FortiGate IPsec/IKEv2 is out of scope: its one-time-code prompts use extensions only FortiClient
implements. OpenConnect is a possible later backend (#2).

## Rules

The rules of this repository apply unchanged (no company or customer names or real hostnames, no
secrets in logs, signed commits, the issue → branch → pull request flow). In addition:

- Linux code lives in the same targets behind `#if os(Linux)` / `#if canImport(…)`, or in Linux-only
  targets (`passtunneld`); the Mac's behavior and binaries do not change.
- Tests never touch a real keyring, credential store or `/run/passtunnel`, and never start a tunnel:
  they set `PASSTUNNEL_HOME`, use the in-memory secret store (on the Mac a test Keychain service),
  fakes for `secret-tool` and `systemd-creds`, and inject the daemon's paths and uids, as
  `HelperCore` already allows. The one exception is marked as such: a CI step of the Linux jobs runs
  one real Secret Service round trip (`RealSecretServiceTests`, only with
  `PASSTUNNEL_TEST_SECRET_SERVICE=1`) against a throwaway keyring on a throwaway session bus inside
  the job's container.
- Every Linux change keeps the `Linux (x86_64)` and `Linux (aarch64)` checks green; they run all tests
  that build on Linux.
