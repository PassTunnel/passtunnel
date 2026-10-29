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
| Later | A desktop app with tray, notifications and live codes, built from the macOS app's design for macOS, Windows and Linux; a password prompt for protected profiles |
| VPN types | OpenVPN, FortiGate SSL VPN and Cisco AnyConnect, with the distribution's `openvpn` (2.6 or later), `openfortivpn` (1.21 or later) and `openconnect` (9.01 or later; not Ubuntu 22.04's 8.20) |
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
                           openvpn / openfortivpn (+ pppd) / openconnect, from the distribution
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
| Run root | `/run/passtunnel/` (0711, root): `<uid>/<id>/` per session as on the Mac (`config.ovpn`, `openfortivpn.conf` or `openconnect.conf`, `auth`, `state`, `mgmt.sock`; for DNS the `dns-hook` link and the record `dns`; for Cisco AnyConnect the `vpn-hook` link, `policy`, the hook's record `network` and its marks `hook` and `stopping`), `daemon.lock` (one daemon per run root), `network.lock` (openconnect's hooks and the daemon's reverts, one at a time) and, while a tunnel's DNS is in `/etc/resolv.conf` itself or something there is left to restore, `resolv.conf.base` (below) |
| Daemon socket | `/run/passtunnel/daemon.sock` (0666, root; access is decided per request, below) |
| Binaries | `/usr/bin/passtunnel`, `/usr/sbin/passtunneld` from the packages; `/usr/local/…` from the tarball |

`PT.profilesSubpath`, `PT.helperRunRoot`, the `sun_path` limit (108 bytes on Linux) and the CA bundle
become platform values. The CA bundle is the first of `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem` that exists (`FortiConfig` takes it as a
parameter), resolved and checked as the tools are (below).

## The daemon protocol

One request per connection, one JSON object per line, at most 64 KiB:

- `{"op":"hello"}` → `{"protocol":4,"build":"<hex SHA-256 of passtunneld>","build_number":N}`. The
  client's `ensureCompatible()` uses it as the `version` and `build` XPC calls are used on the Mac.
  The daemon hashes `/proc/self/exe` once at start. `build_number` (and `helper_build` in every
  reply) is the build number a release build compiles in (`DaemonBuild`, see Distribution);
  development builds have none and leave both out.
- `{"op":"perform","request":<HelperRequest>}` → `<HelperResponse>`. Request decoding is
  `HelperCore.decodeRequest`, unchanged, and so are the request types and `PT.helperProtocolVersion`
  (`startOpenConnect` since #187, below; the `status` reply's `tunnels` for the caller's own Cisco
  AnyConnect sessions).
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
  `/usr/bin/openfortivpn`; `/usr/sbin/pppd` (checked, run by openfortivpn); `/usr/sbin/openconnect`,
  `/usr/bin/openconnect`; for openconnect's hook `ip` (below). Each is resolved with
  `realpath` once, then every component of the real path must be root-owned and not group- or
  world-writable, and the file a regular file. Nothing is pinned by hash: distribution binaries
  change with every security update, so trust rests on the package manager. Versions below
  openvpn 2.6.0, openfortivpn 1.21, pppd 2.4.7 or openconnect 9.01 are refused with a clear message.
  The checks run before every start; the version is read by running the checked file (`openvpn
  --version`, `openfortivpn --version`, `pppd --version`, `openconnect --version`, killed after 5 s).
  The logic is shared with `passtunnel` (`DistributionTools`, `ToolSpec`, `TrustedPath` in
  PassTunnelShared), which checks openconnect the same way before Cisco AnyConnect's sign-in. pppd is run by openfortivpn from
  the path compiled into it, `/usr/sbin/pppd`, so it is checked before every FortiGate start too.
- **The daemon itself** refuses to start unless its own executable (`/proc/self/exe`, resolved) passes
  the same path checks, since OpenVPN runs it as root for DNS (below).
- **Spawning.** `posix_spawn` of the checked path (no suspended start: there is no signature to
  verify), new process group, stdin `/dev/null`, output to the session log, every other descriptor
  closed (`posix_spawn_file_actions_addclosefrom_np`), default signals and an empty mask, a fixed
  environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`; openconnect also
  `P11_KIT_NO_USER_CONFIG=1`, `HelperCore.environment(for:)`). Unlike the Mac, `OPENSSL_CONF` and
  the CA variables are **not** overridden: the distribution's OpenSSL configuration (for example
  system-wide crypto policies) applies.
- **OpenVPN** runs with the Mac's fixed flags (`--pull-filter ignore` for a pushed `verb` and
  `--server-poll-timeout 10` before the config, `--management <run>/mgmt.sock unix`,
  `--management-client-user`, `--auth-nocache`, `--remap-usr1 SIGTERM`, `--connect-retry-max 3`,
  `--tls-version-min 1.2`, capped `--verb`; the same `HelperCore.openVPNArguments`), the sanitized config (`OVPNSanitizer`,
  unchanged: it also refuses a config that would wait for incoming connections, `proto tcp-server` or
  no `remote` at all, with the Mac's words) and `--script-security 2` with
  the DNS hook below, the only script it can run (the sanitizer removes every other). The management
  socket goes to the caller as on the Mac, its mode set before its owner (no `CAP_FOWNER` needed).
- **Device names.** OpenVPN on Linux attaches to an existing device of the name `dev` gives
  (`TUNSETIFF`; with data channel offload it takes over an existing one too), and a persistent tun or
  tap device created earlier for another user (`ip tuntap add … user bob`) stays open to that user,
  who could then read and write the tunnel's packets. So before every start the daemon refuses a
  config whose `dev` names a device the kernel has already (`HelperCore.interfaceExists`,
  `if_nametoindex`; any answer but "no such device" refuses too): "The network device tun5 already
  exists, …". `dev tun` and `dev tap` are never checked, since the kernel (or OpenVPN, with data
  channel offload) then picks a name no device has, and a numbered or named device that is free
  starts as before. Every `dev` line counts, not only the last, each cut to 15 bytes as OpenVPN cuts
  it (`HelperCore.namedDevices`). Between the check and OpenVPN's open nobody else can create the
  device: that takes `CAP_NET_ADMIN` in the host's network namespace. The Mac has no persistent
  devices and does not check.
- **FortiGate** runs openfortivpn as the Mac's helper does: `openfortivpn -c <run>/openfortivpn.conf`
  and nothing else on its command line, the config written by `FortiConfig.render` (typed fields
  only, `checkRendered` as on the Mac) into the session's run directory (0600, root), with the
  password and the one-time code in it, never in an argument or the environment. On Linux the config
  names the distribution's CA bundle (`ca-file`, checked) and keeps the profile's `set-routes`, but
  `set-dns` and `pppd-use-peerdns` are always 0, so neither openfortivpn nor pppd (nor the
  distribution's ppp scripts) touch resolv.conf; the daemon applies DNS (below). Profile directory,
  supervision, stop and the cleanup of a previous instance are those of OpenVPN; there is no
  management socket. openfortivpn's standard output and error (and pppd's, which it passes on) go to
  a pipe only the daemon reads, not to the log: a thread per session (`OutputCopier`) copies every
  byte into the session log as it comes, so the log reads as before and `HelperCore.capLog` trims it
  the same way, and hands each line (at most 4 KiB; a longer one is copied but not read) to the
  supervisor. The daemon's own lines in the log start with `passtunneld: ` and never break into one
  of the tool's. pppd runs in a session of its own on openfortivpn's pseudo-terminal: openfortivpn
  stops it on its way out, and if openfortivpn is killed, pppd ends when the terminal goes.
- **Supervision.** One waiter per child (a thread in `waitid(WNOWAIT)`, so the child is reaped only
  on the supervisor's queue and its pid cannot be reused while it is listed); `stop` sends SIGTERM,
  then SIGKILL after 5 s; at most `SessionPolicy.maxSessionsPerUser` sessions per user; the session
  log is capped with `HelperCore.capLog`. On exit what the session recorded is reverted (when its
  hook did not: a Cisco AnyConnect session's network, then the DNS; `SessionRestore`) and the run
  directory removed.
  There is no adoption: a starting daemon stops tools recorded by a previous instance, reverts the
  DNS their sessions recorded and cleans up (under systemd `KillMode=control-group` has already
  stopped them). The session's `state` records, besides pid, owner and executable, the boot
  (`/proc/sys/kernel/random/boot_id`) and the tool's start time (field 22 of `/proc/<pid>/stat`, read
  before the child is reaped). A recorded pid is signalled only while it provably is that process:
  the same boot, start time and executable (`/proc/<pid>/exe`), checked again right before every
  signal (SIGTERM, and SIGKILL after the grace period). Signals go only through a pidfd
  (`pidfd_open`, `pidfd_send_signal`, called through glibc's `syscall`, since glibc before 2.36 has
  no wrappers), opened before the check, so they cannot reach a process that took the pid over in
  between; nothing is ever signalled by number. Its process group goes through the pidfd too on
  Linux 6.9 (`PIDFD_SIGNAL_PROCESS_GROUP`); before that only the tool itself is signalled (what is
  left in its group are short-lived children, and under systemd the control group is stopped
  anyway). Without pidfds (Linux before 5.3) nothing is signalled: the tool is left running and
  logged, its DNS still reverted. So is a `state` without boot and start time (from a development
  build before they were recorded), which cannot prove the process is the tool, since a stray tool
  left running is better than a signal to an unrelated process.
  A session whose DNS cannot be restored yet (the lock is held, the file cannot be read or written)
  is not removed: its directory keeps the `dns` record and nothing else (the config and auth file
  go), the run root keeps `resolv.conf.base`, the profile cannot start again over it ("not restored
  yet"), and the daemon tries again every 15 s until it is restored; a starting daemon does the same
  with what an earlier one left. Only what is restored, or no longer needed, is swept away.
- **Sandbox** (`packaging/linux/passtunnel.service`, a first version, installed from the release
  tarball):
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

Profiles never run scripts (the sanitizer refuses them, and an import leaves them out); DNS comes from
what the server pushes, and every value of it is treated as hostile: it ends up in the hands of root.

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
  session's tool (its pid, in the same boot, with the recorded start time and executable); anything
  else is refused. It acts on the interface OpenVPN names (`dev`: 1 to 15 letters, digits, `_`, `-`
  and `.`, not digits only, which tools read as an interface index; and it must exist) and notes its
  index, so that a revert never reaches another interface of that name.
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
  machine (the run root is locked with `flock`, by the hook and the daemon alike), in this order of
  preference:
  - systemd-resolved, when `/etc/resolv.conf` is a link into `/run/systemd/resolve/` (or to its
    static `resolv.conf`): `resolvectl dns`, `domain` (the search domains, `~domain` for routing-only
    ones, and `~.` when every name goes through the tunnel) and `default-route` (yes only then) for
    the link. The link is always given by its recorded index, never its name, and right before each
    call the index must still name the interface and no interface may be named like the index
    (`resolvectl` reads a number as an index, but systemd 256 and later first look it up as an
    interface name or alternative name, which `if_nametoindex` finds as well);
    otherwise nothing runs and the set-up fails. Indexes are not reused soon (the kernel counts up),
    so a link that passes is the session's own. `resolvectl revert <index>` undoes it, after the same
    check, while the link (with that index) exists; once it is gone, systemd-resolved has dropped its
    settings. Each tunnel's settings belong to its own link, so sessions that overlap never touch
    each other's.
  - else `resolvconf` (Debian's or openresolv, not systemd's stand-in, which is resolvectl):
    `resolvconf -a <dev>.passtunnel-<index>` with up to three `nameserver` lines and a `search` line
    on standard input, `-d` to revert. resolvconf keeps a record per name and merges them itself, so
    overlapping sessions are separate; the index in the name keeps a session that ends late (a
    crashed tool's reap) from removing the record of a later link that got the same interface name.
    Debian's writes `/run/resolvconf/resolv.conf` (renamed into place), openresolv `/etc/resolv.conf`
    in place; openresolv set to rename a file over it instead (`resolv_conf_mv` in
    `/etc/resolvconf.conf`) is refused where `/etc` is read-only (inside the unit), before it runs.
  - else `/etc/resolv.conf` itself when it is a regular file of root (a link anywhere else is never
    followed, and fails the set-up): a block at the top (`# PassTunnel <dev> begin: …` to
    `# PassTunnel <dev> end`) with up to three servers and the search domains, and the file's own
    `nameserver` lines (and `search` and `domain`, when the tunnel brings domains) disabled with the
    mark `#PassTunnel <dev># `. A resolv.conf cannot route names, so every name goes through the
    tunnel here. The file is never patched on top of an earlier tunnel's: PassTunnel keeps one
    baseline (the file without PassTunnel, in `<run root>/resolv.conf.base` with a digest of what it
    wrote last) and a registry of the sessions whose DNS is in the file (their `dns` records, below,
    each with its servers, search domains and an order of application), and every change, under the
    lock, makes the file again from them: the baseline with the newest session's block (several
    tunnels at once: the newest one's DNS is in effect, an older one's comes back when it ends), or
    with none the baseline itself. So a tunnel that ends while another is up never brings the file's
    own servers back. The baseline is the recorded one while the file is still what PassTunnel
    wrote; changed by someone else meanwhile, it is the file without any PassTunnel block or mark
    (their change stays); a file without them that no session needs any more is left alone. A
    result larger than PassTunnel reads back (64 KiB) is refused before anything changes, so every
    file it writes is one it can restore. Written atomically where it can be: a new file next to it
    (a name of the writer's own), synced, renamed over it. Inside the unit (`/etc` read-only, the
    file a bind mount) and where a container runtime bind-mounts it (rename fails with `EBUSY`) it
    is rewritten in place instead: the whole content in one write from the start, cut to its
    length, synced. Every write is journalled first: `resolv.conf.base` notes the file before and
    after the change, and a writer that dies in the middle (between the write and the cut, say)
    leaves a change the next one finishes (any change, the daemon's retries, a starting daemon),
    recognised as the start of the new content over the rest of the old one; anything else counts
    as someone else's edit. Right before it writes, PassTunnel checks that the file is still the one
    it read (the same inode and content); replaced or changed in between by another writer, it is
    read again and the change worked out anew, three times in all, then the change fails and their
    file stays. Only a writer that changes it in the instant between that check and the write goes
    unseen: PassTunnel's lock cannot hold back writers outside it. A file that lost its name
    (replaced after the unit started) fails the set-up.
  - The tools run only from fixed paths (`/usr/bin/resolvectl`, `/bin/resolvectl`;
    `/usr/sbin/resolvconf`, `/sbin/resolvconf`), checked as the VPN tools are (`TrustedPath`), with
    the fixed environment and argument lists of `Sys.spawn` (never a shell), 10 s each.
- **Recorded and reverted.** Before it changes anything, the hook records in the session directory
  what it is about to change (`dns`: the backend, the interface and its index, and for
  `/etc/resolv.conf` the servers and search domains of its block; root's, 0600). A failed
  set-up reverts what it did, removes the record and prints "setting DNS failed: …" to the session
  log, which the client turns into `PTError.setupFailed`, as on the Mac. OpenVPN goes on after it on
  2.6 (`--route-up`; a failed `--up` would end OpenVPN with a fatal error, which the client reports
  as `connectFailed` before it looks for a failed set-up) and on 2.7 (`--dns-updown`). The hook
  reverts when OpenVPN takes the tunnel down; the daemon reverts whatever is still recorded when it
  reaps the tool (killed, crashed, or the daemon stopping), and a starting daemon what the sessions
  of a previous instance recorded; with the record the session leaves the registry. Nothing of it
  changes without the run root's lock: a revert that cannot take it within 10 s, or that fails,
  keeps the record (and the session in the registry) for the next try (above). A failed set-up on
  the file backend drops its record even so: the journal has what is left to finish. The daemon
  also gives back a baseline no session claims any more (an instance that died between the steps
  of a revert), and finishes a change left under way.
- **FortiGate**, when the profile has `set_dns` (otherwise DNS is left alone): the daemon sets it
  itself, from openfortivpn's own output as its pipe delivers it (above), never from the log file,
  which belongs to the session's user, who could write any line into it. openfortivpn 1.21 prints,
  at its default verbosity, `INFO:   Got addresses: [<local>], ns [<server>, <server>], ns_suffix
  [<domains>]` (servers from the gateway's configuration, `0.0.0.0` for none; `ns_suffix`, the search
  domains separated by `;`, only when the gateway names any), `INFO:   Interface pppN is UP.` and
  `INFO:   Tunnel is up and running.`; pppd prints `Using interface pppN`. Only whole lines that start
  with exactly these words count (`FortiOutput`), in any order (`FortiDNSWatch`): once the tunnel is
  up and the addresses and the interface are known, the set-up runs, once per session; if they are
  not all known 10 s after the tunnel came up, or pppd and openfortivpn name different interfaces,
  it fails.
  - The values are checked as the hook checks OpenVPN's (`DNSSettings`: one bad value fails the
    set-up). No server: "passtunneld: the gateway named no DNS servers; DNS is left as it is". Every
    name goes through the tunnel (`fullTunnel`), as with openfortivpn's own `set-dns` on the Mac.
  - The interface must be the session's, which the kernel confirms (`SessionInterface`) before
    anything changes: named `pppN`, there now, a ppp device (`ARPHRD_PPP` in
    `/sys/class/net/<name>/type`), created after the session started (a higher index than any
    interface had when the daemon started openfortivpn) and carrying the address openfortivpn got for
    the session (`getifaddrs`), which is how openfortivpn itself finds it. A line that a gateway got
    into the output therefore cannot point the DNS at another interface.
  - Applied with `DNSApplier.apply(_:interface:in:)` on a queue of its own (it runs tools and waits for
    the run root's lock), recorded in the session directory as the hook's are, and reverted when the
    tool exits (stopped, killed or crashed), when the daemon stops, and by a starting daemon
    (`PreviousInstance`); the end of a session waits for a set-up that is still running, then
    reverts it. The result goes into the session log: "passtunneld: DNS of ppp0 set through …", or
    "passtunneld: setting DNS failed: …", after which the daemon ends the session. The client
    reports that line as `PTError.setupFailed` (`setup_failed`), as on the Mac, and on Linux counts a
    FortiGate profile with `set_dns` as connected only once one of these lines is there
    (`ConnectionManager.fortiIsConnected`).

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
- **Overlap warnings.** The routes of a FortiGate tunnel for the check "two tunnels claim the same routes or
  DNS names" (ARCHITECTURE.md) come from the same rtnetlink dumps (`RoutingTable.routes(onInterface:)`: the
  main table's unicast routes, IPv4 and IPv6, through the link named like the tunnel interface); OpenVPN's
  come from the push in its log, which 2.6 and 2.7 write at `--verb 3` as on the Mac. The comparison itself
  (`NetworkClaims`, Kit) is the same code.
- **Network path.** Whether the computer is online (`NetworkPath`, `diagnose`'s `network`) comes from
  the same rtnetlink dumps: online when a route that carries all traffic goes through a link whose
  `/sys/class/net/<link>/operstate` is `up` (or `unknown`, as tun devices report it); the interface is
  that of the first such link that is not a tunnel, `wifi` when it has `wireless` or `phy80211` there,
  `ethernet` for link type 1, else `other`. Nothing is contacted. Watching (the app's retries of an
  unreachable server) reads it again every 5 s.
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
- **MCP texts.** The server's instructions and the tool descriptions say "this computer" instead of
  "this Mac" and, instead of the Touch ID prompt, that a protected profile cannot be connected on
  Linux yet (`auth_unavailable`, see Secrets). The Mac's texts are unchanged (`MCPWording`).
- **MCP input.** JSON-RPC parameters are decoded into a small `JSONValue` enum on every platform
  instead of telling booleans from numbers with CoreFoundation (`MCPTools.isBool`); the MCP fuzzer
  covers the new decoder.
- **Version.** Compiled in from a file the build script generates (`BuildVersion+Generated.swift`
  with `-DPASSTUNNEL_BUILD_VERSION`, like `PinnedTools+Generated.swift`, never committed; see
  Distribution); development builds report `0.0.0-dev` and no build number. `AppInfo` reads it on
  Linux instead of `Info.plist`.
- **Language.** English: the `String(localized:)` stand-in of PassTunnelKit is used by Core and the
  CLI on Linux. Turkish follows by turning `Localizable.xcstrings` into a lookup table at build time.
- **Commands that differ.** `helper install`/`uninstall` explain that the daemon is installed and
  removed by hand from the release tarball (its README; the package comes with Phase 3), and fail
  with `invalid_argument`. `--no-auth-prompt` is worded as never asking for a confirmation. `code --copy` uses `wl-copy` (Wayland) or
  `xclip` (X11) when present and fails with `invalid_argument` otherwise. As on the Mac, the code is
  cleared after `clear_clipboard_after` in `config.json` (30, 60 or 120 s, default 60) if PassTunnel
  still owns the clipboard: a process left behind runs the tool in the foreground, where it serves
  the clipboard until another program takes it, and stops it only if it still does.
- **Clock check.** After a FortiGate rejects a sign-in, the Mac asks the gateway for its time
  (`ServerClock.gateway`, APP.md). Linux does not: Foundation's networking there cannot accept a
  certificate by its SHA-256 the way openfortivpn's `trusted-cert` does, so the check would not trust
  the gateway exactly as the VPN does; `ServerClock.gateway` fails with `unavailable` and the failure
  has no `clock`. `diagnose --check-clock` (MCP `check_clock`) works: the same SNTP client asks the NTP
  server the system is set up with, read from systemd-timesyncd's `NTP=` (`/etc/systemd/timesyncd.conf`
  and its `.conf.d` drop-ins; else `FallbackNTP=`), else the first `server` or `pool` of chrony
  (`/etc/chrony/chrony.conf`, `/etc/chrony.conf`) or ntpd (`/etc/ntpsec/ntp.conf`, `/etc/ntp.conf`).
  Servers a service has built in or learned from DHCP are not known; with none in the files the check
  reports `clock_error` ("No time server is set up on this system."). Never `time.apple.com` here.
- **Not used on Linux:** the Mac's file watcher, login item, helper installer and auto-update, QR
  decoding, reading TLS certificates (the fingerprint formats are shared), the gateway clock check
  (above) and distributed notifications (all app-side or macOS-only).

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

- **Phase 2:** a release tarball per architecture, and a `Dockerfile` at the repository root.
  - `scripts/build-linux.sh [--version VERSION] [--build-number N]` builds
    `dist/passtunnel-<version>-linux-<arch>.tar.gz` for the architecture it runs on, in the Swift
    image of Ubuntu 22.04 (`swift:6.4.1-jammy`), the oldest supported, so that the binaries run on
    every later glibc (they need 2.35: Ubuntu 22.04, Debian 12 and later, RHEL 10, not RHEL 9's
    2.34): `passtunnel` and `passtunneld` in release mode with the Swift standard library,
    Foundation and swift-crypto linked statically (from the system they load only glibc, libstdc++
    and libgcc_s), debug information stripped. glibc's `posix_spawn_file_actions_addchdir_np` and
    `…_addclosefrom_np`, which Ubuntu 22.04's headers hide from Swift, are looked up by name.
  - The tarball holds `bin/passtunnel`, `sbin/passtunneld`, `lib/systemd/system/passtunnel.socket`
    and `passtunnel.service` (its `ExecStart` set to `/usr/local/sbin/passtunneld`), `README.md`
    (`packaging/linux/README.md`: requirements, install, update, uninstall), `LICENSE`,
    `THIRD_PARTY_NOTICES.md` (`packaging/linux/THIRD_PARTY_NOTICES.md` with the versions of the build
    added) and `licenses/`: the Swift project's license (standard library, Dispatch, Foundation),
    ICU's, and swift-crypto's and swift-asn1's from the pinned checkouts. Its files are root's and
    dated by the commit. Installed as the README says: `/usr/local/bin/passtunnel`,
    `/usr/local/sbin/passtunneld` (where `HelperBuild.installedDaemon` looks for it), the units in
    `/usr/local/lib/systemd/system/`, the group `passtunnel`, and `passtunnel.socket` enabled.
  - The version is `--version` (what the release scripts compute, once Linux is released;
    `0.0.0-dev` without it). The build number is the commit count, as the Mac's `CFBundleVersion`:
    the same for both binaries and both architectures, growing with every commit on `main`; a
    shallow clone needs `--build-number`. Both are compiled in through files written for the build
    and removed afterwards: `BuildVersion+Generated.swift` (`passtunnel --version`) and
    `DaemonBuild+Generated.swift` (the daemon's `build_number` and `helper_build`). The client
    compares daemons by digest only (above), so development builds, which have no number, compare as
    before; the number tells builds apart in logs and reports.
  - CI (the jobs `Linux release` in `.github/workflows/ci.yml`) builds the tarball once per
    architecture and keeps it as a workflow artifact, then installs it in a clean Ubuntu 22.04
    container: the binaries load no Swift library from the system and report the version and build
    number, `passtunneld` refuses to run as another user than root and, as root, answers `hello` and
    requests with the build number, and `passtunnel` finds it beside itself and reports a replaced
    file as outdated. Attaching tarballs to releases waits for phase 3, and so does a Linux section
    in the README: until then there is nothing to download but the CI artifact.
  - The tarball is repeatable: the same commit, version and build number, built in the same
    container with the checkout at `/src`, give the same bytes (it is built without debug
    information, see `build-linux.sh`). The workflow `Repeatable build` checks it on x86_64; see
    [RELEASING.md](RELEASING.md#verifying-a-release).
  - The `Dockerfile` builds `passtunnel` in release mode on the CI's Swift image (`swift:6.4.1-noble`)
    and runs `passtunnel mcp` on `ubuntu:24.04` as the user `mcp` (uid 10001), both images pinned by
    digest: what MCP directories build and introspect. It starts without a profile store or a secret
    store and answers `initialize` and `tools/list`. Inside a container it can only manage a VPN of
    that container (none without a `passtunneld` there), never the host's. It is a development
    build (`0.0.0-dev`). The jobs `Docker image` build it on both architectures and run an MCP
    session with it, without a network.
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
       reverted in both forms, the refusals, the revert by a starting daemon). Linux routes and log
       parsing (#91). FortiGate (#92): openfortivpn and pppd checked and run as above, its output
       copied from a pipe, and its DNS set from that output for the session's ppp interface; the
       Linux CI jobs start a FortiGate session against the daemon with the distribution's
       openfortivpn and follow its DNS with a stand-in (no tunnel).
   - 2d (#119): the release tarball (`scripts/build-linux.sh`) and the `Dockerfile`, built and tried
     in CI (see Distribution).
3. **Packages:** polkit, systemd units, nfpm packages, the apt/dnf repository, release automation
   (with it, how commits with the scope `linux` count: until then they are left out of the app's
   releases, see [RELEASING.md](RELEASING.md#how-a-release-happens)), install tests on the target
   distributions.
4. **Desktop app:** from the new design: main window with live codes, profile editor, import review,
   tray where the desktop has one (KDE, Ubuntu) and background app with notifications on stock
   GNOME, the polkit prompt for protected profiles.

FortiGate IPsec/IKEv2 is out of scope: its one-time-code prompts use extensions only FortiClient
implements. Cisco AnyConnect through OpenConnect (#2, Phase 1) runs on Linux since #187: see
[Cisco AnyConnect](#cisco-anyconnect) below.

## Cisco AnyConnect

**In place since #187** (scope `linux`, so it stays out of app releases); tested against a real server
in #188. The design is in [ARCHITECTURE.md](ARCHITECTURE.md#cisco-anyconnect-backend-planned) (split
sign-in, the rendered `openconnect.conf` and its refused options, trust, the `vpn-hook`, the log); this is
what differs on Linux. The CLI and MCP offer the type with #185; until then Core connects such a profile
when asked.

- **The tool.** The distribution's `openconnect`, never bundled: `ToolSpec.openconnect` with the
  candidates `/usr/sbin/openconnect`, `/usr/bin/openconnect`, checked with `TrustedPath` before
  every start like the other tools (root-owned path, not pinned by hash). The version comes from
  `openconnect --version` ("OpenConnect version v9.12", "v9.01-3"; killed after 5 s), written as
  openconnect writes it (`ToolVersion.twoDigitMinor`). The minimum is **9.01** (owner decision, #2);
  older versions are refused: "openconnect 8.20 is too old: PassTunnel needs 9.01 or later. Update the
  openconnect package." Ubuntu 22.04 ships 8.20, so AnyConnect profiles are unsupported there
  (everything else keeps working). Versions packaged on 2026-10-27: Ubuntu 24.04 and 26.04 9.12, Debian
  12 9.01, Debian 13 9.12, Fedora 9.12; RHEL has it only in EPEL (9: 9.01, 10: 9.12).
- **Sign-in.** `passtunnel` runs `openconnect --authenticate` itself, as the user, as on the Mac. Before
  the code is used it finds the tool as the daemon does (`AnyConnectSignIn.distributionTool`: the same
  candidates, never `PATH`, `TrustedPath`, the version; `DistributionTools` and `ToolSpec` are shared), so
  a missing, untrusted or old openconnect is `PTError.anyConnectToolUnavailable` with that reason
  (`config_invalid`), and runs `openconnect --help`: `no-external-auth` is rendered only when it lists
  `--no-external-auth` as an option of its own (9.10 and later). With 9.01 openconnect offers the server
  single sign-on, which Phase 1 does not support (ARCHITECTURE.md, "Single sign-on"); making the option a
  requirement would raise the minimum to 9.10 and drop Debian 12 and EPEL 9. Without a pin the sign-in
  gets `no-system-trust` and the distribution's CA bundle as `cafile` (`DistributionTools.caBundle`: the
  first of the candidates above, resolved and checked as a tool is). A server-sent browser sign-in form
  would make it run `xdg-open` as the user. There is no "Fetch fingerprint" on Linux; the pin comes from
  the log hint. The daemon gets only the cookie, the fingerprint and the address.
- **The start** (`Supervisor`, `startOpenConnect`): after the usual start permission check and the
  session limits, a session of the profile whose network or DNS is not restored yet is restored first,
  or the start is refused ("The network settings of the last … session are not restored yet."); then the
  tool is checked and the request is prepared by the Mac's code, unchanged (`HelperCore.prepareOpenConnect`:
  every field checked, the root configuration built only by `OpenConnectAuthResult.tunnelConfig` and checked
  again, a fresh session directory with `openconnect.conf` and `policy`, 0600, root, and the log replaced),
  with `script = <run>/<uid>/<id>/vpn-hook` (`HelperCore.vpnHookPath`), a link to the daemon's own checked
  executable made with the policy (as `dns-hook`; the path is the run root, digits, the profile ID and `/`,
  safe for openconnect's `/bin/sh -c`). A failure removes the directory, and the cookie with it. The root
  configuration needs no CA bundle: it always pins the key the sign-in accepted (`servercert`).
- **The tunnel.** `openconnect --config=<run>/<uid>/<id>/openconnect.conf` and nothing else, stdin
  `/dev/null`, working directory the session directory. Its output goes through a pipe to `MaskingCopier`,
  as on the Mac, which writes whole lines into the session log with the cookie (and every cookie-shaped
  field) masked: a server chooses part of what openconnect prints. Environment: `PATH`, `LC_ALL` and
  `P11_KIT_NO_USER_CONFIG=1` (`HelperCore.environment(for: .openconnect)`). `GNUTLS_SYSTEM_PRIORITY_FILE`
  is not set by the daemon: openconnect sets it to `/dev/null` itself when it is unset (`main.c`
  1837–1858; it overrides the distribution's crypto policy on purpose, for DTLS), and the
  distribution's GnuTLS and p11-kit files, which are read before that, are root's. `interface` is never
  rendered, so the kernel picks a free `tunN` and a persistent device of another user is never attached
  to.
- **Supervision** as for openfortivpn: `posix_spawn` of the checked path, pidfd signalling of an earlier
  instance's tools, `state` with boot ID and start time, SIGTERM then SIGKILL after 5 s, no adoption.
  `state`, for lack of a suspended start, is written right after `posix_spawn`, next to its place and
  renamed over it, so the hook never reads half of it and waits up to 5 s for it; an openconnect whose
  `state` cannot be written is killed and the start fails. Every 5 s the daemon reads each session's
  record (`superviseOpenConnect`) and stops one whose set-up failed, that was not up within 60 s of its
  start (`VPNHook.setupDeadline`) or stayed `reconnecting` for 120 s (`VPNHook.reconnectDeadline`), with a
  line in the session log (`passtunneld: the network set-up failed; stopping`). Stopping sets the
  `stopping` mark first. The `status` reply's `tunnels` gives each of the caller's sessions' state from
  its record (`HelperCore.tunnelStatus`), as the Mac's helper does; the client never reads it from the log.
- **`vpn-hook` mode of `passtunneld`** (`LinuxVPNHook`). The executable started under the name
  `vpn-hook` (the link's path is its `argv[0]`) is the hook, decided in `main` before anything of the
  daemon. Its steps are the Mac's:
  1. *Session proof*, from `/proc` and the daemon's root-owned files, never the environment: euid 0; its
     own executable (`/proc/self/exe`, resolved) passes `TrustedPath`; its parent (`getppid`) runs an
     `openconnect`, or the shell `/bin/sh` resolves to (dash or bash: checked by `/proc/<pid>/exe`, so the
     hook does not depend on the shell replacing itself) whose parent does; that openconnect's working
     directory (`/proc/<pid>/cwd`) is a session directory `<run root>/<uid>/<profile ID>` the daemon owns,
     whose `state` names that pid, that uid and that executable, with a boot ID and start time that are the
     process's now (`PreviousInstance.identify`). A run it cannot prove writes `passtunnel vpn-hook:
     setting up the network failed: this run is not one of a PassTunnel session` and changes nothing.
  2. *Generation*: the boot ID and start time in `state`; once the hook holds `network.lock` it proves the
     session again and compares them (`OpenConnectHook.stillOurs`), so a hook that waited while its session
     ended and the profile started again changes nothing.
  3. The environment checked by `OpenConnectNetwork.parse(_:platform: .linux)` (`TUNDEV` `tun0` to
     `tun99999`, without leading zeros, and existing), the session's `policy`, and the run
     (`OpenConnectHook`: plan, record, apply, verify, revert, sharing) with `OpenConnectHook.runLimit` (30 s)
     and `SIGALRM` a second later. Its lines go to its standard error, which openconnect shares with the
     session log (through `MaskingCopier`). After a failure it sends its openconnect SIGTERM through a
     pidfd opened before the session is proven again.
- **The system** (`LinuxOpenConnectSystem`, the Mac's `MacOpenConnectSystem` for Linux):
  - *Changes* with iproute2's `ip`, run from the first of `/usr/sbin/ip`, `/sbin/ip`, `/usr/bin/ip`,
    `/bin/ip` that passes `TrustedPath` (nothing else is ever run; without one, every change fails with
    the reason), with an argument list, the fixed environment and at most 10 s each (`ToolRunner`), the
    family and the prefix length always spelled out (`OpenConnectCommand.Tools.linux`, golden-tested):
    `ip link set dev tunN up mtu M`, `ip -4 addr add A/32 peer A dev tunN`, `ip -6 addr add A/128 dev
    tunN`, `ip -4 route add N/L dev tunN`, `ip -4 route add S/32 via G dev eth0` for the server and the
    excludes (`dev ppp0` alone for a gateway link without an address), `ip -6 route add unreachable ::/1`
    and `8000::/1` for an IPv4 full tunnel without an IPv6 address (which refuse IPv6 that has no more
    specific route, not all IPv6). A revert is the same command with `del` (`link set … down` for the
    link), naming the route's next hop and type, so the kernel removes only that route. A route that
    already existed is recorded as not owned (`~`) or shared (`&`) and never deleted by this session.
  - *The routing table* from rtnetlink dumps (`Netlink`, moved to PassTunnelShared from Core, which reads
    it for the other-VPN check): the main table's routes with their type (`blackhole`, `unreachable`,
    `prohibit` are reject routes), metric, output interfaces and next hops (`KernelRoute.linux`, ordered
    by metric so the default gateway is the one the kernel uses), and the source selector: a
    source-specific route (`default from 2001:db8:a::/48 via …`, IPv6 source routing on a multihomed host)
    applies to some traffic only, so it is never the default gateway, never a route in the way, the
    session's own or its IPv6 block (`KernelRoute.sourceSpecific`). The other readers of these dumps (the
    other-VPN check, a FortiGate session's routes) do not look at the source and are unchanged. Chosen over `ip -j route`: no program
    run and no tool's text parsed for each look (the hook reads the table several times a run), the
    kernel's own fields (table, type, metric) rather than a format that changed between iproute2
    versions, and no privileges needed. rtnetlink writes may replace `ip` later.
  - *Interfaces*: `if_nametoindex`; MTU and `IFF_UP` from `/sys/class/net/<name>/mtu` and `flags` (a
    checked name only); addresses and the attached networks (`Underlay.attached`: the prefixes of the
    addresses of interfaces that are up, not loopback and not point-to-point) from `getifaddrs`.
  - *DNS* through `DNSApplier`, unchanged: the same backends, record (`dns`, in the session directory, next
    to `network`) and run root lock. A full tunnel's servers take every name (systemd-resolved: the link
    is the default route, `~.`); otherwise the split DNS and default domains are routing domains
    (`~domain`) and the default domains are searched. On the resolvconf and file backends, which cannot
    route names, every name goes through the tunnel. Only the session's own service
    (`passtunnel-<uid>-<id>`) is set or removed. A reconnect's check (`hasDNS`, `DNSApplier.verify`) checks what
    PassTunnel itself set and how the system's resolver reaches it, never what another program may
    legitimately put in front, so a session whose DNS is unchanged always passes:
    - systemd-resolved: `/etc/resolv.conf` still leads where it led when the DNS was set (the same link, the
      stub or the uplink file, recorded next to the record as `dns-path`), and the link's servers, domains and
      default route as `resolvectl dns`, `domain` and `default-route` report them for the recorded index
      (lists wrapped onto continuation lines read whole), compared as systemd-resolved stores them: one entry
      per domain, the routing flag given last winning (a default domain given as search and routing domain is
      listed as `~example.com` only);
    - resolvconf: `/etc/resolv.conf` still leads where it did (a link; a regular file that openresolv
      rewrites in place is not checked further), and resolvconf still holds the record it was given
      (`/run/resolvconf/interface/<name>`, openresolv's `interfaces/<name>`) with the servers and search
      domains; not the final resolv.conf, which a local cache (dnsmasq) may fill with `127.0.0.1` alone;
    - the file backend: `/etc/resolv.conf` is still exactly what PassTunnel wrote last.
    Anything that differs or cannot be established fails the check, and the session is stopped (a new
    sign-in sets it up afresh). A failure's reason (`DNSApplier`'s) reaches
    the failure line (`OpenConnectSystem.dnsFailure`).
- **Revert after a kill** (`SessionRestore`): when a session's tool has exited (stopped, killed or
  crashed), when the daemon stops, and in a starting daemon (`PreviousInstance`), the daemon runs
  `OpenConnectHook.restoreAfterExit` in-process, as the Mac's helper does: `stopping` set, a running hook
  waited for (the lock) and, past its limit, killed (`LinuxVPNHook.killHook`: the process the `hook` mark
  names, only while it still runs the daemon's executable with the recorded start time, through a pidfd),
  then everything the record holds reverted but what another session holds; the tunnel interface went with
  the tool, and with it its link, addresses and routes. Then whatever `DNSApplier` still records. A revert
  that fails keeps only the records (`network`, `dns`; the configuration with the cookie goes), the
  profile cannot start over it, and the daemon tries again every 15 s. A starting daemon keeps
  `network.lock` (a hook of an earlier instance's openconnect may hold it).
- **The unit** needs nothing new: `/dev/net/tun` and `CAP_NET_ADMIN` are allowed already, and the hook
  writes the same DNS paths as `dns-hook`. `/dev/vhost-net` (openconnect's vhost-net acceleration) is not
  in `DeviceAllow`; whether openconnect then uses the plain tun device without a word is for #188 to
  confirm with a real tunnel.
- **Tests.** `OpenConnectLinuxTests` (Core, every platform): `ip`'s argument lists, the hook's set-up,
  revert, failure, sharing and a hook killed in the middle of a change against a simulated Linux, the
  routing table from rtnetlink messages, the version and options. Daemon tests (Linux): the start, its
  configuration, link, policy, state, environment and masked log, refused requests and openconnects (8.20,
  missing), the deadlines, the revert after a kill and by the next daemon, the hook's mode and session
  proof against a simulated process tree, `LinuxOpenConnectSystem` (DNS against a fake root, only the
  checked `ip` run). Nothing starts a tunnel.
- **CI.** The Linux jobs install the distribution's openconnect (Ubuntu 24.04: 9.12) and run the daemon's
  and the sign-in's checks against it (`OpenConnectToolProbeTests`, only with
  `PASSTUNNEL_TEST_OPENCONNECT=1`), then start sessions through the daemon without a tunnel: a request
  refused before anything is prepared, a stand-in at the tool's path that prints 8.20 refused naming the
  minimum, and the real tool against a local socket that never answers (no tunnel, no hook run): its
  arguments, environment, configuration, state, link, masked log, status and stop. #188 adds an ocserv
  service: the sign-in with password and code, wrong code, reused code, wrong password, pin mismatch and
  CA mode, without a tunnel on every run; and an opt-in job (`PASSTUNNEL_TEST_OCSERV=1`) on the runner VM
  with `NET_ADMIN` and `/dev/net/tun` that connects, checks routes and DNS (all three DNS backends) and
  their revert, and kills openconnect to check the daemon's revert. That job is an exception to "tests
  never start a tunnel" (Rules) and marked like `RealSecretServiceTests`.

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
