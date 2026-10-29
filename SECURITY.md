# Security

PassTunnel stores VPN credentials and starts VPN software as root. This document explains, in plain
language, what runs with which privileges, what checks are in place, and where the limits are.
Implementation details are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Supported versions](#supported-versions)
- [How reports are handled](#how-reports-are-handled)
- [Credit](#credit)
- [Components and privileges](#components-and-privileges)
- [The privileged helper](#the-privileged-helper)
- [OpenVPN configuration sanitizer](#openvpn-configuration-sanitizer)
- [Importing an OpenVPN configuration](#importing-an-openvpn-configuration)
- [Cisco AnyConnect (planned)](#cisco-anyconnect-planned)
- [Secrets and files](#secrets-and-files)
- [Confirm with Touch ID (Secure Enclave)](#confirm-with-touch-id-secure-enclave)
- [Network connections](#network-connections)
- [Updates](#updates)
- [Cryptography](#cryptography)
- [MCP server and automation](#mcp-server-and-automation)
- [What is not protected](#what-is-not-protected)

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report it privately through GitHub: on
[github.com/passtunnel/passtunnel](https://github.com/passtunnel/passtunnel) open the **Security**
tab and choose **Report a vulnerability** (private vulnerability reporting / security advisories).
Include the version (at the bottom of Settings → General), your macOS version, the steps to reproduce and what an
attacker gains.

You can expect an acknowledgement within a few days (at the latest 14). What happens next, and how
reporters are credited, is below.

## Supported versions

Only the **latest release** gets fixes. Older versions are not patched; a vulnerability fixed in
1.5.1 is not fixed in 1.4.x, and the advisory names the first fixed version. There are no long-term
support branches.

Users get a fix in the same way as any release:

- **In the app:** PassTunnel checks for updates itself (Settings → Updates) and installs the signed
  update when you click Install ([Updates](#updates)). The helper is replaced after the update as
  soon as no VPN connection is active.
- **Homebrew:** `brew upgrade --cask passtunnel/tap/passtunnel`; the release workflow updates the
  cask with every release.
- **Download:** the latest disk image is always at
  [releases/latest/download/PassTunnel.dmg](https://github.com/PassTunnel/passtunnel/releases/latest/download/PassTunnel.dmg).

Release notes and the [published advisories](https://github.com/PassTunnel/passtunnel/security/advisories)
say which versions are affected. The upgrade path is always to the latest release: profiles and
settings are kept, and changes that break existing setups are marked as breaking in the release
notes ([CONTRIBUTING.md](CONTRIBUTING.md#pull-request-titles)).

## How reports are handled

1. **Report** privately as above. Nothing is discussed in public issues or pull requests at this
   point.
2. **Acknowledgement** by the maintainer within a few days, at the latest 14. Reports that need more
   information get questions in the private thread.
3. **Assessment.** The maintainer reproduces the problem, decides whether it is a vulnerability
   (what an attacker gains, from which starting point: see [What is not protected](#what-is-not-protected)),
   rates its severity and tells the reporter the result and the expected fix date. A report that is
   not a vulnerability is answered with the reasons and, where useful, moved to a public issue.
4. **Private fix.** The fix is prepared where only the maintainer and, if they want, the reporter can
   see it (a temporary private fork of the advisory), with a regression test. If it changes a rule of
   the helper or the sanitizer, [SECURITY.md](SECURITY.md) and
   [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) are updated in the same change. The reporter is
   asked to check the fix.
5. **Release.** The fix is merged and released through the normal flow
   ([docs/RELEASING.md](docs/RELEASING.md)); a security fix is a `fix:` and so a patch release at
   least. Fixes are not held back for a fixed schedule.
6. **Advisory.** When the release is out, the GitHub security advisory is published with the affected
   and fixed versions and a CVE is requested through GitHub. Users are told to update.
7. **Credit** (below) and, if the reporter agrees, public discussion.

The goal is a fix within 90 days of the report, sooner for anything that gives root. The project has
one maintainer ([GOVERNANCE.md](GOVERNANCE.md)), so this is a target, not a guarantee. If a report
is not answered in 14 days, the reporter may contact the maintainer
[`@Furkanprlk`](https://github.com/Furkanprlk) on GitHub (without details) to ask for it to be
looked at.

## Credit

Reporters are credited in the published advisory (GitHub's credit field), under the name or handle
they give, unless they ask to stay anonymous. A reporter who does
not want to be named says so in the report. Credit is given for every vulnerability report that
leads to a fix, whatever its severity.

Advisories published so far:
[GHSA-5v7f-79p2-3x2j](https://github.com/PassTunnel/passtunnel/security/advisories/GHSA-5v7f-79p2-3x2j)
and
[GHSA-5cpw-c3jh-3427](https://github.com/PassTunnel/passtunnel/security/advisories/GHSA-5cpw-c3jh-3427).
Both were found by the maintainer, so there is no outside reporter to credit in them.

## Components and privileges

| Component | Runs as | Purpose |
|---|---|---|
| `PassTunnel.app` (app and `passtunnel` CLI, one binary) | you | UI, profiles, Keychain access, TOTP, talks to the helper |
| `PassTunnelHelper` | **root**, started on demand by launchd | validates requests and starts or stops the VPN tools |
| bundled `openvpn`, `openfortivpn` (+ `dns-updown`) | **root**, started by the helper | the actual tunnel |

**Why root?** Creating a tunnel interface and changing routes and DNS requires it. PassTunnel does
not use a sudoers rule, a setuid binary or a kernel extension. The helper is registered with
Apple's `SMAppService` and shows up under **System Settings → General → Login Items**, where you
approve it once and can turn it off at any time. You can remove it with Settings → Helper → Remove
Helper… or `passtunnel helper uninstall`.

## The privileged helper

The helper is deliberately small. It accepts four requests over XPC: start OpenVPN, start
FortiGate, stop, and status. It enforces the following rules on every request.

### Who may talk to it

- **Client code-signing requirement.** The XPC connection is restricted with
  `NSXPCConnection.setCodeSigningRequirement` to
  `identifier "com.furkanprlk.passtunnel" and anchor apple generic and certificate leaf[subject.OU] = "YH4NUPFH74"`:
  only the PassTunnel app signed with the project's Developer ID Team ID. Other programs cannot
  connect. Any process running as you can, however, run the `passtunnel` command, which is that
  same signed binary: the helper serves it like the app, and it acts on your own profiles only (see
  [What is not protected](#what-is-not-protected)).
- **Caller identity from the kernel.** The calling user is taken from the connection's audit token
  (effective UID), never from the request.
- **Per-user isolation.** A user can only stop or see the status of tunnels they started.
- Requests larger than 64 KB or that do not decode are rejected.

### Which files it reads

- **Profile directory checks.** The profile folder in a request must resolve, with symlinks
  resolved, to exactly `<your home>/Library/Application Support/PassTunnel/profiles/<profile-id>`.
  It must be a real directory owned by the calling user and not group- or world-writable. The resolved path
  is checked again on the open descriptor, and all further file access goes through that
  descriptor, so the folder cannot be swapped between check and use.
- Profile IDs are limited to letters, digits, `-`, `_` and `.` (no leading dot or dash, no trailing
  dot, at most 64 characters).
- `config.ovpn` must be a regular, single-link file owned by you, not group- or world-writable, at
  most 1 MB, valid UTF-8, and is opened without following symlinks.

### Which programs it runs

- **Only the tools bundled in its own app, run from a root-owned copy.** The helper takes
  `Contents/Resources/bin/openvpn` and `Contents/Resources/bin/openfortivpn` and the libraries in
  `Contents/Frameworks` that they load (OpenSSL's `libcrypto` and `libssl`, `lzo`, `lz4`,
  `pkcs11-helper`) from its own app bundle (located through the kernel, not `argv[0]`). The bundle
  also holds `Contents/Resources/bin/openconnect` and its libraries (GnuTLS, nettle, GMP, p11-kit,
  libtasn1, libidn2, libunistring, libintl, stoken, libtomcrypt, libtommath) for Cisco AnyConnect
  ([below](#cisco-anyconnect-planned)): they are copied and checked with the others. The helper
  starts `openconnect` only for its Cisco AnyConnect request, which **nothing in the app sends yet**,
  and only on macOS 15.4 or later (dyld stops Homebrew's build on an older macOS; the helper refuses
  before it copies or starts anything). Its p11-kit and GnuTLS read no configuration from the Homebrew prefix
  ([Paths compiled into the Homebrew build](#paths-compiled-into-the-homebrew-build)). The bundle can
  be changed or renamed by the user who installed it, so the helper does not run the tools from there:
  it copies them, without following symlinks, into `/var/run/passtunnel/tools/<helper build>/`
  (directories `root:wheel` 0755, tools 0555, libraries 0444), with the bundle's layout, so the
  tools' load paths (`@executable_path/../../Frameworks/…`, `@loader_path/…`) resolve to the copied
  libraries and never back into the bundle. Every copied file is checked as copied (below); a copy
  that fails the check, or has an unexpected or missing file, is made again; copies of other helper
  builds are removed unless a tool still runs from them. macOS empties `/var/run` when it starts. A
  path supplied by the client is never executed. System libraries come from macOS.
- **Signature checked on the copies and on the code that runs.** Each tool must satisfy a
  code-signing requirement with its own identifier (`com.furkanprlk.passtunnel.openvpn`,
  `…openfortivpn`, `…openconnect`) and the project's Team ID; each library must be signed with the project's Team ID.
  The helper checks every copied file (strict validation across all architectures), so a file
  replaced in the bundle while it was being copied gives a copy that is refused. It then starts the
  copied tool **suspended**, before its first instruction, checks the code the kernel actually loaded
  for that process against the same requirement (strict validation, which also fails when the file
  on disk no longer matches what was loaded), and only then lets it run. If that check fails, the
  process is killed before it ran. If the helper itself stops between starting a tool and letting it
  run, the helper that starts next kills that tool instead of taking it over.
- **Only the builds it was released with.** The identifier and Team ID requirements accept every
  build the project ever signed, including an older release's `openvpn` or `libcrypto`. A released
  helper also carries the cdhashes (the hash of a code signature, which the kernel records for the
  running process) of the exact tools and libraries it ships with, compiled into its own signed code.
  It copies only those libraries, and refuses a copied tool or library, a started tool, or a
  `dns-updown` copy with any other cdhash. Every app bundle made by `scripts/build-app.sh` is pinned
  this way, and a signed build fails unless every tool and every bundled library is pinned. Only
  plain development builds (`swift build`, tests) pin nothing: they copy every `.dylib` in
  `Contents/Frameworks` and accept any tool or library that satisfies the requirement.
- **DNS script.** OpenVPN's `dns-updown` script is copied into the root-only run directory and the
  *copy* is signature-checked before OpenVPN may use it. OpenVPN's compiled-in default script path
  (which points into a build machine's Homebrew prefix) is never used. If no script is bundled,
  DNS hooks are disabled and `script-security` is set to 1.
- Tools are started with `posix_spawn` in their own process group, stdin from `/dev/null`, default
  signal handling, no inherited file descriptors and a fixed environment: `PATH=/usr/bin:/bin:/usr/sbin:/sbin`,
  `LC_ALL=C`, and settings that keep the bundled OpenSSL away from the Homebrew paths compiled into
  it (on your Mac they may exist and belong to whoever installed Homebrew): `OPENSSL_CONF=/dev/null` (no
  configuration file), `OPENSSL_MODULES` and `OPENSSL_ENGINES` set to `/var/empty/passtunnel-none`
  (a directory that does not exist inside the root-owned `/var/empty`, so no providers or engines are
  loaded), `SSL_CERT_FILE=/etc/ssl/cert.pem` (the system's root-owned CA bundle) and
  `SSL_CERT_DIR=/var/empty`.
- `stop` only signals the process the helper started for that profile (SIGTERM, then SIGKILL to
  its process group after 5 seconds).

### How OpenVPN is started

- **Only the file the app checked.** The start request carries the SHA-256 of the exact
  `config.ovpn` the app read when it decided where your secrets go (see [Bound to the
  server](#confirm-with-touch-id-secure-enclave)). The helper hashes the file it reads and refuses to
  start a different one, so the file cannot be swapped between that check and the start.
- The user's `config.ovpn` is passed through the [sanitizer](#openvpn-configuration-sanitizer).
  The sanitized copy and the credentials file (user name plus password/code, single lines only) are
  written as new `0600` files into a **root-owned run directory**, `/var/run/passtunnel/<uid>/<profile-id>`
  (`0711` like its parents, which must be real, root-owned directories: you can reach a file in it by
  name, but cannot list, rename or replace anything). The run directory is deleted when the tunnel stops.
- OpenVPN gets fixed flags after `--config`, so they override anything left in the file:
  `--management <run directory>/mgmt.sock unix`, `--management-client-user <your user name>`,
  `--verb` (the configuration's `verb`, at most 4; 3 when it sets none), `--auth-nocache`,
  `--remap-usr1 SIGTERM`, `--connect-retry-max 3`, `--tls-version-min 1.2` (`1.3` when the
  `tls-version-min` OpenVPN applies from the configuration is 1.3, read with OpenVPN's own rules so a
  line OpenVPN ignores changes nothing; the flag never lowers it), and explicit
  `--script-security`/`--dns-updown` settings. The cap keeps OpenVPN's debug levels (from 5 every
  packet, from 7 the data-channel keys, from 9 packet contents) out of the log, which you, the app
  and `get_logs` can read. Only `--server-poll-timeout 10` (how long a server that does not answer is
  waited for) comes before `--config`, as a default the configuration may change.
- **Management over a per-user unix socket.** The management interface is a unix socket in the
  session's root-owned run directory, not a TCP port. OpenVPN only serves the user named in
  `--management-client-user` (peer credential check). Once the socket exists, the helper also
  hands it to you with mode `0600`; because nobody but root can change entries in that directory,
  this cannot be redirected to another file (the helper still checks it is a socket and never
  follows links). The socket is removed with the run directory when OpenVPN exits.

### How FortiGate is started

- The openfortivpn configuration is **rendered by the helper from typed fields** (host, port, user
  name, password, code, trusted certificate digest, DNS and routes switches). No user-supplied raw
  configuration and no pppd options are accepted.
- Every value is validated so it stays on its own line: host names are limited to host-name
  characters or an IPv6 literal (hex digits, `:` and `.`, with an optional zone id of letters and
  digits), checked character by character before any C function sees them, so no NUL, control
  character or whitespace is accepted; the port must be 1–65535, the trusted certificate must be a
  64-character SHA-256 hex digest, and credentials may not contain line breaks, control characters
  or surrounding whitespace. The app refuses such a host already when a profile is saved or imported.
- The finished file is checked once more before it is written: the expected number of lines, no NUL,
  carriage return or other control byte, and only the keys PassTunnel writes, each once.
- No value is longer than openfortivpn keeps (it copies each into a fixed buffer and silently drops
  the rest): host at most 253 bytes, user name 64, password 255, one-time code 64 (UTF-8 bytes, not
  characters). The app refuses a longer FortiGate user name already when the profile is saved or a
  user name is entered to connect.
- The file is written into the same root-only run directory and the tool always gets `-c <file>`,
  so no default configuration is read. It always sets `ca-file = /etc/ssl/cert.pem`, so
  openfortivpn never falls back to OpenSSL's compiled-in default store.
- The *Fetch fingerprint* button in the editor reads the gateway certificate's SHA-256 digest with
  a TLS handshake that is aborted right after the certificate is received. You confirm the digest
  before it is saved.

### Logs

- The helper creates `vpn.log` in your profile folder itself: any existing entry is unlinked
  (never followed or truncated), a new file is created owned by you with mode `0600`, and its
  descriptor becomes the tool's stdout/stderr. OpenVPN's `--log` options are not used and are
  rejected in configs, so OpenVPN never opens a file path as root.
- Every session starts with an empty log; while it runs, the helper checks the size once a minute
  and cuts a log above 5 MB down to its first 64 KB and last 1 MB (through its own copy of the descriptor).

## OpenVPN configuration sanitizer

Before running a config as root, the helper parses it with a tokenizer that mirrors OpenVPN's own
(quotes, backslash escapes, `#`/`;` comments, leading `--`, `<tag>…</tag>` inline blocks,
`<connection>` blocks, `setenv opt` prefixes). Where the two could disagree it errs on the strict
side: names are compared case-insensitively with all leading dashes removed. Every violation is
reported with its line number, and nothing is run until the config is clean. The app reads configs
with the same tokenizer when it imports them (embedding referenced files, removing credential
blocks), so the app and the helper never read a line differently.

**Rejected directives** (they run programs, load code, read or write files as root, override the
helper's settings, or make OpenVPN something other than a client connection):

```
up  down  route-up  route-pre-down  ipchange  learn-address
client-connect  client-disconnect  client-crresponse  tls-verify  auth-user-pass-verify
tls-crypt-v2-verify  plugin  dns-updown  iproute
daemon  writepid  cd  chroot  user  group  setcon  config
status  replay-persist  tmp-dir  tls-export-cert  dev-node  memstats
client-config-dir  ifconfig-pool-persist  port-share
engine  providers  pkcs11-providers  capath  show-pkcs11-ids
server  server-ipv6  server-bridge  tls-server  inetd      (server modes)
genkey  mktun  rmtun  help  version  test-crypto           (standalone modes)
show-ciphers  show-digests  show-engines  show-tls  show-curves  show-groups
show-gateway  show-net  show-net-up  show-adapters  show-valid-subnets  allow-nonadmin
win-sys  service  msg-channel
management*  log*            (every directive starting with these)
script-security N            (when N > 1)
mode M                       (unless M is p2p)
dev NAME                     (unless NAME is tun, tap, utun or null, optionally followed by
                              letters, digits, - or _)
proto, proto-force P         (when P is tcp-server, tcp4-server or tcp6-server)
remote, local … P            (the same protocols as the third argument)
```

**TLS 1.2 is the floor.** These are rejected too, so a configuration cannot make OpenVPN accept a
control channel older than TLS 1.2 or weaken OpenSSL's checks:

```
tls-version-min V [or-highest]   (unless V is 1.2 or 1.3; or-highest only as the second word)
tls-version-max V                (unless V is 1.2 or 1.3)
tls-cipher L                     (when an @SECLEVEL in L is not exactly @SECLEVEL=1 to 5, or an
                                  element that adds suites names NULL, EXP, ADH, AECDH, anon or
                                  COMPLEMENTOF…, in any case; elements starting with !, - or +
                                  may: they remove suites or only move ones already selected)
tls-ciphersuites L               (unless every suite is TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
                                  TLS_CHACHA20_POLY1305_SHA256 or TLS_AES_128_CCM_SHA256; - for _ is fine)
tls-cert-profile P               (unless P is legacy, preferred or suiteb: insecure is level 0)
```

OpenSSL allows TLS 1.0 and 1.1, and suites without encryption or authentication, only at security
level 0, which `@SECLEVEL=0` or `tls-cert-profile insecure` selects; OpenVPN's default profile,
`legacy`, is level 1, so `@SECLEVEL=1` stays allowed. With the bundled OpenVPN 2.7 and OpenSSL 4, a
configuration with `tls-version-min 1.0` and `tls-cipher DEFAULT:@SECLEVEL=0` connects with TLS 1.1;
either line alone does not. Whatever the configuration says, the helper also passes
`--tls-version-min 1.2` after it (the last value wins in OpenVPN), so the floor holds even for a
spelling the sanitizer missed.

The list was checked against the option parser of OpenVPN 2.4 to 2.7. A configuration cannot make
OpenVPN a server, run one of its standalone commands or wait for incoming connections, and a device
name can never be a path: OpenVPN opens `/dev/<name>` for some devices on macOS.

**Other rules**

- **No external files.** `ca`, `cert`, `key`, `dh`, `pkcs12`, `extra-certs`, `tls-auth`,
  `tls-crypt`, `tls-crypt-v2`, `secret`, `crl-verify`, `auth-user-pass`, `http-proxy-user-pass` and
  `askpass` must use inline content (`<ca>…</ca>`); otherwise the helper would read arbitrary paths
  as root. `dh none` is allowed. An `http-proxy` credentials argument must be `auto`, `auto-nct` or
  inline. When you import an `.ovpn`, the app embeds referenced files for you.
- **`setenv`** is limited to client metadata (`CLIENT_CERT`, `FORWARD_COMPATIBLE`,
  `PUSH_PEER_INFO`, `FRIENDLY_NAME`, `ALLOW_PASSWORD_SAVE`, `SERVER_POLL_TIMEOUT`,
  `GENERIC_CONFIG`, `IV_*`, `UV_*`), so variables such as `PATH` or `BASH_ENV` cannot steer the DNS
  script.
- `setenv opt <directive>` is checked like the directive itself.
- **A `remote` is required.** Without one OpenVPN waits for a peer to reach it instead of connecting
  out. Only a line OpenVPN certainly reads as a server to connect to counts: `remote` with a host and
  optionally a port and a protocol, with at most one leading `--` or one `setenv opt` prefix, at the
  top level or in a `<connection>` block. A configuration without one is refused as a whole.
- Lines longer than 254 bytes (OpenVPN would silently split them), NUL bytes, unterminated quotes
  and unclosed blocks are rejected, and so is a backslash outside single quotes that does not escape
  `\`, `"` or whitespace. OpenVPN refuses those too, except a backslash at the end of a line, which
  it would take as escaping the line break; PassTunnel rejects that as well.
- **A byte order mark only at the start of the file.** OpenVPN skips a UTF-8 BOM only as the first
  bytes of the file. A line that starts with U+FEFF anywhere else (a later line, also inside an
  inline block, or a second BOM on the first line) is rejected, so stripping the lines above it can
  never make it the file's BOM. When you import an `.ovpn`, a referenced file's own BOM is left out
  of the block it is embedded in.
- **`static-challenge` is stripped** (lines or blocks), because PassTunnel answers the challenge
  itself.

The helper applies these rules to every configuration at every connect, whatever the app did before.
It also starts OpenVPN with `--pull-filter ignore` for a pushed `verb` ahead of the configuration, so a
server cannot raise the capped log level after connecting and a profile's own `pull-filter` lines
cannot let it through. On Linux, `passtunneld` additionally refuses a `dev` that names a device the
system has already (`dev tun` and `dev tap` let the system pick a free one), so OpenVPN never attaches
to a persistent device another user may still hold open ([docs/LINUX.md](docs/LINUX.md)).
When you import a file, the app leaves out some of the refused lines instead of refusing the file
([below](#importing-an-openvpn-configuration)); the rules above do not change.

## Importing an OpenVPN configuration

When you import an `.ovpn` file, PassTunnel reads it before anything is saved: no profile file and no
Keychain item exists until the profile is added. Files the configuration refers to are embedded from
its folder; then each line the [sanitizer](#openvpn-configuration-sanitizer) would refuse is either
**skipped** or **blocks** the file.

- **Skipped** lines are the ones whose whole effect PassTunnel replaces or does not need. You see
  them before the profile is added (`passtunnel import` prints them; `--json` returns them as
  `skipped`), and the stored configuration keeps each as a comment,
  `# PassTunnel skipped: up /etc/openvpn/update-dns`. The sanitizer is not relaxed: it still runs at
  every connect, so a skipped line that came back would stop the connection.
- **Blocking** lines refuse the file. All of them are listed with their line numbers, and nothing is
  created.

| Skipped | Why leaving it out is safe |
|---|---|
| `up`, `down`, `route-up`, `route-pre-down`, `ipchange` | Programs run at points of the connection. PassTunnel never runs scripts from a profile; DNS comes from what the server sends, through PassTunnel's own hook. |
| `iproute` | The program for addresses and routes (Linux builds of OpenVPN); OpenVPN uses its own. |
| `script-security` above 1, or without a valid level | It only allows scripts. OpenVPN's default level, 1, applies, and the helper sets the level on its command line anyway. `script-security 0` and `1` stay. |
| `dns-updown` | A DNS script (or `disable`, `force`); the helper passes its own hook after the configuration. |
| `daemon`, `cd`, `chroot`, `user`, `group` | How OpenVPN runs as a process. The helper starts and supervises it in the foreground, as root so that routes and DNS are undone when it stops; no file is read from a working directory, since every file must be inline. |
| `writepid`, `status`, `tmp-dir`, `tls-export-cert` | Files OpenVPN would write as root that nothing in PassTunnel reads (`tls-export-cert` only feeds a `tls-verify` script, which blocks). |
| `log`, `log-append` | PassTunnel keeps the connection's log itself. |
| `management`, `management-client`, `management-client-user`, `management-client-group`, `management-hold`, `management-query-passwords`, `management-query-proxy`, `management-query-remote`, `management-forget-disconnect`, `management-signal`, `management-up-down`, `management-log-cache` | The helper sets up the management interface itself. |
| `setenv` of anything but client metadata | Variables only scripts see. PassTunnel runs none, and they could steer its DNS hook. The metadata `setenv` lines listed above stay. |

Everything else the sanitizer refuses blocks the file, in particular:

- checking the server or the sign-in: `tls-verify`, `auth-user-pass-verify`, `tls-crypt-v2-verify`;
- loading code: `plugin`, `engine`, `providers`, `pkcs11-providers`, `show-pkcs11-ids`;
- files outside the configuration: a referenced file that cannot be embedded (missing, a device, too
  large), proxy credentials in a file, `config`, `capath`, `dev-node`, `replay-persist` (it also keeps
  replay protection across restarts), `client-config-dir`, `ifconfig-pool-persist`;
- a private key or certificate from another program: `management-external-key`,
  `management-external-cert`;
- server-only directives and server modes, since the file is then not a client configuration:
  `learn-address`, `client-connect`, `client-disconnect`, `client-crresponse`, `port-share`,
  `management-client-auth`, `auth-gen-token-secret` with a file, `server`, `server-ipv6`,
  `server-bridge`, `tls-server`, `inetd`, `mode` other than `p2p`;
- standalone modes, which do something else instead of connecting: `genkey`, `mktun`, `rmtun`,
  `help`, `version`, `test-crypto`, the `show-…` listings, `allow-nonadmin`;
- `memstats`, `setcon`, `win-sys`, `service`, `msg-channel`, and a `dev` name that is not a device
  type;
- a TLS setting below the [floor](#openvpn-configuration-sanitizer) (`tls-version-min` or
  `tls-version-max` below 1.2, `@SECLEVEL=0`, suites without encryption or authentication,
  `tls-cert-profile insecure`): leaving it out would change which servers the profile can reach;
- anything that makes OpenVPN wait for incoming connections: a listening protocol (`tcp-server`,
  `tcp4-server`, `tcp6-server` in `proto`, `proto-force`, `remote` or `local`) and a file without any
  `remote`, which is listed without a line number;
- blocks named after a refused directive (`<plugin>…</plugin>`), unclosed blocks, and lines OpenVPN
  would reject or read differently (too long, NUL bytes, bad escapes, unterminated quotes, a
  byte order mark that does not start the file);
- any other `log…` or `management…` name, and anything this table does not list: a rule added to
  the sanitizer blocks until it is decided here.

`setenv opt <directive>` is decided like the directive. Words inside an inline block such as
`<ca>…</ca>` are its content, not directives. A skipped line inside a `<connection>` block becomes a
comment in that block. The comment is at most 254 bytes, so OpenVPN reads it as one line, and control
characters in it are replaced.

## Cisco AnyConnect (planned)

**Not in any release yet.** Support for Cisco AnyConnect through OpenConnect (issue #2, Phase 1:
password and one-time code, no single sign-on, Mac and Linux) is designed and being implemented. This
section is the threat model the pull requests #179–#189 are reviewed against; the details are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#cisco-anyconnect-backend-planned). In place so far: the
bundled tool (#179), the configuration checks (#180), the profile (#181), the helper's side of a
session (#182: the helper accepts a start request, checks every field of it again and runs
`openconnect` as described below), the Mac's hook that sets up and undoes the network (#183), tested
against a simulated Mac, and the sign-in and connect in PassTunnel's core (#184, macOS 15.4 and later;
the command line and MCP tools since #185, the app since #186), and Linux (#187: `passtunneld`
runs the distribution's `openconnect` and is its hook, tested against a simulated system); what only a real
server and tunnel show is checked against a test server (#188).

### What changes

- **A third tool runs as root.** The bundled `openconnect` brings its own TLS stack (GnuTLS, nettle,
  GMP, p11-kit, libtasn1, libidn2, libunistring) and three unused libraries Homebrew links in
  (gettext's libintl, and stoken with libtomcrypt and libtommath for RSA SecurID tokens). They are
  copied, signature-checked and pinned by cdhash exactly like `openvpn` and its libraries, and their
  own vulnerabilities apply as root once the helper runs it. Since #179 they are in the app bundle and
  in the helper's root-owned copy, pinned; since #182 the helper starts `openconnect` for a Cisco
  AnyConnect start request (macOS 15.4 and later only), which PassTunnel sends since #184. `diagnose`
  runs `openconnect --version` as you (macOS 15.4 and later only). Below macOS 15.4 a Cisco AnyConnect
  profile is refused before anything is asked, read or run ("Cisco AnyConnect requires macOS 15.4 or
  later."). On Linux the distribution's `openconnect` is used (below), 9.01 or later.
- **Signing in runs as you, not as root.** Your password and one-time code go to an `openconnect
  --authenticate` run under your own account, on its standard input. The helper receives only what
  that run returns: the session cookie, the server's public key fingerprint and the address it
  connected to. It never sees your password or code, and the root process never reads the server's
  login pages. Your user name goes to that run in a file, never on its command line, which every
  account on the machine can read: the command line is exactly `--config=<file> --authenticate`, the
  file is `0600` in a directory of its own (`0700`) in your temporary folder and is removed when the
  run ends, and the run gets a fixed environment (no proxy, key log or debug variable of yours). It is
  the app bundle's own `openconnect`, run with your privileges, so it is trusted as much as the app's
  own code is; it is stopped after 60 seconds, or when you disconnect. Its progress messages (never its
  output with the cookie) become the profile's log after passing the log filter, with your password,
  code and the cookie masked literally.
- **The one-time code.** It counts as sent once the sign-in run starts (the next connect waits for a
  fresh code). It is given back only when the run's messages, all of them, show that no form was
  submitted: only one request, the first, which carries no credentials. A redirect counts as a second
  request, and a run stopped at its time limit or with more messages than are kept counts as sent, so a
  code that may have reached any server is never reused. After a form may have been sent, a failure is
  always a refused sign-in, never retried, whatever the server's text says.
- **What the server writes into the log decides nothing.** Its text appears among openconnect's
  messages. Whether the tunnel is up, or its network set-up failed, comes from the helper, which reads
  the hook's root-owned record; openconnect's messages are read only as whole lines in its exact wording,
  and certificate and network failures only from before the server's first answer.
- **Where the sign-in may go.** A server may send the sign-in to another server (load balancing).
  PassTunnel refuses to build a tunnel when the sign-in **ended** on another host or port than the
  profile's (Phase 1), or when the sign-in's log shows a form sent to one; the tunnel run is pinned
  to the address and the public key the sign-in used, so DNS cannot send the cookie elsewhere between
  the two runs. What this does not prevent: openconnect follows redirects during the sign-in by
  itself, and its command line offers no way to refuse one, so your password and code can reach a
  server the profile's server redirects to (even one that redirects back) before PassTunnel can
  object. With a pinned key only a server holding that key can receive them; without a pin, any
  server with a certificate the system trusts for its own name.
- **No single sign-on.** Phase 1 signs in with a password and code only. openconnect is told not to
  offer browser sign-in (from openconnect 9.10, which the Mac bundles; older Linux versions always
  offer it), but a server that asks for it anyway can still make the sign-in run open a page in your
  browser, as you; that run then fails. The root run never signs in.
- **Server certificate.** Either a pinned public key (`pin-sha256:`, only the full 44-character
  value: openconnect itself would accept a prefix as short as 4 characters, which PassTunnel
  refuses), which is then the only trust, or the system's root-owned CA bundle passed explicitly
  (`/etc/ssl/cert.pem` on the Mac). The CA store compiled into Homebrew's GnuTLS is never used.
  The app's *Fetch fingerprint* reads the key's pin with a TLS handshake that is aborted once the
  certificate is received (only when you click it; you confirm the pin before it goes into the
  profile). When a connect fails because the certificate is not trusted, *Trust This Server…*
  offers the key openconnect named, showing the server and the full pin first; it is saved only for
  the server that sign-in went to, and only if the profile still names that server with the pin it
  had then.

### The session cookie

The cookie is a bearer secret: whoever holds it can use your VPN session until the server ends it.

- **Where it lives:** in a pipe from the sign-in run, read in memory by PassTunnel; in the start
  request to the helper (the code-signature-checked XPC connection, on Linux the daemon socket); in
  the helper's memory; in `openconnect.conf` (`0600`, root) in the root-only run directory for as
  long as the session runs; and in `openconnect`'s memory. PassTunnel overwrites its own buffer
  once the request is sent or the connection fails; that is best effort, since copies made while
  encoding the request or by the runtime are not guaranteed to be erased. It is never written to
  your profile folder.
- **Not logged:** the sign-in run's output, which carries it, is read only by PassTunnel's parser,
  and neither run gets `-v` or an HTTP dump option, the levels that would print it. A server can still
  make the tunnel run print text of its choosing (the status line of its CONNECT reply), so the helper
  copies that run's output into the log through a filter that removes the cookie, whole lines at a time:
  the cookie under its name, its value alone and, where openconnect makes one (Linux openconnect before
  9.10), the STRAP key that comes with it, which is the client's private key for the session.
  The filter applied when a log is read masks the cookie's forms as well (`COOKIE=`, `webvpn=`, `Cookie:`
  headers, a `cookie` configuration line). No error message, activity entry or description of the
  start request contains it: a sign-in that cannot be used (it ended on another server, or its output
  is not in the expected form) is reported with a fixed text, since the server chooses every value
  of that output.
- **How long it lives:** the file goes with the run directory when the tunnel stops. On a disconnect
  openconnect tries to tell the server goodbye; whether the server then invalidates the cookie is up
  to the server, and nothing is sent after a forced kill, a crash or a broken connection. Treat the
  cookie as valid until the server's own expiry. After a dropped connection openconnect retries with
  it for a budget of 60 seconds of waiting between tries, and PassTunnel stops the session if it is
  not back within 2 minutes; then PassTunnel signs in again, with a fresh code.

### Values from the server that reach root

openconnect configures neither addresses nor routes nor DNS. It passes what the server sends to a
script, as root, in environment variables: the tunnel addresses and netmasks (IPv4 and IPv6), DNS
servers, the default domain, split-DNS domains, split include and exclude routes, a banner, a proxy
auto-configuration URL and every `X-CSTP-*` header. openconnect checks some of these (IPv4 split
routes) and passes the rest as the server wrote them (the addresses, the IPv6 split routes, every
name): no line breaks, but spaces, quotes, `$`, backquotes and `;` can be in them. The variable
names are openconnect's own, so a server cannot set `BASH_ENV` or similar.

- **vpnc-script is never run.** The usual script rewrites `/etc/resolv.conf`, changes the primary
  network service's DNS servers permanently with `networksetup` (and empties them on disconnect,
  deleting servers you had set by hand), replaces the default route, and hands unchecked values to
  shell commands. openconnect always gets PassTunnel's own hook, `vpn-hook`, instead: on the Mac a
  root-owned copy of the helper itself (checked by hash against the running helper and by its
  signature), on Linux `passtunneld`. The helper checks when it starts that the file it copies is the
  very file running (not merely the one at its path, which the bundle's owner could swap), and copies
  it only for a Cisco AnyConnect connection: if anything about the hook fails, only Cisco AnyConnect is
  refused, and OpenVPN and FortiGate connect as before. The copy acts as the hook only when both the file the system
  reports for the process and the name it was started under are `vpn-hook`, so the installed helper
  can never be made to act as the hook, and the copy never acts as the helper.
- **It first proves which session it serves.** Before it reads anything from its environment, it proves
  from the process tree and the helper's root-only session files (not from anything openconnect or the
  server passes) which PassTunnel session's `openconnect` ran it. A run it cannot prove changes nothing
  and stops nothing.
- **Every value it uses is checked first**, as for OpenVPN's DNS on Linux, with the same address
  and domain rules: addresses must parse strictly (no leading zeros, which some parsers read as
  octal; no zones, ports or blanks; no IPv4 address written as an IPv6 one, which would slip past the
  IPv4 checks) and are written back in canonical form, masks must be
  consistent, domains must be plain host names, the interface must be a tunnel interface that
  exists, values must be printable ASCII, and lists have limits (3 DNS servers, 16 domains of each
  kind, 1,024 routes of each kind, with no gaps or extra entries). One bad value fails the set-up, and
  the message in the log names the setting, never the server's value. What it does not need (the
  banner, the proxy URL, the raw headers) is never read.
- **Its permissions come from root, not from the server.** Whether it may set routes and DNS is
  written by the helper into the root-only run directory before the tool starts; the hook reads
  nothing from your profile and nothing the server sends can change it.
- **No shell, no lasting change.** The hook runs fixed programs (`/sbin/ifconfig` and `/sbin/route` on
  the Mac) with argument lists and none of its own environment, each for at most 10 seconds and the
  whole run for at most 30. On the Mac DNS goes into dynamic, per-session entries of the system
  configuration that disappear on restart; it never changes your network service's saved settings and
  never writes `/etc/resolv.conf`. It records every change in the session's run directory before
  making it, and whether it succeeded, one session at a time: only what it added itself is removed
  later, never a route that was already there, nor one that was replaced since. It undoes them on
  disconnect and after a failed set-up; if `openconnect` is killed before it could, the helper (or the
  Linux daemon) first lets a running hook finish or stops it, then undoes them from that record (what
  belonged to the tunnel interface went with it), and keeps retrying every 15 seconds while that fails;
  the profile cannot connect again until it succeeded.
- **Reconnects do not change the set-up.** If the server sends different DNS, routes or MTU when
  the connection is re-established, the session is stopped instead of being re-configured.
- **The default route stays.** A full tunnel adds two half routes (`0/1`, `128/1`), as OpenVPN
  does; the hook never replaces or deletes your default route. If a route the set-up needs already
  goes elsewhere (another VPN that sends all traffic or a network the server routes, another gateway
  to the server), the set-up fails rather than replacing someone else's route. For a full tunnel's DNS,
  the hook's per-session entries make the tunnel macOS's primary network service, so that every name
  is resolved through the tunnel; macOS then also points the default route at the tunnel while the
  session lasts, and returns it when the entries are removed.
- **Your local network stays local.** A route the server asks for into the tunnel that lies inside a
  network your Mac is attached to (your Wi-Fi or Ethernet subnet), including a DNS server on it, is
  left out and counted in the log ("2 routes kept local"), so the server cannot take over devices on
  your LAN. A broader route (all of `10.0.0.0/8` while your LAN is `10.1.2.0/24`) is kept: your LAN's
  own route is more specific and still wins. A full tunnel is not affected by this.
- **Shared routes are not pulled from under another session, nor left behind.** When two sessions need
  the same route (a block, or the route to a VPN server both use), the one that ends first leaves it in
  place while the other still runs (also when the first one was killed and is still being cleaned up),
  and the last one removes it. A route that was there before any PassTunnel session is never removed.
- **A network change does not leave holes.** When the connection is re-established, the hook checks that
  every route, address and DNS setting it made is still there as it made it; if anything differs, it
  undoes the rest and stops the session, which then connects afresh.
- **A late hook cannot touch a newer session.** Once it holds the lock, the hook proves its session again,
  including its generation (the start time of its `openconnect`), before it reads or changes anything: a
  hook of a session that has ended meanwhile does nothing.
- **IPv6 in a full tunnel.** When all IPv4 traffic goes through the tunnel and the server assigns no
  IPv6 address, IPv6's default path is taken away (reject routes), so IPv6 to the internet is refused
  at once rather than sent around the tunnel, and programs fall back to IPv4 without waiting (the same
  for IPv4 in a tunnel that assigns only IPv6). Nothing the server sends for the blocked family (routes
  to include or exclude) is used, so the server cannot open holes in the block. Split includes that
  together cover every address count as a full tunnel. This is a routing rule, not a firewall: IPv6 to destinations
  with a more specific route (your local network, link-local addresses, other interfaces or VPNs)
  still leaves outside the tunnel. The route to the VPN server itself is kept.
- **A failed set-up stops the session,** whether or not the app or the command is still running.
  openconnect ignores the hook's result and keeps running, so the hook tells its openconnect to stop,
  and the helper (or the Linux daemon) stops a session whose network set-up failed, did not finish
  within 60 seconds of the start, or did not come back within 2 minutes after a dropped connection.
  Only the hook's success marks the profile connected.

### Paths compiled into the Homebrew build

As with OpenSSL (above), the bundled build has paths under `/opt/homebrew` compiled in, which on
your Mac may exist and belong to whoever installed Homebrew. Each is kept out of the root run:

- **openconnect's default script** (`/opt/homebrew/etc/vpnc/vpnc-script`, run with `/bin/sh` when
  no script is named): the configuration always names the hook, and is checked for it before it is
  written.
- **p11-kit's configuration and module files** (`/opt/homebrew/etc/pkcs11.conf`,
  `/opt/homebrew/etc/modules/`, `/opt/homebrew/etc/pkcs11/modules/` and p11-kit's Cellar module
  directory). openconnect initializes PKCS#11 before it reads its options, even for `--version`, and
  p11-kit then reads every module file there. A module file can name a library to load or, with
  `remote: |command`, a command p11-kit runs itself: library validation does not stop that, and no
  environment variable moves these paths (`P11_KIT_NO_USER_CONFIG=1` covers only
  `~/.config/pkcs11/`). So the build overwrites these paths in the bundled `libp11-kit` with
  `/var/empty/none`, a path that does not exist inside the root-owned, empty `/var/empty` (#179):
  the bundled p11-kit reads no file of the Homebrew prefix. The build fails when any Homebrew path is
  left in it, and CI checks with module files in the runner's Homebrew prefix that Homebrew's
  openconnect runs them and the bundled one does not. PassTunnel also passes no option that uses
  PKCS#11 (no client certificate, key or token) and sets `P11_KIT_NO_USER_CONFIG=1`.
- **GnuTLS's configuration file** (`/opt/homebrew/etc/gnutls/config`, which may also name a PKCS#11
  provider library to load) and **its CA store** (`/opt/homebrew/etc/gnutls/cert.pem`): overwritten
  with `/var/empty/none` in the bundled `libgnutls` the same way. On top of that the helper starts the
  tool with `GNUTLS_SYSTEM_PRIORITY_FILE=/dev/null`, and the CA store would not be used anyway (pin,
  or `--no-system-trust` with the system bundle).
- **GnuTLS's `/etc/gnutls/pkcs11.conf`** (a fixed path, not under the Homebrew prefix, which can
  name PKCS#11 provider libraries): left as it is. Only root can create it in `/etc`, so it gives
  no one more than they have, and library validation refuses a provider library not signed by Apple
  or with the project's Team ID.
- **Message catalogs:** not opened (`LC_ALL=C`).
- **A web browser for single sign-on** (`/usr/bin/open`): never started by the root run, which
  never signs in; see "No single sign-on" above for the sign-in run.
- **Environment:** no proxy (`https_proxy`), TLS key log (`SSLKEYLOGFILE`) or debug variables reach
  either run.

### Host checks are refused

Some servers require the client to download and run a host scan (Cisco Secure Desktop; in later
phases GlobalProtect's HIP report and Pulse's Host Checker). PassTunnel never runs such code,
neither the server's nor the scripts Homebrew ships for it: openconnect refuses the request when it
is not given a wrapper, PassTunnel never gives one, and the connection fails saying the server
requires a host scan PassTunnel does not run (`host_scan_required`). It is not retried.

### Linux

Since #187 (not in any release: the Linux packages are not published yet).

- **The distribution's `openconnect`, 9.01 or later**, from fixed paths (`/usr/sbin/openconnect`,
  `/usr/bin/openconnect`, never `PATH`) checked like the other tools: every directory of its real path
  and the file itself root's and not writable by anyone else; not pinned by hash, so trust rests on the
  package manager, as for `openvpn` and `openfortivpn`. Older versions (Ubuntu 22.04's 8.20) are refused,
  naming the minimum; the same check runs before your sign-in, before the one-time code is used. Its
  vulnerabilities apply as root while a session runs. Its environment is fixed (`PATH`, `LC_ALL=C`,
  `P11_KIT_NO_USER_CONFIG=1`); the distribution's GnuTLS and p11-kit configuration, root's files, applies.
- **Sign-in as you**, as on the Mac, with the distribution's CA bundle (checked as a tool is) when the
  profile has no pin. `no-external-auth` is used when that `openconnect` lists it (9.10 and later); 9.01
  offers the server a browser sign-in, which then opens with `xdg-open` as you, and the run fails.
- **The hook is `passtunneld` itself**, through a link in the root-only session directory, acting as the hook
  only when it was started under that name. It proves its session from `/proc` and the daemon's root-only
  files (its parent is the session's recorded `openconnect`, or the shell `/bin/sh` is, whose parent is; that
  `openconnect` works in the session directory; the recorded boot, start time and executable match), checks
  every value as on the Mac, and runs iproute2's `ip` from a fixed, checked path with argument lists, at most
  10 seconds each. It reads the routing table straight from the kernel (rtnetlink), not from a tool's
  output. DNS goes through the same code, backends and records as OpenVPN's on Linux (systemd-resolved per
  link, resolvconf, or a marked block in `/etc/resolv.conf`); with the latter two, every name goes through
  a tunnel that has DNS (they cannot send only some domains there). A full tunnel without IPv6 gets
  `unreachable` routes for both halves of IPv6. A revert names the route's next hop, so the kernel never
  deletes another route of that destination.
- **Supervision** as for the other tools, and what the hook recorded is reverted by the daemon after a
  kill and by the next daemon after a crash; a session the daemon cannot restore keeps only its records
  (the cookie goes) and blocks a new start of that profile until it is restored.
- **What is not verified yet**: the whole path against a real server and tunnel (#188). The tests run the
  hook's logic against a simulated system, and CI starts the distribution's `openconnect` without a tunnel.
  See [docs/LINUX.md](docs/LINUX.md#cisco-anyconnect).

## Secrets and files

- **Keychain.** Passwords and TOTP secrets are stored only in the macOS Keychain as generic
  passwords (service `PassTunnel`, accounts `<profile-id>/password` and `<profile-id>/totp`) in
  your login keychain. They are not synced to iCloud Keychain, but Migration Assistant and backups
  carry them to another Mac together with the rest of the login keychain (items encrypted with
  [Confirm with Touch ID](#confirm-with-touch-id-secure-enclave) move too, but cannot be decrypted
  there). The app uses the Security framework directly. App and CLI are the same signed binary, so
  the Keychain does not prompt between them.
- **Every write replaces the item.** An existing item may have been created by another app, with
  an access list that lets that app read it, so PassTunnel never updates an item in place: it
  deletes it and adds a new one, which gets the default access list (only PassTunnel may read it
  without asking). If the old item cannot be deleted, nothing is written and PassTunnel says so. If
  the new item cannot be added, the previous value (read before the delete) is added back the same
  way, as a new item.
- **A new profile starts without Keychain items.** Items still stored under its ID (left by a
  profile removed outside the app, or from before a reinstall) are deleted when the profile is
  created, so it never uses a secret you did not give it.
- **Uninstalling** keeps the Keychain items, unless you use `brew uninstall --zap --cask passtunnel`,
  which deletes them. The [README's FAQ](README.md#faq) has the manual steps.
- **Secrets go to the helper only at connect time**, over the code-signature-checked XPC
  connection, and are written only into the root-only run directory, which is removed when the
  tunnel stops. OpenVPN runs with `--auth-nocache`.
- **Support folder.** `~/Library/Application Support/PassTunnel` (`0700`) holds `config.json`
  (preferences) and one folder per profile with `profile.json`, `config.ovpn` and `vpn.log`.
  Files are written with `0600`. These files contain no VPN passwords or TOTP secrets, but
  `config.ovpn` may contain certificates and private keys from your VPN provider, and proxy
  credentials (see below).
- **Credentials in an imported `.ovpn`.** A user name and password in an inline `<auth-user-pass>`
  block are not stored with the configuration: on import the user name moves to the profile and the
  password to the Keychain, and the stored `config.ovpn` keeps a bare `auth-user-pass`. Choosing a
  configuration in the editor fills empty Sign-in fields with them instead, saved with the profile. A
  configuration imported by an earlier version keeps its block until you import it again (sharing
  removes it anyway). Proxy credentials (`<http-proxy-user-pass>`, also embedded from a referenced
  file on import) stay in the local `config.ovpn`.
- **Share files (`.passtunnel`) never contain credentials.** No password, no TOTP secret, no user
  name, and no `<auth-user-pass>` or `<http-proxy-user-pass>` block: both are removed from the
  configuration on export. They do contain the connection settings and, for OpenVPN, the
  configuration file with any embedded certificates and keys, so they are written with `0600` and
  should be shared like the original `.ovpn`. On import, only `config.ovpn` is taken from the file,
  it must already be self-contained, and an `<auth-user-pass>` block (the sender's sign-in, in a file
  exported by an earlier version) is dropped.
- **Clipboard.** A copied code, or password + code, is put on the clipboard for this Mac only (not
  Universal Clipboard), marked concealed and transient so clipboard managers skip it, and cleared
  after 1 minute (30 seconds or 2 minutes in Settings → General → Clear copied code) unless
  something else was copied meanwhile. `passtunnel code -c` does the same: it leaves a small
  detached process behind that clears the clipboard.
- **Auto-type** (off by default) needs Accessibility permission, which is requested only when you
  enable it. Global shortcuts use Carbon hotkeys and do not need any permission.
- **Scan QR on screen** (macOS 14 and later) uses the system's content picker: you pick the window or
  display, and that pick is all PassTunnel can capture, without Screen Recording permission. Only if
  macOS does not let it capture the pick does PassTunnel offer, after saying why, one picture of each
  display, which needs Screen Recording permission (macOS asks the first time). The pictures are read
  for a QR code in memory and never saved or sent.
- **No test hooks in releases.** `passtunnel debug drop`, which ends a connection as if the server
  had (and which any process in your login session could trigger through the running app), exists
  only in debug builds.

## Confirm with Touch ID (Secure Enclave)

Off by default, per profile (`require_auth`: `off`, `connect`, `always`; on a Mac without Touch ID the
setting is called "Confirm with your password", and the login password is the confirmation). The profile
editor has one switch, "Require Touch ID before connecting" ("Require your Mac password before connecting"
without Touch ID): on is `always`; `connect` is set with
`passtunnel set ID require_auth=connect` and shows in the editor as on, with a footnote. Without it, anyone using your
Mac while you are logged in can connect with one click, because the app may read its own Keychain items
without asking.

**What is encrypted.** With the option on, PassTunnel creates a P-256 key-agreement key for the profile
in the Mac's **Secure Enclave** (CryptoKit `SecureEnclave.P256.KeyAgreement`) with the access control
`privateKeyUsage` + `userPresence`: the private key never leaves the Secure Enclave, and the Secure
Enclave uses it only after Touch ID or the login password (or an Apple Watch, where set up). The
Keychain item `<profile-id>/sekey` holds only the key's wrapped blob (`dataRepresentation`, usable by
this Mac's Secure Enclave alone) and its public key. The protected secrets replace their plain Keychain
items with an envelope (`ptse1:` + Base64): a fresh ephemeral P-256 key, ECDH with the profile's public
key, HKDF-SHA256 (salt: both public keys, info `PassTunnel secret v1`) and AES-256-GCM with the item's
account name as authenticated data, so an envelope cannot be moved to another item.

- `connect`: the saved password is encrypted; the TOTP secret stays readable so live codes show
  without a prompt. A profile without a saved password gets its TOTP secret encrypted instead
  (otherwise the option would protect nothing), and its code is hidden until you confirm.
- `always`: the password and the TOTP secret are encrypted; codes are hidden until you confirm.

**Decrypting is the confirmation.** There is no separate yes/no check that could be skipped: without
the Secure Enclave operation, PassTunnel has no password or TOTP secret to send. A cancelled or failed
prompt means no connection; nothing falls back to a plain copy. Saving a new secret to a protected
profile only needs the public key (no prompt). Before PassTunnel encrypts to the public key in
`<profile-id>/sekey`, and again before and after it unlocks the key, it checks that the record's public
key belongs to the Secure Enclave key in the same record: a record replaced by another app (to have new
secrets encrypted to its own key) is never used, and PassTunnel stops with an error asking you to set
the profile up again. Turning the option off, or lowering `always` to
`connect`, needs a successful decrypt; the encrypted items are then rewritten in plain text and the key
item is deleted. Deleting the profile deletes its key item.

**Reuse.** After one confirmation, the decrypted values of that profile stay in the app's memory for
the "Ask again after" time (Settings → General → Security: 1, 5 or 15 minutes). Sleep and screen lock
end it early. LocalAuthentication's own `touchIDAuthenticationAllowableReuseDuration` is left at 0: it
would let a recent Touch ID unlock of the Mac count as the confirmation, which is exactly the situation
this option is for. A connected session keeps its
decrypted secrets in memory so an automatic reconnect after a drop needs no prompt; they are
overwritten (best effort) when you disconnect or the session ends. After the Mac was asleep, a
dropped protected profile is not reconnected on its own: a notification asks you to reconnect. In the
same way, "Connect at login" never asks at login: a protected profile set to connect at login gets a
notification you click to connect (and confirm). Each
CLI command is a separate process and asks every time it needs a protected secret; `passtunnel mcp`
is one process for as long as the MCP client runs it, so the window (and its end on sleep and
screen lock) applies within it.

**Bound to the server.** The connect prompt names the server the secrets go to ("connect to “Acme VPN”
(vpn.example.com)"; for OpenVPN the first `remote` of the configuration, read exactly as OpenVPN reads
it, followed by "+2 more" when the configuration lists other servers OpenVPN may use). What you
confirm is bound to the profile's destination at that moment: for OpenVPN the exact contents of `config.ovpn` (servers, CA,
proxy, everything the helper runs), for FortiGate the host, port and trusted certificate. When that
changes, in the editor, with `passtunnel set` or by editing the files, the decrypted values held for the
reuse window and for a connected session are dropped. The next connect asks again and names the new
server, and an automatic reconnect (after a drop or a failed health check) does not happen: a
notification "“Acme VPN” was not reconnected" asks you to connect and confirm again. For OpenVPN the
helper also refuses a `config.ovpn` that is not the one the app checked, so a file replaced at the last
moment is not used either: the connect fails and asks you to connect again.

**Limits.**
- It needs a Secure Enclave (Apple silicon or a T2 Mac). Without one (e.g. a virtual machine), the
  option cannot be turned on; it never silently degrades to plain storage.
- Secure Enclave keys do not move to another Mac or survive erasing this one. After migrating, the
  encrypted items cannot be decrypted; PassTunnel says so, removes them and asks you to enter the
  password or TOTP secret again.
- `userPresence` is used (not `biometryCurrentSet`), so adding a fingerprint does not lock you out and
  the password fallback always works.
- A setting changed outside PassTunnel (e.g. `require_auth` edited in `profile.json`) is reconciled
  safely: plain secrets the setting protects are encrypted on the app's next reload or before the CLI
  uses them (no prompt needed); encrypted secrets of a profile set to `off` stay encrypted (using them
  asks) until the setting is lowered in the app or with `passtunnel set`, which decrypts them. Without a
  Secure Enclave such a hand-edited setting cannot be applied and the secrets stay plain.
- It protects against other people at your unlocked Mac and against other processes or apps reading
  the Keychain items (they get ciphertext). It does **not** protect against malware running as you
  that waits for you to confirm, drives the prompt you then approve, or reads the app's memory while a
  session or the reuse window holds the decrypted values. The profile's files (`profile.json`,
  `config.ovpn`) are not protected either: editing them does not decrypt anything and does not
  redirect secrets you already confirmed, but someone with your account can delete the items or the
  profile.

## Network connections

PassTunnel has no servers of its own. Apart from the VPN itself, the app and the `passtunnel`
command connect only to:

- **Your VPN servers**, through the bundled `openvpn` and `openfortivpn`. Your user name, password and
  one-time code go only there.
- **Hosts you set up:** a profile's health check host while it is connected, and the gateway you
  entered when you click *Fetch fingerprint* (a TLS handshake that stops once the certificate is seen).
- **The FortiGate gateway, after it rejected a sign-in,** to read its clock: one-time codes are worked
  out from the clock, so a Mac whose clock is off sends codes the server refuses. Only after a
  rejection, never at launch, and only to the gateway the VPN just signed in to: one `HEAD /` request
  over TLS, which reads the `Date` header of the answer. The certificate must be the profile's
  trusted certificate or one the system trusts for that name, as openfortivpn requires; otherwise the
  connection ends before anything is sent. The request has no user name, password, code or cookie,
  and the check gives up after 5 seconds. OpenVPN servers are never asked (they tell no reliable time).
- **Apple's time server (`time.apple.com`), only when you ask:** `passtunnel diagnose --check-clock`
  or the MCP tool `diagnose` with `check_clock`. One SNTP request
  that carries no information about your Mac (not even its time: a random number takes its place),
  and an answer that does not echo that number is ignored. On Linux the NTP server the system is set
  up with is asked instead, and the gateway is never asked.
- **GitHub, for updates** (below).

The last clock measurement of a profile is kept in its folder (`clock.json`, `0600`): the offset in
seconds, the host asked and when.

## Updates

- **App updates** come through Sparkle from the feed on the GitHub releases. The feed
  (`appcast.xml`) and every update archive are signed with the project's EdDSA key. The app refuses
  a feed without a valid signature (`SURequireSignedFeed`) and checks an archive's signature before
  unpacking it (`SUVerifyUpdateBeforeExtraction`). An update is installed only when you click
  Install.
- **Releases** are uploaded to a draft release and published only once every file is attached. The
  release tag is signed with a dedicated SSH key (ed25519) whose public half is in
  [`.github/allowed_signers`](.github/allowed_signers); the release workflow refuses to push a tag
  whose signature does not verify, and anyone can check one with
  `git -c gpg.ssh.allowedSignersFile=.github/allowed_signers tag -v vX.Y.Z` (tags up to 1.5.0 are
  not signed with it; see [docs/RELEASING.md](docs/RELEASING.md#signed-tags)). The bundled `openvpn`,
  `openfortivpn`, `openconnect` and their libraries come in pinned versions (`scripts/release.env`); a release
  build stops when Homebrew provides any other version. Details: [docs/RELEASING.md](docs/RELEASING.md).
- **Replacing the helper.** Registering the helper points the root daemon at the copy of PassTunnel
  that registers it, so this is limited:
  - After an app update, the app replaces the running helper on its own only when it runs from
    `/Applications` (symlinks resolved; not `~/Applications`, where any process of yours can put a
    copy) and only when the running helper is an older build. The helper reports the build number of
    the app it was started from in every reply, so a newer helper is never downgraded on its own.
  - `passtunnel helper install` and the `--install-helper` / `--update-helper` launch arguments can
    be used by any local process. A copy outside `/Applications` refuses them, and replacing a running
    helper this way always asks you first.
  - Replacing a newer helper with an older one (Settings → Helper → Update Helper, or the above) shows
    a separate warning first.
  - Removing the helper on request from outside the app always asks.

## Cryptography

PassTunnel does not implement cryptographic primitives. It uses the system's (CryptoKit, Security,
Network.framework), swift-crypto on Linux, the bundled tools' OpenSSL and Sparkle's.

| Use | What | Where |
|---|---|---|
| VPN tunnels | TLS and the data channel are done by the bundled `openvpn` and `openfortivpn` with their OpenSSL. OpenVPN's control channel uses TLS 1.2 or later: the helper passes `--tls-version-min 1.2` after the configuration (1.3 when the configuration asks for it), and the [sanitizer](#openvpn-configuration-sanitizer) refuses a configuration that sets `tls-version-min` or `tls-version-max` below 1.2, lowers OpenSSL's security level to 0 (`@SECLEVEL=0` in `tls-cipher`, `tls-cert-profile insecure`) or selects suites without encryption or authentication. Within that, the configuration's cipher settings and OpenSSL's defaults decide. For FortiGate the helper writes none of the TLS options, and openfortivpn disables insecure protocols unless asked with `--insecure-ssl`, which PassTunnel never passes. The tools verify the gateway certificate against the system CA bundle (`/etc/ssl/cert.pem`, fixed by the helper) or a trusted SHA-256 certificate digest in the profile | [How OpenVPN is started](#how-openvpn-is-started), [How FortiGate is started](#how-fortigate-is-started) |
| Gateway clock probe, *Fetch fingerprint* | TLS through Network.framework with the system's default protocol versions (the code sets none). The clock probe accepts the certificate only when its SHA-256 digest is the profile's trusted one or the system trusts it for that name, and sends no credentials, user name or cookie. *Fetch fingerprint* trusts nothing: it aborts the handshake right after reading the digest, which you confirm before saving | [Network connections](#network-connections) |
| App updates | HTTPS download of the feed and archives from GitHub (Sparkle's URLSession under App Transport Security, which is on with no exceptions in `Info.plist`, so TLS 1.2 or later); the feed and each archive are also signed with an EdDSA (Ed25519) key and refused without a valid signature | [Updates](#updates) |
| Releases | Developer ID code signatures with the hardened runtime, notarization, build provenance attestations (Sigstore), release tags signed with an Ed25519 SSH key (`.github/allowed_signers`) | [docs/RELEASING.md](docs/RELEASING.md) |
| Helper trust | Code-signing requirements (Team ID) and SHA-256 cdhashes of the bundled tools and libraries; SHA-256 of `config.ovpn` | [Which programs it runs](#which-programs-it-runs) |
| Confirm with Touch ID | P-256 key agreement key in the Secure Enclave, ephemeral P-256 ECDH, HKDF-SHA256, AES-256-GCM with the account name as authenticated data | [Confirm with Touch ID](#confirm-with-touch-id-secure-enclave) |
| Secrets on Linux | Desktop keyring, `systemd-creds`, or a file sealed with scrypt (N = 2^17, r = 8, p = 1) and AES-256-GCM | [docs/LINUX.md](docs/LINUX.md#secrets) |
| One-time codes | HMAC-SHA-1 (the default), HMAC-SHA-256 or HMAC-SHA-512 as set in the profile or the `otpauth://` link, RFC 6238 | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#model-passtunnelkitmodelswift) |

**No algorithm with known serious weaknesses protects PassTunnel's own data or channels.** HMAC-SHA-1
appears only as the TOTP default because most servers and authenticator apps expect it (RFC 6238); it
is not affected by the collision attacks against SHA-1, and the profile can use SHA-256 or SHA-512
where the server supports them. There is no CBC mode, MD5 or SSL in PassTunnel's code.

**Algorithm agility.** Choices that can be broken are not hard-wired in a way that needs a rewrite:
the TOTP algorithm, digits and period are per profile; the VPN ciphers and TLS settings belong to the
tools and the configuration (above the TLS 1.2 floor), and bundled tools are updated like any release; secret envelopes carry
a version prefix (`ptse1:`), and the Linux file store a version and a KDF identifier, so a stronger
format can be introduced and old data read; a new hash for pins would be a new release of the
helper.

**Where keys and credentials are kept.** Passwords, TOTP secrets and Secure Enclave key records are
in the Keychain (or the Linux secret store), separate from `profile.json`, `config.json` and logs,
and can be replaced at any time in the app or with `passtunnel secret` without rebuilding anything.
Credentials passed to the tools go through root-owned files that are deleted when the tunnel stops.
The release keys (Developer ID, notarization, Sparkle, tag signing) are kept out of the repository: in the
protected GitHub environment `release` and on the maintainer's Mac
([docs/RELEASING.md](docs/RELEASING.md#setup)).

## MCP server and automation

`passtunnel mcp` lets an AI assistant (an MCP client such as Claude Code or Claude Desktop) use
PassTunnel. Treat it like this: **the MCP client gets the same power as running the `passtunnel`
command yourself, limited further by the read-only default.**

- **What it is.** The same signed binary as the app, started by the MCP client as a child process
  under your user, speaking JSON-RPC over its standard input and output. It opens no port and no
  socket; only the process that started it can talk to it. It adds no privilege: any program
  running as you can already run `passtunnel`.
- **Read-only by default.** Without `--allow-connect` the tools are `list_profiles`, `get_status`,
  `get_logs` and `diagnose`. `connect` and `disconnect` are listed and callable only when the
  server was started with `passtunnel mcp --allow-connect`. No tool creates, changes or deletes a
  profile or a secret, in any mode.
- **No secrets in any answer.** No tool returns a password, a TOTP secret, a current one-time code,
  a private key or the contents of a configuration file; there is deliberately no tool for codes.
  `diagnose` says *whether* a password or TOTP secret is saved and names configuration problems by
  directive, never by value. Tests check every tool's output for a profile with a saved password and
  TOTP secret.
- **Logs.** The VPN tools receive credentials through root-owned files, not on the command line,
  and do not log them or key material at the verbosity the helper allows: OpenVPN always runs with
  `--verb` at most 4, whatever the configuration says, and openfortivpn runs at its default level
  (the helper passes no `-v`, and the configuration it writes has no setting for it or for pppd's
  debug output). `get_logs` adds two filters. It leaves out lines that look like key material or
  packet dumps (OpenVPN `TLS: tls_…` traces and any line with a run of 32 or more hex digits, also
  when split into groups by spaces or colons; openfortivpn's `--trusted-cert <digest>` hint is kept,
  as the gateway certificate's digest is public and explains the failure), and it replaces the saved password and TOTP secret,
  `auth-token` values, OpenVPN challenge responses (`CRV1:`, `SCRV1:`, `RV1:`) and
  `password=…` / `otp: …`-style values with `<redacted>`. The saved password and TOTP secret are
  masked by value only when they are stored in plain text; one protected by Confirm with Touch ID
  is not decrypted for this, so only the keyword and pattern rules apply to it. It returns at most
  500 lines; when the log is longer than the 256 KB it reads, the first, partial line is dropped.
  Log lines do contain server names, your user name and IP addresses. With `source: "activity"` it
  returns PassTunnel's own activity log instead (`profiles/<id>/activity.jsonl`, mode 0600: connecting,
  code waits, what was sent, sign-in accepted or rejected, drops), which never holds a password and
  keeps a one-time code as at most its first three digits, for the app; `get_logs` and
  `passtunnel log --activity` leave those digits out and pass the server's reply through the same
  redaction.
- **Strict arguments.** `profile_id` must be a valid profile id (the same pattern profile folders
  use: lowercase letters, digits and single dashes); unknown arguments, wrong types and
  out-of-range numbers are refused before anything is read.
- **Touch ID still applies.** Connecting a profile with *Confirm with Touch ID* shows the same
  prompt as the app, naming the server, on your Mac: nothing is decrypted or sent until you confirm.
  If no prompt can be shown (for example in an SSH session, or with `passtunnel mcp
  --no-auth-prompt`), the call fails with `auth_unavailable`. A confirmation counts only for the
  server settings the profile had at that moment, exactly as in the app. The MCP server is one
  long-running process, so the [reuse window](#confirm-with-touch-id-secure-enclave) applies to it
  as to the app: a second `connect` of the same profile within the "Ask again after" time (Settings
  → General → Security; 1 minute is the shortest, it cannot be turned off) does not prompt again.
  Sleep and screen lock end the window early, in the MCP server as in the app. Profiles that ask for a
  user name, password or code on every connect cannot be connected through MCP, and there is no
  way to override the check for another VPN that takes all traffic.
- **Prompt injection.** An assistant follows text it reads: a web page, a file, an issue comment or
  a log line can contain instructions. With `--allow-connect`, such instructions could make the
  assistant connect or disconnect a profile, which changes routes and DNS for the whole Mac or
  ends a session. Keep the server read-only unless you need it, turn on Confirm with Touch ID for
  profiles an assistant may connect, and keep your client's per-tool approval on for `connect`
  and `disconnect`.
- **Where the answers go.** Whatever a tool returns (profile names, user names, server names, IP
  addresses, log lines) goes to the assistant and its provider.

For scripts, `--no-input` and `--no-auth-prompt` turn a prompt into an error (`input_required`,
`auth_unavailable`) instead of waiting for an answer that will not come. Neither skips a check:
there is no option that connects a protected profile without the confirmation.

## What is not protected

PassTunnel cannot defend against an attacker who already controls your account or your Mac:

- **A local administrator or root** can read or replace anything, including the app, the helper,
  your files and, with your login password, your Keychain.
- **Malware running as your user** can read your profile folder (configs and embedded keys) and
  logs, can ask the Keychain for PassTunnel's items (macOS shows a consent prompt because the
  requester is not PassTunnel; if you allow it, the secrets are disclosed), and can watch your
  screen or clipboard, where codes appear when you copy (for 1 minute by default) or auto-type
  them. It can also run the `passtunnel` command, the same signed binary as the app, so the
  Keychain and the helper treat it like the app: it reads secrets that are not protected by Confirm
  with Touch ID without any prompt, and it can change a profile's settings and connect it, which
  sends your password to the server it chose. [Confirm with Touch ID](#confirm-with-touch-id-secure-enclave)
  prevents this for the secrets it protects: using them asks, the prompt names the server, and a
  changed destination always asks again.
- **Other accounts on this Mac.** Every local account can use the helper. Sessions are kept apart (a
  user can only stop or see their own), but a VPN changes routes and DNS for the whole Mac: any
  local account can start a full-tunnel profile whose routes and DNS then apply to every logged-in
  user. This is how a VPN client works; PassTunnel does not restrict it further.
- **Older copies of PassTunnel.** Version 1.0.0 lacks the checks under [Updates](#updates) and
  the suspended start of the tools. A copy of it can still register its own helper in place of a
  newer one, without asking. Delete old copies, including disk images and downloads.
- **The helper's build number** is read from the `Info.plist` of the app bundle it was started from.
  Whoever can change that file can make a helper claim another build. The only effect is on
  replacing it: a helper that claims to be newer is not replaced automatically (Settings → Helper
  still offers to, with the warning).
- **A TOTP secret on the same machine as your password** turns two factors into something closer
  to one: anyone who gets your unlocked Mac and Keychain has both ([Confirm with Touch
  ID](#confirm-with-touch-id-secure-enclave) adds Touch ID or your password in front of them). This is the trade-off PassTunnel
  makes for convenience. If your organization requires the second factor on a separate device, use
  *Ask each time* for the one-time code.
- **The VPN configuration itself.** The sanitizer stops configs from running code or touching files
  as root, but a legitimate config still decides where your traffic and DNS go. Only import
  configurations from sources you trust.
- **The bundled tools.** `openvpn`, `openfortivpn` and their libraries run as root, and their own
  vulnerabilities apply. Keep PassTunnel updated to get their fixes.
- **Builds you sign yourself.** The helper trusts the Team ID compiled into it. A build signed with
  a different Team ID has its own trust root, chosen by whoever built it.
