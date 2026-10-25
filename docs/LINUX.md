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
| Run root | `/run/passtunnel/` (0711, root): `<uid>/<id>/` per session as on the Mac (`config.ovpn` or `openfortivpn.conf`, `auth`, `state`, `mgmt.sock`) |
| Daemon socket | `/run/passtunnel/daemon.sock` (0666, root; access is decided per request, below) |
| Binaries | `/usr/bin/passtunnel`, `/usr/sbin/passtunneld` from the packages; `/usr/local/…` from the tarball |

`PT.profilesSubpath`, `PT.helperRunRoot`, the `sun_path` limit (108 bytes on Linux) and the CA bundle
become platform values. The CA bundle is the first of `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem` that exists (`FortiConfig` takes it as a
parameter).

## The daemon protocol

One request per connection, one JSON object per line, at most 64 KiB:

- `{"op":"hello"}` → `{"protocol":3,"build":"<hex SHA-256 of passtunneld>","build_number":N}`. The
  client's `ensureCompatible()` uses it as the `version` and `build` XPC calls are used on the Mac.
- `{"op":"perform","request":<HelperRequest>}` → `<HelperResponse>`. Request decoding is
  `HelperCore.decodeRequest`, unchanged, and so are the request types and `PT.helperProtocolVersion`.

On the client side this is a second `HelperClienting` (`UnixSocketHelperClient`); `ConnectionManager`
needs nothing else from the transport. A Linux `HelperInspecting` reports the daemon as not
installed (no socket), unavailable (no answer within 5 s) or current/outdated (from `hello`).

## Daemon security rules

The macOS rules apply where they make sense; these replace the ones built on code signing.

- **Who is calling.** `SO_PEERCRED` on the accepted socket gives the uid (and `SO_PEERPIDFD` the
  process, where the kernel has it). Every request acts for that uid only: `SessionPolicy` is keyed by
  (uid, profile ID) as on the Mac, so users never see or stop each other's sessions.
- **Who may connect.** Phase 2: root, and members of the group `passtunnel` (supplementary groups of
  the uid from the user database). Phase 3 adds polkit: the action
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
  openvpn 2.6.0 or openfortivpn 1.21 are refused with a clear message.
- **Spawning.** `posix_spawn` of the checked path (no suspended start: there is no signature to
  verify), new process group, stdin `/dev/null`, output to the session log, default signals, a fixed
  environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`). Unlike the Mac, `OPENSSL_CONF` and
  the CA variables are **not** overridden: the distribution's OpenSSL configuration (for example
  system-wide crypto policies) applies.
- **OpenVPN** runs with the Mac's fixed flags (`--management <run>/mgmt.sock unix`,
  `--management-client-user`, `--auth-nocache`, `--remap-usr1 SIGTERM`, `--connect-retry-max 3`,
  capped `--verb`), the sanitized config (`OVPNSanitizer`, unchanged) and the DNS hook below.
- **FortiGate** runs openfortivpn with the config `FortiConfig.render` writes (typed fields only,
  `checkRendered` as on the Mac), the Linux CA bundle, and its own DNS handling switched off; the
  daemon applies DNS (below).
- **Supervision.** One waiter per child (`waitpid` on a thread, or a pidfd); `stop` sends SIGTERM,
  then SIGKILL after 5 s; at most `SessionPolicy.maxSessionsPerUser` sessions per user; the session
  log is capped with `HelperCore.capLog`. On exit the run directory is removed and DNS reverted.
  There is no adoption: a starting daemon stops tools recorded by a previous instance and cleans up
  (under systemd `KillMode=control-group` has already stopped them).
- **Sandbox** (Phase 3 unit): `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID
  CAP_CHOWN CAP_DAC_OVERRIDE CAP_KILL` (trimmed to what testing shows openvpn and pppd need),
  `DeviceAllow=/dev/net/tun` and `/dev/ppp`, `ProtectSystem=strict` with the paths DNS needs
  writable, `ProtectHome=read-only`, `PrivateTmp`, `RuntimeDirectory=passtunnel`.

## DNS

Profiles never run scripts (the sanitizer removes them); DNS comes from what the server pushes.

- OpenVPN 2.7: `--dns-updown` names the daemon's hook; 2.6: `--script-security 2` with `--up` and
  `--down` naming the same hook. The hook is `passtunneld dns-hook`, the daemon's own root-owned
  executable (the daemon refuses to start when its executable is writable by anyone but root). It
  reads the pushed servers and domains from the environment OpenVPN gives it (2.7 `dns_*`, 2.6
  `foreign_option_*`) and applies them for the tunnel interface.
- FortiGate: the daemon reads the servers and search domains openfortivpn logs once the tunnel is up
  and applies them for the `ppp` interface the same way, when the profile has `set_dns`.
- Applying: when systemd-resolved manages `/etc/resolv.conf`, per link (servers; `~domain` routing
  domains for split DNS; the default route only for a full tunnel), reverted when the link goes.
  Otherwise `resolvconf` when present, otherwise a marked block in `/etc/resolv.conf`, written
  atomically and removed on teardown. A failed DNS set-up is `PTError.setupFailed`, as on the Mac.

## Client side

- **Routes.** The "another VPN already takes all traffic" check reads the main routing table and the
  policy rules (rtnetlink, or `/proc/net/route` plus `ip -j rule`): `default`, `0/1` or `128/1`
  through a VPN-type interface (`tun`, `tap`, `ppp`, `wg`, `tailscale`, …) that is not one of
  PassTunnel's sessions refuses the connect (`other_vpn_active`; `--force` skips it).
- **Log parsing.** `VPNLog` learns the Linux lines: the tunnel device ("TUN/TAP device tun0 opened",
  "Interface ppp0 is UP"), addresses, and route/DNS failures as OpenVPN logs them through netlink on
  Linux, so `setupProblem` and the warnings behave as on the Mac. Tests use recorded log lines with
  example hosts only.
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
