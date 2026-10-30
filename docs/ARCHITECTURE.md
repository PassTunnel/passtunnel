# PassTunnel architecture

PassTunnel is a macOS app (13+) that connects VPNs **without ever typing a one-time code**: it keeps
TOTP secrets in the Keychain and fills the code (and password) automatically when it connects.
Supported VPN types: OpenVPN, FortiGate SSL VPN (openfortivpn). More types = new backend; Cisco
AnyConnect (openconnect) is being added: Core connects it on macOS 15.4 and later (#184), the CLI and MCP
tools (#185), the app (#186) and Linux (#187) handle it ([below](#cisco-anyconnect-backend)).

```
PassTunnel.app/Contents/
  MacOS/PassTunnel              app + CLI (same binary; `passtunnel` symlink → CLI mode)
  MacOS/PassTunnelHelper        privileged helper (root, launched by launchd via SMAppService)
  Library/LaunchDaemons/com.furkanprlk.passtunnel.helper.plist
  Resources/bin/openvpn, openfortivpn    bundled, signed with the app's Team ID
  Resources/bin/openconnect     bundled the same way for Cisco AnyConnect (needs macOS 15.4); run by the user for the
                                sign-in (`AnyConnectSignIn`, #184) and by the helper for the tunnel (#182)
  Frameworks/*.dylib            their dependencies (OpenSSL, LZO, LZ4, pkcs11-helper; openconnect's:
                                GnuTLS, nettle, GMP, p11-kit, libtasn1, libidn2, libunistring,
                                libintl, stoken, libtomcrypt, libtommath)
  Frameworks/Sparkle.framework  app updates (Autoupdate, Updater.app, XPCServices signed inside-out)
```

`build-app.sh` deletes the build-machine rpaths SwiftPM leaves in both executables: the app keeps only
`@executable_path/../Frameworks` (Sparkle), the helper none (the Swift runtime is loaded from
`/usr/lib/swift`). It fails when an executable has any other rpath or an `@rpath` load that does not
resolve inside the bundle. `bundle-tools.sh` bundles only the Homebrew versions pinned in
`scripts/release.env` (docs/RELEASING.md). The tools load their dylibs by
`@executable_path/../../Frameworks/<name>`, the dylibs each other by `@loader_path/<name>` (no
`LC_RPATH`), so the tools and dylibs can be copied elsewhere with the same relative layout (the helper
does, `ToolStager`). `build-app.sh` signs the tools and their dylibs **before**
compiling: it writes the cdhash of every architecture of `openvpn`, `openfortivpn`, `openconnect` and
`dns-updown` (`generatedCDHashes`) and of every `Contents/Frameworks/*.dylib` (`generatedLibraryCDHashes`)
(`codesign -dvvv`, `CDHash=`) to `Sources/PassTunnelShared/PinnedTools+Generated.swift` (removed on exit,
never committed) and builds with `-Xswiftc -DPASSTUNNEL_TOOL_PINS`, so the helper carries them in its own
signed code (`PinnedTools`, below). The tools are not signed again afterwards (that would change the
cdhashes); the script checks that each bundled tool's and dylib's cdhashes are in the pins and in the
`PassTunnelHelper` binary, and a signed (non-ad-hoc) build fails when `openvpn`, `openfortivpn`,
`openconnect` or any bundled dylib has no pin (or there is no dylib at all).
A bundle without `dns-updown` pins an empty set for it, so the helper refuses any `dns-updown`.

**Minimum macOS of the tools.** Homebrew's bottles are built for the release runner's macOS
(`minos 26.0`), above the app's minimum (`LSMinimumSystemVersion`, 13.0). dyld does not refuse a binary
for that; it stops a tool at launch (`dyld[…]: Symbol not found: _x … (built for macOS 26.0 which is
newer than running OS)`, exit 134) when the tool or one of its dylibs imports a symbol the running macOS
lacks. So `bundle-tools.sh` ends with `scripts/check-tool-symbols.sh`: every symbol a bundled tool or
dylib imports from a macOS library (what dyld binds, `dyld_info -imports`: the chained fixups or bind
opcodes, plus `nm -m`'s undefined symbols; two-level namespace) must be in that library's list in
`scripts/system-symbols/<version>/` for the file's minimum, or the build fails. A tool's minimum is the
app's, or a later one in `TOOL_MINIMUMS` for a tool the app refuses below it (openconnect: 15.4, below);
a dylib's is the lowest of the tools that load it. Also refused: weak imports of macOS symbols unless
listed (`WEAK_IMPORTS`, empty), flat-namespace lookups, a macOS library loaded (not weakly) without a
list even when nothing is imported from it, a bundled dylib that re-exports a macOS library or symbol
(none does, also in the openconnect closure), and any bundled load path other than the layout above.
The lists are what each library and the libraries it re-exports export for `arm64` (libSystem with
`libsystem_c`, `libsystem_kernel`, …), taken once from older SDKs' stubs (`.tbd`), since the current
SDK's stubs say what exists now, not since when: 13.0 from the macOS 12.3 and 13.1 SDKs (Xcode 13.3
and 14.2; a symbol is listed when both export it, no 13.0 SDK being at hand), for `libSystem.B`,
`libresolv.9` and `libutil`, the only macOS libraries `openvpn` and `openfortivpn` load; 15.4 from the
macOS 15.4 SDK, for the ones the openconnect closure loads (`libSystem.B`, `libz.1`, `libxml2.2`,
`libiconv.2`, `libffi`, and the CoreFoundation, CoreServices, Kerberos, PCSC and Security
frameworks). `SOURCES` in each
version's directory names the SDKs and the stubs' checksums; `scripts/make-system-symbols.sh`
writes them again (docs/RELEASING.md, Bundled tools). CI's `Bundled tools on macOS 15` job also runs
each bundled tool with `--version` on the oldest arm64 runner.

At run time the same failure is recognized in the session log (`VPNLog.toolLoadFailure`): dyld's
line as the log's first (it comes before anything the tool writes; later lines can be a server's words,
which openfortivpn prints) and the tool gone. The connect then ends with `PTError.toolUnsupported` ("This VPN tool does not run on this
version of macOS (Symbol not found: _strchrnul). Check for a PassTunnel update.") and the failure
kind `tool_unsupported`, not the generic "could not be established". On the Mac, `diagnose` (CLI and
MCP) runs each tool of the app bundle with `--version` (`BundledTools`: as the user, not through the
helper, with an empty environment and no input, at most 10 s each, nothing contacted) and reports each
one's version or why it did not start (`tools`). A tool whose `HelperCore.Tool.minimumMacOS` is later
than the running macOS (openconnect below 15.4) is not run: it is reported `ok` with a `note` ("Not run:
it needs macOS 15.4 or later."), not as a failure.

## Targets

| Target | Owns | Depends on |
|---|---|---|
| `PassTunnelVPNConfig` | `OVPNSanitizer`, `FortiConfig`: the configurations the helper runs as root | — |
| `PassTunnelKit` | the portable logic (Foundation, CryptoKit and Security only; builds for macOS 13, iOS 17 and Linux): model, `PTError`, `JSONCoding`, `TOTP`, `OTPAuthURI`, `OTPComposer`, `OVPNAnalyzer`, `OVPNInliner`, `OVPNSkipRules`, `OVPNImportReport`, `ShareFile`, `UnsupportedProfile`, `UnknownProfileKeys`, `AnyConnectServer`, `Slug`, `ProfileFields`, `ProfileMerge`, `SecretEnvelope`, `HealthCheck` (parsing), `ClockOffset` (clock offset, HTTP dates) | VPNConfig (and swift-crypto on Linux) |
| `PassTunnelShared` | XPC protocol, request/response types, `HelperCore` (request decoding, path checks, tool environment; `HelperCore+DNSHook`: the Mac's DNS script wrapper and its record), `SessionPolicy`, `CodeSignature`, `Spawner` (verified, suspended launch), `PinnedTools`, `ToolStager` (root-owned copy of the tools and their dylibs), `HelperBuild`, identifiers | VPNConfig (and swift-crypto on Linux) |
| `PassTunnelCore` | `ProfileStore` + `ImportDraft`, `ProfilesWatcher`, `Secrets` + `SecretStore` (Keychain; on Linux `SecretStores`: secret-service, systemd-creds, file), `SecretVault` + `UserAuthenticator` (Secure Enclave protection), `Preferences`, `HealthCheck.check` (the probe), `QRDecoder`, `OpenedFiles` (files the app is asked to open), `ScannedCodeTarget` (where a scanned code goes), `TLSFingerprint` + `ServerKeyPin` (a certificate's SHA-256, a key's `pin-sha256:`), `AnyConnectEditing` + `ServerTrustOffer` (the app's Cisco AnyConnect fields and "Trust this server"), `ServerClock` + `SNTP` (clock checks), `HelperClient`, `HelperAutoUpdate`, `ConnectionManager` + `ProfileDestination`, `ConnectionFailure`, `UnreachableRetry`, `FailureDetails` ("Copy details"), `NetworkPath` + `NetworkStatus`, `ActivityLog` + `ActivityEvent`, `LoginConnector` (connect at login), CLI parsing (`CLICommand`, `CLIInvocation`), automation objects + `AutomationService`, `MCPServer` + `MCPTools` + `JSONValue` | Kit, VPNConfig, Shared (and swift-crypto's Crypto and CryptoExtras on Linux) |
| `PassTunnelCLI` | the `passtunnel` command: `PassTunnelCLI.run` (entry, `CLIHelp`), `CLIRunner`, `CLICompletions`, `CLITerminal`, `CLIClipboard`; `Pasteboard` (macOS: the app's too) | Core, Kit, Shared |
| `PassTunnelHelper` | `main.swift` XPC listener, process supervision | Shared (and through it VPNConfig) |
| `PassTunnel` | SwiftUI app, menu bar, first run, updates (`AppUpdater`), Scan QR on screen (`ScreenQRScanner`, ScreenCaptureKit, macOS 14 and later); CLI mode runs `PassTunnelCLI` | CLI, Core, Kit, VPNConfig, Shared, Sparkle |
| `PassTunnelCommand` | Linux only: the `passtunnel` executable (product `passtunnel`), `PassTunnelCLI.run` | CLI |
| `PassTunnelDaemon` | Linux only: the root daemon's logic ([LINUX.md](LINUX.md)): `Daemon` (socket, systemd activation, one request per connection), `DaemonCall` (the line protocol), `Access` + `UserDatabase` (root and the group `passtunnel`), `TrustedPath` + `SystemTools` (fixed tool paths, ownership and version checks, the CA bundle), `Supervisor` (OpenVPN and openfortivpn: spawn, stop, exit), `PreviousInstance`; DNS: `DNSSettings` (checked servers and domains), `DNSApplier` + `DNSRecord` + `ResolvConf` (systemd-resolved, resolvconf or /etc/resolv.conf, recorded per session and reverted), `OpenVPNDNS` + `DNSHook` (`passtunneld dns-hook`); FortiGate: `OutputCopier` (the tool's output, from a pipe into the log), `FortiOutput` + `FortiDNSWatch` (openfortivpn's lines), `SessionInterface` + `InterfaceSystem` (the kernel's view of the ppp interface); `DaemonBuild` (the build number a release build compiles in) | Shared, VPNConfig |
| `PassTunnelDaemonCommand` | Linux only: the `passtunneld` executable (product `passtunneld`), also OpenVPN's DNS hook (`dns-hook`) | Daemon, Shared |

The library product `PassTunnelKit` (targets `PassTunnelKit` and `PassTunnelVPNConfig`) is what the
iPhone app uses ([MOBILE.md](MOBILE.md)); `xcodebuild -scheme PassTunnelKit -destination
'generic/platform=iOS Simulator' build` builds it for iOS. The sanitizer and `FortiConfig` are a
target of their own so that the helper links them and nothing else of PassTunnelKit. Internals that
Core needs from Kit (`FileIO`, the lenient decoding helpers, the envelope parts, `ProtectionKeyRecord`)
are `package`, not `public`. The golden cases in [`fixtures/`](../fixtures/README.md) are read by the
`PassTunnelKitTests` test target (and, as a pinned copy, by the Android port).

On Linux ([LINUX.md](LINUX.md)) the package has the targets `PassTunnelVPNConfig`, `PassTunnelKit`,
`PassTunnelShared`, `PassTunnelCore`, `PassTunnelCLI`, the Linux-only `PassTunnelCommand`,
`PassTunnelDaemon` and `PassTunnelDaemonCommand` and the test targets (`PassTunnelDaemonTests` Linux
only), none of the app and helper targets (the `#if os(Linux)` block at the end of `Package.swift`;
the dependencies are declared on every platform). Like `PassTunnelHelper`, the daemon is built from
Shared and VPNConfig only; its logic is a library so that the tests run it with injected run root,
home, user database and tools. The CI jobs `Linux (x86_64)` and `Linux (aarch64)` build them, run
the tests that build there (golden cases included) in the official Swift container, and smoke-test
the `passtunnel` binary and, as root, `passtunneld` (with the distribution's openvpn and
openfortivpn, no tunnel) and its DNS hook (on the container's resolv.conf).
There `Crypto` from swift-crypto takes the place of CryptoKit
(the same API, so codes and `ptse1:` envelopes are the same), `PTError.keychain` shows the bare
`OSStatus`, and `String(localized:)` is an English-only stand-in (Kit's `Localization.swift`,
`package`, used by Core and the CLI too), because Foundation on Linux does not have it yet. Configs are
split into lines at every `\n` scalar (`OVPNInliner.lines`), not with `components(separatedBy: "\n")`,
which on Linux keeps `\r\n` (one Character) together.

The platform seams (Linux code stays in the same files behind `#if`; the Mac's behavior is unchanged):

- **Values.** `PT.profilesSubpath` (`.local/share/passtunnel/profiles`), `PT.helperRunRoot`
  (`/run/passtunnel`), `HelperCore.maxSocketPathBytes` (sun_path is 108 bytes, not 104) and
  `AppPaths.default` (`~/.local/share/passtunnel`; `PASSTUNNEL_HOME` overrides it) are platform values.
- **Combine.** `CombineStandIn.swift`, compiled only where Combine is missing: `ObservableObject`,
  `@Published` (the current value to a new subscriber, then each new value before it is stored),
  `PassthroughSubject`, `compactMap`, `sink`, `AnyCancellable`, `store(in:)`: what Core and the CLI use.
- **Secrets.** `Secrets` keeps its API over a `SecretStore` (read, write, remove raw items by account),
  chosen on every call: `KeychainSecretStore` on the Mac (the write rules below), `MemorySecretStore`
  with `PASSTUNNEL_SECRET_STORE=memory` (tests; debug builds only, a release build has no such store;
  the Linux tests use it), and on Linux otherwise `ChosenSecretStore`: `SecretStores` picks
  `SecretServiceStore` (`secret-tool`), `SystemdCredsStore` (`systemd-creds`) or `FileSecretStore`
  (scrypt + AES-GCM) from `PASSTUNNEL_SECRET_STORE`, `Preferences.secretStore`, the recorded
  `Preferences.secretStoreUsed` or what is available (`SecretStoreSelection`), and records the store
  after its first successful write (LINUX.md, Secrets). The system tools run through `ToolRunning`
  (`SystemToolRunner`: fixed path, exact environment, stdin over a socket pair, timeout); what the
  stores take from the system is a `SecretStoreSystem`, so their tests bring fakes. These types build
  everywhere and their tests run on the Mac too; only Linux selects them. Store failures throw
  `SecretStoreUnavailable` (`keychain_error`) with the store's message. `Secrets.exists` is the
  throwing `has`: connecting, `code` and `diagnose` report the store's error instead of a missing
  secret. `SecretStores.interaction` (set by the CLI on a terminal) lets the file store ask for its
  passphrase and gives a locked keyring time to be unlocked.
- **Confirmation.** `PlatformAuthenticator` is `SecureEnclaveAuthenticator` on the Mac and
  `UnavailableAuthenticator` on Linux (`isAvailable` false; nothing is unlocked, and no key is ever
  reported unusable). On Linux `SecretVault.refuseUnconfirmable` refuses the secrets a profile's
  `require_auth` protects (`PTError.protectionUnavailable`, `auth_unavailable`) instead of using them
  unconfirmed; `VaultExpiry.systemSources` (screen lock, sleep) is empty there.
- **Helper.** `ConnectionManager.defaultHelper` is `HelperClient.shared` on the Mac and
  `UnixSocketHelperClient.shared` on Linux (passtunneld at `PT.daemonSocketPath()`: `hello` for
  `ensureCompatible`, `perform` for requests; no socket is `HelperClientError.notInstalled`). Linux's
  `SystemHelperInspector` reports `not_installed` without the socket, else `enabled`, and from
  `hello` whether the daemon answers and is the build installed with the running `passtunnel`
  (`HelperBuild.installedDaemon`).
  `HelperCore.fixedEnvironment` is `PATH` and `LC_ALL` only on Linux. There `HelperCore.dnsHook` (the
  daemon's own executable) is linked into the session directory as `dns-hook`, which OpenVPN runs as
  `--dns-updown` (2.7) or, where `openVPNHasDNSUpdown` is false (2.6), as `--route-up` and `--down`.
- **Routes.** `RoutingTable.trafficRoutes` is the IPv4 table (`ipv4Routes`, `sysctl`) on the Mac and,
  on Linux, the IPv4 and IPv6 routes of the tables the policy rules send ordinary traffic to, from
  rtnetlink dumps of the links, routes and rules (`Netlink`: the messages are parsed, and the rules
  followed, by code that builds and is tested everywhere; only `Netlink.dump`, the socket, is Linux's).
  `Route.tunnelDevice` carries the kernel's kind of device there (LINUX.md, Client side).
- **Network path.** `NetworkPath` (online or not, and the kind of interface; nothing is contacted) is
  `NWPathMonitor` where the Network framework exists (`#if canImport(Network)`) and, on Linux, the
  routes `RoutingTable.trafficRoutes` reads plus the links' state in `/sys/class/net`
  (`NetworkPath.linuxStatus`, tested everywhere), read again every 5 s while watched (LINUX.md, Client side).
- **MCP input.** `MCPServer` decodes each line into a `JSONValue` with `JSONDecoder` on every
  platform, so JSON booleans are never numbers (no CoreFoundation `CFBoolean` check).
- **Version.** `AppInfo.current` on Linux is `BuildVersion`: a release build
  (`scripts/build-linux.sh`) compiles in `BuildVersion+Generated.swift` (never committed) with
  `-DPASSTUNNEL_BUILD_VERSION`; otherwise `0.0.0-dev` and no build number. The daemon, which links no
  Core, gets the same build number from `DaemonBuild+Generated.swift` (`DaemonBuild`).
- **System calls.** `POSIXSocket` (`SOCK_STREAM`, `SOCK_DGRAM`, `MSG_NOSIGNAL` for `SO_NOSIGPIPE`, no
  `sun_len`) for the management socket, the health probe and the SNTP client; Linux pings with `ping -n -q -c 1 -W <s>` (`-6` for IPv6)
  from `/usr/bin`, `/bin`, `/usr/sbin` or `/sbin`, never `PATH`.
- **macOS only** (`#if os(macOS)`): `ProfilesWatcher`, `LoginItem`, `HelperInstaller`,
  `HelperClient`, `QRDecoder`, `TLSFingerprint.fetch` and `fetchServerKeyPin` (the digest formats and `ServerKeyPin` are portable), `ServerClock.gateway`
  (`#if canImport(Network)`; on Linux it fails with `unavailable`, LINUX.md),
  `HelperSessions.currentProcesses`, `RoutingTable.ipv4Routes` and `parse`, `ConfirmationWording`, and in Shared
  `CodeSignature`, `Spawner`, `ToolStager`, the XPC protocol and `HelperCore`'s `F_GETPATH` (Linux
  reads the `/proc/self/fd` link instead) and `fcopyfile` (only for the Mac's bundled DNS script;
  the Linux daemon is its own hook). On Linux `SessionDirectory.restrictSocket` sets the
  socket's mode before handing it over. The CLI's macOS parts (the app
  hand-offs, `helper install`/`uninstall`, the concealed pasteboard) are under `#if` as well; on Linux
  `helper install`/`uninstall` fail with `invalid_argument` (the package installs the daemon), and
  `code --copy` runs `wl-copy` or `xclip` from `PATH` in a process left behind
  (`__clear-clipboard <seconds>`), which stops it after `Preferences.clearClipboardAfter` (default
  60 s) only while it still serves the clipboard (`invalid_argument` without either).

## Identifiers (`PassTunnelShared/Identifiers.swift`)

```swift
public enum PT {
    public static let bundleID = "com.furkanprlk.passtunnel"
    public static let helperLabel = "com.furkanprlk.passtunnel.helper"     // launchd label == mach service
    public static let helperPlistName = "com.furkanprlk.passtunnel.helper.plist"
    public static let teamID = "YH4NUPFH74"
    public static let keychainService = "PassTunnel"
    public static let helperProtocolVersion = 4   // 3: sessions per (uid, id), socket in the run dir; 4: startOpenConnect
    public static let helperRunRoot = "/var/run/passtunnel"
    public static func sessionDir(uid:profileID:runRoot:) -> String       // <runRoot>/<uid>/<id>
    public static func mgmtSocketPath(uid:profileID:runRoot:) -> String   // <sessionDir>/mgmt.sock
}
```

## Storage

- Support dir: `~/Library/Application Support/PassTunnel/` — override with env `PASSTUNNEL_HOME` (tests).
  - `config.json` – preferences (`Preferences`), incl. `defaultProfile`
  - `profiles/<id>/profile.json`, `profiles/<id>/config.ovpn`, `profiles/<id>/vpn.log`,
    `profiles/<id>/.last-otp` (TOTP window of the last code sent, so app and CLI never reuse a code),
    `profiles/<id>/.mgmt-state` (OpenVPN state shared by the app, which holds the management interface),
    `profiles/<id>/.retry` (`UnreachableRetry`: the app's retries of a server that did not answer, with
    its pid, for `status --json` and `get_status`),
    `profiles/<id>/activity.jsonl` (`ActivityLog`: the last 500 typed events of the profile's connections,
    one JSON object per line, 0600; appended under `profiles/<id>/.activity.lock` and replaced atomically, so
    the app and CLI processes can write at once; no password, a code as at most its first three digits),
    `profiles/<id>/clock.json` (the last `ClockOffset` measured for the profile: a FortiGate gateway's time
    after a rejected sign-in, 0600),
    `profiles/<id>/network.json` (`ProfileNetwork`: the routes and DNS options of the last connect, 0600, replaced
    atomically; read only if it is a regular file of the user without group or other access, for the profile's
    current destination, otherwise ignored)
    (the OpenVPN management socket is in the helper's run directory, see below)
  - Linux only (`~/.local/share/passtunnel/`, LINUX.md): `secrets/<account>.cred` (systemd-creds
    store), `secrets.enc` and `.secrets.lock` (file store)
- Keychain: generic password, service `PT.keychainService` (env `PASSTUNNEL_KEYCHAIN_SERVICE` overrides
  for tests), account `"<profileID>/password"` and `"<profileID>/totp"`. Use the Security framework
  (`SecItemAdd/CopyMatching/Delete`), never the `security` CLI. App and CLI are the same binary,
  so Keychain ACLs never prompt between them. Items live in the file-based login keychain (no
  `kSecUseDataProtectionKeychain`): not synced to iCloud Keychain, but carried by Migration Assistant and
  backups (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` is set on add but does not apply there).
  Every write deletes the item, then adds it (`KeychainSecretStore.write`), never `SecItemUpdate`: an existing item may
  have been created by another app with an ACL that lets it read the value, and the added item gets the
  default ACL (only PassTunnel). `remove` repeats `SecItemDelete` until `errSecItemNotFound` (at most 16
  times); when the old item cannot be removed nothing is written (`KeychainItemNotReplaced`, not retried
  by reconnects). The previous value is read before the delete; when `SecItemAdd` of the new value fails,
  it is added back as a new item (best effort) and `PTError.keychain(status)` is thrown. `ProfileStore.create` first removes every item under the new id (`Secrets.deleteAll`:
  password, totp, sekey), so a new profile never inherits orphaned items. A value is plain text, or, for profiles with
  `requireAuth` ("Confirm with Touch ID"), an envelope `ptse1:…` (`SecretEnvelope`); plain values that start
  with `ptse`/`ptpl` are stored as `ptpl1:<value>`. `"<profileID>/sekey"` holds the profile's protection
  key (`ProtectionKeyRecord`, JSON: Secure Enclave `dataRepresentation` + X9.63 public key); it is never a
  `SecretKind` (the CLI's `secret` command cannot name it). `ProfileStore.delete` removes all three.
- JSON uses snake_case keys (`JSONEncoder.keyEncodingStrategy = .convertToSnakeCase`), pretty, sorted.

## Model (`PassTunnelKit/Model.swift`)

```swift
public enum VPNType: String, Codable, CaseIterable {
    case openvpn, forti, anyconnect   // anyconnect: Cisco AnyConnect (openconnect), macOS 15.4 and later (below)
    case globalprotect                // Palo Alto GlobalProtect (the same openconnect), "Profile (G2)" below
    var defaultOTPDelivery: OTPDelivery  // .combined for OpenVPN, .separate for the other types
    var isExperimental: Bool             // .globalprotect only: the one source of the label ("Experimental")
}
public enum PasswordMode: String, Codable, CaseIterable { case keychain, ask, none }   // none = certificate only
public enum OTPMode: String, Codable, CaseIterable { case none, totp, ask }
/// How the one-time code reaches the server.
/// combined  → one secret built from `otpTemplate` (e.g. "{password}{otp}"); OpenVPN auth file / Forti password field
/// separate  → code sent on its own: OpenVPN static-challenge (SCRV1:b64(password):b64(code)), Forti `otp =` field,
///             Cisco AnyConnect's second answer (the next field openconnect asks for)
public enum OTPDelivery: String, Codable, CaseIterable { case combined, separate }
/// Presets the UI offers; any template containing "{otp}" is valid ("{password}" optional, literal text allowed).
public enum OTPTemplatePreset: String, CaseIterable {
    case append = "{password}{otp}", prepend = "{otp}{password}", colon = "{password}:{otp}", comma = "{password},{otp}"
}
public enum BadgeStyle: String, Codable, CaseIterable { case letter, icon, both }
public enum TOTPAlgorithm: String, Codable, CaseIterable { case sha1, sha256, sha512 }

public struct TOTPParams: Codable, Equatable { var digits = 6; var period = 30; var algorithm = TOTPAlgorithm.sha1 }

public struct Profile: Codable, Identifiable, Equatable {
    public var id: String                 // slug, unique, immutable
    public var name: String
    public var type: VPNType              // changing it empties unknownKeys
    public var order = 0
    // appearance
    public var badge = ""                 // empty → first letter of name
    public var icon = ""                  // SF Symbol name
    public var badgeStyle = BadgeStyle.letter
    public var pinned = false
    // authentication
    public var username = ""              // empty → ask each time (remember lastUsername)
    public var lastUsername = ""
    public var passwordMode = PasswordMode.keychain
    public var otpMode = OTPMode.none
    public var totp = TOTPParams()
    public var requireAuth = AuthRequirement.off   // "Confirm with Touch ID": off | connect | always (JSON require_auth)
    // behaviour
    public var sessionLimitMin = 0
    public var autoReconnect = false
    public var connectAtLogin = false     // the app connects it when it opens at login (LoginConnector)
    public var healthHost = ""            // "10.0.0.5" (ICMP) or "host:port" (TCP) or "[v6]:port"
    public var otpDelivery = OTPDelivery.combined   // default: VPNType.defaultOTPDelivery (set in create, and when the key is missing)
    public var otpTemplate = "{password}{otp}"      // used when .combined; validated: must contain "{otp}"
    // OpenVPN
    public var mgmtPort = 0               // legacy, unused: kept only so older profile.json files decode
    // FortiGate and Cisco AnyConnect (trustedCert FortiGate only)
    public var host = ""
    public var port = 443
    public var trustedCert = ""
    public var setDNS = false
    public var setRoutes = true
    // Cisco AnyConnect only; written (profile.json, share files) only for that type
    public var usergroup = ""             // the URL path: https://host/usergroup
    public var authgroup = ""             // matched against the server's group list
    public var serverCert = ""            // "pin-sha256:…" (OpenConnectPin, normalized) or "" for the system CAs
    public var tlsOnly = false            // openconnect's no-dtls; DTLS by default
    // serverCert and tlsOnly also Palo Alto GlobalProtect's; written only for these two types
    // Palo Alto GlobalProtect only; written only for that type
    public var gateway = ""               // the portal's gateway label, rendered as authgroup
    public var skipPortal = false         // sign in to host as a gateway (path "gateway")
    public var gatewayServerCert = ""     // the gateway's pin when its key is not the portal's
    public var configSourceName: String?    // file name the OpenVPN config was imported from
    public var configImportedAt: Date?      // ISO 8601, whole seconds
    public internal(set) var unknownKeys: UnknownProfileKeys   // keys of a newer version, written back (below)
    // derived
    public var displayBadge: String
    public var needs: [CredentialField]   // what must be asked before connecting (none if password == .none)
    public var unattended: Bool           // can connect without asking (required for auto-reconnect)
    public var usesStoredSecrets: Bool    // keychain password or TOTP: only then is requireAuth offered
    // checks (PTError), used by ProfileStore.save, ProfileFields.set and connecting
    public static func checkUsername(_: String, type: VPNType) throws   // Forti: usernameTooLong; AnyConnect: invalidField
    public func checkHosts() throws                                     // host (by type), health_host
    public func checkAnyConnectFields() throws                          // usergroup, authgroup, server_cert, password_mode, otp_template
    public func checkGlobalProtectFields() throws                       // gateway, server_cert, gateway_server_cert, password_mode, otp_template
}
public enum AuthRequirement: String, Codable, CaseIterable, Comparable { case off, connect, always }   // ordered
public enum CredentialField: String, Codable { case username, password, otp }
```
Decoding must tolerate missing keys (defaults) so older/newer files load (no `require_auth` → `off`;
unknown values → `off`; no `connect_at_login` → false). Share files leave `require_auth` and `connect_at_login` out
(per-user choices, like `pinned`).

An unknown `type` is the exception: a profile written by a newer version (a VPN type added later) is never read as
OpenVPN, which would show it as something it is not and rewrite it without its new fields on the next save.
`Profile.init(from:)` throws `PTError.unsupportedProfileType(type)` for a `type` string that is not a `VPNType` (no
`type` at all is still an old OpenVPN profile). `ProfileStore` keeps such a profile beside the known ones as an
`UnsupportedProfile` (id, name, order, the stored type): `listUnsupported()` lists them, `list()` leaves them out, and
`get`, `update`, `save`, `setDefault`, `exportShare` and `setOVPN` throw `unsupportedProfileType`, so nothing connects,
edits, duplicates, shares or exports it. Its `profile.json` is never read into a `Profile` and never rewritten (every
profile has its own file, so saving another profile cannot touch it: the object, unknown keys included, stays
byte-equal; `save` fails closed: it also refuses to replace an existing `profile.json` that is of an unknown type, too large or
unreadable, or not a JSON object, because a newer version may have written it since the profile was read); only `delete` works. Importing a share file with an unknown `type` throws the same error before anything
is created. The error is `config_invalid` in the CLI and MCP tools, and its message says the profile needs a newer
PassTunnel. `list` and `list_profiles` show the profile with its stored `type` and `needs_newer_version: true`.

`anyconnect` is a known type that Core connects (#184, [Cisco AnyConnect backend](#cisco-anyconnect-backend)) and
the `passtunnel` command, the MCP tools (#185) and the Mac app (#186) handle as an ordinary profile. Its keys and
rules are in [Profile (#181)](#profile-181) below. Such a profile is treated as follows:
- **Core**: `ConnectionManager.connectRefusal(type)` says whether a type can be connected on this system: nil for OpenVPN
  and FortiGate; for Cisco AnyConnect `PTError.anyConnectRequiresMacOS("15.4")` ("Cisco AnyConnect requires macOS 15.4
  or later.") below macOS 15.4 (`HelperCore.Tool.minimumMacOS`; the macOS comes from `ConnectionManager.systemVersion`,
  replaced in tests), `config_invalid`; nothing on Linux (#187), where the sign-in checks the distribution's openconnect
  first (`AnyConnectSignIn.distributionTool`: missing, untrusted or older than 9.01 is
  `PTError.anyConnectToolUnavailable` with the reason, also `config_invalid`, before the code is used).
  `checkConnectable` throws the refusal at the start of `connect` (following an attempt
  too), `checkCanStart` and the attempt itself, before a confirmation is asked for, a secret is read, openconnect runs
  or the helper is asked anything (its status included); `diagnose` reports it with the profile's other problems.
  Otherwise the profile connects as described under [Cisco AnyConnect backend](#cisco-anyconnect-backend).
  `ProfileStore` lists, saves (with the checks above), exports, imports and deletes it like any profile.
- **CLI and MCP** (#185): an ordinary profile of type `anyconnect`. `passtunnel add NAME --type anyconnect
  [--server https://host[:port][/usergroup]]` (`AnyConnectServer.parse` at parse time: an address that is not one is a
  usage error; `ProfileStore.create(name:type:server:)` saves it as `host`, `port` and `usergroup`), `set`/`show` with
  its keys, `export`, `import` and `rm` as for the other types. `ProfileSummary`/`ProfileStatus` (`list`, `status`,
  `show`, `list_profiles`, `get_status`) carry `connect_refusal` (an `ErrorReport` of `connectRefusal`'s error, from
  `AutomationService` and the runner's system) where the system cannot connect the type, and no `needs_newer_version`
  (that is for a type this version does not know). The text output notes it beside the profile: `PTError.unavailableNote`
  ("Requires macOS 15.4 or later"; Linux refuses no type up front since #187) in `list`, `status` and `show`. `connect`, `toggle`
  and the MCP `connect` fail with `connectRefusal`'s error before the helper is asked anything or a secret is read
  (`checkConnectable` with the runner's or manager's `systemVersion`), and `add --type anyconnect` is refused with it
  too, so no profile that cannot connect is made here (a share file's is kept and shown the same way). `diagnose` has
  the refusal and the profile's other problems (host, user name, group and pin fields, saved password/TOTP secret).
  `CLIRunner` takes the system's macOS, the manager and the change signal as parameters, so its tests run on a fake
  helper and an injected macOS (or none: Linux).
- **App** (#186): an ordinary type in the type question of the add view, the File menu ("New Cisco AnyConnect
  Profile…"), the editor (docs/APP.md, "Profile editor"), the list, the detail, the menu bar and scanned codes.
  `AppModel.connectRefusal(type)` is the manager's (its `systemVersion`): below macOS 15.4 the type is shown, disabled,
  in the type question (with the sentence) and the File menu (with the note as tooltip), and a profile of it is listed
  as `DisplayStatus.unavailable` ("Requires macOS 15.4 or later" in the row, the sentence in the status line, a card
  that says what still works), with Connect, Edit and the menu bar switch disabled and no code in its rows;
  `startConnect`, the overlap check, `edit` and `newProfile` refuse it with the message before Touch ID, the Keychain or
  the helper, an import selects it instead of opening the editor, and scanned codes never target it; its secrets are
  never read, reconciled or unlocked (`ConnectionManager.profilesWithUsableSecrets`; the copy actions refuse it). Sharing and
  deleting it work. There is no `VPNType.connectable` any more: every known type is one the app shows as a profile;
  only a type this version does not know is an `UnsupportedProfile`.
- The helper accepts `startOpenConnect` (protocol 4, #182), and so does `passtunneld` (#187, docs/LINUX.md).

### Keys of a newer version (#200)

A newer PassTunnel may add keys to a type this version knows. `Profile.init(from:)` keeps every top-level key that is
not one of its `CodingKeys` in `unknownKeys` (`UnknownProfileKeys`: opaque, the JSON values kept by kind with integers
exact, in key order), and `encode(to:)` writes them back unchanged, so no save drops them: every write of
`profile.json` is `ProfileStore.save` of a profile read from it (`passtunnel set`, `pin`/`unpin` and `secret`, `update`
with the user name a connect remembers, `setOVPN`, the editor's Save, a `ProfileMerge` in `update`). Setting the
default writes only `config.json`. The rules:

- Keys this version knows are never in it, also those it writes only for another type (`usergroup`, `authgroup`,
  `server_cert` and `tls_only` of an OpenVPN or FortiGate profile are dropped on its next save, as before, and so are
  `gateway`, `skip_portal` and `gateway_server_cert` of any type but Palo Alto GlobalProtect) and the read-only
  `otp_format`. Keys inside `totp` are not kept: a newer version adds its keys at the top level.
- They belong to the type the profile was read with: setting `type` to another type empties `unknownKeys`, so a save
  after a change of the type writes none.
- `ProfileMerge` compares and merges the known keys only (`changedFields` never lists an unknown one); the merged
  profile has `current`'s unknown keys, or none when the edit changed the type.
- Share files never carry them: `encode` leaves them out of an export, and decoding a `ShareFile` empties them in its
  profile (unknown top-level keys of the file are ignored, as before), because this version cannot check them for the
  profile an import creates. An import that updates an existing profile (the Mac has none; a port may) keeps the
  existing profile's unknown keys.
- A key is kept as the decoder hands it (after `convertFromSnakeCase`) and written back through `convertToSnakeCase`.
  That round trip is exact for every key `JSONCoding` writes (lower-case words of letters and digits, each starting
  with a letter, joined by single underscores), so a newer version adds only such keys. A key that differs from a
  known key, or from another unknown one, only in case and underscores is dropped (the strategy would write both under
  one name, and a file with a key twice may not be read again), and so is a value `JSONDecoder` cannot read (a number
  beyond `Double`).
- What a newer version may rely on: an older version keeps a key it does not know, unchanged, and nothing more. A
  newer version that changes what an existing key means, or gives it values an older version would misread (an
  unknown enum value is read as the default and written back as that), must not rely on this: it adds a new key
  instead, and when older versions must not use or rewrite the profile at all, it bumps the version they check: a new
  `type` for `profile.json` (an `UnsupportedProfile` for them, never rewritten), a new `passtunnel_profile` for share
  files (`ShareFile.version(for:)`; older readers refuse it).

Golden cases: `fixtures/profile-json.json` (what a save writes back, also after a change of the type or `passtunnel set`),
`fixtures/profile-merge.json` and `fixtures/share-files.json`.

## Core APIs

```swift
public struct ProfileStore {                       // all methods throw PTError on bad input
    public init(paths: AppPaths = .default)
    public func list() -> [Profile]                // sorted by (order, name)
    public func listUnsupported() -> [UnsupportedProfile]   // VPN type of a newer version: listed, refused, deletable
    public func unsupportedProfile(_ id: String) -> UnsupportedProfile?
    public func get(_ id: String) throws -> Profile        // throws unsupportedProfileType for those
    public func create(name: String, type: VPNType) throws -> Profile   // slug id (Turkish chars folded), unique; deletes Keychain items left under the id
    public func save(_ p: Profile) throws
    public func update(_ id: String, _ change: (inout Profile) throws -> Void) throws -> Profile   // re-read, change, save (locked)
    // ProfileMerge.merge(original:edited:current:) → current + the fields edited changed vs original (editor Save)
    public func delete(_ id: String) throws        // also deletes keychain items and the dir
    public var defaultID: String? { get }; public func setDefault(_ id: String?) throws
    public func dir(_ id: String) -> URL
    public func ovpnURL(_ id: String) -> URL
    public func setOVPN(_ id: String, from: URL) throws   // inlined, <auth-user-pass> stripped, sanitized, 0600
    public func importOVPN(_ url: URL, name: String?) throws -> Profile   // analyzeOVPN, then commit with what the file holds
    public func analyzeOVPN(_ url: URL) throws -> ImportDraft             // the review: writes nothing (no file, no Keychain item)
    public func commit(_ draft: ImportDraft, name:, username:, password:, totpSecret: Data?, totp: TOTPParams, now:) throws -> Profile
        // nil values come from the file; ovpnNotAllowed while the draft has blocking lines; the config is checked
        // with the sanitizer again before it is written; <auth-user-pass> → username + Keychain password
    public func exportShare(_ id: String, to: URL) throws                 // ShareFile, 0600; config without credential blocks
    public func importShare(_ url: URL, name: String?) throws -> Profile  // drops an <auth-user-pass> block; an unknown `type` throws unsupportedProfileType
}
public enum OVPNInliner {
    public static func prepare(_ text: String, baseDir: URL?) throws -> String   // referenced files inlined, then OVPNSanitizer
    public static func strippingCredentials(_ text: String, blocks: Set<CredentialBlock> = all) -> StrippedCredentials
    // CredentialBlock: .authUserPass, .httpProxyUserPass. A removed <auth-user-pass> leaves a bare
    // `auth-user-pass` line and yields its user name (line 1) and password (line 2); `auth-user-pass [inline]`
    // becomes `auth-user-pass`; `http-proxy-user-pass [inline]` goes with its block; an unterminated block
    // drops the rest of the file. Import and the editor strip [.authUserPass] (proxy credentials stay in the
    // local config); share export strips both.
    // Lines are read with OVPNSanitizer's tokenizer (`tokens(of:)`, `inlineBlockTag`, `isInlineBlockEnd`), so
    // import and the helper never read a line differently; lines it rejects are kept for the sanitizer to report.
    // Like the sanitizer, they skip a BOM only at the start of the file; a referenced file's own BOM is not embedded.
}
public enum Secrets {                               // Keychain (a SecretStore; see Targets for Linux)
    public static func get(_ profileID: String, _ kind: SecretKind) -> String?   // plain text only; nil if encrypted
    public static func has(_ profileID: String, _ kind: SecretKind) -> Bool      // plain or encrypted
    public static func isProtected(_ profileID: String, _ kind: SecretKind) -> Bool
    public static func set(_ profileID: String, _ kind: SecretKind, _ value: String) throws   // plain
    public static func delete(_ profileID: String, _ kind: SecretKind)
    public static func deleteProtectionKey(_ profileID: String)
}
public enum SecretKind: String { case password, totp }
public enum TOTP {
    public static func code(secret: Data, params: TOTPParams, at: Date = Date()) -> String
    public static func remaining(params: TOTPParams, at: Date = Date()) -> Int
    public static func decodeSecret(_ s: String) throws -> Data         // base32 (case/space/padding tolerant) or hex
}
public struct OTPAuthURI { label, issuer, secret: Data, params: TOTPParams; init(_ uri: String) throws }   // otpauth://totp/...
public enum OVPNAnalyzer {
    public static func analyze(_ text: String) -> (passwordMode, otpMode, otpDelivery, remote: String, remotes: [String])
    public static func servers(_ text: String) -> [Server]   // every remote: host, port, tcp (as endpoint resolves them)
    public static func serverDescription(_ remotes: [String]) -> String   // "vpn.example.com +2 more"; also (_ text:)
    public static func endpoint(_ text: String) -> Endpoint?   // first remote: host, port, tcp, others
    public static func endpointDescription(_ text: String) -> String   // "vpn.example.com:1194 +2 more · UDP"
    public static func redirectsGateway(_ text: String) -> Bool?
}
// static-challenge in the file → otpMode .ask, otpDelivery .separate; otherwise .combined
// Lines are read with OVPNSanitizer.tokens(of:) / inlineBlockTag / isInlineBlockEnd, as the helper's
// sanitizer and OpenVPN read them: quotes and escapes resolved, comments dropped, lines OpenVPN rejects
// skipped, inline block contents skipped (<connection> blocks read), `setenv opt <directive>` applied
// when the name is exact. `remotes` = every `remote` host in file order, `remote` = the first.
// `endpoint`: the port and transport of the `remote` line, else the `port`/`rport` and `proto` lines of its
// <connection> block, then those outside any block (the last of each), else 1194 and UDP.
public enum OVPNSkipRules {                       // which refused lines an import leaves out (SECURITY.md)
    public static func apply(_ text: String) -> Result   // text with skipped lines as "# PassTunnel skipped: …", skipped, blocking
    public static func skipReason(_ v: OVPNSanitizer.Violation) -> Reason?   // nil: the line blocks
}
public struct OVPNImportReport {                  // ImportDraft.report; golden cases: fixtures/ovpn-import.json
    public static func make(_ text: String, baseDir: URL?) throws -> OVPNImportReport   // throws only for embedded files
    config: String?   // inlined, skipped lines commented, <auth-user-pass> removed; nil with a blocking line
    skipped, blocking // numbered as in the file (OVPNInliner.inlineMapped keeps each inlined line's origin)
    servers, certificates (name, file it was embedded from), passwordMode, otpMode, otpDelivery, username, password
    needs: [Field]    // username + password with auth-user-pass, codeSecret with static-challenge (ImportDraft adds .name)
}
// `OVPNSkipRules` classifies the violations `OVPNSanitizer.sanitize` reports, by directive and reason: a line is
// skipped only when every violation on it is in the skip tables (`skippable`, `skippableManaged`, script-security,
// non-metadata setenv); anything else, including any reason the tables do not know, blocks. The rewritten text is
// checked with the sanitizer again, so "no blocking lines" always means the sanitizer accepts it. The sanitizer
// itself, which the helper runs, is unchanged.
public enum OTPComposer {
    public static func validate(template: String) throws               // must contain "{otp}"
    public static func compose(password: String, otp: String?, delivery: OTPDelivery, template: String,
                               type: VPNType) -> (secret: String, separateOTP: String?)
    public static func parts(delivery: OTPDelivery, template: String) -> (secret: [Part], separateCode: Bool)
        // what compose sends, as .password / .code / .text in order: the editor's masked "Server receives"
}
public struct ShareFile: Codable              // {"passtunnel_profile":1, "profile":{…minus username,last_username,order,mgmt_port,pinned,require_auth,connect_at_login,config_imported_at}, "files":{"config.ovpn": base64}} (config without credential blocks)
    // passtunnel_profile: the oldest version that reads the file (version(for: type): 1 for OpenVPN and FortiGate, 2 for
    // Cisco AnyConnect); a reader accepts 1…currentVersion (2) and refuses anything else as unsupportedShareFile
    // fileExtension "passtunnel", typeIdentifier "com.furkanprlk.passtunnel.profile" (exported by the app, conforms to public.json)
public struct Preferences: Codable { defaultProfile, theme, notifyOnDrop, sessionWarnMin=30,
    sessionNotifyMin=10, hotkeys=false, autoType=false, launchAtLogin=true,
    authReuseMinutes=1 /* 1, 5 or 15; others → 1 */,
    waitForFreshCode=true /* wait when freshCodeSeconds (5) or less are left */,
    clearClipboardAfter=60 /* seconds: 30, 60 or 120; others → 60 */,
    secretStore=.auto, secretStoreUsed=nil /* Linux; written only when set */ }
public enum HealthCheck { public static func check(_ host: String, timeout: TimeInterval = 3) -> (ok: Bool, ms: Int) }
```

### Confirm with Touch ID (`SecretVault.swift`, `SecretEnvelope.swift`, `UserPresence.swift`)

`requireAuth` is enforced by encryption, not by a check: the protected secrets are stored encrypted to a
per-profile Secure Enclave key, and decrypting them is the user's confirmation.

```swift
public protocol UserAuthenticator: AnyObject {          // SecureEnclaveAuthenticator; a software P-256 key in tests
    var isAvailable: Bool { get }                        // SecureEnclave.isAvailable
    func createKey() throws -> ProtectionKey             // no prompt; .protectionUnavailable without a Secure Enclave
    func publicKey(keyData: Data) throws -> P256.KeyAgreement.PublicKey   // no prompt; ProtectionKeyUnusable
    func unlock(keyData: Data, reason: String) async throws -> UnlockedProtectionKey   // the prompt; .publicKey of the unlocked key
}
@MainActor public final class SecretVault: ObservableObject {   // ConnectionManager.vault (app: shared with the editor)
    init(authenticator:, now:, reuseWindow:, destination: (Profile) -> ProfileDestination)
    static func protectedKinds(_ p: Profile) -> Set<SecretKind>   // connect: [.password], or [.totp] without a keychain password; always: both
    func needsPrompt(_ p: Profile, _ kinds: Set<SecretKind>) -> Bool   // a kind is encrypted and not unlocked
    func unlock(_ p: Profile, _ kinds: Set<SecretKind>, for: UserPresenceAction, fresh: Bool = false) async throws
    func secret(_ p: Profile, _ kind: SecretKind, for: UserPresenceAction, prompt: Bool = true) async throws -> String?
    func available(_ id: String, _ kind: SecretKind) -> String?    // plain, or decrypted within the reuse window; never asks
    func store(_ p: Profile, _ kind: SecretKind, _ value: String) throws          // encrypts when protected (public key only)
    func applyProtection(from old: Profile?, to new: Profile) async throws        // after a setting/mode change
    func reconcile(_ p: Profile) -> Bool                                          // hand-edited setting: encrypt plain protected items
    func forgetUnlessBound(_ p: Profile) / forgetUnlessBound(_ id, to: fingerprint) -> Bool   // drop values confirmed for another destination
    func hasDecrypted(_ id: String) -> Bool
    func reset() / reset(_ id) / prune()
}
public struct ProfileDestination { fingerprint: String; host: String; static func of(_ p: Profile, store: ProfileStore) -> ProfileDestination }
public enum ConfirmationWording { static let hasTouchID: Bool; static var settingName: String }   // "Confirm with Touch ID" / "Confirm with your password"
```

- `SecureEnclaveAuthenticator`: `SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl:)` with
  `[.privateKeyUsage, .userPresence]` (Touch ID or the login password / Apple Watch; not
  `biometryCurrentSet`, so a new fingerprint does not lock the key). `unlock` evaluates one `LAContext`
  (`evaluateAccessControl(…, operation: .useKeyKeyExchange)`, `localizedReason` =
  `UserPresenceAction.reason(name, host:)`: "connect to “Acme VPN” (vpn.example.com)" with the host of the
  destination read before the prompt ("vpn.example.com +2 more" when an OpenVPN config has several
  `remote` lines, which OpenVPN may try in any order with `remote-random`; without one "connect to “Acme VPN”"), "show the code for …" etc.,
  macOS prefixes "PassTunnel is trying to"; `touchIDAuthenticationAllowableReuseDuration` = 0, so a
  recent Touch ID unlock of the Mac never stands in for the prompt) and loads the key with it, so all key agreements of one unlock share
  one prompt. LAError → `PTError`: user/app cancel → `.userConfirmationCancelled`; `notInteractive`,
  `systemCancel` (no GUI session, e.g. SSH), lockout, no password → `.userConfirmationFailed(reason)`.
  A key blob this Secure Enclave cannot use → `ProtectionKeyUnusable`.
- `SecretEnvelope`: `ptse1:` + Base64(0x01 ‖ ephemeral X9.63 public key (65) ‖ nonce (12) ‖ ciphertext ‖
  tag (16)); ECDH(ephemeral, profile key), HKDF-SHA256 (salt = ephemeral ‖ recipient public key, info
  `PassTunnel secret v1`, 32 bytes), AES-GCM with the account (`<id>/<kind>`) as AAD. Other versions
  are recognized (`ptse…`) but not read. Tampering, a wrong key or a moved item →
  `PTError.protectedSecretUnreadable(kind)`.
- Reuse: one unlock decrypts every encrypted item of the profile into memory (bytes overwritten when
  dropped) for `Preferences.authReuseMinutes` (1/5/15, default 1) per profile, judged with the
  manager's clock (testable). `reset()` on sleep (`ConnectionManager.handleWillSleep`) and screen lock
  (app); `prune()` on every poll.
- `applyProtection(from:to:)`: makes the key when the setting is on (`.protectionUnavailable` without
  a Secure Enclave, before anything changes); encrypts plain items the new setting protects (no prompt);
  decrypts encrypted items it no longer protects (when still used, or when the setting is off), which
  asks; lowering the setting (`always → connect`, `→ off`) always asks with a fresh prompt (the reuse
  window never covers it), using the key once even when nothing is encrypted; deletes the key when the
  setting is off and nothing encrypted is left. A cancel leaves everything as it was.
- Hand-edited setting (`require_auth` changed in `profile.json`): `reconcile` encrypts plain items the
  setting protects (no prompt); it runs in `AppModel.reload`, `ConnectionManager.performConnect` and at
  the start of `needsPrompt` / `secret` / `unlock` (so before every CLI use). Encrypted items of a profile
  set to `off` are left encrypted (reading them asks) until `applyProtection` lowers the setting properly.
  Without a Secure Enclave nothing changes.
- Lost key (another Mac, an erased Secure Enclave): `ProtectionKeyUnusable` → the undecryptable items and
  the key record are deleted and `.protectedSecretUnreadable(kind)` asks the user to enter the secret
  again (a new key is made then). A tampered item is kept (the key still works) and reported the same way.
- Key record check (`ProtectionKeyMismatch`, not retried by reconnects): the record's X9.63 public key must
  be the public key of its Secure Enclave blob. Checked before encrypting (`ensureKey`, via
  `publicKey(keyData:)`) and before the prompt when the blob loads, and always on the unlocked key
  (`UnlockedProtectionKey.publicKey`), so secrets are never encrypted to, or decrypted with, a key a
  replaced record names.
- Destination binding: `ProfileDestination.of` is SHA-256 over a version tag, the type and, for OpenVPN,
  the exact bytes of `config.ovpn` (`host` = first `remote` plus "+N more" for the others,
  `OVPNAnalyzer.serverDescription`; `configSHA256` = the plain
  SHA-256 of those bytes, sent in `OpenVPNStart` so the helper runs no other file; nil when the file
  cannot be read, and then `performConnect` fails with `PTError.missingConfig` before any secret is read);
  for Forti, the trimmed lowercased host, the port and the trusted cert as `TLSFingerprint.normalize`
  gives it (separators and whitespace removed, lowercase, as the editor saves it; else trimmed lowercased). Each decrypted value stores the fingerprint
  read before its prompt; `forgetUnlessBound` overwrites and drops values whose fingerprint differs.
  `ConnectionManager` does the same for its session secrets (`sessionDestinations`): `connect` (before
  `needsPrompt`), `storedSecrets` (before use) and `revalidateDestinations` (every poll, `AppModel.reload`;
  reads only profiles holding such values) drop them, and the profile is marked in `changedDestinations`.
  An automatic or health-forced reconnect of such a profile, when it still needs a confirmation
  (`vault.requiresConfirmation`), does not run: `DestinationChangedError` (not retried) /
  `ConnectionEvent.destinationChanged`. A successful connect, a disconnect or that event clears the mark.

## Automation: `--json` and the MCP server

One model, two front ends. `Automation.swift` defines the result objects (`ProfileSummary`,
`ProfileStatus`, `StatusReport`, `HelperReport`, `LogReport`, `DiagnoseReport`/`ProfileCheck`,
`VersionReport`), the error object (`ErrorReport`, `ErrorEnvelope`; a failed connect's carries the
`ConnectionFailure` of a `ConnectFailedError`), the stable error codes
(`AutomationErrorCode`, mapped from `PTError`, `HelperClientError`, `DestinationChangedError`,
`CLIUsageError` by `AutomationErrorCode.of`) and the exit codes (`AutomationExit`).
`AutomationService` (`@MainActor`, one per CLI command or MCP server, over a `ProfileStore`, a
`ConnectionManager`, a `HelperInspecting` and `AppInfo`) builds them and runs the waiting connect
(`connect(_:given:force:timeout:joining:)`: a task group racing `ConnectionManager.connect` against
the deadline; on timeout or cancellation it stops the attempt only if the manager reported
`ConnectRole.started` for it, never a session it follows. `joining` passes `followOnly`, so a
connect that saw another process's attempt never starts one itself: it gets `NothingToFollow` when
that attempt has ended and the caller runs its own checks before starting) and disconnect
(`disconnect(_:wait:timeout:)`, polling `refresh`). `logs` drops management chatter and lines that
look like key material (`LogRedactor.isKeyMaterial`: `TLS: tls_` traces, hex runs of 32+ digits
except openfortivpn's `--trusted-cert` / `trusted-cert =` digest),
then `LogRedactor` masks credentials. `activity` (`log --activity`, `get_logs` with `source: "activity"`)
returns the activity log's last events without code digits (`ActivityEvent.withoutCodeDigits`), their
server, user name and reply passed through `LogRedactor`, each also worded with its local time. `PromptlessAuthenticator` wraps the Secure Enclave
authenticator for `--no-auth-prompt`.

```
passtunnel … --json ──▶ CLIRunner (PassTunnelCLI) ─┐
                                                    ├─▶ AutomationService ─▶ ConnectionManager, ProfileStore,
passtunnel mcp ──stdio──▶ MCPServer ─▶ MCPTools ────┘                        HelperInspecting, Secrets
```

`Secrets` is used for `has` (`diagnose`) and, in `logs`, for `get` of the profile's password and
TOTP secret: their plaintext values are what `LogRedactor` masks literally. Neither leaves the
process. An encrypted (Confirm with Touch ID) secret is not decrypted for this (`get` returns nil
for an envelope), so literal masking does not cover it; the keyword and pattern rules still apply.

- `CLIRunner` prints the objects with `AutomationJSON.encoder()` (the file style plus ISO 8601
  dates) and maps any error to `ErrorEnvelope` + `exitCode`. Command-only results (`show`,
  `export`, `rm`, `secret`, `default`, `code`) stay local to the runner.
- `MCPServer` decodes lines into a `JSONValue` (`JSONDecoder`: booleans are never numbers, integers
  stay exact; replies are written with `JSONSerialization`), dispatches requests as main-actor tasks
  keyed by JSON-RPC id (so `notifications/cancelled` can cancel one; an id already in flight gets -32600),
  writes each reply as one line through an injected `send` (stdout in `runStdio`, which reads stdin
  on a background thread through `LineReader`, at most 1 MiB per line, a longer one is skipped and
  answered with -32700, and ignores SIGPIPE; it also keeps a `VaultExpiry`, which resets the
  vault on screen lock and sleep as the app does). `MCPTools` holds the tool definitions and JSON
  Schemas (`Schema`), checks arguments (`Arguments`: every key must be consumed, a `null` counts as
  absent; `profile_id` via `Slug.isValid`; booleans must be JSON booleans and integers JSON numbers
  without a fraction) and encodes results with `AutomationJSON.object` for `structuredContent` and as text.
- `SystemHelperInspector` reads `HelperInstaller.status`, then asks a 5 s `HelperClient` for the
  protocol and build. `HelperClient.defaultMachServiceName` is `PT.helperLabel`; debug builds take
  `PASSTUNNEL_HELPER_SERVICE` instead, so a debug binary run against a temporary
  `PASSTUNNEL_HOME` never talks to the installed helper.

## Privileged helper

Registered with `SMAppService.daemon(plistName: PT.helperPlistName)`; the user approves it once in
System Settings → Login Items. App ↔ helper: `NSXPCConnection(machServiceName: PT.helperLabel, options: .privileged)`.
The helper only accepts connections whose code signature satisfies
`identifier "com.furkanprlk.passtunnel" and anchor apple generic and certificate leaf[subject.OU] = "YH4NUPFH74"`
(`NSXPCConnection.setCodeSigningRequirement`, macOS 13). Messages are JSON-encoded `Data` so the protocol
stays tiny and versionable:

```swift
@objc public protocol PassTunnelHelperProtocol {
    func version(reply: @escaping (Int) -> Void)
    func build(reply: @escaping (String) -> Void)                    // HelperBuild digest, protocol ≥ 3
    func perform(_ request: Data, reply: @escaping (Data) -> Void)    // HelperRequest → HelperResponse
}
public enum HelperRequest: Codable {
    case startOpenVPN(OpenVPNStart)        // profileID, profileDir, username?, secret? (password+otp already formatted), logPath,
                                           // configSHA256? ("config_sha256": hex SHA-256 of the config.ovpn the app checked)
                                           // (mgmtPort: Int? still decodes for protocol 1 payloads but is ignored)
    case startForti(FortiStart)            // profileID, profileDir, host, port, username, password, otp?, trustedCert, setDNS, setRoutes, logPath
    case startOpenConnect(OpenConnectStart) // protocol 4: Cisco AnyConnect ("Helper protocol 4" below); passtunneld too since #187
                                            // protocol 5: + protocol (anyconnect | gp), profileGatewayServerCert ("Helper protocol 5")
    case stop(profileID: String)
    case status                            // → running profile IDs with pid
}
public struct HelperResponse: Codable { ok: Bool; error: String?; errorCode: String?   // "error_code": ErrorCode.configChanged
                                         pid: Int32?; running: [String: Int32]?
                                         mgmtSocket: String?               // startOpenVPN → PT.mgmtSocketPath(uid, id)
                                         mgmtSockets: [String: String]?    // status → id → socket (caller's OpenVPN sessions)
                                         helperBuild: Int? }               // "helper_build", every reply (see below)
```

Requests carry `"protocol_version"`; the helper decodes them with `HelperCore.decodeRequest`, which
rejects, in this order: more than 64 KiB, anything but a JSON object, a version other than its own
(a missing version counts as 2), a missing or unknown `type`, then missing/mistyped fields (errors name
the field, never its value). `ConnectionManager` calls `ensureCompatible()` (the `version` XPC call, then
`build` when the protocol matches) before every start, so a helper left running from another app version
fails with `HelperClientError.versionMismatch`, and one from another build of the same protocol with
`.buildMismatch`. The build identity (`HelperBuild`) is the SHA-256 of the helper executable: the helper
hashes itself once at launch (a running helper keeps reporting the build it was started from after the
app bundle is replaced). It opens the path in the bundle, which the bundle's owner can swap, so
`HelperImage.open` (Shared) opens it with `O_NOFOLLOW | O_NONBLOCK` (a link or a FIFO put there never
leads it to another file or blocks it), requires a regular file of at most 256 MB (hard links are fine:
the next check decides), and accepts it only when the descriptor's device and inode are those of the vnode the kernel mapped as the
helper's own Mach-O header (`PROC_PIDREGIONPATHINFO` at `#dsohandle`): the mapping cannot be swapped,
whatever happens to the path. The digest is read from that descriptor, bounded. That fails only when the
path cannot be opened or names another file than the one running, i.e. it was replaced between the exec
and the open (an app update, or someone racing the helper). Then the helper still stages and runs
OpenVPN and FortiGate under a build ID from the kernel's cdhash of its own code
(`HelperImage.fallbackBuildID`, `csops`, no file read, 40 hex digits), refuses openconnect (no hook
source), and reports no build number (nothing read from the bundle is trusted then). The app compares
that ID with its own helper's digest like any other: another build, so `ensureCompatible()` fails with
`.buildMismatch` as it does for any helper that is not the bundled one (after every app update, too), and
`relation()` gives `.older` (no number), so `HelperAutoUpdate` replaces the helper once on its own (from
/Applications, when no session runs) and Settings → Helper offers the update until then; the replaced
helper is started from the bundle and verifies normally. The old code would have hashed whatever the
path named at that moment and could report a build it is not. `Info.plist` (the build number) is read
the same way: no link, no blocking, regular, bounded. The app/CLI hash `Contents/MacOS/PassTunnelHelper` next to their own executable
(no stamping in `build-app.sh` needed; skipped when there is no bundled helper, e.g. tests). `build` is a
separate call rather than a second `version` reply value so a protocol-2 helper is still recognized as
outdated. Digests only say "different"; which side is newer comes from build numbers: the helper reads
`CFBundleVersion` of the bundle it runs from once at launch (`HelperBuild.buildNumber(ofBundleContaining:)`)
and puts it in every `HelperResponse` as `helper_build` (an optional key, so the protocol version stayed
3; older helpers omit it). `HelperClient.relation()` (version, build, then a `status` for the number) feeds
`HelperBuild.relation(helperProtocol:helperDigest:helperNumber:appDigest:appNumber:)` →
`.current` (same digest, or no bundled helper), `.older` (lower protocol or number, or no number
reported), `.newer` (higher protocol or number) or `.different` (same number, or the app's own number
unknown). The app keeps it in `AppModel.helperRelation`; any relation but `.current` shows Settings →
Helper as "Needs an update", whose
**Update Helper** button unregisters the daemon (launchd stops it, which stops its tunnels) and
registers it again from the running app bundle (`HelperInstaller.update`, Core, behind the
`HelperRegistrar` protocol so it is unit-tested with a fake). Right after the unregister, launchd may
refuse the new registration with EPERM ("Operation not permitted") for a few seconds, so `update` waits
up to 1.5 s for the old job to leave `.enabled` and retries EPERM after 0.5, 1, 2 and 3 s; only then does
it fail (`HelperInstallError.notPermitted`). `kSMErrorLaunchDeniedByUser` (switched off in Login Items)
is not retried (`.deniedByUser`); `kSMErrorAlreadyRegistered` counts as success. The button click is the
confirmation, except for a `.newer` helper (asked fresh), which first shows a downgrade warning.
`HelperInstaller.update` itself does not decide who may take over; its callers do.

After an app update (Sparkle replaces the bundle; the running helper keeps its old build) the app
runs that update by itself (`AppModel.updateHelper`, the same flow as the button), decided by
`HelperAutoUpdate` (Core, unit-tested): only for an enabled helper known to be outdated **and** older
(`Situation.helperIsOlder`, relation `.older`: a newer or not comparable helper stays until the user
replaces it), only when the app runs from `/Applications` (`HelperSessions.isInApplicationsFolder`,
symlinks resolved; not `~/Applications`, which any process of the user can write, and never a test build
elsewhere), at most once per outdated helper (a failure is left to the button), and only while no
PassTunnel session is active. Sessions are counted by `HelperSessions` from the process list
(`sysctl KERN_PROC_ALL` + `proc_pidpath`), of any user: children of a `PassTunnelHelper` process;
`openvpn`/`openfortivpn`/`openconnect` run from the helper's staged copy
(`<run root>/tools/<build>/Resources/bin/…`, as written and resolved, `HelperSessions.stagedToolsRoots`;
only root writes there), which is where tools adopted by a restarted helper run, with launchd as their
parent; and the same tools inside an app bundle whose identifier is PassTunnel's (or that is gone,
replaced by the update). So other users' sessions and adopted tools count too;
plus the profiles the app itself sees as active. While sessions are active it notifies once ("The
helper needs an update"), Settings → Helper says it updates itself, and the app re-evaluates on every
5 s reload, so the update runs right after the last session ends.

Hand-offs from outside the app (`HelperHandoff`: `passtunnel helper install|uninstall`, the
`--install-helper` / `--update-helper` / `--uninstall-helper` launch arguments or the distributed
notification) can come from any local process, so `HelperSettings.runPendingAction` installs or updates
only from `/Applications` and asks before replacing an enabled helper (`.older`/`.different`, or no
answer for `update`: "Replace the PassTunnel helper?"; `.newer`: the downgrade warning) or removing it
(docs/APP.md, CLI). The app answers the waiting CLI on `HelperHandoff.replyNotification` (object
`"<action>:<outcome>"`, `HelperHandoff.Outcome`): `asking` when it shows a confirmation, `declined` when
the user cancels it (or a newer request replaces it), `refused` when this copy is not in
`/Applications`. `HelperHandoffWait` (Core, unit-tested) holds the CLI's deadline: 30 s for `install`,
60 s for `update` / `uninstall`, moved out to 10 minutes (`confirmationTimeout`) once the app asks; a
decline or refusal ends the wait at once. The replies are distributed notifications any local process
can post, so they only choose the message: whether the action happened is always read from the helper
itself (`SMAppService` status, and for `update` the running helper's protocol and build), and a forged
reply can at most make the CLI give up early or report the wrong reason.

Run directory layout (all root-owned; `HelperCore.makeRunDir`):

```
/var/run/passtunnel/            0711   run root
  <uid>/                        0711   one per user
    <profileID>/                0711   one per session, recreated on start, removed when the tool exits
      config.ovpn | openfortivpn.conf | openconnect.conf, auth, policy, dns-updown, dns-hook, dns-up.env, state
                                0600/0700 root
      mgmt.sock                 0600   owned by <uid> (OpenVPN only)
  tools/                        0755   staged tools (`ToolStager`), root:wheel
    <helper build>/             0755   hex SHA-256 of the helper executable (`HelperBuild.digest`)
      Resources/bin/openvpn, openfortivpn, openconnect, vpn-hook   0555
      Frameworks/*.dylib        0444
```

Users can traverse to their socket by name but cannot list, rename or replace entries, so handing the
socket to the user (`SessionDirectory.restrictSocket`: `fstatat`/`AT_SYMLINK_NOFOLLOW` on the directory
descriptor, then `fchownat`/`fchmodat`) cannot be redirected to another file. A restarted helper adopts
tools recorded in `<uid>/<id>/state` (`SessionState`: pid, uid, staged executable, profile directory,
socket; read back only from a regular, single-link file the helper owns); tools recorded by a protocol-2
helper (`<root>/<id>/state`) are stopped, since their socket is in the profile directory. The state is
written, atomically (a new file renamed over it), before the tool runs, in `Spawner.spawnVerified`'s
`beforeResume`, with the tool's start time (`ProcessStart`, `proc_pidinfo` `pbi_start_tvsec`/`_tvusec`:
with the pid, the process's identity) and a last line `launching`, and again without that line once the
tool was resumed. A helper that died in between leaves a tool that may never run, so `adoptOrphans`
decides by the record (`SessionRecovery.decide`): the process at the recorded pid must run the recorded
executable and, when the record has one, have the recorded start time, or the record is stale (cleaned
up: DNS undone, directory removed); a matching record without `launching` is adopted (also when the tool
is stopped, by a debugger say); one with `launching` is an interrupted launch: that process alone gets
`SIGKILL`, and the session is cleaned up like one whose tool ended. A record without a start time (older
helpers) is never killed: the old rule (pid and executable) adopts or cleans up. Strays: a stopped
process of the staged copy (`<run root>/tools/…`) with effective and real uid 0, inherited by launchd and
named by no record (the helper died before writing any) is killed too (`strandedLaunches`); a user who
runs the staged tool gets a process of their own, which is never touched. Every signal re-reads pid,
start time, executable (and for strays the rest) right before it is sent, and goes to that pid alone,
never a process group (`SessionRecovery.signal`). A tool killed right after its resume, before the second
write, ends like one never resumed: nothing can tell whether it ran, and stopping is the safe side.

Security rules (helper):
- Runs **only** the tools inside its own app bundle (`Contents/Resources/bin/…`), never a path supplied by
  the client, and only code signed with the tool's identifier and our Team ID (`PT.toolRequirement`).
  It runs them from a root-owned copy (`ToolStager`, Shared): the bundle is writable (and renamable) by
  the user who installed it, and a tool started there would load its dylibs from there after `SIGCONT`,
  checked only for the Team ID by library validation. `ToolStager.stage(inUse:)` (on every start, on the
  supervisor queue): `<runRoot>/tools/<buildID>` (run root realpath'd, so the path matches
  `proc_pidpath` for adoption) is checked (`check`: exactly `Resources/bin/{openvpn,openfortivpn,openconnect}` (and
  openconnect's `vpn-hook`, checked on its own, `stageHook`) and
  the expected dylibs in `Frameworks/`, no other entries, every entry `lstat`-ed: not a symlink, owned by
  the helper's euid, one link, mode exactly 0755/0555/0444; each file `CodeSignature.verify(path:)` with
  `PT.toolRequirement` or, for dylibs, `PT.teamRequirement`, then its cdhash against `PinnedTools`).
  If that fails it is removed and staged again: copied into `.<buildID>.partial` (`open` with
  `O_NOFOLLOW`, regular file, ≤ 256 MB, `fcopyfile` data only into an `O_EXCL` file, `fchown` 0:0 as root,
  `fchmod`), checked the same way, then renamed into place; a failure removes the partial copy. Expected
  dylibs: the keys of `PinnedTools.libraryCDHashes` in a pinned build, else every `*.dylib` entry in
  `Contents/Frameworks` (a symlink is listed and then refused by the copy). Then every other entry of
  `tools/` is removed except the build directories of running jobs (`buildDirectory(ofExecutable:)`), so
  adopting a tool after a helper update still finds its executable. The build ID is the helper's
  `HelperBuild.digest` (must be 16–64 lowercase hex). `adoptOrphans` skips `tools/`.
  `Spawner.spawnVerified` (Shared) then starts the staged tool with `POSIX_SPAWN_START_SUSPENDED` and runs the
  `LaunchVerifier` (`RequirementVerifier` → `CodeSignature.verify(pid:)`: `SecCodeCopyGuestWithAttributes`
  by pid + `SecCodeCheckValidity` with `kSecCSStrictValidate`, which also fails with
  `errSecCSStaticCodeChanged` when the file no longer is what the kernel mapped) on the stopped process;
  only then `SIGCONT`. A failed check (or a failed `SIGCONT`) → `SIGKILL` + `waitpid` before it ran; the
  pid is our unreaped child, so it cannot have been reused. The file check alone would race: posix_spawn
  opens the path again. Security finds the process's code through its path (`proc_pidpath`): if the file
  was unlinked meanwhile, `SecCodeCopyGuestWithAttributes` fails with ESRCH (`100003`) instead, also a
  refusal; the staged files are root-owned, so this only happens when they are tampered with. The
  `dns-updown` copy is still checked by path (OpenVPN runs it, through `dns-hook`; the helper only for a
  dns-down OpenVPN skipped, checked again then: "DNS script (macOS)" below).
- cdhash pins (`PinnedTools`, Shared): `PT.toolRequirement` accepts any build the team ever signed, so a
  pinned helper also requires the exact tool and dylib builds of its release. `PinnedTools.libraryCDHashes`
  (file name in `Contents/Frameworks` → cdhashes) is checked by `ToolStager` on the staged dylibs (only
  when tools are pinned; a dylib without an entry is refused). `PinnedTools.cdhashes` (file name in
  `Contents/Resources/bin` → accepted lowercase-hex cdhashes, one per architecture) comes from
  `generatedCDHashes` (written by `build-app.sh`, see above); without the compile flag
  `PASSTUNNEL_TOOL_PINS` it is empty and nothing is pinned (`swift build`, tests). `allowed(tool)` → nil when nothing is pinned, else the tool's set (empty for a
  tool without an entry: refused). `RequirementVerifier(requirement:cdhashes:)` checks the cdhash
  `CodeSignature.verify(pid:)` returns (`kSecCodeInfoUnique` of the static code the kernel-matched
  validation used, not read from disk again); the `dns-updown` copy's cdhash from `verify(path:)` is checked
  the same way. A mismatch → `PinnedTools.Mismatch` ("… is not the build this PassTunnel was released
  with").
- `Spawner.spawn`: new process group, stdin `/dev/null`, stdout+stderr to the log descriptor, all signals
  default, empty mask, `POSIX_SPAWN_CLOEXEC_DEFAULT`, environment `HelperCore.environment(for:)`, built
  from fixed values and never inherited: `HelperCore.fixedEnvironment`, and for openconnect two more
  ("Fixed environment" under Cisco AnyConnect below). `fixedEnvironment`:
  `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `LC_ALL=C`, `OPENSSL_CONF=/dev/null`,
  `OPENSSL_MODULES` = `OPENSSL_ENGINES` = `/var/empty/passtunnel-none` (`HelperCore.missingDirectory`,
  never created), `SSL_CERT_FILE=/etc/ssl/cert.pem` (`HelperCore.systemCAFile`), `SSL_CERT_DIR=/var/empty`,
  so the bundled libcrypto loads no config, providers or engines from its compiled-in Homebrew prefix and
  trusts the system CA bundle by default.
- **DNS script (macOS).** OpenVPN's `--dns-updown` is OpenVPN's own macOS script (Homebrew's
  `libexec/openvpn/dns-updown`, the release's `distro/dns-scripts/macos-dns-updown.sh`), bundled unchanged,
  signed and pinned; its copy `dns-updown` runs as root through `dns-hook`, a wrapper the helper writes
  into the run directory (`HelperCore.dnsHookText`, `HelperCore+DNSHook.swift`). How it handles what a
  server pushes (issue #151; checked against the OpenVPN 2.7.8 sources and that script, line numbers from
  them):
  - *What reaches it.* Only `dev`, `script_type` and the `dns_*` variables of `setenv_dns_options`
    (`dns.c` 504–569), in an environment built fresh for each run (`do_run_up_down_command`, `dns.c`
    572–588; `make_env_array` adds nothing, `env_set.c` 440–474): no pushed `setenv`, no `PATH`. Pushed
    `dhcp-option DNS`/`DNS6`/`DOMAIN`/`DOMAIN-SEARCH` become `dns_*` only when no `dns` server is set
    (`dhcp_options_postprocess_dns`, `options.c` 3625 ff.). OpenVPN checks every value first: addresses are
    parsed as numbers (`AI_NUMERICHOST`, `socket_util.c` 575; `dns.c` 62–145; `options.c` 1321–1359) and
    printed back by OpenVPN, ports are 1–65535 (`dns.c` 48–59), `dnssec` and `transport` fixed words
    (`options.c` 5364–5402), and every name (`search-domains`, `resolve-domains`, `sni`, `DOMAIN`,
    `DOMAIN-SEARCH`) passes `validate_domain`: ASCII letters, digits, `.`, `-`, `_`, and bytes from 0x80
    (`domain_helper.h` 24–45). `setenv_str` also drops control characters from every value (`CC_PRINT`,
    `env_set.c` 307–310, `buffer.c` 917, 1045–1075). A server cannot name another script: `dns-updown`
    needs `OPT_P_SCRIPT` (`options.c` 7927), which pulled options never have (`init.c` 2520–2533).
  - *Can a value change what runs or is written?* No issue found for the values: none can hold
    whitespace, quotes, `$`, a backquote, `;`, `\`, `/`, `*` or a line break. So the `echo -e` that feeds
    `scutil` its commands (script lines 154, 178, 238, 255, 285) cannot get an escape or another command
    line, `sed -e "s/$1//"` (162, 172) neither a delimiter nor a flag, and the unquoted `=~` patterns (203,
    218) only match. Values reach `scutil` on its input after `d.add <key> *`, where each word becomes an
    element of the array (a leading `-` too), never as an argument; `networksetup` is not used; the keys
    are `State:/Network/Service/openvpn-<dev>/…` (`dev` is the tunnel OpenVPN opened) and the primary
    service's, read from `scutil`, never a value; the only files the script creates are `/var/lock` and its
    lock in it. Bytes from 0x80 that are not UTF-8 make `scutil` abort in the middle of its input (an
    uncaught `NSInvalidArgumentException`), so DNS is not set for that session — no more than a server
    that pushes no DNS. **Found:** the script runs `sleep`, `grep`, `cut`, `xargs` and `sed` by name (42, 51, 56, 162,
    172) and sets no `PATH`, so `/bin/bash` falls back to `/usr/gnu/bin:/usr/local/bin:/bin:/usr/bin:.`;
    on a Mac where `/usr/local/bin` belongs to a user (Homebrew on Intel), a program that user put there
    would run as root at every connect, past the pin. `dns-hook` sets
    `PATH=/usr/bin:/bin:/usr/sbin:/sbin` (`HelperCore.dnsScriptSearchPath`) before it runs the script with
    `/bin/bash` (the `.` at the end of bash's path was the run directory, which only root can write).
  - *Can a value leave DNS behind or move another service?* With `resolve-domains` the script adds
    `State:/Network/Service/openvpn-<dev>/DNS` and puts the search domains on the primary service;
    without, it backs up the primary service's `Setup:` DNS and replaces it (the VPN's DNS for everything,
    as intended), and its dns-down restores it only while that service's servers are still the ones it
    set (274–285: otherwise "not restoring global DNS configuration, server addresses have changed", and
    the backup is dropped — e.g. after a network change during the session). No value chooses the
    service. **Found:** OpenVPN 2.7 forgets its `--dns-updown` when a `PUSH_UPDATE` carries `dns` or
    `-dns`: `update_option` and `remove_option` clear all of `dns_options`, `updown` included (`options.c`
    5492–5504, 5180–5185), so neither `do_update` (`init.c` 2467–2514) nor the final close runs a dns-down
    (`run_up_down_command` returns without `updown`, `dns.c` 702), and what the connect set stays after
    disconnect. A client takes `PUSH_UPDATE` from any server unless DCO is on (`ssl.c` 1978–1983, `push.c`
    1127–1135), and DCO is not used on the Mac. `dns-hook` therefore records the variables of each dns-up
    in `dns-up.env` (0600) and removes the record after a dns-down. A record left when the tool has
    exited (`Supervisor.finish`, `stopAll`, and `adoptOrphans` for a tool that ended while no helper ran)
    is a dns-down OpenVPN skipped: the helper checks the `dns-updown` copy again and runs it with
    `script_type=dns-down` and the recorded variables (`HelperCore.pendingDNSDown`: a regular, single-link
    file it owns, at most 64 KB, only `dev` and the `dns_*` names OpenVPN sets, values of the characters
    above, else nothing runs), output into the session's log, for at most `dnsRestoreTimeout` (10 s),
    before the run directory goes. This also covers a tool killed after `stopGrace`. The Linux daemon
    reverts what its own hook recorded in the same way (LINUX.md, "DNS").
  - *For OpenVPN upstream:* a fixed `PATH` in the script; keeping `updown` across a `PUSH_UPDATE` and
    running the dns-down of the old values before replacing them; the lock in `/var/lock`, which the script
    creates mode 1777 (29–33), so any local user can hold `openvpn-dns-updown.lock` with the pid of a live
    process and make every dns-up and dns-down give up after ten tries; `.` matching any character in the
    `sed` and `=~` patterns (exact matching would never touch another domain); a pushed `DOMAIN-SEARCH`
    without `DOMAIN` gives no `dns_search_domain_1` (the first entry's name is NULL, `options.c` 3684, and
    `setenv_str` then unsets the variable), so the script, which stops at the first gap, uses none of them.
- `profileDir` must be a real directory under the *calling user's* home `Library/Application Support/PassTunnel/profiles/`
  (resolve symlinks; check owner uid == caller's euid from the audit token), not group- or world-writable.
  `config.ovpn` must be a regular, single-link file owned by the user and not group- or world-writable.
  Profile IDs: ASCII letters, digits, `-`, `_`, `.`, 1–64 bytes, no leading `.`/`-`, no trailing `.`.
- OpenVPN: reads `config.ovpn` from profileDir; when the request has `configSHA256` (always from this app
  version; optional so older requests decode) and the bytes read hash differently, fails with
  `HelperCore.Failure.configChanged` (`errorCode` `config_changed`), which `ConnectionManager` turns into
  `DestinationChangedError`. It then runs the file through `OVPNSanitizer` (rejects `up`, `down`,
  `route-up`, `route-pre-down`, `ipchange`, `learn-address`, `client-connect`, `client-disconnect`,
  `tls-verify`, `auth-user-pass-verify`, `plugin`, `script-security` > 1, `management*`, `log*`, `daemon`,
  `writepid`, `cd`, `chroot`, `user`/`group`, `config`, `show-pkcs11-ids`, `genkey`, `port-share`,
  `client-crresponse`, server and standalone modes (`server*`, `tls-server`, `mode` other than `p2p`,
  `mktun`/`rmtun`, `show-*`, …), a `dev` name that is not a device type, a listening protocol
  (`tcp-server`, `tcp4-server`, `tcp6-server` in `proto`, `proto-force`, or as the third argument of
  `remote` or `local`: `OVPNSanitizer.listeningReason`), a config without any `remote` OpenVPN takes as
  one (exactly `remote`, with one leading `--` or one `setenv opt` prefix, 1–3 arguments, also in a
  `<connection>` block; without one OpenVPN waits for a peer to reach it: `OVPNSanitizer.missingRemote`,
  reported as line 0, which `Violation` and `OVPNSkipRules.Blocking` list without a line number),
  external files incl. a `socks-proxy` credentials file, TLS settings below the 1.2 floor (`tls-version-min`
  other than `1.2`/`1.3` with an optional `or-highest`, `tls-version-max` other than `1.2`/`1.3`, a `tls-cipher`
  whose `@SECLEVEL` is not exactly 1–5 or whose adding elements (not `!`, `-`, `+`) name `NULL`, `EXP`, `ADH`, `AECDH`, `anon` or
  `COMPLEMENTOF`, `tls-ciphersuites` outside the four encrypting TLS 1.3 suites, `tls-cert-profile` other than
  `legacy`, `preferred`, `suiteb`: `OVPNSanitizer.tlsReason`; they block an import), and, like OpenVPN's own
  parser, a backslash outside single quotes that does not escape `\`, `"` or whitespace, or ends the line, and a line that
  starts with a byte order mark anywhere but at the start of the file; strips `static-challenge`; the same
  check for every config, also those whose import commented out refused lines, `OVPNSkipRules`), writes
  the sanitized copy and the auth file into the session's run directory, then runs openvpn with fixed flags (`--management <runDir>/mgmt.sock unix`
  `--management-client-user <caller's user name>` so only the calling user can talk to it, no
  `--management-hold`; `--verb N` with the config's last `verb` capped at 4, 3 when it sets none
  (`HelperCore.openVPNVerbosity`, from `OVPNSanitizer.verbosity(of:)`); `--auth-nocache`,
  `--remap-usr1 SIGTERM`, `--connect-retry-max 3`, `--tls-version-min 1.2` (`1.3`, with `or-highest` if given,
  when the `tls-version-min` OpenVPN applies is 1.3: `OVPNSanitizer.tlsVersionFloor(of:)`, which recognizes lines
  exactly as OpenVPN 2.7 does (`OVPNSanitizer.openVPNOption`: one leading `--`, case-sensitive names, one exact
  `setenv opt` with no `--` after it), so a line OpenVPN ignores, like `setenv opt TLS-VERSION-MIN 1.2`, changes
  nothing and the flag never lowers the config; OpenVPN takes the last `tls-version-min` it reads, and this one follows `--config`, so it holds even for a
  spelling the sanitizer missed), stdout/stderr to logPath). Only the pull filters and `--server-poll-timeout 10` come before `--config`. `--pull-filter ignore` for each of
  `HelperCore.ignoredPushPrefixes` (`verb`, `"verb`, `'verb`, `\`) drops a pushed `verb`, which would
  otherwise raise the capped level after connecting: OpenVPN compares the start of each pushed option
  (after leading whitespace) with the filters in the order it read them, the command line up to
  `--config` and then the file, and the first match decides, so a profile's own `pull-filter accept verb`
  never comes into play; the quoted spellings and a line starting with an escaped space are what
  OpenVPN's parser also reads as `verb`. `--server-poll-timeout 10` (`HelperCore.serverPollTimeout`): OpenVPN 2.6 and 2.7
  then give up on a server that does not answer after 10 s instead of 120 (it bounds the TCP connect and,
  over UDP and TCP, the wait for the server's first packet: "Server poll timeout"); before the config, so
  the `<connection>` blocks inherit it (OpenVPN copies the options in force where a block is read) and a
  config's own value wins. With `--remap-usr1 SIGTERM`, the restart OpenVPN schedules after a failed try
  (`connection-failed`, `server_poll`, `tls-error`) is remapped to an exit, so each run makes one try and
  `--connect-retry-max` never comes into play; `ConnectionManager` tries again. A change of these flags
  changes the helper's build (its digest), not `PT.helperProtocolVersion`: the requests and replies stay
  the same, and an app update replaces the older helper (`HelperAutoUpdate`). Once OpenVPN creates the socket the helper chowns it to the user with mode 0600; it goes away
  with the run directory when the process exits. The socket path must fit in `sun_path` (103 bytes):
  `/var/run/passtunnel/<uid>/<id>/mgmt.sock` fits 64-byte IDs for uids up to 8 digits.
- Forti: the helper writes the openfortivpn config itself from the typed fields (no user-supplied raw config;
  no pppd options). Values longer than openfortivpn's buffers (`src/config.h`: host 253, user name 64,
  password 256, code 64 bytes; it cuts them off silently) are refused: `FortiConfig.maxHostBytes`,
  `maxUsernameBytes` (64), `maxPasswordBytes` (255), `maxOTPBytes`; `ProfileStore.save` and
  `ConnectionManager` refuse a longer user name first (`PTError.usernameTooLong`, counted in UTF-8 bytes).
  The host (`FortiConfig.isValidHost`) is a name of ASCII letters, digits, `.` and `-`, or an IPv6 literal
  of hex digits, `:` and `.` with an optional zone id of letters and digits (`fe80::1%en0`); every character
  is checked in Swift before `inet_pton` sees the address, so a NUL, a control character or whitespace can
  neither end the C string early nor start another config line. `ProfileStore.save` (editor, `passtunnel
  set`, share-file import) and `ConnectionManager` refuse such a host before the helper does
  (`PTError.invalidField("host")`). The finished text is checked again before it is written
  (`FortiConfig.checkRendered`: the expected number of lines, no NUL, CR or other control byte, only the
  header comment and `key = value` lines with the keys `render` writes, each once and in order). The helper's
  other line files for root (the OpenVPN `auth` file and its own `state` file) pass `HelperCore.checkLines`
  (exact line count, no NUL or CR), and the written `config.ovpn` is checked for NUL bytes once more.
  OTP is passed in the config (`otp = …`), so no pinentry is needed. Every config sets
  `ca-file = /etc/ssl/cert.pem`, so openfortivpn never uses OpenSSL's compiled-in default store
  (`HelperCore.caFile`; the Linux daemon sets the distribution's bundle and `fortiHandlesDNS` false,
  which renders `set-dns` and `pppd-use-peerdns` as 0: LINUX.md).
- Tracks the pid it started per profile; `stop` only signals that pid (SIGTERM, then SIGKILL after 5 s).
  Several Forti/OpenVPN profiles may run at once, at most `SessionPolicy.maxSessionsPerUser` (8) per user.
  `SessionPolicy` decides, keyed by (caller uid, profile ID): two users may run the same ID; starting one of
  your own running IDs fails; `status` lists only the caller's sessions (root included); another user's session
  is invisible, so `stop` of it is the same successful no-op as an unknown ID (idempotent).
- Logs: `vpn.log` is recreated for every session (`ProfileDirectory.createLogFile`, `O_APPEND`, readable);
  the supervisor keeps a copy of the descriptor and once a minute runs `HelperCore.capLog`: above 5 MB the
  file keeps its first 64 KB (start-up: tunnel device, pushed options, route/DNS set-up) and its last 1 MB,
  whole lines, with a marker line in between.

`HelperClient` (Core) wraps the XPC connection with async functions. `ManagementSocket` (Core) is a
one-shot client for the OpenVPN management socket: `ManagementSocket(path:).command(_:timeout:)` connects,
reads the banner, sends one command and reads until `END` / `SUCCESS:` / `ERROR:` (retrying briefly while
the socket is not there yet or another client is connected); `state()` returns
`ManagementState(name, localIP, since, …)`. `ConnectionManager` (Core) owns state per profile: OpenVPN
state via `ManagementSocket` on the socket the helper reports (`HelperResponse.mgmtSocket` after start,
`mgmtSockets` in each `status` poll, so sessions started by the CLI or before an app restart are found;
`PT.mgmtSocketPath(uid: geteuid(), …)` only as a fallback) (`state` command; first field = since,
refused unless it is a finite time between 1970 and 2100, also when read back from `.mgmt-state`;
disconnect = helper `stop`). The CLI uses one-shot queries (`SocketManagementQuerier`). The app uses
`PersistentManagementQuerier`: one held connection per socket with `state on`, following `>STATE:`
notifications and reopened on the next poll after a drop — OpenVPN logs every client connect, command and
disconnect, so a 3 s one-shot poll grew the log by ~7 MB a day. OpenVPN serves one management client at a
time, so while the app holds it a one-shot query finds it busy; the app therefore writes the state it
sees (only on change) to `<profileDir>/.mgmt-state` with the OpenVPN pid and its own pid, and a busy query
falls back to that file when the pid matches the helper's `status` and the writer is still alive.
When the interface cannot be read and no live writer shares the state (another client holds it, or the
app that wrote the file has quit) while the helper still runs that OpenVPN, the app and the CLI use the
last state written for the same pid even from a dead writer, else the log ("Initialization Sequence
Completed" with no restart after it; address from the `ifconfig` line), and mark the profile in
`ConnectionManager.statusUnavailable` — shown as "Connected (status unavailable)" — instead of
"Starting…". The app retries the interface on every poll and takes it over once it is free.
Forti state comes from helper `status` + log (`Tunnel is up and running`, `Got addresses: [...]`). It resolves
credentials (Keychain / TOTP / caller-supplied for `.ask`), builds what is sent with
`OTPComposer` (Core, pure + unit-tested):
- `.combined`: `otpTemplate` with `{password}` / `{otp}` substituted (no other placeholders; literal text kept)
  → OpenVPN auth-file password, or Forti `password` (Forti `otp` then omitted)
- `.separate`: OpenVPN → `SCRV1:b64(password):b64(code)` (static-challenge), Forti → `password` + `otp` fields
waits for the next TOTP window if the current window's code was already sent (always: servers reject a
reused code; recorded in `.last-otp` once the helper started the tool, and put back when the tool's log
shows the sign-in never reached the server, `ConnectionFailure.credentialsSent`) or, with
`Preferences.waitForFreshCode` (default on, read from `config.json` at every connect), if 5 s or less
remain, and publishes `ConnectionState` changes:

```swift
public enum ConnectionState: Equatable { case disconnected, connecting(String), connected(ip: String, since: Date?) }
```

A server that did not answer (`ConnectionFailure.Kind.unreachable`: nothing reached it, so its code was
given back) is tried again when `retriesUnreachable` is on (the app): every `Timing.unreachableRetryDelay`
(30 s), at most `unreachableMaxTries` (10) tries in all, after a connect of the manager (manual or at login)
and after a drop's automatic reconnects (5, 15, 45 s; decision D-7). `host_not_found`, a rejected sign-in
and every other failure end it. Each try is `performConnect(interactive: false)` with a fresh code: a
protected profile uses the session's or the reuse window's secrets, else it stops with
`confirmationRequired`. `unreachableRetries` (published) and `unreachableRetry(_:)` (also another live
process's, from `profiles/<id>/.retry`) hold the tries, when the first and the last failed, and
`nextTryAt`; `retryNow` is "Try now"; `disconnect` (any process: the user-stopped marker, read on every
poll) and any manual connect end it. The manager watches the network path while it runs
(`networkStatus`): offline, the retries wait (`waitingForNetwork`); online again or on another network,
they start over (count from zero, next try after `networkSettleDelay`, 2 s). After a drop, a success is
`reconnected` and the last try `reconnectFailed`; a manual connect's retries send no events.
`failureDetails(_:)` is the "Copy details" text (`FailureDetails`).

A second `connect` while one of the same manager is in flight awaits it. When the helper already runs the
profile (another process — app or CLI — is connecting it, or won the start race and the helper refused ours),
the manager follows that session until it is up and never stops it on failure; the CLI prints
"Already connecting …; waiting for it…" and exits 0 once it is connected. `disconnect` returns whether
anything was stopped (the helper's `stop` reply names the pid), so the CLI says "X is not connected." otherwise.

Another VPN that already takes all traffic (e.g. another OpenVPN client with `redirect-gateway`) and a
PassTunnel profile that does the same cannot run together: OpenVPN's route adds for `0/1` and `128/1` fail
with "File exists", the DNS hook (`dns-updown`) refuses with "setting DNS failed, already redirecting to
another tunnel", and — inherent to OpenVPN — on teardown it deletes `0/1` and `128/1` anyway (the
`redirect-gateway def1` undo does not check whether its own adds succeeded), which breaks the other
tunnel. Hence:
- Before starting an OpenVPN profile that redirects the gateway (`OVPNAnalyzer.redirectsGateway`: a
  local `redirect-gateway`; unknown → the last session's log shows it was pushed), `ConnectionManager`
  reads the IPv4 routing table (`RoutingTable.trafficRoutes`: `ipv4Routes`, `sysctl NET_RT_DUMP`; Linux:
  LINUX.md) and refuses with
  `PTError.otherVPNActive("utunN")` when `default`, `0/1` or `128/1` (unscoped) goes through a VPN
  interface (`utun`, `ppp`, `ipsec`, `tun`, `tap`) that is not one of PassTunnel's running sessions (their
  interface comes from "Opened utun device …" / "Interface pppN is UP" in their logs; on Linux also
  "TUN/TAP device tunN opened" / "DCO device tunN opened").
  `passtunnel connect --force` skips the check.
- Two tunnels that claim the same routes or DNS names are a warning, never a refusal (`NetworkClaims`, Kit;
  `ProfileNetwork`, Core). `ConnectionManager.checkCanStart(id)` (after the check above) also returns the
  `ProfileOverlap`s of `id` with PassTunnel's own running sessions (the helper's `status` plus the manager's
  active states; `overlaps(for:)` is the same without the other-VPN check, for `--force`), and the CLI and the
  MCP `connect` warn and go ahead (`ConnectWarning`, CLI-JSON.md). What a profile claims is
  `OVPNAnalyzer.networkClaims(config, pushed:)`: its `route`, `route-ipv6`, `redirect-gateway`, `dhcp-option`
  and `dns` lines and the options its server pushed, less what `route-nopull`, `route-noexec` and
  `pull-filter` refuse (a route via `net_gateway` or `remote_host` does not use the tunnel). The push is
  read from the log at `--verb 3`, which PassTunnel runs unless the config says otherwise: OpenVPN logs
  `PUSH: Received control message: 'PUSH_REPLY,…'` at its `D_PUSH` level (3), in several lines for a big
  push (`push-continue 1` on all but the last); `VPNLog.pushedOptions` keeps only routes, redirects and DNS,
  and reads server text with limits (a line of at most 16 KB, 512 bytes and printable ASCII per option, 1024
  options). openfortivpn logs only the gateway's DNS (`Got addresses: …, ns […], ns_suffix […]`), its routes
  come from the routing table through the tunnel interface (`RoutingTable.routes(onInterface:)`: the Mac's
  IPv4 table, Linux's rtnetlink; link-local, multicast and the session's own address left out). After every
  connect this process started, the options go to `profiles/<id>/network.json` together with the
  `ProfileDestination` fingerprint they belong to: the check runs before the new tunnel exists, so it uses
  that file (a profile that never connected is compared by its config lines only), and for a profile that
  runs, its log first. `NetworkClaims.overlaps` is exact CIDR math for IPv4 and IPv6 (containment both ways,
  `/0`, host routes), names match when equal or one is a suffix of the other on a label boundary, and a tunnel
  that carries all traffic meets anything the other claims. The warning does not say which tunnel gets the
  traffic (the Mac keeps the first of two identical routes, a narrower route wins over a broader one).
- While connecting, the log is checked (`VPNLog.setupProblem`): a failed DNS hook or a failed route for
  `0/1`, `128/1`, `default` (or the IPv6 equivalents) is `PTError.setupFailed` — the session is stopped
  instead of being reported connected (with the caveat above about OpenVPN's teardown; the pre-connect
  check is what keeps the other tunnel intact). Any other failed route leaves the session connected with
  `ConnectionManager.warnings[id]` ("Connected, but part of the network setup failed: …"), shown as
  "Setup incomplete" in the app (main window and menu bar) and after the status in the CLI. Not
  counted: "File exists" for a route (destination and mask, from the `/sbin/route add` line) this
  session already added successfully — OpenVPN adds the server's host route up to three times
  (`redirect-gateway`, a config `route <server> 255.255.255.255 net_gateway`, the same route pushed by
  the server) and only the first can succeed — and "File exists" for the host route to the server itself (an address from "link remote: …" / "TCP connection established
  with …" / "Peer Connection Initiated with …") via the default gateway from `ROUTE_GATEWAY`, and the
  "route add command failed" line after it. A session killed without cleanup (e.g. the helper was
  unregistered while connected) leaves that route behind; it is the route OpenVPN wanted anyway.

## Cisco AnyConnect backend

**In place:** the profile model (#181, [Profile](#profile-181)); the helper side (#182): the helper
accepts `startOpenConnect` (protocol 4), checks it, renders the root configuration and runs, supervises,
stops and adopts `openconnect`; the hook that sets up and reverts the network on the Mac (#183,
[The hook](#the-hook-vpn-hook-182-183-macos-187-linux)); and connecting in Core (#184): the user's
sign-in, the start request, the state and failures from the log, on macOS 15.4 and later; and Linux (#187):
`passtunneld` runs the distribution's openconnect and is its hook ([LINUX.md](LINUX.md#cisco-anyconnect)), and the
sign-in runs the distribution's openconnect; the CLI and MCP (#185); the Mac app's editor, views and "Trust this
server" (#186), and the user docs (#189). The tests against a real server are #188. This is the design of Phase 1 of #2: Cisco AnyConnect through OpenConnect,
with a password and a TOTP code (no SAML or other single sign-on), on the Mac and on Linux. The
issues #179–#189 implemented it, each named below where its part landed. Before any of it, #177 makes `Profile`
keep a profile of an unknown `type` intact instead of decoding it as OpenVPN (`Model.swift`,
`lenientEnum(…) ?? .openvpn`), so an older or a companion build cannot rewrite an AnyConnect
profile. Phase 2 (GlobalProtect) is designed under [Palo Alto GlobalProtect backend](#palo-alto-globalprotect-backend)
(#226); Phase 3 (Pulse/Ivanti) gets its own issues. References like
`main.c 1593` are to the openconnect 9.21 sources, from which the tool's behavior below was read;
the pull requests confirm it against the running tool (#188). Linux specifics:
[LINUX.md](LINUX.md#cisco-anyconnect); the threat model: [SECURITY.md](../SECURITY.md#cisco-anyconnect).

```
passtunnel / app (the user)                          PassTunnelHelper / passtunneld (root)
  openconnect --authenticate --config=<file>
    stdin: password, code ─▶ server
    stdout: COOKIE, HOST, CONNECT_URL,
            FINGERPRINT, RESOLVE
  HelperRequest.startOpenConnect ── cookie, pin ──▶ <run>/openconnect.conf (0600)
                                                    openconnect --config=<run>/openconnect.conf
                                                      └─ script: vpn-hook (address, routes, DNS)
```

### Bundling and pins (macOS, #179)

- Homebrew's `openconnect` bottle, bundled like `openvpn`: `Contents/Resources/bin/openconnect`
  (Homebrew installs it in `bin`) and its closure in `Contents/Frameworks`: `libopenconnect.5`,
  `libgnutls.30`, `libnettle.9`, `libhogweed.7`, `libgmp.10`, `libp11-kit.0`, `libtasn1.6`,
  `libidn2.0`, `libunistring.5`, `libintl.8`, `libstoken.1`, `libtomcrypt.1`, `libtommath.1`
  (`.dylib`; about 9 MB, `arm64`). Like the `openvpn` and `openfortivpn` bundled today (Homebrew's
  bottles for the release runner's macOS 26), they carry `minos 26.0`. `libopenconnect` imports
  `strchrnul` (macOS 15.4 and later), so Cisco AnyConnect needs macOS 15.4 (the app stays on 13):
  `check-tool-symbols.sh` holds `openconnect`, and the dylibs only it loads, to 15.4
  (`TOOL_MINIMUMS`; a dylib it shared with `openvpn` or `openfortivpn` would stay at 13.0, none does),
  against the 15.4 symbol lists of the macOS libraries this closure loads
  (`make-system-symbols.sh 15.4 MacOSX15.4.sdk -- /usr/lib/libSystem.B.dylib /usr/lib/libz.1.dylib
  /usr/lib/libxml2.2.dylib /usr/lib/libiconv.2.dylib /usr/lib/libffi.dylib` and the CoreFoundation,
  CoreServices, Kerberos, PCSC and Security frameworks). `HelperCore.Tool.minimumMacOS` says the
  same to the app (`diagnose` does not run it below 15.4). `libstoken`,
  `libtomcrypt`, `libtommath` (RSA SecurID soft tokens, never used) and `libintl` (message catalogs,
  unused with `LC_ALL=C`) are accepted dead weight rather than building openconnect ourselves. The
  rest stays system (`libz`, `libxml2`, `libiconv`, `libffi`, Kerberos, PCSC, Security,
  CoreFoundation). The bottles are unchanged apart from the load paths and the configuration paths
  compiled into two libraries: `bundle-tools.sh` overwrites, in place and NUL-padded to the same
  length, every Homebrew path in `libp11-kit.0.dylib` (`etc/pkcs11.conf`, `etc/modules`,
  `etc/pkcs11/modules`, `Cellar/p11-kit/<version>/lib/pkcs11`) and the `etc/` paths in
  `libgnutls.30.dylib` (`etc/gnutls/config`, `etc/gnutls/cert.pem`) with `/var/empty/none` (root-owned
  `/var/empty`, empty; ENOENT, which p11-kit and GnuTLS treat as "nothing configured"), before signing
  (`NEUTRALIZE`). The same input gives the same bytes (repeatable build). The build fails when a listed
  library is missing or has no such string (a renamed library or changed build must be looked at), and
  when a Homebrew path is left in them; `scripts/test-bundled-config-paths.sh` (CI's `Bundled tools`)
  puts module files with a `remote:` command into the runner's Homebrew prefix and checks that
  Homebrew's openconnect runs them and the bundled one does not. Other Homebrew paths left in the
  bundled tools, all handled where the tools are run: openconnect's `etc/vpnc/vpnc-script` (always
  `script`), the `share/locale` catalogs of openconnect, GnuTLS and libintl (`LC_ALL=C`), OpenSSL's
  `OPENSSLDIR` and `MODULESDIR` (the fixed environment, below), openvpn's plugin directory and
  `dns-updown` (sanitizer, `--dns-updown`), openfortivpn's default configuration (always `-c`).
  Not a Homebrew path, and left as it is: GnuTLS 3.8.13 also reads the fixed `/etc/gnutls/pkcs11.conf`
  when PKCS#11 is initialized (`compat_load(NULL)`, which can name provider libraries). On macOS `/etc`
  is root's, so only root can create that file (no escalation from the Homebrew prefix's owner), and a
  provider library not signed by Apple or with our Team ID is refused by library validation.
  `bundle-tools.sh` takes nothing else of the formula: not `etc/vpnc/vpnc-script`,
  nothing from `libexec/openconnect` (`csd-wrapper.sh`, `hipreport.sh`, `tncc-*`). Its generic
  closure walk resolves both load styles (`/opt/homebrew/opt/<formula>/lib/…` and, in `libhogweed`,
  `libnettle`'s Cellar path); no name clashes with the OpenVPN closure. License `case` entries for
  every formula.
- `scripts/release.env` pins `OPENCONNECT_VERSION`, `GNUTLS_VERSION`, `NETTLE_VERSION`, `GMP_VERSION`,
  `P11_KIT_VERSION`, `LIBTASN1_VERSION`, `LIBIDN2_VERSION`, `LIBUNISTRING_VERSION`,
  `GETTEXT_VERSION`, `STOKEN_VERSION`, `LIBTOMCRYPT_VERSION`, `LIBTOMMATH_VERSION` (names from
  `pin_var`), set to what Homebrew provided when #179 landed (2026-10-28: openconnect 9.21, gnutls
  3.8.13_2, nettle 4.0, libunistring 1.5, …). `release.yml`, `repeatable.yml` and CI's `Bundled
  tools` install `openconnect` with the other tools and upgrade every pinned formula.
- `build-app.sh` signs it with `--identifier com.furkanprlk.passtunnel.openconnect`
  (`PT.openconnectIdentifier`), adds its cdhashes to `generatedCDHashes`, and a signed build fails
  without them, as for `openvpn`; the dylibs are pinned by the existing `generatedLibraryCDHashes`.
- `HelperCore.Tool.openconnect`. `ToolStager.check` then expects exactly
  `Resources/bin/{openvpn,openfortivpn,openconnect}` (`vpn-hook` may be there too) and the pinned dylibs,
  so the closure is staged for every user (about 9 MB per helper build), used or not, on every macOS
  (it is only copied and checked below 15.4, never run). `vpn-hook` (#182) is a copy of the
  helper's own executable: no new target and no pin. The helper opens its executable when it starts,
  verifies it is the running image and hashes that descriptor (`HelperImage`, under "Privileged
  helper"; the digest is the build ID); `ToolStager` copies the hook from the same descriptor
  (`hookSource`, read with `pread` from offset 0), so after an app update replaced the file on disk the
  running helper still stages its own bytes. The hook is staged apart from the tools and only for an
  openconnect start (`stageHook`: checked if present, else copied to `tools/.<build>.vpn-hook`, checked
  and renamed into `Resources/bin`), so it can never keep OpenVPN or FortiGate from starting. The copy is
  accepted only when its SHA-256 is the build ID (byte-identical to the running helper; `HookMismatch`
  otherwise) and it satisfies the helper's requirement (`PT.toolRequirement(identifier:
  PT.helperIdentifier)`, `com.furkanprlk.passtunnel.helper`), checked on every openconnect start. A
  helper without a verified image has no hook source, and `stageHook` refuses every openconnect start
  (`HookMissing`).
  `HelperSessions` counts `openconnect` like `openvpn` and `openfortivpn`, also run from the staged copy (`toolNames` is
  `HelperCore.Tool.allCases`); the hook process is neither a session nor a helper.
- `THIRD_PARTY_NOTICES.md` (#179) lists the LGPL libraries, says where their sources are and that a
  build from source (`PASSTUNNEL_ALLOW_UNPINNED_TOOLS=1 scripts/build-app.sh`, which pins what it
  bundled, signed with one's own Team ID) can run a modified library; there is no further mechanism. OpenConnect code stays out of the mobile apps ([MOBILE.md](MOBILE.md)); the
  Swift written for this backend is our own, not a translation of openconnect's C.

### Authentication, split from the tunnel (#184)

The user's process signs in; root gets only the session cookie and never holds the password or the
code, nor parses the server's login forms (the most complex server-controlled parsing).

1. **Sign-in, unprivileged.** Core runs, through `ToolRunning` (fixed path, the fixed environment
   below, a timeout), the app bundle's `openconnect` (Linux: the daemon's candidate paths, never
   `PATH`) with `--authenticate --config=<file>` and nothing else in argv, which every local user can
   read (`ps`). The file is a descriptor (`/dev/fd/N`) or a 0600 file in a directory only the user
   can read, removed after the run, rendered and checked like the root file (below;
   `OpenConnectAuthConfig`, VPNConfig): `protocol anyconnect`,
   `server https://<host>[:<port>][/<usergroup>]`, `user <name>` (the user name never goes in argv),
   `authgroup <group>` when set, the trust lines, `non-inter`, `passwd-on-stdin`, and
   `no-external-auth` where the tool has it (below). Standard input holds the answers, one per line
   (`OpenConnectAnswers`): `.combined` → line 1 the composed secret; `.separate` (this type's
   default) → line 1 the password, line 2 the code. openconnect gives line 1 to the first password
   field (read at option parsing, `main.c` 2023) and the next line to every later prompt
   (`secondary_password` in the same form, a `challenge` form, ocserv's second "OTP" form;
   `prompt_for_input`, `main.c` 2706–2722); with no line left it fails with "User input required in
   non-interactive mode". Each line is 1–4,095 bytes (`MAX_READ_STDIN_SIZE` with its newline) and
   holds no LF, CR or NUL (`fgets` stops at the LF and removes only it, a CR would stay in the
   answer, a NUL ends it; `main.c` 767–806). Answers are positional: a server
   that answers a wrong password with a retry form gets the code as the second password (the code is
   spent), and a text field before the password other than the user name would get the code; both
   end as a failed sign-in. openconnect's own TOTP (`--token-mode=totp`) is not used: it computes the
   code itself, past the fresh-code wait and `.last-otp`, and needs the TOTP secret.
   - *Single sign-on.* Phase 1 has none. `no-external-auth` (openconnect 9.10 and later; 9.01, the
     release before it, does not know it and always offers SSO) only stops openconnect from
     *offering* the SSO methods (`auth.c` 860–869); it does not stop a server that sends an
     external-browser SSO form anyway (`library.c` 1860–1868): openconnect then opens the server's
     URL with the default browser (`/usr/bin/open`, `xdg-open`) as the user, and the run ends at its
     timeout. `--non-inter` does not change that. The Mac's bundled 9.21 always gets the option; on
     Linux the client renders it when `openconnect --help` lists it (a capability check, #187:
     `ToolSpec.openConnectHasNoExternalAuth`, so 9.01 runs without it).
2. **Its output** is parsed strictly (`OpenConnectAuthResult.parse`, VPNConfig, #180): exactly
   `COOKIE='…'`, `HOST='…'`, `CONNECT_URL='…'`, `FINGERPRINT='pin-sha256:…'` and
   `RESOLVE='<host>:<address>'`, each on its own line and in this order, or a last `RESOLVE=` that
   openconnect prints without a line break (`main.c` 2403–2425; its progress messages go to standard
   error in this mode, `main.c` 2556–2563). Values are printable ASCII without `'` (nothing is
   escaped); the cookie must be one of the two shapes below, `FINGERPRINT` is a full pin, `CONNECT_URL` at most 300 bytes,
   the whole output at most 8 KiB; anything else (an unknown, repeated, missing or reordered key, a CR)
   fails. The server chooses every value, so it could repeat the cookie in any of them: no
   description, mirror or error shows any value of the output, only fixed text and key names.
   Without a proxy (PassTunnel never sets one) openconnect prints the address it connected to: `HOST`
   is that numeric address (in brackets for IPv6; `openconnect_get_hostname`, `library.c` 985–988, set
   in `ssl.c` 489–500), not a name.
   - `CONNECT_URL` (`library.c` 953–980) must be exactly `https://<host>[:<port>]/`: no user info,
     query, fragment, path or control character, at most 300 bytes, its host the profile's host
     (compared without regard to case; an IPv6 literal in brackets, as the URL openconnect was given
     has it) and its port the profile's port, left out when it is 443 as openconnect prints it (a
     `:443` fails). The profile's usergroup is not in it: AnyConnect connects without the path.
     Another host (ASA load balancing) is refused in Phase 1, since `ProfileDestination` binds the
     profile's host (a per-profile switch may come later).
   - For a host name, `RESOLVE` must be `<that host>:<IP literal>` (`inet_pton`) and `HOST` that same
     address; the root run gets it as `resolve`, so DNS cannot move the tunnel to another address
     between the runs. For an IP-literal host openconnect prints `<host as in the URL>:<address>`
     (`[2001:db8::1]:2001:db8::1` for IPv6); the address and `HOST` must be the profile's address (any
     spelling of it) and no `resolve` is rendered (openconnect splits `resolve` at the first `:`,
     `main.c` 1983–2000). An empty `RESOLVE` fails; so does an address with a zone id.
   - `FINGERPRINT` must equal the profile's pin when it has one.
   - *The cookie's name* (`OpenConnectCookie`, #212). openconnect builds `COOKIE` in one place
     (`cstp_obtain_cookie`, `auth.c` 1666–1709; the same in 9.01 and 9.12) in one of two shapes: with a
     STRAP key, which it makes only without `no-external-auth` (Linux 9.01–9.09),
     `openconnect_strapkey=<base64 DER>; webvpn=<value>`; otherwise the **bare value** of the `webvpn`
     cookie (the server's `Set-Cookie` or `<session-token>`). The tunnel run splits its `cookie` option at
     each `;` and each part at its first `=` (`internal_split_cookies(…, "webvpn")`, `http.c` 119), and only
     a part without `=` is taken as the `webvpn` value: a bare value holding `=` (ocserv's base64 tokens)
     would become a cookie named after itself, and the server would get no session cookie ("no cookie
     found"). So the helper is sent the value under its name, `webvpn=<value>` (whatever the value holds),
     or the STRAP form unchanged (`OpenConnectAuthResult.tunnelCookie`). STRAP is recognised only by its
     whole structure (`openconnect_strapkey=<standard base64>; webvpn=<value>`); a value that merely starts
     like it is a bare value, sent as `webvpn=<value>`, so the client gives exactly the options the helper
     accepts. Accepted, and nothing else: a `webvpn` value of RFC 6265 cookie octets without `'` (no blank,
     `"`, `,`, `;` or `\`, so nothing can split it differently), a STRAP key of standard base64, each at least
     8 bytes (the log maskers skip values under 3, and no server issues a session cookie that short), at most
     4,096 bytes under its name. The sign-in's log also masks whatever `COOKIE='…'` held when the parser
     refuses it (whole, per line, per `;` part and after each part's `=`), since the server may echo it. The helper
     and the root file's check (`checkRendered`) accept exactly `webvpn=<value>` and the STRAP form
     (`OpenConnectCookie.isValidTunnelOption`), never a bare value. The STRAP key is the client's own
     private key for the session's resumption, a secret like the value: both are masked on their own too.
   - `OpenConnectAuthResult.checkDestination` makes these checks and returns the address for
     `resolve`; `tunnelConfig` builds the root configuration from them. The helper repeats them on the
     request's fields (`OpenConnectAuthResult.tunnelConfig(host:port:connectURL:resolve:cookie:
     serverCert:profileServerCert:…)`; the request carries no `HOST`): `CONNECT_URL` for the profile's
     host and port (an IP-literal host compared as an address), `resolve` exactly for a host name, and,
     when the profile has a pin (`profileServerCert`, normalized), the accepted `serverCert` equal to it.
   - *Trust model.* `HOST`, `RESOLVE` and `FINGERPRINT` are written by openconnect itself, from the
     address it connected to and the key its TLS check verified; neither the server nor a network
     attacker can set them. Binding the tunnel run to them protects against DNS or a key changing
     between the two runs. It does not protect against the requesting user: the start request comes
     from the user's own process, which can already define a profile for any host, so the address it
     reports cannot be verified independently in pure code. No address range is refused (the ocserv
     tests run on loopback).
   - *What this does not cover:* these are checks of where the sign-in **ended**. openconnect
     follows every `https://` redirect during the sign-in, to any host and port (`handle_redirect`,
     `http.c` 646–690), and submits the forms there; the openconnect command line has no option or
     callback to refuse one, so a redirect away and back cannot be stopped from outside. With a pin,
     only a server holding the pinned key gets the credentials (the pin is checked for every host,
     `main.c` 2589–2600); without one, any server with a certificate the system CA bundle trusts for
     its own name does. The client also fails the connect, after the fact, when a `POST https://…`
     line of the run names another host or port than the profile's. Refusing each redirect before
     anything is sent would need libopenconnect's API or a patched build, not the bundled command.
3. **The cookie** is a bearer secret. The user's process keeps it in memory only, in a bounded byte
   buffer that is overwritten once the start request is sent or the connect fails (best effort: the
   encoded request and any copy the runtime made are not guaranteed to be erased). Neither run's
   output that carries it is logged: the sign-in run's standard output is read only by the parser,
   and neither run gets `-v` or `dump-http-traffic` (the tests check that the cookie is absent from the
   log, the errors, the activity and the request's description). `HelperRequest`'s descriptions,
   mirrors and error texts never include it. A server chooses part of what the tunnel run prints (the
   CONNECT reply's status line, `cstp.c` 384, is logged as it came) and could reflect the cookie there,
   so the helper does not give openconnect the log itself: its standard output and error go into a pipe,
   and `MaskingCopier` (Shared) writes them to the log one complete line at a time, each through
   `OutputMask`, with the cookie under its name, its `webvpn` value alone and a STRAP key as literal secrets
   (`OpenConnectCookie.secrets`). A line over 16 KiB is never written, not even in part (a secret could run over any cut): it
   is replaced as a whole by `[output line over 16 KiB dropped]`, and an unterminated last line is dropped.
   One thread drains the pipe into a bounded queue (4,096 lines, 4 MiB), another writes from it, so openconnect
   never waits for the log: when a stalled file system fills the queue, lines are dropped and
   `[N lines dropped]` is written before the next one. `OutputMask` masks the cookie literally, and
   `COOKIE=…`, `webvpn…=`/`openconnect_strapkey=` values, `Cookie:`/`Set-Cookie:` headers and a `cookie …`
   config line. openconnect ignores SIGPIPE (`main.c` 2348), so if the helper ends first (an update), the
   session runs on and only its further output is lost. `LogRedactor` applies `OutputMask` as well, when a
   log is read; the sign-in's standard error is passed through it, with the answers and the cookie (as
   printed, under its name, and each of its parts) as literal secrets, before it is cut and written.
4. **The tunnel, as root:** `HelperRequest.startOpenConnect` (below). Costs of the split: the cookie
   crosses XPC (or the daemon socket) and sits in a root-only file for the session's life; two runs
   per connect.

`.last-otp` is recorded when the sign-in run starts and given back when its output shows that no
form was submitted after the initial request (each submission logs `POST https://…`, `http.c` 894),
i.e. no credentials left the machine; a failure after that is `ConnectionFailure.Kind.authRejected`.

**As built (#184).** `ConnectionManager.signIn` and `AnyConnectSignIn` (Core):
- **Program and argv:** the app bundle's `Contents/Resources/bin/openconnect` (`AnyConnectSignIn.bundledTool`;
  nil outside an app bundle, which fails the connect with `PTError.fileError`), run as the user through
  `ToolRunning` (`SystemToolRunner`, `Process`) with exactly `["--config=<file>", "--authenticate"]`.
- **The file:** `OpenConnectAuthConfig(host:port:usergroup:username:authgroup:serverCert:)` from the profile
  as stored (the pin normalized), `render(caFile: "/etc/ssl/cert.pem", noExternalAuth: true)` (the bundled
  9.21 has the option); written with `O_CREAT|O_EXCL|O_NOFOLLOW`, 0600, as `openconnect.conf` in a directory
  `mkdtemp` makes for the run in the user's temporary directory (0700); both are removed when the run ends,
  whatever happened.
- **The environment:** exactly `HelperCore.environment(for: .openconnect)` (`AnyConnectSignIn.environment`),
  never this process's.
- **Standard input:** `OpenConnectAnswers.stdin` of the composed answers (`OTPComposer.compose`: `.separate`
  → the password, then the code; `.combined` → the template's secret; no code → the password alone); an answer
  with a line break, CR or NUL fails as `invalidField("password")` before anything runs. The bytes are in one
  buffer (`SecretBytes`), and the tool's input copy is overwritten after the run.
- **Limits:** `Timing.signInTimeout` (60 s; `ToolTimeout` then, with the standard error so far), output kept up
  to `SystemToolRunner.maxOutput` (1 MiB) per stream (`ToolOutput.errorOutputCut` when standard error went
  past it), standard output parsed only up to 8 KiB, at most 64 KiB of standard error logged. `disconnect`
  (and cancelling the connect's task) cancels the run (`ToolCancellation`: the tool is terminated within a
  quarter second, then killed).
- **The log:** the whole of the run's standard error is redacted first (`AnyConnectSignIn.redacted`: each LF
  line through `LogRedactor`, with the answers and the cookie as literal values), then cut to 64 KiB of complete
  lines (what follows the last line break, at the cut or at the end, is dropped), so no secret is left in part
  at the cut. The classification reads complete lines only too: an unterminated last line is never read. It replaces the
  profile's log (0600), so "Show log" and `ConnectionFailure` describe the sign-in; the helper replaces it
  again when it starts the tunnel.
- **Success** (exit 0): `OpenConnectAuthResult.parse` of standard output, then `checkDestination` (another
  server, port or path, another key than the pin, an address that does not match: `PTError.signInUnusable`,
  with a fixed text naming no value; the cookie goes nowhere); the activity records the sign-in accepted.
- **Credentials sent** (`VPNLog.openConnectCredentialsSent`): two or more `POST https://` in the standard
  error, wherever they stand (a text field's prompt is printed without a line break), counted over the whole
  of it as it came, before redaction and the log's limit. A redirect counts as well, so a code is never given
  back that may have reached a server; the server's own text can only add. Evidence that is not complete
  counts as sent: a run stopped at the deadline (`connectTimeout`, kind `timeout`) and standard error past
  what is kept. The manager passes it to `ConnectionFailure.of(credentialsSent:)`; a cookie means sent.
- **Failure** (`VPNLog.openConnectSignInError`, from the whole redacted standard error and the exit status).
  The server's text is printed among openconnect's lines (form errors and messages, after the first TLS
  session) and a CR in it could make part of a line look like another, so only whole LF lines of printable
  ASCII in openconnect's exact 9.21 wording count (`VPNLog.openConnectLines`). In this order: dyld
  (`toolUnsupported`; it never ran); once a form may have been submitted (above), `authFailed` whatever the
  rest says: nothing is reported as unsent or retried that may have used the code (a host scan asked for only
  then, a rejection that quotes "Failed to open HTTPS connection to", a lost connection all count as a
  refused sign-in); a CSD host scan asked for (`hostScanRequired`, owner decision 10: openconnect refuses it
  itself without `csd-wrapper`, as the two lines "Error: Server asked us to run CSD hostscan." / "You need to
  provide a suitable --csd-wrapper argument.", or "Error: Server asked us to download and run a 'Cisco Secure
  Desktop' trojan." / "This facility is disabled by default for security reasons, so you may wish to enable
  it.", `auth.c` 1176–1187); from the lines before the first TLS session ("Connected to HTTPS on …", the only
  stretch with nothing of the server's in it): a certificate or key refused (`serverCertificateRejected`, with
  openconnect's reason and its `    --servercert pin-sha256:…` hint as `ConnectionFailure.serverCert`; "Server
  certificate verify failed" alone is no failure, as openconnect prints it for a pinned server too), the name
  not found (`hostNotFound`), no answer (`serverUnreachable`); the line `Auth choice "<the profile's group>"
  not available` (`invalidField("authgroup")`); the line "User input required in non-interactive mode"
  (`signInNeedsMoreAnswers`); else `connectFailed`.
- **The start request:** `.startOpenConnect` with the profile's host, port, user group, `tls_only`, `set_dns`
  and `set_routes`, the sign-in's `CONNECT_URL`, `RESOLVE` (nil for an IP-address host), cookie and
  `FINGERPRINT` (`server_cert`), and the profile's normalized pin or "" (`profile_server_cert`). No user name,
  password or code. A start the helper refuses because another process started the profile meanwhile is
  followed, as for the other types (that sign-in's cookie is then unused).

### Server trust

- `server_cert` is optional. Only `pin-sha256:` followed by the full base64 SHA-256 of the server's
  public key (SubjectPublicKeyInfo; 44 characters, the last `=`, and the one before it one that
  openconnect's own base64 of a 32-byte digest can end in) is accepted, stored normalized
  (`OpenConnectPin.normalize`: surrounding blanks and line breaks dropped, the prefix lowercased; the
  base64 is case-sensitive and kept as it is).
  openconnect would also take any prefix of 4 or more characters, `sha256:`/`sha1:` hex and a bare
  SHA-1 of the whole certificate (`library.c` 1694–1745); PassTunnel refuses all of them.
- With `servercert`, openconnect turns system trust off (`main.c` 1968–1980): the pin is the only
  trust. Without a pin the sign-in run gets `no-system-trust` and `cafile /etc/ssl/cert.pem` (Linux:
  the checked distribution bundle, `SystemTools.caBundle`), never GnuTLS's compiled-in Homebrew
  store.
- The root run always gets `servercert` = the `FINGERPRINT` the sign-in run accepted (the profile's
  pin, or the key the CA check passed), so the tunnel cannot reach another key than the one the
  credentials went to.
- With `non-inter` a failed check never prompts (`main.c` 2600–2630); the log's `Server certificate
  verify failed: …` and `--servercert pin-sha256:…` lines become "Trust this server" in the editor
  (#186): `ConnectionFailure.serverCert`, and `DisplayStatus.Failure.serverNotTrusted` in the app,
  whose card offers "Trust This Server…" ("Trust the New Key…" when another key was pinned).
  `ConnectionManager` keeps the offer (`ServerTrustOffer`: the profile's host, port, user group and
  pin as the attempt read them, and the hinted pin) beside the failure; `serverTrustOffer(id)`
  gives it only while the stored profile still names that server with that pin, and
  `trustServer(offer)` writes only `server_cert`, after the user confirmed the server and the full
  pin (else `ServerTrustOffer.Stale`). "Fetch fingerprint" needs the SPKI digest, not
  `TLSFingerprint.fetch`'s hash of the whole certificate: `TLSFingerprint.fetchServerKeyPin` reads
  the leaf certificate the same way and `ServerKeyPin` parses its DER with bounds checks
  (tbsCertificate's optional `[0]` version, then serial number, signature algorithm, issuer,
  validity and subject; definite, minimal lengths only) and hashes the complete DER of the
  SubjectPublicKeyInfo that follows. Golden tests (`ServerKeyPinTests`, Tests/Fixtures/certificates:
  RSA 2048, EC P-256 and P-384, Ed25519, and an RSA version 1 certificate without the version field)
  hold the pins `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256`
  gives, which openconnect 9.21 printed as its hint for the same certificates. Linux has no fetch;
  the pin comes from the log hint.

### The root configuration (#180, #182)

`OpenConnectConfig` (VPNConfig, the `FortiConfig` pattern: typed fields, `validate`, `render`,
`checkRendered`). The helper renders `<run>/openconnect.conf` (0600, root) and runs
`openconnect --config=<run>/openconnect.conf` (`HelperCore.openConnectArguments`), nothing else in
argv, stdin `/dev/null`, working directory the session directory; the cookie is an option in the file,
as openfortivpn's password is in its file, so the only change to `Spawner` is `spawnVerified`'s
`beforeResume`, in which the helper writes `state` after the signature check and before `SIGCONT`
(step 1 of the hook; failing to write it kills the suspended openconnect). Next to it the helper writes
`policy` (the hook's step 2, `OpenConnectPolicy`: `uid=<n>`, `profile=<id>`, `set_routes=0|1`,
`set_dns=0|1`, one per line, `checkLines`, and a strict `parse` for the hook); the hook adds
`network` (its record) and `hook` (while one runs), the helper `stopping` (#183), and the run root holds
`network.lock`. The rendered text lives
in a `Data` buffer that is overwritten once written (best effort: the request and the rendered text
are Swift strings, which cannot be erased); the file goes with the session directory when the tool
exits or is stopped (`Supervisor.finish`, `stopAll`, `adoptOrphans`), and with any start that fails
after the directory was made.

```
# Generated by PassTunnel. Do not edit.
protocol anyconnect
server https://vpn.example.com:8443/
cookie <cookie>
servercert pin-sha256:<44 characters>
resolve vpn.example.com:192.0.2.10            (only for a host name)
script <staged build directory>/Resources/bin/vpn-hook
non-inter
reconnect-timeout 60
no-dtls                                       (only with tls_only)
```

- openconnect reads one `option value` per line, skipping leading blanks and one `=` after the name,
  `#` lines are comments (`next_option`, `main.c` 1199–1300); the value is the rest of the line up
  to a NUL, trailing blanks included, and an option is recognized only when its whole name is
  followed by a blank, `=` or the end. So every value has no NUL, CR, LF or other control byte, no
  leading or trailing whitespace and no leading `=`; `checkRendered` checks the expected number of
  lines, the header first and no other comment, only the keys above, each once and in this order,
  the required ones present, each written `key value` with one space (or the key alone), and the
  values of `protocol`, `servercert`, `script` and `reconnect-timeout` again. `server` is parsed by
  the typed rules (`https://` only; a lowercase host by the host rule, an IPv6 literal in brackets; a
  port of 1–65535 without leading zeros, never an explicit 443; the path the renderer writes: empty
  here, a user group by its rule in the sign-in file; so no user info, query or fragment), and
  `resolve` must be there exactly when that host is a name (without it the root run would resolve the
  name again), name that host, and be absent for an IP literal. The sign-in file
  (`OpenConnectAuthConfig.checkRendered`) is checked the same way, and its trust must be `servercert`
  alone or `no-system-trust` with `cafile` naming the bundle the caller passed.
- The host has no IPv6 zone id (a URL cannot carry one the way openconnect reads it); `server` and
  `resolve` both have it lowercased, since openconnect matches `resolve` byte for byte.
- `script` is always rendered: without it openconnect runs its compiled-in `DEFAULT_VPNCSCRIPT`
  (`main.c` 2439). openconnect passes it to `/bin/sh -c` (`script.c` 660–695), so the path must be
  absolute, only `A–Z a–z 0–9 / . _ -` (the staged build directory is hex digits), at most 1,023
  bytes, with no empty, `.` or `..` component.
- `server` is the checked `CONNECT_URL`, rendered from the profile's own host and port, never the
  server's text (for AnyConnect openconnect puts no usergroup path in it, `library.c` 973).
- `reconnect-timeout 60` (openconnect's default is 300) is a retry budget, not a deadline: after a
  dropped connection openconnect retries with the cookie and subtracts only its sleeps between tries
  from the 60 (`ssl.c` 1203–1235), not the time each try or the hook takes. The supervisor's own
  reconnect deadline (below) bounds the elapsed time; after either, `ConnectionManager`'s own
  reconnect (a new sign-in with a fresh code) takes over.
- DTLS (UDP) is on by default; the per-profile `tls_only` renders `no-dtls`.
- Not rendered: `useragent` (openconnect's default string; no field in Phase 1) and `-v` (INFO is
  the default; higher levels and `dump-http-traffic` would log the cookie).
- Refused, never rendered (there is no raw option input at all). `OpenConnectOptions` lists every
  long option of openconnect 9.21 (`long_options`, `main.c` 235–326) and gives each one neither file
  renders a reason (`OpenConnectOptions.refused`); the tests check that table covers all 81 and that
  both final checks refuse each refused option in every form openconnect would read. Among them:
  `script-tun`, `csd-wrapper`, `csd-user`, `external-browser`, `setuid`, `background`, `pid-file`,
  `syslog`, `interface` (a named device could attach to another user's persistent tun on Linux, as
  OpenVPN's `dev`), `certificate`, `sslkey`, `mca-*`, `key-password*`, `token-*`, `config`, `xmlconfig`
  (openconnect writes the server's XML profile to that path, as root), `proxy*`, `libproxy`,
  `dump-http-traffic`, `gnutls-debug`, `gnutls-priority`, `dtls*-ciphers`, `allow-insecure-crypto`,
  `no-cert-check`, `force-*`, `cafile` other than the system bundle, `os`, `version-string`,
  `local-hostname`, `useragent`; and also `form-entry` (submits arbitrary sign-in form values),
  `sni` (another server name), `dtls-local-port` (binds a chosen UDP port as root), `verbose`,
  `quiet`, `timestamp` (the log the parser reads), `authenticate`, `cookieonly`, `printcookie`,
  `cookie-on-stdin` (print or read the cookie elsewhere), `passtos`, `http-auth`, `no-proxy`,
  `juniper`, `usergroup`, `no-passwd`, `no-xmlpost`, `compression`, `deflate` and the others that are
  not needed. Each file's own keys are refused in the other (the root run never signs in; the
  sign-in never gets the cookie, the hook or `resolve`).
- CSD host scan (and in Phase 3 Pulse's TNCC) is refused in every phase: without `csd-wrapper` or
  `csd-user` openconnect refuses a server that asks for it ("Server asked us to run CSD hostscan", "…
  'Cisco Secure Desktop' trojan …", `auth.c` 1176–1187), and the client turns those lines into a
  failure that says the server requires a host scan PassTunnel does not run. GlobalProtect's HIP report
  is never run either, but openconnect goes on without it, and so does the connection (with a notice:
  [HIP](#hip-never-run-the-user-is-told-g4)).

### Fixed environment (#182, #184)

Both runs on the Mac (the sign-in run through `ToolRunning`, the tunnel through `Spawner`) get
`HelperCore.fixedEnvironment` plus `GNUTLS_SYSTEM_PRIORITY_FILE=/dev/null` and
`P11_KIT_NO_USER_CONFIG=1` (the OpenSSL variables do nothing to GnuTLS): for the tunnel exactly
`HelperCore.environment(for: .openconnect)` (#182), a list of fixed values, never the helper's own
environment (tested with proxy and key-log variables set in the test process). openconnect sets the first
itself (`main.c` 1855, without overwriting), but only in `main`; setting it in the spawn
environment makes it hold before any library code runs. None of `https_proxy` (`main.c` 1781),
`SSLKEYLOGFILE`, `GNUTLS_DEBUG_LEVEL`, `TPM_INTERFACE_TYPE` is ever set. On Linux the environment is
`PATH`, `LC_ALL` and `P11_KIT_NO_USER_CONFIG=1` (LINUX.md). What the Homebrew build has compiled in,
and how each is kept out of the root run:

| Compiled-in path | Read when | Neutralized by |
|---|---|---|
| `/opt/homebrew/etc/vpnc/vpnc-script` (`DEFAULT_VPNCSCRIPT`) | no `script` given (`main.c` 2439), run with `/bin/sh -c` | `script` always rendered, `checkRendered` |
| `/opt/homebrew/etc/gnutls/config` (system priority file; may name a PKCS#11 provider to load) | GnuTLS initialization | overwritten with `/var/empty/none` in the bundled `libgnutls` (#179, below); also `GNUTLS_SYSTEM_PRIORITY_FILE=/dev/null` in the spawn environment |
| `/opt/homebrew/etc/gnutls/cert.pem` (`--with-default-trust-store-file`) | system trust (`gnutls.c` 2277) unless turned off | overwritten with `/var/empty/none` (#179), so system trust is empty; and always `no-system-trust` + `cafile /etc/ssl/cert.pem`, or `servercert` |
| `/opt/homebrew/etc/pkcs11.conf` (system configuration), `/opt/homebrew/etc/modules` (system modules), `/opt/homebrew/etc/pkcs11/modules` (package modules), `/opt/homebrew/Cellar/p11-kit/<version>/lib/pkcs11` (module path); `~/.config/pkcs11/…` | at every start: openconnect calls `gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_AUTO)` in `openconnect_init_ssl` (`gnutls.c` 2586–2603) before parsing options, also for `--version`, and p11-kit loads every registered module then. A module file names a library (`module:`) or a command p11-kit runs itself (`remote: \|command`) | the system paths overwritten with `/var/empty/none` in the bundled `libp11-kit` (#179, below); library validation does not cover `remote:` commands, and p11-kit has no variable for its system paths (`P11_ENV_OVERRIDE_PATHS` is not built in). `P11_KIT_NO_USER_CONFIG=1` for the user's files; no `certificate`, `sslkey`, `mca-*`, `token-*` |
| `/etc/gnutls/pkcs11.conf` (fixed in GnuTLS 3.8.13, not under the prefix; may name PKCS#11 provider libraries) | PKCS#11 initialization (`compat_load(NULL)`) | left as it is: root-owned `/etc` (only root can create it), and library validation refuses a provider library not signed by Apple or with our Team ID |
| `…/share/locale` of openconnect and GnuTLS | message lookup | `LC_ALL=C` |
| `/usr/bin/open` (`DEFAULT_EXTERNAL_BROWSER`, spawned by `hpke.c` 63–71) | a server sends an "external browser" sign-in form | the root run never signs in (it has the cookie); in the sign-in run, as the user, `no-external-auth` stops offering it but does not prevent it (above) |
| `/bin/sh`, `/var/tmp` (CSD) | a server requests a host scan | refused (above) |

### The hook: `vpn-hook` (#182, #183 macOS, #187 Linux)

openconnect configures neither the interface nor routes nor DNS; its `script` does, as root, with
server values in its environment. vpnc-script is never run: on the Mac it rewrites `/etc/resolv.conf`,
sets the primary service's DNS persistently with `networksetup` (and to `Empty` on disconnect,
deleting servers the user had set), replaces the default route, and passes unchecked server values to
`route`, `ifconfig` and `scutil` as shell words; on Linux it writes DNS outside `DNSApplier`'s record
and revert. Instead the hook is PassTunnel's own code:

- **macOS:** the staged copy of the helper (above). `PassTunnelHelper`'s `main` decides its mode
  first, before XPC, logging or any state (`VPNHook.mode`): the hook needs both the executable the
  kernel reports (`proc_pidpath`, not chosen by whoever starts it) and the last component of `argv[0]`
  (openconnect's `/bin/sh -c <path>` gives the path) to be `vpn-hook`. The installed helper
  (`Contents/MacOS/PassTunnelHelper`, which launchd starts and which serves XPC) therefore never runs
  as the hook whatever its `argv[0]` (`exec -a`), and the staged copy never runs as the helper; a
  mismatch either way exits with status 2. The CLI is another binary and has no hook code.
- **#183: the hook** (`VPNHook.run`). It proves its session (step 1) before it reads anything; a run
  that is not one of a PassTunnel session writes `passtunnel vpn-hook: setting up the network failed:
  this run is not one of a PassTunnel session` and changes nothing. Then it checks the environment
  (step 3), reads `policy` (step 2) and, under the run root's lock, applies or reverts
  (`OpenConnectHook`, steps 4–7) through `MacOpenConnectSystem`. **Generation:** once it holds the lock,
  before it reads the record or changes anything, it proves the session again and compares its
  generation, the openconnect start time the helper recorded in `state` (with the pid, as the kernel
  reports it for that pid): a hook that waited for the lock while its openconnect ended, the helper
  cleaned up and the profile started again in the same session directory finds another generation (or
  no parent openconnect at all) and does nothing but write `passtunnel vpn-hook: the session this run
  was started for has ended; nothing was changed` (`VPNHook.endedLine`). It writes its lines to its standard
  error, which openconnect shares with the session log. After a failure it sends its openconnect
  SIGTERM, once the session check holds again (the pid is not reused meanwhile): openconnect ends the
  session, runs the hook once more for `disconnect` and exits, and the helper cleans up. Exit status 1
  after a failure, otherwise 0; openconnect ignores both. (#182 shipped a stub here that failed every
  set-up, so no session outlived the 60 s deadline.)
- **Linux (#187):** `<run>/<uid>/<id>/vpn-hook`, a link to `passtunneld` (as `dns-hook`), made with the
  session's `policy`; `passtunneld`'s `main` runs `LinuxVPNHook` when it was started under that name, before
  anything of the daemon. The same steps as the Mac's (`LinuxVPNHook`: the session proven from `/proc` and the
  daemon's `state`, the generation, the environment parsed for `.linux`, `OpenConnectHook`), through
  `LinuxOpenConnectSystem`: `ip` for the commands (`OpenConnectCommand.Tools.linux`, below), the routing
  table from rtnetlink, DNS through `DNSApplier` ([LINUX.md](LINUX.md#cisco-anyconnect)).
- The validation and the plan are shared (`OpenConnectNetwork`, `OpenConnectPlan`, `OpenConnectRecord`,
  `VPNHook.Report`, PassTunnelShared, pure; the address and domain rules are `IPAddress` and
  `DomainName`, which the Linux `DNSSettings` uses too), and so is the run (`OpenConnectHook`: the
  record on disk `OpenConnectJournal`, the lock `OpenConnectLock`, the marks `OpenConnectMarks`). The
  system actions sit behind a protocol (`OpenConnectSystem`: the interfaces, the routing table, one
  program run, the DNS keys), so all of it is tested everywhere against a fake Mac that records every
  command and every DNS write (`OpenConnectHookTests`), the exact argument lists and keys are golden
  tests, and the golden cases in `Tests/Fixtures/openconnect-env.json` (an environment → the event, the
  changes and the report line, or the refusal; read by the Core tests and later the Daemon tests, not by
  the mobile apps, and fuzzed by `FuzzOpenConnectHook`) cover the validation. The Mac's actions are
  `MacOpenConnectSystem` (`#if os(macOS)`).

openconnect runs the script with `fork`, `setpgid(0, 0)`, its environment on top of its own, then
`execl("/bin/sh", "/bin/sh", "-c", script)` and a `waitpid` **without a time limit** (`script.c`
660–695), for the reasons `pre-init`, `connect` (`library.c` 1576, 1593), `disconnect` (`tun.c`
579), `attempt-reconnect` and `reconnect` (`ssl.c` 1214, 1241).

1. **Session check** (as `DNSHook.session`; on the Mac `VPNHook.session` since #182, pure and tested
   with a fake process tree): euid 0; its own executable (`proc_pidpath`)
   `<run root>/tools/<build>/Resources/bin/vpn-hook` (run root resolved), so its openconnect is the
   `openconnect` next to it; the parent that openconnect, or one of `/bin/sh`, `/bin/bash`, `/bin/dash`,
   `/bin/zsh` (checked by executable path; macOS's `/bin/sh` becomes the shell `/private/var/select/sh`
   names, in the same process) whose parent is that openconnect: the hook does not rely on the shell
   replacing itself with the command; that openconnect's working directory (`PROC_PIDVNODEPATHINFO`)
   exactly a session directory `<run root>/<uid>/<profile id>`; and that directory's `state` (a regular,
   single-link file the helper owns, `SessionState.read`) naming that pid, uid and executable. The
   environment plays no part. The helper writes `state`
   before the tool can run a hook: on the Mac while it is still suspended (`Spawner.spawnVerified`
   writes it after the signature check and before `SIGCONT`; failing to write it kills the tool);
   the Linux daemon has no suspended start and writes it right after `posix_spawn`, so there the hook
   waits up to 5 s for a `state` that names its parent before it refuses.
2. **Policy from root only.** What the hook may do comes from `policy` (0600, root), which the
   helper writes into the session directory with `openconnect.conf`, before the start, from the
   checked request: uid, profile ID, `set_routes`, `set_dns` (`HelperCore.checkLines`). The hook
   never reads the user's profile, and nothing in openconnect's environment can change the policy.
3. **Validation** (`OpenConnectNetwork.parse(_:platform:)`). Every value the hook uses is checked;
   one bad value fails the set-up. `pre-init` and `disconnect` read nothing but `reason` (a revert must
   never fail on what the server sent; it works from the record); `connect`, `attempt-reconnect` and
   `reconnect` need the whole network (openconnect 9.21 builds the environment once, before `connect`,
   `library.c` 1567, so the later two see the same values). A value the hook reads is at most 8 KiB of
   printable ASCII (0x20–0x7E: no control byte, no UTF-8), and a name given twice is refused; what it
   does not read is never decoded. The validators are family-specific: an *address* is parsed by
   `IPAddress` (dotted decimal without leading zeros, which `inet_aton` would read as octal; IPv6 groups
   of 1–4 hex digits, one `::`, an IPv4 tail; no zone, port, bracket or blank), cross-checked with
   `inet_pton` and written as `inet_ntop` gives it back; no IPv6 address or split network may be an
   IPv4 one written as IPv6 (IPv4-mapped `::ffff:0:0/96` or IPv4-compatible `::/96`, `isIPv4Embedded`):
   openconnect connects over a real IPv4 or IPv6 address, and such a form would slip past the IPv4
   checks (a `VPNGATEWAY` of `::ffff:192.0.2.10` next to an IPv4 include `192.0.2.0/24`); a *host
   address* is also not unspecified, loopback, `0.0.0.0/8`, `224.0.0.0/3` or `ff00::/8` (`VPNGATEWAY`
   may be loopback: a test server on this machine); a *network* may be `0.0.0.0` or `::`; a *mask* is a contiguous dotted IPv4 mask or a
   length (0–32, 0–128) without leading zeros. Errors name the variable and the rule, never the value
   (`OpenConnectNetwork.Failure`), since they go to the log.

   | Variable | From | Rule |
   |---|---|---|
   | `reason` | openconnect | one of the five above |
   | `TUNDEV` | the kernel | `utun0`–`utun999` (macOS), `tun0`–`tun99999` (Linux), no leading zeros; must exist, and its index is noted when the run starts: every change to the interface, its addresses or routes through it checks that the name still has that index (otherwise "the tunnel interface went away"), and so does a revert in that run |
   | `VPNGATEWAY` | the address openconnect connected to | a host address |
   | `INTERNAL_IP4_ADDRESS` | server (`X-CSTP-Address`, raw text) | absent, or a host address |
   | `INTERNAL_IP4_NETMASK`, `INTERNAL_IP4_NETMASKLEN`, `INTERNAL_IP4_NETADDR` | openconnect, only when the server's netmask parsed and is contiguous (`script.c` 313–340) | all three or none; consistent with each other and the address; none: the address alone (`/32`) |
   | `INTERNAL_IP6_NETMASK` | server (`X-CSTP-Netmask` with `:` or `X-CSTP-Address-IP6`, raw) | absent, or `<host address>/<0–128>` (a mask such as `ffff:ffff::` is refused) |
   | `INTERNAL_IP6_ADDRESS` | server, or the address part of `INTERNAL_IP6_NETMASK` (`script.c` 343–353) | absent, or a host address equal to the address in `INTERNAL_IP6_NETMASK` when both are set; alone: `/128` |
   | `INTERNAL_IP4_MTU` | negotiated | 576–9000, for both families; 1280 or more when IPv6 is assigned |
   | `INTERNAL_IP4_DNS` | server (`X-CSTP-DNS`, `-DNS-IP6`; IPv4 and IPv6 mixed) | at most 3 words (split on blanks), each an address, not unspecified (`DNSSettings.address`'s rule); repeats dropped |
   | `CISCO_DEF_DOMAIN` (split on spaces), `CISCO_SPLIT_DNS` (split on commas) | server | each a plain host name (`DomainName`, the rule of the Linux `DNSSettings.domain`), lowercased, without a final dot, at most 16 of each once repeats are dropped |
   | `CISCO_SPLIT_INC`, `CISCO_SPLIT_EXC` and their `_<n>_ADDR`, `_MASK`, `_MASKLEN` | server (normalized by openconnect, `script.c` 220–247) | the count at most 1,024 (none: 0); every `n` below it has all three, and no other variable starts with `<count>_` (no gap, no index beyond the count, no other field); the address with its host bits already cleared, mask and length agreeing; an exclude of length 0 is refused, an include of length 0 makes the family a full tunnel |
   | `CISCO_IPV6_SPLIT_INC`, `CISCO_IPV6_SPLIT_EXC` and their `_<n>_ADDR`, `_MASKLEN` | server (`_ADDR` raw text up to the `/`, `script.c` 138–142; `_MASKLEN` through `strtol`, so possibly negative) | as above, without `_MASK`: an IPv6 address, length 0–128, host bits cleared here |
   | `VPNPID` | openconnect | absent, or a pid above 1 (not used: the session check proves the pid) |

   At least one of the IPv4 and IPv6 addresses must be set. Ignored, never used: `CISCO_BANNER`
   (decoded `%XX`, may hold line breaks), `CISCO_PROXY_PAC`, `CISCO_CSTP_OPTIONS` (every `X-CSTP-*`
   header), `IDLE_TIMEOUT`, `INTERNAL_IP4_NBNS`, `LOG_LEVEL`. A header value cannot hold CR or LF but may hold
   spaces, quotes, `$`, backquotes, `;` and bytes from 0x80; variable names are openconnect's own
   (fixed or built from counters), so a server cannot set `BASH_ENV` or the like.
4. **Record, then apply**, one change at a time under the run root's lock (`<run root>/network.lock`,
   `flock`, 0600, root; held for the whole run, so changes are made one session at a time and a revert
   reads the other sessions' records while none of them changes). Each change is journaled in the
   session's record (`network`, 0600) before it is made, and its outcome after: a change is the
   session's own only when it succeeded. Every entry is one `write` of one line appended to the file
   (`OpenConnectJournal`), so a hook killed at any point leaves a record that reads back, its last
   change pending at worst. Every program runs from a fixed path with an argument list (no shell, never
   the hook's environment: `PATH` and `LC_ALL=C` only, `Spawner.spawn`, its own process group, its output
   into a pipe of which the first 200 bytes go into a failure's reason) for at most 10 s (and what is left
   of the run), then it is killed; macOS: `/sbin/ifconfig`, `/sbin/route`, DNS through the
   SystemConfiguration API; Linux: `ip` and `DNSApplier` (LINUX.md).

   **The commands** (`OpenConnectCommand`, the platform's programs from `OpenConnectSystem.tools`, golden-tested to
   the byte; `route` always with `-n`, the family and the length spelled out, never a class or a name). macOS:

   ```
   ifconfig utun5 mtu 1406 up                                    link; revert: ifconfig utun5 down
   ifconfig utun5 inet 10.11.0.2 10.11.0.2 netmask 255.255.255.255   revert: ifconfig utun5 inet 10.11.0.2 delete
   ifconfig utun5 inet6 2001:db8:1::2 prefixlen 128              revert: ifconfig utun5 inet6 2001:db8:1::2 delete
   route -n add -inet -net 0.0.0.0 -netmask 128.0.0.0 -interface utun5
   route -n add -inet -host 192.0.2.10 198.51.100.1              (-interface ppp0 for a gateway link without an address)
   route -n add -inet6 -net 2001:db8:5:: -prefixlen 48 fe80::1%en0   (a link-local next hop names its interface)
   route -n add -inet6 -net :: -prefixlen 1 ::1 -reject          (IPv4: 127.0.0.1 -reject)
   route -n delete -inet -net 0.0.0.0 -netmask 128.0.0.0         every route's revert: the destination only
   ```

   Linux (`ip` from the first of `/usr/sbin/ip`, `/sbin/ip`, `/usr/bin/ip`, `/bin/ip` that passes `TrustedPath`; a
   route's revert names its next hop and type, so the kernel deletes only that route):

   ```
   ip link set dev tun0 up mtu 1406                              revert: ip link set dev tun0 down
   ip -4 addr add 10.11.0.2/32 peer 10.11.0.2 dev tun0           revert: ip -4 addr del 10.11.0.2/32 peer 10.11.0.2 dev tun0
   ip -6 addr add 2001:db8:1::2/128 dev tun0                     revert: ip -6 addr del 2001:db8:1::2/128 dev tun0
   ip -4 route add 0.0.0.0/1 dev tun0                            revert: ip -4 route del 0.0.0.0/1 dev tun0
   ip -4 route add 192.0.2.10/32 via 198.51.100.1 dev eth0       (dev ppp0 alone for a gateway link without an address)
   ip -6 route add 2001:db8:5::/48 via fe80::1 dev eth0
   ip -6 route add unreachable ::/1                              revert: ip -6 route del unreachable ::/1
   ```

   `/sbin/route` rather than a routing socket of our own: the commands are the ones every macOS VPN
   script has used for years (`-reject`, `-interface`, a scoped link-local next hop), and the outcome is
   not read from their text. The routing table is read with `sysctl` (`NET_RT_DUMP`, no privileges, both
   families, `KernelRoute.parseDump`): once before the changes, kept up to date with the routes added, and
   again after a `route` that failed. A route is in the way of an `add` when an unscoped entry of that
   destination is there that the kernel did not make itself (`RTF_WASCLONED`, `RTF_LLINFO` entries, such
   as the one for the connection to the server, are replaced by an added route; `RTF_IFSCOPE` entries are
   another key). **Looked for first, journaled after** (`OpenConnectHook.finding`): every change is looked
   for under the lock before anything is journaled for it, so the record never shows as begun (`+`, which a
   revert would undo) something the system had before. **What "File exists" means:** a route already there
   counts only when it has exactly the planned next hop (the same interface, the same gateway on its
   interface, a reject route); it is journaled without a `+` as shared (`&`) when another session's
   record holds it (own, shared or pending), or as not PassTunnel's (`~`, never removed by anyone) when
   none does (a session whose record cannot be read counts as none: `~` may leave a route behind, but
   never removes one that is not PassTunnel's). Any other route of that destination fails the set-up
   ("another route for 10.20.0.0/16 exists already, through utun3"), for every kind of route: traffic the
   set-up claims (an include, the assigned network, a DNS server, a full tunnel's half, the server's own
   route, an exclude, a block) would go elsewhere, and the hook replaces nobody's route. One exception: an
   exclude whose destination is a network the Mac is attached to, held by that network's own on-link route
   (the server excludes the LAN the Mac is on), is `~`: that traffic leaves outside every tunnel already. A
   `route add` that fails is looked at again in a fresh table: exactly the planned route (someone made it
   meanwhile) is `~` or `&`, anything else is a failure (`!`). An address already on the interface is `~`
   too; the link change and DNS are always the session's.

   A revert deletes a route only while the table still holds it as the session added it
   (`KernelRoute.is`): one replaced meanwhile (another next hop) is no longer the session's and stays,
   one gone counts as reverted, and a `route delete` that fails counts once a fresh table no longer holds
   it. An address is deleted only while it is on the interface, the link brought down only while the
   interface is there; DNS keys are removed whether or not they are there.
   - `pre-init`: nothing.
   - `connect` (`OpenConnectPlan.connect(_:policy:underlay:)`, from the checked network, the policy
     and the default gateway of each family before the tunnel, read from the routing table:
     `Underlay(routes:attached:tunnel:)`, the unscoped default route of each family unless it leaves
     through the tunnel itself, then the one scoped default route of an interface that is no `utun` or
     `ipsec`, if there is exactly one; none otherwise), in this order:
     1. the interface: MTU and up (`ifconfig utunN mtu M up`), then its addresses as host addresses
        (`inet A A netmask 255.255.255.255`, `inet6 A prefixlen 128`); networks are routes of their own,
        so with `set_routes` off the tunnel adds no route at all;
     2. with `set_routes`, decided per family that has an address. A family is a **full tunnel** when the
        server sent no split includes for it, or includes that together hold every address (`0.0.0.0/0`;
        `0/1` and `128/1`, which openconnect 9.21 passes as they came; any set of prefixes that covers the
        space, `OpenConnectPlan.covers`): then `0/1` and `128/1` (`::/1` and `8000::/1`) go through the
        interface instead, never replacing `default` (so `RoutingTable.trafficRoutes` and the other-VPN
        check see it as they see OpenVPN's `def1`), and the family counts as a full tunnel for the block of
        the other family, `OverridePrimary` and the server's host route. Otherwise each include goes through
        the interface, then the assigned network (`INTERNAL_IP4_NETADDR/NETMASKLEN`, the
        `INTERNAL_IP6_NETMASK` network; `/1` to `/31` or `/127`) and, with `set_dns`, a host route to each
        DNS server of the family, each where no include holds it already. Each exclude of the family goes
        through its original gateway (left out when the family has none).

        **Local networks stay local** (owner decision): `Underlay.attached` are the networks attached to the
        Mac's interfaces: the network of each address of an interface that is up, not loopback and not
        point-to-point (`getifaddrs`), which is the prefix the kernel puts on-link for it. Not the
        routing table's interface routes, which another session's routes into its tunnel would mimic;
        those on the tunnel's own interface, link-local `fe80::/10` and length 0 do not count. A route the server asked for into
        the tunnel (an include, the assigned network, a DNS server's host route) that lies inside such a
        network, or is one, is left out, so the server cannot take over part of the LAN the Mac is on; it is
        no error, and the success line counts it (`2 routes kept local`). A broader route is kept (`10/8`
        with a LAN `10.1.2.0/24`: the longer on-link prefix still wins), and so are a full tunnel's two
        halves.

        A family **without an address while the other is a full tunnel is blocked**: reject routes for
        both halves of its space (owner decision 8 for IPv6; the same for IPv4 in the rare IPv6-only
        tunnel), and every include, exclude and DNS server the server sent for that family is ignored, so
        nothing of the server's makes a hole in the block (and DNS does not wait for a server it cannot reach). The block is a route, not a packet filter:
        `route add -inet6 -net ::/1 ::1 -reject` (macOS) and `ip -6 route add unreachable ::/1` (Linux),
        chosen over a blackhole (which drops silently, so a program waits for its timeout before it falls
        back to IPv4) and over a route into the tunnel (the utun has no address of that family, the server
        would drop it, again a timeout): a reject route answers at once with "no route to host", and Happy
        Eyeballs moves to the other family. It takes away the family's default path only; routes that are
        more specific stay and win (the local network's on-link prefixes, link-local, other interfaces' and
        other VPNs' routes), so traffic to those still leaves outside the tunnel; a complete block would
        need pf or nftables, which Phase 1 does not use. A reject route does not go with the interface,
        hence the record. With a split tunnel, a family without an address is left alone.

        And a host route to `VPNGATEWAY` through the original gateway of its family, which goes **first** of
        all routes, whenever any route the plan sends into the tunnel (an include or half, the assigned
        network, a DNS server's host route) or a reject route would capture it (not for a loopback server);
        when that family has no usable default gateway (none, or the tunnel itself) the set-up fails ("there
        is no IPv4 default route to keep the VPN server reachable outside the tunnel"). An assigned address
        equal to `VPNGATEWAY` is refused when the environment is checked. A destination is routed once, in
        the order server host route, reject routes, excludes, routes into the tunnel: so a reject route is
        never dropped, an exclude wins over an include of the same network, and the server's host route
        over an include, the assigned network or a DNS server on that host;
     3. with `set_dns` and at least one DNS server: macOS writes dynamic keys of the service
        `passtunnel-<uid>-<profile id>` through `SCDynamicStore`, all at once (`SCDynamicStoreSetMultiple`,
        `OpenConnectDNSSettings`, golden-tested), and removes them on revert. Only that service is ever
        written or removed (checked again right before). Never a `Setup:` key, never `networksetup`, never
        `/etc/resolv.conf`, no `scutil` text. configd's IPMonitor builds the resolver configuration from the
        `State:` services:
        - **split tunnel:** only `State:/Network/Service/<service>/DNS` with `ServerAddresses`,
          `SupplementalMatchDomains` (`CISCO_SPLIT_DNS` then `CISCO_DEF_DOMAIN`; no DNS at all when there are
          none) and `SearchDomains` (`CISCO_DEF_DOMAIN`, when there are any): a resolver for those domains,
          whatever the primary service is, as OpenVPN's own macOS `dns-updown` writes it for split DNS
          (`State:/Network/Service/openvpn-<dev>/DNS`). No `IPv4`/`IPv6` entity, so the service is never a
          candidate for primary.
        - **full tunnel** (every family with an address, and `set_routes`): the service is made the primary
          one, whose `DNS` (`ServerAddresses`, `SearchDomains`) becomes the default resolver
          (`State:/Network/Global/DNS`, resolver #1 of `scutil --dns`). IPMonitor elects the primary service
          among those with a router: `OverridePrimary` = 1 ranks a service first, but a service without
          `Router` is not eligible and keeps only scoped settings (the system's own `utun` services show
          `Router` and `PrimaryRank Scoped` in `scutil`). So `State:/Network/Service/<service>/IPv4` has
          `Addresses`, `SubnetMasks` (`255.255.255.255`), `Router` (the tunnel's own address, on its
          point-to-point link), `InterfaceName` and `OverridePrimary` = 1, and `/IPv6` likewise with
          `PrefixLength` (128), for each family the tunnel has an address of. OpenVPN's `dns-updown` reaches
          the same by rewriting the primary service's `Setup:` DNS, which a crash would leave changed for
          good; these keys go with a restart. As the primary service with a router, the tunnel also gets the
          system's `default` route while the keys are there (configd's change, not the hook's: the full
          tunnel's halves carry that traffic already); the underlay's fallback above is for that case, and
          the revert ends it with the keys.

        Linux uses `DNSApplier`.

     Each change has one line of text, which the record stores and the golden cases compare
     (`OpenConnectPlan.Change.text`; every field a checked value, so no blank or line break in one):

     ```
     link utun5 mtu 1406
     address utun5 10.11.0.2
     route 192.0.2.10/32 gateway 198.51.100.1 en0          (gateway link ppp0: a link without an address)
     route 192.168.0.0/16 gateway 198.51.100.1 en0
     route ::/1 reject
     route 0.0.0.0/1 interface utun5
     dns passtunnel-501-acme utun5 primary servers=10.11.0.53,2001:db8::53 search=example.com match=-
     ```
   - `attempt-reconnect` (`OpenConnectPlan.refresh`): needs a record of this interface whose status is
     `up` or `reconnecting`. The record's status becomes `reconnecting`, then the routes around the
     tunnel follow the default gateway, which may have changed (another network). For each family that
     has a usable gateway now, the session's own and shared routes through another gateway are removed,
     newest first (one another session's record holds is left and journaled as spared, `?`), then the
     ones `connect` would add now and the record does not hold are added, looked for first as in `connect`
     (so a route another session still uses through the old gateway fails the attempt: the session stops
     and signs in afresh rather than replacing it). A family without a gateway right
     now (the network is down while openconnect retries) is left as it is. A route around the tunnel the
     session found there (`~`) was never its own: it is neither removed nor expected afterwards. Nothing is
     written to the log.
   - `reconnect` (`OpenConnectPlan.matches`): openconnect refuses a different address or netmask
     itself (`library.c` 676–712). openconnect 9.21 does not rebuild the hook's environment after a
     reconnect (`prepare_script_env` runs once, in `openconnect_setup_tun_device`, `library.c` 1567),
     so the hook sees the values of `connect`; it still checks them again and compares the plan, but for
     the routes around the tunnel, with what the record holds. Any difference fails the reconnect ("the
     server changed the network settings"), and the session is stopped (below), for a new connect to
     set up afresh. Then the system must still have everything the session holds (`OpenConnectHook.verify`):
     every change it owns or shares (`=`, `&`; not `~`, which was never its) exactly as made: the tunnel
     interface with the index noted when the run started, up and with its MTU (`interfaceLink`: the link
     entry of `getifaddrs`), its addresses, every route with its planned next
     hop (into the tunnel, around it, reject), the DNS keys with their contents
     (`OpenConnectSystem.hasDNS`). It is checked, never repaired: any difference ("the network changed while
     the connection was re-established: …") reverts what the session holds and stops it like any failure,
     and `ConnectionManager` (#184) connects afresh with a new sign-in. A change is journaled as reverted
     only once the system no longer has it, so one that cannot be removed stays the session's for the
     helper's revert. Otherwise the status is `up` again and the success line is
     written again.
   - `disconnect`: everything the record owns is reverted, newest first, and so is a change that was
     begun but has no outcome (it may have been made), except what another session holds (below).
     Reverting is idempotent (a change already gone counts as reverted). openconnect still holds its
     `utun` while it runs the hook for `disconnect`, so the interface's index is looked up then. A revert
     that does not finish writes `passtunnel vpn-hook: restoring the network failed: <reason>`
     (`VPNHook.revertFailureLine`); the helper tries again once openconnect has exited (step 7).
   - **Any failure** (a refused value, the policy, the lock, the interface, the routing table, the plan, a
     change, the record, `stopping`, the time limit) reverts what the record holds, with the interface's
     index noted at the start of the run, records `status failed <reason>`, writes the failure line after
     the revert and stops openconnect (step 6). A failure before the record exists makes one for a checked
     `TUNDEV`, so the helper sees the failure too.

   **The record** (`OpenConnectRecord`, `network`, 0600, root): a journal, strict like `policy`, read
   back only as a whole (`parse` refuses anything `text()` would not write, or an entry out of the
   order `append` allows; at most 4 MiB, `compacted()` keeps a long session's small):

   ```
   passtunnel-network 1
   interface utun5
   + route 192.0.2.10/32 gateway 198.51.100.1 en0        begun: written before the change is made
   = route 192.0.2.10/32 gateway 198.51.100.1 en0        the session's own: reverted later
   & route ::/1 reject                                   found there, held by another session: shared
   ~ route 192.168.1.0/24 gateway 198.51.100.1 en0       found there, held by no session: never removed
   + dns passtunnel-501-acme utun5 primary servers=… search=… match=-
   ! dns passtunnel-501-acme utun5 primary servers=… search=… match=-   failed: nothing changed
   - route 192.0.2.10/32 gateway 198.51.100.1 en0        reverted
   ? route ::/1 reject                                   spared: left to another session at the revert
   status up | status reconnecting | status failed <reason>
   ```

   One change at a time: an outcome must name the change just begun (`&` and `~` may also stand alone, for a
   change found there while none is pending), a status or a new change needs none pending, a revert names
   one that is the session's (own or shared) or pending. What the system has as asked is the session's and
   those that were there already (`applied`); the latest `status` is the set-up's state;
   `compacted()` keeps a pending change after the status (a status cannot follow one).

   **What to revert** (`toRevert(sparing:)`, pure, called under the run root's lock with the records of
   every other session of the run root: not only those whose tool still runs, since a session that ended
   holds what its record holds until its revert has run (the helper's, after the tool exited; a record
   whose revert ran holds nothing more), so a session that connects in between shares what it finds (`&`)
   and that revert spares it; a record that cannot be read claims every change of this session two
   sessions can share, the routes around the tunnel and the reject routes): every change that is the
   session's own, shared or pending, newest first, but none that another session's record lists as its
   own, shared or pending (one it found there with no session holding it, `~`, claims nothing). The
   revert starts with `beginRevert(sparing:)`, which journals each change so left alone as spared (`?`,
   which also settles a pending one, so the rest of the revert can be journaled) and returns the list;
   each change on it is then journaled as reverted once undone. Some
   changes can be the same in two sessions: a reject route (`route ::/1 reject`), the host route to a VPN
   server two profiles share, an exclude through the same gateway. The session that made one first owns
   it, the other finds it held and shares it (`&`), and a pending one may be either session's; removing it
   while the other runs would take away that session's block or its route to the server, so whichever of
   them ends first spares it, and the last one removes it: nothing outlives all the sessions that needed
   it. Unique to a session, and so never spared in practice: its interface's link and addresses, its
   routes through that interface, its DNS service key `passtunnel-<uid>-<profile id>`.
5. **Bounded.** openconnect waits for the hook without a limit, and the hook runs in its own process
   group, which `kill(-pid)` does not reach. So the whole hook run, the lock wait included, has a
   limit of 30 s (`OpenConnectHook.runLimit`: checked before each change, each program gets at most what
   is left; a change past it fails the set-up, "the network set-up did not finish within 30 seconds", and
   what the revert has no time left for is reverted by the `disconnect` run or the helper); `SIGALRM` ends
   the run one second later whatever hangs (set to its default action and unblocked first, since an
   ignored or blocked signal stays so across `exec`). The hook writes its pid and start time to `hook` in
   the session directory under the lock when it starts and removes it when it ends, and it checks for the
   `stopping` mark (below) before each change: once that is set it applies nothing more ("the session is
   being stopped"), but a revert still runs.
6. **Report and enforcement.** The hook records its outcome in the record (`up`, or `failed` and why)
   and writes one line to the session log (`VPNHook.Report.line`, `VPNHook.failureLine`):

   ```
   passtunnel vpn-hook: utun5 up: 10.11.0.2, 2001:db8:1::2, 4 routes, full tunnel, DNS 10.11.0.53, search example.com
   passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes, full tunnel, IPv6 blocked, DNS 10.11.0.53 10.11.0.54, search example.com
   passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes, DNS 10.11.0.53, search example.com, split DNS corp.example.com example.com
   passtunnel vpn-hook: setting up the network failed: INTERNAL_IP4_DNS is not a list of IPv4 and IPv6 addresses
   ```

   The success line holds the interface, its addresses, the number of routes into the tunnel, `full
   tunnel`, a blocked family, the routes kept local, and with DNS its servers, search and split DNS domains, every item a
   checked value or fixed text; `VPNHook.Report.parse` reads back exactly that form (for #184). A
   failure's reason passes through `VPNHook.oneLine` (printable ASCII, at most 300 bytes; anything else
   becomes `?`), so no text can end the line or forge another; the hook's own reasons name variables,
   never values. The failure line is written after reverting what was applied.
   openconnect ignores the result of the `connect` call (`library.c` 1593) and keeps running, so the
   failure must be acted on by PassTunnel, and not only by a client that may be gone: the hook sends
   SIGTERM to its openconnect (the pid the session check proved), and the supervisor, which reads the
   record of each of its openconnect sessions every 5 s (`Supervisor.superviseOpenConnect`), stops a
   session whose record says `failed`, has no `up` within 60 s of the start or adoption
   (`VPNHook.setupDeadline`; `reconnecting` counts as up, it only follows `up`), or stays `reconnecting`
   for 120 s (`VPNHook.reconnectDeadline`, counted from the first check that saw it). A record it cannot
   read at that moment (the hook is appending to it) is looked at again 5 s later. The client learns the same
   record's status from the helper's `status` reply (`TunnelStatus`, #184): `failed` is `PTError.setupFailed`,
   `up` is "connected". The log lines are for people (and the address shown); the server writes part of the
   log, so they decide nothing. openconnect's own `Configured as …` (`main.c` 1660) is printed before the hook
   runs and marks nothing.
7. **Stop and revert.** When the helper stops a session it sets `stopping` first (`terminate`), so a
   hook running now applies nothing more. When a session's tool has exited (`Supervisor.finish`;
   `stopAll` after the kill; `adoptOrphans` for a session that is not adopted, and for a record a
   previous helper could not restore, and an openconnect a restarted helper finds recorded without its start
   time, `SessionRecovery.Decision.stopUnidentified`: its hooks cannot prove their generation and would
   neither set up nor revert anything, so it is killed while it is still the recorded process (pid and
   executable) instead of adopted; on Linux the daemon's exit handling and the previous-instance
   cleanup), the helper runs `OpenConnectHook.restoreAfterExit` in-process, as `pendingDNSDown` does for
   OpenVPN: it sets `stopping`, waits for the run root's lock, which a running hook holds, at most 32 s
   (the hook's limit and its `SIGALRM`), then kills the hook the `hook` mark names (only if it is still
   that process, by pid and start time, a root process of a staged `vpn-hook`) and waits 2 s more, and
   then reverts under the lock, sparing what another session holds. The tunnel interface went with
   the tool, and with it its link, its addresses and the routes through it, which are journaled as
   reverted without a command: a `utun` of that name may be another session's by now. The gateway host
   route, the reject routes and the `State:` keys do not go with it, hence the record. A revert that fails
   keeps the record (and only the record: the configuration with its cookie, the policy, the state and
   the marks go, `keepOnlyRecord`) in the session directory: the profile cannot start over it (a start
   tries the revert once more and is refused while it fails), and the helper tries again every 15 s
   (`restoreRetryInterval`), as the Linux daemon does for DNS (LINUX.md, "Supervision"). A record that
   cannot be read is logged and removed: nothing can be undone from it. While it waits, the helper's
   queue waits too, as it does for OpenVPN's `dns-down`.

### Supervision and log (#182, #184)

- **Start** (#182): `ToolStager` stages the tools and then `vpn-hook` (`stageHook`) while the request is
  prepared (the configuration names the staged hook; `Supervisor.start` hands `prepare` a `stage` that
  stages once per start); `Spawner.spawnVerified` with `PT.toolRequirement(identifier:
  PT.openconnectIdentifier)` and the cdhash pins, `state` written in `beforeResume`; output (INFO on
  stdout, errors on stderr) to the log descriptor, the profile's `.log` replaced as for the other tools
  and trimmed by `capLog`. No `interface`: openconnect opens the first free `utun` (`tun.c` 299–370).
- **Stop:** SIGTERM; openconnect cancels (`main.c` 815–835), tries to send BYE to the server
  (`cstp_bye`, `cstp.c` 1237), runs the hook's `disconnect` and exits 0 ("User cancelled
  (SIGINT/SIGTERM); exiting."). A BYE that was sent does not prove the server invalidated the
  cookie, and none is sent over a broken connection or after SIGKILL: the cookie is treated as
  valid until the server's own expiry. SIGKILL after 5 s as today; a hook still running is handled
  as in step 7 above.
- **Adoption** unchanged (`state`: pid, uid, staged executable; `proc_pidpath`); sessions count
  against `SessionPolicy.maxSessionsPerUser`, and `status` lists them like the others (pids only; the
  helper reports no "connected"). An adopted openconnect gets the set-up deadline again.
- **Exit codes** (`main.c` 2479–2521): 0 cancelled or detached; 1 authentication, I/O, "Session
  terminated by server; exiting."; 2 "Cookie was rejected by server; exiting.".
- **Log** (`VPNLog`, `VPNLog+OpenConnect.swift`, #184):

  | Line | Meaning |
  |---|---|
  | `POST https://vpn.example.com/` (`http.c` 894) | sign-in run: a form was submitted |
  | `Failed to complete authentication` (stderr, `main.c` 2399) | sign-in run failed |
  | `User input required in non-interactive mode` | the server asked for more than was answered |
  | `Server certificate verify failed: …`, `None of the 1 fingerprint(s) specified via --servercert match …` | trust failure; nothing was sent |
  | `getaddrinfo failed for host '…'`, `Failed to connect to host …`, `Failed to open HTTPS connection to …` | `host_not_found` / `unreachable` |
  | `Got CONNECT response: HTTP/1.1 200 OK`, `CSTP connected. DPD …` | root run: tunnel negotiated |
  | `passtunnel vpn-hook: utun5 up: …` | for display: the address (when the line names the interface the helper reports), the routes' count and DNS (`VPNHook.Report.parse`); "connected" itself is the helper's `TunnelStatus` |
  | `passtunnel vpn-hook: setting up the network failed: …` | for display; `PTError.setupFailed` comes from the helper's `TunnelStatus` |
  | `Cookie was rejected by server; exiting.`, `Session terminated by server; exiting.` | the tool exits: a drop, and a reconnect signs in again |

  `NetworkClaims` reads the session's routes from the routing table through its interface (as for
  openfortivpn) and its DNS from the hook's line.

  As built: whether a running session is up is never read from its log, part of which the server writes
  (openconnect logs the CONNECT reply's status line as it came, CR included, so a line could be made to look
  like the hook's). The helper reports it in its `status` reply (`HelperResponse.tunnels`, profile ID →
  `TunnelStatus`: `setting_up`, `up`, `reconnecting`, `failed` with the hook's reason, or `unknown` while the
  record is being written; and the interface), read from the hook's root-owned record
  (`HelperCore.tunnelStatus`, `OpenConnectJournal`). `up` and `reconnecting` are "connected" (`observe`,
  `waitUntilConnected`, which asks for the status every half second while connecting; `unknown` keeps a
  connected session connected), `failed` is `PTError.setupFailed` (the session is stopped, kind `setup`, not
  retried). The log only gives what is shown: the address, from the hook's success line when it names the
  interface the helper reported, read as whole LF lines of printable ASCII only (`VPNLog.openConnectLines`), and
  the failure's tail. The tool's exit while connecting is `connectFailed` (`toolUnsupported` when dyld's line comes
  first). A session that comes up within `Timing.anyConnectTimeout` (90 s) is connected; past it the manager stops
  it (`connectTimeout`, kind `timeout`: the sign-in had reached the server). The tool's exit after "connected" is a
  drop, handled as for the other types: with `auto_reconnect`, a new sign-in (`performConnect(interactive:
  false)`), whose code waits for the next window when the last one's was sent (`.last-otp`); a hook that
  refused openconnect's own reconnect stops it, and so ends the same way. The other-VPN check counts the
  interface the helper reports as PassTunnel's own, and `ProfileNetwork.observedOptions` keeps what the
  session takes over for the overlap check (`ProfileNetwork.anyConnectOptions`: `redirect-gateway def1` with
  `ipv6`/`!ipv4` as the addresses go for a full tunnel, `dhcp-option DNS`, `DOMAIN` (search) and `DOMAIN-ROUTE`
  (split DNS) from the hook's line, read as above, and the routes
  through the interface but its own addresses). Every failure is a `ConnectionFailure` kind:
  `auth_rejected`, `host_not_found`, `unreachable`, `configuration` (certificate or key, with `server_cert`; more
  answers asked for; an unknown group), `host_scan_required` (new), `setup`, `timeout`, `tool_unsupported` (dyld,
  or this macOS older than 15.4), `cancelled`, `failed`; Palo Alto GlobalProtect adds `sso_required` (#231).

### Helper protocol 4 (#182)

`PT.helperProtocolVersion` is 4 since #182; an older helper fails `ensureCompatible()`
with `versionMismatch` and is replaced as today (`HelperBuild.relation`: a lower protocol is `.older`),
an older client's requests fail the helper's version check, and `passtunneld`'s `hello` reports 4 as
well. `passtunneld` refuses `startOpenConnect` ("Cisco AnyConnect is not supported by passtunneld
yet.") before preparing anything, until #187; since then it runs it as the helper does (LINUX.md). The `status`
reply has an optional `tunnels` key since #184:
profile ID → `TunnelStatus` (`state`, `reason`, `interface`) for the caller's own openconnect sessions,
from each one's record (above). It stays within protocol 4, which no released helper speaks, and the app
only works with the helper of its own build (`ensureCompatible`); a reply without the key reads as before.

```swift
case startOpenConnect(OpenConnectStart)   // profileID, profileDir, logPath, host, port, usergroup,
                                          // connectURL, resolve?, cookie, serverCert (the accepted
                                          // FINGERPRINT), profileServerCert (the profile's pin or
                                          // empty), tlsOnly, setDNS, setRoutes
```

JSON keys: `profile_id`, `profile_dir`, `log_path`, `host`, `port`, `usergroup`, `connect_url`,
`resolve` (left out for an IP-address host), `cookie`, `server_cert`, `profile_server_cert`, `tls_only`,
`set_dns`, `set_routes`. `OpenConnectStart`'s description and mirror show neither the cookie nor the
values the server chose (`connect_url`, `resolve`, `server_cert`), which could repeat it; decoding
errors name fields only (`HelperCore.decodeRequest`).

`HelperCore.prepareOpenConnect` (Shared, unit-tested with injected uids, paths and macOS version), in
this order, stopping at the first failure:

1. openconnect runs on this macOS (`checkOpenConnectRuns`: `Tool.minimumMacOS`, 15.4, against
   `HelperCore.systemVersion`): "Cisco AnyConnect requires macOS 15.4 or later." before anything is
   read, staged or written (owner decision, #2);
2. every field (`HelperCore.openConnectConfig`): the profile ID, `usergroup` (empty or the profile
   rule), `profileServerCert` (empty or a full pin), then `OpenConnectAuthResult.tunnelConfig(host:
   port:connectURL:resolve:cookie:serverCert:profileServerCert:scriptPath:tlsOnly:)`, the only builder of
   the root configuration: the profile rules below, `connectURL` exactly `https://<host>[:<port>]/` for
   the request's `host` and `port` (an IP-literal host compared as an address), `resolve` required as
   `<host>:<IP literal>` for a host name and absent for an IP literal, `serverCert` a full pin equal to
   `profileServerCert` when that is set (the destination binding the client checked, held again here:
   the helper has no other notion of an approved destination for this type, as for FortiGate), the
   cookie's length and characters; with a well-formed stand-in hook path, as nothing is staged yet;
3. the profile directory and log path (`openProfileDir`, `logFileName`, as for the other tools);
4. the tools staged and checked (`hookPath`), giving the staged hook's path;
5. the configuration built again with that path, rendered (`render`: `validate`, then `checkRendered`),
   and the text checked once more against the line count the request implies (header and seven
   options, `resolve` for a host name, `no-dtls` for TLS only);
6. a fresh session directory with `openconnect.conf` and `policy` (0600, the helper's), and the
   profile's log replaced; a failure here removes the directory, and the cookie with it.

`server` is rendered from `host` and `port`, not from the text the helper was sent. Errors name fields
and fixed reasons, never values (tested with every refused field). The request stays under the
64 KiB limit (the cookie is at most 4 KiB).

### Profile (#181)

`VPNType.anyconnect` (`--type anyconnect` from #185; later phases add their own types for the same backend), in
`PassTunnelKit` since #181. New keys (JSON snake_case), FortiGate's reused where the meaning is the same; the rules are
`OpenConnectAuthConfig`'s (`PassTunnelVPNConfig`), so the profile, the sign-in file and the helper check the same thing:

| Key | Rule |
|---|---|
| `host` | `OpenConnectAuthConfig.isValidHost`: `FortiConfig.isValidHost` without an IPv6 zone id (a URL cannot carry one), stored as typed; rendered lowercased, in brackets when IPv6 |
| `port` | 1–65535, default 443 |
| `usergroup` | empty or 1–255 bytes of `A–Z a–z 0–9 - _ . ~ /`, no `..`, no leading `/` (the URL path) |
| `authgroup` | empty or 1–255 bytes, no control characters or line separators, no leading or trailing whitespace, no leading `=` (matched against the server's group list) |
| `server_cert` | empty or `pin-sha256:` + 44 base64 characters (`OpenConnectPin.isValid`); `passtunnel set` and share import store `OpenConnectPin.normalize`'s form, `save` refuses any other spelling (not `trusted_cert`: another hash) |
| `tls_only` | boolean, default false: `no-dtls` |
| `set_dns`, `set_routes` | as for FortiGate |
| `username` | empty (asked each time) or, trimmed as it is sent, 1–255 bytes, no control characters, no leading `=` (a config file value) |
| `password_mode` | `keychain` or `ask` (no certificate sign-in) |
| TOTP, `otp_delivery`, `otp_template` | as today; `otp_delivery` defaults to `.separate` (`VPNType.defaultOTPDelivery`, also for a file without the key); with `.combined` and a code, the template is at most 4,095 bytes without LF, CR or NUL (`Profile.isValidAnyConnectTemplate`) |
| password, composed answers | 1–4,095 bytes, no LF, CR or NUL (`OpenConnectAnswers`), checked when they are sent (#184): the password is no profile field |

`usergroup`, `authgroup`, `server_cert` and `tls_only` are written to `profile.json` and share files only for type
`anyconnect` (they are read for any type and dropped on the next save of another type's profile), so OpenVPN and
FortiGate files stay exactly as before. `ProfileFields` sets and shows them for this type only (aliases `user_group`,
`auth_group`; `trusted_cert` is FortiGate's alone, the new keys on another type are `wrong_profile_type`). There is no
user agent field and no raw option. Each rule is `PTError.invalidField(<key>)` (the username's too, where FortiGate's
is `usernameTooLong`), enforced by `ProfileFields.set`, `ProfileStore.save` (`checkUsername`, `checkHosts`,
`checkAnyConnectFields`), `ConnectionManager` before it signs in (#184), and again by the helper (`OpenConnectConfig.validate`).

`ProfileDestination.of` hashes, after the unchanged version tag `passtunnel-destination-1` and the type, the trimmed
lowercased host, the port, `usergroup` and `server_cert` (normalized, so a hand-edited spelling of the same pin does
not move the binding). `authgroup`, `tls_only`, `set_dns` and `set_routes` are not part of it: the group is a choice
the server offers on the same destination. The OpenVPN and FortiGate fingerprints are unchanged (the type is hashed
first, so no AnyConnect profile can share one), and so are the secrets and network records bound to them.

Phase 1 creates profiles by manual entry and by pasting a URL: `AnyConnectServer.parse` takes
`https://vpn.example.com[:port][/usergroup]` (`https://` may be left out or upper case; blanks around it ignored) and
gives the lowercased host (an IPv6 literal from its brackets), the port (443 when none) and the user group as written;
it refuses another scheme, user info, a query or fragment (`?`, `#`, even empty), percent escapes, an IPv6 literal
without brackets or with a zone id, a port with a leading zero or out of range, and a path that is not a user group.
Golden cases: `fixtures/anyconnect-servers.json`.

Share files: `passtunnel_profile` is the oldest format version that reads the file (`ShareFile.version(for:)`). A
Cisco AnyConnect profile is written as version 2; OpenVPN and FortiGate profiles are still written as version 1,
unchanged, so older Macs and the phone apps keep importing them. A reader takes 1…`ShareFile.currentVersion` (2), so
1.1.4 and older (version 1 only) refuse an AnyConnect file ("made by a newer version") instead of importing it as
OpenVPN, which they would have done before #191. A version 1 file with type `anyconnect` (which no PassTunnel writes)
is read too. Import copies the new keys, normalizing the pin, then `save` checks them.

Connecting is in Core (#184, with the macOS 15.4 check), the CLI and MCP handle the type (#185), and so does the Mac
app (#186, see "Model"); `passtunneld` on Linux is #187 (done). The user docs (#189) are in the README and [APP.md](APP.md).

### Tests (#188)

The Mac path is tested with unit tests (`OpenConnectConfig` render and check, the sign-in output
parser, the hook's validation and its actions against a fake system, log fixtures from real runs
with example hosts and documentation addresses) and a manual connect against the ocserv image on a
developer machine (GitHub's macOS runners have no Docker; the procedure is in
[Tests/ocserv/README.md](../Tests/ocserv/README.md)). `OcservSignInTests` (only with
`PASSTUNNEL_TEST_OCSERV_SERVER`) sign in against that image (`plain` with an OTP file: a form for the
user name, one for the password, then a separate one for the code) through `ConnectionManager` with a
real openconnect and a fake helper: on every CI run in the job "Cisco AnyConnect against ocserv" with
Ubuntu's openconnect, and on a Mac with Homebrew's against Docker Desktop. The workflow
`ocserv-tunnel.yml` (`PASSTUNNEL_TEST_OCSERV=1`, not a required check) connects real tunnels through
passtunneld in containers, one per Linux DNS backend, sets and reverts routes and DNS, follows
openconnect's own reconnect, and kills openconnect to check the daemon's revert — an exception to
"tests never start a tunnel", marked as such.

## Palo Alto GlobalProtect backend

**Designed in #226. In place:** the configurations, the cookie and the checks of the sign-in's output in VPNConfig
(G1, #228); the profiles in PassTunnelKit (G2, #229), kept, checked, set and shared
([Profile (G2)](#profile-g2)); the helper's side, protocol 5 (G3, #230: the Mac's helper starts a GlobalProtect
session it is sent, `passtunneld` refuses one); connecting in Core (G4, #231: the sign-in, the start request, the
failures, the HIP notice; on macOS 15.4 and later, Linux refused until G7, [As built (G4)](#as-built-g4-231)). Phase 2
of #2: Palo Alto GlobalProtect
through the same
openconnect (`protocol gp`), with a password and a TOTP code, no SAML or other single sign-on, on macOS 15.4 and
later and on Linux, shipped labelled experimental ([Experimental](#experimental-g2-g5-g6-g9)). It reuses the
[Cisco AnyConnect backend](#cisco-anyconnect-backend) wherever that holds, and this
section says only where GlobalProtect differs. References like `auth-globalprotect.c 652–658` are to openconnect
9.21, the bundled version (the Homebrew tarball, SHA-256 `5b323694…0944a58`); 9.01 and 9.12 are cited where the
Linux distributions' versions differ. The implementation issues are at the end (G1–G9, to be numbered when they are
opened); the threat model is [SECURITY.md](../SECURITY.md#palo-alto-globalprotect), Linux
[LINUX.md](LINUX.md#palo-alto-globalprotect).

```
passtunnel / app (the user)                                     PassTunnelHelper / passtunneld (root)
  openconnect --authenticate --config=<file>   (protocol gp)
    portal  vpn.example.com:  prelogin, getconfig.esp ─ password, code
      └─ gateway gw1.example.com: prelogin, login.esp ─ (replayed, or password and a new code)
    stdout: COOKIE (authcookie=…&user=…), HOST, CONNECT_URL (the gateway), FINGERPRINT, RESOLVE
  HelperRequest.startOpenConnect (protocol 5: protocol gp) ─▶ <run>/openconnect.conf (0600)
                                                                openconnect --config=<run>/openconnect.conf
                                                                  getconfig.esp, HIP check (never a report),
                                                                  ESP or HTTPS tunnel; script: vpn-hook
```

### What is reused unchanged

The bundled tool and its pins (#179: the same `openconnect` closure; Homebrew's build lists `gp` among its protocols
and has ESP, so nothing is added to the bundle and nothing of `libexec/openconnect`, `hipreport.sh` included, is ever
taken); the macOS 15.4 gate (`Tool.minimumMacOS`); the split sign-in (the user's `--authenticate` run, root gets only
the cookie and the server's identity); the fixed environment and the neutralized Homebrew paths; `vpn-hook` and
everything it does (the script environment is built by protocol-independent code, `script.c`, from what
`gpst_parse_config_xml` installs: `ip-address`, `netmask`, `dns`/`dns-v6`, `dns-suffix` as `CISCO_DEF_DOMAIN`,
`access-routes`/`exclude-access-routes` and their `-v6` forms as split includes and excludes, `gpst.c` 431–539; a
GlobalProtect gateway sends no split-DNS list, so its suffixes are the default domains); supervision, the deadlines
(60 s set-up, 120 s reconnecting), the masked log copy, the status from the hook's record; `reconnect-timeout 60`;
trust (an optional full `pin-sha256:` pin, otherwise `no-system-trust` with the system's CA bundle) and "Trust this
server"; the user name in the file, never in argv; IPv6 blocked in a full tunnel without an IPv6 address.

### Signing in: portal, then gateway (G4)

openconnect's GlobalProtect sign-in (`gpst_obtain_cookie`, `auth-globalprotect.c` 807–845) decides by the URL's
path: `portal` signs in to a portal, `gateway` to a gateway, no path tries the portal first and, when the server
answers "GlobalProtect portal does not exist", the gateway (823–837; `-EEXIST`, `gpst.c` 333–336). A `:<field>` at
the end of the path (`portal:portal-userauthcookie`, `gateway:prelogin-cookie`) names a field that carries a SAML
cookie instead of the password (812–821); PassTunnel never renders one. Each login (`gpst_login`, 674–805):

1. **Prelogin:** `POST <server>/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac` (`ssl-vpn/…` for a
   gateway; `clientos=Linux` on Linux), with `cas-support=yes` in the body unless `no-external-auth` is given
   (699–700; 9.01 and 9.12 never send it). It carries no credentials and follows redirects (`HTTP_REDIRECT`). The
   `prelogin-response` gives the labels and the message (`username-label`, `password-label`,
   `authentication-message`, `region`) or a SAML request (below); `parse_prelogin_xml` (78–227) builds the form
   `_login`: `user` (text; hidden once a user name succeeded) and `passwd`. Without a token mode (PassTunnel never
   gives one, as in Phase 1) the secret field is always a password field, whatever its label (206–212,
   `can_gen_tokencode` is `-EINVAL`, `auth-common.c` 281–302).
2. **The form**, answered by `process_auth_form_cb` (`main.c` 2828–2947): `user` from the `user` option (the field's
   name starts with "user", 2888–2893), the first password field from the line `passwd-on-stdin` read at option
   parsing (2023–2025, 2904–2908), every later password field from the next line of standard input (2909–2911,
   `prompt_for_input` 2702–2725; `fgets` blocks while the pipe is open and nothing is there, `main.c` 784). The
   server's message is printed to standard error (2844–2845).
3. **Submit:** `POST …/global-protect/getconfig.esp` (portal) or `…/ssl-vpn/login.esp` (gateway) with the form, the
   client's description (`clientos`, `os-version`, `server`, `computer` = this machine's host name, library.c
   222–230) and `inputStr` when it answers a challenge (737–755). The answer is one of:
   - **a challenge** (the second factor): `var respStatus = "Challenge"; var respMsg = "…"; thisForm.inputStr.value
     = "…";`, or the same wrapped in `<html><body>` (9.10 and later), or `<challenge><inputstr>…</inputstr><respmsg>…
     </respmsg></challenge>` (`gpst.c` 133–209, 296–316). `challenge_cb` (232–275) turns the form into `_challenge`:
     `user` hidden, `passwd` labelled "Challenge: ", the server's `respMsg` as the message and `inputStr` kept for the
     next submission; it is a password field again (no token mode), so it gets the next line. Any number of
     challenges can follow one another.
   - **HTTP 512** (wrong user name or password): the same form again, empty (`http.c` 991–992; 769–777 here), so it reads
     the next line, and so on until standard input has none ("User input required in non-interactive mode").
   - **the portal's configuration** (`parse_portal_xml`, 432–666): its gateways (`policy/gateways/external/list`,
     each `<entry name="host[:port]"><description>label</description>`, with an optional per-region priority), the
     HIP interval, the portal's version (sent back as `app-version`), and its authentication-override cookies
     (`portal-userauthcookie`, `portal-prelogonuserauthcookie`). openconnect prints `N gateway servers available:`
     and one line per gateway (`  <label> (<host>) [priority P]` or `[unprioritized]`; 9.01 and 9.12 print
     `  <label> (<host>)` and do not sort), sorts them by priority (9.20 and later, 626), asks the gateway form
     (below) and goes to the chosen one: `https://<host[:port]>` through `handle_redirect` (652–658), which, for
     another host or port, closes the connection and drops the HTTP cookies (`http.c` 669–677).
   - **the gateway's login** (`<jnlp>`, `parse_login_xml`, 318–416): the session cookie (below). Done.
4. **Portal → gateway** (785–795): after the portal's configuration openconnect goes on as a gateway login. When the
   portal sent an authentication-override cookie, or its login was neither a challenge nor a SAML one, it first
   **replays the portal's last form unchanged** to the gateway's `login.esp`, with the cookie when there is one (the
   password, or the challenge's answer and its `inputStr`): no line is read. When that is refused (512), or when
   there was nothing to replay (the portal's login ended with a challenge and gave no cookie), it starts over at the
   gateway's prelogin (step 1): a **second sign-in**, which asks for the password (the user name now hidden) and,
   if the gateway has a second factor, a code.

So, by the portal's and the gateway's configuration, the server asks for: the password alone; password and code
(at the portal, with the gateway taking the portal's cookie or the replay; or at the gateway after the replay of the
password); or password, code, password, code (both ask, no override cookie). A server whose first form wants the
code alone (some RADIUS set-ups label it "Passcode") gets the profile's `combined` delivery with the template
`{otp}`.

**Choosing the gateway.** The gateway form is a select (`_portal`, field `gateway`, `authgroup_opt`). openconnect
pre-selects the portal's first entry (636–637), but the command-line tool still answers the form itself
(`main.c` 2849–2861): with the `authgroup` option it picks the entry whose **label** (the portal's description, as
the GlobalProtect app lists them) is that text, compared without regard to case, whole or as the only entry it
starts with (`match_choice_label`, 2664–2700); the entry's host is not compared. Without `authgroup`, or when the
text matches none, `prompt_opt_select` takes the only entry of a one-gateway list (2748–2750) and otherwise **reads
the choice from standard input** (2752): the next answer line (the code) would be taken as a gateway's label
(`Auth choice "<code>" not available`, then the prompt again). The design:

- The profile's `gateway` (empty, or a label; rendered as `authgroup`, the AnyConnect `authgroup` rule) names the
  gateway. With one gateway on the portal it may stay empty: the server's choice is used.
- A portal that lists more than one gateway needs it. Without it (or with a label the portal does not list) the
  sign-in fails as `invalidField("gateway")` (`ConnectionFailure` kind `configuration`) with the portal's labels
  (`ConnectionFailure.gateways`, read from the `N gateway servers available:` line and the N lines after it in
  openconnect's form; each label printable ASCII of at most 64 bytes, at most 32, else none and "see the log"), so
  the editor and the CLI can offer them. The portal's form was submitted by then: the code counts as sent.
- `skip_portal` signs in to the profile's host as a gateway (path `gateway`), without the portal: one login, the
  profile's own host as the tunnel's server, no gateway list. For users who know their gateway's address and for
  portals whose second sign-in is unwanted.

(#226 first said "the gateway is chosen by the server unless the profile names one". With the command-line tool
that holds for a one-gateway portal only; answering openconnect's prompt with the first label it prints would need a
reader of the run's partial output lines that writes the answer when the prompt appears, and the labels are the
server's text. So a portal with more than one gateway needs a named one: [Decided](#decided-226), 1.)

### The answers, and the second code (G4)

`GlobalProtectAnswers` (Core) are positional like `OpenConnectAnswers` (each line 1–4,095 bytes without LF, CR or NUL),
with one addition for the second sign-in:

- **First part**, written when the run starts: `.separate` → the password, then the code; `.combined` → the composed
  secret; no code → the password alone.
- **Second part**, only with a code and without `skip_portal`: the same answers again, **composed with the code of
  a later TOTP window**: `.separate` → the password and the new code, `.combined` → the secret composed with it.
  Standard input stays open (a pipe, not a file; openconnect waits in `fgets` meanwhile), and the second part is
  written once both hold: the run's standard error shows the second sign-in (a `POST https://…/ssl-vpn/prelogin.esp…`
  line after a `POST https://…/global-protect/getconfig.esp` line, openconnect's own request lines), and the first
  code's window has ended (so the two codes are of different time steps: a server that refuses a code it has seen,
  as most OTP servers do, accepts the second). Then standard input is closed. It is closed without the second part
  when the run shows that none can follow: a refused login (`Unexpected 512 result from server`, `http.c` 986–988)
  that answers the portal's `getconfig.esp` or a `login.esp` after a gateway prelogin (not the gateway's refusal of
  openconnect's replay, which leads to the second sign-in), or openconnect asking for the gateway (the portal's list of
  two or more gateways while the profile names none, or `Auth choice "<the profile's gateway>" not available`), before
  the second sign-in shows; and with `skip_portal` it is closed after the first part, as in Phase 1. A wrong
  password thus costs the account two refused attempts (the password, then the code in the retry form), as in
  Phase 1, not four. The second code is recorded in `.last-otp` when it is written, so the next connect waits for a
  window after it.
- The sign-in's time limit is 60 s plus the profile's TOTP period (90 s for 30-second codes), since a second
  sign-in may wait for the window; a third prompt within one login (a server chaining challenges) waits for that
  limit. `ToolRunning` gains this input (`ToolInput`: bytes now, more bytes when the caller's condition holds,
  closed after; `SecretBytes` overwritten once written), read from the run's standard error as it comes and
  cancelled like the run.

Positional answers keep Phase 1's limits: after a wrong password the retry form gets the code as a password (the
code is spent); a challenge that asks something other than the code gets the code. openconnect's own replay sends the
portal's answer (with a combined secret, its code) to the gateway a second time; a gateway that refuses a code it
saw answers 512, openconnect starts the second sign-in, and the second part answers it.

### Single sign-on is refused (G4)

A prelogin answer with `saml-auth-method` and `saml-request` is a SAML sign-in. openconnect's command-line tool has
no web view (`main.c` sets none), so it neither opens a browser nor sends anything: it prints `SAML <method>
authentication is required via <url>` and the error line `When SAML authentication is complete, specify destination
form field by appending field_name to login URL.` (`auth-globalprotect.c` 146–154; 9.01 and 9.12 write
`:field_name`) and the sign-in ends ("Failed to parse XML server response", "Failed to complete authentication").
That exact error line, wherever it stands, is `PTError.ssoRequired` (`ConnectionFailure` kind `sso_required`, new):
"This server signs in with single sign-on (SAML), which PassTunnel does not support." At the portal nothing was
submitted (only prelogin requests), so the code is given back; at a gateway after the portal (a gateway with SAML
behind a password portal) the portal's form was, and it counts as sent. Two exceptions in openconnect continue past
a SAML prelogin without a browser: an alternative secret field from the path (never rendered) and a portal
authentication-override cookie from this same run (102–105), which then signs in at the gateway with that cookie
and the form; that is no SSO prompt and is allowed. `no-external-auth` is rendered where the tool has it, as in
Phase 1 (on the Mac always; it also keeps `cas-support=yes` out of the prelogin).

### Output, cookie and destination (G1, G4)

`--authenticate` prints the same five lines for every protocol (`main.c` 2403–2424), here for the server openconnect
ended on: after the portal's hop **the gateway**. `CONNECT_URL` is `https://<gateway host>[:<port>]/` (no path:
`openconnect_get_connect_url` adds one only for Pulse, `library.c` 953–980), `HOST` and `RESOLVE` the gateway's
address, `FINGERPRINT` the gateway's key. `OpenConnectAuthResult.parse` takes them as in Phase 1; the cookie's shape
is GlobalProtect's:

- **`GlobalProtectCookie`** (VPNConfig). openconnect builds it from the gateway's `<jnlp>` arguments (`gp_login_args`,
  `auth-globalprotect.c` 293–315, saved ones URL-decoded at 359 and appended with `append_opt`, `auth-common.c`
  143–156): `authcookie=…&portal=…&user=…&domain=…&preferred-ip=…&preferred-ipv6=…&computer=…`, in that order, an
  argument left out when the server sent it empty, `(null)` or `-1`; `authcookie` and `user` are required (the login
  fails without them, `err_missing`), `computer` (this machine's host name, 394) is always last. Every name and value
  is URL-encoded by `buf_append_urlencoded` (`textbuf.c` 138–149): only `A–Z a–z 0–9 - _ . ~` and `%` with two
  lower-case hex digits. Accepted, and nothing else: exactly those keys in that order, each once, `authcookie` of at
  least 8 bytes, every value in that alphabet (`computer` may be empty), at most 4,096 bytes in all; no `'`, blank or
  `;` can be in it. The tunnel run takes it unchanged (`cookie`, `main.c` 2050–2052; only the AnyConnect, FortiGate,
  F5 and Juniper code splits cookies, `internal_split_cookies`), so `OpenConnectCookie`'s `webvpn=` naming does not
  apply: the helper is sent the cookie as printed and checks it with `GlobalProtectCookie.isValidTunnelOption`.
- **What is secret in it:** `authcookie` is the bearer secret; with `user` and `portal` it opens the session (getconfig,
  the tunnel's `GET /ssl-tunnel-connect.sslvpn?user=…&authcookie=…`, the HIP check and the logout all send it,
  `gpst.c` 665, 743, 880, `auth-globalprotect.c` 865). `user` (the account as the gateway names it) and `computer` are personal but no
  secrets, `portal`, `domain` and the preferred addresses none. The whole cookie and the `authcookie` value alone are
  literal secrets of the log masks (`MaskingCopier`, `LogRedactor`, as `OpenConnectCookie.secrets` for AnyConnect), and
  `OutputMask` masks `authcookie=` values and the `cookie` configuration line. The user name thus reaches root inside
  the cookie (the start request still has no user name field, and no password or code).
- **The portal's override cookies** are printed by openconnect itself in the sign-in run when the gateway's `<jnlp>`
  carries them (`GlobalProtect login returned portal-userauthcookie=<value>`, `…portal-prelogonuserauthcookie=…`,
  `show` at 310–311, printed at 382–385): they sign in to the portal's gateways without the password or code for as
  long as the administrator set. `LogRedactor`'s pass over the sign-in's standard error masks the value of those two
  lines to the end of the line, and of every `GlobalProtect login returned unexpected argument value arg[N]=…` line
  (an argument openconnect does not know, 365–369). They never leave the sign-in run.

**Where the sign-in may go.** The portal's hop to its gateway is a change of host that openconnect makes itself
(above), and in most GlobalProtect deployments with more than one gateway the gateways are other hosts than the
portal. Phase 1 refuses a sign-in that ended on another host (ASA load balancing); for GlobalProtect the rule is
(`OpenConnectAuthResult.checkDestination(host:port:skipPortal:profileServerCert:profileGatewayServerCert:)` of a
result parsed with `protocol: .gp`, which returns the gateway's host, port and `resolve` address; the run's
`POST https://…` lines are read by the sign-in, G4):

- `CONNECT_URL`'s host and port are the profile's (a gateway on the portal's host; `skip_portal`; a gateway reached
  by the no-portal fallback), or, without `skip_portal`, another host only as the portal's hop: the run's
  `POST https://…` lines (openconnect's own, `http.c` 893–899) name at most two servers, the profile's
  (`global-protect/…` requests) and `CONNECT_URL`'s (`ssl-vpn/…` requests, all after the portal's
  `getconfig.esp`); a third server, or a request to the other one before the portal's `getconfig.esp`, fails the
  connect (`signInUnusable`, fixed text), as Phase 1's check of a redirect after the fact.
- `RESOLVE` and `HOST` are checked against `CONNECT_URL`'s host as Phase 1 checks them against the profile's (a name
  resolved to `HOST`; an IP-literal gateway, which portals often list, compared as an address and no `resolve`).
- `FINGERPRINT` must be one of the profile's pins when it has any (below).
- What binds the gateway: its key passed the same trust as the portal's (a pin, or the system CA for the gateway's
  own name), and the portal (whose key the profile trusts) named it. The credentials reach it either way: openconnect
  replays the portal's form there. `ProfileDestination` binds the portal (below), never the gateway.

**Trust: two keys.** openconnect checks every TLS connection of the run, the gateway's too, against the `servercert`
options, and any `servercert` turns system trust off for the whole run (`main.c` 1968–1982, 2589–2616): a pinned portal
with a gateway of another key fails at the gateway, and the two cannot be mixed (pin for one, CA for the other). So
the profile has two optional pins, `server_cert` (the portal's, or the only server's) and `gateway_server_cert`
(the gateway's when its key is another), and the sign-in file has a `servercert` line for each one that is set (each
accepted for any host, which openconnect's option does: `host == NULL`), or `no-system-trust` and `cafile` when
neither is. The tunnel run gets `servercert` = the `FINGERPRINT` the sign-in accepted (the gateway's), as in Phase 1.
"Trust this server" (Phase 1) for the portal writes `server_cert`. A gateway's key that fails comes after the
portal's answer (the code is spent): the line `Certificate from VPN server "<host>" failed verification.` with its
`    --servercert pin-sha256:…` hint (2622–2626), or `None of the N fingerprint(s) specified via --servercert match
server's certificate: pin-sha256:…` (2611–2615), for the gateway host the run went to, becomes
`serverCertificateRejected` with a `ServerTrustOffer` for the gateway ("Trust This Gateway…", writing
`gateway_server_cert`). These lines follow text of the portal's, which the portal could imitate; the user confirms the
host and the full pin as in Phase 1, and only the portal, already trusted, could make them up. When the portal had no
pin, trusting the gateway's key turns system trust off for the portal too, so the offer also pins the portal's key,
read with `TLSFingerprint.fetchServerKeyPin` and shown for confirmation (Mac; on Linux both pins come from log hints).

### The configurations (G1)

The sign-in file (`OpenConnectAuthConfig` with `protocol: .gp`):

```
# Generated by PassTunnel. Do not edit.
protocol gp
server https://vpn.example.com/                (https://vpn.example.com/gateway with skip_portal)
user alice
authgroup US East                              (only when the profile names a gateway)
servercert pin-sha256:<44 characters>          (server_cert, when set)
servercert pin-sha256:<44 characters>          (gateway_server_cert, when set)
no-system-trust                                (only without either pin)
cafile /etc/ssl/cert.pem                       (only without either pin)
non-inter
passwd-on-stdin
no-external-auth                               (where the tool has it)
disable-ipv6                                   (Linux, openconnect before 9.20)
```

The root file (`OpenConnectConfig` with `protocol: .gp`):

```
# Generated by PassTunnel. Do not edit.
protocol gp
server https://gw1.example.com/                (the gateway: CONNECT_URL, rendered from the request's host and port)
cookie authcookie=<…>&portal=<…>&user=<…>&domain=<…>&computer=<…>
servercert pin-sha256:<44 characters>
resolve gw1.example.com:192.0.2.20             (only for a host name)
script <staged build directory>/Resources/bin/vpn-hook
non-inter
reconnect-timeout 60
no-dtls                                        (only with tls_only: no ESP)
disable-ipv6                                   (Linux, openconnect before 9.20)
```

Changes to Phase 1's checks (`checkRendered`, `OpenConnectOptions`), and nothing else:

- `protocol` is `anyconnect` or `gp`, and the rest of the file is checked by that protocol's rules.
- `server`'s path in the sign-in file is empty or `gateway` (no user group, no `:<field>`: a SAML cookie field); in
  the root file empty, as before.
- `servercert` may appear twice in a GlobalProtect sign-in file (still once in every other file); `authgroup` renders
  `gateway`.
- `cookie` in a GlobalProtect root file is `GlobalProtectCookie.isValidTunnelOption`'s shape, not `webvpn=`/STRAP.
- `disable-ipv6`, refused in Phase 1 as not needed, is rendered in both GlobalProtect files when the Linux openconnect
  is older than 9.20 ([LINUX.md](LINUX.md#palo-alto-globalprotect): 9.01–9.12 read a gateway's IPv6 split includes as
  excludes, `gpst.c` 532 in 9.12, fixed in 9.20 by openconnect commit 64f0c03d); it keeps IPv6 off the tunnel (no
  IPv6 address is taken, `gpst.c` 434–436, and `ipv6-support=no` is sent), so the hook blocks IPv6 in a full tunnel
  and leaves it alone in a split one. Refused everywhere else, and in AnyConnect files.
- Still refused, with GlobalProtect reasons added to the table: `csd-wrapper`, `csd-user`, `force-trojan` (the HIP
  script would run **as root, in the tunnel run**: openconnect runs it from `gpst_setup`, after the sign-in, and again
  every interval, `gpst.c` 1058–1109, 1295–1317), `usergroup` (the path decides portal or gateway and can name a SAML
  cookie field), `form-entry` (could fill `_portal:gateway` or any login field), `os` and `version-string`
  (`clientos`/`app-version`, by which gateways choose HIP and client policies), `local-hostname` (`computer`),
  `useragent` (openconnect sends `PAN GlobalProtect` itself, `auth-globalprotect.c` 34–45), and the rest as in Phase 1.

### HIP: never run, the user is told (G4)

openconnect never runs anything for HIP without `csd-wrapper`. In the tunnel run, after the configuration and after
every reconnect, it asks the gateway (`POST …/ssl-vpn/hipreportcheck.esp` with an MD5 of the cookie's stable parts,
`gpst.c` 843–911); when the answer is `<hip-report-needed>yes`, `run_hip_script` (913–937) prints once per run, as
ERR:

```
WARNING: Server asked us to submit HIP report with md5sum <32 hex digits>.
    VPN connectivity may be disabled or limited without HIP report submission.
    You need to provide a --csd-wrapper argument with the HIP report submission script.
```

and **goes on** (it returns 0); the check is repeated at the portal's interval (`hip-report-interval` − 60 s,
`auth-globalprotect.c` 499–511) or hourly (`GlobalProtect HIP check due`), without the warning again. A gateway that
enforces HIP lets the tunnel up and limits what it reaches (a quarantine policy) or ends the session. PassTunnel
reads those three lines, whole, in that wording, from the session log (`VPNLog.globalProtectHIPRequested`) and shows
a notice on the connected profile: "The gateway asked for a host information report, which PassTunnel does not
send. Access may be limited." (`ConnectionStatus.notices`: `hip_report_not_sent`; app, `status`, MCP `get_status`).
The log is partly the server's: the notice is display only and decides nothing, like the address shown. This
replaces Phase 1's line that HIP would be refused like CSD: a HIP request is no failure (owner decision, #226).

### The tunnel: ESP or HTTPS, reconnect, logout (G3, G4)

- **Configuration:** `POST …/ssl-vpn/getconfig.esp` with the cookie (`gpst_get_config`, `gpst.c` 642–717): the
  addresses, DNS, suffixes, routes, the MTU (usually 0: openconnect computes one and prints `No MTU received.
  Calculated <n> for …`, 687–711), the idle timeout, the tunnel's rekey interval (`timeout`), the session's lifetime,
  and the ESP keys and UDP port (`ipsec`, 540–566). openconnect's "DTLS" is ESP for this protocol (`udp_protocol`
  `ESP`, `library.c` 331): with ESP on, it probes the gateway's address over UDP and uses ESP once the probe is
  answered (`ESP session established with server`, `esp.c` 255–256; `ESP tunnel connected; exiting HTTPS mainloop.`),
  and after 5 s without it falls back to the HTTPS tunnel (`Failed to connect ESP tunnel; using HTTPS instead.`,
  `gpst.c` 1143–1160); without keys `Did not receive ESP keys and matching gateway in GlobalProtect config; tunnel will
  be TLS only.` (624–627). Starting the HTTPS tunnel voids the ESP keys (726–731, 792–795). `tls_only` renders
  `no-dtls`: no ESP, the HTTPS tunnel at once (the switch for networks where UDP to the gateway is blocked or
  broken). ESP goes to the same address as the TLS connection (`VPNGATEWAY`), so the hook's host route for the server
  covers it; its keys travel in the TLS-protected configuration and are never logged at the default level.
- **Reconnect:** DPD every 10 s (589–593); a dead peer, a failed read or write, or the rekey interval (`GlobalProtect
  rekey due`, 1319–1337, at `timeout` − 60 s) makes openconnect reconnect with the same cookie: a new getconfig (with
  the addresses it had as `preferred-ip`), the HIP check, the tunnel. That runs the hook's `attempt-reconnect` and
  `reconnect` (Phase 1's check: the same settings pass, other ones stop the session), so a GlobalProtect session sees
  them at every rekey too, not only after a drop. The budget is `reconnect-timeout 60` and the supervisor's 120 s, as
  in Phase 1; after them `ConnectionManager` signs in afresh (portal and gateway, new codes). The gateway refuses the
  cookie with "Invalid authentication cookie", "Portal name not found", "Valid client certificate is required" or
  "Allow Automatic Restoration of SSL VPN is disabled" (`gpst.c` 337–343), HTTP 502 on the tunnel request (776–777) or
  "errors getting SSL/VPN config" (682–683): openconnect exits with "Cookie was rejected by server; exiting." (status
  2), a drop, and the next connect signs in again. The cookie's lifetime is the gateway's (`lifetime`, 441–442;
  `Session authentication will expire at …`, `main.c` 1668–1675).
- **Stop:** SIGTERM makes openconnect log out (`gpst_bye`, `auth-globalprotect.c` 847–895, from `mainloop.c` 412–413):
  `POST …/ssl-vpn/logout.esp` with the cookie, then `Logout successful.` or `Logout failed.`. Unlike AnyConnect's BYE,
  the logout has an answer: after "Logout successful." the gateway has ended the session and the cookie is void.
  After a kill, a crash, a broken connection or "Logout failed." it stays valid until its lifetime.
- **Log** (display only, as Phase 1's): besides the lines above, `POST https://<gateway>/ssl-vpn/getconfig.esp`,
  `Configured as <addresses>, with SSL connected and ESP in progress` (`main.c` 1659–1667; `… and ESP disabled` with
  `tls_only`), `GlobalProtect IPv6 support is experimental. …` (ERR, whenever an IPv6 address is assigned,
  `gpst.c` 596–599), `GPST Dead Peer Detection detected dead peer!`, `Reconnect failed`. The state comes from the hook's
  record, never from these.

### Failures (G4)

`VPNLog.globalProtectSignInError` reads the sign-in's whole redacted standard error as Phase 1's does (whole LF lines
of printable ASCII in openconnect's 9.21 wording, `openConnectLines`), in this order:

1. dyld stopped openconnect: `toolUnsupported`.
2. the SAML line: `ssoRequired` (counted as sent or not by the next rule).
3. **Credentials sent** (`VPNLog.globalProtectCredentialsSent`): any `POST https://…` that is not a prelogin
   (`…/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=<Mac|Linux>`, `…/ssl-vpn/prelogin.esp?…`, the only
   requests without credentials; a portal and a gateway prelogin of the no-portal fallback are two requests and still
   none sent). A redirected prelogin is printed with the redirect's path and so counts as sent, as Phase 1's count
   does; a run stopped at its deadline or past what is kept counts as sent. Once sent: the gateway list
   (`invalidField("gateway")` with the labels), a gateway's certificate (`serverCertificateRejected` for the gateway,
   above); anything else `authFailed`, never retried.
4. Before any form was sent: the lines before the first TLS session as Phase 1 (certificate, name, no answer); "Server
   is neither a GlobalProtect portal nor a gateway." (`auth-globalprotect.c` 835: `invalidField("host")`, "This server
   is not a GlobalProtect portal or gateway"); "User input required in non-interactive mode" (`signInNeedsMoreAnswers`);
   else `connectFailed`.

CSD's `hostScanRequired` lines do not exist in this protocol (`auth.c` is AnyConnect's) and are not read for it.

### As built (G4, #231)

- **`GlobalProtectSignIn`** (Core) runs as `AnyConnectSignIn` does (program, argv, the 0600 file in its own directory,
  the fixed environment, the redacted log cut to 64 KiB) with `OpenConnectAuthConfig(protocol: .gp, …)`, and is called
  by `ConnectionManager` for `.globalprotect`. `GlobalProtectAnswers.lines` composes each part (`OTPComposer.compose`
  with the type); `secondPartNotBefore` is the end of the first code's TOTP window.
- **`ToolInput`** (Core, `ToolRunner.swift`): `first` bytes, copied into a buffer of the input's own that is
  overwritten once the runner has taken its copy (`wipeFirst`; `SystemToolRunner` and the runners that write `first`
  only do it); an optional `second` closure that, when the part is to be written, appends it straight to the runner's
  own buffer (emptied and overwritten first, and overwritten after the run) and overwrites what it made it in, so no
  other copy is handed around; and `decide`, called by the runner with standard error so far after `first` is
  written, whenever standard error grows and at least every quarter second: `.wait`, `.write` (then closed) or
  `.close`. `ToolRunning` gains `run(…, input: ToolInput, …)`; a runner that does not implement it writes `first`
  only. `SystemToolRunner` keeps standard input open while a second part may follow; its `Data` input goes through
  a `ToolInput` of its own copy the same way. Tests drive the decision with a fake runner and `FakeClock`, never
  real waiting.
- **When the second part is written** (`VPNLog.globalProtectSecondPart`, then `GlobalProtectSignIn.input`): the run
  so far must keep the two-server rule (before the portal's `getconfig.esp` only the profile's server; after it the
  first `ssl-vpn/…` request names the gateway, and every later request is an `ssl-vpn/…` one to it; anything else,
  a request that does not read as one included, closes standard input at once, so a prelogin redirected elsewhere
  never gets the answers); `.due` needs the latest request to be that gateway's prelogin and openconnect's prompt
  after it (an unfinished last line); and then standard error must have stayed unchanged for
  `GlobalProtectSignIn.promptQuietTime` (1 s) and the first code's window must have ended. The wait at the prompt is
  what keeps a server's text (a form's message, which openconnect prints among its own lines) from triggering it:
  such text is followed at once by openconnect's own next request, which decides. What remains: a portal that both
  prints such text and then stops openconnect at a prompt of its own (a third prompt) gets the second part itself;
  it is the portal the profile trusts, and nothing else can.
- **The second part** is made only with a code from the profile's TOTP secret and without `skip_portal` (a typed code
  has no later window); only then is the time limit `signInTimeout` plus the TOTP period. Its code is recorded in
  `.last-otp` from the runner's thread just before it is handed to the runner (`SecondPart.record`,
  `ConnectionManager.writeUsedCode`), so another process (the CLI, the MCP server) that connects the profile while
  the run lasts, or after a crash, waits for a later window.
- **The two-server rule** (`VPNLog.globalProtectRouteIsAllowed`) reads every `POST https://` of the whole standard
  error as it came; standard error past what is kept fails it (`signInUnusable`, fixed text), as a request that does
  not read as one does.
- **Failures** (`VPNLog.globalProtectSignInError`): as listed, with these as-built forms. A gateway's key is the new
  `PTError.gatewayCertificateRejected(gateway:reason:pin:log:)` ("The gateway’s certificate was not trusted (…)."),
  not `serverCertificateRejected`, whose message says the sign-in was not sent; it maps to kind `configuration` with
  `server_cert` and `credentials_sent`. Openconnect asking for the gateway also counts when the profile's gateway
  `matches multiple options` (main.c 2690–2694), the same situation as `not available`. `invalidField("host")` for a
  server that is neither portal nor gateway carries `ConnectionFailure.reason` "This server is not a GlobalProtect
  portal or gateway". `PTError.ssoRequired(log:)`, kind `sso_required`. The labels are
  `VPNLog.globalProtectGateways(_:)` (`count`, `labels`), read from the redacted log.
- **"Trust This Gateway…"** (Core): `ServerTrustOffer` gains `type`, `skipPortal`, `gateway` (the gateway's
  `host:port` as the redacted log named it; nil for the portal's or the only server's key) and `portalPin`;
  `needsPortalPin` when the profile pins no portal key. `ConnectionManager.trustServer(_:portalPin:)` writes
  `gateway_server_cert`, and then `server_cert` from `portalPin` (`ServerTrustOffer.PortalPinRequired` without it);
  the front end reads the portal's key with `TLSFingerprint.fetchServerKeyPin` and shows it for confirmation (G6).
- **The HIP notice** is `StatusNotice.hipReportNotSent` (`hip_report_not_sent`, `message`), from
  `VPNLog.globalProtectHIPRequested`; `ConnectionManager.notices(_:)` gives a connected profile's notices. G5 puts them
  in `--json` and MCP (`notices`), G6 in the app.
- **The override-cookie masks** are `OutputMask` patterns, so the helper's `MaskingCopier` applies them to the tunnel
  run's log too.
- **Front ends until G5/G6:** the CLI's `add` does not take the type yet (G5); the app connects such a profile but its
  type lists and editor leave the type out (`AppModel.editableTypes`; the editor is refused with "needs a newer
  PassTunnel") until G6 adds the type's fields.
- The Mac helper's refusal while the last session's network is still being restored names the request's type
  (`HelperCore.stillRestoringMessage`).

### Helper protocol 5 (G3)

`PT.helperProtocolVersion` becomes 5, and `passtunneld`'s `hello` too. The start request gains `protocol`
(`anyconnect` or `gp`, required) and `profile_gateway_server_cert`, and `host`/`port` now mean the server the tunnel
connects to: for AnyConnect the profile's (as before), for GlobalProtect the gateway the sign-in ended on (from
`CONNECT_URL`). A protocol-4 helper (1.6.0 released it) decodes with `Codable`, which ignores keys it does not know,
so without the bump it would take a GlobalProtect start for an AnyConnect one; with it, an older helper or daemon fails
the version check and is replaced (Mac) or refuses (Linux, until its package is updated).

```swift
case startOpenConnect(OpenConnectStart)   // + protocol (.anyconnect | .gp), + profileGatewayServerCert
```

JSON keys: Phase 1's and `protocol`, `profile_gateway_server_cert` (empty for AnyConnect). `prepareOpenConnect` per
protocol, in Phase 1's order: (1) the macOS 15.4 check, with the protocol's name ("Palo Alto GlobalProtect requires
macOS 15.4 or later."); (2) the fields: for `gp` `usergroup` must be empty, the cookie `GlobalProtectCookie`'s shape,
`connectURL` exactly `https://<host>[:<port>]/` for the request's host and port, `resolve` as before, and `serverCert`
equal to `profileServerCert` or `profileGatewayServerCert` when either is set; (3)–(6) as before, the text checked
against the line count the request implies (header and seven options, `resolve`, `no-dtls`, and on Linux
`disable-ipv6`, which the daemon decides from its own openconnect's version, never from the request). The masks the
helper's `MaskingCopier` gets are the protocol's cookie secrets. The description and mirror hide the cookie,
`connect_url`, `resolve` and `server_cert` as before, and for `gp` `host` and `port` too: the portal chose the
gateway and could make a valid host name repeat the cookie (as `OpenConnectConfig`'s description hides them, #228).
No helper or daemon log line or error names the gateway's host, and the masker's literal secrets match regardless
of case, so a gateway name that repeats the `authcookie` lowercased is masked in openconnect's output too.

As built (#230): `protocol` is required in the JSON and in `OpenConnectStart.init` alike (a missing or unknown value
is `invalidField("protocol")`); for `anyconnect`, `profile_gateway_server_cert` must be empty and the cookie
`OpenConnectCookie`'s shape, so a GlobalProtect start labelled `anyconnect` fails too. Step (5) also checks that the
rendered file's `protocol` line is the request's, since `checkRendered` applies the rules of the file's own line.
`disable-ipv6` comes from `HelperCore.openConnectDisableIPv6` (false until #234 sets it from the checked tool's
version; never rendered for AnyConnect). `OutputMask` masks `authcookie=` values wherever they stand (also inside
`…userauthcookie=`). `passtunneld` refuses `gp` ("Palo Alto GlobalProtect is not supported by passtunneld yet.")
after the access check and before anything is checked, resolved or written.

### Profile (G2)

`VPNType.globalprotect` (`--type globalprotect`, "Palo Alto GlobalProtect"), in `PassTunnelKit`, rules from
`OpenConnectAuthConfig` (VPNConfig) like AnyConnect's:

| Key | Rule |
|---|---|
| `host`, `port` | as AnyConnect: the portal (or, with `skip_portal`, the gateway) |
| `gateway` | empty or a gateway's label as the portal lists it: AnyConnect's `authgroup` rule (1–255 bytes, no control characters or line separators, no leading or trailing whitespace, no leading `=`); rendered as `authgroup` |
| `skip_portal` | boolean, default false: sign in to `host` as a gateway (path `gateway`) |
| `server_cert` | as AnyConnect: the portal's key (or the only server's) |
| `gateway_server_cert` | empty or a full pin, normalized as `server_cert`; the gateway's key when it is not the portal's |
| `tls_only` | boolean, default false: `no-dtls` (no ESP) |
| `set_dns`, `set_routes`, `username`, `password_mode`, TOTP, `otp_delivery`, `otp_template` | as AnyConnect (`otp_delivery` defaults to `.separate`; a `.combined` template at most 4,095 bytes without LF, CR or NUL) |

A new key `gateway` rather than AnyConnect's `authgroup`: the value is matched against another list (the portal's
gateway labels, not the server's group list), the editor and CLI name it so, and no key changes its meaning between
types ("Keys of a newer version"). `usergroup` and `authgroup` are AnyConnect's alone (`wrong_profile_type` on this
type); `gateway`, `skip_portal` and `gateway_server_cert` are this type's alone; `server_cert`, `tls_only` are
written for both types. As for AnyConnect they are read for any type and written only for theirs, so OpenVPN,
FortiGate and AnyConnect files stay exactly as before. `ProfileDestination.of`: after `passtunnel-destination-1` and
the type, the host, port, `skip_portal`, `server_cert` and `gateway_server_cert` (normalized); `gateway`, `tls_only`,
`set_dns` and `set_routes` are not part of it (the gateway is the portal's to offer, as AnyConnect's group is the
server's). Addresses: `GlobalProtectServer.parse` takes `[https://]host[:port]`, as `AnyConnectServer.parse` but
without a path (a GlobalProtect address has none; `/global-protect…` or `/ssl-vpn…` pasted from a browser is refused
with that reason). Golden cases `fixtures/globalprotect-servers.json`.

**Share files:** version 2, as AnyConnect (`ShareFile.version(for: .globalprotect)`; `currentVersion` stays 2). Every
reader of version 2 keeps and refuses a profile of a type it does not know (#191 came first), so 1.6.0 lists such an
import as needing a newer PassTunnel, and version-1-only readers refuse the file. A new version is needed only for a
change an older reader of version 2 would misread, which this is not. An older version, or a port, that does not know
the type keeps the whole profile object unchanged (`UnsupportedProfile`); one that knows it keeps the keys a newer
version adds to it (#200). The golden cases ([MOBILE.md](MOBILE.md#shared-logic)): `share-files.json` (decode, encode
as version 2, this type's keys dropped on another type and AnyConnect's on this one), `profile-json.json` (a save
keeps them for this type only, a type change drops them), `profile-fields.json` (`gateway`, `skip_portal`,
`gateway_server_cert`; `wrong_profile_type` elsewhere), `codes.json` (`compose` for this type: separate by default, as
AnyConnect) and `globalprotect-servers.json`.

macOS below 15.4: the type is shown and refused exactly as AnyConnect is (#2's owner decision of 2026-10-28, the
same closure), with "Requires macOS 15.4 or later" (`PTError.globalProtectRequiresMacOS`: "Palo Alto GlobalProtect
requires macOS 15.4 or later.", `config_invalid`, failure kind `tool_unsupported`). Linux:
[LINUX.md](LINUX.md#palo-alto-globalprotect).

**Until the type connects (G4).** G2 ships the type before anything connects it, as #181 did for Cisco AnyConnect:
`VPNType.connectable` (Core) is every type but `globalprotect`, and `ConnectionManager.connectRefusal(.globalprotect)`
is, after the macOS check, `PTError.unsupportedProfileType("globalprotect")` on every system ("needs a newer
PassTunnel", note "Needs a newer PassTunnel"). So a GlobalProtect profile that arrives in a share file, or is written
by a newer version, is listed with that `connect_refusal`, shown, set, shared and deleted, and `connect`, the MCP
`connect`, the app's Connect and editor refuse it before anything is asked, read or sent; `passtunnel add` and the
app's type lists (the editor's type picker, Add VPN's type question) do not offer the type. `diagnose` reports the
refusal and the profile's field problems. G4 adds the type to `VPNType.connectable`; G5 and G6 then offer it.

As built (G4, #231): `VPNType.connectable` is every type, and `connectRefusal(.globalprotect)` is the macOS 15.4 check
on the Mac and, on Linux (`macOS` nil), still `unsupportedProfileType("globalprotect")` until G7 (#234) makes
`passtunneld` run it and the sign-in check the distribution's openconnect for 9.11: refusing up front spends no code on
a sign-in whose cookie the daemon would refuse. The app's type lists and editor keep leaving the type out until G6
(`AppModel.editableTypes`), and `passtunnel add` until G5; `connect`, the MCP `connect` and the app's Connect connect it.

### Tests (G8)

No open-source server speaks GlobalProtect's tunnel, so no test runs a real GlobalProtect tunnel; that is why the
type ships [experimental](#experimental-g2-g5-g6-g9). The sign-in is tested on every CI run against openconnect's own
test portal and gateway, `tests/fake-gp-server.py` (owner decision, #226):

- **Where it comes from:** the openconnect release tarball
  `https://www.infradead.org/openconnect/download/openconnect-<version>.tar.gz`, at the version `release.env` pins as
  `OPENCONNECT_VERSION` (9.21) and checked against a SHA-256 kept next to the test
  (`Tests/globalprotect/fake-gp-server.sha256`; 9.21: `5b32369467db6e5f317aa1ed12cfcbb81ed00bdbc765450b6bfcbdc300944a58`,
  the value Homebrew's formula pins too). The CI job downloads it, checks the hash, extracts that one file and runs
  it unchanged; a version bump updates the hash in the same pull request.
- **Its license:** LGPL-2.1 or later (the file's header), like openconnect. It is test code that is only run: never
  copied into this repository, never modified, never part of the app, the Linux tarball, the Docker image or any
  release, so it adds nothing to `THIRD_PARTY_NOTICES.md`. It needs Python 3 and Flask, from the test container's
  distribution packages (the image pinned by digest, as the ocserv image is).
- **What it offers** (its `/CONFIGURE` endpoint): one or more gateways (all on its own host and port), a challenge at
  the portal, the gateway or both in each of the three encodings (and it clears `inputStr`, so a blind replay of a
  challenge fails as a real gateway's would), the two override cookies, SAML at either, the HIP check. It accepts any
  password and code, so a code's reuse and a gateway on another host are covered by unit tests with a fake runner
  instead.

Cases, through `ConnectionManager` with the distribution's (Linux) or Homebrew's (Mac, by hand) openconnect and a fake
helper: password only; code at the portal with and without an override cookie; code at the gateway after the replay;
both, with the second part written after the first code's window; a portal with two gateways, with and without
`gateway`, and with an unknown one; `skip_portal`; SAML at the portal (code given back) and at the gateway (spent);
pins; the masking of the override cookies; the cookie's checks and the helper's refusal of every wrong field. The hook
needs no new code; `Tests/Fixtures/openconnect-env.json` gains environments as `gpst.c` builds them (many DNS
suffixes, IPv6 includes, `0.0.0.0/0` includes).

### Experimental (G2, G5, G6, G9)

GlobalProtect ships marked **experimental** until reports from real gateways come in (owner decision, #226): only
openconnect's test server and unit tests stand behind the tunnel path. It is a label and nothing else: no feature
flag, no opt-in, no setting; the type connects exactly as designed above.

- **One source of truth:** `VPNType.isExperimental` in `PassTunnelKit` (`Model.swift`), `self == .globalprotect`.
  Every place below reads it; dropping the label later is that one line (and the docs' sentences). Nothing stores it:
  no profile key, no share-file field, no `config.json` value.
- **Mac app** (G6): an "Experimental" badge (a small capsule beside the type's name, localized) in Add VPN's type
  question and the File menu item's title, the editor's type header, the profile list row's type line and the detail
  view's header. The detail view and the failure card add a link "Report how it works…" to the issue template below.
  The menu bar shows no badge (it lists profiles by name only).
- **CLI, human output** (G5): `(experimental)` after the type's name in `list`, `show`, `status` and `diagnose`, and one
  line after `add --type globalprotect` and `import` of such a profile: "Palo Alto GlobalProtect support is
  experimental. Please report how it works: <the template's URL>" (to standard error, so scripts reading standard
  output are unaffected).
- **`--json` and MCP** (G5): `"experimental": true` on every profile object of an experimental type
  (`ProfileSummary`/`ProfileStatus`: `list`, `status`, `show`, MCP `list_profiles` and `get_status`), left out for the
  other types, so their output stays byte for byte as it is; CLI-JSON.md documents the key (additive, as its stability
  rules allow) and that it may disappear when the type stops being experimental.
- **Docs and website** (G9): README's and APP.md's type lists and the website's feature list say "Palo Alto
  GlobalProtect (experimental)" with one sentence asking for reports through the template. The release that first
  makes the type usable says so in its notes: the notes are the commit subjects (RELEASING.md), so that pull request's
  title ends in "(experimental)" (G4: `feat: connect Palo Alto GlobalProtect profiles (experimental)`), and so do
  the other `feat` titles of this phase that can land in a release before it.
- **Issue template** (G9): `.github/ISSUE_TEMPLATE/globalprotect_report.md` ("GlobalProtect report", label
  `globalprotect`): worked or not; macOS or Linux and the openconnect version; portal and gateways (one host or
  several, how many gateways); where the code is asked (portal, gateway, both) and whether an override cookie is used;
  ESP or TLS only; HIP asked or not; and the profile's log with a reminder to replace host names, user names and
  addresses (example hosts as in this repository) and that PassTunnel already masks cookies and codes. It links
  SECURITY.md for anything security-related.
- **Phones:** a port that shows the type names it with the same label, from the Kit's constant (iPhone) or its Kotlin
  counterpart ([MOBILE.md](MOBILE.md#globalprotect-profiles)).

### Decided (#226)

Owner decisions on what this design adds to, or changes in, #226's first list:

1. **Gateway choice:** a portal with more than one gateway needs the profile's `gateway`; without it the sign-in fails
   and lists the portal's gateways. The server chooses only on a one-gateway portal.
2. **Gateway on another host:** allowed within the two-server rule (the portal, then the gateway it names), the
   gateway's key under the same trust as the portal's. No list of allowed gateway hosts.
3. **A second pin,** `gateway_server_cert`, since openconnect cannot pin one server and trust the CA for the other.
4. **The second code** waits for the next TOTP window; the sign-in's time limit is 60 s plus the TOTP period.
5. **Linux minimum 9.11** for this type (Debian 12 and EPEL 9 keep Cisco AnyConnect only), `disable-ipv6` before 9.20.
6. **Helper protocol 5.**
7. **The sign-in tests** run openconnect's `tests/fake-gp-server.py` unchanged, in CI only, never shipped, fetched from
   the pinned openconnect release and checked by its SHA-256 ([Tests](#tests-g8)).
8. **Experimental:** the type ships labelled experimental until real gateways have been reported working; a label
   only, from one constant ([Experimental](#experimental-g2-g5-g6-g9)).

### Implementation issues

In dependency order, mirroring Phase 1's #179–#189; nothing replaces #179 (the bundle already has `gp` and ESP) or
#183 (the hook is reused unchanged):

- **G1** `feat: render and check GlobalProtect configurations` (VPNConfig): `protocol gp` in `OpenConnectAuthConfig`
  and `OpenConnectConfig` (path, `gateway`, two pins, `disable-ipv6`), `GlobalProtectCookie` (parse, check, secrets),
  `OpenConnectAuthResult` for gp (output, `checkDestination` with the gateway host, `tunnelConfig`), the options
  table's changes and reasons; golden and fuzz tests.
- **G2** `feat: GlobalProtect profiles in PassTunnelKit`: `VPNType.globalprotect`, the keys and their rules,
  `ProfileFields`, `ProfileStore` checks, `ProfileDestination`, share files (version 2), `GlobalProtectServer.parse`,
  the fixtures, the macOS 15.4 availability, `VPNType.isExperimental` (the one source of the experimental label).
  Needs G1 (the rules live in VPNConfig).
- **G3** `feat: start GlobalProtect sessions in the helper (protocol 5)`: `OpenConnectStart.protocol` and
  `profileGatewayServerCert`, `prepareOpenConnect` per protocol, the 15.4 message, the cookie masks in
  `MaskingCopier`/`OutputMask`; `passtunneld` reports 5 and refuses `gp` until G7. Needs G1.
- **G4** `feat: connect Palo Alto GlobalProtect profiles (experimental)` (the title the release notes show): the
  sign-in (`GlobalProtectSignIn`), `ToolInput` with the second part and `.last-otp`, the credentials-sent rule, the
  POST-host rule, the failures (`sso_required`, the gateway list, a gateway's key, not a GlobalProtect server), the
  override-cookie masks, the start request, the HIP notice, the time limits. Needs G1–G3.
- **G5** `feat: GlobalProtect in the CLI and MCP`: `add --type globalprotect [--server]`, `set`/`show`, the failure
  kinds and the notice in `--json` and MCP, the experimental label (`(experimental)` and the report line in human
  output, `"experimental": true` in `--json` and MCP), CLI-JSON.md. Needs G4.
- **G6** `feat: GlobalProtect in the Mac app`: the type in Add VPN and the File menu, the editor (Gateway with the
  portal's list after a failure, Skip portal, the two pins, "Trust This Gateway…"), the HIP notice, the
  "Experimental" badge and the "Report how it works…" link. Needs G4.
- **G7** `feat(linux): GlobalProtect in passtunneld`: the daemon accepts `gp`, the per-type minimum 9.11 (daemon and
  sign-in), `disable-ipv6` before 9.20, its tests. Needs G3, G4.
- **G8** `test: GlobalProtect sign-in against openconnect's test server`: the container (Python and Flask from the
  distribution, image pinned by digest), fetching `fake-gp-server.py` from the pinned tarball with its SHA-256, the CI
  job, the cases above; the manual check against a real gateway. Needs G4, G7.
- **G9** `docs: Palo Alto GlobalProtect support (experimental)`: README, APP.md, the website's feature list, each
  marked experimental with the request for reports, and the issue template `globalprotect_report.md`. Last.

## Rules for all code

- English identifiers, English comments (sparse). User-facing strings via `String(localized:)` with
  Turkish translations in `Localizable.xcstrings`.
- No company/customer names, no real hostnames — examples use `Acme`, `vpn.example.com`.
- Tests never touch the real Keychain service or real support dir: they set `PASSTUNNEL_HOME` and
  `PASSTUNNEL_KEYCHAIN_SERVICE`. `MCPServerTests` drive `MCPServer` through its `send` closure with
  `FakeHelper`, `FakeAuthenticator` and a fixed `HelperInspecting`. Management-socket tests run their own fake server on a socket in a
  temp dir. The Linux secret stores' tests use `FakeTools` for `secret-tool` and `systemd-creds` and a
  temp dir for the file store (LINUX.md, Rules, for the one opt-in CI round trip with a real
  keyring). Tests never use the Secure Enclave or show a prompt: `ConnectionManagerTests` and
  `SecretVaultTests` inject `FakeAuthenticator` (a software P-256 key). No test asks a gateway or a time
  server for the clock: managers get `FakeServerClock` (`ConnectionManager.serverClock`); `ServerClockTests`
  run their own SNTP server (UDP) and, on the Mac, TLS server on 127.0.0.1.
- Swift language mode 5 (tools 5.10), macOS 13 APIs, no third-party dependencies except Sparkle (updates)
  and swift-crypto (CryptoKit's API for PassTunnelKit, and scrypt from its CryptoExtras for the Linux
  file store; used on Linux only), each pinned to an exact version in `Package.swift`.
