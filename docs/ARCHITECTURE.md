# PassTunnel architecture

PassTunnel is a macOS app (13+) that connects VPNs **without ever typing a one-time code**: it keeps
TOTP secrets in the Keychain and fills the code (and password) automatically when it connects.
Supported VPN types: OpenVPN, FortiGate SSL VPN (openfortivpn). More types = new backend.

```
PassTunnel.app/Contents/
  MacOS/PassTunnel              app + CLI (same binary; `passtunnel` symlink → CLI mode)
  MacOS/PassTunnelHelper        privileged helper (root, launched by launchd via SMAppService)
  Library/LaunchDaemons/com.furkanprlk.passtunnel.helper.plist
  Resources/bin/openvpn, openfortivpn    bundled, signed with the app's Team ID
  Frameworks/*.dylib            their dependencies (OpenSSL, LZO, LZ4, pkcs11-helper)
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
compiling: it writes the cdhash of every architecture of `openvpn`, `openfortivpn` and `dns-updown`
(`generatedCDHashes`) and of every `Contents/Frameworks/*.dylib` (`generatedLibraryCDHashes`)
(`codesign -dvvv`, `CDHash=`) to `Sources/PassTunnelShared/PinnedTools+Generated.swift` (removed on exit,
never committed) and builds with `-Xswiftc -DPASSTUNNEL_TOOL_PINS`, so the helper carries them in its own
signed code (`PinnedTools`, below). The tools are not signed again afterwards (that would change the
cdhashes); the script checks that each bundled tool's and dylib's cdhashes are in the pins and in the
`PassTunnelHelper` binary, and a signed (non-ad-hoc) build fails when `openvpn`, `openfortivpn` or any
bundled dylib has no pin (or there is no dylib at all).
A bundle without `dns-updown` pins an empty set for it, so the helper refuses any `dns-updown`.

## Targets

| Target | Owns | Depends on |
|---|---|---|
| `PassTunnelVPNConfig` | `OVPNSanitizer`, `FortiConfig`: the configurations the helper runs as root | — |
| `PassTunnelKit` | the portable logic (Foundation, CryptoKit and Security only; builds for macOS 13, iOS 17 and Linux): model, `PTError`, `JSONCoding`, `TOTP`, `OTPAuthURI`, `OTPComposer`, `OVPNAnalyzer`, `OVPNInliner`, `ShareFile`, `Slug`, `ProfileFields`, `ProfileMerge`, `SecretEnvelope`, `HealthCheck` (parsing) | VPNConfig (and swift-crypto on Linux) |
| `PassTunnelShared` | XPC protocol, request/response types, `HelperCore` (request decoding, path checks, tool environment), `SessionPolicy`, `CodeSignature`, `Spawner` (verified, suspended launch), `PinnedTools`, `ToolStager` (root-owned copy of the tools and their dylibs), `HelperBuild`, identifiers | VPNConfig (and swift-crypto on Linux) |
| `PassTunnelCore` | `ProfileStore`, `ProfilesWatcher`, `Secrets` + `SecretStore` (Keychain; on Linux `SecretStores`: secret-service, systemd-creds, file), `SecretVault` + `UserAuthenticator` (Secure Enclave protection), `Preferences`, `HealthCheck.check` (the probe), `QRDecoder`, `OpenedFiles` (files the app is asked to open), `TLSFingerprint`, `HelperClient`, `HelperAutoUpdate`, `ConnectionManager` + `ProfileDestination`, `LoginConnector` (connect at login), CLI parsing (`CLICommand`, `CLIInvocation`), automation objects + `AutomationService`, `MCPServer` + `MCPTools` + `JSONValue` | Kit, VPNConfig, Shared (and swift-crypto's Crypto and CryptoExtras on Linux) |
| `PassTunnelCLI` | the `passtunnel` command: `PassTunnelCLI.run` (entry, `CLIHelp`), `CLIRunner`, `CLICompletions`, `CLITerminal`, `CLIClipboard`; `Pasteboard` (macOS: the app's too) | Core, Kit, Shared |
| `PassTunnelHelper` | `main.swift` XPC listener, process supervision | Shared (and through it VPNConfig) |
| `PassTunnel` | SwiftUI app, menu bar, onboarding, updates (`AppUpdater`); CLI mode runs `PassTunnelCLI` | CLI, Core, Kit, VPNConfig, Shared, Sparkle |
| `PassTunnelCommand` | Linux only: the `passtunnel` executable (product `passtunnel`), `PassTunnelCLI.run` | CLI |
| `PassTunnelDaemon` | Linux only: the root daemon's logic ([LINUX.md](LINUX.md)): `Daemon` (socket, systemd activation, one request per connection), `DaemonCall` (the line protocol), `Access` + `UserDatabase` (root and the group `passtunnel`), `TrustedPath` + `SystemTools` (fixed tool paths, ownership and version checks), `Supervisor` (spawn, stop, exit), `PreviousInstance` | Shared, VPNConfig |
| `PassTunnelDaemonCommand` | Linux only: the `passtunneld` executable (product `passtunneld`) | Daemon, Shared |

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
the `passtunnel` binary and, as root, `passtunneld` (with the distribution's openvpn, no tunnel).
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
  `HelperCore.fixedEnvironment` is `PATH` and `LC_ALL` only on Linux, and `openVPNHasDNSUpdown`
  leaves `--dns-updown` out for OpenVPN 2.6.
- **Routes.** `RoutingTable.trafficRoutes` is the IPv4 table (`ipv4Routes`, `sysctl`) on the Mac and,
  on Linux, the IPv4 and IPv6 routes of the tables the policy rules send ordinary traffic to, from
  rtnetlink dumps of the links, routes and rules (`Netlink`: the messages are parsed, and the rules
  followed, by code that builds and is tested everywhere; only `Netlink.dump`, the socket, is Linux's).
  `Route.tunnelDevice` carries the kernel's kind of device there (LINUX.md, Client side).
- **MCP input.** `MCPServer` decodes each line into a `JSONValue` with `JSONDecoder` on every
  platform, so JSON booleans are never numbers (no CoreFoundation `CFBoolean` check).
- **Version.** `AppInfo.current` on Linux is `BuildVersion`: a release build compiles in
  `BuildVersion+Generated.swift` (never committed) with `-DPASSTUNNEL_BUILD_VERSION`; otherwise
  `0.0.0-dev`.
- **System calls.** `POSIXSocket` (`SOCK_STREAM`, `MSG_NOSIGNAL` for `SO_NOSIGPIPE`, no `sun_len`) for
  the management socket and the health probe; Linux pings with `ping -n -q -c 1 -W <s>` (`-6` for IPv6)
  from `/usr/bin`, `/bin`, `/usr/sbin` or `/sbin`, never `PATH`.
- **macOS only** (`#if os(macOS)`): `ProfilesWatcher`, `LoginItem`, `HelperInstaller`,
  `HelperClient`, `QRDecoder`, `TLSFingerprint.fetch` (its digest formats are portable),
  `HelperSessions.currentProcesses`, `RoutingTable.ipv4Routes` and `parse`, `ConfirmationWording`, and in Shared
  `CodeSignature`, `Spawner`, `ToolStager`, the XPC protocol and `HelperCore`'s `F_GETPATH` (Linux
  reads the `/proc/self/fd` link instead) and `fcopyfile` (only for the Mac's bundled DNS script;
  the Linux daemon will be its own hook). On Linux `SessionDirectory.restrictSocket` sets the
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
    public static let helperProtocolVersion = 3   // 3: sessions per (uid, id), socket in the run dir
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
    `profiles/<id>/.mgmt-state` (OpenVPN state shared by the app, which holds the management interface)
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
public enum VPNType: String, Codable, CaseIterable { case openvpn, forti }
public enum PasswordMode: String, Codable, CaseIterable { case keychain, ask, none }   // none = certificate only
public enum OTPMode: String, Codable, CaseIterable { case none, totp, ask }
/// How the one-time code reaches the server.
/// combined  → one secret built from `otpTemplate` (e.g. "{password}{otp}"); OpenVPN auth file / Forti password field
/// separate  → code sent on its own: OpenVPN static-challenge (SCRV1:b64(password):b64(code)), Forti `otp =` field
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
    public var type: VPNType
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
    public var otpDelivery = OTPDelivery.combined   // default: .combined for OpenVPN, .separate for Forti (set in create)
    public var otpTemplate = "{password}{otp}"      // used when .combined; validated: must contain "{otp}"
    // OpenVPN
    public var mgmtPort = 0               // legacy, unused: kept only so older profile.json files decode
    // FortiGate
    public var host = ""
    public var port = 443
    public var trustedCert = ""
    public var setDNS = false
    public var setRoutes = true
    public var configSourceName: String?    // file name the OpenVPN config was imported from
    public var configImportedAt: Date?      // ISO 8601, whole seconds
    // derived
    public var displayBadge: String
    public var needs: [CredentialField]   // what must be asked before connecting (none if password == .none)
    public var unattended: Bool           // can connect without asking (required for auto-reconnect)
    public var usesStoredSecrets: Bool    // keychain password or TOTP: only then is requireAuth offered
}
public enum AuthRequirement: String, Codable, CaseIterable, Comparable { case off, connect, always }   // ordered
public enum CredentialField: String, Codable { case username, password, otp }
```
Decoding must tolerate missing keys (defaults) so older/newer files load (no `require_auth` → `off`;
unknown values → `off`; no `connect_at_login` → false). Share files leave `require_auth` and `connect_at_login` out
(per-user choices, like `pinned`).

## Core APIs

```swift
public struct ProfileStore {                       // all methods throw PTError on bad input
    public init(paths: AppPaths = .default)
    public func list() -> [Profile]                // sorted by (order, name)
    public func get(_ id: String) throws -> Profile
    public func create(name: String, type: VPNType) throws -> Profile   // slug id (Turkish chars folded), unique; deletes Keychain items left under the id
    public func save(_ p: Profile) throws
    public func update(_ id: String, _ change: (inout Profile) throws -> Void) throws -> Profile   // re-read, change, save (locked)
    // ProfileMerge.merge(original:edited:current:) → current + the fields edited changed vs original (editor Save)
    public func delete(_ id: String) throws        // also deletes keychain items and the dir
    public var defaultID: String? { get }; public func setDefault(_ id: String?) throws
    public func dir(_ id: String) -> URL
    public func ovpnURL(_ id: String) -> URL
    public func setOVPN(_ id: String, from: URL) throws   // inlined, <auth-user-pass> stripped, sanitized, 0600
    public func importOVPN(_ url: URL, name: String?) throws -> Profile   // uses OVPNAnalyzer; <auth-user-pass> → username + Keychain password
    public func exportShare(_ id: String, to: URL) throws                 // ShareFile, 0600; config without credential blocks
    public func importShare(_ url: URL, name: String?) throws -> Profile  // drops an <auth-user-pass> block
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
public enum OTPComposer {
    public static func validate(template: String) throws               // must contain "{otp}"
    public static func compose(password: String, otp: String?, delivery: OTPDelivery, template: String,
                               type: VPNType) -> (secret: String, separateOTP: String?)
    public static func parts(delivery: OTPDelivery, template: String) -> (secret: [Part], separateCode: Bool)
        // what compose sends, as .password / .code / .text in order: the editor's masked "Server receives"
}
public struct ShareFile: Codable              // {"passtunnel_profile":1, "profile":{…minus username,last_username,order,mgmt_port,pinned,require_auth,connect_at_login,config_imported_at}, "files":{"config.ovpn": base64}} (config without credential blocks)
    // fileExtension "passtunnel", typeIdentifier "com.furkanprlk.passtunnel.profile" (exported by the app, conforms to public.json)
public struct Preferences: Codable { defaultProfile, theme, showLock, notifyOnDrop, sessionWarnMin=30,
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
`VersionReport`), the error object (`ErrorReport`, `ErrorEnvelope`), the stable error codes
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
then `LogRedactor` masks credentials. `PromptlessAuthenticator` wraps the Secure Enclave
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
app bundle is replaced), the app/CLI hash `Contents/MacOS/PassTunnelHelper` next to their own executable
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
(`sysctl KERN_PROC_ALL` + `proc_pidpath`): children of a `PassTunnelHelper` process, and
`openvpn`/`openfortivpn` inside an app bundle whose identifier is PassTunnel's (or that is gone,
replaced by the update), so other users' sessions and tools adopted by a restarted helper count too;
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
      config.ovpn | openfortivpn.conf, auth, dns-updown, state   0600/0700 root
      mgmt.sock                 0600   owned by <uid> (OpenVPN only)
  tools/                        0755   staged tools (`ToolStager`), root:wheel
    <helper build>/             0755   hex SHA-256 of the helper executable (`HelperBuild.digest`)
      Resources/bin/openvpn, openfortivpn   0555
      Frameworks/*.dylib        0444
```

Users can traverse to their socket by name but cannot list, rename or replace entries, so handing the
socket to the user (`SessionDirectory.restrictSocket`: `fstatat`/`AT_SYMLINK_NOFOLLOW` on the directory
descriptor, then `fchownat`/`fchmodat`) cannot be redirected to another file. A restarted helper adopts
tools recorded in `<uid>/<id>/state`; tools recorded by a protocol-2 helper (`<root>/<id>/state`) are
stopped, since their socket is in the profile directory.

Security rules (helper):
- Runs **only** the tools inside its own app bundle (`Contents/Resources/bin/…`), never a path supplied by
  the client, and only code signed with the tool's identifier and our Team ID (`PT.toolRequirement`).
  It runs them from a root-owned copy (`ToolStager`, Shared): the bundle is writable (and renamable) by
  the user who installed it, and a tool started there would load its dylibs from there after `SIGCONT`,
  checked only for the Team ID by library validation. `ToolStager.stage(inUse:)` (on every start, on the
  supervisor queue): `<runRoot>/tools/<buildID>` (run root realpath'd, so the path matches
  `proc_pidpath` for adoption) is checked (`check`: exactly `Resources/bin/{openvpn,openfortivpn}` and
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
  `dns-updown` copy is still checked by path (OpenVPN runs it, not the helper).
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
  default, empty mask, `POSIX_SPAWN_CLOEXEC_DEFAULT`, environment `HelperCore.fixedEnvironment`:
  `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `LC_ALL=C`, `OPENSSL_CONF=/dev/null`,
  `OPENSSL_MODULES` = `OPENSSL_ENGINES` = `/var/empty/passtunnel-none` (`HelperCore.missingDirectory`,
  never created), `SSL_CERT_FILE=/etc/ssl/cert.pem` (`HelperCore.systemCAFile`), `SSL_CERT_DIR=/var/empty`,
  so the bundled libcrypto loads no config, providers or engines from its compiled-in Homebrew prefix and
  trusts the system CA bundle by default.
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
  external files incl. a `socks-proxy` credentials file, and, like OpenVPN's own parser, a backslash
  outside single quotes that does not escape `\`, `"` or whitespace, or ends the line; strips
  `static-challenge`), writes the sanitized copy and the auth file
  into the session's run directory, then runs openvpn with fixed flags (`--management <runDir>/mgmt.sock unix`
  `--management-client-user <caller's user name>` so only the calling user can talk to it, no
  `--management-hold`; `--verb N` with the config's last `verb` capped at 4, 3 when it sets none
  (`HelperCore.openVPNVerbosity`, from `OVPNSanitizer.verbosity(of:)`); `--auth-nocache`,
  `--remap-usr1 SIGTERM`, `--connect-retry-max 3`, stdout/stderr to logPath). Once OpenVPN creates the socket the helper chowns it to the user with mode 0600; it goes away
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
  `ca-file = /etc/ssl/cert.pem`, so openfortivpn never uses OpenSSL's compiled-in default store.
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
reused code; recorded in `.last-otp` once the helper started the tool) or, with
`Preferences.waitForFreshCode` (default on, read from `config.json` at every connect), if 5 s or less
remain, and publishes `ConnectionState` changes:

```swift
public enum ConnectionState: Equatable { case disconnected, connecting(String), connected(ip: String, since: Date?) }
```

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
  `SecretVaultTests` inject `FakeAuthenticator` (a software P-256 key).
- Swift language mode 5 (tools 5.10), macOS 13 APIs, no third-party dependencies except Sparkle (updates)
  and swift-crypto (CryptoKit's API for PassTunnelKit, and scrypt from its CryptoExtras for the Linux
  file store; used on Linux only), each pinned to an exact version in `Package.swift`.
