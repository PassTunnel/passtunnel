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
```

## Targets

| Target | Owns | Depends on |
|---|---|---|
| `PassTunnelShared` | XPC protocol, request/response types, `OVPNSanitizer`, `FortiConfig`, identifiers | — |
| `PassTunnelCore` | model, `ProfileStore`, `ProfilesWatcher`, `Secrets` (Keychain), `TOTP`, `OTPAuthURI`, `OVPNAnalyzer`, `ShareFile`, `Preferences`, `HealthCheck`, `HelperClient`, `ConnectionManager` | Shared |
| `PassTunnelHelper` | `main.swift` XPC listener, process supervision | Shared |
| `PassTunnel` | SwiftUI app, menu bar, onboarding, CLI | Core, Shared |

## Identifiers (`PassTunnelShared/Identifiers.swift`)

```swift
public enum PT {
    public static let bundleID = "com.furkanprlk.passtunnel"
    public static let helperLabel = "com.furkanprlk.passtunnel.helper"     // launchd label == mach service
    public static let helperPlistName = "com.furkanprlk.passtunnel.helper.plist"
    public static let teamID = "YH4NUPFH74"
    public static let keychainService = "PassTunnel"
    public static let helperProtocolVersion = 2   // 2: OpenVPN management via unix socket
}
```

## Storage

- Support dir: `~/Library/Application Support/PassTunnel/` — override with env `PASSTUNNEL_HOME` (tests).
  - `config.json` – preferences (`Preferences`), incl. `defaultProfile`
  - `profiles/<id>/profile.json`, `profiles/<id>/config.ovpn`, `profiles/<id>/vpn.log`,
    `profiles/<id>/mgmt.sock` (OpenVPN management socket, exists only while connected)
- Keychain: generic password, service `PT.keychainService` (env `PASSTUNNEL_KEYCHAIN_SERVICE` overrides
  for tests), account `"<profileID>/password"` and `"<profileID>/totp"`. Use the Security framework
  (`SecItemAdd/CopyMatching/Update/Delete`), never the `security` CLI. App and CLI are the same binary,
  so Keychain ACLs never prompt between them.
- JSON uses snake_case keys (`JSONEncoder.keyEncodingStrategy = .convertToSnakeCase`), pretty, sorted.

## Model (`PassTunnelCore/Model.swift`)

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
    // behaviour
    public var sessionLimitMin = 0
    public var autoReconnect = false
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
}
public enum CredentialField: String, Codable { case username, password, otp }
```
Decoding must tolerate missing keys (defaults) so older/newer files load.

## Core APIs

```swift
public struct ProfileStore {                       // all methods throw PTError on bad input
    public init(paths: AppPaths = .default)
    public func list() -> [Profile]                // sorted by (order, name)
    public func get(_ id: String) throws -> Profile
    public func create(name: String, type: VPNType) throws -> Profile   // slug id (Turkish chars folded), unique (no mgmtPort any more)
    public func save(_ p: Profile) throws
    public func update(_ id: String, _ change: (inout Profile) throws -> Void) throws -> Profile   // re-read, change, save (locked)
    public func delete(_ id: String) throws        // also deletes keychain items and the dir
    public var defaultID: String? { get }; public func setDefault(_ id: String?) throws
    public func dir(_ id: String) -> URL
    public func ovpnURL(_ id: String) -> URL
    public func setOVPN(_ id: String, from: URL) throws   // copy, 0600
    public func importOVPN(_ url: URL, name: String?) throws -> Profile   // uses OVPNAnalyzer
    public func exportShare(_ id: String, to: URL) throws                 // ShareFile, 0600
    public func importShare(_ url: URL, name: String?) throws -> Profile
}
public enum Secrets {                               // Keychain
    public static func get(_ profileID: String, _ kind: SecretKind) -> String?
    public static func set(_ profileID: String, _ kind: SecretKind, _ value: String) throws
    public static func delete(_ profileID: String, _ kind: SecretKind)
}
public enum SecretKind: String { case password, totp }
public enum TOTP {
    public static func code(secret: Data, params: TOTPParams, at: Date = Date()) -> String
    public static func remaining(params: TOTPParams, at: Date = Date()) -> Int
    public static func decodeSecret(_ s: String) throws -> Data         // base32 (case/space/padding tolerant) or hex
}
public struct OTPAuthURI { label, issuer, secret: Data, params: TOTPParams; init(_ uri: String) throws }   // otpauth://totp/...
public enum OVPNAnalyzer { public static func analyze(_ text: String) -> (passwordMode, otpMode, otpDelivery, remote: String) }
// static-challenge in the file → otpMode .ask, otpDelivery .separate; otherwise .combined
public enum OTPComposer {
    public static func validate(template: String) throws               // must contain "{otp}"
    public static func compose(password: String, otp: String?, delivery: OTPDelivery, template: String,
                               type: VPNType) -> (secret: String, separateOTP: String?)
}
public struct ShareFile: Codable              // {"passtunnel_profile":1, "profile":{…minus username,last_username,order,mgmt_port,pinned}, "files":{"config.ovpn": base64}}
public struct Preferences: Codable { defaultProfile, theme, showLock, notifyOnDrop, sessionWarnMin=30,
    sessionNotifyMin=10, hotkeys=false, autoType=false, launchAtLogin=true, autoUpdate=false }
public enum HealthCheck { public static func check(_ host: String, timeout: TimeInterval = 3) -> (ok: Bool, ms: Int) }
```

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
    func perform(_ request: Data, reply: @escaping (Data) -> Void)    // HelperRequest → HelperResponse
}
public enum HelperRequest: Codable {
    case startOpenVPN(OpenVPNStart)        // profileID, profileDir, username?, secret? (password+otp already formatted), logPath
                                           // (mgmtPort: Int? still decodes for protocol 1 payloads but is ignored)
    case startForti(FortiStart)            // profileID, profileDir, host, port, username, password, otp?, trustedCert, setDNS, setRoutes, logPath
    case stop(profileID: String)
    case status                            // → running profile IDs with pid
}
public struct HelperResponse: Codable { ok: Bool; error: String?; pid: Int32?; running: [String: Int32]?
                                         mgmtSocket: String? }   // startOpenVPN → "<profileDir>/mgmt.sock"
```

Security rules (helper):
- Runs **only** the tools inside its own app bundle (`Contents/Resources/bin/…`), after verifying their code
  signature has our Team ID. Never a path supplied by the client.
- `profileDir` must be a real directory under the *calling user's* home `Library/Application Support/PassTunnel/profiles/`
  (resolve symlinks; check owner uid == caller's euid from the audit token).
- OpenVPN: reads `config.ovpn` from profileDir, runs it through `OVPNSanitizer` (rejects `up`, `down`,
  `route-up`, `route-pre-down`, `ipchange`, `learn-address`, `client-connect`, `client-disconnect`,
  `tls-verify`, `auth-user-pass-verify`, `plugin`, `script-security` > 1, `management*`, `log*`, `daemon`,
  `writepid`, `cd`, `chroot`, `user`/`group`, `config`; strips `static-challenge`), writes the sanitized copy and the auth file
  into a root-only temp dir, then runs openvpn with fixed flags (`--management <profileDir>/mgmt.sock unix`
  `--management-client-user <caller's user name>` so only the calling user can talk to it, no
  `--management-hold`; `--auth-nocache`, `--remap-usr1 SIGTERM`, `--connect-retry-max 3`, stdout/stderr to
  logPath). A stale `mgmt.sock` is removed through the profile-dir descriptor before launch (refused if it is
  a symlink or not a socket); once OpenVPN creates it the helper chowns it to the user with mode 0600, and
  removes it when the process exits. The socket path must fit in `sun_path` (103 bytes), which limits the
  length of profile IDs.
- Forti: the helper writes the openfortivpn config itself from the typed fields (no user-supplied raw config;
  no pppd options). OTP is passed in the config (`otp = …`), so no pinentry is needed.
- Tracks the pid it started per profile; `stop` only signals that pid (SIGTERM, then SIGKILL after 5 s).
  Several Forti/OpenVPN profiles may run at once.

`HelperClient` (Core) wraps the XPC connection with async functions. `ManagementSocket` (Core) is a
one-shot client for the OpenVPN management socket: `ManagementSocket(path:).command(_:timeout:)` connects,
reads the banner, sends one command and reads until `END` / `SUCCESS:` / `ERROR:` (retrying briefly while
the socket is not there yet or another client is connected); `state()` returns
`ManagementState(name, localIP, since, …)`. `ConnectionManager` (Core) owns state per profile: OpenVPN
state via `ManagementSocket` on `HelperResponse.mgmtSocket` (`state` command; first field = since;
disconnect = helper `stop`),
Forti via helper `status` + log (`Tunnel is up and running`, `Got addresses: [...]`). It resolves
credentials (Keychain / TOTP / caller-supplied for `.ask`), builds what is sent with
`OTPComposer` (Core, pure + unit-tested):
- `.combined`: `otpTemplate` with `{password}` / `{otp}` substituted (no other placeholders; literal text kept)
  → OpenVPN auth-file password, or Forti `password` (Forti `otp` then omitted)
- `.separate`: OpenVPN → `SCRV1:b64(password):b64(code)` (static-challenge), Forti → `password` + `otp` fields
waits for the next TOTP window if fewer than 8 s remain, and publishes `ConnectionState` changes:

```swift
public enum ConnectionState: Equatable { case disconnected, connecting(String), connected(ip: String, since: Date?) }
```

## Rules for all code

- English identifiers, English comments (sparse). User-facing strings via `String(localized:)` with
  Turkish translations in `Localizable.xcstrings`.
- No company/customer names, no real hostnames — examples use `Acme`, `vpn.example.com`.
- Tests never touch the real Keychain service or real support dir: they set `PASSTUNNEL_HOME` and
  `PASSTUNNEL_KEYCHAIN_SERVICE`. Management-socket tests run their own fake server on a socket in a
  temp dir.
- Swift language mode 5 (tools 5.10), macOS 13 APIs, no third-party dependencies except Sparkle (updates).
