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

## Targets

| Target | Owns | Depends on |
|---|---|---|
| `PassTunnelShared` | XPC protocol, request/response types, `HelperCore` (request decoding, path checks), `SessionPolicy`, `CodeSignature`, `OVPNSanitizer`, `FortiConfig`, identifiers | — |
| `PassTunnelCore` | model, `ProfileStore`, `ProfilesWatcher`, `Secrets` (Keychain), `TOTP`, `OTPAuthURI`, `OVPNAnalyzer`, `ShareFile`, `Preferences`, `HealthCheck`, `HelperClient`, `ConnectionManager` | Shared |
| `PassTunnelHelper` | `main.swift` XPC listener, process supervision | Shared |
| `PassTunnel` | SwiftUI app, menu bar, onboarding, CLI, updates (`AppUpdater`) | Core, Shared, Sparkle |

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
    // ProfileMerge.merge(original:edited:current:) → current + the fields edited changed vs original (editor Save)
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
    func build(reply: @escaping (String) -> Void)                    // HelperBuild digest, protocol ≥ 3
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
                                         mgmtSocket: String?               // startOpenVPN → PT.mgmtSocketPath(uid, id)
                                         mgmtSockets: [String: String]? }  // status → id → socket (caller's OpenVPN sessions)
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
outdated. The app then shows Settings → Helper as "Needs an update", whose
**Update Helper** button unregisters the daemon (launchd stops it, which stops its tunnels) and
registers it again from the running app bundle (`HelperInstaller.update`, Core, behind the
`HelperRegistrar` protocol so it is unit-tested with a fake). Right after the unregister, launchd may
refuse the new registration with EPERM ("Operation not permitted") for a few seconds, so `update` waits
up to 1.5 s for the old job to leave `.enabled` and retries EPERM after 0.5, 1, 2 and 3 s; only then does
it fail (`HelperInstallError.notPermitted`). `kSMErrorLaunchDeniedByUser` (switched off in Login Items)
is not retried (`.deniedByUser`); `kSMErrorAlreadyRegistered` counts as success.

After an app update (Sparkle replaces the bundle; the running helper keeps its old build) the app
runs that update by itself (`AppModel.updateHelper`, the same flow as the button), decided by
`HelperAutoUpdate` (Core, unit-tested): only for an enabled helper known to be outdated, only when
the app runs from `/Applications` or `~/Applications` (a test build elsewhere never takes the helper
over), at most once per outdated helper (a failure is left to the button), and only while no
PassTunnel session is active. Sessions are counted by `HelperSessions` from the process list
(`sysctl KERN_PROC_ALL` + `proc_pidpath`): children of a `PassTunnelHelper` process, and
`openvpn`/`openfortivpn` inside an app bundle whose identifier is PassTunnel's (or that is gone,
replaced by the update), so other users' sessions and tools adopted by a restarted helper count too;
plus the profiles the app itself sees as active. While sessions are active it notifies once ("The
helper needs an update"), Settings → Helper says it updates itself, and the app re-evaluates on every
5 s reload, so the update runs right after the last session ends.

Run directory layout (all root-owned; `HelperCore.makeRunDir`):

```
/var/run/passtunnel/            0711   run root
  <uid>/                        0711   one per user
    <profileID>/                0711   one per session, recreated on start, removed when the tool exits
      config.ovpn | openfortivpn.conf, auth, dns-updown, state   0600/0700 root
      mgmt.sock                 0600   owned by <uid> (OpenVPN only)
```

Users can traverse to their socket by name but cannot list, rename or replace entries, so handing the
socket to the user (`SessionDirectory.restrictSocket`: `fstatat`/`AT_SYMLINK_NOFOLLOW` on the directory
descriptor, then `fchownat`/`fchmodat`) cannot be redirected to another file. A restarted helper adopts
tools recorded in `<uid>/<id>/state`; tools recorded by a protocol-2 helper (`<root>/<id>/state`) are
stopped, since their socket is in the profile directory.

Security rules (helper):
- Runs **only** the tools inside its own app bundle (`Contents/Resources/bin/…`), after verifying their code
  signature has our Team ID. Never a path supplied by the client.
- `profileDir` must be a real directory under the *calling user's* home `Library/Application Support/PassTunnel/profiles/`
  (resolve symlinks; check owner uid == caller's euid from the audit token), not group- or world-writable.
  `config.ovpn` must be a regular, single-link file owned by the user and not group- or world-writable.
  Profile IDs: ASCII letters, digits, `-`, `_`, `.`, 1–64 bytes, no leading `.`/`-`, no trailing `.`.
- OpenVPN: reads `config.ovpn` from profileDir, runs it through `OVPNSanitizer` (rejects `up`, `down`,
  `route-up`, `route-pre-down`, `ipchange`, `learn-address`, `client-connect`, `client-disconnect`,
  `tls-verify`, `auth-user-pass-verify`, `plugin`, `script-security` > 1, `management*`, `log*`, `daemon`,
  `writepid`, `cd`, `chroot`, `user`/`group`, `config`, `show-pkcs11-ids`, `genkey`, `port-share`,
  external files incl. a `socks-proxy` credentials file; strips `static-challenge`), writes the sanitized copy and the auth file
  into the session's run directory, then runs openvpn with fixed flags (`--management <runDir>/mgmt.sock unix`
  `--management-client-user <caller's user name>` so only the calling user can talk to it, no
  `--management-hold`; `--auth-nocache`, `--remap-usr1 SIGTERM`, `--connect-retry-max 3`, stdout/stderr to
  logPath). Once OpenVPN creates the socket the helper chowns it to the user with mode 0600; it goes away
  with the run directory when the process exits. The socket path must fit in `sun_path` (103 bytes):
  `/var/run/passtunnel/<uid>/<id>/mgmt.sock` fits 64-byte IDs for uids up to 8 digits.
- Forti: the helper writes the openfortivpn config itself from the typed fields (no user-supplied raw config;
  no pppd options). OTP is passed in the config (`otp = …`), so no pinentry is needed.
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
`PT.mgmtSocketPath(uid: geteuid(), …)` only as a fallback) (`state` command; first field = since;
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
waits for the next TOTP window if fewer than 8 s remain or the current window's code was already sent
(servers reject a reused code; recorded in `.last-otp` once the helper started the tool), and publishes `ConnectionState` changes:

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
  reads the IPv4 routing table (`RoutingTable.ipv4Routes`, `sysctl NET_RT_DUMP`) and refuses with
  `PTError.otherVPNActive("utunN")` when `default`, `0/1` or `128/1` (unscoped) goes through a VPN
  interface (`utun`, `ppp`, `ipsec`, `tun`, `tap`) that is not one of PassTunnel's running sessions (their
  interface comes from "Opened utun device …" / "Interface pppN is UP" in their logs).
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
  `PASSTUNNEL_KEYCHAIN_SERVICE`. Management-socket tests run their own fake server on a socket in a
  temp dir.
- Swift language mode 5 (tools 5.10), macOS 13 APIs, no third-party dependencies except Sparkle (updates,
  pinned to an exact version in `Package.swift`).
