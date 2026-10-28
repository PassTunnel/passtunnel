import Foundation
import PassTunnelKit
import PassTunnelShared
import PassTunnelVPNConfig

#if canImport(Combine)
import Combine
#endif
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto  // swift-crypto: the same API, outside Apple platforms
#endif
#if canImport(AppKit)
import AppKit
#endif

// MARK: - Public types

public enum ConnectionState: Equatable, Sendable {
    case disconnected
    case connecting(String)  // localized phase, e.g. "Signing in…"
    case connected(ip: String, since: Date?)

    public var isConnected: Bool { if case .connected = self { return true }; return false }
    public var isConnecting: Bool { if case .connecting = self { return true }; return false }
    /// Connected or on the way there.
    public var isActive: Bool { self != .disconnected }
}

/// Result of the periodic reachability probe of `Profile.healthHost` while connected.
public enum HealthState: Equatable, Sendable {
    case unknown  // not probed yet, or one failure so far
    case reachable(ms: Int)
    case unreachable  // consecutive failures: "connected but unreachable"
}

/// A pending automatic reconnect after a drop.
public struct ReconnectInfo: Equatable, Sendable {
    public var attempt: Int  // 1-based
    public var maxAttempts: Int
    public var at: Date  // when the attempt starts

    public init(attempt: Int, maxAttempts: Int, at: Date) {
        self.attempt = attempt
        self.maxAttempts = maxAttempts
        self.at = at
    }
}

/// Tries of a server that did not answer (`ConnectionManager.unreachableRetries`): after a connect or a
/// reconnect ended `unreachable`, the manager tries again every `Timing.unreachableRetryDelay` seconds.
public struct UnreachableRetry: Codable, Equatable, Sendable {
    /// Tries that found the server unreachable, since the first one or since the network last changed.
    public var tries: Int
    public var maxTries: Int
    /// When the next try starts; nil while one runs, and while the computer is offline.
    public var nextTryAt: Date?
    /// Offline: the next try starts once the network is back.
    public var waitingForNetwork: Bool
    /// When the first try failed, and the last one.
    public var firstFailedAt: Date
    public var lastFailedAt: Date

    public init(
        tries: Int, maxTries: Int, nextTryAt: Date? = nil, waitingForNetwork: Bool = false, firstFailedAt: Date,
        lastFailedAt: Date
    ) {
        self.tries = tries
        self.maxTries = maxTries
        self.nextTryAt = nextTryAt
        self.waitingForNetwork = waitingForNetwork
        self.firstFailedAt = firstFailedAt
        self.lastFailedAt = lastFailedAt
    }
}

/// Things worth telling the user about. The manager never posts notifications itself; the app maps
/// these to user notifications according to `Preferences`.
public enum ConnectionEvent: Equatable, Sendable {
    case dropped(profileID: String, willReconnect: Bool)
    case reconnected(profileID: String)
    case reconnectFailed(profileID: String, reason: String)
    case unreachable(profileID: String)
    case reachableAgain(profileID: String)
    case sessionEnding(profileID: String, minutes: Int)
    /// Dropped while the Mac was asleep and would be reconnected, but the profile requires a
    /// confirmation to connect: the user is asked to reconnect instead of being prompted out of the blue.
    case droppedWhileAsleep(profileID: String)
    /// Would be reconnected (after a drop or for an outage), but the profile's server settings changed
    /// after the user confirmed the session: not reconnected; the user connects (and confirms) again.
    /// `stillConnected`: found by the health check, so the old tunnel is still up (not responding).
    case destinationChanged(profileID: String, stillConnected: Bool = false)

    public var profileID: String {
        switch self {
        case .dropped(let id, _), .reconnected(let id), .reconnectFailed(let id, _), .unreachable(let id),
            .reachableAgain(let id), .sessionEnding(let id, _), .droppedWhileAsleep(let id),
            .destinationChanged(let id, _):
            return id
        }
    }
}

/// Where a profile sends its credentials, as one fingerprint: SHA-256 over the type and, for OpenVPN,
/// the exact bytes of config.ovpn (servers, CA, proxies, everything the helper runs); for FortiGate,
/// host, port and trusted certificate; for Cisco AnyConnect, host, port, user group and server pin
/// (the group name is not a destination: it is matched against the server's list). Secrets the user confirmed are bound to the fingerprint the
/// profile had then (`SecretVault`, session secrets) and are not sent anywhere else. The helper reads
/// config.ovpn again later, so the start request carries `configSHA256` of the bytes fingerprinted
/// here and the helper refuses any other file.
public struct ProfileDestination: Equatable, Sendable {
    public var fingerprint: String
    /// The server for prompts and messages (OpenVPN: the first `remote`, with "+N more" when there are
    /// several: `OVPNAnalyzer.serverDescription`); may be empty.
    public var host: String
    /// Hex SHA-256 of the config.ovpn read for `fingerprint` (OpenVPN; nil when it could not be read).
    public var configSHA256: String?

    public init(fingerprint: String, host: String, configSHA256: String? = nil) {
        self.fingerprint = fingerprint
        self.host = host
        self.configSHA256 = configSHA256
    }

    public static func of(_ p: Profile, store: ProfileStore) -> ProfileDestination {
        var hash = SHA256()
        func field(_ text: String) {
            hash.update(data: Data(text.utf8))
            hash.update(data: Data([0]))
        }
        field("passtunnel-destination-1")
        field(p.type.rawValue)
        let host: String
        var configSHA256: String?
        switch p.type {
        case .openvpn:
            if let data = try? FileIO.read(store.ovpnURL(p.id), maxSize: ProfileStore.maxOVPNSize) {
                field("config")
                hash.update(data: data)
                host = OVPNAnalyzer.serverDescription(String(decoding: data, as: UTF8.self))
                configSHA256 = HelperCore.sha256Hex(data)
            } else {
                field("no-config")
                host = ""
            }
        case .forti:
            host = p.host.trimmingCharacters(in: .whitespacesAndNewlines)
            field(host.lowercased())
            field(String(p.port))
            // As the editor saves it ("AB:CD:…" → "abcd…"), so its reformatting changes nothing.
            let cert = p.trustedCert.trimmingCharacters(in: .whitespacesAndNewlines)
            field(TLSFingerprint.normalize(cert) ?? cert.lowercased())
        case .anyconnect:
            host = p.host.trimmingCharacters(in: .whitespacesAndNewlines)
            field(host.lowercased())
            field(String(p.port))
            field(p.usergroup)
            // Stored normalized; a hand-edited file's spelling must not move the binding either.
            field(OpenConnectPin.normalize(p.serverCert) ?? p.serverCert.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return ProfileDestination(
            fingerprint: hash.finalize().map { String(format: "%02x", $0) }.joined(), host: host,
            configSHA256: configSHA256)
    }
}

extension VPNType {
    /// The types the front ends offer to create and show as ordinary profiles (the app's type picker and
    /// list, `passtunnel add` and `list`). Cisco AnyConnect is not among them yet: `ConnectionManager`
    /// connects such a profile (where `ConnectionManager.connectRefusal` allows it), but the CLI (#185) and the
    /// app (#186) still list it as needing a newer PassTunnel until they handle its settings; `passtunnel
    /// show`, `set`, `export` and `rm` work on it.
    public static let connectable: [VPNType] = [.openvpn, .forti]

    public var isConnectable: Bool { Self.connectable.contains(self) }
}

/// An automatic reconnect found the profile's server settings changed since the user confirmed the
/// session: its secrets are not sent to the new destination without a new confirmation.
public struct DestinationChangedError: Error, Equatable, LocalizedError {
    public var host: String

    public init(host: String) { self.host = host }

    public var errorDescription: String? {
        String(
            localized:
                "The server settings of this profile changed after you confirmed the connection. Connect it again yourself to confirm the new server."
        )
    }
}

/// The helper calls the manager needs; `HelperClient` in production, a fake in tests.
public protocol HelperClienting: AnyObject {
    func perform(_ request: HelperRequest, timeout: TimeInterval?) async throws -> HelperResponse
    /// Throws `HelperClientError.versionMismatch` / `.buildMismatch` unless the running helper speaks our
    /// protocol and is the build shipped with this app.
    func ensureCompatible() async throws
}

public extension HelperClienting {
    func ensureCompatible() async throws {}
}

#if os(macOS)
extension HelperClient: HelperClienting {}
#endif

/// Reads OpenVPN's state from its management socket.
public protocol ManagementQuerying {
    func state(socketPath: String, timeout: TimeInterval) async throws -> ManagementState
    /// True when this querier holds the management interface open (other processes then cannot query
    /// it), so the manager shares the state it reads through a snapshot file.
    var sharesState: Bool { get }
    /// The connection to `socketPath` is no longer needed.
    func release(socketPath: String)
    /// Sends one management command. The app's querier uses the connection it holds (OpenVPN serves one
    /// client at a time); the default opens a one-shot connection and returns the reply.
    func send(_ command: String, socketPath: String, timeout: TimeInterval) async throws -> String
}

public extension ManagementQuerying {
    var sharesState: Bool { false }
    func release(socketPath: String) {}

    func send(_ command: String, socketPath: String, timeout: TimeInterval) async throws -> String {
        try await ManagementSocket.sendOneShot(command, socketPath: socketPath, timeout: timeout)
    }
}

extension ManagementSocket {
    /// `command` on a background queue (its I/O is blocking).
    static func sendOneShot(_ command: String, socketPath: String, timeout: TimeInterval) async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                let socket = ManagementSocket(path: socketPath)
                cont.resume(with: Result { try socket.command(command, timeout: timeout) })
            }
        }
    }
}

#if DEBUG
/// `passtunnel debug drop ID` (debug builds only): a test hook that makes a connected OpenVPN profile
/// drop as if the server had ended the session, so drop notifications and auto-reconnect can be tried
/// for real. The CLI posts `notification` (object: the profile ID) to a running app — distributed
/// notifications stay within the user's login session — which sends it over the management connection
/// it holds; without the app, the CLI sends it itself.
public enum DebugDrop {
    public static let notification = Notification.Name("com.furkanprlk.passtunnel.debugDrop")
    /// OpenVPN exits as on a fatal server-side error; not a user stop.
    public static let command = "signal SIGTERM"
}
#endif

/// `ManagementSocket` on a background queue (its I/O is blocking).
public struct SocketManagementQuerier: ManagementQuerying {
    public init() {}

    public func state(socketPath: String, timeout: TimeInterval) async throws -> ManagementState {
        // The socket exists only while OpenVPN runs; don't spend retries waiting for it.
        guard FileManager.default.fileExists(atPath: socketPath) else {
            throw ManagementError.connectFailed(socketPath, ENOENT)
        }
        return try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                var socket = ManagementSocket(path: socketPath)
                socket.connectAttempts = 2
                socket.retryDelay = 0.1
                cont.resume(with: Result { try socket.state(timeout: timeout) })
            }
        }
    }
}

/// Time source for everything time-dependent (TOTP windows, timeouts, backoff), injectable for tests.
public protocol ConnectionClock: AnyObject {
    func now() -> Date
    /// Throws `CancellationError` when the task is cancelled.
    func sleep(_ seconds: TimeInterval) async throws
}

public final class SystemClock: ConnectionClock {
    public init() {}
    public func now() -> Date { Date() }
    public func sleep(_ seconds: TimeInterval) async throws {
        guard seconds > 0 else { return try Task.checkCancellation() }
        try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
    }
}

// MARK: - ConnectionManager

/// Owns the connection state of every profile: polling, connect / disconnect, credential resolution,
/// drop detection, auto-reconnect, health checks, wake handling and session-limit timing.
@MainActor
public final class ConnectionManager: ObservableObject {
    public typealias HealthProbe = (String) async -> (ok: Bool, ms: Int)

    public struct Timing {
        public var pollInterval: TimeInterval = 3
        public var healthInterval: TimeInterval = 30
        public var openVPNTimeout: TimeInterval = 60
        public var fortiTimeout: TimeInterval = 120
        /// Cisco AnyConnect: the longest the user's sign-in run may take (`AnyConnectSignIn`), and then the
        /// tunnel run until the hook reports the network up (the helper stops it after `VPNHook.setupDeadline`).
        public var signInTimeout: TimeInterval = AnyConnectSignIn.defaultTimeout
        public var anyConnectTimeout: TimeInterval = 90
        public var connectCheckInterval: TimeInterval = 0.5
        public var processCheckInterval: TimeInterval = 2
        public var reconnectDelays: [TimeInterval] = [5, 15, 45]
        /// With `Preferences.waitForFreshCode`, a code with this many seconds or less left waits for the next one.
        public var freshCodeSeconds = TimeInterval(Preferences.freshCodeSeconds)
        public var wakeDelay: TimeInterval = 4
        public var healthFailuresForOutage = 2
        public var helperTimeout: TimeInterval = 15
        public var stopTimeout: TimeInterval = 20
        /// A server that did not answer is tried again after this long, at most `unreachableMaxTries`
        /// times; after the network path changes, after `networkSettleDelay`.
        public var unreachableRetryDelay: TimeInterval = 30
        public var unreachableMaxTries = 10
        public var networkSettleDelay: TimeInterval = 2
        public init() {}
    }

    /// Localized connecting phases shown in `ConnectionState.connecting`.
    public enum Phase {
        public static var preparing: String { String(localized: "Preparing…") }
        public static var waitingForCode: String { String(localized: "Waiting for a fresh code…") }
        public static var starting: String { String(localized: "Starting…") }
        public static var connecting: String { String(localized: "Connecting…") }
        public static var signingIn: String { String(localized: "Signing in…") }
        public static var configuring: String { String(localized: "Configuring…") }
        public static var reconnecting: String { String(localized: "Reconnecting…") }
    }

    /// Filters connecting phases for display so they only move forward: a session followed from
    /// another process is polled, and its phases can be seen out of order (Configuring… → Preparing…).
    /// Phases outside the usual order (Reconnecting…) are shown whenever they change.
    public struct PhaseProgress {
        static var order: [String] {
            [Phase.preparing, Phase.waitingForCode, Phase.starting, Phase.connecting, Phase.signingIn, Phase.configuring]
        }
        private var last = ""
        private var rank = -1

        public init() {}

        public mutating func shouldPrint(_ phase: String) -> Bool {
            guard phase != last else { return false }
            if let r = Self.order.firstIndex(of: phase) {
                guard r > rank else { return false }
                rank = r
            }
            last = phase
            return true
        }
    }

    static let userStoppedMarker = ".user-stopped"
    /// TOTP window whose code was last sent (`UsedOTPWindow`), shared by the app and the CLI.
    static let usedOTPFile = ".last-otp"

    /// Servers usually accept a TOTP code only once, so the window of the last code sent is kept
    /// per profile and the next connect within that window waits for a new code.
    struct UsedOTPWindow: Codable, Equatable {
        var counter: UInt64
        var period: Int
    }

    /// OpenVPN state shared through the profile directory by the process that holds the management
    /// interface open (the app), for processes that then find it busy (the CLI).
    static let sharedStateFile = ".mgmt-state"

    struct SharedState: Codable, Equatable {
        var pid: Int32  // the OpenVPN process the state belongs to
        var writer: Int32  // the process that wrote it; ignored once that is gone
        var name: String
        var localIP: String
        var since: Date
        var detail: String
        var remoteIP: String
        var localIPv6: String

        // Raw values survive JSONCoding's snake_case round trip ("local_ip" ↔ "localIp").
        enum CodingKeys: String, CodingKey {
            case pid, writer, name, since, detail
            case localIP = "localIp", remoteIP = "remoteIp", localIPv6 = "localIpv6"
        }

        init(pid: Int32, writer: Int32, _ s: ManagementState) {
            self.pid = pid
            self.writer = writer
            name = s.name
            localIP = s.localIP
            since = s.since
            detail = s.detail
            remoteIP = s.remoteIP
            localIPv6 = s.localIPv6
        }

        var state: ManagementState {
            ManagementState(
                name: name, localIP: localIP, since: since, detail: detail, remoteIP: remoteIP,
                localIPv6: localIPv6)
        }
    }

    @Published public private(set) var states: [String: ConnectionState] = [:]
    @Published public private(set) var lastError: [String: String] = [:]
    /// Log excerpt for the last error (tooltip / "Show log").
    @Published public private(set) var lastErrorLog: [String: String] = [:]
    /// Why the last connect failed, typed (also for a cancelled one, which leaves `lastError` empty).
    @Published public private(set) var failures: [String: ConnectionFailure] = [:]
    @Published public private(set) var health: [String: HealthState] = [:]
    @Published public private(set) var reconnecting: [String: ReconnectInfo] = [:]
    /// Why the last helper `status` call failed (nil when it worked).
    @Published public private(set) var helperError: String?
    /// Connected, but part of the tunnel set-up failed (e.g. a route OpenVPN could not add).
    @Published public private(set) var warnings: [String: String] = [:]
    /// Profiles whose state could not be read from the management interface (another client holds
    /// it, OpenVPN serves one at a time) and comes from the last state written for the same OpenVPN
    /// process or from the log instead: shown as "(status unavailable)".
    @Published public private(set) var statusUnavailable: Set<String> = []
    /// While a connect waits for a fresh TOTP code: when that wait ends.
    @Published public private(set) var codeWaitUntil: [String: Date] = [:]
    /// The last clock measurement per profile in this process (`lastClock` also reads the other
    /// processes'): the FortiGate gateway's time, after it rejected a sign-in.
    @Published public private(set) var clockOffsets: [String: ClockOffset] = [:]
    /// The last check with the time server (`checkClock`, on request only).
    @Published public private(set) var timeServerClock: ClockOffset?
    /// Measures the clock (`ServerClock`); tests put in one that never goes to the network.
    public var serverClock: ClockChecking = ServerClock()
    private var clockChecks: [String: (seq: Int, task: Task<Void, Never>)] = [:]
    private var clockCheckSeq = 0
    /// Servers that did not answer and are tried again (`retriesUnreachable`); this process's only
    /// (`unreachableRetry(_:)` also reads another process's).
    @Published public private(set) var unreachableRetries: [String: UnreachableRetry] = [:]
    /// The network path as the system sees it, while the manager runs (`start`); `.unknown` before.
    @Published public private(set) var networkStatus = NetworkStatus.unknown

    /// Try a server that did not answer again (`UnreachableRetry`), after a connect of this manager
    /// (manual or at login) and after the automatic reconnects of a drop. The app turns it on; the CLI
    /// and the MCP server report the failure and leave the retrying to their caller.
    public var retriesUnreachable = false

    public let events = PassthroughSubject<ConnectionEvent, Never>()
    /// Every activity event this manager records, as it is appended to the profile's `activity.jsonl`
    /// (`activity(_:)` reads the file, which also holds what other processes recorded).
    public let activity = PassthroughSubject<ActivityRecord, Never>()

    public let store: ProfileStore
    /// Protected secrets (`Profile.requireAuth`): decrypting them is the user's confirmation.
    public let vault: SecretVault
    public var timing: Timing
    private let helper: HelperClienting
    private let management: ManagementQuerying
    private let clock: ConnectionClock
    private let healthProbe: HealthProbe
    private let preferences: () -> Preferences
    private let routes: () -> [RoutingTable.Route]
    /// The routes through a tunnel interface (`RoutingTable.routes(onInterface:)`), read for a FortiGate
    /// tunnel when it is up; replaced in tests.
    var tunnelRoutes: (String) -> [RoutingTable.Route] = RoutingTable.routes(onInterface:)
    /// The macOS this runs on, for the types that need a later one than the app (`connectRefusal`); nil on
    /// Linux. Replaced in tests.
    var systemVersion: OperatingSystemVersion? = ConnectionManager.currentMacOS
    /// Runs Cisco AnyConnect's sign-in (`AnyConnectSignIn`); a fake in tests, which never run openconnect.
    var toolRunner: ToolRunning = SystemToolRunner()
    /// The openconnect the sign-in runs: the app bundle's (`AnyConnectSignIn.bundledTool`); nil outside one.
    var openConnectPath: String? = AnyConnectSignIn.bundledTool()
    /// Cisco AnyConnect sign-ins under way, which `disconnect` stops.
    private var signIns: [String: ToolCancellation] = [:]

    private var pollSeq = 0
    private var appliedSeq = 0
    private var busy: [String: Int] = [:]  // actions in flight per profile
    private var actionToken: [String: Int] = [:]  // bumped by disconnect: cancels a running connect
    private var userStopped: Set<String> = []
    private var sessionActive: Set<String> = []  // reached "connected" in the current session
    private var connectedAt: [String: Date] = [:]
    private var mgmtSockets: [String: String] = [:]  // management socket per profile, as the helper reports it
    private var sharedStates: [String: SharedState] = [:]  // last state written to the shared file per profile
    private var reconnectGen: [String: Int] = [:]
    private var reconnectTasks: [String: Task<Void, Never>] = [:]
    private var codeWaits: [String: Task<Void, Error>] = [:]  // waiting for a fresh code; disconnect cancels
    /// Decrypted protected secrets of a session the user confirmed, so an automatic reconnect after a
    /// drop needs no prompt. Dropped (overwritten, best effort) when the session ends for good, and
    /// when the profile's destination no longer is the one the session was confirmed for.
    private var sessionSecrets: [String: [SecretKind: [UInt8]]] = [:]
    /// `ProfileDestination.fingerprint` each entry of `sessionSecrets` belongs to.
    private var sessionDestinations: [String: String] = [:]
    /// Sessions whose secrets were dropped because the destination changed: not reconnected
    /// automatically (`destinationChanged`) until the user connects again.
    private var changedDestinations: Set<String> = []
    private var connectTasks: [String: Task<Void, Error>] = [:]  // connects started through `connect`
    private var healthFailures: [String: Int] = [:]
    private var outage: Set<String> = []
    private var forcedReconnectDone: Set<String> = []
    private var sessionWarned: [String: Date] = [:]  // session start that was already warned about
    private var connectedBeforeSleep: Set<String> = []
    private var sleeping = false
    private var loops: [Task<Void, Never>] = []
    private var observers: [NSObjectProtocol] = []
    private let network: NetworkPathWatching
    private var retryGen: [String: Int] = [:]
    private var retryWaits: [String: Task<Void, Never>] = [:]  // the wait before the next try
    private var retryRunning: Set<String> = []  // a try is under way
    private var retryAfterDrop: Set<String> = []  // the retries continue a drop's reconnects
    private var retryNetworkChanged: Set<String> = []  // the path changed while a try ran
    public private(set) var isRunning = false

    public init(
        store: ProfileStore = ProfileStore(),
        helper: HelperClienting = ConnectionManager.defaultHelper,
        management: ManagementQuerying = SocketManagementQuerier(),
        clock: ConnectionClock = SystemClock(),
        healthProbe: @escaping HealthProbe = ConnectionManager.defaultHealthProbe,
        preferences: @escaping () -> Preferences = { Preferences.load() },
        routes: @escaping () -> [RoutingTable.Route] = RoutingTable.trafficRoutes,
        timing: Timing = Timing(),
        vault: SecretVault? = nil,
        authenticator: UserAuthenticator? = nil,
        network: NetworkPathWatching? = nil
    ) {
        self.store = store
        self.helper = helper
        self.management = management
        self.clock = clock
        self.healthProbe = healthProbe
        self.preferences = preferences
        self.routes = routes
        self.timing = timing
        self.network = network ?? NetworkPath()
        self.vault =
            vault
            ?? SecretVault(
                authenticator: authenticator ?? PlatformAuthenticator(),
                now: { [clock] in clock.now() },
                reuseWindow: { preferences().authReuseInterval },
                destination: { [store] in ProfileDestination.of($0, store: store) })
    }

    /// The helper a manager uses unless it is given one: the privileged helper (XPC) on the Mac,
    /// passtunneld through its unix socket on Linux (docs/LINUX.md).
    nonisolated public static var defaultHelper: HelperClienting {
        #if os(macOS)
        HelperClient.shared
        #else
        UnixSocketHelperClient.shared
        #endif
    }

    nonisolated public static func defaultHealthProbe(_ host: String) async -> (ok: Bool, ms: Int) {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async { cont.resume(returning: HealthCheck.check(host)) }
        }
    }

    public func state(_ id: String) -> ConnectionState { states[id] ?? .disconnected }

    // MARK: lifecycle

    /// Starts polling, health checks and sleep/wake observation (the app calls this once).
    public func start() {
        guard !isRunning else { return }
        isRunning = true
        network.start { [weak self] in self?.networkChanged($0) }
        loops.append(
            Task { [weak self] in
                while !Task.isCancelled {
                    guard let self else { return }
                    if !self.sleeping { await self.refresh() }
                    do { try await self.clock.sleep(self.timing.pollInterval) } catch { return }
                }
            })
        loops.append(
            Task { [weak self] in
                while !Task.isCancelled {
                    guard let self else { return }
                    do { try await self.clock.sleep(self.timing.healthInterval) } catch { return }
                    if !self.sleeping { await self.runHealthChecks() }
                }
            })
        #if canImport(AppKit)
        let nc = NSWorkspace.shared.notificationCenter
        observers.append(
            nc.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.handleWillSleep() }
            })
        observers.append(
            nc.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in await self?.handleDidWake() }
            })
        #endif
    }

    public func stop() {
        isRunning = false
        loops.forEach { $0.cancel() }
        loops.removeAll()
        #if canImport(AppKit)
        observers.forEach { NSWorkspace.shared.notificationCenter.removeObserver($0) }
        #endif
        observers.removeAll()
        network.stop()
        for id in Set(reconnectTasks.keys).union(unreachableRetries.keys) { cancelReconnect(id) }
    }

    // MARK: polling

    /// Reads the state of every profile once and applies it unless a newer poll or an action
    /// happened meanwhile.
    public func refresh() async {
        await refresh(wakeIDs: [])
    }

    private func refresh(wakeIDs: Set<String>) async {
        vault.prune()
        pollSeq += 1
        let seq = pollSeq
        let profiles = store.list()
        revalidateDestinations(profiles)

        var running: [String: Int32]?
        do {
            let r = try await helper.perform(.status, timeout: timing.helperTimeout)
            if r.ok {
                running = r.running ?? [:]
                mgmtSockets = r.mgmtSockets ?? [:]
                helperError = nil
            } else {
                helperError = r.error ?? ""
            }
        } catch {
            helperError = error.localizedDescription
        }

        var observed: [String: ConnectionState] = [:]
        var unverified: Set<String> = []
        for p in profiles where !isBusy(p.id) {
            let o = await observe(p, running: running)
            observed[p.id] = o.state
            if o.unverified { unverified.insert(p.id) }
        }
        guard seq > appliedSeq else { return }  // stale: a newer poll or an action got in first
        appliedSeq = seq
        let unavailable = statusUnavailable.filter { observed[$0] == nil }.union(unverified)
        if unavailable != statusUnavailable { statusUnavailable = unavailable }

        let ids = Set(profiles.map(\.id))
        for id in states.keys where !ids.contains(id) { forget(id) }
        for p in profiles {
            guard let new = observed[p.id], !isBusy(p.id) else { continue }
            apply(new, to: p, immediateReconnect: wakeIDs.contains(p.id))
        }
        // Stopped by a disconnect in another process (app ↔ CLI).
        for id in unreachableRetries.keys where !retryRunning.contains(id) && hasUserStoppedMarker(id) { cancelReconnect(id) }
    }

    private func observe(_ p: Profile, running: [String: Int32]?) async -> (state: ConnectionState, unverified: Bool) {
        let isRunning = running?[p.id] != nil
        switch p.type {
        case .openvpn:
            if running != nil && !isRunning {
                stopSharing(p.id)
                return (.disconnected, false)
            }
            let socket = mgmtSockets[p.id] ?? socketPath(p.id)
            if let s = await managementState(p.id, socketPath: socket, pid: running?[p.id]) {
                return (Self.map(s.state), s.unverified)
            }
            return (isRunning ? .connecting(Phase.starting) : .disconnected, false)
        case .forti:
            guard isRunning else { return (.disconnected, false) }
            let log = VPNLog.read(store.logURL(p.id))
            guard fortiIsConnected(p, log: log) else { return (.connecting(Phase.connecting), false) }
            return (.connected(ip: VPNLog.fortiAddress(log) ?? "", since: connectedAt[p.id] ?? logCreated(p.id)), false)
        case .anyconnect:
            // Connected once the hook reported the network up (its last line is the success line).
            guard isRunning else { return (.disconnected, false) }
            guard let report = VPNLog.openConnectReport(VPNLog.read(store.logURL(p.id))) else {
                return (.connecting(Phase.configuring), false)
            }
            return (.connected(ip: report.addresses.first?.description ?? "", since: connectedAt[p.id] ?? logCreated(p.id)), false)
        }
    }

    private func logCreated(_ id: String) -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: store.logURL(id).path))?[.creationDate] as? Date
    }

    /// OpenVPN's state from its management socket, or, while another process holds the interface (the
    /// app keeps a connection open), the state that process shares for the same OpenVPN `pid`.
    /// When the interface cannot be read and no live process shares the state (e.g. a client other
    /// than the app holds it, or the app that wrote the state has quit), the helper still runs
    /// OpenVPN: the last state written for that process, else the log's, marked `unverified`, rather
    /// than "Starting…" for a tunnel that is up. The app reopens the interface on every poll, so it
    /// takes it over as soon as it is free.
    private func managementState(
        _ id: String, socketPath: String,
        pid: Int32?
    ) async -> (state: ManagementState, unverified: Bool)? {
        // A live holder keeps the interface busy anyway: don't wait for the busy timeout.
        if !management.sharesState, let pid, let shared = sharedState(id, pid: pid) { return (shared, false) }
        do {
            let s = try await management.state(socketPath: socketPath, timeout: 2)
            if management.sharesState, let pid { share(id, SharedState(pid: pid, writer: getpid(), s)) }
            return (s, false)
        } catch {
            guard let pid else { return nil }
            if !management.sharesState, let shared = sharedState(id, pid: pid) { return (shared, false) }
            if let last = sharedState(id, pid: pid, requireLiveWriter: false) { return (last, true) }
            let log = VPNLog.read(store.logURL(id))
            guard VPNLog.openVPNIsUp(log) else { return nil }
            let since = connectedAt[id] ?? logCreated(id) ?? clock.now()
            return (ManagementState(name: "CONNECTED", localIP: VPNLog.openVPNLocalIP(log) ?? "", since: since), true)
        }
    }

    private func sharedStateURL(_ id: String) -> URL { store.dir(id).appendingPathComponent(Self.sharedStateFile) }

    /// Writes the shared state when it changed (not on every poll).
    private func share(_ id: String, _ state: SharedState) {
        guard sharedStates[id] != state, FileManager.default.fileExists(atPath: store.dir(id).path) else { return }
        sharedStates[id] = state
        try? JSONCoding.write(state, to: sharedStateURL(id), mode: 0o600)
    }

    private func stopSharing(_ id: String) {
        guard sharedStates.removeValue(forKey: id) != nil else { return }
        try? FileManager.default.removeItem(at: sharedStateURL(id))
        management.release(socketPath: mgmtSockets[id] ?? socketPath(id))
    }

    /// The state another live process shared for OpenVPN process `pid`, if any.
    /// `requireLiveWriter: false`: also when the process that wrote it has exited (last known state).
    func sharedState(_ id: String, pid: Int32, requireLiveWriter: Bool = true) -> ManagementState? {
        guard let s = try? JSONCoding.read(SharedState.self, from: sharedStateURL(id)), s.pid == pid,
            ManagementState.isPlausible(s.since)
        else { return nil }
        guard !requireLiveWriter || kill(s.writer, 0) == 0 || errno == EPERM else { return nil }
        return s.state
    }

    static func map(_ s: ManagementState) -> ConnectionState {
        switch s.name {
        case "CONNECTED":
            return .connected(ip: s.localIP.isEmpty ? s.localIPv6 : s.localIP, since: s.since)
        case "EXITING":
            return .disconnected
        case "AUTH", "AUTH_PENDING":
            return .connecting(Phase.signingIn)
        case "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES":
            return .connecting(Phase.configuring)
        case "RECONNECTING":
            return .connecting(Phase.reconnecting)
        default:
            return .connecting(Phase.connecting)
        }
    }

    private func apply(_ new: ConnectionState, to p: Profile, immediateReconnect: Bool) {
        let id = p.id
        setState(id, new)
        switch new {
        case .connected(_, let since):
            if !sessionActive.contains(id) {
                // Connected by someone else (e.g. the CLI) or found running at launch.
                sessionActive.insert(id)
                userStopped.remove(id)
                noteSetupProblems(p)
            }
            if unreachableRetries[id] != nil && !retryRunning.contains(id) { endRetry(id, .connected) }
            let start = connectedAt[id] ?? since ?? clock.now()
            connectedAt[id] = start
            checkSessionLimit(p, start: start)
        case .connecting:
            break
        case .disconnected:
            guard sessionActive.remove(id) != nil else { break }
            endSession(id)
            if userStopped.remove(id) != nil || hasUserStoppedMarker(id) { break }
            handleDrop(p, afterWake: immediateReconnect)
        }
    }

    // MARK: actions

    /// Connects `id`. `given` supplies the fields the profile asks for (`Profile.needs`).
    /// Returns once connected; cancels any pending automatic reconnect. A second call while a connect
    /// of this manager is in flight waits for that one; when another process (app ↔ CLI) is already
    /// starting the profile, its session is followed instead of starting a second one.
    /// `force` skips the check for another VPN that already takes all traffic.
    /// Protected secrets are decrypted first (`vault`: Touch ID or the Mac password); a cancel throws
    /// `PTError.userConfirmationCancelled` before anything starts. Automatic reconnects after a drop
    /// and health-forced reconnects do not ask again: they reuse the secrets of the session the user
    /// confirmed, as long as the profile still points where it did then (`ProfileDestination`).
    /// `followOnly`: only wait for an attempt already under way (this manager's, or a session the
    /// helper runs for another process); throws `NothingToFollow` instead of starting one, and asks
    /// for nothing. `role` learns whether this call started the session or follows another process's
    /// (not called when it waits for this manager's own attempt or there was nothing to do).
    /// `interactive` false (connect at login): never asks; protected secrets come only from the reuse
    /// window, else `PTError.confirmationRequired`, as for an automatic reconnect.
    public func connect(
        _ id: String, given: [CredentialField: String] = [:], force: Bool = false,
        followOnly: Bool = false, interactive: Bool = true,
        role: ((ConnectRole) -> Void)? = nil
    ) async throws {
        // On every path (following too), before the helper is asked anything or a confirmation would
        // decrypt the secrets.
        if let p = try? store.get(id) { try Self.checkConnectable(p, macOS: systemVersion) }
        cancelReconnect(id)
        if let inFlight = connectTasks[id] { return try await inFlight.value }
        let current = state(id).isActive || followOnly ? nil : try? store.get(id)
        // A confirmation given for other server settings does not count: ask now, naming the new server.
        if let p = current { vault.forgetUnlessBound(p) }
        if interactive, let p = current, vault.needsPrompt(p, for: .connect) {
            do {
                try await vault.unlock(p, for: .connect)
            } catch {
                // Shown like any connect failure; a cancel is not a failure.
                if (error as? PTError) != .userConfirmationCancelled {
                    lastError[id] = error.localizedDescription
                    lastErrorLog[id] = ""
                }
                failures[id] = ConnectionFailure.of(error, log: nil, handed: nil, at: clock.now())
                throw error
            }
            if let inFlight = connectTasks[id] { return try await inFlight.value }
        }
        let task = Task {
            try await self.performConnect(
                id, given: given, force: force, interactive: interactive, followOnly: followOnly,
                role: role)
        }
        connectTasks[id] = task
        defer { if connectTasks[id] == task { connectTasks[id] = nil } }
        do {
            try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                task.cancel()
            }
        } catch {
            if !followOnly { beginRetryIfUnreachable(id, afterDrop: false) }
            throw error
        }
    }

    /// Whether a `connect` call started its session or follows one another process started.
    public enum ConnectRole: Sendable { case started, followed }

    /// `connect(followOnly:)` found no attempt to follow: the one seen before has ended.
    public struct NothingToFollow: Error {}

    /// Stops `id` (also cancels a connect in progress) and marks it user-stopped so the exit is not
    /// reported as a drop. Returns false when there was nothing to stop: no VPN process (the helper
    /// names the pid it stopped) and no connect in progress here.
    @discardableResult
    public func disconnect(_ id: String) async throws -> Bool {
        let wasActive = state(id).isActive || isBusy(id) || codeWaits[id] != nil
        // Also the retries of an unreachable server another process (the app) runs: it ends them on its
        // next poll (the user-stopped marker).
        let wasReconnecting = reconnecting[id] != nil || unreachableRetry(id) != nil
        // A session this process has not seen (a `passtunnel` command): whether it was up, from its log,
        // read before the stop adds its exit to it.
        let wasConnected = state(id).isConnected || (!wasActive && toolLogSaysUp(id))
        cancelReconnect(id)
        removeSharedRetry(id)
        actionToken[id, default: 0] += 1
        codeWaits.removeValue(forKey: id)?.cancel()
        signIns.removeValue(forKey: id)?.cancel()
        endSessionSecrets(id)
        changedDestinations.remove(id)
        userStopped.insert(id)
        setUserStoppedMarker(id, true)
        sessionActive.remove(id)
        endSession(id)
        begin(id)
        defer { end(id) }
        let r = try await helper.perform(.stop(profileID: id), timeout: timing.stopTimeout)
        setState(id, .disconnected)
        guard r.ok else { throw PTError.helperFailed(r.error ?? "") }
        if wasActive || wasReconnecting || r.pid != nil {
            record(id, wasConnected ? .disconnectedByUser : .stoppedByUser)
        }
        return wasActive || r.pid != nil
    }

    /// The tool's log shows the tunnel up (OpenVPN "Initialization Sequence Completed" with no restart
    /// after it, openfortivpn "Tunnel is up and running", Cisco AnyConnect the hook's success line).
    private func toolLogSaysUp(_ id: String) -> Bool {
        guard let p = try? store.get(id) else { return false }
        let log = VPNLog.read(store.logURL(id))
        switch p.type {
        case .openvpn: return VPNLog.openVPNIsUp(log)
        case .forti: return VPNLog.fortiIsUp(log)
        case .anyconnect: return VPNLog.openConnectIsUp(log)
        }
    }

    /// Disconnect when connected or connecting, connect otherwise.
    public func toggle(_ id: String, given: [CredentialField: String] = [:]) async throws {
        if state(id).isActive {
            try await disconnect(id)
        } else {
            try await connect(id, given: given)
        }
    }

    /// Disconnects every profile that is connected, connecting, or running according to the helper.
    public func disconnectAll() async throws {
        await refresh()
        var firstError: Error?
        for p in store.list() where state(p.id).isActive {
            do { try await disconnect(p.id) } catch { firstError = firstError ?? error }
        }
        if let firstError { throw firstError }
    }

    /// `interactive` false (automatic reconnects): protected secrets come from the confirmed session or
    /// the reuse window, never from a prompt (`PTError.confirmationRequired` otherwise), and never for
    /// a destination other than the one they were confirmed for (`DestinationChangedError`).
    private func performConnect(
        _ id: String, given: [CredentialField: String], force: Bool = false,
        interactive: Bool = true, followOnly: Bool = false,
        role: ((ConnectRole) -> Void)? = nil
    ) async throws {
        guard !isBusy(id), !state(id).isConnected else { return }
        // Before the helper is asked for its status (checked again below on the profile as read then).
        if let p = try? store.get(id) { try Self.checkConnectable(p, macOS: systemVersion) }
        // Before anything changes state: the last error of the attempt that ended stays visible.
        if followOnly, session(id, in: await currentStatus()) == nil { throw NothingToFollow() }
        guard !isBusy(id), !state(id).isConnected else { return }
        actionToken[id, default: 0] += 1
        let token = actionToken[id]!
        begin(id)
        defer {
            end(id)
            if isRunning { Task { await self.refresh() } }
        }
        userStopped.remove(id)
        setUserStoppedMarker(id, false)
        lastError[id] = nil
        lastErrorLog[id] = nil
        failures[id] = nil
        warnings[id] = nil
        setState(id, .connecting(Phase.preparing))
        var progress = AttemptProgress()

        do {
            // Always the profile as stored now (the CLI may have changed it), never a cached copy.
            let p = try store.get(id)
            try Self.checkConnectable(p, macOS: systemVersion)
            let status = await currentStatus()
            if let session = session(id, in: status) {
                role?(.followed)
                progress.toolRan = true
                return try await follow(p, token: token, session: session)
            }
            if followOnly { throw NothingToFollow() }
            role?(.started)
            progress.owned = true
            if p.type == .openvpn && !force { try checkNoOtherFullTunnel(p, running: status?.running ?? [:]) }
            vault.reconcile(p)  // a setting edited by hand: encrypt what it protects before use
            let destination = ProfileDestination.of(p, store: store)
            // An unreadable config.ovpn has no hash for the helper to hold the file to, and no server
            // to show in a prompt: nothing is sent.
            if p.type == .openvpn && destination.configSHA256 == nil { throw PTError.missingConfig(id) }
            let stored = try await storedSecrets(p, destination: destination, interactive: interactive)
            try checkToken(id, token)
            let creds = try resolveCredentials(p, given: given, stored: stored)
            // A helper left running from another app version would misplace or reject the session.
            try await helper.ensureCompatible()
            record(id, connectingEvent(p))
            progress.recorded = true

            var otp = creds.otp
            var codeTime: Date?
            if let secret = creds.totpSecret {
                try await waitForFreshCode(p, secret: secret, token: token)
                let now = clock.now()
                codeTime = now
                otp = TOTP.code(secret: secret, params: p.totp, at: now)
            }
            try checkToken(id, token)
            setState(id, .connecting(Phase.starting))

            let composed = OTPComposer.compose(
                password: creds.password ?? "", otp: otp, delivery: p.otpDelivery,
                template: p.otpTemplate, type: p.type)
            let request: HelperRequest
            switch p.type {
            case .openvpn:
                request = .startOpenVPN(
                    OpenVPNStart(
                        profileID: id, profileDir: store.dir(id).path, username: creds.username,
                        secret: creds.password == nil ? nil : composed.secret, logPath: store.logURL(id).path,
                        configSHA256: destination.configSHA256))
            case .forti:
                request = .startForti(
                    FortiStart(
                        profileID: id, profileDir: store.dir(id).path, host: p.host, port: p.port,
                        username: creds.username ?? "", password: composed.secret, otp: composed.separateOTP,
                        trustedCert: p.trustedCert, setDNS: p.setDNS, setRoutes: p.setRoutes,
                        logPath: store.logURL(id).path))
            case .anyconnect:
                // The user's own sign-in first; only its cookie goes to the helper.
                request = try await signIn(
                    p, username: creds.username ?? "", password: creds.password ?? "", composed: composed, otp: otp,
                    codeTime: codeTime, token: token, progress: &progress)
            }
            let response = try await helper.perform(request, timeout: timing.helperTimeout)
            guard response.ok else {
                // config.ovpn changed after the secrets were checked against it: not sent anywhere.
                if response.errorCode == HelperResponse.ErrorCode.configChanged {
                    throw DestinationChangedError(host: destination.host)
                }
                // Another process started it in the meantime: the helper refuses a second session.
                if let session = session(id, in: await currentStatus()) {
                    role?(.followed)
                    progress.owned = false
                    progress.toolRan = true
                    return try await follow(p, token: token, session: session)
                }
                throw PTError.helperFailed(response.error ?? "")
            }
            progress.toolRan = true
            // Cisco AnyConnect: the sign-in run had the code and the password (`signIn` noted both).
            let sent = sending(p, username: creds.username ?? "", password: creds.password ?? "", otp: otp, codeTime: codeTime)
            if !progress.anyConnect {
                progress.handed = ConnectionFailure.Handed(code: sent.code, codeSecondsLeft: sent.secondsLeft)
                if let codeTime {
                    // The tool has it now; given back if it never reaches the server (`noteFailure`).
                    progress.usedCode = (usedCode(id), rememberUsedCode(p, at: codeTime))
                }
            }
            if actionToken[id] != token {
                // Disconnected while the helper was starting the tool; its stop may have come first.
                await stopQuietly(id)
                throw PTError.connectCancelled
            }
            if creds.username != nil && !progress.anyConnect { record(id, .sending(sent)) }

            if let socket = response.mgmtSocket { mgmtSockets[id] = socket }
            let result = try await waitUntilConnected(
                p, token: token, socketPath: response.mgmtSocket ?? socketPath(id),
                pid: response.pid)
            let since = result.since ?? clock.now()
            setState(id, .connected(ip: result.ip, since: result.since ?? since))
            record(id, .connected(address: result.ip))
            sessionActive.insert(id)
            connectedAt[id] = since
            healthFailures[id] = 0
            keepSessionSecrets(p, stored, destination: destination)
            noteSetupProblems(p)
            ProfileNetwork.record(p, store: store, tunnelRoutes: tunnelRoutes)
            if p.username.trimmingCharacters(in: .whitespaces).isEmpty, let u = creds.username, p.lastUsername != u {
                // Only this field: the profile may have been edited (CLI, editor) while connecting.
                _ = try? store.update(id) { $0.lastUsername = u }
            }
        } catch {
            let cancelled = actionToken[id] != token
            if !(error is NothingToFollow) { noteFailure(id, cancelled ? PTError.connectCancelled : error, progress) }
            if cancelled { throw PTError.connectCancelled }
            setState(id, .disconnected)
            if (error as? PTError) == .connectCancelled || (error as? PTError) == .userConfirmationCancelled
                || error is NothingToFollow
            {
                throw error
            }
            lastError[id] = error.localizedDescription
            lastErrorLog[id] = (error as? PTError)?.logTail ?? ""
            throw error
        }
    }

    /// Cisco AnyConnect's sign-in (docs/ARCHITECTURE.md, "Authentication, split from the tunnel"): runs
    /// `openconnect --authenticate` as the user (`AnyConnectSignIn`) and returns the start request with the
    /// session cookie it got, the address and the key it reached, and the profile's own settings. The
    /// password and the code go to openconnect's standard input only, as `OpenConnectAnswers` lays them out
    /// for the profile's `otp_delivery` (`.separate`: the password, then the code; `.combined`: the composed
    /// secret). The code counts as sent once the run starts (`.last-otp`); `progress.credentialsSent` tells
    /// `noteFailure` whether it can be given back. The run's standard error, redacted, becomes the profile's log
    /// (the helper replaces it when it starts the tunnel). `disconnect` stops a run under way.
    private func signIn(
        _ p: Profile, username: String, password: String, composed: (secret: String, separateOTP: String?), otp: String?,
        codeTime: Date?, token: Int, progress: inout AttemptProgress
    ) async throws -> HelperRequest {
        let id = p.id
        progress.anyConnect = true
        guard let tool = openConnectPath else { throw PTError.fileError("openconnect") }
        let pin = p.serverCert.isEmpty ? "" : OpenConnectPin.normalize(p.serverCert) ?? p.serverCert
        let config = OpenConnectAuthConfig(
            host: p.host, port: p.port, usergroup: p.usergroup, username: username, authgroup: p.authgroup, serverCert: pin)
        let texts = [composed.secret] + (composed.separateOTP.map { [$0] } ?? [])
        let answers: SecretBytes
        do {
            answers = SecretBytes(try OpenConnectAnswers.stdin(texts))
        } catch {
            // Its description names the answer's position, never its value.
            throw PTError.invalidField("password")
        }
        defer { answers.wipe() }

        // openconnect has the code from here on: recorded now, given back by `noteFailure` when no form was sent.
        let sent = sending(p, username: username, password: password, otp: otp, codeTime: codeTime)
        progress.handed = ConnectionFailure.Handed(code: sent.code, codeSecondsLeft: sent.secondsLeft)
        if let codeTime { progress.usedCode = (usedCode(id), rememberUsedCode(p, at: codeTime)) }
        progress.credentialsSent = false
        record(id, .sending(sent))
        setState(id, .connecting(Phase.signingIn))

        let run = AnyConnectSignIn(toolPath: tool, runner: toolRunner, timeout: timing.signInTimeout)
        let cancellation = ToolCancellation()
        signIns[id] = cancellation
        defer { if signIns[id] === cancellation { signIns[id] = nil } }
        if actionToken[id] != token { cancellation.cancel() }
        let secrets = Array(Set(texts + [password] + (otp.map { [$0] } ?? [])))
        let server = serverAddress(p)
        let outcome = await withTaskCancellationHandler {
            await withCheckedContinuation { (done: CheckedContinuation<Result<AnyConnectSignIn.Success, AnyConnectSignIn.Failure>, Never>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    done.resume(
                        returning: run.run(config, answers: answers.bytes, secrets: secrets, server: server, cancellation: cancellation))
                }
            }
        } onCancel: {
            cancellation.cancel()
        }

        switch outcome {
        case .failure(let failure):
            progress.credentialsSent = failure.credentialsSent
            if !failure.log.isEmpty { writeSignInLog(id, failure.log) }
            progress.toolRan = !failure.log.isEmpty
            if actionToken[id] != token { throw PTError.connectCancelled }
            throw failure.error
        case .success(let success):
            progress.credentialsSent = true
            writeSignInLog(id, success.log)
            progress.toolRan = true
            try checkToken(id, token)
            record(id, .authAccepted)
            setState(id, .connecting(Phase.configuring))
            let r = success.result
            return .startOpenConnect(
                OpenConnectStart(
                    profileID: id, profileDir: store.dir(id).path, logPath: store.logURL(id).path, host: p.host, port: p.port,
                    usergroup: p.usergroup, connectURL: r.connectURL, resolve: success.resolve, cookie: r.cookie,
                    serverCert: r.fingerprint, profileServerCert: pin, tlsOnly: p.tlsOnly, setDNS: p.setDNS,
                    setRoutes: p.setRoutes))
        }
    }

    /// The sign-in's standard error (already redacted) as the profile's log, 0600; best effort.
    private func writeSignInLog(_ id: String, _ log: String) {
        guard FileManager.default.fileExists(atPath: store.dir(id).path) else { return }
        try? FileIO.writeAtomically(Data(log.utf8), to: store.logURL(id), mode: 0o600)
    }

    /// The helper's `status` reply, nil when it failed.
    private func currentStatus() async -> HelperResponse? {
        guard let r = try? await helper.perform(.status, timeout: timing.helperTimeout), r.ok else { return nil }
        return r
    }

    /// The management socket and pid of `id` when the helper already runs it (started by another
    /// process, or left from before), else nil.
    private func session(_ id: String, in status: HelperResponse?) -> (socket: String, pid: Int32)? {
        guard let pid = status?.running?[id] else { return nil }
        let socket = status?.mgmtSockets?[id] ?? socketPath(id)
        mgmtSockets[id] = socket
        return (socket, pid)
    }

    #if DEBUG
    /// Test hook (`DebugDrop`): asks the OpenVPN of `id` to exit over its management interface. The
    /// profile is not marked user-stopped, so the exit is handled as a drop (notification,
    /// auto-reconnect). Returns false when the helper does not run the profile.
    @discardableResult
    public func simulateDrop(_ id: String) async throws -> Bool {
        let p = try store.get(id)
        guard p.type == .openvpn else { throw PTError.wrongProfileType(id) }
        guard let session = session(id, in: await currentStatus()) else { return false }
        _ = try await management.send(DebugDrop.command, socketPath: session.socket, timeout: 3)
        return true
    }
    #endif

    /// The macOS this process runs on; nil on Linux.
    public nonisolated static var currentMacOS: OperatingSystemVersion? {
        #if os(macOS)
        return ProcessInfo.processInfo.operatingSystemVersion
        #else
        return nil
        #endif
    }

    /// Why a profile of `type` cannot be connected on this system, nil when it can: what the front ends show
    /// such a profile (and its type in the type picker) disabled with. Cisco AnyConnect needs macOS 15.4 or
    /// later (`HelperCore.Tool.minimumMacOS`: dyld stops the bundled openconnect on anything older; owner
    /// decision, #2): `PTError.anyConnectRequiresMacOS`. On Linux (`macOS` nil) it is not supported yet
    /// (passtunneld refuses it until #187): `PTError.anyConnectNotSupported`.
    public nonisolated static func connectRefusal(_ type: VPNType, macOS: OperatingSystemVersion? = currentMacOS) -> PTError? {
        switch type {
        case .openvpn, .forti:
            return nil
        case .anyconnect:
            guard let macOS else { return .anyConnectNotSupported }
            let tool = HelperCore.Tool.openconnect
            guard !tool.runs(on: macOS), let minimum = tool.minimumMacOS else { return nil }
            return .anyConnectRequiresMacOS(HelperCore.Tool.versionText(minimum))
        }
    }

    /// `connectRefusal` for this manager's system.
    public func connectRefusal(_ type: VPNType) -> PTError? { Self.connectRefusal(type, macOS: systemVersion) }

    /// Throws `connectRefusal`'s error for a profile whose type cannot be connected on this system: before
    /// any secret is read, any confirmation is asked or the helper is asked anything.
    public nonisolated static func checkConnectable(_ p: Profile, macOS: OperatingSystemVersion? = currentMacOS) throws {
        if let refusal = connectRefusal(p.type, macOS: macOS) { throw refusal }
    }

    /// The check `connect` runs before starting `id` (without `force`), on its own, so a caller can
    /// report a refusal before it says it is connecting. Nothing to check when the helper already runs
    /// the profile (`connect` then follows that session). Throws when another VPN takes all traffic or
    /// the profile's type is not connected yet (`checkConnectable`); returns the profiles of PassTunnel's
    /// own sessions whose routes or DNS names overlap with the ones `id` takes (`overlaps(for:)`), which
    /// is a warning for the caller to show, never a refusal.
    @discardableResult
    public func checkCanStart(_ id: String) async throws -> [ProfileOverlap] {
        let p = try store.get(id)
        try Self.checkConnectable(p, macOS: systemVersion)
        let status = await currentStatus()
        guard status?.running?[id] == nil else { return [] }
        if p.type == .openvpn { try checkNoOtherFullTunnel(p, running: status?.running ?? [:]) }
        return overlaps(of: p, running: status?.running ?? [:])
    }

    /// The connected profiles (connecting ones too) whose tunnel takes over some of the same networks or DNS
    /// names as `id`'s would (`NetworkClaims.overlaps`): what the app shows a sheet for ("Switch to …",
    /// "Connect both") and the CLI and MCP warn about. From the profiles' configs and what their servers
    /// pushed the last time they connected (`ProfileNetwork`), so a profile that never connected is only
    /// compared by its own config lines. Empty for a profile that is already running, when nothing is
    /// connected, and when anything cannot be read.
    public func overlaps(for id: String) async -> [ProfileOverlap] {
        guard let p = try? store.get(id) else { return [] }
        let status = await currentStatus()
        guard status?.running?[id] == nil else { return [] }
        return overlaps(of: p, running: status?.running ?? [:])
    }

    private func overlaps(of p: Profile, running: [String: Int32]) -> [ProfileOverlap] {
        let active = Set(running.keys).union(states.filter { $0.value.isActive }.keys).subtracting([p.id])
        let others = active.sorted().compactMap { try? store.get($0) }
        guard !others.isEmpty else { return [] }
        return ProfileNetwork.overlaps(of: p, with: others, store: store, tunnelRoutes: tunnelRoutes)
    }

    /// Refuses to start a profile that takes all traffic while another VPN (not one of ours) already
    /// does: its routes would collide, and OpenVPN's teardown would then delete the other tunnel's.
    /// Whether the profile redirects is read from its config, else from its last log (pushed option).
    private func checkNoOtherFullTunnel(_ p: Profile, running: [String: Int32]) throws {
        guard let config = try? String(contentsOf: store.ovpnURL(p.id), encoding: .utf8) else { return }
        let redirects =
            OVPNAnalyzer.redirectsGateway(config)
            ?? VPNLog.pushedRedirectGateway(VPNLog.readHead(store.logURL(p.id)))
        guard redirects else { return }
        let own = Set(running.keys.filter { $0 != p.id }.compactMap { VPNLog.tunnelInterface(VPNLog.readHead(store.logURL($0))) })
        if let other = FullTunnelCheck.foreignFullTunnel(in: routes(), own: own) {
            throw PTError.otherVPNActive(other)
        }
    }

    /// Publishes a warning when the log shows a failed set-up step (see `VPNLog.setupProblem`).
    private func noteSetupProblems(_ p: Profile) {
        guard p.type == .openvpn, let problem = VPNLog.setupProblem(VPNLog.readHead(store.logURL(p.id), maxBytes: 256 * 1024)) else {
            warnings[p.id] = nil
            return
        }
        warnings[p.id] = String(localized: "Connected, but part of the network setup failed: \(problem.reason)")
    }

    /// Waits for a session this manager did not start to come up. Failures are reported but the
    /// session is left alone: the process that started it handles them.
    private func follow(_ p: Profile, token: Int, session: (socket: String, pid: Int32)) async throws {
        let result = try await waitUntilConnected(
            p, token: token, socketPath: session.socket, pid: session.pid,
            owned: false)
        let since = result.since ?? clock.now()
        setState(p.id, .connected(ip: result.ip, since: since))
        sessionActive.insert(p.id)
        connectedAt[p.id] = since
        healthFailures[p.id] = 0
    }

    struct Credentials {
        var username: String?
        var password: String?  // nil: certificate only
        var otp: String?  // `.ask` code
        var totpSecret: Data?
    }

    /// The stored secrets connecting `p` uses: from the vault without asking (plain, or unlocked), from
    /// the confirmed session, or decrypted now (asking) when `interactive`. Decrypted values confirmed
    /// for another destination are dropped first; an automatic reconnect then stops.
    private func storedSecrets(
        _ p: Profile, destination: ProfileDestination,
        interactive: Bool
    ) async throws -> [SecretKind: String] {
        dropSecrets(p.id, unlessBoundTo: destination.fingerprint)
        vault.forgetUnlessBound(p.id, to: destination.fingerprint)
        if !interactive && changedDestinations.contains(p.id) && vault.requiresConfirmation(p) {
            throw DestinationChangedError(host: destination.host)
        }
        try vault.refuseUnconfirmable(p, SecretVault.usedKinds(p))
        var out: [SecretKind: String] = [:]
        for kind in SecretVault.usedKinds(p) {
            if let value = vault.available(p.id, kind) {
                out[kind] = value
            } else if let bytes = sessionSecrets[p.id]?[kind] {
                out[kind] = String(decoding: bytes, as: UTF8.self)
            } else if let value = try await vault.secret(p, kind, for: .connect, prompt: interactive) {
                out[kind] = value
            }
        }
        return out
    }

    private func keepSessionSecrets(_ p: Profile, _ stored: [SecretKind: String], destination: ProfileDestination) {
        endSessionSecrets(p.id)
        changedDestinations.remove(p.id)
        let protected = stored.filter { vault.isProtected(p.id, $0.key) }
        guard !protected.isEmpty else { return }
        sessionSecrets[p.id] = protected.mapValues { Array($0.utf8) }
        sessionDestinations[p.id] = destination.fingerprint
    }

    /// Ends the session secrets of `id` when they were confirmed for another destination.
    private func dropSecrets(_ id: String, unlessBoundTo fingerprint: String) {
        guard let bound = sessionDestinations[id], bound != fingerprint else { return }
        endSessionSecrets(id)
        changedDestinations.insert(id)
    }

    /// Drops session secrets and confirmations of profiles whose destination is no longer the one the
    /// user confirmed (profile.json or config.ovpn changed). Runs on every poll; the app also calls
    /// it when the profile files change. Reads only profiles that hold such secrets.
    public func revalidateDestinations(_ profiles: [Profile]? = nil) {
        for p in profiles ?? store.list() where sessionDestinations[p.id] != nil || vault.hasDecrypted(p.id) {
            let fingerprint = ProfileDestination.of(p, store: store).fingerprint
            dropSecrets(p.id, unlessBoundTo: fingerprint)
            vault.forgetUnlessBound(p.id, to: fingerprint)
        }
    }

    private func endSessionSecrets(_ id: String) {
        sessionDestinations[id] = nil
        guard var secrets = sessionSecrets.removeValue(forKey: id) else { return }
        for kind in Array(secrets.keys) {
            _ = secrets[kind]?.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
        }
    }

    /// `stored`: the Keychain secrets `p` uses, already decrypted (`storedSecrets`).
    func resolveCredentials(_ p: Profile, given: [CredentialField: String], stored: [SecretKind: String]) throws -> Credentials {
        let id = p.id
        switch p.type {
        case .openvpn:
            guard FileManager.default.fileExists(atPath: store.ovpnURL(id).path) else { throw PTError.missingConfig(id) }
        case .forti:
            guard !p.host.trimmingCharacters(in: .whitespaces).isEmpty else { throw PTError.missingHost(id) }
            // The helper refuses it too; a profile.json changed outside the app fails here, before any secret is sent.
            guard FortiConfig.isValidHost(p.host) else { throw PTError.invalidField("host") }
        case .anyconnect:
            guard !p.host.trimmingCharacters(in: .whitespaces).isEmpty else { throw PTError.missingHost(id) }
            // As stored, which is what the sign-in uses; a profile.json changed outside the app fails here.
            guard Profile.isValidHost(p.host, type: .anyconnect) else { throw PTError.invalidField("host") }
            try p.checkAnyConnectFields()
        }
        // A store that cannot be read says so (`SecretStoreUnavailable`), rather than "missing".
        if p.passwordMode == .keychain, try !Secrets.exists(id, .password) { throw PTError.missingPassword(id) }
        if p.otpMode == .totp, try !Secrets.exists(id, .totp) { throw PTError.missingTOTPSecret(id) }

        func value(_ field: CredentialField) -> String? {
            let v = given[field]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return v.isEmpty ? nil : v
        }
        var c = Credentials()
        if p.type == .openvpn && p.passwordMode == .none { return c }

        let fixed = p.username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let username = fixed.isEmpty ? value(.username) : fixed else { throw PTError.missingCredential(.username) }
        try Profile.checkUsername(username, type: p.type)
        c.username = username

        switch p.passwordMode {
        case .keychain:
            guard let pw = stored[.password] else { throw PTError.missingPassword(id) }
            c.password = pw
        case .ask:
            guard let pw = given[.password], !pw.isEmpty else { throw PTError.missingCredential(.password) }
            c.password = pw
        case .none:
            c.password = ""
        }

        switch p.otpMode {
        case .none:
            break
        case .totp:
            guard let text = stored[.totp] else { throw PTError.missingTOTPSecret(id) }
            c.totpSecret = try TOTP.decodeSecret(text)
        case .ask:
            guard let code = value(.otp) else { throw PTError.missingCredential(.otp) }
            c.otp = code
        }
        return c
    }

    /// Waits for the next TOTP window when the code of the current one was already sent by this or
    /// another process (always: servers reject a reused code), or when `freshCodeSeconds` or less
    /// remain in it and `Preferences.waitForFreshCode` is on. The wait is at most one window, is not
    /// counted against the connect timeout, and ends at once on `disconnect`.
    private func waitForFreshCode(_ p: Profile, secret: Data, token: Int) async throws {
        let period = Double(max(1, p.totp.period))
        let now = clock.now()
        let left = period - (now.timeIntervalSince1970 - Double(TOTP.counter(params: p.totp, at: now)) * period)
        let reused = usedCode(p.id) == UsedOTPWindow(counter: TOTP.counter(params: p.totp, at: now), period: Int(period))
        let fresh = timing.freshCodeSeconds
        let expiring = period > fresh && left <= fresh && preferences().waitForFreshCode
        guard reused || expiring else { return }
        let wait = max(0, left) + 0.25
        codeWaitUntil[p.id] = now.addingTimeInterval(wait)
        defer { codeWaitUntil[p.id] = nil }
        record(
            p.id,
            .waitingForCode(
                reason: reused ? .used : .expiring, seconds: Int(max(0, left).rounded(.up)),
                codePrefix: ActivityEvent.codePrefix(TOTP.code(secret: secret, params: p.totp, at: now))))
        setState(p.id, .connecting(Phase.waitingForCode))
        try await waitCancellably(p.id, wait)
        try checkToken(p.id, token)
    }

    /// `clock.sleep` that `disconnect` (or cancelling the calling task) ends early with `connectCancelled`,
    /// so a cancelled connect does not keep the profile busy until its wait is over.
    private func waitCancellably(_ id: String, _ seconds: TimeInterval) async throws {
        let clock = self.clock
        let wait = Task { try await clock.sleep(seconds) }
        codeWaits[id] = wait
        defer { if codeWaits[id] == wait { codeWaits[id] = nil } }
        do {
            try await withTaskCancellationHandler {
                try await wait.value
            } onCancel: {
                wait.cancel()
            }
        } catch {
            throw PTError.connectCancelled
        }
    }

    private func usedCodeURL(_ id: String) -> URL { store.dir(id).appendingPathComponent(Self.usedOTPFile) }

    func usedCode(_ id: String) -> UsedOTPWindow? {
        try? JSONCoding.read(UsedOTPWindow.self, from: usedCodeURL(id))
    }

    /// When `id` last sent a one-time code (by this process or another): the start of that code's window; nil
    /// when it never did. Reads the profile directory.
    public func lastCodeSent(_ id: String) -> Date? {
        usedCode(id).map { Date(timeIntervalSince1970: TimeInterval($0.counter) * TimeInterval($0.period)) }
    }

    @discardableResult
    private func rememberUsedCode(_ p: Profile, at date: Date) -> UsedOTPWindow {
        let used = UsedOTPWindow(counter: TOTP.counter(params: p.totp, at: date), period: max(1, p.totp.period))
        guard FileManager.default.fileExists(atPath: store.dir(p.id).path) else { return used }
        try? JSONCoding.write(used, to: usedCodeURL(p.id), mode: 0o600)
        return used
    }

    /// Puts back the record that a code which never reached the server replaced (none: removes it).
    private func restoreUsedCode(_ id: String, _ previous: UsedOTPWindow?) {
        guard FileManager.default.fileExists(atPath: store.dir(id).path) else { return }
        if let previous {
            try? JSONCoding.write(previous, to: usedCodeURL(id), mode: 0o600)
        } else {
            try? FileManager.default.removeItem(at: usedCodeURL(id))
        }
    }

    /// How far a connect got, for the failure it may end with.
    struct AttemptProgress {
        /// This manager started the session (not one another process started, which it follows).
        var owned = false
        /// `connecting` is in the activity.
        var recorded = false
        /// The VPN tool ran for this attempt (or the followed session's does): its log is about it.
        var toolRan = false
        /// What the tool was given.
        var handed: ConnectionFailure.Handed?
        /// The used-code record before this attempt, and the one it wrote.
        var usedCode: (previous: UsedOTPWindow?, written: UsedOTPWindow)?
        /// Cisco AnyConnect: the sign-in ran (or was about to run) in this process (`signIn`). Its errors carry
        /// what the log says, and whether the credentials left is `credentialsSent`, not the log's markers.
        var anyConnect = false
        /// Whether the sign-in's credentials can have reached the server, when this process knows it.
        var credentialsSent: Bool?
    }

    /// Keeps why the attempt failed (`failures`), records it in the activity of a session this manager
    /// started, and gives the code's period back when the code never reached the server, so the next
    /// connect need not wait for a fresh code (only if no other process recorded a code since). Not after
    /// a cancel: the tool may still be on its way to the server while the stop is under way.
    private func noteFailure(_ id: String, _ error: Error, _ progress: AttemptProgress) {
        // A Cisco AnyConnect log is openconnect's: its errors (`VPNLog.openConnectSignInError`, `waitUntilConnected`)
        // already carry what it says, which the markers of the other tools would misread.
        let anyConnect = progress.anyConnect || (try? store.get(id))?.type == .anyconnect
        let log = progress.toolRan && !anyConnect ? VPNLog.read(store.logURL(id)) : nil
        var failure = ConnectionFailure.of(
            error, log: log, handed: progress.handed, at: clock.now(), credentialsSent: progress.credentialsSent)
        // A try of the retries counts on from the ones before it.
        if failure.kind == .unreachable, let retry = unreachableRetries[id] { failure.tries = retry.tries + (failure.tries ?? 1) }
        failures[id] = failure
        if failure.kind == .authRejected && progress.owned { checkGatewayClock(id, after: failure) }
        if let used = progress.usedCode, !failure.credentialsSent, failure.kind != .cancelled, usedCode(id) == used.written {
            restoreUsedCode(id, used.previous)
        }
        guard progress.owned && progress.recorded else { return }
        switch failure.kind {
        case .authRejected: record(id, .rejected(reply: failure.reply))
        case .unreachable: record(id, .unreachable(tries: failure.tries ?? 1, reason: failure.reason))
        case .cancelled: break  // `disconnect` records the stop
        case .hostNotFound, .configuration, .setup, .timeout, .toolUnsupported, .hostScanRequired, .failed:
            record(id, .failed(kind: failure.kind, reason: failure.reason, credentialsSent: failure.credentialsSent))
        }
    }

    /// The server was never reached, as its log tells: `hostNotFound`, or `serverUnreachable` with the
    /// tool's reason; after `timeout` seconds also when the tool tried and nothing answered. nil when the
    /// log tells otherwise (or nothing).
    private func unreached(_ p: Profile, log: String, timeout: TimeInterval? = nil) -> PTError? {
        let tail = VPNLog.tail(log)
        let verdict = VPNLog.verdict(log)
        switch verdict?.kind {
        case .hostNotFound?: return .hostNotFound(server: serverAddress(p), log: tail)
        case .unreachable?: return .serverUnreachable(server: serverAddress(p), reason: verdict?.reason ?? "", log: tail)
        default: break
        }
        guard let timeout, verdict == nil, !VPNLog.credentialsSent(log), VPNLog.attempted(log) else { return nil }
        return .serverUnreachable(
            server: serverAddress(p), reason: String(localized: "no answer within \(Int(timeout)) seconds"),
            log: tail)
    }

    /// Why a tool that stopped on its own (`exited`) or showed a fatal error ended: dyld did not let it
    /// start on this macOS (`toolUnsupported`, only once it is gone: dyld aborts it), the server was not
    /// reached (`unreached`), else `connectFailed`.
    private func ended(_ p: Profile, log: String, exited: Bool) -> PTError {
        if exited, let reason = VPNLog.toolLoadFailure(log) { return .toolUnsupported(reason: reason, log: VPNLog.tail(log)) }
        return unreached(p, log: log) ?? .connectFailed(VPNLog.tail(log))
    }

    /// "vpn.example.com:1194", "[2001:db8::1]:443": the server a connect goes to; "" when unknown.
    private func serverAddress(_ p: Profile) -> String {
        guard case let .connecting(host, port, _) = connectingEvent(p), !host.isEmpty else { return "" }
        let name = host.contains(":") ? "[\(host)]" : host
        return port.map { "\(name):\($0)" } ?? name
    }

    /// Polls until `p` is connected. When `owned` is false (a session another process started), the
    /// session is never stopped here.
    private func waitUntilConnected(
        _ p: Profile, token: Int, socketPath: String, pid: Int32?,
        owned: Bool = true
    ) async throws -> (ip: String, since: Date?) {
        let id = p.id
        let timeout: TimeInterval
        switch p.type {
        case .openvpn: timeout = timing.openVPNTimeout
        case .forti: timeout = timing.fortiTimeout
        case .anyconnect: timeout = timing.anyConnectTimeout
        }
        let started = clock.now()
        var lastProcessCheck = started
        let logURL = store.logURL(id)
        // The activity of a session another process started is that process's to record.
        var accepted = false
        func noteAccepted() {
            guard owned, !accepted else { return }
            accepted = true
            record(id, .authAccepted)
        }

        while true {
            try checkToken(id, token)
            let log = VPNLog.read(logURL)
            if p.type == .anyconnect {
                // The sign-in is over (`signIn` recorded it accepted); this is the tunnel run's log.
                if let error = anyConnectFailure(log, exited: false) {
                    if owned { await stopQuietly(id) }
                    throw error
                }
            } else {
                if VPNLog.isAuthFailure(log) {
                    if owned { await stopQuietly(id) }
                    throw PTError.authFailed(VPNLog.tail(log))
                }
                if VPNLog.isFatal(log) {
                    if owned { await stopQuietly(id) }
                    throw ended(p, log: log, exited: false)
                }
                try await checkSetup(p, log: log, owned: owned)
                if VPNLog.authAccepted(log) { noteAccepted() }
            }
            switch p.type {
            case .openvpn:
                if let s = await managementState(id, socketPath: socketPath, pid: pid)?.state {
                    try checkToken(id, token)
                    if s.isConnected {
                        // Routes and DNS are set up before CONNECTED: their errors are in the log by now.
                        try await checkSetup(p, log: VPNLog.read(logURL), owned: owned)
                        noteAccepted()
                        return (s.localIP.isEmpty ? s.localIPv6 : s.localIP, s.since)
                    }
                    if s.name == "RECONNECTING" && s.detail.lowercased().contains("auth") {
                        if owned { await stopQuietly(id) }
                        throw PTError.authFailed(VPNLog.tail(VPNLog.read(logURL)))
                    }
                    // Past the sign-in: the server is sending the tunnel settings.
                    if ["GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES"].contains(s.name) { noteAccepted() }
                    setState(id, Self.map(s))
                }
            case .forti:
                if fortiIsConnected(p, log: log) {
                    noteAccepted()
                    return (VPNLog.fortiAddress(log) ?? "", clock.now())
                }
            case .anyconnect:
                if let report = VPNLog.openConnectReport(log) { return (report.addresses.first?.description ?? "", clock.now()) }
            }

            let now = clock.now()
            if now.timeIntervalSince(lastProcessCheck) >= timing.processCheckInterval {
                lastProcessCheck = now
                if let r = try? await helper.perform(.status, timeout: timing.helperTimeout), r.ok,
                    (r.running ?? [:])[id] == nil
                {
                    try checkToken(id, token)
                    // Stopped by a disconnect in another process (app ↔ CLI): a cancel, not a failure.
                    if hasUserStoppedMarker(id) { throw PTError.connectCancelled }
                    let final = VPNLog.read(logURL)
                    if p.type == .anyconnect { throw anyConnectFailure(final, exited: true) ?? PTError.connectFailed(VPNLog.tail(final)) }
                    if VPNLog.isAuthFailure(final) { throw PTError.authFailed(VPNLog.tail(final)) }
                    throw ended(p, log: final, exited: true)
                }
            }
            if clock.now().timeIntervalSince(started) >= timeout {
                if owned { await stopQuietly(id) }
                // Cisco AnyConnect: the sign-in reached the server already.
                if p.type == .anyconnect { throw PTError.connectTimeout(Int(timeout)) }
                throw unreached(p, log: VPNLog.read(logURL), timeout: timeout) ?? PTError.connectTimeout(Int(timeout))
            }
            do { try await clock.sleep(timing.connectCheckInterval) } catch { throw PTError.connectCancelled }
        }
    }

    /// Why the tunnel run of a Cisco AnyConnect session failed, from its log: the hook's failure line
    /// (`PTError.setupFailed`: it reverted the network and stopped openconnect), the server ending the session
    /// ("Cookie was rejected by server", "Session terminated by server"), and, once the tool has `exited`,
    /// dyld having stopped it (`toolUnsupported`). nil when the log shows none of them.
    private func anyConnectFailure(_ log: String, exited: Bool) -> PTError? {
        if case .failed(let reason) = VPNLog.openConnectHook(log) { return .setupFailed(reason: reason, log: VPNLog.tail(log)) }
        if exited, let reason = VPNLog.toolLoadFailure(log) { return .toolUnsupported(reason: reason, log: VPNLog.tail(log)) }
        if VPNLog.openConnectServerEnd(log) != nil { return .connectFailed(VPNLog.tail(log)) }
        return nil
    }

    /// An OpenVPN session whose DNS hook or all-traffic routes failed is unusable (another VPN is in
    /// the way): stop it (when ours) and fail instead of reporting it connected. On Linux the same for a
    /// FortiGate session whose DNS passtunneld could not set (it ends the session itself as well).
    private func checkSetup(_ p: Profile, log: String, owned: Bool) async throws {
        guard p.type == .openvpn || Self.daemonSetsFortiDNS, let problem = VPNLog.setupProblem(log), problem.allTraffic else {
            return
        }
        if owned { await stopQuietly(p.id) }
        throw PTError.setupFailed(reason: problem.reason, log: VPNLog.tail(log))
    }

    /// Linux: passtunneld sets a FortiGate session's DNS itself (docs/LINUX.md, "DNS"); on the Mac
    /// openfortivpn does, and nothing is waited for.
    #if os(Linux)
    static let daemonSetsFortiDNS = true
    #else
    static let daemonSetsFortiDNS = false
    #endif

    /// A FortiGate session is connected once openfortivpn's tunnel is up and, where passtunneld sets the
    /// DNS of a profile with `set_dns`, once it said how that went.
    func fortiIsConnected(_ p: Profile, log: String) -> Bool {
        guard VPNLog.fortiIsUp(log) else { return false }
        return !(Self.daemonSetsFortiDNS && p.setDNS) || VPNLog.fortiDNSSettled(log)
    }

    private func checkToken(_ id: String, _ token: Int) throws {
        if actionToken[id] != token { throw PTError.connectCancelled }
    }

    private func stopQuietly(_ id: String) async {
        _ = try? await helper.perform(.stop(profileID: id), timeout: timing.stopTimeout)
    }

    // MARK: drops and auto-reconnect

    /// True when the profile may be reconnected without asking: enabled, unattended, secrets present.
    public func canAutoReconnect(_ p: Profile) -> Bool {
        guard p.autoReconnect, p.unattended else { return false }
        if p.passwordMode == .keychain && !Secrets.has(p.id, .password) { return false }
        if p.otpMode == .totp && !Secrets.has(p.id, .totp) { return false }
        return true
    }

    /// `afterWake`: the drop was found right after the Mac woke up; reconnect at once, or, for a profile
    /// that requires a confirmation to connect, ask the user (`droppedWhileAsleep`) rather than prompt.
    private func handleDrop(_ p: Profile, afterWake: Bool) {
        let willReconnect = canAutoReconnect(p)
        if afterWake && willReconnect && vault.requiresConfirmation(p) {
            endSessionSecrets(p.id)
            record(p.id, .linkDropped(willReconnect: false))
            events.send(.droppedWhileAsleep(profileID: p.id))
            return
        }
        if willReconnect && stopsForChangedDestination(p) {
            record(p.id, .linkDropped(willReconnect: false))
            return
        }
        record(p.id, .linkDropped(willReconnect: willReconnect))
        events.send(.dropped(profileID: p.id, willReconnect: willReconnect))
        if willReconnect { scheduleReconnect(p.id, immediate: afterWake) } else { endSessionSecrets(p.id) }
    }

    /// Cancels a pending automatic reconnect and the retries of an unreachable server (any manual action
    /// does this).
    public func cancelReconnect(_ id: String) {
        reconnectGen[id, default: 0] += 1
        reconnectTasks.removeValue(forKey: id)?.cancel()
        reconnecting[id] = nil
        endRetry(id, .cancelled)
    }

    private func scheduleReconnect(_ id: String, immediate: Bool) {
        cancelReconnect(id)
        let gen = reconnectGen[id]!
        let first = immediate ? 0 : (timing.reconnectDelays.first ?? 0)
        reconnecting[id] = ReconnectInfo(
            attempt: 1, maxAttempts: timing.reconnectDelays.count,
            at: clock.now().addingTimeInterval(first))
        reconnectTasks[id] = Task { [weak self] in
            await self?.runReconnect(id, gen: gen, immediate: immediate)
        }
    }

    private func runReconnect(_ id: String, gen: Int, immediate: Bool) async {
        let delays = timing.reconnectDelays
        var reason = ""
        var unreachableTries = 0  // of the attempts in a row that found the server unreachable
        defer {
            if reconnectGen[id] == gen {
                reconnecting[id] = nil
                reconnectTasks[id] = nil
            }
        }
        for (i, delay) in delays.enumerated() {
            guard reconnectGen[id] == gen else { return }
            let wait = (i == 0 && immediate) ? 0 : delay
            reconnecting[id] = ReconnectInfo(
                attempt: i + 1, maxAttempts: delays.count,
                at: clock.now().addingTimeInterval(wait))
            // After a failed attempt; before the first one, the drop says it reconnects.
            if i > 0 && wait > 0 { record(id, .nextTry(at: clock.now().addingTimeInterval(wait))) }
            do { try await clock.sleep(wait) } catch { return }
            guard reconnectGen[id] == gen else { return }
            if state(id).isConnected {
                events.send(.reconnected(profileID: id))
                return
            }
            record(id, .reconnecting(attempt: i + 1, of: delays.count))
            do {
                try await performConnect(id, given: [:], interactive: false)
                guard reconnectGen[id] == gen else { return }
                if state(id).isConnected {
                    events.send(.reconnected(profileID: id))
                    return
                }
            } catch {
                guard reconnectGen[id] == gen else { return }
                if error is DestinationChangedError { return reportChangedDestination(id) }
                reason = error.localizedDescription
                unreachableTries = failures[id]?.kind == .unreachable ? unreachableTries + (failures[id]?.tries ?? 1) : 0
                if !Self.isRetryable(error) { break }
            }
        }
        guard reconnectGen[id] == gen else { return }
        // A server that does not answer is tried on (decision D-7); the session's secrets stay for it.
        if beginRetryIfUnreachable(id, afterDrop: true, tries: unreachableTries) { return }
        endSessionSecrets(id)
        events.send(.reconnectFailed(profileID: id, reason: reason))
    }

    /// The session's secrets were dropped because the destination changed and connecting needs a
    /// confirmation: tells the user (`destinationChanged`) instead of reconnecting. Returns true then.
    /// `stillConnected`: the health check asked, the tunnel was not stopped.
    private func stopsForChangedDestination(_ p: Profile, stillConnected: Bool = false) -> Bool {
        guard changedDestinations.contains(p.id), vault.requiresConfirmation(p) else { return false }
        reportChangedDestination(p.id, stillConnected: stillConnected)
        return true
    }

    private func reportChangedDestination(_ id: String, stillConnected: Bool = false) {
        endSessionSecrets(id)
        changedDestinations.remove(id)
        events.send(.destinationChanged(profileID: id, stillConnected: stillConnected))
    }

    /// Wrong credentials or missing secrets will not fix themselves; retrying could lock the account.
    static func isRetryable(_ error: Error) -> Bool {
        if error is DestinationChangedError || error is ProtectionKeyMismatch || error is KeychainItemNotReplaced
            || error is SecretStoreUnavailable
        {
            return false
        }
        switch error as? PTError {
        case .authFailed, .missingPassword, .missingTOTPSecret, .missingCredential, .missingConfig,
            .missingHost, .usernameTooLong, .invalidSecret, .profileNotFound, .otherVPNActive, .setupFailed,
            .userConfirmationCancelled, .userConfirmationFailed, .confirmationRequired, .protectedSecretUnreadable,
            .protectionUnavailable, .anyConnectRequiresMacOS, .anyConnectNotSupported, .hostScanRequired,
            .serverCertificateRejected, .signInNeedsMoreAnswers, .signInUnusable:
            return false
        default:
            return true
        }
    }

    // MARK: unreachable server

    /// The retries of each profile, shared through its directory for the CLI and the MCP server.
    static let sharedRetryFile = ".retry"

    struct SharedRetry: Codable, Equatable {
        var writer: Int32  // the process that runs the retries; ignored once that is gone
        var retry: UnreachableRetry
    }

    /// With `retriesUnreachable`, after a connect or a drop's reconnects that ended `unreachable` (the
    /// server never answered, so nothing was sent): tries it again every `unreachableRetryDelay` seconds,
    /// at most `unreachableMaxTries` times. `host_not_found`, a rejected sign-in and any other failure are
    /// not retried. `afterDrop`: the end is reported as the reconnect's (`reconnected`,
    /// `reconnectFailed`). `tries`: the tries that already found it unreachable (default: the failure's).
    @discardableResult
    private func beginRetryIfUnreachable(_ id: String, afterDrop: Bool, tries: Int? = nil) -> Bool {
        guard retriesUnreachable, let failure = failures[id], failure.kind == .unreachable, unreachableRetries[id] == nil,
            !hasUserStoppedMarker(id)
        else { return false }
        retryGen[id, default: 0] += 1
        if afterDrop { retryAfterDrop.insert(id) } else { retryAfterDrop.remove(id) }
        setRetry(
            id,
            UnreachableRetry(
                tries: max(1, tries ?? failure.tries ?? 1), maxTries: max(1, timing.unreachableMaxTries),
                firstFailedAt: failure.at, lastFailedAt: failure.at))
        scheduleRetry(id, after: timing.unreachableRetryDelay)
        return true
    }

    /// The next try after `delay` seconds, or the end after the last one. While offline nothing is
    /// scheduled: the try waits for the network (`networkChanged`).
    private func scheduleRetry(_ id: String, after delay: TimeInterval) {
        guard var retry = unreachableRetries[id] else { return }
        retryWaits.removeValue(forKey: id)?.cancel()
        guard retry.tries < retry.maxTries else { return endRetry(id, .failed) }
        retryGen[id, default: 0] += 1
        retry.waitingForNetwork = networkStatus.online == false
        guard !retry.waitingForNetwork else {
            retry.nextTryAt = nil
            return setRetry(id, retry)
        }
        let at = clock.now().addingTimeInterval(delay)
        retry.nextTryAt = at
        setRetry(id, retry)
        if delay > 0 { record(id, .nextTry(at: at)) }
        let gen = retryGen[id]!
        let clock = self.clock
        retryWaits[id] = Task { [weak self] in
            do { try await clock.sleep(delay) } catch { return }
            guard let self, self.retryGen[id] == gen else { return }
            self.retryWaits[id] = nil
            await self.runRetry(id, gen: gen)
        }
    }

    /// "Try now": the next try of `id` starts at once (it counts like the others), also while offline.
    /// False when there are no retries or a try is under way.
    @discardableResult
    public func retryNow(_ id: String) -> Bool {
        guard unreachableRetries[id] != nil, !retryRunning.contains(id) else { return false }
        retryWaits.removeValue(forKey: id)?.cancel()
        retryGen[id, default: 0] += 1
        let gen = retryGen[id]!
        Task { await self.runRetry(id, gen: gen, anyNetwork: true) }
        return true
    }

    /// One try: a connect that never asks (`interactive: false`: a protected profile uses the secrets its
    /// session or the reuse window holds, else it stops with `confirmationRequired`) and sends a fresh
    /// code (the code of a try that never reached the server is given back, `noteFailure`).
    private func runRetry(_ id: String, gen: Int, anyNetwork: Bool = false) async {
        guard retryGen[id] == gen, var retry = unreachableRetries[id], !retryRunning.contains(id) else { return }
        if hasUserStoppedMarker(id) { return endRetry(id, .cancelled) }
        if state(id).isConnected { return endRetry(id, .connected) }
        retry.nextTryAt = nil
        retry.waitingForNetwork = !anyNetwork && networkStatus.online == false
        setRetry(id, retry)
        guard !retry.waitingForNetwork else { return }
        retryRunning.insert(id)
        do {
            try await performConnect(id, given: [:], interactive: false)
            retryRunning.remove(id)
            guard retryGen[id] == gen else { return }
            endRetry(id, state(id).isConnected ? .connected : .cancelled)
        } catch {
            retryRunning.remove(id)
            guard retryGen[id] == gen, var retry = unreachableRetries[id] else { return }
            if error is DestinationChangedError && retryAfterDrop.contains(id) {
                endRetry(id, .cancelled)
                return reportChangedDestination(id)
            }
            guard let failure = failures[id], failure.kind == .unreachable else { return endRetry(id, .failed) }
            retry.tries = failure.tries ?? retry.tries + 1
            retry.lastFailedAt = failure.at
            setRetry(id, retry)
            let restarted = retryNetworkChanged.remove(id) != nil
            scheduleRetry(id, after: restarted ? timing.networkSettleDelay : timing.unreachableRetryDelay)
        }
    }

    private enum RetryEnd { case connected, failed, cancelled }

    private func endRetry(_ id: String, _ end: RetryEnd) {
        guard unreachableRetries[id] != nil else { return }
        retryGen[id, default: 0] += 1
        retryWaits.removeValue(forKey: id)?.cancel()
        retryNetworkChanged.remove(id)
        setRetry(id, nil)
        guard retryAfterDrop.remove(id) != nil else { return }
        switch end {
        case .connected:
            events.send(.reconnected(profileID: id))
        case .failed:
            endSessionSecrets(id)
            events.send(.reconnectFailed(profileID: id, reason: lastError[id] ?? ""))
        case .cancelled:
            break
        }
    }

    /// A new network path (kept in `networkStatus`). Online again, or on another network, the retries
    /// start over: their count from zero, the next try after `networkSettleDelay`. Offline, they wait.
    func networkChanged(_ new: NetworkStatus) {
        let old = networkStatus
        guard new != old else { return }
        networkStatus = new
        guard old.online != nil else { return }  // the first answer, not a change
        for id in Array(unreachableRetries.keys) {
            guard var retry = unreachableRetries[id] else { continue }
            if new.online == false {
                guard !retryRunning.contains(id) else { continue }
                retryWaits.removeValue(forKey: id)?.cancel()
                retryGen[id, default: 0] += 1
                retry.nextTryAt = nil
                retry.waitingForNetwork = true
                setRetry(id, retry)
                continue
            }
            retry.tries = 0
            setRetry(id, retry)
            if retryRunning.contains(id) {
                retryNetworkChanged.insert(id)
            } else {
                scheduleRetry(id, after: timing.networkSettleDelay)
            }
        }
    }

    private func sharedRetryURL(_ id: String) -> URL { store.dir(id).appendingPathComponent(Self.sharedRetryFile) }

    /// Publishes the retries of `id` and shares them through its directory (nil: they ended).
    private func setRetry(_ id: String, _ retry: UnreachableRetry?) {
        if unreachableRetries[id] != retry { unreachableRetries[id] = retry }
        guard let retry else { return removeSharedRetry(id) }
        guard FileManager.default.fileExists(atPath: store.dir(id).path) else { return }
        try? JSONCoding.write(SharedRetry(writer: getpid(), retry: retry), to: sharedRetryURL(id), mode: 0o600)
    }

    private func removeSharedRetry(_ id: String) {
        try? FileManager.default.removeItem(at: sharedRetryURL(id))
    }

    /// The retries of `id`: this manager's, else those another live process (the app) shares.
    public func unreachableRetry(_ id: String) -> UnreachableRetry? {
        if let own = unreachableRetries[id] { return own }
        guard let shared = try? JSONCoding.read(SharedRetry.self, from: sharedRetryURL(id)), shared.writer != getpid(),
            kill(shared.writer, 0) == 0 || errno == EPERM
        else { return nil }
        return shared.retry
    }

    /// "Copy details" of the last failure of `id`: a plain-text summary for the user's IT team (no
    /// password, code or user name; the tool's reason redacted as the log is). nil without a failure.
    public func failureDetails(_ id: String, app: AppInfo = .current) -> FailureDetails? {
        guard let p = try? store.get(id), let failure = failures[id] else { return nil }
        var server = serverAddress(p)
        if case let .connecting(_, _, transport) = connectingEvent(p), !server.isEmpty { server += " (\(transport.uppercased()))" }
        return FailureDetails(
            profileName: p.name, server: server, failure: AutomationService.redacted(failure, id: id),
            retry: unreachableRetry(id), network: networkStatus, app: app, at: clock.now())
    }

    // MARK: health

    /// Probes `healthHost` of every connected profile once.
    public func runHealthChecks() async {
        let candidates = store.list().filter {
            state($0.id).isConnected && !isBusy($0.id) && !$0.healthHost.trimmingCharacters(in: .whitespaces).isEmpty
        }
        for p in candidates { await checkHealth(p) }
    }

    private func checkHealth(_ p: Profile) async {
        let id = p.id
        let result = await healthProbe(p.healthHost)
        guard state(id).isConnected, !isBusy(id) else { return }
        if result.ok {
            healthFailures[id] = 0
            health[id] = .reachable(ms: result.ms)
            if outage.remove(id) != nil {
                forcedReconnectDone.remove(id)
                events.send(.reachableAgain(profileID: id))
            }
            return
        }
        let failures = (healthFailures[id] ?? 0) + 1
        healthFailures[id] = failures
        guard failures >= timing.healthFailuresForOutage else {
            if health[id] == nil { health[id] = .unknown }
            return
        }
        health[id] = .unreachable
        if outage.insert(id).inserted {
            events.send(.unreachable(profileID: id))
        }
        if canAutoReconnect(p), forcedReconnectDone.insert(id).inserted, !stopsForChangedDestination(p, stillConnected: true) {
            forceReconnect(id)
        }
    }

    /// Stop + connect once, not reported as a drop. Cancelled by any manual action.
    private func forceReconnect(_ id: String) {
        cancelReconnect(id)
        let gen = reconnectGen[id]!
        reconnectTasks[id] = Task { [weak self] in
            guard let self else { return }
            defer { if self.reconnectGen[id] == gen { self.reconnectTasks[id] = nil } }
            self.actionToken[id, default: 0] += 1
            self.sessionActive.remove(id)
            self.begin(id)
            _ = try? await self.helper.perform(.stop(profileID: id), timeout: self.timing.stopTimeout)
            self.end(id)
            guard self.reconnectGen[id] == gen else { return }
            self.setState(id, .disconnected)
            self.record(id, .reconnecting(attempt: 1, of: 1))
            do {
                try await self.performConnect(id, given: [:], interactive: false)
                guard self.reconnectGen[id] == gen else { return }
                self.events.send(.reconnected(profileID: id))
            } catch {
                guard self.reconnectGen[id] == gen else { return }
                if error is DestinationChangedError { return self.reportChangedDestination(id) }
                if self.beginRetryIfUnreachable(id, afterDrop: true) { return }
                self.events.send(.reconnectFailed(profileID: id, reason: error.localizedDescription))
            }
        }
    }

    // MARK: sleep / wake

    /// Remembers what is connected and forgets every confirmation: whoever is at the Mac after it
    /// wakes up confirms again.
    public func handleWillSleep() {
        connectedBeforeSleep = Set(states.filter { $0.value.isConnected }.map(\.key))
        sleeping = true
        vault.reset()
    }

    /// Polls after `wakeDelay`, probes health and reconnects eligible profiles that were connected
    /// before sleep. Profiles that require a confirmation to connect are not reconnected: the user
    /// gets `droppedWhileAsleep` and reconnects (and confirms) from there.
    public func handleDidWake() async {
        try? await clock.sleep(timing.wakeDelay)
        sleeping = false
        let before = connectedBeforeSleep
        connectedBeforeSleep = []
        var asked = Set<String>()
        let sub = events.sink { event in
            if case .droppedWhileAsleep(let id) = event { asked.insert(id) }
        }
        await refresh(wakeIDs: before)
        sub.cancel()
        await runHealthChecks()
        for id in before where state(id) == .disconnected && reconnectTasks[id] == nil && !isBusy(id) {
            guard let p = try? store.get(id), canAutoReconnect(p), !hasUserStoppedMarker(id) else { continue }
            if vault.requiresConfirmation(p) {
                endSessionSecrets(id)
                if !asked.contains(id) { events.send(.droppedWhileAsleep(profileID: id)) }
                continue
            }
            scheduleReconnect(id, immediate: true)
        }
    }

    // MARK: session limit

    private func checkSessionLimit(_ p: Profile, start: Date) {
        guard p.sessionLimitMin > 0, sessionWarned[p.id] != start else { return }
        let notify = preferences().sessionNotifyMin
        guard notify > 0, notify < p.sessionLimitMin else { return }
        let remaining = Double(p.sessionLimitMin) - clock.now().timeIntervalSince(start) / 60
        guard remaining <= Double(notify), remaining > 0 else { return }
        sessionWarned[p.id] = start
        events.send(.sessionEnding(profileID: p.id, minutes: Int(remaining.rounded(.up))))
    }

    // MARK: clock

    /// `profiles/<id>/clock.json`: the profile's last clock measurement (`ClockOffset`), for the other
    /// processes (the app, the CLI's `diagnose`).
    static let clockFile = "clock.json"

    /// After a FortiGate rejected a sign-in this manager sent: one request to the gateway for its time
    /// (`ServerClock`), in the background. The result is kept for the profile (`clockOffsets`,
    /// `clock.json`) and added to the failure if that is still the profile's last one. Never at launch,
    /// never for OpenVPN (its servers tell no reliable time).
    private func checkGatewayClock(_ id: String, after failure: ConnectionFailure) {
        guard let p = try? store.get(id), p.type == .forti else { return }
        let host = p.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard FortiConfig.isValidHost(host) else { return }
        let port = p.port
        let pin = TLSFingerprint.normalize(p.trustedCert)
        let checker = serverClock
        clockCheckSeq += 1
        let seq = clockCheckSeq
        clockChecks[id] = (
            seq,
            Task { [weak self] in
                let measured = try? await checker.gateway(host: host, port: port, trustedCert: pin, timeout: ServerClock.gatewayTimeout)
                guard let self else { return }
                if self.clockChecks[id]?.seq == seq { self.clockChecks[id] = nil }
                guard let measured else { return }
                self.noteClock(id, measured)
                if self.failures[id] == failure { self.failures[id]?.clock = measured }
            }
        )
    }

    /// Returns once the clock check started after `id`'s last rejected sign-in has finished (at most
    /// `ServerClock.gatewayTimeout`), so a failure reported right after it carries the measurement.
    public func clockCheckFinished(_ id: String) async {
        await clockChecks[id]?.task.value
    }

    /// On request only (the app's Check button, `diagnose --check-clock`): asks the time server
    /// (`ServerClock.timeServer`). The result is also added to each rejected sign-in's failure that has
    /// no newer measurement.
    public func checkClock() async throws -> ClockOffset {
        let measured = try await serverClock.timeServer(timeout: ServerClock.timeServerTimeout)
        timeServerClock = measured
        for (id, failure) in failures
        where failure.kind == .authRejected
            && (failure.clock?.checkedAt ?? .distantPast) <= measured.checkedAt
        {
            failures[id]?.clock = measured
        }
        return measured
    }

    /// The last clock measurement for `id`: the newer of this process's and the one in `clock.json`.
    public func lastClock(_ id: String) -> ClockOffset? {
        let saved = try? JSONCoding.read(ClockOffset.self, from: store.dir(id).appendingPathComponent(Self.clockFile))
        return [saved, clockOffsets[id]].compactMap { $0 }.max { $0.checkedAt < $1.checkedAt }
    }

    private func noteClock(_ id: String, _ measured: ClockOffset) {
        clockOffsets[id] = measured
        guard FileManager.default.fileExists(atPath: store.dir(id).path) else { return }
        try? JSONCoding.write(measured, to: store.dir(id).appendingPathComponent(Self.clockFile), mode: 0o600)
    }

    // MARK: activity

    /// The profile's activity, oldest first, as every process recorded it (`ActivityLog`).
    public func activity(_ id: String) -> [ActivityEvent] {
        ActivityLog(url: store.activityURL(id)).read()
    }

    /// The last `sending` in the activity: when the credentials went to the VPN tool, and the code's seconds
    /// left then ("sent at 09:41:02", "Sent with 22 s left").
    public func lastSending(_ id: String) -> (at: Date, sending: ActivityEvent.Sending)? {
        ActivityEvent.lastSending(in: activity(id))
    }

    /// Appends to the profile's `activity.jsonl` (best effort: a log that cannot be written never fails a
    /// connection) and publishes it on `activity`.
    private func record(_ id: String, _ kind: ActivityEvent.Kind) {
        let event = ActivityEvent(at: clock.now(), kind)
        try? ActivityLog(url: store.activityURL(id)).append(event)
        activity.send(ActivityRecord(profileID: id, event: event))
    }

    /// Where `p` connects: OpenVPN's first `remote` with its port and transport, FortiGate's host and port.
    private func connectingEvent(_ p: Profile) -> ActivityEvent.Kind {
        switch p.type {
        case .openvpn:
            let config = (try? FileIO.readText(store.ovpnURL(p.id), maxSize: ProfileStore.maxOVPNSize)) ?? ""
            guard let e = OVPNAnalyzer.endpoint(config) else { return .connecting(host: "", port: nil, transport: "udp") }
            return .connecting(host: ActivityEvent.clean(e.host, limit: 255), port: Int(e.port), transport: e.tcp ? "tcp" : "udp")
        case .forti, .anyconnect:
            return .connecting(host: ActivityEvent.clean(p.host, limit: 255), port: p.port, transport: "tcp")
        }
    }

    /// What was handed to the VPN tool, without the password; `codeTime` when the code came from the TOTP secret.
    private func sending(_ p: Profile, username: String, password: String, otp: String?, codeTime: Date?) -> ActivityEvent.Sending {
        let code = otp.map { !$0.isEmpty } ?? false
        var left: Int?
        if let codeTime {
            let period = TimeInterval(max(1, p.totp.period))
            let end = TimeInterval(TOTP.counter(params: p.totp, at: codeTime) + 1) * period
            left = Int(max(0, end - clock.now().timeIntervalSince1970).rounded(.down))
        }
        return ActivityEvent.Sending(
            username: ActivityEvent.clean(username, limit: 256), password: !password.isEmpty, code: code,
            codePrefix: code ? ActivityEvent.codePrefix(otp) : nil, secondsLeft: code ? left : nil,
            format: code ? (p.otpDelivery == .separate ? "separate" : p.otpTemplate) : nil)
    }

    // MARK: bookkeeping

    private func setState(_ id: String, _ s: ConnectionState) {
        if states[id] != s { states[id] = s }
    }

    private func endSession(_ id: String) {
        connectedAt[id] = nil
        warnings[id] = nil
        sessionWarned[id] = nil
        health[id] = nil
        healthFailures[id] = nil
        outage.remove(id)
        forcedReconnectDone.remove(id)
    }

    private func forget(_ id: String) {
        cancelReconnect(id)
        endSessionSecrets(id)
        changedDestinations.remove(id)
        vault.reset(id)
        endSession(id)
        sharedStates[id] = nil
        management.release(socketPath: mgmtSockets[id] ?? socketPath(id))
        states[id] = nil
        lastError[id] = nil
        lastErrorLog[id] = nil
        failures[id] = nil
        clockOffsets[id] = nil
        sessionActive.remove(id)
        userStopped.remove(id)
    }

    /// Marks the profile busy and makes in-flight polls stale.
    private func begin(_ id: String) {
        busy[id, default: 0] += 1
        appliedSeq = pollSeq
    }

    private func end(_ id: String) {
        let n = (busy[id] ?? 1) - 1
        busy[id] = n > 0 ? n : nil
        appliedSeq = pollSeq
    }

    private func isBusy(_ id: String) -> Bool { busy[id] != nil }

    func isBusyForTests(_ id: String) -> Bool { isBusy(id) }

    /// Where the helper puts our OpenVPN socket; used when no reply has named it (e.g. helper unreachable).
    private func socketPath(_ id: String) -> String {
        PT.mgmtSocketPath(uid: geteuid(), profileID: id)
    }

    /// File marker so a disconnect made by another process (app ↔ CLI) is not seen as a drop.
    private func setUserStoppedMarker(_ id: String, _ on: Bool) {
        let url = store.dir(id).appendingPathComponent(Self.userStoppedMarker)
        if on {
            guard FileManager.default.fileExists(atPath: store.dir(id).path) else { return }
            try? FileIO.writeAtomically(Data(), to: url, mode: 0o600)
        } else {
            try? FileManager.default.removeItem(at: url)
        }
    }

    private func hasUserStoppedMarker(_ id: String) -> Bool {
        FileManager.default.fileExists(atPath: store.dir(id).appendingPathComponent(Self.userStoppedMarker).path)
    }
}
