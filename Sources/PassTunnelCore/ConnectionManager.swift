import Combine
import Foundation
import PassTunnelShared
#if canImport(AppKit)
import AppKit
#endif

// MARK: - Public types

public enum ConnectionState: Equatable, Sendable {
    case disconnected
    case connecting(String)                    // localized phase, e.g. "Signing in…"
    case connected(ip: String, since: Date?)

    public var isConnected: Bool { if case .connected = self { return true }; return false }
    public var isConnecting: Bool { if case .connecting = self { return true }; return false }
    /// Connected or on the way there.
    public var isActive: Bool { self != .disconnected }
}

/// Result of the periodic reachability probe of `Profile.healthHost` while connected.
public enum HealthState: Equatable, Sendable {
    case unknown                               // not probed yet, or one failure so far
    case reachable(ms: Int)
    case unreachable                           // consecutive failures: "connected but unreachable"
}

/// A pending automatic reconnect after a drop.
public struct ReconnectInfo: Equatable, Sendable {
    public var attempt: Int                    // 1-based
    public var maxAttempts: Int
    public var at: Date                        // when the attempt starts
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

    public var profileID: String {
        switch self {
        case .dropped(let id, _), .reconnected(let id), .reconnectFailed(let id, _), .unreachable(let id),
             .reachableAgain(let id), .sessionEnding(let id, _):
            return id
        }
    }
}

/// The helper calls the manager needs; `HelperClient` in production, a fake in tests.
public protocol HelperClienting: AnyObject {
    func perform(_ request: HelperRequest, timeout: TimeInterval?) async throws -> HelperResponse
}

extension HelperClient: HelperClienting {}

/// Reads OpenVPN's state from its management socket.
public protocol ManagementQuerying {
    func state(socketPath: String, timeout: TimeInterval) async throws -> ManagementState
}

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
        public var connectCheckInterval: TimeInterval = 0.5
        public var processCheckInterval: TimeInterval = 2
        public var reconnectDelays: [TimeInterval] = [5, 15, 45]
        public var minCodeSeconds: TimeInterval = 8
        public var wakeDelay: TimeInterval = 4
        public var healthFailuresForOutage = 2
        public var helperTimeout: TimeInterval = 15
        public var stopTimeout: TimeInterval = 20
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

    static let userStoppedMarker = ".user-stopped"

    @Published public private(set) var states: [String: ConnectionState] = [:]
    @Published public private(set) var lastError: [String: String] = [:]
    /// Log excerpt for the last error (tooltip / "Show log").
    @Published public private(set) var lastErrorLog: [String: String] = [:]
    @Published public private(set) var health: [String: HealthState] = [:]
    @Published public private(set) var reconnecting: [String: ReconnectInfo] = [:]
    /// Why the last helper `status` call failed (nil when it worked).
    @Published public private(set) var helperError: String?

    public let events = PassthroughSubject<ConnectionEvent, Never>()

    public let store: ProfileStore
    public var timing: Timing
    private let helper: HelperClienting
    private let management: ManagementQuerying
    private let clock: ConnectionClock
    private let healthProbe: HealthProbe
    private let preferences: () -> Preferences

    private var pollSeq = 0
    private var appliedSeq = 0
    private var busy: [String: Int] = [:]                 // actions in flight per profile
    private var actionToken: [String: Int] = [:]          // bumped by disconnect: cancels a running connect
    private var userStopped: Set<String> = []
    private var sessionActive: Set<String> = []           // reached "connected" in the current session
    private var connectedAt: [String: Date] = [:]
    private var reconnectGen: [String: Int] = [:]
    private var reconnectTasks: [String: Task<Void, Never>] = [:]
    private var healthFailures: [String: Int] = [:]
    private var outage: Set<String> = []
    private var forcedReconnectDone: Set<String> = []
    private var sessionWarned: [String: Date] = [:]       // session start that was already warned about
    private var connectedBeforeSleep: Set<String> = []
    private var sleeping = false
    private var loops: [Task<Void, Never>] = []
    private var observers: [NSObjectProtocol] = []
    public private(set) var isRunning = false

    public init(store: ProfileStore = ProfileStore(),
                helper: HelperClienting = HelperClient.shared,
                management: ManagementQuerying = SocketManagementQuerier(),
                clock: ConnectionClock = SystemClock(),
                healthProbe: @escaping HealthProbe = ConnectionManager.defaultHealthProbe,
                preferences: @escaping () -> Preferences = { Preferences.load() },
                timing: Timing = Timing()) {
        self.store = store
        self.helper = helper
        self.management = management
        self.clock = clock
        self.healthProbe = healthProbe
        self.preferences = preferences
        self.timing = timing
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
        loops.append(Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                if !self.sleeping { await self.refresh() }
                do { try await self.clock.sleep(self.timing.pollInterval) } catch { return }
            }
        })
        loops.append(Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                do { try await self.clock.sleep(self.timing.healthInterval) } catch { return }
                if !self.sleeping { await self.runHealthChecks() }
            }
        })
        #if canImport(AppKit)
        let nc = NSWorkspace.shared.notificationCenter
        observers.append(nc.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.handleWillSleep() }
        })
        observers.append(nc.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
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
        for id in Array(reconnectTasks.keys) { cancelReconnect(id) }
    }

    // MARK: polling

    /// Reads the state of every profile once and applies it unless a newer poll or an action
    /// happened meanwhile.
    public func refresh() async {
        await refresh(wakeIDs: [])
    }

    private func refresh(wakeIDs: Set<String>) async {
        pollSeq += 1
        let seq = pollSeq
        let profiles = store.list()

        var running: [String: Int32]?
        do {
            let r = try await helper.perform(.status, timeout: timing.helperTimeout)
            if r.ok {
                running = r.running ?? [:]
                helperError = nil
            } else {
                helperError = r.error ?? ""
            }
        } catch {
            helperError = error.localizedDescription
        }

        var observed: [String: ConnectionState] = [:]
        for p in profiles where !isBusy(p.id) {
            observed[p.id] = await observe(p, running: running)
        }
        guard seq > appliedSeq else { return }   // stale: a newer poll or an action got in first
        appliedSeq = seq

        let ids = Set(profiles.map(\.id))
        for id in states.keys where !ids.contains(id) { forget(id) }
        for p in profiles {
            guard let new = observed[p.id], !isBusy(p.id) else { continue }
            apply(new, to: p, immediateReconnect: wakeIDs.contains(p.id))
        }
    }

    private func observe(_ p: Profile, running: [String: Int32]?) async -> ConnectionState {
        let isRunning = running?[p.id] != nil
        switch p.type {
        case .openvpn:
            if running != nil && !isRunning { return .disconnected }
            if let s = try? await management.state(socketPath: socketPath(p.id), timeout: 2) {
                return Self.map(s)
            }
            return isRunning ? .connecting(Phase.starting) : .disconnected
        case .forti:
            guard isRunning else { return .disconnected }
            let log = VPNLog.read(store.logURL(p.id))
            guard VPNLog.fortiIsUp(log) else { return .connecting(Phase.connecting) }
            let created = (try? FileManager.default.attributesOfItem(atPath: store.logURL(p.id).path))?[.creationDate] as? Date
            return .connected(ip: VPNLog.fortiAddress(log) ?? "", since: connectedAt[p.id] ?? created)
        }
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
            }
            let start = connectedAt[id] ?? since ?? clock.now()
            connectedAt[id] = start
            checkSessionLimit(p, start: start)
        case .connecting:
            break
        case .disconnected:
            guard sessionActive.remove(id) != nil else { break }
            endSession(id)
            if userStopped.remove(id) != nil || hasUserStoppedMarker(id) { break }
            handleDrop(p, immediate: immediateReconnect)
        }
    }

    // MARK: actions

    /// Connects `id`. `given` supplies the fields the profile asks for (`Profile.needs`).
    /// Returns once connected; cancels any pending automatic reconnect.
    public func connect(_ id: String, given: [CredentialField: String] = [:]) async throws {
        cancelReconnect(id)
        try await performConnect(id, given: given)
    }

    /// Stops `id` (also cancels a connect in progress) and marks it user-stopped so the exit is not
    /// reported as a drop.
    public func disconnect(_ id: String) async throws {
        cancelReconnect(id)
        actionToken[id, default: 0] += 1
        userStopped.insert(id)
        setUserStoppedMarker(id, true)
        sessionActive.remove(id)
        endSession(id)
        begin(id)
        defer { end(id) }
        let r = try await helper.perform(.stop(profileID: id), timeout: timing.stopTimeout)
        setState(id, .disconnected)
        guard r.ok else { throw PTError.helperFailed(r.error ?? "") }
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

    private func performConnect(_ id: String, given: [CredentialField: String]) async throws {
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
        setState(id, .connecting(Phase.preparing))

        do {
            // Always the profile as stored now (the CLI may have changed it), never a cached copy.
            let p = try store.get(id)
            let creds = try resolveCredentials(p, given: given)

            var otp = creds.otp
            if let secret = creds.totpSecret {
                try await waitForFreshCode(p, token: token)
                otp = TOTP.code(secret: secret, params: p.totp, at: clock.now())
            }
            try checkToken(id, token)
            setState(id, .connecting(Phase.starting))

            let composed = OTPComposer.compose(password: creds.password ?? "", otp: otp, delivery: p.otpDelivery,
                                               template: p.otpTemplate, type: p.type)
            let request: HelperRequest
            switch p.type {
            case .openvpn:
                request = .startOpenVPN(OpenVPNStart(
                    profileID: id, profileDir: store.dir(id).path, username: creds.username,
                    secret: creds.password == nil ? nil : composed.secret, logPath: store.logURL(id).path))
            case .forti:
                request = .startForti(FortiStart(
                    profileID: id, profileDir: store.dir(id).path, host: p.host, port: p.port,
                    username: creds.username ?? "", password: composed.secret, otp: composed.separateOTP,
                    trustedCert: p.trustedCert, setDNS: p.setDNS, setRoutes: p.setRoutes,
                    logPath: store.logURL(id).path))
            }
            let response = try await helper.perform(request, timeout: timing.helperTimeout)
            guard response.ok else { throw PTError.helperFailed(response.error ?? "") }
            if actionToken[id] != token {
                // Disconnected while the helper was starting the tool; its stop may have come first.
                await stopQuietly(id)
                throw PTError.connectCancelled
            }

            let result = try await waitUntilConnected(p, token: token, socketPath: response.mgmtSocket ?? socketPath(id))
            let since = result.since ?? clock.now()
            setState(id, .connected(ip: result.ip, since: result.since ?? since))
            sessionActive.insert(id)
            connectedAt[id] = since
            healthFailures[id] = 0
            if p.username.trimmingCharacters(in: .whitespaces).isEmpty, let u = creds.username, p.lastUsername != u {
                // Only this field: the profile may have been edited (CLI, editor) while connecting.
                _ = try? store.update(id) { $0.lastUsername = u }
            }
        } catch {
            let cancelled = actionToken[id] != token
            if cancelled { throw PTError.connectCancelled }
            setState(id, .disconnected)
            lastError[id] = error.localizedDescription
            lastErrorLog[id] = (error as? PTError)?.logTail ?? ""
            throw error
        }
    }

    struct Credentials {
        var username: String?
        var password: String?      // nil: certificate only
        var otp: String?           // `.ask` code
        var totpSecret: Data?
    }

    func resolveCredentials(_ p: Profile, given: [CredentialField: String]) throws -> Credentials {
        let id = p.id
        switch p.type {
        case .openvpn:
            guard FileManager.default.fileExists(atPath: store.ovpnURL(id).path) else { throw PTError.missingConfig(id) }
        case .forti:
            guard !p.host.trimmingCharacters(in: .whitespaces).isEmpty else { throw PTError.missingHost(id) }
        }
        if p.passwordMode == .keychain && !Secrets.has(id, .password) { throw PTError.missingPassword(id) }
        if p.otpMode == .totp && !Secrets.has(id, .totp) { throw PTError.missingTOTPSecret(id) }

        func value(_ field: CredentialField) -> String? {
            let v = given[field]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return v.isEmpty ? nil : v
        }
        var c = Credentials()
        if p.type == .openvpn && p.passwordMode == .none { return c }

        let fixed = p.username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let username = fixed.isEmpty ? value(.username) : fixed else { throw PTError.missingCredential(.username) }
        c.username = username

        switch p.passwordMode {
        case .keychain:
            guard let pw = Secrets.get(id, .password) else { throw PTError.missingPassword(id) }
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
            guard let text = Secrets.get(id, .totp) else { throw PTError.missingTOTPSecret(id) }
            c.totpSecret = try TOTP.decodeSecret(text)
        case .ask:
            guard let code = value(.otp) else { throw PTError.missingCredential(.otp) }
            c.otp = code
        }
        return c
    }

    /// Waits for the next TOTP window when fewer than `minCodeSeconds` remain in the current one.
    private func waitForFreshCode(_ p: Profile, token: Int) async throws {
        let period = Double(max(1, p.totp.period))
        guard period > timing.minCodeSeconds else { return }
        let left = period - clock.now().timeIntervalSince1970.truncatingRemainder(dividingBy: period)
        guard left < timing.minCodeSeconds else { return }
        setState(p.id, .connecting(Phase.waitingForCode))
        do { try await clock.sleep(left + 0.25) } catch { throw PTError.connectCancelled }
        try checkToken(p.id, token)
    }

    private func waitUntilConnected(_ p: Profile, token: Int, socketPath: String) async throws -> (ip: String, since: Date?) {
        let id = p.id
        let timeout = p.type == .openvpn ? timing.openVPNTimeout : timing.fortiTimeout
        let started = clock.now()
        var lastProcessCheck = started
        let logURL = store.logURL(id)

        while true {
            try checkToken(id, token)
            let log = VPNLog.read(logURL)
            if VPNLog.isAuthFailure(log) {
                await stopQuietly(id)
                throw PTError.authFailed(VPNLog.tail(log))
            }
            if VPNLog.isFatal(log) {
                await stopQuietly(id)
                throw PTError.connectFailed(VPNLog.tail(log))
            }
            switch p.type {
            case .openvpn:
                if let s = try? await management.state(socketPath: socketPath, timeout: 2) {
                    try checkToken(id, token)
                    if s.isConnected { return (s.localIP.isEmpty ? s.localIPv6 : s.localIP, s.since) }
                    if s.name == "RECONNECTING" && s.detail.lowercased().contains("auth") {
                        await stopQuietly(id)
                        throw PTError.authFailed(VPNLog.tail(VPNLog.read(logURL)))
                    }
                    setState(id, Self.map(s))
                }
            case .forti:
                if VPNLog.fortiIsUp(log) { return (VPNLog.fortiAddress(log) ?? "", clock.now()) }
            }

            let now = clock.now()
            if now.timeIntervalSince(lastProcessCheck) >= timing.processCheckInterval {
                lastProcessCheck = now
                if let r = try? await helper.perform(.status, timeout: timing.helperTimeout), r.ok,
                   (r.running ?? [:])[id] == nil {
                    try checkToken(id, token)
                    let final = VPNLog.read(logURL)
                    if VPNLog.isAuthFailure(final) { throw PTError.authFailed(VPNLog.tail(final)) }
                    throw PTError.connectFailed(VPNLog.tail(final))
                }
            }
            if clock.now().timeIntervalSince(started) >= timeout {
                await stopQuietly(id)
                throw PTError.connectTimeout(Int(timeout))
            }
            do { try await clock.sleep(timing.connectCheckInterval) } catch { throw PTError.connectCancelled }
        }
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

    private func handleDrop(_ p: Profile, immediate: Bool) {
        let willReconnect = canAutoReconnect(p)
        events.send(.dropped(profileID: p.id, willReconnect: willReconnect))
        if willReconnect { scheduleReconnect(p.id, immediate: immediate) }
    }

    /// Cancels a pending automatic reconnect (any manual action does this).
    public func cancelReconnect(_ id: String) {
        reconnectGen[id, default: 0] += 1
        reconnectTasks.removeValue(forKey: id)?.cancel()
        reconnecting[id] = nil
    }

    private func scheduleReconnect(_ id: String, immediate: Bool) {
        cancelReconnect(id)
        let gen = reconnectGen[id]!
        let first = immediate ? 0 : (timing.reconnectDelays.first ?? 0)
        reconnecting[id] = ReconnectInfo(attempt: 1, maxAttempts: timing.reconnectDelays.count,
                                         at: clock.now().addingTimeInterval(first))
        reconnectTasks[id] = Task { [weak self] in
            await self?.runReconnect(id, gen: gen, immediate: immediate)
        }
    }

    private func runReconnect(_ id: String, gen: Int, immediate: Bool) async {
        let delays = timing.reconnectDelays
        var reason = ""
        defer {
            if reconnectGen[id] == gen {
                reconnecting[id] = nil
                reconnectTasks[id] = nil
            }
        }
        for (i, delay) in delays.enumerated() {
            guard reconnectGen[id] == gen else { return }
            let wait = (i == 0 && immediate) ? 0 : delay
            reconnecting[id] = ReconnectInfo(attempt: i + 1, maxAttempts: delays.count,
                                             at: clock.now().addingTimeInterval(wait))
            do { try await clock.sleep(wait) } catch { return }
            guard reconnectGen[id] == gen else { return }
            if state(id).isConnected {
                events.send(.reconnected(profileID: id))
                return
            }
            do {
                try await performConnect(id, given: [:])
                guard reconnectGen[id] == gen else { return }
                if state(id).isConnected {
                    events.send(.reconnected(profileID: id))
                    return
                }
            } catch {
                guard reconnectGen[id] == gen else { return }
                reason = error.localizedDescription
                if !Self.isRetryable(error) { break }
            }
        }
        guard reconnectGen[id] == gen else { return }
        events.send(.reconnectFailed(profileID: id, reason: reason))
    }

    /// Wrong credentials or missing secrets will not fix themselves; retrying could lock the account.
    static func isRetryable(_ error: Error) -> Bool {
        switch error as? PTError {
        case .authFailed, .missingPassword, .missingTOTPSecret, .missingCredential, .missingConfig,
             .missingHost, .invalidSecret, .profileNotFound:
            return false
        default:
            return true
        }
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
        if canAutoReconnect(p), forcedReconnectDone.insert(id).inserted {
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
            do {
                try await self.performConnect(id, given: [:])
                guard self.reconnectGen[id] == gen else { return }
                self.events.send(.reconnected(profileID: id))
            } catch {
                guard self.reconnectGen[id] == gen else { return }
                self.events.send(.reconnectFailed(profileID: id, reason: error.localizedDescription))
            }
        }
    }

    // MARK: sleep / wake

    public func handleWillSleep() {
        connectedBeforeSleep = Set(states.filter { $0.value.isConnected }.map(\.key))
        sleeping = true
    }

    /// Polls after `wakeDelay`, probes health and reconnects eligible profiles that were connected
    /// before sleep.
    public func handleDidWake() async {
        try? await clock.sleep(timing.wakeDelay)
        sleeping = false
        let before = connectedBeforeSleep
        connectedBeforeSleep = []
        await refresh(wakeIDs: before)
        await runHealthChecks()
        for id in before where state(id) == .disconnected && reconnectTasks[id] == nil && !isBusy(id) {
            guard let p = try? store.get(id), canAutoReconnect(p), !hasUserStoppedMarker(id) else { continue }
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

    // MARK: bookkeeping

    private func setState(_ id: String, _ s: ConnectionState) {
        if states[id] != s { states[id] = s }
    }

    private func endSession(_ id: String) {
        connectedAt[id] = nil
        sessionWarned[id] = nil
        health[id] = nil
        healthFailures[id] = nil
        outage.remove(id)
        forcedReconnectDone.remove(id)
    }

    private func forget(_ id: String) {
        cancelReconnect(id)
        endSession(id)
        states[id] = nil
        lastError[id] = nil
        lastErrorLog[id] = nil
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

    private func socketPath(_ id: String) -> String {
        store.dir(id).appendingPathComponent(PT.mgmtSocketName).path
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
