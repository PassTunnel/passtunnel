import PassTunnelShared
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

#if canImport(Combine)
import Combine
#endif

// MARK: - Fakes

/// OpenVPN-like management server that answers `state` with a mutable line, for any number of clients.
final class LoopingManagementServer: @unchecked Sendable {
    let path: String
    private let lock = NSLock()
    private var line: String
    private var stopped = false
    private var _commands: [String] = []
    private let listenFD: Int32
    private let finished = DispatchSemaphore(value: 0)
    /// Runs on the server's thread after each `state` reply.
    private let onStateQuery: (() -> Void)?

    init(path: String, stateLine: String, onStateQuery: (() -> Void)? = nil) {
        self.path = path
        self.line = stateLine
        self.onStateQuery = onStateQuery
        unlink(path)
        listenFD = TestSocket.listenUnix(path, backlog: 8)
        Thread.detachNewThread { [self] in self.loop() }
    }

    var stateLine: String {
        get { lock.lock(); defer { lock.unlock() }; return line }
        set { lock.lock(); line = newValue; lock.unlock() }
    }

    private var isStopped: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
    /// Commands other than `state` that clients sent.
    var commands: [String] { lock.lock(); defer { lock.unlock() }; return _commands }

    private func loop() {
        while !isStopped {
            var p = pollfd(fd: listenFD, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, 50) > 0 else { continue }
            let c = accept(listenFD, nil, nil)
            guard c >= 0 else { continue }
            POSIXSocket.noSigPipe(c)
            FakeManagementServer.send(c, FakeManagementServer.banner)
            let cmd = FakeManagementServer.readLine(c)
            if cmd == "state" {
                FakeManagementServer.send(c, stateLine + "\r\nEND\r\n")
                onStateQuery?()
            } else if cmd.hasPrefix("signal ") {
                lock.lock(); _commands.append(cmd); lock.unlock()
                FakeManagementServer.send(c, "SUCCESS: \(cmd) thrown\r\n")
            } else {
                FakeManagementServer.send(c, "ERROR: unknown command\r\n")
            }
            close(c)
        }
        close(listenFD)
        finished.signal()
    }

    func stop() {
        lock.lock()
        let wasStopped = stopped
        stopped = true
        lock.unlock()
        guard !wasStopped else { return }
        _ = finished.wait(timeout: .now() + 2)
        unlink(path)
    }

    static func connectedLine(ip: String = "10.8.0.6", since: Date) -> String {
        "\(Int(since.timeIntervalSince1970)),CONNECTED,SUCCESS,\(ip),203.0.113.5,1194,,,"
    }
}

/// Stands in for the privileged helper: tracks "running" profiles and, for OpenVPN, serves a
/// management socket (in the temp profile directory; the manager only learns the path from the
/// start and status replies, as with the real helper).
final class FakeHelper: HelperClienting, @unchecked Sendable {
    private let lock = NSLock()
    private var _requests: [HelperRequest] = []
    private var _running: [String: Int32] = [:]
    private var servers: [String: LoopingManagementServer] = [:]
    private var sockets: [String: String] = [:]

    /// Protocol version the fake helper reports; anything else than ours fails `ensureCompatible`.
    var protocolVersion = PT.helperProtocolVersion

    /// Start requests fail with this message while > 0 (decremented per start).
    var failStarts = 0
    var failMessage = "boom"
    /// What a started OpenVPN reports; nil = no management socket (process stuck before it).
    var openVPNStateLine: ((Date) -> String)? = { LoopingManagementServer.connectedLine(since: $0) }
    /// Log written when a tool starts.
    var startLog = ""
    /// A started tool is gone at once (as one dyld aborts at launch).
    var exitAtStart = false
    /// Delays (seconds) for the next `status` calls, consumed in order.
    var statusDelays: [TimeInterval] = []
    /// Runs when a start request arrives, before the tool "starts" (e.g. to edit files meanwhile).
    var onStart: ((HelperRequest) -> Void)?
    /// Runs (on the management server's thread, with the profile id) each time the management socket
    /// of an OpenVPN started here answers `state`: the manager has the start's reply and is waiting
    /// for the connection.
    var onStateQuery: ((String) -> Void)?
    /// When set, `status` calls fail with this error (helper unreachable).
    var statusError: Error?
    /// Runs at the start of every `status` call with its number (1 for the first).
    var onStatus: ((Int) -> Void)?
    private var statusCalls = 0

    func locked<T>(_ body: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return body() }

    var requests: [HelperRequest] { locked { _requests } }
    var running: [String: Int32] { locked { _running } }

    var starts: [HelperRequest] {
        requests.filter {
            switch $0 {
            case .startOpenVPN, .startForti: return true
            default: return false
            }
        }
    }

    var stops: [String] {
        requests.compactMap {
            if case .stop(let id) = $0 { return id }; return nil
        }
    }

    /// False: the fake helper is another build than the app ships (same protocol).
    var sameBuild = true

    func ensureCompatible() async throws {
        let v = locked { protocolVersion }
        guard v == PT.helperProtocolVersion else {
            throw HelperClientError.versionMismatch(helper: v, app: PT.helperProtocolVersion)
        }
        guard locked({ sameBuild }) else { throw HelperClientError.buildMismatch }
    }

    func perform(_ request: HelperRequest, timeout: TimeInterval?) async throws -> HelperResponse {
        locked { _requests.append(request) }
        switch request {
        case .status:
            let call = locked { () -> Int in
                statusCalls += 1; return statusCalls
            }
            onStatus?(call)
            if let error = locked({ statusError }) { throw error }
            let (snapshot, socks, delay) = locked { () -> ([String: Int32], [String: String], TimeInterval) in
                (_running, sockets, _statusDelayPop())
            }
            if delay > 0 { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            return .success(running: snapshot, mgmtSockets: socks)
        case .startOpenVPN(let s):
            onStart?(request)
            // Like the helper: only the config.ovpn the app checked is started.
            if let expected = s.configSHA256 {
                let data = (try? Data(contentsOf: URL(fileURLWithPath: s.profileDir + "/config.ovpn"))) ?? Data()
                if HelperCore.sha256Hex(data) != expected { return .failure(HelperCore.Failure.configChanged) }
            }
            if let failure = takeFailure() { return failure }
            write(startLog, to: s.logPath)
            let sock = s.profileDir + "/" + PT.mgmtSocketName
            if let line = openVPNStateLine {
                let id = s.profileID
                let onQuery = onStateQuery.map { f in { f(id) } }
                let server = LoopingManagementServer(path: sock, stateLine: line(Date()), onStateQuery: onQuery)
                locked { servers[s.profileID] = server }
            }
            if locked({ exitAtStart }) {
                simulateExit(s.profileID)
                return .success(pid: 4242, mgmtSocket: sock)
            }
            locked {
                _running[s.profileID] = 4242; sockets[s.profileID] = sock
            }
            return .success(pid: 4242, mgmtSocket: sock)
        case .startForti(let s):
            if let failure = takeFailure() { return failure }
            write(startLog, to: s.logPath)
            if !locked({ exitAtStart }) { locked { _running[s.profileID] = 4343 } }
            return .success(pid: 4343)
        case .stop(let id):
            // Like the helper: the pid only when something was running.
            let pid = locked { _running[id] }
            simulateExit(id)
            return .success(pid: pid)
        }
    }

    private func _statusDelayPop() -> TimeInterval {
        statusDelays.isEmpty ? 0 : statusDelays.removeFirst()
    }

    private func takeFailure() -> HelperResponse? {
        locked {
            guard failStarts > 0 else { return nil }
            failStarts -= 1
            return HelperResponse.failure(failMessage)
        }
    }

    private func write(_ text: String, to path: String) {
        try? Data(text.utf8).write(to: URL(fileURLWithPath: path))
    }

    /// The VPN process went away (drop, crash or stop).
    func simulateExit(_ id: String) {
        let server = locked { () -> LoopingManagementServer? in
            _running[id] = nil
            sockets[id] = nil
            return servers.removeValue(forKey: id)
        }
        server?.stop()
    }

    /// Another process (e.g. the CLI) started the profile.
    func simulateExternalStart(_ id: String, profileDir: String, since: Date) {
        let sock = profileDir + "/" + PT.mgmtSocketName
        let server = LoopingManagementServer(path: sock, stateLine: LoopingManagementServer.connectedLine(since: since))
        locked {
            servers[id] = server
            sockets[id] = sock
            _running[id] = 5151
        }
    }

    func managementCommands(_ id: String) -> [String] {
        locked { servers[id] }?.commands ?? []
    }

    func setStateLine(_ id: String, _ line: String) {
        locked { servers[id] }?.stateLine = line
    }

    func shutdown() {
        let all = locked { () -> [LoopingManagementServer] in
            let s = Array(servers.values)
            servers.removeAll()
            return s
        }
        all.forEach { $0.stop() }
    }
}

/// Virtual time: `sleep` returns at once and advances the clock.
final class FakeClock: ConnectionClock, @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date
    private var _sleeps: [TimeInterval] = []

    init(_ start: Date) { current = start }

    var sleeps: [TimeInterval] { lock.lock(); defer { lock.unlock() }; return _sleeps }

    func now() -> Date { lock.lock(); defer { lock.unlock() }; return current }

    private func advance(_ seconds: TimeInterval) {
        lock.lock()
        _sleeps.append(seconds)
        current = current.addingTimeInterval(max(0, seconds))
        lock.unlock()
    }

    func sleep(_ seconds: TimeInterval) async throws {
        try Task.checkCancellation()
        advance(seconds)
        await Task.yield()
        try Task.checkCancellation()
    }
}

/// A `FakeClock` that, each time something sleeps, takes `look` on the main actor while the sleeper waits.
final class WatchingClock: ConnectionClock, @unchecked Sendable {
    let base: FakeClock
    @MainActor var look: (() -> DisplayStatus)?
    @MainActor private(set) var seen: [DisplayStatus] = []

    init(_ base: FakeClock) { self.base = base }

    func now() -> Date { base.now() }

    func sleep(_ seconds: TimeInterval) async throws {
        await MainActor.run {
            if let look { seen.append(look()) }
        }
        try await base.sleep(seconds)
    }
}

// MARK: - Tests

@MainActor
final class ConnectionManagerTests: XCTestCase {
    var home: String!
    var service: String!
    var helper: FakeHelper!
    var clock: FakeClock!
    var prefs = Preferences()
    var events: [ConnectionEvent] = []
    var bag: Set<AnyCancellable> = []
    var healthResults: [Bool] = []
    /// What the manager sees as the routing table (never the real one).
    var routeTable: [RoutingTable.Route] = []
    /// Stands in for Touch ID: no test ever shows a real prompt.
    var authenticator = FakeAuthenticator()
    /// Stands in for the gateway and the time server: no test goes to the network for the clock.
    var serverClock = FakeServerClock()
    var store: ProfileStore { ProfileStore() }

    /// 1_700_000_000 is 20 s into a 30 s window: 10 s left.
    let t0 = Date(timeIntervalSince1970: 1_700_000_000)
    let totpSecret = "JBSWY3DPEHPK3PXP"

    override func setUp() async throws {
        // Short path: the management socket must fit in sun_path.
        var template = Array("/tmp/pt-cm-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        home = String(cString: made)
        service = "PassTunnelTests-\(UUID().uuidString)"
        setenv("PASSTUNNEL_HOME", home, 1)
        useTestSecrets(service: service)
        helper = FakeHelper()
        clock = FakeClock(t0)
        events = []
        bag = []
        healthResults = []
        routeTable = []
        prefs = Preferences()
        authenticator = FakeAuthenticator()
        serverClock = FakeServerClock()
    }

    override func tearDown() async throws {
        helper.shutdown()
        Secrets.deleteAllInOverriddenService()
        try? FileManager.default.removeItem(atPath: home)
    }

    func makeManager(clock: ConnectionClock? = nil, timing: ConnectionManager.Timing = .init()) -> ConnectionManager {
        let m = ConnectionManager(
            store: store, helper: helper, clock: clock ?? self.clock,
            healthProbe: { [weak self] _ in
                await MainActor.run {
                    guard let self, !self.healthResults.isEmpty else { return (false, 0) }
                    return (self.healthResults.removeFirst(), 12)
                }
            },
            preferences: { [weak self] in self?.prefs ?? Preferences() },
            routes: { [weak self] in self?.routeTable ?? [] },
            timing: timing,
            authenticator: authenticator)
        m.events.sink { [weak self] in self?.events.append($0) }.store(in: &bag)
        m.serverClock = serverClock
        return m
    }

    @discardableResult
    func makeOpenVPN(
        _ name: String = "Acme", otp: OTPMode = .none, autoReconnect: Bool = false,
        healthHost: String = "", sessionLimitMin: Int = 0
    ) throws -> Profile {
        var p = try store.create(name: name, type: .openvpn)
        p.username = "alice"
        p.otpMode = otp
        p.autoReconnect = autoReconnect
        p.healthHost = healthHost
        p.sessionLimitMin = sessionLimitMin
        try store.save(p)
        try Data("client\nremote vpn.example.com 1194\nauth-user-pass\n".utf8).write(to: store.ovpnURL(p.id))
        try Secrets.set(p.id, .password, "pw")
        if otp == .totp { try Secrets.set(p.id, .totp, totpSecret) }
        return p
    }

    func code(at date: Date, params: TOTPParams = TOTPParams()) throws -> String {
        TOTP.code(secret: try TOTP.decodeSecret(totpSecret), params: params, at: date)
    }

    func secretSent(_ request: HelperRequest) -> String? {
        if case .startOpenVPN(let s) = request { return s.secret }
        return nil
    }

    func waitUntil(
        timeout: TimeInterval = 5, file: StaticString = #filePath, line: UInt = #line,
        _ condition: () -> Bool
    ) async {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            if Date() > deadline { return XCTFail("condition not met in time", file: file, line: line) }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    // MARK: connect

    func testConnectHappyPathOpenVPN() async throws {
        let p = try makeOpenVPN(otp: .totp)
        let m = makeManager()
        try await m.connect(p.id)

        guard case let .connected(ip, since) = m.state(p.id) else { return XCTFail("\(m.state(p.id))") }
        XCTAssertEqual(ip, "10.8.0.6")
        XCTAssertEqual(since?.timeIntervalSinceNow ?? 99, 0, accuracy: 2)
        XCTAssertNil(m.lastError[p.id])
        XCTAssertEqual(clock.sleeps, [], "10 s left in the window: no wait")

        XCTAssertEqual(helper.starts.count, 1)
        guard case .startOpenVPN(let s) = helper.starts[0] else { return XCTFail() }
        XCTAssertEqual(s.profileID, p.id)
        XCTAssertEqual(s.username, "alice")
        XCTAssertEqual(s.secret, "pw" + (try code(at: t0)))  // combined, {password}{otp}
        XCTAssertEqual(s.profileDir, store.dir(p.id).path)
        XCTAssertEqual(s.logPath, store.logURL(p.id).path)
        XCTAssertTrue(events.isEmpty)
    }

    func testConnectFortiParsesLog() async throws {
        var p = try store.create(name: "Acme Forti", type: .forti)
        p.host = "vpn.example.com"
        p.port = 10443
        p.username = "alice"
        p.otpMode = .totp
        try store.save(p)
        try Secrets.set(p.id, .password, "pw")
        try Secrets.set(p.id, .totp, totpSecret)
        helper.startLog =
            "INFO:   Connected to gateway.\nINFO:   Got addresses: [10.212.134.200], ns [10.0.0.1, 10.0.0.2]\n"
            + "INFO:   Tunnel is up and running.\n"
        let m = makeManager()
        try await m.connect(p.id)

        guard case .connected(let ip, _) = m.state(p.id) else { return XCTFail("\(m.state(p.id))") }
        XCTAssertEqual(ip, "10.212.134.200")
        guard case .startForti(let s) = helper.starts.first else { return XCTFail() }
        XCTAssertEqual([s.host, s.username, s.password], ["vpn.example.com", "alice", "pw"])
        XCTAssertEqual(s.port, 10443)
        XCTAssertEqual(s.otp, try code(at: t0))  // separate delivery
        XCTAssertNil(s.description.range(of: "pw,"))

        // The poll keeps it connected (helper status + log).
        await m.refresh()
        XCTAssertEqual(m.state(p.id).isConnected, true)
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .disconnected)
    }

    static let fortiUp =
        "INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54]\n"
        + "INFO:   Interface ppp0 is UP.\nINFO:   Tunnel is up and running.\n"

    func makeFortiWithDNS() throws -> Profile {
        var p = try store.create(name: "Acme Forti", type: .forti)
        p.host = "vpn.example.com"
        p.username = "alice"
        p.setDNS = true
        try store.save(p)
        try Secrets.set(p.id, .password, "pw")
        return p
    }

    #if os(Linux)
    /// Linux: passtunneld sets the DNS of a profile with `set_dns` once the tunnel is up; connected
    /// only once it said how that went.
    func testFortiWaitsForTheDaemonsDNS() async throws {
        let p = try makeFortiWithDNS()
        helper.startLog =
            Self.fortiUp
            + "passtunneld: DNS of ppp0 set through systemd-resolved: 198.51.100.53, 198.51.100.54\n"
        let m = makeManager()
        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
        try await m.disconnect(p.id)

        helper.startLog = Self.fortiUp
        var timing = ConnectionManager.Timing()
        timing.fortiTimeout = 2
        let waiting = makeManager(timing: timing)
        do {
            try await waiting.connect(p.id)
            XCTFail("connected before the DNS was set")
        } catch {
            XCTAssertEqual(error as? PTError, .connectTimeout(2))
        }
        await waiting.refresh()
        XCTAssertFalse(waiting.state(p.id).isConnected)
    }

    func testFortiDNSFailureIsASetupFailure() async throws {
        let p = try makeFortiWithDNS()
        helper.startLog =
            Self.fortiUp + "passtunneld: setting DNS failed: ppp0 is not this session's interface: "
            + "it existed before the session started\n"
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("reported connected")
        } catch {
            guard case .setupFailed(let reason, _)? = error as? PTError else { return XCTFail("\(error)") }
            XCTAssertEqual(
                reason,
                "passtunneld: setting DNS failed: ppp0 is not this session's interface: "
                    + "it existed before the session started")
        }
        XCTAssertEqual(helper.stops, [p.id])
    }
    #else
    /// The Mac: openfortivpn sets the DNS itself; nothing is waited for.
    func testFortiDoesNotWaitForDNSOnTheMac() async throws {
        let p = try makeFortiWithDNS()
        helper.startLog = Self.fortiUp
        let m = makeManager()
        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
    }
    #endif

    /// A user name asked at connect time that openfortivpn would cut off is refused before anything
    /// is sent to the helper.
    func testFortiUsernameTooLongIsRefusedBeforeStarting() async throws {
        var p = try store.create(name: "Acme Forti", type: .forti)
        p.host = "vpn.example.com"
        p.username = ""
        try store.save(p)
        try Secrets.set(p.id, .password, "pw")
        let m = makeManager()
        do {
            try await m.connect(p.id, given: [.username: String(repeating: "ş", count: 33)])
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? PTError, .usernameTooLong(maxBytes: 64))
        }
        XCTAssertTrue(helper.starts.isEmpty)
        XCTAssertFalse(ConnectionManager.isRetryable(PTError.usernameTooLong(maxBytes: 64)))
    }

    func testAuthFailureFromLog() async throws {
        let p = try makeOpenVPN()
        helper.openVPNStateLine = nil
        helper.startLog =
            "Mon Oct 20 10:00:00 2026 TCP connection established\n"
            + "Mon Oct 20 10:00:01 2026 AUTH: Received control message: AUTH_FAILED\n"
            + "Mon Oct 20 10:00:01 2026 SIGTERM[soft,auth-failure] received, process exiting\n"
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("expected an error")
        } catch let PTError.authFailed(tail) {
            XCTAssertTrue(tail.contains("AUTH_FAILED"), tail)
        }
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertEqual(helper.stops, [p.id], "the failed process is stopped")
        XCTAssertNotNil(m.lastError[p.id])
        XCTAssertTrue(m.lastErrorLog[p.id]?.contains("AUTH_FAILED") == true)
        XCTAssertTrue(events.isEmpty)
    }

    func testProcessExitAndTimeout() async throws {
        let p = try makeOpenVPN()
        helper.openVPNStateLine = nil
        let m = makeManager()

        // The tool exits without connecting → connectFailed with the log.
        helper.startLog = "Options error: something odd\n"
        do { try await m.connect(p.id); XCTFail() } catch let PTError.connectFailed(tail) {
            XCTAssertTrue(tail.contains("Options error"))
        }

        // Nothing happens for 60 s (virtual) → timeout, process stopped.
        helper.startLog = "still trying\n"
        do { try await m.connect(p.id); XCTFail() } catch {
            XCTAssertEqual(error as? PTError, .connectTimeout(60))
        }
        XCTAssertEqual(helper.stops.last, p.id)
        XCTAssertEqual(m.state(p.id), .disconnected)
    }

    func testMissingSecretsGivePreciseErrors() async throws {
        let p = try makeOpenVPN(otp: .totp)
        let m = makeManager()
        Secrets.delete(p.id, .totp)
        do { try await m.connect(p.id); XCTFail() } catch { XCTAssertEqual(error as? PTError, .missingTOTPSecret(p.id)) }
        Secrets.delete(p.id, .password)
        do { try await m.connect(p.id); XCTFail() } catch { XCTAssertEqual(error as? PTError, .missingPassword(p.id)) }

        var q = try makeOpenVPN("Ask", otp: .ask)
        q.username = ""
        try store.save(q)
        do { try await m.connect(q.id); XCTFail() } catch { XCTAssertEqual(error as? PTError, .missingCredential(.username)) }
        do { try await m.connect(q.id, given: [.username: "bob"]); XCTFail() } catch {
            XCTAssertEqual(error as? PTError, .missingCredential(.otp))
        }
        try FileManager.default.removeItem(at: store.ovpnURL(q.id))
        do { try await m.connect(q.id); XCTFail() } catch { XCTAssertEqual(error as? PTError, .missingConfig(q.id)) }
        XCTAssertTrue(helper.starts.isEmpty)
        XCTAssertNotNil(m.lastError[q.id])

        // Given values are used for `.ask`, and the asked user name is remembered.
        try Data("client\n".utf8).write(to: store.ovpnURL(q.id))
        try await m.connect(q.id, given: [.username: "bob", .otp: "123456"])
        guard case .startOpenVPN(let s) = helper.starts.last else { return XCTFail() }
        XCTAssertEqual(s.username, "bob")
        XCTAssertEqual(s.secret, "pw123456")
        XCTAssertEqual(try store.get(q.id).lastUsername, "bob")
    }

    /// A config.ovpn the app cannot read has no hash to hold the helper to: the connect fails before
    /// any secret is read or sent.
    func testUnreadableConfigFailsTheConnect() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        let url = store.ovpnURL(p.id)
        try Data(repeating: 0x41, count: ProfileStore.maxOVPNSize + 1).write(to: url)
        do { try await m.connect(p.id); XCTFail() } catch { XCTAssertEqual(error as? PTError, .missingConfig(p.id)) }
        XCTAssertTrue(helper.starts.isEmpty)

        if geteuid() != 0 {
            try Data("client\nremote vpn.example.com 1194\n".utf8).write(to: url)
            XCTAssertEqual(chmod(url.path, 0), 0)
            defer { chmod(url.path, 0o600) }
            do { try await m.connect(p.id); XCTFail() } catch { XCTAssertEqual(error as? PTError, .missingConfig(p.id)) }
            XCTAssertTrue(helper.starts.isEmpty)
        }
    }

    /// The app keeps a loaded copy of its profiles; the CLI may change the file and the Keychain
    /// afterwards. Connecting must use what is stored at that moment.
    func testConnectUsesProfileAndSecretAsStoredNow() async throws {
        let p = try makeOpenVPN(otp: .ask)
        let m = makeManager()
        await m.refresh()  // the manager has seen the old profile

        // "CLI": another store instance, as a separate process would use.
        let newSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        var changed = try ProfileStore().get(p.id)
        changed.otpMode = .totp
        changed.totp.period = 60
        try ProfileStore().save(changed)
        try Secrets.set(p.id, .totp, newSecret)
        try Secrets.set(p.id, .password, "new-pw")

        try await m.connect(p.id)  // no `.otp` given: the old copy would need one
        var params = TOTPParams()
        params.period = 60
        let expected = TOTP.code(secret: try TOTP.decodeSecret(newSecret), params: params, at: t0)
        XCTAssertEqual(secretSent(try XCTUnwrap(helper.starts.last)), "new-pw" + expected)
        XCTAssertEqual(clock.sleeps, [], "40 s left in the 60 s window: no wait")
    }

    /// Remembering the asked user name must not write back a profile read before the connect.
    func testRememberedUsernameKeepsEditsMadeWhileConnecting() async throws {
        var p = try makeOpenVPN()
        p.username = ""
        try store.save(p)
        helper.onStart = { [id = p.id] _ in
            _ = try? ProfileStore().update(id) {
                $0.healthHost = "10.0.0.5"; $0.totp.period = 60
            }
        }
        let m = makeManager()
        try await m.connect(p.id, given: [.username: "bob"])
        let saved = try store.get(p.id)
        XCTAssertEqual(saved.lastUsername, "bob")
        XCTAssertEqual(saved.healthHost, "10.0.0.5")
        XCTAssertEqual(saved.totp.period, 60)
    }

    func testWaitsForFreshTOTPWindow() async throws {
        let p = try makeOpenVPN(otp: .totp)
        clock = FakeClock(t0.addingTimeInterval(7))  // 27 s into the window: 3 s left
        let m = makeManager()
        var seen: [ConnectionState] = []
        m.$states.compactMap { $0[p.id] }.sink { seen.append($0) }.store(in: &bag)

        try await m.connect(p.id)
        XCTAssertEqual(clock.sleeps.count, 1)
        XCTAssertEqual(clock.sleeps[0], 3.25, accuracy: 0.01)
        let fresh = try code(at: t0.addingTimeInterval(10.25))
        XCTAssertEqual(secretSent(helper.starts[0]), "pw" + fresh)
        XCTAssertNotEqual(fresh, try code(at: t0.addingTimeInterval(7)))
        XCTAssertTrue(seen.contains(.connecting(ConnectionManager.Phase.waitingForCode)))
    }

    func testCodeWaitEndIsPublishedDuringTheWait() async throws {
        let p = try makeOpenVPN(otp: .totp)
        clock = FakeClock(t0.addingTimeInterval(7))
        let m = makeManager()
        var waits: [Date] = []
        m.$states.compactMap { $0[p.id] }.sink { state in
            if state == .connecting(ConnectionManager.Phase.waitingForCode), let until = m.codeWaitUntil[p.id] {
                waits.append(until)
            }
        }.store(in: &bag)
        try await m.connect(p.id)
        XCTAssertEqual(waits.count, 1)
        XCTAssertEqual(waits.first?.timeIntervalSince(t0.addingTimeInterval(7)) ?? 0, 3.25, accuracy: 0.01)
        XCTAssertNil(m.codeWaitUntil[p.id])
    }

    func testFreshCodeWaitStartsAtFiveSecondsLeft() async throws {
        let p = try makeOpenVPN(otp: .totp)
        clock = FakeClock(t0.addingTimeInterval(5))  // 25 s into the window: exactly 5 s left
        try await makeManager().connect(p.id)
        XCTAssertEqual(clock.sleeps.count, 1)
        XCTAssertEqual(clock.sleeps[0], 5.25, accuracy: 0.01)
        XCTAssertEqual(secretSent(helper.starts[0]), "pw" + (try code(at: t0.addingTimeInterval(10.25))))
    }

    func testSixSecondsLeftSendsTheCurrentCode() async throws {
        let p = try makeOpenVPN(otp: .totp)
        clock = FakeClock(t0.addingTimeInterval(4))  // 6 s left
        try await makeManager().connect(p.id)
        XCTAssertEqual(clock.sleeps, [])
        XCTAssertEqual(secretSent(helper.starts[0]), "pw" + (try code(at: t0.addingTimeInterval(4))))
    }

    func testNoWaitForTheTimeLeftWhenTheSettingIsOff() async throws {
        let p = try makeOpenVPN(otp: .totp)
        prefs.waitForFreshCode = false
        for (i, offset) in [5.0, 7, 9.5].enumerated() {  // 5, 3 and 0.5 s left
            clock = FakeClock(t0.addingTimeInterval(offset))
            let m = makeManager()
            try await m.connect(p.id)
            try await m.disconnect(p.id)
            try FileManager.default.removeItem(at: store.dir(p.id).appendingPathComponent(ConnectionManager.usedOTPFile))
            XCTAssertEqual(clock.sleeps, [], "\(offset)")
            XCTAssertEqual(secretSent(helper.starts[i]), "pw" + (try code(at: t0.addingTimeInterval(offset))))
        }
    }

    /// The server rejects a code it has seen: the setting never makes PassTunnel send one again.
    func testReusedCodeWaitsWhenTheSettingIsOff() async throws {
        let p = try makeOpenVPN(otp: .totp)
        prefs.waitForFreshCode = false
        let m = makeManager()
        try await m.connect(p.id)  // 10 s left
        try await m.disconnect(p.id)
        try await m.connect(p.id)  // same window
        XCTAssertEqual(clock.sleeps.count, 1)
        XCTAssertEqual(clock.sleeps[0], 10.25, accuracy: 0.01)
        XCTAssertEqual(secretSent(helper.starts[1]), "pw" + (try code(at: t0.addingTimeInterval(10.25))))
        XCTAssertNotEqual(secretSent(helper.starts[0]), secretSent(helper.starts[1]))
    }

    /// The CLI and the MCP server make their manager without `preferences:`: it reads config.json,
    /// which the app's Settings write, so all three follow the same setting.
    func testDefaultPreferencesComeFromTheConfigFile() async throws {
        let p = try makeOpenVPN(otp: .totp)
        var saved = Preferences()
        saved.waitForFreshCode = false
        try saved.save()
        clock = FakeClock(t0.addingTimeInterval(7))  // 3 s left
        let m = ConnectionManager(
            store: store, helper: helper, clock: clock, routes: { [] },
            authenticator: authenticator)
        try await m.connect(p.id)
        XCTAssertEqual(clock.sleeps, [])

        saved.waitForFreshCode = true
        try saved.save()
        try await m.disconnect(p.id)
        clock = FakeClock(t0.addingTimeInterval(37))  // next window, 3 s left
        let next = ConnectionManager(
            store: store, helper: helper, clock: clock, routes: { [] },
            authenticator: authenticator)
        try await next.connect(p.id)
        XCTAssertEqual(clock.sleeps.count, 1)
        XCTAssertEqual(clock.sleeps[0], 3.25, accuracy: 0.01)
    }

    func testPhasesOnlyMoveForward() {
        typealias P = ConnectionManager.Phase
        var progress = ConnectionManager.PhaseProgress()
        let seen = [
            P.preparing, P.starting, P.configuring, P.preparing, P.configuring, P.signingIn, P.reconnecting,
            P.reconnecting, P.connecting
        ].filter { progress.shouldPrint($0) }
        XCTAssertEqual(seen, [P.preparing, P.starting, P.configuring, P.reconnecting])
    }

    func testDisconnectReportsWhetherAnythingWasRunning() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        let stoppedIdle = try await m.disconnect(p.id)
        XCTAssertFalse(stoppedIdle)
        try await m.connect(p.id)
        let stoppedConnected = try await m.disconnect(p.id)
        XCTAssertTrue(stoppedConnected)

        // Another process (the CLI) has not seen the connection, but the helper names the stopped pid.
        try await m.connect(p.id)
        let cli = ConnectionManager(store: store, helper: helper, clock: clock)
        let stoppedByCLI = try await cli.disconnect(p.id)
        XCTAssertTrue(stoppedByCLI)
        let again = try await cli.disconnect(p.id)
        XCTAssertFalse(again)
    }

    // MARK: drops

    func testUserStopIsNotADrop() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        try await m.disconnect(p.id)
        XCTAssertEqual(m.state(p.id), .disconnected)
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertTrue(events.isEmpty, "\(events)")

        // A stop by another process (CLI) is recognized through the marker file.
        try await m.connect(p.id)
        let other = ConnectionManager(store: store, helper: helper, clock: clock)
        try await other.disconnect(p.id)
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertTrue(events.isEmpty, "\(events)")
        XCTAssertEqual(helper.starts.count, 2)
    }

    func testDropWithoutAutoReconnect() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        try await m.connect(p.id)
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertEqual(events, [.dropped(profileID: p.id, willReconnect: false)])
        await m.refresh()
        XCTAssertEqual(events.count, 1)
        XCTAssertNil(m.reconnecting[p.id])
    }

    /// `passtunnel debug drop`: OpenVPN is asked to exit over its management socket, and the exit is a
    /// drop (not a user stop), so auto-reconnect runs.
    func testSimulatedDropIsHandledAsADrop() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        let dropped = try await m.simulateDrop(p.id)
        XCTAssertTrue(dropped)
        XCTAssertEqual(helper.managementCommands(p.id), [DebugDrop.command])
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(events.first, .dropped(profileID: p.id, willReconnect: true))
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events.last, .reconnected(profileID: p.id))
        // Nothing to drop once it is not running.
        let other = try makeOpenVPN("Other")
        let droppedOther = try await m.simulateDrop(other.id)
        XCTAssertFalse(droppedOther)
    }

    func testDropReconnectsWithBackoff() async throws {
        let p = try makeOpenVPN(otp: .totp, autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        helper.failStarts = 2  // attempts 1 and 2 fail, 3 succeeds
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(events.first, .dropped(profileID: p.id, willReconnect: true))
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events.last, .reconnected(profileID: p.id))
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertNil(m.reconnecting[p.id])
        XCTAssertEqual(clock.sleeps.filter { [5, 15, 45].contains($0) }, [5, 15, 45])
        XCTAssertEqual(helper.starts.count, 4)
    }

    func testReconnectGivesUpAfterLastAttempt() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        helper.failStarts = 99
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { self.events.count == 2 }
        guard case let .reconnectFailed(id, reason) = events.last else { return XCTFail("\(events)") }
        XCTAssertEqual(id, p.id)
        XCTAssertTrue(reason.contains("boom"), reason)
        XCTAssertEqual(clock.sleeps, [5, 15, 45])
        XCTAssertEqual(helper.starts.count, 4)
        XCTAssertEqual(m.state(p.id), .disconnected)
    }

    func testReconnectStopsOnAuthFailure() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        helper.openVPNStateLine = nil
        helper.startLog = "AUTH: Received control message: AUTH_FAILED\n"
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { self.events.count == 2 }
        guard case .reconnectFailed = events.last else { return XCTFail("\(events)") }
        XCTAssertEqual(clock.sleeps, [5], "no retry after the server rejected the credentials")
    }

    func testManualActionCancelsPendingReconnect() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        var timing = ConnectionManager.Timing()
        timing.reconnectDelays = [0.3, 0.3, 0.3]
        let m = makeManager(clock: SystemClock(), timing: timing)
        try await m.connect(p.id)
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(events, [.dropped(profileID: p.id, willReconnect: true)])
        XCTAssertEqual(m.reconnecting[p.id]?.attempt, 1)
        XCTAssertEqual(m.reconnecting[p.id]?.maxAttempts, 3)

        try await m.disconnect(p.id)  // manual action
        XCTAssertNil(m.reconnecting[p.id])
        try await Task.sleep(nanoseconds: 800_000_000)
        XCTAssertEqual(helper.starts.count, 1, "no reconnect attempt after the manual action")
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(m.state(p.id), .disconnected)
    }

    // MARK: polling

    func testStalePollAfterActionIsIgnored() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        helper.statusDelays = [0.4]
        let slowPoll = Task { await m.refresh() }  // sees "not running" and returns late
        try await Task.sleep(nanoseconds: 100_000_000)
        try await m.connect(p.id)
        await slowPoll.value
        XCTAssertTrue(m.state(p.id).isConnected, "\(m.state(p.id))")
        XCTAssertTrue(events.isEmpty)
    }

    func testOlderPollNeverOverwritesNewerPoll() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        try await m.connect(p.id)
        helper.simulateExit(p.id)
        helper.statusDelays = [0.4, 0]
        let older = Task { await m.refresh() }  // snapshot: not running
        try await Task.sleep(nanoseconds: 100_000_000)
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        await m.refresh()  // newer: connected
        await older.value
        XCTAssertTrue(m.state(p.id).isConnected, "\(m.state(p.id))")
        XCTAssertTrue(events.isEmpty, "\(events)")
    }

    func testExternalConnectIsPickedUp() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .disconnected)
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        helper.setStateLine(p.id, "1700000000,AUTH,,,,,,,")
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .connecting(ConnectionManager.Phase.signingIn))
        helper.setStateLine(p.id, LoopingManagementServer.connectedLine(ip: "10.8.0.9", since: t0))
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .connected(ip: "10.8.0.9", since: t0))
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(events, [.dropped(profileID: p.id, willReconnect: false)])
    }

    /// After an app restart or a CLI connect the socket is found through the helper's status reply,
    /// wherever the helper put it (the profile directory is not involved).
    func testSocketPathComesFromHelperStatus() async throws {
        let p = try makeOpenVPN()
        let elsewhere = home + "/run-" + p.id
        try FileManager.default.createDirectory(atPath: elsewhere, withIntermediateDirectories: true)
        let m = makeManager()
        helper.simulateExternalStart(p.id, profileDir: elsewhere, since: t0)
        await m.refresh()
        XCTAssertTrue(m.state(p.id).isConnected, "\(m.state(p.id))")
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.dir(p.id).appendingPathComponent(PT.mgmtSocketName).path))
    }

    // MARK: another VPN

    /// Another app's OpenVPN with redirect-gateway: 0/1 and 128/1 via its utun.
    let otherVPNRoutes = [
        RoutingTable.Route(destination: "0.0.0.0", prefixLength: 0, interface: "en0"),
        RoutingTable.Route(destination: "0.0.0.0", prefixLength: 1, interface: "utun9"),
        RoutingTable.Route(destination: "128.0.0.0", prefixLength: 1, interface: "utun9")
    ]

    func makeFullTunnel(_ name: String = "Acme") throws -> Profile {
        let p = try makeOpenVPN(name)
        try Data("client\nremote vpn.example.com 1194\nauth-user-pass\nredirect-gateway def1\n".utf8)
            .write(to: store.ovpnURL(p.id))
        return p
    }

    func testFullTunnelProfileRefusesToStartOverAnotherFullTunnel() async throws {
        let p = try makeFullTunnel()
        routeTable = otherVPNRoutes
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("connected over another VPN")
        } catch {
            XCTAssertEqual(error as? PTError, .otherVPNActive("utun9"))
            XCTAssertEqual(
                error.localizedDescription,
                "Another VPN is already routing all traffic (utun9). Disconnect it first.")
        }
        XCTAssertTrue(helper.starts.isEmpty)
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertNotNil(m.lastError[p.id])
        XCTAssertFalse(ConnectionManager.isRetryable(PTError.otherVPNActive("utun9")))

        try await m.connect(p.id, force: true)
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    func testCheckCanStartRefusesBeforeAnythingStarts() async throws {
        let p = try makeFullTunnel()
        routeTable = otherVPNRoutes
        let m = makeManager()
        do {
            try await m.checkCanStart(p.id)
            XCTFail("allowed over another VPN")
        } catch {
            XCTAssertEqual(error as? PTError, .otherVPNActive("utun9"))
        }
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertTrue(helper.starts.isEmpty)
        routeTable = []
        try await m.checkCanStart(p.id)
        // Already running (started elsewhere): connect follows that session, nothing to check.
        routeTable = otherVPNRoutes
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        try await m.checkCanStart(p.id)
    }

    func testRedirectPushedLastTimeCountsToo() async throws {
        let p = try makeOpenVPN()  // no redirect-gateway in the config
        routeTable = otherVPNRoutes
        try Data("PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.8.0.1'\n".utf8)
            .write(to: store.logURL(p.id))
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("connected over another VPN")
        } catch {
            XCTAssertEqual(error as? PTError, .otherVPNActive("utun9"))
        }
    }

    func testSplitTunnelAndOwnSessionsAreNotBlocked() async throws {
        routeTable = otherVPNRoutes
        let split = try makeOpenVPN("Split")
        let m = makeManager()
        try await m.connect(split.id)  // does not redirect: fine next to it
        XCTAssertTrue(m.state(split.id).isConnected)

        // utun9 belongs to a PassTunnel session: not "another VPN".
        try Data("2026-01-01 10:00:00 Opened utun device utun9\n".utf8).write(to: store.logURL(split.id))
        let full = try makeFullTunnel("Full")
        try await m.connect(full.id)
        XCTAssertTrue(m.state(full.id).isConnected)
    }

    func testFailedDNSStepIsAnErrorAndStopsTheSession() async throws {
        let p = try makeOpenVPN()
        helper.startLog = """
            2026-01-01 10:00:00 Opened utun device utun10
            setting DNS failed, already redirecting to another tunnel
            2026-01-01 10:00:01 WARNING: Failed running dns updown
            2026-01-01 10:00:01 Initialization Sequence Completed

            """
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("reported connected")
        } catch {
            XCTAssertEqual(
                error as? PTError,
                .setupFailed(
                    reason: "setting DNS failed, already redirecting to another tunnel",
                    log: VPNLog.tail(helper.startLog)))
            XCTAssertFalse((error as? PTError)?.logTail.isEmpty ?? true)
        }
        XCTAssertEqual(helper.stops, [p.id])
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertNotNil(m.lastError[p.id])
    }

    /// Linux: passtunneld's DNS hook fails the same way on OpenVPN 2.6, which runs it as --route-up
    /// (unlike --up, a failure there does not make OpenVPN exit, so nothing fatal comes first), and
    /// on 2.7 (--dns-updown).
    func testFailedLinuxDNSHookIsSetupFailed() async throws {
        let hook = "passtunneld dns-hook: setting DNS failed: invalid DNS server “192.0.2.1;x”"
        let logs = [
            """
            2026-01-01 10:00:00 OpenVPN 2.6.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
            2026-01-01 10:00:01 PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 192.0.2.1;x,route-gateway 10.8.0.1,topology subnet,ifconfig 10.8.0.6 255.255.255.0'
            2026-01-01 10:00:01 TUN/TAP device tun0 opened
            2026-01-01 10:00:01 net_addr_v4_add: 10.8.0.6/24 dev tun0
            2026-01-01 10:00:01 net_route_v4_add: 0.0.0.0/1 via 10.8.0.1 dev [NULL] table 0 metric -1
            2026-01-01 10:00:01 net_route_v4_add: 128.0.0.0/1 via 10.8.0.1 dev [NULL] table 0 metric -1
            \(hook)
            2026-01-01 10:00:01 WARNING: Failed running command (--route-up): external program exited with error status: 1
            2026-01-01 10:00:01 Initialization Sequence Completed

            """,
            """
            2026-01-01 10:00:00 OpenVPN 2.7.1 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
            2026-01-01 10:00:01 TUN/TAP device tun0 opened
            2026-01-01 10:00:01 net_addr_v4_add: 10.8.0.6/24 dev tun0
            2026-01-01 10:00:01 /run/passtunnel/1000/openvpn/dns-hook
            \(hook)
            2026-01-01 10:00:01 WARNING: Failed running command (dns updown): external program exited with error status: 1
            2026-01-01 10:00:01 dns up command exited with status 1
            2026-01-01 10:00:01 Initialization Sequence Completed

            """
        ]
        for (name, log) in zip(["OpenVPN 2.6", "OpenVPN 2.7"], logs) {
            XCTAssertFalse(VPNLog.isFatal(log), name)
            helper.startLog = log
            let p = try makeOpenVPN(name)
            let m = makeManager()
            do {
                try await m.connect(p.id)
                XCTFail("reported connected: \(name)")
            } catch {
                XCTAssertEqual(error as? PTError, .setupFailed(reason: hook, log: VPNLog.tail(log)), name)
            }
            XCTAssertEqual(helper.stops.filter { $0 == p.id }, [p.id], name)
            XCTAssertEqual(m.state(p.id), .disconnected, name)
        }
    }

    func testFailedAllTrafficRouteIsAnError() async throws {
        let p = try makeOpenVPN()
        helper.startLog = """
            2026-01-01 10:00:00 /sbin/route add -net 0.0.0.0 10.8.0.1 128.0.0.0
            route: writing to routing socket: File exists
            add net 0.0.0.0: gateway 10.8.0.1: File exists

            """
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("reported connected")
        } catch {
            XCTAssertEqual(
                (error as? PTError).map {
                    if case .setupFailed = $0 { return true }; return false
                }, true, "\(error)")
        }
        XCTAssertEqual(helper.stops, [p.id])
    }

    func testOtherFailedRouteLeavesAWarning() async throws {
        let p = try makeOpenVPN()
        helper.startLog = """
            2026-01-01 10:00:00 /sbin/route add -net 203.0.113.5 192.168.1.1 255.255.255.255
            add net 203.0.113.5: gateway 192.168.1.1: File exists

            """
        let m = makeManager()
        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertEqual(
            m.warnings[p.id],
            "Connected, but part of the network setup failed: add net 203.0.113.5: gateway 192.168.1.1: File exists")
        // Another process (the CLI after connecting elsewhere) sees the same.
        let cli = ConnectionManager(store: store, helper: helper, clock: clock, routes: { [] })
        await cli.refresh()
        XCTAssertNotNil(cli.warnings[p.id])
        try await m.disconnect(p.id)
        XCTAssertNil(m.warnings[p.id])
    }

    /// Linux: the routes come with the kernel's kind of device, and sessions name their device in
    /// OpenVPN's Linux lines.
    func testLinuxTunnelsAndOwnSessions() async throws {
        routeTable = [
            RoutingTable.Route(destination: "0.0.0.0", prefixLength: 0, interface: "wlp2s0"),
            RoutingTable.Route(destination: "0.0.0.0", prefixLength: 0, interface: "acme", tunnelDevice: true)
        ]
        let full = try makeFullTunnel("Full")
        let m = makeManager()
        do {
            try await m.checkCanStart(full.id)
            XCTFail("allowed over another VPN")
        } catch {
            XCTAssertEqual(error as? PTError, .otherVPNActive("acme"))
        }
        routeTable = [
            RoutingTable.Route(destination: "0.0.0.0", prefixLength: 1, interface: "tun0", tunnelDevice: true),
            RoutingTable.Route(destination: "128.0.0.0", prefixLength: 1, interface: "tun0", tunnelDevice: true)
        ]
        let split = try makeOpenVPN("Split")
        try await m.connect(split.id)
        try Data("2026-01-01 10:00:00 TUN/TAP device tun0 opened\n".utf8).write(to: store.logURL(split.id))
        try await m.connect(full.id)
        XCTAssertTrue(m.state(full.id).isConnected)
    }

    func testLinuxOtherFailedRouteLeavesAWarning() async throws {
        let p = try makeOpenVPN()
        helper.startLog = FullTunnelTests.linuxOpenVPNLog.replacingOccurrences(
            of: "Initialization Sequence Completed\n",
            with: """
                net_route_v4_add: 10.30.0.0/16 via 10.8.0.1 dev [NULL] table 0 metric -1
                2026-01-01 10:00:01 sitnl_send: rtnl: generic error (-101): Network is unreachable
                2026-01-01 10:00:01 ERROR: Linux route add command failed
                2026-01-01 10:00:01 Initialization Sequence Completed

                """)
        let m = makeManager()
        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertEqual(
            m.warnings[p.id],
            "Connected, but part of the network setup failed: "
                + "net_route_v4_add: 10.30.0.0/16 via 10.8.0.1 dev [NULL] table 0 metric -1: Network is unreachable")
    }

    func testLeftoverServerRouteLeavesNoWarning() async throws {
        for log in [FullTunnelTests.leftoverServerRouteLog, FullTunnelTests.duplicateServerRouteLog, FullTunnelTests.linuxOpenVPNLog] {
            let p = try makeOpenVPN()
            helper.startLog = log
            let m = makeManager()
            try await m.connect(p.id)
            XCTAssertTrue(m.state(p.id).isConnected)
            XCTAssertNil(m.warnings[p.id])
            try await m.disconnect(p.id)
        }
    }

    // MARK: concurrent connects

    func testSecondConnectInTheSameProcessWaitsForTheFirst() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        async let first: Void = m.connect(p.id)
        async let second: Void = m.connect(p.id)
        _ = try await (first, second)
        XCTAssertEqual(helper.starts.count, 1)
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    /// The CLI connects while the app (another process) is still connecting: it follows that session
    /// instead of asking the helper for a second one, and returns once it is up.
    func testConnectFollowsASessionAnotherProcessIsStarting() async throws {
        let p = try makeOpenVPN()
        var timing = ConnectionManager.Timing()
        timing.openVPNTimeout = 100_000  // virtual seconds: the fake clock runs fast
        let cli = makeManager(timing: timing)
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        helper.setStateLine(p.id, "1700000000,AUTH,,,,,,,")
        await cli.refresh()
        XCTAssertTrue(cli.state(p.id).isConnecting)

        let connect = Task { try await cli.connect(p.id) }
        await waitUntil { cli.state(p.id) == .connecting(ConnectionManager.Phase.signingIn) && cli.isBusyForTests(p.id) }
        helper.setStateLine(p.id, LoopingManagementServer.connectedLine(ip: "10.8.0.7", since: t0))
        try await connect.value
        XCTAssertEqual(cli.state(p.id), .connected(ip: "10.8.0.7", since: t0))
        XCTAssertTrue(helper.starts.isEmpty, "no second session requested")
    }

    /// Lost race: the other process got its start in first, so the helper refuses ours.
    func testRefusedStartFollowsTheOtherSession() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        helper.failStarts = 1
        helper.failMessage = "Profile \(p.id) is already running (pid 5151)."
        helper.onStart = { [helper, store, t0] _ in
            helper!.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        }
        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertNil(m.lastError[p.id])
    }

    /// A followed session that fails is reported, but stopping it is left to its owner.
    func testFollowedSessionFailureDoesNotStopIt() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        helper.setStateLine(p.id, "1700000000,AUTH,,,,,,,")
        try Data("AUTH: Received control message: AUTH_FAILED\n".utf8).write(to: store.logURL(p.id))
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(
                (error as? PTError).map {
                    if case .authFailed = $0 { return true }; return false
                }, true, "\(error)")
        }
        XCTAssertTrue(helper.stops.isEmpty)
        XCTAssertNotNil(helper.running[p.id])
    }

    func testOutdatedHelperFailsBeforeAnyStart() async throws {
        let p = try makeOpenVPN()
        helper.protocolVersion = 2
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("connected through an outdated helper")
        } catch {
            XCTAssertEqual(error as? HelperClientError, .versionMismatch(helper: 2, app: PT.helperProtocolVersion))
        }
        XCTAssertTrue(helper.starts.isEmpty)
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertNotNil(m.lastError[p.id])
        helper.protocolVersion = PT.helperProtocolVersion
        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    func testHelperFromAnotherBuildFailsBeforeAnyStart() async throws {
        let p = try makeOpenVPN()
        helper.sameBuild = false
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("connected through another helper build")
        } catch {
            XCTAssertEqual(error as? HelperClientError, .buildMismatch)
        }
        XCTAssertTrue(helper.starts.isEmpty)
    }

    // MARK: health

    func testHealthOutageNotifiesOnceAndForcesOneReconnect() async throws {
        let p = try makeOpenVPN(autoReconnect: true, healthHost: "10.0.0.5")
        let m = makeManager()
        try await m.connect(p.id)

        healthResults = [false]
        await m.runHealthChecks()
        XCTAssertEqual(m.health[p.id], .unknown)
        XCTAssertTrue(events.isEmpty)

        healthResults = [false]
        await m.runHealthChecks()
        XCTAssertEqual(m.health[p.id], .unreachable)
        XCTAssertEqual(events.first, .unreachable(profileID: p.id))
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events.last, .reconnected(profileID: p.id), "one forced reconnect")
        XCTAssertEqual(helper.starts.count, 2)
        XCTAssertEqual(helper.stops, [p.id])

        healthResults = [false, false, false]
        for _ in 0..<3 { await m.runHealthChecks() }
        XCTAssertEqual(m.health[p.id], .unreachable)
        XCTAssertEqual(events.count, 2, "still the same outage: no new notification or reconnect")
        XCTAssertEqual(helper.starts.count, 2)

        healthResults = [true]
        await m.runHealthChecks()
        XCTAssertEqual(m.health[p.id], .reachable(ms: 12))
        XCTAssertEqual(events.last, .reachableAgain(profileID: p.id))

        // A new outage is reported (and repaired) again.
        healthResults = [false, false]
        await m.runHealthChecks()
        await m.runHealthChecks()
        XCTAssertEqual(events.filter { $0 == .unreachable(profileID: p.id) }.count, 2)
        await waitUntil { self.helper.starts.count == 3 }
    }

    func testHealthWithoutAutoReconnectOnlyReports() async throws {
        let p = try makeOpenVPN(healthHost: "10.0.0.5:443")
        let m = makeManager()
        try await m.connect(p.id)
        healthResults = [false, false]
        await m.runHealthChecks()
        await m.runHealthChecks()
        XCTAssertEqual(events, [.unreachable(profileID: p.id)])
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(helper.starts.count, 1)
        try await m.disconnect(p.id)
        XCTAssertNil(m.health[p.id])
    }

    // MARK: the status the app's views show (DisplayStatus)

    private func displayStatus(_ p: Profile, _ m: ConnectionManager) -> DisplayStatus {
        DisplayStatus(DisplayStatus.Facts(p, in: m))
    }

    func testDisplayStatusThroughAConnect() async throws {
        let p = try makeOpenVPN(otp: .totp)
        let watching = WatchingClock(FakeClock(t0.addingTimeInterval(7)))  // 3 s left: waits for the next code
        let m = makeManager(clock: watching)
        watching.look = { [unowned m] in self.displayStatus(p, m) }
        XCTAssertEqual(displayStatus(p, m), .off)

        try await m.connect(p.id)
        XCTAssertEqual(watching.seen.first, .waitingForCode(until: t0.addingTimeInterval(10.25)))
        guard case .connected(let c) = displayStatus(p, m) else { return XCTFail("\(displayStatus(p, m))") }
        XCTAssertEqual(c.address, "10.8.0.6")
        XCTAssertNotNil(c.since)

        try await m.disconnect(p.id)
        XCTAssertEqual(displayStatus(p, m), .off)
    }

    func testDisplayStatusThroughADropAndAReconnectThatGivesUp() async throws {
        let p = try makeOpenVPN(otp: .totp, autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        helper.failStarts = 99
        helper.simulateExit(p.id)
        await m.refresh()
        let pending = try XCTUnwrap(m.reconnecting[p.id])
        XCTAssertEqual(pending.attempt, 1)
        XCTAssertEqual(displayStatus(p, m), .reconnecting(pending, freshCode: true))

        await waitUntil { self.events.count == 2 }
        guard case .failed(.message(let reason)) = displayStatus(p, m) else { return XCTFail("\(displayStatus(p, m))") }
        XCTAssertTrue(reason.contains("boom"), reason)
    }

    func testDisplayStatusOfAConnectionWithProblems() async throws {
        let p = try makeOpenVPN(healthHost: "10.0.0.5:443")
        helper.startLog = """
            2026-01-01 10:00:00 /sbin/route add -net 203.0.113.5 192.168.1.1 255.255.255.255
            add net 203.0.113.5: gateway 192.168.1.1: File exists

            """
        let m = makeManager()
        try await m.connect(p.id)
        guard case .setupIncomplete(_, let warning) = displayStatus(p, m) else { return XCTFail("\(displayStatus(p, m))") }
        XCTAssertEqual(warning, m.warnings[p.id])

        healthResults = [false, false]
        await m.runHealthChecks()
        await m.runHealthChecks()
        guard case .notResponding = displayStatus(p, m) else { return XCTFail("\(displayStatus(p, m))") }
    }

    // MARK: session limit / wake

    func testSessionEndingNotifiedOnce() async throws {
        let p = try makeOpenVPN(sessionLimitMin: 60)
        helper.openVPNStateLine = { [t0] _ in LoopingManagementServer.connectedLine(since: t0.addingTimeInterval(-55 * 60)) }
        let m = makeManager()
        try await m.connect(p.id)
        await m.refresh()
        await m.refresh()
        XCTAssertEqual(events, [.sessionEnding(profileID: p.id, minutes: 5)])

        prefs.sessionNotifyMin = 0
        try await m.disconnect(p.id)
        try await m.connect(p.id)
        await m.refresh()
        XCTAssertEqual(events.count, 1, "turned off")
    }

    func testWakeReconnectsImmediately() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        m.handleWillSleep()
        helper.simulateExit(p.id)
        await m.handleDidWake()
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events, [.dropped(profileID: p.id, willReconnect: true), .reconnected(profileID: p.id)])
        XCTAssertEqual(clock.sleeps.first, 4)
        XCTAssertFalse(clock.sleeps.contains(5), "no backoff delay after wake")
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    // MARK: activity

    let acme = ActivityEvent.Kind.connecting(host: "vpn.example.com", port: 1194, transport: "udp")

    func testActivityOfAConnect() async throws {
        let p = try makeOpenVPN(otp: .totp)
        let m = makeManager()
        var published: [ActivityRecord] = []
        m.activity.sink { published.append($0) }.store(in: &bag)
        try await m.connect(p.id)

        let code = try code(at: t0)
        let sent = ActivityEvent.Sending(
            username: "alice", password: true, code: true, codePrefix: String(code.prefix(3)),
            secondsLeft: 10, format: "{password}{otp}")
        let expected: [ActivityEvent] = [acme, .sending(sent), .authAccepted, .connected(address: "10.8.0.6")]
            .map { ActivityEvent(at: t0, $0) }
        XCTAssertEqual(m.activity(p.id), expected)
        XCTAssertEqual(published, expected.map { ActivityRecord(profileID: p.id, event: $0) })
        XCTAssertEqual(try mode(store.activityURL(p.id)), 0o600)
        let text = try String(contentsOf: store.activityURL(p.id), encoding: .utf8)
        XCTAssertFalse(text.contains(code), "at most the first three digits are kept")
        XCTAssertEqual(m.lastSending(p.id)?.at, t0)
        XCTAssertEqual(m.lastSending(p.id)?.sending.secondsLeft, 10)

        // Another process (the CLI) reads the same file.
        let cli = ConnectionManager(store: store, helper: helper, clock: clock)
        XCTAssertEqual(cli.activity(p.id), expected)
    }

    func mode(_ url: URL) throws -> Int {
        ((try FileManager.default.attributesOfItem(atPath: url.path))[.posixPermissions] as! NSNumber).intValue & 0o777
    }

    func testActivityOfCodeWaits() async throws {
        let p = try makeOpenVPN(otp: .totp)
        let m = makeManager()
        try await m.connect(p.id)
        try await m.disconnect(p.id)
        try await m.connect(p.id)  // the same window: its code was sent
        let kinds = m.activity(p.id).map(\.kind)
        XCTAssertEqual(kinds[4], .disconnectedByUser)
        XCTAssertEqual(kinds[5], acme)
        XCTAssertEqual(kinds[6], .waitingForCode(reason: .used, seconds: 10, codePrefix: String(try code(at: t0).prefix(3))))
        guard case .sending(let s) = kinds[7] else { return XCTFail("\(kinds)") }
        XCTAssertEqual(s.codePrefix, String(try code(at: t0.addingTimeInterval(10.25)).prefix(3)))
        XCTAssertEqual(s.secondsLeft, 29, "a fresh window")

        // 4 s left in the window: the next code is waited for.
        let q = try makeOpenVPN("Lab", otp: .totp)
        clock = FakeClock(t0.addingTimeInterval(6))
        try await makeManager().connect(q.id)
        XCTAssertEqual(
            makeManager().activity(q.id).map(\.kind)[1],
            .waitingForCode(reason: .expiring, seconds: 4, codePrefix: String(try code(at: t0.addingTimeInterval(6)).prefix(3))))
    }

    func testActivityOfARejectedSignIn() async throws {
        let p = try makeOpenVPN()
        helper.openVPNStateLine = nil
        helper.startLog =
            "2026-01-01 10:00:01 AUTH: Received control message: AUTH_FAILED,Invalid OTP\n"
            + "2026-01-01 10:00:01 SIGTERM[soft,auth-failure] received, process exiting\n"
        let m = makeManager()
        do { try await m.connect(p.id); XCTFail("connected") } catch PTError.authFailed {}
        XCTAssertEqual(
            m.activity(p.id).map(\.kind),
            [acme, .sending(.init(username: "alice", password: true, code: false)), .rejected(reply: "AUTH_FAILED,Invalid OTP")])
    }

    func testActivityOfAForti() async throws {
        var p = try store.create(name: "Acme Forti", type: .forti)
        p.host = "vpn.example.com"
        p.port = 10443
        p.username = "alice"
        p.otpMode = .totp
        try store.save(p)
        try Secrets.set(p.id, .password, "pw")
        try Secrets.set(p.id, .totp, totpSecret)
        helper.startLog =
            "INFO:   Connected to gateway.\nINFO:   Authenticated.\n"
            + "INFO:   Got addresses: [10.212.134.200], ns [10.0.0.1]\nINFO:   Tunnel is up and running.\n"
        let m = makeManager()
        try await m.connect(p.id)
        let sent = ActivityEvent.Sending(
            username: "alice", password: true, code: true, codePrefix: String(try code(at: t0).prefix(3)),
            secondsLeft: 10, format: "separate")
        XCTAssertEqual(
            m.activity(p.id).map(\.kind),
            [
                .connecting(host: "vpn.example.com", port: 10443, transport: "tcp"),
                .sending(sent), .authAccepted, .connected(address: "10.212.134.200")
            ])
    }

    func testActivityOfADropAndItsReconnects() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        helper.failStarts = 1  // the first attempt fails
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events.last, .reconnected(profileID: p.id))
        let sent = ActivityEvent.Kind.sending(.init(username: "alice", password: true, code: false))
        XCTAssertEqual(
            Array(m.activity(p.id).map(\.kind).dropFirst(4)),
            [
                .linkDropped(willReconnect: true), .reconnecting(attempt: 1, of: 3), acme,
                .failed(kind: .failed, reason: nil, credentialsSent: false),
                .nextTry(at: t0.addingTimeInterval(5 + 15)), .reconnecting(attempt: 2, of: 3), acme, sent,
                .authAccepted, .connected(address: "10.8.0.6")
            ])
    }

    func testActivityOfStops() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        let m = makeManager()
        try await m.disconnect(p.id)
        XCTAssertEqual(m.activity(p.id), [], "nothing was running")

        // A session another process started, not up yet: stopped; once up: disconnected.
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        try await ConnectionManager(store: store, helper: helper, clock: clock).disconnect(p.id)
        XCTAssertEqual(m.activity(p.id).last?.kind, .stoppedByUser)
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        try Data("2026-01-01 10:00:01 Initialization Sequence Completed\n".utf8).write(to: store.logURL(p.id))
        try await ConnectionManager(store: store, helper: helper, clock: clock).disconnect(p.id)
        XCTAssertEqual(m.activity(p.id).last?.kind, .disconnectedByUser)

        // Stopping the automatic reconnects after a drop.
        var timing = ConnectionManager.Timing()
        timing.reconnectDelays = [30, 30, 30]
        let app = makeManager(clock: SystemClock(), timing: timing)
        try await app.connect(p.id)
        helper.simulateExit(p.id)
        await app.refresh()
        XCTAssertNotNil(app.reconnecting[p.id])
        let stopped = try await app.disconnect(p.id)
        XCTAssertFalse(stopped)
        XCTAssertEqual(Array(app.activity(p.id).map(\.kind).suffix(2)), [.linkDropped(willReconnect: true), .stoppedByUser])
    }

    // MARK: failures

    static let refusedLog =
        "2026-10-25 09:41:00 Attempting to establish TCP connection with [AF_INET]203.0.113.10:1194\n"
        + "2026-10-25 09:41:00 TCP: connect to [AF_INET]203.0.113.10:1194 failed: Connection refused\n"

    /// A server that never answered got nothing: the failure says so, and the code's period is given back
    /// (the record from before is restored), so trying again does not wait for a fresh code.
    func testAnUnreachableServerGetsNoCode() async throws {
        let p = try makeOpenVPN(otp: .totp)
        let before = ConnectionManager.UsedOTPWindow(counter: TOTP.counter(params: p.totp, at: t0) - 1, period: 30)
        try JSONCoding.write(before, to: store.dir(p.id).appendingPathComponent(ConnectionManager.usedOTPFile), mode: 0o600)
        helper.openVPNStateLine = nil
        helper.startLog = Self.refusedLog
        var timing = ConnectionManager.Timing()
        timing.openVPNTimeout = 2
        let m = makeManager(timing: timing)
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(
                error as? PTError,
                .serverUnreachable(
                    server: "vpn.example.com:1194", reason: "Connection refused",
                    log: VPNLog.tail(Self.refusedLog)))
        }
        XCTAssertEqual(
            m.failures[p.id],
            ConnectionFailure(
                kind: .unreachable, at: t0.addingTimeInterval(2), reason: "Connection refused",
                credentialsSent: false, codeSent: false, tries: 1))
        XCTAssertEqual(m.usedCode(p.id), before, "the code never reached the server")
        XCTAssertEqual(helper.stops, [p.id])
        XCTAssertEqual(m.activity(p.id).last?.kind, .unreachable(tries: 1, reason: "Connection refused"))
        XCTAssertNotNil(m.lastError[p.id])

        // Trying again in the same period sends the same period's code at once.
        helper.openVPNStateLine = { LoopingManagementServer.connectedLine(since: $0) }
        helper.startLog = ""
        try await m.connect(p.id)
        XCTAssertFalse(
            m.activity(p.id).contains {
                if case .waitingForCode = $0.kind { return true }; return false
            })
        XCTAssertNil(m.failures[p.id], "cleared by the next attempt")
    }

    func testARejectedSignInUsedTheCodeAndIsNotRetried() async throws {
        let p = try makeOpenVPN(otp: .totp, autoReconnect: true)
        helper.openVPNStateLine = nil
        let log =
            "2026-10-25 09:41:01 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384\n"
            + "2026-10-25 09:41:02 AUTH: Received control message: AUTH_FAILED,Invalid OTP\n"
        helper.startLog = log
        let m = makeManager()
        do { try await m.connect(p.id); XCTFail("connected") } catch PTError.authFailed {}
        XCTAssertEqual(
            m.failures[p.id],
            ConnectionFailure(
                kind: .authRejected, at: t0, reply: "AUTH_FAILED,Invalid OTP",
                credentialsSent: true, codeSent: true, codeSecondsLeft: 10))
        XCTAssertEqual(m.usedCode(p.id), .init(counter: TOTP.counter(params: p.totp, at: t0), period: 30), "the code was used")
        XCTAssertEqual(helper.starts.count, 1, "never retried")
        XCTAssertNil(m.reconnecting[p.id])
        await m.clockCheckFinished(p.id)
        XCTAssertEqual(serverClock.gatewayCalls, [], "an OpenVPN server tells no time")
        XCTAssertEqual(serverClock.timeServerCalls, 0)
        XCTAssertNil(m.failures[p.id]?.clock)
    }

    static let fortiRejected =
        "INFO:   Connected to gateway.\n"
        + "ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.\n"

    func makeForti(trustedCert: String = "") throws -> Profile {
        var p = try store.create(name: "Acme Forti", type: .forti)
        p.host = "vpn.example.com"
        p.port = 10443
        p.username = "alice"
        p.trustedCert = trustedCert
        try store.save(p)
        try Secrets.set(p.id, .password, "pw")
        return p
    }

    /// A FortiGate that rejected the sign-in is asked for its time, once, as the VPN trusts it; the
    /// failure carries the result, and the profile keeps it for other processes.
    func testARejectedFortiSignInChecksTheGatewayClock() async throws {
        let digest = String(repeating: "ab", count: 32)
        let p = try makeForti(trustedCert: digest)
        let measured = ClockOffset(offsetSeconds: 48, source: .gateway, server: "vpn.example.com", checkedAt: t0)
        serverClock.gatewayResult = .success(measured)
        helper.startLog = Self.fortiRejected
        let m = makeManager()
        do { try await m.connect(p.id); XCTFail("connected") } catch PTError.authFailed {}
        await m.clockCheckFinished(p.id)

        XCTAssertEqual(serverClock.gatewayCalls, [.init(host: "vpn.example.com", port: 10443, trustedCert: digest)])
        XCTAssertEqual(serverClock.timeServerCalls, 0, "the time server only on request")
        XCTAssertEqual(m.failures[p.id]?.kind, .authRejected)
        XCTAssertEqual(m.failures[p.id]?.clock, measured)
        XCTAssertEqual(
            m.failures[p.id]?.details,
            "Your clock is 48 s behind the gateway’s, so one-time codes made from it are likely refused. Fix the clock, "
                + "then try again. Not retried, to avoid a lockout.")
        XCTAssertEqual(m.clockOffsets[p.id], measured)
        let file = URL(fileURLWithPath: store.dir(p.id).path).appendingPathComponent(ConnectionManager.clockFile)
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(makeManager().lastClock(p.id), measured, "another process reads it from the profile")
        XCTAssertEqual(helper.starts.count, 1, "never retried")

        // The next attempt starts without it; a check that fails leaves no measurement behind.
        serverClock.gatewayResult = .failure(ServerClock.Failure.untrusted)
        let other = try makeForti()
        do { try await m.connect(other.id); XCTFail("connected") } catch PTError.authFailed {}
        await m.clockCheckFinished(other.id)
        XCTAssertEqual(serverClock.gatewayCalls.last, .init(host: "vpn.example.com", port: 10443, trustedCert: nil))
        XCTAssertNil(m.failures[other.id]?.clock)
        XCTAssertNil(m.lastClock(other.id))
    }

    /// Only a rejected sign-in: a gateway that cannot be reached is not asked again for its time.
    func testOtherFortiFailuresDoNotCheckTheClock() async throws {
        let p = try makeForti()
        helper.startLog = "ERROR:  connect: Operation timed out\nINFO:   Closed connection to gateway.\n"
        helper.onStatus = { [helper] _ in helper!.simulateExit(p.id) }
        let m = makeManager()
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        await m.clockCheckFinished(p.id)
        XCTAssertEqual(m.failures[p.id]?.kind, .unreachable)
        XCTAssertEqual(serverClock.gatewayCalls, [])
    }

    /// "Check" asks the time server and adds the result to a rejected sign-in's failure.
    func testCheckingTheClockOnRequest() async throws {
        let p = try makeOpenVPN()
        helper.openVPNStateLine = nil
        helper.startLog =
            "2026-10-25 09:41:01 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384\n"
            + "2026-10-25 09:41:02 AUTH: Received control message: AUTH_FAILED\n"
        let m = makeManager()
        do { try await m.connect(p.id); XCTFail("connected") } catch PTError.authFailed {}
        XCTAssertEqual(serverClock.timeServerCalls, 0)

        let measured = ClockOffset(offsetSeconds: -31, source: .timeServer, server: "time.apple.com", checkedAt: t0.addingTimeInterval(5))
        serverClock.timeServerResult = .success(measured)
        let result = try await m.checkClock()
        XCTAssertEqual(result, measured)
        XCTAssertEqual(m.timeServerClock, measured)
        XCTAssertEqual(m.failures[p.id]?.clock, measured)
        XCTAssertEqual(serverClock.timeServerCalls, 1)
        XCTAssertEqual(serverClock.gatewayCalls, [])

        serverClock.timeServerResult = .failure(ServerClock.Failure.timedOut)
        do { _ = try await m.checkClock(); XCTFail("expected a failure") } catch {
            XCTAssertEqual(error as? ServerClock.Failure, .timedOut)
        }
        XCTAssertEqual(m.failures[p.id]?.clock, measured, "kept")
    }

    func testAServerNameThatDoesNotResolve() async throws {
        let p = try makeOpenVPN()
        helper.openVPNStateLine = nil
        helper.startLog = "2026-10-25 09:41:00 RESOLVE: Cannot resolve host address: vpn.example.com:1194 (Name or service not known)\n"
        let m = makeManager()
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(error as? PTError, .hostNotFound(server: "vpn.example.com:1194", log: VPNLog.tail(helper.startLog)))
        }
        XCTAssertEqual(m.failures[p.id]?.kind, .hostNotFound)
        XCTAssertEqual(m.failures[p.id]?.reason, "Name or service not known")
        XCTAssertEqual(m.activity(p.id).last?.kind, .failed(kind: .hostNotFound, reason: "Name or service not known", credentialsSent: false))
    }

    /// dyld stops the tool at launch on a macOS that lacks a symbol it imports: the connect fails at once
    /// with its own error and failure kind, for OpenVPN and openfortivpn alike, and nothing counts as sent.
    func testAToolThatDoesNotRunOnThisMacOS() async throws {
        helper.openVPNStateLine = nil
        helper.exitAtStart = true
        helper.startLog = """
            dyld[4242]: Symbol not found: _strchrnul
              Referenced from: <3C3A9F0E-1D6B-3C2E-9E4A-0B6E1C9A7F21> /var/run/passtunnel/run/Frameworks/libidn2.0.dylib (built for macOS 26.0 which is newer than running OS)
              Expected in:     <5F2B8E1A-6C4D-3A9B-8E7F-2D1C0B9A8E76> /usr/lib/libSystem.B.dylib

            """
        let m = makeManager()
        let openVPN = try makeOpenVPN()
        var forti = try store.create(name: "Forti", type: .forti)
        forti.host = "vpn.example.com"
        forti.username = "alice"
        try store.save(forti)
        try Secrets.set(forti.id, .password, "pw")
        for p in [openVPN, forti] {
            do { try await m.connect(p.id); XCTFail("connected") } catch {
                XCTAssertEqual(
                    error as? PTError, .toolUnsupported(reason: "Symbol not found: _strchrnul", log: VPNLog.tail(helper.startLog)), p.name)
                XCTAssertEqual(
                    error.localizedDescription,
                    "This VPN tool does not run on this version of macOS (Symbol not found: _strchrnul). Check for a PassTunnel update.")
            }
            XCTAssertEqual(m.failures[p.id]?.kind, .toolUnsupported, p.name)
            XCTAssertEqual(m.failures[p.id]?.reason, "Symbol not found: _strchrnul", p.name)
            XCTAssertEqual(m.failures[p.id]?.credentialsSent, false, p.name)
            XCTAssertEqual(
                m.activity(p.id).last?.kind, .failed(kind: .toolUnsupported, reason: "Symbol not found: _strchrnul", credentialsSent: false),
                p.name)
            XCTAssertEqual(m.state(p.id), .disconnected, p.name)
        }
    }

    /// dyld's words where a server could have put them (after the tool's own output), or a tool that keeps
    /// running: not a reason to fail a connect.
    func testDyldLinesFromElsewhereDoNotFailAConnect() async throws {
        let dyld = "dyld[4242]: Symbol not found: _strchrnul\n"
        let m = makeManager()
        let p = try makeOpenVPN()
        for log in [
            "2026-10-25 09:41:00 OpenVPN 2.7.8 aarch64-apple-darwin25.6.0 [SSL (OpenSSL)]\n" + dyld,
            dyld + "2026-10-25 09:41:00 OpenVPN 2.7.8 aarch64-apple-darwin25.6.0 [SSL (OpenSSL)]\n"
        ] {
            helper.startLog = log
            try await m.connect(p.id)
            XCTAssertTrue(m.state(p.id).isConnected, log)
            XCTAssertNil(m.failures[p.id], log)
            _ = try await m.disconnect(p.id)
        }
        // A tool that exits with dyld's words after its own: a plain failure.
        helper.openVPNStateLine = nil
        helper.exitAtStart = true
        helper.startLog = "2026-10-25 09:41:00 OpenVPN 2.7.8 aarch64-apple-darwin25.6.0\n" + dyld
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(error as? PTError, .connectFailed(VPNLog.tail(helper.startLog)))
        }
        XCTAssertEqual(m.failures[p.id]?.kind, .failed)
    }

    /// The tool tried and nothing answered within the connect's limit: unreachable, not a plain timeout.
    /// A log that says nothing at all stays a timeout (`testProcessExitAndTimeout`).
    func testNoAnswerUntilTheLimitIsUnreachable() async throws {
        let p = try makeOpenVPN()
        helper.openVPNStateLine = nil
        helper.startLog = "2026-10-25 09:41:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194\n"
        let m = makeManager()
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(
                error as? PTError,
                .serverUnreachable(
                    server: "vpn.example.com:1194", reason: "no answer within 60 seconds",
                    log: VPNLog.tail(helper.startLog)))
        }
        XCTAssertEqual(AutomationErrorCode.of(PTError.serverUnreachable(server: "", reason: "", log: "")), .serverUnreachable)

        // Reached, then nothing: a timeout after the sign-in was sent.
        helper.startLog = "2026-10-25 09:41:01 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384\n"
        do { try await m.connect(p.id); XCTFail("connected") } catch { XCTAssertEqual(error as? PTError, .connectTimeout(60)) }
        XCTAssertEqual(m.failures[p.id]?.kind, .timeout)
        XCTAssertEqual(m.failures[p.id]?.credentialsSent, true)
    }

    func testFortiThatExitsWithoutAnAnswer() async throws {
        var p = try store.create(name: "Acme Forti", type: .forti)
        p.host = "vpn.example.com"
        p.port = 10443
        p.username = "alice"
        try store.save(p)
        try Secrets.set(p.id, .password, "pw")
        helper.startLog = "ERROR:  connect: Operation timed out\nINFO:   Closed connection to gateway.\n"
        helper.onStatus = { [helper] _ in helper!.simulateExit(p.id) }  // openfortivpn gave up
        let m = makeManager()
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(
                error as? PTError,
                .serverUnreachable(
                    server: "vpn.example.com:10443", reason: "Operation timed out",
                    log: VPNLog.tail(helper.startLog)))
        }
        XCTAssertEqual(m.failures[p.id]?.credentialsSent, false)
    }

    func testCancelledAttemptsAreTypedButNotShownAsErrors() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m, otp: .totp)
        authenticator.results = [PTError.userConfirmationCancelled]
        do { try await m.connect(p.id); XCTFail("connected") } catch { XCTAssertEqual(error as? PTError, .userConfirmationCancelled) }
        XCTAssertEqual(m.failures[p.id], ConnectionFailure(kind: .cancelled, at: t0))
        XCTAssertNil(m.lastError[p.id])
    }

    /// A session another process started is that process's to record.
    func testFollowingASessionRecordsNothing() async throws {
        let p = try makeOpenVPN()
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        let m = makeManager()
        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertEqual(m.activity(p.id), [])
    }
}
