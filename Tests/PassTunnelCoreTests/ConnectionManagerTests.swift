import Combine
import XCTest
@testable import PassTunnelCore
import PassTunnelShared

// MARK: - Fakes

/// OpenVPN-like management server that answers `state` with a mutable line, for any number of clients.
final class LoopingManagementServer: @unchecked Sendable {
    let path: String
    private let lock = NSLock()
    private var line: String
    private var stopped = false
    private let listenFD: Int32
    private let finished = DispatchSemaphore(value: 0)

    init(path: String, stateLine: String) {
        self.path = path
        self.line = stateLine
        unlink(path)
        listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: path.utf8)
            raw[path.utf8.count] = 0
        }
        let fd = listenFD
        _ = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        listen(listenFD, 8)
        Thread.detachNewThread { [self] in self.loop() }
    }

    var stateLine: String {
        get { lock.lock(); defer { lock.unlock() }; return line }
        set { lock.lock(); line = newValue; lock.unlock() }
    }

    private var isStopped: Bool { lock.lock(); defer { lock.unlock() }; return stopped }

    private func loop() {
        while !isStopped {
            var p = pollfd(fd: listenFD, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, 50) > 0 else { continue }
            let c = accept(listenFD, nil, nil)
            guard c >= 0 else { continue }
            var one: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            FakeManagementServer.send(c, FakeManagementServer.banner)
            let cmd = FakeManagementServer.readLine(c)
            if cmd == "state" {
                FakeManagementServer.send(c, stateLine + "\r\nEND\r\n")
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
    /// Delays (seconds) for the next `status` calls, consumed in order.
    var statusDelays: [TimeInterval] = []
    /// Runs when a start request arrives, before the tool "starts" (e.g. to edit files meanwhile).
    var onStart: ((HelperRequest) -> Void)?
    /// When set, `status` calls fail with this error (helper unreachable).
    var statusError: Error?

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
        requests.compactMap { if case .stop(let id) = $0 { return id }; return nil }
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
            if let error = locked({ statusError }) { throw error }
            let (snapshot, socks, delay) = locked { () -> ([String: Int32], [String: String], TimeInterval) in
                (_running, sockets, _statusDelayPop())
            }
            if delay > 0 { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            return .success(running: snapshot, mgmtSockets: socks)
        case .startOpenVPN(let s):
            onStart?(request)
            if let failure = takeFailure() { return failure }
            write(startLog, to: s.logPath)
            let sock = s.profileDir + "/" + PT.mgmtSocketName
            if let line = openVPNStateLine {
                let server = LoopingManagementServer(path: sock, stateLine: line(Date()))
                locked { servers[s.profileID] = server }
            }
            locked { _running[s.profileID] = 4242; sockets[s.profileID] = sock }
            return .success(pid: 4242, mgmtSocket: sock)
        case .startForti(let s):
            if let failure = takeFailure() { return failure }
            write(startLog, to: s.logPath)
            locked { _running[s.profileID] = 4343 }
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
        setenv("PASSTUNNEL_KEYCHAIN_SERVICE", service, 1)
        helper = FakeHelper()
        clock = FakeClock(t0)
        events = []
        bag = []
        healthResults = []
        routeTable = []
        prefs = Preferences()
    }

    override func tearDown() async throws {
        helper.shutdown()
        Secrets.deleteAllInOverriddenService()
        try? FileManager.default.removeItem(atPath: home)
    }

    func makeManager(clock: ConnectionClock? = nil, timing: ConnectionManager.Timing = .init()) -> ConnectionManager {
        let m = ConnectionManager(store: store, helper: helper, clock: clock ?? self.clock,
                                  healthProbe: { [weak self] _ in
                                      await MainActor.run {
                                          guard let self, !self.healthResults.isEmpty else { return (false, 0) }
                                          return (self.healthResults.removeFirst(), 12)
                                      }
                                  },
                                  preferences: { [weak self] in self?.prefs ?? Preferences() },
                                  routes: { [weak self] in self?.routeTable ?? [] },
                                  timing: timing)
        m.events.sink { [weak self] in self?.events.append($0) }.store(in: &bag)
        return m
    }

    @discardableResult
    func makeOpenVPN(_ name: String = "Acme", otp: OTPMode = .none, autoReconnect: Bool = false,
                     healthHost: String = "", sessionLimitMin: Int = 0) throws -> Profile {
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

    func waitUntil(timeout: TimeInterval = 5, file: StaticString = #filePath, line: UInt = #line,
                   _ condition: () -> Bool) async {
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
        XCTAssertEqual(s.secret, "pw" + (try code(at: t0)))          // combined, {password}{otp}
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
        helper.startLog = "INFO:   Connected to gateway.\nINFO:   Got addresses: [10.212.134.200], ns [10.0.0.1, 10.0.0.2]\n"
            + "INFO:   Tunnel is up and running.\n"
        let m = makeManager()
        try await m.connect(p.id)

        guard case .connected(let ip, _) = m.state(p.id) else { return XCTFail("\(m.state(p.id))") }
        XCTAssertEqual(ip, "10.212.134.200")
        guard case .startForti(let s) = helper.starts.first else { return XCTFail() }
        XCTAssertEqual([s.host, s.username, s.password], ["vpn.example.com", "alice", "pw"])
        XCTAssertEqual(s.port, 10443)
        XCTAssertEqual(s.otp, try code(at: t0))                      // separate delivery
        XCTAssertNil(s.description.range(of: "pw,"))

        // The poll keeps it connected (helper status + log).
        await m.refresh()
        XCTAssertEqual(m.state(p.id).isConnected, true)
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .disconnected)
    }

    func testAuthFailureFromLog() async throws {
        let p = try makeOpenVPN()
        helper.openVPNStateLine = nil
        helper.startLog = "Mon Oct 20 10:00:00 2026 TCP connection established\n"
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

    /// The app keeps a loaded copy of its profiles; the CLI may change the file and the Keychain
    /// afterwards. Connecting must use what is stored at that moment.
    func testConnectUsesProfileAndSecretAsStoredNow() async throws {
        let p = try makeOpenVPN(otp: .ask)
        let m = makeManager()
        await m.refresh()                                   // the manager has seen the old profile

        // "CLI": another store instance, as a separate process would use.
        let newSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        var changed = try ProfileStore().get(p.id)
        changed.otpMode = .totp
        changed.totp.period = 60
        try ProfileStore().save(changed)
        try Secrets.set(p.id, .totp, newSecret)
        try Secrets.set(p.id, .password, "new-pw")

        try await m.connect(p.id)                           // no `.otp` given: the old copy would need one
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
            _ = try? ProfileStore().update(id) { $0.healthHost = "10.0.0.5"; $0.totp.period = 60 }
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
        clock = FakeClock(t0.addingTimeInterval(7))          // 27 s into the window: 3 s left
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

    func testPhasesOnlyMoveForward() {
        typealias P = ConnectionManager.Phase
        var progress = ConnectionManager.PhaseProgress()
        let seen = [P.preparing, P.starting, P.configuring, P.preparing, P.configuring, P.signingIn, P.reconnecting,
                    P.reconnecting, P.connecting].filter { progress.shouldPrint($0) }
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

    func testDropReconnectsWithBackoff() async throws {
        let p = try makeOpenVPN(otp: .totp, autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        helper.failStarts = 2                                  // attempts 1 and 2 fail, 3 succeeds
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

        try await m.disconnect(p.id)                         // manual action
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
        let slowPoll = Task { await m.refresh() }              // sees "not running" and returns late
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
        let older = Task { await m.refresh() }                 // snapshot: not running
        try await Task.sleep(nanoseconds: 100_000_000)
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        await m.refresh()                                      // newer: connected
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
        RoutingTable.Route(destination: "128.0.0.0", prefixLength: 1, interface: "utun9"),
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
            XCTAssertEqual(error.localizedDescription,
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
        let p = try makeOpenVPN()                                  // no redirect-gateway in the config
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
        try await m.connect(split.id)                              // does not redirect: fine next to it
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
            XCTAssertEqual(error as? PTError, .setupFailed(reason: "setting DNS failed, already redirecting to another tunnel",
                                                           log: VPNLog.tail(helper.startLog)))
            XCTAssertFalse((error as? PTError)?.logTail.isEmpty ?? true)
        }
        XCTAssertEqual(helper.stops, [p.id])
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertNotNil(m.lastError[p.id])
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
            XCTAssertEqual((error as? PTError).map { if case .setupFailed = $0 { return true }; return false }, true, "\(error)")
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
        XCTAssertEqual(m.warnings[p.id],
                       "Connected, but part of the network setup failed: add net 203.0.113.5: gateway 192.168.1.1: File exists")
        // Another process (the CLI after connecting elsewhere) sees the same.
        let cli = ConnectionManager(store: store, helper: helper, clock: clock, routes: { [] })
        await cli.refresh()
        XCTAssertNotNil(cli.warnings[p.id])
        try await m.disconnect(p.id)
        XCTAssertNil(m.warnings[p.id])
    }

    func testLeftoverServerRouteLeavesNoWarning() async throws {
        for log in [FullTunnelTests.leftoverServerRouteLog, FullTunnelTests.duplicateServerRouteLog] {
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
        timing.openVPNTimeout = 100_000          // virtual seconds: the fake clock runs fast
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
            XCTAssertEqual((error as? PTError).map { if case .authFailed = $0 { return true }; return false }, true, "\(error)")
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
}
