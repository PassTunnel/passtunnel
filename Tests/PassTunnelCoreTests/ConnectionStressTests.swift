import Combine
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit
import PassTunnelShared

/// Virtual time where `sleep` blocks until the test releases it (or the sleeping task is cancelled),
/// so a test can act while the manager is in the middle of a wait.
final class GateClock: ConnectionClock, @unchecked Sendable {
    private struct Sleeper {
        let id: Int
        let seconds: TimeInterval
        let cont: CheckedContinuation<Void, Error>
    }

    private let lock = NSLock()
    private var current: Date
    private var sleepers: [Sleeper] = []
    private var nextID = 0
    private var _sleeps: [TimeInterval] = []

    init(_ start: Date) { current = start }

    func now() -> Date { lock.lock(); defer { lock.unlock() }; return current }
    var pending: Int { lock.lock(); defer { lock.unlock() }; return sleepers.count }
    var sleeps: [TimeInterval] { lock.lock(); defer { lock.unlock() }; return _sleeps }

    func sleep(_ seconds: TimeInterval) async throws {
        let id: Int = { lock.lock(); defer { lock.unlock() }; nextID += 1; return nextID }()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                lock.lock()
                if Task.isCancelled {
                    lock.unlock()
                    cont.resume(throwing: CancellationError())
                    return
                }
                sleepers.append(Sleeper(id: id, seconds: seconds, cont: cont))
                _sleeps.append(seconds)
                lock.unlock()
            }
        } onCancel: {
            lock.lock()
            let index = sleepers.firstIndex { $0.id == id }
            let sleeper = index.map { sleepers.remove(at: $0) }
            lock.unlock()
            sleeper?.cont.resume(throwing: CancellationError())
        }
    }

    /// Wakes every sleeper, advancing the clock by the longest of their waits.
    func releaseAll() {
        lock.lock()
        let woken = sleepers
        sleepers.removeAll()
        if let longest = woken.map(\.seconds).max() { current = current.addingTimeInterval(max(0, longest)) }
        lock.unlock()
        woken.forEach { $0.cont.resume() }
    }
}

/// Adversarial connection scenarios and TOTP reuse avoidance, with a fake helper, fake management
/// sockets and virtual clocks (no real VPN, helper or Keychain service).
@MainActor
final class ConnectionStressTests: XCTestCase {
    var home: String!
    var helper: FakeHelper!
    var clock: FakeClock!
    var events: [ConnectionEvent] = []
    var bag: Set<AnyCancellable> = []
    var store: ProfileStore { ProfileStore() }

    /// 20 s into a 30 s window: 10 s left.
    let t0 = Date(timeIntervalSince1970: 1_700_000_000)
    let totpSecret = "JBSWY3DPEHPK3PXP"

    override func setUp() async throws {
        var template = Array("/tmp/pt-cs-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        home = String(cString: made)
        setenv("PASSTUNNEL_HOME", home, 1)
        setenv("PASSTUNNEL_KEYCHAIN_SERVICE", "PassTunnelTests-\(UUID().uuidString)", 1)
        helper = FakeHelper()
        clock = FakeClock(t0)
        events = []
        bag = []
    }

    override func tearDown() async throws {
        helper.shutdown()
        Secrets.deleteAllInOverriddenService()
        try? FileManager.default.removeItem(atPath: home)
    }

    func makeManager(clock: ConnectionClock? = nil, healthProbe: ConnectionManager.HealthProbe? = nil) -> ConnectionManager {
        let m = ConnectionManager(store: store, helper: helper, clock: clock ?? self.clock,
                                  healthProbe: healthProbe ?? { _ in (true, 1) },
                                  preferences: { Preferences() })
        m.events.sink { [weak self] in self?.events.append($0) }.store(in: &bag)
        return m
    }

    @discardableResult
    func makeOpenVPN(_ name: String = "Acme", otp: OTPMode = .totp, autoReconnect: Bool = false,
                     period: Int = 30, healthHost: String = "") throws -> Profile {
        var p = try store.create(name: name, type: .openvpn)
        p.username = "alice"
        p.otpMode = otp
        p.totp.period = period
        p.autoReconnect = autoReconnect
        p.healthHost = healthHost
        try store.save(p)
        try Data("client\nremote vpn.example.com 1194\nauth-user-pass\n".utf8).write(to: store.ovpnURL(p.id))
        try Secrets.set(p.id, .password, "pw")
        if otp == .totp { try Secrets.set(p.id, .totp, totpSecret) }
        return p
    }

    func code(at date: Date, period: Int = 30) throws -> String {
        TOTP.code(secret: try TOTP.decodeSecret(totpSecret), params: TOTPParams(period: period), at: date)
    }

    func secrets() -> [String?] {
        helper.starts.map { if case .startOpenVPN(let s) = $0 { return s.secret }; return nil }
    }

    func usedCodeURL(_ id: String) -> URL { store.dir(id).appendingPathComponent(ConnectionManager.usedOTPFile) }

    func waitUntil(timeout: TimeInterval = 3, file: StaticString = #filePath, line: UInt = #line,
                   _ condition: () -> Bool) async {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            if Date() > deadline { return XCTFail("condition not met in time", file: file, line: line) }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }

    // MARK: TOTP reuse avoidance

    func testSameWindowReconnectWaitsForTheNextCode() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        var seen: [ConnectionState] = []
        m.$states.compactMap { $0[p.id] }.sink { seen.append($0) }.store(in: &bag)

        try await m.connect(p.id)
        XCTAssertEqual(clock.sleeps, [], "fresh window, 10 s left: no wait")
        try await m.disconnect(p.id)
        seen.removeAll()

        try await m.connect(p.id)                                   // same window, 10 s left
        XCTAssertEqual(clock.sleeps.count, 1)
        XCTAssertEqual(clock.sleeps.first ?? 0, 10.25, accuracy: 0.01)
        XCTAssertTrue(seen.contains(.connecting(ConnectionManager.Phase.waitingForCode)), "\(seen)")
        XCTAssertEqual(secrets(), ["pw" + (try code(at: t0)), "pw" + (try code(at: t0.addingTimeInterval(10.25)))])
        XCTAssertNotEqual(secrets()[0], secrets()[1])
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertTrue(events.isEmpty, "\(events)")
    }

    /// CLI connects (and later disconnects), then the app connects within the same window.
    func testUsedWindowIsSharedBetweenProcesses() async throws {
        let p = try makeOpenVPN()
        let cli = makeManager()
        try await cli.connect(p.id)
        try await cli.disconnect(p.id)

        let url = usedCodeURL(p.id)
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(cli.usedCode(p.id), .init(counter: TOTP.counter(params: TOTPParams(), at: t0), period: 30))
        XCTAssertEqual(try store.get(p.id).id, p.id, "profile.json untouched")

        let app = makeManager()                                     // a separate process: no shared memory
        try await app.connect(p.id)
        XCTAssertEqual(clock.sleeps.count, 1)
        XCTAssertEqual(clock.sleeps.first ?? 0, 10.25, accuracy: 0.01)
        XCTAssertEqual(secrets().last, "pw" + (try code(at: t0.addingTimeInterval(10.25))))
    }

    func testNextWindowNeedsNoWait() async throws {
        let p = try makeOpenVPN()
        try await makeManager().connect(p.id)
        helper.simulateExit(p.id)

        clock = FakeClock(t0.addingTimeInterval(15))                // next window, 25 s left
        let m = makeManager()
        try await m.connect(p.id)
        XCTAssertEqual(clock.sleeps, [])
        XCTAssertEqual(secrets().last, "pw" + (try code(at: t0.addingTimeInterval(15))))
    }

    func testRejectedStartDoesNotUseUpTheCode() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        helper.failStarts = 1
        do { try await m.connect(p.id); XCTFail("expected an error") } catch {
            XCTAssertEqual(error as? PTError, .helperFailed("boom"))
        }
        XCTAssertNil(m.usedCode(p.id))
        XCTAssertFalse(FileManager.default.fileExists(atPath: usedCodeURL(p.id).path))
        try await m.connect(p.id)
        XCTAssertEqual(clock.sleeps, [], "the code never reached the server: no wait")
    }

    func testCodeSentToARejectingServerIsNotReused() async throws {
        let p = try makeOpenVPN()
        helper.openVPNStateLine = nil
        helper.startLog = "AUTH: Received control message: AUTH_FAILED\n"
        let m = makeManager()
        do { try await m.connect(p.id); XCTFail() } catch { XCTAssertEqual((error as? PTError)?.logTail.contains("AUTH_FAILED"), true) }
        helper.openVPNStateLine = { LoopingManagementServer.connectedLine(since: $0) }
        helper.startLog = ""
        try await m.connect(p.id)
        XCTAssertEqual(clock.sleeps.first ?? 0, 10.25, accuracy: 0.01)
        XCTAssertNotEqual(secrets()[0], secrets()[1])
    }

    func testAutoReconnectAfterDropWaitsForTheNextCode() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events, [.dropped(profileID: p.id, willReconnect: true), .reconnected(profileID: p.id)])
        // Backoff 5 s lands in the same window (5 s left) → wait 5.25 s for the next code.
        XCTAssertEqual(clock.sleeps.count, 2)
        XCTAssertEqual(clock.sleeps.first, 5)
        XCTAssertEqual(clock.sleeps.last ?? 0, 5.25, accuracy: 0.01)
        XCTAssertEqual(secrets().last, "pw" + (try code(at: t0.addingTimeInterval(10.25))))
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    func testDamagedForeignOrStaleRecordsAreIgnored() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        let now = TOTP.counter(params: TOTPParams(), at: t0)

        try Data("garbage".utf8).write(to: usedCodeURL(p.id))
        try await m.connect(p.id)
        XCTAssertEqual(clock.sleeps, [], "unreadable record")
        try await m.disconnect(p.id)

        // Another period (the profile was edited), or a window from the future (the clock went back).
        for record in [ConnectionManager.UsedOTPWindow(counter: now, period: 60),
                       ConnectionManager.UsedOTPWindow(counter: now + 100, period: 30)] {
            try JSONCoding.write(record, to: usedCodeURL(p.id), mode: 0o600)
            try await m.connect(p.id)
            try await m.disconnect(p.id)
        }
        XCTAssertEqual(clock.sleeps, [], "never wait for a window that is not the current one")
        XCTAssertEqual(m.usedCode(p.id), .init(counter: now, period: 30), "rewritten after each start")
    }

    func testLongPeriodWaitIsBoundedByOneWindow() async throws {
        let p = try makeOpenVPN(period: 60)                         // t0 is 20 s into a 60 s window
        let m = makeManager()
        try await m.connect(p.id)
        try await m.disconnect(p.id)
        try await m.connect(p.id)
        XCTAssertEqual(clock.sleeps.count, 1)
        XCTAssertEqual(clock.sleeps[0], 40.25, accuracy: 0.01)
        XCTAssertLessThanOrEqual(clock.sleeps[0], 60.25)
        XCTAssertEqual(secrets().last, "pw" + (try code(at: t0.addingTimeInterval(40.25), period: 60)))
    }

    func testTypedCodesAreNotTracked() async throws {
        let p = try makeOpenVPN(otp: .ask)
        let m = makeManager()
        try await m.connect(p.id, given: [.otp: "123456"])
        try await m.disconnect(p.id)
        try await m.connect(p.id, given: [.otp: "654321"])
        XCTAssertNil(m.usedCode(p.id))
        XCTAssertEqual(clock.sleeps, [])
    }

    func testWatcherIgnoresTheUsedCodeRecord() {
        let dir = store.dir("acme").path
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: dir + "/" + ConnectionManager.usedOTPFile))
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: dir + "/." + ConnectionManager.usedOTPFile + ".1A2B.tmp"))
        XCTAssertTrue(ProfilesWatcher.isRelevant(path: dir + "/profile.json"))
    }

    // MARK: cancelling

    /// A cancelled connect must not keep the profile busy until its code wait would have ended:
    /// connecting again right away has to work.
    func testDisconnectEndsTheCodeWaitAtOnce() async throws {
        let p = try makeOpenVPN()
        let gate = GateClock(t0.addingTimeInterval(7))              // 3 s left: waits for a fresh code
        let m = makeManager(clock: gate)
        defer { gate.releaseAll() }

        var outcome: Error?
        var finished = false
        Task {
            do { try await m.connect(p.id) } catch { outcome = error }
            finished = true
        }
        await waitUntil { gate.pending == 1 }
        XCTAssertEqual(m.state(p.id), .connecting(ConnectionManager.Phase.waitingForCode))

        try await m.disconnect(p.id)
        await waitUntil { finished }
        XCTAssertEqual(outcome as? PTError, .connectCancelled)
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertTrue(helper.starts.isEmpty, "no code was sent")
        XCTAssertEqual(gate.pending, 0)

        // Connecting again starts a new wait instead of returning as a no-op.
        finished = false
        outcome = nil
        Task {
            do { try await m.connect(p.id) } catch { outcome = error }
            finished = true
        }
        await waitUntil { gate.pending == 1 }
        gate.releaseAll()
        await waitUntil { finished }
        XCTAssertNil(outcome)
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertEqual(helper.starts.count, 1)
        XCTAssertTrue(events.isEmpty, "\(events)")
    }

    func testDisconnectWhileConnectingStopsTheToolWithoutADrop() async throws {
        let p = try makeOpenVPN(otp: .none, autoReconnect: true)
        helper.openVPNStateLine = { _ in "1700000000,WAIT,,,,,,," }
        let gate = GateClock(t0)
        let m = makeManager(clock: gate)
        defer { gate.releaseAll() }
        var outcome: Error?
        var finished = false
        Task {
            do { try await m.connect(p.id) } catch { outcome = error }
            finished = true
        }
        await waitUntil { gate.pending == 1 }                       // polling the management socket
        XCTAssertTrue(m.state(p.id).isConnecting)
        try await m.disconnect(p.id)
        gate.releaseAll()
        await waitUntil { finished }
        XCTAssertEqual(outcome as? PTError, .connectCancelled)
        XCTAssertEqual(helper.stops, [p.id])
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertNil(m.lastError[p.id], "a cancel is not an error")
        await m.refresh()
        XCTAssertTrue(events.isEmpty, "\(events)")
        XCTAssertNil(m.reconnecting[p.id])
    }

    func testConcurrentConnectsStartTheToolOnce() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        async let a: Void = m.connect(p.id)
        async let b: Void = m.connect(p.id)
        _ = try await (a, b)
        XCTAssertEqual(helper.starts.count, 1)
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    // MARK: drops, reconnects, outages

    func testHelperOutageIsNotADrop() async throws {
        let p = try makeOpenVPN(otp: .none, autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        helper.statusError = HelperClientError.timeout(15)
        await m.refresh()
        XCTAssertTrue(m.state(p.id).isConnected, "the management socket still answers")
        XCTAssertNotNil(m.helperError)
        XCTAssertTrue(events.isEmpty)
        helper.statusError = nil
        await m.refresh()
        XCTAssertNil(m.helperError)
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertTrue(events.isEmpty)
    }

    func testManualConnectDuringBackoffCancelsTheReconnect() async throws {
        let p = try makeOpenVPN(otp: .none, autoReconnect: true)
        let gate = GateClock(t0)
        let m = makeManager(clock: gate)
        defer { gate.releaseAll() }
        try await m.connect(p.id)
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { gate.pending == 1 }                       // backoff of attempt 1
        XCTAssertEqual(m.reconnecting[p.id]?.attempt, 1)

        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertNil(m.reconnecting[p.id])
        await waitUntil { gate.pending == 0 }
        XCTAssertEqual(helper.starts.count, 2)
        XCTAssertEqual(events, [.dropped(profileID: p.id, willReconnect: true)])
    }

    func testProfileDeletedDuringBackoffIsForgotten() async throws {
        let p = try makeOpenVPN(otp: .none, autoReconnect: true)
        let gate = GateClock(t0)
        let m = makeManager(clock: gate)
        defer { gate.releaseAll() }
        try await m.connect(p.id)
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { gate.pending == 1 }
        try ProfileStore().delete(p.id)                             // e.g. `passtunnel rm`
        await m.refresh()
        XCTAssertNil(m.reconnecting[p.id])
        XCTAssertNil(m.states[p.id])
        await waitUntil { gate.pending == 0 }
        XCTAssertEqual(helper.starts.count, 1)
        XCTAssertEqual(events, [.dropped(profileID: p.id, willReconnect: true)])
    }

    func testStopByAnotherProcessDuringSleepIsNotReconnectedOnWake() async throws {
        let p = try makeOpenVPN(otp: .none, autoReconnect: true)
        let m = makeManager()
        try await m.connect(p.id)
        m.handleWillSleep()
        try await makeManager().disconnect(p.id)                    // the CLI, while the app sleeps
        await m.handleDidWake()
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertNil(m.reconnecting[p.id])
        XCTAssertEqual(helper.starts.count, 1)
        XCTAssertTrue(events.isEmpty, "\(events)")
    }

    func testHealthResultArrivingAfterDisconnectIsIgnored() async throws {
        let p = try makeOpenVPN(otp: .none, autoReconnect: true, healthHost: "10.0.0.5")
        weak var manager: ConnectionManager?
        let m = makeManager(healthProbe: { [id = p.id] _ in
            // The user disconnects while the probe is still running.
            _ = try? await manager?.disconnect(id)
            return (false, 0)
        })
        manager = m
        try await m.connect(p.id)
        await m.runHealthChecks()
        try await m.connect(p.id)
        await m.runHealthChecks()
        XCTAssertNil(m.health[p.id])
        XCTAssertTrue(events.isEmpty, "a probe of a stopped tunnel must not report an outage: \(events)")
        XCTAssertEqual(helper.starts.count, 2, "and must not force a reconnect")
    }

    func testFortiAuthFailureIsNotRetried() async throws {
        var p = try store.create(name: "Acme Forti", type: .forti)
        p.host = "vpn.example.com"
        p.username = "alice"
        p.autoReconnect = true
        try store.save(p)
        try Secrets.set(p.id, .password, "pw")
        helper.startLog = "INFO:   Got addresses: [10.212.134.200]\nINFO:   Tunnel is up and running.\n"
        let m = makeManager()
        try await m.connect(p.id)
        helper.startLog = "ERROR:  Could not authenticate to gateway. Please check the password.\n"
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { self.events.count == 2 }
        guard case .reconnectFailed = events.last else { return XCTFail("\(events)") }
        XCTAssertEqual(helper.starts.count, 2, "one attempt, then stop: retrying could lock the account")
        XCTAssertEqual(m.state(p.id), .disconnected)
    }
}
