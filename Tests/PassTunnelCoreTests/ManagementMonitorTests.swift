import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit
import PassTunnelShared

/// The app keeps one management connection per OpenVPN and follows real-time state; the CLI, which
/// then finds the interface busy, reads the state the app shares.
final class PersistentManagementQuerierTests: XCTestCase {
    var dir: String!
    var sock: String { dir + "/mgmt.sock" }

    override func setUpWithError() throws {
        var template = Array("/tmp/pt-mon-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        dir = String(cString: made)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: dir)
    }

    func waitForSocket() {
        let deadline = Date().addingTimeInterval(2)
        while !FileManager.default.fileExists(atPath: sock) && Date() < deadline { usleep(10_000) }
    }

    static let auth = "1700000000,AUTH,,,,,,,"
    static let connected = "1700000010,CONNECTED,SUCCESS,10.8.0.6,203.0.113.5,1194,,,"
    static let reconnected = "1700000020,CONNECTED,SUCCESS,10.8.0.9,203.0.113.5,1194,,,"

    /// What the app sends on connect: real-time state on, then the current state.
    static func open(_ fd: Int32, state: String) {
        FakeManagementServer.send(fd, FakeManagementServer.banner)
        XCTAssertEqual(FakeManagementServer.readLine(fd), "state on")
        FakeManagementServer.send(fd, "SUCCESS: real-time state notification set to ON\r\n")
        XCTAssertEqual(FakeManagementServer.readLine(fd), "state")
        FakeManagementServer.send(fd, state + "\r\nEND\r\n")
    }

    func eventually(_ q: PersistentManagementQuerier, _ name: String, ip: String = "",
                    file: StaticString = #filePath, line: UInt = #line) async throws -> ManagementState {
        let deadline = Date().addingTimeInterval(3)
        while true {
            let s = try await q.state(socketPath: sock, timeout: 2)
            if s.name == name && (ip.isEmpty || s.localIP == ip) { return s }
            if Date() > deadline {
                XCTFail("state stayed \(s)", file: file, line: line)
                return s
            }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    func testOneConnectionFollowsNotificationsAndReconnectsAfterADrop() async throws {
        let push = DispatchSemaphore(value: 0)
        let drop = DispatchSemaphore(value: 0)
        var accepted = 0
        let server = FakeManagementServer(path: sock, handlers: [
            { fd in
                accepted += 1
                Self.open(fd, state: Self.auth)
                push.wait()
                FakeManagementServer.send(fd, ">BYTECOUNT:1,2\r\n>STATE:" + Self.connected + "\r\n")
                drop.wait()
            },
            { fd in
                accepted += 1
                Self.open(fd, state: Self.reconnected)
                // Held until the client releases it.
                var b: UInt8 = 0
                while read(fd, &b, 1) == 1 {}
            },
        ])
        waitForSocket()
        let q = PersistentManagementQuerier()

        for _ in 0..<5 {
            let s = try await q.state(socketPath: sock, timeout: 2)
            XCTAssertEqual(s.name, "AUTH")
        }
        XCTAssertEqual(accepted, 1, "polls reuse the connection")
        XCTAssertEqual(q.openConnections, 1)

        push.signal()
        let up = try await eventually(q, "CONNECTED", ip: "10.8.0.6")
        XCTAssertEqual(up.since, Date(timeIntervalSince1970: 1_700_000_010))
        XCTAssertEqual(accepted, 1)

        drop.signal()                                    // OpenVPN closed the connection
        let again = try await eventually(q, "CONNECTED", ip: "10.8.0.9")
        XCTAssertEqual(again.since, Date(timeIntervalSince1970: 1_700_000_020))
        XCTAssertEqual(accepted, 2)

        q.releaseAll()
        server.wait()
        XCTAssertEqual(q.openConnections, 0)
    }

    /// A command (the debug drop) goes over the held connection: a second client would only wait.
    func testSendUsesTheHeldConnection() async throws {
        var accepted = 0
        var received: String?
        let server = FakeManagementServer(path: sock, handlers: [
            { fd in
                accepted += 1
                Self.open(fd, state: Self.connected)
                received = FakeManagementServer.readLine(fd)
                FakeManagementServer.send(fd, "SUCCESS: signal SIGTERM thrown\r\n")
                var b: UInt8 = 0
                while read(fd, &b, 1) == 1 {}
            },
        ])
        waitForSocket()
        let q = PersistentManagementQuerier()
        _ = try await q.state(socketPath: sock, timeout: 2)
        _ = try await q.send(DebugDrop.command, socketPath: sock, timeout: 2)
        q.releaseAll()
        server.wait()
        XCTAssertEqual(accepted, 1)
        XCTAssertEqual(received, DebugDrop.command)
    }

    func testBusyWhenAnotherClientHoldsTheInterface() async throws {
        let server = FakeManagementServer(path: sock, handlers: [{ _ in usleep(600_000) }])
        waitForSocket()
        let q = PersistentManagementQuerier()
        q.bannerTimeout = 0.2
        do {
            _ = try await q.state(socketPath: sock, timeout: 2)
            XCTFail("expected busy")
        } catch {
            XCTAssertEqual(error as? ManagementError, .busy)
        }
        server.wait()
    }

    func testMissingSocket() async {
        let q = PersistentManagementQuerier()
        do {
            _ = try await q.state(socketPath: sock, timeout: 1)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(error as? ManagementError, .connectFailed(sock, ENOENT))
        }
    }
}

/// Answers from a fixed result; `shares` marks the app's querier.
final class StubQuerier: ManagementQuerying, @unchecked Sendable {
    var result: Result<ManagementState, Error>
    let shares: Bool
    init(_ result: Result<ManagementState, Error>, shares: Bool) {
        self.result = result
        self.shares = shares
    }
    private(set) var calls = 0
    var sharesState: Bool { shares }
    func state(socketPath: String, timeout: TimeInterval) async throws -> ManagementState {
        calls += 1
        return try result.get()
    }
}

@MainActor
final class SharedStateTests: XCTestCase {
    var home: String!
    var service: String!
    var helper: FakeHelper!
    var store: ProfileStore { ProfileStore() }
    let since = Date(timeIntervalSince1970: 1_700_000_000)

    override func setUp() async throws {
        var template = Array("/tmp/pt-ss-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        home = String(cString: made)
        service = "PassTunnelTests-\(UUID().uuidString)"
        setenv("PASSTUNNEL_HOME", home, 1)
        setenv("PASSTUNNEL_KEYCHAIN_SERVICE", service, 1)
        helper = FakeHelper()
    }

    override func tearDown() async throws {
        helper.shutdown()
        Secrets.deleteAllInOverriddenService()
        try? FileManager.default.removeItem(atPath: home)
    }

    func manager(_ q: ManagementQuerying) -> ConnectionManager {
        ConnectionManager(store: store, helper: helper, management: q, clock: FakeClock(since))
    }

    func makeProfile() throws -> Profile {
        let p = try store.create(name: "Acme", type: .openvpn)
        try Data("client\nremote vpn.example.com 1194\n".utf8).write(to: store.ovpnURL(p.id))
        return p
    }

    var connected: ManagementState {
        ManagementState(name: "CONNECTED", localIP: "10.8.0.6", since: since, detail: "SUCCESS")
    }

    func testCLISeesTheStateTheAppShares() async throws {
        let p = try makeProfile()
        helper.openVPNStateLine = nil
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: since)
        let app = manager(StubQuerier(.success(connected), shares: true))
        let cliQuerier = StubQuerier(.failure(ManagementError.busy), shares: false)
        let cli = manager(cliQuerier)

        await cli.refresh()
        XCTAssertEqual(cli.state(p.id), .connecting(ConnectionManager.Phase.starting), "nothing shared yet")

        await app.refresh()
        let url = store.dir(p.id).appendingPathComponent(ConnectionManager.sharedStateFile)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: url.path))
        let queried = cliQuerier.calls
        await cli.refresh()
        XCTAssertEqual(cli.state(p.id), .connected(ip: "10.8.0.6", since: since))
        XCTAssertEqual(cliQuerier.calls, queried, "a live holder's state is used without waiting for the busy socket")

        // Unchanged state: no rewrite on every poll.
        let written = try FileManager.default.attributesOfItem(atPath: url.path)[.modificationDate] as? Date
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 0)], ofItemAtPath: url.path)
        await app.refresh()
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: url.path)[.modificationDate] as? Date,
                       Date(timeIntervalSince1970: 0))
        XCTAssertNotNil(written)

        // Gone when the app sees the session end.
        helper.simulateExit(p.id)
        await app.refresh()
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }

    func testSharedStateOfAnotherProcessOrWriterIsIgnored() async throws {
        let p = try makeProfile()
        let url = store.dir(p.id).appendingPathComponent(ConnectionManager.sharedStateFile)
        let cli = manager(StubQuerier(.failure(ManagementError.busy), shares: false))

        try JSONCoding.write(ConnectionManager.SharedState(pid: 4242, writer: getpid(), connected), to: url)
        XCTAssertEqual(cli.sharedState(p.id, pid: 4242), connected)
        XCTAssertNil(cli.sharedState(p.id, pid: 4243), "another OpenVPN process")

        // A writer that has exited (pid 0 is never a user process here; use a reaped child instead).
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try child.run()
        child.waitUntilExit()
        try JSONCoding.write(ConnectionManager.SharedState(pid: 4242, writer: child.processIdentifier, connected), to: url)
        XCTAssertNil(cli.sharedState(p.id, pid: 4242), "writer gone")
    }
}

extension SharedStateTests {
    /// A damaged shared state file with an absurd timestamp is ignored, like a missing one.
    func testSharedStateWithAnImplausibleTimestampIsIgnored() throws {
        let p = try makeProfile()
        let url = store.dir(p.id).appendingPathComponent(ConnectionManager.sharedStateFile)
        let cli = manager(StubQuerier(.failure(ManagementError.busy), shares: false))
        for epoch in [1e300, -1e300, -1, 1e20] {
            var damaged = connected
            damaged.since = Date(timeIntervalSince1970: epoch)
            try JSONCoding.write(ConnectionManager.SharedState(pid: 4242, writer: getpid(), damaged), to: url)
            XCTAssertNil(cli.sharedState(p.id, pid: 4242), "\(epoch)")
            XCTAssertNil(cli.sharedState(p.id, pid: 4242, requireLiveWriter: false), "\(epoch)")
        }
        try JSONCoding.write(ConnectionManager.SharedState(pid: 4242, writer: getpid(), connected), to: url)
        XCTAssertEqual(cli.sharedState(p.id, pid: 4242), connected)
    }

    /// `status` (CLI and MCP `get_status`) reports instead of trapping, whatever `since` the state carries.
    func testStatusDurationNeverTraps() async throws {
        let p = try makeProfile()
        helper.openVPNStateLine = nil
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: since)
        let cases: [(TimeInterval, Int)] = [(1e300, 0), (.infinity, 0), (.nan, 0), (since.timeIntervalSince1970 + 60, 0),
                                            (-1e300, Int.max), (-.infinity, 0), (since.timeIntervalSince1970 - 90, 90)]
        for (epoch, expected) in cases {
            var state = connected
            state.since = Date(timeIntervalSince1970: epoch)
            let m = manager(StubQuerier(.success(state), shares: true))
            await m.refresh()
            let status = AutomationService(store: store, manager: m).status(p, now: since)
            XCTAssertEqual(status.state, "connected", "\(epoch)")
            XCTAssertEqual(status.durationSeconds, expected, "\(epoch)")
        }
    }

    static let upLog = """
    2026-01-01 10:00:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194
    2026-01-01 10:00:01 /sbin/ifconfig utun6 10.8.0.6 10.8.0.6 netmask 255.255.255.0 mtu 1500 up
    2026-01-01 10:00:02 Initialization Sequence Completed

    """

    func reapedPID() throws -> Int32 {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try child.run()
        child.waitUntilExit()
        return child.processIdentifier
    }

    /// Another client holds the interface and the app that shared the state has quit: the last state
    /// written for the same OpenVPN process, marked as unverified, not "Starting…".
    func testBusySocketFallsBackToTheLastStateOfADeadWriter() async throws {
        let p = try makeProfile()
        helper.openVPNStateLine = nil
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: since)
        let url = store.dir(p.id).appendingPathComponent(ConnectionManager.sharedStateFile)
        try JSONCoding.write(ConnectionManager.SharedState(pid: 5151, writer: try reapedPID(), connected), to: url)
        let cli = manager(StubQuerier(.failure(ManagementError.busy), shares: false))
        await cli.refresh()
        XCTAssertEqual(cli.state(p.id), .connected(ip: "10.8.0.6", since: since))
        XCTAssertEqual(cli.statusUnavailable, [p.id])

        // Another OpenVPN process than the one that is running: not used.
        try JSONCoding.write(ConnectionManager.SharedState(pid: 4242, writer: try reapedPID(), connected), to: url)
        await cli.refresh()
        XCTAssertEqual(cli.state(p.id), .connecting(ConnectionManager.Phase.starting))
        XCTAssertEqual(cli.statusUnavailable, [])
    }

    func testBusySocketFallsBackToTheLog() async throws {
        let p = try makeProfile()
        helper.openVPNStateLine = nil
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: since)
        try Data(Self.upLog.utf8).write(to: store.logURL(p.id))
        let querier = StubQuerier(.failure(ManagementError.busy), shares: true)
        let app = manager(querier)
        await app.refresh()
        guard case .connected(let ip, _) = app.state(p.id) else { return XCTFail("\(app.state(p.id))") }
        XCTAssertEqual(ip, "10.8.0.6")
        XCTAssertEqual(app.statusUnavailable, [p.id])

        // The interface is free again: the app takes it over and the state is verified.
        querier.result = .success(connected)
        await app.refresh()
        XCTAssertEqual(app.state(p.id), .connected(ip: "10.8.0.6", since: since))
        XCTAssertEqual(app.statusUnavailable, [])
    }

    func testBusySocketWithoutAnUpLogStaysStarting() async throws {
        let p = try makeProfile()
        helper.openVPNStateLine = nil
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: since)
        try Data((Self.upLog + "2026-01-01 10:05:00 SIGUSR1[soft,ping-restart] received, process restarting\n").utf8)
            .write(to: store.logURL(p.id))
        let cli = manager(StubQuerier(.failure(ManagementError.busy), shares: false))
        await cli.refresh()
        XCTAssertEqual(cli.state(p.id), .connecting(ConnectionManager.Phase.starting))
        XCTAssertEqual(cli.statusUnavailable, [])
    }

    func testOpenVPNStateFromTheLog() {
        XCTAssertTrue(VPNLog.openVPNIsUp(Self.upLog))
        XCTAssertFalse(VPNLog.openVPNIsUp(Self.upLog + "2026-01-01 10:05:00 Restart pause, 5 second(s)\n"))
        XCTAssertTrue(VPNLog.openVPNIsUp(Self.upLog + "Restart pause, 5 second(s)\n" + "Initialization Sequence Completed\n"))
        XCTAssertFalse(VPNLog.openVPNIsUp("2026-01-01 10:00:00 TLS: Initial packet\n"))
        XCTAssertEqual(VPNLog.openVPNLocalIP(Self.upLog), "10.8.0.6")
        XCTAssertEqual(VPNLog.openVPNLocalIP("net_addr_v4_add: 10.8.0.7/24 dev utun3\n"), "10.8.0.7")
        XCTAssertNil(VPNLog.openVPNLocalIP("/sbin/ifconfig utun6 delete\n"))
    }
}

extension PersistentManagementQuerierTests {
    /// Two callers at once (a poll and a connect) share one open instead of queueing a second client.
    func testConcurrentQueriesOpenOnce() async throws {
        var accepted = 0
        let server = FakeManagementServer(path: sock, handlers: [
            { fd in
                accepted += 1
                Self.open(fd, state: Self.connected)
                var b: UInt8 = 0
                while read(fd, &b, 1) == 1 {}
            },
            { _ in accepted += 1 },
        ])
        waitForSocket()
        let q = PersistentManagementQuerier()
        async let a = q.state(socketPath: sock, timeout: 2)
        async let b = q.state(socketPath: sock, timeout: 2)
        let (x, y) = try await (a, b)
        XCTAssertEqual(x, y)
        XCTAssertEqual(accepted, 1)
        q.releaseAll()
        // Let the server finish: the second handler only runs if someone connects again.
        let close = ManagementSocket(path: sock)
        _ = try? close.command("state", timeout: 0.5)
        server.wait()
    }
}
