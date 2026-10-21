import XCTest
@testable import PassTunnelCore
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
    var sharesState: Bool { shares }
    func state(socketPath: String, timeout: TimeInterval) async throws -> ManagementState { try result.get() }
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
        let cli = manager(StubQuerier(.failure(ManagementError.busy), shares: false))

        await cli.refresh()
        XCTAssertEqual(cli.state(p.id), .connecting(ConnectionManager.Phase.starting), "nothing shared yet")

        await app.refresh()
        let url = store.dir(p.id).appendingPathComponent(ConnectionManager.sharedStateFile)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: url.path))
        await cli.refresh()
        XCTAssertEqual(cli.state(p.id), .connected(ip: "10.8.0.6", since: since))

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
