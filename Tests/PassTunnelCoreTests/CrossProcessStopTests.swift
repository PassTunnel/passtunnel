import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

/// A connect in one process (app or CLI) that another process disconnects.
extension ConnectionManagerTests {
    private func startStuckConnect() throws -> (Profile, ConnectionManager, Task<Error?, Never>) {
        let p = try makeOpenVPN()
        helper.openVPNStateLine = { _ in "1700000000,AUTH,,,,,,," }  // never gets to CONNECTED
        var timing = ConnectionManager.Timing()
        timing.connectCheckInterval = 0.02
        timing.processCheckInterval = 0.02
        let m = makeManager(clock: SystemClock(), timing: timing)
        let task = Task<Error?, Never> {
            do { try await m.connect(p.id); return nil } catch { return error }
        }
        return (p, m, task)
    }

    func testDisconnectFromAnotherProcessCancelsConnect() async throws {
        let (p, m, task) = try startStuckConnect()
        await waitUntil { self.helper.running[p.id] != nil }
        // What `disconnect` in the other process leaves behind: the marker, and no process.
        try Data().write(to: store.dir(p.id).appendingPathComponent(ConnectionManager.userStoppedMarker))
        helper.simulateExit(p.id)

        let error = await task.value
        XCTAssertEqual(error as? PTError, .connectCancelled, "\(String(describing: error))")
        XCTAssertNil(m.lastError[p.id], "a cancel is not shown as a failure")
        XCTAssertEqual(m.state(p.id), .disconnected)
    }

    func testToolExitWithoutDisconnectIsAFailure() async throws {
        let (p, m, task) = try startStuckConnect()
        await waitUntil { self.helper.running[p.id] != nil }
        helper.simulateExit(p.id)

        let error = await task.value
        guard case .connectFailed = error as? PTError else { return XCTFail("\(String(describing: error))") }
        XCTAssertNotNil(m.lastError[p.id])
        XCTAssertEqual(m.state(p.id), .disconnected)
    }
}

final class VPNLogTailTests: XCTestCase {
    func testTailSkipsManagementPolls() {
        let log = """
            2026-01-01 10:00:00 MANAGEMENT: unix domain socket listening on /tmp/x/mgmt.sock
            2026-01-01 10:00:01 SENT CONTROL [vpn.example.com]: 'PUSH_REQUEST' (status=1)
            2026-01-01 10:00:01 MANAGEMENT: Client connected from /tmp/x/mgmt.sock
            2026-01-01 10:00:01 MANAGEMENT: CMD 'state'
            2026-01-01 10:00:01 MANAGEMENT: Client disconnected
            2026-01-01 10:00:02 AUTH: Received control message: AUTH_FAILED
            2026-01-01 10:00:02 MANAGEMENT: Client connected from /tmp/x/mgmt.sock
            2026-01-01 10:00:02 MANAGEMENT: CMD 'state'
            2026-01-01 10:00:02 MANAGEMENT: Client disconnected
            2026-01-01 10:00:02 SIGTERM[soft,auth-failure] received, process exiting
            """
        XCTAssertEqual(
            VPNLog.tail(log, lines: 3),
            """
            2026-01-01 10:00:01 SENT CONTROL [vpn.example.com]: 'PUSH_REQUEST' (status=1)
            2026-01-01 10:00:02 AUTH: Received control message: AUTH_FAILED
            2026-01-01 10:00:02 SIGTERM[soft,auth-failure] received, process exiting
            """)
        XCTAssertTrue(VPNLog.tail(log).hasPrefix("2026-01-01 10:00:00 MANAGEMENT: unix domain socket"))
    }
}
