import PassTunnelShared
import XCTest

@testable import PassTunnelCore

final class HelperAutoUpdateTests: XCTestCase {
    private func situation(
        status: HelperStatus = .enabled, outdated: Bool? = true, older: Bool = true,
        sessions: Int = 0, updating: Bool = false,
        inApplications: Bool = true
    ) -> HelperAutoUpdate.Situation {
        .init(
            status: status, outdated: outdated, helperIsOlder: older, activeSessions: sessions, updating: updating,
            inApplicationsFolder: inApplications)
    }

    func testOutdatedWithoutSessionsUpdatesOnce() {
        var policy = HelperAutoUpdate()
        XCTAssertEqual(policy.next(situation()), .update)
        XCTAssertTrue(policy.attempted)
        // Still outdated afterwards (the update failed): no second automatic attempt.
        XCTAssertEqual(policy.next(situation()), .none)
        XCTAssertEqual(policy.next(situation(sessions: 1)), .none)
    }

    func testCurrentOrUnknownHelperIsLeftAlone() {
        var policy = HelperAutoUpdate()
        XCTAssertEqual(policy.next(situation(outdated: false)), .none)
        XCTAssertEqual(policy.next(situation(outdated: nil)), .none)
        for status in [HelperStatus.notRegistered, .requiresApproval, .notFound] {
            XCTAssertEqual(policy.next(situation(status: status)), .none, "\(status)")
        }
        XCTAssertFalse(policy.attempted)
    }

    func testActiveSessionsWaitAndNotifyOnce() {
        var policy = HelperAutoUpdate()
        XCTAssertEqual(policy.next(situation(sessions: 2)), .wait(notify: true))
        XCTAssertTrue(policy.waiting)
        XCTAssertEqual(policy.next(situation(sessions: 1)), .wait(notify: false))
        XCTAssertEqual(policy.next(situation(sessions: 1)), .wait(notify: false))
        // The last session ended: update now.
        XCTAssertEqual(policy.next(situation(sessions: 0)), .update)
        XCTAssertFalse(policy.waiting)
    }

    func testNothingWhileAnUpdateRuns() {
        var policy = HelperAutoUpdate()
        XCTAssertEqual(policy.next(situation(updating: true)), .none)
        XCTAssertFalse(policy.attempted)
        // A manual update from Settings that left it outdated still allows the automatic one.
        XCTAssertEqual(policy.next(situation()), .update)
    }

    func testCopyOutsideApplicationsNeverUpdatesOnItsOwn() {
        var policy = HelperAutoUpdate()
        XCTAssertEqual(policy.next(situation(inApplications: false)), .none)
        XCTAssertEqual(policy.next(situation(sessions: 1, inApplications: false)), .none)
    }

    /// Never a downgrade, and never a same-number build: those only after the user confirms in Settings.
    func testNewerOrNotComparableHelperIsNeverReplacedOnItsOwn() {
        var policy = HelperAutoUpdate()
        XCTAssertEqual(policy.next(situation(older: false)), .none)
        XCTAssertEqual(policy.next(situation(older: false, sessions: 1)), .none, "no waiting, no notification")
        XCTAssertFalse(policy.waiting)
        XCTAssertFalse(policy.notified)
        XCTAssertFalse(policy.attempted)
    }

    func testWaitingEndsWhenTheUpdateIsNoLongerAllowed() {
        var policy = HelperAutoUpdate()
        XCTAssertEqual(policy.next(situation(sessions: 1)), .wait(notify: true))
        XCTAssertTrue(policy.waiting)
        XCTAssertEqual(policy.next(situation(older: false, sessions: 1)), .none)
        XCTAssertFalse(policy.waiting)
    }

    func testBecomingCurrentResetsTheState() {
        var policy = HelperAutoUpdate()
        XCTAssertEqual(policy.next(situation(sessions: 1)), .wait(notify: true))
        XCTAssertEqual(policy.next(situation(sessions: 0)), .update)
        XCTAssertEqual(policy.next(situation(outdated: false)), .none)
        XCTAssertFalse(policy.attempted)
        XCTAssertFalse(policy.notified)
        // A later app update makes it outdated again: the cycle starts over.
        XCTAssertEqual(policy.next(situation(sessions: 1)), .wait(notify: true))
        XCTAssertEqual(policy.next(situation(sessions: 0)), .update)
    }

    func testUnknownOutdatedKeepsWaitingState() {
        var policy = HelperAutoUpdate()
        XCTAssertEqual(policy.next(situation(sessions: 1)), .wait(notify: true))
        // The helper did not answer once: nothing changes, and no second notification later.
        XCTAssertEqual(policy.next(situation(outdated: nil, sessions: 1)), .none)
        XCTAssertTrue(policy.notified)
        XCTAssertEqual(policy.next(situation(sessions: 1)), .wait(notify: false))
    }

    // MARK: sessions from the process list

    private typealias P = HelperSessions.RunningProcess

    func testToolsOfTheHelperAndOfPassTunnelBundlesCount() {
        let processes: [P] = [
            P(pid: 1, parent: 0, name: "launchd", path: "/sbin/launchd"),
            P(pid: 100, parent: 1, name: "PassTunnelHelper", path: "/Applications/PassTunnel.app/Contents/MacOS/PassTunnelHelper"),
            // Child of the helper whose path cannot be read.
            P(pid: 101, parent: 100, name: "openvpn", path: nil),
            // Adopted by a restarted helper: parent is launchd now.
            P(pid: 102, parent: 1, name: "openfortivpn", path: "/Applications/PassTunnel.app/Contents/Resources/bin/openfortivpn"),
            // The bundle was replaced by an update and the old one is gone.
            P(pid: 103, parent: 1, name: "openvpn", path: "/private/var/folders/x/Old.app/Contents/Resources/bin/openvpn"),
            // Another VPN client's OpenVPN.
            P(pid: 200, parent: 1, name: "openvpn", path: "/Applications/Other.app/Contents/Resources/bin/openvpn"),
            P(pid: 201, parent: 1, name: "openvpn", path: "/opt/homebrew/sbin/openvpn"),
            P(pid: 202, parent: 1, name: "openvpn", path: nil),
            // The app itself is not a session.
            P(pid: 300, parent: 1, name: "PassTunnel", path: "/Applications/PassTunnel.app/Contents/MacOS/PassTunnel"),
            // Cisco AnyConnect: openconnect counts like the others; its hook (a copy of the helper, run by
            // openconnect) is neither a session nor a helper.
            P(pid: 104, parent: 100, name: "openconnect", path: "/private/var/run/passtunnel/tools/ab/Resources/bin/openconnect"),
            P(pid: 105, parent: 1, name: "openconnect", path: "/Applications/PassTunnel.app/Contents/Resources/bin/openconnect"),
            P(pid: 106, parent: 104, name: "vpn-hook", path: "/private/var/run/passtunnel/tools/ab/Resources/bin/vpn-hook")
        ]
        let ids = [
            "/Applications/PassTunnel.app": PT.bundleID,
            "/Applications/Other.app": "com.example.other"
        ]
        let pids = HelperSessions.toolPIDs(
            in: processes, bundleIdentifier: { ids[$0] },
            exists: { ids[$0] != nil })
        XCTAssertEqual(pids, [101, 102, 103, 104, 105])
    }

    func testNoHelperNoTools() {
        let processes: [P] = [P(pid: 1, parent: 0, name: "launchd", path: "/sbin/launchd")]
        XCTAssertEqual(HelperSessions.toolPIDs(in: processes, bundleIdentifier: { _ in nil }, exists: { _ in true }), [])
    }

    func testAppPathOfTool() {
        XCTAssertEqual(
            HelperSessions.appPath(ofTool: "/Applications/PassTunnel.app/Contents/Resources/bin/openvpn"),
            "/Applications/PassTunnel.app")
        XCTAssertNil(HelperSessions.appPath(ofTool: "/Applications/PassTunnel.app/Contents/Resources/bin/dns-updown"))
        XCTAssertNil(HelperSessions.appPath(ofTool: "/usr/local/bin/openvpn"))
        XCTAssertNil(HelperSessions.appPath(ofTool: "/x/Contents/Resources/bin/openvpn"))
    }

    #if os(macOS)
    func testCurrentProcessesSeesItself() {
        let me = getpid()
        let processes = HelperSessions.currentProcesses()
        XCTAssertTrue(processes.contains { $0.pid == me && $0.path != nil })
        XCTAssertTrue(processes.contains { $0.pid == 1 })
    }
    #endif

    func testApplicationsFolder() throws {
        XCTAssertTrue(HelperSessions.isInApplicationsFolder("/Applications/PassTunnel.app"))
        XCTAssertTrue(HelperSessions.isInApplicationsFolder("/Applications/Utilities/PassTunnel.app"))
        XCTAssertFalse(
            HelperSessions.isInApplicationsFolder(NSHomeDirectory() + "/Applications/PassTunnel.app"),
            "~/Applications is writable by any process of the user")
        XCTAssertFalse(HelperSessions.isInApplicationsFolder("/Users/alice/Applications/PassTunnel.app"))
        XCTAssertFalse(HelperSessions.isInApplicationsFolder("/Users/alice/src/build/PassTunnel.app"))
        XCTAssertFalse(HelperSessions.isInApplicationsFolder("/Volumes/PassTunnel/PassTunnel.app"))
        XCTAssertFalse(HelperSessions.isInApplicationsFolder("/ApplicationsX/PassTunnel.app"))
        XCTAssertFalse(HelperSessions.isInApplicationsFolder("/Applications/../Users/alice/PassTunnel.app"))

        // A symlink in /Applications to a copy elsewhere does not count.
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("pt-apps-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: dir) }
        try fm.createDirectory(at: dir.appendingPathComponent("PassTunnel.app"), withIntermediateDirectories: true)
        let link = dir.appendingPathComponent("Link.app")
        try fm.createSymbolicLink(at: link, withDestinationURL: dir.appendingPathComponent("PassTunnel.app"))
        XCTAssertFalse(HelperSessions.isInApplicationsFolder(link.path))
    }
}
