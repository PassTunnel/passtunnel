import XCTest

@testable import PassTunnelShared

/// The helper's account of OpenVPN sessions' DNS (`OpenVPNDNSKeeper`): what a start waits for, what is carried over
/// it, where each note goes, what `finish`, `stopAll` and `adoptOrphans` keep. Against session directories in a
/// temporary run root, the fake system of `OpenVPNDNSTests`, a lock that can be taken or not, and logs in memory.
final class OpenVPNDNSKeeperTests: XCTestCase {
    var root: URL!
    var system: FakeDNSSystem!
    var keeper: OpenVPNDNSKeeper!
    var lockFree = true
    var lockCalls = 0
    var appended: [(key: OpenVPNDNSKeeper.Key, owner: HelperCore.DNSOwner, line: String)] = []
    var reports: [String] = []

    static let wifi = OpenVPNDNSTests.wifi
    static let ethernet = OpenVPNDNSTests.ethernet
    let alice = OpenVPNDNSKeeper.Key(uid: 501, profileID: "work")
    let bob = OpenVPNDNSKeeper.Key(uid: 502, profileID: "lab")

    static let recordA = "dev=utun7\ndns_server_1_address_1=10.8.0.1\n"
    static let recordB = "dev=utun8\ndns_server_1_address_1=10.9.0.1\n"
    static let sessionA = OpenVPNDNSSession(dev: "utun7", servers: ["10.8.0.1"])
    static let sessionB = OpenVPNDNSSession(dev: "utun8", servers: ["10.9.0.1"])

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("pt-dnskeeper-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        system = FakeDNSSystem()
        system.names = [Self.wifi: "Wi-Fi", Self.ethernet: "Ethernet"]
        system.preferences = [Self.wifi: [:], Self.ethernet: [:]]
        lockFree = true
        appended = []
        reports = []
        keeper = OpenVPNDNSKeeper(
            runRoot: root.path, system: system,
            lock: { [unowned self] in
                self.lockCalls += 1
                return self.lockFree ? ScriptLock.Held(path: nil) : nil
            },
            appendToLog: { [unowned self] key, owner, line in self.appended.append((key, owner, line)) },
            report: { [unowned self] in self.reports.append($0) })
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    /// A session directory with a record, its result and an owner file.
    @discardableResult
    func session(_ key: OpenVPNDNSKeeper.Key, record: String, service: String?, status: Int = 0) throws -> String {
        let dir = keeper.runDir(key)
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try HelperCore.writeNewFile(dir + "/" + HelperCore.dnsRecordName, Data(record.utf8), mode: 0o600)
        try HelperCore.writeNewFile(
            dir + "/" + HelperCore.dnsResultName, Data("status=\(status)\nservice=\(service ?? "")\n".utf8), mode: 0o600)
        try HelperCore.writeDNSOwner(runDir: dir, HelperCore.DNSOwner(profileDir: "/Users/u\(key.uid)/p", logName: "vpn.log"))
        try HelperCore.writeNewFile(dir + "/config.ovpn", Data("client\n".utf8), mode: 0o600)
        return dir
    }

    func files(_ dir: String) -> Set<String> {
        Set((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [])
    }

    // MARK: Start

    /// While a check that ran fails, a start of that profile is refused, saying what to do; once it succeeds, the
    /// start goes ahead, and the note of its last session comes back for the new log.
    func testAStartWaitsWhileTheCheckFails() throws {
        let dir = try session(alice, record: Self.recordA, service: Self.wifi)
        system.services[Self.wifi] = Self.sessionA.overrideEntity
        system.refusedWrites = 2
        XCTAssertFalse(keeper.settle(alice, runDir: dir, live: []))
        XCTAssertEqual(keeper.pending[alice], .failed)

        let refused = keeper.beforeStart(alice, live: [], isRunning: { _ in false })
        XCTAssertEqual(refused.start, .refuse(OpenVPNDNSKeeper.stillRestoringMessage))
        XCTAssertTrue(OpenVPNDNSKeeper.stillRestoringMessage.contains("DNS settings of this profile's last OpenVPN session"))
        XCTAssertTrue(OpenVPNDNSKeeper.stillRestoringMessage.contains("restarting the Mac clears it"))

        let (start, notes) = keeper.beforeStart(alice, live: [], isRunning: { _ in false })
        XCTAssertEqual(start, .proceed)
        XCTAssertEqual(notes, [OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: ["10.8.0.1"])])
        XCTAssertTrue(appended.allSatisfy { !$0.line.contains("restored the DNS") }, "its own note goes into its new log, not the old one")
        XCTAssertNil(keeper.pending[alice])
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir))
    }

    /// A lock that cannot be had (anyone can hold or fill the lock file) is no failed check: the session stays
    /// pending (`lockBusy`), a start is never refused for it, and the record is carried into the new session.
    func testABusyLockNeverRefusesAStart() throws {
        let dir = try session(alice, record: Self.recordA, service: Self.wifi)
        system.services[Self.wifi] = Self.sessionA.overrideEntity
        system.refusedWrites = 1
        XCTAssertFalse(keeper.settle(alice, runDir: dir, live: []))
        XCTAssertEqual(keeper.pending[alice], .failed)
        lockFree = false
        let (start, _) = keeper.beforeStart(alice, live: [], isRunning: { _ in false })
        XCTAssertEqual(start, .proceed, "not even over a check that failed before: this one did not run")
        XCTAssertEqual(system.writes.count, 1, "nothing written without the lock")
        XCTAssertTrue(reports.contains { $0.contains("lock is held") })

        // The start makes the directory anew; the record goes with it, and the session's end settles it.
        try FileManager.default.removeItem(atPath: dir)
        let new = try session(alice, record: Self.recordB, service: nil, status: 1)
        keeper.carry(into: new, key: alice)
        lockFree = true
        XCTAssertTrue(keeper.settle(alice, runDir: new, live: []))
        XCTAssertNil(system.services[Self.wifi])
    }

    /// One event asks for the lock once, for all the sessions it checks, never once per session; an event with
    /// nothing to check does not ask.
    func testTheLockIsAskedForOncePerEvent() throws {
        for (i, key) in [alice, bob, OpenVPNDNSKeeper.Key(uid: 503, profileID: "home")].enumerated() {
            try session(key, record: "dev=utun\(i + 1)\ndns_server_1_address_1=10.8.0.\(i + 1)\n", service: Self.wifi)
            lockFree = false
            keeper.settle(key, runDir: keeper.runDir(key), live: [])
        }
        XCTAssertEqual(keeper.pending.count, 3)
        lockCalls = 0
        keeper.retry(live: [], isRunning: { _ in false })
        XCTAssertEqual(lockCalls, 1)
        XCTAssertEqual(Set(keeper.pending.values), [.lockBusy])
        lockCalls = 0
        _ = keeper.beforeStart(alice, live: [], isRunning: { _ in false })
        XCTAssertEqual(lockCalls, 1)
        lockFree = true
        keeper.retry(live: [], isRunning: { _ in false })
        XCTAssertEqual(keeper.pending.count, 0)
        lockCalls = 0
        keeper.retry(live: [], isRunning: { _ in false })
        let nobody = OpenVPNDNSKeeper.Key(uid: 504, profileID: "none")
        XCTAssertTrue(keeper.settle(nobody, runDir: keeper.runDir(nobody), live: []))
        XCTAssertEqual(lockCalls, 0, "nothing to check")
    }

    /// A record that is done goes, whichever slot it is in: the session's own one is not checked again while a
    /// carried one waits.
    func testADoneRecordGoesWhicheverSlot() throws {
        let dir = try session(alice, record: Self.recordA, service: Self.wifi)
        try HelperCore.writeCarriedDNSRecord(runDir: dir, record: Self.recordB, result: "status=0\nservice=\(Self.ethernet)\n")
        system.services[Self.wifi] = Self.sessionA.overrideEntity
        system.interfaces = ["utun9"]
        system.backups["utun9"] = Self.sessionB.overrideEntity
        XCTAssertFalse(keeper.settle(alice, runDir: dir, live: []))
        XCTAssertEqual(keeper.pending[alice], .parked)
        XCTAssertNil(try HelperCore.dnsRecord(runDir: dir, slot: .current), "done: gone")
        XCTAssertNotNil(try HelperCore.dnsRecord(runDir: dir, slot: .carried), "parked: kept")
        let writes = system.writes
        keeper.retry(live: [], isRunning: { _ in false })
        XCTAssertEqual(system.writes, writes)
    }

    /// A start retries everyone's pending sessions; each one's notes go into its own log only.
    func testNotesGoOnlyToTheirOwner() throws {
        let a = try session(alice, record: Self.recordA, service: Self.wifi)
        let b = try session(bob, record: Self.recordB, service: Self.ethernet)
        system.services = [Self.wifi: Self.sessionA.overrideEntity, Self.ethernet: Self.sessionB.overrideEntity]
        lockFree = false
        keeper.settle(alice, runDir: a, live: [])
        keeper.settle(bob, runDir: b, live: [])
        lockFree = true

        let (_, notes) = keeper.beforeStart(alice, live: [], isRunning: { _ in false })
        XCTAssertEqual(notes, [OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: ["10.8.0.1"])])
        XCTAssertEqual(appended.count, 1)
        XCTAssertEqual(appended.first?.key, bob)
        XCTAssertEqual(appended.first?.owner, HelperCore.DNSOwner(profileDir: "/Users/u502/p", logName: "vpn.log"))
        XCTAssertEqual(appended.first?.line, OpenVPNDNS.Note(.restored, service: "Ethernet", settings: ["10.9.0.1"]).line + "\n")
    }

    /// A session settled after the helper no longer holds its log (an adopted one, a retry): its notes go to the log
    /// its owner file names, failures too.
    func testWithoutADescriptorNotesGoToTheOwnersLog() throws {
        let dir = try session(alice, record: Self.recordA, service: Self.wifi)
        system.services[Self.wifi] = Self.sessionA.overrideEntity
        system.refusedWrites = 1
        XCTAssertFalse(keeper.settle(alice, runDir: dir, live: []))
        XCTAssertEqual(appended.map(\.line.first), ["P"])
        XCTAssertTrue(appended[0].line.contains("could not restore the DNS of “Wi-Fi”"))
        keeper.retry(live: [], isRunning: { _ in false })
        XCTAssertEqual(appended.count, 2)
        XCTAssertEqual(OpenVPNDNS.Note(line: String(appended[1].line.dropLast()))?.kind, .restored)
        XCTAssertNil(keeper.pending[alice])
    }

    /// A start over a parked record (the session's DNS sits in a running session's backup) goes ahead and carries
    /// the record into the new session directory; that session's end settles it once the DNS is back on a service.
    func testAStartOverAParkedRecordKeepsTheEvidence() throws {
        let old = try session(alice, record: Self.recordA, service: Self.wifi)
        system.interfaces = ["utun9"]
        system.backups["utun9"] = Self.sessionA.overrideEntity
        XCTAssertFalse(keeper.settle(alice, runDir: old, live: []))
        XCTAssertEqual(keeper.pending[alice], .parked)

        let (start, _) = keeper.beforeStart(alice, live: [], isRunning: { _ in false })
        XCTAssertEqual(start, .proceed)
        // The start makes the directory anew (`makeRunDir`), with the new session's own record.
        try FileManager.default.removeItem(atPath: old)
        let new = try session(alice, record: "dev=utun3\ndns_server_1_address_1=10.8.0.1\n", service: Self.wifi, status: 1)
        keeper.carry(into: new, key: alice)
        XCTAssertNotNil(try HelperCore.dnsRecord(runDir: new, slot: .carried))

        // The other session ended; its script put the backup back on Wi-Fi. The new session ends too.
        system.backups = [:]
        system.interfaces = []
        system.services[Self.wifi] = Self.sessionA.overrideEntity
        var notes: [OpenVPNDNS.Note] = []
        XCTAssertTrue(keeper.settle(alice, runDir: new, live: [], sink: { notes.append($0) }))
        XCTAssertEqual(notes, [OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: ["10.8.0.1"])])
        XCTAssertNil(try HelperCore.dnsRecord(runDir: new, slot: .carried))
    }

    /// A start that fails after `beforeStart` let it go ahead loses nothing it carried.
    func testAFailedStartKeepsWhatItCarried() throws {
        let old = try session(alice, record: Self.recordA, service: Self.wifi)
        system.interfaces = ["utun9"]
        system.backups["utun9"] = Self.sessionA.overrideEntity
        keeper.settle(alice, runDir: old, live: [])
        _ = keeper.beforeStart(alice, live: [], isRunning: { _ in false })
        // Failed after the directory was made anew and removed again.
        try FileManager.default.removeItem(atPath: old)
        XCTAssertFalse(keeper.startFailed(alice, runDir: old))
        XCTAssertEqual(keeper.pending[alice], .parked)
        XCTAssertEqual(try HelperCore.dnsRecord(runDir: old, slot: .carried)?.session, Self.sessionA)

        // Failed after the record was carried into the new directory: it stays there.
        _ = keeper.beforeStart(alice, live: [], isRunning: { _ in false })
        try FileManager.default.removeItem(atPath: old)
        let new = try session(alice, record: Self.recordB, service: nil, status: 1)
        keeper.carry(into: new, key: alice)
        XCTAssertFalse(keeper.startFailed(alice, runDir: new))
        XCTAssertEqual(try HelperCore.dnsRecord(runDir: new, slot: .carried)?.session, Self.sessionA)
        XCTAssertFalse(files(new).contains("config.ovpn"))

        // Nothing carried, nothing kept.
        let other = try session(bob, record: Self.recordB, service: nil)
        XCTAssertTrue(keeper.startFailed(bob, runDir: other))
    }

    // MARK: End

    /// What `finish` and `stopAll` keep: everything goes once the network and the DNS are back; while only the DNS
    /// is not, its records, marks and owner; while the network is not, what its own revert kept.
    func testWhatAnEndKeeps() throws {
        let dir = try session(alice, record: Self.recordA, service: Self.wifi)
        HelperCore.markDNSDownTried(runDir: dir)
        OpenVPNDNSKeeper.cleanUp(runDir: dir, settled: false, networkRestored: false)
        XCTAssertTrue(files(dir).contains("config.ovpn"))
        OpenVPNDNSKeeper.cleanUp(runDir: dir, settled: false, networkRestored: true)
        XCTAssertEqual(
            files(dir), [HelperCore.dnsRecordName, HelperCore.dnsResultName, HelperCore.dnsDownTriedName, HelperCore.dnsOwnerName])
        OpenVPNDNSKeeper.cleanUp(runDir: dir, settled: true, networkRestored: true)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir))
    }

    /// A record that cannot be read is no evidence: nothing is changed, and the directory can go.
    func testAnUnreadableRecordIsDropped() throws {
        let dir = try session(alice, record: Self.recordA, service: Self.wifi)
        system.services[Self.wifi] = Self.sessionA.overrideEntity
        XCTAssertEqual(chmod(dir + "/" + HelperCore.dnsRecordName, 0o666), 0)
        XCTAssertTrue(keeper.settle(alice, runDir: dir, live: []))
        XCTAssertEqual(system.writes, [])
        XCTAssertTrue(reports.contains { $0.contains("not checking the DNS of work") })
    }

    /// `adoptOrphans` settles the ended sessions only once every running one is adopted: a running session that
    /// changed the same service the same way holds it.
    func testOrphansAreSettledAfterTheRunningSessionsAreKnown() throws {
        let ended = try session(alice, record: Self.recordA, service: Self.wifi)
        let running = try session(bob, record: "dev=utun8\ndns_server_1_address_1=10.8.0.1\n", service: Self.wifi)
        system.interfaces = ["utun8"]
        system.services[Self.wifi] = Self.sessionA.overrideEntity
        keeper.settleOrphans([(alice, ended)], live: [running])
        XCTAssertEqual(system.writes, [], "left to the running session")
        XCTAssertFalse(FileManager.default.fileExists(atPath: ended))

        let again = try session(alice, record: Self.recordA, service: Self.wifi)
        keeper.settleOrphans([(alice, again)], live: [])
        XCTAssertEqual(system.writes, ["set \(Self.wifi) removed"], "without it, it would have been taken")
        XCTAssertEqual(appended.count, 1, "into the owner's log")
    }

    /// A running session whose dns-down ran, or whose dns-up failed, holds nothing.
    func testOnlyARunningSessionThatSucceededHolds() throws {
        let ended = try session(alice, record: Self.recordA, service: Self.wifi)
        let failed = try session(bob, record: "dev=utun8\ndns_server_1_address_1=10.8.0.1\n", service: Self.wifi, status: 1)
        system.services[Self.wifi] = Self.sessionA.overrideEntity
        XCTAssertTrue(keeper.settle(alice, runDir: ended, live: [failed]))
        XCTAssertEqual(system.writes, ["set \(Self.wifi) removed"])
    }

    /// Before a start: a leftover without a record is reported, but not one a pending record claims.
    func testLeftBehindNotesLeaveOutWhatAPendingSessionClaims() throws {
        system.services = [
            Self.wifi: ["ServerAddresses": OpenVPNDNSTests.strings(["10.8.0.1"]), "SearchOrder": .integer(5000)],
            Self.ethernet: ["ServerAddresses": OpenVPNDNSTests.strings(["10.6.0.1"]), "SearchOrder": .integer(5000)]
        ]
        let dir = try session(alice, record: Self.recordA, service: Self.wifi)
        lockFree = false
        keeper.settle(alice, runDir: dir, live: [])
        XCTAssertEqual(keeper.leftBehindNotes(before: bob), [OpenVPNDNS.Note(.leftBehind, service: "Ethernet", settings: ["10.6.0.1"])])
    }
}
