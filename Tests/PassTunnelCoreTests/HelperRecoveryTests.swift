import XCTest

@testable import PassTunnelShared

/// A restarted helper and the launches a previous one did not finish (`SessionRecovery`), and the session
/// record that tells it (`SessionState.launching`).
final class SessionRecoveryTests: XCTestCase {
    typealias Facts = SessionRecovery.ProcessFacts
    let start = ProcessStart(seconds: 1_700_000_000, microseconds: 42)
    let tools = "/private/var/run/passtunnel/tools"
    var staged: String { tools + "/" + String(repeating: "ab", count: 32) + "/Resources/bin/openvpn" }
    var state: SessionState { SessionState(pid: 4242, uid: 501, executable: staged, profileDir: "/p", mgmtSocket: nil, startTime: start) }

    func facts(
        pid: pid_t = 4242, parent: pid_t = 1, path: String? = nil, stopped: Bool = false, start: ProcessStart? = nil, uid: uid_t = 0, ruid: uid_t = 0
    ) -> Facts {
        Facts(pid: pid, parent: parent, path: path ?? staged, stopped: stopped, start: start ?? self.start, uid: uid, ruid: ruid)
    }

    func testDecision() {
        let launching = state.launching(true)
        let later = ProcessStart(seconds: start.seconds + 7, microseconds: 0)
        // Only the launching mark means an interrupted launch.
        XCTAssertEqual(SessionRecovery.decide(state, current: facts()), .adopt)
        XCTAssertEqual(SessionRecovery.decide(state, current: facts(stopped: true)), .adopt, "stopped (a debugger): left alone")
        XCTAssertEqual(SessionRecovery.decide(launching, current: facts()), .stopInterruptedLaunch)
        XCTAssertEqual(SessionRecovery.decide(launching, current: facts(stopped: true)), .stopInterruptedLaunch)
        // Gone, another executable, or the pid reused by another run of the same tool.
        for s in [state, launching] {
            XCTAssertEqual(SessionRecovery.decide(s, current: nil), .cleanUp)
            XCTAssertEqual(SessionRecovery.decide(s, current: facts(path: "/bin/sleep")), .cleanUp)
            XCTAssertEqual(
                SessionRecovery.decide(s, current: Facts(pid: 4242, parent: 1, path: nil, stopped: false, start: start, uid: 0, ruid: 0)), .cleanUp)
            XCTAssertEqual(SessionRecovery.decide(s, current: facts(start: later)), .cleanUp, "pid reused")
        }
        // A record of an older helper (no start time): the old rule, and never killed.
        let old = SessionState(pid: 4242, uid: 501, executable: staged, profileDir: "/p", mgmtSocket: nil)
        XCTAssertEqual(SessionRecovery.decide(old, current: facts(start: later)), .adopt)
        XCTAssertEqual(SessionRecovery.decide(old.launching(true), current: facts(stopped: true)), .adopt, "unverifiable: not killed")
        XCTAssertEqual(SessionRecovery.decide(old, current: nil), .cleanUp)
    }

    func testRecordRoundTripAndOlderRecords() throws {
        XCTAssertEqual(start.text, "1700000000.000042")
        XCTAssertEqual(ProcessStart.parse("1700000000.000042"), start)
        for bad in ["", "1.1", "x.000001", "01.000001", "1.0000001", "1.-00001", "1.000001.2"] {
            XCTAssertNil(ProcessStart.parse(bad), bad)
        }
        XCTAssertEqual(try state.launching(true).text(), "4242\n501\n\(staged)\n/p\n\n1700000000.000042\nlaunching\n")
        XCTAssertEqual(SessionState.parse(try state.launching(true).text()), state.launching(true))
        XCTAssertEqual(SessionState.parse(try state.text()), state)
        // Without a start time: an empty line.
        let unknown = SessionState(pid: 4242, uid: 501, executable: staged, profileDir: "/p", mgmtSocket: nil, launching: true)
        XCTAssertEqual(SessionState.parse(try unknown.text()), unknown)
        // Records of helpers before #182: five lines, no start time, not launching.
        let older = SessionState.parse("4242\n501\n\(staged)\n/p\n/var/run/passtunnel/501/a/mgmt.sock\n")
        XCTAssertNil(older?.startTime)
        XCTAssertEqual(older?.launching, false)
        XCTAssertEqual(older?.mgmtSocket, "/var/run/passtunnel/501/a/mgmt.sock")
        for bad in [
            "4242\n501\n/x\n/p\n\nsoon\n", "4242\n501\n/x\n/p\n\n1.000001\nrunning\n",
            "4242\n501\n/x\n/p\n\n1.000001\nlaunching\nmore\n"
        ] {
            XCTAssertNil(SessionState.parse(bad), bad.debugDescription)
        }
        XCTAssertEqual(state.launching(true).launching(false), state)
    }

    func testStrays() {
        let processes = [
            facts(pid: 10, stopped: true),  // a stray
            facts(pid: 11, stopped: false),  // running: never touched
            facts(pid: 12, stopped: true),  // recorded: decided by its record
            facts(pid: 13, parent: 500, stopped: true),  // a living parent
            facts(pid: 14, stopped: true, uid: 501, ruid: 501),  // a user's own run of the staged tool
            facts(pid: 15, stopped: true, uid: 0, ruid: 501),
            facts(pid: 16, stopped: true, uid: 501, ruid: 0),
            facts(pid: 17, path: "/opt/homebrew/sbin/openvpn", stopped: true),
            facts(pid: 18, path: tools + "-x/openvpn", stopped: true),
            Facts(pid: 19, parent: 1, path: nil, stopped: true, start: start, uid: 0, ruid: 0),
            Facts(pid: 20, parent: 1, path: staged, stopped: true, start: nil, uid: 0, ruid: 0),
            facts(pid: 1, parent: 0, stopped: true)
        ]
        XCTAssertEqual(SessionRecovery.strandedLaunches(processes: processes, toolsRoot: tools, recorded: [12]).map(\.pid), [10])
    }

    /// Every signal is sent to that pid alone, and only while the process there is still the one judged.
    func testSignalChecksIdentityRightBefore() {
        let expected = facts(pid: 10, stopped: true)
        var sent: [(pid_t, Int32)] = []
        let send: (pid_t, Int32) -> Int32 = {
            sent.append(($0, $1)); return 0
        }
        let stray: (Facts) -> Bool = { SessionRecovery.isStranded($0, toolsRoot: self.tools) }
        let now: [String: Facts?] = [
            "gone": nil,
            "pid reused, same tool": facts(pid: 10, stopped: true, start: ProcessStart(seconds: start.seconds + 1, microseconds: 0)),
            "pid reused, other program": facts(pid: 10, path: "/bin/sleep", stopped: true),
            "resumed meanwhile": facts(pid: 10, stopped: false),
            "reparented away": facts(pid: 10, parent: 77, stopped: true),
            "user's now": facts(pid: 10, stopped: true, uid: 501, ruid: 501)
        ]
        for (name, current) in now {
            XCTAssertFalse(SessionRecovery.signal(expected, SIGKILL, still: stray, read: { _ in current }, send: send), name)
        }
        XCTAssertTrue(sent.isEmpty)
        XCTAssertTrue(SessionRecovery.signal(expected, SIGKILL, still: stray, read: { _ in expected }, send: send))
        XCTAssertEqual(sent.map(\.0), [10], "the pid alone, never a process group")
        XCTAssertEqual(sent.map(\.1), [SIGKILL])
        // No start time known: never signalled.
        let unknown = Facts(pid: 10, parent: 1, path: staged, stopped: true, start: nil, uid: 0, ruid: 0)
        XCTAssertFalse(SessionRecovery.signal(unknown, SIGKILL, read: { _ in unknown }, send: send))
        XCTAssertFalse(SessionRecovery.signal(facts(pid: 1), SIGKILL, read: { _ in self.facts(pid: 1) }, send: send))
        XCTAssertEqual(sent.count, 1)
    }

    #if os(macOS)
    func testStateIsReplacedAtomically() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pt-state-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try state.launching(true).write(runDir: dir)
        XCTAssertEqual(SessionState.read(dir + "/state"), state.launching(true))
        try state.write(runDir: dir)
        XCTAssertEqual(SessionState.read(dir + "/state"), state)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir), ["state"], "no temporary file left")
        let attrs = try FileManager.default.attributesOfItem(atPath: dir + "/state")
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        // A line break in a field: nothing replaces the record.
        let bad = SessionState(pid: 4242, uid: 501, executable: "/x\n/y", profileDir: "/p", mgmtSocket: nil)
        XCTAssertThrowsError(try bad.write(runDir: dir))
        XCTAssertEqual(SessionState.read(dir + "/state"), state)
    }

    /// The helper's launch as it is, cut short between the state and the resume, with a real suspended
    /// process: recorded as launching with its start time, it is recognized and killed alone; resumed and
    /// recorded again it is adopted; a record with another start time (a reused pid) is not this process.
    func testInterruptedLaunchOfARealProcess() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pt-launch-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let devNull = open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { close(devNull) }
        let pid = try Spawner.spawn(
            executable: "/bin/sleep", arguments: ["30"], environment: HelperCore.fixedEnvironment, workingDirectory: dir,
            outputFD: devNull, suspended: true)
        var reaped = false
        defer {
            if !reaped {
                kill(pid, SIGKILL)
                var status: Int32 = 0
                while waitpid(pid, &status, 0) == -1, errno == EINTR {}
            }
        }
        let now = try XCTUnwrap(SessionRecovery.facts(of: pid))
        XCTAssertTrue(now.stopped)
        XCTAssertEqual(now.path, "/bin/sleep")
        XCTAssertEqual(now.parent, getpid())
        XCTAssertEqual(now.uid, geteuid())
        let start = try XCTUnwrap(now.start)
        XCTAssertGreaterThan(start.seconds, 0)
        XCTAssertEqual(SessionRecovery.systemProcesses().first { $0.pid == pid }, now)

        let recorded = SessionState(
            pid: pid, uid: getuid(), executable: "/bin/sleep", profileDir: dir, mgmtSocket: nil, startTime: start, launching: true)
        try recorded.write(runDir: dir)
        let read = try XCTUnwrap(SessionState.read(dir + "/state"))
        XCTAssertTrue(SessionRecovery.isAlive(read))
        XCTAssertEqual(SessionRecovery.decide(read, current: SessionRecovery.facts(of: pid)), .stopInterruptedLaunch)
        let reused = SessionState(
            pid: pid, uid: getuid(), executable: "/bin/sleep", profileDir: dir, mgmtSocket: nil,
            startTime: ProcessStart(seconds: start.seconds - 60, microseconds: start.microseconds), launching: true)
        XCTAssertEqual(SessionRecovery.decide(reused, current: SessionRecovery.facts(of: pid)), .cleanUp, "an older run with this pid")
        XCTAssertFalse(SessionRecovery.isAlive(reused))

        // Resumed and recorded again, as a finished launch: adopted, also while stopped again.
        XCTAssertEqual(kill(pid, SIGCONT), 0)
        try recorded.launching(false).write(runDir: dir)
        let finished = try XCTUnwrap(SessionState.read(dir + "/state"))
        XCTAssertEqual(SessionRecovery.decide(finished, current: SessionRecovery.facts(of: pid)), .adopt)
        XCTAssertEqual(kill(pid, SIGSTOP), 0)
        XCTAssertTrue(eventuallyStopped(pid))
        XCTAssertEqual(SessionRecovery.decide(finished, current: SessionRecovery.facts(of: pid)), .adopt, "stopped, not launching: left alone")

        // The kill itself: verified right before, then that pid alone.
        XCTAssertTrue(SessionRecovery.signal(now, SIGKILL, read: SessionRecovery.facts(of:), send: kill))
        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1, errno == EINTR {}
        reaped = true
        XCTAssertEqual(status & 0x7f, SIGKILL)
        XCTAssertFalse(SessionRecovery.signal(now, SIGKILL, read: SessionRecovery.facts(of:), send: kill), "gone: nothing sent")
    }

    func eventuallyStopped(_ pid: pid_t) -> Bool {
        for _ in 0..<100 {
            if SessionRecovery.facts(of: pid)?.stopped == true { return true }
            usleep(10_000)
        }
        return false
    }
    #endif
}

#if os(macOS)
/// The helper's own executable, verified as the running image before it is hashed or staged as the hook.
/// Uses the test bundle's own image in place of the helper's.
final class HelperImageTests: XCTestCase {
    var dir: String!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pt-image-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: dir)
    }

    /// The file the kernel mapped for this test code.
    func ownImage() throws -> String {
        var info = Dl_info()
        guard dladdr(#dsohandle, &info) != 0, let name = info.dli_fname else { throw XCTSkip("no image path") }
        return String(cString: name)
    }

    func failure(_ path: String) -> HelperImage.Failure? {
        do {
            let image = try HelperImage.open(path, imageAddress: #dsohandle)
            close(image.descriptor)
            return nil
        } catch {
            return error as? HelperImage.Failure
        }
    }

    func testTheRunningImageIsVerifiedAndHashed() throws {
        let path = try ownImage()
        let image = try HelperImage.open(path, imageAddress: #dsohandle)
        defer { close(image.descriptor) }
        XCTAssertEqual(image.digest, HelperBuild.digest(ofFile: path))
        XCTAssertEqual(fcntl(image.descriptor, F_GETFD) & FD_CLOEXEC, FD_CLOEXEC)
        // A hard link to the running image (a second name in the same directory) does not matter: the
        // identity check decides, so this cannot push the helper onto its fallback build ID.
        let second = path + ".link-\(UUID().uuidString)"
        guard link(path, second) == 0 else { return }
        defer { unlink(second) }
        let linked = try HelperImage.open(path, imageAddress: #dsohandle)
        close(linked.descriptor)
        XCTAssertEqual(linked.digest, image.digest)
        let viaSecond = try HelperImage.open(second, imageAddress: #dsohandle)
        close(viaSecond.descriptor)
    }

    func testAnythingElseAtThePathIsRefused() throws {
        let path = try ownImage()
        // A copy: same bytes, another file than the one running.
        let copy = dir + "/copy"
        try FileManager.default.copyItem(atPath: path, toPath: copy)
        XCTAssertEqual(failure(copy), .notTheRunningImage)
        // A link to the running image itself is not followed.
        XCTAssertEqual(symlink(path, dir + "/link"), 0)
        XCTAssertEqual(failure(dir + "/link"), .open(ELOOP))
        // A FIFO: refused at once, the open does not wait for a writer.
        XCTAssertEqual(mkfifo(dir + "/fifo", 0o600), 0)
        let start = Date()
        XCTAssertEqual(failure(dir + "/fifo"), .notARegularFile)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
        XCTAssertEqual(failure(dir), .notARegularFile)
        XCTAssertEqual(link(copy, dir + "/hard"), 0)
        XCTAssertEqual(failure(dir + "/hard"), .notTheRunningImage)
        XCTAssertEqual(failure(dir + "/missing"), .open(ENOENT))
    }

    func testDigestIsBounded() throws {
        let file = dir + "/big"
        try Data(count: 3 << 20).write(to: URL(fileURLWithPath: file))
        let fd = open(file, O_RDONLY | O_CLOEXEC)
        defer { close(fd) }
        XCTAssertNotNil(HelperBuild.digest(ofDescriptor: fd, maxBytes: 3 << 20))
        XCTAssertNil(HelperBuild.digest(ofDescriptor: fd, maxBytes: (3 << 20) - 1))
    }

    func testFallbackBuildIDComesFromTheKernel() {
        // Test binaries are signed (ad hoc) on Apple silicon; anything else may have no cdhash.
        guard let id = HelperImage.fallbackBuildID() else { return }
        XCTAssertEqual(id.count, 40)
        XCTAssertTrue(id.allSatisfy { $0.isHexDigit && !$0.isUppercase })
        XCTAssertEqual(HelperImage.fallbackBuildID(), id)
    }

    func testInfoPlistIsReadWithoutFollowingOrBlocking() throws {
        let contents = dir + "/Acme.app/Contents"
        try FileManager.default.createDirectory(atPath: contents + "/MacOS", withIntermediateDirectories: true)
        let plist = try PropertyListSerialization.data(fromPropertyList: ["CFBundleVersion": "214"], format: .xml, options: 0)
        try plist.write(to: URL(fileURLWithPath: dir + "/real.plist"))
        XCTAssertEqual(mkfifo(contents + "/Info.plist", 0o600), 0)
        XCTAssertNil(HelperBuild.buildNumber(ofBundleContaining: contents + "/MacOS/PassTunnelHelper"), "a FIFO is not waited on")
        unlink(contents + "/Info.plist")
        XCTAssertEqual(symlink(dir + "/real.plist", contents + "/Info.plist"), 0)
        XCTAssertNil(HelperBuild.buildNumber(ofBundleContaining: contents + "/MacOS/PassTunnelHelper"), "a link is not followed")
        unlink(contents + "/Info.plist")
        try plist.write(to: URL(fileURLWithPath: contents + "/Info.plist"))
        XCTAssertEqual(HelperBuild.buildNumber(ofBundleContaining: contents + "/MacOS/PassTunnelHelper"), 214)
    }
}
#endif
