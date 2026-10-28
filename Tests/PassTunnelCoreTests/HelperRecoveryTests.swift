import XCTest

@testable import PassTunnelShared

/// A restarted helper and the launches a previous one did not finish (`SessionRecovery`), and the session
/// record that tells it (`SessionState.launching`).
final class SessionRecoveryTests: XCTestCase {
    let state = SessionState(pid: 4242, uid: 501, executable: "/x/openvpn", profileDir: "/p", mgmtSocket: nil)

    func testDecision() {
        let launching = state.launching(true)
        XCTAssertEqual(SessionRecovery.decide(state, alive: true, stopped: false), .adopt)
        XCTAssertEqual(SessionRecovery.decide(state, alive: true, stopped: true), .stopInterruptedLaunch, "never resumed")
        XCTAssertEqual(SessionRecovery.decide(launching, alive: true, stopped: false), .stopInterruptedLaunch, "resumed, not recorded")
        XCTAssertEqual(SessionRecovery.decide(launching, alive: true, stopped: true), .stopInterruptedLaunch)
        for s in [state, launching] {
            XCTAssertEqual(SessionRecovery.decide(s, alive: false, stopped: false), .cleanUp)
            XCTAssertEqual(SessionRecovery.decide(s, alive: false, stopped: true), .cleanUp)
        }
    }

    func testLaunchingMarkRoundTrip() throws {
        XCTAssertEqual(try state.launching(true).text(), "4242\n501\n/x/openvpn\n/p\n\nlaunching\n")
        XCTAssertEqual(SessionState.parse(try state.launching(true).text()), state.launching(true))
        XCTAssertEqual(SessionState.parse(try state.text())?.launching, false)
        XCTAssertNil(SessionState.parse("4242\n501\n/x/openvpn\n/p\n\nrunning\n"), "nothing else in the sixth line")
        XCTAssertEqual(state.launching(true).launching(false), state)
    }

    func testStrandedLaunches() {
        let tools = "/private/var/run/passtunnel/tools"
        let staged = tools + "/" + String(repeating: "ab", count: 32) + "/Resources/bin/openvpn"
        let processes = [
            SessionRecovery.Process(pid: 10, parent: 1, path: staged, stopped: true),  // stranded
            SessionRecovery.Process(pid: 11, parent: 1, path: staged, stopped: false),  // running: not ours to judge
            SessionRecovery.Process(pid: 12, parent: 1, path: staged, stopped: true),  // recorded: decided by its state
            SessionRecovery.Process(pid: 13, parent: 500, path: staged, stopped: true),  // a living parent
            SessionRecovery.Process(pid: 14, parent: 1, path: "/opt/homebrew/sbin/openvpn", stopped: true),
            SessionRecovery.Process(pid: 15, parent: 1, path: tools + "-x/openvpn", stopped: true),
            SessionRecovery.Process(pid: 16, parent: 1, path: nil, stopped: true),
            SessionRecovery.Process(pid: 1, parent: 0, path: staged, stopped: true)
        ]
        XCTAssertEqual(SessionRecovery.strandedLaunches(processes: processes, toolsRoot: tools, recorded: [12]), [10])
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

    /// The helper's launch as it is, cut short between the state and the resume: the restarted helper sees
    /// a stopped tool recorded as launching and stops it; the same tool resumed and recorded is adopted.
    func testInterruptedLaunchIsRecognized() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pt-launch-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let devNull = open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { close(devNull) }
        let pid = try Spawner.spawn(
            executable: "/bin/sleep", arguments: ["30"], environment: HelperCore.fixedEnvironment, workingDirectory: dir,
            outputFD: devNull, suspended: true)
        defer {
            kill(pid, SIGKILL)
            var status: Int32 = 0
            while waitpid(pid, &status, 0) == -1, errno == EINTR {}
        }
        let recorded = SessionState(pid: pid, uid: getuid(), executable: "/bin/sleep", profileDir: dir, mgmtSocket: nil, launching: true)
        try recorded.write(runDir: dir)
        let read = try XCTUnwrap(SessionState.read(dir + "/state"))
        XCTAssertTrue(SessionRecovery.isAlive(read))
        XCTAssertTrue(SessionRecovery.isStopped(pid))
        XCTAssertEqual(SessionRecovery.decide(read, alive: true, stopped: SessionRecovery.isStopped(pid)), .stopInterruptedLaunch)
        // Not recorded at all: found among the system's processes as stopped (here our child, so not stranded).
        let seen = SessionRecovery.systemProcesses().first { $0.pid == pid }
        XCTAssertEqual(seen, SessionRecovery.Process(pid: pid, parent: getpid(), path: "/bin/sleep", stopped: true))
        XCTAssertEqual(
            SessionRecovery.strandedLaunches(processes: [seen!], toolsRoot: "/bin", recorded: []), [], "a living parent: not stranded")

        // Resumed and recorded again, as a finished launch.
        XCTAssertEqual(kill(pid, SIGCONT), 0)
        try recorded.launching(false).write(runDir: dir)
        let finished = try XCTUnwrap(SessionState.read(dir + "/state"))
        XCTAssertFalse(SessionRecovery.isStopped(pid))
        XCTAssertEqual(SessionRecovery.decide(finished, alive: SessionRecovery.isAlive(finished), stopped: SessionRecovery.isStopped(pid)), .adopt)
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
        XCTAssertEqual(failure(copy), .multipleLinks)
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
