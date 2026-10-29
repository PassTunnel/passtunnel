// macOS only, like Spawner (code signatures, suspended launch).
#if os(macOS)
import Darwin
import Security
import XCTest
@testable import PassTunnelShared

/// The helper starts tools suspended and only resumes them once the code the kernel loaded passed the
/// signature check (`Spawner.spawnVerified`). Uses macOS's own binaries, never the VPN tools.
final class SpawnerTests: XCTestCase {
    var dir: URL!
    var output: URL { dir.appendingPathComponent("out.log") }
    var outputFD: Int32 = -1

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pt-spawn-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        outputFD = open(output.path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(outputFD, 0)
    }

    override func tearDownWithError() throws {
        if outputFD >= 0 { close(outputFD) }
        try? FileManager.default.removeItem(at: dir)
    }

    /// Records what it saw and accepts or rejects.
    final class FakeVerifier: LaunchVerifier {
        struct Rejected: Error {}
        let accept: Bool
        var pid: pid_t = 0
        var executable = ""
        var wasStopped = false
        var before: (() throws -> Void)?

        init(accept: Bool) { self.accept = accept }

        func verify(pid: pid_t, executable: String) throws {
            self.pid = pid
            self.executable = executable
            wasStopped = SpawnerTests.isStopped(pid)
            try before?()
            if !accept { throw Rejected() }
        }
    }

    static func isStopped(_ pid: pid_t) -> Bool {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size && info.pbi_status == UInt32(SSTOP)
    }

    static func isGone(_ pid: pid_t) -> Bool {
        kill(pid, 0) == -1 && errno == ESRCH
    }

    func spawn(
        _ executable: String, _ args: [String], verifier: LaunchVerifier,
        environment: [String] = HelperCore.fixedEnvironment
    ) throws -> pid_t {
        try Spawner.spawnVerified(
            executable: executable, arguments: args, environment: environment,
            workingDirectory: dir.path, outputFD: outputFD, verifier: verifier)
    }

    func waitForExit(_ pid: pid_t) -> Int32 {
        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1, errno == EINTR {}
        return status
    }

    func outputText() throws -> String { try String(contentsOf: output, encoding: .utf8) }

    func testAcceptedChildIsCheckedWhileSuspendedThenResumed() throws {
        let verifier = FakeVerifier(accept: true)
        let pid = try spawn("/bin/echo", ["started"], verifier: verifier)
        XCTAssertEqual(verifier.pid, pid)
        XCTAssertEqual(verifier.executable, "/bin/echo")
        XCTAssertTrue(verifier.wasStopped, "verified before it ran")
        let status = waitForExit(pid)
        XCTAssertEqual(status, 0)
        XCTAssertEqual(try outputText(), "started\n")
    }

    func testRejectedChildIsKilledAndReapedBeforeItRuns() throws {
        let verifier = FakeVerifier(accept: false)
        XCTAssertThrowsError(try spawn("/bin/echo", ["started"], verifier: verifier)) { error in
            XCTAssertTrue(error is FakeVerifier.Rejected, "the verifier's error is reported: \(error)")
        }
        XCTAssertGreaterThan(verifier.pid, 0)
        XCTAssertTrue(verifier.wasStopped)
        XCTAssertTrue(Self.isGone(verifier.pid), "killed and reaped (no zombie left)")
        XCTAssertEqual(try outputText(), "", "it never ran")
    }

    func testChildGetsOnlyTheFixedEnvironment() throws {
        setenv("PT_SPAWN_TEST_LEAK", "1", 1)
        defer { unsetenv("PT_SPAWN_TEST_LEAK") }
        let pid = try spawn("/usr/bin/env", [], verifier: FakeVerifier(accept: true))
        XCTAssertEqual(waitForExit(pid), 0)
        let lines = try outputText().split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.sorted(), HelperCore.fixedEnvironment.sorted())
    }

    /// The helper writes the session's `state` here, before the tool can run its hook.
    func testBeforeResumeRunsWhileSuspendedAndItsFailureKillsTheChild() throws {
        var seen: (pid: pid_t, stopped: Bool)?
        let pid = try Spawner.spawnVerified(
            executable: "/bin/echo", arguments: ["started"], environment: HelperCore.fixedEnvironment,
            workingDirectory: dir.path, outputFD: outputFD, verifier: FakeVerifier(accept: true),
            beforeResume: { seen = ($0, Self.isStopped($0)) })
        XCTAssertEqual(seen?.pid, pid)
        XCTAssertEqual(seen?.stopped, true)
        XCTAssertEqual(waitForExit(pid), 0)

        struct NotRecorded: Error {}
        var failed: pid_t = 0
        XCTAssertThrowsError(
            try Spawner.spawnVerified(
                executable: "/bin/echo", arguments: ["never"], environment: HelperCore.fixedEnvironment,
                workingDirectory: dir.path, outputFD: outputFD, verifier: FakeVerifier(accept: true),
                beforeResume: {
                    failed = $0
                    throw NotRecorded()
                })
        ) { XCTAssertTrue($0 is NotRecorded) }
        XCTAssertTrue(Self.isGone(failed), "killed and reaped before it ran")
        // A rejected child never reaches it.
        var reached = false
        XCTAssertThrowsError(
            try Spawner.spawnVerified(
                executable: "/bin/echo", arguments: ["never"], environment: HelperCore.fixedEnvironment,
                workingDirectory: dir.path, outputFD: outputFD, verifier: FakeVerifier(accept: false),
                beforeResume: { _ in reached = true }))
        XCTAssertFalse(reached)
        XCTAssertEqual(try outputText(), "started\n")
    }

    /// openconnect's environment as spawned: exactly `HelperCore.environment(for: .openconnect)`, nothing
    /// from the helper's own (here a proxy and a TLS key log are set in it).
    func testOpenConnectGetsOnlyItsBuiltEnvironment() throws {
        for name in ["https_proxy", "SSLKEYLOGFILE", "GNUTLS_DEBUG_LEVEL"] { setenv(name, "/tmp/pt-leak", 1) }
        defer { for name in ["https_proxy", "SSLKEYLOGFILE", "GNUTLS_DEBUG_LEVEL"] { unsetenv(name) } }
        let pid = try spawn("/usr/bin/env", [], verifier: FakeVerifier(accept: true), environment: HelperCore.environment(for: .openconnect))
        XCTAssertEqual(waitForExit(pid), 0)
        let lines = try outputText().split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.sorted(), HelperCore.environment(for: .openconnect).sorted())
    }

    func testChildRunsInItsOwnProcessGroup() throws {
        let verifier = FakeVerifier(accept: true)
        verifier.before = { XCTAssertEqual(getpgid(verifier.pid), verifier.pid) }
        let pid = try spawn("/bin/echo", [], verifier: verifier)
        XCTAssertEqual(waitForExit(pid), 0)
    }

    func testRealRequirementIsCheckedOnTheRunningProcess() throws {
        // Apple's own binary passes an Apple requirement and fails ours.
        let pid = try spawn("/bin/echo", ["apple"], verifier: RequirementVerifier(requirement: "anchor apple"))
        XCTAssertEqual(waitForExit(pid), 0)
        XCTAssertEqual(try outputText(), "apple\n")

        let tool = RequirementVerifier(requirement: PT.toolRequirement(identifier: PT.openvpnIdentifier))
        let recorder = Recording(tool)
        XCTAssertThrowsError(try spawn("/bin/echo", ["ours"], verifier: recorder)) { error in
            XCTAssertEqual((error as? CodeSignature.Failure)?.status, errSecCSReqFailed, "\(error)")
        }
        XCTAssertTrue(Self.isGone(recorder.pid))
        XCTAssertEqual(try outputText(), "apple\n", "the rejected process never ran")
    }

    /// Builds an ad-hoc signed program printing `text` (copies of macOS's own binaries do not run
    /// outside their system location).
    func makeTool(_ name: String, prints text: String) throws -> String {
        let src = dir.appendingPathComponent(name + ".c")
        let bin = dir.appendingPathComponent(name).path
        try "#include <stdio.h>\nint main(void) { puts(\"\(text)\"); return 0; }\n"
            .write(to: src, atomically: true, encoding: .utf8)
        guard run("/usr/bin/xcrun", ["clang", "-o", bin, src.path]) == 0,
            run("/usr/bin/codesign", ["-f", "-s", "-", "-i", "com.example.acme." + name, bin]) == 0
        else {
            throw XCTSkip("no C compiler or codesign available")
        }
        return bin
    }

    func run(_ executable: String, _ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return -1 }
        p.waitUntilExit()
        return p.terminationStatus
    }

    /// The race the suspended start closes: the file at the path is replaced after posix_spawn opened
    /// it. A check by path now sees a valid file; the check on the process sees the mismatch.
    func testFileSwappedAfterTheSpawnIsDetected() throws {
        let fm = FileManager.default
        let real = try makeTool("real", prints: "real")
        let other = try makeTool("other", prints: "other")
        let requirement = "identifier \"com.example.acme.real\""

        // Control: the real tool passes the check on the running process.
        let ok = try spawn(real, [], verifier: RequirementVerifier(requirement: requirement))
        XCTAssertEqual(waitForExit(ok), 0)
        XCTAssertEqual(try outputText(), "real\n")
        XCTAssertThrowsError(try spawn(other, [], verifier: RequirementVerifier(requirement: requirement))) {
            XCTAssertEqual(($0 as? CodeSignature.Failure)?.status, errSecCSReqFailed, "\($0)")
        }

        // `other` is what runs; by the time of the check, the real tool is back at the path.
        let path = dir.appendingPathComponent("tool").path
        try fm.copyItem(atPath: other, toPath: path)
        let swap = FakeVerifier(accept: true)
        swap.before = {
            try fm.removeItem(atPath: path)
            try fm.copyItem(atPath: real, toPath: path)
        }
        try Data().write(to: output)
        let verifier = Chain([swap, RequirementVerifier(requirement: requirement)])
        // Which call notices depends on timing: Security finds the process's code through its path
        // (proc_pidpath), which fails with ESRCH once the file it was started from is unlinked; if the
        // name lookup still resolves, the check finds the new file (errSecCSStaticCodeChanged) or no
        // matching guest. Either way the process is refused.
        XCTAssertThrowsError(try spawn(path, [], verifier: verifier)) { error in
            XCTAssertNotNil(error as? CodeSignature.Failure, "\(error)")
        }
        XCTAssertNoThrow(
            try CodeSignature.verify(path: path, requirement: requirement),
            "the file now at the path is valid on its own")
        XCTAssertTrue(Self.isGone(swap.pid))
        XCTAssertEqual(try outputText(), "", "the swapped-in program never ran")
    }

    // MARK: cdhash pins (PinnedTools)

    /// `CDHash=` as `codesign -dvvv` prints it (what build-app.sh pins).
    func codesignCDHash(_ path: String) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        p.arguments = ["-dvvv", path]
        let pipe = Pipe()
        p.standardError = pipe
        p.standardOutput = FileHandle.nullDevice
        try p.run()
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        let line = try XCTUnwrap(out.split(separator: "\n").first { $0.hasPrefix("CDHash=") })
        return String(line.dropFirst("CDHash=".count))
    }

    func testPinComparison() throws {
        func verifier(_ pins: Set<String>?, reports cdhash: String) -> RequirementVerifier {
            RequirementVerifier(requirement: "anchor apple", cdhashes: pins) { pid, path, requirement in
                XCTAssertEqual(pid, 42)
                XCTAssertEqual(path, "/x/bin/openvpn")
                XCTAssertEqual(requirement, "anchor apple")
                return cdhash
            }
        }
        XCTAssertNoThrow(try verifier(nil, reports: "aa11").verify(pid: 42, executable: "/x/bin/openvpn"))
        XCTAssertNoThrow(try verifier(["aa11", "bb22"], reports: "AA11").verify(pid: 42, executable: "/x/bin/openvpn"))
        XCTAssertThrowsError(try verifier(["bb22"], reports: "aa11").verify(pid: 42, executable: "/x/bin/openvpn")) {
            XCTAssertEqual($0 as? PinnedTools.Mismatch, PinnedTools.Mismatch(tool: "openvpn", cdhash: "aa11"))
        }
        XCTAssertThrowsError(try verifier([], reports: "aa11").verify(pid: 42, executable: "/x/bin/openvpn"))
        // A failed requirement is reported as such, before any pin is looked at.
        let failing = RequirementVerifier(requirement: "anchor apple", cdhashes: ["aa11"]) { _, path, _ in
            throw CodeSignature.Failure(path: path, status: errSecCSReqFailed)
        }
        XCTAssertThrowsError(try failing.verify(pid: 42, executable: "/x/bin/openvpn")) {
            XCTAssertEqual(($0 as? CodeSignature.Failure)?.status, errSecCSReqFailed)
        }

        // Nothing pinned at all: no restriction. Pinned: a tool without an entry is refused.
        XCTAssertNil(PinnedTools.allowed("openvpn", pins: [:]))
        XCTAssertEqual(PinnedTools.allowed("openvpn", pins: ["openvpn": ["aa11"]]), ["aa11"])
        XCTAssertEqual(PinnedTools.allowed("openfortivpn", pins: ["openvpn": ["aa11"]]), [])
        XCTAssertEqual(PinnedTools.cdhashes, [:], "test builds pin nothing (build-app.sh does)")
    }

    func testPinMismatchKillsTheSuspendedChild() throws {
        let verifier = RequirementVerifier(requirement: "anchor apple", cdhashes: ["0000"]) { _, _, _ in "ffff" }
        let recorder = Recording(verifier)
        XCTAssertThrowsError(try spawn("/bin/echo", ["started"], verifier: recorder)) {
            XCTAssertEqual($0 as? PinnedTools.Mismatch, PinnedTools.Mismatch(tool: "echo", cdhash: "ffff"))
        }
        XCTAssertTrue(Self.isGone(recorder.pid), "killed and reaped")
        XCTAssertEqual(try outputText(), "", "it never ran")
    }

    /// An older build with the same identifier (and, in a release, the same Team ID) passes the
    /// requirement; only the pin tells it apart. The cdhash of the running process is the one
    /// `codesign -dvvv` reports for the file.
    func testPinnedCDHashOfTheRunningProcess() throws {
        let current = try makeTool("tool", prints: "current")
        let older = dir.appendingPathComponent("older").path
        let src = dir.appendingPathComponent("older.c")
        try "#include <stdio.h>\nint main(void) { puts(\"older\"); return 0; }\n".write(to: src, atomically: true, encoding: .utf8)
        guard run("/usr/bin/xcrun", ["clang", "-o", older, src.path]) == 0,
            run("/usr/bin/codesign", ["-f", "-s", "-", "-i", "com.example.acme.tool", older]) == 0
        else {
            throw XCTSkip("no C compiler or codesign available")
        }
        let requirement = "identifier \"com.example.acme.tool\""
        let pin = try codesignCDHash(current)
        XCTAssertEqual(pin.count, 40)
        XCTAssertNotEqual(try codesignCDHash(older), pin)

        var seen = ""
        let checked = RequirementVerifier(requirement: requirement, cdhashes: [pin]) { pid, path, requirement in
            seen = try CodeSignature.verify(pid: pid, path: path, requirement: requirement)
            return seen
        }
        let ok = try spawn(current, [], verifier: checked)
        XCTAssertEqual(waitForExit(ok), 0)
        XCTAssertEqual(seen, pin)
        XCTAssertEqual(try outputText(), "current\n")
        XCTAssertEqual(try CodeSignature.verify(path: current, requirement: requirement), pin)

        try Data().write(to: output)
        let recorder = Recording(RequirementVerifier(requirement: requirement, cdhashes: [pin]))
        XCTAssertThrowsError(try spawn(older, [], verifier: recorder)) { error in
            XCTAssertEqual((error as? PinnedTools.Mismatch)?.cdhash, try? self.codesignCDHash(older), "\(error)")
        }
        XCTAssertTrue(Self.isGone(recorder.pid))
        XCTAssertEqual(try outputText(), "", "the older build never ran")
    }

    func testSpawnFailureIsReported() {
        XCTAssertThrowsError(try spawn(dir.appendingPathComponent("missing").path, [], verifier: FakeVerifier(accept: true))) {
            XCTAssertEqual(($0 as? Spawner.Failure)?.code, ENOENT)
        }
    }

    final class Recording: LaunchVerifier {
        let inner: LaunchVerifier
        var pid: pid_t = 0
        init(_ inner: LaunchVerifier) { self.inner = inner }
        func verify(pid: pid_t, executable: String) throws {
            self.pid = pid
            try inner.verify(pid: pid, executable: executable)
        }
    }

    struct Chain: LaunchVerifier {
        let verifiers: [LaunchVerifier]
        init(_ verifiers: [LaunchVerifier]) { self.verifiers = verifiers }
        func verify(pid: pid_t, executable: String) throws {
            for v in verifiers { try v.verify(pid: pid, executable: executable) }
        }
    }
}

// MARK: - Tool environment

final class ToolEnvironmentTests: XCTestCase {
    func value(_ name: String) -> String? {
        HelperCore.fixedEnvironment.first { $0.hasPrefix(name + "=") }.map { String($0.dropFirst(name.count + 1)) }
    }

    func testOpenSSLNeverReadsTheBuildMachinePrefix() {
        XCTAssertEqual(value("OPENSSL_CONF"), "/dev/null")
        XCTAssertEqual(value("OPENSSL_MODULES"), HelperCore.missingDirectory)
        XCTAssertEqual(value("OPENSSL_ENGINES"), HelperCore.missingDirectory)
        XCTAssertEqual(value("SSL_CERT_FILE"), HelperCore.systemCAFile)
        XCTAssertEqual(value("SSL_CERT_DIR"), "/var/empty")
        XCTAssertEqual(value("PATH"), "/usr/bin:/bin:/usr/sbin:/sbin")
        XCTAssertEqual(value("LC_ALL"), "C")
        XCTAssertFalse(HelperCore.fixedEnvironment.contains { $0.hasPrefix("DYLD_") })
        XCTAssertEqual(
            Set(HelperCore.fixedEnvironment.map { $0.prefix { $0 != "=" } }).count,
            HelperCore.fixedEnvironment.count, "no variable twice")
    }

    func testPathsAreRootOwned() {
        var st = stat()
        XCTAssertEqual(lstat(HelperCore.systemCAFile, &st), 0)
        XCTAssertEqual(st.st_uid, 0)
        XCTAssertEqual(st.st_mode & S_IFMT, S_IFREG)
        XCTAssertEqual(lstat("/var/empty", &st), 0)
        XCTAssertEqual(st.st_uid, 0)
        XCTAssertEqual(st.st_mode & 0o022, 0, "only root can create entries")
        XCTAssertFalse(FileManager.default.fileExists(atPath: HelperCore.missingDirectory))
    }
}
#endif
