import Foundation
import XCTest

@testable import PassTunnelDaemon
@testable import PassTunnelShared

/// The tool checks, against files in a temporary directory owned by the test's user (the checks
/// start there instead of at `/`, and that user stands in for root).
final class ToolCheckTests: DaemonTestCase {
    func check(_ path: String, owner: uid_t? = nil) throws {
        try TrustedPath.check(path, owner: owner ?? me, base: base)
    }

    func testTrustedPath() throws {
        XCTAssertNoThrow(try check(toolPath))
        XCTAssertThrowsError(try check(toolPath, owner: me + 1)) {
            XCTAssertEqual($0 as? TrustedPath.Failure, .wrongOwner(base, me))
        }
        XCTAssertThrowsError(try check(base + "/bin")) { XCTAssertEqual($0 as? TrustedPath.Failure, .notARegularFile(base + "/bin")) }
        XCTAssertThrowsError(try check(base + "/bin/none")) { XCTAssertEqual($0 as? TrustedPath.Failure, .missing(base + "/bin/none")) }
        XCTAssertThrowsError(try check("bin/openvpn")) { XCTAssertEqual($0 as? TrustedPath.Failure, .notAbsolute("bin/openvpn")) }
        XCTAssertThrowsError(try TrustedPath.check("/usr/bin/env", owner: me, base: base), "outside the base")
    }

    func testWritableComponentsAreRefused() throws {
        chmod(toolPath, 0o775)
        XCTAssertThrowsError(try check(toolPath)) { XCTAssertEqual($0 as? TrustedPath.Failure, .writableByOthers(toolPath)) }
        chmod(toolPath, 0o757)
        XCTAssertThrowsError(try check(toolPath)) { XCTAssertEqual($0 as? TrustedPath.Failure, .writableByOthers(toolPath)) }
        chmod(toolPath, 0o755)
        chmod(base + "/bin", 0o1777)  // sticky does not help
        XCTAssertThrowsError(try check(toolPath)) { XCTAssertEqual($0 as? TrustedPath.Failure, .writableByOthers(base + "/bin")) }
        chmod(base + "/bin", 0o775)
        XCTAssertThrowsError(try check(toolPath)) { XCTAssertEqual($0 as? TrustedPath.Failure, .writableByOthers(base + "/bin")) }
        chmod(base + "/bin", 0o755)
        XCTAssertNoThrow(try check(toolPath))
    }

    func testLinksAreRefused() throws {
        XCTAssertEqual(symlink(toolPath, base + "/bin/link"), 0)
        XCTAssertThrowsError(try check(base + "/bin/link")) { XCTAssertEqual($0 as? TrustedPath.Failure, .symlink(base + "/bin/link")) }
        try FileManager.default.createDirectory(
            atPath: base + "/real", withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755])
        XCTAssertEqual(symlink(base + "/real", base + "/dirlink"), 0)
        try makeTool(version: "2.6.9", at: base + "/real/openvpn")
        XCTAssertThrowsError(try check(base + "/dirlink/openvpn")) {
            XCTAssertEqual($0 as? TrustedPath.Failure, .symlink(base + "/dirlink"))
        }
    }

    /// Another owner anywhere on the path (only root can hand a file to someone else).
    func testOtherOwnersAreRefused() throws {
        guard me == 0 else { throw XCTSkip("needs root to change owners") }
        XCTAssertEqual(chown(toolPath, 65534, 65534), 0)
        XCTAssertThrowsError(try check(toolPath)) { XCTAssertEqual($0 as? TrustedPath.Failure, .wrongOwner(toolPath, 65534)) }
        XCTAssertEqual(chown(toolPath, 0, 0), 0)
        XCTAssertEqual(chown(base + "/bin", 65534, 65534), 0)
        XCTAssertThrowsError(try check(toolPath)) { XCTAssertEqual($0 as? TrustedPath.Failure, .wrongOwner(base + "/bin", 65534)) }
    }

    func spec(_ candidates: [String]) -> ToolSpec {
        ToolSpec(
            name: "OpenVPN", candidates: candidates, minimum: ToolVersion(2, 6, 0), package: "openvpn",
            versionArguments: ["--version"], parseVersion: ToolSpec.openVPNVersion)
    }

    func testResolveRunsTheFirstExistingCandidate() throws {
        let tool = try fakeTools.resolve(spec([base + "/sbin/openvpn", toolPath]))
        XCTAssertEqual(tool, ResolvedTool(path: toolPath, version: ToolVersion(2, 6, 9)))
        // A symlinked candidate is resolved once; its target is what is checked and run.
        XCTAssertEqual(symlink(toolPath, base + "/bin/openvpn-link"), 0)
        XCTAssertEqual(try fakeTools.resolve(spec([base + "/bin/openvpn-link"])).path, toolPath)
    }

    func testResolveFailures() throws {
        XCTAssertThrowsError(try fakeTools.resolve(spec([base + "/none", base + "/sbin/none"]))) { error in
            guard case .notInstalled = error as? ToolFailure else { return XCTFail("\(error)") }
            let text = String(describing: error)
            XCTAssertTrue(text.contains("openvpn package") && text.contains("2.6 or later"), text)
        }
        try makeTool(version: "2.5.11")
        XCTAssertThrowsError(try fakeTools.resolve(spec([toolPath]))) {
            XCTAssertEqual(
                $0 as? ToolFailure,
                .tooOld(
                    name: "OpenVPN", version: ToolVersion(2, 5, 11),
                    minimum: ToolVersion(2, 6, 0), package: "openvpn"))
            XCTAssertEqual(String(describing: $0), "OpenVPN 2.5.11 is too old: PassTunnel needs 2.6.0 or later. Update the openvpn package.")
        }
        try makeTool(version: "unknown")
        XCTAssertThrowsError(try fakeTools.resolve(spec([toolPath]))) {
            XCTAssertEqual($0 as? ToolFailure, .unknownVersion(name: "OpenVPN", path: toolPath))
        }
        try makeTool(version: "2.6.9")
        chmod(base + "/bin", 0o777)
        XCTAssertThrowsError(try fakeTools.resolve(spec([toolPath]))) { error in
            guard case .untrusted(_, let path, let reason) = error as? ToolFailure else { return XCTFail("\(error)") }
            XCTAssertEqual(path, toolPath)
            XCTAssertTrue(reason.contains("writable"), reason)
        }
        chmod(base + "/bin", 0o755)
    }

    func testFortiToolsAndVersions() throws {
        XCTAssertEqual(ToolSpec.openfortivpn.candidates, ["/usr/bin/openfortivpn"])
        XCTAssertEqual(ToolSpec.openfortivpn.minimum, ToolVersion(1, 21, 0))
        XCTAssertEqual(ToolSpec.pppd.candidates, ["/usr/sbin/pppd"])
        XCTAssertEqual(ToolSpec.firstVersion("1.21.0\n"), ToolVersion(1, 21, 0))
        XCTAssertEqual(ToolSpec.firstVersion("v1.22.1-3-gabcdef0\n"), ToolVersion(1, 22, 1))
        XCTAssertEqual(ToolSpec.firstVersion("openfortivpn 1.23.1\n"), ToolVersion(1, 23, 1))
        XCTAssertEqual(ToolSpec.firstVersion("pppd version 2.4.9\n"), ToolVersion(2, 4, 9))
        XCTAssertEqual(ToolSpec.firstVersion("pppd version 2.5.1\n"), ToolVersion(2, 5, 1))
        XCTAssertNil(ToolSpec.firstVersion("pppd: unrecognized option '--version'\n"))
        XCTAssertNil(ToolSpec.firstVersion(""))
        let tools = SystemTools(owner: me, base: base)
        XCTAssertEqual(try testTools.resolve(.openfortivpn), ResolvedTool(path: fortiPath, version: ToolVersion(1, 21, 0)))
        XCTAssertEqual(try testTools.resolve(.pppd), ResolvedTool(path: pppdPath, version: ToolVersion(2, 4, 9)))
        XCTAssertEqual(
            tools.caBundles,
            [
                "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/cert.pem"
            ])
    }

    /// The first CA bundle that exists, resolved and checked like a tool.
    func testCABundle() throws {
        XCTAssertEqual(try fakeTools.caBundle(), caPath)
        XCTAssertEqual(symlink(caPath, base + "/certs/link.pem"), 0)
        var tools = fakeTools
        tools.caBundles = [base + "/certs/link.pem"]
        XCTAssertEqual(try tools.caBundle(), caPath, "a symlinked bundle is resolved")
        chmod(base + "/certs", 0o777)
        XCTAssertThrowsError(try tools.caBundle()) { error in
            guard case .untrustedCABundle(let path, let reason) = error as? ToolFailure else { return XCTFail("\(error)") }
            XCTAssertEqual(path, caPath)
            XCTAssertTrue(reason.contains("writable"), reason)
        }
        chmod(base + "/certs", 0o755)
        tools.caBundles = [base + "/none.pem"]
        XCTAssertThrowsError(try tools.caBundle()) {
            XCTAssertEqual($0 as? ToolFailure, .noCABundle(candidates: [base + "/none.pem"]))
        }
    }

    /// The version is read only from a file that passed the checks: an untrusted one never runs.
    func testUntrustedToolIsNeverRun() throws {
        chmod(toolPath, 0o777)
        var ran = false
        let tools = SystemTools(
            owner: me, base: base,
            versionOutput: { _, _ in
                ran = true; return "OpenVPN 2.6.9"
            })
        XCTAssertThrowsError(try tools.resolve(spec([toolPath])))
        XCTAssertFalse(ran)
    }
}

/// How the tools are started: the checked path, the fixed environment, nothing inherited.
final class SpawnTests: DaemonTestCase {
    func testFixedEnvironment() {
        XCTAssertEqual(HelperCore.fixedEnvironment, ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"])
        let output = ToolRunner.output(of: "/usr/bin/env", arguments: [])
        XCTAssertEqual(output?.split(separator: "\n").map(String.init), HelperCore.fixedEnvironment)
    }

    func testNoInheritedDescriptors() throws {
        let fd = open("/dev/null", O_RDONLY)  // without O_CLOEXEC
        XCTAssertGreaterThanOrEqual(fd, 0)
        XCTAssertEqual(dup2(fd, 100), 100)
        defer { close(fd); close(100) }
        let output = try XCTUnwrap(ToolRunner.output(of: "/bin/ls", arguments: ["/proc/self/fd"]))
        let fds = Set(output.split(separator: "\n").map(String.init))
        XCTAssertTrue(fds.isSuperset(of: ["0", "1", "2"]), output)
        XCTAssertFalse(fds.contains("100"), output)
        XCTAssertFalse(fds.contains(String(fd)) && fd > 3, output)
        XCTAssertLessThanOrEqual(fds.count, 4, "0, 1, 2 and the directory ls reads: \(output)")
    }

    /// Default signal actions, nothing blocked, a process group of its own, stdin from /dev/null.
    func testSignalsAndProcessGroup() throws {
        let saved = signal(SIGHUP, SIG_IGN)
        var block = sigset_t()
        sigemptyset(&block)
        sigaddset(&block, SIGUSR2)
        var old = sigset_t()
        pthread_sigmask(SIG_BLOCK, &block, &old)
        defer {
            signal(SIGHUP, saved)
            pthread_sigmask(SIG_SETMASK, &old, nil)
        }
        let status = try XCTUnwrap(ToolRunner.output(of: "/bin/cat", arguments: ["/proc/self/status"]))
        let fields = Dictionary(
            status.split(separator: "\n").compactMap { line -> (String, String)? in
                let parts = line.split(separator: ":", maxSplits: 1)
                return parts.count == 2 ? (String(parts[0]), parts[1].trimmingCharacters(in: .whitespaces)) : nil
            }, uniquingKeysWith: { a, _ in a })
        // Signals 1–31. glibc's posix_spawn leaves its two internal real-time signals (32, 33)
        // ignored in the child, and the child's own glibc takes them over at start.
        func standard(_ key: String) -> UInt64? { fields[key].flatMap { UInt64($0, radix: 16) }.map { $0 & 0x7FFF_FFFF } }
        XCTAssertEqual(standard("SigBlk"), 0, status)
        XCTAssertEqual(standard("SigIgn"), 0, status)
        XCTAssertEqual(fields["SigBlk"], "0000000000000000", "nothing blocked at all: \(status)")

        let stat = try XCTUnwrap(ToolRunner.output(of: "/bin/cat", arguments: ["/proc/self/stat"]))
        let pid = stat.prefix { $0 != " " }
        let after = stat[stat.index(after: try XCTUnwrap(stat.lastIndex(of: ")")))...].split(separator: " ")
        XCTAssertEqual(String(after[2]), String(pid), "process group leader: \(stat)")

        let stdin = try XCTUnwrap(ToolRunner.output(of: "/bin/readlink", arguments: ["/proc/self/fd/0"]))
        XCTAssertEqual(stdin, "/dev/null\n")
    }

    func testRunnerTimesOut() {
        let start = Date()
        let output = ToolRunner.output(of: "/bin/sh", arguments: ["-c", "echo started; exec sleep 30"], timeout: 0.5)
        XCTAssertEqual(output, "started\n")
        XCTAssertLessThan(Date().timeIntervalSince(start), 5, "killed at the timeout")
        XCTAssertNil(ToolRunner.output(of: base + "/none", arguments: []))
    }
}
