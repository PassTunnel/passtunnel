import Foundation
import XCTest

@testable import PassTunnelDaemon
@testable import PassTunnelShared

/// A temporary home with one profile (`acme`), a run root, fake OpenVPN, openfortivpn and pppd and a CA
/// bundle, all owned by the user running the tests (root in the Linux CI container). Nothing here
/// touches /run/passtunnel or starts a tunnel: the "tools" are shell scripts that sleep.
class DaemonTestCase: XCTestCase {
    var base = ""
    var home: String { base + "/home" }
    var runRoot: String { base + "/run" }
    var toolPath: String { base + "/bin/openvpn" }
    var fortiPath: String { base + "/bin/openfortivpn" }
    var pppdPath: String { base + "/bin/pppd" }
    var openConnectPath: String { base + "/bin/openconnect" }
    var caPath: String { base + "/certs/ca-certificates.crt" }
    let me = geteuid()
    /// A user outside the group `passtunnel`.
    var stranger: uid_t { me + 4242 }
    static let groupID: gid_t = 4242
    static let config = "client\nremote vpn.example.com 1194\nauth-user-pass\n"

    /// The caller the injected `peer` reports for the next connections.
    let caller = CallerBox()
    private var daemons: [Daemon] = []

    override func setUpWithError() throws {
        var template = Array("/tmp/ptd-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        base = HelperCore.realPath(String(cString: made)) ?? String(cString: made)
        try FileManager.default.createDirectory(
            atPath: profileDir("acme"), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755])
        try Self.config.write(toFile: profileDir("acme") + "/config.ovpn", atomically: true, encoding: .utf8)
        try makeTool(version: "2.6.9")
        try makeForti(version: "1.21.0")
        try makePPPD(version: "2.4.9")
        try makeOpenConnect(version: "v9.12")
        try FileManager.default.createDirectory(
            atPath: base + "/certs", withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755])
        try "-----BEGIN CERTIFICATE-----\n".write(toFile: caPath, atomically: true, encoding: .utf8)
        chmod(caPath, 0o644)
        caller.uid = me
    }

    override func tearDownWithError() throws {
        daemons.forEach { $0.shutdown() }
        daemons = []
        try? FileManager.default.removeItem(atPath: base)
    }

    func profileDir(_ id: String) -> String { home + "/" + PT.profilesSubpath + "/" + id }

    var users: UserDatabase {
        let me = self.me, stranger = self.stranger, home = self.home
        return UserDatabase(
            name: { uid in uid == me ? "alice" : uid == stranger ? "bob" : nil },
            home: { uid in uid == me || uid == stranger ? home : nil },
            groups: { uid in uid == me ? [100, Self.groupID] : uid == stranger ? [100] : nil },
            groupID: { $0 == Access.groupName ? Self.groupID : nil })
    }

    /// The fake OpenVPN: prints a version for `--version`, else its arguments, then sleeps.
    func makeTool(version: String, at path: String? = nil) throws {
        let path = path ?? toolPath
        try FileManager.default.createDirectory(
            atPath: (path as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        let script = """
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "OpenVPN \(version) x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL]"
              echo "library versions: OpenSSL 3.0.13 30 Jan 2024, LZO 2.10"
              exit 1
            fi
            echo "fake openvpn $*"
            exec sleep 30

            """
        try? FileManager.default.removeItem(atPath: path)
        try script.write(toFile: path, atomically: true, encoding: .utf8)
        chmod(path, 0o755)
    }

    /// The fake openfortivpn: prints a version for `--version`, else its arguments, then sleeps.
    func makeForti(version: String) throws {
        try makeScript(
            fortiPath,
            """
            #!/bin/sh
            if [ "$1" = "--version" ]; then echo "\(version)"; exit 0; fi
            echo "fake openfortivpn $*"
            exec sleep 30

            """)
    }

    /// The fake pppd: only its version (openfortivpn would run it; the fake one does not).
    func makePPPD(version: String) throws {
        try makeScript(
            pppdPath,
            """
            #!/bin/sh
            echo "pppd version \(version)" >&2
            exit 0

            """)
    }

    /// The fake openconnect: its version for `--version` (as openconnect prints it), its options for `--help`,
    /// else its arguments and a line with the session's cookie (which the log must never show), then it sleeps.
    func makeOpenConnect(version: String) throws {
        try makeScript(
            openConnectPath,
            """
            #!/bin/sh
            if [ "$1" = "--version" ]; then echo "OpenConnect version \(version)"; echo "Using GnuTLS 3.8.3. Features present: PKCS#11"; exit 0; fi
            if [ "$1" = "--help" ]; then echo "      --no-external-auth          Do not offer or use auth methods requiring external browser"; exit 1; fi
            echo "fake openconnect $*"
            config="${1#--config=}"
            echo "Got CONNECT response: HTTP/1.1 200 OK $(sed -n 's/^cookie //p' "$config")"
            exec sleep 30

            """)
    }

    func makeScript(_ path: String, _ script: String) throws {
        try? FileManager.default.removeItem(atPath: path)
        try script.write(toFile: path, atomically: true, encoding: .utf8)
        chmod(path, 0o755)
    }

    /// The real checks and version reading, on files below `base` owned by the test's user.
    var fakeTools: SystemTools {
        SystemTools(owner: me, base: base, caBundles: [base + "/certs/none.crt", caPath])
    }

    /// What the daemon runs in these tests: each tool is its fake below `base`.
    struct TestTools: ToolResolving {
        let system: SystemTools
        /// Tool name → the fake that stands in for it.
        let paths: [String: String]

        func resolve(_ spec: ToolSpec) throws -> ResolvedTool {
            try system.resolve(
                ToolSpec(
                    name: spec.name, candidates: paths[spec.name].map { [$0] } ?? [],
                    minimum: spec.minimum, package: spec.package,
                    versionArguments: spec.versionArguments, parseVersion: spec.parseVersion))
        }

        func caBundle() throws -> String { try system.caBundle() }
    }

    var testTools: TestTools {
        TestTools(
            system: fakeTools, paths: ["OpenVPN": toolPath, "openfortivpn": fortiPath, "pppd": pppdPath, "openconnect": openConnectPath])
    }

    func fortiStart(_ id: String = "acme", setDNS: Bool = false) -> FortiStart {
        let dir = profileDir(id)
        return FortiStart(
            profileID: id, profileDir: dir, host: "vpn.example.com", username: "alice",
            password: "pw-forti", otp: "123456", setDNS: setDNS, logPath: dir + "/vpn.log")
    }

    func start(_ id: String = "acme", sha: String? = nil) -> OpenVPNStart {
        let dir = profileDir(id)
        return OpenVPNStart(
            profileID: id, profileDir: dir, username: "alice", secret: "pw123456",
            logPath: dir + "/vpn.log",
            configSHA256: sha ?? HelperCore.sha256Hex(Data(Self.config.utf8)))
    }

    /// A daemon on the temporary run root, serving until the test ends.
    func makeDaemon(_ configure: (inout Daemon.Options) -> Void = { _ in }) throws -> Daemon {
        var options = Daemon.Options()
        options.runRoot = runRoot
        options.users = users
        options.tools = testTools
        options.ownExecutable = nil
        options.build = "test-build"
        options.readTimeout = 2
        options.writeTimeout = 2
        options.stopGrace = 2
        let caller = self.caller
        options.peer = { _ in Caller(uid: caller.uid, gid: 100, pid: getpid()) }
        configure(&options)
        let daemon = try Daemon(options: options)
        try daemon.listen(environment: [:])
        daemon.serve()
        daemons.append(daemon)
        return daemon
    }

    /// Connects to `path` and sends `bytes` (nothing when nil); the descriptor stays open.
    func connect(_ path: String, sending bytes: Data? = nil) throws -> Int32 {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: path.utf8)
            raw[path.utf8.count] = 0
        }
        let fd = Sys.unixStreamSocket()
        XCTAssertGreaterThanOrEqual(fd, 0)
        let rc = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Sys.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0 else {
            close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        if let bytes {
            _ = bytes.withUnsafeBytes { Sys.send(fd, $0.baseAddress!, $0.count) }
        }
        return fd
    }

    /// Everything the peer sends until it closes (or `timeout`).
    func readAll(_ fd: Int32, timeout: TimeInterval = 5) -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, 100) >= 0 else { break }
            if p.revents == 0 { continue }
            let n = read(fd, &buffer, buffer.count)
            if n <= 0 { break }
            data.append(contentsOf: buffer[0..<n])
        }
        return data
    }

    /// One line to the daemon, its reply line back.
    func exchange(_ path: String, _ line: String) throws -> String {
        let fd = try connect(path, sending: Data((line + "\n").utf8))
        defer { close(fd) }
        let reply = String(decoding: readAll(fd), as: UTF8.self)
        XCTAssertTrue(reply.hasSuffix("\n"), reply)
        return String(reply.dropLast())
    }

    func response(_ path: String, _ request: HelperRequest) throws -> HelperResponse {
        let line = String(decoding: try DaemonProtocol.performLine(request).dropLast(), as: UTF8.self)
        return try HelperResponse(jsonData: Data(try exchange(path, line).utf8))
    }

    /// Waits up to `timeout` for `condition`.
    func eventually(_ timeout: TimeInterval = 5, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            usleep(20_000)
        }
        return condition()
    }

    func exists(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0
    }
}

final class CallerBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: uid_t = 0

    var uid: uid_t {
        get { lock.lock(); defer { lock.unlock() }; return value }
        set { lock.lock(); value = newValue; lock.unlock() }
    }
}
