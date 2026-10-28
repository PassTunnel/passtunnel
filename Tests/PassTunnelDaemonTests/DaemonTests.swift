import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelDaemon
@testable import PassTunnelShared

// MARK: - The socket

final class DaemonSocketTests: DaemonTestCase {
    func testRunRootAndSocket() throws {
        let daemon = try makeDaemon()
        var st = stat()
        XCTAssertEqual(lstat(runRoot, &st), 0)
        XCTAssertEqual(st.st_mode & 0o7777, 0o711)
        XCTAssertEqual(st.st_uid, me)
        XCTAssertEqual(lstat(daemon.socketPath, &st), 0)
        XCTAssertEqual(st.st_mode & S_IFMT, S_IFSOCK)
        XCTAssertEqual(st.st_mode & 0o777, 0o666, "anyone may connect; requests are checked one by one")
        XCTAssertEqual(daemon.socketPath, runRoot + "/daemon.sock")
        daemon.shutdown()
        XCTAssertFalse(exists(daemon.socketPath), "its own socket goes with it")
    }

    func testHello() throws {
        let daemon = try makeDaemon { $0.buildNumber = 214 }
        let reply = try exchange(daemon.socketPath, #"{"op":"hello"}"#)
        XCTAssertEqual(
            try DaemonHello(jsonData: Data(reply.utf8)),
            DaemonHello(protocolVersion: PT.helperProtocolVersion, build: "test-build", buildNumber: 214))
        caller.uid = stranger
        XCTAssertEqual(
            try DaemonHello(jsonData: Data(try exchange(daemon.socketPath, #"{"op":"hello"}"#).utf8)).build,
            "test-build", "anyone may ask")
    }

    func testStatusIsEmptyAndCarriesTheBuildNumber() throws {
        let daemon = try makeDaemon { $0.buildNumber = 214 }
        let status = try response(daemon.socketPath, .status)
        XCTAssertTrue(status.ok)
        XCTAssertEqual(status.running, [:])
        XCTAssertEqual(status.mgmtSockets, [:])
        XCTAssertEqual(status.helperBuild, 214)
    }

    /// A development build has no number (scripts/build-linux.sh compiles one in): `hello` and the
    /// replies leave it out, as the Mac's helper does outside a bundle.
    func testDevelopmentBuildHasNoNumber() throws {
        XCTAssertNil(DaemonBuild.number, "tests are not release builds")
        let daemon = try makeDaemon { $0.buildNumber = DaemonBuild.number }
        let hello = try exchange(daemon.socketPath, #"{"op":"hello"}"#)
        XCTAssertFalse(hello.contains("build_number"), hello)
        XCTAssertNil(try response(daemon.socketPath, .status).helperBuild)
    }

    func testBadMessages() throws {
        let daemon = try makeDaemon()
        let cases = [
            ("nonsense", "Malformed message"),
            (#"{"op":"reboot"}"#, "Unknown operation “reboot”"),
            (#"{"op":"perform"}"#, "without a “request”"),
            (#"{"op":"perform","request":{"type":"status"}}"#, "Protocol version mismatch"),
            (#"{"op":"perform","request":{"type":"shell","protocol_version":4}}"#, "Unknown request type “shell”"),
            (#"{"op":"perform","request":{"type":"stop","protocol_version":4}}"#, "field “profile_id”")
        ]
        for (line, expected) in cases {
            let reply = try HelperResponse(jsonData: Data(try exchange(daemon.socketPath, line).utf8))
            XCTAssertFalse(reply.ok, line)
            XCTAssertTrue(reply.error?.contains(expected) == true, "\(line): \(reply.error ?? "")")
        }
    }

    func testLineLimit() throws {
        let daemon = try makeDaemon()
        // A request that fills the line exactly is read (and judged by decodeRequest).
        var line = #"{"op":"perform","request":{"type":"status","protocol_version":4}}"#
        line += String(repeating: " ", count: DaemonProtocol.maxLineBytes - line.utf8.count)
        XCTAssertTrue(try HelperResponse(jsonData: Data(try exchange(daemon.socketPath, line).utf8)).ok)
        let reply = try HelperResponse(jsonData: Data(try exchange(daemon.socketPath, line + " ").utf8))
        XCTAssertFalse(reply.ok)
        XCTAssertTrue(reply.error?.contains("too large") == true, reply.error ?? "")
    }

    /// A client that never sends its line is dropped at the read timeout, and does not hold up others.
    func testSilentClientsDoNotBlockOthers() throws {
        let daemon = try makeDaemon { $0.readTimeout = 1 }
        let silent = try connect(daemon.socketPath)
        defer { close(silent) }
        let start = Date()
        XCTAssertTrue(try response(daemon.socketPath, .status).ok)
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.9, "answered while the other connection waits")
        XCTAssertEqual(readAll(silent, timeout: 5), Data(), "closed without a reply")
        XCTAssertLessThan(Date().timeIntervalSince(start), 4)
    }

    /// More connections than a user may hold are turned away at once.
    func testConnectionLimitPerUser() throws {
        let daemon = try makeDaemon {
            $0.maxConnectionsPerUser = 2
            $0.readTimeout = 3
        }
        let held = [try connect(daemon.socketPath), try connect(daemon.socketPath)]
        defer { held.forEach { close($0) } }
        usleep(200_000)
        let start = Date()
        let busy = try HelperResponse(jsonData: Data(try exchange(daemon.socketPath, #"{"op":"hello"}"#).utf8))
        XCTAssertFalse(busy.ok)
        XCTAssertTrue(busy.error?.contains("busy") == true)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
        // Another user is not affected.
        caller.uid = stranger
        XCTAssertTrue(try response(daemon.socketPath, .status).ok)
    }

    /// One daemon per run root.
    func testSecondInstanceIsRefused() throws {
        _ = try makeDaemon()
        var options = Daemon.Options()
        options.runRoot = runRoot
        options.ownExecutable = nil
        XCTAssertThrowsError(try Daemon(options: options)) {
            XCTAssertEqual($0 as? Daemon.Failure, .alreadyRunning(runRoot + "/daemon.lock"))
        }
    }

    /// The daemon refuses to run from a file anyone but root could replace.
    func testOwnExecutableMustBeTrusted() throws {
        var options = Daemon.Options()
        options.runRoot = runRoot
        options.ownExecutable = toolPath  // in /tmp: world-writable, or not root's
        XCTAssertThrowsError(try Daemon(options: options)) { error in
            guard case .untrustedExecutable(let path, _) = error as? Daemon.Failure else { return XCTFail("\(error)") }
            XCTAssertEqual(path, toolPath)
        }
        XCTAssertFalse(exists(runRoot), "refused before anything is set up")
    }

    func testSocketActivation() throws {
        XCTAssertNil(Daemon.activationSocket(environment: [:]))
        XCTAssertNil(Daemon.activationSocket(environment: ["LISTEN_PID": "1", "LISTEN_FDS": "1"]), "another process's")
        XCTAssertNil(Daemon.activationSocket(environment: ["LISTEN_PID": "\(getpid())", "LISTEN_FDS": "0"]))
        // Descriptor 3 must be a listening unix stream socket.
        try FileManager.default.createDirectory(atPath: runRoot, withIntermediateDirectories: true)
        let listener = try Daemon.makeSocket(at: runRoot + "/test.sock")
        defer { close(listener) }
        XCTAssertTrue(Daemon.isListeningUnixStream(listener))
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, Sys.streamType, 0, &pair), 0)
        defer { pair.forEach { close($0) } }
        XCTAssertFalse(Daemon.isListeningUnixStream(pair[0]), "connected, not listening")
        let file = open("/dev/null", O_RDONLY | O_CLOEXEC)
        defer { close(file) }
        XCTAssertFalse(Daemon.isListeningUnixStream(file))
    }

    func testStaleSocketIsReplacedButNothingElse() throws {
        try FileManager.default.createDirectory(atPath: runRoot, withIntermediateDirectories: true)
        let path = runRoot + "/daemon.sock"
        close(try Daemon.makeSocket(at: path))
        let again = try Daemon.makeSocket(at: path)
        close(again)
        unlink(path)
        XCTAssertEqual(symlink("/etc/passwd", path), 0)
        XCTAssertThrowsError(try Daemon.makeSocket(at: path)) { XCTAssertEqual($0 as? Daemon.Failure, .notASocket(path)) }
    }
}

// MARK: - Starting and stopping

final class DaemonSessionTests: DaemonTestCase {
    func testStartStatusStop() throws {
        let daemon = try makeDaemon()
        let started = try response(daemon.socketPath, .startOpenVPN(start()))
        XCTAssertTrue(started.ok, started.error ?? "")
        let pid = try XCTUnwrap(started.pid)
        let runDir = PT.sessionDir(uid: me, profileID: "acme", runRoot: runRoot)
        XCTAssertEqual(started.mgmtSocket, runDir + "/mgmt.sock")
        XCTAssertTrue(exists(runDir + "/config.ovpn"))
        XCTAssertEqual(try String(contentsOfFile: runDir + "/auth", encoding: .utf8), "alice\npw123456\n")
        let state = try String(contentsOfFile: runDir + "/state", encoding: .utf8)
        let identity = try XCTUnwrap(PreviousInstance.bootID()) + "\n\(try XCTUnwrap(PreviousInstance.startTime(of: pid)))\n"
        XCTAssertEqual(state, "\(pid)\n\(me)\n\(toolPath)\n\(profileDir("acme"))\n\(runDir)/mgmt.sock\n" + identity)
        let recorded = try XCTUnwrap(PreviousInstance.readState(runDir + "/state"))
        XCTAssertEqual(recorded.bootID, PreviousInstance.bootID())
        XCTAssertEqual(recorded.startTime, PreviousInstance.startTime(of: pid))

        // OpenVPN 2.6 gets no DNS option at all; the log is the profile's, owned by its user.
        let log = profileDir("acme") + "/vpn.log"
        XCTAssertTrue(eventually { ((try? String(contentsOfFile: log, encoding: .utf8)) ?? "").contains("fake openvpn") })
        let line = try String(contentsOfFile: log, encoding: .utf8)
        XCTAssertTrue(
            line.contains(
                "--config \(runDir)/config.ovpn --verb 3 --management \(runDir)/mgmt.sock unix "
                    + "--management-client-user alice --auth-nocache --remap-usr1 SIGTERM "
                    + "--connect-retry-max 3 --tls-version-min 1.2 --auth-user-pass \(runDir)/auth "
                    + "--script-security 1\n"), line)
        XCTAssertFalse(line.contains("dns-updown"))

        let status = try response(daemon.socketPath, .status)
        XCTAssertEqual(status.running, ["acme": pid])
        XCTAssertEqual(status.mgmtSockets, ["acme": runDir + "/mgmt.sock"])

        // The same profile twice is refused.
        let twice = try response(daemon.socketPath, .startOpenVPN(start()))
        XCTAssertFalse(twice.ok)
        XCTAssertTrue(twice.error?.contains("already running") == true, twice.error ?? "")

        let stopped = try response(daemon.socketPath, .stop(profileID: "acme"))
        XCTAssertTrue(stopped.ok)
        XCTAssertEqual(stopped.pid, pid)
        XCTAssertFalse(exists(runDir), "the session directory goes with the tool")
        XCTAssertEqual(kill(pid, 0), -1, "reaped")
        XCTAssertEqual(try response(daemon.socketPath, .status).running, [:])
        XCTAssertNil(try response(daemon.socketPath, .stop(profileID: "acme")).pid, "stop is idempotent")
    }

    /// Sessions are keyed by (uid, profile ID): another user neither sees nor stops them.
    func testOtherUsersSessionsAreInvisible() throws {
        let daemon = try makeDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startOpenVPN(start())).pid)
        caller.uid = stranger
        XCTAssertEqual(try response(daemon.socketPath, .status).running, [:])
        let stop = try response(daemon.socketPath, .stop(profileID: "acme"))
        XCTAssertTrue(stop.ok)
        XCTAssertNil(stop.pid, "nothing of theirs to stop")
        XCTAssertEqual(kill(pid, 0), 0, "still running")
        caller.uid = me
        XCTAssertEqual(try response(daemon.socketPath, .status).running, ["acme": pid])
        XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, pid)
    }

    func testOutsidersMayNotStart() throws {
        let daemon = try makeDaemon()
        caller.uid = stranger
        let refused = try response(daemon.socketPath, .startOpenVPN(start()))
        XCTAssertFalse(refused.ok)
        XCTAssertTrue(refused.error?.contains("“passtunnel”") == true, refused.error ?? "")
        XCTAssertFalse(exists(runRoot + "/\(stranger)"), "refused before anything was prepared")
        XCTAssertTrue(try response(daemon.socketPath, .status).ok, "status stays allowed")
    }

    /// Cisco AnyConnect is not run by passtunneld before #187: the request is refused, and nothing is
    /// prepared or started for it.
    func testOpenConnectIsNotSupportedYet() throws {
        let daemon = try makeDaemon()
        let request = OpenConnectStart(
            profileID: "acme", profileDir: profileDir("acme"), logPath: profileDir("acme") + "/vpn.log", host: "vpn.example.com",
            connectURL: "https://vpn.example.com/", resolve: "vpn.example.com:192.0.2.10", cookie: "EXAMPLE-COOKIE",
            serverCert: "pin-sha256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk=")
        let refused = try response(daemon.socketPath, .startOpenConnect(request))
        XCTAssertFalse(refused.ok)
        XCTAssertEqual(refused.error, "Cisco AnyConnect is not supported by passtunneld yet.")
        XCTAssertFalse(exists(PT.sessionDir(uid: me, profileID: "acme", runRoot: runRoot)), "nothing prepared")
        XCTAssertFalse(exists(profileDir("acme") + "/vpn.log"), "no log")
        XCTAssertEqual(try response(daemon.socketPath, .status).running, [:])
        // Outsiders get the usual refusal first.
        caller.uid = stranger
        XCTAssertTrue(try response(daemon.socketPath, .startOpenConnect(request)).error?.contains("“passtunnel”") == true)
    }

    /// FortiGate: openfortivpn with the config the daemon wrote (password and code in it, never in the
    /// arguments), the distribution's CA bundle, resolv.conf left to the daemon; then status and stop.
    func testFortiStartStatusStop() throws {
        let daemon = try makeDaemon()
        let started = try response(daemon.socketPath, .startForti(fortiStart(setDNS: true)))
        XCTAssertTrue(started.ok, started.error ?? "")
        let pid = try XCTUnwrap(started.pid)
        XCTAssertNil(started.mgmtSocket)
        let runDir = PT.sessionDir(uid: me, profileID: "acme", runRoot: runRoot)
        let configPath = runDir + "/openfortivpn.conf"
        XCTAssertEqual(
            try String(contentsOfFile: configPath, encoding: .utf8),
            """
            # Generated by PassTunnel. Do not edit.
            host = vpn.example.com
            port = 443
            username = alice
            password = pw-forti
            otp = 123456
            ca-file = \(caPath)
            set-routes = 1
            set-dns = 0
            pppd-use-peerdns = 0

            """)
        var st = stat()
        XCTAssertEqual(lstat(configPath, &st), 0)
        XCTAssertEqual(st.st_mode & 0o777, 0o600)
        XCTAssertEqual(st.st_uid, geteuid())
        let state = try String(contentsOfFile: runDir + "/state", encoding: .utf8)
        XCTAssertEqual(state, "\(pid)\n\(me)\n\(fortiPath)\n\(profileDir("acme"))\n\n" + PreviousInstance.identityLines(of: pid))
        XCTAssertFalse(PreviousInstance.identityLines(of: pid).hasPrefix("\n"))

        let log = profileDir("acme") + "/vpn.log"
        XCTAssertTrue(eventually { ((try? String(contentsOfFile: log, encoding: .utf8)) ?? "").contains("fake openfortivpn") })
        let text = try String(contentsOfFile: log, encoding: .utf8)
        XCTAssertEqual(text, "fake openfortivpn -c \(configPath)\n")
        XCTAssertFalse(try String(contentsOfFile: "/proc/\(pid)/environ", encoding: .utf8).contains("pw-forti"))
        XCTAssertEqual(lstat(log, &st), 0)
        XCTAssertEqual(st.st_uid, me)
        XCTAssertEqual(st.st_mode & 0o777, 0o600)

        let status = try response(daemon.socketPath, .status)
        XCTAssertEqual(status.running, ["acme": pid])
        XCTAssertEqual(status.mgmtSockets, [:])
        XCTAssertFalse(try response(daemon.socketPath, .startForti(fortiStart())).ok, "already running")
        XCTAssertFalse(try response(daemon.socketPath, .startOpenVPN(start())).ok, "the same profile, either type")

        let stopped = try response(daemon.socketPath, .stop(profileID: "acme"))
        XCTAssertEqual(stopped.pid, pid)
        XCTAssertFalse(exists(runDir), "config, password and code go with the tool")
        XCTAssertEqual(kill(pid, 0), -1, "reaped")
    }

    /// openfortivpn, the pppd it runs and the CA bundle are checked before every start; nothing is
    /// prepared when one fails.
    func testFortiToolChecks() throws {
        let daemon = try makeDaemon()
        func refusal() throws -> String {
            let reply = try response(daemon.socketPath, .startForti(fortiStart()))
            XCTAssertFalse(reply.ok)
            XCTAssertFalse(exists(runRoot + "/\(me)/acme"))
            return reply.error ?? ""
        }
        try makeForti(version: "1.20.5")
        XCTAssertEqual(try refusal(), "openfortivpn 1.20.5 is too old: PassTunnel needs 1.21.0 or later. Update the openfortivpn package.")
        try makeForti(version: "1.21.0")
        try makePPPD(version: "2.4.5")
        XCTAssertEqual(try refusal(), "pppd 2.4.5 is too old: PassTunnel needs 2.4.7 or later. Update the ppp package.")
        try FileManager.default.removeItem(atPath: pppdPath)
        XCTAssertEqual(
            try refusal(),
            "pppd is not installed (none of \(pppdPath) exists). "
                + "Install the distribution's ppp package, version 2.4 or later.")
        try makePPPD(version: "2.5.1")
        chmod(caPath, 0o666)
        XCTAssertTrue(try refusal().hasPrefix("Refusing to use the CA bundle \(caPath): "))
        try FileManager.default.removeItem(atPath: caPath)
        XCTAssertEqual(
            try refusal(),
            "No CA bundle to verify the gateway with (none of \(base)/certs/none.crt, \(caPath) exists). "
                + "Install the distribution's ca-certificates package.")
    }

    /// The typed fields are checked (`FortiConfig`) before anything is written.
    func testFortiFieldsAreChecked() throws {
        let daemon = try makeDaemon()
        var s = fortiStart()
        s.host = "vpn.example.com\npppd-plugin = /tmp/x.so"
        let reply = try response(daemon.socketPath, .startForti(s))
        XCTAssertFalse(reply.ok)
        XCTAssertEqual(reply.error, "Invalid gateway host name.")
        XCTAssertFalse(exists(runRoot + "/\(me)/acme"))
        s = fortiStart()
        s.profileDir = base + "/elsewhere"
        XCTAssertTrue(try response(daemon.socketPath, .startForti(s)).error?.contains("not inside the PassTunnel profiles folder") == true)
        caller.uid = stranger
        XCTAssertTrue(try response(daemon.socketPath, .startForti(fortiStart())).error?.contains("“passtunnel”") == true)
    }

    /// A FortiGate session that ends by itself (a refused login, a lost gateway) takes its files with it.
    func testFortiExitCleansUp() throws {
        try makeScript(
            fortiPath,
            """
            #!/bin/sh
            if [ "$1" = "--version" ]; then echo "1.22.1"; exit 0; fi
            echo "ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc."
            exit 1

            """)
        let daemon = try makeDaemon()
        XCTAssertTrue(try response(daemon.socketPath, .startForti(fortiStart())).ok)
        XCTAssertTrue(eventually { !self.exists(self.runRoot + "/\(self.me)/acme") })
        XCTAssertEqual(try response(daemon.socketPath, .status).running, [:])
        XCTAssertTrue(try String(contentsOfFile: profileDir("acme") + "/vpn.log", encoding: .utf8).contains("Could not authenticate"))
    }

    func testOpenVPN27DisablesTheDNSHook() throws {
        try makeTool(version: "2.7.0")
        let daemon = try makeDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startOpenVPN(start())).pid)
        let log = profileDir("acme") + "/vpn.log"
        XCTAssertTrue(eventually { ((try? String(contentsOfFile: log, encoding: .utf8)) ?? "").contains("fake openvpn") })
        XCTAssertTrue(try String(contentsOfFile: log, encoding: .utf8).contains("--script-security 1 --dns-updown disable\n"))
        XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, pid)
    }

    func testToolProblemsAreReported() throws {
        try makeTool(version: "2.5.11")
        let daemon = try makeDaemon()
        let reply = try response(daemon.socketPath, .startOpenVPN(start()))
        XCTAssertFalse(reply.ok)
        XCTAssertEqual(reply.error, "OpenVPN 2.5.11 is too old: PassTunnel needs 2.6.0 or later. Update the openvpn package.")
        XCTAssertFalse(exists(runRoot + "/\(me)/acme"))
    }

    func testChangedConfigIsRefused() throws {
        let daemon = try makeDaemon()
        let reply = try response(daemon.socketPath, .startOpenVPN(start(sha: String(repeating: "0", count: 64))))
        XCTAssertFalse(reply.ok)
        XCTAssertEqual(reply.errorCode, HelperResponse.ErrorCode.configChanged)
    }

    func testProfileOutsideTheHomeIsRefused() throws {
        let daemon = try makeDaemon()
        let elsewhere = base + "/elsewhere/acme"
        try FileManager.default.createDirectory(atPath: elsewhere, withIntermediateDirectories: true)
        try Self.config.write(toFile: elsewhere + "/config.ovpn", atomically: true, encoding: .utf8)
        var s = start()
        s.profileDir = elsewhere
        s.logPath = elsewhere + "/vpn.log"
        let reply = try response(daemon.socketPath, .startOpenVPN(s))
        XCTAssertFalse(reply.ok)
        XCTAssertTrue(reply.error?.contains("not inside the PassTunnel profiles folder") == true, reply.error ?? "")
    }

    /// A tool that exits by itself takes its session directory with it.
    func testExitCleansUp() throws {
        try FileManager.default.removeItem(atPath: toolPath)
        try """
        #!/bin/sh
        if [ "$1" = "--version" ]; then echo "OpenVPN 2.6.9 x86_64-pc-linux-gnu"; exit 1; fi
        exit 0

        """.write(toFile: toolPath, atomically: true, encoding: .utf8)
        chmod(toolPath, 0o755)
        let daemon = try makeDaemon()
        XCTAssertTrue(try response(daemon.socketPath, .startOpenVPN(start())).ok)
        XCTAssertTrue(eventually { !self.exists(self.runRoot + "/\(self.me)/acme") })
        XCTAssertEqual(try response(daemon.socketPath, .status).running, [:])
    }

    /// Shutting down stops every tool and cleans up.
    /// A profile whose device name the kernel has already is refused before anything is prepared: OpenVPN
    /// would attach to that device, and a persistent one stays open to its owner. `dev tun` and `dev tap`
    /// get a name the kernel picks, and a free name starts.
    func testExistingDeviceIsRefused() throws {
        let daemon = try makeDaemon { $0.interfaces.exists = { $0 != "tun6" } }
        func start(dev: String) throws -> HelperResponse {
            let text = "client\nremote vpn.example.com 1194\nauth-user-pass\ndev \(dev)\n"
            try text.write(toFile: profileDir("acme") + "/config.ovpn", atomically: true, encoding: .utf8)
            return try response(daemon.socketPath, .startOpenVPN(self.start(sha: HelperCore.sha256Hex(Data(text.utf8)))))
        }
        let refused = try start(dev: "tun5")
        XCTAssertFalse(refused.ok)
        XCTAssertEqual(refused.error, HelperCore.Failure.deviceExists("tun5").description)
        XCTAssertFalse(exists(runRoot + "/\(me)/acme"), "nothing prepared for a refused start")
        for dev in ["tun", "tap", "tun6"] {
            let started = try start(dev: dev)
            XCTAssertTrue(started.ok, "\(dev): \(started.error ?? "")")
            XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, started.pid, dev)
        }
    }

    /// The kernel's answer, as the daemon asks for it.
    func testKernelInterfaces() throws {
        XCTAssertTrue(try InterfaceSystem.kernelHas("lo"))
        XCTAssertFalse(try InterfaceSystem.kernelHas("ptnone\(getpid() % 10000)"))
    }

    func testShutdownStopsEverything() throws {
        let daemon = try makeDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startOpenVPN(start())).pid)
        daemon.shutdown()
        XCTAssertEqual(kill(pid, 0), -1)
        XCTAssertFalse(exists(runRoot + "/\(me)/acme"))
    }

    /// The management socket goes to the session's user with mode 0600, the mode set first.
    func testManagementSocketHandOff() throws {
        let owner: uid_t = me == 0 ? 65534 : me
        let core = HelperCore(runRoot: runRoot, homeDirectory: users.home, userName: users.name)
        let session = try core.makeRunDir(profileID: "acme", uid: owner)
        let socketPath = session.path + "/" + PT.mgmtSocketName
        close(try Daemon.makeSocket(at: socketPath))
        XCTAssertTrue(session.restrictSocket(PT.mgmtSocketName))
        var st = stat()
        XCTAssertEqual(lstat(socketPath, &st), 0)
        XCTAssertEqual(st.st_uid, owner)
        XCTAssertEqual(st.st_mode & 0o777, 0o600)
        XCTAssertTrue(session.restrictSocket(PT.mgmtSocketName), "again: nothing to change")
        unlink(socketPath)
        XCTAssertEqual(symlink("/etc/passwd", socketPath), 0)
        XCTAssertFalse(session.restrictSocket(PT.mgmtSocketName), "never through a link")
    }
}

// MARK: - The profile checks on Linux

final class LinuxProfileCheckTests: DaemonTestCase {
    var core: HelperCore { HelperCore(runRoot: runRoot, homeDirectory: users.home, userName: users.name) }

    func assertFails(
        _ expr: @autoclosure () throws -> Any, _ check: (HelperCore.Failure) -> Bool,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        do {
            _ = try expr()
            XCTFail("expected a failure", file: file, line: line)
        } catch let f as HelperCore.Failure {
            XCTAssertTrue(check(f), "unexpected \(f)", file: file, line: line)
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
        }
    }

    func testProfileDirectory() throws {
        XCTAssertEqual(PT.profilesSubpath, ".local/share/passtunnel/profiles")
        let dir = try core.openProfileDir(profileDir("acme"), profileID: "acme", uid: me)
        XCTAssertEqual(dir.path, home + "/.local/share/passtunnel/profiles/acme")
        XCTAssertEqual(HelperCore.path(of: dir.fd), dir.path, "/proc/self/fd")
    }

    func testProfileDirectoryChecks() throws {
        assertFails(try core.openProfileDir(profileDir("acme"), profileID: "other", uid: me)) { $0 == .wrongDirectoryName(profileDir("acme")) }
        assertFails(try core.openProfileDir(profileDir("acme"), profileID: "acme", uid: 99999)) { $0 == .unknownUser(99999) }
        // Through a symlink that leaves the profiles folder.
        try FileManager.default.createDirectory(atPath: base + "/other/acme", withIntermediateDirectories: true)
        XCTAssertEqual(symlink(base + "/other/acme", profileDir("evil")), 0)
        assertFails(try core.openProfileDir(profileDir("evil"), profileID: "acme", uid: me)) { $0 == .outsideProfilesRoot(profileDir("evil")) }
        chmod(profileDir("acme"), 0o775)
        assertFails(try core.openProfileDir(profileDir("acme"), profileID: "acme", uid: me)) { $0 == .insecurePermissions(profileDir("acme")) }
        chmod(profileDir("acme"), 0o755)
        assertFails(try core.openProfileDir(profileDir("acme"), profileID: "acme", uid: stranger)) {
            if case .wrongOwner = $0 { return true }
            return false
        }
    }

    func testConfigChecks() throws {
        let config = profileDir("acme") + "/config.ovpn"
        XCTAssertEqual(link(config, base + "/hardlink"), 0)
        assertFails(try core.prepareOpenVPN(start(), uid: me)) { $0 == .multipleLinks(config) }
        unlink(base + "/hardlink")
        chmod(config, 0o666)
        assertFails(try core.prepareOpenVPN(start(), uid: me)) { $0 == .insecurePermissions(config) }
        chmod(config, 0o644)
        assertFails(try core.prepareOpenVPN(start(sha: String(repeating: "a", count: 64)), uid: me)) { $0 == .configChanged }
        XCTAssertFalse(exists(runRoot + "/\(me)/acme"), "nothing prepared for a refused start")
    }

    func testArguments() throws {
        var core = self.core
        core.openVPNHasDNSUpdown = false
        let plan = try core.prepareOpenVPN(start(), uid: me)
        defer { close(plan.logFD); core.removeRunDir(profileID: "acme", uid: me) }
        XCTAssertEqual(Array(plan.arguments.suffix(2)), ["--script-security", "1"])
        XCTAssertFalse(plan.arguments.contains("--dns-updown"))
        // The Mac's flags: a pushed `verb` is ignored, a server that does not answer is given up on after 10 s.
        let filters = HelperCore.ignoredPushPrefixes.flatMap { ["--pull-filter", "ignore", $0] }
        XCTAssertEqual(Array(plan.arguments.prefix(filters.count + 3)), filters + ["--server-poll-timeout", "10", "--config"])
        core.openVPNHasDNSUpdown = true
        XCTAssertEqual(
            HelperCore.openVPNArguments(
                configPath: "/c", mgmtSocket: "/m", clientUser: "alice", authFile: nil,
                dnsUpdown: nil
            ).suffix(4),
            ["--script-security", "1", "--dns-updown", "disable"], "the Mac's default is unchanged")
    }
}

// MARK: - The previous instance

final class PreviousInstanceTests: DaemonTestCase {
    /// `sleep 30` in a process group of its own, as the daemon starts its tools; killed when the test ends
    /// unless the test reaped it (then its pid may be another process's).
    func sleeper() throws -> pid_t {
        let devNull = open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { close(devNull) }
        let pid = try Sys.spawn(
            executable: "/bin/sleep", arguments: ["30"], environment: HelperCore.fixedEnvironment,
            workingDirectory: "/", outputFD: devNull)
        addTeardownBlock {
            var info = siginfo_t()
            guard waitid(P_PID, id_t(pid), &info, WEXITED | WNOHANG | WNOWAIT) == 0 else { return }  // reaped already
            kill(pid, SIGKILL)
            var status: Int32 = 0
            waitpid(pid, &status, 0)
        }
        return pid
    }

    /// A state file in `<runRoot>/<me>/<id>`: the five lines of the earlier format, then `identity`.
    func record(_ id: String, pid: pid_t, executable: String, identity: String) throws {
        try FileManager.default.createDirectory(atPath: runRoot + "/\(me)/\(id)", withIntermediateDirectories: true)
        try ("\(pid)\n\(me)\n\(executable)\n/home/alice/x\n\n" + identity)
            .write(toFile: runRoot + "/\(me)/\(id)/state", atomically: true, encoding: .utf8)
    }

    func testStopsRecordedToolsAndCleansUp() throws {
        try FileManager.default.createDirectory(atPath: runRoot + "/junk", withIntermediateDirectories: true)
        try "x".write(toFile: runRoot + "/file", atomically: true, encoding: .utf8)
        try "keep".write(toFile: runRoot + "/daemon.sock", atomically: true, encoding: .utf8)

        let pid = try sleeper(), other = try sleeper()
        let exe = try XCTUnwrap(PreviousInstance.executable(of: pid))
        let boot = try XCTUnwrap(PreviousInstance.bootID())
        let otherStart = try XCTUnwrap(PreviousInstance.startTime(of: other))
        try record("acme", pid: pid, executable: exe, identity: PreviousInstance.identityLines(of: pid))
        try record("gone", pid: 999999, executable: exe, identity: "\(boot)\n1\n")
        // A live pid is not touched unless it is provably the recorded process: something else runs
        // under it, it started at another time or in another boot, or the state cannot tell (written
        // by an earlier build, without boot ID and start time).
        try record("recycled", pid: other, executable: "/usr/sbin/openvpn", identity: "\(boot)\n\(otherStart)\n")
        try record("restarted", pid: other, executable: exe, identity: "\(boot)\n\(otherStart + 1)\n")
        try record("rebooted", pid: other, executable: exe, identity: "00000000-0000-4000-8000-000000000000\n\(otherStart)\n")
        try record("unverifiable", pid: other, executable: exe, identity: "")

        let stopped = PreviousInstance.cleanUp(runRoot: runRoot, keep: ["daemon.sock"], grace: 3)
        XCTAssertEqual(stopped, .init(signalled: [pid]))
        var status: Int32 = 0
        XCTAssertEqual(waitpid(pid, &status, 0), pid)
        XCTAssertEqual(status & 0x7F, SIGTERM, "stopped with SIGTERM")
        XCTAssertEqual(kill(other, 0), 0)
        XCTAssertEqual(PreviousInstance.processState(other).map { "RS".contains($0) }, true, "not signalled")
        XCTAssertEqual(PreviousInstance.entries(runRoot), ["daemon.sock"])
    }

    func testIdentify() throws {
        let pid = try sleeper()
        let exe = try XCTUnwrap(PreviousInstance.executable(of: pid))
        let boot = try XCTUnwrap(PreviousInstance.bootID())
        let start = try XCTUnwrap(PreviousInstance.startTime(of: pid))
        let same = PreviousInstance.State(pid: pid, uid: me, executable: exe, bootID: boot, startTime: start)
        XCTAssertEqual(PreviousInstance.identify(same), .same)
        XCTAssertTrue(PreviousInstance.isAlive(same))
        XCTAssertEqual(PreviousInstance.identify(.init(pid: pid, uid: me, executable: exe, bootID: boot, startTime: start + 1)), .gone)
        XCTAssertEqual(
            PreviousInstance.identify(
                .init(
                    pid: pid, uid: me, executable: exe,
                    bootID: "00000000-0000-4000-8000-000000000000", startTime: start)), .gone)
        XCTAssertEqual(
            PreviousInstance.identify(
                .init(
                    pid: pid, uid: me, executable: "/usr/sbin/openvpn", bootID: boot,
                    startTime: start)), .gone)
        XCTAssertEqual(PreviousInstance.identify(.init(pid: pid, uid: me, executable: exe)), .unverifiable)
        XCTAssertFalse(PreviousInstance.isAlive(.init(pid: pid, uid: me, executable: exe)))
        XCTAssertEqual(PreviousInstance.identify(.init(pid: 999999, uid: me, executable: exe, bootID: boot, startTime: start)), .gone)
        // A process started later has a later start time; our own started before it.
        XCTAssertLessThanOrEqual(try XCTUnwrap(PreviousInstance.startTime(of: getpid())), start)
    }

    /// Every signal is preceded by the check: a state that is not the process is never signalled.
    func testDeliverChecksFirst() throws {
        let pid = try sleeper()
        let exe = try XCTUnwrap(PreviousInstance.executable(of: pid))
        let boot = try XCTUnwrap(PreviousInstance.bootID())
        let start = try XCTUnwrap(PreviousInstance.startTime(of: pid))
        XCTAssertFalse(
            PreviousInstance.deliver(
                SIGKILL,
                to: .init(
                    pid: pid, uid: me, executable: exe, bootID: boot,
                    startTime: start + 1)))
        XCTAssertFalse(PreviousInstance.deliver(SIGKILL, to: .init(pid: pid, uid: me, executable: exe)))
        XCTAssertEqual(kill(pid, 0), 0, "still running")
        XCTAssertTrue(PreviousInstance.deliver(SIGTERM, to: .init(pid: pid, uid: me, executable: exe, bootID: boot, startTime: start)))
        var status: Int32 = 0
        XCTAssertEqual(waitpid(pid, &status, 0), pid)
        XCTAssertEqual(status & 0x7F, SIGTERM)
    }

    /// The pidfd calls themselves: a pidfd of a running child, a signal through it, then `ESRCH` for a
    /// process that is gone (the kernel of the CI runners has pidfds).
    func testPidfdCalls() throws {
        let pid = try sleeper()
        let pidfd = try XCTUnwrap(Sys.pidfdOpen(pid))
        defer { close(pidfd) }
        XCTAssertEqual(Sys.pid(ofPidfd: pidfd), pid)
        XCTAssertEqual(Sys.pidfdSignal(pidfd, SIGTERM, processGroup: false), 0)
        var status: Int32 = 0
        XCTAssertEqual(waitpid(pid, &status, 0), pid)
        XCTAssertEqual(status & 0x7F, SIGTERM)
        XCTAssertEqual(Sys.pidfdSignal(pidfd, SIGTERM, processGroup: false), ESRCH)
        XCTAssertNil(Sys.pidfdOpen(999999))
    }

    /// Without pidfds nothing is signalled at all, not even a verified process: by number the signal
    /// could reach another process that took the pid over. The DNS is still reverted and the run root
    /// cleaned up; the tool is left running.
    func testNoPidfdsNoSignals() throws {
        let pid = try sleeper()
        let exe = try XCTUnwrap(PreviousInstance.executable(of: pid))
        try record("acme", pid: pid, executable: exe, identity: PreviousInstance.identityLines(of: pid))
        var none = PreviousInstance.Pidfds()
        none.open = { _ in nil }
        let state = try XCTUnwrap(PreviousInstance.readState(runRoot + "/\(me)/acme/state"))
        XCTAssertEqual(PreviousInstance.identify(state), .same)
        XCTAssertFalse(PreviousInstance.deliver(SIGKILL, to: state, pidfds: none))
        XCTAssertEqual(PreviousInstance.cleanUp(runRoot: runRoot, keep: [], grace: 0.5, pidfds: none), .init())
        XCTAssertEqual(PreviousInstance.processState(pid).map { "RS".contains($0) }, true, "left running")
        XCTAssertEqual(PreviousInstance.entries(runRoot), [])
    }

    func testDaemonCleansUpWhenItStarts() throws {
        try FileManager.default.createDirectory(atPath: runRoot + "/\(me)/acme", withIntermediateDirectories: true)
        _ = try makeDaemon()
        XCTAssertFalse(exists(runRoot + "/\(me)"))
        XCTAssertTrue(exists(runRoot + "/daemon.sock"))
    }

    func testReadState() throws {
        try FileManager.default.createDirectory(atPath: runRoot, withIntermediateDirectories: true)
        let path = runRoot + "/state"
        try "42\n1000\n/usr/sbin/openvpn\n/home/alice/x\n/run/m\n".write(toFile: path, atomically: true, encoding: .utf8)
        XCTAssertEqual(PreviousInstance.readState(path), .init(pid: 42, uid: 1000, executable: "/usr/sbin/openvpn"))
        let boot = "6a1b2c3d-0000-4e5f-8a9b-0123456789ab"
        try "42\n1000\n/usr/sbin/openvpn\n/home/alice/x\n/run/m\n\(boot)\n12345\n".write(toFile: path, atomically: true, encoding: .utf8)
        XCTAssertEqual(
            PreviousInstance.readState(path),
            .init(
                pid: 42, uid: 1000, executable: "/usr/sbin/openvpn",
                bootID: boot, startTime: 12345))
        try "42\n1000\n/usr/sbin/openvpn\n/home/alice/x\n/run/m\n\n\n".write(toFile: path, atomically: true, encoding: .utf8)
        XCTAssertEqual(
            PreviousInstance.readState(path), .init(pid: 42, uid: 1000, executable: "/usr/sbin/openvpn"),
            "none could be read when it was written")
        for bad in [
            "1\n1000\n/usr/sbin/openvpn\n", "x\n1000\n/a\n", "42\n\n/a\n", "42\n1000\nrelative\n", "42\n",
            "42\n1000\n/a\n/h\n\n\(boot)\n\n", "42\n1000\n/a\n/h\n\n\n12345\n", "42\n1000\n/a\n/h\n\n\(boot)\n012\n",
            "42\n1000\n/a\n/h\n\n\(boot.uppercased())\n12\n", "42\n1000\n/a\n/h\n\nboot\n12\n", "42\n1000\n/a\n/h\n\n\(boot)\n-1\n"
        ] {
            try bad.write(toFile: path, atomically: true, encoding: .utf8)
            XCTAssertNil(PreviousInstance.readState(path), bad)
        }
        let own = try XCTUnwrap(PreviousInstance.processState(getpid()))
        XCTAssertTrue("RS".contains(own), "\(own)")
        XCTAssertNil(PreviousInstance.processState(999999))
        XCTAssertNil(PreviousInstance.startTime(of: 999999))
        XCTAssertTrue(PreviousInstance.isBootID(try XCTUnwrap(PreviousInstance.bootID())))
        XCTAssertNil(PreviousInstance.bootID(path: base + "/none"))
    }
}

// MARK: - The client

final class UnixSocketClientTests: DaemonTestCase {
    func testHelloAndCompatibility() async throws {
        let daemon = try makeDaemon()
        let client = UnixSocketHelperClient(socketPath: daemon.socketPath, timeout: 5, expectedBuild: "test-build")
        XCTAssertTrue(client.isInstalled)
        let hello = try await client.hello()
        XCTAssertEqual(hello, DaemonHello(build: "test-build"))
        try await client.ensureCompatible()
        let outdated = try await client.isOutdated()
        XCTAssertFalse(outdated)
        let other = UnixSocketHelperClient(socketPath: daemon.socketPath, timeout: 5, expectedBuild: "another-build")
        do {
            try await other.ensureCompatible()
            XCTFail("expected a build mismatch")
        } catch {
            XCTAssertEqual(error as? HelperClientError, .buildMismatch)
            XCTAssertEqual(AutomationErrorCode.of(error), .helperOutdated)
            XCTAssertTrue(error.localizedDescription.contains("systemctl restart passtunnel"), error.localizedDescription)
        }
        let unchecked = UnixSocketHelperClient(socketPath: daemon.socketPath, timeout: 5, expectedBuild: nil)
        try await unchecked.ensureCompatible()
    }

    func testPerform() async throws {
        let daemon = try makeDaemon()
        let client = UnixSocketHelperClient(socketPath: daemon.socketPath, timeout: 5, expectedBuild: nil)
        let status = try await client.perform(.status, timeout: nil)
        XCTAssertEqual(status.running, [:])
        let started = try await client.perform(.startOpenVPN(start()), timeout: nil)
        XCTAssertTrue(started.ok, started.error ?? "")
        let pid = try XCTUnwrap(started.pid)
        let running = try await client.perform(.status, timeout: nil)
        XCTAssertEqual(running.running, ["acme": pid])
        let stopped = try await client.perform(.stop(profileID: "acme"), timeout: 10)
        XCTAssertEqual(stopped.pid, pid)
        caller.uid = stranger
        let refused = try await client.perform(.startOpenVPN(start()), timeout: nil)
        XCTAssertFalse(refused.ok, "a refusal is a reply, not a transport error")
    }

    /// A server that answers with something else, nothing at all, or not in time.
    func testTransportErrors() async throws {
        try FileManager.default.createDirectory(atPath: runRoot, withIntermediateDirectories: true)
        let path = runRoot + "/fake.sock"
        let listener = try Daemon.makeSocket(at: path)
        defer { close(listener) }
        let client = UnixSocketHelperClient(socketPath: path, timeout: 0.5, expectedBuild: nil)

        // Accepted, never answered.
        let start = Date()
        do {
            _ = try await client.hello()
            XCTFail("expected a timeout")
        } catch {
            XCTAssertEqual(error as? HelperClientError, .timeout(0.5))
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 3)

        // Read the request, answer `reply`, hang up.
        for (index, (reply, expected)) in [
            ("not json\n", HelperClientError.badResponse),
            ("", HelperClientError.unavailable(String(cString: strerror(ECONNRESET))))
        ].enumerated() {
            let serverPath = runRoot + "/fake\(index).sock"
            let server = try Daemon.makeSocket(at: serverPath)
            let thread = Thread {
                defer { close(server) }
                let fd = accept(server, nil, nil)
                guard fd >= 0 else { return }
                _ = LineIO.readLine(fd, limit: 1 << 16, deadline: Date().addingTimeInterval(5))
                _ = reply.withCString { Sys.send(fd, $0, strlen($0)) }
                close(fd)
            }
            thread.start()
            do {
                _ = try await UnixSocketHelperClient(socketPath: serverPath, timeout: 5, expectedBuild: nil).perform(.status, timeout: nil)
                XCTFail("expected \(expected)")
            } catch {
                XCTAssertEqual(error as? HelperClientError, expected)
            }
        }

        // A socket nobody listens on any more.
        let stale = runRoot + "/stale.sock"
        close(try Daemon.makeSocket(at: stale))
        do {
            _ = try await UnixSocketHelperClient(socketPath: stale, timeout: 1, expectedBuild: nil).hello()
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(error as? HelperClientError, .unavailable(String(cString: strerror(ECONNREFUSED))))
            XCTAssertEqual(AutomationErrorCode.of(error), .helperUnavailable)
            XCTAssertTrue(error.localizedDescription.contains("passtunneld"), error.localizedDescription)
        }
    }

    func testInspector() async throws {
        let missing = await SystemHelperInspector(socketPath: runRoot + "/none.sock", expectedBuild: nil).report()
        XCTAssertEqual(missing, HelperReport(state: "not_installed", responding: false))

        let daemon = try makeDaemon()
        let current = await SystemHelperInspector(socketPath: daemon.socketPath, expectedBuild: "test-build").report()
        XCTAssertEqual(current, HelperReport(state: "enabled", responding: true, protocolVersion: 4, outdated: false))
        XCTAssertTrue(current.isUsable)
        let outdated = await SystemHelperInspector(socketPath: daemon.socketPath, expectedBuild: "older").report()
        XCTAssertEqual(outdated.outdated, true)
        XCTAssertFalse(outdated.isUsable)

        let silentPath = runRoot + "/silent.sock"
        let silent = try Daemon.makeSocket(at: silentPath)
        defer { close(silent) }
        let quiet = await SystemHelperInspector(socketPath: silentPath, timeout: 0.5, expectedBuild: nil).report()
        XCTAssertEqual(quiet.state, "enabled")
        XCTAssertFalse(quiet.responding)
        XCTAssertNotNil(quiet.error)
    }

    func testInstalledDaemonPath() throws {
        let prefix = base + "/usr"
        try FileManager.default.createDirectory(atPath: prefix + "/bin", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: prefix + "/sbin", withIntermediateDirectories: true)
        try "cli".write(toFile: prefix + "/bin/passtunnel", atomically: true, encoding: .utf8)
        XCTAssertNil(HelperBuild.installedDaemonPath(nextTo: prefix + "/bin/passtunnel"))
        try "dev".write(toFile: prefix + "/bin/passtunneld", atomically: true, encoding: .utf8)
        XCTAssertEqual(HelperBuild.installedDaemonPath(nextTo: prefix + "/bin/passtunnel"), prefix + "/bin/passtunneld")
        try "daemon".write(toFile: prefix + "/sbin/passtunneld", atomically: true, encoding: .utf8)
        XCTAssertEqual(HelperBuild.installedDaemonPath(nextTo: prefix + "/bin/passtunnel"), prefix + "/sbin/passtunneld")
        // Through a symlink to the command (/usr/local/bin/passtunnel → the tarball's copy).
        XCTAssertEqual(symlink(prefix + "/bin/passtunnel", base + "/passtunnel-link"), 0)
        XCTAssertEqual(HelperBuild.installedDaemonPath(nextTo: base + "/passtunnel-link"), prefix + "/sbin/passtunneld")
    }
}
