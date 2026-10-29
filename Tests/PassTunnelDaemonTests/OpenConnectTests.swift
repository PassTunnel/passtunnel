import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelDaemon
@testable import PassTunnelShared

/// A fake Linux for the daemon's openconnect sessions (`OpenConnectSystem`): it records every command and every
/// DNS change and applies them to an in-memory routing table. Nothing here touches the real network.
final class FakeLinuxSystem: OpenConnectSystem, @unchecked Sendable {
    private let lock = NSLock()
    private var _log: [String] = []
    var table: [KernelRoute] = [KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("198.51.100.1"), interface: "eth0")]
    var failing: (OpenConnectCommand) -> Bool = { _ in false }
    var tools: OpenConnectCommand.Tools { .linux(ip: "/usr/sbin/ip") }

    var log: [String] {
        lock.lock()
        defer { lock.unlock() }
        return _log
    }

    private func append(_ line: String) {
        lock.lock()
        _log.append(line)
        lock.unlock()
    }

    func interfaceIndex(_ name: String) -> UInt32? { name == "eth0" ? 2 : nil }
    func interfaceLink(_ name: String) -> (mtu: Int, up: Bool)? { nil }
    func interfaceAddresses(_ name: String) -> [IPAddress] { [] }
    func attachedNetworks() -> [OpenConnectPlan.Attached] { [] }
    func routes() -> [KernelRoute]? {
        lock.lock()
        defer { lock.unlock() }
        return table
    }

    func run(_ command: OpenConnectCommand, timeout: TimeInterval) -> OpenConnectCommand.Result {
        append(command.line)
        if failing(command) { return .init(status: 2, output: "RTNETLINK answers: Operation not permitted") }
        lock.lock()
        defer { lock.unlock() }
        switch command.effect {
        case .addRoute(let route): table.append(KernelRoute(route))
        case .deleteRoute(let route): table.removeAll { $0.is(route) }
        default: break
        }
        return .init(status: 0)
    }

    func setDNS(_ settings: OpenConnectDNSSettings) -> Bool { append("dns set " + settings.service); return true }
    func hasDNS(_ settings: OpenConnectDNSSettings) -> Bool { true }
    func removeDNS(service: String) -> Bool { append("dns remove " + service); return true }
}

/// Cisco AnyConnect in passtunneld (#187): the start request checked and refused as on the Mac, the root
/// configuration and the hook's link and policy, openconnect run with the fixed environment and its output
/// masked, supervised (the record's status, the deadlines), stopped, and what its hook recorded reverted after a
/// kill, also by the next daemon. The "openconnect" is a script that sleeps; the system is a fake.
final class OpenConnectDaemonTests: DaemonTestCase {
    static let pin = "pin-sha256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk="
    /// The cookie under its name, as the client sends it (`OpenConnectCookie`); `value` is what a server could make
    /// openconnect print alone.
    static let value = "4C1D2A@1048576@A3F1@9C8B7A6F5E4D3C2B1A0F9E8D7C6B5A4F3E2D1C0B"
    static let cookie = "webvpn=" + value
    var hookTarget: String { base + "/sbin/passtunneld" }
    var runDir: String { PT.sessionDir(uid: me, profileID: "acme", runRoot: runRoot) }
    let system = FakeLinuxSystem()

    func request(
        _ id: String = "acme", host: String = "vpn.example.com", connectURL: String = "https://vpn.example.com/",
        resolve: String? = "vpn.example.com:192.0.2.10", cookie: String = cookie, serverCert: String = pin, profileServerCert: String = "",
        usergroup: String = "", tlsOnly: Bool = false
    ) -> OpenConnectStart {
        let dir = profileDir(id)
        return OpenConnectStart(
            profileID: id, profileDir: dir, logPath: dir + "/vpn.log", host: host, usergroup: usergroup, connectURL: connectURL,
            resolve: resolve, cookie: cookie, serverCert: serverCert, profileServerCert: profileServerCert, tlsOnly: tlsOnly,
            setDNS: true, setRoutes: true)
    }

    func makeOpenConnectDaemon(_ configure: (inout Daemon.Options) -> Void = { _ in }) throws -> Daemon {
        let system = self.system, target = hookTarget
        return try makeDaemon { options in
            options.dnsHook = target
            options.openConnectSystem = { _, _ in system }
            options.openConnectTiming = OpenConnectTiming(checkInterval: 0.1, setupDeadline: 60, reconnectDeadline: 120)
            configure(&options)
        }
    }

    func log(_ id: String = "acme") -> String {
        (try? String(contentsOfFile: profileDir(id) + "/vpn.log", encoding: .utf8)) ?? ""
    }

    // MARK: - Start, status, stop

    func testStartStatusStop() throws {
        let daemon = try makeOpenConnectDaemon()
        let started = try response(daemon.socketPath, .startOpenConnect(request(tlsOnly: true)))
        XCTAssertTrue(started.ok, started.error ?? "")
        let pid = try XCTUnwrap(started.pid)
        XCTAssertNil(started.mgmtSocket)

        // The root configuration: the cookie only in it (0600), `script` the session's link to the daemon.
        let configPath = runDir + "/openconnect.conf"
        XCTAssertEqual(
            try String(contentsOfFile: configPath, encoding: .utf8),
            """
            # Generated by PassTunnel. Do not edit.
            protocol anyconnect
            server https://vpn.example.com/
            cookie \(Self.cookie)
            servercert \(Self.pin)
            resolve vpn.example.com:192.0.2.10
            script \(runDir)/vpn-hook
            non-inter
            reconnect-timeout 60
            no-dtls

            """)
        let attributes = try FileManager.default.attributesOfItem(atPath: configPath)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: runDir + "/vpn-hook"), hookTarget)
        XCTAssertEqual(
            try String(contentsOfFile: runDir + "/policy", encoding: .utf8), "uid=\(me)\nprofile=acme\nset_routes=1\nset_dns=1\n")
        // What the hook proves its session with: pid, uid, executable, boot and start time.
        let state = try XCTUnwrap(PreviousInstance.readState(runDir + "/state"))
        XCTAssertEqual(state.pid, pid)
        XCTAssertEqual(state.executable, openConnectPath)
        XCTAssertNotNil(state.startTime)
        XCTAssertFalse(exists(runDir + "/state.new"))

        // argv: the config file and nothing else; the environment: the fixed one with P11_KIT_NO_USER_CONFIG.
        XCTAssertTrue(eventually { (try? String(contentsOfFile: "/proc/\(pid)/cmdline", encoding: .utf8))?.contains("sleep") == true })
        XCTAssertTrue(eventually { self.log().contains("Got CONNECT response") }, log())
        XCTAssertTrue(log().contains("fake openconnect --config=\(configPath)\n"), log())
        // (What the fake's shell adds itself left out.)
        let environment = try String(contentsOfFile: "/proc/\(pid)/environ", encoding: .utf8).split(separator: "\0").map(String.init)
            .filter { !["PWD", "OLDPWD", "SHLVL", "_"].contains($0.split(separator: "=").first.map(String.init) ?? "") }
        XCTAssertEqual(Set(environment), Set(HelperCore.fixedEnvironment + ["P11_KIT_NO_USER_CONFIG=1"]))
        // The cookie never reaches the user's log, even when the server makes openconnect print it.
        XCTAssertFalse(log().contains(Self.value), log())
        XCTAssertTrue(log().contains("Got CONNECT response: HTTP/1.1 200 OK <redacted>\n"), log())
        XCTAssertTrue(log().contains("Reflected: <redacted>\n"), "the value alone is masked too: \(log())")

        // Status: the session, and its network as the record says (none yet: setting up).
        let status = try response(daemon.socketPath, .status)
        XCTAssertEqual(status.running, ["acme": pid])
        XCTAssertEqual(status.tunnels, ["acme": TunnelStatus(state: .settingUp)])
        caller.uid = stranger
        XCTAssertNil(try response(daemon.socketPath, .status).tunnels, "only the caller's own sessions")
        caller.uid = me

        XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, pid)
        XCTAssertFalse(exists(runDir), "the cookie went with the session directory")
        XCTAssertNotEqual(kill(pid, 0), 0)
    }

    /// The request is checked as the Mac's helper checks it, before anything is prepared: no directory, no
    /// log, nothing started.
    func testRefusedRequests() throws {
        let daemon = try makeOpenConnectDaemon()
        let otherPin = "pin-sha256:/+9qLXvY4QvSoKy/ojXS6HTlG1iniUJkmUyKWlahaLE="
        let refused: [(OpenConnectStart, String)] = [
            (request(connectURL: "https://vpn.example.net/"), "connect"),
            (request(resolve: nil), "address"),
            (request(resolve: "vpn.example.com:not-an-address"), "address"),
            (request(cookie: "a\nb"), "cookie"),
            (request(cookie: ""), "cookie"),
            (request(cookie: Self.value), "cookie"),  // a bare value: openconnect would split it at its first '='
            (request(cookie: "webvpn=a b"), "cookie"),
            (request(serverCert: "sha256:abc"), "certificate"),
            (request(serverCert: otherPin, profileServerCert: Self.pin), "pinned key"),
            (request(usergroup: "../x"), "user group"),
            (request("../acme"), "profile id")
        ]
        for (start, word) in refused {
            let reply = try response(daemon.socketPath, .startOpenConnect(start))
            XCTAssertFalse(reply.ok, "\(word)")
            XCTAssertTrue(reply.error?.lowercased().contains(word) == true, "\(word): \(reply.error ?? "")")
            XCTAssertFalse(reply.error?.contains(Self.cookie) == true)
        }
        XCTAssertFalse(exists(runDir), "nothing prepared")
        XCTAssertFalse(exists(profileDir("acme") + "/vpn.log"), "no log")
        XCTAssertEqual(try response(daemon.socketPath, .status).running, [:])
        // Outsiders get the usual refusal first.
        caller.uid = stranger
        XCTAssertTrue(try response(daemon.socketPath, .startOpenConnect(request())).error?.contains("“passtunnel”") == true)
    }

    /// Ubuntu 22.04's openconnect 8.20 (and anything before 9.01) is refused with the minimum named; so is a
    /// missing openconnect, and one without a daemon executable to run as its hook.
    func testOldOrMissingOpenConnect() throws {
        let daemon = try makeOpenConnectDaemon()
        try makeOpenConnect(version: "v8.20-1")
        var reply = try response(daemon.socketPath, .startOpenConnect(request()))
        XCTAssertEqual(reply.error, "openconnect 8.20 is too old: PassTunnel needs 9.01 or later. Update the openconnect package.")
        XCTAssertFalse(exists(runDir))
        try makeOpenConnect(version: "v9.01-3")
        reply = try response(daemon.socketPath, .startOpenConnect(request()))
        XCTAssertTrue(reply.ok, reply.error ?? "")
        XCTAssertTrue(try response(daemon.socketPath, .stop(profileID: "acme")).ok)
        unlink(openConnectPath)
        reply = try response(daemon.socketPath, .startOpenConnect(request()))
        XCTAssertTrue(reply.error?.hasPrefix("openconnect is not installed (none of \(openConnectPath) exists).") == true, reply.error ?? "")

        try makeOpenConnect(version: "v9.12")
        let noHook = try makeDaemon { options in
            options.runRoot = self.base + "/run2"
            options.dnsHook = nil
        }
        reply = try response(noHook.socketPath, .startOpenConnect(request()))
        XCTAssertFalse(reply.ok)
        XCTAssertFalse(exists(PT.sessionDir(uid: me, profileID: "acme", runRoot: base + "/run2")))
    }

    // MARK: - Supervision

    /// openconnect ignores its hook's result: the daemon stops a session whose record says failed, and one that
    /// was not set up within the deadline.
    func testAFailedOrLateSetUpIsStopped() throws {
        let daemon = try makeOpenConnectDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startOpenConnect(request())).pid)
        let journal = try OpenConnectJournal.create(runDir: runDir, interface: "tun0")
        try journal.append(.status(.failed("TUNDEV is not an existing interface")))
        XCTAssertTrue(eventually { (try? self.response(daemon.socketPath, .status).running) == [:] })
        XCTAssertNotEqual(kill(pid, 0), 0)
        XCTAssertTrue(log().contains("passtunneld: the network set-up failed; stopping\n"), log())

        let late = try makeOpenConnectDaemon { options in
            options.runRoot = self.base + "/run2"
            options.openConnectTiming = OpenConnectTiming(checkInterval: 0.1, setupDeadline: 0.5, reconnectDeadline: 120)
        }
        XCTAssertTrue(try response(late.socketPath, .startOpenConnect(request())).ok)
        XCTAssertTrue(eventually(5) { (try? self.response(late.socketPath, .status).running) == [:] })
        XCTAssertTrue(log().contains("passtunneld: the network was not set up within 0 seconds; stopping\n"), log())
    }

    func testAnUpSessionReconnectingTooLongIsStopped() throws {
        let daemon = try makeOpenConnectDaemon { options in
            options.openConnectTiming = OpenConnectTiming(checkInterval: 0.1, setupDeadline: 60, reconnectDeadline: 0.5)
        }
        XCTAssertTrue(try response(daemon.socketPath, .startOpenConnect(request())).ok)
        let journal = try OpenConnectJournal.create(runDir: runDir, interface: "tun0")
        try journal.append(.status(.up))
        usleep(400_000)
        XCTAssertEqual(try response(daemon.socketPath, .status).tunnels?["acme"]?.state, .up)
        XCTAssertEqual(try response(daemon.socketPath, .status).running?.count, 1, "up stays")
        try journal.append(.status(.reconnecting))
        XCTAssertTrue(eventually(5) { (try? self.response(daemon.socketPath, .status).running) == [:] })
        XCTAssertTrue(log().contains("did not come back within 0 seconds; stopping"), log())
    }

    // MARK: - Revert after a kill

    /// A record the hook left (openconnect killed before its `disconnect` run): the daemon reverts it when it
    /// reaps the tool, but what went with the tunnel interface; a revert that fails keeps only the record, the
    /// profile cannot start over it, and a later try finishes it.
    func testTheDaemonRevertsAKilledSession() throws {
        let daemon = try makeOpenConnectDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startOpenConnect(request())).pid)
        let server = OpenConnectPlan.Route(
            IPNetwork("192.0.2.10/32")!, via: .gateway(OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "eth0")!))
        let half = OpenConnectPlan.Route(IPNetwork("0.0.0.0/1")!, via: .interface("tun0"))
        let reject = OpenConnectPlan.Route(IPNetwork("::/1")!, via: .reject)
        let journal = try OpenConnectJournal.create(runDir: runDir, interface: "tun0")
        for route in [server, reject, half] {
            try journal.append(.begin(.route(route)))
            try journal.append(.owned(.route(route)))
            system.table.append(KernelRoute(route))
        }
        try journal.append(.status(.up))
        system.failing = { $0.line.contains("unreachable") }
        kill(pid, SIGKILL)
        XCTAssertTrue(eventually { (try? self.response(daemon.socketPath, .status).running) == [:] })
        XCTAssertEqual(
            system.log,
            [
                "/usr/sbin/ip -6 route del unreachable ::/1",
                "/usr/sbin/ip -4 route del 192.0.2.10/32 via 198.51.100.1 dev eth0"
            ])
        XCTAssertEqual(PreviousInstance.entries(runDir), [OpenConnectRecord.fileName], "only the record is left")
        XCTAssertTrue(log().contains("passtunneld: restoring the network failed; trying again\n"), log())
        var refused = try response(daemon.socketPath, .startOpenConnect(request()))
        XCTAssertEqual(refused.error, "The network settings of the last acme session are not restored yet. Try again shortly.")

        system.failing = { _ in false }
        refused = try response(daemon.socketPath, .startOpenConnect(request()))
        XCTAssertTrue(refused.ok, "restored first, then started: \(refused.error ?? "")")
        XCTAssertFalse(system.table.contains { $0.is(reject) })
        XCTAssertTrue(system.table.contains { $0.is(half) }, "the tunnel's own routes went with its interface: never touched")
        XCTAssertTrue(try response(daemon.socketPath, .stop(profileID: "acme")).ok)
    }

    /// What a session of an earlier daemon recorded is reverted by the next one, which keeps the network lock.
    func testTheNextDaemonRevertsWhatAnEarlierOneLeft() throws {
        let session = try HelperCore(runRoot: runRoot).makeRunDir(profileID: "acme", uid: me)
        let reject = OpenConnectPlan.Route(IPNetwork("::/1")!, via: .reject)
        let journal = try OpenConnectJournal.create(runDir: session.path, interface: "tun0")
        try journal.append(.begin(.route(reject)))
        system.table.append(KernelRoute(reject))
        try "x".write(toFile: session.path + "/openconnect.conf", atomically: false, encoding: .utf8)
        _ = OpenConnectLock.acquire(runRoot: runRoot, until: Date())  // makes the lock file
        _ = try makeOpenConnectDaemon()
        XCTAssertEqual(system.log, ["/usr/sbin/ip -6 route del unreachable ::/1"])
        XCTAssertFalse(exists(session.path))
        XCTAssertTrue(exists(runRoot + "/" + OpenConnectLock.fileName), "the network lock stays")
    }
}

// MARK: - The hook's mode and session proof

/// `vpn-hook` mode of passtunneld: chosen by `argv[0]`, and acting only for the session whose openconnect ran it.
final class LinuxVPNHookTests: DaemonTestCase {
    var runDir: String { PT.sessionDir(uid: me, profileID: "acme", runRoot: runRoot) }
    let toolPID: pid_t = 4100
    let shellPID: pid_t = 4101
    let shell = "/usr/bin/dash"
    var tree: [pid_t: (exe: String, parent: pid_t, cwd: String)] = [:]
    var lines: [String] = []

    override func setUpWithError() throws {
        try super.setUpWithError()
        let session = try HelperCore(runRoot: runRoot).makeRunDir(profileID: "acme", uid: me)
        try writeState(session.path, pid: toolPID, executable: openConnectPath, start: 777)
        try OpenConnectPolicy(uid: me, profileID: "acme", setRoutes: true, setDNS: true).text()
            .write(toFile: session.path + "/policy", atomically: false, encoding: .utf8)
        chmod(session.path + "/policy", 0o600)
        tree = [toolPID: (openConnectPath, 1, runDir), shellPID: (shell, toolPID, runDir), 4102: ("/usr/bin/bash", 1, runDir)]
    }

    func writeState(_ dir: String, pid: pid_t, executable: String, uid: uid_t? = nil, start: UInt64) throws {
        let text = "\(pid)\n\(uid ?? me)\n\(executable)\n\(profileDir("acme"))\n\n00000000-1111-2222-3333-444444444444\n\(start)\n"
        unlink(dir + "/state")
        try text.write(toFile: dir + "/state", atomically: false, encoding: .utf8)
        chmod(dir + "/state", 0o600)
    }

    func options(parent: pid_t) -> LinuxVPNHook.Options {
        var options = LinuxVPNHook.Options()
        options.runRoot = runRoot
        options.ownExecutable = nil
        options.effectiveUID = { 0 }
        options.parent = { parent }
        let tree = self.tree
        options.processes = VPNHook.Processes(
            executable: { tree[$0]?.exe }, parent: { tree[$0]?.parent }, workingDirectory: { tree[$0]?.cwd })
        let shell = self.shell
        options.shell = { shell }
        options.isRecordedTool = { _ in true }
        options.stateWait = 0
        return options
    }

    func testMode() {
        XCTAssertTrue(LinuxVPNHook.isInvocation(["/run/passtunnel/1000/acme/vpn-hook"]))
        XCTAssertTrue(LinuxVPNHook.isInvocation(["vpn-hook", "ignored"]))
        XCTAssertFalse(LinuxVPNHook.isInvocation(["/usr/sbin/passtunneld"]))
        XCTAssertFalse(LinuxVPNHook.isInvocation(["/usr/sbin/passtunneld", "vpn-hook"]), "only the name it was started under")
        XCTAssertFalse(LinuxVPNHook.isInvocation(["/run/passtunnel/1000/acme/dns-hook"]))
        XCTAssertFalse(LinuxVPNHook.isInvocation([]))
        XCTAssertFalse(DNSHook.isInvocation(["/run/passtunnel/1000/acme/vpn-hook"]))
    }

    func testSessionProof() throws {
        let root = try XCTUnwrap(HelperCore.realPath(runRoot))
        let direct = try XCTUnwrap(LinuxVPNHook.session(options(parent: toolPID), runRoot: root, wait: false))
        XCTAssertEqual(direct.session, VPNHook.Session(toolPID: toolPID, runDir: runDir, ownerUID: me, profileID: "acme"))
        XCTAssertEqual(direct.startTime, 777)
        // One shell level, by the executable /bin/sh resolves to.
        XCTAssertEqual(LinuxVPNHook.session(options(parent: shellPID), runRoot: root, wait: false), direct)
        // Its openconnect (or shell) replaced by a package update while it runs: still the same programs.
        tree[toolPID]?.exe = openConnectPath + " (deleted)"
        tree[shellPID]?.exe = shell + " (deleted)"
        XCTAssertEqual(LinuxVPNHook.session(options(parent: shellPID), runRoot: root, wait: false), direct)
        tree[toolPID]?.exe = openConnectPath
        tree[shellPID]?.exe = shell
        // Another shell, another parent, another directory, another state: refused.
        XCTAssertNil(LinuxVPNHook.session(options(parent: 4102), runRoot: root, wait: false))
        XCTAssertNil(LinuxVPNHook.session(options(parent: 9999), runRoot: root, wait: false))
        tree[toolPID]?.cwd = base
        XCTAssertNil(LinuxVPNHook.session(options(parent: toolPID), runRoot: root, wait: false))
        tree[toolPID]?.cwd = runDir
        try writeState(runDir, pid: toolPID + 7, executable: openConnectPath, start: 777)
        XCTAssertNil(LinuxVPNHook.session(options(parent: toolPID), runRoot: root, wait: false), "another pid")
        try writeState(runDir, pid: toolPID, executable: openConnectPath, uid: me + 1, start: 777)
        XCTAssertNil(LinuxVPNHook.session(options(parent: toolPID), runRoot: root, wait: false), "another user")
        try writeState(runDir, pid: toolPID, executable: toolPath, start: 777)
        tree[toolPID]?.exe = toolPath
        XCTAssertNil(LinuxVPNHook.session(options(parent: toolPID), runRoot: root, wait: false), "not an openconnect")
        tree[toolPID]?.exe = openConnectPath
        try writeState(runDir, pid: toolPID, executable: openConnectPath, start: 777)
        var notTheTool = options(parent: toolPID)
        notTheTool.isRecordedTool = { _ in false }
        XCTAssertNil(LinuxVPNHook.session(notTheTool, runRoot: root, wait: false), "the recorded process is gone")
        var notRoot = options(parent: toolPID)
        notRoot.effectiveUID = { 1000 }
        XCTAssertNil(LinuxVPNHook.prove(notRoot, runRoot: root))
        // A later session in the same directory is another generation.
        try writeState(runDir, pid: toolPID, executable: openConnectPath, start: 778)
        XCTAssertNotEqual(LinuxVPNHook.session(options(parent: toolPID), runRoot: root, wait: false), direct)
    }

    /// The whole run against a fake system: a connect on `tun0` sets up the plan and writes the success line; a
    /// run that is not a session's changes nothing; a failure asks for openconnect to be stopped.
    func testRun() throws {
        let fake = FakeLinuxSystem()
        var options = options(parent: shellPID)
        options.system = { _, _ in fake }
        var output: [String] = []
        options.output = { output.append($0) }
        var stopped: [pid_t] = []
        options.stopTool = { pid, still in if still() { stopped.append(pid) } }
        options.environment = {
            [
                "reason=connect", "TUNDEV=tun0", "VPNGATEWAY=192.0.2.10", "INTERNAL_IP4_ADDRESS=10.11.0.2", "INTERNAL_IP4_MTU=1406",
                "INTERNAL_IP4_DNS=10.11.0.53", "CISCO_DEF_DOMAIN=example.com"
            ].map { Array($0.utf8) }
        }
        fake.table = [KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("198.51.100.1"), interface: "eth0")]
        // tun0 does not exist in the fake: the set-up fails, and openconnect is to be stopped.
        XCTAssertEqual(LinuxVPNHook.run(options: options), 1)
        XCTAssertEqual(output, [VPNHook.failureLine("TUNDEV is not an existing interface")])
        XCTAssertEqual(stopped, [toolPID])
        XCTAssertEqual(OpenConnectJournal.status(runDir: runDir), .failed("TUNDEV is not an existing interface"))

        output = []
        stopped = []
        options.parent = { 4102 }
        XCTAssertEqual(LinuxVPNHook.run(options: options), 1)
        XCTAssertEqual(output, [VPNHook.failureLine("this run is not one of a PassTunnel session")])
        XCTAssertEqual(stopped, [])
    }
}

// MARK: - The Linux system

/// `LinuxOpenConnectSystem` against a fake root: DNS through `DNSApplier` (the file backend here), only the
/// checked `ip` run, the attached networks from the interfaces' addresses.
final class LinuxOpenConnectSystemTests: DNSTestCase {
    func makeSystem(
        _ session: SessionDirectory?, ip: [String]? = nil, records: [String]? = nil,
        run: @escaping (String, [String], TimeInterval) -> ToolRunner.Result? = { _, _, _ in nil }
    )
        -> LinuxOpenConnectSystem
    {
        var kernel = LinuxOpenConnectSystem.Kernel()
        let indexes = self.indexes
        kernel.interfaceIndex = { indexes.get($0) }
        kernel.run = run
        var dnsSystem = system
        dnsSystem.resolvconfRecords = records ?? [resolvconfRecords]
        return LinuxOpenConnectSystem(
            session: session, dns: DNSApplier(system: dnsSystem, runRoot: runRoot), kernel: kernel,
            ipCandidates: ip ?? [root + "/usr/sbin/ip"], owner: me, base: base)
    }

    /// Where the fake resolvconf below keeps what it is given (Debian's `/run/resolvconf/interface`).
    var resolvconfRecords: String { root + "/run/resolvconf/interface" }

    func dns(primary: Bool, id: String = "acme", servers: [String] = ["10.11.0.53"], search: [String] = ["example.com"])
        -> OpenConnectDNSSettings
    {
        OpenConnectDNSSettings(
            OpenConnectPlan.DNS(
                service: "passtunnel-\(me)-\(id)", interface: "tun0", primary: primary, servers: servers.map { IPAddress($0)! },
                searchDomains: search, matchDomains: primary ? [] : ["corp.example.com"] + search),
            addresses: [IPAddress("10.11.0.2")!])
    }

    /// A fake `resolvectl` that answers `dns`, `domain` and `default-route` for link 7 as systemd-resolved does
    /// (one entry per domain; a long list wrapped onto indented lines).
    func answer(dns: String, domain: String, route: String = "no") throws {
        try """
        #!/bin/sh
        echo "resolvectl $*" >> '\(calls)'
        case "$1" in
          dns) printf '%s\\n' "\(dns)" ;;
          domain) printf '%s\\n' "\(domain)" ;;
          default-route) echo "Link 7 (tun0): \(route)" ;;
        esac
        exit 0

        """.write(toFile: resolvectl, atomically: false, encoding: .utf8)
        chmod(resolvectl, 0o755)
    }

    func testDNSThroughTheApplier() throws {
        let session = try session()
        let system = makeSystem(session)
        XCTAssertTrue(system.setDNS(dns(primary: true)), system.dnsFailure ?? "")
        XCTAssertTrue(resolvConfText.contains("nameserver 10.11.0.53\n"), resolvConfText)
        XCTAssertTrue(resolvConfText.contains("search example.com\n"), resolvConfText)
        XCTAssertTrue(system.hasDNS(dns(primary: true)))
        XCTAssertFalse(
            system.hasDNS(
                OpenConnectDNSSettings(
                    OpenConnectPlan.DNS(
                        service: "passtunnel-\(me)-acme", interface: "tun0", primary: true, servers: [IPAddress("10.11.0.54")!], searchDomains: [],
                        matchDomains: []),
                    addresses: [])), "other servers")
        indexes.set(["tun0": 9])
        XCTAssertFalse(system.hasDNS(dns(primary: true)), "another link of that name")
        indexes.set(["tun0": 7])
        XCTAssertTrue(system.removeDNS(service: "passtunnel-\(me)-acme"))
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertNil(recorded(session))
        // Only the session's own service.
        XCTAssertFalse(
            system.setDNS(
                OpenConnectDNSSettings(
                    OpenConnectPlan.DNS(
                        service: "passtunnel-\(me)-other", interface: "tun0", primary: true, servers: [IPAddress("10.11.0.53")!], searchDomains: [],
                        matchDomains: []),
                    addresses: [])))
        XCTAssertEqual(system.dnsFailure, "the DNS settings are not this session's")
        XCTAssertFalse(system.removeDNS(service: "passtunnel-\(me)-other"))
    }

    /// A reconnect's check reads back what the system resolves with: on the file backend `/etc/resolv.conf`
    /// still as PassTunnel wrote it; another writer's change fails the check.
    func testReconnectCheckReadsTheFileBack() throws {
        let session = try session()
        let system = makeSystem(session)
        XCTAssertTrue(system.setDNS(dns(primary: true)), system.dnsFailure ?? "")
        XCTAssertTrue(system.hasDNS(dns(primary: true)), system.dnsFailure ?? "")
        // A network manager rewrites the file in place: the record is still there, the DNS is not.
        try "nameserver 192.0.2.1\n".write(toFile: resolvConf, atomically: false, encoding: .utf8)
        XCTAssertFalse(system.hasDNS(dns(primary: true)))
        XCTAssertEqual(system.dnsFailure, "\(resolvConf) was changed by something else")
        XCTAssertNotNil(recorded(session))
    }

    /// systemd-resolved: the link's servers, domains and default route as `resolvectl` reports them for the
    /// recorded index, compared as resolved stores them; anything else (dropped settings, other values, another
    /// form, a failing tool, `/etc/resolv.conf` no longer its link) fails the check.
    func testReconnectCheckAsksSystemdResolved() throws {
        try useResolved()
        let session = try session()
        let system = makeSystem(session)
        XCTAssertTrue(system.setDNS(dns(primary: false)), system.dnsFailure ?? "")
        XCTAssertTrue(callLog.contains("resolvectl domain 7 example.com ~corp.example.com ~example.com\n"), callLog)
        // What systemd 249 and 255 list for that: example.com was given searched, then routing-only, and the
        // last flag wins (one entry per domain).
        try answer(dns: "Link 7 (tun0): 10.11.0.53", domain: "Link 7 (tun0): ~corp.example.com ~example.com")
        XCTAssertTrue(system.hasDNS(dns(primary: false)), system.dnsFailure ?? "")
        XCTAssertTrue(callLog.hasSuffix("resolvectl dns 7\nresolvectl domain 7\nresolvectl default-route 7\n"), callLog)
        try answer(dns: "Link 7 (tun0): [10.11.0.53]:53#dns.example.com", domain: "Link 7 (tun0): ~example.com ~corp.example.com")
        XCTAssertTrue(system.hasDNS(dns(primary: false)), system.dnsFailure ?? "")
        // Dropped by systemd-resolved (or someone else), or other values.
        try answer(dns: "Link 7 (tun0):", domain: "Link 7 (tun0): ~corp.example.com ~example.com")
        XCTAssertFalse(system.hasDNS(dns(primary: false)))
        XCTAssertEqual(system.dnsFailure, "systemd-resolved no longer has the link's DNS servers")
        try answer(dns: "Link 7 (tun0): 10.11.0.53 192.0.2.66", domain: "Link 7 (tun0): ~corp.example.com ~example.com")
        XCTAssertFalse(system.hasDNS(dns(primary: false)))
        try answer(dns: "Link 7 (tun0): 10.11.0.53", domain: "Link 7 (tun0): ~corp.example.com")
        XCTAssertFalse(system.hasDNS(dns(primary: false)))
        XCTAssertEqual(system.dnsFailure, "systemd-resolved no longer has the link's DNS domains")
        try answer(dns: "Link 7 (tun0): 10.11.0.53", domain: "Link 7 (tun0): ~corp.example.com ~example.com", route: "yes")
        XCTAssertFalse(system.hasDNS(dns(primary: false)))
        try answer(dns: "Link 8 (tun1): 10.11.0.53", domain: "Link 7 (tun0): ~corp.example.com ~example.com")
        XCTAssertFalse(system.hasDNS(dns(primary: false)), "another link's line")
        try "#!/bin/sh\nexit 1\n".write(toFile: resolvectl, atomically: false, encoding: .utf8)
        XCTAssertFalse(system.hasDNS(dns(primary: false)), "cannot be established")

        // A file put in place of systemd-resolved's link: the link's settings stay, names go elsewhere.
        try answer(dns: "Link 7 (tun0): 10.11.0.53", domain: "Link 7 (tun0): ~corp.example.com ~example.com")
        XCTAssertTrue(system.hasDNS(dns(primary: false)), system.dnsFailure ?? "")
        unlink(resolvConf)
        try "nameserver 192.0.2.66\n".write(toFile: resolvConf, atomically: false, encoding: .utf8)
        XCTAssertFalse(system.hasDNS(dns(primary: false)))
        XCTAssertEqual(system.dnsFailure, "\(resolvConf) no longer leads where it did when the DNS was set")
        unlink(resolvConf)
        XCTAssertEqual(symlink("../usr/lib/systemd/resolv.conf", resolvConf), 0)
        XCTAssertFalse(system.hasDNS(dns(primary: false)), "systemd-resolved's uplink file instead of its stub")
        unlink(resolvConf)
        XCTAssertEqual(symlink("../run/systemd/resolve/stub-resolv.conf", resolvConf), 0)
        XCTAssertTrue(system.hasDNS(dns(primary: false)), system.dnsFailure ?? "")
    }

    /// A full tunnel with three IPv6 servers and long domains: `resolvectl` wraps the lists, as systemd 249
    /// and 255 do past 80 columns.
    func testReconnectCheckReadsWrappedLists() throws {
        try useResolved()
        let session = try session()
        let system = makeSystem(session)
        let servers = ["2001:db8:1111:2222:3333:4444:5555:53", "2001:db8:1111:2222:3333:4444:5555:54", "2001:db8:1111:2222:3333:4444:5555:55"]
        let search = ["engineering.corp.example.com", "operations.corp.example.com", "research.corp.example.com"]
        let settings = dns(primary: true, servers: servers, search: search)
        XCTAssertTrue(system.setDNS(settings), system.dnsFailure ?? "")
        let indent = String(repeating: " ", count: "Link 7 (tun0):".count)
        try answer(
            dns: "Link 7 (tun0): \(servers[0])\n\(indent) \(servers[1])\n\(indent) \(servers[2])",
            domain: "Link 7 (tun0): \(search[0]) \(search[1])\n\(indent) \(search[2]) ~.", route: "yes")
        XCTAssertTrue(system.hasDNS(settings), system.dnsFailure ?? "")
        XCTAssertEqual(
            DNSApplier.linkLines("Link 7 (tun0): a b\n               c\nLink 8 (tun1): d\n", index: 7, interface: "tun0"), ["a", "b", "c"])
        XCTAssertNil(DNSApplier.linkLines("Global: a\n", index: 7, interface: "tun0"))
        XCTAssertEqual(DNSApplier.serverAddress("[2001:db8::53]:53"), "2001:db8::53")
        XCTAssertNil(DNSApplier.serverAddress("10.11.0.53:5353"))
        XCTAssertNil(DNSApplier.serverAddress("fe80::53%tun0"))
    }

    /// resolvconf: the record it was given for the interface, not the final resolv.conf, which a local cache
    /// (dnsmasq) may fill with 127.0.0.1 alone; found in each layout (Debian's `interface/`, openresolv's
    /// `interfaces/` and, from 3.17, `keys/`), and its resolver lines exactly those given.
    func testReconnectCheckReadsResolvconfsRecord() throws {
        let layouts = ["interface", "interfaces", "keys"].map { root + "/run/resolvconf/" + $0 }
        for (n, store) in layouts.enumerated() {
            try FileManager.default.createDirectory(atPath: store, withIntermediateDirectories: true)
            // Keeps what `-a <name>` reads under `store`, as that resolvconf does; `-d` removes it.
            try """
            #!/bin/sh
            echo "resolvconf $*" >> '\(calls)'
            if [ "$1" = "-a" ]; then cat > '\(store)'/"$2"; fi
            if [ "$1" = "-d" ]; then rm -f '\(store)'/"$2"; fi
            exit 0

            """.write(toFile: resolvconf, atomically: false, encoding: .utf8)
            chmod(resolvconf, 0o755)
            let session = try session("acme\(n)")
            let system = makeSystem(session, records: layouts)
            let settings = dns(primary: true, id: "acme\(n)", servers: ["10.11.0.53", "10.11.0.54"])
            XCTAssertTrue(system.setDNS(settings), system.dnsFailure ?? "")
            let record = store + "/tun0.passtunnel-7"
            XCTAssertEqual(try String(contentsOfFile: record, encoding: .utf8), "nameserver 10.11.0.53\nnameserver 10.11.0.54\nsearch example.com\n")
            try "nameserver 127.0.0.1\n".write(toFile: resolvConf, atomically: false, encoding: .utf8)
            XCTAssertTrue(system.hasDNS(settings), "\(store): \(system.dnsFailure ?? "")")
            // Comments and blank lines do not matter; anything else in the resolver lines does.
            try "# from PassTunnel\nnameserver 10.11.0.53\n\nnameserver  10.11.0.54\nsearch example.com\n"
                .write(toFile: record, atomically: false, encoding: .utf8)
            XCTAssertTrue(system.hasDNS(settings), system.dnsFailure ?? "")
            for changed in [
                "nameserver 192.0.2.66\nnameserver 10.11.0.53\nnameserver 10.11.0.54\nsearch example.com\n",
                "nameserver 10.11.0.54\nnameserver 10.11.0.53\nsearch example.com\n",
                "nameserver 10.11.0.53\nnameserver 10.11.0.54\nsearch example.com example.net\n",
                "nameserver 10.11.0.53\nnameserver 10.11.0.54\n"
            ] {
                try changed.write(toFile: record, atomically: false, encoding: .utf8)
                XCTAssertFalse(system.hasDNS(settings), changed)
                XCTAssertEqual(system.dnsFailure, "resolvconf's record of tun0 is no longer the one it was given")
            }
            unlink(record)
            XCTAssertFalse(system.hasDNS(settings))
            XCTAssertEqual(system.dnsFailure, "resolvconf no longer holds the record of tun0")
            try FileManager.default.removeItem(atPath: store)
        }
    }

    func testDNSFailureSaysWhy() throws {
        let session = try session()
        let system = makeSystem(session)
        unlink(resolvConf)
        XCTAssertEqual(symlink("/elsewhere/resolv.conf", resolvConf), 0)
        XCTAssertFalse(system.setDNS(dns(primary: true)))
        XCTAssertTrue(system.dnsFailure?.hasPrefix("setting DNS failed: ") == true, system.dnsFailure ?? "")
    }

    func testSplitDNSRoutesTheDomains() throws {
        let settings = try LinuxOpenConnectSystem.settings(dns(primary: false).dns)
        XCTAssertEqual(
            settings,
            try DNSSettings(
                servers: ["10.11.0.53"], searchDomains: ["example.com"], routingDomains: ["corp.example.com", "example.com"], fullTunnel: false))
        XCTAssertEqual(
            try LinuxOpenConnectSystem.settings(dns(primary: true).dns),
            try DNSSettings(servers: ["10.11.0.53"], searchDomains: ["example.com"], fullTunnel: true))
    }

    func testOnlyTheCheckedIPRuns() throws {
        let ip = root + "/usr/sbin/ip"
        try "#!/bin/sh\nexit 0\n".write(toFile: ip, atomically: false, encoding: .utf8)
        chmod(ip, 0o755)
        var ran: [[String]] = []
        let system = makeSystem(nil) { path, arguments, timeout in
            ran.append([path] + arguments + [String(Int(timeout))])
            return ToolRunner.Result(status: 2, output: "RTNETLINK answers: File exists\n")
        }
        XCTAssertEqual(system.tools, .linux(ip: ip))
        let command = OpenConnectCommand(.linkDown(interface: "tun0"), tools: system.tools)
        XCTAssertEqual(system.run(command, timeout: 7), OpenConnectCommand.Result(status: 2, output: "RTNETLINK answers: File exists"))
        XCTAssertEqual(ran, [[ip, "link", "set", "dev", "tun0", "down", "7"]])
        let other = OpenConnectCommand(executable: "/bin/sh", arguments: ["-c", "true"], effect: .linkDown(interface: "tun0"))
        XCTAssertEqual(system.run(other, timeout: 7).status, nil)
        XCTAssertEqual(ran.count, 1, "nothing but the checked ip")

        // No ip, or one others can write: nothing runs, and the reason says why.
        let missing = makeSystem(nil, ip: [root + "/none"])
        XCTAssertTrue(missing.run(command, timeout: 1).output.contains("ip is not installed"))
        chmod(ip, 0o777)
        let untrusted = makeSystem(nil) { _, _, _ in
            XCTFail("ran"); return nil
        }
        XCTAssertTrue(untrusted.run(OpenConnectCommand(.linkDown(interface: "tun0"), tools: untrusted.tools), timeout: 1).output.contains("writable"))
    }

    func testAttachedNetworks() {
        let entries = [
            LinuxOpenConnectSystem.InterfaceAddress(name: "wlan0", address: IPAddress("192.168.1.46")!, prefixLength: 24, up: true),
            LinuxOpenConnectSystem.InterfaceAddress(name: "wlan0", address: IPAddress("2001:db8:9::46")!, prefixLength: 64, up: true),
            LinuxOpenConnectSystem.InterfaceAddress(name: "lo", address: IPAddress("127.0.0.1")!, prefixLength: 8, up: true, loopback: true),
            LinuxOpenConnectSystem.InterfaceAddress(name: "tun3", address: IPAddress("10.9.0.2")!, prefixLength: 32, up: true, pointToPoint: true),
            LinuxOpenConnectSystem.InterfaceAddress(name: "eth1", address: IPAddress("172.16.5.1")!, prefixLength: 16, up: false)
        ]
        XCTAssertEqual(
            LinuxOpenConnectSystem.attached(entries),
            [
                OpenConnectPlan.Attached(IPNetwork("192.168.1.0/24")!, interface: "wlan0"),
                OpenConnectPlan.Attached(IPNetwork("2001:db8:9::/64")!, interface: "wlan0")
            ])
    }

    #if os(Linux)
    /// Read only: every network namespace has a loopback link, and rtnetlink answers without privileges.
    func testTheKernelIsReadable() throws {
        let system = LinuxOpenConnectSystem(session: nil, dns: applier)
        XCTAssertNotNil(system.routes())
        XCTAssertNotNil(system.interfaceIndex("lo"))
        XCTAssertEqual(system.interfaceLink("lo")?.up, true)
        XCTAssertTrue(system.interfaceAddresses("lo").contains(IPAddress("127.0.0.1")!))
        XCTAssertNil(system.interfaceLink("../lo"))
    }
    #endif
}

// MARK: - The distribution's openconnect (CI only)

/// The distribution's own openconnect, as the daemon and `passtunnel` check it: run only where it is installed
/// for the purpose, with `PASSTUNNEL_TEST_OPENCONNECT=1` (the Linux CI jobs; Ubuntu 24.04 ships 9.12). It only
/// runs `--version` and `--help`: nothing connects.
final class OpenConnectToolProbeTests: XCTestCase {
    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["PASSTUNNEL_TEST_OPENCONNECT"] == "1" else {
            throw XCTSkip("set PASSTUNNEL_TEST_OPENCONNECT=1 where the distribution's openconnect is installed")
        }
    }

    func testTheDaemonsChecks() throws {
        let tool = try SystemTools().resolve(.openconnect)
        XCTAssertTrue(ToolSpec.openconnect.candidates.contains(tool.path), tool.path)
        XCTAssertGreaterThanOrEqual(tool.version, ToolSpec.openconnect.minimum)
        let help = try XCTUnwrap(ToolRunner.output(of: tool.path, arguments: ToolSpec.helpArguments))
        // 9.10 and later list it; the sign-in renders `no-external-auth` then.
        XCTAssertEqual(ToolSpec.openConnectHasNoExternalAuth(help: help), tool.version >= ToolVersion(9, 10), help)
        print("openconnect \(tool.version) at \(tool.path), no-external-auth: \(ToolSpec.openConnectHasNoExternalAuth(help: help))")
    }

    #if os(Linux)
    func testTheSignInsLookup() throws {
        let tool = try AnyConnectSignIn.distributionTool(runner: SystemToolRunner())
        XCTAssertEqual(tool.path, try SystemTools().resolve(.openconnect).path)
        XCTAssertEqual(tool.caFile, try SystemTools().caBundle())
        XCTAssertTrue(tool.noExternalAuth, "Ubuntu 24.04's 9.12 has it")
    }
    #endif
}
