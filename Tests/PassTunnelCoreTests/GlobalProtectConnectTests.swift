import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

/// Stands in for the bundled openconnect signing in to a GlobalProtect portal and gateway: plays a script of
/// standard error chunks and clock steps, asks the run's `ToolInput` what to write after each (as
/// `SystemToolRunner` does while the run lasts), and records what was written when. Never runs anything.
final class FakeGlobalProtect: ToolRunning, @unchecked Sendable {
    enum Step {
        /// openconnect wrote this on standard error.
        case stderr(String)
        /// Time passes while openconnect waits (`FakeClock.advance`, no real waiting).
        case advance(TimeInterval)
        /// Something else happens meanwhile (another process writes `.last-otp`).
        case action(() -> Void)
    }

    struct Run {
        var arguments: [String]
        var config: String
        var first: Data
        var timeout: TimeInterval
        /// The second part, with the clock's time when it was written.
        var writes: [(at: Date, bytes: Data)] = []
        /// Standard input was closed without a second part, after this much of standard error.
        var closedAfter: String?
        /// A second part could follow the first when the run started.
        var hadSecondPart = false
    }

    private let lock = NSLock()
    private var _runs: [Run] = []
    let clock: FakeClock
    var script: [Step]
    var status: Int32
    var stdout: String
    /// Runs on the runner's thread right after the second part was handed over (while the run lasts).
    var onWrite: (() -> Void)?

    init(clock: FakeClock, script: [Step], status: Int32 = 0, stdout: String = "") {
        self.clock = clock
        self.script = script
        self.status = status
        self.stdout = stdout
    }

    var runs: [Run] {
        lock.lock()
        defer { lock.unlock() }
        return _runs
    }

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data, timeout: TimeInterval
    ) throws -> ToolOutput {
        XCTFail("a GlobalProtect sign-in writes standard input in parts")
        throw ToolCancelled()
    }

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: ToolInput, timeout: TimeInterval,
        cancellation: ToolCancellation?
    ) throws -> ToolOutput {
        let configPath = arguments.first.map { String($0.dropFirst("--config=".count)) } ?? ""
        var run = Run(
            arguments: arguments, config: (try? String(contentsOfFile: configPath, encoding: .utf8)) ?? "", first: Data(input.first),
            timeout: timeout, hadSecondPart: input.hasSecondPart)
        var err = Data()
        var open = input.hasSecondPart
        func poll() {
            guard open else { return }
            var pending = Data()
            switch input.next(errorOutput: err, into: &pending) {
            case .wait: break
            case .close:
                open = false
                run.closedAfter = String(decoding: err, as: UTF8.self)
            case .wrote:
                open = false
                run.writes.append((clock.now(), pending))
                onWrite?()
            }
        }
        poll()
        for step in script {
            switch step {
            case .stderr(let text): err.append(Data(text.utf8))
            case .advance(let seconds): clock.advance(seconds)
            case .action(let body): body()
            }
            poll()
        }
        lock.lock()
        _runs.append(run)
        lock.unlock()
        return ToolOutput(status: status, output: Data(stdout.utf8), errorOutput: err)
    }
}

/// openconnect 9.21's GlobalProtect sign-in output, written from its sources' messages (auth-globalprotect.c,
/// http.c, main.c), for a portal `vpn.example.com:8443` whose gateway `US East` is `gw1.example.com`.
enum GlobalProtectOutput {
    static let portalPin = "pin-sha256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk="
    static let gatewayPin = "pin-sha256:VIvehxhDt2KjN5O2MU6TnoXZFEsHIwCppUURj1ynWsE="
    static let otherPin = "pin-sha256:/+9qLXvY4QvSoKy/ojXS6HTlG1iniUJkmUyKWlahaLE="
    static let authcookie = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    static let cookie = "authcookie=\(authcookie)&portal=Acme-Portal&user=alice&domain=%28empty_domain%29&computer=mac-alice"
    static let override = "OVERRIDE-SECRET-5150 with blanks"

    static let portalPrelogin = "POST https://vpn.example.com:8443/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n"
    static let portalTLS =
        "Connected to 192.0.2.10:8443\nSSL negotiation with vpn.example.com\n"
        + "Connected to HTTPS on vpn.example.com with ciphersuite (TLS1.3)-(ECDHE-SECP256R1)-(RSA-PSS-RSAE-SHA256)-(AES-256-GCM)\n"
    static let portalConfig = "POST https://vpn.example.com:8443/global-protect/getconfig.esp\n"
    static let oneGateway = "1 gateway servers available:\n  US East (gw1.example.com) [unprioritized]\n"
    static let threeGateways =
        "3 gateway servers available:\n  US East (gw1.example.com) [priority 1]\n  EU West (gw2.example.com) [priority 2]\n"
        + "  APAC (gw3.example.com:4443) [unprioritized]\n"
    static let gatewayLogin = "POST https://gw1.example.com/ssl-vpn/login.esp\n"
    static let gatewayPrelogin = "POST https://gw1.example.com/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n"
    static let gatewayTLS =
        "Connected to 192.0.2.20:443\nSSL negotiation with gw1.example.com\n"
        + "Connected to HTTPS on gw1.example.com with ciphersuite (TLS1.3)-(ECDHE-SECP256R1)-(RSA-PSS-RSAE-SHA256)-(AES-256-GCM)\n"
    static let refused = "Unexpected 512 result from server\n"
    static let loginReturned =
        "GlobalProtect login returned portal-userauthcookie=\(override)\n"
        + "GlobalProtect login returned portal-prelogonuserauthcookie=PRELOGON-SECRET-6160\n"
        + "GlobalProtect login returned unexpected argument value arg[17]=ARG-SECRET-7170\n"
    static let failed = "Failed to complete authentication\n"

    /// The gateway's form after its prelogin: its message, and the password's prompt, where openconnect waits.
    static let gatewayPrompt = "Please enter your username and password\nPassword: "
    /// Password at the portal, a challenge for the code, the replay refused by the gateway, and the second sign-in
    /// there: up to the gateway's prelogin, without its answer yet.
    static let untilGatewayPrelogin =
        portalPrelogin + portalTLS + portalConfig + "Challenge: " + portalConfig + oneGateway + gatewayLogin + gatewayTLS + refused
        + gatewayPrelogin
    /// The same, with the gateway's form: openconnect waits for the password.
    static let untilSecondSignIn = untilGatewayPrelogin + gatewayPrompt
    /// The second sign-in answered (password, then the challenge), and the gateway's cookie.
    static let afterSecondSignIn = gatewayLogin + "Challenge: " + gatewayLogin + loginReturned

    static func stdout(
        cookie: String = cookie, host: String = "192.0.2.20", connectURL: String = "https://gw1.example.com/",
        fingerprint: String = gatewayPin, resolve: String = "gw1.example.com:192.0.2.20"
    ) -> String {
        "COOKIE='\(cookie)'\nHOST='\(host)'\nCONNECT_URL='\(connectURL)'\nFINGERPRINT='\(fingerprint)'\nRESOLVE='\(resolve)'\n"
    }

    /// The tunnel run: the gateway asked for a HIP report, and the hook set up the network.
    static let hipAndUp =
        "POST https://gw1.example.com/ssl-vpn/getconfig.esp\n"
        + "WARNING: Server asked us to submit HIP report with md5sum 0123456789abcdef0123456789abcdef.\n"
        + "    VPN connectivity may be disabled or limited without HIP report submission.\n"
        + "    You need to provide a --csd-wrapper argument with the HIP report submission script.\n"
        + "Configured as 10.12.0.2, with SSL connected and ESP in progress\n"
        + "passtunnel vpn-hook: utun5 up: 10.12.0.2, 2 routes, DNS 10.12.0.53, search example.com\n"
}

extension ConnectionManagerTests {
    typealias GP = GlobalProtectOutput

    @discardableResult
    func makeGlobalProtectProfile(
        _ name: String = "Acme GlobalProtect", otp: OTPMode = .totp, delivery: OTPDelivery = .separate, gateway: String = "US East",
        serverCert: String = GlobalProtectOutput.portalPin, gatewayServerCert: String = GlobalProtectOutput.gatewayPin,
        skipPortal: Bool = false
    ) throws -> Profile {
        var p = try store.create(name: name, type: .globalprotect)
        p.host = "vpn.example.com"
        p.port = 8443
        p.gateway = gateway
        p.serverCert = serverCert
        p.gatewayServerCert = gatewayServerCert
        p.skipPortal = skipPortal
        p.setDNS = true
        p.username = "alice"
        p.otpMode = otp
        p.otpDelivery = delivery
        try store.save(p)
        try Secrets.set(p.id, .password, "hunter2-pw")
        if otp == .totp { try Secrets.set(p.id, .totp, totpSecret) }
        return p
    }

    /// A manager on macOS 15.4 with a fake openconnect (an executable placeholder that is never run).
    func makeGlobalProtectManager(_ fake: ToolRunning) throws -> ConnectionManager {
        let m = makeManager()
        m.systemVersion = OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0)
        m.toolRunner = fake
        let tool = URL(fileURLWithPath: home).appendingPathComponent("openconnect")
        if !FileManager.default.fileExists(atPath: tool.path) {
            try Data("#!/bin/sh\nexit 99\n".utf8).write(to: tool)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tool.path)
        }
        m.openConnectPath = tool.path
        return m
    }

    func globalProtectStarts() -> [OpenConnectStart] {
        helper.starts.compactMap {
            if case .startOpenConnect(let s) = $0 { return s }
            return nil
        }
    }

    /// Connects and returns the error it failed with, and the failure kept.
    func globalProtectFailure(
        _ fake: FakeGlobalProtect, profile: Profile? = nil
    ) async throws -> (error: Error, failure: ConnectionFailure, profile: Profile, manager: ConnectionManager) {
        let p = try profile ?? makeGlobalProtectProfile()
        let m = try makeGlobalProtectManager(fake)
        do {
            try await m.connect(p.id)
            XCTFail("connected")
            throw PTError.connectFailed("")
        } catch {
            let failure = try XCTUnwrap(m.failures[p.id])
            XCTAssertTrue(globalProtectStarts().isEmpty, "nothing reaches the helper")
            return (error, failure, p, m)
        }
    }

    // MARK: signing in

    /// Portal, then gateway on another host, both asking for the code: the first part now, the second (the password
    /// and the code of the next window) only once the second sign-in shows and the first code's window has ended.
    func testGlobalProtectSignInWritesTheSecondCodeInTheNextWindow() async throws {
        let p = try makeGlobalProtectProfile()
        helper.startLog = GP.hipAndUp
        // t0 is 10 s before the window ends: the second sign-in shows at once, the code waits for the window.
        let fake = FakeGlobalProtect(
            clock: clock, script: [.stderr(GP.untilSecondSignIn), .advance(4), .advance(6), .stderr(GP.afterSecondSignIn)],
            stdout: GP.stdout())
        // What another process reads in `.last-otp` the moment the second part is handed over, while the run lasts.
        let usedURL = store.dir(p.id).appendingPathComponent(ConnectionManager.usedOTPFile)
        let seen = Locked<ConnectionManager.UsedOTPWindow?>(nil)
        fake.onWrite = { seen.mutate { $0 = try? JSONCoding.read(ConnectionManager.UsedOTPWindow.self, from: usedURL) } }
        let m = try makeGlobalProtectManager(fake)
        try await m.connect(p.id)

        let code1 = try code(at: t0)
        let code2 = try code(at: t0.addingTimeInterval(10))
        XCTAssertNotEqual(code1, code2)
        XCTAssertEqual(
            seen.value, .init(counter: TOTP.counter(params: p.totp, at: t0) + 1, period: 30),
            "the second code is spent before it leaves, not when the run returns")
        let run = try XCTUnwrap(fake.runs.first)
        XCTAssertEqual(run.first, Data("hunter2-pw\n\(code1)\n".utf8), "the password, then the code")
        XCTAssertTrue(run.hadSecondPart)
        XCTAssertEqual(run.writes.count, 1)
        XCTAssertEqual(run.writes.first?.at, t0.addingTimeInterval(10), "not before the first code's window ended")
        XCTAssertEqual(run.writes.first?.bytes, Data("hunter2-pw\n\(code2)\n".utf8), "the password and the new code")
        XCTAssertNil(run.closedAfter)
        XCTAssertEqual(run.timeout, 90, "60 s and the TOTP period")
        XCTAssertEqual(run.arguments.count, 2, "nothing else in argv")
        XCTAssertEqual(run.arguments.last, "--authenticate")
        XCTAssertTrue(run.arguments.first?.hasPrefix("--config=") == true)
        XCTAssertEqual(
            run.config,
            """
            # Generated by PassTunnel. Do not edit.
            protocol gp
            server https://vpn.example.com:8443/
            user alice
            authgroup US East
            servercert \(GP.portalPin)
            servercert \(GP.gatewayPin)
            non-inter
            passwd-on-stdin
            no-external-auth

            """)
        // Both codes are spent: the next connect waits for a window after the second.
        XCTAssertEqual(m.usedCode(p.id), .init(counter: TOTP.counter(params: p.totp, at: t0) + 1, period: 30))

        // The gateway is the tunnel's server, bound to the sign-in's address and key, with both pins.
        let s = try XCTUnwrap(globalProtectStarts().first)
        XCTAssertEqual(s.protocol, .gp)
        XCTAssertEqual([s.host, s.usergroup, s.connectURL], ["gw1.example.com", "", "https://gw1.example.com/"])
        XCTAssertEqual(s.port, 443)
        XCTAssertEqual(s.resolve, "gw1.example.com:192.0.2.20")
        XCTAssertEqual(s.cookie, GP.cookie, "unchanged")
        XCTAssertEqual([s.serverCert, s.profileServerCert, s.profileGatewayServerCert], [GP.gatewayPin, GP.portalPin, GP.gatewayPin])
        XCTAssertEqual([s.tlsOnly, s.setDNS, s.setRoutes], [false, true, true])
        // The helper takes it (its own checks of protocol 5).
        XCTAssertNoThrow(
            try OpenConnectAuthResult.tunnelConfig(
                protocol: .gp, host: s.host, port: s.port, connectURL: s.connectURL, resolve: s.resolve, cookie: s.cookie,
                serverCert: s.serverCert, profileServerCert: s.profileServerCert, profileGatewayServerCert: s.profileGatewayServerCert,
                scriptPath: "/Applications/PassTunnel.app/Contents/Resources/bin/vpn-hook", tlsOnly: s.tlsOnly, disableIPv6: false))
        let encoded = try XCTUnwrap(String(data: try HelperRequest.startOpenConnect(s).jsonData(), encoding: .utf8))
        for secret in ["hunter2-pw", code1, code2, GP.override, "PRELOGON-SECRET-6160"] {
            XCTAssertFalse(encoded.contains(secret), secret)
        }
        XCTAssertFalse(String(describing: helper.requests).contains(GP.authcookie))

        guard case .connected(let ip, _) = m.state(p.id) else { return XCTFail("\(m.state(p.id))") }
        XCTAssertEqual(ip, "10.12.0.2")
        // HIP asked for and not sent: the notice, display only.
        XCTAssertEqual(m.notices(p.id), [.hipReportNotSent])
        XCTAssertEqual(
            StatusNotice.hipReportNotSent.message,
            "The gateway asked for a host information report, which PassTunnel does not send. Access may be limited.")
        XCTAssertEqual(StatusNotice.hipReportNotSent.rawValue, "hip_report_not_sent")
    }

    /// The second part waits as long as the second sign-in does not show, and is composed the profile's way.
    func testGlobalProtectSecondPartCombined() async throws {
        var p = try makeGlobalProtectProfile(delivery: .combined)
        p.otpTemplate = "{password}:{otp}"
        try store.save(p)
        helper.startLog = GP.hipAndUp
        let fake = FakeGlobalProtect(
            clock: clock,
            script: [
                .stderr(GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.oneGateway + GP.gatewayLogin), .advance(15),
                .stderr(GP.gatewayTLS + GP.refused), .advance(1), .stderr(GP.gatewayPrelogin),
                // Waiting for the gateway's answer: no prompt yet.
                .advance(3), .stderr(GP.gatewayPrompt),
                // At the prompt, but only just: openconnect may still go on by itself.
                .advance(0.5), .advance(0.5), .stderr(GP.gatewayLogin + GP.loginReturned)
            ],
            stdout: GP.stdout())
        let m = try makeGlobalProtectManager(fake)
        try await m.connect(p.id)
        let run = try XCTUnwrap(fake.runs.first)
        XCTAssertEqual(run.first, Data("hunter2-pw:\(try code(at: t0))\n".utf8))
        XCTAssertEqual(run.writes.first?.at, t0.addingTimeInterval(20), "a second after the prompt showed, the window over")
        XCTAssertEqual(run.writes.first?.bytes, Data("hunter2-pw:\(try code(at: t0.addingTimeInterval(20)))\n".utf8))
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    /// The portal's override cookies and unknown arguments, the cookie and the codes never reach the log, the
    /// errors or the activity.
    func testGlobalProtectSignInLogIsMasked() async throws {
        let p = try makeGlobalProtectProfile()
        helper.failStarts = 1
        let fake = FakeGlobalProtect(
            clock: clock,
            script: [.stderr(GP.untilSecondSignIn), .advance(10), .stderr(GP.afterSecondSignIn + "Server says \(GP.authcookie)\n")],
            stdout: GP.stdout())
        let m = try makeGlobalProtectManager(fake)
        do { try await m.connect(p.id); XCTFail("connected") } catch PTError.helperFailed {}
        let log = VPNLog.read(store.logURL(p.id))
        XCTAssertTrue(log.contains("GlobalProtect login returned portal-userauthcookie=<redacted>\n"), log)
        XCTAssertTrue(log.contains("GlobalProtect login returned portal-prelogonuserauthcookie=<redacted>\n"), log)
        XCTAssertTrue(log.contains("GlobalProtect login returned unexpected argument value arg[17]=<redacted>\n"), log)
        XCTAssertTrue(log.contains("Server says <redacted>\n"), log)
        let activity = String(describing: m.activity(p.id))
        for secret in [
            GP.override, "with blanks", "PRELOGON-SECRET-6160", "ARG-SECRET-7170", GP.authcookie, "hunter2-pw", try code(at: t0),
            try code(at: t0.addingTimeInterval(10))
        ] {
            XCTAssertFalse(log.contains(secret), "\(secret) in \(log)")
            XCTAssertFalse((m.lastError[p.id] ?? "").contains(secret))
            XCTAssertFalse((m.lastErrorLog[p.id] ?? "").contains(secret))
            XCTAssertFalse(activity.contains(secret))
        }
    }

    /// `skip_portal`: one login at the profile's host, no second part, the sign-in's own time limit.
    func testGlobalProtectSkipPortal() async throws {
        let p = try makeGlobalProtectProfile(gateway: "", skipPortal: true)
        helper.startLog = GP.hipAndUp
        let stderr =
            "POST https://vpn.example.com:8443/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n" + GP.portalTLS
            + "POST https://vpn.example.com:8443/ssl-vpn/login.esp\nChallenge: POST https://vpn.example.com:8443/ssl-vpn/login.esp\n"
        let fake = FakeGlobalProtect(
            clock: clock, script: [.stderr(stderr)],
            stdout: GP.stdout(
                host: "192.0.2.10", connectURL: "https://vpn.example.com:8443/", fingerprint: GP.portalPin, resolve: "vpn.example.com:192.0.2.10"))
        let m = try makeGlobalProtectManager(fake)
        try await m.connect(p.id)
        let run = try XCTUnwrap(fake.runs.first)
        XCTAssertFalse(run.hadSecondPart, "closed after the first part, as in Phase 1")
        XCTAssertTrue(run.writes.isEmpty)
        XCTAssertEqual(run.timeout, 60)
        XCTAssertTrue(run.config.contains("server https://vpn.example.com:8443/gateway\n"), run.config)
        XCTAssertFalse(run.config.contains("authgroup"))
        let s = try XCTUnwrap(globalProtectStarts().first)
        XCTAssertEqual([s.host, s.connectURL], ["vpn.example.com", "https://vpn.example.com:8443/"])
        XCTAssertEqual(s.port, 8443)
    }

    /// Without a code (or with a code typed in) no second part can be made: the sign-in's own limit.
    func testGlobalProtectWithoutACodeOnlyThePassword() async throws {
        let p = try makeGlobalProtectProfile(otp: .none)
        helper.startLog = GP.hipAndUp
        let fake = FakeGlobalProtect(
            clock: clock, script: [.stderr(GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.oneGateway + GP.gatewayLogin)],
            stdout: GP.stdout())
        let m = try makeGlobalProtectManager(fake)
        try await m.connect(p.id)
        let run = try XCTUnwrap(fake.runs.first)
        XCTAssertEqual(run.first, Data("hunter2-pw\n".utf8))
        XCTAssertFalse(run.hadSecondPart)
        XCTAssertEqual(run.timeout, 60)
        XCTAssertNil(m.usedCode(p.id))
    }

    // MARK: closing standard input early

    /// A refused password at the portal: standard input is closed at once, the second code is never made, and the
    /// sign-in is a refused one (two attempts, as in Phase 1).
    func testGlobalProtectRefusedPasswordClosesStandardInput() async throws {
        let fake = FakeGlobalProtect(
            clock: clock,
            script: [
                .stderr(GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.refused), .advance(30),
                .stderr(GP.portalConfig + GP.refused + "User input required in non-interactive mode\n" + GP.failed)
            ],
            status: 1)
        let r = try await globalProtectFailure(fake)
        let run = try XCTUnwrap(fake.runs.first)
        XCTAssertTrue(run.writes.isEmpty, "no second part")
        XCTAssertEqual(run.closedAfter, GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.refused)
        XCTAssertEqual(r.error as? PTError, .authFailed(VPNLog.tail(VPNLog.read(store.logURL(r.profile.id)))))
        XCTAssertEqual(r.failure.kind, .authRejected)
        XCTAssertTrue(r.failure.credentialsSent)
        XCTAssertEqual(r.manager.usedCode(r.profile.id), .init(counter: TOTP.counter(params: r.profile.totp, at: t0), period: 30))
    }

    /// A portal's message (printed by openconnect among its own lines, main.c 2844–2845) that looks like the second
    /// sign-in writes nothing: openconnect goes on with its own next request at once, which decides, and here breaks
    /// the two-server rule, so standard input is closed.
    func testGlobalProtectServerTextDoesNotWriteTheSecondPart() async throws {
        try await serverTextCase()
    }

    // MARK: the second code's window

    /// Another process (the CLI, the MCP server) sent the next window's code while this run waited: the second part
    /// waits for the window after it, and `.last-otp` then holds that one.
    func testGlobalProtectSecondCodeSkipsAWindowAnotherProcessUsed() async throws {
        let p = try makeGlobalProtectProfile()
        helper.startLog = GP.hipAndUp
        let usedURL = store.dir(p.id).appendingPathComponent(ConnectionManager.usedOTPFile)
        let w1 = TOTP.counter(params: p.totp, at: t0)
        let w2 = ConnectionManager.UsedOTPWindow(counter: w1 + 1, period: 30)
        let fake = FakeGlobalProtect(
            clock: clock,
            script: [
                .stderr(GP.untilSecondSignIn), .action { try? JSONCoding.write(w2, to: usedURL, mode: 0o600) }, .advance(10),
                .advance(29), .advance(1), .stderr(GP.afterSecondSignIn)
            ],
            stdout: GP.stdout())
        let m = try makeGlobalProtectManager(fake)
        try await m.connect(p.id)
        let run = try XCTUnwrap(fake.runs.first)
        XCTAssertEqual(run.writes.count, 1)
        XCTAssertEqual(run.writes.first?.at, t0.addingTimeInterval(40), "not in W2, which another process used")
        XCTAssertEqual(run.writes.first?.bytes, Data("hunter2-pw\n\(try code(at: t0.addingTimeInterval(40)))\n".utf8))
        XCTAssertEqual(m.usedCode(p.id), .init(counter: w1 + 2, period: 30))
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    /// When the window after the one another process used would come too late for the time limit, standard input is
    /// closed and the failure says why (nothing is reported as the server's refusal).
    func testGlobalProtectSecondCodeWithNoFreeWindowInTime() async throws {
        let p = try makeGlobalProtectProfile()
        let usedURL = store.dir(p.id).appendingPathComponent(ConnectionManager.usedOTPFile)
        let w2 = ConnectionManager.UsedOTPWindow(counter: TOTP.counter(params: p.totp, at: t0) + 1, period: 30)
        let fake = FakeGlobalProtect(
            clock: clock,
            script: [
                .stderr(GP.untilSecondSignIn), .action { try? JSONCoding.write(w2, to: usedURL, mode: 0o600) }, .advance(10),
                .stderr("\nUser input required in non-interactive mode\n" + GP.failed)
            ],
            status: 1)
        let m = try makeGlobalProtectManager(fake)
        m.timing.signInTimeout = 5  // with the 30 s period: 35 s, before the window after W2 (40 s)
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? PTError, .signInUnusable(GlobalProtectSignIn.codeInUseReason))
        }
        let run = try XCTUnwrap(fake.runs.first)
        XCTAssertEqual(run.timeout, 35)
        XCTAssertTrue(run.writes.isEmpty)
        XCTAssertEqual(run.closedAfter, GP.untilSecondSignIn)
        XCTAssertEqual(m.failures[p.id]?.credentialsSent, true)
    }

    /// `testGlobalProtectServerTextDoesNotWriteTheSecondPart`.
    private func serverTextCase() async throws {
        let message =
            "POST https://vpn.example.com:8443/global-protect/getconfig.esp\n"
            + "POST https://gw1.example.com/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\nPassword: "
        // Past the first code's window already: only the wait at the prompt holds it back.
        clock.advance(30)
        let fake = FakeGlobalProtect(
            clock: clock,
            script: [
                .stderr(GP.portalPrelogin + GP.portalTLS + message), .advance(0.1), .stderr(GP.portalConfig + GP.oneGateway),
                .advance(20), .stderr(GP.gatewayLogin + GP.refused + GP.gatewayPrelogin + GP.gatewayPrompt), .advance(5),
                .stderr("***\nUser input required in non-interactive mode\n" + GP.failed)
            ],
            status: 1)
        let r = try await globalProtectFailure(fake)
        let run = try XCTUnwrap(fake.runs.first)
        XCTAssertTrue(run.writes.isEmpty, "nothing more is sent because of the server's text")
        XCTAssertEqual(run.closedAfter, GP.portalPrelogin + GP.portalTLS + message + GP.portalConfig + GP.oneGateway)
        XCTAssertEqual(r.failure.kind, .authRejected)
        // The pure reading alone would take it for the second sign-in: the wait at the prompt is what holds.
        XCTAssertEqual(
            VPNLog.globalProtectSecondPart(GP.portalPrelogin + GP.portalTLS + message, gateway: "US East", host: "vpn.example.com", port: 8443),
            .due)
    }

    /// The gateway refusing openconnect's replay of the portal's answer is no reason to close: the second sign-in
    /// follows. A refusal after the gateway's prelogin is, and so is any request the two-server rule refuses.
    func testGlobalProtectSecondPartDecisions() {
        typealias S = VPNLog.GlobalProtectSecondPart
        func step(_ text: String, gateway: String = "US East") -> S {
            VPNLog.globalProtectSecondPart(text, gateway: gateway, host: "vpn.example.com", port: 8443)
        }
        let portal = GP.portalPrelogin + GP.portalTLS + GP.portalConfig
        XCTAssertEqual(step(GP.portalPrelogin + GP.portalTLS), .pending)
        XCTAssertEqual(step(portal), .pending)
        XCTAssertEqual(step(portal + GP.oneGateway + GP.gatewayLogin + GP.gatewayTLS + GP.refused), .pending, "the replay refused")
        XCTAssertEqual(step(GP.untilSecondSignIn), .due)
        XCTAssertEqual(step(GP.untilGatewayPrelogin), .pending, "the gateway has not answered yet: no prompt")
        XCTAssertEqual(step(portal + GP.oneGateway + "Challenge: " + GP.gatewayPrelogin + GP.gatewayPrompt), .due, "after a prompt on the line")
        XCTAssertEqual(step(portal + GP.refused), .none, "the portal refused the password")
        XCTAssertEqual(step(portal + "Challenge: " + GP.portalConfig + GP.refused), .none, "or the code")
        XCTAssertEqual(step(GP.untilSecondSignIn + GP.gatewayLogin + GP.refused), .none, "the gateway refused the second password")
        // A gateway on the portal's own server.
        let sameHost =
            portal + "1 gateway servers available:\n  Main (vpn.example.com:8443) [unprioritized]\n"
            + "POST https://vpn.example.com:8443/ssl-vpn/login.esp\n" + GP.refused
            + "POST https://vpn.example.com:8443/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n" + GP.gatewayPrompt
        XCTAssertEqual(step(sameHost, gateway: "Main"), .due)
        // Somewhere else than the portal and the gateway it named: closed at once, the code never made.
        let third = "POST https://gw9.example.com/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n"
        XCTAssertEqual(step(GP.untilGatewayPrelogin + third + GP.gatewayPrompt), .none, "the gateway's prelogin redirected")
        XCTAssertEqual(step(portal + GP.oneGateway + GP.gatewayLogin + third), .none)
        XCTAssertEqual(step(GP.portalPrelogin + GP.gatewayPrelogin), .none, "the gateway before the portal's configuration")
        XCTAssertEqual(step(GP.untilGatewayPrelogin + GP.portalConfig), .none, "the portal after the gateway")
        XCTAssertEqual(step(GP.portalPrelogin + "POST https://vpn.example.com:8443\n"), .none, "not a request")
        // The no-portal fallback: a gateway prelogin without the portal's configuration, then its refusal.
        let fallback =
            GP.portalPrelogin + GP.portalTLS + "POST https://vpn.example.com:8443/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n"
            + "POST https://vpn.example.com:8443/ssl-vpn/login.esp\n"
        XCTAssertEqual(step(fallback), .pending)
        XCTAssertEqual(step(fallback + GP.refused), .none)
        // openconnect asks for the gateway.
        XCTAssertEqual(step(portal + GP.threeGateways, gateway: ""), .none)
        XCTAssertEqual(step(portal + GP.oneGateway, gateway: ""), .pending, "the only gateway is taken")
        XCTAssertEqual(step(portal + GP.threeGateways + "Auth choice \"US Central\" not available\n", gateway: "US Central"), .none)
        XCTAssertEqual(step(portal + GP.threeGateways + "Auth choice \"E\" matches multiple options\n", gateway: "E"), .none)
        XCTAssertEqual(step(portal + GP.threeGateways), .pending, "the profile's gateway is listed")
        // Only openconnect's whole lines count.
        XCTAssertEqual(step(portal + "Unexpected 512 result from server\r\n"), .pending)
    }

    // MARK: failures

    /// A portal with several gateways and none named: the labels for the profile's `gateway`; the code counts as sent.
    func testGlobalProtectGatewayListFailure() async throws {
        let p = try makeGlobalProtectProfile(gateway: "")
        let fake = FakeGlobalProtect(
            clock: clock,
            script: [
                .stderr(GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.threeGateways), .advance(20),
                .stderr("GATEWAY: [US East|EU West|APAC]:Auth choice \"<redacted>\" not available\n"),
                .stderr("GATEWAY: [US East|EU West|APAC]:***\nUser input required in non-interactive mode\n" + GP.failed)
            ],
            status: 1)
        let r = try await globalProtectFailure(fake, profile: p)
        let run = try XCTUnwrap(fake.runs.first)
        XCTAssertTrue(run.writes.isEmpty)
        XCTAssertEqual(run.closedAfter, GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.threeGateways)
        XCTAssertEqual(r.error as? PTError, .invalidField("gateway"))
        XCTAssertEqual(r.failure.kind, .configuration)
        XCTAssertEqual(r.failure.gateways, ["US East", "EU West", "APAC"])
        XCTAssertTrue(r.failure.credentialsSent)
        XCTAssertTrue(r.failure.codeSent)
        // In the JSON as `gateways`; absent from every other failure.
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: JSONCoding.encoder().encode(r.failure)) as? [String: Any])
        XCTAssertEqual(json["gateways"] as? [String], ["US East", "EU West", "APAC"])
        let other = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: JSONCoding.encoder().encode(ConnectionFailure(kind: .failed, at: t0))) as? [String: Any])
        XCTAssertNil(other["gateways"])
    }

    func testGlobalProtectGatewayLabels() {
        XCTAssertEqual(VPNLog.globalProtectGateways(GP.threeGateways)?.labels, ["US East", "EU West", "APAC"])
        XCTAssertEqual(VPNLog.globalProtectGateways(GP.oneGateway)?.count, 1)
        // 9.01 and 9.12 print no priority.
        XCTAssertEqual(
            VPNLog.globalProtectGateways("2 gateway servers available:\n  A (a.example.com)\n  B (b) (b.example.com)\n")?.labels, ["A", "B (b)"])
        XCTAssertEqual(
            VPNLog.globalProtectGateways("2 gateway servers available:\n  A (a.example.com) [priority -1]\n  B (b.example.com) [priority 20]\n")?
                .labels,
            ["A", "B"])
        // Bounded: a label over 64 bytes, one that is not printable ASCII, a line missing, more than 32: none.
        let long = String(repeating: "x", count: 65)
        XCTAssertNil(VPNLog.globalProtectGateways("2 gateway servers available:\n  \(long) (a.example.com)\n  B (b.example.com)\n")?.labels)
        XCTAssertNotNil(VPNLog.globalProtectGateways("1 gateway servers available:\n  \(long.dropLast()) (a.example.com)\n")?.labels)
        XCTAssertNil(VPNLog.globalProtectGateways("2 gateway servers available:\n  Ä (a.example.com)\n  B (b.example.com)\n")?.labels)
        XCTAssertNil(VPNLog.globalProtectGateways("2 gateway servers available:\n  A (a.example.com)\n")?.labels)
        XCTAssertNil(VPNLog.globalProtectGateways("2 gateway servers available:\n  A\n  B (b.example.com)\n")?.labels)
        let many = "33 gateway servers available:\n" + (0..<33).map { "  G\($0) (g\($0).example.com)\n" }.joined()
        XCTAssertEqual(VPNLog.globalProtectGateways(many)?.count, 33)
        XCTAssertNil(VPNLog.globalProtectGateways(many)?.labels)
        XCTAssertNil(VPNLog.globalProtectGateways("no list\n"))
    }

    /// SAML at the portal: nothing was submitted, so the code is given back.
    func testGlobalProtectSSOAtThePortal() async throws {
        let stderr =
            GP.portalPrelogin + GP.portalTLS + "SAML REDIRECT authentication is required via https://idp.example.com/sso\n"
            + "When SAML authentication is complete, specify destination form field by appending field_name to login URL.\n"
            + "Failed to parse XML server response\n" + GP.failed
        let r = try await globalProtectFailure(FakeGlobalProtect(clock: clock, script: [.stderr(stderr)], status: 1))
        XCTAssertEqual(r.error as? PTError, .ssoRequired(log: VPNLog.tail(stderr)))
        XCTAssertEqual(r.error.localizedDescription, "This server signs in with single sign-on (SAML), which PassTunnel does not support.")
        XCTAssertEqual(r.failure.kind, .ssoRequired)
        XCTAssertEqual(r.failure.kind.rawValue, "sso_required")
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(r.manager.usedCode(r.profile.id), "the code is given back")
        XCTAssertEqual(r.failure.details, "Your sign-in was not sent.")
        XCTAssertFalse(ConnectionManager.isRetryable(r.error))
    }

    /// SAML at a gateway behind a password portal: the portal's form was sent (9.12's wording of the line).
    func testGlobalProtectSSOAtTheGateway() async throws {
        let stderr =
            GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.oneGateway + GP.gatewayLogin + GP.gatewayTLS + GP.refused
            + GP.gatewayPrelogin
            + "When SAML authentication is complete, specify destination form field by appending :field_name to login URL.\n" + GP.failed
        let r = try await globalProtectFailure(FakeGlobalProtect(clock: clock, script: [.stderr(stderr)], status: 1))
        XCTAssertEqual(r.failure.kind, .ssoRequired)
        XCTAssertTrue(r.failure.credentialsSent)
        XCTAssertNotNil(r.manager.usedCode(r.profile.id), "spent")
    }

    /// The gateway's key, after the portal's answer: "Trust This Gateway…" writes `gateway_server_cert`, and with no
    /// portal pin needs the portal's too.
    func testGlobalProtectGatewayKeyNotTrusted() async throws {
        let p = try makeGlobalProtectProfile(serverCert: "", gatewayServerCert: "")
        let stderr =
            GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.oneGateway + GP.gatewayLogin
            + "Connected to 192.0.2.20:443\nSSL negotiation with gw1.example.com\nServer certificate verify failed: signer not found\n\n"
            + "Certificate from VPN server \"gw1.example.com\" failed verification.\nReason: signer not found\n"
            + "To trust this server in future, perhaps add this to your command line:\n    --servercert \(GP.otherPin)\n"
            + "SSL connection failure: Error in the certificate.\nFailed to open HTTPS connection to gw1.example.com\n" + GP.failed
        let r = try await globalProtectFailure(FakeGlobalProtect(clock: clock, script: [.stderr(stderr)], status: 1), profile: p)
        guard case .gatewayCertificateRejected(let gateway, let reason, let pin, _)? = r.error as? PTError else { return XCTFail("\(r.error)") }
        XCTAssertEqual([gateway, reason, pin], ["gw1.example.com:443", "signer not found", GP.otherPin])
        XCTAssertEqual(r.error.localizedDescription, "The gateway’s certificate was not trusted (signer not found).")
        XCTAssertEqual(r.failure.kind, .configuration)
        XCTAssertEqual(r.failure.serverCert, GP.otherPin)
        XCTAssertTrue(r.failure.credentialsSent, "the portal's answer went first")
        XCTAssertFalse(ConnectionManager.isRetryable(r.error))

        let offer = try XCTUnwrap(r.manager.serverTrustOffer(p.id))
        XCTAssertEqual(offer.gateway, "gw1.example.com:443")
        XCTAssertEqual(offer.server, "gw1.example.com:443")
        XCTAssertEqual(offer.pin, GP.otherPin)
        XCTAssertTrue(offer.needsPortalPin)
        XCTAssertThrowsError(try r.manager.trustServer(offer)) { XCTAssertEqual($0 as? ServerTrustOffer.PortalPinRequired, .init()) }
        XCTAssertThrowsError(try r.manager.trustServer(offer, portalPin: "pin-sha256:short"))
        let saved = try r.manager.trustServer(offer, portalPin: " " + GP.portalPin)
        XCTAssertEqual([saved.serverCert, saved.gatewayServerCert], [GP.portalPin, GP.otherPin])
        XCTAssertNil(r.manager.serverTrustOffer(p.id))
    }

    /// With the portal pinned, the gateway's other key ("None of the … fingerprint(s)") is offered on its own; the
    /// portal's own key refused before anything was sent writes `server_cert`.
    func testGlobalProtectTrustOffers() async throws {
        let p = try makeGlobalProtectProfile(gatewayServerCert: "")
        let gatewayLines =
            GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.oneGateway + GP.gatewayLogin
            + "Connected to 192.0.2.20:443\nSSL negotiation with gw1.example.com\n"
            + "None of the 1 fingerprint(s) specified via --servercert match server's certificate: \(GP.otherPin)\n"
            + "SSL connection failure: Error in the certificate.\n" + GP.failed
        let r = try await globalProtectFailure(FakeGlobalProtect(clock: clock, script: [.stderr(gatewayLines)], status: 1), profile: p)
        let offer = try XCTUnwrap(r.manager.serverTrustOffer(p.id))
        XCTAssertFalse(offer.needsPortalPin)
        XCTAssertEqual(offer.portalPin, GP.portalPin)
        // The profile changed meanwhile: stale.
        var changed = try store.get(p.id)
        changed.skipPortal = true
        try store.save(changed)
        XCTAssertNil(r.manager.serverTrustOffer(p.id))
        XCTAssertThrowsError(try r.manager.trustServer(offer)) { XCTAssertEqual($0 as? ServerTrustOffer.Stale, .init()) }
        changed.skipPortal = false
        try store.save(changed)
        XCTAssertEqual(try r.manager.trustServer(offer).gatewayServerCert, GP.otherPin)

        // The portal's key: nothing sent; the offer writes server_cert.
        let q = try makeGlobalProtectProfile("Acme Portal", serverCert: GP.otherPin)
        let portalLines =
            GP.portalPrelogin + "Connected to 192.0.2.10:8443\nSSL negotiation with vpn.example.com\n"
            + "None of the 2 fingerprint(s) specified via --servercert match server's certificate: \(GP.portalPin)\n"
            + "SSL connection failure: Error in the certificate.\nFailed to open HTTPS connection to vpn.example.com\n" + GP.failed
        let s = try await globalProtectFailure(FakeGlobalProtect(clock: clock, script: [.stderr(portalLines)], status: 1), profile: q)
        XCTAssertEqual(
            s.error as? PTError, .serverCertificateRejected(reason: "not the pinned key", pin: GP.portalPin, log: VPNLog.tail(portalLines)))
        XCTAssertFalse(s.failure.credentialsSent)
        let portalOffer = try XCTUnwrap(s.manager.serverTrustOffer(q.id))
        XCTAssertNil(portalOffer.gateway)
        XCTAssertEqual(portalOffer.server, "vpn.example.com:8443")
        XCTAssertFalse(portalOffer.needsPortalPin)
        XCTAssertEqual(try s.manager.trustServer(portalOffer).serverCert, GP.portalPin)
    }

    func testGlobalProtectSignInFailureClasses() {
        func error(_ stderr: String, status: Int32 = 1, gateway: String = "US East") -> PTError {
            VPNLog.globalProtectSignInError(
                stderr, status: status, credentialsSent: VPNLog.globalProtectCredentialsSent(stderr), gateway: gateway,
                host: "vpn.example.com", port: 8443, server: "vpn.example.com:8443")
        }
        // Not a GlobalProtect server: two prelogins (the no-portal fallback), nothing sent.
        let neither =
            GP.portalPrelogin + GP.portalTLS + "POST https://vpn.example.com:8443/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n"
            + "Server is neither a GlobalProtect portal nor a gateway.\n" + GP.failed
        XCTAssertFalse(VPNLog.globalProtectCredentialsSent(neither))
        XCTAssertEqual(error(neither), .invalidField("host"))
        // Before the server: name, no answer, certificate.
        let notFound =
            GP.portalPrelogin + "getaddrinfo failed for host 'vpn.example.com': nodename nor servname provided, or not known\n"
            + "Failed to open HTTPS connection to vpn.example.com\n" + GP.failed
        XCTAssertEqual(error(notFound), .hostNotFound(server: "vpn.example.com:8443", log: VPNLog.tail(notFound)))
        let refused =
            GP.portalPrelogin + "Failed to connect to 192.0.2.10:8443: Connection refused\nFailed to connect to host vpn.example.com\n" + GP.failed
        XCTAssertEqual(
            error(refused), .serverUnreachable(server: "vpn.example.com:8443", reason: "Connection refused", log: VPNLog.tail(refused)))
        // More answers than given, before anything was sent (a text field before the password).
        let more = GP.portalPrelogin + GP.portalTLS + "Token:***\nUser input required in non-interactive mode\n" + GP.failed
        XCTAssertEqual(error(more), .signInNeedsMoreAnswers(log: VPNLog.tail(more)))
        // Anything else before sending, and dyld.
        let odd = GP.portalPrelogin + GP.portalTLS + "Failed to parse XML server response\n" + GP.failed
        XCTAssertEqual(error(odd), .connectFailed(VPNLog.tail(odd)))
        let dyld = "dyld[4242]: Symbol not found: _strchrnul\n"
        XCTAssertEqual(error(dyld, status: 134), .toolUnsupported(reason: "Symbol not found: _strchrnul", log: VPNLog.tail(dyld)))
        // Once sent, everything else is a refused sign-in, whatever the server's text says.
        let sentThenOdd = GP.portalPrelogin + GP.portalTLS + GP.portalConfig + "Server is neither a GlobalProtect portal nor a gateway.\n"
        XCTAssertEqual(error(sentThenOdd), .authFailed(VPNLog.tail(sentThenOdd)))
        // The gateway named but not listed.
        let unlisted = GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.threeGateways + "Auth choice \"US Central\" not available\n"
        XCTAssertEqual(error(unlisted, gateway: "US Central"), .invalidField("gateway"))
        XCTAssertEqual(error(unlisted), .authFailed(VPNLog.tail(unlisted)), "the profile's own gateway is listed")
        // A server's text with a CR is not openconnect's line.
        let cr =
            GP.portalPrelogin + GP.portalTLS
            + "When SAML authentication is complete, specify destination form field by appending field_name to login URL.\r\n"
        XCTAssertEqual(error(cr), .connectFailed(VPNLog.tail(cr)))
        XCTAssertFalse(VPNLog.globalProtectSSORequired(cr))
    }

    func testGlobalProtectNotAGlobalProtectServer() async throws {
        let stderr =
            GP.portalPrelogin + GP.portalTLS + "POST https://vpn.example.com:8443/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n"
            + "Server is neither a GlobalProtect portal nor a gateway.\n" + GP.failed
        let r = try await globalProtectFailure(FakeGlobalProtect(clock: clock, script: [.stderr(stderr)], status: 1))
        XCTAssertEqual(r.error as? PTError, .invalidField("host"))
        XCTAssertEqual(r.failure.kind, .configuration)
        XCTAssertEqual(r.failure.reason, "This server is not a GlobalProtect portal or gateway")
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(r.manager.usedCode(r.profile.id), "the code is given back")
    }

    func testGlobalProtectCredentialsSent() {
        XCTAssertFalse(VPNLog.globalProtectCredentialsSent(""))
        XCTAssertFalse(VPNLog.globalProtectCredentialsSent(GP.portalPrelogin + GP.portalTLS))
        XCTAssertFalse(VPNLog.globalProtectCredentialsSent(GP.portalPrelogin.replacingOccurrences(of: "Mac", with: "Linux")))
        XCTAssertTrue(VPNLog.globalProtectCredentialsSent(GP.portalPrelogin + GP.portalConfig))
        XCTAssertTrue(VPNLog.globalProtectCredentialsSent("Challenge: " + GP.gatewayLogin), "wherever it stands")
        XCTAssertTrue(VPNLog.globalProtectCredentialsSent(String(GP.portalPrelogin.dropLast())), "cut off: counted as sent")
        XCTAssertTrue(
            VPNLog.globalProtectCredentialsSent(
                "POST https://vpn.example.com:8443/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac&x\n"),
            "a redirected prelogin")
        XCTAssertTrue(VPNLog.globalProtectCredentialsSent("POST https://vpn.example.com:8443/\n"))
    }

    /// The two-server rule: the profile's server, then the gateway the portal named, and nothing else.
    func testGlobalProtectRequestsNameAtMostTwoServers() async throws {
        let gateway = OpenConnectAuthResult.Destination(host: "gw1.example.com", port: 443, resolveAddress: "192.0.2.20")
        func allowed(_ text: String, _ destination: OpenConnectAuthResult.Destination = gateway) -> Bool {
            VPNLog.globalProtectRouteIsAllowed(text, host: "vpn.example.com", port: 8443, destination: destination)
        }
        XCTAssertTrue(allowed(GP.untilSecondSignIn + GP.afterSecondSignIn))
        XCTAssertTrue(allowed(GP.portalPrelogin + "POST https://VPN.Example.com:8443/global-protect/getconfig.esp\n" + GP.gatewayLogin))
        XCTAssertFalse(allowed(GP.portalPrelogin + GP.gatewayLogin + GP.portalConfig), "the gateway before the portal's configuration")
        XCTAssertFalse(allowed(GP.untilSecondSignIn + "POST https://gw2.example.com/ssl-vpn/login.esp\n"), "a third server")
        XCTAssertFalse(allowed(GP.portalPrelogin + GP.portalConfig + "POST https://gw1.example.com/global-protect/getconfig.esp\n"))
        XCTAssertFalse(allowed(GP.portalPrelogin + GP.portalConfig + "POST https://vpn.example.com:8443/ssl-vpn/login.esp\n" + GP.gatewayLogin))
        XCTAssertFalse(allowed(GP.portalPrelogin + GP.portalConfig + "POST https://gw1.example.com:8443/ssl-vpn/login.esp\n"), "another port")
        XCTAssertFalse(allowed(GP.portalPrelogin + "POST https://vpn.example.com:8443/global-protect/getconfig.esp"), "cut off")
        // A gateway on the portal's server (and the no-portal fallback): one server, any path.
        let same = OpenConnectAuthResult.Destination(host: "vpn.example.com", port: 8443, resolveAddress: "192.0.2.10")
        XCTAssertTrue(
            allowed(GP.portalPrelogin + "POST https://VPN.example.com:8443/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n", same))
        XCTAssertFalse(allowed(GP.portalPrelogin + GP.gatewayLogin, same))
        // IPv6 literals in brackets, any spelling.
        let v6 = OpenConnectAuthResult.Destination(host: "2001:db8::20", port: 443, resolveAddress: nil)
        XCTAssertTrue(allowed(GP.portalPrelogin + GP.portalConfig + "POST https://[2001:DB8:0::20]/ssl-vpn/login.esp\n", v6))

        // Through the manager: a third server fails the connect with the fixed text, after the fact.
        let fake = FakeGlobalProtect(
            clock: clock,
            script: [
                .stderr(GP.portalPrelogin + GP.portalTLS + GP.portalConfig + "POST https://gw9.example.com/ssl-vpn/login.esp\n" + GP.gatewayLogin)
            ],
            stdout: GP.stdout())
        let r = try await globalProtectFailure(fake, profile: try makeGlobalProtectProfile(otp: .none))
        XCTAssertEqual(r.error as? PTError, .signInUnusable(GlobalProtectSignIn.otherServerReason))
        XCTAssertTrue(r.failure.credentialsSent)
        // `skip_portal`: the sign-in may end only at the profile's server.
        let skip = FakeGlobalProtect(
            clock: clock, script: [.stderr("POST https://vpn.example.com:8443/ssl-vpn/login.esp\n")], stdout: GP.stdout())
        let s = try await globalProtectFailure(skip, profile: try makeGlobalProtectProfile("Acme Skip", otp: .none, skipPortal: true))
        guard case .signInUnusable? = s.error as? PTError else { return XCTFail("\(s.error)") }
    }

    func testGlobalProtectTimeoutAndCancel() async throws {
        let p = try makeGlobalProtectProfile()
        final class Stuck: ToolRunning, @unchecked Sendable {
            func run(_ path: String, _ arguments: [String], environment: [String: String], input: Data, timeout: TimeInterval) throws -> ToolOutput {
                throw ToolTimeout(seconds: Int(timeout), errorOutput: Data((GlobalProtectOutput.untilSecondSignIn).utf8))
            }
        }
        let m = try makeGlobalProtectManager(Stuck())
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(error as? PTError, .connectTimeout(90))
        }
        XCTAssertEqual(m.failures[p.id]?.kind, .timeout)
        XCTAssertEqual(m.failures[p.id]?.credentialsSent, true)
    }

    /// The helper names the profile's type when a start waits for the last session's network to be restored.
    func testTheHelpersRestoreMessageNamesTheType() {
        XCTAssertEqual(
            HelperCore.stillRestoringMessage(typeName: OpenConnectProtocol.gp.displayName),
            "The network settings of this profile's last Palo Alto GlobalProtect session are still being restored. Try again shortly.")
        XCTAssertEqual(
            HelperCore.stillRestoringMessage(typeName: OpenConnectProtocol.anyconnect.displayName),
            "The network settings of this profile's last Cisco AnyConnect session are still being restored. Try again shortly.")
        XCTAssertEqual(
            HelperCore.stillRestoringMessage(typeName: nil),
            "The network settings of this profile's last session are still being restored. Try again shortly.")
    }
}

/// The parts of a GlobalProtect sign-in that need no manager.
final class GlobalProtectSignInTests: XCTestCase {
    func testAnswers() {
        XCTAssertEqual(GlobalProtectAnswers.lines(password: "pw", code: "123456", delivery: .separate, template: ""), ["pw", "123456"])
        XCTAssertEqual(GlobalProtectAnswers.lines(password: "pw", code: "123456", delivery: .combined, template: "{password}{otp}"), ["pw123456"])
        XCTAssertEqual(GlobalProtectAnswers.lines(password: "pw", code: nil, delivery: .separate, template: ""), ["pw"])
        XCTAssertTrue(GlobalProtectAnswers.hasSecondPart(skipPortal: false, totp: true))
        XCTAssertFalse(GlobalProtectAnswers.hasSecondPart(skipPortal: true, totp: true))
        XCTAssertFalse(GlobalProtectAnswers.hasSecondPart(skipPortal: false, totp: false))
        XCTAssertEqual(
            GlobalProtectAnswers.secondPartNotBefore(codeTime: Date(timeIntervalSince1970: 1_700_000_000), params: TOTPParams()),
            Date(timeIntervalSince1970: 1_700_000_010))
        XCTAssertEqual(
            GlobalProtectAnswers.secondPartNotBefore(codeTime: Date(timeIntervalSince1970: 1_700_000_010), params: TOTPParams()),
            Date(timeIntervalSince1970: 1_700_000_040), "a code at the window's first second waits for the whole window")
        XCTAssertEqual(GlobalProtectSignIn.timeout(base: 60, secondPartPeriod: 30), 90)
        XCTAssertEqual(GlobalProtectSignIn.timeout(base: 60, secondPartPeriod: 60), 120)
        XCTAssertEqual(GlobalProtectSignIn.timeout(base: 60, secondPartPeriod: nil), 60)
    }

    func testToolInputParts() {
        var sink = Data()
        XCTAssertFalse(ToolInput(Array("a\n".utf8)).hasSecondPart)
        XCTAssertEqual(ToolInput(Array("a\n".utf8)).next(errorOutput: Data(), into: &sink), .close)

        var made = 0
        var answer: ToolInput.Decision = .wait
        let input = ToolInput(
            Array("a\n".utf8),
            second: { pending in
                made += 1
                pending.append(contentsOf: Array("b\n".utf8))
                return true
            }, decide: { _ in answer })
        XCTAssertTrue(input.hasSecondPart)
        XCTAssertEqual(input.next(errorOutput: Data(), into: &sink), .wait)
        XCTAssertEqual(made, 0, "made only when it is written")
        answer = .write
        XCTAssertEqual(input.next(errorOutput: Data(), into: &sink), .wrote)
        XCTAssertEqual(sink, Data("b\n".utf8), "straight into the runner's buffer")
        XCTAssertTrue(input.secondWritten)
        XCTAssertEqual(input.next(errorOutput: Data(), into: &sink), .close, "once")
        XCTAssertEqual(made, 1)
        XCTAssertFalse(input.hasSecondPart)

        let closing = ToolInput(
            Array("a\n".utf8),
            second: {
                $0.append(1); return true
            }, decide: { _ in .close })
        XCTAssertEqual(closing.next(errorOutput: Data(), into: &sink), .close)
        XCTAssertFalse(closing.secondWritten)
        let none = ToolInput(Array("a\n".utf8), second: { _ in false }, decide: { _ in .write })
        XCTAssertEqual(none.next(errorOutput: Data(), into: &sink), .close, "nothing to write closes it")
    }

    /// `first` lives in a buffer of the input's own, which is overwritten once the runner has taken it; the caller's
    /// bytes are never the ones overwritten (or kept).
    func testToolInputKeepsAndWipesItsOwnCopy() throws {
        let caller = Array("secret-answer\n".utf8)
        let input = ToolInput(caller)
        XCTAssertEqual(input.first, caller)
        input.wipeFirst()
        XCTAssertTrue(input.first.allSatisfy { $0 == 0 }, "overwritten")
        XCTAssertEqual(caller, Array("secret-answer\n".utf8), "the caller's own bytes are the caller's to overwrite")
        var copy = ToolInput.copy(caller)
        copy.wipe()
        XCTAssertEqual(caller, Array("secret-answer\n".utf8), "a copy in storage of its own")
        // The `Data` input (Cisco AnyConnect, the Linux secret stores' tools): copied once, straight into the input's
        // own buffer, and overwritten there.
        let data = Data("stored-secret\n".utf8)
        XCTAssertEqual(ToolInput.copy(data), Array("stored-secret\n".utf8))
        let fromData = ToolInput(copying: data)
        XCTAssertEqual(fromData.first, Array(data))
        XCTAssertFalse(fromData.hasSecondPart)
        fromData.wipeFirst()
        XCTAssertTrue(fromData.first.allSatisfy { $0 == 0 })
        XCTAssertEqual(data, Data("stored-secret\n".utf8))

        // After a run, the runner's copy is all that held it, and the input's is overwritten.
        let ran = ToolInput(Array("x\n".utf8))
        _ = try SystemToolRunner().run("/bin/sh", ["-c", "read a"], environment: [:], input: ran, timeout: 10, cancellation: nil)
        XCTAssertTrue(ran.first.allSatisfy { $0 == 0 })
        // A runner that writes the first part only overwrites it too.
        final class FirstOnly: ToolRunning {
            func run(_ path: String, _ arguments: [String], environment: [String: String], input: Data, timeout: TimeInterval) throws
                -> ToolOutput
            { ToolOutput(status: 0, output: Data(), errorOutput: Data()) }
        }
        let other = ToolInput(Array("y\n".utf8))
        _ = try FirstOnly().run("/bin/true", [], environment: [:], input: other, timeout: 1, cancellation: nil)
        XCTAssertTrue(other.first.allSatisfy { $0 == 0 })
    }

    /// `SystemToolRunner` writes the second part when the tool's standard error shows it is due, and closes standard
    /// input early when it is told to: a real child process (`/bin/sh`), no network.
    func testSystemToolRunnerStreamsTheSecondPart() throws {
        let script = "read a; echo ready >&2; read b; echo \"$a|$b\"; read c && echo more"
        func run(_ decision: @escaping (String) -> ToolInput.Decision) throws -> (String, ToolInput) {
            let input = ToolInput(
                Array("first\n".utf8),
                second: {
                    $0.append(contentsOf: Array("second\n".utf8))
                    return true
                }, decide: { decision(String(decoding: $0, as: UTF8.self)) })
            let out = try SystemToolRunner().run("/bin/sh", ["-c", script], environment: [:], input: input, timeout: 10, cancellation: nil)
            return (String(decoding: out.output, as: UTF8.self), input)
        }
        let (written, input) = try run { $0.contains("ready\n") ? .write : .wait }
        XCTAssertEqual(written, "first|second\n", "and closed after it: no third line")
        XCTAssertTrue(input.secondWritten)
        let (closed, closedInput) = try run { $0.contains("ready\n") ? .close : .wait }
        XCTAssertEqual(closed, "first|\n")
        XCTAssertFalse(closedInput.secondWritten)
        // Data input as before: written, then closed.
        let out = try SystemToolRunner().run(
            "/bin/sh", ["-c", "read a; read b; echo \"$a|$b\""], environment: [:], input: Data("x\ny\n".utf8), timeout: 10)
        XCTAssertEqual(String(decoding: out.output, as: UTF8.self), "x|y\n")
    }

    /// The masks of the portal's override cookies apply wherever a log line is masked: the sign-in's redaction and
    /// the helper's copy of the tunnel run's output.
    func testOverrideCookiesAreMaskedToTheEndOfTheLine() {
        XCTAssertEqual(
            OutputMask.apply("GlobalProtect login returned portal-userauthcookie=abc def;ghi"),
            "GlobalProtect login returned portal-userauthcookie=<redacted>")
        XCTAssertEqual(
            OutputMask.apply("GlobalProtect login returned portal-prelogonuserauthcookie=abc"),
            "GlobalProtect login returned portal-prelogonuserauthcookie=<redacted>")
        XCTAssertEqual(
            OutputMask.apply("GlobalProtect login returned unexpected argument value arg[3]=x y"),
            "GlobalProtect login returned unexpected argument value arg[3]=<redacted>")
        XCTAssertEqual(
            LogRedactor(secrets: []).redact("GlobalProtect login returned portal-userauthcookie=abc def"),
            "GlobalProtect login returned portal-userauthcookie=<redacted>")
        // Other lines as before.
        XCTAssertEqual(OutputMask.apply("GlobalProtect login returned domain=x"), "GlobalProtect login returned domain=x")
    }

    func testHIPNoticeOnlyFromOpenConnectsThreeLines() {
        let lines = [
            "WARNING: Server asked us to submit HIP report with md5sum 0123456789abcdef0123456789abcdef.",
            "    VPN connectivity may be disabled or limited without HIP report submission.",
            "    You need to provide a --csd-wrapper argument with the HIP report submission script."
        ]
        XCTAssertTrue(VPNLog.globalProtectHIPRequested(lines.joined(separator: "\n") + "\n"))
        XCTAssertEqual(StatusNotice.of(.globalprotect, log: lines.joined(separator: "\n") + "\n"), [.hipReportNotSent])
        XCTAssertEqual(StatusNotice.of(.anyconnect, log: lines.joined(separator: "\n") + "\n"), [], "GlobalProtect's only")
        XCTAssertFalse(VPNLog.globalProtectHIPRequested(lines.dropLast().joined(separator: "\n") + "\n"))
        XCTAssertFalse(VPNLog.globalProtectHIPRequested(lines.joined(separator: "\n")), "the last line not complete")
        var other = lines
        other[0] = "WARNING: Server asked us to submit HIP report with md5sum 0123."
        XCTAssertFalse(VPNLog.globalProtectHIPRequested(other.joined(separator: "\n") + "\n"))
        other = lines
        other[1] += "\r"
        XCTAssertFalse(VPNLog.globalProtectHIPRequested(other.joined(separator: "\n") + "\n"))
        XCTAssertEqual(StatusNotice.allCases.map(\.rawValue), ["hip_report_not_sent"])
    }
}
