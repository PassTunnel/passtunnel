import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

/// Stands in for the bundled openconnect: records what the sign-in run was given (the config file is read
/// while the run lasts, since it is removed after) and returns scripted results. Never runs anything.
final class FakeOpenConnect: ToolRunning, @unchecked Sendable {
    struct Call {
        var path: String
        var arguments: [String]
        var environment: [String: String]
        var input: Data
        var configPath: String
        var config: String
        var configMode: Int
        var directoryMode: Int
        var timeout: TimeInterval
    }

    private let lock = NSLock()
    private var _calls: [Call] = []
    private var _results: [Result<ToolOutput, Error>] = []
    private var _sawCancel = false
    /// The run waits until it is cancelled, then throws `ToolCancelled`.
    var blockUntilCancelled = false

    var calls: [Call] {
        lock.lock()
        defer { lock.unlock() }
        return _calls
    }

    var sawCancel: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _sawCancel
    }

    /// What the next runs return, in order; the last one again for every later run.
    var results: [Result<ToolOutput, Error>] {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _results
        }
        set {
            lock.lock()
            _results = newValue
            lock.unlock()
        }
    }

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data, timeout: TimeInterval
    ) throws -> ToolOutput {
        try run(path, arguments, environment: environment, input: input, timeout: timeout, cancellation: nil)
    }

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data, timeout: TimeInterval,
        cancellation: ToolCancellation?
    ) throws -> ToolOutput {
        let configPath = arguments.first.map { String($0.dropFirst("--config=".count)) } ?? ""
        func mode(_ path: String) -> Int {
            ((try? FileManager.default.attributesOfItem(atPath: path))?[.posixPermissions] as? NSNumber)?.intValue ?? -1
        }
        let call = Call(
            path: path, arguments: arguments, environment: environment, input: input, configPath: configPath,
            config: (try? String(contentsOfFile: configPath, encoding: .utf8)) ?? "", configMode: mode(configPath),
            directoryMode: mode((configPath as NSString).deletingLastPathComponent), timeout: timeout)
        lock.lock()
        _calls.append(call)
        let result = _results.count > 1 ? _results.removeFirst() : _results.first
        lock.unlock()
        if blockUntilCancelled {
            while cancellation?.isCancelled != true { usleep(5000) }
            lock.lock()
            _sawCancel = true
            lock.unlock()
            throw ToolCancelled()
        }
        guard let result else { throw ToolTimeout(seconds: Int(timeout)) }
        return try result.get()
    }
}

/// openconnect 9.21's output, as it prints it (captured from the bundled tool against a closed local port, a
/// name that does not resolve and a local TLS server with a self-signed certificate; the rest written from
/// its sources' messages), for a profile of `vpn.example.com:8443/engineering`.
enum OpenConnectOutput {
    static let pin = "pin-sha256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk="
    static let otherPin = "pin-sha256:/+9qLXvY4QvSoKy/ojXS6HTlG1iniUJkmUyKWlahaLE="
    static let cookie = "4C1D2A@1048576@A3F1@9C8B7A6F5E4D3C2B1A0F9E8D7C6B5A4F3E2D1C0B"

    static let post = "POST https://vpn.example.com:8443/engineering\n"
    static let tls =
        "Connected to 192.0.2.10:8443\nSSL negotiation with vpn.example.com\nServer certificate verify failed: signer not found\n"
        + "Connected to HTTPS on vpn.example.com with ciphersuite (TLS1.3)-(ECDHE-SECP256R1)-(RSA-PSS-RSAE-SHA256)-(AES-256-GCM)\n"
    static let failed = "Failed to complete authentication\n"

    /// A sign-in that worked: the initial request, the form with the password and the code.
    static let signedIn = post + tls + "XML POST enabled\nPlease enter your username and password.\n" + post + "Password:\n" + post

    static func stdout(
        cookie: String = cookie, host: String = "192.0.2.10", connectURL: String = "https://vpn.example.com:8443/",
        fingerprint: String = pin, resolve: String = "vpn.example.com:192.0.2.10"
    ) -> String {
        "COOKIE='\(cookie)'\nHOST='\(host)'\nCONNECT_URL='\(connectURL)'\nFINGERPRINT='\(fingerprint)'\nRESOLVE='\(resolve)'\n"
    }

    static func output(status: Int32 = 0, stdout: String = "", stderr: String) -> Result<ToolOutput, Error> {
        .success(ToolOutput(status: status, output: Data(stdout.utf8), errorOutput: Data(stderr.utf8)))
    }

    static let success = output(stdout: stdout(), stderr: signedIn)

    // Failures (exit status 1 unless noted).
    static let refused =
        post + "Failed to connect to 192.0.2.10:8443: Connection refused\nFailed to connect to host vpn.example.com\n"
        + "Failed to open HTTPS connection to vpn.example.com\n" + failed
    /// macOS reports a refused connect this way to openconnect (captured).
    static let refusedLocally =
        "POST https://127.0.0.1:47123/\nFailed to connect to 127.0.0.1:47123: Invalid argument\nFailed to connect to host 127.0.0.1\n"
        + "Failed to open HTTPS connection to 127.0.0.1\n" + failed
    static let notFound =
        post + "getaddrinfo failed for host 'vpn.example.com': nodename nor servname provided, or not known\n"
        + "Failed to open HTTPS connection to vpn.example.com\n" + failed
    static let untrusted =
        post + "Connected to 192.0.2.10:8443\nSSL negotiation with vpn.example.com\nServer certificate verify failed: signer not found\n\n"
        + "Certificate from VPN server \"vpn.example.com\" failed verification.\nReason: signer not found\n"
        + "To trust this server in future, perhaps add this to your command line:\n    --servercert \(otherPin)\n"
        + "SSL connection failure: Error in the certificate.\nFailed to open HTTPS connection to vpn.example.com\n" + failed
    static let pinMismatch =
        post + "Connected to 192.0.2.10:8443\nSSL negotiation with vpn.example.com\nServer certificate verify failed: signer not found\n"
        + "None of the 1 fingerprint(s) specified via --servercert match server's certificate: \(otherPin)\n"
        + "SSL connection failure: Error in the certificate.\nFailed to open HTTPS connection to vpn.example.com\n" + failed
    static let hostScan =
        post + tls + "XML POST enabled\nError: Server asked us to run CSD hostscan.\n"
        + "You need to provide a suitable --csd-wrapper argument.\n" + failed
    static let csdTrojan =
        post + tls + "XML POST enabled\nFetched CSD stub for mac-intel platform (size is 4096 bytes).\n"
        + "Error: Server asked us to download and run a 'Cisco Secure Desktop' trojan.\n"
        + "This facility is disabled by default for security reasons, so you may wish to enable it.\n" + failed
    /// A wrong password: the server answers the form with the form again, which gets the code as the
    /// password, and then a third time, with nothing left to answer.
    static let rejected =
        post + tls + "XML POST enabled\nPlease enter your username and password.\n" + post + "Login failed.\n"
        + "Please enter your username and password.\nPassword:\n" + post + "Login failed.\n"
        + "Please enter your username and password.\nPassword:***\nUser input required in non-interactive mode\n" + failed
    /// The first form asks for two hidden fields, and only one answer was given (`.combined`).
    static let moreAnswers =
        post + tls + "XML POST enabled\nPlease enter your username and password.\nSecond Password:***\n"
        + "User input required in non-interactive mode\n" + failed
    static let noSuchGroup =
        post + tls + "XML POST enabled\nAuth choice \"Employees\" not available\n" + failed
    /// The form sent, then the next request's connection failed (a redirect to a server that does not answer).
    static let lostAfterForm =
        post + tls + "XML POST enabled\n" + post + "Failed to connect to 198.51.100.7:443: Operation timed out\n"
        + "Failed to open HTTPS connection to 198.51.100.7\n" + failed
    /// dyld stopped it (exit 134) on a macOS that lacks a symbol.
    static let dyld =
        "dyld[4242]: Symbol not found: _strchrnul\n  Referenced from: <1234> /Applications/PassTunnel.app/Contents/Frameworks/libopenconnect.5.dylib\n"

    /// The tunnel run (the helper's log): the hook set up the network.
    static let hookUp =
        "Connected to HTTPS on vpn.example.com with ciphersuite (TLS1.3)-(ECDHE-SECP256R1)-(RSA-PSS-RSAE-SHA256)-(AES-256-GCM)\n"
        + "Got CONNECT response: HTTP/1.1 200 OK\nCSTP connected. DPD 30, Keepalive 20\n"
        + "Configured as 10.11.0.2, with SSL connected and DTLS in progress\n"
        + "passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes, DNS 10.11.0.53, search example.com, split DNS corp.example.com\n"
    static let hookFailed =
        "Got CONNECT response: HTTP/1.1 200 OK\nConfigured as 10.11.0.2, with SSL connected and DTLS in progress\n"
        + "passtunnel vpn-hook: setting up the network failed: INTERNAL_IP4_DNS is not a list of IPv4 and IPv6 addresses\n"
}

extension ConnectionManagerTests {
    typealias Out = OpenConnectOutput

    @discardableResult
    func makeAnyConnect(
        _ name: String = "Acme AnyConnect", otp: OTPMode = .totp, delivery: OTPDelivery = .separate, pin: String = Out.pin,
        autoReconnect: Bool = false
    ) throws -> Profile {
        var p = try store.create(name: name, type: .anyconnect)
        p.host = "vpn.example.com"
        p.port = 8443
        p.usergroup = "engineering"
        p.authgroup = "Employees"
        p.serverCert = pin
        p.tlsOnly = true
        p.setDNS = true
        p.username = "alice"
        p.otpMode = otp
        p.otpDelivery = delivery
        p.autoReconnect = autoReconnect
        try store.save(p)
        try Secrets.set(p.id, .password, "hunter2-pw")
        if otp == .totp { try Secrets.set(p.id, .totp, totpSecret) }
        return p
    }

    /// A manager on macOS 15.4 with a fake openconnect (an executable placeholder that is never run).
    func makeAnyConnectManager(
        _ fake: FakeOpenConnect, macOS: OperatingSystemVersion? = OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0)
    ) throws -> ConnectionManager {
        let m = makeManager()
        m.systemVersion = macOS
        m.toolRunner = fake
        let tool = URL(fileURLWithPath: home).appendingPathComponent("openconnect")
        if !FileManager.default.fileExists(atPath: tool.path) {
            try Data("#!/bin/sh\nexit 99\n".utf8).write(to: tool)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tool.path)
        }
        m.openConnectPath = tool.path
        return m
    }

    func openConnectStarts() -> [OpenConnectStart] {
        helper.starts.compactMap {
            if case .startOpenConnect(let s) = $0 { return s }
            return nil
        }
    }

    // MARK: the sign-in run

    func testSignInRunsOpenConnectWithTheConfigFileAndTheAnswersOnly() async throws {
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        fake.results = [Out.success]
        helper.startLog = Out.hookUp
        setenv("https_proxy", "http://proxy.example.com:3128", 1)
        setenv("SSLKEYLOGFILE", home + "/keys.log", 1)
        defer {
            unsetenv("https_proxy")
            unsetenv("SSLKEYLOGFILE")
        }
        let m = try makeAnyConnectManager(fake)
        try await m.connect(p.id)

        let code = try code(at: t0)
        XCTAssertEqual(fake.calls.count, 1)
        let call = try XCTUnwrap(fake.calls.first)
        XCTAssertEqual(call.path, m.openConnectPath)
        XCTAssertEqual(call.arguments, ["--config=" + call.configPath, "--authenticate"], "nothing else in argv")
        for secret in ["alice", "hunter2-pw", code, "Employees"] {
            XCTAssertFalse(call.arguments.joined(separator: " ").contains(secret), secret)
        }
        XCTAssertTrue(call.configPath.hasSuffix("/openconnect.conf"))
        XCTAssertTrue(((call.configPath as NSString).deletingLastPathComponent as NSString).lastPathComponent.hasPrefix("passtunnel-signin-"))
        XCTAssertEqual(call.configMode, 0o600)
        XCTAssertEqual(call.directoryMode, 0o700)
        XCTAssertFalse(FileManager.default.fileExists(atPath: call.configPath), "the config file is removed")
        XCTAssertFalse(FileManager.default.fileExists(atPath: (call.configPath as NSString).deletingLastPathComponent))
        XCTAssertEqual(
            call.config,
            """
            # Generated by PassTunnel. Do not edit.
            protocol anyconnect
            server https://vpn.example.com:8443/engineering
            user alice
            authgroup Employees
            servercert \(Out.pin)
            non-inter
            passwd-on-stdin
            no-external-auth

            """)
        XCTAssertEqual(call.input, Data("hunter2-pw\n\(code)\n".utf8), "the password, then the code")
        XCTAssertEqual(call.timeout, AnyConnectSignIn.defaultTimeout)
        XCTAssertEqual(call.environment, AnyConnectSignIn.environment)
        XCTAssertEqual(Set(call.environment.map { "\($0.key)=\($0.value)" }), Set(HelperCore.environment(for: .openconnect)))
        XCTAssertNil(call.environment["https_proxy"])
        XCTAssertNil(call.environment["SSLKEYLOGFILE"])
        XCTAssertEqual(call.environment["LC_ALL"], "C")
        XCTAssertEqual(call.environment["P11_KIT_NO_USER_CONFIG"], "1")
        #if os(macOS)
        XCTAssertEqual(call.environment["GNUTLS_SYSTEM_PRIORITY_FILE"], "/dev/null")
        #endif

        // Only the cookie and what the helper needs to bind the tunnel to the sign-in.
        let s = try XCTUnwrap(openConnectStarts().first)
        XCTAssertEqual(s.profileID, p.id)
        XCTAssertEqual(s.profileDir, store.dir(p.id).path)
        XCTAssertEqual(s.logPath, store.logURL(p.id).path)
        XCTAssertEqual([s.host, s.usergroup, s.connectURL], ["vpn.example.com", "engineering", "https://vpn.example.com:8443/"])
        XCTAssertEqual(s.port, 8443)
        XCTAssertEqual(s.resolve, "vpn.example.com:192.0.2.10")
        XCTAssertEqual(s.cookie, "webvpn=" + Out.cookie, "the value under its name (#212)")
        XCTAssertEqual(s.serverCert, Out.pin, "the key the sign-in accepted")
        XCTAssertEqual(s.profileServerCert, Out.pin, "the profile's own pin")
        XCTAssertEqual([s.tlsOnly, s.setDNS, s.setRoutes], [true, true, true])
        XCTAssertFalse(String(describing: helper.requests).contains(Out.cookie))
        let encoded = try XCTUnwrap(String(data: try HelperRequest.startOpenConnect(s).jsonData(), encoding: .utf8))
        XCTAssertFalse(encoded.contains("hunter2-pw") || encoded.contains("alice"), "no password or user name to root")

        guard case .connected(let ip, _) = m.state(p.id) else { return XCTFail("\(m.state(p.id))") }
        XCTAssertEqual(ip, "10.11.0.2")
        XCTAssertEqual(m.usedCode(p.id), .init(counter: TOTP.counter(params: p.totp, at: t0), period: 30), "the code is spent")
        let kinds = m.activity(p.id).map(\.kind)
        XCTAssertEqual(kinds.count, 4)
        guard case .connecting(let host, let port, _) = kinds.first else { return XCTFail("\(kinds)") }
        XCTAssertEqual(host, "vpn.example.com")
        XCTAssertEqual(port, 8443)
        guard case .sending(let sent) = kinds[1] else { return XCTFail("\(kinds)") }
        XCTAssertEqual(sent.username, "alice")
        XCTAssertTrue(sent.code)
        XCTAssertEqual(kinds[2], .authAccepted)
        XCTAssertEqual(kinds[3], .connected(address: "10.11.0.2"))

        // The poll keeps it connected from the hook's line; an exit is a drop.
        await m.refresh()
        XCTAssertTrue(m.state(p.id).isConnected)
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .disconnected)
    }

    /// #212: whatever shape openconnect printed, the helper gets the cookie under its name, and no log or error
    /// holds any part of it.
    func testTheCookieGoesToTheHelperUnderItsName() async throws {
        typealias C = OpenConnectCookieTests
        for (printed, sent) in [
            (C.ocservToken, "webvpn=" + C.ocservToken), (C.asaToken, "webvpn=" + C.asaToken), (C.strap, C.strap)
        ] {
            helper = FakeHelper()
            helper.startLog = Out.hookUp
            let p = try makeAnyConnect("Acme \(UUID().uuidString.prefix(8))")
            let fake = FakeOpenConnect()
            // A server that makes openconnect print each part.
            fake.results = [
                Out.output(stdout: Out.stdout(cookie: printed), stderr: Out.signedIn + "x \(C.strapKey)\ny \(C.ocservToken)\nz \(printed)\n")
            ]
            let m = try makeAnyConnectManager(fake)
            try await m.connect(p.id)
            XCTAssertEqual(openConnectStarts().first?.cookie, sent, printed)
            for part in OpenConnectCookie.secrets(sent) {
                XCTAssertFalse(String(describing: helper.requests).contains(part))
                XCTAssertFalse((m.lastErrorLog[p.id] ?? "").contains(part))
            }
        }
    }

    func testTheSignInLogHoldsNoPartOfTheCookie() async throws {
        typealias C = OpenConnectCookieTests
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        fake.results = [Out.output(stdout: Out.stdout(cookie: C.strap), stderr: Out.signedIn + "x \(C.strapKey)\ny \(C.ocservToken)\n")]
        helper.failStarts = 1
        let m = try makeAnyConnectManager(fake)
        do { try await m.connect(p.id); XCTFail("connected") } catch PTError.helperFailed {}
        let log = VPNLog.read(store.logURL(p.id))
        XCTAssertTrue(log.contains("x <redacted>\ny <redacted>\n"), log)
        XCTAssertFalse(log.contains(C.strapKey) || log.contains(C.ocservToken), log)
    }

    func testCombinedDeliverySendsOneLine() async throws {
        var p = try makeAnyConnect(delivery: .combined)
        p.otpTemplate = "{password}:{otp}"
        try store.save(p)
        let fake = FakeOpenConnect()
        fake.results = [Out.success]
        helper.startLog = Out.hookUp
        let m = try makeAnyConnectManager(fake)
        try await m.connect(p.id)
        XCTAssertEqual(fake.calls.first?.input, Data("hunter2-pw:\(try code(at: t0))\n".utf8))
    }

    func testWithoutACodeOnlyThePassword() async throws {
        let p = try makeAnyConnect(otp: .none, pin: "")
        let fake = FakeOpenConnect()
        fake.results = [Out.success]
        helper.startLog = Out.hookUp
        let m = try makeAnyConnectManager(fake)
        try await m.connect(p.id)
        let call = try XCTUnwrap(fake.calls.first)
        XCTAssertEqual(call.input, Data("hunter2-pw\n".utf8))
        // No pin: the system CA bundle, passed explicitly; the helper gets the key the sign-in accepted.
        XCTAssertTrue(call.config.contains("\nno-system-trust\ncafile /etc/ssl/cert.pem\n"), call.config)
        XCTAssertFalse(call.config.contains("servercert"))
        XCTAssertEqual(openConnectStarts().first?.serverCert, Out.pin)
        XCTAssertEqual(openConnectStarts().first?.profileServerCert, "")
        XCTAssertNil(m.usedCode(p.id))
    }

    /// An answer that would end its line (and so answer the next prompt) is refused before anything runs.
    func testAnAnswerWithALineBreakIsRefused() async throws {
        var p = try makeAnyConnect(otp: .ask)
        p.passwordMode = .ask
        try store.save(p)
        let fake = FakeOpenConnect()
        let m = try makeAnyConnectManager(fake)
        do {
            try await m.connect(p.id, given: [.password: "pw\nservercert x", .otp: "123456"])
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? PTError, .invalidField("password"))
        }
        XCTAssertTrue(fake.calls.isEmpty)
        XCTAssertTrue(helper.starts.isEmpty)
    }

    // MARK: the cookie

    func testTheCookieNeverReachesALogAnErrorOrTheActivity() async throws {
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        // A server could make openconnect print it (it is a bearer secret; openconnect at INFO does not).
        fake.results = [Out.output(stdout: Out.stdout(), stderr: Out.signedIn + "Set-Cookie: webvpn=\(Out.cookie); path=/\n\(Out.cookie)\n")]
        helper.failStarts = 1
        helper.failMessage = "refused"
        let m = try makeAnyConnectManager(fake)
        do { try await m.connect(p.id); XCTFail("connected") } catch PTError.helperFailed {}

        let log = VPNLog.read(store.logURL(p.id))
        XCTAssertTrue(log.contains("POST https://vpn.example.com:8443/engineering"), log)
        XCTAssertFalse(log.contains(Out.cookie), log)
        XCTAssertFalse(log.contains("hunter2-pw"))
        XCTAssertEqual(try mode(store.logURL(p.id)), 0o600)
        let failure = try XCTUnwrap(m.failures[p.id])
        XCTAssertEqual(failure.kind, .failed)
        XCTAssertTrue(failure.credentialsSent)
        XCTAssertTrue(failure.codeSent)
        let everything = [
            m.lastError[p.id] ?? "", m.lastErrorLog[p.id] ?? "", String(describing: failure),
            String(describing: helper.requests), (try? String(contentsOf: store.activityURL(p.id), encoding: .utf8)) ?? ""
        ].joined(separator: "\n")
        XCTAssertFalse(everything.contains(Out.cookie))
        XCTAssertFalse(everything.contains("hunter2-pw"))
        XCTAssertEqual(m.usedCode(p.id)?.counter, TOTP.counter(params: p.totp, at: t0), "the server had the code")
    }

    // MARK: failures of the sign-in

    func signInFailure(
        _ result: Result<ToolOutput, Error>, pin: String = Out.pin, file: StaticString = #filePath, line: UInt = #line
    ) async throws -> (error: Error, failure: ConnectionFailure, profile: Profile, manager: ConnectionManager) {
        let p = try makeAnyConnect("Acme \(UUID().uuidString.prefix(8))", pin: pin)
        let fake = FakeOpenConnect()
        fake.results = [result]
        let m = try makeAnyConnectManager(fake)
        do {
            try await m.connect(p.id)
            XCTFail("connected", file: file, line: line)
            throw PTError.connectCancelled
        } catch {
            XCTAssertTrue(openConnectStarts().isEmpty, "nothing went to the helper", file: file, line: line)
            return (error, try XCTUnwrap(m.failures[p.id], file: file, line: line), p, m)
        }
    }

    func testUnreachableServerGivesTheCodeBack() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.refused))
        XCTAssertEqual(
            r.error as? PTError,
            .serverUnreachable(server: "vpn.example.com:8443", reason: "Connection refused", log: VPNLog.tail(Out.refused)))
        XCTAssertEqual(r.failure.kind, .unreachable)
        XCTAssertEqual(r.failure.reason, "Connection refused")
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertFalse(r.failure.codeSent)
        XCTAssertNil(r.manager.usedCode(r.profile.id), "no form was sent: the code's period is given back")
        XCTAssertEqual(VPNLog.read(store.logURL(r.profile.id)), Out.refused, "the run's standard error is the log")
        XCTAssertTrue(r.error.localizedDescription.hasSuffix("Your sign-in was not sent."))
    }

    func testCapturedLocalRefusal() {
        let error = VPNLog.openConnectSignInError(
            Out.refusedLocally, status: 1, credentialsSent: false, authgroup: "", server: "127.0.0.1:47123")
        XCTAssertEqual(error, .serverUnreachable(server: "127.0.0.1:47123", reason: "Invalid argument", log: VPNLog.tail(Out.refusedLocally)))
    }

    func testHostNotFound() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.notFound))
        XCTAssertEqual(r.error as? PTError, .hostNotFound(server: "vpn.example.com:8443", log: VPNLog.tail(Out.notFound)))
        XCTAssertEqual(r.failure.kind, .hostNotFound)
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(r.manager.usedCode(r.profile.id))
    }

    /// No pin, and the CA bundle does not trust the server: openconnect's hint is the pin to offer trusting.
    func testUntrustedCertificateOffersThePin() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.untrusted), pin: "")
        XCTAssertEqual(
            r.error as? PTError, .serverCertificateRejected(reason: "signer not found", pin: Out.otherPin, log: VPNLog.tail(Out.untrusted)))
        XCTAssertEqual(r.failure.kind, .configuration)
        XCTAssertEqual(r.failure.reason, "signer not found")
        XCTAssertEqual(r.failure.serverCert, Out.otherPin)
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(r.manager.usedCode(r.profile.id))
        XCTAssertEqual(
            r.error.localizedDescription, "The server’s certificate was not trusted (signer not found). Your sign-in was not sent.")
        XCTAssertEqual(AutomationErrorCode.of(r.error), .connectFailed)
        let json = try JSONSerialization.jsonObject(with: try AutomationJSON.encoder().encode(r.failure)) as? [String: Any]
        XCTAssertEqual(json?["server_cert"] as? String, Out.otherPin, "the key to offer trusting")
    }

    func testPinMismatch() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.pinMismatch))
        XCTAssertEqual(
            r.error as? PTError,
            .serverCertificateRejected(reason: "not the pinned key", pin: Out.otherPin, log: VPNLog.tail(Out.pinMismatch)))
        XCTAssertEqual(r.failure.kind, .configuration)
        XCTAssertFalse(r.failure.credentialsSent)
    }

    /// With a pin that matches, openconnect still prints the CA check it then ignores: no failure.
    func testAMatchingPinIsNoCertificateFailure() {
        XCTAssertNil(VPNLog.openConnectCertificateFailure(VPNLog.openConnectBeforeServer(Out.signedIn)))
    }

    func testHostScanIsRefused() async throws {
        for stderr in [Out.hostScan, Out.csdTrojan] {
            let r = try await signInFailure(Out.output(status: 1, stderr: stderr))
            XCTAssertEqual(r.error as? PTError, .hostScanRequired(log: VPNLog.tail(stderr)))
            XCTAssertEqual(r.failure.kind, .hostScanRequired)
            XCTAssertFalse(r.failure.credentialsSent)
            XCTAssertEqual(
                r.error.localizedDescription,
                "The server requires a host scan (Cisco Secure Desktop), which PassTunnel does not run. Your sign-in was not sent.")
            XCTAssertFalse(ConnectionManager.isRetryable(r.error))
        }
    }

    func testRejectedSignInKeepsTheCodeSpentAndIsNotRetried() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.rejected))
        // The log as written: "Password:***" passes the redactor as any "password: …" does.
        XCTAssertEqual(r.error as? PTError, .authFailed(VPNLog.tail(VPNLog.read(store.logURL(r.profile.id)))))
        XCTAssertTrue(VPNLog.read(store.logURL(r.profile.id)).contains("Login failed."))
        XCTAssertEqual(r.failure.kind, .authRejected)
        XCTAssertTrue(r.failure.credentialsSent)
        XCTAssertTrue(r.failure.codeSent)
        XCTAssertEqual(r.manager.usedCode(r.profile.id)?.counter, TOTP.counter(params: r.profile.totp, at: t0))
        XCTAssertFalse(ConnectionManager.isRetryable(r.error))
        XCTAssertEqual(AutomationErrorCode.of(r.error), .credentialsRejected)
    }

    func testMoreAnswersThanGivenBeforeAnyForm() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.moreAnswers))
        XCTAssertEqual(r.error as? PTError, .signInNeedsMoreAnswers(log: VPNLog.tail(VPNLog.read(store.logURL(r.profile.id)))))
        XCTAssertEqual(r.failure.kind, .configuration)
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(r.manager.usedCode(r.profile.id))
    }

    func testUnknownGroup() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.noSuchGroup))
        XCTAssertEqual(r.error as? PTError, .invalidField("authgroup"))
        XCTAssertEqual(r.failure.kind, .configuration)
    }

    /// Once a form may have been submitted, whatever the rest of the output says (the server's text is in it),
    /// the sign-in counts as refused: not retried, not reported as unsent, the code kept as spent.
    func testAfterAFormEverythingIsARejection() async throws {
        let afterForm = Out.post + Out.tls + "XML POST enabled\n" + Out.post
        let cases = [
            Out.lostAfterForm,
            // A rejection message holding openconnect's own words, and a host scan asked for only now.
            afterForm + "Login failed.\nFailed to open HTTPS connection to vpn.example.com\n" + Out.failed,
            afterForm + "Error: Server asked us to run CSD hostscan.\nYou need to provide a suitable --csd-wrapper argument.\n" + Out.failed,
            afterForm + "getaddrinfo failed for host 'vpn.example.com': no\n" + Out.failed
        ]
        for stderr in cases {
            let r = try await signInFailure(Out.output(status: 1, stderr: stderr))
            XCTAssertEqual(r.error as? PTError, .authFailed(VPNLog.tail(VPNLog.read(store.logURL(r.profile.id)))), stderr)
            XCTAssertEqual(r.failure.kind, .authRejected)
            XCTAssertTrue(r.failure.credentialsSent)
            XCTAssertFalse(ConnectionManager.isRetryable(r.error))
            XCTAssertNotNil(r.manager.usedCode(r.profile.id), "the code stays spent")
        }
    }

    /// openconnect's messages count only as the whole lines it writes.
    func testMarkersCountOnlyAsOpenConnectsOwnLines() {
        func error(_ stderr: String) -> PTError {
            VPNLog.openConnectSignInError(stderr, status: 1, credentialsSent: false, authgroup: "Employees", server: "vpn.example.com")
        }
        let start = Out.post + Out.tls + "XML POST enabled\n"
        // Not the two exact lines: no host scan.
        let prefixed = start + "Notice: Error: Server asked us to run CSD hostscan.\nYou need to provide a suitable --csd-wrapper argument.\n"
        XCTAssertEqual(error(prefixed), .connectFailed(VPNLog.tail(prefixed)))
        let half = start + "Error: Server asked us to run CSD hostscan.\n" + Out.failed
        XCTAssertEqual(error(half), .connectFailed(VPNLog.tail(half)))
        // A CR inside the line makes it the server's text.
        let cr = start + "Error: Server asked us to run CSD hostscan.\r\nYou need to provide a suitable --csd-wrapper argument.\n"
        XCTAssertEqual(error(cr), .connectFailed(VPNLog.tail(cr)))
        // The exact two lines.
        XCTAssertEqual(error(Out.hostScan), .hostScanRequired(log: VPNLog.tail(Out.hostScan)))
        // Only the profile's own group, in openconnect's words.
        XCTAssertEqual(error(start + "Auth choice \"Employees\" not available\n"), .invalidField("authgroup"))
        let other = start + "Auth choice \"Staff\" not available\n"
        XCTAssertEqual(error(other), .connectFailed(VPNLog.tail(other)))
        // Network failures only before the server's first answer.
        let late = start + "Failed to connect to 192.0.2.10:8443: Connection refused\n"
        XCTAssertEqual(error(late), .connectFailed(VPNLog.tail(late)))
    }

    func testDyldStoppedTheTool() async throws {
        let r = try await signInFailure(Out.output(status: 134, stderr: Out.dyld))
        XCTAssertEqual(r.error as? PTError, .toolUnsupported(reason: "Symbol not found: _strchrnul", log: VPNLog.tail(Out.dyld)))
        XCTAssertEqual(r.failure.kind, .toolUnsupported)
        XCTAssertNil(r.manager.usedCode(r.profile.id))
    }

    /// A run stopped at the deadline: what it did last is unknown, so the code counts as sent.
    func testATimeoutKeepsTheCodeSpent() async throws {
        for stderr in [Out.post, Out.post + Out.tls + Out.post] {
            let r = try await signInFailure(.failure(ToolTimeout(seconds: 60, errorOutput: Data(stderr.utf8))))
            XCTAssertEqual(r.error as? PTError, .connectTimeout(60))
            XCTAssertEqual(r.failure.kind, .timeout)
            XCTAssertTrue(r.failure.credentialsSent)
            XCTAssertNotNil(r.manager.usedCode(r.profile.id))
            XCTAssertEqual(VPNLog.read(store.logURL(r.profile.id)), stderr)
        }
    }

    /// A banner past the log's limit does not hide the form that was submitted after it.
    func testSubmissionsAreCountedOverTheWholeOutput() async throws {
        let banner = (0..<2000).map { "Banner line \($0): " + String(repeating: "x", count: 60) }.joined(separator: "\n") + "\n"
        let stderr = Out.post + Out.tls + "XML POST enabled\n" + banner + Out.post + "Login failed.\n" + Out.failed
        XCTAssertGreaterThan(stderr.utf8.count, AnyConnectSignIn.maxLogBytes)
        let r = try await signInFailure(Out.output(status: 1, stderr: stderr))
        XCTAssertEqual(r.failure.kind, .authRejected)
        XCTAssertTrue(r.failure.credentialsSent)
        XCTAssertNotNil(r.manager.usedCode(r.profile.id))
        let log = VPNLog.read(store.logURL(r.profile.id))
        XCTAssertLessThanOrEqual(log.utf8.count, AnyConnectSignIn.maxLogBytes)
        XCTAssertFalse(log.contains("Login failed."), "cut, but counted")
        XCTAssertTrue(log.hasSuffix("x\n"), "whole lines only")

        // Standard error beyond what is kept: evidence missing, so sent.
        var cut = ToolOutput(status: 1, output: Data(), errorOutput: Data(Out.refused.utf8))
        cut.errorOutputCut = true
        let truncated = try await signInFailure(.success(cut))
        XCTAssertEqual(truncated.failure.kind, .authRejected)
        XCTAssertTrue(truncated.failure.credentialsSent)
        XCTAssertNotNil(truncated.manager.usedCode(truncated.profile.id))
    }

    /// A secret across the log's limit is masked before the cut, never left in part.
    func testASecretAtTheCutIsMaskedWhole() {
        let filler = String(repeating: "y", count: AnyConnectSignIn.maxLogBytes - 20) + "\n"
        let stderr = Data((filler + "Server says: hunter2-pw echoed\nnext\n").utf8)
        let log = AnyConnectSignIn.log(AnyConnectSignIn.redacted(stderr, secrets: ["hunter2-pw"]))
        XCTAssertFalse(log.contains("hunter2"), String(log.suffix(80)))
        XCTAssertEqual(log, filler, "the incomplete last line is dropped")
        let short = AnyConnectSignIn.log(AnyConnectSignIn.redacted(Data("a hunter2-pw b\n".utf8), secrets: ["hunter2-pw"]))
        XCTAssertEqual(short, "a <redacted> b\n")
    }

    /// owner decision 2: a sign-in that ended on another server is not used; the cookie goes nowhere.
    func testASignInEndingOnAnotherServerIsRefused() async throws {
        let cases: [(String, String)] = [
            (Out.stdout(connectURL: "https://vpn2.example.com:8443/"), "another server"),
            (Out.stdout(connectURL: "https://vpn.example.com/"), "another server"),
            (Out.stdout(fingerprint: Out.otherPin), "pinned key"),
            (Out.stdout(resolve: "vpn2.example.com:192.0.2.10"), "address"),
            (Out.stdout(host: "192.0.2.99"), "address")
        ]
        for (stdout, words) in cases {
            let r = try await signInFailure(Out.output(stdout: stdout, stderr: Out.signedIn))
            guard case .signInUnusable(let reason)? = r.error as? PTError else { return XCTFail("\(r.error)") }
            XCTAssertTrue(reason.contains(words), reason)
            XCTAssertFalse(reason.contains(Out.cookie))
            XCTAssertEqual(r.failure.kind, .failed)
            XCTAssertTrue(r.failure.credentialsSent)
            XCTAssertFalse(ConnectionManager.isRetryable(r.error))
            XCTAssertFalse(VPNLog.read(store.logURL(r.profile.id)).contains(Out.cookie))
        }
    }

    func testMalformedOutputIsRefusedWithoutItsValues() async throws {
        let r = try await signInFailure(Out.output(stdout: "COOKIE='\(Out.cookie)'\nHOST='x'\n", stderr: Out.signedIn))
        guard case .signInUnusable(let reason)? = r.error as? PTError else { return XCTFail("\(r.error)") }
        XCTAssertFalse(reason.contains(Out.cookie))
        XCTAssertFalse(r.error.localizedDescription.contains(Out.cookie))
        XCTAssertFalse(String(describing: r.failure).contains(Out.cookie))
    }

    // MARK: cancelling and the time limit

    func testDisconnectStopsASignInUnderWay() async throws {
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        fake.blockUntilCancelled = true
        let m = try makeAnyConnectManager(fake)
        let task = Task { try await m.connect(p.id) }
        await waitUntil { fake.calls.count == 1 }
        XCTAssertEqual(m.state(p.id), .connecting(ConnectionManager.Phase.signingIn))
        try await m.disconnect(p.id)
        do {
            try await task.value
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? PTError, .connectCancelled)
        }
        XCTAssertTrue(fake.sawCancel)
        XCTAssertTrue(openConnectStarts().isEmpty)
        XCTAssertEqual(m.failures[p.id]?.kind, .cancelled)
        XCTAssertNotNil(m.usedCode(p.id), "after a cancel the code is not given back")
        XCTAssertFalse(m.isBusyForTests(p.id))
    }

    // MARK: the tunnel run

    func testAFailedHookIsASetupFailure() async throws {
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        fake.results = [Out.success]
        helper.startLog = Out.hookFailed
        let reason = "INTERNAL_IP4_DNS is not a list of IPv4 and IPv6 addresses"
        helper.openConnectTunnel = TunnelStatus(state: .failed, reason: reason, interface: "utun5")
        let m = try makeAnyConnectManager(fake)
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(error as? PTError, .setupFailed(reason: reason, log: VPNLog.tail(Out.hookFailed)))
        }
        XCTAssertEqual(m.failures[p.id]?.kind, .setup)
        XCTAssertEqual(helper.stops, [p.id], "stopped")
        XCTAssertEqual(m.state(p.id), .disconnected)
    }

    func testCookieRejectedByTheTunnelRun() async throws {
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        fake.results = [Out.success]
        let log = "Got inappropriate HTTP CONNECT response: HTTP/1.1 401 Unauthorized\nCookie was rejected by server; exiting.\n"
        helper.startLog = log
        helper.exitAtStart = true
        let m = try makeAnyConnectManager(fake)
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(error as? PTError, .connectFailed(VPNLog.tail(log)))
        }
        XCTAssertEqual(m.failures[p.id]?.kind, .failed)
        XCTAssertEqual(m.failures[p.id]?.credentialsSent, true)
        XCTAssertTrue(ConnectionManager.isRetryable(PTError.connectFailed("")), "a reconnect signs in afresh")
    }

    func testTheTunnelThatNeverComesUpTimesOut() async throws {
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        fake.results = [Out.success]
        helper.startLog = "Got CONNECT response: HTTP/1.1 200 OK\n"
        helper.openConnectTunnel = TunnelStatus(state: .settingUp)
        let m = try makeAnyConnectManager(fake)
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(error as? PTError, .connectTimeout(90))
        }
        XCTAssertEqual(m.failures[p.id]?.kind, .timeout)
        XCTAssertEqual(helper.stops, [p.id])
    }

    /// A drop (the server ended the session, or the hook refused openconnect's own reconnect and stopped it)
    /// is reconnected like the other types: a new sign-in, with a code from the next window.
    func testADropSignsInAgainWithAFreshCode() async throws {
        let p = try makeAnyConnect(autoReconnect: true)
        let fake = FakeOpenConnect()
        fake.results = [Out.success]
        helper.startLog = Out.hookUp
        let m = try makeAnyConnectManager(fake)
        try await m.connect(p.id)
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(events.first, .dropped(profileID: p.id, willReconnect: true))
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events.last, .reconnected(profileID: p.id))
        XCTAssertEqual(fake.calls.count, 2)
        XCTAssertEqual(openConnectStarts().count, 2)
        let first = try code(at: t0)
        let second = String(decoding: fake.calls[1].input, as: UTF8.self)
        XCTAssertTrue(second.hasPrefix("hunter2-pw\n"))
        XCTAssertNotEqual(second, "hunter2-pw\n\(first)\n", "a code from the next window")
        XCTAssertTrue(clock.sleeps.contains { $0 > 4 && $0 < 6 && $0 != 5 }, "waited for the next window: \(clock.sleeps)")
    }

    func testFollowsASessionAnotherProcessStarted() async throws {
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        let m = try makeAnyConnectManager(fake)
        try Data(Out.hookUp.utf8).write(to: store.logURL(p.id))
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        helper.setTunnel(p.id, TunnelStatus(state: .up, interface: "utun5"))
        try await m.connect(p.id)
        XCTAssertTrue(fake.calls.isEmpty, "no second sign-in")
        guard case .connected(let ip, _) = m.state(p.id) else { return XCTFail("\(m.state(p.id))") }
        XCTAssertEqual(ip, "10.11.0.2")
    }

    /// The log is partly the server's: a line that looks like the hook's (after a CR in the CONNECT reply's
    /// status line, or on a line of its own) neither connects nor fails the session. The helper's report does.
    func testTheLogNeverDecidesTheSessionsState() async throws {
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        fake.results = [Out.success]
        helper.startLog =
            "Got CONNECT response: HTTP/1.1 200 OK\rpasstunnel vpn-hook: utun9 up: 10.0.0.9, 0 routes\r\n"
            + "passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes, DNS 10.11.0.53, search example.com, split DNS corp.example.com\n"
        helper.openConnectTunnel = TunnelStatus(state: .settingUp)
        let m = try makeAnyConnectManager(fake)
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(error as? PTError, .connectTimeout(90), "not connected by the log")
        }

        // Up by the helper's report, though the log's last line is a failure line.
        let q = try makeAnyConnect("Acme 2")
        helper.startLog = Out.hookUp + "passtunnel vpn-hook: setting up the network failed: forged\n"
        helper.openConnectTunnel = TunnelStatus(state: .up, interface: "utun5")
        try await m.connect(q.id)
        XCTAssertEqual(m.state(q.id).isConnected, true)

        // The address shown is the log's only for the interface the helper reported.
        let r = try makeAnyConnect("Acme 3")
        helper.startLog = Out.hookUp
        helper.openConnectTunnel = TunnelStatus(state: .up, interface: "utun7")
        try await m.connect(r.id)
        guard case .connected(let ip, _) = m.state(r.id) else { return XCTFail("\(m.state(r.id))") }
        XCTAssertEqual(ip, "")
    }

    /// The poll: connected while the helper reports the record up (or cannot read it for a moment), not once
    /// it reports a failure.
    func testThePollFollowsTheHelpersReport() async throws {
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        fake.results = [Out.success]
        helper.startLog = Out.hookUp
        let m = try makeAnyConnectManager(fake)
        try await m.connect(p.id)
        helper.setTunnel(p.id, TunnelStatus(state: .reconnecting, interface: "utun5"))
        await m.refresh()
        XCTAssertTrue(m.state(p.id).isConnected)
        helper.setTunnel(p.id, TunnelStatus(state: .unknown))
        await m.refresh()
        XCTAssertTrue(m.state(p.id).isConnected, "a record being written keeps the state")
        helper.setTunnel(p.id, TunnelStatus(state: .failed, reason: "the network changed", interface: "utun5"))
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .connecting(ConnectionManager.Phase.configuring))
    }

    // MARK: the macOS 15.4 and Linux gates

    func testBelowMacOS154NothingIsAskedOrRun() async throws {
        var plain = try makeAnyConnect()
        let fake = FakeOpenConnect()
        fake.results = [Out.success]
        let m = try makeAnyConnectManager(fake, macOS: OperatingSystemVersion(majorVersion: 15, minorVersion: 3, patchVersion: 9))
        var p = plain
        p.requireAuth = .connect
        try await m.vault.applyProtection(from: plain, to: p)
        try store.save(p)
        plain = p

        let requestsBefore = helper.requests.count
        let attempts: [() async throws -> Void] = [
            { try await m.connect(p.id) },
            { try await m.connect(p.id, followOnly: true) },
            { try await m.connect(p.id, interactive: false) },
            { _ = try await m.checkCanStart(p.id) }
        ]
        for (n, attempt) in attempts.enumerated() {
            do {
                try await attempt()
                XCTFail("attempt \(n) went ahead")
            } catch {
                XCTAssertEqual(error as? PTError, .anyConnectRequiresMacOS("15.4"), "attempt \(n)")
                XCTAssertEqual(error.localizedDescription, "Cisco AnyConnect requires macOS 15.4 or later.")
                XCTAssertEqual(AutomationErrorCode.of(error), .configInvalid)
            }
        }
        XCTAssertEqual(authenticator.calls, 0, "no Touch ID")
        XCTAssertFalse(m.vault.isUnlocked(p.id, .password))
        XCTAssertEqual(helper.requests.count, requestsBefore, "the helper was not asked anything")
        XCTAssertTrue(fake.calls.isEmpty)
        XCTAssertEqual(m.connectRefusal(.anyconnect), .anyConnectRequiresMacOS("15.4"))
        XCTAssertNil(m.connectRefusal(.forti))
        XCTAssertEqual(ConnectionFailure.of(PTError.anyConnectRequiresMacOS("15.4"), log: nil, handed: nil, at: t0).kind, .toolUnsupported)
    }

    func testTheMacOSGate() {
        func refusal(_ major: Int, _ minor: Int, _ patch: Int = 0) -> PTError? {
            let version = OperatingSystemVersion(majorVersion: major, minorVersion: minor, patchVersion: patch)
            return ConnectionManager.connectRefusal(.anyconnect, macOS: version)
        }
        XCTAssertEqual(refusal(13, 0), .anyConnectRequiresMacOS("15.4"))
        XCTAssertEqual(refusal(14, 7, 6), .anyConnectRequiresMacOS("15.4"))
        XCTAssertEqual(refusal(15, 3, 2), .anyConnectRequiresMacOS("15.4"))
        XCTAssertNil(refusal(15, 4))
        XCTAssertNil(refusal(15, 7, 1))
        XCTAssertNil(refusal(26, 0))
        for type in [VPNType.openvpn, .forti] {
            XCTAssertNil(ConnectionManager.connectRefusal(type, macOS: nil))
            XCTAssertNil(ConnectionManager.connectRefusal(type, macOS: OperatingSystemVersion(majorVersion: 13, minorVersion: 0, patchVersion: 0)))
        }
        // Linux (no macOS) refuses nothing up front: the distribution's openconnect is checked at the sign-in.
        XCTAssertNil(ConnectionManager.connectRefusal(.anyconnect, macOS: nil))
        #if os(macOS)
        XCTAssertNotNil(ConnectionManager.currentMacOS)
        #else
        XCTAssertNil(ConnectionManager.currentMacOS)
        XCTAssertNil(ConnectionManager.connectRefusal(.anyconnect))
        #endif
    }

    /// Linux: the sign-in runs the distribution's openconnect that `locateOpenConnect` found and checked, with
    /// its CA bundle, and `no-external-auth` only when that openconnect lists it (9.10 and later).
    func testLinuxSignsInWithTheDistributionTool() async throws {
        for noExternalAuth in [false, true] {
            let p = try makeAnyConnect(noExternalAuth ? "Acme 9.12" : "Acme 9.01", pin: "")
            let fake = FakeOpenConnect()
            fake.results = [Out.output(stdout: Out.stdout(), stderr: Out.signedIn)]
            helper.startLog = Out.hookUp
            let m = try makeAnyConnectManager(fake, macOS: nil)
            // The distribution's path in real life; an executable placeholder here (never run).
            let distribution = try XCTUnwrap(m.openConnectPath)
            m.openConnectPath = nil
            var lookups = 0
            m.locateOpenConnect = { runner in
                lookups += 1
                XCTAssertTrue(runner as AnyObject === fake, "the manager's runner")
                return AnyConnectSignIn.Tool(
                    path: distribution, caFile: "/etc/ssl/certs/ca-certificates.crt", noExternalAuth: noExternalAuth)
            }
            try await m.connect(p.id)
            XCTAssertEqual(lookups, 1)
            let call = try XCTUnwrap(fake.calls.first)
            XCTAssertEqual(call.path, distribution)
            XCTAssertTrue(call.config.contains("no-system-trust\ncafile /etc/ssl/certs/ca-certificates.crt\n"), call.config)
            XCTAssertEqual(call.config.contains("no-external-auth"), noExternalAuth, call.config)
            XCTAssertEqual(openConnectStarts().last?.profileID, p.id)
        }
    }

    /// Linux: an openconnect that is missing or too old (Ubuntu 22.04's 8.20) is refused with the reason before
    /// anything is run, the code used or the daemon asked.
    func testLinuxRefusesAnOldOpenConnectBeforeTheCode() async throws {
        let p = try makeAnyConnect()
        let fake = FakeOpenConnect()
        let m = try makeAnyConnectManager(fake, macOS: nil)
        m.openConnectPath = nil
        let reason = ToolFailure.tooOld(
            name: "openconnect", version: ToolVersion(8, 20, twoDigitMinor: true), minimum: ToolSpec.openconnect.minimum,
            package: "openconnect")
        m.locateOpenConnect = { _ in throw PTError.anyConnectToolUnavailable(reason.description) }
        let before = helper.requests.count
        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(error as? PTError, .anyConnectToolUnavailable(reason.description))
            XCTAssertEqual(
                error.localizedDescription,
                "Cisco AnyConnect cannot be used here: openconnect 8.20 is too old: PassTunnel needs 9.01 or later. Update the openconnect package.")
        }
        XCTAssertEqual(helper.requests.filter { if case .startOpenConnect = $0 { return true } else { return false } }.count, 0)
        XCTAssertLessThanOrEqual(helper.requests.count, before + 1, "at most the status")
        XCTAssertTrue(fake.calls.isEmpty, "no sign-in ran")
        XCTAssertNil(m.usedCode(p.id), "the code is unused")
    }
}

// MARK: - Log parsing and redaction

final class OpenConnectLogTests: XCTestCase {
    typealias Out = OpenConnectOutput

    func testHookLinesForDisplay() {
        XCTAssertNil(VPNLog.openConnectHook("Got CONNECT response: HTTP/1.1 200 OK\nConfigured as 10.11.0.2\n"))
        guard case .up(let report)? = VPNLog.openConnectHook(Out.hookUp) else { return XCTFail() }
        XCTAssertEqual(report.interface, "utun5")
        XCTAssertEqual(report.dnsServers.map(\.description), ["10.11.0.53"])
        XCTAssertEqual(VPNLog.openConnectAddress(Out.hookUp, interface: "utun5"), "10.11.0.2")
        XCTAssertEqual(VPNLog.openConnectAddress(Out.hookUp, interface: "utun6"), "")
        XCTAssertNil(VPNLog.tunnelInterface(Out.hookUp), "the helper names the interface, not the log")
        XCTAssertTrue(VPNLog.openConnectIsUp(Out.hookUp))
        let later = Out.hookUp + "passtunnel vpn-hook: setting up the network failed: the network changed\n"
        XCTAssertEqual(VPNLog.openConnectHook(later), .failed(reason: "the network changed"))
        XCTAssertTrue(VPNLog.openConnectIsUp(later + Out.hookUp))
        // Only whole LF lines of printable ASCII: a CR (the server's text) or text in front does not count.
        XCTAssertNil(VPNLog.openConnectHook("Got CONNECT response: HTTP/1.1 200 OK\rpasstunnel vpn-hook: utun9 up: 10.0.0.9, 0 routes\r\n"))
        XCTAssertNil(VPNLog.openConnectHook("x\rpasstunnel vpn-hook: setting up the network failed: forged\n"))
        XCTAssertNil(VPNLog.openConnectHook("Got CONNECT response: passtunnel vpn-hook: utun9 up: 10.0.0.9, 0 routes\n"))
        XCTAssertNil(VPNLog.openConnectHook("passtunnel vpn-hook: utun9 up: 10.0.0.9, 0 routes, nonsense\n"))
        XCTAssertNil(VPNLog.openConnectHook(VPNHook.endedLine))
    }

    func testPostsCountWhereverTheyStand() {
        XCTAssertEqual(VPNLog.openConnectPosts(Out.refused), 1)
        XCTAssertFalse(VPNLog.openConnectCredentialsSent(Out.untrusted))
        XCTAssertEqual(VPNLog.openConnectPosts(Out.signedIn), 3)
        // A text prompt is printed without a line break; the next request follows it on its line.
        XCTAssertTrue(VPNLog.openConnectCredentialsSent(Out.post + Out.tls + "Answer:" + Out.post))
    }

    func testOnlyOpenConnectsOwnLinesBeforeTheServerAnswered() {
        // After the TLS session the server's text could imitate a certificate failure: not read.
        let forged = Out.post + Out.tls + Out.untrusted
        XCTAssertNil(VPNLog.openConnectCertificateFailure(VPNLog.openConnectBeforeServer(forged)))
        XCTAssertNil(VPNLog.openConnectUnreached(VPNLog.openConnectBeforeServer(Out.post + Out.tls + Out.refused)))
    }

    func testCookieRedaction() {
        let r = LogRedactor(secrets: [])
        XCTAssertEqual(r.redact("COOKIE='\(Out.cookie)'"), "COOKIE=<redacted>")
        XCTAssertEqual(r.redact("Set-Cookie: webvpn=\(Out.cookie); path=/; secure"), "Set-Cookie: <redacted>")
        XCTAssertEqual(r.redact("Cookie: webvpn=\(Out.cookie)"), "Cookie: <redacted>")
        XCTAssertEqual(r.redact("cookie \(Out.cookie)"), "cookie <redacted>")
        XCTAssertEqual(r.redact("sent webvpn=\(Out.cookie); webvpnc=bu:/&p:t"), "sent webvpn=<redacted>; webvpnc=<redacted>")
        XCTAssertEqual(r.redact("openconnect_strapkey=abc; webvpn=def"), "openconnect_strapkey=<redacted>; webvpn=<redacted>")
        // openconnect's own messages and the pins stay.
        XCTAssertEqual(r.redact("Cookie was rejected by server; exiting."), "Cookie was rejected by server; exiting.")
        XCTAssertEqual(r.redact("    --servercert \(Out.pin)"), "    --servercert \(Out.pin)")
        XCTAssertFalse(LogRedactor.isKeyMaterial("    --servercert \(Out.pin)"))
        XCTAssertEqual(LogRedactor(secrets: [Out.cookie]).redact("x \(Out.cookie) y"), "x <redacted> y")
    }

    func testSignInLogIsRedactedAndBounded() {
        let stderr = Data(("Password: hunter2-pw\nline \(Out.cookie)\n" + String(repeating: "x", count: 100_000)).utf8)
        let log = AnyConnectSignIn.log(AnyConnectSignIn.redacted(stderr, secrets: ["hunter2-pw", Out.cookie]))
        XCTAssertFalse(log.contains("hunter2-pw"))
        XCTAssertFalse(log.contains(Out.cookie))
        XCTAssertEqual(log, "Password: <redacted>\nline <redacted>\n", "the long incomplete line is dropped")
    }

    func testOutputMask() {
        XCTAssertEqual(
            OutputMask.apply("Got CONNECT response: HTTP/1.1 200 \(Out.cookie)", secrets: [Out.cookie]),
            "Got CONNECT response: HTTP/1.1 200 <redacted>")
        XCTAssertEqual(OutputMask.apply("Set-Cookie: webvpn=abc; path=/"), "Set-Cookie: <redacted>")
        XCTAssertEqual(OutputMask.apply("x webvpn=abcdef;"), "x webvpn=<redacted>;")
        XCTAssertEqual(OutputMask.apply("cookie \(Out.cookie)"), "cookie <redacted>")
        XCTAssertEqual(OutputMask.apply("Cookie was rejected by server; exiting."), "Cookie was rejected by server; exiting.")
        XCTAssertEqual(OutputMask.apply("passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes"), "passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes")
    }

    /// Writes `parts` into a pipe that a copier drains (writing on another thread, so a test fails rather than
    /// hangs when the copier stops draining); returns what reached the log.
    func copy(_ parts: [String], copier configure: (MaskingCopier) -> Void = { _ in }, release: (() -> Void)? = nil) throws -> String {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&fds), 0)
        let logURL = FileManager.default.temporaryDirectory.appendingPathComponent("mask-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: logURL) }
        let logFD = open(logURL.path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        XCTAssertGreaterThanOrEqual(logFD, 0)
        let copier = MaskingCopier(readFD: fds[0], logFD: logFD, secrets: [Out.cookie])
        configure(copier)
        let done = expectation(description: "copied")
        Thread {
            copier.run()
            done.fulfill()
        }.start()
        let written = expectation(description: "the tool's writes all went through")
        let writeFD = fds[1]
        Thread {
            for part in parts {
                let bytes = Array(part.utf8)
                var offset = 0
                while offset < bytes.count {
                    let n = bytes[offset...].withUnsafeBytes { write(writeFD, $0.baseAddress, $0.count) }
                    guard n > 0 else { break }
                    offset += n
                }
            }
            close(writeFD)
            written.fulfill()
        }.start()
        wait(for: [written], timeout: 10)
        release?()
        wait(for: [done], timeout: 10)
        return try String(contentsOf: logURL, encoding: .utf8)
    }

    /// The helper's copy of openconnect's output into the log: whole lines, each masked; an overlong line is
    /// replaced as a whole, and an unterminated last line is not written.
    func testMaskingCopier() throws {
        let long = String(repeating: "z", count: MaskingCopier.maxLineBytes + 100)
        let written = try copy([
            "Got CONNECT response: HTTP/1.1 200 \(Out.cookie)\n" + "a " + String(Out.cookie.prefix(10)),
            String(Out.cookie.dropFirst(10)) + " b\n", long + "\(Out.cookie)\nnext\nunfinished \(Out.cookie.prefix(8))"
        ])
        XCTAssertFalse(written.contains(Out.cookie))
        XCTAssertFalse(written.contains(String(Out.cookie.prefix(8))), "split across reads, masked whole; the unfinished line dropped")
        XCTAssertEqual(
            written,
            "Got CONNECT response: HTTP/1.1 200 <redacted>\na <redacted> b\n\(MaskingCopier.overlongMarker)\nnext\n")
    }

    /// A bare cookie that runs over the 16 KiB limit leaves nothing of itself: the line is replaced whole.
    func testACookieOverTheLineLimitLeavesNoPrefix() throws {
        for before in [MaskingCopier.maxLineBytes - 10, MaskingCopier.maxLineBytes - 1, MaskingCopier.maxLineBytes] {
            let written = try copy([String(repeating: "w", count: before) + Out.cookie + " tail\n", "after\n"])
            XCTAssertFalse(written.contains(String(Out.cookie.prefix(4))), "\(before)")
            XCTAssertFalse(written.contains("w"))
            XCTAssertEqual(written, MaskingCopier.overlongMarker + "\nafter\n")
        }
        // Exactly at the limit, the line is kept, and masked.
        let exact = String(repeating: "v", count: MaskingCopier.maxLineBytes - Out.cookie.utf8.count) + Out.cookie
        XCTAssertEqual(try copy([exact + "\n"]), String(repeating: "v", count: MaskingCopier.maxLineBytes - Out.cookie.utf8.count) + "<redacted>\n")
    }

    /// A log that does not take writes (a stalled file system) never holds the tool up: the pipe is drained,
    /// lines past the queue's bound are dropped, and the log says how many.
    func testAStalledLogNeverBlocksTheTool() throws {
        let gate = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var lines: [String] = []
        let count = MaskingCopier.maxQueuedLines * 3
        let parts = (0..<count).map { "line \($0) " + String(repeating: "p", count: 100) + "\n" }
        _ = try copy(
            parts,
            copier: { copier in
                var first = true
                copier.writeLine = { _, bytes in
                    if first {
                        first = false
                        gate.wait()  // the log stalls until the tool has written everything
                    }
                    lock.lock()
                    lines.append(String(decoding: bytes, as: UTF8.self))
                    lock.unlock()
                }
            },
            release: { gate.signal() })
        lock.lock()
        defer { lock.unlock() }
        let markers = lines.filter { $0.hasPrefix("[") }
        XCTAssertEqual(markers.count, 1, "\(markers)")
        let dropped = Int(markers[0].dropFirst().prefix { $0.isNumber }) ?? 0
        XCTAssertGreaterThan(dropped, 0)
        XCTAssertEqual(lines.count - 1 + dropped, count, "every line written or counted")
        XCTAssertEqual(markers[0], MaskingCopier.droppedMarker(dropped) + "\n")
    }

    /// Only complete lines are stored or read: an unterminated last line changes nothing.
    func testAnUnterminatedLastLineIsNeitherStoredNorRead() {
        XCTAssertEqual(AnyConnectSignIn.log("complete\npartial"), "complete\n")
        XCTAssertEqual(AnyConnectSignIn.log("complete\n"), "complete\n")
        XCTAssertEqual(AnyConnectSignIn.log("partial"), "")
        let start = Out.post + Out.tls + "XML POST enabled\n"
        let unterminated = start + "User input required in non-interactive mode"
        XCTAssertEqual(
            VPNLog.openConnectSignInError(unterminated, status: 1, credentialsSent: false, authgroup: "", server: "vpn.example.com"),
            .connectFailed(VPNLog.tail(unterminated)))
        let hostScan = start + "Error: Server asked us to run CSD hostscan.\nYou need to provide a suitable --csd-wrapper argument."
        XCTAssertEqual(
            VPNLog.openConnectSignInError(hostScan, status: 1, credentialsSent: false, authgroup: "", server: "vpn.example.com"),
            .connectFailed(VPNLog.tail(hostScan)))
        XCTAssertNil(VPNLog.openConnectHook("passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes"))
        XCTAssertNotNil(VPNLog.openConnectHook("passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes\n"))
    }

    /// The helper's report of a session's network, from the hook's record, never from the log.
    func testTunnelStatusFromTheRecord() throws {
        let runDir = FileManager.default.temporaryDirectory.appendingPathComponent("oc-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: runDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: runDir) }
        XCTAssertEqual(HelperCore.tunnelStatus(runDir: runDir), TunnelStatus(state: .settingUp))
        let journal = try OpenConnectJournal.create(runDir: runDir, interface: "utun5")
        XCTAssertEqual(HelperCore.tunnelStatus(runDir: runDir), TunnelStatus(state: .settingUp, interface: "utun5"))
        try journal.append(.status(.up))
        XCTAssertEqual(HelperCore.tunnelStatus(runDir: runDir), TunnelStatus(state: .up, interface: "utun5"))
        try journal.append(.status(.reconnecting))
        XCTAssertTrue(HelperCore.tunnelStatus(runDir: runDir).isUp)
        try journal.append(.status(.failed("the network changed")))
        XCTAssertEqual(
            HelperCore.tunnelStatus(runDir: runDir), TunnelStatus(state: .failed, reason: "the network changed", interface: "utun5"))
        try Data("garbage".utf8).write(to: URL(fileURLWithPath: OpenConnectJournal.path(runDir: runDir)))
        XCTAssertEqual(HelperCore.tunnelStatus(runDir: runDir).state, .unknown)

        // In the reply, an optional key: a reply without it reads as before.
        let reply = HelperResponse.success(running: ["acme": 42], tunnels: ["acme": TunnelStatus(state: .up, interface: "utun5")])
        XCTAssertEqual(try HelperResponse(jsonData: try reply.jsonData()), reply)
        let json = String(decoding: try reply.jsonData(), as: UTF8.self)
        XCTAssertTrue(json.contains(#""tunnels":{"acme":{"interface":"utun5","state":"up"}}"#), json)
        XCTAssertNil(try HelperResponse(jsonData: Data(#"{"ok":true,"running":{}}"#.utf8)).tunnels)
    }

    /// What a session takes over, for the overlap check: from the hook's line and the routes through its
    /// interface.
    func testNetworkClaims() throws {
        let report = try XCTUnwrap(
            VPNHook.Report.parse(
                "passtunnel vpn-hook: utun5 up: 10.11.0.2, 2001:db8:1::2, 4 routes, full tunnel, DNS 10.11.0.53, search example.com, split DNS corp.example.com"
            ))
        let routes = [
            RoutingTable.Route(destination: "10.20.0.0", prefixLength: 16, interface: "utun5"),
            RoutingTable.Route(destination: "10.11.0.2", prefixLength: 32, interface: "utun5")
        ]
        let options = ProfileNetwork.anyConnectOptions(report, routes: routes)
        XCTAssertEqual(
            options,
            [
                "redirect-gateway def1 ipv6", "dhcp-option DNS 10.11.0.53", "dhcp-option DOMAIN example.com",
                "dhcp-option DOMAIN-ROUTE corp.example.com", "route 10.20.0.0 255.255.0.0"
            ])
        let claims = OVPNAnalyzer.networkClaims("", pushed: options)
        XCTAssertTrue(claims.fullTunnel)
        XCTAssertTrue(claims.fullTunnelIPv6)
        XCTAssertEqual(claims.dnsServers, ["10.11.0.53"])
        XCTAssertEqual(claims.dnsDomains, ["corp.example.com"])

        let split = try XCTUnwrap(VPNHook.Report.parse("passtunnel vpn-hook: utun6 up: 10.11.0.2, 1 route"))
        XCTAssertEqual(ProfileNetwork.anyConnectOptions(split, routes: []), [])
    }
}

extension ToolRunnerTests {
    func testCancellationStopsTheTool() throws {
        let cancellation = ToolCancellation()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { cancellation.cancel() }
        let start = Date()
        XCTAssertThrowsError(
            try runner.run("/bin/sleep", ["30"], environment: [:], input: Data(), timeout: 20, cancellation: cancellation)
        ) { XCTAssertTrue($0 is ToolCancelled, "\($0)") }
        XCTAssertLessThan(Date().timeIntervalSince(start), 5)
    }

    func testATimeoutKeepsTheErrorOutputOnly() {
        XCTAssertThrowsError(
            try runner.run("/bin/sh", ["-c", "echo secret; echo progress >&2; sleep 30"], environment: [:], input: Data(), timeout: 1)
        ) { error in
            XCTAssertEqual((error as? ToolTimeout)?.errorOutput, Data("progress\n".utf8))
        }
    }
}
