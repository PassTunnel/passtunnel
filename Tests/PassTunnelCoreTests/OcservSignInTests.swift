import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

// MARK: - Against a real ocserv (opt-in)

/// Cisco AnyConnect's sign-in against a real server: the test image in Tests/ocserv (ocserv's `plain`
/// module, a password form, then a second form for the TOTP code), with a real openconnect and the real
/// clock, through `ConnectionManager.connect` (the helper is `FakeHelper`: no tunnel is ever started).
/// Only when `PASSTUNNEL_TEST_OCSERV_SERVER` names the server (`vpn.example.com:443`), which the CI job
/// "Cisco AnyConnect against ocserv" sets (Tests/ocserv/README.md); never against any other server.
///
/// - `PASSTUNNEL_TEST_OCSERV_SERVER`: `host:port` of the test server (a name the test machine resolves to
///   it, or `127.0.0.1`).
/// - `PASSTUNNEL_TEST_OCSERV_CA`: the image's test CA (`/etc/ocserv/ca.pem`), for the CA mode only; the
///   sign-in otherwise always gets the system bundle, as in the product.
/// - `PASSTUNNEL_TEST_OCSERV_PIN`: the server key's pin (`/etc/ocserv/pin.txt`).
/// - `PASSTUNNEL_TEST_OCSERV_OPENCONNECT`: the openconnect to run, only where there is no distribution's
///   (a Mac developer's Homebrew one); on Linux the sign-in finds and checks the distribution's itself.
///
/// ocserv refuses a code it has accepted before for the same user, and nothing older; a successful
/// sign-in therefore takes a window of its own (`freshWindow`), and two users share the work.
@MainActor
final class OcservSignInTests: XCTestCase {
    struct Server {
        var host: String
        var port: Int
        var pin: String
        var caFile: String
        var tool: String?
    }

    /// Tests/ocserv's test-only credentials: alice and bob, the same password and TOTP secret (RFC 6238's
    /// test key "12345678901234567890").
    nonisolated static let password = "example-password"
    nonisolated static let totpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    /// The window of the newest code ocserv accepted per user (it refuses that one and anything older).
    static var accepted: [String: UInt64] = [:]

    var server: Server!
    var home: String!
    var helper: FakeHelper!
    let params = TOTPParams()

    override func setUp() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let address = env["PASSTUNNEL_TEST_OCSERV_SERVER"], !address.isEmpty else {
            throw XCTSkip("set PASSTUNNEL_TEST_OCSERV_SERVER to the test server of Tests/ocserv to run")
        }
        guard let colon = address.lastIndex(of: ":"), let port = Int(address[address.index(after: colon)...]) else {
            return XCTFail("PASSTUNNEL_TEST_OCSERV_SERVER is not host:port: \(address)")
        }
        let pin = try XCTUnwrap(env["PASSTUNNEL_TEST_OCSERV_PIN"], "PASSTUNNEL_TEST_OCSERV_PIN")
        let ca = try XCTUnwrap(env["PASSTUNNEL_TEST_OCSERV_CA"], "PASSTUNNEL_TEST_OCSERV_CA")
        XCTAssertTrue(OpenConnectPin.isValid(pin), pin)
        XCTAssertTrue(FileManager.default.isReadableFile(atPath: ca), ca)
        server = Server(
            host: String(address[..<colon]), port: port, pin: pin, caFile: ca,
            tool: env["PASSTUNNEL_TEST_OCSERV_OPENCONNECT"].flatMap { $0.isEmpty ? nil : $0 })

        var template = Array("/tmp/pt-oc-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        home = String(cString: made)
        setenv("PASSTUNNEL_HOME", home, 1)
        useTestSecrets(service: "PassTunnelTests-\(UUID().uuidString)")
        helper = FakeHelper()
        helper.startLog = OpenConnectOutput.hookUp
    }

    override func tearDown() async throws {
        helper?.shutdown()
        Secrets.deleteAllInOverriddenService()
        if let home { try? FileManager.default.removeItem(atPath: home) }
    }

    var store: ProfileStore { ProfileStore() }

    /// A manager with the real clock and the real openconnect; `caFile` replaces the system bundle (CA mode
    /// against the test CA, in this test only).
    func makeManager(caFile: String? = nil) -> ConnectionManager {
        let m = ConnectionManager(
            store: store, helper: helper, clock: SystemClock(), healthProbe: { _ in (true, 1) }, preferences: { Preferences() },
            routes: { [] }, timing: .init(), authenticator: FakeAuthenticator())
        m.serverClock = FakeServerClock()
        m.openConnectPath = nil
        let tool = server.tool
        m.locateOpenConnect = { runner in
            var found: AnyConnectSignIn.Tool
            if let tool {
                found = AnyConnectSignIn.Tool(path: tool)
            } else {
                found = try AnyConnectSignIn.distributionTool(runner: runner)
            }
            if let caFile { found.caFile = caFile }
            return found
        }
        return m
    }

    @discardableResult
    func makeProfile(
        user: String = "alice", pin: String? = nil, totpSecret: String = totpSecret, password: String = password,
        delivery: OTPDelivery = .separate
    ) throws -> Profile {
        var p = try store.create(name: "Acme \(UUID().uuidString.prefix(8))", type: .anyconnect)
        p.host = server.host
        p.port = server.port
        p.serverCert = pin ?? server.pin
        p.tlsOnly = true
        p.setDNS = true
        p.username = user
        p.otpMode = .totp
        p.otpDelivery = delivery
        p.otpTemplate = "{password}{otp}"
        try store.save(p)
        try Secrets.set(p.id, .password, password)
        try Secrets.set(p.id, .totp, totpSecret)
        return p
    }

    var now: UInt64 { TOTP.counter(params: params, at: Date()) }

    /// Waits until a code of `user` would be one ocserv has not seen (a window after the last accepted one),
    /// and until enough of the window is left for a sign-in.
    func freshWindow(_ user: String) async throws {
        while true {
            let seconds = Date().timeIntervalSince1970
            let left = 30 - seconds.truncatingRemainder(dividingBy: 30)
            if let last = Self.accepted[user], now <= last {
                try await Task.sleep(nanoseconds: UInt64((left + 0.3) * 1e9))
            } else if left < 8 {
                try await Task.sleep(nanoseconds: UInt64((left + 0.3) * 1e9))
            } else {
                return
            }
        }
    }

    func starts() -> [OpenConnectStart] {
        helper.starts.compactMap {
            if case .startOpenConnect(let s) = $0 { return s }
            return nil
        }
    }

    /// `RESOLVE` as the sign-in returns it for the server's host.
    func checkResolve(_ start: OpenConnectStart, file: StaticString = #filePath, line: UInt = #line) {
        if OpenConnectSyntax.isIPLiteral(server.host) {
            XCTAssertNil(start.resolve, file: file, line: line)
        } else {
            let resolve = start.resolve ?? ""
            XCTAssertTrue(resolve.hasPrefix(server.host + ":"), resolve, file: file, line: line)
            XCTAssertTrue(OpenConnectSyntax.isIPLiteral(String(resolve.dropFirst(server.host.count + 1))), resolve, file: file, line: line)
        }
    }

    /// What reached the helper is what the helper accepts: its own check and the root configuration, with
    /// the cookie ocserv really hands out.
    func checkTheHelperTakesIt(_ s: OpenConnectStart, file: StaticString = #filePath, line: UInt = #line) throws {
        let config = try OpenConnectAuthResult.tunnelConfig(
            host: s.host, port: s.port, connectURL: s.connectURL, resolve: s.resolve, cookie: s.cookie, serverCert: s.serverCert,
            profileServerCert: s.profileServerCert, scriptPath: "/run/passtunnel/501/acme/vpn-hook", tlsOnly: s.tlsOnly)
        // `render` checks its text again (`checkRendered`).
        XCTAssertTrue(try config.render().contains("\ncookie \(s.cookie)\n"), file: file, line: line)
    }

    /// The secrets never reach the log, the activity or an error.
    func checkNothingLeaks(_ p: Profile, _ m: ConnectionManager, cookie: String? = nil, file: StaticString = #filePath, line: UInt = #line) {
        let everything = [
            VPNLog.read(store.logURL(p.id)), m.lastError[p.id] ?? "", m.lastErrorLog[p.id] ?? "",
            m.failures[p.id].map { String(describing: $0) } ?? "",
            (try? String(contentsOf: store.activityURL(p.id), encoding: .utf8)) ?? ""
        ].joined(separator: "\n")
        XCTAssertFalse(everything.contains(Self.password), file: file, line: line)
        if let cookie { XCTAssertFalse(everything.contains(cookie), file: file, line: line) }
    }

    // MARK: Signed in

    /// The password, then the code in ocserv's second form; the cookie, the key and the address bound to
    /// the profile's server reach the helper. A second connect in the same window waits for the next code
    /// rather than send the spent one (which ocserv refuses: `testOcservRefusesASpentCode`).
    func testPasswordAndCodeWithThePinAndNoCodeTwice() async throws {
        try await freshWindow("alice")
        let p = try makeProfile()
        let m = makeManager()
        try await m.connect(p.id)
        guard case .connected = m.state(p.id) else { return XCTFail("\(m.state(p.id)) \(m.lastError[p.id] ?? "")") }
        let first = try XCTUnwrap(m.usedCode(p.id), "the code is spent")
        Self.accepted["alice"] = first.counter
        let s = try XCTUnwrap(starts().first)
        XCTAssertFalse(s.cookie.isEmpty)
        XCTAssertEqual(s.serverCert, server.pin, "the key the sign-in reached")
        XCTAssertEqual(s.profileServerCert, server.pin)
        let host = OpenConnectSyntax.isIPv6Literal(server.host) ? "[\(server.host)]" : server.host
        XCTAssertEqual(s.connectURL, server.port == 443 ? "https://\(host)/" : "https://\(host):\(server.port)/")
        checkResolve(s)
        try checkTheHelperTakesIt(s)
        checkNothingLeaks(p, m, cookie: s.cookie)

        try await m.disconnect(p.id)
        let before = Date()
        try await m.connect(p.id)
        guard case .connected = m.state(p.id) else { return XCTFail("\(m.state(p.id)) \(m.lastError[p.id] ?? "")") }
        let second = try XCTUnwrap(m.usedCode(p.id))
        Self.accepted["alice"] = second.counter
        XCTAssertGreaterThan(second.counter, first.counter, "a code of a later window")
        XCTAssertEqual(starts().count, 2)
        XCTAssertGreaterThan(Date().timeIntervalSince(before), 0.2, "it waited for the window to end")
        XCTAssertTrue(
            m.activity(p.id).contains {
                if case .waitingForCode(reason: .used, _, _) = $0.kind { return true }
                return false
            })
    }

    /// Without a pin, the server checked against a CA (the test CA here, the system bundle in the product);
    /// the helper gets the key the sign-in accepted, which is the server's.
    func testCAMode() async throws {
        try await freshWindow("bob")
        let p = try makeProfile(user: "bob", pin: "")
        let m = makeManager(caFile: server.caFile)
        try await m.connect(p.id)
        guard case .connected = m.state(p.id) else { return XCTFail("\(m.state(p.id)) \(m.lastError[p.id] ?? "")") }
        Self.accepted["bob"] = m.usedCode(p.id)?.counter
        let s = try XCTUnwrap(starts().first)
        XCTAssertEqual(s.serverCert, server.pin, "FINGERPRINT is the server's key")
        XCTAssertEqual(s.profileServerCert, "")
        checkResolve(s)
        try checkTheHelperTakesIt(s)
    }

    // MARK: Refused before anything is sent

    /// The system's CAs do not know the test CA: refused, with the server key's pin to offer trusting, and
    /// the code given back.
    func testTheSystemCAsRefuseTheTestCA() async throws {
        let p = try makeProfile(pin: "")
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            guard case .serverCertificateRejected(_, let pin, _)? = error as? PTError else { return XCTFail("\(error)") }
            XCTAssertEqual(pin, server.pin, "openconnect's hint is the server's key")
        }
        let failure = try XCTUnwrap(m.failures[p.id])
        XCTAssertEqual(failure.kind, .configuration)
        XCTAssertEqual(failure.serverCert, server.pin)
        XCTAssertFalse(failure.credentialsSent)
        XCTAssertNil(m.usedCode(p.id), "no form was sent: the code's window is given back")
        XCTAssertTrue(starts().isEmpty)
        checkNothingLeaks(p, m)
    }

    func testAnotherPinIsRefused() async throws {
        let other = "pin-sha256:/+9qLXvY4QvSoKy/ojXS6HTlG1iniUJkmUyKWlahaLE="
        let p = try makeProfile(pin: other)
        let m = makeManager(caFile: server.caFile)
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            guard case .serverCertificateRejected(let reason, let pin, _)? = error as? PTError else { return XCTFail("\(error)") }
            XCTAssertEqual(reason, "not the pinned key")
            XCTAssertEqual(pin, server.pin)
        }
        let failure = try XCTUnwrap(m.failures[p.id])
        XCTAssertEqual(failure.kind, .configuration)
        XCTAssertFalse(failure.credentialsSent)
        XCTAssertNil(m.usedCode(p.id))
        XCTAssertTrue(starts().isEmpty)
    }

    // MARK: Refused by the server

    /// The right password and a wrong code (another secret): refused after both forms, the code spent.
    func testAWrongCode() async throws {
        let p = try makeProfile(totpSecret: "JBSWY3DPEHPK3PXP")
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            guard case .authFailed? = error as? PTError else { return XCTFail("\(error)") }
            XCTAssertFalse(ConnectionManager.isRetryable(error))
        }
        let failure = try XCTUnwrap(m.failures[p.id])
        XCTAssertEqual(failure.kind, .authRejected)
        XCTAssertTrue(failure.credentialsSent)
        XCTAssertTrue(failure.codeSent)
        XCTAssertNotNil(m.usedCode(p.id), "the code stays spent")
        let log = VPNLog.read(store.logURL(p.id))
        XCTAssertTrue(log.contains("Please enter your OTP password."), log)
        XCTAssertTrue(starts().isEmpty)
        checkNothingLeaks(p, m)
    }

    /// A wrong password: ocserv answers with its password form again ("Login failed."), which the positional
    /// answers fill with the code; then the form a third time, with nothing left (docs/ARCHITECTURE.md, the
    /// known limitation). The safe outcome: refused, the code counted as sent, nothing retried.
    func testAWrongPasswordAndOcservsRetryForm() async throws {
        let p = try makeProfile(password: "not-the-password")
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            guard case .authFailed? = error as? PTError else { return XCTFail("\(error)") }
        }
        let failure = try XCTUnwrap(m.failures[p.id])
        XCTAssertEqual(failure.kind, .authRejected)
        XCTAssertTrue(failure.credentialsSent)
        XCTAssertTrue(failure.codeSent)
        XCTAssertNotNil(m.usedCode(p.id), "the code went in the retry form: spent")
        let log = VPNLog.read(store.logURL(p.id))
        XCTAssertTrue(log.contains("Login failed."), log)
        XCTAssertTrue(log.contains("User input required in non-interactive mode"), log)
        XCTAssertFalse(log.contains("Please enter your OTP password."), "the code never reached the OTP form")
        XCTAssertTrue(starts().isEmpty)
        checkNothingLeaks(p, m)
        XCTAssertFalse(log.contains("not-the-password"))
    }

    /// `combined` delivery against a server that asks in two forms: the one line goes to the password form,
    /// which refuses it; refused, as a wrong password is.
    func testCombinedDeliveryAgainstSeparateForms() async throws {
        let p = try makeProfile(delivery: .combined)
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            guard case .authFailed? = error as? PTError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(m.failures[p.id]?.kind, .authRejected)
        XCTAssertTrue(VPNLog.read(store.logURL(p.id)).contains("Login failed."))
        XCTAssertTrue(starts().isEmpty)
    }

    /// Why the fresh-code rule exists: ocserv refuses a code it accepted once. Straight through
    /// `AnyConnectSignIn`, which has no such rule of its own.
    func testOcservRefusesASpentCode() async throws {
        try await freshWindow("bob")
        let path: String
        let runner = SystemToolRunner()
        if let tool = server.tool {
            path = tool
        } else {
            path = try AnyConnectSignIn.distributionTool(runner: runner).path
        }
        let run = AnyConnectSignIn(toolPath: path, runner: runner, caFile: server.caFile)
        let config = OpenConnectAuthConfig(
            host: server.host, port: server.port, usergroup: "", username: "bob", authgroup: "", serverCert: server.pin)
        let date = Date()
        let code = TOTP.code(secret: try TOTP.decodeSecret(Self.totpSecret), params: params, at: date)
        let answers = try OpenConnectAnswers.stdin([Self.password, code])
        let server = "\(self.server.host):\(self.server.port)"
        guard case .success = run.run(config, answers: answers, secrets: [Self.password, code], server: server) else {
            return XCTFail("the first sign-in failed")
        }
        Self.accepted["bob"] = TOTP.counter(params: params, at: date)
        guard case .failure(let failure) = run.run(config, answers: answers, secrets: [Self.password, code], server: server) else {
            return XCTFail("the code was accepted twice")
        }
        guard case .authFailed? = failure.error as? PTError else { return XCTFail("\(failure.error)") }
        XCTAssertTrue(failure.credentialsSent)
        XCTAssertFalse(failure.log.contains(code))
    }

    // MARK: The tunnel run

    /// A cookie ocserv does not know (expired, or never issued): the tunnel run (as the helper renders it,
    /// run here as this user) ends at ocserv's CSTP CONNECT, before any tunnel device is asked for.
    func testAnUnknownCookieEndsTheTunnelRun() throws {
        let path: String
        let runner = SystemToolRunner()
        if let tool = server.tool {
            path = tool
        } else {
            path = try AnyConnectSignIn.distributionTool(runner: runner).path
        }
        let address = OpenConnectSyntax.isIPLiteral(server.host) ? nil : try resolved(server.host)
        let config = OpenConnectConfig(
            host: server.host, port: server.port, cookie: "webvpn=PassTunnelTestUnknownCookie0123456789abcdef=",
            serverCert: server.pin, resolveAddress: address, scriptPath: "/usr/bin/true", tlsOnly: true)
        let file = home + "/openconnect.conf"
        try AnyConnectSignIn.writeNewFile(file, Data(try config.render().utf8))
        let output = try runner.run(path, ["--config=" + file], environment: AnyConnectSignIn.environment, input: Data(), timeout: 30)
        // Outside --authenticate openconnect writes its progress to standard output.
        let log = String(decoding: output.output + output.errorOutput, as: UTF8.self)
        XCTAssertNotEqual(output.status, 0, log)
        XCTAssertTrue(log.contains("Connected to HTTPS on "), log)
        XCTAssertTrue(log.contains("Creating SSL connection failed"), log)
        XCTAssertFalse(log.contains("Configured as "), log)
        XCTAssertFalse(log.contains("PassTunnelTestUnknownCookie"), "openconnect does not print the cookie")
    }

    /// The address `host` resolves to here, as openconnect's `RESOLVE` would give it.
    func resolved(_ host: String) throws -> String {
        var hints = addrinfo()
        hints.ai_socktype = POSIXSocket.stream
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &list) == 0, let first = list else { throw PTError.fileError(host) }
        defer { freeaddrinfo(list) }
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(first.pointee.ai_addr, first.pointee.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0
        else { throw PTError.fileError(host) }
        return String(cString: buffer)
    }
}
