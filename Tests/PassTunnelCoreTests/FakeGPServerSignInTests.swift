import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

// MARK: - Against openconnect's GlobalProtect test server (opt-in)

/// Palo Alto GlobalProtect's sign-in against a real portal and gateway: openconnect's own `tests/fake-gp-server.py`,
/// run unchanged in the image of Tests/globalprotect, once per configuration on a port of its own (README.md there,
/// "What it offers"), with a real openconnect and the real clock, through `ConnectionManager.connect` (the helper is
/// `FakeHelper`: no tunnel is ever started). Only when `PASSTUNNEL_TEST_GP_SERVER` names the server, which the CI
/// job "Palo Alto GlobalProtect against openconnect's test server" sets; never against any other server.
///
/// - `PASSTUNNEL_TEST_GP_SERVER`: the address the server listens on, which its portal also lists as its gateways'
///   host (`172.31.212.10`).
/// - `PASSTUNNEL_TEST_GP_NAME`: a name this machine resolves to that address and that the certificates name
///   (`vpn.example.com`): a portal by name whose gateway is listed by address, another host for the sign-in.
/// - `PASSTUNNEL_TEST_GP_CA`: the image's test CA (`/etc/fake-gp/ca.pem`), for the CA mode only; the sign-in
///   otherwise always gets the system bundle, as in the product.
/// - `PASSTUNNEL_TEST_GP_PIN`: the server key's pin (`/etc/fake-gp/pin.txt`), the same for every port.
/// - `PASSTUNNEL_TEST_GP_OPENCONNECT`: the openconnect to run, only where there is no distribution's; on Linux the
///   sign-in finds and checks the distribution's itself (Ubuntu's 9.12 in CI: `disable-ipv6` rendered).
///
/// The server accepts any password and any answer to its challenges and remembers no code, so what depends on
/// the server checking them (a refused password, a spent code, a code of the wrong window) stays with the unit
/// tests (`GlobalProtectConnectTests`); what is checked here is what openconnect really does with PassTunnel's
/// files and answers, and what PassTunnel makes of its real output.
@MainActor
final class FakeGPServerSignInTests: XCTestCase {
    struct Server {
        var address: String
        var name: String
        var pin: String
        var caFile: String
        var tool: AnyConnectSignIn.Tool
    }

    /// The test configurations, each on its own port (Tests/globalprotect/entrypoint.sh).
    enum Port {
        /// One gateway, "Default gateway"; the password only.
        static let plain = 443
        /// Two gateways, "US East" and "US West".
        static let twoGateways = 4432
        /// A challenge at the portal (the JavaScript form), and the portal's `portal-userauthcookie`.
        static let portalCode = 4433
        /// A challenge at the gateway (the XML form).
        static let gatewayCode = 4434
        /// A challenge at the portal and at the gateway (the HTML-wrapped form), no override cookie.
        static let bothCodes = 4435
        /// SAML at the portal.
        static let portalSAML = 4436
        /// A challenge at the portal (XML), SAML at the gateway.
        static let gatewaySAML = 4437
        /// One gateway; a certificate for the name only, not the address the portal lists the gateway at.
        static let nameOnlyCertificate = 4438
        /// Nothing listens here.
        static let closed = 4439
    }

    nonisolated static let password = "example-password-gp"
    nonisolated static let totpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    nonisolated static let otherPin = "pin-sha256:/+9qLXvY4QvSoKy/ojXS6HTlG1iniUJkmUyKWlahaLE="

    var server: Server!
    var home: String!
    var helper: FakeHelper!
    let params = TOTPParams()
    /// The sign-in's log as it was when the start request reached the helper, which then replaces it.
    let signInLogs = Locked<[String: String]>([:])

    override func setUp() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let address = env["PASSTUNNEL_TEST_GP_SERVER"], !address.isEmpty else {
            throw XCTSkip("set PASSTUNNEL_TEST_GP_SERVER to the test server of Tests/globalprotect to run")
        }
        let name = try XCTUnwrap(env["PASSTUNNEL_TEST_GP_NAME"], "PASSTUNNEL_TEST_GP_NAME")
        let pin = try XCTUnwrap(env["PASSTUNNEL_TEST_GP_PIN"], "PASSTUNNEL_TEST_GP_PIN")
        let ca = try XCTUnwrap(env["PASSTUNNEL_TEST_GP_CA"], "PASSTUNNEL_TEST_GP_CA")
        XCTAssertTrue(OpenConnectSyntax.isIPLiteral(address), address)
        XCTAssertFalse(OpenConnectSyntax.isIPLiteral(name), name)
        XCTAssertTrue(OpenConnectPin.isValid(pin), pin)
        XCTAssertTrue(FileManager.default.isReadableFile(atPath: ca), ca)
        let tool: AnyConnectSignIn.Tool
        if let path = env["PASSTUNNEL_TEST_GP_OPENCONNECT"], !path.isEmpty {
            tool = AnyConnectSignIn.Tool(path: path)
        } else {
            tool = try AnyConnectSignIn.distributionTool(for: .gp, runner: SystemToolRunner())
        }
        server = Server(address: address, name: name, pin: pin, caFile: ca, tool: tool)

        var template = Array("/tmp/pt-gp-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        home = String(cString: made)
        setenv("PASSTUNNEL_HOME", home, 1)
        useTestSecrets(service: "PassTunnelTests-\(UUID().uuidString)")
        helper = FakeHelper()
        helper.startLog = OpenConnectOutput.hookUp
        let logs = signInLogs
        helper.onStart = { request in
            guard case .startOpenConnect(let s) = request else { return }
            logs.mutate { $0[s.profileID] = VPNLog.read(URL(fileURLWithPath: s.logPath)) }
        }
    }

    override func tearDown() async throws {
        helper?.shutdown()
        Secrets.deleteAllInOverriddenService()
        if let home { try? FileManager.default.removeItem(atPath: home) }
    }

    var store: ProfileStore { ProfileStore() }

    /// A manager with the real clock and the real openconnect; `caFile` replaces the system bundle (CA mode against
    /// the test CA, in this test only).
    func makeManager(caFile: String? = nil) -> ConnectionManager {
        let m = ConnectionManager(
            store: store, helper: helper, clock: SystemClock(), healthProbe: { _ in (true, 1) }, preferences: { Preferences() },
            routes: { [] }, timing: .init(), authenticator: FakeAuthenticator())
        m.serverClock = FakeServerClock()
        m.openConnectPath = nil
        var tool = server.tool
        if let caFile { tool.caFile = caFile }
        m.locateOpenConnect = { proto, _ in
            XCTAssertEqual(proto, .gp)
            return tool
        }
        return m
    }

    @discardableResult
    func makeProfile(
        port: Int, byName: Bool = false, gateway: String = "", skipPortal: Bool = false, pin: String? = nil, gatewayPin: String = "",
        otp: OTPMode = .totp
    ) throws -> Profile {
        var p = try store.create(name: "Acme GP \(UUID().uuidString.prefix(8))", type: .globalprotect)
        p.host = byName ? server.name : server.address
        p.port = port
        p.gateway = gateway
        p.skipPortal = skipPortal
        p.serverCert = pin ?? server.pin
        p.gatewayServerCert = gatewayPin
        p.setDNS = true
        p.username = "alice"
        p.otpMode = otp
        p.otpDelivery = .separate
        try store.save(p)
        try Secrets.set(p.id, .password, Self.password)
        if otp == .totp { try Secrets.set(p.id, .totp, Self.totpSecret) }
        return p
    }

    func starts() -> [OpenConnectStart] {
        helper.starts.compactMap {
            if case .startOpenConnect(let s) = $0 { return s }
            return nil
        }
    }

    /// The sign-in's redacted standard error as the profile's log kept it: from when the start reached the helper,
    /// else (a failed sign-in) the log itself.
    func signInLog(_ p: Profile) -> String { signInLogs.value[p.id] ?? VPNLog.read(store.logURL(p.id)) }

    /// Connects and returns the start request, failing the test with the manager's error when it did not connect.
    func connected(_ p: Profile, _ m: ConnectionManager, file: StaticString = #filePath, line: UInt = #line) async throws -> OpenConnectStart {
        do {
            try await m.connect(p.id)
        } catch {
            XCTFail("\(error) \(m.lastError[p.id] ?? "")\n\(signInLog(p))", file: file, line: line)
            throw error
        }
        guard case .connected = m.state(p.id) else {
            XCTFail("\(m.state(p.id))", file: file, line: line)
            throw PTError.connectFailed("")
        }
        XCTAssertEqual(starts().count, 1, file: file, line: line)
        return try XCTUnwrap(starts().last, file: file, line: line)
    }

    /// Connects and returns the error it failed with; nothing reached the helper.
    func failure(_ p: Profile, _ m: ConnectionManager, file: StaticString = #filePath, line: UInt = #line) async throws -> (
        error: Error, failure: ConnectionFailure
    ) {
        do {
            try await m.connect(p.id)
            XCTFail("connected", file: file, line: line)
            throw PTError.connectFailed("")
        } catch {
            XCTAssertTrue(starts().isEmpty, "nothing reaches the helper", file: file, line: line)
            return (error, try XCTUnwrap(m.failures[p.id], file: file, line: line))
        }
    }

    // MARK: What reaches the helper

    /// The gateway the portal named (its address: every gateway of the test server is the server itself) as the
    /// tunnel's server, with the key the sign-in accepted and the profile's pins; the cookie in openconnect's
    /// GlobalProtect shape, `preferred-ipv6` only when IPv6 was not turned off (`disable-ipv6` sends
    /// `ipv6-support=no`, and the server then assigns none); and the helper takes it: the request through its wire
    /// format, its checks of protocol 5 and the root file it renders.
    func checkStart(
        _ s: OpenConnectStart, port: Int, profilePin: String, gatewayPin: String = "", file: StaticString = #filePath, line: UInt = #line
    ) throws {
        XCTAssertEqual(s.protocol, .gp, file: file, line: line)
        XCTAssertEqual(s.host, server.address, file: file, line: line)
        XCTAssertEqual(s.port, port, file: file, line: line)
        XCTAssertEqual(s.connectURL, port == 443 ? "https://\(server.address)/" : "https://\(server.address):\(port)/", file: file, line: line)
        XCTAssertNil(s.resolve, "an address: nothing to resolve", file: file, line: line)
        XCTAssertEqual(s.usergroup, "", file: file, line: line)
        XCTAssertEqual(s.serverCert, server.pin, "the key the sign-in reached", file: file, line: line)
        XCTAssertEqual([s.profileServerCert, s.profileGatewayServerCert], [profilePin, gatewayPin], file: file, line: line)

        let cookie = try XCTUnwrap(GlobalProtectCookie.parse(s.cookie), s.cookie.count.description, file: file, line: line)
        let keys = ["authcookie", "portal", "user", "domain", "preferred-ip"] + (server.tool.disableIPv6 ? [] : ["preferred-ipv6"])
        XCTAssertEqual(cookie.map(\.key), keys + ["computer"], file: file, line: line)
        let values = Dictionary(cookie.map { ($0.key, $0.value) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(values["user"], "alice", file: file, line: line)
        XCTAssertTrue(values["portal"]?.hasPrefix("Portal") == true, file: file, line: line)
        XCTAssertTrue(values["domain"]?.hasPrefix("Domain") == true, file: file, line: line)
        XCTAssertFalse(values["computer"]?.isEmpty ?? true, "this machine's host name", file: file, line: line)

        let request = HelperRequest.startOpenConnect(s)
        let decoded = try HelperCore.decodeRequest(try request.jsonData())
        XCTAssertEqual(decoded, request, file: file, line: line)
        guard case .startOpenConnect(let received) = decoded else { return XCTFail("\(decoded)", file: file, line: line) }
        let disableIPv6 = server.tool.disableIPv6
        let config = try HelperCore.openConnectConfig(received, scriptPath: HelperCore.hookPathForChecks, disableIPv6: disableIPv6)
        let text = try config.render()
        try OpenConnectConfig.checkRendered(text, lineCount: HelperCore.openConnectLineCount(received, disableIPv6: disableIPv6))
        XCTAssertTrue(text.contains("\nprotocol gp\nserver \(s.connectURL)\ncookie \(s.cookie)\n"), file: file, line: line)
        XCTAssertEqual(text.contains("\ndisable-ipv6\n"), disableIPv6, file: file, line: line)
        XCTAssertFalse(String(describing: helper.requests).contains(values["authcookie"] ?? "-"), file: file, line: line)
    }

    /// The password, the codes of `windows`, the cookie and its `authcookie` never reach the log, an error or the
    /// activity.
    func checkNothingLeaks(
        _ p: Profile, _ m: ConnectionManager, windows: [UInt64] = [], cookie: String? = nil, file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let everything = [
            signInLog(p), VPNLog.read(store.logURL(p.id)), m.lastError[p.id] ?? "", m.lastErrorLog[p.id] ?? "",
            m.failures[p.id].map { String(describing: $0) } ?? "", String(describing: m.activity(p.id)),
            (try? String(contentsOf: store.activityURL(p.id), encoding: .utf8)) ?? ""
        ].joined(separator: "\n")
        var secrets = [Self.password]
        let secret = try TOTP.decodeSecret(Self.totpSecret)
        secrets += windows.map { TOTP.code(secret: secret, params: params, at: Date(timeIntervalSince1970: TimeInterval($0) * 30)) }
        if let cookie { secrets += GlobalProtectCookie.secrets(cookie) }
        for s in secrets { XCTAssertFalse(everything.contains(s), "\(s) in\n\(everything)", file: file, line: line) }
    }

    /// The TOTP windows from `start` to now: the codes a sign-in that began then can have made.
    func windows(since start: Date) -> [UInt64] {
        Array(TOTP.counter(params: params, at: start)...TOTP.counter(params: params, at: Date()) + 1)
    }

    // MARK: Signed in

    /// The password alone, at the portal, replayed by openconnect to its one gateway (the portal's own host and port):
    /// the gateway's cookie reaches the helper, bound to its address and key.
    func testPasswordOnlyPortalThenItsGateway() async throws {
        let p = try makeProfile(port: Port.plain, otp: .none)
        let m = makeManager()
        let s = try await connected(p, m)
        try checkStart(s, port: Port.plain, profilePin: server.pin)
        XCTAssertNil(m.usedCode(p.id), "no code")
        let log = signInLog(p)
        XCTAssertTrue(log.contains("POST https://\(server.address)/global-protect/getconfig.esp\n"), log)
        XCTAssertTrue(log.contains("1 gateway servers available:\n  Default gateway (\(server.address):443)"), log)
        XCTAssertTrue(log.contains("POST https://\(server.address)/ssl-vpn/login.esp\n"), log)
        XCTAssertFalse(log.contains("ssl-vpn/prelogin.esp"), "openconnect's replay was taken: no second sign-in")
        try checkNothingLeaks(p, m, cookie: s.cookie)
    }

    /// The portal by name, its gateway listed by address: another host, reached only after the portal's
    /// configuration (the two-server rule), its key checked against the CA for that address (the test CA here,
    /// the system bundle in the product).
    func testCAModeAndAGatewayOnAnotherHost() async throws {
        let p = try makeProfile(port: Port.plain, byName: true, pin: "", otp: .none)
        let m = makeManager(caFile: server.caFile)
        let s = try await connected(p, m)
        try checkStart(s, port: Port.plain, profilePin: "")
        let log = signInLog(p)
        XCTAssertTrue(log.contains("POST https://\(server.name)/global-protect/getconfig.esp\n"), log)
        XCTAssertTrue(log.contains("POST https://\(server.address)/ssl-vpn/login.esp\n"), log)
        XCTAssertFalse(log.contains("POST https://\(server.name)/ssl-vpn/"), log)
    }

    /// Two pins, the gateway's matching: both are `servercert` lines, and openconnect takes either for any server.
    func testTwoPinsTheGatewaysMatching() async throws {
        let p = try makeProfile(port: Port.plain, pin: Self.otherPin, gatewayPin: server.pin, otp: .none)
        let s = try await connected(p, makeManager())
        try checkStart(s, port: Port.plain, profilePin: Self.otherPin, gatewayPin: server.pin)
    }

    /// The code at the portal (its challenge), and the portal's override cookie, which takes openconnect's replay
    /// through the gateway: one code, no second sign-in, and the cookie's value masked in the log.
    func testTheCodeAtThePortalAndItsOverrideCookie() async throws {
        let p = try makeProfile(port: Port.portalCode)
        let m = makeManager()
        let start = Date()
        let s = try await connected(p, m)
        try checkStart(s, port: Port.portalCode, profilePin: server.pin)
        let used = try XCTUnwrap(m.usedCode(p.id), "the code is spent")
        XCTAssertTrue(windows(since: start).contains(used.counter))
        let log = signInLog(p)
        XCTAssertTrue(log.contains("Challenge: "), log)
        XCTAssertFalse(log.contains("ssl-vpn/prelogin.esp"), "the override cookie spared the second sign-in")
        XCTAssertTrue(log.contains("GlobalProtect login returned portal-userauthcookie=<redacted>\n"), log)
        XCTAssertFalse(log.contains("portal-cookie-"), log)
        try checkNothingLeaks(p, m, windows: windows(since: start), cookie: s.cookie)
    }

    /// The code at the gateway: openconnect replays the portal's password there, the gateway's challenge takes the
    /// code. One code, no second sign-in.
    func testTheCodeAtTheGatewayAfterTheReplay() async throws {
        let p = try makeProfile(port: Port.gatewayCode)
        let m = makeManager()
        let start = Date()
        let s = try await connected(p, m)
        try checkStart(s, port: Port.gatewayCode, profilePin: server.pin)
        XCTAssertTrue(windows(since: start).contains(try XCTUnwrap(m.usedCode(p.id)).counter))
        let log = signInLog(p)
        XCTAssertTrue(log.contains("Challenge: "), log)
        XCTAssertFalse(log.contains("ssl-vpn/prelogin.esp"), log)
        try checkNothingLeaks(p, m, windows: windows(since: start), cookie: s.cookie)
    }

    /// `skip_portal`: one login at the profile's host as a gateway, the code at its challenge; no portal request.
    func testSkipPortal() async throws {
        let p = try makeProfile(port: Port.gatewayCode, skipPortal: true)
        let m = makeManager()
        let start = Date()
        let s = try await connected(p, m)
        try checkStart(s, port: Port.gatewayCode, profilePin: server.pin)
        let log = signInLog(p)
        XCTAssertTrue(log.contains("POST https://\(server.address):\(Port.gatewayCode)/ssl-vpn/prelogin.esp?"), log)
        XCTAssertFalse(log.contains("global-protect/"), log)
        XCTAssertFalse(log.contains("gateway servers available"), log)
        try checkNothingLeaks(p, m, windows: windows(since: start), cookie: s.cookie)
    }

    /// Portal and gateway both ask for a code and no override cookie spares the second sign-in: the first part
    /// (password, code) answers the portal; the second (password, the code of a later window) is written only once
    /// openconnect waits at the gateway's password prompt and the first code's window has ended.
    func testBothAskTheSecondCodeInALaterWindow() async throws {
        let p = try makeProfile(port: Port.bothCodes)
        let m = makeManager()
        let start = Date()
        let first = TOTP.counter(params: params, at: start)
        let s = try await connected(p, m)
        try checkStart(s, port: Port.bothCodes, profilePin: server.pin)
        let used = try XCTUnwrap(m.usedCode(p.id), "the second code is spent")
        XCTAssertGreaterThan(used.counter, first, "a code of a later window than the first")
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince1970, TimeInterval(first + 1) * 30, "not before the first window ended")
        let log = signInLog(p)
        let config = try XCTUnwrap(log.range(of: "/global-protect/getconfig.esp\n", options: .backwards), log)
        let prelogin = try XCTUnwrap(log.range(of: "/ssl-vpn/prelogin.esp?"), "the second sign-in")
        XCTAssertLessThan(config.lowerBound, prelogin.lowerBound)
        XCTAssertGreaterThanOrEqual(log.components(separatedBy: "Challenge: ").count - 1, 2, "a challenge at each")
        try checkNothingLeaks(p, m, windows: windows(since: start), cookie: s.cookie)
    }

    // MARK: The portal's gateways

    /// Two gateways, the profile's named: openconnect chooses it by its label.
    func testTheNamedGatewayOfTwo() async throws {
        let p = try makeProfile(port: Port.twoGateways, gateway: "US West", otp: .none)
        let s = try await connected(p, makeManager())
        try checkStart(s, port: Port.twoGateways, profilePin: server.pin)
        XCTAssertTrue(signInLog(p).contains("2 gateway servers available:\n"))
    }

    /// Two gateways and none named: the sign-in fails with the portal's labels, for the profile's `gateway`; the
    /// code, which openconnect read as a choice, is spent and masked.
    func testTwoGatewaysAndNoneNamed() async throws {
        let p = try makeProfile(port: Port.twoGateways)
        let m = makeManager()
        let start = Date()
        let r = try await failure(p, m)
        XCTAssertEqual(r.error as? PTError, .invalidField("gateway"))
        XCTAssertEqual(r.failure.kind, .configuration)
        XCTAssertEqual(r.failure.detail, .gatewayRequired)
        XCTAssertEqual(r.failure.gateways?.sorted(), ["US East", "US West"])
        XCTAssertTrue(r.failure.credentialsSent)
        XCTAssertTrue(r.failure.codeSent)
        XCTAssertNotNil(m.usedCode(p.id))
        try checkNothingLeaks(p, m, windows: windows(since: start))
    }

    /// A gateway the portal does not list: the same failure, with the labels; choosing one of them (the editor's
    /// and the command's offer) and connecting again signs in there.
    func testAGatewayThePortalDoesNotListThenOneItDoes() async throws {
        let p = try makeProfile(port: Port.twoGateways, gateway: "Mars", otp: .none)
        let m = makeManager()
        let r = try await failure(p, m)
        XCTAssertEqual(r.error as? PTError, .invalidField("gateway"))
        XCTAssertEqual(r.failure.detail, .gatewayRequired)
        XCTAssertEqual(r.failure.gateways?.sorted(), ["US East", "US West"])
        XCTAssertTrue(signInLog(p).contains("Auth choice \"Mars\" not available\n"))
        try checkNothingLeaks(p, m)
        let choice = try XCTUnwrap(m.gatewayChoice(p.id))
        XCTAssertEqual(choice.labels.sorted(), ["US East", "US West"])
        XCTAssertEqual(try m.chooseGateway(choice, label: "US East").gateway, "US East")
        let s = try await connected(p, m)
        try checkStart(s, port: Port.twoGateways, profilePin: server.pin)
    }

    // MARK: Single sign-on

    /// SAML at the portal: refused before anything was sent; the code is given back.
    func testSSOAtThePortal() async throws {
        let p = try makeProfile(port: Port.portalSAML)
        let m = makeManager()
        let r = try await failure(p, m)
        guard case .ssoRequired? = r.error as? PTError else { return XCTFail("\(r.error)") }
        XCTAssertEqual(r.failure.kind, .ssoRequired)
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(m.usedCode(p.id), "the code is given back")
    }

    /// SAML at the gateway behind a portal that took the password and a code: refused, the code spent.
    func testSSOAtTheGatewayAfterThePortal() async throws {
        let p = try makeProfile(port: Port.gatewaySAML)
        let m = makeManager()
        let r = try await failure(p, m)
        guard case .ssoRequired? = r.error as? PTError else { return XCTFail("\(r.error)") }
        XCTAssertTrue(r.failure.credentialsSent)
        XCTAssertNotNil(m.usedCode(p.id), "spent at the portal")
        XCTAssertTrue(signInLog(p).contains("/ssl-vpn/prelogin.esp?"))
    }

    /// The same gateway with `skip_portal`: its prelogin asks for SAML, nothing was sent.
    func testSSOAtTheGatewayWithSkipPortal() async throws {
        let p = try makeProfile(port: Port.gatewaySAML, skipPortal: true)
        let m = makeManager()
        let r = try await failure(p, m)
        guard case .ssoRequired? = r.error as? PTError else { return XCTFail("\(r.error)") }
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(m.usedCode(p.id))
    }

    // MARK: Trust

    /// The system's CAs do not know the test CA: refused before anything was sent, with the portal key's pin to
    /// offer; "Trust this server" writes it, and the next connect signs in with it.
    func testTheSystemCAsRefuseTheTestCAThenTrustThisServer() async throws {
        let p = try makeProfile(port: Port.plain, pin: "")
        let m = makeManager()
        let r = try await failure(p, m)
        guard case .serverCertificateRejected(_, let pin, _)? = r.error as? PTError else { return XCTFail("\(r.error)") }
        XCTAssertEqual(pin, server.pin)
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(m.usedCode(p.id), "no form was sent: the code's window is given back")
        let offer = try XCTUnwrap(m.serverTrustOffer(p.id))
        XCTAssertNil(offer.gateway, "the portal's key")
        XCTAssertEqual(offer.pin, server.pin)
        XCTAssertEqual(try m.trustServer(offer).serverCert, server.pin)
        let s = try await connected(p, m)
        try checkStart(s, port: Port.plain, profilePin: server.pin)
    }

    func testAnotherPinIsRefused() async throws {
        let p = try makeProfile(port: Port.plain, pin: Self.otherPin)
        let m = makeManager()
        let r = try await failure(p, m)
        guard case .serverCertificateRejected(let reason, let pin, _)? = r.error as? PTError else { return XCTFail("\(r.error)") }
        XCTAssertEqual(reason, "not the pinned key")
        XCTAssertEqual(pin, server.pin)
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(m.usedCode(p.id))
    }

    /// The portal by name passes the CA; its gateway, listed by address, has a certificate for the name only and
    /// fails it after the portal's answer: "Trust This Gateway…" with the gateway's key, which needs the portal's
    /// too (no portal pin); with both pinned the next connect signs in.
    func testTheGatewaysCertificateFailsThenTrustThisGateway() async throws {
        let p = try makeProfile(port: Port.nameOnlyCertificate, byName: true, pin: "", otp: .none)
        let m = makeManager(caFile: server.caFile)
        let r = try await failure(p, m)
        let gateway = "\(server.address):\(Port.nameOnlyCertificate)"
        guard case .gatewayCertificateRejected(let named, let reason, let pin, _)? = r.error as? PTError else {
            return XCTFail("\(r.error)\n\(signInLog(p))")
        }
        XCTAssertEqual(named, gateway)
        XCTAssertFalse(reason.isEmpty)
        XCTAssertEqual(pin, server.pin)
        XCTAssertEqual(r.failure.kind, .configuration)
        XCTAssertTrue(r.failure.credentialsSent, "the portal's answer went first")
        let offer = try XCTUnwrap(m.serverTrustOffer(p.id))
        XCTAssertEqual(offer.gateway, gateway)
        XCTAssertTrue(offer.needsPortalPin)
        let saved = try m.trustServer(offer, portalPin: server.pin)
        XCTAssertEqual([saved.serverCert, saved.gatewayServerCert], [server.pin, server.pin])
        let s = try await connected(p, m)
        try checkStart(s, port: Port.nameOnlyCertificate, profilePin: server.pin, gatewayPin: server.pin)
    }

    // MARK: No server

    func testNoServerAtThePort() async throws {
        let p = try makeProfile(port: Port.closed)
        let m = makeManager()
        let r = try await failure(p, m)
        guard case .serverUnreachable? = r.error as? PTError else { return XCTFail("\(r.error)\n\(signInLog(p))") }
        XCTAssertEqual(r.failure.kind, .unreachable)
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(m.usedCode(p.id))
    }

    // MARK: The tunnel run

    /// The root file the helper renders from the start request, run here as this user with the gateway's real
    /// cookie: openconnect reads every option of it and asks the gateway for its configuration, which the test
    /// server refuses outside the sign-in's own HTTP session ("errors getting SSL/VPN config", a rejected cookie),
    /// so the run ends there, before any tunnel device is asked for.
    func testTheTunnelRunTakesTheRootFile() async throws {
        let p = try makeProfile(port: Port.plain, otp: .none)
        let s = try await connected(p, makeManager())
        let config = try HelperCore.openConnectConfig(s, scriptPath: "/usr/bin/true", disableIPv6: server.tool.disableIPv6)
        let path = home + "/openconnect.conf"
        try AnyConnectSignIn.writeNewFile(path, Data(try config.render().utf8))
        let output = try SystemToolRunner().run(
            server.tool.path, ["--config=" + path], environment: AnyConnectSignIn.environment, input: Data(), timeout: 30)
        // Outside --authenticate openconnect writes its progress to standard output.
        let log = String(decoding: output.output + output.errorOutput, as: UTF8.self)
        XCTAssertNotEqual(output.status, 0, log)
        XCTAssertTrue(log.contains("POST https://\(server.address)/ssl-vpn/getconfig.esp"), log)
        XCTAssertFalse(log.contains("Configured as "), log)
        for secret in GlobalProtectCookie.secrets(s.cookie) { XCTAssertFalse(log.contains(secret), "openconnect does not print the cookie") }
    }
}
