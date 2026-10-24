import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit
import PassTunnelShared

/// The agent-facing CLI options, error codes and result objects (`Automation.swift`).
final class AutomationCLITests: XCTestCase {
    func parse(_ line: String, environment: [String: String] = [:]) throws -> CLIInvocation {
        try CLIInvocation.parse(line.split(separator: " ").map(String.init), environment: environment)
    }

    func command(_ line: String) throws -> CLICommand { try parse(line).command }

    func assertUsage(_ line: String, file: StaticString = #filePath, line l: UInt = #line) {
        XCTAssertThrowsError(try parse(line), line, file: file, line: l) { error in
            XCTAssertTrue(error is CLIUsageError, "\(error)", file: file, line: l)
            XCTAssertEqual(AutomationErrorCode.of(error), .invalidArgument, file: file, line: l)
        }
    }

    func testJSONOnEveryCommandWithAResult() throws {
        XCTAssertEqual(try command("connect acme --json"), .connect(id: "acme", json: true))
        XCTAssertEqual(try command("disconnect --all --json"), .disconnect(id: nil, all: true, json: true))
        XCTAssertEqual(try command("toggle --json"), .toggle(id: nil, json: true))
        XCTAssertEqual(try command("set acme username=alice --json"),
                       .set(id: "acme", assignments: [.init(key: "username", value: "alice")], json: true))
        XCTAssertEqual(try command("add Acme --type forti --json"), .add(name: "Acme", type: .forti, json: true))
        XCTAssertEqual(try command("import a.ovpn --json"), .importFile(path: "a.ovpn", name: nil, json: true))
        XCTAssertEqual(try command("export acme --json"), .export(id: "acme", output: nil, json: true))
        XCTAssertEqual(try command("rm acme -y --json"), .remove(id: "acme", yes: true, json: true))
        XCTAssertEqual(try command("secret acme totp --json"), .secret(id: "acme", kind: .totp, json: true))
        XCTAssertEqual(try command("default --json"), .setDefault(id: nil, json: true))
        XCTAssertEqual(try command("pin acme --json"), .pin(id: "acme", json: true))
        XCTAssertEqual(try command("log acme --json -n 20"), .log(id: "acme", follow: false, json: true, lines: 20))
        XCTAssertEqual(try command("helper status --json"), .helper(.status, json: true))
        XCTAssertEqual(try command("version --json"), .version(json: true))
        XCTAssertEqual(try command("--version"), .version())
        XCTAssertEqual(try command("--version --json"), .version(json: true))
        assertUsage("log acme -f --json")
        assertUsage("log acme -n 0")
        assertUsage("helper install --json")
        assertUsage("completion zsh --json")
    }

    func testWaitAndTimeout() throws {
        XCTAssertEqual(try command("connect acme --wait"), .connect(id: "acme", wait: true))
        XCTAssertEqual(try command("connect acme --timeout 90"), .connect(id: "acme", wait: true, timeout: 90))
        XCTAssertEqual(try command("connect --timeout=5 -w"), .connect(id: nil, wait: true, timeout: 5))
        XCTAssertEqual(try command("disconnect acme --wait --json"), .disconnect(id: "acme", all: false, json: true, wait: true))
        assertUsage("connect acme --timeout 0")
        assertUsage("connect acme --timeout soon")
        assertUsage("connect acme --timeout")
        assertUsage("toggle --wait")
    }

    func testGlobalOptionsAnywhereAndFromTheEnvironment() throws {
        XCTAssertEqual(try parse("--no-input connect acme"),
                       CLIInvocation(command: .connect(id: "acme"), options: CLIOptions(noInput: true)))
        XCTAssertEqual(try parse("connect acme --no-auth-prompt --no-input"),
                       CLIInvocation(command: .connect(id: "acme"), options: CLIOptions(noInput: true, noAuthPrompt: true)))
        XCTAssertEqual(try parse("status", environment: ["PASSTUNNEL_NO_INPUT": "1"]).options, CLIOptions(noInput: true))
        XCTAssertEqual(try parse("status", environment: ["PASSTUNNEL_NO_INPUT": "0"]).options, CLIOptions())
        XCTAssertEqual(try parse("--no-input").command, .status(id: nil, json: false))
        // After "--" it is an argument, not an option.
        XCTAssertEqual(try CLIInvocation.parse(["import", "--", "--no-input"], environment: [:]),
                       CLIInvocation(command: .importFile(path: "--no-input", name: nil)))
        XCTAssertTrue(CLICommand.isCommand("--no-input"))
        XCTAssertTrue(CLICommand.isCommand("mcp"))
        XCTAssertTrue(CLICommand.isCommand("version"))
    }

    func testMCPCommand() throws {
        XCTAssertEqual(try command("mcp"), .mcp(allowConnect: false))
        XCTAssertEqual(try command("mcp --allow-connect"), .mcp(allowConnect: true))
        assertUsage("mcp --allow-everything")
        assertUsage("mcp acme")
    }

    func testRequestsJSONAlsoForUsageErrors() {
        XCTAssertTrue(CLICommand.requestsJSON(["connect", "--bogus", "--json"]))
        XCTAssertFalse(CLICommand.requestsJSON(["import", "--", "--json"]))
        XCTAssertFalse(CLICommand.requestsJSON(["status"]))
    }

    func testErrorCodesAndExitCodes() {
        let cases: [(Error, AutomationErrorCode, Int32)] = [
            (CLIUsageError("x"), .invalidArgument, 2),
            (PTError.profileNotFound("acme"), .profileNotFound, 3),
            (PTError.invalidProfileID("../x"), .invalidArgument, 2),
            (PTError.userConfirmationCancelled, .authCancelled, 4),
            (PTError.userConfirmationFailed("no window server"), .authUnavailable, 4),
            (PTError.confirmationRequired, .authUnavailable, 4),
            (AutomationError(.inputRequired, "x"), .inputRequired, 4),
            (HelperClientError.notInstalled, .helperNotInstalled, 5),
            (HelperClientError.requiresApproval, .helperNotInstalled, 5),
            (HelperClientError.versionMismatch(helper: 2, app: 3), .helperOutdated, 5),
            (HelperClientError.timeout(5), .helperUnavailable, 5),
            (PTError.connectFailed("tail"), .connectFailed, 6),
            (PTError.authFailed("tail"), .credentialsRejected, 6),
            (PTError.missingPassword("acme"), .credentialsMissing, 6),
            (PTError.otherVPNActive("utun9"), .otherVPNActive, 6),
            (DestinationChangedError(host: "vpn.example.com"), .destinationChanged, 6),
            (PTError.connectTimeout(60), .timeout, 7),
            (PTError.missingConfig("acme"), .configInvalid, 1),
            (PTError.keychain(-25300), .keychainError, 1),
            (SecretStoreUnavailable("no store"), .keychainError, 1),
            (PTError.protectionUnavailable, .authUnavailable, 4),
            (NSError(domain: "x", code: 1), .internal, 1),
        ]
        for (error, code, exit) in cases {
            XCTAssertEqual(AutomationErrorCode.of(error), code, "\(error)")
            XCTAssertEqual(AutomationErrorCode.of(error).exitCode, exit, "\(error)")
        }
        XCTAssertEqual(AutomationExit.interrupted, 130)
        // Codes are stable snake_case strings.
        for code in AutomationErrorCode.allCases {
            XCTAssertTrue(code.rawValue.allSatisfy { $0.isLowercase || $0 == "_" }, code.rawValue)
        }
    }

    func testErrorEnvelopeShape() throws {
        let data = try AutomationJSON.encoder(pretty: false).encode(ErrorEnvelope(PTError.profileNotFound("acme")))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Array(object.keys), ["error"])
        let error = try XCTUnwrap(object["error"] as? [String: Any])
        XCTAssertEqual(error["code"] as? String, "profile_not_found")
        XCTAssertEqual(error["message"] as? String, PTError.profileNotFound("acme").localizedDescription)
    }

    func testLogRedactor() {
        let r = LogRedactor(secrets: ["S3cr3t-Pa55", "ab"])
        XCTAssertEqual(r.redact("sent S3cr3t-Pa55123456 to server"), "sent <redacted>123456 to server")
        XCTAssertEqual(r.redact("PUSH: auth-token SESS_ID_abc,ping 10"), "PUSH: auth-token <redacted>,ping 10")
        XCTAssertEqual(r.redact("password = hunter2"), "password = <redacted>")
        XCTAssertEqual(r.redact("otp: 123456"), "otp: <redacted>")
        XCTAssertEqual(r.redact("SCRV1:cHc=:MTIz"), "SCRV1:<redacted>")
        XCTAssertEqual(r.redact("challenge CRV1::c3RhdGU=::123456 sent"), "challenge CRV1:<redacted> sent")
        XCTAssertEqual(r.redact("RV1:abc"), "RV1:<redacted>")
        XCTAssertEqual(r.redact("Initialization Sequence Completed"), "Initialization Sequence Completed")
        // Too short to redact without destroying the line.
        XCTAssertEqual(r.redact("about tab"), "about tab")
    }

    /// Lines `logs` leaves out: what OpenVPN prints at `verb` 7 and up (keys, key sources, packets).
    func testKeyMaterialLines() {
        let digest = String(repeating: "0123456789abcdef", count: 4)
        let dropped = [
            "2026-10-21 10:00:00 Outgoing Data Channel: CIPHER KEY: 0123abcd 4567ef01 89abcdef 01234567 89abcdef",
            "2026-10-21 10:00:00 Incoming Data Channel: HMAC KEY: 0123456789abcdef0123456789abcdef",
            "2026-10-21 10:00:00 pre_master: 01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef",
            "2026-10-21 10:00:00 TLS: tls_pre_encrypt: key_id=0",
            "2026-10-21 10:00:00 UDPv4 WRITE [42] to [AF_INET]203.0.113.5:1194: P_DATA_V2 kid=0 DATA 5a1b2c3d 4e5f6071 8293a4b5 c6d7e8f9 0a1b",
        ]
        for line in dropped { XCTAssertTrue(LogRedactor.isKeyMaterial(line), line) }
        let kept = [
            "2026-10-21 10:00:00 Initialization Sequence Completed",
            "2026-10-21 10:00:00 Outgoing Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key",
            "2026-10-21 10:00:00 TLS: Initial packet from [AF_INET]203.0.113.5:1194, sid=0123abcd 89ef0123",
            "2026-10-21 10:00:00 net_addr_v4_add: 10.8.0.6/24 dev utun6",
            "2026-10-21 10:00:00 /sbin/route add -net 0.0.0.0 10.8.0.1 128.0.0.0",
            "INFO:   Remote gateway has allocated a VPN.",
            // openfortivpn's hint: the gateway certificate's public digest.
            "ERROR:      --trusted-cert " + digest,
            "ERROR:      trusted-cert = " + digest.uppercased(),
        ]
        for line in kept { XCTAssertFalse(LogRedactor.isKeyMaterial(line), line) }
        // Only the digest in that place is exempt.
        for line in ["ERROR:      --trusted-cert \(digest) key: \(digest)", "certificate digest: " + digest,
                     "trusted-cert = \(digest)00"] {
            XCTAssertTrue(LogRedactor.isKeyMaterial(line), line)
        }
    }
}

// MARK: - MCP server

struct FixedHelperInspector: HelperInspecting {
    var value = HelperReport(state: "enabled", responding: true, protocolVersion: PT.helperProtocolVersion, outdated: false)
    func report() async -> HelperReport { value }
}

@MainActor
final class MCPServerTests: XCTestCase {
    var home: String!
    var service: String!
    var helper: FakeHelper!
    var clock: FakeClock!
    var authenticator = FakeAuthenticator()
    var inspector = FixedHelperInspector()
    var sent: [Data] = []
    var logs: [String] = []
    var store: ProfileStore { ProfileStore() }

    let t0 = Date(timeIntervalSince1970: 1_700_000_000)
    let password = "S3cr3t-Pa55"
    let totpSecret = "JBSWY3DPEHPK3PXP"
    static let modern = "2026-07-28"

    override func setUp() async throws {
        // Short path: the fake management socket must fit in sun_path.
        var template = Array("/tmp/pt-mcp-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        home = String(cString: made)
        service = "PassTunnelTests-\(UUID().uuidString)"
        setenv("PASSTUNNEL_HOME", home, 1)
        useTestSecrets(service: service)
        helper = FakeHelper()
        clock = FakeClock(t0)
        authenticator = FakeAuthenticator()
        inspector = FixedHelperInspector()
        sent = []
        logs = []
    }

    override func tearDown() async throws {
        helper.shutdown()
        Secrets.deleteAllInOverriddenService()
        try? FileManager.default.removeItem(atPath: home)
    }

    // MARK: harness

    func makeServer(allowConnect: Bool = false, authenticator: UserAuthenticator? = nil,
                    clock: ConnectionClock? = nil) -> MCPServer {
        let manager = ConnectionManager(store: store, helper: helper, clock: clock ?? self.clock,
                                        healthProbe: { _ in (false, 0) }, preferences: { Preferences() },
                                        routes: { [] }, authenticator: authenticator ?? self.authenticator)
        let automation = AutomationService(store: store, manager: manager, helperInspector: inspector,
                                           appInfo: AppInfo(version: "9.9.9", build: "99", appPath: "/Applications/PassTunnel.app"))
        return MCPServer(service: automation, allowConnect: allowConnect, serverVersion: "9.9.9",
                         send: { [weak self] in self?.sent.append($0) }, log: { [weak self] in self?.logs.append($0) })
    }

    var meta: [String: Any] {
        ["io.modelcontextprotocol/protocolVersion": Self.modern, "io.modelcontextprotocol/clientCapabilities": [String: Any]()]
    }

    func line(_ object: Any) -> Data { try! JSONSerialization.data(withJSONObject: object) }

    /// Sends one message and returns the reply (nil when there was none).
    @discardableResult
    func exchange(_ server: MCPServer, _ object: Any) async -> [String: Any]? {
        await exchange(server, raw: line(object))
    }

    @discardableResult
    func exchange(_ server: MCPServer, raw: Data) async -> [String: Any]? {
        let before = sent.count
        await server.handle(raw)
        guard sent.count > before, let last = sent.last else { return nil }
        return try? JSONSerialization.jsonObject(with: last) as? [String: Any]
    }

    func request(_ id: Any, _ method: String, _ params: [String: Any] = [:], withMeta: Bool = true) -> [String: Any] {
        var p = params
        if withMeta { p["_meta"] = meta }
        return ["jsonrpc": "2.0", "id": id, "method": method, "params": p]
    }

    /// `tools/call` over the modern protocol; returns the result object.
    func callTool(_ server: MCPServer, _ name: String, _ arguments: [String: Any] = [:],
                  file: StaticString = #filePath, line: UInt = #line) async throws -> [String: Any] {
        let reply = await exchange(server, request(name, "tools/call", ["name": name, "arguments": arguments]))
        return try XCTUnwrap(reply?["result"] as? [String: Any], "\(String(describing: reply))", file: file, line: line)
    }

    /// The reply, which must exist.
    func reply(_ server: MCPServer, _ object: Any, file: StaticString = #filePath, line: UInt = #line) async throws -> [String: Any] {
        let r = await exchange(server, object)
        return try XCTUnwrap(r, file: file, line: line)
    }

    func reply(_ server: MCPServer, raw: Data, file: StaticString = #filePath, line: UInt = #line) async throws -> [String: Any] {
        let r = await exchange(server, raw: raw)
        return try XCTUnwrap(r, file: file, line: line)
    }

    func rpcError(_ reply: [String: Any]?) -> Int? { (reply?["error"] as? [String: Any])?["code"] as? Int }

    /// `structuredContent` of a successful call.
    func structured(_ server: MCPServer, _ name: String, _ arguments: [String: Any] = [:],
                    file: StaticString = #filePath, line: UInt = #line) async throws -> [String: Any] {
        let result = try await callTool(server, name, arguments, file: file, line: line)
        return try XCTUnwrap(result["structuredContent"] as? [String: Any], "\(result)", file: file, line: line)
    }

    /// The error code of a failed call (nil when it succeeded).
    func toolError(_ server: MCPServer, _ name: String, _ arguments: [String: Any] = [:],
                   file: StaticString = #filePath, line: UInt = #line) async throws -> String? {
        errorCode(try await callTool(server, name, arguments, file: file, line: line))
    }

    func errorCode(_ result: [String: Any]) -> String? {
        guard result["isError"] as? Bool == true,
              let text = ((result["content"] as? [[String: Any]])?.first)?["text"] as? String,
              let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { return nil }
        return (object["error"] as? [String: Any])?["code"] as? String
    }

    @discardableResult
    func makeOpenVPN(_ name: String = "Acme", otp: OTPMode = .none, config: String? = nil) throws -> Profile {
        var p = try store.create(name: name, type: .openvpn)
        p.username = "alice"
        p.otpMode = otp
        try store.save(p)
        try Data((config ?? "client\nremote vpn.example.com 1194\nauth-user-pass\n").utf8).write(to: store.ovpnURL(p.id))
        try Secrets.set(p.id, .password, password)
        if otp == .totp { try Secrets.set(p.id, .totp, totpSecret) }
        return p
    }

    func waitUntil(timeout: TimeInterval = 5, file: StaticString = #filePath, line: UInt = #line,
                   _ condition: () -> Bool) async {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            if Date() > deadline { return XCTFail("condition not met in time", file: file, line: line) }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    // MARK: protocol

    func testInitializeHandshakeEchoesASupportedVersion() async throws {
        let server = makeServer()
        let reply = try await self.reply(server, ["jsonrpc": "2.0", "id": 1, "method": "initialize", "params": [
            "protocolVersion": "2025-06-18", "capabilities": [String: Any](), "clientInfo": ["name": "test", "version": "1"],
        ]])
        XCTAssertEqual(reply["id"] as? Int, 1)
        let result = try XCTUnwrap(reply["result"] as? [String: Any])
        XCTAssertEqual(result["protocolVersion"] as? String, "2025-06-18")
        XCTAssertEqual((result["serverInfo"] as? [String: Any])?["name"] as? String, "passtunnel")
        XCTAssertEqual((result["serverInfo"] as? [String: Any])?["version"] as? String, "9.9.9")
        XCTAssertEqual(Array((result["capabilities"] as? [String: Any] ?? [:]).keys), ["tools"])
        XCTAssertNotNil(result["instructions"] as? String)
        XCTAssertNil(result["resultType"], "handshake protocols have no resultType")

        // The notification gets no reply; requests without _meta now use the negotiated version.
        let none = await exchange(server, ["jsonrpc": "2.0", "method": "notifications/initialized"])
        XCTAssertNil(none)
        let list = await exchange(server, request(2, "tools/list", withMeta: false))
        let tools = try XCTUnwrap((list?["result"] as? [String: Any])?["tools"] as? [[String: Any]])
        XCTAssertNotNil(tools.first?["outputSchema"])
    }

    func testInitializeWithAnUnknownVersionGetsTheNewestHandshakeVersion() async throws {
        let server = makeServer()
        for requested in ["1999-01-01", "2026-07-28"] {
            let reply = await exchange(server, ["jsonrpc": "2.0", "id": "a", "method": "initialize",
                                                "params": ["protocolVersion": requested, "capabilities": [String: Any]()]])
            XCTAssertEqual((reply?["result"] as? [String: Any])?["protocolVersion"] as? String, "2025-11-25")
            XCTAssertEqual(reply?["id"] as? String, "a")
        }
        let missing = await exchange(server, ["jsonrpc": "2.0", "id": 3, "method": "initialize", "params": [String: Any]()])
        XCTAssertEqual((missing?["error"] as? [String: Any])?["code"] as? Int, -32602)
    }

    func testOlderHandshakeVersionsGetOnlyWhatTheyKnow() async throws {
        let server = makeServer()
        await exchange(server, ["jsonrpc": "2.0", "id": 1, "method": "initialize",
                                "params": ["protocolVersion": "2024-11-05", "capabilities": [String: Any]()]])
        let list = await exchange(server, request(2, "tools/list", withMeta: false))
        let tools = try XCTUnwrap((list?["result"] as? [String: Any])?["tools"] as? [[String: Any]])
        XCTAssertNil(tools[0]["outputSchema"])
        XCTAssertNil(tools[0]["annotations"])
        XCTAssertNil(tools[0]["title"])
        try makeOpenVPN()
        let call = await exchange(server, request(3, "tools/call", ["name": "list_profiles"], withMeta: false))
        let result = try XCTUnwrap(call?["result"] as? [String: Any])
        XCTAssertNil(result["structuredContent"])
        XCTAssertNotNil(result["content"])
    }

    func testModernRequestsCarryTheirVersion() async throws {
        let server = makeServer()
        let reply = try await self.reply(server, request(1, "tools/list"))
        let result = try XCTUnwrap(reply["result"] as? [String: Any])
        XCTAssertEqual(result["resultType"] as? String, "complete")
        XCTAssertEqual(result["ttlMs"] as? Int, 0)
        XCTAssertEqual(result["cacheScope"] as? String, "private")
        let info = (result["_meta"] as? [String: Any])?["io.modelcontextprotocol/serverInfo"] as? [String: Any]
        XCTAssertEqual(info?["name"] as? String, "passtunnel")

        let discoverReply = try await self.reply(server, request(2, "server/discover"))
        let discover = try XCTUnwrap(discoverReply["result"] as? [String: Any])
        XCTAssertEqual(discover["supportedVersions"] as? [String], MCPServer.supportedVersions)
        XCTAssertEqual(MCPServer.supportedVersions.first, Self.modern)
        XCTAssertNotNil((discover["capabilities"] as? [String: Any])?["tools"])
        XCTAssertEqual(discover["resultType"] as? String, "complete")

        let ping = try await self.reply(server, request(3, "ping"))
        XCTAssertEqual((ping["result"] as? [String: Any])?["resultType"] as? String, "complete")
    }

    func testVersionAndMetaErrors() async throws {
        let server = makeServer()
        var bad = request(1, "tools/list")
        bad["params"] = ["_meta": ["io.modelcontextprotocol/protocolVersion": "1900-01-01",
                                   "io.modelcontextprotocol/clientCapabilities": [String: Any]()]]
        let badReply = try await self.reply(server, bad)
        let unsupported = try XCTUnwrap(badReply["error"] as? [String: Any])
        XCTAssertEqual(unsupported["code"] as? Int, -32022)
        let data = try XCTUnwrap(unsupported["data"] as? [String: Any])
        XCTAssertEqual(data["requested"] as? String, "1900-01-01")
        XCTAssertEqual(data["supported"] as? [String], MCPServer.supportedVersions)

        var noCapabilities = request(2, "tools/list")
        noCapabilities["params"] = ["_meta": ["io.modelcontextprotocol/protocolVersion": Self.modern]]
        let noCapabilitiesReply = await exchange(server, noCapabilities)
        XCTAssertEqual(rpcError(noCapabilitiesReply), -32602)

        // Neither _meta nor a handshake: malformed.
        let noMeta = await exchange(server, request(3, "tools/list", withMeta: false))
        XCTAssertEqual(rpcError(noMeta), -32602)
        // ping always works.
        let ping = await exchange(server, request(4, "ping", withMeta: false))
        XCTAssertNotNil(ping?["result"])
    }

    func testJSONRPCErrors() async throws {
        let server = makeServer()
        let parse = try await self.reply(server, raw: Data("{not json".utf8))
        XCTAssertEqual((parse["error"] as? [String: Any])?["code"] as? Int, -32700)
        XCTAssertNil(parse["id"])

        let batch = try await self.reply(server, [request(1, "ping")])
        XCTAssertEqual((batch["error"] as? [String: Any])?["code"] as? Int, -32600)

        let version = try await self.reply(server, ["jsonrpc": "1.0", "id": 2, "method": "ping"])
        XCTAssertEqual((version["error"] as? [String: Any])?["code"] as? Int, -32600)
        XCTAssertEqual(version["id"] as? Int, 2)

        let badID = try await self.reply(server, ["jsonrpc": "2.0", "id": true, "method": "ping"])
        XCTAssertEqual((badID["error"] as? [String: Any])?["code"] as? Int, -32600)

        let unknown = try await self.reply(server, request(3, "resources/list"))
        XCTAssertEqual((unknown["error"] as? [String: Any])?["code"] as? Int, -32601)
        XCTAssertEqual(unknown["id"] as? Int, 3)

        let noName = try await self.reply(server, request(4, "tools/call", ["arguments": [String: Any]()]))
        XCTAssertEqual((noName["error"] as? [String: Any])?["code"] as? Int, -32602)
        let badArguments = try await self.reply(server, request(5, "tools/call", ["name": "diagnose", "arguments": [1]]))
        XCTAssertEqual((badArguments["error"] as? [String: Any])?["code"] as? Int, -32602)
        let unknownTool = try await self.reply(server, request(6, "tools/call", ["name": "get_code"]))
        XCTAssertEqual((unknownTool["error"] as? [String: Any])?["code"] as? Int, -32602)
        let params = try await self.reply(server, ["jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": [1, 2]])
        XCTAssertEqual((params["error"] as? [String: Any])?["code"] as? Int, -32602)

        // A response or an unknown notification from the client: no reply.
        let quiet1 = await exchange(server, ["jsonrpc": "2.0", "id": 9, "result": [String: Any]()])
        let quiet2 = await exchange(server, ["jsonrpc": "2.0", "method": "notifications/progress"])
        XCTAssertNil(quiet1)
        XCTAssertNil(quiet2)
    }

    func testToolListIsReadOnlyUnlessConnectIsAllowed() async throws {
        func names(_ server: MCPServer) async throws -> [String] {
            let reply = await exchange(server, request(1, "tools/list"))
            let tools = try XCTUnwrap((reply?["result"] as? [String: Any])?["tools"] as? [[String: Any]])
            for tool in tools {
                let input = try XCTUnwrap(tool["inputSchema"] as? [String: Any])
                XCTAssertEqual(input["type"] as? String, "object")
                XCTAssertEqual(input["additionalProperties"] as? Bool, false)
                XCTAssertEqual((tool["outputSchema"] as? [String: Any])?["type"] as? String, "object")
                XCTAssertFalse((tool["description"] as? String ?? "").isEmpty)
            }
            return tools.compactMap { $0["name"] as? String }
        }
        let readOnly = try await names(makeServer())
        XCTAssertEqual(readOnly, ["list_profiles", "get_status", "get_logs", "diagnose"])
        let all = try await names(makeServer(allowConnect: true))
        XCTAssertEqual(all, ["list_profiles", "get_status", "get_logs", "diagnose", "connect", "disconnect"])

        try makeOpenVPN()
        let server = makeServer()
        let refused = try await self.reply(server, request(2, "tools/call", ["name": "connect", "arguments": ["profile_id": "acme"]]))
        XCTAssertEqual((refused["error"] as? [String: Any])?["code"] as? Int, -32602, "not listed, not callable")
        XCTAssertTrue(helper.starts.isEmpty)
    }

    // MARK: tools

    func testListProfilesAndStatus() async throws {
        let p = try makeOpenVPN()
        var forti = try store.create(name: "Lab", type: .forti)
        forti.host = "vpn.example.com"
        forti.autoReconnect = true
        try store.save(forti)
        try store.setDefault(p.id)
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        let server = makeServer()

        let list = try await callTool(server, "list_profiles")
        let profiles = try XCTUnwrap((list["structuredContent"] as? [String: Any])?["profiles"] as? [[String: Any]])
        XCTAssertEqual(profiles.map { $0["id"] as? String }, ["acme", "lab"])
        XCTAssertEqual(profiles[0]["state"] as? String, "connected")
        XCTAssertEqual(profiles[0]["is_default"] as? Bool, true)
        XCTAssertEqual(profiles[0]["protected"] as? Bool, false)
        XCTAssertEqual(profiles[1]["type"] as? String, "forti")
        XCTAssertEqual(profiles[1]["auto_reconnect"] as? Bool, true)
        XCTAssertEqual(profiles[1]["state"] as? String, "disconnected")
        // The text content is the same object.
        let text = try XCTUnwrap(((list["content"] as? [[String: Any]])?.first)?["text"] as? String)
        let parsed = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
        XCTAssertEqual((parsed["profiles"] as? [[String: Any]])?.count, 2)

        let status = try await structured(server, "get_status", ["profile_id": "acme"])
        let only = try XCTUnwrap((status["profiles"] as? [[String: Any]])?.first)
        XCTAssertEqual(only["state"] as? String, "connected")
        XCTAssertEqual(only["ip"] as? String, "10.8.0.6")
        XCTAssertNotNil(only["since"] as? String)
        XCTAssertNotNil(only["duration_seconds"] as? Int)
        XCTAssertEqual((status["helper"] as? [String: Any])?["state"] as? String, "enabled")
        XCTAssertEqual((status["profiles"] as? [[String: Any]])?.count, 1)
    }

    func testStatusWithoutTheHelperDoesNotFail() async throws {
        try makeOpenVPN()
        helper.statusError = HelperClientError.notInstalled
        inspector.value = HelperReport(state: "not_installed", responding: false)
        let server = makeServer()
        let result = try await callTool(server, "get_status")
        XCTAssertNil(result["isError"] as? Bool == true ? result : nil)
        let status = try XCTUnwrap(result["structuredContent"] as? [String: Any])
        let helperReport = try XCTUnwrap(status["helper"] as? [String: Any])
        XCTAssertEqual(helperReport["state"] as? String, "not_installed")
        XCTAssertEqual(helperReport["responding"] as? Bool, false)
        XCTAssertNotNil(helperReport["error"] as? String)
        XCTAssertEqual(((status["profiles"] as? [[String: Any]])?.first)?["state"] as? String, "disconnected")
    }

    func testArgumentsAreCheckedStrictly() async throws {
        try makeOpenVPN()
        let server = makeServer(allowConnect: true)
        for (tool, args) in [("get_status", ["profile_id": "../../etc"]), ("get_status", ["profile_id": "Acme"]),
                             ("get_status", ["profile_id": 7]), ("get_status", ["id": "acme"]),
                             ("get_logs", [:]), ("get_logs", ["profile_id": "acme", "lines": 501]),
                             ("get_logs", ["profile_id": "acme", "lines": "10"]), ("get_logs", ["profile_id": "acme", "lines": true]),
                             ("diagnose", ["verbose": true]), ("connect", ["profile_id": "acme", "wait": "yes"]),
                             ("connect", ["profile_id": "acme", "timeout_seconds": 0]),
                             ("connect", ["profile_id": "acme", "wait": 1]), ("connect", ["profile_id": "acme", "timeout_seconds": true]),
                             ("get_logs", ["profile_id": "acme", "lines": 10.5]), ("get_status", ["profile_id": ["acme"]]),
                             ("disconnect", ["profile_id": "acme", "force": true])] as [(String, [String: Any])] {
            let result = try await callTool(server, tool, args)
            XCTAssertEqual(errorCode(result), "invalid_argument", "\(tool) \(args)")
            XCTAssertNil(result["structuredContent"])
        }
        let code = try await toolError(server, "get_status", ["profile_id": "nope"])
        XCTAssertEqual(code, "profile_not_found")
        XCTAssertTrue(helper.starts.isEmpty)
        XCTAssertTrue(helper.stops.isEmpty)
    }

    /// Booleans and numbers stay apart on every platform (`JSONValue`): 1 is not true, false is not 0,
    /// and 5.0 is the integer 5. Sent as raw lines, so the numbers are exactly as written.
    func testBooleansAndNumbersStayApart() async throws {
        let p = try makeOpenVPN()
        try Data("one\ntwo\nthree\n".utf8).write(to: store.logURL(p.id))
        let server = makeServer(allowConnect: true)
        let meta = #""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}"#
        func call(_ tool: String, _ arguments: String) async throws -> [String: Any] {
            let line = #"{"jsonrpc":"2.0","id":"t","method":"tools/call","params":{"# + meta + #","name":""# + tool
                + #"","arguments":"# + arguments + "}}"
            let r = try await reply(server, raw: Data(line.utf8))
            return try XCTUnwrap(r["result"] as? [String: Any], "\(r)")
        }
        let two = try await call("get_logs", #"{"profile_id":"acme","lines":2.0}"#)
        XCTAssertEqual((two["structuredContent"] as? [String: Any])?["lines"] as? [String], ["two", "three"])
        for (tool, arguments) in [("get_logs", #"{"profile_id":"acme","lines":true}"#),
                                  ("get_logs", #"{"profile_id":"acme","lines":2.5}"#),
                                  ("get_logs", #"{"profile_id":"acme","lines":1e300}"#),
                                  ("disconnect", #"{"profile_id":"acme","wait":0}"#),
                                  ("disconnect", #"{"profile_id":"acme","wait":"false"}"#),
                                  ("get_status", #"{"profile_id":true}"#)] {
            let result = try await call(tool, arguments)
            XCTAssertEqual(errorCode(result), "invalid_argument", "\(tool) \(arguments)")
        }
        let stopped = try await call("disconnect", #"{"profile_id":"acme","wait":false,"timeout_seconds":5.0}"#)
        XCTAssertEqual(stopped["isError"] as? Bool, false, "\(stopped)")

        // Request ids: strings and integers (also written 1.0), echoed as integers.
        let whole = try await reply(server, raw: Data(#"{"jsonrpc":"2.0","id":1.0,"method":"ping"}"#.utf8))
        XCTAssertEqual(whole["id"] as? Int, 1)
        XCTAssertNotNil(whole["result"])
        let big = try await reply(server, raw: Data(#"{"jsonrpc":"2.0","id":12345678901234567,"method":"ping"}"#.utf8))
        XCTAssertEqual((big["id"] as? NSNumber)?.int64Value, 12_345_678_901_234_567)
        for id in ["1.5", "true", "false", "null", "[1]", #"{"a":1}"#] {
            let r = try await reply(server, raw: Data((#"{"jsonrpc":"2.0","id":"# + id + #","method":"ping"}"#).utf8))
            XCTAssertEqual(rpcError(r), -32600, id)
            XCTAssertNil(r["id"], id)
        }
    }

    func testGetLogsReturnsRedactedTail() async throws {
        let p = try makeOpenVPN()
        var log = (1...80).map { "line \($0)" }
        log.append("MANAGEMENT: Client connected from /tmp/x")
        log.append("SENT CONTROL [server]: 'PUSH_REQUEST' auth-token SESS_ID_secret")
        log.append("echo \(password) back")
        try Data((log.joined(separator: "\n") + "\n").utf8).write(to: store.logURL(p.id))
        let server = makeServer()

        let report = try await structured(server, "get_logs", ["profile_id": "acme", "lines": 3])
        XCTAssertEqual(report["lines"] as? [String], ["line 80", "SENT CONTROL [server]: 'PUSH_REQUEST' auth-token <redacted>",
                                                      "echo <redacted> back"])
        XCTAssertEqual(report["truncated"] as? Bool, true)
        let all = try await structured(server, "get_logs", ["profile_id": "acme"])
        XCTAssertEqual((all["lines"] as? [String])?.count, 50)
        XCTAssertFalse((all["lines"] as? [String] ?? []).contains { $0.contains("MANAGEMENT:") })

        // No log yet: an empty list, not an error.
        try makeOpenVPN("Lab")
        let empty = try await structured(server, "get_logs", ["profile_id": "lab"])
        XCTAssertEqual(empty["lines"] as? [String], [])
    }

    func testGetLogsLeavesOutKeyMaterial() async throws {
        let p = try makeOpenVPN()
        let log = ["Peer Connection Initiated with [AF_INET]203.0.113.5:1194",
                   "Outgoing Data Channel: CIPHER KEY: 0123abcd 4567ef01 89abcdef 01234567 89abcdef",
                   "TLS: tls_process: chg=0",
                   "Initialization Sequence Completed"]
        try Data((log.joined(separator: "\n") + "\n").utf8).write(to: store.logURL(p.id))
        let report = try await structured(makeServer(), "get_logs", ["profile_id": "acme"])
        XCTAssertEqual(report["lines"] as? [String], [log[0], log[3]])
    }

    /// The 256 KB tail starts mid-line: that line is dropped, so a cut "password=…" cannot slip past
    /// the keyword rule as "word=…".
    func testGetLogsDropsTheCutFirstLine() async throws {
        let p = try makeOpenVPN()
        let cut = "sent password=hunter2xyz"
        let after = String(repeating: "x", count: 99) + "\n"
        var body = ""
        while body.utf8.count < VPNLog.maxReadBytes { body += after }
        // The tail begins at "word=…" of `cut`.
        let tailStart = cut.utf8.count - "word=hunter2xyz".utf8.count
        let rest = String(body.utf8.prefix(VPNLog.maxReadBytes - (cut.utf8.count - tailStart) - 1))!
        let text = "head line\n" + cut + "\n" + rest
        try Data(text.utf8).write(to: store.logURL(p.id))
        XCTAssertEqual(VPNLog.read(store.logURL(p.id)).prefix(15), "word=hunter2xyz", "the test cuts where it means to")

        let report = try await structured(makeServer(), "get_logs", ["profile_id": "acme", "lines": 500])
        let lines = try XCTUnwrap(report["lines"] as? [String])
        XCTAssertFalse(lines.contains { $0.contains("hunter2") }, "\(lines.prefix(2))")
        XCTAssertEqual(report["truncated"] as? Bool, true)
    }

    func testDiagnoseNamesProblemsWithoutValues() async throws {
        try makeOpenVPN()
        try makeOpenVPN("Bad", config: "client\nremote vpn.example.com 1194\nup /bin/sh\n")
        var noSecret = try store.create(name: "Forti", type: .forti)
        noSecret.otpMode = .totp
        try store.save(noSecret)
        inspector.value = HelperReport(state: "enabled", responding: true, protocolVersion: 2, outdated: true)
        let server = makeServer()

        let report = try await structured(server, "diagnose")
        XCTAssertEqual(report["version"] as? String, "9.9.9")
        XCTAssertEqual(report["in_applications"] as? Bool, true)
        XCTAssertEqual((report["helper"] as? [String: Any])?["outdated"] as? Bool, true)
        let checks = try XCTUnwrap(report["profiles"] as? [[String: Any]])
        let byID = Dictionary(uniqueKeysWithValues: checks.map { ($0["id"] as! String, $0) })
        XCTAssertEqual(byID["acme"]?["ok"] as? Bool, true)
        XCTAssertEqual(byID["acme"]?["server"] as? String, "vpn.example.com")
        XCTAssertEqual(byID["acme"]?["password_saved"] as? Bool, true)
        func codes(_ id: String) -> [String] {
            (byID[id]?["problems"] as? [[String: Any]] ?? []).compactMap { $0["code"] as? String }
        }
        XCTAssertEqual(codes("bad"), ["config_invalid"])
        XCTAssertEqual(Set(codes("forti")), ["config_invalid", "credentials_missing"])
        XCTAssertEqual(byID["forti"]?["totp_saved"] as? Bool, false)
        let text = sent.map { String(decoding: $0, as: UTF8.self) }.joined()
        XCTAssertFalse(text.contains(password))
        XCTAssertFalse(text.contains("/bin/sh"), "config contents stay out")
    }

    func testConnectAndDisconnect() async throws {
        try makeOpenVPN()
        let server = makeServer(allowConnect: true)

        let connected = try await structured(server, "connect", ["profile_id": "acme"])
        XCTAssertEqual(connected["state"] as? String, "connected")
        XCTAssertEqual(connected["ip"] as? String, "10.8.0.6")
        XCTAssertEqual(helper.starts.count, 1)

        // Already connected: no second start.
        let again = try await structured(server, "connect", ["profile_id": "acme"])
        XCTAssertEqual(again["state"] as? String, "connected")
        XCTAssertEqual(helper.starts.count, 1)

        let stopped = try await structured(server, "disconnect", ["profile_id": "acme"])
        XCTAssertEqual(stopped["state"] as? String, "disconnected")
        XCTAssertEqual(helper.stops, ["acme"])
    }

    func testConnectWithoutWaitingReturnsAtOnce() async throws {
        try makeOpenVPN()
        let server = makeServer(allowConnect: true)
        let result = try await structured(server, "connect", ["profile_id": "acme", "wait": false])
        XCTAssertNotEqual(result["state"] as? String, "disconnected")
        await server.drain()
        XCTAssertEqual(helper.starts.count, 1)
    }

    func testProtectedProfileAsksOnTheMacAndReportsWhyItFailed() async throws {
        let server = makeServer(allowConnect: true)
        let manager = ConnectionManager(store: store, helper: helper, clock: clock, authenticator: authenticator)
        let plain = try makeOpenVPN()
        var p = plain
        p.requireAuth = .connect
        try await manager.vault.applyProtection(from: plain, to: p)
        try store.save(p)

        authenticator.results = [PTError.userConfirmationCancelled]
        let code = try await toolError(server, "connect", ["profile_id": "acme"])
        XCTAssertEqual(code, "auth_cancelled")
        XCTAssertEqual(authenticator.calls, 1)
        XCTAssertTrue(authenticator.reasons[0].contains("vpn.example.com"), "the prompt names the server")
        XCTAssertTrue(helper.starts.isEmpty)

        let list = try await structured(server, "list_profiles")
        XCTAssertEqual(((list["profiles"] as? [[String: Any]])?.first)?["protected"] as? Bool, true)

        // Confirmed on the Mac: connects.
        let ok = try await structured(server, "connect", ["profile_id": "acme"])
        XCTAssertEqual(ok["state"] as? String, "connected")

        // --no-auth-prompt: refused without a prompt.
        let promptless = makeServer(allowConnect: true, authenticator: PromptlessAuthenticator(authenticator))
        _ = try await callTool(promptless, "disconnect", ["profile_id": "acme"])
        let calls = authenticator.calls
        let refused = try await toolError(promptless, "connect", ["profile_id": "acme"])
        XCTAssertEqual(refused, "auth_unavailable")
        XCTAssertEqual(authenticator.calls, calls)
    }

    func testProfilesThatAskEachTimeCannotBeConnected() async throws {
        var p = try makeOpenVPN()
        p.passwordMode = .ask
        try store.save(p)
        let server = makeServer(allowConnect: true)
        let code = try await toolError(server, "connect", ["profile_id": "acme"])
        XCTAssertEqual(code, "input_required")
        XCTAssertTrue(helper.starts.isEmpty)
    }

    func testConnectTimeoutStopsTheAttempt() async throws {
        try makeOpenVPN()
        helper.openVPNStateLine = { "\(Int($0.timeIntervalSince1970)),WAIT,,,,,,," }
        let server = makeServer(allowConnect: true, clock: SystemClock())
        let started = Date()
        let result = try await callTool(server, "connect", ["profile_id": "acme", "timeout_seconds": 1])
        XCTAssertEqual(errorCode(result), "timeout")
        XCTAssertLessThan(Date().timeIntervalSince(started), 10)
        XCTAssertEqual(helper.stops, ["acme"], "the half-started connection is stopped")
    }

    /// Sends request 41, a connect of "acme" that stays in WAIT, and returns once the manager has the
    /// helper's reply to the start and polls the management socket. Seeing the start request is not
    /// enough: a cancel that arrives while the start is still in the helper is handled too, but with
    /// two stops (the cancelled call's disconnect, then the manager's stop of the session that came up
    /// meanwhile), so tests that count stops must not cancel before this point.
    func startConnectThatWaits(_ server: MCPServer) async {
        helper.openVPNStateLine = { "\(Int($0.timeIntervalSince1970)),WAIT,,,,,,," }
        let polled = expectation(description: "the connect polls the management socket")
        polled.assertForOverFulfill = false
        helper.onStateQuery = { _ in polled.fulfill() }
        server.receive(line(request(41, "tools/call", ["name": "connect", "arguments": ["profile_id": "acme", "timeout_seconds": 60]])))
        await fulfillment(of: [polled], timeout: 5)
        XCTAssertEqual(helper.starts.count, 1)
    }

    func testRequestsRunConcurrentlyAndCanBeCancelled() async throws {
        try makeOpenVPN()
        let server = makeServer(allowConnect: true, clock: SystemClock())
        await startConnectThatWaits(server)
        // A ping is answered while the connect waits.
        server.receive(line(request(42, "ping")))
        await waitUntil { self.sent.count == 1 }
        XCTAssertEqual((try JSONSerialization.jsonObject(with: sent[0]) as? [String: Any])?["id"] as? Int, 42)

        server.receive(line(["jsonrpc": "2.0", "method": "notifications/cancelled", "params": ["requestId": 41]]))
        await server.drain()
        XCTAssertEqual(sent.count, 1, "no response for the cancelled request")
        XCTAssertEqual(helper.stops, ["acme"])
    }

    /// An id still in flight cannot be reused: the second request is refused, the first one keeps
    /// its id (its cancel and its reply), and the id is free again once it has finished.
    func testDuplicateInFlightIDIsRefused() async throws {
        try makeOpenVPN()
        let server = makeServer(allowConnect: true, clock: SystemClock())
        await startConnectThatWaits(server)
        // Refused at once, in `receive`.
        server.receive(line(request(41, "ping")))
        XCTAssertEqual(sent.count, 1)
        let duplicate = try XCTUnwrap(try JSONSerialization.jsonObject(with: XCTUnwrap(sent.first)) as? [String: Any])
        XCTAssertEqual(rpcError(duplicate), -32600)
        XCTAssertEqual(duplicate["id"] as? Int, 41)

        server.receive(line(["jsonrpc": "2.0", "method": "notifications/cancelled", "params": ["requestId": 41]]))
        await server.drain()
        XCTAssertEqual(helper.stops, ["acme"], "the cancel reached the first request")
        XCTAssertEqual(sent.count, 1)
        let reused = await exchange(server, request(41, "ping"))
        XCTAssertNotNil(reused?["result"])
    }

    func testOversizedLineIsAParseError() async throws {
        let server = makeServer()
        server.receiveOversizedLine()
        let reply = try XCTUnwrap(try JSONSerialization.jsonObject(with: XCTUnwrap(sent.last)) as? [String: Any])
        XCTAssertEqual(rpcError(reply), -32700)
        XCTAssertNil(reply["id"])
        // The server keeps serving.
        let ping = await exchange(server, request(1, "ping"))
        XCTAssertNotNil(ping?["result"])
        XCTAssertEqual(MCPServer.maxLineBytes, 1 << 20)
    }

    func testLineReader() {
        var r = LineReader(maxBytes: 8)
        func text(_ s: String) -> LineReader.Line { .text(Data(s.utf8)) }
        XCTAssertEqual(r.feed(Array("abc\r\nde".utf8)), [text("abc")])
        XCTAssertEqual(r.feed(Array("f\n\n".utf8)), [text("def"), text("")])
        // Too long: skipped up to its newline, in one chunk or across several.
        XCTAssertEqual(r.feed(Array("0123456789\nok\n".utf8)), [.tooLong, text("ok")])
        XCTAssertEqual(r.feed(Array("01234".utf8)), [])
        XCTAssertEqual(r.feed(Array("56789".utf8)), [])
        XCTAssertEqual(r.feed(Array("abcdef\nnext".utf8)), [.tooLong])
        XCTAssertEqual(r.finish(), [text("next")])
        XCTAssertEqual(r.finish(), [])
        // Exactly the limit, with or without "\r".
        XCTAssertEqual(r.feed(Array("12345678\n12345678\r\n123456789\r\n".utf8)), [text("12345678"), text("12345678"), .tooLong])
        XCTAssertEqual(r.feed(Array("0123456789".utf8)), [])
        XCTAssertEqual(r.finish(), [.tooLong])
    }

    /// Some clients send optional arguments as null: the same as leaving them out.
    func testNullArgumentsAreAbsent() async throws {
        let p = try makeOpenVPN()
        try Data("one\ntwo\n".utf8).write(to: store.logURL(p.id))
        let server = makeServer(allowConnect: true)
        let status = try await structured(server, "get_status", ["profile_id": NSNull()])
        XCTAssertEqual((status["profiles"] as? [[String: Any]])?.count, 1)
        let logs = try await structured(server, "get_logs", ["profile_id": "acme", "lines": NSNull()])
        XCTAssertEqual(logs["lines"] as? [String], ["one", "two"])
        let connected = try await structured(server, "connect", ["profile_id": "acme", "wait": NSNull(), "timeout_seconds": NSNull()])
        XCTAssertEqual(connected["state"] as? String, "connected")
        let list = await exchange(server, request(9, "tools/call", ["name": "list_profiles", "arguments": NSNull()]))
        XCTAssertEqual((list?["result"] as? [String: Any])?["isError"] as? Bool, false)
        // A required one is still required.
        let missing = try await toolError(server, "get_logs", ["profile_id": NSNull()])
        XCTAssertEqual(missing, "invalid_argument")
    }

    /// The attempt seen under way (another process's) ends before this connect can follow it: this
    /// connect then gets the usual checks instead of starting unchecked.
    func testJoiningAnAttemptThatEndedRunsTheChecks() async throws {
        var p = try makeOpenVPN()
        p.passwordMode = .ask
        try store.save(p)
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        helper.setStateLine(p.id, "1700000000,AUTH,,,,,,,")
        helper.onStatus = { [helper] call in if call == 2 { helper!.simulateExit("acme") } }
        let server = makeServer(allowConnect: true)
        let code = try await toolError(server, "connect", ["profile_id": "acme"])
        XCTAssertEqual(code, "input_required")
        XCTAssertTrue(helper.starts.isEmpty)
    }

    /// Another process starts the profile between this connect's checks and its start: this connect
    /// follows that session, so its timeout leaves it running.
    func testTimeoutLeavesASessionAnotherProcessStartedMeanwhile() async throws {
        let p = try makeOpenVPN()
        let dir = store.dir(p.id).path
        helper.onStatus = { [helper] call in
            guard call == 2 else { return }
            helper!.simulateExternalStart("acme", profileDir: dir, since: Date())
            helper!.setStateLine("acme", "1700000000,AUTH,,,,,,,")
        }
        let server = makeServer(allowConnect: true, clock: SystemClock())
        let code = try await toolError(server, "connect", ["profile_id": "acme", "timeout_seconds": 1])
        XCTAssertEqual(code, "timeout")
        XCTAssertTrue(helper.starts.isEmpty)
        XCTAssertTrue(helper.stops.isEmpty, "not this process's session")
        XCTAssertNotNil(helper.running["acme"])
    }

    /// Screen lock and sleep end the reuse window (`passtunnel mcp` registers this, like the app).
    func testVaultExpiryForgetsConfirmationsOnLockAndSleep() async throws {
        let manager = ConnectionManager(store: store, helper: helper, clock: clock, preferences: { Preferences() },
                                        authenticator: authenticator)
        let plain = try makeOpenVPN()
        var p = plain
        p.requireAuth = .connect
        try await manager.vault.applyProtection(from: plain, to: p)
        try store.save(p)

        let lock = NotificationCenter()
        let sleep = NotificationCenter()
        let sleepName = Notification.Name("test.willSleep")
        let expiry = VaultExpiry(vault: manager.vault, screenLock: lock, sleep: sleep, sleepNotification: sleepName)
        for (center, name) in [(lock, VaultExpiry.screenLockedNotification), (sleep, sleepName)] {
            try await manager.vault.unlock(p, for: .connect)
            XCTAssertFalse(manager.vault.needsPrompt(p, for: .connect), "within the reuse window")
            center.post(name: name, object: nil)
            await waitUntil { manager.vault.needsPrompt(p, for: .connect) }
        }
        XCTAssertEqual(authenticator.calls, 2)
        withExtendedLifetime(expiry) {}
    }

    /// A client may write all its requests and close stdin at once: each still gets its response.
    func testEndOfInputFinishesTheRequestsReceived() async throws {
        try makeOpenVPN()
        let server = makeServer(allowConnect: true)
        server.receive(line(request(1, "tools/call", ["name": "list_profiles"])))
        server.receive(line(request(2, "tools/call", ["name": "connect", "arguments": ["profile_id": "acme"]])))
        server.receive(line(request(3, "tools/call", ["name": "get_status"])))
        await server.drain()
        let ids = sent.compactMap { (try? JSONSerialization.jsonObject(with: $0) as? [String: Any])?["id"] as? Int }
        XCTAssertEqual(Set(ids), [1, 2, 3])
        XCTAssertTrue(helper.stops.isEmpty)
    }

    /// Every tool, every way: no password, TOTP secret or live code ever reaches the output, and
    /// everything sent is a JSON-RPC message (diagnostics go to the log only).
    func testNoSecretInAnyOutputAndOnlyProtocolMessages() async throws {
        let p = try makeOpenVPN(otp: .totp)
        try Data("Peer Connection Initiated\npassword: \(password)\n".utf8).write(to: store.logURL(p.id))
        let server = makeServer(allowConnect: true)
        await exchange(server, ["jsonrpc": "2.0", "id": 0, "method": "initialize",
                                "params": ["protocolVersion": "2025-11-25", "capabilities": [String: Any]()]])
        await exchange(server, request(1, "tools/list"))
        for (name, args) in [("list_profiles", [:]), ("get_status", [:]), ("get_status", ["profile_id": "acme"]),
                             ("get_logs", ["profile_id": "acme", "lines": 500]), ("diagnose", [:]),
                             ("connect", ["profile_id": "acme"]), ("get_status", [:]),
                             ("disconnect", ["profile_id": "acme"])] as [(String, [String: Any])] {
            let result = try await callTool(server, name, args)
            XCTAssertNotEqual(result["isError"] as? Bool, true, "\(name): \(result)")
        }
        XCTAssertEqual(helper.starts.count, 1)

        let secret = try TOTP.decodeSecret(totpSecret)
        var codes: Set<String> = []
        for date in [t0, Date()] {
            for offset in -2...2 {
                codes.insert(TOTP.code(secret: secret, params: p.totp, at: date.addingTimeInterval(Double(offset * 30))))
            }
        }
        for data in sent {
            let text = String(decoding: data, as: UTF8.self)
            XCTAssertFalse(text.contains("\n"), "one message per line")
            XCTAssertFalse(text.contains(password))
            XCTAssertFalse(text.contains(totpSecret))
            for code in codes { XCTAssertFalse(text.contains(code), "live code \(code) in \(text)") }
            let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertEqual(object["jsonrpc"] as? String, "2.0")
            XCTAssertTrue(object["result"] != nil || object["error"] != nil)
        }
        XCTAssertFalse(logs.joined().contains(password))
    }
}
