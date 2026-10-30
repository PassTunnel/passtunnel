import Foundation
import XCTest

@testable import PassTunnelCLI
@testable import PassTunnelCore
@testable import PassTunnelKit

private let pin = "pin-sha256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk="
private let macOS154 = OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0)
private let macOS153 = OperatingSystemVersion(majorVersion: 15, minorVersion: 3, patchVersion: 0)
private let macOS13 = OperatingSystemVersion(majorVersion: 13, minorVersion: 0, patchVersion: 0)

/// The command line of Cisco AnyConnect profiles: `add --type anyconnect`, `set`, `show`, `list`, `status`, and
/// the refusal on a system that cannot connect them. Every test uses a temporary profile directory, a private
/// secret store and a fake helper; nothing is connected.
@MainActor
final class AnyConnectCLITests: CoreTestCase {
    var helper: FakeHelper!
    var changesAnnounced = 0

    override func setUp() async throws {
        helper = FakeHelper()
        changesAnnounced = 0
    }

    override func tearDown() async throws {
        helper.shutdown()
    }

    /// A runner as on a Mac with `macOS` (nil: Linux) over the fake helper.
    func runner(macOS: OperatingSystemVersion?, options: CLIOptions = CLIOptions()) -> CLIRunner {
        let manager = ConnectionManager(
            store: store, helper: helper, clock: FakeClock(Date(timeIntervalSince1970: 1_700_000_000)),
            healthProbe: { _ in (false, 0) }, preferences: { Preferences() }, routes: { [] },
            authenticator: FakeAuthenticator())
        manager.systemVersion = macOS
        return CLIRunner(options: options, macOS: macOS, manager: manager, announceChanges: { [unowned self] in changesAnnounced += 1 })
    }

    struct Output {
        var code: Int32
        var out: String
        var err: String

        var json: [String: Any]? { (try? JSONSerialization.jsonObject(with: Data(out.utf8))) as? [String: Any] }
        var jsonArray: [[String: Any]]? { (try? JSONSerialization.jsonObject(with: Data(out.utf8))) as? [[String: Any]] }
    }

    /// Runs `command`, capturing what it writes to standard output and standard error.
    func run(_ command: CLICommand, macOS: OperatingSystemVersion?, options: CLIOptions = CLIOptions()) async throws -> Output {
        let outFile = home.appendingPathComponent("stdout-\(UUID().uuidString)")
        let errFile = home.appendingPathComponent("stderr-\(UUID().uuidString)")
        XCTAssertTrue(FileManager.default.createFile(atPath: outFile.path, contents: nil))
        XCTAssertTrue(FileManager.default.createFile(atPath: errFile.path, contents: nil))
        let outHandle = try FileHandle(forWritingTo: outFile)
        let errHandle = try FileHandle(forWritingTo: errFile)
        let savedOut = dup(STDOUT_FILENO)
        let savedErr = dup(STDERR_FILENO)
        dup2(outHandle.fileDescriptor, STDOUT_FILENO)
        dup2(errHandle.fileDescriptor, STDERR_FILENO)
        let code = await runner(macOS: macOS, options: options).run(command)
        dup2(savedOut, STDOUT_FILENO)
        dup2(savedErr, STDERR_FILENO)
        close(savedOut)
        close(savedErr)
        try outHandle.close()
        try errHandle.close()
        return Output(
            code: code, out: try String(contentsOf: outFile, encoding: .utf8), err: try String(contentsOf: errFile, encoding: .utf8))
    }

    /// An AnyConnect profile as `add --server` and `set` leave it, with a user name.
    @discardableResult
    func makeProfile(_ name: String = "Acme") throws -> Profile {
        var p = try store.create(name: name, type: .anyconnect, server: AnyConnectServer.parse("https://vpn.example.com:8443/engineering"))
        p.username = "alice"
        try store.save(p)
        return p
    }

    // MARK: parsing

    func parse(_ args: [String]) throws -> CLICommand { try CLICommand.parse(args) }

    func testAddParsesTheTypeAndTheServer() throws {
        XCTAssertEqual(try parse(["add", "Acme", "--type", "anyconnect"]), .add(name: "Acme", type: .anyconnect))
        XCTAssertEqual(try parse(["add", "Acme", "--type", "ANYCONNECT"]), .add(name: "Acme", type: .anyconnect))
        XCTAssertEqual(
            try parse(["add", "Acme", "VPN", "--type=anyconnect", "--server", "https://vpn.example.com:8443/engineering", "--json"]),
            .add(
                name: "Acme VPN", type: .anyconnect, json: true,
                server: AnyConnectServer(host: "vpn.example.com", port: 8443, usergroup: "engineering")))
        XCTAssertEqual(
            try parse(["add", "--server=VPN.Example.com", "Acme", "--type", "anyconnect"]),
            .add(name: "Acme", type: .anyconnect, server: AnyConnectServer(host: "vpn.example.com")))
        XCTAssertEqual(
            try parse(["add", "Acme", "-t", "anyconnect", "--server", "https://[2001:db8::1]:8443/"]),
            .add(name: "Acme", type: .anyconnect, server: AnyConnectServer(host: "2001:db8::1", port: 8443)))
        // The other types are unchanged.
        XCTAssertEqual(try parse(["add", "Lab", "--type", "forti"]), .add(name: "Lab", type: .forti))
        XCTAssertEqual(try parse(["add", "Lab", "--type", "fortigate"]), .add(name: "Lab", type: .forti))
        XCTAssertEqual(try parse(["add", "Lab", "--type", "openvpn"]), .add(name: "Lab", type: .openvpn))
    }

    func testAddRefusesWhatIsNotAServerAddress() throws {
        for server in [
            "", "ftp://vpn.example.com", "http://vpn.example.com", "https://alice@vpn.example.com", "https://vpn.example.com?x=1",
            "https://vpn.example.com#top", "https://vpn.example.com:0", "https://vpn.example.com:65536", "https://vpn.example.com:08443",
            "https://vpn.example.com:abc", "https://", "https://vpn example.com", "https://vpn.example.com/../x",
            "https://vpn.example.com/a%2Fb", "https://2001:db8::1/", "https://[2001:db8::1%en0]/", "https://:443"
        ] {
            XCTAssertNil(AnyConnectServer.parse(server), server)
            XCTAssertThrowsError(try parse(["add", "Acme", "--type", "anyconnect", "--server", server]), server) { error in
                let usage = error as? CLIUsageError
                XCTAssertEqual(usage?.command, "add", server)
                XCTAssertEqual(AutomationErrorCode.of(error), .invalidArgument)
                if server.count > 8 { XCTAssertFalse(usage?.message.contains(server) ?? true, "\(server) is not echoed") }
            }
        }
    }

    /// A refused address may carry a password (user info) or a token (a query): no error repeats it, in text or JSON.
    func testARefusedServerAddressNeverEchoesItsSecrets() throws {
        let secrets = ["MyPassword", "tok3n-9f2c", "frag-s3cret"]
        let lines: [[String]] = [
            ["add", "Acme", "--type", "anyconnect", "--server", "https://alice:MyPassword@vpn.example.com"],
            ["add", "Acme", "--type", "anyconnect", "--server=https://alice:MyPassword@vpn.example.com/staff"],
            ["add", "Acme", "--type", "anyconnect", "--server", "https://vpn.example.com/?token=tok3n-9f2c"],
            ["add", "Acme", "--type", "anyconnect", "--server", "https://vpn.example.com/staff#frag-s3cret"],
            ["add", "Acme", "--type", "anyconnect", "--server", "ftp://alice:MyPassword@vpn.example.com"],
            // The wrong option name: refused as unknown, without what follows the "=".
            ["add", "Acme", "--type", "anyconnect", "--servr=https://alice:MyPassword@vpn.example.com"],
            ["add", "Acme", "--type", "forti", "--server", "https://alice:MyPassword@vpn.example.com"]
        ]
        for args in lines {
            XCTAssertThrowsError(try parse(args), args.joined(separator: " ")) { error in
                XCTAssertTrue(error is CLIUsageError)
                var shown = error.localizedDescription + ((error as? CLIUsageError)?.message ?? "")
                shown += String(decoding: (try? AutomationJSON.encoder().encode(ErrorEnvelope(error))) ?? Data(), as: UTF8.self)
                for secret in secrets { XCTAssertFalse(shown.contains(secret), "\(secret) in: \(shown)") }
                XCTAssertFalse(shown.contains("alice:"), shown)
            }
        }
        // It says what is wrong instead.
        XCTAssertThrowsError(try parse(lines[0])) {
            let message = ($0 as? CLIUsageError)?.message ?? ""
            XCTAssertTrue(message.contains("without user info, a query or a fragment"), message)
        }
    }

    /// `set acme MyPassword`: the error names the position of the argument that is wrong, never its text.
    func testASetArgumentWithoutAKeyIsNotEchoed() throws {
        let cases: [([String], String)] = [
            (["set", "acme", "MyPassword"], "Argument 2 is not in key=value form."),
            (["set", "acme", "username=alice", "MyPassword"], "Argument 3 is not in key=value form."),
            (["set", "acme", "--json", "=MyPassword"], "Argument 2 is not in key=value form."),
            (["set", "acme", "MyPassword", "username=alice"], "Argument 2 is not in key=value form.")
        ]
        for (args, message) in cases {
            XCTAssertThrowsError(try parse(args), args.joined(separator: " ")) { error in
                let usage = error as? CLIUsageError
                XCTAssertEqual(usage?.message, message)
                XCTAssertEqual(usage?.command, "set")
                XCTAssertEqual(AutomationErrorCode.of(error), .invalidArgument)
                let json = String(decoding: (try? AutomationJSON.encoder().encode(ErrorEnvelope(error))) ?? Data(), as: UTF8.self)
                XCTAssertTrue(json.contains(message), json)
                XCTAssertFalse(json.contains("MyPassword"), json)
                XCTAssertFalse(error.localizedDescription.contains("MyPassword"))
            }
        }
        // Well-formed assignments are unchanged.
        XCTAssertEqual(
            try parse(["set", "acme", "authgroup=a=b"]), .set(id: "acme", assignments: [.init(key: "authgroup", value: "a=b")]))
    }

    func testAddRefusesTheServerForOtherTypesAndWithoutAValue() throws {
        for type in ["forti", "openvpn"] {
            XCTAssertThrowsError(try parse(["add", "Lab", "--type", type, "--server", "https://vpn.example.com"])) { error in
                XCTAssertEqual((error as? CLIUsageError)?.command, "add")
            }
        }
        XCTAssertThrowsError(try parse(["add", "Acme", "--type", "anyconnect", "--server"]))
        XCTAssertThrowsError(try parse(["add", "--type", "anyconnect", "--server", "vpn.example.com"]))  // no name
        XCTAssertNoThrow(try parse(["add", "Acme", "--type", "globalprotect"]))  // GlobalProtectCLITests
        XCTAssertThrowsError(try parse(["add", "Acme", "--type", "cisco"]))
        XCTAssertThrowsError(try parse(["add", "Acme"]))
    }

    func testUsageAndCompletionNameTheType() {
        let usage = CLIHelp.usage(for: "add")
        XCTAssertTrue(usage.contains("--type openvpn|forti|anyconnect|globalprotect [--server URL]"), usage)
        XCTAssertTrue(usage.contains("Cisco AnyConnect"), usage)
        XCTAssertTrue(
            CLIHelp.usage(for: "set").contains(
                "usergroup, authgroup, gateway, skip_portal, trusted_cert, server_cert, gateway_server_cert, tls_only"))
        for shell in CLICommand.Shell.allCases {
            let script = CLICompletions.script(for: shell)
            XCTAssertTrue(script.contains("anyconnect"), "\(shell)")
            XCTAssertTrue(script.contains("--server") || script.contains("-l server"), "\(shell)")
            for key in ["usergroup", "authgroup", "server_cert", "tls_only"] { XCTAssertTrue(script.contains(key), "\(shell) \(key)") }
        }
        XCTAssertTrue(CLIRunner.wantsJSON(.add(name: "A", type: .anyconnect, json: true, server: nil)))
        XCTAssertFalse(CLIRunner.wantsJSON(.add(name: "A", type: .anyconnect)))
    }

    // MARK: add

    func testAddCreatesTheProfileFromTheServerAddress() async throws {
        let server = AnyConnectServer.parse("https://VPN.example.com:8443/engineering")
        let result = try await run(.add(name: "Acme", type: .anyconnect, server: server), macOS: macOS154)
        XCTAssertEqual(result.code, 0, result.err)
        XCTAssertEqual(result.out, "Created “Acme” (acme).\n")
        XCTAssertTrue(result.err.contains("passtunnel set acme username=alice"), result.err)
        XCTAssertTrue(result.err.contains("passtunnel secret acme password"), result.err)
        XCTAssertEqual(changesAnnounced, 1)
        let p = try store.get("acme")
        XCTAssertEqual(p.type, .anyconnect)
        XCTAssertEqual([p.host, p.usergroup], ["vpn.example.com", "engineering"])
        XCTAssertEqual(p.port, 8443)
        XCTAssertEqual(p.otpDelivery, .separate)
        XCTAssertEqual(p.passwordMode, .keychain)
        XCTAssertTrue(helper.requests.isEmpty, "nothing asks the helper")
    }

    func testAddWithoutAServerPointsAtTheKeys() async throws {
        let result = try await run(.add(name: "Acme", type: .anyconnect), macOS: macOS154)
        XCTAssertEqual(result.code, 0, result.err)
        XCTAssertTrue(result.err.contains("passtunnel set acme host=vpn.example.com username=alice"), result.err)
        let p = try store.get("acme")
        XCTAssertEqual([p.host, p.usergroup], ["", ""])
        XCTAssertEqual(p.port, 443)
    }

    func testAddJSONIsTheSummary() async throws {
        let server = AnyConnectServer.parse("vpn.example.com")
        let result = try await run(.add(name: "Acme", type: .anyconnect, json: true, server: server), macOS: macOS154)
        XCTAssertEqual(result.code, 0, result.err)
        let json = try XCTUnwrap(result.json)
        XCTAssertEqual(json["id"] as? String, "acme")
        XCTAssertEqual(json["type"] as? String, "anyconnect")
        XCTAssertNil(json["connect_refusal"])
        XCTAssertNil(json["needs_newer_version"])
        XCTAssertEqual(try store.get("acme").host, "vpn.example.com")
    }

    func testAddIsRefusedWhereTheProfileCannotConnect() async throws {
        let server = AnyConnectServer.parse("https://vpn.example.com")
        for (macOS, message) in [
            (macOS153, "Cisco AnyConnect requires macOS 15.4 or later."), (macOS13, "Cisco AnyConnect requires macOS 15.4 or later.")
        ] as [(OperatingSystemVersion?, String)] {
            let text = try await run(.add(name: "Acme", type: .anyconnect, server: server), macOS: macOS)
            XCTAssertEqual(text.code, AutomationErrorCode.configInvalid.exitCode)
            XCTAssertEqual(text.out, "")
            XCTAssertEqual(text.err, "passtunnel: \(message)\n")
            let json = try await run(.add(name: "Acme", type: .anyconnect, json: true, server: server), macOS: macOS)
            XCTAssertEqual(json.code, AutomationErrorCode.configInvalid.exitCode)
            let error = try XCTUnwrap(json.json?["error"] as? [String: Any])
            XCTAssertEqual(error["code"] as? String, "config_invalid")
            XCTAssertEqual(error["message"] as? String, message)
            XCTAssertEqual(store.list(), [], "no profile is made")
        }
        // The other types are not affected by the system.
        let forti = try await run(.add(name: "Lab", type: .forti), macOS: macOS13)
        XCTAssertEqual(forti.code, 0, forti.err)
        let open = try await run(.add(name: "Home", type: .openvpn), macOS: nil)
        XCTAssertEqual(open.code, 0, open.err)
    }

    func testAddStoresNothingForAnInvalidServerThatSkippedTheParser() throws {
        // `create` is the one place that writes it: another type has no such setting.
        let server = AnyConnectServer.parse("https://vpn.example.com")
        XCTAssertThrowsError(try store.create(name: "Lab", type: .forti, server: server)) {
            XCTAssertEqual($0 as? PTError, .invalidField("server"))
        }
        XCTAssertEqual(store.list(), [])
        // And what the parser accepts, `save` accepts.
        let p = try store.create(name: "Acme", type: .anyconnect, server: AnyConnectServer.parse("https://[2001:db8::1]:8443/eng-1"))
        XCTAssertEqual([p.host, p.usergroup], ["2001:db8::1", "eng-1"])
        XCTAssertEqual(try store.get(p.id), p)
    }

    // MARK: set / show

    func testSetAndShowTheAnyConnectKeys() async throws {
        try makeProfile()
        let assignments: [CLICommand.Assignment] = [
            .init(key: "host", value: "gw.example.com"), .init(key: "port", value: "4443"), .init(key: "usergroup", value: "staff"),
            .init(key: "auth-group", value: "Employees"), .init(key: "server_cert", value: pin), .init(key: "tls-only", value: "yes"),
            .init(key: "set_dns", value: "true"), .init(key: "set-routes", value: "false"), .init(key: "otp_mode", value: "totp"),
            .init(key: "username", value: "bob")
        ]
        let set = try await run(.set(id: "acme", assignments: assignments), macOS: macOS154)
        XCTAssertEqual(set.code, 0, set.err)
        XCTAssertEqual(set.out, "Saved.\n")
        XCTAssertEqual(changesAnnounced, 1)
        let p = try store.get("acme")
        XCTAssertEqual([p.host, p.usergroup, p.authgroup, p.serverCert, p.username], ["gw.example.com", "staff", "Employees", pin, "bob"])
        XCTAssertEqual(p.port, 4443)
        XCTAssertTrue(p.tlsOnly)
        XCTAssertTrue(p.setDNS)
        XCTAssertFalse(p.setRoutes)
        XCTAssertEqual(p.otpMode, .totp)
        XCTAssertEqual(p.otpDelivery, .separate)

        // The same, as `show --json` (set --json prints it too).
        let json = try await run(.set(id: "acme", assignments: [.init(key: "tls_only", value: "off")], json: true), macOS: macOS154)
        XCTAssertEqual(json.code, 0, json.err)
        let profile = try XCTUnwrap(json.json?["profile"] as? [String: Any])
        XCTAssertEqual(profile["type"] as? String, "anyconnect")
        XCTAssertEqual(profile["host"] as? String, "gw.example.com")
        XCTAssertEqual(profile["port"] as? Int, 4443)
        XCTAssertEqual(profile["usergroup"] as? String, "staff")
        XCTAssertEqual(profile["authgroup"] as? String, "Employees")
        XCTAssertEqual(profile["server_cert"] as? String, pin)
        XCTAssertEqual(profile["tls_only"] as? Bool, false)
        XCTAssertEqual(profile["set_dns"] as? Bool, true)
        XCTAssertEqual(profile["set_routes"] as? Bool, false)
        XCTAssertEqual(profile["otp_delivery"] as? String, "separate")
        XCTAssertNil(json.json?["connect_refusal"], "it can connect here")
        XCTAssertNil(json.json?["config_file"])

        let text = try await run(.show(id: "acme", json: false), macOS: macOS154)
        XCTAssertEqual(text.code, 0, text.err)
        let rows = Dictionary(
            uniqueKeysWithValues: text.out.split(separator: "\n").compactMap { line -> (String, String)? in
                let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                return parts.count == 2 ? (String(parts[0]), parts[1].trimmingCharacters(in: .whitespaces)) : nil
            })
        XCTAssertEqual(rows["type"], "anyconnect")
        XCTAssertEqual(rows["host"], "gw.example.com")
        XCTAssertEqual(rows["port"], "4443")
        XCTAssertEqual(rows["usergroup"], "staff")
        XCTAssertEqual(rows["authgroup"], "Employees")
        XCTAssertEqual(rows["server_cert"], pin)
        XCTAssertEqual(rows["tls_only"], "false")
        XCTAssertEqual(rows["set_dns"], "true")
        XCTAssertEqual(rows["set_routes"], "false")
        XCTAssertNil(rows["trusted_cert"], "FortiGate's key is not listed")
        XCTAssertNil(rows["config"], "OpenVPN's neither")
        XCTAssertNil(rows["connect"], "nothing to note")
    }

    func testSetRefusesWhatTheProfileRulesRefuse() async throws {
        try makeProfile()
        let before = try store.get("acme")
        let bad: [(String, String)] = [
            ("host", "https://vpn.example.com"), ("host", "vpn.example.com:8443"), ("host", "fe80::1%en0"), ("port", "0"),
            ("port", "70000"), ("usergroup", "/engineering"), ("usergroup", "a/../b"), ("authgroup", "=Employees"),
            ("server_cert", "pin-sha256:short"), ("tls_only", "maybe"), ("password_mode", "none"), ("username", "a\u{7}b")
        ]
        for (key, value) in bad {
            let result = try await run(.set(id: "acme", assignments: [.init(key: key, value: value)], json: true), macOS: macOS154)
            XCTAssertEqual(result.code, AutomationExit.usage, "\(key)=\(value): \(result.out)")
            XCTAssertEqual((result.json?["error"] as? [String: Any])?["code"] as? String, "invalid_argument", "\(key)=\(value)")
        }
        XCTAssertEqual(try store.get("acme"), before)
        // FortiGate's key on an AnyConnect profile, and AnyConnect's on another type.
        let wrong = try await run(.set(id: "acme", assignments: [.init(key: "trusted_cert", value: "aa")], json: true), macOS: macOS154)
        XCTAssertEqual(wrong.code, AutomationExit.usage)
        let forti = try store.create(name: "Lab", type: .forti)
        let other = try await run(.set(id: forti.id, assignments: [.init(key: "usergroup", value: "staff")], json: true), macOS: macOS154)
        XCTAssertEqual(other.code, AutomationExit.usage)
        let unknown = try await run(.set(id: "acme", assignments: [.init(key: "user_agent", value: "x")]), macOS: macOS154)
        XCTAssertEqual(unknown.code, AutomationExit.usage)
    }

    func testSetAndShowWorkWhereTheProfileCannotConnect() async throws {
        try makeProfile()
        for macOS in [macOS153, nil] as [OperatingSystemVersion?] {
            let set = try await run(.set(id: "acme", assignments: [.init(key: "authgroup", value: "Staff")]), macOS: macOS)
            XCTAssertEqual(set.code, 0, set.err)
            let show = try await run(.show(id: "acme", json: false), macOS: macOS)
            XCTAssertEqual(show.code, 0, show.err)
            XCTAssertTrue(show.out.contains("authgroup"), show.out)
        }
    }

    func testShowSaysWhyTheProfileCannotConnect() async throws {
        try makeProfile()
        let old = try await run(.show(id: "acme", json: false), macOS: macOS153)
        XCTAssertTrue(old.out.contains("Requires macOS 15.4 or later"), old.out)
        // Linux refuses nothing up front (#187): the distribution's openconnect is checked when connecting.
        let linux = try await run(.show(id: "acme", json: false), macOS: nil)
        XCTAssertFalse(linux.out.contains("Linux"), linux.out)

        let json = try await run(.show(id: "acme", json: true), macOS: macOS153)
        let refusal = try XCTUnwrap(json.json?["connect_refusal"] as? [String: Any])
        XCTAssertEqual(refusal["code"] as? String, "config_invalid")
        XCTAssertEqual(refusal["message"] as? String, "Cisco AnyConnect requires macOS 15.4 or later.")
        XCTAssertEqual((json.json?["profile"] as? [String: Any])?["type"] as? String, "anyconnect")
        let linuxJSON = try await run(.show(id: "acme", json: true), macOS: nil)
        XCTAssertNil(linuxJSON.json?["connect_refusal"])
        let ok = try await run(.show(id: "acme", json: true), macOS: macOS154)
        XCTAssertNil(ok.json?["connect_refusal"])
        // No password, TOTP secret or code in any of it.
        try Secrets.set("acme", .password, "S3cr3t-Pa55")
        let withSecret = try await run(.show(id: "acme", json: true), macOS: macOS154)
        XCTAssertEqual(withSecret.json?["password_saved"] as? Bool, true)
        XCTAssertFalse(withSecret.out.contains("S3cr3t-Pa55"))
    }

    // MARK: list

    func testListPresentsItAsAnOrdinaryProfile() async throws {
        try makeProfile()
        _ = try store.create(name: "Lab", type: .forti)
        let text = try await run(.list(json: false, quiet: false), macOS: macOS154)
        XCTAssertEqual(text.code, 0, text.err)
        let line = try XCTUnwrap(text.out.split(separator: "\n").first { $0.contains("acme") }.map(String.init))
        XCTAssertTrue(line.contains("Cisco AnyConnect"), line)
        XCTAssertTrue(line.contains("alice"), line)
        XCTAssertFalse(line.contains("Needs a newer PassTunnel"), line)
        XCTAssertFalse(line.contains("Requires macOS"), line)
        XCTAssertFalse(text.out.contains("Needs a newer PassTunnel"), text.out)

        let json = try await run(.list(json: true, quiet: false), macOS: macOS154)
        let profiles = try XCTUnwrap(json.jsonArray)
        let entry = try XCTUnwrap(profiles.first { $0["id"] as? String == "acme" })
        XCTAssertEqual(entry["type"] as? String, "anyconnect")
        XCTAssertEqual(entry["username"] as? String, "alice")
        XCTAssertEqual(entry["password_mode"] as? String, "keychain")
        XCTAssertNil(entry["needs_newer_version"])
        XCTAssertNil(entry["connect_refusal"])
        let quiet = try await run(.list(json: false, quiet: true), macOS: macOS154)
        XCTAssertEqual(quiet.out, "acme\nlab\n")
    }

    func testListShowsThePlatformRefusalInsteadOfNeedsANewerPassTunnel() async throws {
        try makeProfile()
        _ = try store.create(name: "Lab", type: .forti)
        let expected: [(OperatingSystemVersion?, String, String)] = [
            (macOS153, "Requires macOS 15.4 or later", "Cisco AnyConnect requires macOS 15.4 or later."),
            (macOS13, "Requires macOS 15.4 or later", "Cisco AnyConnect requires macOS 15.4 or later.")
        ]
        for (macOS, note, message) in expected {
            let text = try await run(.list(json: false, quiet: false), macOS: macOS)
            let line = try XCTUnwrap(text.out.split(separator: "\n").first { $0.contains("acme") }.map(String.init))
            XCTAssertTrue(line.contains("Cisco AnyConnect · " + note + " · alice"), line)
            XCTAssertFalse(text.out.contains("Needs a newer PassTunnel"), text.out)
            let lab = try XCTUnwrap(text.out.split(separator: "\n").first { $0.contains("lab") }.map(String.init))
            XCTAssertFalse(lab.contains(note), "only the profile that cannot connect: \(lab)")

            let json = try await run(.list(json: true, quiet: false), macOS: macOS)
            let profiles = try XCTUnwrap(json.jsonArray)
            let entry = try XCTUnwrap(profiles.first { $0["id"] as? String == "acme" })
            XCTAssertNil(entry["needs_newer_version"])
            let refusal = try XCTUnwrap(entry["connect_refusal"] as? [String: Any])
            XCTAssertEqual(refusal["code"] as? String, "config_invalid")
            XCTAssertEqual(refusal["message"] as? String, message)
            XCTAssertNil(try XCTUnwrap(profiles.first { $0["id"] as? String == "lab" })["connect_refusal"])
        }
    }

    func testAProfileOfAnUnknownTypeIsStillNeedingANewerPassTunnel() async throws {
        try makeProfile()
        try store.paths.ensureDirectories()
        try FileIO.makeDirectory(store.dir("future"))
        try Data(UnsupportedProfileTests.futureJSON.utf8).write(to: store.profileURL("future"))
        let text = try await run(.list(json: false, quiet: false), macOS: macOS154)
        let line = try XCTUnwrap(text.out.split(separator: "\n").first { $0.contains("future") }.map(String.init))
        XCTAssertTrue(line.contains("wireguard · Needs a newer PassTunnel"), line)
        let json = try await run(.list(json: true, quiet: false), macOS: macOS154)
        let profiles = try XCTUnwrap(json.jsonArray)
        XCTAssertEqual(profiles.first { $0["id"] as? String == "future" }?["needs_newer_version"] as? Bool, true)
        XCTAssertNil(profiles.first { $0["id"] as? String == "acme" }?["needs_newer_version"])
    }

    // MARK: status

    func testStatusSaysWhyItCannotConnect() async throws {
        try makeProfile()
        let old = try await run(.status(id: nil, json: false), macOS: macOS153)
        XCTAssertEqual(old.code, 0, old.err)
        XCTAssertTrue(old.out.contains("disconnected"), old.out)
        XCTAssertTrue(old.out.contains("Requires macOS 15.4 or later"), old.out)
        let linux = try await run(.status(id: nil, json: false), macOS: nil)
        XCTAssertFalse(linux.out.contains("Linux"), "nothing refused up front on Linux: \(linux.out)")
        let ok = try await run(.status(id: nil, json: false), macOS: macOS154)
        XCTAssertTrue(ok.out.contains("disconnected"), ok.out)
        XCTAssertFalse(ok.out.contains("Requires macOS"), ok.out)

        let json = try await run(.status(id: "acme", json: true), macOS: macOS153)
        XCTAssertEqual(json.code, AutomationExit.notFound, "not connected")
        let status = try XCTUnwrap(json.json)
        XCTAssertEqual(status["type"] as? String, "anyconnect")
        XCTAssertEqual(status["state"] as? String, "disconnected")
        let refusal = try XCTUnwrap(status["connect_refusal"] as? [String: Any])
        XCTAssertEqual(refusal["code"] as? String, "config_invalid")
        XCTAssertEqual(refusal["message"] as? String, "Cisco AnyConnect requires macOS 15.4 or later.")
        let all = try await run(.status(id: nil, json: true), macOS: nil)
        XCTAssertNil(all.jsonArray?.first?["connect_refusal"])
        let fine = try await run(.status(id: "acme", json: true), macOS: macOS154)
        XCTAssertNil(fine.json?["connect_refusal"])
    }

    // MARK: connect / toggle

    func testConnectAndToggleRefuseWithTheSameText() async throws {
        try makeProfile()
        try Secrets.set("acme", .password, "S3cr3t-Pa55")
        for (macOS, message) in [
            (macOS153, "Cisco AnyConnect requires macOS 15.4 or later.")
        ] as [(OperatingSystemVersion?, String)] {
            for command in [
                CLICommand.connect(id: "acme"), .connect(id: nil), .toggle(id: "acme"), .connect(id: "acme", force: true, wait: true, timeout: 5)
            ] {
                let text = try await run(command, macOS: macOS, options: CLIOptions(noInput: true, noAuthPrompt: true))
                XCTAssertEqual(text.code, AutomationErrorCode.configInvalid.exitCode, "\(command)")
                XCTAssertEqual(text.out, "")
                XCTAssertEqual(text.err, "passtunnel: \(message)\n", "\(command)")
            }
            for command in [CLICommand.connect(id: "acme", json: true), .toggle(id: "acme", json: true)] {
                let json = try await run(command, macOS: macOS)
                XCTAssertEqual(json.code, AutomationErrorCode.configInvalid.exitCode)
                let error = try XCTUnwrap(json.json?["error"] as? [String: Any])
                XCTAssertEqual(error["code"] as? String, "config_invalid")
                XCTAssertEqual(error["message"] as? String, message)
                XCTAssertNil(error["failure"], "refused before an attempt")
            }
        }
        XCTAssertTrue(helper.requests.isEmpty, "the helper is not asked anything: \(helper.requests)")
        XCTAssertEqual(helper.starts.count, 0)
    }

    // MARK: files that other versions write

    func testExportAndRemoveWorkWhereItCannotConnect() async throws {
        try makeProfile()
        let url = home.appendingPathComponent("acme.passtunnel")
        let export = try await run(.export(id: "acme", output: url.path, json: true), macOS: macOS153)
        XCTAssertEqual(export.code, 0, export.err)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        let text = try String(contentsOf: url, encoding: .utf8)
        XCTAssertTrue(text.contains("\"anyconnect\""), text)
        XCTAssertTrue(text.contains("engineering"), text)
        XCTAssertFalse(text.contains("alice"), "the user name is not shared")
        let imported = try await run(.importFile(path: url.path, name: "Copy", json: true), macOS: macOS153)
        XCTAssertEqual(imported.code, 0, imported.err)
        let summary = try XCTUnwrap(imported.json)
        XCTAssertEqual(summary["type"] as? String, "anyconnect")
        XCTAssertEqual((summary["connect_refusal"] as? [String: Any])?["code"] as? String, "config_invalid")
        let copy = try store.get("copy")
        XCTAssertEqual([copy.host, copy.usergroup, copy.authgroup, copy.serverCert], ["vpn.example.com", "engineering", "", ""])
        XCTAssertEqual(copy.port, 8443)
        let removed = try await run(.remove(id: "acme", yes: true, json: true), macOS: macOS153)
        XCTAssertEqual(removed.code, 0, removed.err)
        XCTAssertFalse(store.exists("acme"))
        XCTAssertEqual(helper.starts.count, 0)
    }
}
