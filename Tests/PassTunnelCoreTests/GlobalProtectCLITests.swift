import Foundation
import PassTunnelShared
import XCTest

@testable import PassTunnelCLI
@testable import PassTunnelCore
@testable import PassTunnelKit

private let pin = "pin-sha256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk="
private let gatewayPin = "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
private let macOS154 = OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0)
private let macOS153 = OperatingSystemVersion(majorVersion: 15, minorVersion: 3, patchVersion: 0)
private let reportURL = "https://github.com/PassTunnel/passtunnel/issues/new?template=globalprotect_report.md"
private let feedback = "Palo Alto GlobalProtect support is experimental. Please report how it works: \(reportURL)"

/// The command line of Palo Alto GlobalProtect profiles (experimental): `add --type globalprotect`, `set`, `show`,
/// `list`, `status`, `diagnose`, `import`, the label, and that every other type's output is untouched. Every test
/// uses a temporary profile directory, a private secret store and a fake helper; nothing is connected.
@MainActor
final class GlobalProtectCLITests: CoreTestCase {
    var helper: FakeHelper!
    var changesAnnounced = 0

    override func setUp() async throws {
        helper = FakeHelper()
        changesAnnounced = 0
    }

    override func tearDown() async throws {
        helper.shutdown()
    }

    func runner(macOS: OperatingSystemVersion?) -> CLIRunner {
        let manager = ConnectionManager(
            store: store, helper: helper, clock: FakeClock(Date(timeIntervalSince1970: 1_700_000_000)),
            healthProbe: { _ in (false, 0) }, preferences: { Preferences() }, routes: { [] },
            authenticator: FakeAuthenticator())
        manager.systemVersion = macOS
        return CLIRunner(options: CLIOptions(), macOS: macOS, manager: manager, announceChanges: { [unowned self] in changesAnnounced += 1 })
    }

    struct Output {
        var code: Int32
        var out: String
        var err: String

        var json: [String: Any]? { (try? JSONSerialization.jsonObject(with: Data(out.utf8))) as? [String: Any] }
        var jsonArray: [[String: Any]]? { (try? JSONSerialization.jsonObject(with: Data(out.utf8))) as? [[String: Any]] }
    }

    func run(_ command: CLICommand, macOS: OperatingSystemVersion? = macOS154) async throws -> Output {
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
        let code = await runner(macOS: macOS).run(command)
        dup2(savedOut, STDOUT_FILENO)
        dup2(savedErr, STDERR_FILENO)
        close(savedOut)
        close(savedErr)
        try outHandle.close()
        try errHandle.close()
        return Output(
            code: code, out: try String(contentsOf: outFile, encoding: .utf8), err: try String(contentsOf: errFile, encoding: .utf8))
    }

    @discardableResult
    func makeProfile(_ name: String = "Acme") throws -> Profile {
        var p = try store.create(name: name, type: .globalprotect, server: AnyConnectServer(host: "vpn.example.com"))
        p.username = "alice"
        try store.save(p)
        return p
    }

    func parse(_ args: [String]) throws -> CLICommand { try CLICommand.parse(args) }

    // MARK: parsing

    func testAddParsesTheTypeAndTheServer() throws {
        XCTAssertEqual(try parse(["add", "Acme", "--type", "globalprotect"]), .add(name: "Acme", type: .globalprotect))
        XCTAssertEqual(try parse(["add", "Acme", "-t", "GlobalProtect"]), .add(name: "Acme", type: .globalprotect))
        XCTAssertEqual(
            try parse(["add", "Acme", "VPN", "--type=globalprotect", "--server", "https://VPN.example.com:8443", "--json"]),
            .add(name: "Acme VPN", type: .globalprotect, json: true, server: AnyConnectServer(host: "vpn.example.com", port: 8443)))
        XCTAssertEqual(
            try parse(["add", "Acme", "--type", "globalprotect", "--server", "vpn.example.com/"]),
            .add(name: "Acme", type: .globalprotect, server: AnyConnectServer(host: "vpn.example.com")))
        // The other types parse as before.
        XCTAssertEqual(try parse(["add", "Lab", "--type", "forti"]), .add(name: "Lab", type: .forti))
        XCTAssertEqual(
            try parse(["add", "Acme", "--type", "anyconnect", "--server", "https://vpn.example.com/staff"]),
            .add(name: "Acme", type: .anyconnect, server: AnyConnectServer(host: "vpn.example.com", usergroup: "staff")))
    }

    func testAddRefusesWhatIsNotAPortalAddress() throws {
        for server in [
            "", "ftp://vpn.example.com", "http://vpn.example.com", "https://alice@vpn.example.com", "https://vpn.example.com?x=1",
            "https://vpn.example.com#top", "https://vpn.example.com:0", "https://vpn.example.com:70000", "https://",
            "https://vpn.example.com/global-protect/login.esp", "https://vpn.example.com/ssl-vpn/login.esp", "https://vpn.example.com/staff"
        ] {
            XCTAssertNil(GlobalProtectServer.parse(server), server)
            XCTAssertThrowsError(try parse(["add", "Acme", "--type", "globalprotect", "--server", server]), server) { error in
                XCTAssertEqual((error as? CLIUsageError)?.command, "add", server)
                XCTAssertEqual(AutomationErrorCode.of(error), .invalidArgument)
                if server.count > 8 { XCTAssertFalse((error as? CLIUsageError)?.message.contains(server) ?? true, "\(server) is not echoed") }
            }
        }
        // The other types still refuse the option, and without echoing it.
        for type in ["forti", "openvpn"] {
            XCTAssertThrowsError(try parse(["add", "Lab", "--type", type, "--server", "https://vpn.example.com"])) {
                XCTAssertEqual(($0 as? CLIUsageError)?.command, "add")
            }
        }
    }

    /// A refused address may carry a password (user info) or a token (a query): no error repeats it, in text or JSON.
    func testARefusedServerOrValueNeverEchoesItsSecrets() throws {
        let secrets = ["MyPassword", "tok3n-9f2c", "frag-s3cret"]
        let lines: [[String]] = [
            ["add", "Acme", "--type", "globalprotect", "--server", "https://alice:MyPassword@vpn.example.com"],
            ["add", "Acme", "--type", "globalprotect", "--server=https://alice:MyPassword@vpn.example.com:8443"],
            ["add", "Acme", "--type", "globalprotect", "--server", "https://vpn.example.com/?token=tok3n-9f2c"],
            ["add", "Acme", "--type", "globalprotect", "--server", "https://vpn.example.com#frag-s3cret"],
            ["add", "Acme", "--type", "globalprotect", "--server", "https://vpn.example.com/global-protect/MyPassword"],
            ["add", "Acme", "--type", "globalprotect", "--servr=https://alice:MyPassword@vpn.example.com"],
            ["add", "Acme", "--type", "openvpn", "--server", "https://alice:MyPassword@vpn.example.com"],
            ["set", "acme", "MyPassword"]
        ]
        for args in lines {
            XCTAssertThrowsError(try parse(args), args.joined(separator: " ")) { error in
                XCTAssertTrue(error is CLIUsageError)
                var shown = error.localizedDescription + ((error as? CLIUsageError)?.message ?? "")
                shown += String(decoding: (try? AutomationJSON.encoder().encode(ErrorEnvelope(error))) ?? Data(), as: UTF8.self)
                for secret in secrets { XCTAssertFalse(shown.contains(secret), "\(secret) in: \(shown)") }
            }
        }
        XCTAssertThrowsError(try parse(lines[0])) {
            let message = ($0 as? CLIUsageError)?.message ?? ""
            XCTAssertTrue(message.contains("without a path, user info, a query or a fragment"), message)
        }
    }

    func testUsageAndCompletionNameTheType() {
        let usage = CLIHelp.usage(for: "add")
        XCTAssertTrue(usage.contains("--type openvpn|forti|anyconnect|globalprotect [--server URL]"), usage)
        XCTAssertTrue(usage.contains("Palo Alto GlobalProtect"), usage)
        for shell in CLICommand.Shell.allCases {
            XCTAssertTrue(CLICompletions.script(for: shell).contains("globalprotect"), "\(shell)")
        }
    }

    // MARK: add

    func testAddCreatesTheProfileAndAsksForReports() async throws {
        let server = GlobalProtectServer.parse("https://VPN.example.com:8443").map { AnyConnectServer(host: $0.host, port: $0.port) }
        let result = try await run(.add(name: "Acme", type: .globalprotect, server: server))
        XCTAssertEqual(result.code, 0, result.err)
        XCTAssertEqual(result.out, "Created “Acme” (acme).\n")
        XCTAssertTrue(result.err.contains("passtunnel set acme username=alice"), result.err)
        XCTAssertTrue(result.err.contains("passtunnel secret acme password"), result.err)
        XCTAssertEqual(result.err.components(separatedBy: feedback).count - 1, 1, "the report line, once: \(result.err)")
        XCTAssertEqual(changesAnnounced, 1)
        let p = try store.get("acme")
        XCTAssertEqual(p.type, .globalprotect)
        XCTAssertEqual([p.host, p.usergroup, p.gateway], ["vpn.example.com", "", ""])
        XCTAssertEqual(p.port, 8443)
        XCTAssertFalse(p.skipPortal)
        XCTAssertEqual(p.otpDelivery, .separate)
        XCTAssertTrue(helper.requests.isEmpty, "nothing asks the helper")

        let without = try await run(.add(name: "Other", type: .globalprotect))
        XCTAssertEqual(without.code, 0, without.err)
        XCTAssertTrue(without.err.contains("passtunnel set other host=vpn.example.com username=alice"), without.err)
        XCTAssertTrue(without.err.contains(feedback), without.err)
    }

    func testAddJSONHasTheLabelAndNoLine() async throws {
        let result = try await run(.add(name: "Acme", type: .globalprotect, json: true, server: AnyConnectServer(host: "vpn.example.com")))
        XCTAssertEqual(result.code, 0, result.err)
        let json = try XCTUnwrap(result.json)
        XCTAssertEqual(json["type"] as? String, "globalprotect")
        XCTAssertEqual(json["experimental"] as? Bool, true)
        XCTAssertNil(json["connect_refusal"])
        XCTAssertEqual(result.err, "", "standard output is the JSON, standard error is quiet")
    }

    func testAddOfOtherTypesPrintsNoReportLineAndNoLabel() async throws {
        for (type, server) in [
            (VPNType.openvpn, nil), (.forti, nil), (.anyconnect, AnyConnectServer(host: "vpn.example.com"))
        ] as [(VPNType, AnyConnectServer?)] {
            let human = try await run(.add(name: "H \(type.rawValue)", type: type, server: server))
            XCTAssertEqual(human.code, 0, human.err)
            XCTAssertFalse(human.err.contains("experimental"), human.err)
            XCTAssertFalse(human.out.contains("experimental"), human.out)
            let json = try await run(.add(name: "J \(type.rawValue)", type: type, json: true, server: server))
            XCTAssertNil(json.json?["experimental"], type.rawValue)
            XCTAssertFalse(json.out.contains("experimental"), json.out)
        }
    }

    func testAddIsRefusedWhereTheProfileCannotConnect() async throws {
        let server = AnyConnectServer(host: "vpn.example.com")
        let text = try await run(.add(name: "Acme", type: .globalprotect, server: server), macOS: macOS153)
        XCTAssertEqual(text.code, AutomationErrorCode.configInvalid.exitCode)
        XCTAssertEqual(text.out, "")
        XCTAssertEqual(text.err, "passtunnel: Palo Alto GlobalProtect requires macOS 15.4 or later.\n", "no report line either")
        let json = try await run(.add(name: "Acme", type: .globalprotect, json: true, server: server), macOS: macOS153)
        XCTAssertEqual(json.code, AutomationErrorCode.configInvalid.exitCode)
        XCTAssertEqual((json.json?["error"] as? [String: Any])?["code"] as? String, "config_invalid")
        XCTAssertEqual(store.list(), [], "no profile is made")
    }

    func testStoreAcceptsOnlyAServerWithoutAUserGroupForGlobalProtect() throws {
        XCTAssertThrowsError(
            try store.create(name: "Acme", type: .globalprotect, server: AnyConnectServer(host: "vpn.example.com", usergroup: "staff"))
        ) {
            XCTAssertEqual($0 as? PTError, .invalidField("usergroup"))
        }
        XCTAssertThrowsError(try store.create(name: "Lab", type: .forti, server: AnyConnectServer(host: "vpn.example.com"))) {
            XCTAssertEqual($0 as? PTError, .invalidField("server"))
        }
        XCTAssertEqual(store.list(), [])
    }

    // MARK: set / show

    func testSetAndShowTheGlobalProtectKeys() async throws {
        try makeProfile()
        let assignments: [CLICommand.Assignment] = [
            .init(key: "host", value: "portal.example.com"), .init(key: "port", value: "4443"), .init(key: "gateway", value: "Gateway 1"),
            .init(key: "skip-portal", value: "yes"), .init(key: "server_cert", value: pin), .init(key: "gateway_server_cert", value: gatewayPin),
            .init(key: "tls-only", value: "true"), .init(key: "set_dns", value: "true"), .init(key: "otp_mode", value: "totp")
        ]
        let set = try await run(.set(id: "acme", assignments: assignments))
        XCTAssertEqual(set.code, 0, set.err)
        XCTAssertEqual(set.out, "Saved.\n")
        let p = try store.get("acme")
        XCTAssertEqual([p.host, p.gateway, p.serverCert, p.gatewayServerCert], ["portal.example.com", "Gateway 1", pin, gatewayPin])
        XCTAssertEqual(p.port, 4443)
        XCTAssertTrue(p.skipPortal)
        XCTAssertTrue(p.tlsOnly)
        XCTAssertEqual(p.otpDelivery, .separate)

        let json = try await run(.set(id: "acme", assignments: [.init(key: "skip_portal", value: "off")], json: true))
        XCTAssertEqual(json.code, 0, json.err)
        let profile = try XCTUnwrap(json.json?["profile"] as? [String: Any])
        XCTAssertEqual(profile["type"] as? String, "globalprotect")
        XCTAssertEqual(profile["experimental"] as? Bool, true)
        XCTAssertEqual(profile["gateway"] as? String, "Gateway 1")
        XCTAssertEqual(profile["skip_portal"] as? Bool, false)
        XCTAssertEqual(profile["server_cert"] as? String, pin)
        XCTAssertEqual(profile["gateway_server_cert"] as? String, gatewayPin)
        XCTAssertEqual(profile["tls_only"] as? Bool, true)
        XCTAssertNil(profile["usergroup"], "AnyConnect's alone")
        XCTAssertNil(profile["authgroup"], "AnyConnect's alone")
        XCTAssertNil(json.json?["experimental"], "on the profile object, not beside it")

        let text = try await run(.show(id: "acme", json: false))
        let rows = Dictionary(
            uniqueKeysWithValues: text.out.split(separator: "\n").compactMap { line -> (String, String)? in
                let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                return parts.count == 2 ? (String(parts[0]), parts[1].trimmingCharacters(in: .whitespaces)) : nil
            })
        XCTAssertEqual(rows["type"], "globalprotect (experimental)")
        XCTAssertEqual(rows["gateway"], "Gateway 1")
        XCTAssertEqual(rows["skip_portal"], "false")
        XCTAssertEqual(rows["gateway_server_cert"], gatewayPin)
        XCTAssertNil(rows["usergroup"])
        XCTAssertNil(rows["config"])
    }

    func testSetRefusesWrongKeysAndBadValuesWithoutEchoingThem() async throws {
        try makeProfile()
        let before = try store.get("acme")
        let bad: [(String, String)] = [
            ("gateway", "=MyPassword"), ("server_cert", "pin-sha256:MyPassword"),
            ("gateway_server_cert", "MyPassword"), ("skip_portal", "MyPassword"), ("tls_only", "MyPassword"),
            ("host", "https://alice:MyPassword@vpn.example.com"), ("usergroup", "MyPassword"), ("authgroup", "MyPassword"),
            ("trusted_cert", "MyPassword"), ("password_mode", "none")
        ]
        for (key, value) in bad {
            let result = try await run(.set(id: "acme", assignments: [.init(key: key, value: value)], json: true))
            XCTAssertEqual(result.code, AutomationExit.usage, "\(key)=\(value): \(result.out)")
            XCTAssertEqual((result.json?["error"] as? [String: Any])?["code"] as? String, "invalid_argument", "\(key)")
            XCTAssertFalse(result.out.contains("MyPassword"), "\(key): \(result.out)")
            let human = try await run(.set(id: "acme", assignments: [.init(key: key, value: value)]))
            XCTAssertFalse((human.out + human.err).contains("MyPassword"), "\(key): \(human.err)")
        }
        XCTAssertEqual(try store.get("acme"), before)
        // GlobalProtect's keys on another type.
        let anyconnect = try store.create(name: "Corp", type: .anyconnect)
        for key in ["gateway", "skip_portal", "gateway_server_cert"] {
            let other = try await run(.set(id: anyconnect.id, assignments: [.init(key: key, value: "x")], json: true))
            XCTAssertEqual(other.code, AutomationExit.usage, key)
        }
    }

    func testSetAndShowWorkWhereTheProfileCannotConnect() async throws {
        try makeProfile()
        for macOS in [macOS153, OperatingSystemVersion(majorVersion: 13, minorVersion: 0, patchVersion: 0)] as [OperatingSystemVersion?] {
            let set = try await run(.set(id: "acme", assignments: [.init(key: "gateway", value: "Gateway 2")]), macOS: macOS)
            XCTAssertEqual(set.code, 0, set.err)
            let show = try await run(.show(id: "acme", json: true), macOS: macOS)
            XCTAssertEqual(show.code, 0, show.err)
            XCTAssertNotNil(show.json?["connect_refusal"])
            XCTAssertEqual((show.json?["profile"] as? [String: Any])?["experimental"] as? Bool, true)
        }
        let old = try await run(.show(id: "acme", json: false), macOS: macOS153)
        XCTAssertTrue(old.out.contains("Requires macOS 15.4 or later"), old.out)
    }

    // MARK: list / status / diagnose

    func testListLabelsOnlyTheExperimentalType() async throws {
        try makeProfile()
        _ = try store.create(name: "Lab", type: .forti)
        var corp = try store.create(name: "Corp", type: .anyconnect)
        corp.host = "vpn.example.com"
        try store.save(corp)
        _ = try store.create(name: "Home", type: .openvpn)
        let text = try await run(.list(json: false, quiet: false))
        XCTAssertEqual(text.code, 0, text.err)
        let lines = text.out.split(separator: "\n").map(String.init)
        let gp = try XCTUnwrap(lines.first { $0.contains("acme") })
        XCTAssertTrue(gp.contains("Palo Alto GlobalProtect (experimental)"), gp)
        XCTAssertTrue(gp.contains("alice"), gp)
        for line in lines where !line.contains("acme") { XCTAssertFalse(line.contains("experimental"), line) }
        XCTAssertEqual(text.err, "")

        let json = try await run(.list(json: true, quiet: false))
        let profiles = try XCTUnwrap(json.jsonArray)
        for entry in profiles {
            if entry["id"] as? String == "acme" {
                XCTAssertEqual(entry["experimental"] as? Bool, true)
                XCTAssertEqual(entry["type"] as? String, "globalprotect")
            } else {
                XCTAssertNil(entry["experimental"], "\(entry["id"] ?? "")")
            }
        }
    }

    /// The other types' output is exactly what it was: no `experimental` key and the same bytes as the summary
    /// encoded before the key existed.
    func testOutputOfOtherTypesIsByteIdentical() async throws {
        let forti = try store.create(name: "Lab", type: .forti)
        let open = try store.create(name: "Home", type: .openvpn)
        var corp = try store.create(name: "Corp", type: .anyconnect)
        corp.host = "vpn.example.com"
        try store.save(corp)
        let list = try await run(.list(json: true, quiet: false))
        XCTAssertFalse(list.out.contains("experimental"), list.out)
        let expectedKeys: Set<String> = [
            "id", "name", "type", "is_default", "pinned", "username", "password_mode", "otp_mode", "require_auth", "protected",
            "auto_reconnect", "connect_at_login"
        ]
        for entry in try XCTUnwrap(list.jsonArray) {
            XCTAssertEqual(Set(entry.keys), expectedKeys, "\(entry["id"] ?? "")")
        }
        for id in [forti.id, open.id, corp.id] {
            let status = try await run(.status(id: id, json: true))
            XCTAssertFalse(status.out.contains("experimental"), status.out)
            XCTAssertFalse(status.out.contains("notices"), status.out)
            let show = try await run(.show(id: id, json: true))
            XCTAssertFalse(show.out.contains("experimental"), show.out)
        }
        let table = try await run(.status(id: nil, json: false))
        XCTAssertFalse(table.out.contains("experimental"), table.out)
        let encoded = String(decoding: try AutomationJSON.encoder().encode(ProfileSummary(forti, isDefault: false)), as: UTF8.self)
        XCTAssertFalse(encoded.contains("experimental"), encoded)
        let diagnose = try await run(.diagnose(checkClock: false, json: true))
        XCTAssertFalse(diagnose.out.contains("experimental"), diagnose.out)
    }

    func testStatusAndDiagnoseCarryTheLabel() async throws {
        try makeProfile()
        _ = try store.create(name: "Lab", type: .forti)
        let table = try await run(.status(id: nil, json: false))
        let gp = try XCTUnwrap(table.out.split(separator: "\n").first { $0.contains("acme") })
        XCTAssertTrue(gp.contains("(experimental)"), String(gp))
        XCTAssertFalse(try XCTUnwrap(table.out.split(separator: "\n").first { $0.contains("lab") }).contains("experimental"))

        let json = try await run(.status(id: "acme", json: true))
        XCTAssertEqual(json.json?["experimental"] as? Bool, true)
        XCTAssertNil(json.json?["notices"])
        let all = try await run(.status(id: nil, json: true))
        XCTAssertEqual(all.jsonArray?.map { $0["experimental"] as? Bool }, [true, nil])

        let human = try await run(.diagnose(checkClock: false, json: false))
        let line = try XCTUnwrap(human.out.split(separator: "\n").first { $0.contains("acme") })
        XCTAssertTrue(line.contains("globalprotect (experimental)"), String(line))
        let report = try await run(.diagnose(checkClock: false, json: true))
        let profiles = try XCTUnwrap(report.json?["profiles"] as? [[String: Any]])
        XCTAssertEqual(profiles.first { $0["id"] as? String == "acme" }?["experimental"] as? Bool, true)
        XCTAssertNil(profiles.first { $0["id"] as? String == "lab" }?["experimental"])
    }

    static let hipLog =
        [
            "WARNING: Server asked us to submit HIP report with md5sum 0123456789abcdef0123456789abcdef.",
            "    VPN connectivity may be disabled or limited without HIP report submission.",
            "    You need to provide a --csd-wrapper argument with the HIP report submission script."
        ].joined(separator: "\n") + "\n"

    /// Human-mode `connect` prints the notice on every successful path: already connected, joining a connection
    /// another process is establishing, and (JSON has it on all of them) not otherwise.
    func testConnectPrintsTheHIPNoticeWhenAlreadyConnected() async throws {
        try makeProfile()
        helper.simulateExternalStart("acme", profileDir: store.dir("acme").path, since: Date(timeIntervalSince1970: 1_700_000_000))
        helper.setTunnel("acme", TunnelStatus(state: .up, interface: "utun5"))
        try Self.hipLog.write(to: store.logURL("acme"), atomically: true, encoding: .utf8)
        let human = try await run(.connect(id: "acme"))
        XCTAssertEqual(human.code, 0, human.err)
        XCTAssertTrue(human.out.contains("already connected"), human.out)
        XCTAssertTrue(human.err.contains(StatusNotice.hipReportNotSent.message), human.err)
        let json = try await run(.connect(id: "acme", json: true))
        XCTAssertEqual((json.json?["notices"] as? [[String: Any]])?.count, 1)
        XCTAssertEqual(json.err, "")
    }

    func testConnectPrintsTheHIPNoticeWhenJoiningAConnectionInProgress() async throws {
        try makeProfile()
        helper.simulateExternalStart("acme", profileDir: store.dir("acme").path, since: Date(timeIntervalSince1970: 1_700_000_000))
        helper.setTunnel("acme", TunnelStatus(state: .settingUp))
        try Self.hipLog.write(to: store.logURL("acme"), atomically: true, encoding: .utf8)
        // The connection comes up while this process follows it (the clock here is virtual).
        let helper = self.helper!
        helper.onStatus = { call in
            if call >= 4 { helper.setTunnel("acme", TunnelStatus(state: .up, interface: "utun5")) }
        }
        let human = try await run(.connect(id: "acme"))
        XCTAssertEqual(human.code, 0, human.err)
        XCTAssertTrue(human.err.contains("Already connecting"), human.err)
        XCTAssertTrue(human.err.contains(StatusNotice.hipReportNotSent.message), human.err)
    }

    func testAConnectedProfileOfAnotherTypePrintsNoNotice() async throws {
        let forti = try store.create(name: "Lab", type: .forti)
        helper.simulateExternalStart(forti.id, profileDir: store.dir(forti.id).path, since: Date(timeIntervalSince1970: 1_700_000_000))
        let human = try await run(.connect(id: forti.id))
        XCTAssertFalse(human.err.contains("host information report"), human.err)
    }

    func testTheToolUnavailableErrorMapsToConfigInvalidAndConfigurationKind() {
        let error = PTError.globalProtectToolUnavailable("openconnect 9.01 is too old")
        XCTAssertEqual(AutomationErrorCode.of(error), .configInvalid)
        XCTAssertEqual(ErrorReport(error).code, "config_invalid")
        let failure = ConnectionFailure.of(error, log: nil, handed: nil, at: Date(timeIntervalSince1970: 0))
        XCTAssertEqual(failure.kind, .configuration)
        XCTAssertFalse(failure.credentialsSent)
    }

    func testAConnectedProfileShowsTheHIPNotice() async throws {
        try makeProfile()
        helper.simulateExternalStart("acme", profileDir: store.dir("acme").path, since: Date(timeIntervalSince1970: 1_700_000_000))
        helper.setTunnel("acme", TunnelStatus(state: .up, interface: "utun5"))
        let log = [
            "WARNING: Server asked us to submit HIP report with md5sum 0123456789abcdef0123456789abcdef.",
            "    VPN connectivity may be disabled or limited without HIP report submission.",
            "    You need to provide a --csd-wrapper argument with the HIP report submission script."
        ]
        try (log.joined(separator: "\n") + "\n").write(to: store.logURL("acme"), atomically: true, encoding: .utf8)

        let json = try await run(.status(id: "acme", json: true))
        XCTAssertEqual(json.code, 0, json.err)
        XCTAssertEqual(json.json?["state"] as? String, "connected")
        let notices = try XCTUnwrap(json.json?["notices"] as? [[String: Any]])
        XCTAssertEqual(notices.count, 1)
        XCTAssertEqual(notices[0]["kind"] as? String, "hip_report_not_sent")
        XCTAssertEqual(notices[0]["message"] as? String, StatusNotice.hipReportNotSent.message)
        XCTAssertFalse(json.out.contains("md5sum"), "the log is not repeated")

        let human = try await run(.status(id: "acme", json: false))
        XCTAssertTrue(human.out.contains(StatusNotice.hipReportNotSent.message), human.out)

        // Without the warning, or not connected, there is none.
        try "Connected as 10.0.0.2\n".write(to: store.logURL("acme"), atomically: true, encoding: .utf8)
        let quiet = try await run(.status(id: "acme", json: true))
        XCTAssertNil(quiet.json?["notices"])
    }

    // MARK: import

    func testImportingAGlobalProtectProfileAsksForReports() async throws {
        try makeProfile()
        let file = home.appendingPathComponent("acme.passtunnel")
        try store.exportShare("acme", to: file)
        let result = try await run(.importFile(path: file.path, name: "Copy"))
        XCTAssertEqual(result.code, 0, result.err)
        XCTAssertTrue(result.out.contains("Imported “Copy” as copy."), result.out)
        XCTAssertEqual(result.err.components(separatedBy: feedback).count - 1, 1, result.err)
        XCTAssertEqual(try store.get("copy").type, .globalprotect)

        let json = try await run(.importFile(path: file.path, name: "Third", json: true))
        XCTAssertEqual(json.json?["experimental"] as? Bool, true)
        XCTAssertEqual(json.err, "")

        // Another type's import says nothing of the kind.
        let forti = try store.create(name: "Lab", type: .forti)
        let other = home.appendingPathComponent("lab.passtunnel")
        try store.exportShare(forti.id, to: other)
        let plain = try await run(.importFile(path: other.path, name: "Lab Copy"))
        XCTAssertEqual(plain.code, 0, plain.err)
        XCTAssertFalse(plain.err.contains("experimental"), plain.err)
    }
}
