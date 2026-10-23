import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

final class CLICommandTests: XCTestCase {
    func parse(_ line: String) throws -> CLICommand {
        try CLICommand.parse(line.split(separator: " ").map(String.init))
    }

    func assertUsage(_ line: String, file: StaticString = #filePath, line l: UInt = #line) {
        XCTAssertThrowsError(try parse(line), line, file: file, line: l) { error in
            XCTAssertTrue(error is CLIUsageError, "\(error)", file: file, line: l)
        }
    }

    func testFoundationLanguageArgumentsAreIgnored() throws {
        let args = CLICommand.strippingSystemArguments(["help", "-AppleLanguages", "(tr)", "-AppleLocale", "tr_TR"])
        XCTAssertEqual(args, ["help"])
        XCTAssertEqual(try CLICommand.parse(CLICommand.strippingSystemArguments(["-AppleLanguages", "(tr)", "list", "--json"])),
                       .list(json: true, quiet: false))
        // Ordinary options and a trailing key without a value stay.
        XCTAssertEqual(CLICommand.strippingSystemArguments(["code", "-c", "-AppleLanguages"]), ["code", "-c", "-AppleLanguages"])
    }

    func testStatusAndDefaults() throws {
        XCTAssertEqual(try CLICommand.parse([]), .status(id: nil, json: false))
        XCTAssertEqual(try parse("status"), .status(id: nil, json: false))
        XCTAssertEqual(try parse("status acme --json"), .status(id: "acme", json: true))
        XCTAssertEqual(try parse("--json"), .status(id: nil, json: true))
        XCTAssertEqual(try parse("connect"), .connect(id: nil))
        XCTAssertEqual(try parse("up acme"), .connect(id: "acme"))
        XCTAssertEqual(try parse("connect --force acme"), .connect(id: "acme", force: true))
        XCTAssertEqual(try parse("connect -f"), .connect(id: nil, force: true))
        assertUsage("toggle --force")
        XCTAssertEqual(try parse("toggle acme"), .toggle(id: "acme"))
        XCTAssertEqual(try parse("disconnect --all"), .disconnect(id: nil, all: true))
        XCTAssertEqual(try parse("disconnect acme"), .disconnect(id: "acme", all: false))
        assertUsage("disconnect acme --all")
        assertUsage("connect a b")
        assertUsage("status --bogus")
    }

    func testCodeListShow() throws {
        XCTAssertEqual(try parse("code"), .code(id: nil, copy: false, json: false))
        XCTAssertEqual(try parse("code acme -c"), .code(id: "acme", copy: true, json: false))
        XCTAssertEqual(try parse("code --copy --json acme"), .code(id: "acme", copy: true, json: true))
        XCTAssertEqual(try parse("list --json"), .list(json: true, quiet: false))
        XCTAssertEqual(try parse("ls -q"), .list(json: false, quiet: true))
        XCTAssertEqual(try parse("show acme"), .show(id: "acme", json: false))
        assertUsage("show")
    }

    func testSetAddImportExport() throws {
        XCTAssertEqual(try CLICommand.parse(["set", "acme", "username=alice", "otp_template={password}:{otp}", "badge="]),
                       .set(id: "acme", assignments: [.init(key: "username", value: "alice"),
                                                      .init(key: "otp_template", value: "{password}:{otp}"),
                                                      .init(key: "badge", value: "")]))
        assertUsage("set acme")
        assertUsage("set acme username")
        assertUsage("set acme =x")
        XCTAssertEqual(try parse("add Acme VPN --type forti"), .add(name: "Acme VPN", type: .forti))
        XCTAssertEqual(try parse("add --type=openvpn Acme"), .add(name: "Acme", type: .openvpn))
        assertUsage("add Acme")
        assertUsage("add Acme --type wireguard")
        assertUsage("add --type forti")
        XCTAssertEqual(try parse("import ~/acme.ovpn --name Acme"), .importFile(path: "~/acme.ovpn", name: "Acme"))
        XCTAssertEqual(try parse("import a.passtunnel"), .importFile(path: "a.passtunnel", name: nil))
        assertUsage("import a.ovpn --name")
        XCTAssertEqual(try parse("export acme -o out.passtunnel"), .export(id: "acme", output: "out.passtunnel"))
        XCTAssertEqual(try parse("export acme"), .export(id: "acme", output: nil))
        XCTAssertEqual(try CLICommand.parse(["import", "--", "-odd.ovpn"]), .importFile(path: "-odd.ovpn", name: nil))
    }

    func testMiscCommands() throws {
        XCTAssertEqual(try parse("rm acme"), .remove(id: "acme", yes: false))
        XCTAssertEqual(try parse("rm -y acme"), .remove(id: "acme", yes: true))
        XCTAssertEqual(try parse("secret acme totp"), .secret(id: "acme", kind: .totp))
        XCTAssertEqual(try parse("secret acme PASSWORD"), .secret(id: "acme", kind: .password))
        assertUsage("secret acme pin")
        XCTAssertEqual(try parse("default"), .setDefault(id: nil))
        XCTAssertEqual(try parse("default acme"), .setDefault(id: "acme"))
        XCTAssertEqual(try parse("pin acme"), .pin(id: "acme"))
        XCTAssertEqual(try parse("unpin acme"), .unpin(id: "acme"))
        XCTAssertEqual(try parse("log acme -f"), .log(id: "acme", follow: true))
        XCTAssertEqual(try parse("helper"), .helper(.status))
        XCTAssertEqual(try parse("helper install"), .helper(.install))
        XCTAssertEqual(try parse("debug drop acme"), .debug(.drop, id: "acme"))
        XCTAssertThrowsError(try parse("debug"))
        XCTAssertThrowsError(try parse("debug drop"))
        XCTAssertThrowsError(try parse("debug crash acme"))
        XCTAssertTrue(CLICommand.isCommand("debug"))
        XCTAssertFalse(CLICommand.commandNames.contains("debug"), "hidden from help and completion")
        assertUsage("helper reboot")
        XCTAssertEqual(try parse("completion fish"), .completion(.fish))
        assertUsage("completion tcsh")
        XCTAssertEqual(try parse("help"), .help(command: nil))
        XCTAssertEqual(try parse("help ls"), .help(command: "list"))
        XCTAssertEqual(try parse("connect --help"), .help(command: "connect"))
        XCTAssertEqual(try parse("--help"), .help(command: nil))
        XCTAssertEqual(try parse("--version"), .version())
        assertUsage("frobnicate")
    }

    func testIsCommand() {
        for word in ["status", "connect", "ls", "--help", "--version", "completion"] {
            XCTAssertTrue(CLICommand.isCommand(word), word)
        }
        for word in ["-psn_0_12345", "-NSDocumentRevisionsDebugMode", "", "Status"] {
            XCTAssertFalse(CLICommand.isCommand(word), word)
        }
    }
}

final class ProfileFieldsTests: XCTestCase {
    func testSetValues() throws {
        var p = Profile(id: "acme", name: "Acme", type: .forti)
        let pairs = [("name", "Acme Prod"), ("username", "alice"), ("otp_mode", "TOTP"), ("totp.digits", "8"),
                     ("period", "60"), ("algorithm", "SHA-256"), ("otp-delivery", "combined"), ("template", "colon"),
                     ("session_limit", "480"), ("auto_reconnect", "yes"), ("health_host", "10.0.0.5:443"),
                     ("host", "vpn.example.com"), ("port", "10443"), ("set_dns", "on"), ("routes", "0"),
                     ("pinned", "true"), ("badge_style", "both")]
        for (k, v) in pairs { try ProfileFields.set(&p, key: k, value: v) }
        XCTAssertEqual(p.name, "Acme Prod")
        XCTAssertEqual(p.username, "alice")
        XCTAssertEqual(p.otpMode, .totp)
        XCTAssertEqual(p.totp, TOTPParams(digits: 8, period: 60, algorithm: .sha256))
        XCTAssertEqual(p.otpDelivery, .combined)
        XCTAssertEqual(p.otpTemplate, "{password}:{otp}")
        XCTAssertEqual(p.sessionLimitMin, 480)
        XCTAssertTrue(p.autoReconnect)
        XCTAssertEqual(p.healthHost, "10.0.0.5:443")
        XCTAssertEqual([p.host, String(p.port)], ["vpn.example.com", "10443"])
        XCTAssertTrue(p.setDNS)
        XCTAssertFalse(p.setRoutes)
        XCTAssertTrue(p.pinned)
        XCTAssertEqual(p.badgeStyle, .both)
        XCTAssertEqual(ProfileFields.value(p, key: "algorithm"), "sha256")
        XCTAssertEqual(ProfileFields.value(p, key: "set_routes"), "false")
    }

    func testRejectsBadInput() {
        var p = Profile(id: "acme", name: "Acme", type: .openvpn)
        func expect(_ k: String, _ v: String, _ error: PTError) {
            XCTAssertThrowsError(try ProfileFields.set(&p, key: k, value: v), "\(k)=\(v)") {
                XCTAssertEqual($0 as? PTError, error, "\(k)=\(v)")
            }
        }
        expect("nope", "1", .invalidField("nope"))
        expect("digits", "9", .invalidField("digits"))
        expect("period", "x", .invalidField("period"))
        expect("auto_reconnect", "maybe", .invalidField("auto_reconnect"))
        expect("health_host", "a b", .invalidField("health_host"))
        expect("name", " ", .emptyName)
        expect("host", "vpn.example.com", .wrongProfileType("acme"))
        XCTAssertThrowsError(try ProfileFields.set(&p, key: "otp_template", value: "{password}"))
        XCTAssertNoThrow(try ProfileFields.set(&p, key: "password_mode", value: "none"))
        var f = Profile(id: "f", name: "F", type: .forti)
        XCTAssertThrowsError(try ProfileFields.set(&f, key: "password_mode", value: "none"))
        XCTAssertEqual(ProfileFields.keys(for: .openvpn).contains("host"), false)
        XCTAssertEqual(ProfileFields.canonicalKey("TOTP.Digits"), "digits")
    }
}

final class VPNLogAndBase32Tests: XCTestCase {
    func testFortiLog() {
        let log = """
        INFO:   Connected to gateway.
        INFO:   Authenticated.
        INFO:   Got addresses: [10.212.134.200], ns [10.0.0.1, 10.0.0.2], ns_suffix [example.com]
        INFO:   Negotiation complete.
        INFO:   Tunnel is up and running.
        """
        XCTAssertTrue(VPNLog.fortiIsUp(log))
        XCTAssertEqual(VPNLog.fortiAddress(log), "10.212.134.200")
        XCTAssertFalse(VPNLog.fortiIsUp("INFO:   Connected to gateway."))
        XCTAssertNil(VPNLog.fortiAddress("Got addresses: []"))
        XCTAssertTrue(VPNLog.isAuthFailure("ERROR:  Could not authenticate to gateway. Please check the password"))
        XCTAssertTrue(VPNLog.isAuthFailure("AUTH: Received control message: AUTH_FAILED"))
        XCTAssertFalse(VPNLog.isAuthFailure(log))
        XCTAssertTrue(VPNLog.isFatal("ERROR:  Gateway certificate validation failed"))
        XCTAssertEqual(VPNLog.tail("a\n\nb\nc\nd", lines: 2), "c\nd")
    }

    func testBase32RoundTrip() throws {
        for hex in ["", "00", "48656c6c6f21deadbeef", "ffffffffff", "0102030405060708090a"] {
            let data = TOTP.hex(hex) ?? Data()
            let encoded = TOTP.base32Encode(data)
            if data.isEmpty { XCTAssertEqual(encoded, ""); continue }
            XCTAssertEqual(try TOTP.decodeSecret(encoded), data, hex)
        }
        XCTAssertEqual(TOTP.base32Encode(Data("Hello!".utf8) + Data([0xDE, 0xAD, 0xBE, 0xEF])), "JBSWY3DPEHPK3PXP")
    }
}
