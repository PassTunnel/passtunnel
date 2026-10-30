import Foundation
import XCTest

@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

/// Palo Alto GlobalProtect in the openconnect files and the sign-in result (issue #228; ARCHITECTURE.md,
/// "Output, cookie and destination" and "The configurations"). The Cisco AnyConnect behavior these share is
/// in OpenConnectConfigTests and stays as it was.

/// A cookie in the shape openconnect 9.21 prints (`parse_login_xml`), with made-up values.
let exampleGPCookie =
    "authcookie=0123456789abcdef0123456789abcdef&portal=Acme-Portal&user=alice&domain=%28empty_domain%29&computer=alice-mac"
let exampleGPAuthcookie = "0123456789abcdef0123456789abcdef"

// MARK: - The cookie

final class GlobalProtectCookieTests: XCTestCase {
    /// openconnect's `append_opt` with `buf_append_urlencoded` (auth-common.c 143–156, textbuf.c 138–149).
    static func appendOpt(_ cookie: inout String, _ key: String, _ value: String) {
        func encoded(_ s: String) -> String {
            s.utf8.map { b in
                FortiConfig.isASCIIAlphanumeric(b) || "-_.~".utf8.contains(b)
                    ? String(UnicodeScalar(b)) : "%" + String(format: "%02x", b)
            }.joined()
        }
        if !cookie.isEmpty { cookie += "&" }
        cookie += encoded(key) + "=" + encoded(value)
    }

    /// The cookie openconnect builds from these arguments: the saved ones in its order, empty ones left out,
    /// `computer` last.
    static func printed(_ args: [String: String], computer: String = "alice-mac") -> String {
        var cookie = ""
        for key in ["authcookie", "portal", "user", "domain", "preferred-ip", "preferred-ipv6"] {
            if let value = args[key], !value.isEmpty { appendOpt(&cookie, key, value) }
        }
        appendOpt(&cookie, "computer", computer)
        return cookie
    }

    func testParse() throws {
        let parts = try XCTUnwrap(GlobalProtectCookie.parse(exampleGPCookie))
        XCTAssertEqual(parts.map(\.key), ["authcookie", "portal", "user", "domain", "computer"])
        XCTAssertEqual(parts.map(\.value), [exampleGPAuthcookie, "Acme-Portal", "alice", "%28empty_domain%29", "alice-mac"])
        let all =
            "authcookie=\(exampleGPAuthcookie)&portal=Acme&user=alice&domain=acme&preferred-ip=192.0.2.30"
            + "&preferred-ipv6=2001%3adb8%3a%3a30&computer=alice-mac"
        XCTAssertEqual(GlobalProtectCookie.parse(all)?.map(\.key), GlobalProtectCookie.keys)
        // Only authcookie, user and computer are always there; computer may be empty.
        XCTAssertTrue(GlobalProtectCookie.isValidTunnelOption("authcookie=12345678&user=a&computer="))
        XCTAssertTrue(GlobalProtectCookie.isValidTunnelOption("authcookie=12345678&user=a&computer=localhost"))
    }

    /// Whatever openconnect builds from the gateway's arguments is accepted, and its values are what it encoded.
    func testEveryCookieOpenConnectPrintsIsAccepted() throws {
        let cases: [([String: String], String)] = [
            (["authcookie": exampleGPAuthcookie, "user": "alice"], "alice-mac"),
            (["authcookie": exampleGPAuthcookie, "portal": "Acme Portal", "user": "alice@example.com", "domain": "(empty_domain)"], "Alice's Mac"),
            (["authcookie": "a+b/c=d&e;f'g h", "user": "ACME\\alice", "preferred-ip": "192.0.2.30", "preferred-ipv6": "2001:db8::30"], ""),
            (["authcookie": String(repeating: "f", count: 32), "portal": "Ayşe", "user": "kullanıcı", "domain": "%41"], "localhost")
        ]
        for (args, computer) in cases {
            let cookie = Self.printed(args, computer: computer)
            let parts = try XCTUnwrap(GlobalProtectCookie.parse(cookie), cookie)
            XCTAssertEqual(parts.last?.key, "computer")
            for (key, value) in parts {
                XCTAssertEqual(value.removingPercentEncoding, key == "computer" ? computer : args[key], key)
            }
            XCTAssertFalse(cookie.contains { "' ;\n\r\t".contains($0) }, cookie)
        }
    }

    func testRefusedShapes() {
        let a = "authcookie=\(exampleGPAuthcookie)"
        let refused: [String] = [
            "", exampleGPAuthcookie, "webvpn=\(exampleGPAuthcookie)", "openconnect_strapkey=AAAAAAAA; webvpn=\(exampleGPAuthcookie)",
            // Keys: missing, repeated, reordered, unknown, another case.
            "\(a)&computer=x", "user=alice&computer=x", "\(a)&user=alice", "\(a)&user=alice&computer=x&computer=y",
            "\(a)&user=alice&user=bob&computer=x", "user=alice&\(a)&computer=x", "\(a)&computer=x&user=alice",
            "\(a)&domain=acme&portal=Acme&user=alice&computer=x", "\(a)&user=alice&computer=x&domain=acme",
            "\(a)&persistent-cookie=0123&user=alice&computer=x", "\(a)&user=alice&authentication-source=LDAP&computer=x",
            "\(a)&user=alice&portal-userauthcookie=secret00&computer=x", "AUTHCOOKIE=\(exampleGPAuthcookie)&user=alice&computer=x",
            "\(a)&User=alice&computer=x", "\(a)&user=alice&computer",
            // Values: empty but computer's, a short authcookie, outside the encoding.
            "authcookie=&user=alice&computer=x", "authcookie=1234567&user=alice&computer=x", "\(a)&user=&computer=x",
            "\(a)&portal=&user=alice&computer=x", "\(a)&user=alice&domain=&computer=x", "\(a)&user=al ice&computer=x",
            "\(a)&user=al+ice&computer=x", "\(a)&user=al'ice&computer=x", "\(a)&user=al;ice&computer=x", "\(a)&user=a=b&computer=x",
            "\(a)&user=al%2Fice&computer=x", "\(a)&user=al%2&computer=x", "\(a)&user=al%&computer=x", "\(a)&user=al%zzice&computer=x",
            "\(a)&user=ayşe&computer=x", "\(a)&user=alice\n&computer=x", "\(a)&user=alice\r&computer=x", "\(a)&user=al\u{0}ice&computer=x",
            "\(a)&user=alice&computer=x\u{7F}", "\(a)&user=alice&computer=a/b", "\(a)&user=alice&computer=\"x\"",
            // Separators.
            "\(a)&&user=alice&computer=x", "&\(a)&user=alice&computer=x", "\(a)&user=alice&computer=x&", "\(a);user=alice;computer=x",
            "\(a)&user=alice&computer=x ", " \(a)&user=alice&computer=x"
        ]
        for cookie in refused {
            XCTAssertNil(GlobalProtectCookie.parse(cookie), cookie.debugDescription)
            XCTAssertFalse(GlobalProtectCookie.isValidTunnelOption(cookie), cookie.debugDescription)
        }
    }

    func testTheLimit() {
        let base = "authcookie=\(exampleGPAuthcookie)&user=alice&computer="
        let fits = base + String(repeating: "c", count: 4096 - base.utf8.count)
        XCTAssertEqual(fits.utf8.count, 4096)
        XCTAssertTrue(GlobalProtectCookie.isValidTunnelOption(fits))
        XCTAssertFalse(GlobalProtectCookie.isValidTunnelOption(fits + "c"))
    }

    /// The whole cookie and its bearer secret; the user name and the rest are no secrets.
    func testSecrets() {
        XCTAssertEqual(GlobalProtectCookie.secrets(exampleGPCookie), [exampleGPCookie, exampleGPAuthcookie])
        XCTAssertEqual(GlobalProtectCookie.secrets("authcookie=1234567&user=a&computer="), ["authcookie=1234567&user=a&computer="])
        // The helper's masker hides both wherever the gateway's text repeats them.
        let secrets = GlobalProtectCookie.secrets(exampleGPCookie)
        for part in secrets {
            XCTAssertEqual(OutputMask.apply("GlobalProtect error \(part) x", secrets: secrets), "GlobalProtect error <redacted> x", part)
        }
    }
}

// MARK: - The sign-in file

final class GlobalProtectAuthConfigTests: XCTestCase {
    func config(_ change: (inout OpenConnectAuthConfig) -> Void = { _ in }) -> OpenConnectAuthConfig {
        var c = OpenConnectAuthConfig(protocol: .gp, host: "vpn.example.com", username: "alice")
        change(&c)
        return c
    }

    func testRenderThePortalWithTheSystemCABundle() throws {
        XCTAssertEqual(
            try config { $0.gateway = "US East" }.render(noExternalAuth: true),
            """
            # Generated by PassTunnel. Do not edit.
            protocol gp
            server https://vpn.example.com/
            user alice
            authgroup US East
            no-system-trust
            cafile /etc/ssl/cert.pem
            non-inter
            passwd-on-stdin
            no-external-auth

            """)
    }

    /// Both pins, each a `servercert` line; a gateway without its portal; Linux before 9.20.
    func testRenderAGatewayWithTwoPinsOnLinux() throws {
        XCTAssertEqual(
            try config {
                $0.port = 8443; $0.skipPortal = true; $0.serverCert = examplePin; $0.gatewayServerCert = otherExamplePin
            }.render(caFile: "/etc/ssl/certs/ca-certificates.crt", noExternalAuth: true, disableIPv6: true),
            """
            # Generated by PassTunnel. Do not edit.
            protocol gp
            server https://vpn.example.com:8443/gateway
            user alice
            servercert \(examplePin)
            servercert \(otherExamplePin)
            non-inter
            passwd-on-stdin
            no-external-auth
            disable-ipv6

            """)
    }

    func testEachPinThatIsSetIsALine() throws {
        let gatewayOnly = try config { $0.gatewayServerCert = otherExamplePin }.render(noExternalAuth: false)
        XCTAssertTrue(gatewayOnly.contains("\nuser alice\nservercert \(otherExamplePin)\nnon-inter\n"), gatewayOnly)
        let portalOnly = try config { $0.serverCert = examplePin }.render(noExternalAuth: false)
        XCTAssertTrue(portalOnly.contains("\nuser alice\nservercert \(examplePin)\nnon-inter\n"), portalOnly)
        XCTAssertFalse(portalOnly.contains("cafile"))
        XCTAssertFalse(portalOnly.contains("no-system-trust"))
        XCTAssertTrue(try config().render(noExternalAuth: false).contains("\nno-system-trust\ncafile /etc/ssl/cert.pem\n"))
    }

    func testHostsAndPorts() throws {
        XCTAssertTrue(try config { $0.host = "2001:db8::1" }.render(noExternalAuth: true).contains("\nserver https://[2001:db8::1]/\n"))
        XCTAssertTrue(
            try config {
                $0.host = "192.0.2.10"; $0.port = 4443; $0.skipPortal = true
            }.render(noExternalAuth: true).contains("\nserver https://192.0.2.10:4443/gateway\n"))
        XCTAssertTrue(try config { $0.host = "VPN.Example.com" }.render(noExternalAuth: true).contains("\nserver https://vpn.example.com/\n"))
        XCTAssertThrowsError(try config { $0.host = "fe80::1%en0" }.render(noExternalAuth: true))
        XCTAssertThrowsError(try config { $0.port = 0 }.render(noExternalAuth: true))
    }

    /// The gateway's label follows the group name's rule.
    func testTheGateway() throws {
        XCTAssertTrue(try config { $0.gateway = "Avrupa = 1 # x" }.render(noExternalAuth: true).contains("\nauthgroup Avrupa = 1 # x\n"))
        XCTAssertNoThrow(try config { $0.gateway = String(repeating: "g", count: 255) }.render(noExternalAuth: true))
        XCTAssertTrue(OpenConnectAuthConfig.isValidGateway("US East"))
        for bad in [
            " US", "US ", "\tUS", "=US", "U\nS", "U\rS", "U\u{0}S", "U\u{2028}S", "U\u{85}S", String(repeating: "g", count: 256)
        ] as [String] {
            XCTAssertFalse(OpenConnectAuthConfig.isValidGateway(bad), bad.debugDescription)
            XCTAssertThrowsError(try config { $0.gateway = bad }.render(noExternalAuth: true), bad.debugDescription) {
                guard case .invalidValue("gateway", _)? = $0 as? OpenConnectConfig.ValidationError else { return XCTFail("\($0)") }
            }
        }
        XCTAssertFalse(OpenConnectAuthConfig.isValidGateway(""))
    }

    /// Each protocol's own fields are refused for the other.
    func testFieldsOfTheOtherProtocol() {
        typealias E = OpenConnectConfig.ValidationError
        func assertField(_ c: OpenConnectAuthConfig, _ field: String, disableIPv6: Bool = false, line: UInt = #line) {
            XCTAssertThrowsError(try c.render(noExternalAuth: true, disableIPv6: disableIPv6), line: line) {
                guard case .invalidValue(field, _)? = $0 as? E else { return XCTFail("\($0)", line: line) }
            }
        }
        assertField(config { $0.usergroup = "engineering" }, "user group")
        assertField(config { $0.usergroup = "gateway" }, "user group")
        assertField(config { $0.authgroup = "Staff" }, "group")
        let ac = OpenConnectAuthConfig(host: "vpn.example.com", username: "alice")
        XCTAssertNoThrow(try ac.render(noExternalAuth: true))
        var c = ac
        c.skipPortal = true
        assertField(c, "skip portal")
        c = ac
        c.gateway = "US East"
        assertField(c, "gateway")
        c = ac
        c.gatewayServerCert = otherExamplePin
        assertField(c, "gateway server certificate")
        assertField(ac, "disable-ipv6", disableIPv6: true)
    }

    func testPinsMustBeFull() {
        for bad in [String(examplePin.prefix(15)), "sha1:" + String(repeating: "ab", count: 20), examplePin + "\n"] as [String] {
            XCTAssertThrowsError(try config { $0.serverCert = bad }.render(noExternalAuth: true)) {
                XCTAssertEqual($0 as? OpenConnectConfig.ValidationError, .invalidServerCert)
            }
            XCTAssertThrowsError(try config { $0.gatewayServerCert = bad }.render(noExternalAuth: true)) {
                XCTAssertEqual($0 as? OpenConnectConfig.ValidationError, .invalidServerCert)
            }
        }
    }

    func testInjectionRejectedInEveryField() {
        for p in ["x\nscript-tun", "x\rcsd-wrapper /tmp/x", "x\u{0}y", "x\u{2028}y", "x\u{1b}[2J", "x\tno-cert-check"] {
            XCTAssertThrowsError(try config { $0.host = p }.render(noExternalAuth: true), "host \(p.debugDescription)")
            XCTAssertThrowsError(try config { $0.username = p }.render(noExternalAuth: true), "user \(p.debugDescription)")
            XCTAssertThrowsError(try config { $0.gateway = p }.render(noExternalAuth: true), "gateway \(p.debugDescription)")
            XCTAssertThrowsError(try config { $0.gatewayServerCert = examplePin + p }.render(noExternalAuth: true), "pin \(p.debugDescription)")
        }
    }
}

// MARK: - The root file

/// The root file for a gateway on another host than the portal.
func exampleGPConfig(_ change: (inout OpenConnectConfig) -> Void = { _ in }) -> OpenConnectConfig {
    var c = OpenConnectConfig(
        protocol: .gp, host: "gw1.example.com", cookie: exampleGPCookie, serverCert: examplePin, resolveAddress: "192.0.2.20",
        scriptPath: exampleHook)
    change(&c)
    return c
}

final class GlobalProtectConfigTests: XCTestCase {
    func config(_ change: (inout OpenConnectConfig) -> Void = { _ in }) -> OpenConnectConfig { exampleGPConfig(change) }

    func testRender() throws {
        XCTAssertEqual(
            try config().render(),
            """
            # Generated by PassTunnel. Do not edit.
            protocol gp
            server https://gw1.example.com/
            cookie \(exampleGPCookie)
            servercert \(examplePin)
            resolve gw1.example.com:192.0.2.20
            script \(exampleHook)
            non-inter
            reconnect-timeout 60

            """)
    }

    /// TLS only (no ESP), and Linux before 9.20.
    func testRenderVariants() throws {
        XCTAssertEqual(
            try config {
                $0.host = "192.0.2.20"; $0.port = 4443; $0.resolveAddress = nil; $0.tlsOnly = true; $0.disableIPv6 = true
            }.render(),
            """
            # Generated by PassTunnel. Do not edit.
            protocol gp
            server https://192.0.2.20:4443/
            cookie \(exampleGPCookie)
            servercert \(examplePin)
            script \(exampleHook)
            non-inter
            reconnect-timeout 60
            no-dtls
            disable-ipv6

            """)
        XCTAssertTrue(try config { $0.disableIPv6 = true }.render().hasSuffix("\nreconnect-timeout 60\ndisable-ipv6\n"))
    }

    /// Each protocol's cookie only; `disable-ipv6` for GlobalProtect only.
    func testTheCookieAndIPv6ByProtocol() {
        for bad in ["webvpn=EXAMPLE-COOKIE", OpenConnectCookieTests.strap, exampleGPAuthcookie, "", exampleGPCookie + "&x=y"] {
            XCTAssertThrowsError(try config { $0.cookie = bad }.render(), bad) { error in
                guard case .invalidValue("cookie", _)? = error as? OpenConnectConfig.ValidationError else { return XCTFail("\(error)") }
                if !bad.isEmpty { XCTAssertFalse("\(error)".contains(bad), "the error must not include the cookie") }
            }
        }
        let ac = OpenConnectConfig(
            host: "vpn.example.com", cookie: exampleGPCookie, serverCert: examplePin, resolveAddress: "192.0.2.10", scriptPath: exampleHook)
        XCTAssertThrowsError(try ac.render(), "a GlobalProtect cookie is no webvpn option") {
            guard case .invalidValue("cookie", _)? = $0 as? OpenConnectConfig.ValidationError else { return XCTFail("\($0)") }
        }
        var acIPv6 = ac
        acIPv6.cookie = "webvpn=EXAMPLE-COOKIE"
        XCTAssertNoThrow(try acIPv6.render())
        acIPv6.disableIPv6 = true
        XCTAssertThrowsError(try acIPv6.render()) {
            guard case .invalidValue("disable-ipv6", _)? = $0 as? OpenConnectConfig.ValidationError else { return XCTFail("\($0)") }
        }
    }

    func testDescriptionsNeverShowTheCookie() {
        let c = config()
        var dumped = ""
        dump(c, to: &dumped)
        for text in [c.description, c.debugDescription, String(describing: c), String(reflecting: c), dumped] {
            XCTAssertFalse(text.contains(exampleGPAuthcookie), text)
            XCTAssertTrue(text.contains("protocol: gp"), text)
        }
        XCTAssertFalse(Mirror(reflecting: c).children.contains { "\($0.value)".contains(exampleGPAuthcookie) })
    }
}

// MARK: - The final check of both files

final class GlobalProtectRenderedCheckTests: XCTestCase {
    static let root = try! exampleGPConfig().render()
    static let fullRoot = try! exampleGPConfig {
        $0.tlsOnly = true; $0.disableIPv6 = true
    }.render()
    static let auth = try! OpenConnectAuthConfig(protocol: .gp, host: "vpn.example.com", username: "alice", gateway: "US East")
        .render(noExternalAuth: true)
    static let fullAuth = try! OpenConnectAuthConfig(
        protocol: .gp, host: "vpn.example.com", username: "alice", serverCert: examplePin, skipPortal: true, gateway: "US East",
        gatewayServerCert: otherExamplePin
    ).render(noExternalAuth: true, disableIPv6: true)

    var root: String { Self.root }
    var auth: String { Self.auth }
    var fullAuth: String { Self.fullAuth }

    func lineCount(_ text: String) -> Int { text.split(separator: "\n", omittingEmptySubsequences: false).count - 1 }

    func checkRoot(_ text: String, lines: Int? = nil) throws { try OpenConnectConfig.checkRendered(text, lineCount: lines ?? lineCount(text)) }
    func checkAuth(_ text: String, lines: Int? = nil) throws {
        try OpenConnectAuthConfig.checkRendered(text, lineCount: lines ?? lineCount(text), caFile: OpenConnectConfig.systemCAFile)
    }

    func assertUnsafe(_ check: () throws -> Void, _ text: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try check(), text.debugDescription, file: file, line: line) {
            guard case .unsafeOutput? = $0 as? OpenConnectConfig.ValidationError else { return XCTFail("\($0)", file: file, line: line) }
        }
    }
    func assertRootUnsafe(_ text: String, file: StaticString = #filePath, line: UInt = #line) {
        assertUnsafe({ try checkRoot(text) }, text, file: file, line: line)
    }
    func assertAuthUnsafe(_ text: String, file: StaticString = #filePath, line: UInt = #line) {
        assertUnsafe({ try checkAuth(text) }, text, file: file, line: line)
    }

    func testRenderedFilesPassTheCheck() throws {
        for text in [root, Self.fullRoot] { XCTAssertNoThrow(try checkRoot(text)) }
        for text in [auth, fullAuth] { XCTAssertNoThrow(try checkAuth(text)) }
        let keys = { (text: String) in text.split(separator: "\n").dropFirst().map { String($0.prefix { $0 != " " }) } }
        XCTAssertEqual(keys(Self.fullRoot), OpenConnectConfig.renderedKeys)
        XCTAssertEqual(
            keys(fullAuth),
            [
                "protocol", "server", "user", "authgroup", "servercert", "servercert", "non-inter", "passwd-on-stdin", "no-external-auth",
                "disable-ipv6"
            ])
        XCTAssertEqual(Set(keys(fullAuth) + keys(auth)), Set(OpenConnectAuthConfig.renderedKeys))
    }

    /// The protocol line decides the rules: each file is refused under the other protocol's.
    func testTheProtocolDecidesTheRules() {
        assertRootUnsafe(root.replacingOccurrences(of: "protocol gp", with: "protocol anyconnect"))
        assertRootUnsafe(root.replacingOccurrences(of: "protocol gp", with: "protocol GP"))
        assertRootUnsafe(root.replacingOccurrences(of: "protocol gp", with: "protocol nc"))
        assertRootUnsafe(root.replacingOccurrences(of: "protocol gp", with: "protocol gp "))
        assertRootUnsafe(root.replacingOccurrences(of: "protocol gp", with: "protocol=gp"))
        assertRootUnsafe(root.replacingOccurrences(of: "protocol gp\n", with: ""))
        assertAuthUnsafe(fullAuth.replacingOccurrences(of: "protocol gp", with: "protocol anyconnect"))
        assertAuthUnsafe(auth.replacingOccurrences(of: "protocol gp", with: "protocol pulse"))
        // A Cisco AnyConnect file with the protocol changed: its cookie is no GlobalProtect cookie.
        assertRootUnsafe(OpenConnectRenderedCheckTests.root.replacingOccurrences(of: "protocol anyconnect", with: "protocol gp"))
        // A protocol line anywhere but first.
        assertRootUnsafe(
            root.replacingOccurrences(of: "protocol gp\nserver", with: "server").replacingOccurrences(of: ".com/\n", with: ".com/\nprotocol gp\n"))
    }

    func testTheCookieIsGlobalProtectsShape() {
        assertRootUnsafe(root.replacingOccurrences(of: exampleGPCookie, with: "webvpn=EXAMPLE-COOKIE"))
        assertRootUnsafe(root.replacingOccurrences(of: exampleGPCookie, with: exampleGPAuthcookie))
        assertRootUnsafe(root.replacingOccurrences(of: "&computer=alice-mac", with: ""))
        assertRootUnsafe(root.replacingOccurrences(of: "user=alice", with: "user=al ice"))
        assertRootUnsafe(root.replacingOccurrences(of: "%28", with: "%2A%28"))
        assertRootUnsafe(root.replacingOccurrences(of: "\ncookie ", with: "\ncookie="))
    }

    /// `server`'s path: the root file has none; the sign-in file empty or `gateway`.
    func testThePath() {
        for path in ["gateway", "portal", "ssl-vpn", "global-protect"] {
            assertRootUnsafe(root.replacingOccurrences(of: "gw1.example.com/\n", with: "gw1.example.com/\(path)\n"))
        }
        XCTAssertTrue(fullAuth.contains("\nserver https://vpn.example.com/gateway\n"))
        for path in [
            "portal", "gateway:prelogin-cookie", "portal:portal-userauthcookie", "engineering", "gateway/", "gateway/x", "Gateway", "ssl-vpn",
            "global-protect/prelogin.esp", "gateway?x=1", "gateway#x", "../gateway"
        ] {
            assertAuthUnsafe(auth.replacingOccurrences(of: "vpn.example.com/\n", with: "vpn.example.com/\(path)\n"))
            assertAuthUnsafe(fullAuth.replacingOccurrences(of: "vpn.example.com/gateway\n", with: "vpn.example.com/\(path)\n"))
        }
    }

    /// `servercert` twice in a GlobalProtect sign-in file only; once in every other file.
    func testServercertCount() {
        let third = fullAuth.replacingOccurrences(
            of: "servercert \(otherExamplePin)\n", with: "servercert \(otherExamplePin)\nservercert \(examplePin)\n")
        assertAuthUnsafe(third)
        assertRootUnsafe(
            root.replacingOccurrences(of: "servercert \(examplePin)\n", with: "servercert \(examplePin)\nservercert \(otherExamplePin)\n"))
        let acTwice = OpenConnectRenderedCheckTests.pinnedAuth.replacingOccurrences(
            of: "servercert \(examplePin)\n", with: "servercert \(examplePin)\nservercert \(otherExamplePin)\n")
        XCTAssertThrowsError(try checkAuth(acTwice))
        // The trust is still the pins or the system's bundle alone.
        assertAuthUnsafe(fullAuth.replacingOccurrences(of: "non-inter\n", with: "no-system-trust\ncafile /etc/ssl/cert.pem\nnon-inter\n"))
        assertAuthUnsafe(auth.replacingOccurrences(of: "no-system-trust\n", with: ""))
        assertAuthUnsafe(auth.replacingOccurrences(of: "cafile /etc/ssl/cert.pem\n", with: ""))
        assertAuthUnsafe(auth.replacingOccurrences(of: "no-system-trust\n", with: "servercert \(examplePin)\nno-system-trust\n"))
    }

    /// `disable-ipv6`: last, without a value, in GlobalProtect files only.
    func testDisableIPv6() {
        assertRootUnsafe(Self.fullRoot.replacingOccurrences(of: "disable-ipv6", with: "disable-ipv6 1"))
        assertRootUnsafe(Self.fullRoot.replacingOccurrences(of: "no-dtls\ndisable-ipv6\n", with: "disable-ipv6\nno-dtls\n"))
        assertRootUnsafe(Self.fullRoot + "disable-ipv6\n")
        assertAuthUnsafe(fullAuth.replacingOccurrences(of: "no-external-auth\ndisable-ipv6\n", with: "disable-ipv6\nno-external-auth\n"))
        for form in ["disable-ipv6", "disable-ipv6 1", "disable-ipv6=1", " disable-ipv6", "\tdisable-ipv6"] {
            let acRoot = OpenConnectRenderedCheckTests.root + form + "\n"
            XCTAssertThrowsError(try checkRoot(acRoot), form)
            let acAuth = OpenConnectRenderedCheckTests.auth + form + "\n"
            XCTAssertThrowsError(try checkAuth(acAuth), form)
            let acPinned = OpenConnectRenderedCheckTests.pinnedAuth + form + "\n"
            XCTAssertThrowsError(try checkAuth(acPinned), form)
        }
    }

    /// Every refused option, in every form openconnect's reader would accept, fails both GlobalProtect files;
    /// so does each file's own keys in the other.
    func testEveryRefusedOptionIsRefused() {
        for (option, _) in OpenConnectOptions.refused {
            for form in ["\(option)", "\(option) /tmp/x", "\(option)=/tmp/x", "\(option) = 1", " \(option) x", "\t\(option)", "\(option)\t1"] {
                let files: [(text: String, check: (String) throws -> Void)] = [
                    (root, { try self.checkRoot($0) }), (Self.fullRoot, { try self.checkRoot($0) }), (auth, { try self.checkAuth($0) }),
                    (fullAuth, { try self.checkAuth($0) })
                ]
                for (text, check) in files {
                    for candidate in [
                        text + form + "\n", text.replacingOccurrences(of: "protocol gp\n", with: "protocol gp\n\(form)\n"),
                        text.replacingOccurrences(of: "non-inter\n", with: "\(form)\n")
                    ] {
                        XCTAssertThrowsError(try check(candidate), "\(option): \(form.debugDescription)")
                    }
                }
            }
        }
        let shared: Set = ["protocol", "server", "servercert", "non-inter", "disable-ipv6"]
        for key in OpenConnectAuthConfig.renderedKeys where !shared.contains(key) {
            for line in ["\(key)\n", "\(key) x\n"] { assertRootUnsafe(root.replacingOccurrences(of: "non-inter\n", with: "non-inter\n" + line)) }
        }
        for key in OpenConnectConfig.renderedKeys where !shared.contains(key) {
            for line in ["\(key)\n", "\(key) 1\n"] { assertAuthUnsafe(auth.replacingOccurrences(of: "non-inter\n", with: "non-inter\n" + line)) }
        }
    }

    /// The options the design names get their GlobalProtect reasons; `disable-ipv6` is rendered, not refused.
    func testTheTablesGlobalProtectReasons() {
        let reasons = Dictionary(OpenConnectOptions.refused.map { ($0.option, $0.reason) }, uniquingKeysWith: { a, _ in a })
        for option in ["csd-wrapper", "csd-user", "force-trojan", "usergroup", "form-entry", "os", "version-string", "local-hostname", "useragent"] {
            XCTAssertTrue(reasons[option]?.contains("GlobalProtect") == true, option)
        }
        XCTAssertNil(reasons["disable-ipv6"])
        XCTAssertTrue(OpenConnectConfig.renderedKeys.contains("disable-ipv6"))
        XCTAssertTrue(OpenConnectAuthConfig.renderedKeys.contains("disable-ipv6"))
    }
}

// MARK: - The sign-in output

final class GlobalProtectAuthResultTests: XCTestCase {
    func output(
        cookie: String = exampleGPCookie, host: String = "192.0.2.20", url: String = "https://gw1.example.com/",
        fingerprint: String = examplePin, resolve: String? = "'gw1.example.com:192.0.2.20'\n"
    ) -> String {
        "COOKIE='\(cookie)'\nHOST='\(host)'\nCONNECT_URL='\(url)'\nFINGERPRINT='\(fingerprint)'\nRESOLVE=" + (resolve ?? "")
    }

    func parse(_ text: String) throws -> OpenConnectAuthResult { try OpenConnectAuthResult.parse(text, protocol: .gp) }

    func testParse() throws {
        let r = try parse(output())
        XCTAssertEqual(r.protocol, .gp)
        XCTAssertEqual(r.cookie, exampleGPCookie)
        XCTAssertEqual(r.tunnelCookie, exampleGPCookie, "the tunnel run takes it unchanged")
        XCTAssertEqual(r.connectURL, "https://gw1.example.com/")
        XCTAssertEqual(r.output, output())
        XCTAssertEqual(try OpenConnectAuthResult.parse(Array(output().utf8), protocol: .gp), r)
        XCTAssertEqual(try OpenConnectAuthResult.parse(output()).protocol, .anyconnect, "the default is Cisco AnyConnect")
    }

    func testRefusesAnotherCookie() {
        for cookie in [
            "EXAMPLE-SESSION-COOKIE-9C1D", OpenConnectCookieTests.ocservToken, OpenConnectCookieTests.strap, "webvpn=EXAMPLE-SESSION-COOKIE",
            "authcookie=1234567&user=alice&computer=x", "authcookie=\(exampleGPAuthcookie)&computer=x",
            "authcookie=\(exampleGPAuthcookie)&user=al ice&computer=x"
        ] {
            XCTAssertThrowsError(try parse(output(cookie: cookie)), cookie) { error in
                guard case .invalidValue("COOKIE", _)? = error as? OpenConnectAuthResult.ParseError else { return XCTFail("\(error)") }
                XCTAssertFalse("\(error)".contains(cookie), "an error must never include the cookie")
            }
        }
        XCTAssertThrowsError(
            try OpenConnectAuthResult(
                protocol: .gp, cookie: "webvpn=EXAMPLE-COOKIE", host: "192.0.2.20", connectURL: "https://gw1.example.com/", fingerprint: examplePin,
                resolve: ""))
    }

    func destination(
        _ text: String, host: String = "vpn.example.com", port: Int = 443, skipPortal: Bool = false, pin: String = "", gatewayPin: String = ""
    ) throws -> OpenConnectAuthResult.Destination {
        try parse(text).checkDestination(
            host: host, port: port, skipPortal: skipPortal, profileServerCert: pin, profileGatewayServerCert: gatewayPin)
    }

    func assertRefused(
        _ text: String, host: String = "vpn.example.com", port: Int = 443, skipPortal: Bool = false, pin: String = "", gatewayPin: String = "",
        _ expected: OpenConnectAuthResult.DestinationError, file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try destination(text, host: host, port: port, skipPortal: skipPortal, pin: pin, gatewayPin: gatewayPin), text.debugDescription,
            file: file, line: line
        ) {
            XCTAssertEqual($0 as? OpenConnectAuthResult.DestinationError, expected, file: file, line: line)
            XCTAssertFalse("\($0)".contains(exampleGPAuthcookie), file: file, line: line)
        }
    }

    /// The portal's hop to a gateway on another host or port: the tunnel goes to CONNECT_URL's server.
    func testAGatewayThePortalNamed() throws {
        typealias D = OpenConnectAuthResult.Destination
        XCTAssertEqual(try destination(output()), D(host: "gw1.example.com", port: 443, resolveAddress: "192.0.2.20"))
        XCTAssertEqual(
            try destination(output(url: "https://gw1.example.com:4443/")), D(host: "gw1.example.com", port: 4443, resolveAddress: "192.0.2.20"))
        // openconnect prints the portal's spelling of the gateway's name; the tunnel's is lowercase.
        XCTAssertEqual(
            try destination(output(url: "https://GW1.Example.com/", resolve: "'GW1.Example.com:192.0.2.20'\n")),
            D(host: "gw1.example.com", port: 443, resolveAddress: "192.0.2.20"))
        // An IPv6 address the gateway's name resolved to.
        XCTAssertEqual(
            try destination(output(host: "[2001:db8::20]", resolve: "'gw1.example.com:2001:db8::20'\n")),
            D(host: "gw1.example.com", port: 443, resolveAddress: "2001:db8::20"))
        // Portals often list gateways by address: compared as an address, no resolve.
        XCTAssertEqual(
            try destination(output(url: "https://192.0.2.20/", resolve: "'192.0.2.20:192.0.2.20'\n")),
            D(host: "192.0.2.20", port: 443, resolveAddress: nil))
        XCTAssertEqual(
            try destination(output(host: "[2001:db8::20]", url: "https://[2001:db8:0::20]:4443/", resolve: "'[2001:db8:0::20]:2001:db8::20'\n")),
            D(host: "2001:db8:0::20", port: 4443, resolveAddress: nil))
        // The profile's host as an address, the gateway a name.
        XCTAssertEqual(try destination(output(), host: "192.0.2.10").host, "gw1.example.com")
    }

    /// A gateway on the portal's own server, a gateway signed in to directly, and the no-portal fallback.
    func testTheProfilesServer() throws {
        let same = output(url: "https://vpn.example.com:8443/", resolve: "'vpn.example.com:192.0.2.20'\n")
        for skipPortal in [false, true] {
            XCTAssertEqual(
                try destination(same, host: "VPN.example.com", port: 8443, skipPortal: skipPortal),
                OpenConnectAuthResult.Destination(host: "vpn.example.com", port: 8443, resolveAddress: "192.0.2.20"))
        }
        let literal = output(host: "192.0.2.10", url: "https://192.0.2.10/", resolve: "'192.0.2.10:192.0.2.10'\n")
        XCTAssertNil(try destination(literal, host: "192.0.2.10", skipPortal: true).resolveAddress)
    }

    func testSkipPortalAllowsNoOtherServer() {
        assertRefused(output(), skipPortal: true, .otherServer)
        assertRefused(output(url: "https://vpn.example.com:8443/", resolve: "'vpn.example.com:192.0.2.20'\n"), skipPortal: true, .otherServer)
        assertRefused(
            output(host: "192.0.2.11", url: "https://192.0.2.11/", resolve: "'192.0.2.11:192.0.2.11'\n"), host: "192.0.2.10", skipPortal: true,
            .otherServer)
    }

    func testCONNECT_URLHasNoPathOrAnythingElse() {
        for url in [
            "https://gw1.example.com/gateway", "https://gw1.example.com/ssl-vpn/", "https://gw1.example.com:443/", "https://gw1.example.com:04443/",
            "https://alice@gw1.example.com/", "https://gw1.example.com/?x=1", "https://gw1.example.com/#x", "https://gw1.example.com",
            "http://gw1.example.com/", "https://gw1.example.com//", "https://gw1_example.com/", "https://[gw1.example.com]/",
            "https://gw1.example.com:0/", "https://gw1.example.com:65536/", "https://[2001:db8::1%en0]/"
        ] {
            assertRefused(output(url: url), .otherServer)
        }
    }

    /// RESOLVE and HOST belong to CONNECT_URL's host, not to the portal's.
    func testTheAddressIsTheGateways() {
        assertRefused(output(resolve: "'vpn.example.com:192.0.2.20'\n"), .addressMismatch)
        assertRefused(output(resolve: "'gw2.example.com:192.0.2.20'\n"), .addressMismatch)
        assertRefused(output(host: "192.0.2.21"), .addressMismatch)
        assertRefused(output(host: "2001:db8::20", resolve: "'gw1.example.com:2001:db8::20'\n"), .addressMismatch)
        assertRefused(output(resolve: "'gw1.example.com:fe80::1%en0'\n"), .addressMismatch)
        assertRefused(output(resolve: ""), .noResolvedAddress)
        assertRefused(output(url: "https://192.0.2.20/", resolve: "'192.0.2.20:192.0.2.21'\n"), .addressMismatch)
        assertRefused(output(host: "192.0.2.21", url: "https://192.0.2.20/", resolve: "'192.0.2.20:192.0.2.20'\n"), .addressMismatch)
    }

    /// With pins, the accepted key is one of the two; without, the CA check decided.
    func testThePins() throws {
        XCTAssertNoThrow(try destination(output(), pin: examplePin))
        XCTAssertNoThrow(try destination(output(), gatewayPin: examplePin))
        XCTAssertNoThrow(try destination(output(fingerprint: otherExamplePin), pin: examplePin, gatewayPin: otherExamplePin))
        XCTAssertNoThrow(try destination(output(fingerprint: otherExamplePin)))
        assertRefused(output(fingerprint: otherExamplePin), pin: examplePin, .fingerprintMismatch)
        assertRefused(output(fingerprint: otherExamplePin), gatewayPin: examplePin, .fingerprintMismatch)
        let third = "pin-sha256:" + String(repeating: "A", count: 43) + "="
        assertRefused(output(fingerprint: third), pin: examplePin, gatewayPin: otherExamplePin, .fingerprintMismatch)
        for bad in [String(examplePin.prefix(20)), "PIN-SHA256:" + examplePin.dropFirst(11)] {
            XCTAssertThrowsError(try destination(output(), pin: bad))
            XCTAssertThrowsError(try destination(output(), gatewayPin: bad))
        }
    }

    func testTheProfileItselfIsChecked() {
        XCTAssertThrowsError(try destination(output(), host: "vpn.example.com/x"))
        XCTAssertThrowsError(try destination(output(), host: ""))
        XCTAssertThrowsError(try destination(output(), port: 0))
    }

    /// A Cisco AnyConnect result keeps Phase 1's rules: the profile's server only, one pin.
    func testCiscoAnyConnectKeepsItsRules() throws {
        let ac = try OpenConnectAuthResult.parse(
            "COOKIE='EXAMPLE-COOKIE-1'\nHOST='192.0.2.10'\nCONNECT_URL='https://vpn.example.com/'\nFINGERPRINT='\(examplePin)'\n"
                + "RESOLVE='vpn.example.com:192.0.2.10'\n")
        XCTAssertEqual(
            try ac.checkDestination(host: "vpn.example.com", port: 443, skipPortal: false, profileServerCert: "", profileGatewayServerCert: ""),
            OpenConnectAuthResult.Destination(host: "vpn.example.com", port: 443, resolveAddress: "192.0.2.10"))
        XCTAssertThrowsError(
            try ac.checkDestination(host: "vpn.example.com", port: 443, skipPortal: true, profileServerCert: "", profileGatewayServerCert: ""))
        XCTAssertThrowsError(
            try ac.checkDestination(
                host: "vpn.example.com", port: 443, skipPortal: false, profileServerCert: "", profileGatewayServerCert: examplePin))
        let other = try OpenConnectAuthResult.parse(
            "COOKIE='EXAMPLE-COOKIE-1'\nHOST='192.0.2.20'\nCONNECT_URL='https://gw1.example.com/'\nFINGERPRINT='\(examplePin)'\n"
                + "RESOLVE='gw1.example.com:192.0.2.20'\n")
        XCTAssertThrowsError(
            try other.checkDestination(host: "vpn.example.com", port: 443, skipPortal: false, profileServerCert: "", profileGatewayServerCert: "")
        ) {
            XCTAssertEqual($0 as? OpenConnectAuthResult.DestinationError, .otherServer)
        }
    }

    func testTheTunnelConfig() throws {
        let r = try parse(output(fingerprint: otherExamplePin))
        let text = try r.tunnelConfig(
            host: "vpn.example.com", port: 443, skipPortal: false, profileServerCert: examplePin, profileGatewayServerCert: otherExamplePin,
            scriptPath: exampleHook, tlsOnly: true, disableIPv6: true
        ).render()
        XCTAssertEqual(
            text,
            """
            # Generated by PassTunnel. Do not edit.
            protocol gp
            server https://gw1.example.com/
            cookie \(exampleGPCookie)
            servercert \(otherExamplePin)
            resolve gw1.example.com:192.0.2.20
            script \(exampleHook)
            non-inter
            reconnect-timeout 60
            no-dtls
            disable-ipv6

            """, "the gateway's server, its address and the key the sign-in accepted")
        XCTAssertThrowsError(
            try r.tunnelConfig(
                host: "vpn.example.com", port: 443, skipPortal: true, profileServerCert: "", profileGatewayServerCert: "", scriptPath: exampleHook,
                tlsOnly: false, disableIPv6: false))
        XCTAssertThrowsError(
            try r.tunnelConfig(
                host: "vpn.example.com", port: 443, skipPortal: false, profileServerCert: examplePin, profileGatewayServerCert: "",
                scriptPath: exampleHook, tlsOnly: false, disableIPv6: false))
    }

    /// The helper's side, on the fields the client sends: the gateway as host and port, the cookie as printed.
    func testTheHelpersCheck() throws {
        func build(
            protocol p: OpenConnectProtocol = .gp, host: String = "gw1.example.com", port: Int = 443, url: String = "https://gw1.example.com/",
            resolve: String? = "gw1.example.com:192.0.2.20", cookie: String = exampleGPCookie, pin: String = examplePin, profilePin: String = "",
            gatewayPin: String = "", disableIPv6: Bool = false
        ) throws -> OpenConnectConfig {
            try OpenConnectAuthResult.tunnelConfig(
                protocol: p, host: host, port: port, connectURL: url, resolve: resolve, cookie: cookie, serverCert: pin,
                profileServerCert: profilePin, profileGatewayServerCert: gatewayPin, scriptPath: exampleHook, tlsOnly: false,
                disableIPv6: disableIPv6)
        }
        XCTAssertEqual(try build().resolveAddress, "192.0.2.20")
        XCTAssertEqual(try build().protocol, .gp)
        XCTAssertEqual(try build(profilePin: examplePin).serverCert, examplePin)
        XCTAssertEqual(try build(pin: otherExamplePin, profilePin: examplePin, gatewayPin: otherExamplePin).serverCert, otherExamplePin)
        XCTAssertTrue(try build(disableIPv6: true).render().hasSuffix("\ndisable-ipv6\n"))
        XCTAssertNil(try build(host: "192.0.2.20", url: "https://192.0.2.20/", resolve: nil).resolveAddress)
        let refused: [() throws -> OpenConnectConfig] = [
            { try build(cookie: "webvpn=EXAMPLE-COOKIE") }, { try build(cookie: exampleGPAuthcookie) }, { try build(cookie: "") },
            { try build(cookie: exampleGPCookie + "\nscript-tun") }, { try build(url: "https://vpn.example.com/") },
            { try build(url: "https://gw1.example.com:4443/") }, { try build(url: "https://gw1.example.com/gateway") },
            { try build(resolve: nil) }, { try build(resolve: "vpn.example.com:192.0.2.20") }, { try build(pin: "") },
            { try build(pin: otherExamplePin, profilePin: examplePin) }, { try build(pin: otherExamplePin, gatewayPin: examplePin) },
            { try build(gatewayPin: String(examplePin.prefix(20))) },
            // Cisco AnyConnect: no gateway pin, no disable-ipv6, its own cookie.
            { try build(protocol: .anyconnect, cookie: "webvpn=EXAMPLE-COOKIE", gatewayPin: examplePin) },
            { try build(protocol: .anyconnect, cookie: "webvpn=EXAMPLE-COOKIE", disableIPv6: true) }, { try build(protocol: .anyconnect) }
        ]
        for (n, attempt) in refused.enumerated() {
            XCTAssertThrowsError(try attempt(), "case \(n + 1)") { XCTAssertFalse("\($0)".contains(exampleGPAuthcookie)) }
        }
        XCTAssertNoThrow(try build(protocol: .anyconnect, cookie: "webvpn=EXAMPLE-COOKIE"))
    }

    /// The helper builds the same file from what the client sends it as the client built.
    func testTheHelperAgreesWithTheClient() throws {
        let outputs = [
            output(), output(url: "https://gw1.example.com:4443/"),
            output(url: "https://GW1.Example.com/", resolve: "'GW1.Example.com:192.0.2.20'\n"),
            output(url: "https://192.0.2.20/", resolve: "'192.0.2.20:192.0.2.20'\n"),
            output(host: "[2001:db8::20]", url: "https://[2001:db8::20]/", resolve: "'[2001:db8::20]:2001:db8::20'\n"),
            output(url: "https://vpn.example.com/", resolve: "'vpn.example.com:192.0.2.20'\n")
        ]
        for text in outputs {
            let r = try parse(text)
            for (pin, gatewayPin) in [("", ""), (examplePin, ""), ("", examplePin)] {
                let client = try r.tunnelConfig(
                    host: "vpn.example.com", port: 443, skipPortal: false, profileServerCert: pin, profileGatewayServerCert: gatewayPin,
                    scriptPath: exampleHook, tlsOnly: false, disableIPv6: false)
                let destination = try r.checkDestination(
                    host: "vpn.example.com", port: 443, skipPortal: false, profileServerCert: pin, profileGatewayServerCert: gatewayPin)
                let helper = try OpenConnectAuthResult.tunnelConfig(
                    protocol: .gp, host: destination.host, port: destination.port, connectURL: r.connectURL,
                    resolve: destination.resolveAddress == nil ? nil : r.resolve, cookie: r.tunnelCookie, serverCert: r.fingerprint,
                    profileServerCert: pin, profileGatewayServerCert: gatewayPin, scriptPath: exampleHook, tlsOnly: false, disableIPv6: false)
                XCTAssertEqual(helper, client, text)
            }
        }
    }

    /// The gateway's host is the server's choice: the destination's description shows none of it, and no
    /// description or error of the result shows the cookie.
    func testNoServerValueIsShown() throws {
        let secret = "SESSIONSECRET0123"
        let text = output(
            cookie: "authcookie=\(secret)&user=alice&computer=x", url: "https://\(secret.lowercased()).example.com/",
            resolve: "'\(secret.lowercased()).example.com:192.0.2.20'\n")
        let r = try parse(text)
        let d = try r.checkDestination(host: "vpn.example.com", port: 443, skipPortal: false, profileServerCert: "", profileGatewayServerCert: "")
        var dumped = ""
        dump(d, to: &dumped)
        var shown = [d.description, d.debugDescription, String(describing: d), String(reflecting: d), dumped]
        shown += Mirror(reflecting: d).children.map { "\($0.value)" }
        var dumpedResult = ""
        dump(r, to: &dumpedResult)
        shown += [r.description, String(reflecting: r), dumpedResult]
        for t in shown {
            XCTAssertFalse(t.lowercased().contains(secret.lowercased()), t)
            XCTAssertFalse(t.contains("192.0.2.20"), t)
        }
        XCTAssertThrowsError(
            try r.checkDestination(host: "vpn.example.com", port: 443, skipPortal: true, profileServerCert: "", profileGatewayServerCert: "")
        ) {
            XCTAssertFalse("\($0)".lowercased().contains(secret.lowercased()))
        }
    }
}
