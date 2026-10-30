import Foundation
import XCTest

@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

/// The helper's side of a Palo Alto GlobalProtect session that needs no files (issue #230; ARCHITECTURE.md,
/// "Helper protocol 5"): the request's `protocol` and `profile_gateway_server_cert`, the checks by protocol (the
/// gateway as the tunnel's server, the two pins, the cookie's shape), the line count, and the cookie masks. The
/// files `prepareOpenConnect` writes are in OpenConnectSessionTests; Cisco AnyConnect's checks in
/// OpenConnectRequestTests, unchanged.
final class GlobalProtectRequestTests: XCTestCase {
    /// A pin neither of the profile's.
    static let thirdPin = "pin-sha256:" + String(repeating: "A", count: 43) + "="

    /// The portal vpn.example.com (key `examplePin`) sent the sign-in to the gateway gw1.example.com (key
    /// `otherExamplePin`), at 192.0.2.20: the request names the gateway.
    static func start(_ change: (inout OpenConnectStart) -> Void = { _ in }) -> OpenConnectStart {
        var s = OpenConnectStart(
            protocol: .gp, profileID: "acme", profileDir: "/d/acme", logPath: "/d/acme/vpn.log", host: "gw1.example.com",
            connectURL: "https://gw1.example.com/", resolve: "gw1.example.com:192.0.2.20", cookie: exampleGPCookie,
            serverCert: otherExamplePin, profileServerCert: examplePin, profileGatewayServerCert: otherExamplePin, setDNS: true)
        change(&s)
        return s
    }

    func config(_ change: (inout OpenConnectStart) -> Void = { _ in }, disableIPv6: Bool = false) throws -> OpenConnectConfig {
        try HelperCore.openConnectConfig(Self.start(change), scriptPath: exampleHook, disableIPv6: disableIPv6)
    }

    // MARK: Wire format

    func testWireFormat() throws {
        for s in [
            Self.start(), Self.start { $0.profileGatewayServerCert = "" },
            Self.start {
                $0.host = "192.0.2.20"; $0.connectURL = "https://192.0.2.20/"; $0.resolve = nil
            }
        ] {
            let request = HelperRequest.startOpenConnect(s)
            XCTAssertEqual(try HelperCore.decodeRequest(try request.jsonData()), request)
        }
        let object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: try HelperRequest.startOpenConnect(Self.start()).jsonData()) as? [String: Any])
        XCTAssertEqual(object["protocol_version"] as? Int, 5)
        XCTAssertEqual(object["protocol"] as? String, "gp")
        XCTAssertEqual(object["host"] as? String, "gw1.example.com")
        XCTAssertEqual(object["profile_server_cert"] as? String, examplePin)
        XCTAssertEqual(object["profile_gateway_server_cert"] as? String, otherExamplePin)
        XCTAssertEqual(object["cookie"] as? String, exampleGPCookie)
        // The keys as the design names them, decoded from text.
        let json = """
            {"type":"start_openconnect","protocol_version":5,"protocol":"gp","profile_id":"acme","profile_dir":"/d/acme",\
            "log_path":"/d/acme/vpn.log","host":"gw1.example.com","port":443,"usergroup":"",\
            "connect_url":"https://gw1.example.com/","resolve":"gw1.example.com:192.0.2.20","cookie":"\(exampleGPCookie)",\
            "server_cert":"\(otherExamplePin)","profile_server_cert":"\(examplePin)",\
            "profile_gateway_server_cert":"\(otherExamplePin)","tls_only":false,"set_dns":true,"set_routes":true}
            """
        XCTAssertEqual(try HelperCore.decodeRequest(Data(json.utf8)), .startOpenConnect(Self.start()))
    }

    /// A GlobalProtect start is never taken for a Cisco AnyConnect one: without `protocol` it is refused, from a
    /// protocol-4 client it never decodes, and one labelled `anyconnect` fails that protocol's checks.
    func testAGlobalProtectStartIsNeverReadAsAnyConnect() throws {
        var json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: try HelperRequest.startOpenConnect(Self.start()).jsonData()) as? [String: Any])
        json["protocol"] = nil
        XCTAssertThrowsError(try HelperCore.decodeRequest(try JSONSerialization.data(withJSONObject: json))) {
            XCTAssertEqual($0 as? HelperCore.RequestError, .invalidField("protocol"))
            XCTAssertFalse(String(describing: $0).contains(exampleGPAuthcookie))
        }
        // What a 1.6.0 app sends (protocol 4, no `protocol`), and a protocol-4 request with the new keys.
        for withKeys in [false, true] {
            var old = json
            old["protocol_version"] = 4
            if withKeys { old["protocol"] = "gp" } else { old["profile_gateway_server_cert"] = nil }
            XCTAssertThrowsError(try HelperCore.decodeRequest(try JSONSerialization.data(withJSONObject: old))) {
                XCTAssertEqual($0 as? HelperCore.RequestError, .versionMismatch(client: 4, helper: 5))
            }
        }
        // Labelled Cisco AnyConnect: GlobalProtect's cookie, its gateway pin and a gateway on another server than
        // the profile's all fail that protocol's checks.
        let relabelled = Self.start { $0.protocol = .anyconnect }
        XCTAssertThrowsError(try HelperCore.openConnectConfig(relabelled, scriptPath: exampleHook))
        XCTAssertThrowsError(
            try HelperCore.openConnectConfig(
                Self.start {
                    $0.protocol = .anyconnect; $0.profileGatewayServerCert = ""
                }, scriptPath: exampleHook))
    }

    func testSecretAndServerValuesAreRedacted() {
        // The portal chose the gateway (host and port) too: a host that repeats the secret is hidden with the rest.
        let host = exampleGPAuthcookie + ".example.com"
        let s = Self.start {
            $0.host = host
            $0.port = 46_587
            $0.connectURL = "https://\(host):46587/?\(exampleGPAuthcookie)"
            $0.resolve = "\(host):\(exampleGPAuthcookie)"
            $0.serverCert = exampleGPCookie
        }
        let request = HelperRequest.startOpenConnect(s)
        var dumped = ""
        dump(s, to: &dumped)
        for text in [s.description, s.debugDescription, String(describing: request), String(reflecting: request), dumped] {
            XCTAssertFalse(text.contains(exampleGPAuthcookie), text)
            XCTAssertFalse(text.contains("authcookie"), text)
            XCTAssertFalse(text.contains("192.0.2.20"), text)
            XCTAssertFalse(text.contains("46587") || text.contains("46_587"), text)
        }
        // The protocol and the profile's own pins are shown.
        XCTAssertTrue(s.description.contains("protocol: gp") && s.description.contains("host: <redacted>, port: <redacted>"), s.description)
        XCTAssertTrue(s.description.contains("profileGatewayServerCert: \(otherExamplePin)"), s.description)
        XCTAssertTrue(dumped.contains("gp"), dumped)
        // Cisco AnyConnect's host is the profile's own and stays shown.
        let anyconnect = OpenConnectRequestTests.start()
        XCTAssertTrue(anyconnect.description.contains("host: vpn.example.com, port: 8443"), anyconnect.description)
    }

    /// The portal chose the gateway: a gateway host that embeds the cookie's secret (lowercased, as a host name has
    /// it) is shown by no description, mirror or error of the helper's, and the masker hides it in openconnect's
    /// output (ARCHITECTURE.md, "Helper protocol 5").
    func testNoServerValueIsShown() throws {
        let secret = "SESSIONSECRET0123"
        let host = "\(secret.lowercased()).example.com"
        let cookie = "authcookie=\(secret)&user=alice&computer=x"
        for port in [443, 4443] {
            let url = "https://\(host)\(port == 443 ? "" : ":\(port)")/"
            let s = Self.start {
                $0.host = host; $0.port = port; $0.connectURL = url; $0.resolve = "\(host):192.0.2.20"; $0.cookie = cookie
            }
            XCTAssertNoThrow(try HelperCore.openConnectConfig(s, scriptPath: exampleHook), "a valid request")
            var dumped = ""
            dump(s, to: &dumped)
            let request = HelperRequest.startOpenConnect(s)
            var shown = [s.description, s.debugDescription, String(describing: request), String(reflecting: request), dumped]
            shown += Mirror(reflecting: s).children.map { "\($0.value)" }
            // Every refusal of a request with this gateway: the errors name fields and fixed reasons only.
            let refusals: [(inout OpenConnectStart) -> Void] = [
                { $0.serverCert = Self.thirdPin }, { $0.connectURL = "https://\(host):1/" }, { $0.connectURL = url + "x" },
                { $0.resolve = nil }, { $0.resolve = "\(host):\(host)" }, { $0.resolve = "vpn.example.com:192.0.2.10" },
                { $0.cookie = "webvpn=\(secret)" }, { $0.cookie = cookie + "&x=\(secret)" }, { $0.usergroup = "gateway" },
                { $0.host = host + "." }, { $0.host = host.uppercased() + "\n" }, { $0.profileGatewayServerCert = "sha1:00" },
                { $0.connectURL = url + "\n" }, { $0.protocol = .anyconnect }
            ]
            for change in refusals {
                var bad = s
                change(&bad)
                XCTAssertThrowsError(try HelperCore.openConnectConfig(bad, scriptPath: exampleHook)) {
                    shown += [String(describing: $0), $0.localizedDescription, String(reflecting: $0)]
                }
                // The refused request's own description too (Cisco AnyConnect's host is the profile's, and shown).
                if bad.protocol == .gp { shown += [bad.description, String(reflecting: bad)] }
            }
            for text in shown {
                XCTAssertFalse(text.lowercased().contains(secret.lowercased()), text)
                XCTAssertFalse(text.contains(String(port)) && port != 443, text)
            }
        }
        // openconnect prints the gateway's name itself; the masker hides the secret in it, whatever its case.
        let secrets = GlobalProtectCookie.secrets(cookie)
        for line in [
            "POST https://\(host)/ssl-vpn/getconfig.esp", "Connected to \(host):443", "SSL negotiation with \(host.uppercased())",
            "Got HTTP response: HTTP/1.1 200 \(secret)"
        ] {
            let masked = OutputMask.apply(line, secrets: secrets)
            XCTAssertFalse(masked.lowercased().contains(secret.lowercased()), masked)
            XCTAssertTrue(masked.contains("<redacted>"), masked)
        }
    }

    // MARK: Checks

    func testValidRequests() throws {
        let c = try config()
        XCTAssertEqual(c.protocol, .gp)
        XCTAssertEqual(c.host, "gw1.example.com")
        XCTAssertEqual(c.port, 443)
        XCTAssertEqual(c.cookie, exampleGPCookie, "taken unchanged")
        XCTAssertEqual(c.serverCert, otherExamplePin)
        XCTAssertEqual(c.resolveAddress, "192.0.2.20")
        XCTAssertFalse(c.disableIPv6)
        // The gateway has the portal's key; only the portal is pinned; only the gateway; no pin (the system CAs).
        XCTAssertNoThrow(try config { $0.serverCert = examplePin })
        XCTAssertNoThrow(
            try config {
                $0.serverCert = examplePin; $0.profileGatewayServerCert = ""
            })
        XCTAssertNoThrow(try config { $0.profileServerCert = "" })
        XCTAssertNoThrow(
            try config {
                $0.profileServerCert = ""; $0.profileGatewayServerCert = ""; $0.serverCert = Self.thirdPin
            })
        // The gateway on the portal's own host (or `skip_portal`): the request does not tell, and needs not.
        XCTAssertEqual(
            try config {
                $0.host = "vpn.example.com"; $0.connectURL = "https://vpn.example.com/"; $0.resolve = "vpn.example.com:192.0.2.10"
            }.host, "vpn.example.com")
        XCTAssertEqual(
            try config {
                $0.port = 4443; $0.connectURL = "https://gw1.example.com:4443/"
            }.port, 4443)
        // IP-literal gateways, as portals often list them: no resolve.
        XCTAssertNil(
            try config {
                $0.host = "192.0.2.20"; $0.connectURL = "https://192.0.2.20/"; $0.resolve = nil
            }.resolveAddress)
        XCTAssertNil(
            try config {
                $0.host = "2001:db8::20"; $0.connectURL = "https://[2001:db8::20]/"; $0.resolve = nil
            }.resolveAddress)
        XCTAssertTrue(try config { $0.tlsOnly = true }.tlsOnly)
        // The cookie's smallest shape (no portal, empty computer).
        XCTAssertNoThrow(try config { $0.cookie = "authcookie=12345678&user=alice&computer=" })
        // `disable-ipv6`: the daemon's decision, for GlobalProtect.
        XCTAssertTrue(try config(disableIPv6: true).disableIPv6)
    }

    /// Every field the helper refuses for GlobalProtect, each with what it throws; none of the errors carries the
    /// cookie or its secret.
    func testEveryInvalidFieldIsRefused() {
        typealias V = OpenConnectConfig.ValidationError
        typealias D = OpenConnectAuthResult.DestinationError
        func invalid(_ field: String) -> (Error) -> Bool {
            { if case .invalidValue(field, _)? = $0 as? V { return true } else { return false } }
        }
        let long = "authcookie=\(exampleGPAuthcookie)&user=alice&computer="
        let cases: [(String, (inout OpenConnectStart) -> Void, (Error) -> Bool)] = [
            ("profile ID", { $0.profileID = "../acme" }, { ($0 as? HelperCore.Failure) == .invalidProfileID("../acme") }),
            // The user group is Cisco AnyConnect's: a path would decide portal or gateway or name a SAML field.
            ("user group", { $0.usergroup = "staff" }, invalid("user group")),
            ("user group gateway", { $0.usergroup = "gateway" }, invalid("user group")),
            ("user group SAML field", { $0.usergroup = "gateway:prelogin-cookie" }, invalid("user group")),
            // The two pins: each empty or full; the accepted key one of them when either is set.
            ("profile pin", { $0.profileServerCert = "sha1:0123" }, { ($0 as? V) == .invalidServerCert }),
            ("gateway pin", { $0.profileGatewayServerCert = "sha1:0123" }, { ($0 as? V) == .invalidServerCert }),
            ("gateway pin prefix", { $0.profileGatewayServerCert = "pin-sha256:z5Gv" }, { ($0 as? V) == .invalidServerCert }),
            ("gateway pin line", { $0.profileGatewayServerCert = otherExamplePin + "\n" }, { ($0 as? V) == .invalidServerCert }),
            ("key neither pin", { $0.serverCert = Self.thirdPin }, { ($0 as? D) == .fingerprintMismatch }),
            (
                "key not the gateway pin",
                {
                    $0.profileServerCert = ""; $0.serverCert = examplePin
                },
                { ($0 as? D) == .fingerprintMismatch }
            ),
            (
                "key not the portal pin",
                {
                    $0.profileGatewayServerCert = ""; $0.serverCert = otherExamplePin
                },
                { ($0 as? D) == .fingerprintMismatch }
            ),
            ("server cert", { $0.serverCert = "sha256:00" }, { ($0 as? V) == .invalidServerCert }),
            ("server cert empty", { $0.serverCert = "" }, { ($0 as? V) == .invalidServerCert }),
            // The gateway: CONNECT_URL must name the request's host and port, without a path.
            ("host", { $0.host = "gw1.example.com\nscript /tmp/x" }, { ($0 as? V) == .invalidHost }),
            ("port", { $0.port = 0 }, { ($0 as? V) == .invalidPort(0) }),
            ("connect URL the portal", { $0.connectURL = "https://vpn.example.com/" }, { ($0 as? D) == .otherServer }),
            ("connect URL port", { $0.connectURL = "https://gw1.example.com:4443/" }, { ($0 as? D) == .otherServer }),
            ("connect URL gateway path", { $0.connectURL = "https://gw1.example.com/gateway" }, { ($0 as? D) == .otherServer }),
            ("connect URL ssl-vpn path", { $0.connectURL = "https://gw1.example.com/ssl-vpn" }, { ($0 as? D) == .otherServer }),
            ("connect URL query", { $0.connectURL = "https://gw1.example.com/?a=b" }, { ($0 as? D) == .otherServer }),
            ("connect URL user", { $0.connectURL = "https://alice@gw1.example.com/" }, { ($0 as? D) == .otherServer }),
            ("connect URL scheme", { $0.connectURL = "http://gw1.example.com/" }, { ($0 as? D) == .otherServer }),
            ("connect URL empty", { $0.connectURL = "" }, { $0 is OpenConnectAuthResult.ParseError }),
            ("connect URL line", { $0.connectURL = "https://gw1.example.com/\n" }, { $0 is OpenConnectAuthResult.ParseError }),
            // resolve: the gateway's, an address.
            ("resolve missing", { $0.resolve = nil }, { ($0 as? D) == .noResolvedAddress }),
            ("resolve the portal", { $0.resolve = "vpn.example.com:192.0.2.10" }, { ($0 as? D) == .addressMismatch }),
            ("resolve not an address", { $0.resolve = "gw1.example.com:gw2.example.com" }, { ($0 as? D) == .addressMismatch }),
            ("resolve line", { $0.resolve = "gw1.example.com:192.0.2.20\nscript /tmp/x" }, { $0 is OpenConnectAuthResult.ParseError }),
            (
                "resolve for an address",
                {
                    $0.host = "192.0.2.20"; $0.connectURL = "https://192.0.2.20/"; $0.resolve = "192.0.2.20:192.0.2.20"
                },
                { ($0 as? D) == .addressMismatch }
            ),
            // The cookie: openconnect's GlobalProtect shape only.
            ("cookie empty", { $0.cookie = "" }, invalid("cookie")),
            ("cookie Cisco AnyConnect", { $0.cookie = OpenConnectRequestTests.cookie }, invalid("cookie")),
            ("cookie STRAP", { $0.cookie = OpenConnectCookieTests.strap }, invalid("cookie")),
            ("cookie line", { $0.cookie = exampleGPCookie + "\nscript /tmp/x" }, invalid("cookie")),
            ("cookie blank", { $0.cookie = exampleGPCookie.replacingOccurrences(of: "alice-mac", with: "alice mac") }, invalid("cookie")),
            ("cookie quote", { $0.cookie = exampleGPCookie + "'" }, invalid("cookie")),
            ("cookie no computer", { $0.cookie = "authcookie=\(exampleGPAuthcookie)&user=alice" }, invalid("cookie")),
            ("cookie no user", { $0.cookie = "authcookie=\(exampleGPAuthcookie)&computer=x" }, invalid("cookie")),
            ("cookie short secret", { $0.cookie = "authcookie=1234567&user=alice&computer=x" }, invalid("cookie")),
            (
                "cookie override", { $0.cookie = "authcookie=\(exampleGPAuthcookie)&user=alice&portal-userauthcookie=abcdefgh&computer=x" },
                invalid("cookie")
            ),
            ("cookie order", { $0.cookie = "user=alice&authcookie=\(exampleGPAuthcookie)&computer=x" }, invalid("cookie")),
            ("cookie upper hex", { $0.cookie = "authcookie=\(exampleGPAuthcookie)&user=al%2Fice&domain=%2F&computer=%2F" }, invalid("cookie")),
            ("cookie long", { $0.cookie = long + String(repeating: "c", count: 4097 - long.utf8.count) }, invalid("cookie"))
        ]
        for (name, change, expected) in cases {
            var start = Self.start()
            change(&start)
            XCTAssertThrowsError(try HelperCore.openConnectConfig(start, scriptPath: exampleHook), name) { error in
                XCTAssertTrue(expected(error), "\(name): \(error)")
                for text in [String(describing: error), error.localizedDescription] {
                    XCTAssertFalse(text.contains(exampleGPAuthcookie), name)
                    XCTAssertFalse(text.contains("authcookie="), name)
                }
            }
        }
        // The hook path itself (it reaches `/bin/sh -c`).
        for bad in ["relative/vpn-hook", "/tmp/a b", "/tmp/$(x)", "/tmp/../vpn-hook", ""] {
            XCTAssertThrowsError(try HelperCore.openConnectConfig(Self.start(), scriptPath: bad), bad)
        }
    }

    func testLineCountFollowsTheRequest() throws {
        for s in [
            Self.start(), Self.start { $0.tlsOnly = true },
            Self.start {
                $0.host = "192.0.2.20"; $0.connectURL = "https://192.0.2.20/"; $0.resolve = nil; $0.tlsOnly = true
            }
        ] {
            for disableIPv6 in [false, true] {
                let text = try HelperCore.openConnectConfig(s, scriptPath: exampleHook, disableIPv6: disableIPv6).render()
                let count = HelperCore.openConnectLineCount(s, disableIPv6: disableIPv6)
                XCTAssertEqual(text.split(separator: "\n").count, count)
                XCTAssertEqual(count, 8 + (s.resolve == nil ? 0 : 1) + (s.tlsOnly ? 1 : 0) + (disableIPv6 ? 1 : 0))
                XCTAssertTrue(text.hasPrefix(OpenConnectConfig.header + "\nprotocol gp\n"))
                XCTAssertEqual(text.hasSuffix("disable-ipv6\n"), disableIPv6)
                XCTAssertNoThrow(try OpenConnectConfig.checkRendered(text, lineCount: count))
                // A file of another length than the request implies fails the final check.
                XCTAssertThrowsError(try OpenConnectConfig.checkRendered(text, lineCount: count + 1))
            }
        }
    }

    // MARK: Masks

    func testTheMaskerGetsTheProtocolsSecrets() {
        XCTAssertEqual(HelperCore.openConnectSecrets(Self.start()), [exampleGPCookie, exampleGPAuthcookie])
        XCTAssertEqual(
            HelperCore.openConnectSecrets(OpenConnectRequestTests.start()), OpenConnectCookie.secrets(OpenConnectRequestTests.cookie))
    }

    /// `OutputMask` hides an `authcookie=` value wherever it stands, the whole cookie and its secret as given, and
    /// the `cookie` configuration line; openconnect's own messages stay.
    func testOutputMaskHidesTheGlobalProtectCookie() {
        let secrets = GlobalProtectCookie.secrets(exampleGPCookie)
        let cases: [(String, String)] = [
            (
                "GET https://gw1.example.com/ssl-tunnel-connect.sslvpn?user=alice&authcookie=fedcba9876543210 HTTP/1.1",
                "GET https://gw1.example.com/ssl-tunnel-connect.sslvpn?user=alice&authcookie=<redacted> HTTP/1.1"
            ),
            ("x authcookie=fedcba9876543210&portal=Acme", "x authcookie=<redacted>&portal=Acme"),
            ("x AUTHCOOKIE=fedcba9876543210;", "x AUTHCOOKIE=<redacted>;"),
            ("portal-userauthcookie=fedcba9876543210", "portal-userauthcookie=<redacted>"),
            ("cookie \(exampleGPCookie)", "cookie <redacted>"),
            ("Got HTTP response: HTTP/1.1 502 \(exampleGPCookie) x", "Got HTTP response: HTTP/1.1 502 <redacted> x"),
            ("Got HTTP response: HTTP/1.1 502 \(exampleGPAuthcookie) x", "Got HTTP response: HTTP/1.1 502 <redacted> x"),
            ("Cookie was rejected by server; exiting.", "Cookie was rejected by server; exiting."),
            ("Invalid authentication cookie", "Invalid authentication cookie"),
            ("ESP session established with server", "ESP session established with server")
        ]
        for (line, masked) in cases {
            XCTAssertEqual(OutputMask.apply(line, secrets: secrets), masked, line)
        }
    }

    /// The helper's copy of openconnect's output, with the secrets `prepareOpenConnect` gives it.
    func testTheMaskingCopierHidesTheCookie() throws {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&fds), 0)
        let logURL = FileManager.default.temporaryDirectory.appendingPathComponent("gp-mask-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: logURL) }
        let logFD = open(logURL.path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        XCTAssertGreaterThanOrEqual(logFD, 0)
        let output = """
            POST https://gw1.example.com/ssl-vpn/getconfig.esp
            Got HTTP response: HTTP/1.1 512 \(exampleGPCookie)
            reflected \(exampleGPAuthcookie) here
            GET /ssl-tunnel-connect.sslvpn?user=alice&authcookie=\(exampleGPAuthcookie)

            """
        let bytes = Array(output.utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { write(fds[1], $0.baseAddress, $0.count) }, bytes.count)
        close(fds[1])
        MaskingCopier(readFD: fds[0], logFD: logFD, secrets: HelperCore.openConnectSecrets(Self.start())).run()
        let log = try String(contentsOf: logURL, encoding: .utf8)
        XCTAssertEqual(
            log,
            """
            POST https://gw1.example.com/ssl-vpn/getconfig.esp
            Got HTTP response: HTTP/1.1 512 <redacted>
            reflected <redacted> here
            GET /ssl-tunnel-connect.sslvpn?user=alice&authcookie=<redacted>

            """)
    }
}
