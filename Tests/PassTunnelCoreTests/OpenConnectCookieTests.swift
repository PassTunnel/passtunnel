import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

/// The session cookie from what `openconnect --authenticate` prints to the tunnel run's `cookie` option
/// (`OpenConnectCookie`; issue #212). The fixtures have the shapes of real outputs (#188, against ocserv 1.3.0
/// with Ubuntu's openconnect 9.12 and Homebrew's 9.21), with made-up values.
final class OpenConnectCookieTests: XCTestCase {
    /// ocserv's session token: base64 of 32 bytes, so it ends in `=`. Printed bare with `no-external-auth`.
    static let ocservToken = "ZXhhbXBsZSBvY3NlcnYgc2Vzc2lvbiB0b2tlbiAwMSE="
    /// A token without `=` (the form of an ASA's), printed bare too.
    static let asaToken = "4C1D2A@1048576@A3F1@9C8B7A6F5E4D3C2B1A0F9E8D7C6B5A4F3E2D1C0B"
    /// The STRAP key: base64 of a 121-byte DER (a P-256 private key), as openconnect prints it without
    /// `no-external-auth` (Linux openconnect 9.01 to 9.09).
    static let strapKey =
        "ZXhhbXBsZSBTVFJBUCBrZXkgREVSLCBub3QgYSByZWFsIGtleS4gZXhhbXBsZSBTVFJBUCBrZXkgREVSLCBub3QgYSByZWFsIGtleS4gZXhhbXBsZSBTVFJBUCBrZXkg"
        + "REVSLCBub3QgYSByZWFsIGtleS4gZXhhbQ=="
    static let strap = "openconnect_strapkey=\(strapKey); webvpn=\(ocservToken)"

    /// What openconnect's tunnel run makes of its `cookie` option (`internal_split_cookies(…, "webvpn")`,
    /// http.c 119 in 9.21): parts at `;` (blanks after it skipped), each split at its first `=`; a part without
    /// `=` is the value of `webvpn`.
    static func splitLikeOpenConnect(_ option: String) -> [(name: String, value: String)] {
        var out: [(String, String)] = []
        var rest = Substring(option)
        while !rest.isEmpty {
            let part = rest.prefix { $0 != ";" }
            rest = rest.dropFirst(part.count)
            if rest.first == ";" { rest = rest.dropFirst().drop { $0 == " " || $0 == "\t" } }
            if let eq = part.firstIndex(of: "=") {
                out.append((String(part[..<eq]), String(part[part.index(after: eq)...])))
            } else {
                out.append(("webvpn", String(part)))
            }
        }
        return out
    }

    func webvpn(_ option: String) -> String? {
        Self.splitLikeOpenConnect(option).first { $0.name == "webvpn" }?.value
    }

    /// The bug of #212: the bare ocserv token, split as openconnect splits it, gives no `webvpn` cookie at all.
    func testABareTokenWithEqualsLosesItsName() {
        XCTAssertNil(webvpn(Self.ocservToken))
        XCTAssertEqual(webvpn(Self.asaToken), Self.asaToken, "without '=' openconnect names it webvpn itself")
    }

    func testEachPrintedShapeReachesTheServerAsWebvpn() throws {
        for (printed, option) in [
            (Self.ocservToken, "webvpn=" + Self.ocservToken),
            (Self.asaToken, "webvpn=" + Self.asaToken),
            // Still a value: openconnect prints only the value without STRAP, whatever it holds.
            ("webvpn=" + Self.asaToken, "webvpn=webvpn=" + Self.asaToken),
            (Self.strap, Self.strap)
        ] {
            XCTAssertEqual(OpenConnectCookie.tunnelOption(printed: printed), option, printed)
            XCTAssertTrue(OpenConnectCookie.isValidTunnelOption(option), option)
            let value = printed == Self.strap ? Self.ocservToken : printed
            XCTAssertEqual(webvpn(option), value, "openconnect sends the value under its name: \(option)")
        }
        let strap = Self.splitLikeOpenConnect(Self.strap)
        XCTAssertEqual(strap.map(\.name), ["openconnect_strapkey", "webvpn"])
        XCTAssertEqual(strap.first?.value, Self.strapKey)
    }

    func testRefusedShapes() {
        let printed: [String] = [
            "", "a b", "a;b", "a,b", "a\"b", "a\\b", "a'b", "a\tb", "a\u{7F}", "çerez", String(repeating: "c", count: 4090),
            "openconnect_strapkey=\(Self.strapKey); webvpn=", "openconnect_strapkey=; webvpn=\(Self.ocservToken)",
            "openconnect_strapkey=\(Self.strapKey)", "openconnect_strapkey=\(Self.strapKey);webvpn=\(Self.ocservToken)",
            "openconnect_strapkey=\(Self.strapKey.dropLast()); webvpn=\(Self.ocservToken)",
            "openconnect_strapkey=\(Self.strapKey); webvpn=\(Self.ocservToken); other=x"
        ]
        for text in printed {
            XCTAssertNil(OpenConnectCookie.tunnelOption(printed: text), text.debugDescription)
        }
        XCTAssertNotNil(OpenConnectCookie.tunnelOption(printed: String(repeating: "c", count: 4089)))
        for option in [Self.ocservToken, Self.asaToken, "webvpn=", "WEBVPN=x", "webvpn=x; other=y", "other=x", "webvpn=a b"] {
            XCTAssertFalse(OpenConnectCookie.isValidTunnelOption(option), option)
        }
    }

    func testSecretsHoldEveryPart() {
        XCTAssertEqual(OpenConnectCookie.secrets("webvpn=" + Self.ocservToken), ["webvpn=" + Self.ocservToken, Self.ocservToken])
        XCTAssertEqual(OpenConnectCookie.secrets(Self.strap), [Self.strap, Self.strapKey, Self.ocservToken])
        XCTAssertEqual(OpenConnectCookie.secrets(Self.ocservToken), [Self.ocservToken])
    }

    /// The helper's masker: the cookie under its name, its value alone and the STRAP key never reach the log.
    func testTheMaskerHidesEveryPart() {
        for option in ["webvpn=" + Self.ocservToken, Self.strap] {
            let secrets = OpenConnectCookie.secrets(option)
            for part in secrets {
                let line = OutputMask.apply("Got inappropriate HTTP CONNECT response: HTTP/1.1 401 \(part) x", secrets: secrets)
                XCTAssertEqual(line, "Got inappropriate HTTP CONNECT response: HTTP/1.1 401 <redacted> x", part)
            }
        }
    }

    /// The sign-in's log redaction (`AnyConnectSignIn`), with what it masks for a STRAP cookie.
    func testTheSignInLogHidesEveryPart() throws {
        let result = try OpenConnectAuthResult(
            cookie: Self.strap, host: "192.0.2.10", connectURL: "https://vpn.example.com/", fingerprint: examplePin,
            resolve: "vpn.example.com:192.0.2.10")
        let secrets = OpenConnectCookie.secrets(result.cookie) + OpenConnectCookie.secrets(result.tunnelCookie)
        let stderr = Data("a \(Self.strapKey)\nb \(Self.ocservToken)\nc \(Self.strap)\n".utf8)
        let log = AnyConnectSignIn.redacted(stderr, secrets: secrets)
        XCTAssertEqual(log, "a <redacted>\nb <redacted>\nc <redacted>\n")
        XCTAssertFalse(String(describing: result).contains(Self.ocservToken))
        XCTAssertFalse(String(reflecting: result).contains(Self.strapKey))
    }
}
