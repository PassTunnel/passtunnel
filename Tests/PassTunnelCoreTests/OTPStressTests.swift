import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

/// Edge cases for TOTP generation, secret decoding, code composition and otpauth links.
final class TOTPEdgeTests: CoreTestCase {
    let seed1 = Data("12345678901234567890".utf8)
    let seed256 = Data("12345678901234567890123456789012".utf8)
    let seed512 = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8)

    func at(_ t: TimeInterval) -> Date { Date(timeIntervalSince1970: t) }

    /// RFC 6238 Appendix B with 6 and 7 digits (truncations of the 8-digit values) and period 60
    /// (time step T/60 equals the 30 s step of T/2).
    func testRFCVectorsAcrossDigitsAndPeriods() {
        let rows: [(TimeInterval, TOTPAlgorithm, Data, String)] = [
            (59, .sha1, seed1, "94287082"), (1111111109, .sha256, seed256, "68084774"),
            (1234567890, .sha512, seed512, "93441116"), (2000000000, .sha1, seed1, "69279037")
        ]
        for (t, alg, seed, eight) in rows {
            for digits in 6...8 {
                let code = TOTP.code(secret: seed, params: TOTPParams(digits: digits, algorithm: alg), at: at(t))
                XCTAssertEqual(code, String(eight.suffix(digits)), "\(alg) \(digits) @\(t)")
            }
            let doubled = TOTP.code(secret: seed, params: TOTPParams(digits: 8, period: 60, algorithm: alg), at: at(t * 2))
            XCTAssertEqual(
                doubled, TOTP.code(secret: seed, params: TOTPParams(digits: 8, algorithm: alg), at: at(t)),
                "period 60 at 2T == period 30 at T (\(alg))")
        }
    }

    func testWindowBoundaries() {
        for period in [30, 60] {
            let params = TOTPParams(period: period)
            let k = 56_666_666.0
            let start = k * Double(period)
            XCTAssertEqual(TOTP.counter(params: params, at: at(start - 1)), UInt64(k) - 1)
            XCTAssertEqual(TOTP.counter(params: params, at: at(start - 0.001)), UInt64(k) - 1)
            XCTAssertEqual(TOTP.counter(params: params, at: at(start)), UInt64(k))
            XCTAssertEqual(TOTP.counter(params: params, at: at(start + Double(period) - 0.001)), UInt64(k))
            XCTAssertEqual(TOTP.remaining(params: params, at: at(start - 1)), 1)
            XCTAssertEqual(TOTP.remaining(params: params, at: at(start)), period)
            XCTAssertEqual(TOTP.remaining(params: params, at: at(start + 0.999)), period)
            let last = TOTP.code(secret: seed1, params: params, at: at(start - 1))
            let first = TOTP.code(secret: seed1, params: params, at: at(start))
            XCTAssertNotEqual(last, first, "a new window gives a new code (period \(period))")
            XCTAssertEqual(first, TOTP.code(secret: seed1, params: params, at: at(start + Double(period) - 1)))
        }
    }

    func testClockFarInThePastOrFuture() {
        let params = TOTPParams()
        // Before 1970 the counter stays at 0 and the countdown keeps its 1...period contract.
        XCTAssertEqual(TOTP.counter(params: params, at: at(-1)), 0)
        XCTAssertEqual(
            TOTP.code(secret: seed1, params: params, at: at(-12345)),
            TOTP.code(secret: seed1, params: params, at: at(0)))
        for t in [-1.0, -29, -30, -31, -1e9] {
            XCTAssertTrue((1...30).contains(TOTP.remaining(params: params, at: at(t))), "remaining @\(t)")
        }
        XCTAssertEqual(TOTP.remaining(params: params, at: at(-1)), 1)
        XCTAssertEqual(TOTP.remaining(params: params, at: at(-30)), 30)
        // Far future and nonsense dates neither trap nor produce malformed codes.
        for date in [Date.distantFuture, Date.distantPast, at(1e18), at(.infinity), at(-.infinity), at(.nan)] {
            let code = TOTP.code(secret: seed1, params: params, at: date)
            XCTAssertEqual(code.count, 6, "\(date)")
            XCTAssertTrue(code.allSatisfy(\.isNumber))
            XCTAssertTrue((1...30).contains(TOTP.remaining(params: params, at: date)), "\(date)")
        }
        XCTAssertEqual(TOTP.counter(params: params, at: at(.infinity)), 0, "non-finite: no counter")
        XCTAssertEqual(TOTP.counter(params: params, at: at(1e30)), UInt64.max, "saturates")
    }

    func testDegenerateParamsAreClamped() {
        let date = at(1111111109)
        XCTAssertEqual(
            TOTP.code(secret: seed1, params: TOTPParams(period: 0), at: date),
            TOTP.code(secret: seed1, params: TOTPParams(period: 1), at: date))
        XCTAssertEqual(TOTP.code(secret: seed1, params: TOTPParams(period: -30), at: date).count, 6)
        XCTAssertEqual(TOTP.remaining(params: TOTPParams(period: 0), at: date), 1)
        XCTAssertEqual(TOTP.code(secret: Data(), params: TOTPParams(), at: date).count, 6, "empty key does not crash")
        XCTAssertEqual(TOTP.code(secret: Data(repeating: 7, count: 4096), params: TOTPParams(), at: date).count, 6)
    }

    func testSecretFormatsUsersPaste() throws {
        let hello = Data("Hello!".utf8) + Data([0xDE, 0xAD, 0xBE, 0xEF])
        for text in [
            "JBSWY3DPEHPK3PXP", "jbswy3dpehpk3pxp", "JBSW Y3DP EHPK 3PXP", "jbsw-y3dp-ehpk-3pxp",
            "  JBSWY3DPEHPK3PXP\n", "JBSWY3DP\tEHPK3PXP", "JBSWY3DPEHPK3PXP====",
            "JBSW\u{00A0}Y3DP\u{2003}EHPK3PXP", "JbSwY3dPeHpK3pXp\r\n"
        ] {
            XCTAssertEqual(try TOTP.decodeSecret(text), hello, text.debugDescription)
        }
    }

    func testInvalidSecretsAreRejected() {
        for text in [
            "", " ", "====", "=", "0x", "0X", "0xABC", "0xGG", "JBSWY3DP!EHPK3PXP", "MF=RGG", "A",
            "JBSWY3DPEHPK3PXP\u{200B}", "ünïcödé", "189", "🔑🔑🔑🔑"
        ] {
            assertThrows(.invalidSecret) { _ = try TOTP.decodeSecret(text) }
        }
    }
}

final class OTPComposerEdgeTests: CoreTestCase {
    func compose(_ pw: String, _ otp: String?, _ d: OTPDelivery, _ t: String, _ type: VPNType = .openvpn) -> (String, String?) {
        let r = OTPComposer.compose(password: pw, otp: otp, delivery: d, template: t, type: type)
        return (r.secret, r.separateOTP)
    }

    func scrv1Parts(_ secret: String) -> (String, String)? {
        let parts = secret.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "SCRV1",
            let pw = Data(base64Encoded: String(parts[1])).flatMap({ String(data: $0, encoding: .utf8) }),
            let code = Data(base64Encoded: String(parts[2])).flatMap({ String(data: $0, encoding: .utf8) })
        else { return nil }
        return (pw, code)
    }

    func testEveryPresetWithEveryDeliveryAndType() {
        for preset in OTPTemplatePreset.allCases {
            for type in VPNType.allCases {
                let combined = compose("pw", "123456", .combined, preset.rawValue, type)
                XCTAssertNil(combined.1)
                XCTAssertEqual(
                    combined.0,
                    preset.rawValue.replacingOccurrences(of: "{password}", with: "pw")
                        .replacingOccurrences(of: "{otp}", with: "123456"))
                let separate = compose("pw", "123456", .separate, preset.rawValue, type)
                switch type {
                case .openvpn:
                    XCTAssertNil(separate.1)
                    XCTAssertEqual(scrv1Parts(separate.0)?.0, "pw")
                    XCTAssertEqual(scrv1Parts(separate.0)?.1, "123456")
                case .forti, .anyconnect, .globalprotect:
                    XCTAssertEqual(separate.0, "pw", "the template is not used when separate")
                    XCTAssertEqual(separate.1, "123456")
                }
            }
        }
    }

    func testCustomTemplates() throws {
        let cases: [(String, String)] = [
            ("pin{otp}", "pin123456"),  // no {password}
            ("{otp}{otp}", "123456123456"),  // duplicated
            ("{password}{password}{otp}", "pwpw123456"),
            ("{{otp}}", "{123456}"),  // literal braces around a placeholder
            ("{otp}}", "123456}"),
            ("{ {otp}", "{ 123456"),
            ("a{b{otp}", "a{b123456"),
            ("🔐{password}·{otp}✓", "🔐pw·123456✓")
        ]
        for (template, expected) in cases {
            XCTAssertNoThrow(try OTPComposer.validate(template: template), template)
            XCTAssertEqual(compose("pw", "123456", .combined, template).0, expected, template)
        }
        for bad in ["{password}", "{}{otp}", "{x}{otp}", "{otp", "otp}", "{Otp}", "{password}{otp}{pass}"] {
            XCTAssertThrowsError(try OTPComposer.validate(template: bad), bad)
            // A template that slipped past validation (hand-edited file) falls back to append.
            XCTAssertEqual(compose("pw", "1", .combined, bad).0, "pw1", bad)
        }
    }

    /// The parts shown in the editor's "Server receives" are what `compose` sends, in the same order.
    func testPartsMatchCompose() {
        func joined(_ parts: [OTPComposer.Part]) -> String {
            parts.map { part -> String in
                switch part {
                case .password: return "pw"
                case .code: return "123456"
                case .text(let text): return text
                }
            }.joined()
        }
        let templates =
            OTPTemplatePreset.allCases.map(\.rawValue)
            + ["pin{otp}", "{otp}{otp}", "{{otp}}", "a{b{otp}", "🔐{password}·{otp}✓", "{password}", "{x}{otp}", ""]
        for template in templates {
            let parts = OTPComposer.parts(delivery: .combined, template: template)
            XCTAssertFalse(parts.separateCode, template)
            XCTAssertEqual(joined(parts.secret), compose("pw", "123456", .combined, template).0, template)
        }
        XCTAssertEqual(
            OTPComposer.parts(delivery: .combined, template: "{password}:{otp}").secret,
            [.password, .text(":"), .code])
        XCTAssertEqual(
            OTPComposer.parts(delivery: .combined, template: "{password}").secret, [.password, .code],
            "an invalid template falls back to append")
        for template in templates {
            let parts = OTPComposer.parts(delivery: .separate, template: template)
            XCTAssertEqual(parts.secret, [.password], template)
            XCTAssertTrue(parts.separateCode, template)
        }
    }

    func testHostilePasswordsAndCodes() {
        let long = String(repeating: "ş🔥x", count: 5000)
        XCTAssertEqual(compose(long, "1", .combined, "{password}:{otp}").0, long + ":1")
        XCTAssertEqual(
            compose("{otp}{password}", "9", .combined, "{password}{otp}").0, "{otp}{password}9",
            "values are inserted literally")
        XCTAssertEqual(compose("pw", "{password}", .combined, "{otp}-{password}").0, "{password}-pw")
        XCTAssertEqual(compose("", "123456", .combined, "{password}{otp}").0, "123456", "empty password")
        XCTAssertEqual(compose("pw", "", .combined, "{otp}:{password}").0, "pw", "empty code: plain password")
        XCTAssertEqual(compose("pw", nil, .separate, "", .forti).1, nil)
        XCTAssertEqual(compose("pw", "", .separate, "", .forti).1, nil, "empty code is not sent as a code")
    }

    func testSCRV1EncodesAnything() {
        for pw in ["", ":", "a:b:c", "p@ss w0rd/+=", "şifre🔥", "\u{0}nul", String(repeating: "x", count: 1000)] {
            for code in ["1", "000000", "12345678"] {
                let secret = compose(pw, code, .separate, "{password}{otp}").0
                guard let parts = scrv1Parts(secret) else { XCTFail("\(pw.debugDescription) → \(secret)"); continue }
                XCTAssertEqual(parts.0, pw)
                XCTAssertEqual(parts.1, code)
                XCTAssertFalse(secret.contains("\n"))
            }
        }
    }
}

final class OTPAuthURIEdgeTests: CoreTestCase {
    let secret = "JBSWY3DPEHPK3PXP"

    func uri(_ query: String, label: String = "Acme:alice") -> String { "otpauth://totp/\(label)?\(query)" }

    func testHostileParameters() {
        let bad = [
            uri("issuer=Acme"), uri("secret="), uri("secret"), uri("secret=%ZZ"), uri("secret=!!!!"),
            uri("secret=\(secret)&digits=0"), uri("secret=\(secret)&digits=5"), uri("secret=\(secret)&digits=9"),
            uri("secret=\(secret)&digits=10"), uri("secret=\(secret)&digits=six"), uri("secret=\(secret)&digits="),
            uri("secret=\(secret)&period=0"), uri("secret=\(secret)&period=-30"), uri("secret=\(secret)&period=601"),
            uri("secret=\(secret)&period=99999999999999999999999"), uri("secret=\(secret)&period=30.5"),
            uri("secret=\(secret)&algorithm=MD5"), uri("secret=\(secret)&algorithm="),
            "otpauth:/totp/Acme?secret=\(secret)", "otpauth://steam/Acme?secret=\(secret)",
            "otpauth-migration://offline?data=AAAA", "otpauth://", "", "   "
        ]
        for text in bad {
            XCTAssertThrowsError(try OTPAuthURI(text), text) { XCTAssertNotNil($0 as? PTError, text) }
        }
    }

    func testTolerantParsing() throws {
        let percent = try OTPAuthURI(uri("secret=JBSWY3DPEHPK3PXP%3D%3D%3D%3D&algorithm=sha-512&digits=8&period=600"))
        XCTAssertEqual(percent.secret, try TOTP.decodeSecret(secret))
        XCTAssertEqual(percent.params, TOTPParams(digits: 8, period: 600, algorithm: .sha512))

        let spaced = try OTPAuthURI(uri("secret=jbsw+y3dp%20ehpk+3pxp"))
        XCTAssertEqual(spaced.secret, try TOTP.decodeSecret(secret))

        let first = try OTPAuthURI(uri("secret=\(secret)&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
        XCTAssertEqual(first.secret, try TOTP.decodeSecret(secret), "the first value wins")

        let noLabel = try OTPAuthURI("otpauth://TOTP?secret=\(secret)")
        XCTAssertEqual([noLabel.label, noLabel.account, noLabel.issuer], ["", "", ""])

        let encodedColon = try OTPAuthURI(uri("secret=\(secret)", label: "Acme%3A%20alice%40example.com"))
        XCTAssertEqual(encodedColon.issuer, "Acme")
        XCTAssertEqual(encodedColon.account, "alice@example.com")

        let badEscape = try OTPAuthURI(uri("secret=\(secret)", label: "Acme%ZZ"))
        XCTAssertEqual(badEscape.label, "Acme%ZZ", "an invalid escape is kept as written")

        let huge = try OTPAuthURI(uri("secret=\(secret)&x=" + String(repeating: "a", count: 200_000)))
        XCTAssertEqual(huge.params, TOTPParams())
    }
}
