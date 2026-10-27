import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

final class TOTPTests: CoreTestCase {
    // RFC 6238 Appendix B
    let seed1 = Data("12345678901234567890".utf8)
    let seed256 = Data("12345678901234567890123456789012".utf8)
    let seed512 = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8)
    let vectors: [(TimeInterval, String, String, String)] = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826")
    ]

    func testRFC6238Vectors() {
        for (t, sha1, sha256, sha512) in vectors {
            let date = Date(timeIntervalSince1970: t)
            XCTAssertEqual(TOTP.code(secret: seed1, params: TOTPParams(digits: 8, algorithm: .sha1), at: date), sha1)
            XCTAssertEqual(TOTP.code(secret: seed256, params: TOTPParams(digits: 8, algorithm: .sha256), at: date), sha256)
            XCTAssertEqual(TOTP.code(secret: seed512, params: TOTPParams(digits: 8, algorithm: .sha512), at: date), sha512)
        }
    }

    func testSixAndSevenDigitsAreSuffixes() {
        let date = Date(timeIntervalSince1970: 1111111109)
        XCTAssertEqual(TOTP.code(secret: seed1, params: TOTPParams(digits: 6), at: date), "081804")
        XCTAssertEqual(TOTP.code(secret: seed1, params: TOTPParams(digits: 7), at: date), "7081804")
    }

    func testDigitsAreClamped() {
        let date = Date(timeIntervalSince1970: 59)
        XCTAssertEqual(TOTP.code(secret: seed1, params: TOTPParams(digits: 3), at: date).count, 6)
        XCTAssertEqual(TOTP.code(secret: seed1, params: TOTPParams(digits: 12), at: date).count, 8)
    }

    func testRemaining() {
        let p = TOTPParams()
        XCTAssertEqual(TOTP.remaining(params: p, at: Date(timeIntervalSince1970: 60)), 30)
        XCTAssertEqual(TOTP.remaining(params: p, at: Date(timeIntervalSince1970: 59)), 1)
        XCTAssertEqual(TOTP.remaining(params: p, at: Date(timeIntervalSince1970: 75.9)), 15)
        XCTAssertEqual(TOTP.remaining(params: TOTPParams(period: 60), at: Date(timeIntervalSince1970: 61)), 59)
    }

    func testDecodeBase32Tolerant() throws {
        let canonical = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        XCTAssertEqual(try TOTP.decodeSecret(canonical), seed1)
        XCTAssertEqual(try TOTP.decodeSecret(canonical.lowercased()), seed1)
        XCTAssertEqual(try TOTP.decodeSecret("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"), seed1)
        XCTAssertEqual(try TOTP.decodeSecret("JBSWY3DPEHPK3PXP"), Data("Hello!".utf8) + Data([0xDE, 0xAD, 0xBE, 0xEF]))
        // padding
        XCTAssertEqual(try TOTP.decodeSecret("MFRGG==="), Data("abc".utf8))
        XCTAssertEqual(try TOTP.decodeSecret("mfrgg"), Data("abc".utf8))
    }

    func testDecodeHex() throws {
        XCTAssertEqual(try TOTP.decodeSecret("3132333435363738393031323334353637383930"), seed1)
        XCTAssertEqual(try TOTP.decodeSecret("0x3132333435363738393031323334353637383930"), seed1)
        XCTAssertEqual(try TOTP.decodeSecret("0xDEADbeef"), Data([0xDE, 0xAD, 0xBE, 0xEF]))
    }

    func testDecodeRejectsGarbage() {
        assertThrows(.invalidSecret) { _ = try TOTP.decodeSecret("") }
        assertThrows(.invalidSecret) { _ = try TOTP.decodeSecret("   ") }
        assertThrows(.invalidSecret) { _ = try TOTP.decodeSecret("not a secret!") }
        assertThrows(.invalidSecret) { _ = try TOTP.decodeSecret("0xZZ") }
        assertThrows(.invalidSecret) { _ = try TOTP.decodeSecret("189") }  // neither base32 nor even-length hex
    }
}

final class OTPAuthURITests: CoreTestCase {
    func testFullURI() throws {
        let u = try OTPAuthURI(
            "otpauth://totp/Acme:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Acme&digits=8&period=60&algorithm=SHA256")
        XCTAssertEqual(u.label, "Acme:alice@example.com")
        XCTAssertEqual(u.account, "alice@example.com")
        XCTAssertEqual(u.issuer, "Acme")
        XCTAssertEqual(u.secret, Data("12345678901234567890".utf8))
        XCTAssertEqual(u.params, TOTPParams(digits: 8, period: 60, algorithm: .sha256))
    }

    func testPercentDecodingAndDefaults() throws {
        let u = try OTPAuthURI("otpauth://totp/Acme%20VPN%3Aalice%C5%9F?secret=jbswy3dpehpk3pxp")
        XCTAssertEqual(u.label, "Acme VPN:aliceş")
        XCTAssertEqual(u.issuer, "Acme VPN")
        XCTAssertEqual(u.account, "aliceş")
        XCTAssertEqual(u.params, TOTPParams())
    }

    func testIssuerParamWinsAndPlusIsSpace() throws {
        let u = try OTPAuthURI("OTPAUTH://TOTP/Old:alice?issuer=Acme+Corp&secret=JBSWY3DPEHPK3PXP&algorithm=sha512")
        XCTAssertEqual(u.issuer, "Acme Corp")
        XCTAssertEqual(u.params.algorithm, .sha512)
    }

    func testLabelWithoutIssuer() throws {
        let u = try OTPAuthURI("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(u.account, "alice")
        XCTAssertEqual(u.issuer, "")
    }

    func testRejections() {
        assertThrows(.hotpNotSupported) { _ = try OTPAuthURI("otpauth://hotp/Acme:alice?secret=JBSWY3DPEHPK3PXP&counter=1") }
        XCTAssertThrowsError(try OTPAuthURI("https://vpn.example.com")) { XCTAssertNotNil($0 as? PTError) }
        XCTAssertThrowsError(try OTPAuthURI("otpauth://totp/Acme:alice?issuer=Acme"))
        XCTAssertThrowsError(try OTPAuthURI("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=10"))
        XCTAssertThrowsError(try OTPAuthURI("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"))
        XCTAssertThrowsError(try OTPAuthURI("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&period=0"))
        XCTAssertThrowsError(try OTPAuthURI("otpauth://totp/Acme:alice?secret=!!!")) {
            XCTAssertEqual($0 as? PTError, .invalidSecret)
        }
    }

    func testHOTPErrorIsReadable() {
        XCTAssertTrue(PTError.hotpNotSupported.localizedDescription.contains("HOTP"))
    }
}

final class OTPComposerTests: CoreTestCase {
    func compose(
        _ pw: String, _ otp: String?, _ d: OTPDelivery, _ t: String = "{password}{otp}",
        _ type: VPNType = .openvpn
    ) -> (String, String?) {
        let r = OTPComposer.compose(password: pw, otp: otp, delivery: d, template: t, type: type)
        return (r.secret, r.separateOTP)
    }

    func testPresets() throws {
        let expected: [OTPTemplatePreset: String] = [
            .append: "s3cret123456", .prepend: "123456s3cret", .colon: "s3cret:123456", .comma: "s3cret,123456"
        ]
        for preset in OTPTemplatePreset.allCases {
            try OTPComposer.validate(template: preset.rawValue)
            for type in VPNType.allCases {
                let r = compose("s3cret", "123456", .combined, preset.rawValue, type)
                XCTAssertEqual(r.0, expected[preset])
                XCTAssertNil(r.1)
            }
        }
    }

    func testCustomLiteralText() throws {
        try OTPComposer.validate(template: "{password}-{otp}!")
        XCTAssertEqual(compose("pw", "000111", .combined, "{password}-{otp}!").0, "pw-000111!")
        try OTPComposer.validate(template: "pin{otp}")
        XCTAssertEqual(compose("pw", "42", .combined, "pin{otp}").0, "pin42")
        XCTAssertEqual(compose("pw", "42", .combined, "{otp}{otp}").0, "4242")
        XCTAssertEqual(compose("pw", "42", .combined, "{ {password}} {otp}").0, "{ pw} 42")
    }

    func testValuesAreNotRescanned() {
        XCTAssertEqual(compose("a{otp}b", "99", .combined).0, "a{otp}b99")
    }

    func testTurkishPassword() {
        XCTAssertEqual(compose("Şifre-ğüıöçİ", "123456", .combined, "{password}:{otp}").0, "Şifre-ğüıöçİ:123456")
        let scrv = compose("Şifre-ğüıöçİ", "123456", .separate).0
        let parts = scrv.split(separator: ":")
        XCTAssertEqual(parts.count, 3)
        XCTAssertEqual(String(data: Data(base64Encoded: String(parts[1]))!, encoding: .utf8), "Şifre-ğüıöçİ")
    }

    func testSCRV1Exact() {
        // base64("pass") = cGFzcw==, base64("123456") = MTIzNDU2
        let r = compose("pass", "123456", .separate)
        XCTAssertEqual(r.0, "SCRV1:cGFzcw==:MTIzNDU2")
        XCTAssertNil(r.1)
        XCTAssertEqual(compose("", "1", .separate).0, "SCRV1::MQ==")
    }

    func testSeparateWithoutCode() {
        XCTAssertEqual(compose("pass", nil, .separate).0, "pass")
        XCTAssertEqual(compose("pass", "", .separate).0, "pass")
        let forti = compose("pass", nil, .separate, "{password}{otp}", .forti)
        XCTAssertEqual(forti.0, "pass")
        XCTAssertNil(forti.1)
    }

    func testFortiSeparate() {
        let r = compose("pass", "654321", .separate, "{password}:{otp}", .forti)
        XCTAssertEqual(r.0, "pass")
        XCTAssertEqual(r.1, "654321")
    }

    func testCombinedWithoutCodeIsPlainPassword() {
        XCTAssertEqual(compose("pass", nil, .combined, "{password}:{otp}").0, "pass")
        XCTAssertEqual(compose("pass", "", .combined, "x{otp}y{password}").0, "pass")
    }

    func testInvalidTemplateFallsBackToAppend() {
        XCTAssertEqual(compose("pw", "12", .combined, "{password}").0, "pw12")
        XCTAssertEqual(compose("pw", "12", .combined, "").0, "pw12")
    }

    func testValidateRejects() {
        for bad in ["", "{password}", "plain", "{password}{code}", "{otp}{user}", "{OTP}", "{ otp }"] {
            XCTAssertThrowsError(try OTPComposer.validate(template: bad), bad) { error in
                guard case .invalidTemplate = error as? PTError else { return XCTFail("\(bad): \(error)") }
            }
        }
        XCTAssertNoThrow(try OTPComposer.validate(template: "{otp}"))
        XCTAssertNoThrow(try OTPComposer.validate(template: "x{otp}{password}y"))
    }
}
