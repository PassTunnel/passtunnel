import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// "What the server receives" in the redesigned window: the rows follow the profile's real format with eight bullets
/// for the password, the code is the one the code card shows (the next one while a connect waits for it), and the
/// card adapts to codes that are hidden, asked or missing, to no code, FortiGate and certificate-only profiles.
final class ServerReceivesTests: XCTestCase {
    private typealias Row = ServerReceives.Row
    private let shown = ServerReceives.Codes.shown(current: "482913", next: "771204")

    private func profile(_ type: VPNType = .openvpn, _ edit: (inout Profile) -> Void = { _ in }) -> Profile {
        var p = Profile(id: "work", name: "Work", type: type)
        p.username = "alice"
        p.otpMode = .totp
        p.otpDelivery = .combined
        edit(&p)
        return p
    }

    private func receives(_ p: Profile, _ codes: ServerReceives.Codes? = nil, waiting: Bool = false) -> ServerReceives {
        ServerReceives(p, codes: codes ?? shown, waitingForCode: waiting)
    }

    private func password(_ segments: ServerReceives.Segment...) -> Row { Row(field: .password, segments: segments) }
    private let alice = Row(field: .username, segments: [.text("alice")])

    // MARK: rows

    func testAppendWithTheCurrentCode() {
        let r = receives(profile())
        XCTAssertEqual(r.rows, [alice, password(.password, .code("482913"))])
        XCTAssertEqual(r.footer, "Format: Append · preview with the current code")
        XCTAssertEqual(r.rows.map(\.field.label), ["user name", "password"])
    }

    func testWaitingForAFreshCodeShowsTheNextCode() {
        let r = receives(profile(), waiting: true)
        XCTAssertEqual(r.rows, [alice, password(.password, .code("771204"))])
        XCTAssertEqual(r.footer, "Format: Append · will send the next code")
    }

    func testHiddenOrLockedCodesAreBullets() {
        let r = receives(profile(), .masked)
        XCTAssertEqual(r.rows, [alice, password(.password, .hiddenCode(digits: 6))])
        XCTAssertEqual(r.rows[1].segments.map(\.text).joined(), "••••••••••••••", "all bullets")
        XCTAssertEqual(r.footer, "Format: Append · preview with the current code")
        XCTAssertEqual(receives(profile(), .masked, waiting: true).footer, "Format: Append · will send the next code")
        XCTAssertEqual(receives(profile { $0.totp.digits = 8 }, .masked).rows[1].segments.last,
                       .hiddenCode(digits: 8))
    }

    func testEveryCodeFormat() {
        let cases: [(String, [ServerReceives.Segment], String)] = [
            (OTPTemplatePreset.prepend.rawValue, [.code("482913"), .password], "Prepend"),
            (OTPTemplatePreset.colon.rawValue, [.password, .text(":"), .code("482913")], "password:code"),
            (OTPTemplatePreset.comma.rawValue, [.password, .text(","), .code("482913")], "password,code"),
            ("{otp}-{password}", [.code("482913"), .text("-"), .password], "Custom template"),
            ("pin{otp}", [.text("pin"), .code("482913")], "Custom template"),
            // An invalid template is sent as Append, as OTPComposer.compose does.
            ("{password}", [.password, .code("482913")], "Custom template"),
        ]
        for (template, segments, name) in cases {
            let r = receives(profile { $0.otpTemplate = template })
            XCTAssertEqual(r.rows, [alice, Row(field: .password, segments: segments)], template)
            XCTAssertEqual(r.footer, "Format: \(name) · preview with the current code", template)
        }
    }

    func testSentSeparately() {
        for type in VPNType.allCases {
            let r = receives(profile(type) { $0.otpDelivery = .separate })
            XCTAssertEqual(r.rows, [alice, password(.password), Row(field: .code, segments: [.code("482913")])], "\(type)")
            XCTAssertEqual(r.footer, "Format: Sent separately · preview with the current code")
            XCTAssertEqual(r.rows.map(\.field.label), ["user name", "password", "code"])
        }
        XCTAssertEqual(receives(profile(.forti) { $0.otpDelivery = .separate }, waiting: true).rows.last,
                       Row(field: .code, segments: [.code("771204")]))
    }

    func testFortiGateCombined() {
        let r = receives(profile(.forti))
        XCTAssertEqual(r.rows, [alice, password(.password, .code("482913"))])
    }

    // MARK: without a code to show

    func testNoOneTimeCode() {
        let r = receives(profile { $0.otpMode = .none })
        XCTAssertEqual(r.rows, [alice, password(.password)])
        XCTAssertEqual(r.footer, "Password only, no one-time code")
    }

    func testACodeAskedWhenConnecting() {
        // Asked: example digits, whatever a stored secret would give.
        let r = receives(profile { $0.otpMode = .ask })
        XCTAssertEqual(r.rows, [alice, password(.password, .exampleCode(digits: 6))])
        XCTAssertEqual(r.rows[1].segments.last?.text, "123456")
        XCTAssertEqual(r.footer, "Format: Append · asks for the code when connecting")
        XCTAssertEqual(receives(profile { $0.otpMode = .ask }, waiting: true).footer,
                       "Format: Append · asks for the code when connecting")
    }

    func testNoSecretYet() {
        let r = receives(profile { $0.otpDelivery = .separate }, .noSecret)
        XCTAssertEqual(r.rows.last, Row(field: .code, segments: [.exampleCode(digits: 6)]))
        XCTAssertEqual(r.footer, "Format: Sent separately · no secret added yet")
        XCTAssertEqual(ServerReceives.Segment.exampleCode(digits: 8).text, "12345678")
    }

    func testAUserNameAskedWhenConnecting() {
        for name in ["", "  "] {
            let r = receives(profile { $0.username = name; $0.lastUsername = "bob" })
            XCTAssertEqual(r.rows.first, Row(field: .username, segments: [.askedUsername]))
            XCTAssertEqual(r.rows.first?.segments.first?.text, "asked when connecting")
        }
        XCTAssertEqual(receives(profile { $0.username = " alice\n" }).rows.first, alice, "sent trimmed")
    }

    func testCertificateOnly() {
        for otp in OTPMode.allCases {
            let r = receives(profile { $0.passwordMode = .none; $0.otpMode = otp })
            XCTAssertEqual(r.rows, [], "OpenVPN sends no user name, password or code (\(otp))")
            XCTAssertEqual(r.footer, "Certificate only: the configuration contains everything needed to sign in.")
        }
    }

    func testAFortiGateProfileWithoutAPassword() {
        let none: (inout Profile) -> Void = { $0.passwordMode = .none }
        XCTAssertEqual(receives(profile(.forti, none)).rows, [alice, password(.code("482913"))])
        XCTAssertEqual(receives(profile(.forti) { none(&$0); $0.otpDelivery = .separate }).rows,
                       [alice, Row(field: .code, segments: [.code("482913")])])
        XCTAssertEqual(receives(profile(.forti) { none(&$0); $0.otpMode = .none }).rows, [alice])
    }

    // MARK: the password

    func testThePasswordIsAlwaysEightBullets() {
        XCTAssertEqual(ServerReceives.Segment.password.text, "••••••••")
        for mode in [PasswordMode.keychain, .ask] {
            let r = receives(profile { $0.passwordMode = mode })
            XCTAssertEqual(r.rows[1].segments.first, .password)
        }
    }

    func testWhatIsDimmed() {
        let dimmed: [ServerReceives.Segment] = [.password, .askedUsername, .hiddenCode(digits: 6), .exampleCode(digits: 6)]
        XCTAssertTrue(dimmed.allSatisfy(\.isDimmed))
        XCTAssertFalse(ServerReceives.Segment.code("482913").isDimmed)
        XCTAssertFalse(ServerReceives.Segment.text("alice").isDimmed)
    }
}
