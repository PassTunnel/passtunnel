import Foundation
import PassTunnelKit

/// "What the server receives", the second card of the detail in the redesigned window: what the sign-in sends, built
/// from the profile's real code format (`OTPComposer.parts`) with a placeholder password, never the real one, and
/// the code the code card shows. Kept apart from SwiftUI so it is tested; the app draws the rows.
public struct ServerReceives: Equatable, Sendable {
    /// What the code card can show of the profile's TOTP code.
    public enum Codes: Equatable, Sendable {
        /// No TOTP secret is saved yet.
        case noSecret
        /// Hidden or locked, as in the code card.
        case masked
        /// The code of the current window and of the next one.
        case shown(current: String, next: String)
    }

    /// One row: what the server gets in one field.
    public struct Row: Equatable, Sendable {
        public var field: Field
        public var segments: [Segment]
    }

    public enum Field: Sendable {
        case username, password, code

        /// The row's label.
        public var label: String {
            switch self {
            case .username: return String(localized: "user name")
            case .password: return String(localized: "password")
            case .code: return String(localized: "code")
            }
        }
    }

    public enum Segment: Equatable, Sendable {
        /// Sent as it is: the user name, or text from the code format.
        case text(String)
        /// The user name is asked when connecting.
        case askedUsername
        /// The password: always eight bullets, never its real length.
        case password
        /// The digits that are sent, or will be.
        case code(String)
        /// The code, hidden or locked: one bullet per digit.
        case hiddenCode(digits: Int)
        /// No code to show (asked when connecting, or no secret yet): example digits.
        case exampleCode(digits: Int)

        public static let maskedPassword = String(repeating: "•", count: 8)

        /// The segment as the row shows it.
        public var text: String {
            switch self {
            case .text(let text): return text
            case .askedUsername: return String(localized: "asked when connecting")
            case .password: return Self.maskedPassword
            case .code(let digits): return digits
            case .hiddenCode(let digits): return String(repeating: "•", count: digits)
            case .exampleCode(let digits): return String("12345678".prefix(digits))
            }
        }

        /// Drawn dimmed: everything that is not what the server gets as written.
        public var isDimmed: Bool {
            switch self {
            case .text, .code: return false
            case .askedUsername, .password, .hiddenCode, .exampleCode: return true
            }
        }
    }

    /// The rows in the order the sign-in sends them; none for a certificate-only profile.
    public var rows: [Row]
    /// "Format: Append · preview with the current code", or what the profile sends instead.
    public var footer: String

    /// - Parameters:
    ///   - codes: what the code card shows of the TOTP code (read only when the profile generates its code).
    ///   - waitingForCode: a connect waits for a fresh code (`ConnectionManager.codeWaitUntil`): the next code is
    ///     the one it sends.
    ///   - sentAt: when the sign-in was sent, for a profile that is connected (`ConnectionManager.lastSending`):
    ///     the footer then says so instead of "preview with the current code".
    public init(_ p: Profile, codes: Codes, waitingForCode: Bool, sentAt: Date? = nil, timeZone: TimeZone = .current) {
        // Without a password, OpenVPN signs in with the certificate alone: no user name, password or code.
        if p.type == .openvpn && p.passwordMode == .none {
            rows = []
            footer = String(localized: "Certificate only: the configuration contains everything needed to sign in.")
            return
        }
        let username = p.username.trimmingCharacters(in: .whitespacesAndNewlines)
        rows = [Row(field: .username, segments: [username.isEmpty ? .askedUsername : .text(username)])]

        let digits = min(8, max(6, p.totp.digits))
        let format = Self.formatName(p)
        let code: Segment?
        switch (p.otpMode, codes) {
        case (.none, _):
            code = nil
            footer = String(localized: "Password only, no one-time code")
        case (.ask, _):
            code = .exampleCode(digits: digits)
            footer = String(localized: "Format: \(format) · asks for the code when connecting")
        case (.totp, .noSecret):
            code = .exampleCode(digits: digits)
            footer = String(localized: "Format: \(format) · no secret added yet")
        case (.totp, .masked), (.totp, .shown):
            if case .shown(let current, let next) = codes {
                code = .code(waitingForCode ? next : current)
            } else {
                code = .hiddenCode(digits: digits)
            }
            if waitingForCode {
                footer = String(localized: "Format: \(format) · will send the next code")
            } else if let sentAt {
                let time = ActivityEvent.clockTime(sentAt, timeZone: timeZone)
                footer = String(localized: "Format: \(format) · sent at \(time)")
            } else {
                footer = String(localized: "Format: \(format) · preview with the current code")
            }
        }

        // An empty password (no password on a FortiGate profile) adds nothing.
        let password: [Segment] = p.passwordMode == .none ? [] : [.password]
        guard let code else {
            if !password.isEmpty { rows.append(Row(field: .password, segments: password)) }
            return
        }
        let parts = OTPComposer.parts(delivery: p.otpDelivery, template: p.otpTemplate)
        if parts.separateCode {
            if !password.isEmpty { rows.append(Row(field: .password, segments: password)) }
            rows.append(Row(field: .code, segments: [code]))
            return
        }
        let segments = parts.secret.flatMap { part -> [Segment] in
            switch part {
            case .password: return password
            case .code: return [code]
            case .text(let text): return [.text(text)]
            }
        }
        rows.append(Row(field: .password, segments: segments))
    }

    /// The code format as the editor names it: Append, Prepend, password:code, password,code, Custom template or
    /// Sent separately.
    public static func formatName(_ p: Profile) -> String {
        if p.otpDelivery == .separate { return String(localized: "Sent separately") }
        switch OTPTemplatePreset(rawValue: p.otpTemplate) {
        case .append: return String(localized: "Append")
        case .prepend: return String(localized: "Prepend")
        case .colon: return "password:code"   // as the editor shows them, untranslated
        case .comma: return "password,code"
        case nil: return String(localized: "Custom template")
        }
    }
}
