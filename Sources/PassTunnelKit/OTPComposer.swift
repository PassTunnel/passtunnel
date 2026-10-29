import Foundation

/// Builds what is sent to the VPN from a password and a one-time code.
public enum OTPComposer {
    static let passwordToken = "{password}"
    static let otpToken = "{otp}"

    /// A template must contain "{otp}"; "{password}" is optional; any other `{…}` placeholder is rejected.
    public static func validate(template: String) throws {
        guard !template.isEmpty else { throw PTError.invalidTemplate(String(localized: "it is empty")) }
        var sawOTP = false
        for token in placeholders(in: template) {
            switch token {
            case otpToken: sawOTP = true
            case passwordToken: break
            default: throw PTError.invalidTemplate(String(localized: "unknown placeholder \(token)"))
            }
        }
        guard sawOTP else { throw PTError.invalidTemplate(String(localized: "it must contain {otp}")) }
    }

    /// - `.combined`: `template` with `{password}` / `{otp}` substituted in one pass (literal text kept,
    ///   values are never re-scanned for placeholders). Without a code (`otp` nil or empty) the secret is
    ///   the plain password. An invalid template falls back to `OTPTemplatePreset.append`.
    /// - `.separate` + OpenVPN: `SCRV1:b64(password):b64(otp)`; without a code, the plain password.
    /// - `.separate` + Forti or AnyConnect: secret = password, separateOTP = otp (Forti's `otp` field,
    ///   AnyConnect's second answer line).
    public static func compose(
        password: String, otp: String?, delivery: OTPDelivery, template: String,
        type: VPNType
    ) -> (secret: String, separateOTP: String?) {
        let code = (otp?.isEmpty == false) ? otp : nil
        switch delivery {
        case .combined:
            guard let code else { return (password, nil) }
            let t = (try? validate(template: template)) != nil ? template : OTPTemplatePreset.append.rawValue
            return (render(t, password: password, otp: code), nil)
        case .separate:
            switch type {
            case .forti, .anyconnect:
                return (password, code)
            case .openvpn:
                guard let code else { return (password, nil) }
                return ("SCRV1:\(Data(password.utf8).base64EncodedString()):\(Data(code.utf8).base64EncodedString())", nil)
            }
        }
    }

    /// One part of what the server receives: the password, the code, or text from the template.
    public enum Part: Equatable, Sendable {
        case password, code
        case text(String)
    }

    /// What `compose` sends, as parts in order, so it can be shown without the password (the editor's "Server
    /// receives"). `.combined`: the template's parts (an invalid template falls back to `OTPTemplatePreset.append`,
    /// as in `compose`), `separateCode` false. `.separate`: the password alone, and `separateCode` true: the code
    /// goes in a field of its own (the OpenVPN static challenge, the FortiGate `otp` field, the Cisco AnyConnect
    /// form's next field).
    public static func parts(delivery: OTPDelivery, template: String) -> (secret: [Part], separateCode: Bool) {
        guard delivery == .combined else { return ([.password], true) }
        let t = (try? validate(template: template)) != nil ? template : OTPTemplatePreset.append.rawValue
        var parts: [Part] = []
        var literal = ""
        var rest = Substring(t)
        while !rest.isEmpty {
            let token: Part
            if rest.hasPrefix(passwordToken) {
                token = .password
                rest = rest.dropFirst(passwordToken.count)
            } else if rest.hasPrefix(otpToken) {
                token = .code
                rest = rest.dropFirst(otpToken.count)
            } else {
                literal.append(rest.removeFirst())
                continue
            }
            if !literal.isEmpty { parts.append(.text(literal)) }
            literal = ""
            parts.append(token)
        }
        if !literal.isEmpty { parts.append(.text(literal)) }
        return (parts, false)
    }

    private static func placeholders(in template: String) -> [String] {
        var out: [String] = []
        var i = template.startIndex
        while let open = template[i...].firstIndex(of: "{") {
            guard let close = template[open...].firstIndex(of: "}") else { break }
            let inner = template[template.index(after: open)..<close]
            if let nested = inner.lastIndex(of: "{") {
                i = nested  // "{{otp}" → restart at the inner brace
                continue
            }
            out.append(String(template[open...close]))
            i = template.index(after: close)
        }
        return out
    }

    private static func render(_ template: String, password: String, otp: String) -> String {
        var out = ""
        var rest = Substring(template)
        while !rest.isEmpty {
            if rest.hasPrefix(passwordToken) {
                out += password
                rest = rest.dropFirst(passwordToken.count)
            } else if rest.hasPrefix(otpToken) {
                out += otp
                rest = rest.dropFirst(otpToken.count)
            } else {
                out.append(rest.removeFirst())
            }
        }
        return out
    }
}
