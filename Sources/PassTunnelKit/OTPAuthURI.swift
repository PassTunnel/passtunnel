import Foundation

/// A parsed `otpauth://totp/Issuer:account?secret=…&issuer=…&digits=…&period=…&algorithm=…` link.
public struct OTPAuthURI: Equatable {
    public var label: String  // full decoded label, e.g. "Acme:alice"
    public var account: String  // label without the issuer prefix, e.g. "alice"
    public var issuer: String  // `issuer` parameter, else the label prefix
    public var secret: Data
    public var params: TOTPParams

    public init(_ uri: String) throws {
        let text = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let schemeEnd = text.range(of: "://"),
            text[..<schemeEnd.lowerBound].lowercased() == "otpauth"
        else {
            throw PTError.invalidOTPAuthURI(String(localized: "it does not start with otpauth://"))
        }
        let rest = text[schemeEnd.upperBound...]
        let (pathPart, queryPart): (Substring, Substring) = {
            if let q = rest.firstIndex(of: "?") { return (rest[..<q], rest[rest.index(after: q)...]) }
            return (rest, "")
        }()
        let typeEnd = pathPart.firstIndex(of: "/") ?? pathPart.endIndex
        let kind = pathPart[..<typeEnd].lowercased()
        if kind == "hotp" { throw PTError.hotpNotSupported }
        guard kind == "totp" else {
            throw PTError.invalidOTPAuthURI(String(localized: "unknown code type “\(kind)”"))
        }
        let rawLabel = typeEnd < pathPart.endIndex ? String(pathPart[pathPart.index(after: typeEnd)...]) : ""
        label = Self.decode(rawLabel, plusIsSpace: false)

        var query: [String: String] = [:]
        for pair in queryPart.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let key = Self.decode(String(kv[0]), plusIsSpace: true).lowercased()
            let value = kv.count > 1 ? Self.decode(String(kv[1]), plusIsSpace: true) : ""
            if query[key] == nil { query[key] = value }
        }

        if let colon = label.firstIndex(of: ":") {
            let prefix = label[..<colon].trimmingCharacters(in: .whitespaces)
            account = label[label.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            issuer = query["issuer"].flatMap { $0.isEmpty ? nil : $0 } ?? prefix
        } else {
            account = label.trimmingCharacters(in: .whitespaces)
            issuer = query["issuer"] ?? ""
        }

        guard let secretText = query["secret"], !secretText.isEmpty else {
            throw PTError.invalidOTPAuthURI(String(localized: "the secret is missing"))
        }
        secret = try TOTP.decodeSecret(secretText)

        var p = TOTPParams()
        if let d = query["digits"] {
            guard let v = Int(d), (6...8).contains(v) else {
                throw PTError.invalidOTPAuthURI(String(localized: "digits must be 6, 7 or 8"))
            }
            p.digits = v
        }
        if let s = query["period"] {
            guard let v = Int(s), (1...600).contains(v) else {
                throw PTError.invalidOTPAuthURI(String(localized: "the period is not valid"))
            }
            p.period = v
        }
        if let a = query["algorithm"] {
            guard let alg = TOTPAlgorithm(rawValue: a.lowercased().replacingOccurrences(of: "-", with: "")) else {
                throw PTError.invalidOTPAuthURI(String(localized: "unsupported algorithm “\(a)”"))
            }
            p.algorithm = alg
        }
        params = p
    }

    private static func decode(_ s: String, plusIsSpace: Bool) -> String {
        let t = plusIsSpace ? s.replacingOccurrences(of: "+", with: " ") : s
        return t.removingPercentEncoding ?? t
    }
}
