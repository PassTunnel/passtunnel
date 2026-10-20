import Foundation

/// Reads an .ovpn file and guesses how the profile authenticates.
public enum OVPNAnalyzer {
    public typealias Result = (passwordMode: PasswordMode, otpMode: OTPMode, otpDelivery: OTPDelivery, remote: String)

    /// No `auth-user-pass` → certificate only (password none, otp none).
    /// `static-challenge` → otp ask, delivery separate. Otherwise delivery combined.
    /// `remote` is the host of the first `remote` directive ("" if none).
    /// Comments (`#`, `;`) and inline blocks such as `<ca>…</ca>` are ignored (`<connection>` blocks are read).
    public static func analyze(_ text: String) -> Result {
        var hasAuth = false
        var hasChallenge = false
        var remote = ""
        var skippingBlock: String?

        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            let lower = line.lowercased()
            if let block = skippingBlock {
                if lower == "</\(block)>" { skippingBlock = nil }
                continue
            }
            if lower.hasPrefix("<"), lower.hasSuffix(">") {
                let name = String(lower.dropFirst().dropLast())
                if name.hasPrefix("/") || name == "connection" { continue }
                skippingBlock = name
                continue
            }
            let words = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let first = words.first else { continue }
            var directive = first.lowercased()
            if directive.hasPrefix("--") { directive.removeFirst(2) }
            switch directive {
            case "auth-user-pass": hasAuth = true
            case "static-challenge": hasChallenge = true
            case "remote":
                if remote.isEmpty, words.count > 1 { remote = String(words[1]) }
            default: break
            }
        }

        guard hasAuth else { return (.none, .none, .combined, remote) }
        if hasChallenge { return (.keychain, .ask, .separate, remote) }
        return (.keychain, .none, .combined, remote)
    }
}
