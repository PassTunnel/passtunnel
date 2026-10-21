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

        for words in directives(text) {
            switch words[0] {
            case "auth-user-pass": hasAuth = true
            case "static-challenge": hasChallenge = true
            case "remote":
                if remote.isEmpty, words.count > 1 { remote = words[1] }
            default: break
            }
        }

        guard hasAuth else { return (.none, .none, .combined, remote) }
        if hasChallenge { return (.keychain, .ask, .separate, remote) }
        return (.keychain, .none, .combined, remote)
    }

    /// Whether the profile sends all traffic through the tunnel: true with a local `redirect-gateway`,
    /// false when pushed routes are refused (`route-nopull`, `pull-filter ignore "redirect-gateway…"`),
    /// nil when it depends on what the server pushes.
    public static func redirectsGateway(_ text: String) -> Bool? {
        var refusesPush = false
        for words in directives(text) {
            switch words[0] {
            case "redirect-gateway": return true
            case "route-nopull": refusesPush = true
            case "pull-filter":
                if words.count > 2, words[1].lowercased() == "ignore",
                   "redirect-gateway".hasPrefix(words[2].trimmingCharacters(in: CharacterSet(charactersIn: "\"'")).lowercased()) {
                    refusesPush = true
                }
            default: break
            }
        }
        return refusesPush ? false : nil
    }

    /// Directive lines as words, directive lowercased and without a leading `--`. Comments (`#`, `;`)
    /// and inline blocks such as `<ca>…</ca>` are skipped (`<connection>` blocks are read).
    static func directives(_ text: String) -> [[String]] {
        var out: [[String]] = []
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
            var words = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard !words.isEmpty else { continue }
            words[0] = words[0].lowercased()
            if words[0].hasPrefix("--") { words[0].removeFirst(2) }
            out.append(words)
        }
        return out
    }
}
