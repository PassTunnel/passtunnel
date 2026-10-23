import Foundation
import PassTunnelVPNConfig

/// Reads an .ovpn file and guesses how the profile authenticates.
public enum OVPNAnalyzer {
    public typealias Result = (passwordMode: PasswordMode, otpMode: OTPMode, otpDelivery: OTPDelivery, remote: String,
                               remotes: [String])

    /// No `auth-user-pass` → certificate only (password none, otp none).
    /// `static-challenge` → otp ask, delivery separate. Otherwise delivery combined.
    /// `remotes` are the hosts of every `remote` directive in file order (`<connection>` blocks included),
    /// `remote` the first of them ("" if none). Lines are read as OpenVPN reads them (`directives`).
    public static func analyze(_ text: String) -> Result {
        var hasAuth = false
        var hasChallenge = false
        var remotes: [String] = []

        for words in directives(text) {
            switch words[0] {
            case "auth-user-pass": hasAuth = true
            case "static-challenge": hasChallenge = true
            case "remote":
                if words.count > 1 { remotes.append(words[1]) }
            default: break
            }
        }

        let remote = remotes.first ?? ""
        guard hasAuth else { return (.none, .none, .combined, remote, remotes) }
        if hasChallenge { return (.keychain, .ask, .separate, remote, remotes) }
        return (.keychain, .none, .combined, remote, remotes)
    }

    /// The server to show for a config: the first `remote` host, followed by "+N more" when OpenVPN
    /// may connect to others (it tries them in order, or shuffled with `remote-random`); "" if none.
    public static func serverDescription(_ remotes: [String]) -> String {
        guard let first = remotes.first else { return "" }
        let others = remotes.count - 1
        if others == 0 { return first }
        return String(localized: "\(first) +\(others) more")
    }

    /// `serverDescription` of the config's `remote` hosts.
    public static func serverDescription(_ text: String) -> String {
        serverDescription(analyze(text).remotes)
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
                   "redirect-gateway".hasPrefix(words[2].lowercased()) {
                    refusesPush = true
                }
            default: break
            }
        }
        return refusesPush ? false : nil
    }

    /// Directive lines as tokens, read with `OVPNSanitizer`'s tokenizer so the two (and OpenVPN) never
    /// read a line differently: quotes and backslash escapes resolved, comments (`#`, `;`) dropped,
    /// lines OpenVPN rejects skipped. The directive is lowercased without leading dashes, as the
    /// sanitizer checks it. The contents of inline blocks such as `<ca>…</ca>` are skipped;
    /// `<connection>` blocks are read. `setenv opt <directive …>` yields the directive, which OpenVPN
    /// applies only when its name is exact (no dashes, lowercase) and otherwise ignores.
    static func directives(_ text: String) -> [[String]] {
        var out: [[String]] = []
        var blocks: [(tag: String, verbatim: Bool)] = []
        for (index, rawLine) in text.components(separatedBy: "\n").enumerated() {
            var line = rawLine
            if index == 0, line.hasPrefix("\u{FEFF}") { line.removeFirst() }   // UTF-8 BOM
            if let top = blocks.last {
                if OVPNSanitizer.isInlineBlockEnd(line, tag: top.tag) { blocks.removeLast(); continue }
                if top.verbatim { continue }
            }
            guard var words = OVPNSanitizer.tokens(of: line), !words.isEmpty else { continue }
            if words.count == 1, let tag = OVPNSanitizer.inlineBlockTag(words[0]) {
                blocks.append((tag: tag, verbatim: normalize(tag) != "connection"))
                continue
            }
            if words.count > 2, normalize(words[0]) == "setenv", words[1].lowercased() == "opt" {
                words.removeFirst(2)
                guard words[0] == normalize(words[0]) else { continue }
            }
            words[0] = normalize(words[0])
            out.append(words)
        }
        return out
    }

    /// `OVPNSanitizer`'s directive name: lowercased, all leading dashes removed.
    static func normalize(_ token: String) -> String {
        String(token.drop(while: { $0 == "-" })).lowercased()
    }
}
