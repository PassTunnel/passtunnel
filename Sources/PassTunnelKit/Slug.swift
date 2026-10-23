import Foundation

/// Turns a display name into a profile identifier: Turkish letters folded, ASCII, lowercase,
/// runs of anything else collapsed to "-". "Şirket VPN İç" → "sirket-vpn-ic".
public enum Slug {
    /// Longest id handed out to new profiles. The OpenVPN management socket lives at
    /// `/var/run/passtunnel/<uid>/<id>/mgmt.sock`, which must fit in `sun_path` (103 bytes).
    public static let maxIDLength = 24

    static let turkish: [Character: String] = [
        "ı": "i", "İ": "I", "ş": "s", "Ş": "S", "ğ": "g", "Ğ": "G",
        "ü": "u", "Ü": "U", "ö": "o", "Ö": "O", "ç": "c", "Ç": "C",
    ]

    public static func make(_ name: String, maxLength: Int = maxIDLength) -> String {
        // Fold Turkish letters before any case mapping ("İ".lowercased() would keep a combining dot).
        var s = String(name.flatMap { turkish[$0] ?? String($0) })
        s = s.applyingTransform(StringTransform("Any-Latin; Latin-ASCII"), reverse: false) ?? s
        s = s.folding(options: [.diacriticInsensitive, .widthInsensitive], locale: Locale(identifier: "en_US_POSIX"))
        s = s.lowercased()

        var out = ""
        var pendingDash = false
        for scalar in s.unicodeScalars {
            let isAlnum = (scalar >= "a" && scalar <= "z") || (scalar >= "0" && scalar <= "9")
            if isAlnum {
                if pendingDash && !out.isEmpty { out.append("-") }
                pendingDash = false
                out.unicodeScalars.append(scalar)
            } else {
                pendingDash = true
            }
        }
        if out.count > maxLength {
            out = String(out.prefix(maxLength))
            while out.hasSuffix("-") { out.removeLast() }
        }
        return out
    }

    /// `base` with "-n" appended, shortened so the result stays within `maxLength`.
    public static func suffixed(_ base: String, _ n: Int, maxLength: Int = maxIDLength) -> String {
        let suffix = "-\(n)"
        var head = String(base.prefix(max(1, maxLength - suffix.count)))
        while head.hasSuffix("-") { head.removeLast() }
        return head + suffix
    }

    /// True for strings `make` can produce (up to 64 characters, so ids of older profiles still load): lowercase ASCII letters/digits separated by single dashes.
    public static func isValid(_ id: String) -> Bool {
        guard !id.isEmpty, id.count <= 64, !id.hasPrefix("-"), !id.hasSuffix("-"), !id.contains("--") else { return false }
        return id.unicodeScalars.allSatisfy { ($0 >= "a" && $0 <= "z") || ($0 >= "0" && $0 <= "9") || $0 == "-" }
    }
}
