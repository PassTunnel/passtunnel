import Foundation

/// The Cisco AnyConnect session cookie, from what the sign-in prints to what the tunnel run's `cookie` option
/// must hold.
///
/// **What `openconnect --authenticate` prints** as `COOKIE` (main.c 2405, `vpninfo->cookie`), for the AnyConnect
/// protocol, is built in one place (`cstp_obtain_cookie`, auth.c 1666–1709 in 9.21; the same code in 9.01 and
/// 9.12), in exactly one of two shapes:
/// - **STRAP**, only when openconnect holds a STRAP key, which it makes only without `no-external-auth`:
///   `openconnect_strapkey=<base64 of the key's DER>; webvpn=<value>`;
/// - **otherwise the bare value** of the `webvpn` cookie: the server's `Set-Cookie: webvpn=…` or its
///   `<session-token>`, without a name. This is what PassTunnel gets wherever it renders `no-external-auth`
///   (always on the Mac; on Linux from openconnect 9.10).
///
/// **What the tunnel run does with its `cookie` option** (`cstp_connect`, cstp.c 696, then
/// `internal_split_cookies(…, "webvpn")`, http.c 119): it splits the text at each `;` (skipping blanks after
/// it) and each part at its first `=` into a name and a value; only a part *without* `=` is taken as the value
/// of `webvpn`. A bare value that holds `=` (ocserv's base64 tokens end in `=`) would become a cookie named
/// after the token, with no `webvpn` cookie at all, and the server refuses the CONNECT. So the tunnel run
/// always gets the value under its name: `webvpn=<value>` for a bare value (whatever it holds: a bare value
/// that happens to start with `webvpn=` is still a value), and the STRAP form unchanged (it names both parts).
///
/// **Accepted** (`tunnelOption`, `isValidTunnelOption`), and nothing else: a `webvpn` value of RFC 6265
/// cookie octets without `'` (printable ASCII but blanks, `"` `,` `;` `\`; so no `;` or blank that would split
/// it differently); a STRAP key of standard base64; the tunnel option at most `OpenConnectConfig.maxCookieBytes`.
/// Every part is a bearer secret: `secrets` lists them for the log maskers, and no error names a value.
public enum OpenConnectCookie {
    public static let name = "webvpn"
    public static let strapName = "openconnect_strapkey"
    static let strapSeparator = "; " + name + "="

    /// The tunnel run's `cookie` option for what the sign-in printed, nil when it is neither shape.
    public static func tunnelOption(printed: String) -> String? {
        guard let parts = parts(ofPrinted: printed) else { return nil }
        let option = parts.key == nil ? name + "=" + printed : printed
        return option.utf8.count <= OpenConnectConfig.maxCookieBytes ? option : nil
    }

    /// Whether `option` is one `tunnelOption` gives: `webvpn=<value>` or the STRAP form, within the limit.
    public static func isValidTunnelOption(_ option: String) -> Bool {
        guard option.utf8.count <= OpenConnectConfig.maxCookieBytes else { return false }
        if option.hasPrefix(strapName + "=") { return strapParts(option) != nil }
        guard option.hasPrefix(name + "=") else { return false }
        return isValidValue(option.dropFirst(name.count + 1))
    }

    /// The secrets in a printed cookie or a tunnel option, for the maskers: the whole text, the `webvpn` value
    /// and the STRAP key (each also printable on its own).
    public static func secrets(_ text: String) -> [String] {
        var out = [text]
        if let strap = strapParts(text) {
            out += [String(strap.key), String(strap.value)]
        } else if text.hasPrefix(name + "="), isValidValue(text.dropFirst(name.count + 1)) {
            out.append(String(text.dropFirst(name.count + 1)))
        }
        return out
    }

    /// The STRAP key (nil for a bare value) and the `webvpn` value of what the sign-in printed.
    static func parts(ofPrinted printed: String) -> (key: Substring?, value: Substring)? {
        if printed.hasPrefix(strapName + "=") {
            return strapParts(printed).map { (key: $0.key, value: $0.value) }
        }
        return isValidValue(Substring(printed)) ? (key: nil, value: Substring(printed)) : nil
    }

    /// `openconnect_strapkey=<base64>; webvpn=<value>`, split.
    static func strapParts(_ text: String) -> (key: Substring, value: Substring)? {
        guard text.hasPrefix(strapName + "="), let separator = text.range(of: strapSeparator) else { return nil }
        let key = text[text.index(text.startIndex, offsetBy: strapName.count + 1)..<separator.lowerBound]
        let value = text[separator.upperBound...]
        guard isValidBase64(key), isValidValue(value) else { return nil }
        return (key, value)
    }

    /// RFC 6265's cookie-octet (`%x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E`) without `'`, 1 byte or more.
    static func isValidValue(_ s: Substring) -> Bool {
        !s.isEmpty
            && s.utf8.allSatisfy { b in
                (0x21...0x7E).contains(b) && !"\"',;\\".utf8.contains(b)
            }
    }

    /// Standard base64 with its padding: groups of four of `A–Z a–z 0–9 + /`, `=` only at the end.
    static func isValidBase64(_ s: Substring) -> Bool {
        let bytes = Array(s.utf8)
        guard !bytes.isEmpty, bytes.count % 4 == 0 else { return false }
        let padding = bytes.reversed().prefix { $0 == UInt8(ascii: "=") }.count
        guard padding <= 2 else { return false }
        return bytes.dropLast(padding).allSatisfy { FortiConfig.isASCIIAlphanumeric($0) || $0 == UInt8(ascii: "+") || $0 == UInt8(ascii: "/") }
    }
}
