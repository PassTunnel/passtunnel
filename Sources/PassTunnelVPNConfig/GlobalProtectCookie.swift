/// The Palo Alto GlobalProtect session cookie, as `openconnect --authenticate` prints it (`COOKIE`) and as the
/// tunnel run's `cookie` option takes it, unchanged.
///
/// **What openconnect prints** (9.21 `parse_login_xml`, auth-globalprotect.c 293–416): it builds the cookie from
/// the gateway's `<jnlp>` arguments, the saved ones URL-decoded (359) and appended with `append_opt`
/// (auth-common.c 143–156), as `authcookie=…&portal=…&user=…&domain=…&preferred-ip=…&preferred-ipv6=…&computer=…`,
/// in that order. An argument the server sent empty, `(null)` or `-1` is left out; `authcookie` and `user` are
/// required (the login fails without them); `computer` (this machine's host name) is always last. Every name and
/// value is URL-encoded by `buf_append_urlencoded` (textbuf.c 138–149): only `A–Z a–z 0–9 - _ . ~` stay, every
/// other byte becomes `%` and two lower-case hex digits.
///
/// **The tunnel run** takes its `cookie` option as it is (main.c 2050–2052; only the AnyConnect, FortiGate, F5 and
/// Juniper code splits cookies), so unlike `OpenConnectCookie` nothing is renamed: the helper is sent the cookie as
/// printed and checks it with `isValidTunnelOption`.
///
/// **Accepted**, and nothing else: exactly the keys above in that order, each at most once, `authcookie`, `user`
/// and `computer` present; every value in that alphabet, non-empty but `computer`'s (which may be empty),
/// `authcookie`'s at least `minAuthcookieBytes`; at most `OpenConnectConfig.maxCookieBytes` in all. So no `'`,
/// blank, `;` or line break can be in it.
///
/// **What is secret:** `authcookie` is the bearer secret; with `user` and `portal` it opens the session. `user`
/// (the account as the gateway names it) and `computer` are personal but no secrets, the others none. `secrets`
/// gives the whole cookie and the `authcookie` value, for the log maskers (which mask values of 3 bytes and more).
/// No error names a value.
public enum GlobalProtectCookie {
    /// The keys openconnect writes, in its order.
    public static let keys = ["authcookie", "portal", "user", "domain", "preferred-ip", "preferred-ipv6", "computer"]
    /// The keys every cookie has.
    public static let requiredKeys: Set = ["authcookie", "user", "computer"]
    /// The bearer secret's key.
    public static let secretKey = "authcookie"
    /// The shortest `authcookie` value accepted: long enough for every masker to hide it.
    public static let minAuthcookieBytes = 8

    /// The cookie's arguments in order, nil when it is not exactly openconnect's shape (see the type's note).
    public static func parse(_ cookie: String) -> [(key: String, value: String)]? {
        guard cookie.utf8.count <= OpenConnectConfig.maxCookieBytes else { return nil }
        var out: [(key: String, value: String)] = []
        var next = 0  // index into keys: each at most once, in order
        for part in cookie.split(separator: "&", omittingEmptySubsequences: false) {
            guard let eq = part.firstIndex(of: "=") else { return nil }
            let key = String(part[..<eq])
            let value = part[part.index(after: eq)...]
            guard let k = keys[next...].firstIndex(of: key) else { return nil }
            next = k + 1
            guard isEncoded(value) else { return nil }
            if key == secretKey {
                guard value.utf8.count >= minAuthcookieBytes else { return nil }
            } else if key != "computer" {
                guard !value.isEmpty else { return nil }
            }
            out.append((key, String(value)))
        }
        guard Set(out.map(\.key)).isSuperset(of: requiredKeys), out.last?.key == "computer" else { return nil }
        return out
    }

    /// Whether `cookie` is one openconnect prints for GlobalProtect, which the tunnel run gets unchanged.
    public static func isValidTunnelOption(_ cookie: String) -> Bool { parse(cookie) != nil }

    /// The secrets in a cookie, for the maskers: the whole text and, when it parses, the `authcookie` value.
    public static func secrets(_ cookie: String) -> [String] {
        var out = [cookie]
        if let secret = parse(cookie)?.first(where: { $0.key == secretKey })?.value { out.append(secret) }
        return out
    }

    /// `buf_append_urlencoded`'s output: `A–Z a–z 0–9 - _ . ~`, and `%` followed by two lower-case hex digits.
    static func isEncoded(_ s: Substring) -> Bool {
        let bytes = Array(s.utf8)
        var i = 0
        while i < bytes.count {
            let b = bytes[i]
            if FortiConfig.isASCIIAlphanumeric(b) || "-_.~".utf8.contains(b) {
                i += 1
            } else if b == UInt8(ascii: "%"), i + 2 < bytes.count, isLowerHex(bytes[i + 1]), isLowerHex(bytes[i + 2]) {
                i += 3
            } else {
                return false
            }
        }
        return true
    }

    static func isLowerHex(_ b: UInt8) -> Bool { FortiConfig.isASCIIDigit(b) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(b) }
}
