import Foundation

/// openfortivpn configuration rendered from typed fields. openfortivpn's format is one `key = value`
/// per line with no quoting or escaping, so every value is validated to stay on its own line.
public struct FortiConfig: Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var host: String
    public var port: Int
    public var username: String
    public var password: String
    public var otp: String?
    public var trustedCert: String      // sha256 digest of the gateway certificate, or empty
    public var setDNS: Bool
    public var setRoutes: Bool

    public enum ValidationError: Error, Equatable, LocalizedError, CustomStringConvertible {
        case invalidHost
        case invalidPort(Int)
        case invalidTrustedCert
        case invalidValue(field: String, reason: String)
        /// The rendered text failed the final check (`checkRendered`): a validator let something through.
        case unsafeOutput(String)

        public var description: String {
            switch self {
            case .invalidHost: return "Invalid gateway host name."
            case .invalidPort(let p): return "Invalid port \(p) (must be 1–65535)."
            case .invalidTrustedCert: return "The trusted certificate must be a SHA-256 digest (64 hex characters)."
            case .invalidValue(let f, let r): return "Invalid \(f): \(r)."
            case .unsafeOutput(let r): return "The openfortivpn configuration failed its final check: \(r)."
            }
        }
        public var errorDescription: String? { description }
    }

    // openfortivpn (src/config.h) copies each value into a fixed buffer and silently drops what does
    // not fit: GATEWAY_HOST_SIZE 253, USERNAME_SIZE 64, PASSWORD_SIZE 256, OTP_SIZE 64 bytes. A longer
    // value is refused here instead of being sent cut off. Bytes, not characters: "ş" is two.
    public static let maxHostBytes = 253
    public static let maxUsernameBytes = 64
    public static let maxPasswordBytes = 255
    public static let maxOTPBytes = 64

    /// The system's CA bundle (root-owned, writable only by root). The bundled OpenSSL's default store is the
    /// build machine's Homebrew prefix, which its owner (or any admin) can change.
    public static let systemCAFile = "/etc/ssl/cert.pem"

    public init(host: String, port: Int = 443, username: String, password: String, otp: String? = nil,
                trustedCert: String = "", setDNS: Bool = false, setRoutes: Bool = true) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.otp = otp
        self.trustedCert = trustedCert
        self.setDNS = setDNS
        self.setRoutes = setRoutes
    }

    public var description: String {
        "FortiConfig(host: \(host), port: \(port), username: \(username), password: <redacted>, "
            + "otp: \(otp == nil ? "nil" : "<redacted>"), trustedCert: \(trustedCert), setDNS: \(setDNS), "
            + "setRoutes: \(setRoutes))"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: ["host": host, "port": port, "username": username, "password": "<redacted>",
                                "otp": otp == nil ? "nil" : "<redacted>", "trustedCert": trustedCert,
                                "setDNS": setDNS, "setRoutes": setRoutes])
    }

    public func validate() throws {
        guard Self.isValidHost(host) else { throw ValidationError.invalidHost }
        guard (1...65535).contains(port) else { throw ValidationError.invalidPort(port) }
        if !trustedCert.isEmpty, !Self.isValidDigest(trustedCert) { throw ValidationError.invalidTrustedCert }
        try Self.checkValue(username, field: "username", maxBytes: Self.maxUsernameBytes, allowEmpty: false)
        try Self.checkValue(password, field: "password", maxBytes: Self.maxPasswordBytes, allowEmpty: false)
        if let otp, !otp.isEmpty {
            try Self.checkValue(otp, field: "one-time code", maxBytes: Self.maxOTPBytes, allowEmpty: false)
        }
    }

    /// Every key `render` can write, in its order.
    public static let renderedKeys = ["host", "port", "username", "password", "otp", "ca-file", "trusted-cert",
                                      "set-routes", "set-dns", "pppd-use-peerdns"]

    /// The config file text. Throws `ValidationError` instead of emitting anything unsafe: the fields
    /// are validated first, and the finished text is checked again (`checkRendered`) before it is returned.
    /// `caFile` is the CA bundle openfortivpn verifies the gateway with: the Mac's system bundle, or
    /// the distribution's that the Linux daemon found. With `handlesDNS` false, openfortivpn and pppd
    /// leave DNS alone whatever `setDNS` says (`set-dns` and `pppd-use-peerdns` 0): the Linux daemon
    /// applies it itself.
    public func render(caFile: String = FortiConfig.systemCAFile, handlesDNS: Bool = true) throws -> String {
        try validate()
        guard Self.isValidPath(caFile) else {
            throw ValidationError.invalidValue(field: "CA file", reason: "not an absolute path without spaces or control characters")
        }
        var lines = [
            "# Generated by PassTunnel. Do not edit.",
            "host = \(host)",
            "port = \(port)",
            "username = \(username)",
            "password = \(password)",
        ]
        if let otp, !otp.isEmpty { lines.append("otp = \(otp)") }
        // Explicit, so openfortivpn never falls back to OpenSSL's default store (a Homebrew prefix).
        lines.append("ca-file = \(caFile)")
        if !trustedCert.isEmpty { lines.append("trusted-cert = \(trustedCert.lowercased())") }
        lines.append("set-routes = \(setRoutes ? 1 : 0)")
        let dns = setDNS && handlesDNS
        lines.append("set-dns = \(dns ? 1 : 0)")
        lines.append("pppd-use-peerdns = \(dns ? 1 : 0)")
        let text = lines.joined(separator: "\n") + "\n"
        try Self.checkRendered(text, lineCount: lines.count)
        return text
    }

    /// A file path for the config: absolute, at most 4096 bytes, no whitespace (openfortivpn trims it)
    /// and no control character.
    static func isValidPath(_ path: String) -> Bool {
        path.hasPrefix("/") && path.utf8.count <= 4096
            && !path.unicodeScalars.contains(where: { isForbiddenScalar($0) || $0.properties.isWhitespace })
    }

    /// Defense in depth for the file a root process reads: `text` must be exactly `lineCount` lines, each
    /// ending in "\n", with no NUL, CR or other control byte, and every line either a `#` comment or
    /// `key = value` with a key from `renderedKeys`, each key at most once and in that order.
    static func checkRendered(_ text: String, lineCount: Int) throws {
        func fail(_ reason: String) -> ValidationError { .unsafeOutput(reason) }
        let bytes = Array(text.utf8)
        guard !bytes.contains(0) else { throw fail("NUL byte") }
        guard !bytes.contains(0x0D) else { throw fail("carriage return") }
        guard !bytes.contains(where: { ($0 < 0x20 && $0 != 0x0A) || $0 == 0x7F }) else { throw fail("control byte") }
        guard bytes.last == 0x0A else { throw fail("no final line break") }
        let lines = bytes.dropLast().split(separator: 0x0A, omittingEmptySubsequences: false)
        guard lines.count == lineCount else { throw fail("\(lines.count) lines instead of \(lineCount)") }
        var next = 0   // index into renderedKeys: keys must appear once each, in order
        for (n, line) in lines.enumerated() {
            if line.first == UInt8(ascii: "#") { continue }
            let separator = Array(" = ".utf8)
            guard let eq = line.firstIndex(of: UInt8(ascii: "=")), eq > line.startIndex,
                  Array(line[(eq - 1)...].prefix(3)) == separator, eq + 2 < line.endIndex else {
                throw fail("line \(n + 1) is not “key = value”")
            }
            let key = String(decoding: line[..<(eq - 1)], as: UTF8.self)
            guard let k = renderedKeys[next...].firstIndex(of: key) else {
                throw fail("line \(n + 1) has an unexpected or repeated key")
            }
            next = k + 1
        }
    }

    // MARK: - Validation helpers

    public static func isValidDigest(_ s: String) -> Bool {
        s.utf8.count == 64 && s.utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }
    }

    /// Host name, IPv4 or IPv6 literal (no brackets, no port). Every character is checked here, in
    /// Swift, before anything reaches a C function: C reads a string only up to its first NUL, so a
    /// C-level check alone would pass whatever follows one.
    public static func isValidHost(_ s: String) -> Bool {
        guard !s.isEmpty, s.utf8.count <= maxHostBytes, !s.hasPrefix("-"), !s.hasPrefix("."),
              !s.unicodeScalars.contains(where: { isForbiddenScalar($0) || $0.properties.isWhitespace }) else {
            return false
        }
        if s.utf8.contains(UInt8(ascii: ":")) { return isValidIPv6(s) }
        return s.utf8.allSatisfy { isASCIIAlphanumeric($0) || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "-") }
    }

    /// Longest zone id ("%en0", "%utun10", "%4"): an interface name is at most IFNAMSIZ - 1 bytes.
    static let maxZoneIDBytes = 15

    /// An IPv6 literal: hex digits, `:` and `.` (for an IPv4-mapped tail) that `inet_pton` accepts,
    /// optionally followed by a zone id of ASCII letters and digits. The zone id is checked here
    /// because macOS `inet_pton` accepts any bytes after `%`, and only the address part is passed to it.
    static func isValidIPv6(_ s: String) -> Bool {
        let bytes = Array(s.utf8)
        let percent = bytes.firstIndex(of: UInt8(ascii: "%"))
        let address = bytes[..<(percent ?? bytes.endIndex)]
        guard !address.isEmpty, address.allSatisfy({
            isASCIIHexDigit($0) || $0 == UInt8(ascii: ":") || $0 == UInt8(ascii: ".")
        }) else { return false }
        if let percent {
            let zone = bytes[(percent + 1)...]
            guard (1...maxZoneIDBytes).contains(zone.count), zone.allSatisfy(isASCIIAlphanumeric) else { return false }
        }
        var addr = in6_addr()
        return String(decoding: address, as: UTF8.self).withCString { inet_pton(AF_INET6, $0, &addr) } == 1
    }

    static func isASCIIAlphanumeric(_ b: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(b) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(b)
            || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(b)
    }

    static func isASCIIHexDigit(_ b: UInt8) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(b) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(b)
            || (UInt8(ascii: "A")...UInt8(ascii: "F")).contains(b)
    }

    static func checkValue(_ s: String, field: String, maxBytes: Int, allowEmpty: Bool) throws {
        if s.isEmpty {
            if allowEmpty { return }
            throw ValidationError.invalidValue(field: field, reason: "must not be empty")
        }
        guard s.utf8.count <= maxBytes else {
            throw ValidationError.invalidValue(field: field, reason: "longer than \(maxBytes) bytes")
        }
        for c in s.unicodeScalars where isForbiddenScalar(c) {
            throw ValidationError.invalidValue(field: field, reason: "contains a line break or control character")
        }
        // openfortivpn trims whitespace around values, so it cannot be represented.
        if let f = s.unicodeScalars.first, let l = s.unicodeScalars.last,
           f.properties.isWhitespace || l.properties.isWhitespace {
            throw ValidationError.invalidValue(field: field, reason: "cannot start or end with whitespace")
        }
    }

    /// C0/C1 controls, DEL and Unicode line/paragraph separators.
    static func isForbiddenScalar(_ c: Unicode.Scalar) -> Bool {
        switch c.value {
        case 0x00...0x1F, 0x7F...0x9F, 0x2028, 0x2029: return true
        default: return false
        }
    }
}
