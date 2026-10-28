import Foundation

/// A numeric IPv4 or IPv6 address, parsed strictly and written as `inet_ntop` writes it. Root code that
/// takes addresses from a VPN server (the Linux DNS hook, openconnect's hook) uses this one parser, so
/// every value is read the same way everywhere.
///
/// Accepted: dotted decimal IPv4 (four parts of 0–255, no leading zeros: `010.0.0.1` is refused, since
/// `inet_aton` reads it as octal and `inet_pton` on the Mac as decimal) and IPv6 in the usual notation
/// (groups of 1–4 hex digits, at most one `::`, an IPv4 tail as above), upper or lower case. Refused:
/// host names, zones (`%en0`), ports, brackets, prefixes, blanks and anything else. The result is
/// cross-checked against the system's `inet_pton`.
public struct IPAddress: Hashable, Sendable, CustomStringConvertible {
    public enum Family: Hashable, Sendable {
        case ipv4, ipv6

        /// Bits in an address.
        public var bits: Int { self == .ipv4 ? 32 : 128 }
    }

    public let family: Family
    /// 4 or 16 bytes, network order.
    public let bytes: [UInt8]

    /// The longest text accepted (an IPv6 address with an IPv4 tail, written out).
    public static let maxTextBytes = 45

    public init?(_ text: String) {
        let utf8 = Array(text.utf8)
        guard (2...Self.maxTextBytes).contains(utf8.count),
            utf8.allSatisfy({ Self.isHexDigit($0) || $0 == 0x2E || $0 == 0x3A })
        else { return nil }
        let parsed: [UInt8]?
        if utf8.contains(0x3A) {
            parsed = Self.parseIPv6(utf8[...])
        } else {
            parsed = Self.parseIPv4(utf8[...])
        }
        guard let bytes = parsed else { return nil }
        // Belt and braces: the system must read the same bytes.
        let family: Family = bytes.count == 4 ? .ipv4 : .ipv6
        var system = [UInt8](repeating: 0, count: 16)
        guard inet_pton(family == .ipv4 ? AF_INET : AF_INET6, text, &system) == 1, Array(system.prefix(bytes.count)) == bytes
        else { return nil }
        self.family = family
        self.bytes = bytes
    }

    /// The address with these bytes (4 or 16).
    public init?(bytes: [UInt8]) {
        guard bytes.count == 4 || bytes.count == 16 else { return nil }
        self.family = bytes.count == 4 ? .ipv4 : .ipv6
        self.bytes = bytes
    }

    /// As `inet_ntop` writes it: `192.0.2.1`, `2001:db8::1`, `::ffff:192.0.2.1`.
    public var description: String {
        var buffer = [CChar](repeating: 0, count: 64)
        var copy = bytes
        guard inet_ntop(family == .ipv4 ? AF_INET : AF_INET6, &copy, &buffer, socklen_t(buffer.count)) != nil else {
            return "?"
        }
        return String(cString: buffer)
    }

    /// `0.0.0.0`, `::`.
    public var isUnspecified: Bool { bytes.allSatisfy { $0 == 0 } }

    /// `127.0.0.0/8`, `::1`.
    public var isLoopback: Bool {
        family == .ipv4 ? bytes[0] == 127 : bytes.dropLast().allSatisfy { $0 == 0 } && bytes[15] == 1
    }

    /// An address no interface may take as its own and no route may lead to: unspecified, loopback,
    /// IPv4 `0.0.0.0/8`, multicast and above (`224.0.0.0/3`, which holds `255.255.255.255`), IPv6
    /// multicast (`ff00::/8`).
    public var isSpecial: Bool {
        switch family {
        case .ipv4: return bytes[0] == 0 || bytes[0] == 127 || bytes[0] >= 224
        case .ipv6: return isUnspecified || isLoopback || bytes[0] == 0xFF
        }
    }

    /// IPv6 `fe80::/10`, IPv4 `169.254.0.0/16`.
    public var isLinkLocal: Bool {
        family == .ipv4 ? bytes[0] == 169 && bytes[1] == 254 : bytes[0] == 0xFE && bytes[1] & 0xC0 == 0x80
    }

    /// The address with every bit after the first `prefixLength` cleared.
    public func masked(_ prefixLength: Int) -> IPAddress {
        var out = bytes
        for i in 0..<out.count {
            let bitsBefore = i * 8
            if prefixLength <= bitsBefore {
                out[i] = 0
            } else if prefixLength < bitsBefore + 8 {
                out[i] &= UInt8(truncatingIfNeeded: 0xFF << (8 - (prefixLength - bitsBefore)))
            }
        }
        return IPAddress(bytes: out)!
    }

    /// The length of a contiguous mask (`255.255.255.0` is 24); nil when the ones do not all come first.
    public var maskLength: Int? {
        var ones = 0
        var seenZero = false
        for byte in bytes {
            for bit in (0..<8).reversed() {
                if byte >> bit & 1 == 1 {
                    if seenZero { return nil }
                    ones += 1
                } else {
                    seenZero = true
                }
            }
        }
        return ones
    }

    /// The contiguous mask of `length` bits.
    public static func mask(family: Family, length: Int) -> IPAddress {
        IPAddress(bytes: [UInt8](repeating: 0xFF, count: family.bits / 8))!.masked(length)
    }

    // MARK: Parsing

    static func isHexDigit(_ c: UInt8) -> Bool {
        (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) || (c >= 0x41 && c <= 0x46)
    }

    static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }

    /// Four decimal parts of 0–255 without leading zeros.
    static func parseIPv4(_ text: ArraySlice<UInt8>) -> [UInt8]? {
        let parts = text.split(separator: 0x2E, omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var out: [UInt8] = []
        for part in parts {
            guard (1...3).contains(part.count), part.allSatisfy(isDigit), part.count == 1 || part.first != 0x30 else { return nil }
            let value = part.reduce(0) { $0 * 10 + Int($1 - 0x30) }
            guard value <= 255 else { return nil }
            out.append(UInt8(value))
        }
        return out
    }

    /// Groups of 1–4 hex digits, at most one `::` standing for one or more zero groups, an IPv4 tail as
    /// the last two groups.
    static func parseIPv6(_ text: ArraySlice<UInt8>) -> [UInt8]? {
        // Where `::` is, if anywhere; a second one is refused.
        var gap: Int?
        var i = text.startIndex
        while i < text.endIndex - 1 {
            if text[i] == 0x3A && text[i + 1] == 0x3A {
                guard gap == nil else { return nil }
                gap = i
                i += 2
            } else {
                i += 1
            }
        }
        func groups(_ part: ArraySlice<UInt8>, last: Bool) -> [UInt8]? {
            guard !part.isEmpty else { return [] }
            let pieces = part.split(separator: 0x3A, omittingEmptySubsequences: false)
            var out: [UInt8] = []
            for (n, piece) in pieces.enumerated() {
                if last && n == pieces.count - 1 && piece.contains(0x2E) {
                    guard let v4 = parseIPv4(piece) else { return nil }
                    out += v4
                    continue
                }
                guard (1...4).contains(piece.count), piece.allSatisfy(isHexDigit) else { return nil }
                let value = piece.reduce(0) { $0 << 4 | Int(hexValue($1)) }
                out += [UInt8(value >> 8), UInt8(value & 0xFF)]
            }
            return out
        }
        if let gap {
            guard let head = groups(text[text.startIndex..<gap], last: false),
                let tail = groups(text[(gap + 2)...], last: true),
                head.count + tail.count <= 14
            else { return nil }
            return head + [UInt8](repeating: 0, count: 16 - head.count - tail.count) + tail
        }
        guard let all = groups(text, last: true), all.count == 16 else { return nil }
        return all
    }

    static func hexValue(_ c: UInt8) -> UInt8 {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x61...0x66: return c - 0x61 + 10
        default: return c - 0x41 + 10
        }
    }
}

/// An IPv4 or IPv6 network: an address with its host bits cleared and a prefix length.
public struct IPNetwork: Hashable, Sendable, CustomStringConvertible {
    public let address: IPAddress
    public let prefixLength: Int

    /// `address` with the bits after `prefixLength` cleared; nil for a length beyond the family's.
    public init?(address: IPAddress, prefixLength: Int) {
        guard (0...address.family.bits).contains(prefixLength) else { return nil }
        self.address = address.masked(prefixLength)
        self.prefixLength = prefixLength
    }

    /// `10.0.0.0/8`, `2001:db8::/32`: the address must have no host bits set, the length is decimal
    /// without leading zeros.
    public init?(_ text: String) {
        let parts = text.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let address = IPAddress(String(parts[0])), let length = Self.decimal(parts[1], max: address.family.bits),
            address.masked(length) == address
        else { return nil }
        self.address = address
        self.prefixLength = length
    }

    /// The host network of `address`: `/32` or `/128`.
    public static func host(_ address: IPAddress) -> IPNetwork {
        IPNetwork(address: address, prefixLength: address.family.bits)!
    }

    public var family: IPAddress.Family { address.family }

    public var description: String { "\(address)/\(prefixLength)" }

    public func contains(_ other: IPAddress) -> Bool {
        other.family == family && other.masked(prefixLength) == address
    }

    public func contains(_ other: IPNetwork) -> Bool {
        other.family == family && other.prefixLength >= prefixLength && other.address.masked(prefixLength) == address
    }

    /// The network's two halves (one bit longer); nil for a host.
    public func split() -> (IPNetwork, IPNetwork)? {
        guard prefixLength < family.bits else { return nil }
        var high = address.bytes
        high[prefixLength / 8] |= UInt8(0x80 >> (prefixLength % 8))
        return (
            IPNetwork(address: address, prefixLength: prefixLength + 1)!, IPNetwork(address: IPAddress(bytes: high)!, prefixLength: prefixLength + 1)!
        )
    }

    /// The two halves of the family's address space, `0.0.0.0/1` and `128.0.0.0/1` or `::/1` and
    /// `8000::/1`: together every destination, yet never the default route.
    public static func halves(_ family: IPAddress.Family) -> [IPNetwork] {
        var high = [UInt8](repeating: 0, count: family.bits / 8)
        high[0] = 0x80
        return [
            IPNetwork(address: IPAddress(bytes: [UInt8](repeating: 0, count: family.bits / 8))!, prefixLength: 1)!,
            IPNetwork(address: IPAddress(bytes: high)!, prefixLength: 1)!
        ]
    }

    /// ASCII digits without leading zeros, at most `max`.
    static func decimal(_ text: Substring, max: Int) -> Int? {
        let bytes = Array(text.utf8)
        guard (1...3).contains(bytes.count), bytes.allSatisfy(IPAddress.isDigit), bytes.count == 1 || bytes[0] != 0x30 else {
            return nil
        }
        let value = bytes.reduce(0) { $0 * 10 + Int($1 - 0x30) }
        return value <= max ? value : nil
    }
}

/// A plain host name as a DNS domain: lowercased and without a final dot, at most 253 bytes in labels
/// of 1 to 63 ASCII letters, digits, `-` and `_`, none starting or ending with `-`. Nothing a tool could
/// take for an option (`-x`), a routing marker (`~`) or anything but a name. nil for anything else.
public enum DomainName {
    public static func normalize(_ text: String) -> String? {
        guard text.utf8.count <= 254, text.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else { return nil }
        var name = text.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...253).contains(name.utf8.count), labels.allSatisfy(isLabel) else { return nil }
        return name
    }

    static func isLabel(_ label: Substring) -> Bool {
        guard (1...63).contains(label.utf8.count), label.first != "-", label.last != "-" else { return false }
        return label.utf8.allSatisfy { c in
            (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c == 0x2D || c == 0x5F  // a-z 0-9 - _
        }
    }
}
