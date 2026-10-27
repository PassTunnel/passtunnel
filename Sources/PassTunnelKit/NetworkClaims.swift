import Foundation

/// An IPv4 or IPv6 network: an address and a prefix length, with the host bits cleared (`10.1.2.3/8` is
/// `10.0.0.0/8`, as the routing table keeps it). A bare address is a host route (`/32`, `/128`).
/// Parsing is exact and does not use the system resolver: only numeric addresses are accepted.
public struct CIDR: Hashable, Comparable, Sendable, Codable, CustomStringConvertible {
    public let isIPv6: Bool
    public let prefixLength: Int
    /// The address as 128 bits; an IPv4 address is the low 32 bits of `low`.
    let high: UInt64
    let low: UInt64

    private init(isIPv6: Bool, high: UInt64, low: UInt64, prefixLength: Int) {
        let mask = Self.mask(isIPv6: isIPv6, prefixLength: prefixLength)
        self.isIPv6 = isIPv6
        self.prefixLength = prefixLength
        self.high = high & mask.high
        self.low = low & mask.low
    }

    /// "10.0.0.0/8", "10.1.2.3" (a host), "2001:db8::/32", "2001:db8::1". nil for anything else: host
    /// names, zones (`%en0`), ports, a prefix beyond the address size, signs, spaces.
    public init?(_ text: String) {
        let parts = text.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard !parts.isEmpty, parts.count <= 2, let address = Self.parseAddress(parts[0]) else { return nil }
        let size = address.isIPv6 ? 128 : 32
        var prefix = size
        if parts.count == 2 {
            guard let p = Self.decimal(parts[1], maxDigits: 3), p <= size else { return nil }
            prefix = p
        }
        self.init(isIPv6: address.isIPv6, high: address.high, low: address.low, prefixLength: prefix)
    }

    /// An IPv4 network as `route` writes it: "10.0.0.0" and "255.0.0.0". The mask must be contiguous
    /// ("255.0.255.0" is refused).
    public init?(address: String, netmask: String) {
        guard let a = Self.parseIPv4(address[...]), let m = Self.parseIPv4(netmask[...]) else { return nil }
        let ones = m.nonzeroBitCount
        // Contiguous: the ones are the top `ones` bits.
        let expected: UInt32 = ones == 0 ? 0 : UInt32.max << UInt32(32 - ones)
        guard m == expected else { return nil }
        self.init(isIPv6: false, high: 0, low: UInt64(a), prefixLength: ones)
    }

    /// The numeric address of `text` ("10.1.2.3", "2001:db8::1") as a host route, nil if it is not one.
    public static func host(_ text: String) -> CIDR? {
        text.contains("/") ? nil : CIDR(text)
    }

    public var description: String {
        if isIPv6 { return Self.format(high: high, low: low) + "/\(prefixLength)" }
        return Self.formatIPv4(UInt32(truncatingIfNeeded: low)) + "/\(prefixLength)"
    }

    /// The address alone: "10.0.0.0", "2001:db8::".
    public var address: String {
        isIPv6 ? Self.format(high: high, low: low) : Self.formatIPv4(UInt32(truncatingIfNeeded: low))
    }

    /// A host route: `/32` or `/128`.
    public var isHost: Bool { prefixLength == (isIPv6 ? 128 : 32) }

    /// `self` holds every address of `other` (same family, a prefix at most as long, same leading bits).
    public func contains(_ other: CIDR) -> Bool {
        guard isIPv6 == other.isIPv6, prefixLength <= other.prefixLength else { return false }
        let mask = Self.mask(isIPv6: isIPv6, prefixLength: prefixLength)
        return other.high & mask.high == high && other.low & mask.low == low
    }

    /// The two share an address: one holds the other (networks either nest or are apart).
    public func overlaps(_ other: CIDR) -> Bool {
        contains(other) || other.contains(self)
    }

    /// What both hold: the narrower of two overlapping networks; nil when they are apart.
    public func intersection(_ other: CIDR) -> CIDR? {
        if contains(other) { return other }
        return other.contains(self) ? self : nil
    }

    public static func < (a: CIDR, b: CIDR) -> Bool {
        (a.isIPv6 ? 1 : 0, a.high, a.low, a.prefixLength) < (b.isIPv6 ? 1 : 0, b.high, b.low, b.prefixLength)
    }

    public init(from decoder: Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let cidr = CIDR(text) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "not a network"))
        }
        self = cidr
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }

    // MARK: Bits

    private static func mask(isIPv6: Bool, prefixLength p: Int) -> (high: UInt64, low: UInt64) {
        if !isIPv6 { return (0, p == 0 ? 0 : (UInt64(UInt32.max) << UInt64(32 - p)) & UInt64(UInt32.max)) }
        if p == 0 { return (0, 0) }
        if p <= 64 { return (UInt64.max << UInt64(64 - p), 0) }
        return (UInt64.max, p == 128 ? UInt64.max : UInt64.max << UInt64(128 - p))
    }

    // MARK: Text

    /// ASCII digits only, no leading zeros ("08" is refused: some parsers read it as octal), at most
    /// `maxDigits` of them.
    private static func decimal(_ text: Substring, maxDigits: Int) -> Int? {
        let bytes = text.utf8
        guard !bytes.isEmpty, bytes.count <= maxDigits, bytes.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
            bytes.count == 1 || bytes.first != 0x30
        else { return nil }
        return Int(text)
    }

    static func parseIPv4(_ text: Substring) -> UInt32? {
        let octets = text.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var value: UInt32 = 0
        for octet in octets {
            guard let n = decimal(octet, maxDigits: 3), n <= 255 else { return nil }
            value = value << 8 | UInt32(n)
        }
        return value
    }

    private static func parseAddress(_ text: Substring) -> (isIPv6: Bool, high: UInt64, low: UInt64)? {
        if text.contains(":") {
            guard let (high, low) = parseIPv6(text) else { return nil }
            return (true, high, low)
        }
        guard let v4 = parseIPv4(text) else { return nil }
        return (false, 0, UInt64(v4))
    }

    /// RFC 4291 text: eight groups of one to four hex digits, one `::` for a run of zero groups, an IPv4
    /// address in place of the last two groups.
    private static func parseIPv6(_ text: Substring) -> (UInt64, UInt64)? {
        guard text.utf8.count <= 45 else { return nil }
        let halves = text.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }
        func groups(_ part: String, last: Bool) -> [UInt16]? {
            if part.isEmpty { return [] }
            let items = part.split(separator: ":", omittingEmptySubsequences: false)
            var out: [UInt16] = []
            for (i, item) in items.enumerated() {
                if item.contains(".") {
                    guard last, i == items.count - 1, let v4 = parseIPv4(item) else { return nil }
                    out += [UInt16(v4 >> 16), UInt16(v4 & 0xFFFF)]
                } else {
                    guard (1...4).contains(item.utf8.count),
                        item.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 | 0x20 >= 0x61 && $0 | 0x20 <= 0x66) }),
                        let g = UInt16(item, radix: 16)
                    else { return nil }
                    out.append(g)
                }
            }
            return out
        }
        var all: [UInt16]
        if halves.count == 1 {
            guard let g = groups(halves[0], last: true), g.count == 8 else { return nil }
            all = g
        } else {
            guard let head = groups(halves[0], last: false), let tail = groups(halves[1], last: true),
                head.count + tail.count <= 7
            else { return nil }
            all = head + [UInt16](repeating: 0, count: 8 - head.count - tail.count) + tail
        }
        let high = all[0..<4].reduce(UInt64(0)) { $0 << 16 | UInt64($1) }
        let low = all[4..<8].reduce(UInt64(0)) { $0 << 16 | UInt64($1) }
        return (high, low)
    }

    private static func formatIPv4(_ v: UInt32) -> String {
        "\(v >> 24).\(v >> 16 & 255).\(v >> 8 & 255).\(v & 255)"
    }

    /// RFC 5952: lowercase, leading zeros dropped, the longest run of two or more zero groups (the first
    /// of equals) as `::`.
    private static func format(high: UInt64, low: UInt64) -> String {
        let groups = (0..<8).map { i -> UInt16 in
            let word = i < 4 ? high : low
            return UInt16(truncatingIfNeeded: word >> UInt64(16 * (3 - i % 4)))
        }
        var best = (start: -1, length: 0)
        var i = 0
        while i < 8 {
            guard groups[i] == 0 else { i += 1; continue }
            var j = i
            while j < 8, groups[j] == 0 { j += 1 }
            if j - i > best.length { best = (i, j - i) }
            i = j
        }
        let hex = groups.map { String($0, radix: 16) }
        guard best.length >= 2 else { return hex.joined(separator: ":") }
        let head = hex[0..<best.start].joined(separator: ":")
        let tail = hex[(best.start + best.length)...].joined(separator: ":")
        return head + "::" + tail
    }
}

/// What a tunnel takes over on this computer: the networks it routes, whether it carries all traffic,
/// the DNS servers it sets and the names those servers answer. Built from a profile's configuration and
/// what its server pushed (`OVPNAnalyzer.networkClaims`), compared with `overlaps`. Pure data and math:
/// builds everywhere.
public struct NetworkClaims: Equatable, Sendable {
    /// The most of each kind kept, so a server cannot make the comparison arbitrarily large.
    public static let maxRoutes = 1024
    public static let maxDNSServers = 16
    public static let maxDomains = 64
    /// The most overlaps `overlaps` reports.
    public static let maxOverlaps = 256

    /// Networks sent through the tunnel (both families), sorted, without repeats. A route for all of
    /// IPv4 (`0.0.0.0/0`, or both `/1` halves) is `fullTunnel` instead.
    public private(set) var routes: [CIDR]
    /// All IPv4 traffic goes through the tunnel (`redirect-gateway`, a default route).
    public var fullTunnel: Bool
    /// All IPv6 traffic does (`redirect-gateway ipv6`, `::/0`).
    public var fullTunnelIPv6: Bool
    /// DNS servers the tunnel sets, as addresses.
    public private(set) var dnsServers: [String]
    /// Names only the tunnel's servers resolve (split DNS), lowercase, without a final dot.
    public private(set) var dnsDomains: [String]
    /// Names the tunnel adds to the search list (`dhcp-option DOMAIN`), the same form.
    public private(set) var searchDomains: [String]

    public init(
        routes: [CIDR] = [], fullTunnel: Bool = false, fullTunnelIPv6: Bool = false, dnsServers: [String] = [],
        dnsDomains: [String] = [], searchDomains: [String] = []
    ) {
        self.routes = []
        self.fullTunnel = fullTunnel
        self.fullTunnelIPv6 = fullTunnelIPv6
        self.dnsServers = []
        self.dnsDomains = []
        self.searchDomains = []
        routes.forEach { addRoute($0) }
        dnsServers.forEach { addDNSServer($0) }
        dnsDomains.forEach { addDNSDomain($0) }
        searchDomains.forEach { addSearchDomain($0) }
    }

    public var isEmpty: Bool {
        routes.isEmpty && !fullTunnel && !fullTunnelIPv6 && dnsServers.isEmpty && dnsDomains.isEmpty && searchDomains.isEmpty
    }

    /// Carries all IPv4 or all IPv6 traffic.
    public var allTraffic: Bool { fullTunnel || fullTunnelIPv6 }

    public var ipv4Routes: [CIDR] { routes.filter { !$0.isIPv6 } }
    public var ipv6Routes: [CIDR] { routes.filter(\.isIPv6) }

    /// Names the tunnel's servers are asked for: split DNS and search domains.
    public var domains: [String] { Array(Set(dnsDomains).union(searchDomains)).sorted() }

    // MARK: Adding

    /// Adds a route. `/0` and the two `/1` halves of an address family (and IPv6's `2000::/3`, all
    /// global addresses) turn on the family's full tunnel instead.
    public mutating func addRoute(_ route: CIDR) {
        if route.prefixLength == 0 || (route.isIPv6 && route == Self.globalUnicast) {
            if route.isIPv6 { fullTunnelIPv6 = true } else { fullTunnel = true }
            return
        }
        guard !routes.contains(route), routes.count < Self.maxRoutes else { return }
        routes.append(route)
        routes.sort()
        if route.prefixLength == 1 { mergeHalves(isIPv6: route.isIPv6) }
    }

    private static let globalUnicast = CIDR("2000::/3")!

    private mutating func mergeHalves(isIPv6: Bool) {
        let halves = isIPv6 ? [CIDR("::/1")!, CIDR("8000::/1")!] : [CIDR("0.0.0.0/1")!, CIDR("128.0.0.0/1")!]
        guard halves.allSatisfy({ routes.contains($0) }) else { return }
        routes.removeAll { halves.contains($0) }
        if isIPv6 { fullTunnelIPv6 = true } else { fullTunnel = true }
    }

    /// Adds a DNS server given as an address ("10.8.0.1", "2001:db8::53"); anything else is ignored.
    public mutating func addDNSServer(_ text: String) {
        guard let host = CIDR.host(text), host.high != 0 || host.low != 0 else { return }
        let address = host.address
        guard !dnsServers.contains(address), dnsServers.count < Self.maxDNSServers else { return }
        dnsServers.append(address)
    }

    public mutating func addDNSDomain(_ text: String) {
        guard let name = Self.normalizedDomain(text), !dnsDomains.contains(name), dnsDomains.count < Self.maxDomains else { return }
        dnsDomains.append(name)
    }

    public mutating func addSearchDomain(_ text: String) {
        guard let name = Self.normalizedDomain(text), !searchDomains.contains(name),
            searchDomains.count < Self.maxDomains
        else { return }
        searchDomains.append(name)
    }

    /// `other`'s claims too.
    public mutating func merge(_ other: NetworkClaims) {
        other.routes.forEach { addRoute($0) }
        fullTunnel = fullTunnel || other.fullTunnel
        fullTunnelIPv6 = fullTunnelIPv6 || other.fullTunnelIPv6
        other.dnsServers.forEach { addDNSServer($0) }
        other.dnsDomains.forEach { addDNSDomain($0) }
        other.searchDomains.forEach { addSearchDomain($0) }
    }

    // MARK: Domains

    /// A DNS name in the form the comparison uses: trimmed, lowercase, without a final dot, and without
    /// the marks some tools put before a routing domain (`~example.com`, `.example.com`, `*.example.com`).
    /// Labels are 1 to 63 ASCII letters, digits, `-` or `_` (not starting or ending with `-`), the whole
    /// name at most 253 bytes. nil for anything else, including "" and ".".
    public static func normalizedDomain(_ text: String) -> String? {
        var name = text.trimmingCharacters(in: .whitespaces).lowercased()
        while name.hasPrefix("~") || name.hasPrefix("*") || name.hasPrefix(".") { name.removeFirst() }
        if name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, name.utf8.count <= 253 else { return nil }
        for label in name.split(separator: ".", omittingEmptySubsequences: false) {
            guard (1...63).contains(label.utf8.count), label.first != "-", label.last != "-",
                label.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D || $0 == 0x5F })
            else { return nil }
        }
        return name
    }

    /// The names are equal, or one is a suffix of the other on a label boundary: "corp.example.com" is
    /// inside "example.com", "notexample.com" is not. Both in `normalizedDomain` form.
    public static func domainsOverlap(_ a: String, _ b: String) -> Bool {
        a == b || a.hasSuffix("." + b) || b.hasSuffix("." + a)
    }

    // MARK: Overlap

    /// One thing two tunnels both claim.
    public enum Overlap: Equatable, Sendable {
        /// A route of each, one holding the other (or equal).
        case route(CIDR, CIDR)
        /// A name of each, equal or one inside the other.
        case domain(String, String)
        /// A tunnel that carries all traffic meets anything the other claims. `first` and `second`: which of
        /// the two carries all traffic (the other may too).
        case allTraffic(first: Bool, second: Bool)
    }

    /// Everything `a` and `b` both claim, in a fixed order (all traffic, routes, names), at most
    /// `maxOverlaps`. Empty when they do not collide.
    public static func overlaps(_ a: NetworkClaims, _ b: NetworkClaims) -> [Overlap] {
        var out: [Overlap] = []
        if collide(fullTunnelOf: a, with: b) || collide(fullTunnelOf: b, with: a) {
            out.append(.allTraffic(first: a.allTraffic, second: b.allTraffic))
        }
        networks: for x in a.routes {
            for y in b.routes where x.overlaps(y) {
                if out.count >= maxOverlaps { break networks }
                out.append(.route(x, y))
            }
        }
        let namesA = a.domains, namesB = b.domains
        names: for x in namesA {
            for y in namesB where domainsOverlap(x, y) {
                if out.count >= maxOverlaps { break names }
                out.append(.domain(x, y))
            }
        }
        return out
    }

    /// `x` carries all traffic of a family and `y` claims something in it (or does too).
    private static func collide(fullTunnelOf x: NetworkClaims, with y: NetworkClaims) -> Bool {
        let dns = !y.dnsServers.isEmpty || !y.dnsDomains.isEmpty || !y.searchDomains.isEmpty
        if x.fullTunnel, y.fullTunnel || y.routes.contains(where: { !$0.isIPv6 }) || dns { return true }
        if x.fullTunnelIPv6, y.fullTunnelIPv6 || y.routes.contains(where: \.isIPv6) || dns { return true }
        return false
    }
}

extension NetworkClaims {
    /// `overlaps` for `self` and `other`.
    public func overlaps(with other: NetworkClaims) -> [Overlap] {
        Self.overlaps(self, other)
    }
}

/// The overlaps of two tunnels in the lists a message or a report shows.
public struct OverlapSummary: Equatable, Sendable {
    /// The networks both send through their tunnel, as the narrower of each overlapping pair, sorted.
    public var routes: [CIDR]
    /// The names both look up through their tunnel, as the narrower of each overlapping pair, sorted.
    public var domains: [String]
    /// The first / second tunnel carries all traffic and meets something the other claims.
    public var firstTakesAllTraffic: Bool
    public var secondTakesAllTraffic: Bool

    public init(_ overlaps: [NetworkClaims.Overlap]) {
        var routes = Set<CIDR>()
        var domains = Set<String>()
        var first = false, second = false
        for overlap in overlaps {
            switch overlap {
            case let .route(a, b): if let shared = a.intersection(b) { routes.insert(shared) }
            case let .domain(a, b): domains.insert(a.count >= b.count ? a : b)
            case let .allTraffic(f, s): first = first || f; second = second || s
            }
        }
        self.routes = routes.sorted()
        self.domains = domains.sorted()
        firstTakesAllTraffic = first
        secondTakesAllTraffic = second
    }

    public var isEmpty: Bool { routes.isEmpty && domains.isEmpty && !firstTakesAllTraffic && !secondTakesAllTraffic }
}
