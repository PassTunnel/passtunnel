import Foundation
import PassTunnelShared

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Read-only view of the routes ordinary traffic takes, without external commands or privileges: on
/// the Mac the IPv4 routing table (`sysctl` `NET_RT_DUMP`), on Linux the IPv4 and IPv6 routes of the
/// tables the policy rules send ordinary traffic to (rtnetlink dumps of the links, routes and rules).
public enum RoutingTable {
    public struct Route: Equatable, Sendable {
        public var destination: String  // dotted quad, or (Linux) an IPv6 address
        public var prefixLength: Int
        public var interface: String  // e.g. "utun4", "en0", "tun0"
        public var scoped: Bool  // RTF_IFSCOPE: only used for traffic bound to the interface
        /// Linux: the kernel's kind of `interface` is a tunnel device (tun/tap, ppp, WireGuard, …),
        /// whatever its name.
        public var tunnelDevice: Bool

        public init(
            destination: String, prefixLength: Int, interface: String, scoped: Bool = false,
            tunnelDevice: Bool = false
        ) {
            self.destination = destination
            self.prefixLength = prefixLength
            self.interface = interface
            self.scoped = scoped
            self.tunnelDevice = tunnelDevice
        }

        /// `default`, `0/1` or `128/1`: a route that captures all traffic (OpenVPN's `redirect-gateway`).
        /// IPv6 (Linux): `::/0`, `::/1`, `8000::/1`, and `2000::/3` or its halves `2000::/4` and
        /// `3000::/4` (OpenVPN's `redirect-gateway ipv6`).
        public var capturesAllTraffic: Bool {
            switch destination {
            case "0.0.0.0", "::": return prefixLength <= 1
            case "128.0.0.0", "8000::": return prefixLength == 1
            case "2000::": return prefixLength == 3 || prefixLength == 4
            case "3000::": return prefixLength == 4
            default: return false
            }
        }
    }

    /// The routes `FullTunnelCheck` looks at; empty if they cannot be read.
    public static func trafficRoutes() -> [Route] {
        #if os(macOS)
        return ipv4Routes()
        #elseif os(Linux)
        return linuxTrafficRoutes()
        #else
        return []
        #endif
    }

    #if os(macOS)
    /// Current IPv4 routes; empty if the table cannot be read.
    public static func ipv4Routes() -> [Route] {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0]
        var len = 0
        guard sysctl(&mib, 6, nil, &len, nil, 0) == 0, len > 0 else { return [] }
        len += len / 8  // the table may grow between the two calls
        var buf = [UInt8](repeating: 0, count: len)
        guard sysctl(&mib, 6, &buf, &len, nil, 0) == 0 else { return [] }
        return parse(Array(buf.prefix(len)))
    }

    /// Parses a `NET_RT_DUMP` buffer: `rt_msghdr` records, each followed by its socket addresses.
    static func parse(_ buf: [UInt8]) -> [Route] {
        let headerSize = MemoryLayout<rt_msghdr>.size
        var out: [Route] = []
        var offset = 0
        buf.withUnsafeBytes { raw in
            while offset + headerSize <= raw.count {
                let hdr = raw.loadUnaligned(fromByteOffset: offset, as: rt_msghdr.self)
                let length = Int(hdr.rtm_msglen)
                guard length >= headerSize, offset + length <= raw.count else { break }
                defer { offset += length }
                guard hdr.rtm_version == RTM_VERSION else { continue }
                var p = offset + headerSize
                var addresses: [Int: ArraySlice<UInt8>] = [:]
                for i in 0..<Int(RTAX_MAX) where hdr.rtm_addrs & (1 << i) != 0 {
                    guard p < offset + length else { break }
                    let saLen = Int(raw[p])
                    addresses[i] = buf[p..<min(p + saLen, offset + length)]
                    p += saLen > 0 ? 1 + ((saLen - 1) | 3) : 4  // sockaddrs are padded to 4 bytes
                }
                guard let dst = addresses[Int(RTAX_DST)], dst.count >= 2, dst[dst.startIndex + 1] == UInt8(AF_INET) else {
                    continue
                }
                let prefix: Int
                if let mask = addresses[Int(RTAX_NETMASK)] {
                    prefix = ipv4Bytes(mask).reduce(0) { $0 + $1.nonzeroBitCount }
                } else {
                    prefix = 32
                }
                var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
                let iface = if_indextoname(UInt32(hdr.rtm_index), &name) != nil ? String(cString: name) : ""
                out.append(
                    Route(
                        destination: ipv4Bytes(dst).map(String.init).joined(separator: "."),
                        prefixLength: prefix, interface: iface,
                        scoped: hdr.rtm_flags & RTF_IFSCOPE != 0))
            }
        }
        return out
    }

    /// The four address bytes of a (possibly truncated) `sockaddr_in`; missing bytes are zero.
    static func ipv4Bytes(_ sa: ArraySlice<UInt8>) -> [UInt8] {
        let bytes = Array(sa)
        return (4..<8).map { $0 < bytes.count ? bytes[$0] : 0 }
    }
    #endif

    // MARK: Linux

    /// Routes with a longer prefix never capture all traffic (`Route.capturesAllTraffic`); the Linux
    /// reader keeps only these, however large the tables are.
    static let maxCapturingPrefix = 4

    /// The routes ordinary traffic of user `uid` can take, from rtnetlink dumps of every table, the
    /// policy rules and the links. The rules are followed in priority order as the kernel does for a
    /// packet of a local program (no mark, any destination): a rule applies when its selectors match
    /// such a packet (none, `iif lo`, a mark of 0, a uid range holding `uid`), or, for `not` rules,
    /// when they do not. Each applying rule that looks up a table contributes the table's routes that
    /// capture all traffic, less those it suppresses (`suppress_prefixlength`, as wg-quick sets on the
    /// main table); the walk ends at the first table whose routes cover every destination (a default
    /// route, or both halves) and at a rule that drops all traffic. Without any rules, the main table.
    static func trafficRoutes(
        routes: [Netlink.Route], rules: [Netlink.Rule], links: [Int32: Netlink.Link],
        uid: UInt32
    ) -> [Route] {
        var out: [Route] = []
        for family in [Netlink.inet, Netlink.inet6] {
            // The kernel dumps rules in priority order; sorted again, keeping that order among equals.
            let familyRules = rules.enumerated().filter { $0.element.family == family }
                .sorted { ($0.element.priority, $0.offset) < ($1.element.priority, $1.offset) }.map(\.element)
            let walk =
                familyRules.isEmpty
                ? [Netlink.Rule(family: family, priority: 0, table: Netlink.mainTable, action: Netlink.toTable)]
                : familyRules
            for rule in walk where rule.applies(uid: uid) {
                guard rule.action == Netlink.toTable else {
                    if Netlink.dropActions.contains(rule.action) { break }
                    continue  // goto, nop: rare, not followed
                }
                let candidates = routes.filter {
                    $0.family == family && $0.table == rule.table && $0.type == Netlink.unicast
                        && $0.prefixLength > (rule.suppressPrefixLength ?? -1)
                }
                var captured: [Route] = []
                for route in candidates {
                    guard let destination = Netlink.address(route.destination, family: family) else { continue }
                    for index in route.interfaces {
                        let link = links[index]
                        let r = Route(
                            destination: destination, prefixLength: route.prefixLength,
                            interface: link?.name ?? "", tunnelDevice: link?.isTunnel ?? false)
                        if r.capturesAllTraffic { captured.append(r) }
                    }
                }
                out += captured
                if Netlink.coversEverything(captured) { break }
            }
        }
        return out
    }

    #if os(Linux)
    static func linuxTrafficRoutes() -> [Route] {
        var routes: [Netlink.Route] = []
        var rules: [Netlink.Rule] = []
        var links: [Int32: Netlink.Link] = [:]
        let read = Netlink.dump(Netlink.getRoute) { type, body in
            if type == Netlink.newRoute, let r = Netlink.Route(body), r.prefixLength <= maxCapturingPrefix { routes.append(r) }
        }
        guard read else { return [] }
        _ = Netlink.dump(Netlink.getRule) { type, body in
            if type == Netlink.newRule, let r = Netlink.Rule(body) { rules.append(r) }
        }
        _ = Netlink.dump(Netlink.getLink) { type, body in
            if type == Netlink.newLink, let l = Netlink.Link(body) { links[l.index] = l }
        }
        return trafficRoutes(routes: routes, rules: rules, links: links, uid: getuid())
    }
    #endif
}

extension Netlink {
    /// The routes, all of which capture all traffic, leave no destination to a later table: a default
    /// route, or both halves of the address space.
    static func coversEverything(_ routes: [RoutingTable.Route]) -> Bool {
        let covered = Set(routes.map { "\($0.destination)/\($0.prefixLength)" })
        return routes.contains { $0.prefixLength == 0 } || covered.isSuperset(of: ["0.0.0.0/1", "128.0.0.0/1"])
            || covered.isSuperset(of: ["::/1", "8000::/1"])
    }
}

/// Finds another VPN that already routes all traffic, before a profile that does the same connects:
/// OpenVPN would fail to add its routes ("File exists"), the DNS hook would refuse, and on disconnect
/// OpenVPN would delete the other tunnel's `0/1` and `128/1` routes.
public enum FullTunnelCheck {
    #if os(Linux)
    static let vpnInterfacePrefixes = ["utun", "ppp", "ipsec", "tun", "tap", "wg", "tailscale"]
    #else
    static let vpnInterfacePrefixes = ["utun", "ppp", "ipsec", "tun", "tap"]
    #endif

    public static func isVPNInterface(_ name: String) -> Bool {
        vpnInterfacePrefixes.contains { name.hasPrefix($0) && name.dropFirst($0.count).allSatisfy(\.isNumber) }
    }

    /// The VPN interface that carries all traffic, unless it belongs to `own` (PassTunnel's sessions).
    /// A VPN interface has a VPN's name (`isVPNInterface`) or, on Linux, is a tunnel device.
    public static func foreignFullTunnel(in routes: [RoutingTable.Route], own: Set<String>) -> String? {
        routes.first {
            $0.capturesAllTraffic && !$0.scoped && ($0.tunnelDevice || isVPNInterface($0.interface)) && !own.contains($0.interface)
        }?.interface
    }
}
