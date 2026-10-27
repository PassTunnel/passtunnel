import Foundation

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

/// rtnetlink, Linux's interface to the routing tables (`linux/netlink.h`, `linux/rtnetlink.h`,
/// `linux/if_link.h`, `linux/fib_rules.h`): the dump requests and the messages they return. Parsing
/// is plain byte handling in host order, so it builds and is tested on every platform; only the
/// socket is Linux's.
enum Netlink {
    static let headerSize = 16  // struct nlmsghdr
    static let error: UInt16 = 2  // NLMSG_ERROR
    static let done: UInt16 = 3  // NLMSG_DONE
    static let request: UInt16 = 0x1  // NLM_F_REQUEST
    static let dumpFlags: UInt16 = 0x300  // NLM_F_DUMP
    static let newLink: UInt16 = 16, getLink: UInt16 = 18
    static let newRoute: UInt16 = 24, getRoute: UInt16 = 26
    static let newRule: UInt16 = 32, getRule: UInt16 = 34
    /// Linux's address families (Darwin's AF_INET6 is 30).
    static let inet: UInt8 = 2, inet6: UInt8 = 10
    static let mainTable: UInt32 = 254
    static let unicast: UInt8 = 1  // RTN_UNICAST
    static let toTable: UInt8 = 1  // FR_ACT_TO_TBL
    /// FR_ACT_BLACKHOLE, FR_ACT_UNREACHABLE, FR_ACT_PROHIBIT: nothing after such a rule is reached.
    static let dropActions: Set<UInt8> = [6, 7, 8]
    /// Link kinds (`IFLA_INFO_KIND`) of tunnel devices: tun and tap, ppp, WireGuard, OpenVPN's data
    /// channel offload (out of tree and in the kernel), IPsec interfaces.
    static let tunnelKinds: Set<String> = ["tun", "ppp", "wireguard", "ovpn-dco", "ovpn", "xfrm", "vti", "vti6"]

    struct Route: Equatable {
        var family: UInt8
        var destination: [UInt8]  // network order; empty for a default route
        var prefixLength: Int
        var table: UInt32
        var type: UInt8
        /// Output interfaces (RTA_OIF, or each next hop of RTA_MULTIPATH).
        var interfaces: [Int32]
    }

    struct Rule: Equatable {
        enum Selector: Equatable {
            case source, destination, tos
            case inputInterface(String)
            case mark(UInt32, mask: UInt32)
            case uidRange(UInt32, UInt32)
            /// Output interface, realms, tunnel id, VRF, IP protocol, ports, DSCP, flow label, …: never
            /// all traffic.
            case other(UInt16)
        }

        var family: UInt8
        var priority: UInt32
        var table: UInt32
        var action: UInt8
        var invert = false
        var suppressPrefixLength: Int?
        var selectors: [Selector] = []

        /// A packet of a local program, with no mark, to any destination, matches the rule.
        func applies(uid: UInt32) -> Bool {
            let matches = selectors.allSatisfy { selector in
                switch selector {
                case .inputInterface(let name): return name == "lo"  // locally generated traffic
                case .mark(let mark, let mask): return mark & mask == 0
                case .uidRange(let start, let end): return (start...max(start, end)).contains(uid)
                case .source, .destination, .tos, .other: return false
                }
            }
            return invert ? !matches : matches
        }
    }

    struct Link: Equatable {
        var index: Int32
        var name: String
        var kind: String?

        var isTunnel: Bool { kind.map(Netlink.tunnelKinds.contains) ?? false }
    }

    /// The messages in `buf` (one datagram or several): type and payload of each, and whether the dump
    /// ended (NLMSG_DONE, or NLMSG_ERROR). A truncated message ends the list.
    static func messages(_ buf: [UInt8]) -> (messages: [(type: UInt16, body: ArraySlice<UInt8>)], finished: Bool) {
        var out: [(type: UInt16, body: ArraySlice<UInt8>)] = []
        var offset = 0
        while offset + headerSize <= buf.count {
            let length = Int(u32(buf, offset))
            guard length >= headerSize, offset + length <= buf.count else { break }
            let type = u16(buf, offset + 4)
            if type == done || type == error { return (out, true) }
            out.append((type, buf[(offset + headerSize)..<(offset + length)]))
            offset += align(length)
        }
        return (out, false)
    }

    /// Attributes (`struct rtattr` / `nlattr`) from `start` to the end of `body`: type (without the
    /// nested and byte-order flags) and value.
    static func attributes(_ body: ArraySlice<UInt8>, from start: Int) -> [(type: UInt16, value: ArraySlice<UInt8>)] {
        var out: [(type: UInt16, value: ArraySlice<UInt8>)] = []
        var offset = start
        while offset + 4 <= body.endIndex {
            let length = Int(u16(body, offset))
            guard length >= 4, offset + length <= body.endIndex else { break }
            out.append((u16(body, offset + 2) & 0x3FFF, body[(offset + 4)..<(offset + length)]))
            offset += align(length)
        }
        return out
    }

    static func align(_ n: Int) -> Int { (n + 3) & ~3 }

    static func u16<C: RandomAccessCollection>(_ b: C, _ i: Int) -> UInt16 where C.Element == UInt8, C.Index == Int {
        UInt16(b[i]) | UInt16(b[i + 1]) << 8
    }

    static func u32<C: RandomAccessCollection>(_ b: C, _ i: Int) -> UInt32 where C.Element == UInt8, C.Index == Int {
        UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24
    }

    /// A 32-bit attribute value, if it is one.
    static func u32(_ value: ArraySlice<UInt8>) -> UInt32? {
        value.count >= 4 ? u32(value, value.startIndex) : nil
    }

    /// A NUL-terminated string attribute.
    static func string(_ value: ArraySlice<UInt8>) -> String {
        String(decoding: value.prefix { $0 != 0 }, as: UTF8.self)
    }

    /// `destination` as `inet_ntop` writes it ("0.0.0.0", "8000::"); empty means the default route.
    static func address(_ destination: [UInt8], family: UInt8) -> String? {
        let size = family == inet ? 4 : 16
        guard destination.isEmpty || destination.count == size else { return nil }
        var bytes = destination.isEmpty ? [UInt8](repeating: 0, count: size) : destination
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let af = family == inet ? AF_INET : AF_INET6
        guard inet_ntop(af, &bytes, &text, socklen_t(text.count)) != nil else { return nil }
        return String(cString: text)
    }

    /// The routes, all of which capture all traffic, leave no destination to a later table: a default
    /// route, or both halves of the address space.
    static func coversEverything(_ routes: [RoutingTable.Route]) -> Bool {
        let covered = Set(routes.map { "\($0.destination)/\($0.prefixLength)" })
        return routes.contains { $0.prefixLength == 0 } || covered.isSuperset(of: ["0.0.0.0/1", "128.0.0.0/1"])
            || covered.isSuperset(of: ["::/1", "8000::/1"])
    }
}

extension Netlink.Route {
    /// An RTM_NEWROUTE payload: `struct rtmsg` (family, dst_len, src_len, tos, table, protocol, scope,
    /// type, flags), then RTA_DST, RTA_OIF, RTA_MULTIPATH and RTA_TABLE among the attributes. Cached
    /// routes (RTM_F_CLONED) and those of other families are left out.
    init?(_ body: ArraySlice<UInt8>) {
        guard body.count >= 12 else { return nil }
        let s = body.startIndex
        family = body[s]
        guard family == Netlink.inet || family == Netlink.inet6, Netlink.u32(body, s + 8) & 0x200 == 0 else { return nil }
        prefixLength = Int(body[s + 1])
        table = UInt32(body[s + 4])
        type = body[s + 7]
        destination = []
        interfaces = []
        for (attribute, value) in Netlink.attributes(body, from: s + 12) {
            switch attribute {
            case 1: destination = Array(value)  // RTA_DST
            case 4: if let i = Netlink.u32(value) { interfaces.append(Int32(bitPattern: i)) }  // RTA_OIF
            case 15: if let t = Netlink.u32(value) { table = t }  // RTA_TABLE
            case 9:  // RTA_MULTIPATH
                // struct rtnexthop: length, flags, hops, ifindex, then the hop's own attributes.
                var offset = value.startIndex
                while offset + 8 <= value.endIndex {
                    let length = Int(Netlink.u16(value, offset))
                    guard length >= 8, offset + length <= value.endIndex else { break }
                    interfaces.append(Int32(bitPattern: Netlink.u32(value, offset + 4)))
                    offset += Netlink.align(length)
                }
            default: break
            }
        }
    }
}

extension Netlink.Rule {
    /// An RTM_NEWRULE payload: `struct fib_rule_hdr` (family, dst_len, src_len, tos, table, two reserved
    /// bytes, action, flags), then the FRA_* attributes.
    init?(_ body: ArraySlice<UInt8>) {
        guard body.count >= 12 else { return nil }
        let s = body.startIndex
        family = body[s]
        guard family == Netlink.inet || family == Netlink.inet6 else { return nil }
        priority = 0
        table = UInt32(body[s + 4])
        action = body[s + 7]
        invert = Netlink.u32(body, s + 8) & 0x2 != 0  // FIB_RULE_INVERT
        if body[s + 1] > 0 { selectors.append(.destination) }
        if body[s + 2] > 0 { selectors.append(.source) }
        if body[s + 3] != 0 { selectors.append(.tos) }
        var mark: UInt32?
        var mask: UInt32?
        for (attribute, value) in Netlink.attributes(body, from: s + 12) {
            switch attribute {
            case 1, 2, 4, 18, 21: break  // FRA_DST, FRA_SRC (lengths above), FRA_GOTO, FRA_PAD, FRA_PROTOCOL
            case 3: selectors.append(.inputInterface(Netlink.string(value)))  // FRA_IIFNAME
            case 6: priority = Netlink.u32(value) ?? 0  // FRA_PRIORITY
            case 10: mark = Netlink.u32(value)  // FRA_FWMARK
            case 16: mask = Netlink.u32(value)  // FRA_FWMASK
            case 13: break  // FRA_SUPPRESS_IFGROUP
            case 14:  // FRA_SUPPRESS_PREFIXLEN, -1: none
                if let v = Netlink.u32(value), Int32(bitPattern: v) >= 0 { suppressPrefixLength = Int(v) }
            case 15: if let t = Netlink.u32(value) { table = t }  // FRA_TABLE
            case 20:  // FRA_UID_RANGE: start, end
                if value.count >= 8 {
                    selectors.append(.uidRange(Netlink.u32(value, value.startIndex), Netlink.u32(value, value.startIndex + 4)))
                } else {
                    selectors.append(.other(attribute))
                }
            default: selectors.append(.other(attribute))
            }
        }
        if mark != nil || mask != nil {
            let m = mark ?? 0
            selectors.append(.mark(m, mask: mask ?? (m != 0 ? .max : 0)))
        }
    }
}

extension Netlink.Link {
    /// An RTM_NEWLINK payload: `struct ifinfomsg` (family, pad, type, index, flags, change), then
    /// IFLA_IFNAME and IFLA_LINKINFO with its IFLA_INFO_KIND.
    init?(_ body: ArraySlice<UInt8>) {
        guard body.count >= 16 else { return nil }
        index = Int32(bitPattern: Netlink.u32(body, body.startIndex + 4))
        name = ""
        kind = nil
        for (attribute, value) in Netlink.attributes(body, from: body.startIndex + 16) {
            if attribute == 3 { name = Netlink.string(value) }  // IFLA_IFNAME
            if attribute == 18 {  // IFLA_LINKINFO
                for (info, data) in Netlink.attributes(value, from: value.startIndex) where info == 1 {  // IFLA_INFO_KIND
                    kind = Netlink.string(data)
                }
            }
        }
        guard !name.isEmpty else { return nil }
    }
}

#if os(Linux)
extension Netlink {
    static let afNetlink: Int32 = 16  // AF_NETLINK
    static let routeProtocol: Int32 = 0  // NETLINK_ROUTE

    /// Sends one dump request (`type`, every family) to the kernel on a new socket and hands each
    /// message of the reply to `each`, until the dump ends. False when the socket fails, the kernel
    /// answers with an error or says nothing for 2 s. Needs no privileges.
    static func dump(_ type: UInt16, each: (UInt16, ArraySlice<UInt8>) -> Void) -> Bool {
        let fd = socket(afNetlink, Int32(SOCK_RAW.rawValue) | Int32(SOCK_CLOEXEC.rawValue), routeProtocol)
        guard fd >= 0 else { return false }
        defer { _ = Glibc.close(fd) }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        // nlmsghdr (length, type, flags, sequence, port 0: the kernel), then a zeroed rtmsg / fib_rule_hdr
        // (12 bytes) or ifinfomsg (16): AF_UNSPEC, every family. Unaddressed, it goes to the kernel.
        let sequence: UInt32 = 1
        var request = [UInt8](repeating: 0, count: headerSize + (type == getLink ? 16 : 12))
        func put(_ value: UInt32, at offset: Int, bytes: Int) {
            for i in 0..<bytes { request[offset + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
        }
        put(UInt32(request.count), at: 0, bytes: 4)
        put(UInt32(type), at: 4, bytes: 2)
        put(UInt32(Netlink.request | dumpFlags), at: 6, bytes: 2)
        put(sequence, at: 8, bytes: 4)
        guard Glibc.send(fd, request, request.count, 0) == request.count else { return false }
        var buffer = [UInt8](repeating: 0, count: 64 << 10)
        while true {
            let n = recv(fd, &buffer, buffer.count, 0)
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { return false }
            let chunk = Array(buffer[0..<n])
            if let failure = firstError(chunk), failure != 0 { return false }
            let (messages, finished) = Netlink.messages(chunk)
            for message in messages { each(message.type, message.body) }
            if finished { return true }
        }
    }

    /// The error code of an NLMSG_ERROR message in `buf` (0 is an acknowledgement).
    static func firstError(_ buf: [UInt8]) -> Int32? {
        var offset = 0
        while offset + headerSize <= buf.count {
            let length = Int(u32(buf, offset))
            guard length >= headerSize, offset + length <= buf.count else { return nil }
            if u16(buf, offset + 4) == error, length >= headerSize + 4 {
                return Int32(bitPattern: u32(buf, offset + headerSize))
            }
            offset += align(length)
        }
        return nil
    }
}
#endif

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
