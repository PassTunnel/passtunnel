import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// rtnetlink, Linux's interface to the routing tables (`linux/netlink.h`, `linux/rtnetlink.h`,
/// `linux/if_link.h`, `linux/fib_rules.h`): the dump requests and the messages they return. Parsing
/// is plain byte handling in host order, so it builds and is tested on every platform; only the
/// socket is Linux's.
public enum Netlink {
    public static let headerSize = 16  // struct nlmsghdr
    public static let error: UInt16 = 2  // NLMSG_ERROR
    public static let done: UInt16 = 3  // NLMSG_DONE
    public static let request: UInt16 = 0x1  // NLM_F_REQUEST
    public static let dumpFlags: UInt16 = 0x300  // NLM_F_DUMP
    public static let newLink: UInt16 = 16, getLink: UInt16 = 18
    public static let newRoute: UInt16 = 24, getRoute: UInt16 = 26
    public static let newRule: UInt16 = 32, getRule: UInt16 = 34
    /// Linux's address families (Darwin's AF_INET6 is 30).
    public static let inet: UInt8 = 2, inet6: UInt8 = 10
    public static let mainTable: UInt32 = 254
    public static let unicast: UInt8 = 1  // RTN_UNICAST
    public static let toTable: UInt8 = 1  // FR_ACT_TO_TBL
    /// FR_ACT_BLACKHOLE, FR_ACT_UNREACHABLE, FR_ACT_PROHIBIT: nothing after such a rule is reached.
    public static let dropActions: Set<UInt8> = [6, 7, 8]
    /// Link kinds (`IFLA_INFO_KIND`) of tunnel devices: tun and tap, ppp, WireGuard, OpenVPN's data
    /// channel offload (out of tree and in the kernel), IPsec interfaces.
    public static let tunnelKinds: Set<String> = ["tun", "ppp", "wireguard", "ovpn-dco", "ovpn", "xfrm", "vti", "vti6"]

    public struct Route: Equatable {
        /// One way out of a route: the interface and the next hop's address on it (`RTA_GATEWAY`; empty for a
        /// route to the interface itself).
        public struct NextHop: Equatable {
            public var interface: Int32
            public var gateway: [UInt8]

            public init(interface: Int32, gateway: [UInt8] = []) {
                self.interface = interface
                self.gateway = gateway
            }
        }

        public var family: UInt8
        public var destination: [UInt8]  // network order; empty for a default route
        public var prefixLength: Int
        public var table: UInt32
        public var type: UInt8
        /// RTA_OIF with RTA_GATEWAY, or each next hop of RTA_MULTIPATH; none for a route without an output
        /// interface (an IPv4 `unreachable` route).
        public var nextHops: [NextHop]
        /// RTA_PRIORITY: the metric. Of two routes of a destination the kernel uses the lower.
        public var priority: UInt32
        /// The source selector (`rtm_src_len`, RTA_SRC): a route `from <prefix>` (IPv6 source-specific
        /// routing) applies only to traffic from that prefix. 0 (and no source) for every other route.
        public var sourceLength: Int = 0
        public var source: [UInt8] = []

        /// Output interfaces (RTA_OIF, or each next hop of RTA_MULTIPATH).
        public var interfaces: [Int32] { nextHops.map(\.interface) }

        public init(
            family: UInt8, destination: [UInt8], prefixLength: Int, table: UInt32, type: UInt8, interfaces: [Int32] = [],
            priority: UInt32 = 0
        ) {
            self.init(
                family: family, destination: destination, prefixLength: prefixLength, table: table, type: type,
                nextHops: interfaces.map { NextHop(interface: $0) }, priority: priority)
        }

        public init(
            family: UInt8, destination: [UInt8], prefixLength: Int, table: UInt32, type: UInt8, nextHops: [NextHop],
            priority: UInt32 = 0, sourceLength: Int = 0, source: [UInt8] = []
        ) {
            self.family = family
            self.destination = destination
            self.prefixLength = prefixLength
            self.table = table
            self.type = type
            self.nextHops = nextHops
            self.priority = priority
            self.sourceLength = sourceLength
            self.source = source
        }
    }

    public struct Rule: Equatable {
        public enum Selector: Equatable {
            case source, destination, tos
            case inputInterface(String)
            case mark(UInt32, mask: UInt32)
            case uidRange(UInt32, UInt32)
            /// Output interface, realms, tunnel id, VRF, IP protocol, ports, DSCP, flow label, …: never
            /// all traffic.
            case other(UInt16)
        }

        public var family: UInt8
        public var priority: UInt32
        public var table: UInt32
        public var action: UInt8
        public var invert = false
        public var suppressPrefixLength: Int?
        public var selectors: [Selector] = []

        public init(
            family: UInt8, priority: UInt32, table: UInt32, action: UInt8, invert: Bool = false, suppressPrefixLength: Int? = nil,
            selectors: [Selector] = []
        ) {
            self.family = family
            self.priority = priority
            self.table = table
            self.action = action
            self.invert = invert
            self.suppressPrefixLength = suppressPrefixLength
            self.selectors = selectors
        }

        /// A packet of a local program, with no mark, to any destination, matches the rule.
        public func applies(uid: UInt32) -> Bool {
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

    public struct Link: Equatable {
        public var index: Int32
        public var name: String
        public var kind: String?

        public init(index: Int32, name: String, kind: String? = nil) {
            self.index = index
            self.name = name
            self.kind = kind
        }

        public var isTunnel: Bool { kind.map(Netlink.tunnelKinds.contains) ?? false }
    }

    /// The messages in `buf` (one datagram or several): type and payload of each, and whether the dump
    /// ended (NLMSG_DONE, or NLMSG_ERROR). A truncated message ends the list.
    public static func messages(_ buf: [UInt8]) -> (messages: [(type: UInt16, body: ArraySlice<UInt8>)], finished: Bool) {
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
    public static func attributes(_ body: ArraySlice<UInt8>, from start: Int) -> [(type: UInt16, value: ArraySlice<UInt8>)] {
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

    public static func align(_ n: Int) -> Int { (n + 3) & ~3 }

    public static func u16<C: RandomAccessCollection>(_ b: C, _ i: Int) -> UInt16 where C.Element == UInt8, C.Index == Int {
        UInt16(b[i]) | UInt16(b[i + 1]) << 8
    }

    public static func u32<C: RandomAccessCollection>(_ b: C, _ i: Int) -> UInt32 where C.Element == UInt8, C.Index == Int {
        UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24
    }

    /// A 32-bit attribute value, if it is one.
    public static func u32(_ value: ArraySlice<UInt8>) -> UInt32? {
        value.count >= 4 ? u32(value, value.startIndex) : nil
    }

    /// A NUL-terminated string attribute.
    public static func string(_ value: ArraySlice<UInt8>) -> String {
        String(decoding: value.prefix { $0 != 0 }, as: UTF8.self)
    }

    /// `destination` as `inet_ntop` writes it ("0.0.0.0", "8000::"); empty means the default route.
    public static func address(_ destination: [UInt8], family: UInt8) -> String? {
        let size = family == inet ? 4 : 16
        guard destination.isEmpty || destination.count == size else { return nil }
        var bytes = destination.isEmpty ? [UInt8](repeating: 0, count: size) : destination
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let af = family == inet ? AF_INET : AF_INET6
        guard inet_ntop(af, &bytes, &text, socklen_t(text.count)) != nil else { return nil }
        return String(cString: text)
    }
}

extension Netlink.Route {
    /// `RTN_BLACKHOLE`, `RTN_UNREACHABLE`, `RTN_PROHIBIT`: a route that refuses its traffic.
    public static let rejectTypes: Set<UInt8> = [6, 7, 8]

    /// An RTM_NEWROUTE payload: `struct rtmsg` (family, dst_len, src_len, tos, table, protocol, scope,
    /// type, flags), then RTA_DST, RTA_SRC, RTA_OIF, RTA_GATEWAY, RTA_PRIORITY, RTA_MULTIPATH (each next
    /// hop's interface and RTA_GATEWAY) and RTA_TABLE among the attributes. Cached routes (RTM_F_CLONED)
    /// and those of other families are left out.
    public init?(_ body: ArraySlice<UInt8>) {
        guard body.count >= 12 else { return nil }
        let s = body.startIndex
        family = body[s]
        guard family == Netlink.inet || family == Netlink.inet6, Netlink.u32(body, s + 8) & 0x200 == 0 else { return nil }
        prefixLength = Int(body[s + 1])
        sourceLength = Int(body[s + 2])
        table = UInt32(body[s + 4])
        type = body[s + 7]
        destination = []
        nextHops = []
        priority = 0
        var oif: Int32?
        var gateway: [UInt8] = []
        var multipath: [NextHop] = []
        for (attribute, value) in Netlink.attributes(body, from: s + 12) {
            switch attribute {
            case 1: destination = Array(value)  // RTA_DST
            case 2: source = Array(value)  // RTA_SRC
            case 4: if let i = Netlink.u32(value) { oif = Int32(bitPattern: i) }  // RTA_OIF
            case 5: gateway = Array(value)  // RTA_GATEWAY
            case 6: priority = Netlink.u32(value) ?? 0  // RTA_PRIORITY
            case 15: if let t = Netlink.u32(value) { table = t }  // RTA_TABLE
            case 9:  // RTA_MULTIPATH
                // struct rtnexthop: length, flags, hops, ifindex, then the hop's own attributes.
                var offset = value.startIndex
                while offset + 8 <= value.endIndex {
                    let length = Int(Netlink.u16(value, offset))
                    guard length >= 8, offset + length <= value.endIndex else { break }
                    var hop = NextHop(interface: Int32(bitPattern: Netlink.u32(value, offset + 4)))
                    for (inner, data) in Netlink.attributes(value[..<(offset + length)], from: offset + 8) where inner == 5 {
                        hop.gateway = Array(data)
                    }
                    multipath.append(hop)
                    offset += Netlink.align(length)
                }
            default: break
            }
        }
        if let oif { nextHops.append(NextHop(interface: oif, gateway: gateway)) }
        nextHops += multipath
    }
}

extension Netlink.Rule {
    /// An RTM_NEWRULE payload: `struct fib_rule_hdr` (family, dst_len, src_len, tos, table, two reserved
    /// bytes, action, flags), then the FRA_* attributes.
    public init?(_ body: ArraySlice<UInt8>) {
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
    public init?(_ body: ArraySlice<UInt8>) {
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
    public static let afNetlink: Int32 = 16  // AF_NETLINK
    public static let routeProtocol: Int32 = 0  // NETLINK_ROUTE

    /// Sends one dump request (`type`, every family) to the kernel on a new socket and hands each
    /// message of the reply to `each`, until the dump ends. False when the socket fails, the kernel
    /// answers with an error or says nothing for 2 s. Needs no privileges.
    public static func dump(_ type: UInt16, each: (UInt16, ArraySlice<UInt8>) -> Void) -> Bool {
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
    public static func firstError(_ buf: [UInt8]) -> Int32? {
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

extension KernelRoute {
    /// The main table's routes of an rtnetlink dump as the hook compares them with its own (Linux's
    /// `OpenConnectSystem.routes`), the preferred first: by metric (`RTA_PRIORITY`), the kernel's order among
    /// equals kept. One entry per next hop of a route; `name` gives an interface index's name. A
    /// `blackhole`, `unreachable` or `prohibit` route is a reject route. A source-specific route (`from
    /// <prefix>`) is marked as such (`KernelRoute.sourceSpecific`): it applies only to some traffic, so it is
    /// never a default gateway, a route in the way, nor one the hook made. Linux has no scoped or cloned routes in
    /// the main table (cached ones are left out of the dump), and a route whose destination has host bits set is
    /// left out, as the Mac's reader does.
    public static func linux(_ routes: [Netlink.Route], name: (Int32) -> String?) -> [KernelRoute] {
        var out: [(priority: UInt32, route: KernelRoute)] = []
        for route in routes where route.table == Netlink.mainTable {
            let size = route.family == Netlink.inet ? 4 : 16
            guard route.destination.isEmpty || route.destination.count == size,
                let destination = IPAddress(bytes: route.destination.isEmpty ? [UInt8](repeating: 0, count: size) : route.destination),
                let network = IPNetwork(address: destination, prefixLength: route.prefixLength), network.address == destination
            else { continue }
            let reject = Netlink.Route.rejectTypes.contains(route.type)
            let hops = route.nextHops.isEmpty ? [Netlink.Route.NextHop(interface: 0)] : route.nextHops
            for hop in hops {
                let gateway = hop.gateway.count == size ? IPAddress(bytes: hop.gateway) : nil
                let interface = hop.interface > 0 ? name(hop.interface) ?? "" : ""
                out.append(
                    (
                        route.priority,
                        KernelRoute(
                            network: network, gateway: reject ? nil : gateway, interface: interface, reject: reject,
                            sourceSpecific: route.sourceLength > 0 || !route.source.isEmpty)
                    ))
            }
        }
        // A stable sort: `sorted` is not guaranteed to keep the order of equals.
        return out.enumerated().sorted { ($0.element.priority, $0.offset) < ($1.element.priority, $1.offset) }.map(\.element.route)
    }
}
