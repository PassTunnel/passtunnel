#if canImport(Darwin)
import Darwin
#endif
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// Routing table parsing, the other-VPN check and reading set-up failures from the OpenVPN log.
final class FullTunnelTests: XCTestCase {
    typealias Route = RoutingTable.Route

    // MARK: routing table

    #if os(macOS)
    /// One NET_RT_DUMP record: header, then destination, gateway and a truncated netmask.
    func record(dst: [UInt8], mask: [UInt8]?, index: UInt16, flags: Int32 = RTF_UP | RTF_GATEWAY | RTF_STATIC) -> [UInt8] {
        func sin(_ a: [UInt8], len: Int = 16) -> [UInt8] {
            var b = [UInt8](repeating: 0, count: 16)
            b[0] = UInt8(len); b[1] = UInt8(AF_INET)
            for (i, x) in a.enumerated() { b[4 + i] = x }
            return Array(b.prefix(len))
        }
        func padded(_ b: [UInt8]) -> [UInt8] { b + [UInt8](repeating: 0, count: (4 - b.count % 4) % 4) }
        var body = padded(sin(dst)) + padded(sin([10, 8, 0, 1]))
        var addrs = RTA_DST | RTA_GATEWAY
        if let mask {
            // Netmasks are stored with trailing zero bytes cut off (sa_len 0 for a /0).
            var m = [UInt8](repeating: 0, count: 8)
            for (i, x) in mask.enumerated() { m[4 + i] = x }
            let used = (m.lastIndex { $0 != 0 }).map { $0 + 1 } ?? 0
            var bytes = Array(m.prefix(used))
            if !bytes.isEmpty { bytes[0] = UInt8(used) }
            body += bytes.isEmpty ? [0, 0, 0, 0] : padded(bytes)
            addrs |= RTA_NETMASK
        }
        var hdr = rt_msghdr()
        hdr.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + body.count)
        hdr.rtm_version = UInt8(RTM_VERSION)
        hdr.rtm_type = UInt8(RTM_GET)
        hdr.rtm_index = index
        hdr.rtm_flags = flags
        hdr.rtm_addrs = addrs
        return withUnsafeBytes(of: &hdr) { Array($0) } + body
    }

    func testParsesDestinationsPrefixesAndInterfaces() {
        let lo = UInt16(if_nametoindex("lo0"))
        XCTAssertGreaterThan(lo, 0)
        let buf = record(dst: [0, 0, 0, 0], mask: [128, 0, 0, 0], index: lo)
            + record(dst: [128, 0, 0, 0], mask: [128, 0, 0, 0], index: lo)
            + record(dst: [0, 0, 0, 0], mask: [], index: lo)
            + record(dst: [10, 1, 0, 0], mask: [255, 255, 0, 0], index: lo, flags: RTF_UP | RTF_IFSCOPE)
            + record(dst: [10, 1, 2, 3], mask: nil, index: lo, flags: RTF_UP | RTF_HOST)
        let routes = RoutingTable.parse(buf)
        XCTAssertEqual(routes, [
            Route(destination: "0.0.0.0", prefixLength: 1, interface: "lo0"),
            Route(destination: "128.0.0.0", prefixLength: 1, interface: "lo0"),
            Route(destination: "0.0.0.0", prefixLength: 0, interface: "lo0"),
            Route(destination: "10.1.0.0", prefixLength: 16, interface: "lo0", scoped: true),
            Route(destination: "10.1.2.3", prefixLength: 32, interface: "lo0"),
        ])
        XCTAssertEqual(routes.map(\.capturesAllTraffic), [true, true, true, false, false])
        XCTAssertEqual(RoutingTable.parse(Array(buf.prefix(10))), [], "truncated")
    }

    func testReadsTheLiveTable() {
        // Read-only; every Mac has loopback routes.
        XCTAssertTrue(RoutingTable.ipv4Routes().contains { $0.interface == "lo0" })
    }
    #elseif os(Linux)
    func testReadsTheLiveTables() {
        // Read-only, without privileges; every network namespace has the default rules, a loopback
        // link and its routes in the local table.
        var routes: [Netlink.Route] = []
        var rules: [Netlink.Rule] = []
        var links: [Netlink.Link] = []
        let readRoutes = Netlink.dump(Netlink.getRoute) { type, body in
            if type == Netlink.newRoute, let r = Netlink.Route(body) { routes.append(r) }
        }
        let readRules = Netlink.dump(Netlink.getRule) { type, body in
            if type == Netlink.newRule, let r = Netlink.Rule(body) { rules.append(r) }
        }
        let readLinks = Netlink.dump(Netlink.getLink) { type, body in
            if type == Netlink.newLink, let l = Netlink.Link(body) { links.append(l) }
        }
        XCTAssertTrue(readRoutes && readRules && readLinks)
        XCTAssertTrue(rules.contains { $0.family == Netlink.inet && $0.priority == 32766 && $0.table == Netlink.mainTable },
                      "\(rules)")
        let lo = links.first { $0.name == "lo" }?.index ?? -1
        XCTAssertTrue(routes.contains { $0.table == 255 && $0.interfaces.contains(lo) }, "\(routes)")
        // No VPN in the CI container: its default route goes through an ordinary link.
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: RoutingTable.trafficRoutes(), own: []))
    }
    #endif

    // MARK: Linux routes (rtnetlink, parsed on every platform)

    func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xFF), UInt8(v >> 8)] }
    func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }

    /// `struct rtattr`: length, type, value, padded to 4 bytes.
    func attribute(_ type: UInt16, _ value: [UInt8]) -> [UInt8] {
        let bytes = le16(UInt16(4 + value.count)) + le16(type) + value
        return bytes + [UInt8](repeating: 0, count: (4 - bytes.count % 4) % 4)
    }

    func string(_ s: String) -> [UInt8] { Array(s.utf8) + [0] }

    /// One netlink message: `struct nlmsghdr`, then the payload.
    func message(_ type: UInt16, _ payload: [UInt8], flags: UInt16 = 0x2) -> [UInt8] {
        le32(UInt32(16 + payload.count)) + le16(type) + le16(flags) + le32(1) + le32(4242) + payload
    }

    /// RTM_NEWROUTE: `struct rtmsg` and RTA_TABLE, RTA_DST (unless default), RTA_OIF or RTA_MULTIPATH.
    func route(_ dst: [UInt8], _ prefix: UInt8, family: UInt8 = 2, table: UInt32 = 254, type: UInt8 = 1,
               oif: Int32? = nil, nexthops: [Int32] = [], flags: UInt32 = 0) -> [UInt8] {
        var payload: [UInt8] = [family, prefix, 0, 0, UInt8(min(table, 252)), 3, 0, type] + le32(flags)
        payload += attribute(15, le32(table))
        if !dst.isEmpty { payload += attribute(1, dst) }
        if let oif { payload += attribute(4, le32(UInt32(bitPattern: oif))) }
        if !nexthops.isEmpty {
            let hops = nexthops.flatMap { le16(8) + [0, 0] + le32(UInt32(bitPattern: $0)) }
            payload += attribute(9, hops)
        }
        return message(24, payload)
    }

    /// RTM_NEWRULE: `struct fib_rule_hdr`, FRA_TABLE, FRA_PRIORITY, FRA_SUPPRESS_PREFIXLEN (-1 unless
    /// given), then `extra` attributes.
    func rule(_ family: UInt8 = 2, priority: UInt32, table: UInt32, action: UInt8 = 1, invert: Bool = false,
              suppress: Int32 = -1, extra: [[UInt8]] = []) -> [UInt8] {
        var payload: [UInt8] = [family, 0, 0, 0, UInt8(min(table, 252)), 0, 0, action] + le32(invert ? 2 : 0)
        payload += attribute(15, le32(table)) + attribute(14, le32(UInt32(bitPattern: suppress)))
        if priority != 0 { payload += attribute(6, le32(priority)) }
        return message(32, payload + extra.flatMap { $0 })
    }

    /// The three rules every network namespace starts with, for `family`.
    func defaultRules(_ family: UInt8 = 2) -> [UInt8] {
        rule(family, priority: 0, table: 255) + rule(family, priority: 32766, table: 254)
            + rule(family, priority: 32767, table: 253)
    }

    /// RTM_NEWLINK: `struct ifinfomsg`, IFLA_IFNAME and IFLA_LINKINFO / IFLA_INFO_KIND.
    func link(_ index: Int32, _ name: String, kind: String? = nil) -> [UInt8] {
        var payload: [UInt8] = [0, 0] + le16(1) + le32(UInt32(bitPattern: index)) + le32(0x1043) + le32(0)
        payload += attribute(3, string(name))
        if let kind { payload += attribute(18, attribute(1, string(kind))) }
        return message(16, payload)
    }

    static let done: [UInt8] = [20, 0, 0, 0, 3, 0, 2, 0, 1, 0, 0, 0, 0x92, 0x10, 0, 0, 0, 0, 0, 0]

    /// A laptop's links: loopback, Wi-Fi, Docker's bridge, and the VPNs and the modem the cases use.
    var links: [UInt8] {
        link(1, "lo") + link(2, "wlp2s0") + link(3, "docker0", kind: "bridge") + link(4, "tun0", kind: "tun")
            + link(5, "wg0", kind: "wireguard") + link(6, "tailscale0", kind: "tun") + link(7, "acme", kind: "wireguard")
            + link(8, "ppp0", kind: "ppp") + link(9, "wwan0", kind: "wwan")
    }

    /// Parses dumps the way the Linux reader does (routes with a prefix of at most 4 bits), then
    /// follows the rules.
    func traffic(routes: [UInt8], rules: [UInt8], uid: UInt32 = 1000) -> [Route] {
        var parsedRoutes: [Netlink.Route] = [], parsedRules: [Netlink.Rule] = [], parsedLinks: [Int32: Netlink.Link] = [:]
        for (type, body) in Netlink.messages(routes + Self.done).messages where type == Netlink.newRoute {
            if let r = Netlink.Route(body), r.prefixLength <= RoutingTable.maxCapturingPrefix { parsedRoutes.append(r) }
        }
        for (type, body) in Netlink.messages(rules + Self.done).messages where type == Netlink.newRule {
            if let r = Netlink.Rule(body) { parsedRules.append(r) }
        }
        for (type, body) in Netlink.messages(links + Self.done).messages where type == Netlink.newLink {
            if let l = Netlink.Link(body) { parsedLinks[l.index] = l }
        }
        return RoutingTable.trafficRoutes(routes: parsedRoutes, rules: parsedRules, links: parsedLinks, uid: uid)
    }

    /// The Wi-Fi's routes in the main table: default, its subnet, and loopback in the local table.
    var mainTable: [UInt8] {
        route([], 0, oif: 2) + route([192, 168, 1, 0], 24, oif: 2)
            + route([127, 0, 0, 0], 8, table: 255, type: 2, oif: 1)
    }

    func testMessagesAndAttributes() {
        let buf = link(1, "lo") + link(4, "tun0", kind: "tun") + Self.done + link(9, "after")
        let (messages, finished) = Netlink.messages(buf)
        XCTAssertTrue(finished)
        XCTAssertEqual(messages.map(\.type), [16, 16])
        XCTAssertEqual(messages.compactMap { Netlink.Link($0.body) },
                       [Netlink.Link(index: 1, name: "lo"), Netlink.Link(index: 4, name: "tun0", kind: "tun")])
        XCTAssertFalse(Netlink.messages(Array(buf.prefix(30))).finished, "more to come")
        XCTAssertEqual(Netlink.messages(Array(buf.prefix(30))).messages.count, 0, "truncated message")
        XCTAssertEqual(Netlink.messages([]).messages.count, 0)
        // A bad attribute length ends the attributes, not the parse.
        let header: [UInt8] = [0, 0] + le16(1) + le32(5) + le32(0) + le32(0)
        let broken: [UInt8] = le16(200) + le16(3) + [1, 2, 3, 4]
        let bad = message(16, header + attribute(3, string("eth0")) + broken)
        XCTAssertEqual(Netlink.messages(bad).messages.compactMap { Netlink.Link($0.body) }, [Netlink.Link(index: 5, name: "eth0")])
    }

    func testParsesRoutesAndRules() throws {
        let routes = Netlink.messages(route([], 0, oif: 2) + route([10, 8, 0, 0], 24, oif: 4)
                                      + route([0x20] + [UInt8](repeating: 0, count: 15), 4, family: 10, table: 254, oif: 4)
                                      + route([], 0, table: 51820, nexthops: [5, 7])
                                      + route([], 0, oif: 2, flags: 0x200)          // cached
                                      + route([], 0, family: 28, oif: 2)).messages          // AF_MPLS
            .compactMap { Netlink.Route($0.body) }
        XCTAssertEqual(routes, [
            Netlink.Route(family: 2, destination: [], prefixLength: 0, table: 254, type: 1, interfaces: [2]),
            Netlink.Route(family: 2, destination: [10, 8, 0, 0], prefixLength: 24, table: 254, type: 1, interfaces: [4]),
            Netlink.Route(family: 10, destination: [0x20] + [UInt8](repeating: 0, count: 15), prefixLength: 4, table: 254,
                          type: 1, interfaces: [4]),
            Netlink.Route(family: 2, destination: [], prefixLength: 0, table: 51820, type: 1, interfaces: [5, 7]),
        ])
        XCTAssertEqual(Netlink.address([], family: 2), "0.0.0.0")
        XCTAssertEqual(Netlink.address([128, 0, 0, 0], family: 2), "128.0.0.0")
        XCTAssertEqual(Netlink.address([0x80] + [UInt8](repeating: 0, count: 15), family: 10), "8000::")
        XCTAssertEqual(Netlink.address([], family: 10), "::")
        XCTAssertNil(Netlink.address([1, 2, 3], family: 2))

        let rules = Netlink.messages(
            rule(priority: 32764, table: 254, suppress: 0)
            + rule(priority: 32765, table: 51820, invert: true, extra: [attribute(10, le32(0xCA6C))])
            + rule(priority: 5210, table: 254, extra: [attribute(10, le32(0x80000)), attribute(16, le32(0xFF0000))])
            + rule(priority: 100, table: 100, extra: [attribute(20, le32(1000) + le32(1999)), attribute(3, string("lo"))])
            + rule(priority: 200, table: 200, extra: [attribute(17, string("wlp2s0")), attribute(22, [6])])
            + rule(10, priority: 0, table: 255)).messages.compactMap { Netlink.Rule($0.body) }
        XCTAssertEqual(rules, [
            Netlink.Rule(family: 2, priority: 32764, table: 254, action: 1, suppressPrefixLength: 0),
            Netlink.Rule(family: 2, priority: 32765, table: 51820, action: 1, invert: true,
                         selectors: [.mark(0xCA6C, mask: .max)]),
            Netlink.Rule(family: 2, priority: 5210, table: 254, action: 1, selectors: [.mark(0x80000, mask: 0xFF0000)]),
            Netlink.Rule(family: 2, priority: 100, table: 100, action: 1, selectors: [.uidRange(1000, 1999), .inputInterface("lo")]),
            Netlink.Rule(family: 2, priority: 200, table: 200, action: 1, selectors: [.other(17), .other(22)]),
            Netlink.Rule(family: 10, priority: 0, table: 255, action: 1),
        ])
        XCTAssertTrue(rules[1].applies(uid: 1000), "not fwmark: ordinary traffic has no mark")
        XCTAssertFalse(rules[2].applies(uid: 1000), "marked traffic only")
        XCTAssertTrue(rules[3].applies(uid: 1500))
        XCTAssertFalse(rules[3].applies(uid: 2000))
        XCTAssertFalse(rules[4].applies(uid: 1000), "bound to an interface, one protocol")
    }

    func testPlainMachineHasNoForeignTunnel() {
        let routes = traffic(routes: mainTable, rules: defaultRules())
        XCTAssertEqual(routes, [Route(destination: "0.0.0.0", prefixLength: 0, interface: "wlp2s0")])
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: routes, own: []))
        XCTAssertEqual(traffic(routes: mainTable, rules: []), routes, "without rules: the main table")
    }

    /// Another OpenVPN client with `redirect-gateway def1`: 0/1 and 128/1 through its tun device.
    func testOtherOpenVPNInTheMainTable() {
        let table = mainTable + route([], 1, oif: 4) + route([128, 0, 0, 0], 1, oif: 4) + route([10, 8, 0, 0], 24, oif: 4)
        let routes = traffic(routes: table, rules: defaultRules())
        XCTAssertEqual(routes.map(\.interface), ["wlp2s0", "tun0", "tun0"])
        XCTAssertEqual(FullTunnelCheck.foreignFullTunnel(in: routes, own: []), "tun0")
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: routes, own: ["tun0"]), "one of PassTunnel's sessions")
    }

    /// wg-quick: the main table without its default route (`suppress_prefixlength 0`), then every
    /// packet without wg-quick's mark through table 51820, whose default route is the WireGuard link.
    func testWireGuardThroughPolicyRules() {
        let wgRules = rule(priority: 0, table: 255) + rule(priority: 32764, table: 254, suppress: 0)
            + rule(priority: 32765, table: 51820, invert: true, extra: [attribute(10, le32(0xCA6C))])
            + rule(priority: 32766, table: 254) + rule(priority: 32767, table: 253)
        let routes = traffic(routes: mainTable + route([], 0, table: 51820, oif: 5), rules: wgRules)
        XCTAssertEqual(routes, [Route(destination: "0.0.0.0", prefixLength: 0, interface: "wg0", tunnelDevice: true)])
        XCTAssertEqual(FullTunnelCheck.foreignFullTunnel(in: routes, own: []), "wg0")
        // Named freely, it is still a WireGuard device.
        let named = traffic(routes: mainTable + route([], 0, table: 51820, oif: 7), rules: wgRules)
        XCTAssertEqual(FullTunnelCheck.foreignFullTunnel(in: named, own: []), "acme")
        // A rule for marked packets only does not take ordinary traffic there.
        let marked = rule(priority: 32765, table: 51820, extra: [attribute(10, le32(0xCA6C))]) + defaultRules()
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: traffic(routes: mainTable + route([], 0, table: 51820, oif: 5),
                                                                    rules: marked), own: []))
    }

    /// Tailscale: table 52 is looked up before main; with an exit node it holds a default route.
    func testTailscaleExitNode() {
        let tsRules = rule(priority: 0, table: 255)
            + rule(priority: 5210, table: 254, extra: [attribute(10, le32(0x80000)), attribute(16, le32(0xFF0000))])
            + rule(priority: 5230, table: 253, extra: [attribute(10, le32(0x80000)), attribute(16, le32(0xFF0000))])
            + rule(priority: 5250, table: 0, action: 7, extra: [attribute(10, le32(0x80000)), attribute(16, le32(0xFF0000))])
            + rule(priority: 5270, table: 52) + rule(priority: 32766, table: 254) + rule(priority: 32767, table: 253)
        let tailnet = route([100, 64, 0, 0], 10, table: 52, oif: 6) + route([100, 100, 100, 100], 32, table: 52, oif: 6)
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: traffic(routes: mainTable + tailnet, rules: tsRules), own: []))
        let exit = traffic(routes: mainTable + tailnet + route([], 0, table: 52, oif: 6), rules: tsRules)
        XCTAssertEqual(exit, [Route(destination: "0.0.0.0", prefixLength: 0, interface: "tailscale0", tunnelDevice: true)])
        XCTAssertEqual(FullTunnelCheck.foreignFullTunnel(in: exit, own: []), "tailscale0")
    }

    func testRulesOrderUidsAndDrops() {
        let vpnTable = route([], 0, table: 100, oif: 8)
        // Looked up only after main, which already has a default route.
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: traffic(routes: mainTable + vpnTable,
                                                                    rules: defaultRules() + rule(priority: 32800, table: 100)),
                                                       own: []))
        // Per user: only for uids 1000-1000.
        let perUser = rule(priority: 100, table: 100, extra: [attribute(20, le32(1000) + le32(1000))]) + defaultRules()
        XCTAssertEqual(FullTunnelCheck.foreignFullTunnel(in: traffic(routes: mainTable + vpnTable, rules: perUser, uid: 1000),
                                                         own: []), "ppp0")
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: traffic(routes: mainTable + vpnTable, rules: perUser, uid: 1001),
                                                       own: []))
        // Locally generated traffic (`iif lo`) counts; another input interface does not.
        let local = rule(priority: 100, table: 100, extra: [attribute(3, string("lo"))]) + defaultRules()
        XCTAssertEqual(FullTunnelCheck.foreignFullTunnel(in: traffic(routes: mainTable + vpnTable, rules: local), own: []), "ppp0")
        let forwarded = rule(priority: 100, table: 100, extra: [attribute(3, string("docker0"))]) + defaultRules()
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: traffic(routes: mainTable + vpnTable, rules: forwarded), own: []))
        // A rule that drops all traffic ends the walk.
        let blackhole = rule(priority: 50, table: 0, action: 6) + rule(priority: 100, table: 100) + defaultRules()
        XCTAssertEqual(traffic(routes: mainTable + vpnTable, rules: blackhole), [])
        // Unreachable and other non-unicast routes are not paths.
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(
            in: traffic(routes: route([], 0, table: 100, type: 7, oif: 8) + mainTable,
                        rules: rule(priority: 100, table: 100) + defaultRules()), own: []))
    }

    func testIPv6AndMultipath() {
        let v6Main = route([], 0, family: 10, oif: 2)
            + route([0x20] + [UInt8](repeating: 0, count: 15), 4, family: 10, oif: 4)
            + route([0x30] + [UInt8](repeating: 0, count: 15), 4, family: 10, oif: 4)
        let routes = traffic(routes: mainTable + v6Main, rules: defaultRules() + defaultRules(10))
        XCTAssertEqual(routes.map { "\($0.destination)/\($0.prefixLength) \($0.interface)" },
                       ["0.0.0.0/0 wlp2s0", "::/0 wlp2s0", "2000::/4 tun0", "3000::/4 tun0"])
        XCTAssertEqual(FullTunnelCheck.foreignFullTunnel(in: routes, own: []), "tun0")
        // A default route over two links, one of them a tunnel.
        let multipath = traffic(routes: route([], 0, nexthops: [2, 4]), rules: defaultRules())
        XCTAssertEqual(multipath.map(\.interface), ["wlp2s0", "tun0"])
        XCTAssertEqual(FullTunnelCheck.foreignFullTunnel(in: multipath, own: []), "tun0")
    }

    func testInterfaceKinds() {
        XCTAssertTrue(Netlink.Link(index: 1, name: "tun0", kind: "tun").isTunnel)
        XCTAssertTrue(Netlink.Link(index: 1, name: "vpn0", kind: "tun").isTunnel, "openconnect's name, a tun device")
        XCTAssertTrue(Netlink.Link(index: 1, name: "ppp0", kind: "ppp").isTunnel)
        XCTAssertTrue(Netlink.Link(index: 1, name: "tun1", kind: "ovpn-dco").isTunnel)
        XCTAssertFalse(Netlink.Link(index: 1, name: "wwan0", kind: "wwan").isTunnel, "a modem, not a VPN")
        XCTAssertFalse(Netlink.Link(index: 1, name: "eth0", kind: "veth").isTunnel)
        XCTAssertFalse(Netlink.Link(index: 1, name: "enp0s31f6").isTunnel)
        // A raw-IP modem with the default route is not another VPN.
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: traffic(routes: route([], 0, oif: 9), rules: defaultRules()), own: []))
        #if os(Linux)
        XCTAssertTrue(FullTunnelCheck.isVPNInterface("wg0"))
        XCTAssertTrue(FullTunnelCheck.isVPNInterface("tailscale0"))
        XCTAssertFalse(FullTunnelCheck.isVPNInterface("wlp2s0"))
        #else
        XCTAssertFalse(FullTunnelCheck.isVPNInterface("wg0"), "the Mac's names are unchanged")
        #endif
    }

    // MARK: other VPN

    func testForeignFullTunnel() {
        let other = [Route(destination: "0.0.0.0", prefixLength: 0, interface: "en0"),
                     Route(destination: "0.0.0.0", prefixLength: 1, interface: "utun4"),
                     Route(destination: "128.0.0.0", prefixLength: 1, interface: "utun4")]
        XCTAssertEqual(FullTunnelCheck.foreignFullTunnel(in: other, own: []), "utun4")
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: other, own: ["utun4"]), "our own session")
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: [other[0]], own: []), "plain default route")
        XCTAssertEqual(FullTunnelCheck.foreignFullTunnel(in: [Route(destination: "0.0.0.0", prefixLength: 0, interface: "ppp0")],
                                                         own: []), "ppp0")
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: [Route(destination: "0.0.0.0", prefixLength: 0, interface: "utun2",
                                                                  scoped: true)], own: []), "scoped")
        XCTAssertNil(FullTunnelCheck.foreignFullTunnel(in: [Route(destination: "10.0.0.0", prefixLength: 8, interface: "utun3")],
                                                       own: []), "split tunnel")
        XCTAssertFalse(FullTunnelCheck.isVPNInterface("utunx"))
        XCTAssertFalse(FullTunnelCheck.isVPNInterface("en0"))
        XCTAssertTrue(FullTunnelCheck.isVPNInterface("ipsec0"))
    }

    func testRedirectGatewayInConfig() {
        XCTAssertEqual(OVPNAnalyzer.redirectsGateway("client\nredirect-gateway def1 bypass-dhcp\n"), true)
        XCTAssertEqual(OVPNAnalyzer.redirectsGateway("client\n--redirect-gateway\n"), true)
        XCTAssertEqual(OVPNAnalyzer.redirectsGateway("client\n# redirect-gateway def1\n"), nil, "comment")
        XCTAssertEqual(OVPNAnalyzer.redirectsGateway("client\n<ca>\nredirect-gateway\n</ca>\n"), nil, "inline block")
        XCTAssertEqual(OVPNAnalyzer.redirectsGateway("client\nroute-nopull\n"), false)
        XCTAssertEqual(OVPNAnalyzer.redirectsGateway("client\npull-filter ignore \"redirect-gateway\"\n"), false)
        XCTAssertEqual(OVPNAnalyzer.redirectsGateway("client\npull-filter ignore redirect\n"), false)
        XCTAssertEqual(OVPNAnalyzer.redirectsGateway("client\npull-filter ignore \"route\"\n"), nil)
        XCTAssertEqual(OVPNAnalyzer.redirectsGateway("client\nremote vpn.example.com 1194\n"), nil)
        // Unchanged analysis.
        XCTAssertEqual(OVPNAnalyzer.analyze("remote vpn.example.com 1194\nauth-user-pass\n").remote, "vpn.example.com")
    }

    // MARK: log

    func testTunnelInterfaceAndPushedRedirect() {
        XCTAssertEqual(VPNLog.tunnelInterface("2026-01-01 10:00:00 Opened utun device utun5\n"), "utun5")
        XCTAssertEqual(VPNLog.tunnelInterface("INFO:   Interface ppp0 is UP.\n"), "ppp0")
        XCTAssertNil(VPNLog.tunnelInterface("Interface configuration done\n"))
        XCTAssertTrue(VPNLog.pushedRedirectGateway("PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,redirect-gateway def1'"))
        XCTAssertTrue(VPNLog.pushedRedirectGateway("2026-01-01 10:00:00 /sbin/route add -net 128.0.0.0 10.8.0.1 128.0.0.0"))
        XCTAssertFalse(VPNLog.pushedRedirectGateway("PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0'"))
    }

    func testSetupProblems() {
        XCTAssertNil(VPNLog.setupProblem("2026-01-01 10:00:00 Initialization Sequence Completed\n"))

        let dns = VPNLog.setupProblem("""
        2026-01-01 10:00:00 Opened utun device utun10
        setting DNS failed, already redirecting to another tunnel
        2026-01-01 10:00:01 WARNING: Failed running dns updown
        """)
        XCTAssertEqual(dns, VPNLog.SetupProblem(reason: "setting DNS failed, already redirecting to another tunnel", allTraffic: true))
        XCTAssertEqual(VPNLog.setupProblem("2026-01-01 10:00:01 WARNING: Failed running dns updown\n")?.allTraffic, true)

        XCTAssertEqual(VPNLog.setupProblem("add net 128.0.0.0: gateway 10.8.0.1: File exists\n"),
                       VPNLog.SetupProblem(reason: "add net 128.0.0.0: gateway 10.8.0.1: File exists", allTraffic: true))
        XCTAssertEqual(VPNLog.setupProblem("add net ::: gateway fe80::1%utun5: File exists\n")?.allTraffic, true)

        // A single other route: incomplete, not unusable — unless a DNS failure follows.
        let route = "add host 203.0.113.5: gateway 192.168.1.1: File exists"
        XCTAssertEqual(VPNLog.setupProblem(route), VPNLog.SetupProblem(reason: route, allTraffic: false))
        XCTAssertEqual(VPNLog.setupProblem(route + "\nsetting DNS failed, no compatible server profile\n")?.allTraffic, true)
        XCTAssertEqual(VPNLog.setupProblem("2026-01-01 10:00:00 ERROR: OS X route add command failed: external program exited with error status: 1\n"),
                       VPNLog.SetupProblem(reason: "ERROR: OS X route add command failed: external program exited with error status: 1",
                                           allTraffic: false))
    }

    /// A session killed without cleanup (e.g. its helper was unregistered) leaves the host route to the
    /// server via the original gateway; the next connect's "File exists" for it is harmless.
    static let leftoverServerRouteLog = """
    2026-01-01 10:00:00 TCP/UDP: Preserving recently used remote address: [AF_INET]203.0.113.10:1194
    2026-01-01 10:00:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194
    2026-01-01 10:00:01 ROUTE_GATEWAY 192.0.2.1/255.255.255.0 IFACE=en0 HWADDR=aa:bb:cc:dd:ee:ff
    2026-01-01 10:00:01 Opened utun device utun6
    2026-01-01 10:00:01 /sbin/route add -net 203.0.113.10 192.0.2.1 255.255.255.255
                                    route: writing to routing socket: File exists
    add net 203.0.113.10: gateway 192.0.2.1: File exists
    2026-01-01 10:00:01 ERROR: OS X route add command failed: external program exited with error status: 1
    2026-01-01 10:00:01 /sbin/route add -net 0.0.0.0 10.8.0.1 128.0.0.0
    add net 0.0.0.0: gateway 10.8.0.1
    2026-01-01 10:00:01 /sbin/route add -net 128.0.0.0 10.8.0.1 128.0.0.0
    add net 128.0.0.0: gateway 10.8.0.1
    2026-01-01 10:00:02 Initialization Sequence Completed

    """

    /// Every session adds the server's host route three times: from `redirect-gateway def1` (works),
    /// from a config `route <server> 255.255.255.255 net_gateway` and from the same route pushed by the
    /// server (both "File exists"). The log names no server address here, so only the duplicate rule applies.
    static let duplicateServerRouteLog = """
    2026-01-01 10:00:01 /sbin/route add -net 203.0.113.10 192.0.2.1 255.255.255.255
    add net 203.0.113.10: gateway 192.0.2.1
    2026-01-01 10:00:01 /sbin/route add -net 0.0.0.0 10.8.0.1 128.0.0.0
    add net 0.0.0.0: gateway 10.8.0.1
    2026-01-01 10:00:01 /sbin/route add -net 128.0.0.0 10.8.0.1 128.0.0.0
    add net 128.0.0.0: gateway 10.8.0.1
    2026-01-01 10:00:01 /sbin/route add -net 203.0.113.10 192.0.2.1 255.255.255.255
                                    route: writing to routing socket: File exists
    add net 203.0.113.10: gateway 192.0.2.1: File exists
    2026-01-01 10:00:01 ERROR: OS X route add command failed: external program exited with error status: 1
    2026-01-01 10:00:01 /sbin/route add -net 10.20.0.0 10.8.0.1 255.255.0.0
    add net 10.20.0.0: gateway 10.8.0.1
    2026-01-01 10:00:01 /sbin/route add -net 203.0.113.10 192.0.2.1 255.255.255.255
    add net 203.0.113.10: gateway 192.0.2.1: File exists
    2026-01-01 10:00:02 Initialization Sequence Completed

    """

    func testRouteAddedEarlierInTheSessionIsNotASetupProblem() {
        XCTAssertNil(VPNLog.setupProblem(Self.duplicateServerRouteLog))
        // A route that exists, but not because this session added it: still reported.
        let foreign = Self.duplicateServerRouteLog + """
        2026-01-01 10:00:03 /sbin/route add -net 10.30.0.0 10.8.0.1 255.255.0.0
        add net 10.30.0.0: gateway 10.8.0.1: File exists

        """
        XCTAssertEqual(VPNLog.setupProblem(foreign)?.reason, "add net 10.30.0.0: gateway 10.8.0.1: File exists")
        // The same destination with another mask is another route.
        let otherMask = Self.duplicateServerRouteLog + """
        2026-01-01 10:00:03 /sbin/route add -net 10.20.0.0 10.8.0.1 255.255.255.0
        add net 10.20.0.0: gateway 10.8.0.1: File exists

        """
        XCTAssertEqual(VPNLog.setupProblem(otherMask)?.reason, "add net 10.20.0.0: gateway 10.8.0.1: File exists")
        // A duplicate that fails for another reason than "File exists" is still a problem.
        let unreachable = Self.duplicateServerRouteLog.replacingOccurrences(
            of: "add net 10.20.0.0: gateway 10.8.0.1\n",
            with: "add net 10.20.0.0: gateway 10.8.0.1\n2026-01-01 10:00:01 /sbin/route add -net 10.20.0.0 10.8.0.1 255.255.0.0\n"
                + "add net 10.20.0.0: gateway 10.8.0.1: Network is unreachable\n")
        XCTAssertEqual(VPNLog.setupProblem(unreachable)?.reason, "add net 10.20.0.0: gateway 10.8.0.1: Network is unreachable")
    }

    func testRouteCommandParsing() {
        XCTAssertEqual(VPNLog.RouteCommand("/sbin/route add -net 203.0.113.10 192.0.2.1 255.255.255.255"),
                       VPNLog.RouteCommand(destination: "203.0.113.10", mask: "255.255.255.255"))
        XCTAssertEqual(VPNLog.RouteCommand("/sbin/route add -inet6 2000:: -prefixlen 3 fe80::1%utun6")?.mask, "3")
        XCTAssertEqual(VPNLog.addedRouteDestination("add net 10.20.0.0: gateway 10.8.0.1"), "10.20.0.0")
        XCTAssertNil(VPNLog.addedRouteDestination("add net 10.20.0.0: gateway 10.8.0.1: File exists"))
    }

    func testRemoteAddressesAndDefaultGateway() {
        XCTAssertEqual(VPNLog.remoteAddresses(Self.leftoverServerRouteLog), ["203.0.113.10"])
        XCTAssertEqual(VPNLog.remoteAddresses("2026-01-01 10:00:00 TCP connection established with [AF_INET]203.0.113.20:443\n"),
                       ["203.0.113.20"])
        XCTAssertEqual(VPNLog.remoteAddresses("TCPv4_CLIENT link remote: [AF_INET]203.0.113.21:443\n"), ["203.0.113.21"])
        XCTAssertEqual(VPNLog.remoteAddresses("UDPv6 link remote: [AF_INET6]2001:db8::5:1194\n"), ["2001:db8::5"])
        XCTAssertEqual(VPNLog.remoteAddresses("[vpn.example.com] Peer Connection Initiated with [AF_INET]203.0.113.22:1194\n"),
                       ["203.0.113.22"])
        XCTAssertEqual(VPNLog.remoteAddresses("UDPv4 link local: (not bound)\n"), [])
        XCTAssertEqual(VPNLog.defaultGateway(Self.leftoverServerRouteLog), "192.0.2.1")
        XCTAssertNil(VPNLog.defaultGateway("ROUTE: default_gateway=UNDEF\n"))
    }

    func testLeftoverServerRouteIsNotASetupProblem() {
        XCTAssertNil(VPNLog.setupProblem(Self.leftoverServerRouteLog))
        // The same without the "command failed" line (route's own error line only).
        XCTAssertNil(VPNLog.setupProblem(Self.leftoverServerRouteLog.replacingOccurrences(
            of: "2026-01-01 10:00:01 ERROR: OS X route add command failed: external program exited with error status: 1\n", with: "")))
    }

    func testOtherRouteFailuresStillCount() {
        // Another host than the server.
        let otherHost = Self.leftoverServerRouteLog.replacingOccurrences(of: "add net 203.0.113.10:", with: "add net 203.0.113.99:")
        XCTAssertEqual(VPNLog.setupProblem(otherHost),
                       VPNLog.SetupProblem(reason: "add net 203.0.113.99: gateway 192.0.2.1: File exists", allTraffic: false))
        // The server, but through another gateway than the default one.
        let otherGateway = Self.leftoverServerRouteLog.replacingOccurrences(of: "add net 203.0.113.10: gateway 192.0.2.1",
                                                                            with: "add net 203.0.113.10: gateway 192.0.2.9")
        XCTAssertEqual(VPNLog.setupProblem(otherGateway)?.reason, "add net 203.0.113.10: gateway 192.0.2.9: File exists")
        // The server, but another error than "File exists".
        let unreachable = Self.leftoverServerRouteLog.replacingOccurrences(of: "gateway 192.0.2.1: File exists",
                                                                           with: "gateway 192.0.2.1: Network is unreachable")
        XCTAssertEqual(VPNLog.setupProblem(unreachable)?.reason, "add net 203.0.113.10: gateway 192.0.2.1: Network is unreachable")
        // A later route command that fails is still reported, even after the ignored one.
        let laterFailure = Self.leftoverServerRouteLog.replacingOccurrences(
            of: "add net 128.0.0.0: gateway 10.8.0.1\n",
            with: "add net 128.0.0.0: gateway 10.8.0.1\n2026-01-01 10:00:01 /sbin/route add -net 10.20.0.0 10.8.0.1 255.255.0.0\n"
                + "2026-01-01 10:00:01 ERROR: OS X route add command failed: external program exited with error status: 1\n")
        XCTAssertEqual(VPNLog.setupProblem(laterFailure)?.reason,
                       "ERROR: OS X route add command failed: external program exited with error status: 1")
        // Without a known server address nothing is excused.
        XCTAssertEqual(VPNLog.setupProblem("add net 203.0.113.10: gateway 192.0.2.1: File exists\n")?.allTraffic, false)
    }

    func testTimestampIsDropped() {
        XCTAssertEqual(VPNLog.withoutTimestamp("2026-01-01 10:00:00 WARNING: x"), "WARNING: x")
        XCTAssertEqual(VPNLog.withoutTimestamp("setting DNS failed"), "setting DNS failed")
    }

    // MARK: Linux logs

    /// OpenVPN 2.6 on Linux (rtnetlink, `redirect-gateway def1`), at the default verbosity.
    static let linuxOpenVPNLog = """
    2026-01-01 10:00:00 OpenVPN 2.6.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
    2026-01-01 10:00:00 library versions: OpenSSL 3.0.13 30 Jan 2024, LZO 2.10
    2026-01-01 10:00:00 DCO version: N/A
    2026-01-01 10:00:00 MANAGEMENT: unix domain socket listening on /run/passtunnel/1000/acme/mgmt.sock
    2026-01-01 10:00:00 TCP/UDP: Preserving recently used remote address: [AF_INET]203.0.113.10:1194
    2026-01-01 10:00:00 UDPv4 link local: (not bound)
    2026-01-01 10:00:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194
    2026-01-01 10:00:01 [vpn.example.com] Peer Connection Initiated with [AF_INET]203.0.113.10:1194
    2026-01-01 10:00:01 PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.8.0.1,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,ifconfig 10.8.0.6 255.255.255.0,peer-id 0,cipher AES-256-GCM'
    2026-01-01 10:00:01 OPTIONS IMPORT: --ifconfig/up options modified
    2026-01-01 10:00:01 OPTIONS IMPORT: route options modified
    2026-01-01 10:00:01 net_route_v4_best_gw query: dst 0.0.0.0
    2026-01-01 10:00:01 net_route_v4_best_gw result: via 192.0.2.1 dev wlp2s0
    2026-01-01 10:00:01 ROUTE_GATEWAY 192.0.2.1/255.255.255.0 IFACE=wlp2s0 HWADDR=02:00:00:00:00:01
    2026-01-01 10:00:01 TUN/TAP device tun0 opened
    2026-01-01 10:00:01 net_iface_mtu_set: mtu 1500 for tun0
    2026-01-01 10:00:01 net_iface_up: set tun0 up
    2026-01-01 10:00:01 net_addr_v4_add: 10.8.0.6/24 dev tun0
    2026-01-01 10:00:01 net_route_v4_add: 203.0.113.10/32 via 192.0.2.1 dev [NULL] table 0 metric -1
    2026-01-01 10:00:01 net_route_v4_add: 0.0.0.0/1 via 10.8.0.1 dev [NULL] table 0 metric -1
    2026-01-01 10:00:01 net_route_v4_add: 128.0.0.0/1 via 10.8.0.1 dev [NULL] table 0 metric -1
    2026-01-01 10:00:01 Initialization Sequence Completed

    """

    func linuxLog(replacing line: String, with replacement: String) -> String {
        precondition(Self.linuxOpenVPNLog.contains(line + "\n"))
        return Self.linuxOpenVPNLog.replacingOccurrences(of: line + "\n", with: replacement + "\n")
    }

    func testLinuxOpenVPNSession() {
        let log = Self.linuxOpenVPNLog
        XCTAssertEqual(VPNLog.tunnelInterface(log), "tun0")
        XCTAssertEqual(VPNLog.openVPNLocalIP(log), "10.8.0.6")
        XCTAssertTrue(VPNLog.openVPNIsUp(log))
        XCTAssertTrue(VPNLog.pushedRedirectGateway(log))
        XCTAssertTrue(VPNLog.pushedRedirectGateway("2026-01-01 10:00:01 net_route_v4_add: 128.0.0.0/1 via 10.8.0.1 dev [NULL] table 0 metric -1"))
        XCTAssertFalse(VPNLog.pushedRedirectGateway("2026-01-01 10:00:01 net_route_v4_add: 10.20.0.0/16 via 10.8.0.1 dev [NULL] table 0 metric -1"))
        XCTAssertEqual(VPNLog.remoteAddresses(log), ["203.0.113.10"])
        XCTAssertEqual(VPNLog.defaultGateway(log), "192.0.2.1")
        XCTAssertNil(VPNLog.setupProblem(log))
        XCTAssertFalse(VPNLog.isFatal(log))
        XCTAssertFalse(VPNLog.isAuthFailure(log))

        // Data channel offload: OpenVPN makes the device itself.
        let dco = linuxLog(replacing: "2026-01-01 10:00:01 TUN/TAP device tun0 opened",
                           with: "2026-01-01 10:00:01 net_iface_new: add tun0 type ovpn-dco\n2026-01-01 10:00:01 DCO device tun0 opened")
        XCTAssertEqual(VPNLog.tunnelInterface(dco), "tun0")
        XCTAssertEqual(VPNLog.tunnelInterface("2026-01-01 10:00:01 TUN/TAP device tap-acme opened\n"), "tap-acme")
        XCTAssertNil(VPNLog.tunnelInterface("2026-01-01 10:00:01 TUN/TAP device /dev/tun0 opened\n"))
        XCTAssertNil(VPNLog.tunnelInterface("2026-01-01 10:00:01 Cannot open TUN/TAP dev /dev/net/tun: No such file or directory\n"))
        // Point-to-point topology, and builds that run `ip`.
        XCTAssertEqual(VPNLog.openVPNLocalIP("2026-01-01 10:00:01 net_addr_ptp_v4_add: 10.8.0.6 peer 10.8.0.5 dev tun0\n"), "10.8.0.6")
        XCTAssertEqual(VPNLog.openVPNLocalIP("2026-01-01 10:00:01 /sbin/ip addr add dev tun0 10.8.0.10/24 broadcast 10.8.0.255\n"),
                       "10.8.0.10")
        XCTAssertEqual(VPNLog.openVPNLocalIP("2026-01-01 10:00:01 /usr/sbin/ip addr add dev tun0 local 10.8.0.14 peer 10.8.0.13\n"),
                       "10.8.0.14")
    }

    /// Another VPN already has `0/1`: the kernel refuses OpenVPN's route.
    func testLinuxAllTrafficRouteFailure() {
        let log = linuxLog(replacing: "2026-01-01 10:00:01 net_route_v4_add: 0.0.0.0/1 via 10.8.0.1 dev [NULL] table 0 metric -1",
                           with: """
                           2026-01-01 10:00:01 net_route_v4_add: 0.0.0.0/1 via 10.8.0.1 dev [NULL] table 0 metric -1
                           2026-01-01 10:00:01 sitnl_send: rtnl: generic error (-17): File exists
                           2026-01-01 10:00:01 NOTE: Linux route add command failed because route exists
                           """)
        XCTAssertEqual(VPNLog.setupProblem(log), VPNLog.SetupProblem(
            reason: "net_route_v4_add: 0.0.0.0/1 via 10.8.0.1 dev [NULL] table 0 metric -1: File exists", allTraffic: true))
        // OpenVPN's note alone (no rtnetlink line) says the same.
        let noteOnly = log.replacingOccurrences(of: "2026-01-01 10:00:01 sitnl_send: rtnl: generic error (-17): File exists\n", with: "")
        XCTAssertEqual(VPNLog.setupProblem(noteOnly)?.allTraffic, true)
        // IPv6 (`redirect-gateway ipv6`).
        let v6 = """
        2026-01-01 10:00:01 net_route_v6_add: 2000::/4 via :: dev tun0 table 0 metric -1
        2026-01-01 10:00:01 sitnl_send: rtnl: generic error (-17): File exists
        2026-01-01 10:00:01 NOTE: Linux route add command failed because route exists
        """
        XCTAssertEqual(VPNLog.setupProblem(v6), VPNLog.SetupProblem(
            reason: "net_route_v6_add: 2000::/4 via :: dev tun0 table 0 metric -1: File exists", allTraffic: true))
        // A build that runs `ip`.
        let iproute = """
        2026-01-01 10:00:01 /sbin/ip route add 128.0.0.0/1 via 10.8.0.1
        RTNETLINK answers: File exists
        2026-01-01 10:00:01 ERROR: Linux route add command failed: external program exited with error status: 2
        """
        XCTAssertEqual(VPNLog.setupProblem(iproute), VPNLog.SetupProblem(
            reason: "/sbin/ip route add 128.0.0.0/1 via 10.8.0.1: File exists", allTraffic: true))
        XCTAssertTrue(VPNLog.pushedRedirectGateway(iproute))
    }

    func testLinuxOtherRouteFailureIsAWarning() {
        let route = "2026-01-01 10:00:01 net_route_v4_add: 10.30.0.0/16 via 10.8.0.1 dev [NULL] table 0 metric -1"
        let log = linuxLog(replacing: "2026-01-01 10:00:01 Initialization Sequence Completed", with: """
        \(route)
        2026-01-01 10:00:01 sitnl_send: rtnl: generic error (-101): Network is unreachable
        2026-01-01 10:00:01 ERROR: Linux route add command failed
        2026-01-01 10:00:01 Initialization Sequence Completed
        """)
        XCTAssertEqual(VPNLog.setupProblem(log), VPNLog.SetupProblem(
            reason: "net_route_v4_add: 10.30.0.0/16 via 10.8.0.1 dev [NULL] table 0 metric -1: Network is unreachable",
            allTraffic: false))
        // OpenVPN's error line alone.
        let errorOnly = log.replacingOccurrences(of: "2026-01-01 10:00:01 sitnl_send: rtnl: generic error (-101): Network is unreachable\n",
                                                 with: "")
        XCTAssertEqual(VPNLog.setupProblem(errorOnly)?.reason,
                       "net_route_v4_add: 10.30.0.0/16 via 10.8.0.1 dev [NULL] table 0 metric -1: ERROR: Linux route add command failed")
        // A DNS failure after it still makes the session unusable.
        XCTAssertEqual(VPNLog.setupProblem(log + "setting DNS failed, no compatible server profile\n")?.allTraffic, true)
    }

    /// The server's host route, added a second time (from a config `route … net_gateway` and from the
    /// server), or left behind by a session killed without cleanup: "File exists" is harmless then.
    func testLinuxServerRouteThatExistsIsNotAProblem() {
        let serverRoute = "2026-01-01 10:00:01 net_route_v4_add: 203.0.113.10/32 via 192.0.2.1 dev [NULL] table 0 metric -1"
        let exists = "2026-01-01 10:00:01 sitnl_send: rtnl: generic error (-17): File exists\n"
            + "2026-01-01 10:00:01 NOTE: Linux route add command failed because route exists"
        let duplicate = linuxLog(replacing: "2026-01-01 10:00:01 Initialization Sequence Completed",
                                 with: "\(serverRoute)\n\(exists)\n2026-01-01 10:00:01 Initialization Sequence Completed")
        XCTAssertNil(VPNLog.setupProblem(duplicate))
        let leftover = linuxLog(replacing: serverRoute, with: "\(serverRoute)\n\(exists)")
        XCTAssertNil(VPNLog.setupProblem(leftover))
        // Through another gateway than the default one, it is not the route OpenVPN wanted.
        let otherGateway = leftover.replacingOccurrences(of: "203.0.113.10/32 via 192.0.2.1", with: "203.0.113.10/32 via 192.0.2.9")
        XCTAssertEqual(VPNLog.setupProblem(otherGateway)?.reason,
                       "net_route_v4_add: 203.0.113.10/32 via 192.0.2.9 dev [NULL] table 0 metric -1: File exists")
        // A route that exists, but not because this session added it.
        let foreign = linuxLog(replacing: "2026-01-01 10:00:01 Initialization Sequence Completed", with: """
        2026-01-01 10:00:01 net_route_v4_add: 10.20.0.0/16 via 10.8.0.1 dev [NULL] table 0 metric -1
        \(exists)
        """)
        XCTAssertEqual(VPNLog.setupProblem(foreign)?.allTraffic, false)
        // The same destination with another prefix length is another route.
        let added = linuxLog(replacing: "2026-01-01 10:00:01 Initialization Sequence Completed", with: """
        2026-01-01 10:00:01 net_route_v4_add: 10.20.0.0/16 via 10.8.0.1 dev [NULL] table 0 metric -1
        2026-01-01 10:00:01 net_route_v4_add: 10.20.0.0/16 via 10.8.0.1 dev [NULL] table 0 metric -1
        \(exists)
        2026-01-01 10:00:01 net_route_v4_add: 10.20.0.0/24 via 10.8.0.1 dev [NULL] table 0 metric -1
        \(exists)
        """)
        XCTAssertEqual(VPNLog.setupProblem(added)?.reason,
                       "net_route_v4_add: 10.20.0.0/24 via 10.8.0.1 dev [NULL] table 0 metric -1: File exists")
    }

    func testLinuxDNSHookFailure() {
        // OpenVPN 2.6 runs the daemon's hook as --up; 2.7 as --dns-updown (the Mac's lines).
        let up = "2026-01-01 10:00:01 WARNING: Failed running command (--up/--down): external program exited with error status: 1\n"
        XCTAssertEqual(VPNLog.setupProblem(Self.linuxOpenVPNLog + up), VPNLog.SetupProblem(
            reason: "WARNING: Failed running command (--up/--down): external program exited with error status: 1", allTraffic: true))
        let updown = VPNLog.setupProblem(Self.linuxOpenVPNLog + "2026-01-01 10:00:01 WARNING: Failed running dns updown\n")
        XCTAssertEqual(updown?.allTraffic, true)
    }

    /// openfortivpn on Linux: the same lines as on the Mac for the address and the interface.
    func testLinuxOpenFortiVPNSession() {
        let log = """
        INFO:   Connected to gateway.
        INFO:   Authenticated.
        INFO:   Remote gateway has allocated a VPN.
        INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54]
        INFO:   Negotiation complete.
        INFO:   Interface ppp0 is UP.
        INFO:   Setting new routes...
        INFO:   Tunnel is up and running.

        """
        XCTAssertEqual(VPNLog.tunnelInterface(log), "ppp0")
        XCTAssertTrue(VPNLog.fortiIsUp(log))
        XCTAssertEqual(VPNLog.fortiAddress(log), "10.212.134.200")
        XCTAssertFalse(VPNLog.isFatal(log))
    }
}
