import Darwin
import XCTest
@testable import PassTunnelCore

/// Routing table parsing, the other-VPN check and reading set-up failures from the OpenVPN log.
final class FullTunnelTests: XCTestCase {
    typealias Route = RoutingTable.Route

    // MARK: routing table

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

    func testTimestampIsDropped() {
        XCTAssertEqual(VPNLog.withoutTimestamp("2026-01-01 10:00:00 WARNING: x"), "WARNING: x")
        XCTAssertEqual(VPNLog.withoutTimestamp("setting DNS failed"), "setting DNS failed")
    }
}
