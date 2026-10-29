import Foundation
import XCTest

@testable import PassTunnelShared

/// The Linux side of openconnect's hook as far as it is shared (#187): `ip`'s argument lists to the byte, the
/// hook's run against a fake Linux (`FakeOpenConnectSystem` with `ip`) for a set-up, its revert, a failure, two
/// sessions sharing a route and a hook killed in the middle of a change, the routing table read from rtnetlink
/// (`KernelRoute.linux`), and the distribution tool's version and options (`ToolSpec.openconnect`). Runs on every
/// platform; nothing here touches the real network.
final class OpenConnectLinuxTests: XCTestCase {
    var root: String!
    var runDir: String { root + "/1000/acme" }
    var otherDir: String { root + "/1000/other" }
    var system: FakeOpenConnectSystem!
    let clock = Date(timeIntervalSince1970: 1_000_000)
    static let ip = "/usr/sbin/ip"

    static let policy = OpenConnectPolicy(uid: 1000, profileID: "acme", setRoutes: true, setDNS: true)
    static let otherPolicy = OpenConnectPolicy(uid: 1000, profileID: "other", setRoutes: true, setDNS: true)

    /// IPv4 only, no includes: a full tunnel, IPv6 blocked.
    static let full = OpenConnectNetwork(
        interface: "tun0", gateway: IPAddress("192.0.2.10")!,
        ipv4: .init(address: IPAddress("10.11.0.2")!, network: IPNetwork("10.11.0.0/24")), ipv6: nil, mtu: 1406,
        dnsServers: [IPAddress("10.11.0.53")!], defaultDomains: ["example.com"])

    /// Both families, split includes and an exclude, split DNS.
    static let split = OpenConnectNetwork(
        interface: "tun0", gateway: IPAddress("192.0.2.10")!,
        ipv4: .init(address: IPAddress("10.11.0.2")!, network: IPNetwork("10.11.0.0/24")),
        ipv6: .init(address: IPAddress("2001:db8:1::2")!, network: IPNetwork("2001:db8:1::/64")), mtu: 1400,
        dnsServers: [IPAddress("172.16.0.53")!], defaultDomains: ["example.com"], splitDNSDomains: ["corp.example.com"],
        ipv4Includes: [IPNetwork("10.0.0.0/8")!], ipv4Excludes: [IPNetwork("10.99.0.0/16")!], ipv6Includes: [IPNetwork("2001:db8::/32")!])

    /// A second session to the same server (another profile, another tunnel).
    static let second = OpenConnectNetwork(
        interface: "tun1", gateway: IPAddress("192.0.2.10")!, ipv4: .init(address: IPAddress("10.12.0.2")!, network: nil), ipv6: nil,
        mtu: 1406, ipv4Includes: [IPNetwork("192.0.2.0/24")!])

    /// A laptop on Wi-Fi as rtnetlink shows it: default routes of both families through wlan0, its subnet.
    static let table = [
        KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("198.51.100.1"), interface: "wlan0"),
        KernelRoute(network: IPNetwork("198.51.100.0/24")!, interface: "wlan0"),
        KernelRoute(network: IPNetwork("::/0")!, gateway: IPAddress("fe80::1"), interface: "wlan0"),
        KernelRoute(network: IPNetwork("fe80::/64")!, interface: "wlan0")
    ]

    override func setUpWithError() throws {
        var template = Array("/tmp/pt-linux-hook-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        root = String(cString: made)
        try FileManager.default.createDirectory(atPath: runDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: otherDir, withIntermediateDirectories: true)
        system = FakeOpenConnectSystem()
        system.tools = .linux(ip: Self.ip)
        system.interfaces = ["tun0": 30, "tun1": 31, "wlan0": 3]
        system.attached = [OpenConnectPlan.Attached(IPNetwork("198.51.100.0/24")!, interface: "wlan0")]
        system.table = Self.table
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: root)
    }

    @discardableResult
    func run(_ event: OpenConnectNetwork.Event, policy: OpenConnectPolicy = policy, dir: String? = nil) -> OpenConnectHook.Outcome {
        var hook = OpenConnectHook(
            runRoot: root, runDir: dir ?? runDir, system: system, deadline: clock.addingTimeInterval(OpenConnectHook.runLimit),
            identity: (4242, ProcessStart(seconds: 12_345, microseconds: 670_000)))
        let clock = clock
        hook.now = { clock }
        return hook.run(event: { event }, policy: { policy })
    }

    func restore(dir: String? = nil) -> OpenConnectHook.Restore {
        let clock = clock
        return OpenConnectHook.restoreAfterExit(runRoot: root, runDir: dir ?? runDir, system: system, killHook: {}, now: { clock })
    }

    func recordText(_ dir: String? = nil) throws -> String {
        try String(contentsOfFile: OpenConnectJournal.path(runDir: dir ?? runDir), encoding: .utf8)
    }

    func ip(_ arguments: String) -> String { Self.ip + " " + arguments }

    // MARK: - ip, to the byte

    func testIPArgumentLists() {
        func route(_ network: String, _ via: OpenConnectPlan.Via) -> OpenConnectPlan.Route { .init(IPNetwork(network)!, via: via) }
        let v4 = OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "wlan0")!
        let v6 = OpenConnectPlan.Gateway(address: IPAddress("fe80::1"), interface: "wlan0")!
        let link = OpenConnectPlan.Gateway(address: nil, interface: "ppp0")!
        let tools = OpenConnectCommand.Tools.linux(ip: Self.ip)
        let cases: [(OpenConnectCommand.Effect, String)] = [
            (.link(interface: "tun0", mtu: 1406), "link set dev tun0 up mtu 1406"),
            (.linkDown(interface: "tun0"), "link set dev tun0 down"),
            (.addAddress(interface: "tun0", IPAddress("10.11.0.2")!), "-4 addr add 10.11.0.2/32 peer 10.11.0.2 dev tun0"),
            (.deleteAddress(interface: "tun0", IPAddress("10.11.0.2")!), "-4 addr del 10.11.0.2/32 peer 10.11.0.2 dev tun0"),
            (.addAddress(interface: "tun0", IPAddress("2001:db8:1::2")!), "-6 addr add 2001:db8:1::2/128 dev tun0"),
            (.deleteAddress(interface: "tun0", IPAddress("2001:db8:1::2")!), "-6 addr del 2001:db8:1::2/128 dev tun0"),
            (.addRoute(route("0.0.0.0/1", .interface("tun0"))), "-4 route add 0.0.0.0/1 dev tun0"),
            (.addRoute(route("128.0.0.0/1", .interface("tun0"))), "-4 route add 128.0.0.0/1 dev tun0"),
            (.addRoute(route("10.11.0.53/32", .interface("tun0"))), "-4 route add 10.11.0.53/32 dev tun0"),
            (.addRoute(route("192.0.2.10/32", .gateway(v4))), "-4 route add 192.0.2.10/32 via 198.51.100.1 dev wlan0"),
            (.addRoute(route("10.99.0.0/16", .gateway(v4))), "-4 route add 10.99.0.0/16 via 198.51.100.1 dev wlan0"),
            (.addRoute(route("192.0.2.10/32", .gateway(link))), "-4 route add 192.0.2.10/32 dev ppp0"),
            (.addRoute(route("2001:db8:5::/48", .gateway(v6))), "-6 route add 2001:db8:5::/48 via fe80::1 dev wlan0"),
            (.addRoute(route("::/1", .interface("tun0"))), "-6 route add ::/1 dev tun0"),
            (.addRoute(route("8000::/1", .interface("tun0"))), "-6 route add 8000::/1 dev tun0"),
            (.addRoute(route("::/1", .reject)), "-6 route add unreachable ::/1"),
            (.addRoute(route("8000::/1", .reject)), "-6 route add unreachable 8000::/1"),
            (.addRoute(route("0.0.0.0/1", .reject)), "-4 route add unreachable 0.0.0.0/1"),
            // A revert names the route's next hop (and type): the kernel deletes that route and no other.
            (.deleteRoute(route("0.0.0.0/1", .interface("tun0"))), "-4 route del 0.0.0.0/1 dev tun0"),
            (.deleteRoute(route("192.0.2.10/32", .gateway(v4))), "-4 route del 192.0.2.10/32 via 198.51.100.1 dev wlan0"),
            (.deleteRoute(route("::/1", .reject)), "-6 route del unreachable ::/1"),
            (.deleteRoute(route("2001:db8:5::/48", .gateway(v6))), "-6 route del 2001:db8:5::/48 via fe80::1 dev wlan0")
        ]
        for (effect, arguments) in cases {
            let command = OpenConnectCommand(effect, tools: tools)
            XCTAssertEqual(command.line, ip(arguments))
            XCTAssertEqual(command.executable, Self.ip)
            XCTAssertEqual(command.effect, effect)
            // An argument list: no word holds a blank or anything a shell would read.
            XCTAssertTrue(command.arguments.allSatisfy { !$0.isEmpty && $0.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7F && $0 != 0x24 && $0 != 0x60 } })
        }
        // The Mac's tools are unchanged by the platform switch.
        XCTAssertEqual(
            OpenConnectCommand(.link(interface: "utun5", mtu: 1406), tools: .macOS), OpenConnectCommand.link("utun5", mtu: 1406))
    }

    // MARK: - The hook on Linux

    func testConnectFullTunnelThenDisconnect() throws {
        XCTAssertEqual(
            run(.connect(Self.full)),
            OpenConnectHook.Outcome(
                lines: ["passtunnel vpn-hook: tun0 up: 10.11.0.2, 2 routes, full tunnel, IPv6 blocked, DNS 10.11.0.53, search example.com\n"]))
        XCTAssertEqual(
            system.log,
            [
                ip("link set dev tun0 up mtu 1406"),
                ip("-4 addr add 10.11.0.2/32 peer 10.11.0.2 dev tun0"),
                ip("-4 route add 192.0.2.10/32 via 198.51.100.1 dev wlan0"),
                ip("-6 route add unreachable ::/1"),
                ip("-6 route add unreachable 8000::/1"),
                ip("-4 route add 0.0.0.0/1 dev tun0"),
                ip("-4 route add 128.0.0.0/1 dev tun0"),
                "dns set passtunnel-1000-acme"
            ])
        XCTAssertTrue(
            try recordText().hasSuffix("= dns passtunnel-1000-acme tun0 primary servers=10.11.0.53 search=example.com match=-\nstatus up\n"))
        XCTAssertEqual(HelperCore.tunnelStatus(runDir: runDir), TunnelStatus(state: .up, interface: "tun0"))

        system.log = []
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertEqual(
            system.log,
            [
                "dns remove passtunnel-1000-acme",
                ip("-4 route del 128.0.0.0/1 dev tun0"),
                ip("-4 route del 0.0.0.0/1 dev tun0"),
                ip("-6 route del unreachable 8000::/1"),
                ip("-6 route del unreachable ::/1"),
                ip("-4 route del 192.0.2.10/32 via 198.51.100.1 dev wlan0"),
                ip("-4 addr del 10.11.0.2/32 peer 10.11.0.2 dev tun0"),
                ip("link set dev tun0 down")
            ])
        XCTAssertEqual(system.table, Self.table)
        XCTAssertEqual(system.dns, [:])
    }

    func testConnectSplitTunnel() throws {
        XCTAssertFalse(run(.connect(Self.split)).stopTool)
        XCTAssertEqual(
            system.log,
            [
                ip("link set dev tun0 up mtu 1400"),
                ip("-4 addr add 10.11.0.2/32 peer 10.11.0.2 dev tun0"),
                ip("-6 addr add 2001:db8:1::2/128 dev tun0"),
                ip("-4 route add 10.99.0.0/16 via 198.51.100.1 dev wlan0"),
                ip("-4 route add 10.0.0.0/8 dev tun0"),
                ip("-4 route add 172.16.0.53/32 dev tun0"),
                ip("-6 route add 2001:db8::/32 dev tun0"),
                "dns set passtunnel-1000-acme"
            ])
        XCTAssertTrue(
            try recordText().contains(
                "= dns passtunnel-1000-acme tun0 split servers=172.16.0.53 search=example.com match=corp.example.com,example.com\n"))
    }

    func testAFailedChangeRevertsEverythingAndStops() throws {
        system.failing = {
            $0.line == self.ip("-4 route add 128.0.0.0/1 dev tun0") ? .init(status: 2, output: "RTNETLINK answers: Network is unreachable") : nil
        }
        let outcome = run(.connect(Self.full))
        let reason = ip("-4 route add 128.0.0.0/1 dev tun0") + " failed (exit status 2: RTNETLINK answers: Network is unreachable)"
        XCTAssertEqual(outcome, OpenConnectHook.Outcome(lines: [VPNHook.failureLine(reason)], stopTool: true))
        XCTAssertEqual(
            Array(system.log.suffix(6)),
            [
                ip("-4 route del 0.0.0.0/1 dev tun0"),
                ip("-6 route del unreachable 8000::/1"),
                ip("-6 route del unreachable ::/1"),
                ip("-4 route del 192.0.2.10/32 via 198.51.100.1 dev wlan0"),
                ip("-4 addr del 10.11.0.2/32 peer 10.11.0.2 dev tun0"),
                ip("link set dev tun0 down")
            ])
        XCTAssertEqual(system.table, Self.table)
        XCTAssertTrue(try recordText().hasSuffix("status failed " + reason + "\n"))
        XCTAssertEqual(HelperCore.tunnelStatus(runDir: runDir).state, .failed)
    }

    /// `DNSApplier`'s reason reaches the failure line (Linux's `dnsFailure`), and the routes are reverted.
    func testADNSFailureSaysWhy() throws {
        system.dnsWritable = false
        system.dnsFailure = "setting DNS failed: /etc/resolv.conf is not a regular file owned by root"
        let outcome = run(.connect(Self.full))
        XCTAssertEqual(outcome.lines.last, VPNHook.failureLine("setting DNS failed: /etc/resolv.conf is not a regular file owned by root"))
        XCTAssertTrue(outcome.stopTool)
        XCTAssertEqual(system.table, Self.table)
    }

    /// Two sessions to one server: the second finds the server's route the first made and shares it (`&`); the
    /// first to end spares it, the last removes it.
    func testASharedRouteOutlivesTheFirstSession() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        system.log = []
        XCTAssertFalse(run(.connect(Self.second), policy: Self.otherPolicy, dir: otherDir).stopTool)
        XCTAssertFalse(system.log.contains { $0.contains("192.0.2.10/32") })
        XCTAssertTrue(try recordText(otherDir).contains("& route 192.0.2.10/32 gateway 198.51.100.1 wlan0\n"))

        system.log = []
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertFalse(system.log.contains { $0.contains("192.0.2.10/32") }, "\(system.log)")
        XCTAssertTrue(try recordText().contains("? route 192.0.2.10/32 gateway 198.51.100.1 wlan0\n"))
        system.log = []
        XCTAssertEqual(run(.disconnect, policy: Self.otherPolicy, dir: otherDir), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log.filter { $0.contains("192.0.2.10/32") }, [ip("-4 route del 192.0.2.10/32 via 198.51.100.1 dev wlan0")])
        XCTAssertEqual(system.table, Self.table)
    }

    /// The hook was killed while it added the block (begun, no outcome) and openconnect with it: the daemon's
    /// revert removes what may have been made, but not what went with the tunnel interface.
    func testAHookKilledInTheMiddleOfAChange() throws {
        // The record stops at the begun change, which the system has made.
        let reject = OpenConnectPlan.Change.route(.init(IPNetwork("::/1")!, via: .reject))
        let server = OpenConnectPlan.Change.route(
            .init(IPNetwork("192.0.2.10/32")!, via: .gateway(OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "wlan0")!)))
        var record = try XCTUnwrap(OpenConnectRecord(interface: "tun0"))
        try record.append(.begin(.link(interface: "tun0", mtu: 1406)))
        try record.append(.owned(.link(interface: "tun0", mtu: 1406)))
        try record.append(.begin(server))
        try record.append(.owned(server))
        try record.append(.begin(reject))
        try record.text().write(toFile: OpenConnectJournal.path(runDir: runDir), atomically: false, encoding: .utf8)
        system.table.append(KernelRoute(network: IPNetwork("192.0.2.10/32")!, gateway: IPAddress("198.51.100.1"), interface: "wlan0"))
        system.table.append(KernelRoute(OpenConnectPlan.Route(IPNetwork("::/1")!, via: .reject)))
        // openconnect was killed: tun0 went with it (another tun0 may be someone else's now).
        system.interfaces["tun0"] = 40
        XCTAssertEqual(restore(), .done)
        XCTAssertEqual(system.log, [ip("-6 route del unreachable ::/1"), ip("-4 route del 192.0.2.10/32 via 198.51.100.1 dev wlan0")])
        XCTAssertEqual(system.table, Self.table)
        XCTAssertTrue(OpenConnectMarks.isStopping(runDir: runDir))
    }

    // MARK: - The routing table from rtnetlink

    func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xFF), UInt8(v >> 8)] }
    func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }
    func attribute(_ type: UInt16, _ value: [UInt8]) -> [UInt8] {
        let length = 4 + value.count
        return le16(UInt16(length)) + le16(type) + value + [UInt8](repeating: 0, count: Netlink.align(length) - length)
    }

    /// An RTM_NEWROUTE payload: `struct rtmsg`, then RTA_DST, RTA_SRC, RTA_OIF, RTA_GATEWAY, RTA_PRIORITY,
    /// RTA_MULTIPATH.
    func route(
        _ destination: [UInt8], _ length: UInt8, family: UInt8 = 2, table: UInt8 = 254, type: UInt8 = 1, oif: UInt32? = nil,
        gateway: [UInt8]? = nil, priority: UInt32? = nil, hops: [(UInt32, [UInt8])] = [], source: ([UInt8], UInt8)? = nil
    ) -> Netlink.Route? {
        var body: [UInt8] = [family, length, source?.1 ?? 0, 0, table, 3, 0, type] + le32(0)
        if !destination.isEmpty { body += attribute(1, destination) }
        if let source { body += attribute(2, source.0) }
        if let oif { body += attribute(4, le32(oif)) }
        if let gateway { body += attribute(5, gateway) }
        if let priority { body += attribute(6, le32(priority)) }
        if !hops.isEmpty {
            var multipath: [UInt8] = []
            for (index, address) in hops {
                let inner = attribute(5, address)
                multipath += le16(UInt16(8 + inner.count)) + [0, 0] + le32(index) + inner
            }
            body += attribute(9, multipath)
        }
        return Netlink.Route(ArraySlice(body))
    }

    func testRoutesFromRtnetlink() throws {
        let names: [Int32: String] = [1: "lo", 2: "eth0", 3: "wlan0", 30: "tun0"]
        let fe80: [UInt8] = [0xFE, 0x80] + [UInt8](repeating: 0, count: 13) + [1]
        let parsed = [
            route([], 0, oif: 3, gateway: [198, 51, 100, 1], priority: 600),
            route([], 0, oif: 2, gateway: [192, 168, 1, 1], priority: 100),
            route([10, 0, 0, 0], 8, oif: 30),
            route([0, 0, 0, 0], 1, type: 7),  // unreachable 0.0.0.0/1
            route([], 0, family: 10, oif: 3, gateway: fe80, priority: 1024),
            route([0x80] + [UInt8](repeating: 0, count: 15), 1, family: 10, type: 7, oif: 1),
            route([203, 0, 113, 0], 24, hops: [(2, [192, 168, 1, 1]), (3, [198, 51, 100, 1])]),
            route([127, 0, 0, 0], 8, table: 255, type: 2, oif: 1),  // the local table
            route([10, 1, 2, 3], 8, oif: 2)  // host bits set: not a route this reader keeps
        ].compactMap { $0 }
        XCTAssertEqual(parsed.count, 9)
        XCTAssertEqual(parsed[0].nextHops, [.init(interface: 3, gateway: [198, 51, 100, 1])])
        XCTAssertEqual(parsed[0].priority, 600)
        XCTAssertEqual(parsed[6].interfaces, [2, 3])
        let routes = KernelRoute.linux(parsed) { names[$0] }
        XCTAssertEqual(
            routes,
            [
                // Metric 0 first, in the kernel's order; then 100, 600, 1024.
                KernelRoute(network: IPNetwork("10.0.0.0/8")!, interface: "tun0"),
                KernelRoute(network: IPNetwork("0.0.0.0/1")!, interface: "", reject: true),
                KernelRoute(network: IPNetwork("8000::/1")!, interface: "lo", reject: true),
                KernelRoute(network: IPNetwork("203.0.113.0/24")!, gateway: IPAddress("192.168.1.1"), interface: "eth0"),
                KernelRoute(network: IPNetwork("203.0.113.0/24")!, gateway: IPAddress("198.51.100.1"), interface: "wlan0"),
                KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("192.168.1.1"), interface: "eth0"),
                KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("198.51.100.1"), interface: "wlan0"),
                KernelRoute(network: IPNetwork("::/0")!, gateway: IPAddress("fe80::1"), interface: "wlan0")
            ])
        // The default gateway is the preferred one (the lower metric), as the kernel uses it.
        let underlay = OpenConnectPlan.Underlay(routes: routes, attached: [], tunnel: "tun0")
        XCTAssertEqual(underlay.ipv4?.description, "192.168.1.1 eth0")
        XCTAssertEqual(underlay.ipv6?.description, "fe80::1 wlan0")
        // The hook's own routes, as `ip` adds them, are what it planned.
        XCTAssertTrue(routes[0].is(.init(IPNetwork("10.0.0.0/8")!, via: .interface("tun0"))))
        XCTAssertTrue(routes[1].is(.init(IPNetwork("0.0.0.0/1")!, via: .reject)))
        XCTAssertFalse(routes[1].is(.init(IPNetwork("0.0.0.0/1")!, via: .interface("tun0"))))
    }

    /// A source-specific route (`from <prefix>`, IPv6 source routing on a multihomed host) only applies to some
    /// traffic: never the default gateway, never in the way of a route the hook adds, never one it made or
    /// holds, so a source-specific reject route does not count as the IPv6 block.
    func testSourceSpecificRoutesAreNotForAllTraffic() throws {
        let names: [Int32: String] = [1: "lo", 3: "wlan0", 4: "eth1"]
        let fe80a: [UInt8] = [0xFE, 0x80] + [UInt8](repeating: 0, count: 13) + [0xA]
        let fe80: [UInt8] = [0xFE, 0x80] + [UInt8](repeating: 0, count: 13) + [1]
        let prefixA: [UInt8] = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x0A] + [UInt8](repeating: 0, count: 10)
        let parsed = [
            // default from 2001:db8:a::/48 via fe80::a dev eth1 (metric 0), then the ordinary default (1024).
            route([], 0, family: 10, oif: 4, gateway: fe80a, source: (prefixA, 48)),
            route([], 0, family: 10, oif: 3, gateway: fe80, priority: 1024),
            // unreachable ::/1 from 2001:db8:a::/48: not a block of all IPv6.
            route([], 1, family: 10, type: 7, oif: 1, source: (prefixA, 48)),
            route([], 0, oif: 3, gateway: [198, 51, 100, 1])
        ].compactMap { $0 }
        XCTAssertEqual(parsed.count, 4)
        XCTAssertEqual(parsed[0].sourceLength, 48)
        XCTAssertEqual(parsed[0].source, prefixA)
        XCTAssertEqual(parsed[3].sourceLength, 0)
        let routes = KernelRoute.linux(parsed) { names[$0] }
        XCTAssertEqual(routes.filter(\.sourceSpecific).count, 2)
        XCTAssertFalse(routes.filter(\.sourceSpecific).contains(where: \.holdsDestination))

        let underlay = OpenConnectPlan.Underlay(routes: routes, attached: [], tunnel: "tun0")
        XCTAssertEqual(underlay.ipv6?.description, "fe80::1 wlan0", "not the source-specific default")
        let block = OpenConnectPlan.Route(IPNetwork("::/1")!, via: .reject)
        XCTAssertFalse(routes.contains { $0.is(block) })
        XCTAssertEqual(OpenConnectHook.finding(block, in: routes, claimed: [], attached: []), .absent)

        // The hook sets up the real block next to it, and a reconnect that finds only the source-specific one
        // fails.
        system.table = routes
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertTrue(system.log.contains(ip("-6 route add unreachable ::/1")), "\(system.log)")
        XCTAssertTrue(system.log.contains(ip("-4 route add 192.0.2.10/32 via 198.51.100.1 dev wlan0")), "\(system.log)")
        system.table.removeAll { $0.reject && !$0.sourceSpecific && $0.network == IPNetwork("::/1")! }
        let outcome = run(.reconnect(Self.full))
        XCTAssertTrue(outcome.stopTool)
        XCTAssertEqual(
            outcome.lines.last,
            VPNHook.failureLine("the network changed while the connection was re-established: the route for ::/1 is no longer as it was set up"))
    }

    // MARK: - The distribution's openconnect

    func testOpenConnectVersionsAndOptions() {
        XCTAssertEqual(ToolSpec.openConnectVersion("OpenConnect version v9.12\nUsing GnuTLS 3.8.3. Features present: PKCS#11\n"), ToolVersion(9, 12))
        XCTAssertEqual(ToolSpec.openConnectVersion("OpenConnect version v9.01-3\n"), ToolVersion(9, 1))
        XCTAssertEqual(ToolSpec.openConnectVersion("OpenConnect version v8.20-1\n"), ToolVersion(8, 20))
        XCTAssertEqual(ToolSpec.openConnectVersion("OpenConnect version v9.21-12-gabcdef0\n"), ToolVersion(9, 21))
        XCTAssertNil(ToolSpec.openConnectVersion("openconnect: unrecognized option\n"))
        XCTAssertNil(ToolSpec.openConnectVersion("OpenVPN 2.6.9\n"))
        XCTAssertEqual(ToolSpec.openconnect.candidates, ["/usr/sbin/openconnect", "/usr/bin/openconnect"])
        XCTAssertEqual(ToolSpec.openconnect.minimum, ToolVersion(9, 1))
        XCTAssertTrue(ToolVersion(9, 1) >= ToolSpec.openconnect.minimum, "Debian 12, EPEL 9")
        XCTAssertTrue(ToolVersion(9, 12) >= ToolSpec.openconnect.minimum, "Ubuntu 24.04, Debian 13, Fedora")
        XCTAssertTrue(ToolVersion(8, 20) < ToolSpec.openconnect.minimum, "Ubuntu 22.04")
        // openconnect's own way of writing its versions.
        XCTAssertEqual(ToolSpec.openconnect.minimum.description, "9.01")
        XCTAssertEqual(ToolVersion(9, 12, twoDigitMinor: true).description, "9.12")
        XCTAssertEqual(ToolVersion(2, 6, 9).description, "2.6.9")
        XCTAssertEqual(
            ToolFailure.tooOld(
                name: "openconnect", version: ToolSpec.openConnectVersion("OpenConnect version v8.20-1\n")!,
                minimum: ToolSpec.openconnect.minimum, package: "openconnect"
            ).description,
            "openconnect 8.20 is too old: PassTunnel needs 9.01 or later. Update the openconnect package.")
        XCTAssertEqual(
            ToolFailure.notInstalled(
                name: "openconnect", candidates: ToolSpec.openconnect.candidates, package: "openconnect", minimum: ToolSpec.openconnect.minimum
            )
            .description,
            "openconnect is not installed (none of /usr/sbin/openconnect, /usr/bin/openconnect exists). "
                + "Install the distribution's openconnect package, version 9.01 or later.")
        XCTAssertEqual(
            ToolFailure.tooOld(name: "OpenVPN", version: ToolVersion(2, 5, 11), minimum: ToolVersion(2, 6, 0), package: "openvpn").description,
            "OpenVPN 2.5.11 is too old: PassTunnel needs 2.6.0 or later. Update the openvpn package.")

        // `--no-external-auth` only as an option of its own (9.10 and later).
        let help912 = """
            Usage:  openconnect [options] <server>
                  --no-external-auth          Do not offer or use auth methods requiring external browser
                  --no-http-keepalive         Disable HTTP connection re-use
            """
        XCTAssertTrue(ToolSpec.openConnectHasNoExternalAuth(help: help912))
        XCTAssertFalse(ToolSpec.openConnectHasNoExternalAuth(help: "      --no-http-keepalive         Disable HTTP connection re-use\n"))
        XCTAssertFalse(ToolSpec.openConnectHasNoExternalAuth(help: "      --no-external-authentication\n"))
        XCTAssertFalse(ToolSpec.openConnectHasNoExternalAuth(help: ""))
    }

    /// `DistributionTools.resolve` on files of the test's own user (owner and base are the test's): the version
    /// read from what the tool prints, 8.20 refused naming the minimum, a tool writable by others refused.
    func testResolvingTheDistributionTool() throws {
        let base = try XCTUnwrap(HelperCore.realPath(root))
        let bin = base + "/sbin"
        try FileManager.default.createDirectory(atPath: bin, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        chmod(base, 0o755)
        let tool = bin + "/openconnect"
        try "#!/bin/sh\nexit 0\n".write(toFile: tool, atomically: true, encoding: .utf8)
        chmod(tool, 0o755)
        let spec = ToolSpec(
            name: "openconnect", candidates: [bin + "/none", tool], minimum: ToolSpec.openconnect.minimum, package: "openconnect",
            versionArguments: ["--version"], parseVersion: ToolSpec.openConnectVersion)
        var output = "OpenConnect version v9.12\n"
        let resolve = {
            try DistributionTools.resolve(spec, owner: geteuid(), base: base) { path, arguments in
                XCTAssertEqual(path, tool)
                XCTAssertEqual(arguments, ["--version"])
                return output
            }
        }
        XCTAssertEqual(try resolve(), ResolvedTool(path: tool, version: ToolVersion(9, 12)))
        output = "OpenConnect version v8.20-1\n"
        XCTAssertThrowsError(try resolve()) {
            XCTAssertEqual(String(describing: $0), "openconnect 8.20 is too old: PassTunnel needs 9.01 or later. Update the openconnect package.")
        }
        output = "garbage"
        XCTAssertThrowsError(try resolve()) { XCTAssertEqual($0 as? ToolFailure, .unknownVersion(name: "openconnect", path: tool)) }
        chmod(tool, 0o777)
        output = "OpenConnect version v9.12\n"
        XCTAssertThrowsError(try resolve()) {
            XCTAssertEqual($0 as? ToolFailure, .untrusted(name: "openconnect", path: tool, reason: "\(tool) is writable by its group or by others."))
        }
    }
}
