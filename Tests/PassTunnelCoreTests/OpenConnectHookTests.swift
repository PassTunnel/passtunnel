import Foundation
import XCTest

@testable import PassTunnelShared

/// A Mac that only exists in memory: the routing table, the interfaces and the DNS keys the hook reads and
/// changes, and a log of every command line and DNS write. Nothing here touches the real network.
final class FakeOpenConnectSystem: OpenConnectSystem {
    var interfaces: [String: UInt32] = ["utun5": 20, "en0": 11, "en7": 12]
    var addresses: [String: [IPAddress]] = [:]
    var up: Set<String> = []
    var attached: [OpenConnectPlan.Attached] = [OpenConnectPlan.Attached(IPNetwork("192.168.1.0/24")!, interface: "en0")]
    var table: [KernelRoute] = [
        KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("198.51.100.1"), interface: "en0"),
        KernelRoute(network: IPNetwork("192.168.1.0/24")!, interface: "en0"),
        KernelRoute(network: IPNetwork("::/0")!, gateway: IPAddress("fe80::1"), interface: "en0"),
        // Made by the kernel for the connection to the server: never in the way of a route.
        KernelRoute(network: IPNetwork("192.0.2.10/32")!, gateway: IPAddress("198.51.100.1"), interface: "en0", cloned: true)
    ]
    var dns: [String: [String: OpenConnectDNSSettings.Value]] = [:]
    var log: [String] = []
    var routesReadable = true
    var dnsWritable = true
    /// Makes a command fail (a result) or lets it run (nil).
    var failing: (OpenConnectCommand) -> OpenConnectCommand.Result? = { _ in nil }
    /// Runs before every command.
    var before: (OpenConnectCommand) -> Void = { _ in }
    var timeouts: [TimeInterval] = []

    func interfaceIndex(_ name: String) -> UInt32? { interfaces[name] }
    func interfaceAddresses(_ name: String) -> [IPAddress] { addresses[name] ?? [] }
    func attachedNetworks() -> [OpenConnectPlan.Attached] { attached }
    func routes() -> [KernelRoute]? { routesReadable ? table : nil }

    func run(_ command: OpenConnectCommand, timeout: TimeInterval) -> OpenConnectCommand.Result {
        before(command)
        log.append(command.line)
        timeouts.append(timeout)
        if let result = failing(command) { return result }
        switch command.effect {
        case .link(let interface, _):
            guard interfaces[interface] != nil else { return .init(status: 1, output: "ifconfig: interface does not exist") }
            up.insert(interface)
        case .linkDown(let interface):
            up.remove(interface)
        case .addAddress(let interface, let address):
            addresses[interface, default: []].append(address)
        case .deleteAddress(let interface, let address):
            addresses[interface]?.removeAll { $0 == address }
        case .addRoute(let route):
            if let i = table.firstIndex(where: { $0.network == route.network && $0.cloned }) { table.remove(at: i) }
            if table.contains(where: { $0.network == route.network && $0.holdsDestination }) {
                return .init(status: 1, output: "route: writing to routing socket: File exists")
            }
            table.append(KernelRoute(route))
        case .deleteRoute(let route):
            guard let i = table.firstIndex(where: { $0.network == route.network && $0.holdsDestination }) else {
                return .init(status: 1, output: "not in table")
            }
            table.remove(at: i)
        }
        return .init(status: 0)
    }

    func setDNS(_ settings: OpenConnectDNSSettings) -> Bool {
        log.append("dns set " + settings.service)
        guard dnsWritable else { return false }
        for key in settings.removedKeys { dns[key] = nil }
        for (key, value) in settings.values { dns[key] = value }
        return true
    }

    func hasDNS(_ settings: OpenConnectDNSSettings) -> Bool {
        settings.values.allSatisfy { dns[$0.key] == $0.value }
    }

    func removeDNS(service: String) -> Bool {
        log.append("dns remove " + service)
        guard dnsWritable else { return false }
        for key in OpenConnectDNSSettings.keys(service: service) { dns[key] = nil }
        return true
    }
}

/// openconnect's hook, the part that changes the network (#183): `OpenConnectHook` against the fake Mac above,
/// its record and lock in a temporary run root, the exact argument lists and DNS keys, and the helper's revert.
final class OpenConnectHookTests: XCTestCase {
    var root: String!
    var runDir: String { root + "/501/acme" }
    var otherDir: String { root + "/501/other" }
    var system: FakeOpenConnectSystem!
    var clock = Date(timeIntervalSince1970: 1_000_000)

    static let policy = OpenConnectPolicy(uid: 501, profileID: "acme", setRoutes: true, setDNS: true)

    /// IPv4 only, no includes: a full tunnel, IPv6 blocked.
    static let full = OpenConnectNetwork(
        interface: "utun5", gateway: IPAddress("192.0.2.10")!,
        ipv4: .init(address: IPAddress("10.11.0.2")!, network: IPNetwork("10.11.0.0/24")), ipv6: nil, mtu: 1406,
        dnsServers: [IPAddress("10.11.0.53")!], defaultDomains: ["example.com"])

    /// Both families, split includes, split DNS.
    static let split = OpenConnectNetwork(
        interface: "utun5", gateway: IPAddress("192.0.2.10")!,
        ipv4: .init(address: IPAddress("10.11.0.2")!, network: IPNetwork("10.11.0.0/24")),
        ipv6: .init(address: IPAddress("2001:db8:1::2")!, network: IPNetwork("2001:db8:1::/64")), mtu: 1400,
        dnsServers: [IPAddress("172.16.0.53")!, IPAddress("2001:db8:1::53")!], defaultDomains: ["example.com"],
        splitDNSDomains: ["corp.example.com"], ipv4Includes: [IPNetwork("10.0.0.0/8")!], ipv4Excludes: [IPNetwork("10.99.0.0/16")!],
        ipv6Includes: [IPNetwork("2001:db8::/32")!])

    override func setUpWithError() throws {
        var template = Array("/tmp/pt-hook-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        root = String(cString: made)
        try FileManager.default.createDirectory(atPath: runDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: otherDir, withIntermediateDirectories: true)
        system = FakeOpenConnectSystem()
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: root)
    }

    func hook(dir: String? = nil, deadline: TimeInterval = OpenConnectHook.runLimit) -> OpenConnectHook {
        var hook = OpenConnectHook(
            runRoot: root, runDir: dir ?? runDir, system: system, deadline: clock.addingTimeInterval(deadline),
            identity: (4242, ProcessStart(seconds: 1_000_000, microseconds: 5)))
        let clock = clock
        hook.now = { clock }
        return hook
    }

    @discardableResult
    func run(_ event: OpenConnectNetwork.Event, policy: OpenConnectPolicy = OpenConnectHookTests.policy, dir: String? = nil)
        -> OpenConnectHook.Outcome
    {
        hook(dir: dir).run(event: { event }, policy: { policy })
    }

    func record(_ dir: String? = nil) throws -> OpenConnectRecord {
        try XCTUnwrap(OpenConnectJournal.read(OpenConnectJournal.path(runDir: dir ?? runDir)))
    }

    func recordText(_ dir: String? = nil) throws -> String {
        try String(contentsOfFile: OpenConnectJournal.path(runDir: dir ?? runDir), encoding: .utf8)
    }

    var originalTable: [KernelRoute] { FakeOpenConnectSystem().table }

    // MARK: - Commands and keys, to the byte

    func testCommandArgumentLists() {
        func route(_ network: String, _ via: OpenConnectPlan.Via) -> OpenConnectPlan.Route { .init(IPNetwork(network)!, via: via) }
        let v4 = OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "en0")!
        let v6 = OpenConnectPlan.Gateway(address: IPAddress("fe80::1"), interface: "en0")!
        let v6Global = OpenConnectPlan.Gateway(address: IPAddress("2001:db8::1"), interface: "en0")!
        let link = OpenConnectPlan.Gateway(address: nil, interface: "ppp0")!
        let cases: [(OpenConnectCommand, String)] = [
            (.link("utun5", mtu: 1406), "/sbin/ifconfig utun5 mtu 1406 up"),
            (.linkDown("utun5"), "/sbin/ifconfig utun5 down"),
            (.addAddress("utun5", IPAddress("10.11.0.2")!), "/sbin/ifconfig utun5 inet 10.11.0.2 10.11.0.2 netmask 255.255.255.255"),
            (.addAddress("utun5", IPAddress("2001:db8:1::2")!), "/sbin/ifconfig utun5 inet6 2001:db8:1::2 prefixlen 128"),
            (.deleteAddress("utun5", IPAddress("10.11.0.2")!), "/sbin/ifconfig utun5 inet 10.11.0.2 delete"),
            (.deleteAddress("utun5", IPAddress("2001:db8:1::2")!), "/sbin/ifconfig utun5 inet6 2001:db8:1::2 delete"),
            (.addRoute(route("0.0.0.0/1", .interface("utun5"))), "/sbin/route -n add -inet -net 0.0.0.0 -netmask 128.0.0.0 -interface utun5"),
            (.addRoute(route("128.0.0.0/1", .interface("utun5"))), "/sbin/route -n add -inet -net 128.0.0.0 -netmask 128.0.0.0 -interface utun5"),
            (.addRoute(route("10.0.0.0/8", .interface("utun5"))), "/sbin/route -n add -inet -net 10.0.0.0 -netmask 255.0.0.0 -interface utun5"),
            (.addRoute(route("10.11.0.53/32", .interface("utun5"))), "/sbin/route -n add -inet -host 10.11.0.53 -interface utun5"),
            (.addRoute(route("192.0.2.10/32", .gateway(v4))), "/sbin/route -n add -inet -host 192.0.2.10 198.51.100.1"),
            (.addRoute(route("10.99.0.0/16", .gateway(v4))), "/sbin/route -n add -inet -net 10.99.0.0 -netmask 255.255.0.0 198.51.100.1"),
            (.addRoute(route("192.0.2.10/32", .gateway(link))), "/sbin/route -n add -inet -host 192.0.2.10 -interface ppp0"),
            (.addRoute(route("2001:db8::10/128", .gateway(v6))), "/sbin/route -n add -inet6 -host 2001:db8::10 fe80::1%en0"),
            (.addRoute(route("2001:db8:5::/48", .gateway(v6Global))), "/sbin/route -n add -inet6 -net 2001:db8:5:: -prefixlen 48 2001:db8::1"),
            (.addRoute(route("::/1", .interface("utun5"))), "/sbin/route -n add -inet6 -net :: -prefixlen 1 -interface utun5"),
            (.addRoute(route("8000::/1", .interface("utun5"))), "/sbin/route -n add -inet6 -net 8000:: -prefixlen 1 -interface utun5"),
            (.addRoute(route("::/1", .reject)), "/sbin/route -n add -inet6 -net :: -prefixlen 1 ::1 -reject"),
            (.addRoute(route("8000::/1", .reject)), "/sbin/route -n add -inet6 -net 8000:: -prefixlen 1 ::1 -reject"),
            (.addRoute(route("0.0.0.0/1", .reject)), "/sbin/route -n add -inet -net 0.0.0.0 -netmask 128.0.0.0 127.0.0.1 -reject"),
            (.deleteRoute(route("0.0.0.0/1", .interface("utun5"))), "/sbin/route -n delete -inet -net 0.0.0.0 -netmask 128.0.0.0"),
            (.deleteRoute(route("192.0.2.10/32", .gateway(v4))), "/sbin/route -n delete -inet -host 192.0.2.10"),
            (.deleteRoute(route("::/1", .reject)), "/sbin/route -n delete -inet6 -net :: -prefixlen 1"),
            (.deleteRoute(route("2001:db8::10/128", .gateway(v6))), "/sbin/route -n delete -inet6 -host 2001:db8::10")
        ]
        for (command, line) in cases {
            XCTAssertEqual(command.line, line)
            XCTAssertTrue(command.executable == "/sbin/route" || command.executable == "/sbin/ifconfig")
            // An argument list: no word holds a blank or anything a shell would read.
            XCTAssertTrue(command.arguments.allSatisfy { !$0.isEmpty && $0.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7F && $0 != 0x24 && $0 != 0x60 } })
        }
    }

    func testDNSKeys() {
        let service = "passtunnel-501-acme"
        // A full tunnel: the service names the tunnel as its router and asks to be the primary one, so its DNS is
        // the default resolver.
        let primary = OpenConnectDNSSettings(
            OpenConnectPlan.DNS(
                service: service, interface: "utun5", primary: true, servers: [IPAddress("10.11.0.53")!], searchDomains: ["example.com"],
                matchDomains: []), addresses: [IPAddress("10.11.0.2")!])
        XCTAssertEqual(
            primary.values,
            [
                "State:/Network/Service/passtunnel-501-acme/IPv4": [
                    "Addresses": .strings(["10.11.0.2"]), "SubnetMasks": .strings(["255.255.255.255"]), "Router": .string("10.11.0.2"),
                    "InterfaceName": .string("utun5"), "OverridePrimary": .number(1)
                ],
                "State:/Network/Service/passtunnel-501-acme/DNS": [
                    "ServerAddresses": .strings(["10.11.0.53"]), "SearchDomains": .strings(["example.com"])
                ]
            ])
        XCTAssertEqual(primary.removedKeys, ["State:/Network/Service/passtunnel-501-acme/IPv6"])

        let dual = OpenConnectDNSSettings(
            OpenConnectPlan.DNS(
                service: service, interface: "utun5", primary: true, servers: [IPAddress("2001:db8:1::53")!], searchDomains: [],
                matchDomains: []), addresses: [IPAddress("10.11.0.2")!, IPAddress("2001:db8:1::2")!])
        XCTAssertEqual(
            dual.values["State:/Network/Service/passtunnel-501-acme/IPv6"],
            [
                "Addresses": .strings(["2001:db8:1::2"]), "PrefixLength": .numbers([128]), "Router": .string("2001:db8:1::2"),
                "InterfaceName": .string("utun5"), "OverridePrimary": .number(1)
            ])
        XCTAssertEqual(dual.values["State:/Network/Service/passtunnel-501-acme/DNS"], ["ServerAddresses": .strings(["2001:db8:1::53"])])
        XCTAssertEqual(dual.removedKeys, [])

        // A split tunnel: a resolver for its domains only; the service is never a candidate for primary.
        let split = OpenConnectDNSSettings(
            OpenConnectPlan.DNS(
                service: service, interface: "utun5", primary: false, servers: [IPAddress("10.11.0.53")!, IPAddress("2001:db8:1::53")!],
                searchDomains: [], matchDomains: ["corp.example.com", "example.com"]),
            addresses: [IPAddress("10.11.0.2")!, IPAddress("2001:db8:1::2")!])
        XCTAssertEqual(
            split.values,
            [
                "State:/Network/Service/passtunnel-501-acme/DNS": [
                    "ServerAddresses": .strings(["10.11.0.53", "2001:db8:1::53"]),
                    "SupplementalMatchDomains": .strings(["corp.example.com", "example.com"])
                ]
            ])
        XCTAssertEqual(split.removedKeys, ["State:/Network/Service/passtunnel-501-acme/IPv4", "State:/Network/Service/passtunnel-501-acme/IPv6"])
        // Only dynamic keys of the session's own service.
        for key in OpenConnectDNSSettings.keys(service: service) { XCTAssertTrue(key.hasPrefix("State:/Network/Service/passtunnel-501-acme/")) }
    }

    func testResultSummary() {
        XCTAssertEqual(OpenConnectCommand.Result(status: 1, output: "File exists").summary, "exit status 1: File exists")
        XCTAssertEqual(OpenConnectCommand.Result(status: nil).summary, "did not finish")
        XCTAssertTrue(OpenConnectCommand.Result(status: 0).succeeded)
    }

    // MARK: - connect and disconnect

    func testConnectFullTunnelThenDisconnect() throws {
        let outcome = run(.connect(Self.full))
        XCTAssertEqual(
            outcome,
            OpenConnectHook.Outcome(
                lines: ["passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes, full tunnel, IPv6 blocked, DNS 10.11.0.53, search example.com\n"]))
        XCTAssertEqual(
            system.log,
            [
                "/sbin/ifconfig utun5 mtu 1406 up",
                "/sbin/ifconfig utun5 inet 10.11.0.2 10.11.0.2 netmask 255.255.255.255",
                "/sbin/route -n add -inet -host 192.0.2.10 198.51.100.1",
                "/sbin/route -n add -inet6 -net :: -prefixlen 1 ::1 -reject",
                "/sbin/route -n add -inet6 -net 8000:: -prefixlen 1 ::1 -reject",
                "/sbin/route -n add -inet -net 0.0.0.0 -netmask 128.0.0.0 -interface utun5",
                "/sbin/route -n add -inet -net 128.0.0.0 -netmask 128.0.0.0 -interface utun5",
                "dns set passtunnel-501-acme"
            ])
        XCTAssertEqual(system.dns["State:/Network/Service/passtunnel-501-acme/IPv4"]?["OverridePrimary"], .number(1))
        XCTAssertEqual(system.dns["State:/Network/Service/passtunnel-501-acme/IPv4"]?["Router"], .string("10.11.0.2"))
        XCTAssertNil(system.dns["State:/Network/Service/passtunnel-501-acme/IPv6"])
        XCTAssertEqual(
            try recordText(),
            """
            passtunnel-network 1
            interface utun5
            + link utun5 mtu 1406
            = link utun5 mtu 1406
            + address utun5 10.11.0.2
            = address utun5 10.11.0.2
            + route 192.0.2.10/32 gateway 198.51.100.1 en0
            = route 192.0.2.10/32 gateway 198.51.100.1 en0
            + route ::/1 reject
            = route ::/1 reject
            + route 8000::/1 reject
            = route 8000::/1 reject
            + route 0.0.0.0/1 interface utun5
            = route 0.0.0.0/1 interface utun5
            + route 128.0.0.0/1 interface utun5
            = route 128.0.0.0/1 interface utun5
            + dns passtunnel-501-acme utun5 primary servers=10.11.0.53 search=example.com match=-
            = dns passtunnel-501-acme utun5 primary servers=10.11.0.53 search=example.com match=-
            status up

            """)
        XCTAssertTrue(VPNHook.reportedUp(runDir: runDir))
        // Every tool had the per-tool limit; the marks are gone, the lock file stays.
        XCTAssertTrue(system.timeouts.allSatisfy { $0 == OpenConnectHook.toolLimit })
        XCTAssertNil(OpenConnectMarks.runningHook(runDir: runDir))
        XCTAssertTrue(FileManager.default.fileExists(atPath: root + "/" + OpenConnectLock.fileName))

        system.log = []
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertEqual(
            system.log,
            [
                "dns remove passtunnel-501-acme",
                "/sbin/route -n delete -inet -net 128.0.0.0 -netmask 128.0.0.0",
                "/sbin/route -n delete -inet -net 0.0.0.0 -netmask 128.0.0.0",
                "/sbin/route -n delete -inet6 -net 8000:: -prefixlen 1",
                "/sbin/route -n delete -inet6 -net :: -prefixlen 1",
                "/sbin/route -n delete -inet -host 192.0.2.10",
                "/sbin/ifconfig utun5 inet 10.11.0.2 delete",
                "/sbin/ifconfig utun5 down"
            ])
        XCTAssertEqual(system.table, originalTable.filter { !$0.cloned })
        XCTAssertEqual(system.dns, [:])
        XCTAssertEqual(try record().owned, [])
        XCTAssertTrue(try record().states.values.allSatisfy { $0 == .reverted })
        // A second disconnect finds nothing to do.
        system.log = []
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log, [])
    }

    func testConnectSplitTunnel() throws {
        system.addresses["en0"] = [IPAddress("192.168.1.46")!]
        let outcome = run(.connect(Self.split))
        XCTAssertFalse(outcome.stopTool)
        XCTAssertEqual(
            outcome.lines,
            [
                "passtunnel vpn-hook: utun5 up: 10.11.0.2, 2001:db8:1::2, 3 routes, DNS 172.16.0.53 2001:db8:1::53, search example.com, split DNS corp.example.com example.com\n"
            ])
        XCTAssertEqual(
            system.log,
            [
                "/sbin/ifconfig utun5 mtu 1400 up",
                "/sbin/ifconfig utun5 inet 10.11.0.2 10.11.0.2 netmask 255.255.255.255",
                "/sbin/ifconfig utun5 inet6 2001:db8:1::2 prefixlen 128",
                "/sbin/route -n add -inet -net 10.99.0.0 -netmask 255.255.0.0 198.51.100.1",
                "/sbin/route -n add -inet -net 10.0.0.0 -netmask 255.0.0.0 -interface utun5",
                // The DNS server outside the includes; the assigned networks and the other server are inside them.
                "/sbin/route -n add -inet -host 172.16.0.53 -interface utun5",
                "/sbin/route -n add -inet6 -net 2001:db8:: -prefixlen 32 -interface utun5",
                "dns set passtunnel-501-acme"
            ])
        let dns = system.dns["State:/Network/Service/passtunnel-501-acme/DNS"]
        XCTAssertEqual(dns?["SupplementalMatchDomains"], .strings(["corp.example.com", "example.com"]))
        // Split: no entity that could make the service primary.
        XCTAssertNil(system.dns["State:/Network/Service/passtunnel-501-acme/IPv4"])
        XCTAssertNil(system.dns["State:/Network/Service/passtunnel-501-acme/IPv6"])

        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        // The server's address is not captured: no route to it was added (and the kernel's own stays).
        XCTAssertEqual(system.table, originalTable)
        XCTAssertEqual(system.addresses["utun5"], [])
        XCTAssertEqual(system.dns, [:])
    }

    func testPolicyWithoutRoutesOrDNS() throws {
        let policy = OpenConnectPolicy(uid: 501, profileID: "acme", setRoutes: false, setDNS: false)
        XCTAssertFalse(run(.connect(Self.full), policy: policy).stopTool)
        XCTAssertEqual(system.log, ["/sbin/ifconfig utun5 mtu 1406 up", "/sbin/ifconfig utun5 inet 10.11.0.2 10.11.0.2 netmask 255.255.255.255"])
        XCTAssertEqual(system.dns, [:])
    }

    func testPreInitDoesNothing() {
        XCTAssertEqual(run(.preInit), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log, [])
        XCTAssertFalse(OpenConnectJournal.exists(runDir: runDir))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root + "/" + OpenConnectLock.fileName))
    }

    // MARK: - Routes that are there already

    func testTheSameRouteThereAlreadyIsNotTheSessions() throws {
        // Another session's block: found there (`~`), never removed by this session.
        system.table.append(KernelRoute(OpenConnectPlan.Route(IPNetwork("::/1")!, via: .reject)))
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertFalse(system.log.contains("/sbin/route -n add -inet6 -net :: -prefixlen 1 ::1 -reject"))
        XCTAssertTrue(try recordText().contains("~ route ::/1 reject\n"))
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertFalse(system.log.contains("/sbin/route -n delete -inet6 -net :: -prefixlen 1"))
        XCTAssertTrue(system.table.contains { $0.network == IPNetwork("::/1")! && $0.reject })
    }

    func testAnotherRouteOfTheDestination() throws {
        // The server excludes the LAN the Mac is on: that route exists (on-link), and is the session's to keep.
        var network = Self.split
        network = OpenConnectNetwork(
            interface: network.interface, gateway: network.gateway, ipv4: network.ipv4, ipv6: nil, mtu: 1400, ipv4Includes: network.ipv4Includes,
            ipv4Excludes: [IPNetwork("192.168.1.0/24")!])
        XCTAssertFalse(run(.connect(network)).stopTool)
        XCTAssertTrue(try recordText().contains("~ route 192.168.1.0/24 gateway 198.51.100.1 en0\n"))
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertTrue(system.table.contains { $0.network == IPNetwork("192.168.1.0/24")! && $0.gateway == nil })
    }

    func testAFullTunnelHalfThatExistsFailsTheSetUp() throws {
        // Another VPN routes all traffic already.
        system.interfaces["utun3"] = 18
        system.table.append(KernelRoute(network: IPNetwork("0.0.0.0/1")!, interface: "utun3"))
        let outcome = run(.connect(Self.full))
        XCTAssertTrue(outcome.stopTool)
        XCTAssertEqual(
            outcome.lines, [VPNHook.failureLine("another route for 0.0.0.0/1 exists already, through utun3")])
        // What the set-up made is reverted, the other VPN's route is not touched.
        XCTAssertEqual(
            Array(system.log.suffix(6)),
            [
                // Found in the way before any command: never added.
                "/sbin/route -n add -inet6 -net 8000:: -prefixlen 1 ::1 -reject",
                "/sbin/route -n delete -inet6 -net 8000:: -prefixlen 1",
                "/sbin/route -n delete -inet6 -net :: -prefixlen 1",
                "/sbin/route -n delete -inet -host 192.0.2.10",
                "/sbin/ifconfig utun5 inet 10.11.0.2 delete",
                "/sbin/ifconfig utun5 down"
            ])
        XCTAssertTrue(system.table.contains { $0.network == IPNetwork("0.0.0.0/1")! && $0.interface == "utun3" })
        let record = try record()
        XCTAssertEqual(record.status, .failed("another route for 0.0.0.0/1 exists already, through utun3"))
        // Found in the way before anything was journaled for it.
        XCTAssertNil(record.states[.route(.init(IPNetwork("0.0.0.0/1")!, via: .interface("utun5")))])
        XCTAssertEqual(record.owned, [])
        XCTAssertFalse(VPNHook.reportedUp(runDir: runDir))
    }

    func testARejectRouteThatFindsAnotherRouteFails() {
        system.table.append(KernelRoute(network: IPNetwork("8000::/1")!, interface: "utun3"))
        let outcome = run(.connect(Self.full))
        XCTAssertTrue(outcome.stopTool)
        XCTAssertEqual(outcome.lines.last, VPNHook.failureLine("another route for 8000::/1 exists already, through utun3"))
    }

    func testARouteAddedMeanwhileCountsAsThere() throws {
        // `route add` fails because another program added the same route after the table was read.
        system.before = { command in
            if case .addRoute(let route) = command.effect, route.network == IPNetwork("::/1")! {
                self.system.table.append(KernelRoute(route))
            }
        }
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertTrue(try recordText().contains("~ route ::/1 reject\n"))
    }

    // MARK: - Failures

    func testAFailedChangeRevertsEverythingAndStops() throws {
        system.failing = { $0.line.hasPrefix("/sbin/route -n add -inet -net 128.0.0.0 ") ? .init(status: 1, output: "Network is unreachable") : nil }
        let outcome = run(.connect(Self.full))
        let reason = "/sbin/route -n add -inet -net 128.0.0.0 -netmask 128.0.0.0 -interface utun5 failed (exit status 1: Network is unreachable)"
        XCTAssertEqual(outcome, OpenConnectHook.Outcome(lines: [VPNHook.failureLine(reason)], stopTool: true))
        XCTAssertEqual(
            Array(system.log.suffix(6)),
            [
                "/sbin/route -n delete -inet -net 0.0.0.0 -netmask 128.0.0.0",
                "/sbin/route -n delete -inet6 -net 8000:: -prefixlen 1",
                "/sbin/route -n delete -inet6 -net :: -prefixlen 1",
                "/sbin/route -n delete -inet -host 192.0.2.10",
                "/sbin/ifconfig utun5 inet 10.11.0.2 delete",
                "/sbin/ifconfig utun5 down"
            ])
        XCTAssertFalse(system.log.contains("dns set passtunnel-501-acme"))
        XCTAssertEqual(system.table, originalTable.filter { !$0.cloned })
        let text = try recordText()
        XCTAssertTrue(text.contains("! route 128.0.0.0/1 interface utun5\n"))
        XCTAssertTrue(text.hasSuffix("status failed " + reason + "\n"))
        // openconnect runs the hook again for `disconnect`: nothing is left.
        system.log = []
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log, [])
    }

    func testDNSThatCannotBeWrittenFails() {
        system.dnsWritable = false
        let outcome = run(.connect(Self.full))
        XCTAssertTrue(outcome.stopTool)
        XCTAssertEqual(outcome.lines.last, VPNHook.failureLine("the DNS settings could not be written"))
        XCTAssertEqual(system.table, originalTable.filter { !$0.cloned })
    }

    func testRefusedInputsFailClosed() throws {
        // The environment refused: no command, no record (its interface is not known), openconnect stopped.
        let refused = hook().run(event: { throw OpenConnectNetwork.Failure.missing("TUNDEV") }, policy: { Self.policy })
        XCTAssertEqual(refused, OpenConnectHook.Outcome(lines: [VPNHook.failureLine("TUNDEV is not set")], stopTool: true))
        XCTAssertEqual(system.log, [])
        XCTAssertFalse(OpenConnectJournal.exists(runDir: runDir))

        // No policy: nothing changes, the failure is recorded for the helper.
        let noPolicy = hook().run(event: { .connect(Self.full) }, policy: { throw OpenConnectHook.Failure.policy })
        XCTAssertEqual(noPolicy, OpenConnectHook.Outcome(lines: [VPNHook.failureLine("the session's policy cannot be read")], stopTool: true))
        XCTAssertEqual(system.log, [])
        XCTAssertEqual(try record().status, .failed("the session's policy cannot be read"))
    }

    func testMissingInterfaceRoutesOrGateway() throws {
        system.interfaces["utun5"] = nil
        XCTAssertEqual(run(.connect(Self.full)).lines, [VPNHook.failureLine("TUNDEV is not an interface of this Mac")])
        XCTAssertEqual(system.log, [])

        try FileManager.default.removeItem(atPath: OpenConnectJournal.path(runDir: runDir))
        system.interfaces["utun5"] = 20
        system.routesReadable = false
        XCTAssertEqual(run(.connect(Self.full)).lines, [VPNHook.failureLine("the routing table cannot be read")])

        try FileManager.default.removeItem(atPath: OpenConnectJournal.path(runDir: runDir))
        system.routesReadable = true
        system.table = []
        XCTAssertEqual(
            run(.connect(Self.full)).lines,
            [VPNHook.failureLine("there is no IPv4 default route to keep the VPN server reachable outside the tunnel")])
        XCTAssertEqual(system.log, [])
    }

    func testConnectTwiceFails() {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        let again = run(.connect(Self.full))
        XCTAssertEqual(again.lines.last, VPNHook.failureLine("the network was set up already"))
        // The first set-up is reverted: the session is being stopped.
        XCTAssertEqual(system.table, originalTable.filter { !$0.cloned })
    }

    func testTheInterfaceGoingAwayFails() {
        system.before = { command in
            if command.line.contains("inet 10.11.0.2 10.11.0.2") { self.system.interfaces["utun5"] = 77 }  // another utun5
        }
        let outcome = run(.connect(Self.full))
        XCTAssertEqual(outcome.lines.last, VPNHook.failureLine("the tunnel interface went away"))
        // Nothing is done to the interface that now has the name.
        XCTAssertFalse(system.log.contains("/sbin/ifconfig utun5 down"))
        XCTAssertFalse(system.log.contains { $0.contains("delete") && $0.contains("utun5") })
    }

    func testStoppingStopsApplying() throws {
        let dir = runDir
        system.before = { command in
            if command.line.contains("-reject") { OpenConnectMarks.setStopping(runDir: dir) }
        }
        let outcome = run(.connect(Self.full))
        XCTAssertEqual(outcome.lines.last, VPNHook.failureLine("the session is being stopped"))
        // The reject route being added is the last change made; everything is reverted.
        XCTAssertEqual(system.log.filter { $0.contains(" add ") }.count, 2)
        XCTAssertEqual(system.table, originalTable.filter { !$0.cloned })
        // Reverting is still allowed while stopping.
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
    }

    func testTheRunLimit() throws {
        // Out of time before the first change: nothing is made.
        let outcome = hook(deadline: 0).run(event: { .connect(Self.full) }, policy: { Self.policy })
        XCTAssertTrue(outcome.stopTool)
        XCTAssertEqual(outcome.lines.last, VPNHook.failureLine("the network set-up did not finish within 30 seconds"))
        XCTAssertEqual(system.log, [])
        XCTAssertEqual(try record().status, .failed("the network set-up did not finish within 30 seconds"))
        try FileManager.default.removeItem(atPath: OpenConnectJournal.path(runDir: runDir))

        // Out of time half way: the changes stop, what is left is reverted later (openconnect's disconnect).
        var calls = 0
        var hook = hook()
        hook.now = {
            calls += 1
            // The run's start, the link, the address, the server's route, the first reject route: then 31 s later.
            return self.clock.addingTimeInterval(calls > 9 ? 31 : 0)
        }
        let halfway = hook.run(event: { .connect(Self.full) }, policy: { Self.policy })
        XCTAssertTrue(halfway.stopTool)
        XCTAssertEqual(
            halfway.lines,
            [
                VPNHook.revertFailureLine("restoring the network did not finish within 30 seconds"),
                VPNHook.failureLine("the network set-up did not finish within 30 seconds")
            ])
        XCTAssertEqual(system.log.count, 4)
        XCTAssertEqual(try record().owned.count, 4)
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertEqual(try record().owned, [])
        XCTAssertEqual(system.table, originalTable.filter { !$0.cloned })
    }

    // MARK: - Reconnecting

    func testAttemptReconnectFollowsTheGatewayAndReconnectChecks() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        // Another network: the default gateway moved to en7.
        system.table.removeAll { $0.network == IPNetwork("0.0.0.0/0")! }
        system.table.append(KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("203.0.113.1"), interface: "en7"))
        system.log = []
        XCTAssertEqual(run(.attemptReconnect(Self.full)), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log, ["/sbin/route -n delete -inet -host 192.0.2.10", "/sbin/route -n add -inet -host 192.0.2.10 203.0.113.1"])
        XCTAssertEqual(try record().status, .reconnecting)
        XCTAssertTrue(VPNHook.reportedUp(runDir: runDir))

        system.log = []
        let back = run(.reconnect(Self.full))
        XCTAssertEqual(
            back.lines, ["passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes, full tunnel, IPv6 blocked, DNS 10.11.0.53, search example.com\n"])
        XCTAssertEqual(system.log, [])
        XCTAssertEqual(try record().status, .up)

        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log.filter { $0.contains("192.0.2.10") }, ["/sbin/route -n delete -inet -host 192.0.2.10"])
        XCTAssertFalse(system.table.contains { $0.network == IPNetwork("192.0.2.10/32")! && $0.holdsDestination })
    }

    func testTheDefaultRouteThroughTheTunnelIsNoGateway() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        // The system made the tunnel's service primary: the default route leaves through utun5, the Wi-Fi's is
        // scoped. The scoped one is the gateway to follow.
        system.table.removeAll { $0.network == IPNetwork("0.0.0.0/0")! }
        system.table.append(KernelRoute(network: IPNetwork("0.0.0.0/0")!, interface: "utun5"))
        system.table.append(KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("198.51.100.1"), interface: "en0", scoped: true))
        system.log = []
        XCTAssertEqual(run(.attemptReconnect(Self.full)), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log, [])
    }

    func testReconnectFindsEverythingInPlace() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertFalse(run(.attemptReconnect(Self.full)).stopTool)
        system.log = []
        XCTAssertEqual(
            run(.reconnect(Self.full)),
            OpenConnectHook.Outcome(
                lines: ["passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes, full tunnel, IPv6 blocked, DNS 10.11.0.53, search example.com\n"]))
        XCTAssertEqual(system.log, [])
        XCTAssertEqual(try record().status, .up)
    }

    /// What reconnect finds changed it never repairs: it reverts what the session holds and stops, for a new
    /// connection to set up afresh.
    func reconnectFails(_ reason: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let outcome = run(.reconnect(Self.full))
        XCTAssertEqual(
            outcome,
            OpenConnectHook.Outcome(
                lines: [VPNHook.failureLine("the network changed while the connection was re-established: " + reason)], stopTool: true),
            file: file, line: line)
        XCTAssertEqual(try record().held, [], file: file, line: line)
        XCTAssertEqual(try record().status, .failed("the network changed while the connection was re-established: " + reason), file: file, line: line)
        XCTAssertFalse(system.table.contains { $0.interface == "utun5" || $0.reject }, file: file, line: line)
        XCTAssertEqual(system.dns, [:], file: file, line: line)
    }

    func testReconnectWithOneDNSKeyGoneFailsAndRemovesTheRest() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertFalse(run(.attemptReconnect(Self.full)).stopTool)
        // Only the IPv4 entity went: the DNS entity that survived is still the session's, and is removed.
        system.dns["State:/Network/Service/passtunnel-501-acme/IPv4"] = nil
        XCTAssertNotNil(system.dns["State:/Network/Service/passtunnel-501-acme/DNS"])
        try reconnectFails("the DNS settings are no longer as they were set up")
        XCTAssertTrue(try recordText().contains("- dns passtunnel-501-acme utun5 primary"))
    }

    func testAChangeIsJournaledRevertedOnlyOnceItIsGone() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        system.dns["State:/Network/Service/passtunnel-501-acme/IPv4"] = nil
        // The DNS keys cannot be removed now: the change stays the session's, for the next revert.
        system.dnsWritable = false
        let outcome = run(.reconnect(Self.full))
        XCTAssertTrue(outcome.stopTool)
        let dns = try XCTUnwrap(try record().held.first { if case .dns = $0 { return true } else { return false } })
        XCTAssertEqual(try record().states[dns], .owned)
        system.dnsWritable = true
        var killed = 0
        XCTAssertEqual(restore(killed: &killed), .done)
        XCTAssertEqual(system.dns, [:])
        XCTAssertEqual(try record().states[dns], .reverted)
    }

    func testReconnectWithARouteGoneFails() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertFalse(run(.attemptReconnect(Self.full)).stopTool)
        system.table.removeAll { $0.network == IPNetwork("0.0.0.0/1")! }
        try reconnectFails("the route for 0.0.0.0/1 is no longer as it was set up")
    }

    func testReconnectWithARouteTakenByAnotherVPNFails() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        system.interfaces["utun3"] = 18
        system.table.removeAll { $0.network == IPNetwork("128.0.0.0/1")! }
        let other = KernelRoute(network: IPNetwork("128.0.0.0/1")!, interface: "utun3")
        system.table.append(other)
        let outcome = run(.reconnect(Self.full))
        XCTAssertTrue(outcome.stopTool)
        XCTAssertEqual(
            outcome.lines,
            [
                VPNHook.failureLine(
                    "the network changed while the connection was re-established: the route for 128.0.0.0/1 is no longer as it was set up")
            ])
        // The other VPN's route is not touched.
        XCTAssertTrue(system.table.contains(other))
        XCTAssertFalse(system.log.contains("/sbin/route -n delete -inet -net 128.0.0.0 -netmask 128.0.0.0"))
    }

    func testReconnectWithoutAGatewayAndAnExcludeGoneFails() throws {
        try FileManager.default.removeItem(atPath: runDir)
        try FileManager.default.createDirectory(atPath: runDir, withIntermediateDirectories: true)
        XCTAssertFalse(run(.connect(Self.split)).stopTool)
        // The network is down: no default route, and the exclude went with it.
        system.table.removeAll { $0.network == IPNetwork("0.0.0.0/0")! || $0.network == IPNetwork("10.99.0.0/16")! }
        system.log = []
        XCTAssertEqual(run(.attemptReconnect(Self.split)), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log, [], "attempt-reconnect leaves a family without a gateway alone")
        let outcome = run(.reconnect(Self.split))
        XCTAssertEqual(
            outcome.lines,
            [
                VPNHook.failureLine(
                    "the network changed while the connection was re-established: the route for 10.99.0.0/16 is no longer as it was set up")
            ])
        XCTAssertNotEqual(try record().status, .up)
        XCTAssertEqual(try record().held, [])
    }

    func testRoamingReplacesTheServerRouteNotFoundThere() throws {
        // The server's route was there before the session (not its own: `~`).
        let wifi = OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "en0")!
        let old = OpenConnectPlan.Route(IPNetwork("192.0.2.10/32")!, via: .gateway(wifi))
        system.table.append(KernelRoute(old))
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertTrue(try recordText().contains("~ route 192.0.2.10/32 gateway 198.51.100.1 en0\n"))
        // Roaming to another network: the default gateway moved, the old route went with the Wi-Fi.
        system.table.removeAll { $0.network == IPNetwork("0.0.0.0/0")! || $0.network == IPNetwork("192.0.2.10/32")! }
        system.table.append(KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("203.0.113.1"), interface: "en7"))
        system.log = []
        XCTAssertEqual(run(.attemptReconnect(Self.full)), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log, ["/sbin/route -n add -inet -host 192.0.2.10 203.0.113.1"])
        // The route found there is not expected any more: the reconnect is up.
        XCTAssertFalse(run(.reconnect(Self.full)).stopTool)
        XCTAssertEqual(try record().status, .up)
        // The new route is the session's: the disconnect removes it.
        system.log = []
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertTrue(system.log.contains("/sbin/route -n delete -inet -host 192.0.2.10"))
        XCTAssertFalse(system.table.contains { $0.network == IPNetwork("192.0.2.10/32")! && $0.holdsDestination })
    }

    func testAReconnectWithOtherSettingsFails() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertFalse(run(.attemptReconnect(Self.full)).stopTool)
        let other = OpenConnectNetwork(
            interface: "utun5", gateway: Self.full.gateway, ipv4: Self.full.ipv4, ipv6: nil, mtu: 1406, dnsServers: [IPAddress("10.11.0.54")!],
            defaultDomains: ["example.com"])
        let outcome = run(.reconnect(other))
        XCTAssertEqual(outcome, OpenConnectHook.Outcome(lines: [VPNHook.failureLine("the server changed the network settings")], stopTool: true))
        XCTAssertEqual(system.table, originalTable.filter { !$0.cloned })
        XCTAssertEqual(system.dns, [:])
        XCTAssertEqual(try record().status, .failed("the server changed the network settings"))
    }

    func testReconnectWithoutASetUpFails() {
        XCTAssertEqual(run(.attemptReconnect(Self.full)).lines.last, VPNHook.failureLine("the network was not set up"))
        XCTAssertEqual(run(.reconnect(Self.full)).lines.last, VPNHook.failureLine("the network was not set up"))
    }

    // MARK: - Other sessions

    /// Another session of the run root with `entries` in its record.
    func otherSession(_ entries: [OpenConnectRecord.Entry], interface: String = "utun6") throws {
        var record = try XCTUnwrap(OpenConnectRecord(interface: interface))
        for entry in entries { try record.append(entry) }
        try record.text().write(toFile: OpenConnectJournal.path(runDir: otherDir), atomically: false, encoding: .utf8)
    }

    func testWhatAnotherLiveSessionHoldsIsSpared() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        let reject = OpenConnectPlan.Change.route(.init(IPNetwork("::/1")!, via: .reject))
        let server = OpenConnectPlan.Change.route(
            .init(IPNetwork("192.0.2.10/32")!, via: .gateway(OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "en0")!)))
        try otherSession([.shared(reject), .shared(server)])
        system.log = []
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertFalse(system.log.contains("/sbin/route -n delete -inet6 -net :: -prefixlen 1"))
        XCTAssertFalse(system.log.contains("/sbin/route -n delete -inet -host 192.0.2.10"))
        XCTAssertTrue(system.log.contains("/sbin/route -n delete -inet6 -net 8000:: -prefixlen 1"))
        let text = try recordText()
        XCTAssertTrue(text.contains("? route ::/1 reject\n"))
        XCTAssertTrue(text.contains("? route 192.0.2.10/32 gateway 198.51.100.1 en0\n"))
    }

    func testARecordWhoseRevertRanSparesNothing() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        let reject = OpenConnectPlan.Change.route(.init(IPNetwork("::/1")!, via: .reject))
        // The other session shared it, and its revert has run (it spared it to this one).
        try otherSession([.shared(reject), .spared(reject)])
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertTrue(system.log.contains("/sbin/route -n delete -inet6 -net :: -prefixlen 1"))
    }

    func testARecordThatOnlyFoundAChangeThereSparesNothing() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        let reject = OpenConnectPlan.Change.route(.init(IPNetwork("::/1")!, via: .reject))
        try otherSession([.existed(reject)])
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertTrue(system.log.contains("/sbin/route -n delete -inet6 -net :: -prefixlen 1"))
    }

    /// A session that ended (killed) still holds what its record holds until the helper's revert has run: a
    /// session that connects meanwhile shares what it finds, and that revert leaves it to the new session.
    func testASessionThatEndedHoldsItsRoutesUntilItsRevert() throws {
        system.interfaces["utun6"] = 21
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        // A's openconnect is killed: its utun goes, its record stays until the helper reverts it.
        system.interfaces["utun5"] = nil
        system.table.removeAll { $0.interface == "utun5" }
        // B connects before that revert: the server's route A made is shared, not nobody's.
        system.log = []
        XCTAssertFalse(run(.connect(Self.second), policy: Self.secondPolicy, dir: otherDir).stopTool)
        XCTAssertTrue(try recordText(otherDir).contains("& route 192.0.2.10/32 gateway 198.51.100.1 en0\n"))
        // A's revert spares it for B; B's disconnect then removes it.
        var killed = 0
        XCTAssertEqual(restore(killed: &killed), .done)
        XCTAssertTrue(system.table.contains { $0.network == IPNetwork("192.0.2.10/32")! && $0.holdsDestination })
        XCTAssertTrue(try recordText().contains("? route 192.0.2.10/32 gateway 198.51.100.1 en0\n"))
        system.log = []
        XCTAssertEqual(run(.disconnect, policy: Self.secondPolicy, dir: otherDir), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log.filter { $0.contains("192.0.2.10") }, ["/sbin/route -n delete -inet -host 192.0.2.10"])
    }

    func testAnUnreadableRecordOfAnotherSessionSparesWhatCanBeShared() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        try "garbage\n".write(toFile: OpenConnectJournal.path(runDir: otherDir), atomically: false, encoding: .utf8)
        system.log = []
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertEqual(
            system.log,
            [
                "dns remove passtunnel-501-acme",
                "/sbin/route -n delete -inet -net 128.0.0.0 -netmask 128.0.0.0",
                "/sbin/route -n delete -inet -net 0.0.0.0 -netmask 128.0.0.0",
                "/sbin/ifconfig utun5 inet 10.11.0.2 delete",
                "/sbin/ifconfig utun5 down"
            ])
    }

    func testAttemptReconnectSparesAHostRouteAnotherSessionUses() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        let server = OpenConnectPlan.Change.route(
            .init(IPNetwork("192.0.2.10/32")!, via: .gateway(OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "en0")!)))
        try otherSession([.shared(server)])
        system.table.removeAll { $0.network == IPNetwork("0.0.0.0/0")! }
        system.table.append(KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("203.0.113.1"), interface: "en7"))
        system.log = []
        let outcome = run(.attemptReconnect(Self.full))
        // Not removed from under the other session; then the new route finds it in its way: the session stops
        // and signs in afresh rather than replacing a route another session uses.
        XCTAssertFalse(system.log.contains("/sbin/route -n delete -inet -host 192.0.2.10"))
        XCTAssertTrue(try recordText().contains("? route 192.0.2.10/32 gateway 198.51.100.1 en0\n"))
        XCTAssertEqual(
            outcome.lines.last, VPNHook.failureLine("another route for 192.0.2.10/32 exists already, through 198.51.100.1 en0"))
        XCTAssertTrue(system.table.contains { $0.network == IPNetwork("192.0.2.10/32")! && $0.gateway == IPAddress("198.51.100.1") })
    }

    // MARK: - Shared changes

    /// Session B of another profile, to the same server, on utun6: a split tunnel whose include holds the
    /// server, so it needs the server's host route too. (Two full tunnels cannot run at once: the second finds
    /// the first's halves in its way.)
    static let second = OpenConnectNetwork(
        interface: "utun6", gateway: IPAddress("192.0.2.10")!, ipv4: .init(address: IPAddress("10.12.0.2")!, network: nil), ipv6: nil,
        mtu: 1406, ipv4Includes: [IPNetwork("192.0.2.0/24")!])
    static let secondPolicy = OpenConnectPolicy(uid: 501, profileID: "other", setRoutes: true, setDNS: true)

    func testTheLastSessionToEndRemovesWhatTwoShare() throws {
        system.interfaces["utun6"] = 21
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        // B finds the server's route A made: shared, not made again.
        system.log = []
        XCTAssertFalse(run(.connect(Self.second), policy: Self.secondPolicy, dir: otherDir).stopTool)
        XCTAssertFalse(system.log.contains { $0.contains("192.0.2.10") })
        let b = try recordText(otherDir)
        XCTAssertTrue(b.contains("& route 192.0.2.10/32 gateway 198.51.100.1 en0\n"), b)
        XCTAssertFalse(b.contains("+ route 192.0.2.10/32"), b)

        // A ends first: B still runs, so the route stays (A journals it as spared).
        system.log = []
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertFalse(system.log.contains { $0.contains("192.0.2.10") })
        XCTAssertTrue(try recordText().contains("? route 192.0.2.10/32 gateway 198.51.100.1 en0\n"))
        // B ends last: nobody holds it any more, and B removes it.
        system.log = []
        XCTAssertEqual(run(.disconnect, policy: Self.secondPolicy, dir: otherDir), OpenConnectHook.Outcome())
        XCTAssertEqual(system.log.filter { $0.contains("192.0.2.10") }, ["/sbin/route -n delete -inet -host 192.0.2.10"])
        XCTAssertEqual(system.table, originalTable.filter { !$0.cloned })

        // The same for a block: shared by a session that found it held by a live one, removed by the last.
        let reject = OpenConnectPlan.Change.route(.init(IPNetwork("::/1")!, via: .reject))
        var a = OpenConnectRecord(interface: "utun5")!
        try a.append(.begin(reject))
        try a.append(.owned(reject))
        var c = OpenConnectRecord(interface: "utun6")!
        try c.append(.shared(reject))
        XCTAssertEqual(a.toRevert(sparing: [c]), [])
        XCTAssertEqual(c.toRevert(sparing: [a]), [])
        XCTAssertEqual(c.toRevert(sparing: []), [reject])
    }

    func testARouteNoSessionHoldsIsNeverRemoved() throws {
        // There before any session (or its session has ended): not PassTunnel's, never removed by anyone.
        system.table.append(KernelRoute(OpenConnectPlan.Route(IPNetwork("::/1")!, via: .reject)))
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertTrue(try recordText().contains("~ route ::/1 reject\n"))
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        // Nor by the helper's revert after a kill.
        var killed = 0
        XCTAssertEqual(restore(killed: &killed), .done)
        XCTAssertTrue(system.table.contains { $0.network == IPNetwork("::/1")! && $0.reject })
    }

    func testAFindingIsJournaledWithoutABegin() throws {
        // What the system had is never journaled as begun, so a hook killed right after cannot leave it pending
        // for a revert to remove.
        system.table.append(KernelRoute(OpenConnectPlan.Route(IPNetwork("::/1")!, via: .reject)))
        let dir = runDir
        var snapshot = ""
        system.before = { command in
            if command.line.contains("8000::") && snapshot.isEmpty {
                snapshot = (try? String(contentsOfFile: OpenConnectJournal.path(runDir: dir), encoding: .utf8)) ?? ""
            }
        }
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertTrue(snapshot.hasSuffix("~ route ::/1 reject\n+ route 8000::/1 reject\n"), snapshot)
        XCTAssertFalse(snapshot.contains("+ route ::/1 reject"))
        // The record as a kill at that moment would leave it: the revert undoes the pending change only.
        try FileManager.default.removeItem(atPath: OpenConnectJournal.path(runDir: runDir))
        try snapshot.write(toFile: OpenConnectJournal.path(runDir: runDir), atomically: false, encoding: .utf8)
        system.interfaces["utun5"] = nil
        system.log = []
        var killed = 0
        XCTAssertEqual(restore(killed: &killed), .done)
        XCTAssertFalse(system.log.contains("/sbin/route -n delete -inet6 -net :: -prefixlen 1"))
        XCTAssertTrue(system.log.contains("/sbin/route -n delete -inet6 -net 8000:: -prefixlen 1"))
        XCTAssertTrue(system.table.contains { $0.network == IPNetwork("::/1")! && $0.reject })
    }

    // MARK: - Routes with another next hop

    func testARouteOfTheServerThroughAnotherNextHopFails() throws {
        let cases: [(String, KernelRoute)] = [
            // An include another VPN routes already.
            ("10.0.0.0/8", KernelRoute(network: IPNetwork("10.0.0.0/8")!, interface: "utun3")),
            // A DNS server's host route through a physical gateway.
            ("172.16.0.53/32", KernelRoute(network: IPNetwork("172.16.0.53/32")!, gateway: IPAddress("198.51.100.9"), interface: "en0")),
            // An exclude through another gateway than the default one.
            ("10.99.0.0/16", KernelRoute(network: IPNetwork("10.99.0.0/16")!, gateway: IPAddress("198.51.100.9"), interface: "en0"))
        ]
        for (network, route) in cases {
            try? FileManager.default.removeItem(atPath: OpenConnectJournal.path(runDir: runDir))
            system = FakeOpenConnectSystem()
            system.table.append(route)
            let outcome = run(.connect(Self.split))
            XCTAssertTrue(outcome.stopTool, network)
            XCTAssertTrue(outcome.lines.last?.contains("another route for \(network) exists already") ?? false, network)
            // Nothing of someone else's is replaced, and the set-up is reverted.
            XCTAssertFalse(system.log.contains { $0.contains(" add ") && $0.contains(" " + network.split(separator: "/")[0] + " ") }, network)
            XCTAssertTrue(system.table.contains(route), network)
            XCTAssertEqual(system.table.filter { $0 != route }, originalTable, network)
        }
        // The VPN server's own route through another gateway.
        try? FileManager.default.removeItem(atPath: OpenConnectJournal.path(runDir: runDir))
        system = FakeOpenConnectSystem()
        system.table.append(KernelRoute(network: IPNetwork("192.0.2.10/32")!, gateway: IPAddress("198.51.100.9"), interface: "en0"))
        XCTAssertEqual(
            run(.connect(Self.full)).lines.last,
            VPNHook.failureLine("another route for 192.0.2.10/32 exists already, through 198.51.100.9 en0"))
    }

    func testAnAddThatFailsIsCheckedAgainstWhatIsThere() throws {
        // `route add` fails because another program put a route of the destination through another VPN meanwhile.
        system.interfaces["utun3"] = 18
        system.before = { command in
            if case .addRoute(let route) = command.effect, route.network == IPNetwork("0.0.0.0/1")! {
                self.system.table.append(KernelRoute(network: route.network, interface: "utun3"))
            }
        }
        let outcome = run(.connect(Self.full))
        XCTAssertTrue(outcome.stopTool)
        XCTAssertTrue(
            outcome.lines.last?.contains("/sbin/route -n add -inet -net 0.0.0.0 -netmask 128.0.0.0 -interface utun5 failed") ?? false)
        XCTAssertTrue(try recordText().contains("! route 0.0.0.0/1 interface utun5\n"))
        XCTAssertTrue(system.table.contains { $0.network == IPNetwork("0.0.0.0/1")! && $0.interface == "utun3" })
    }

    // MARK: - The session's generation

    func testARunWhoseSessionEndedChangesNothing() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        let before = try recordText()
        system.log = []
        var late = hook()
        late.stillOurs = { false }
        for event in [OpenConnectNetwork.Event.disconnect, .connect(Self.full), .attemptReconnect(Self.full)] {
            let outcome = late.run(event: { event }, policy: { Self.policy })
            XCTAssertEqual(outcome, OpenConnectHook.Outcome(lines: [VPNHook.endedLine]))
        }
        // Not even a refused environment is recorded.
        XCTAssertEqual(
            late.run(event: { throw OpenConnectNetwork.Failure.missing("TUNDEV") }, policy: { Self.policy }),
            OpenConnectHook.Outcome(lines: [VPNHook.endedLine]))
        XCTAssertEqual(system.log, [])
        XCTAssertEqual(try recordText(), before)
        XCTAssertNil(OpenConnectMarks.runningHook(runDir: runDir))
        XCTAssertTrue(VPNHook.endedLine.hasPrefix(VPNHook.linePrefix))
        XCTAssertNil(VPNHook.Report.parse(VPNHook.endedLine[...]))
    }

    // MARK: - The helper's revert

    func restore(dir: String? = nil, killed: inout Int) -> OpenConnectHook.Restore {
        let clock = clock
        return OpenConnectHook.restoreAfterExit(
            runRoot: root, runDir: dir ?? runDir, system: system, killHook: { killed += 1 }, now: { clock })
    }

    func testTheHelperRevertsAfterTheToolWasKilled() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        // openconnect was killed: its utun went with it, and a new utun5 may be another session's.
        system.interfaces["utun5"] = 21
        system.table.removeAll { $0.interface == "utun5" }
        system.log = []
        var killed = 0
        XCTAssertEqual(restore(killed: &killed), .done)
        XCTAssertEqual(killed, 0)
        XCTAssertEqual(
            system.log,
            [
                "dns remove passtunnel-501-acme",
                "/sbin/route -n delete -inet6 -net 8000:: -prefixlen 1",
                "/sbin/route -n delete -inet6 -net :: -prefixlen 1",
                "/sbin/route -n delete -inet -host 192.0.2.10"
            ])
        XCTAssertTrue(OpenConnectMarks.isStopping(runDir: runDir))
        XCTAssertEqual(try record().owned, [])
        XCTAssertEqual(system.table, originalTable.filter { !$0.cloned })
        // Nothing left: done again, without a command.
        system.log = []
        XCTAssertEqual(restore(killed: &killed), .done)
        XCTAssertEqual(system.log, [])
    }

    func testARevertThatFailsKeepsTheRecordForTheNextTry() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        system.failing = { $0.line == "/sbin/route -n delete -inet6 -net :: -prefixlen 1" ? .init(status: 1, output: "busy") : nil }
        let outcome = run(.disconnect)
        XCTAssertEqual(
            outcome.lines, [VPNHook.revertFailureLine("/sbin/route -n delete -inet6 -net :: -prefixlen 1 failed (exit status 1: busy)")])
        XCTAssertFalse(outcome.stopTool)
        XCTAssertEqual(try record().owned, [.route(.init(IPNetwork("::/1")!, via: .reject))])

        // The helper's turn: still failing, the record stays and nothing else does.
        try "x".write(toFile: runDir + "/openconnect.conf", atomically: false, encoding: .utf8)
        var killed = 0
        XCTAssertEqual(restore(killed: &killed), .failed("/sbin/route -n delete -inet6 -net :: -prefixlen 1 failed (exit status 1: busy)"))
        OpenConnectHook.keepOnlyRecord(runDir: runDir)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: runDir), ["network"])
        // The next try succeeds.
        system.failing = { _ in nil }
        XCTAssertEqual(restore(killed: &killed), .done)
        XCTAssertFalse(system.table.contains { $0.network == IPNetwork("::/1")! })
    }

    func testAChangeBegunWithoutOutcomeIsReverted() throws {
        // The hook was killed while it added the server's route: it may have been made.
        let server = OpenConnectPlan.Change.route(
            .init(IPNetwork("192.0.2.10/32")!, via: .gateway(OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "en0")!)))
        let reject = OpenConnectPlan.Change.route(.init(IPNetwork("::/1")!, via: .reject))
        var record = try XCTUnwrap(OpenConnectRecord(interface: "utun5"))
        try record.append(.begin(server))
        try record.append(.owned(server))
        try record.append(.begin(reject))
        try record.text().write(toFile: OpenConnectJournal.path(runDir: runDir), atomically: false, encoding: .utf8)
        let wifi = OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "en0")!
        system.table.append(KernelRoute(OpenConnectPlan.Route(IPNetwork("192.0.2.10/32")!, via: .gateway(wifi))))
        system.table.append(KernelRoute(OpenConnectPlan.Route(IPNetwork("::/1")!, via: .reject)))
        var killed = 0
        XCTAssertEqual(restore(killed: &killed), .done)
        XCTAssertEqual(system.log, ["/sbin/route -n delete -inet6 -net :: -prefixlen 1", "/sbin/route -n delete -inet -host 192.0.2.10"])
        XCTAssertEqual(try self.record().states[reject], .reverted)

        // Begun but never made: nothing to delete, still settled.
        try FileManager.default.removeItem(atPath: OpenConnectJournal.path(runDir: runDir))
        var again = try XCTUnwrap(OpenConnectRecord(interface: "utun5"))
        try again.append(.begin(reject))
        try again.text().write(toFile: OpenConnectJournal.path(runDir: runDir), atomically: false, encoding: .utf8)
        system.log = []
        XCTAssertEqual(restore(killed: &killed), .done)
        XCTAssertEqual(system.log, [])
        XCTAssertEqual(try self.record().states[reject], .reverted)
    }

    func testARouteThatIsNoLongerTheSessionsIsLeftAlone() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        // Someone replaced the server's route by one through another gateway.
        system.table.removeAll { $0.network == IPNetwork("192.0.2.10/32")! }
        system.table.append(KernelRoute(network: IPNetwork("192.0.2.10/32")!, gateway: IPAddress("198.51.100.7"), interface: "en0"))
        system.log = []
        XCTAssertEqual(run(.disconnect), OpenConnectHook.Outcome())
        XCTAssertFalse(system.log.contains("/sbin/route -n delete -inet -host 192.0.2.10"))
        XCTAssertTrue(system.table.contains { $0.gateway == IPAddress("198.51.100.7") })
    }

    func testTheHelperWaitsForTheLockThenKillsTheHook() throws {
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        // A hook holds the lock: the helper's clock runs past the limit while it waits.
        let held = try XCTUnwrap(OpenConnectLock.acquire(runRoot: root, until: Date()))
        var killed = 0
        var tick = 0
        let result = OpenConnectHook.restoreAfterExit(
            runRoot: root, runDir: runDir, system: system, killHook: { killed += 1 },
            now: {
                tick += 1
                return self.clock.addingTimeInterval(Double(tick) * 10)
            })
        XCTAssertEqual(result, .failed("the network lock was not free"))
        XCTAssertEqual(killed, 1)
        XCTAssertTrue(OpenConnectMarks.isStopping(runDir: runDir))
        withExtendedLifetime(held) {}
    }

    func testRestoreWithoutARecordOrWithAnUnreadableOne() throws {
        var killed = 0
        XCTAssertEqual(restore(killed: &killed), .done)
        XCTAssertFalse(OpenConnectMarks.isStopping(runDir: runDir))
        try "garbage\n".write(toFile: OpenConnectJournal.path(runDir: runDir), atomically: false, encoding: .utf8)
        XCTAssertEqual(restore(killed: &killed), .unreadable)
        XCTAssertEqual(system.log, [])
    }

    // MARK: - Record, lock, marks

    func testTheRecordIsWrittenALineAtATime() throws {
        let journal = try OpenConnectJournal.create(runDir: runDir, interface: "utun5")
        XCTAssertThrowsError(try OpenConnectJournal.create(runDir: runDir, interface: "utun5"))
        let link = OpenConnectPlan.Change.link(interface: "utun5", mtu: 1400)
        try journal.append(.begin(link))
        XCTAssertEqual(try recordText(), "passtunnel-network 1\ninterface utun5\n+ link utun5 mtu 1400\n")
        // Out of order: refused, nothing written.
        XCTAssertThrowsError(try journal.append(.status(.up)))
        XCTAssertEqual(try recordText(), "passtunnel-network 1\ninterface utun5\n+ link utun5 mtu 1400\n")
        try journal.append(.owned(link))
        try journal.append(.status(.up))
        XCTAssertEqual(OpenConnectJournal.status(runDir: runDir), .up)
        XCTAssertEqual(try OpenConnectJournal.open(runDir: runDir)?.record, journal.record)
        XCTAssertNil(try OpenConnectJournal.open(runDir: otherDir))
    }

    func testALargeRecordIsCompactedWhenOpened() throws {
        var record = try XCTUnwrap(OpenConnectRecord(interface: "utun5"))
        let gateway = OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "en0")!
        let route = OpenConnectPlan.Change.route(.init(IPNetwork("192.0.2.10/32")!, via: .gateway(gateway)))
        try record.append(.status(.up))
        // Three lines of at least 40 bytes a round.
        for _ in 0...(OpenConnectJournal.compactAbove / 120) {
            try record.append(.begin(route))
            try record.append(.owned(route))
            try record.append(.reverted(route))
        }
        XCTAssertGreaterThan(try record.text().utf8.count, OpenConnectJournal.compactAbove)
        try record.append(.begin(route))
        try record.append(.owned(route))
        try record.text().write(toFile: OpenConnectJournal.path(runDir: runDir), atomically: false, encoding: .utf8)
        let journal = try XCTUnwrap(OpenConnectJournal.open(runDir: runDir))
        XCTAssertEqual(journal.record.owned, [route])
        XCTAssertEqual(journal.record.status, .up)
        XCTAssertEqual(
            try recordText(),
            "passtunnel-network 1\ninterface utun5\n+ route 192.0.2.10/32 gateway 198.51.100.1 en0\n= route 192.0.2.10/32 gateway 198.51.100.1 en0\nstatus up\n"
        )
    }

    func testTheRecordMustBeARegularFileOfOurs() throws {
        try FileManager.default.createSymbolicLink(atPath: OpenConnectJournal.path(runDir: runDir), withDestinationPath: "/etc/hosts")
        XCTAssertThrowsError(try OpenConnectJournal.open(runDir: runDir))
        XCTAssertThrowsError(try OpenConnectJournal.create(runDir: runDir, interface: "utun5"))
    }

    func testTheLockIsExclusive() throws {
        do {
            let first = try XCTUnwrap(OpenConnectLock.acquire(runRoot: root, until: Date()))
            XCTAssertNil(OpenConnectLock.acquire(runRoot: root, until: Date().addingTimeInterval(0.1)))
            withExtendedLifetime(first) {}
        }
        // Released with the object.
        XCTAssertNotNil(OpenConnectLock.acquire(runRoot: root, until: Date()))
        // Never through a link.
        let other = root + "/elsewhere"
        try FileManager.default.createDirectory(atPath: other, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: other + "/" + OpenConnectLock.fileName, withDestinationPath: root + "/x")
        XCTAssertNil(OpenConnectLock.acquire(runRoot: other, until: Date()))
    }

    func testMarks() throws {
        XCTAssertNil(OpenConnectMarks.runningHook(runDir: runDir))
        try OpenConnectMarks.setHook(runDir: runDir, pid: 4242, start: ProcessStart(seconds: 7, microseconds: 8))
        let mark = try XCTUnwrap(OpenConnectMarks.runningHook(runDir: runDir))
        XCTAssertEqual(mark.pid, 4242)
        XCTAssertEqual(mark.start, ProcessStart(seconds: 7, microseconds: 8))
        OpenConnectMarks.clearHook(runDir: runDir)
        XCTAssertNil(OpenConnectMarks.runningHook(runDir: runDir))
        // Without a start time the mark names no process the helper could kill.
        try OpenConnectMarks.setHook(runDir: runDir, pid: 4242, start: nil)
        XCTAssertNil(OpenConnectMarks.runningHook(runDir: runDir))

        XCTAssertFalse(OpenConnectMarks.isStopping(runDir: runDir))
        OpenConnectMarks.setStopping(runDir: runDir)
        OpenConnectMarks.setStopping(runDir: runDir)
        XCTAssertTrue(OpenConnectMarks.isStopping(runDir: runDir))
    }

    func testTheHookMarkIsSetWhileItRuns() {
        let dir = runDir
        var seen: (pid: pid_t, start: ProcessStart)?
        system.before = { _ in if seen == nil { seen = OpenConnectMarks.runningHook(runDir: dir) } }
        XCTAssertFalse(run(.connect(Self.full)).stopTool)
        XCTAssertEqual(seen?.pid, 4242)
        XCTAssertNil(OpenConnectMarks.runningHook(runDir: runDir))
    }

    // MARK: - Underlay

    func testUnderlayFromTheRoutingTable() {
        let attached = [OpenConnectPlan.Attached(IPNetwork("192.168.1.0/24")!, interface: "en0")]
        let wifi = KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("198.51.100.1"), interface: "en0")
        let v6 = KernelRoute(network: IPNetwork("::/0")!, gateway: IPAddress("fe80::1"), interface: "en0")
        var underlay = OpenConnectPlan.Underlay(routes: [wifi, v6], attached: attached, tunnel: "utun5")
        XCTAssertEqual(underlay.ipv4?.description, "198.51.100.1 en0")
        XCTAssertEqual(underlay.ipv6?.description, "fe80::1 en0")
        XCTAssertEqual(underlay.attached, attached)

        // The system's own utuns have scoped default routes: never a gateway.
        let system = KernelRoute(network: IPNetwork("::/0")!, gateway: IPAddress("fe80::"), interface: "utun0", scoped: true)
        underlay = OpenConnectPlan.Underlay(routes: [wifi, system], attached: [], tunnel: "utun5")
        XCTAssertNil(underlay.ipv6)

        // The default through the tunnel itself: the one scoped default of another interface.
        let throughTunnel = KernelRoute(network: IPNetwork("0.0.0.0/0")!, interface: "utun5")
        var scoped = wifi
        scoped.scoped = true
        underlay = OpenConnectPlan.Underlay(routes: [throughTunnel, scoped], attached: [], tunnel: "utun5")
        XCTAssertEqual(underlay.ipv4?.description, "198.51.100.1 en0")
        // Two of them: no way to tell which one the system would use.
        let ethernet = KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("203.0.113.1"), interface: "en7", scoped: true)
        underlay = OpenConnectPlan.Underlay(routes: [throughTunnel, scoped, ethernet], attached: [], tunnel: "utun5")
        XCTAssertNil(underlay.ipv4)
        // A link without an address (PPP).
        underlay = OpenConnectPlan.Underlay(routes: [KernelRoute(network: IPNetwork("0.0.0.0/0")!, interface: "ppp0")], attached: [], tunnel: "utun5")
        XCTAssertEqual(underlay.ipv4?.description, "link ppp0")
        // Reject routes are no way out.
        let rejectDefault = KernelRoute(network: IPNetwork("0.0.0.0/0")!, interface: "lo0", reject: true)
        underlay = OpenConnectPlan.Underlay(routes: [rejectDefault], attached: [], tunnel: "utun5")
        XCTAssertNil(underlay.ipv4)
    }

    func testKernelRouteMatching() {
        func finding(_ route: OpenConnectPlan.Route, _ table: [KernelRoute], claimed: Bool = false, attached: [OpenConnectPlan.Attached] = [])
            -> OpenConnectHook.Finding
        {
            OpenConnectHook.finding(route, in: table, claimed: claimed ? [.route(route)] : [], attached: attached)
        }
        let gateway = OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "en0")!
        let host = OpenConnectPlan.Route(IPNetwork("192.0.2.10/32")!, via: .gateway(gateway))
        XCTAssertTrue(KernelRoute(host).is(host))
        var cloned = KernelRoute(host)
        cloned.cloned = true
        XCTAssertFalse(cloned.is(host))
        XCTAssertEqual(finding(host, [cloned]), .absent)
        var scoped = KernelRoute(host)
        scoped.scoped = true
        XCTAssertEqual(finding(host, [scoped]), .absent)
        XCTAssertEqual(finding(host, [KernelRoute(host)]), .there(shared: false))
        XCTAssertEqual(finding(host, [KernelRoute(host)], claimed: true), .there(shared: true))
        // The server's route through another gateway: the set-up would not reach it as planned.
        let elsewhere = KernelRoute(network: host.network, gateway: IPAddress("198.51.100.2"), interface: "en0")
        XCTAssertFalse(elsewhere.is(host))
        XCTAssertEqual(finding(host, [elsewhere]), .conflict("another route for 192.0.2.10/32 exists already, through 198.51.100.2 en0"))
        let reject = OpenConnectPlan.Route(IPNetwork("::/1")!, via: .reject)
        XCTAssertTrue(KernelRoute(network: reject.network, gateway: IPAddress("::1"), interface: "lo0", reject: true).is(reject))
        XCTAssertFalse(KernelRoute(network: reject.network, interface: "utun3").is(reject))
        let inside = OpenConnectPlan.Route(IPNetwork("10.0.0.0/8")!, via: .interface("utun5"))
        XCTAssertTrue(KernelRoute(network: inside.network, interface: "utun5").is(inside))
        XCTAssertFalse(KernelRoute(network: inside.network, interface: "utun6").is(inside))
        // A server's include that finds another route: a conflict, as a full tunnel's half.
        XCTAssertEqual(
            finding(inside, [KernelRoute(network: inside.network, interface: "utun6")]),
            .conflict("another route for 10.0.0.0/8 exists already, through utun6"))
        let half = OpenConnectPlan.Route(IPNetwork("128.0.0.0/1")!, via: .interface("utun5"))
        XCTAssertEqual(
            finding(half, [KernelRoute(network: half.network, gateway: IPAddress("::1"), interface: "lo0", reject: true)]),
            .conflict("another route for 128.0.0.0/1 exists already, a reject route"))
        // An exclude of the LAN the Mac is on, held by its on-link route: that traffic leaves outside already.
        let lan = OpenConnectPlan.Route(IPNetwork("192.168.1.0/24")!, via: .gateway(gateway))
        let onLink = KernelRoute(network: lan.network, interface: "en0")
        let attached = [OpenConnectPlan.Attached(lan.network, interface: "en0")]
        XCTAssertEqual(finding(lan, [onLink], attached: attached), .there(shared: false))
        XCTAssertEqual(
            finding(lan, [onLink], attached: []), .conflict("another route for 192.168.1.0/24 exists already, through en0"))
        // Not for a route into the tunnel.
        let lanInside = OpenConnectPlan.Route(lan.network, via: .interface("utun5"))
        XCTAssertEqual(
            finding(lanInside, [onLink], attached: attached), .conflict("another route for 192.168.1.0/24 exists already, through en0"))
    }

    #if os(macOS)
    // MARK: - The routing table's dump (macOS)

    /// One `rt_msghdr` record with its socket addresses, as `NET_RT_DUMP` gives it.
    static func message(flags: Int32, index: UInt16, _ addresses: [(Int32, [UInt8])]) -> [UInt8] {
        var header = rt_msghdr()
        header.rtm_version = UInt8(RTM_VERSION)
        header.rtm_type = UInt8(RTM_GET)
        header.rtm_flags = flags
        header.rtm_index = index
        var body: [UInt8] = []
        for (rtax, sa) in addresses {
            header.rtm_addrs |= 1 << rtax
            body += sa
            let padded = sa.isEmpty ? 4 : 1 + ((sa.count - 1) | 3)
            body += [UInt8](repeating: 0, count: padded - sa.count)
        }
        header.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + body.count)
        return withUnsafeBytes(of: header) { Array($0) } + body
    }

    static func sin(_ a: [UInt8]) -> [UInt8] { [16, UInt8(AF_INET), 0, 0] + a + [UInt8](repeating: 0, count: 8) }
    static func sin6(_ a: [UInt8]) -> [UInt8] { [28, UInt8(AF_INET6), 0, 0, 0, 0, 0, 0] + a + [0, 0, 0, 0] }
    static func sdl(_ index: UInt8) -> [UInt8] { [20, UInt8(AF_LINK), index, 0] + [UInt8](repeating: 0, count: 16) }

    func testRoutingTableDump() throws {
        let lo = UInt16(if_nametoindex("lo0"))
        let fe80: [UInt8] = [0xFE, 0x80, 0, UInt8(lo), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]  // scope embedded
        let buffer =
            Self.message(
                flags: RTF_UP | RTF_GATEWAY | RTF_STATIC, index: lo,
                [(RTAX_DST, Self.sin([0, 0, 0, 0])), (RTAX_GATEWAY, Self.sin([198, 51, 100, 1])), (RTAX_NETMASK, [0, 0, 0, 0])])
            + Self.message(
                flags: RTF_UP | RTF_HOST | RTF_GATEWAY | RTF_WASCLONED, index: lo,
                [(RTAX_DST, Self.sin([192, 0, 2, 10])), (RTAX_GATEWAY, Self.sin([198, 51, 100, 1]))])
            + Self.message(
                flags: RTF_UP | RTF_CLONING, index: lo,
                [(RTAX_DST, Self.sin([192, 168, 1, 0])), (RTAX_GATEWAY, Self.sdl(UInt8(lo))), (RTAX_NETMASK, [7, 0, 0, 0, 255, 255, 255])])
            + Self.message(
                flags: RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_REJECT, index: lo,
                [
                    (RTAX_DST, Self.sin6([UInt8](repeating: 0, count: 16))), (RTAX_GATEWAY, Self.sin6([UInt8](repeating: 0, count: 15) + [1])),
                    (RTAX_NETMASK, [9, 0, 0, 0, 0, 0, 0, 0, 0x80])
                ])
            + Self.message(
                flags: RTF_UP | RTF_GATEWAY | RTF_IFSCOPE, index: lo,
                [(RTAX_DST, Self.sin6([UInt8](repeating: 0, count: 16))), (RTAX_GATEWAY, Self.sin6(fe80)), (RTAX_NETMASK, [0, 0, 0, 0])])
            // A mask with a hole: left out.
            + Self.message(
                flags: RTF_UP, index: lo,
                [(RTAX_DST, Self.sin([10, 0, 0, 0])), (RTAX_GATEWAY, Self.sdl(UInt8(lo))), (RTAX_NETMASK, [8, 0, 0, 0, 255, 0, 255, 0])])
        let routes = KernelRoute.parseDump(buffer)
        XCTAssertEqual(
            routes,
            [
                KernelRoute(network: IPNetwork("0.0.0.0/0")!, gateway: IPAddress("198.51.100.1"), interface: "lo0"),
                KernelRoute(network: IPNetwork("192.0.2.10/32")!, gateway: IPAddress("198.51.100.1"), interface: "lo0", cloned: true),
                KernelRoute(network: IPNetwork("192.168.1.0/24")!, interface: "lo0"),
                KernelRoute(network: IPNetwork("::/1")!, gateway: IPAddress("::1"), interface: "lo0", reject: true),
                KernelRoute(network: IPNetwork("::/0")!, gateway: IPAddress("fe80::1"), interface: "lo0", scoped: true)
            ])
        // A truncated buffer ends the list, it does not trap.
        XCTAssertEqual(KernelRoute.parseDump(Array(buffer.prefix(buffer.count - 3))).count, 5)
        XCTAssertEqual(KernelRoute.parseDump([1, 2, 3]), [])
    }
    #endif
}
