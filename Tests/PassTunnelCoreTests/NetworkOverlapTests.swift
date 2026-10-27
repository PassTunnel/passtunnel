import PassTunnelShared
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

#if canImport(Combine)
import Combine
#endif

/// Reading what a tunnel takes over from the tools' logs and the routing table (examples only).
final class NetworkLogParsingTests: XCTestCase {
    static let push =
        "2026-10-25 09:41:02 PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0,route-ipv6 2001:db8::/32,"
        + "dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN-ROUTE example.com,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,"
        + "ifconfig 10.8.0.6 255.255.255.0,peer-id 0,cipher AES-256-GCM,auth-token SESS_ID_secret'"

    func testThePushedOptionsOfOpenVPN() {
        let log = """
            2026-10-25 09:41:00 OpenVPN 2.7.8 aarch64-apple-darwin25.6.0 [SSL (OpenSSL)]
            2026-10-25 09:41:01 TLS: Initial packet from [AF_INET]203.0.113.10:1194, sid=1234abcd
            \(Self.push)
            2026-10-25 09:41:02 OPTIONS IMPORT: route options modified

            """
        XCTAssertEqual(
            VPNLog.pushedOptions(log),
            [
                "route 10.0.0.0 255.0.0.0", "route-ipv6 2001:db8::/32", "dhcp-option DNS 10.8.0.1",
                "dhcp-option DOMAIN-ROUTE example.com"
            ],
            "only routes, redirects and DNS; no address, timer, cipher or token")
        XCTAssertFalse(VPNLog.pushedOptions(log)!.joined().contains("SESS_ID"))
    }

    func testNoPushIsNotAnEmptyPush() {
        XCTAssertNil(VPNLog.pushedOptions(""))
        XCTAssertNil(VPNLog.pushedOptions("2026-10-25 09:41:01 TLS: Initial packet from [AF_INET]203.0.113.10:1194\n"))
        XCTAssertNil(VPNLog.pushedOptions("PUSH: Received control message: 'AUTH_FAILED'\n"))
        XCTAssertNil(VPNLog.pushedOptions("PUSH: Received control message: 'PUSH_REPLYX,route 10.0.0.0 255.0.0.0'\n"), "another message")
        XCTAssertNil(VPNLog.pushedOptions("PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0\n"), "no closing quote")
        XCTAssertEqual(VPNLog.pushedOptions("PUSH: Received control message: 'PUSH_REPLY'\n"), [])
        XCTAssertEqual(
            VPNLog.pushedOptions("PUSH: Received control message: 'PUSH_REPLY,ping 10,ifconfig 10.8.0.6 255.255.255.0'\n"), [],
            "a push that says nothing about routes or DNS")
    }

    func testAPushInSeveralMessagesIsOnePush() {
        let log = """
            PUSH: Received control message: 'PUSH_REPLY,route 10.1.0.0 255.255.0.0,route 10.2.0.0 255.255.0.0,push-continue 1'
            PUSH: Received control message: 'PUSH_REPLY,route 10.3.0.0 255.255.0.0,dhcp-option DNS 10.8.0.1,push-continue 1'
            PUSH: Received control message: 'PUSH_REPLY,route 10.4.0.0 255.255.0.0,ifconfig 10.8.0.6 255.255.255.0,push-continue 2'

            """
        XCTAssertEqual(
            VPNLog.pushedOptions(log),
            [
                "route 10.1.0.0 255.255.0.0", "route 10.2.0.0 255.255.0.0", "route 10.3.0.0 255.255.0.0",
                "dhcp-option DNS 10.8.0.1", "route 10.4.0.0 255.255.0.0"
            ])
    }

    func testALaterPushReplacesAnEarlierOne() {
        let log = """
            PUSH: Received control message: 'PUSH_REPLY,route 10.1.0.0 255.255.0.0,ifconfig 10.8.0.6 255.255.255.0'
            SIGUSR1[soft,ping-restart] received, process restarting
            PUSH: Received control message: 'PUSH_REPLY,route 10.9.0.0 255.255.0.0,ifconfig 10.8.0.6 255.255.255.0'

            """
        XCTAssertEqual(VPNLog.pushedOptions(log), ["route 10.9.0.0 255.255.0.0"])
        // A push that is cut off after a "push-continue 1" is still what there is.
        XCTAssertEqual(
            VPNLog.pushedOptions("PUSH: Received control message: 'PUSH_REPLY,route 10.1.0.0 255.255.0.0,push-continue 1'\n"),
            ["route 10.1.0.0 255.255.0.0"])
    }

    func testServerTextIsReadWithLimits() {
        // Control characters, non-ASCII, and long options are dropped; the rest of the line still counts.
        let longOption = "dhcp-option DOMAIN " + String(repeating: "a", count: 600)
        let line =
            "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0,route 10.1.0.0\u{7} 255.0.0.0,"
            + "dhcp-option DOMAIN bücher.example,\(longOption),dhcp-option DNS 10.8.0.1'\n"
        XCTAssertEqual(VPNLog.pushedOptions(line), ["route 10.0.0.0 255.0.0.0", "dhcp-option DNS 10.8.0.1"])
        // A line over the limit is not read at all.
        let huge = "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0," + String(repeating: "x", count: VPNLog.maxPushLine) + "'\n"
        XCTAssertNil(VPNLog.pushedOptions(huge))
        XCTAssertEqual(VPNLog.pushedOptions(huge + Self.push + "\n")?.count, 4)
        // At most `maxPushedOptions` are kept, however many messages the push comes in.
        let chunks = (0..<5).map { chunk in
            (0..<400).map { "route 10.\(($0 + chunk * 400) / 256).\(($0 + chunk * 400) % 256).0 255.255.255.0" }.joined(separator: ",")
        }
        let flood = chunks.map { "PUSH: Received control message: 'PUSH_REPLY,\($0),push-continue 1'\n" }.joined()
        XCTAssertEqual(VPNLog.pushedOptions(flood)?.count, 1024)
        // Options of the same kind with odd spacing are kept as sent, and read by `networkClaims`.
        XCTAssertEqual(
            VPNLog.pushedOptions("PUSH: Received control message: 'PUSH_REPLY, route 10.0.0.0 255.0.0.0 ,,'\n"),
            ["route 10.0.0.0 255.0.0.0"])
    }

    func testTheGatewaysDNSOfOpenFortiVPN() {
        let line = "INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54], ns_suffix [example.com;corp.example.com]\n"
        XCTAssertEqual(
            VPNLog.fortiOptions("INFO:   Connected to gateway.\n" + line + "INFO:   Tunnel is up and running.\n"),
            [
                "dhcp-option DNS 198.51.100.53", "dhcp-option DNS 198.51.100.54", "dhcp-option DOMAIN example.com",
                "dhcp-option DOMAIN corp.example.com"
            ])
        XCTAssertEqual(
            VPNLog.fortiOptions("INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 0.0.0.0]\n"),
            ["dhcp-option DNS 198.51.100.53"])
        XCTAssertEqual(VPNLog.fortiOptions("INFO:   Got addresses: [10.212.134.200], ns [0.0.0.0, 0.0.0.0]\n"), [])
        XCTAssertEqual(
            VPNLog.fortiOptions("INFO:   Got addresses: [10.1.2.3], ns [2001:db8::53, bad name], ns_suffix [bad!name;a.example]\n"),
            ["dhcp-option DNS 2001:db8::53", "dhcp-option DOMAIN a.example"])
        XCTAssertNil(VPNLog.fortiOptions("INFO:   Tunnel is up and running.\n"))
        XCTAssertNil(VPNLog.fortiOptions("INFO:   Got addresses: [10.1.2.3]\n"))
        // The last addresses line wins (a reconnect).
        XCTAssertEqual(
            VPNLog.fortiOptions(line + "INFO:   Got addresses: [10.2.3.4], ns [198.51.100.99, 0.0.0.0]\n"),
            ["dhcp-option DNS 198.51.100.99"])
        // What comes out is read by the same code as an OpenVPN push.
        let claims = OVPNAnalyzer.networkClaims("", pushed: VPNLog.fortiOptions(line)!)
        XCTAssertEqual(claims.dnsServers, ["198.51.100.53", "198.51.100.54"])
        XCTAssertEqual(claims.searchDomains, ["example.com", "corp.example.com"])
    }

    // MARK: routing table

    typealias Route = RoutingTable.Route

    func testRoutesOfATunnelInterface() {
        let table = [
            Route(destination: "10.20.0.0", prefixLength: 16, interface: "ppp0"),
            Route(destination: "192.0.2.0", prefixLength: 24, interface: "ppp0"),
            Route(destination: "10.30.0.0", prefixLength: 16, interface: "ppp1"),
            Route(destination: "10.40.0.0", prefixLength: 16, interface: "ppp0", scoped: true),
            Route(destination: "169.254.2.1", prefixLength: 32, interface: "ppp0"),
            Route(destination: "224.0.0.0", prefixLength: 4, interface: "ppp0"),
            Route(destination: "255.255.255.255", prefixLength: 32, interface: "ppp0"),
            Route(destination: "fe80::", prefixLength: 64, interface: "ppp0"),
            Route(destination: "2001:db8::", prefixLength: 32, interface: "ppp0"),
            Route(destination: "0.0.0.0", prefixLength: 0, interface: "en0"),
            Route(destination: "not an address", prefixLength: 8, interface: "ppp0")
        ]
        let served = RoutingTable.servedRoutes(in: table, interface: "ppp0")
        XCTAssertEqual(served.map { "\($0.destination)/\($0.prefixLength)" }, ["10.20.0.0/16", "192.0.2.0/24", "2001:db8::/32"])
        XCTAssertEqual(RoutingTable.servedRoutes(in: table, interface: "utun9"), [])
        XCTAssertEqual(RoutingTable.routes(onInterface: ""), [])
    }

    func testLinuxRoutesOfALink() {
        let links: [Int32: Netlink.Link] = [4: Netlink.Link(index: 4, name: "ppp0", kind: "ppp"), 2: Netlink.Link(index: 2, name: "eth0", kind: nil)]
        func route(
            _ destination: [UInt8], _ prefix: Int, family: UInt8 = Netlink.inet, table: UInt32 = Netlink.mainTable,
            type: UInt8 = Netlink.unicast, via: [Int32]
        ) -> Netlink.Route {
            Netlink.Route(family: family, destination: destination, prefixLength: prefix, table: table, type: type, interfaces: via)
        }
        let routes = [
            route([10, 20, 0, 0], 16, via: [4]),
            route([], 0, via: [4]),  // a default route through the tunnel
            route([192, 0, 2, 0], 24, via: [2]),  // not this link
            route([10, 50, 0, 0], 16, table: 100, via: [4]),  // not the main table
            route([10, 60, 0, 0], 16, type: 7, via: [4]),  // not unicast (RTN_UNREACHABLE)
            route([169, 254, 0, 0], 16, via: [4]),  // link-local
            route([0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 12), 32, family: Netlink.inet6, via: [4]),
            route([10, 70, 0, 0], 16, via: [9])  // a link nobody knows
        ]
        let served = RoutingTable.linuxRoutes(onInterface: "ppp0", routes: routes, links: links)
        XCTAssertEqual(served.map { "\($0.destination)/\($0.prefixLength)" }, ["10.20.0.0/16", "0.0.0.0/0", "2001:db8::/32"])
        XCTAssertTrue(served.allSatisfy { $0.tunnelDevice && $0.interface == "ppp0" })
    }

    func testRoutesBecomeOptions() {
        XCTAssertEqual(ProfileNetwork.option(Route(destination: "10.20.0.0", prefixLength: 16, interface: "ppp0")), "route 10.20.0.0 255.255.0.0")
        XCTAssertEqual(ProfileNetwork.option(Route(destination: "0.0.0.0", prefixLength: 0, interface: "ppp0")), "route 0.0.0.0 0.0.0.0")
        XCTAssertEqual(ProfileNetwork.option(Route(destination: "192.0.2.7", prefixLength: 32, interface: "ppp0")), "route 192.0.2.7 255.255.255.255")
        XCTAssertEqual(ProfileNetwork.option(Route(destination: "10.0.0.0", prefixLength: 9, interface: "ppp0")), "route 10.0.0.0 255.128.0.0")
        XCTAssertEqual(ProfileNetwork.option(Route(destination: "2001:db8::", prefixLength: 32, interface: "ppp0")), "route-ipv6 2001:db8::/32")
        XCTAssertNil(ProfileNetwork.option(Route(destination: "nope", prefixLength: 8, interface: "ppp0")))
        for prefix in 0...32 {
            let option = ProfileNetwork.option(Route(destination: "10.0.0.0", prefixLength: prefix, interface: "ppp0"))!
            let words = option.split(separator: " ").map(String.init)
            XCTAssertEqual(CIDR(address: words[1], netmask: words[2])?.prefixLength, prefix, option)
        }
    }

    // MARK: words

    func overlap(_ mine: NetworkClaims, _ theirs: NetworkClaims) -> ProfileOverlap {
        ProfileOverlap(profileID: "work", name: "Work", overlaps: NetworkClaims.overlaps(mine, theirs), mine: mine, theirs: theirs)
    }

    func testMessageLines() {
        let mine = NetworkClaims(routes: [CIDR("10.0.0.0/8")!], dnsServers: ["10.9.0.1"], dnsDomains: ["example.com"])
        let theirs = NetworkClaims(routes: [CIDR("10.0.0.0/8")!, CIDR("10.9.0.0/16")!], dnsServers: ["10.8.0.1"], dnsDomains: ["example.com"])
        let lines = overlap(mine, theirs).messageLines(connecting: "Lab")
        XCTAssertEqual(lines.first, "Warning: Lab overlaps with Work.")
        XCTAssertTrue(lines.contains("Both send these networks through their tunnel: 10.0.0.0/8, 10.9.0.0/16"), "\(lines)")
        XCTAssertTrue(lines.contains("Both look up these names through their tunnel: example.com"))
        XCTAssertEqual(lines.last, "That traffic can only go through one of the two tunnels.")
        XCTAssertFalse(lines.contains { $0.contains("all traffic") })

        let full = overlap(NetworkClaims(fullTunnel: true), theirs).messageLines(connecting: "Lab")
        XCTAssertEqual(full[1], "Lab sends all traffic through its tunnel.")
        let theirFull = overlap(mine, NetworkClaims(routes: [CIDR("10.1.0.0/16")!], fullTunnel: true)).messageLines(connecting: "Lab")
        XCTAssertEqual(theirFull[1], "Work sends all traffic through its tunnel.")
        let both = overlap(NetworkClaims(fullTunnel: true), NetworkClaims(fullTunnel: true)).messageLines(connecting: "Lab")
        XCTAssertEqual(
            both,
            [
                "Warning: Lab overlaps with Work.", "Both send all traffic through their tunnel.",
                "That traffic can only go through one of the two tunnels."
            ])
    }

    func testLongListsAreShortened() {
        let many = NetworkClaims(routes: (0..<8).map { CIDR("10.\($0).0.0/16")! })
        let lines = overlap(many, many).messageLines(connecting: "Lab")
        XCTAssertTrue(
            lines.contains("Both send these networks through their tunnel: 10.0.0.0/16, 10.1.0.0/16, 10.2.0.0/16, 10.3.0.0/16, 10.4.0.0/16 +3 more"),
            "\(lines)")
    }

    func testTheWarningOfAConnect() throws {
        let mine = NetworkClaims(routes: [CIDR("10.0.0.0/8")!], fullTunnel: true, dnsDomains: ["example.com"])
        let theirs = NetworkClaims(routes: [CIDR("10.9.0.0/16")!, CIDR("192.0.2.0/24")!], dnsDomains: ["corp.example.com"])
        let warning = ConnectWarning(overlap(mine, theirs), connecting: "lab")
        XCTAssertEqual(
            warning,
            ConnectWarning(
                kind: "overlap", with: "work", name: "Work", routes: ["10.9.0.0/16"],
                domains: ["corp.example.com"], allTraffic: ["lab"]))
        let encoder = JSONCoding.encoder()
        let json = String(decoding: try encoder.encode(warning), as: UTF8.self)
        XCTAssertTrue(json.contains(#""all_traffic" : ["#), json)
        XCTAssertTrue(json.contains(#""kind" : "overlap""#), json)
        XCTAssertTrue(json.contains(#""with" : "work""#), json)
        let none = ConnectWarning(
            overlap(NetworkClaims(routes: [CIDR("10.0.0.0/8")!]), NetworkClaims(routes: [CIDR("10.1.0.0/16")!])), connecting: "lab")
        XCTAssertNil(none.allTraffic)
        XCTAssertFalse(String(decoding: try encoder.encode(none), as: UTF8.self).contains("all_traffic"))
    }
}

/// `profiles/<id>/network.json`: written by the profile owner's process only, read back with care.
final class NetworkCacheTests: CoreTestCase {
    func makeProfile(_ name: String = "Work", config: String = "client\nremote vpn.example.com 1194\n") throws -> Profile {
        let p = try store.create(name: name, type: .openvpn)
        try Data(config.utf8).write(to: store.ovpnURL(p.id))
        return p
    }

    func url(_ p: Profile) -> URL { store.dir(p.id).appendingPathComponent(ProfileNetwork.fileName) }

    func testSavedAndReadBack() throws {
        let p = try makeProfile()
        XCTAssertNil(ProfileNetwork.savedOptions(p, store: store), "a first connect has nothing")
        let options = ["route 10.0.0.0 255.0.0.0", "dhcp-option DNS 10.8.0.1"]
        ProfileNetwork.save(options, for: p, store: store)
        XCTAssertEqual(ProfileNetwork.savedOptions(p, store: store), options)
        XCTAssertEqual(try mode(url(p)), 0o600)
        let text = try String(contentsOf: url(p), encoding: .utf8)
        XCTAssertTrue(text.contains("\"options\""), text)
        // Replaced atomically: no temp file stays behind.
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: store.dir(p.id).path).filter { $0.hasSuffix(".tmp") }
        XCTAssertEqual(leftovers, [])
        ProfileNetwork.save([], for: p, store: store)
        XCTAssertEqual(ProfileNetwork.savedOptions(p, store: store), [], "a push that claimed nothing is remembered too")
    }

    func testAChangedServerMakesItStale() throws {
        let p = try makeProfile()
        ProfileNetwork.save(["route 10.0.0.0 255.0.0.0"], for: p, store: store)
        XCTAssertNotNil(ProfileNetwork.savedOptions(p, store: store))
        try Data("client\nremote vpn2.example.com 1194\n".utf8).write(to: store.ovpnURL(p.id))
        XCTAssertNil(ProfileNetwork.savedOptions(p, store: store), "another config is another server")
        try Data("client\nremote vpn.example.com 1194\n".utf8).write(to: store.ovpnURL(p.id))
        XCTAssertNotNil(ProfileNetwork.savedOptions(p, store: store))
    }

    func testDamagedFilesAreIgnored() throws {
        let p = try makeProfile()
        let destination = ProfileDestination.of(p, store: store).fingerprint
        func write(_ text: String, mode: mode_t = 0o600) throws {
            try? FileManager.default.removeItem(at: url(p))
            try FileIO.writeAtomically(Data(text.utf8), to: url(p), mode: mode)
        }
        let good = #"{"version": 1, "destination": "\#(destination)", "options": ["route 10.0.0.0 255.0.0.0"]}"#
        try write(good)
        XCTAssertEqual(ProfileNetwork.savedOptions(p, store: store), ["route 10.0.0.0 255.0.0.0"])

        let bad = [
            "", "not json", "[]", "null", "{}", "{\"version\": 1}", good.replacingOccurrences(of: "\"version\": 1", with: "\"version\": 2"),
            good.replacingOccurrences(of: "\"version\": 1", with: "\"version\": \"1\""),
            good.replacingOccurrences(of: destination, with: "other"),
            good.replacingOccurrences(of: "route 10.0.0.0 255.0.0.0", with: "auth-token SESS_ID_x"),
            good.replacingOccurrences(of: "route 10.0.0.0 255.0.0.0", with: "route 10.0.0.0\\u0007255.0.0.0"),
            good.replacingOccurrences(of: "[\"route 10.0.0.0 255.0.0.0\"]", with: "[1, 2]"),
            good.replacingOccurrences(of: "[\"route 10.0.0.0 255.0.0.0\"]", with: "\"route\""),
            String(good.dropLast(5)),
            good + good
        ]
        for text in bad {
            try write(text)
            XCTAssertNil(ProfileNetwork.savedOptions(p, store: store), text)
        }
        // Too many options, an option that is too long, a file that is too big.
        let flood = (0..<1025).map { "\"route 10.\($0 / 256).\($0 % 256).0 255.255.255.0\"" }.joined(separator: ",")
        try write(#"{"version": 1, "destination": "\#(destination)", "options": [\#(flood)]}"#)
        XCTAssertNil(ProfileNetwork.savedOptions(p, store: store))
        try write(#"{"version": 1, "destination": "\#(destination)", "options": ["route \#(String(repeating: "1", count: 600))"]}"#)
        XCTAssertNil(ProfileNetwork.savedOptions(p, store: store))
        try write(good + String(repeating: " ", count: ProfileNetwork.maxFileSize))
        XCTAssertNil(ProfileNetwork.savedOptions(p, store: store))
        // Access for the group or others makes it not ours.
        for loose: mode_t in [0o640, 0o604, 0o644, 0o666] {
            try write(good, mode: loose)
            XCTAssertNil(ProfileNetwork.savedOptions(p, store: store), String(loose, radix: 8))
        }
        try write(good)
        XCTAssertNotNil(ProfileNetwork.savedOptions(p, store: store))
        try? FileManager.default.removeItem(at: url(p))
        XCTAssertNil(ProfileNetwork.savedOptions(p, store: store))
    }

    func testALinkIsNotFollowed() throws {
        let p = try makeProfile()
        ProfileNetwork.save(["route 10.0.0.0 255.0.0.0"], for: p, store: store)
        let real = store.dir(p.id).appendingPathComponent("elsewhere.json")
        try FileManager.default.moveItem(at: url(p), to: real)
        try FileManager.default.createSymbolicLink(at: url(p), withDestinationURL: real)
        XCTAssertNil(ProfileNetwork.savedOptions(p, store: store))
        // A directory in its place, and a fifo, are not read either.
        try FileManager.default.removeItem(at: url(p))
        try FileManager.default.createDirectory(at: url(p), withIntermediateDirectories: false)
        XCTAssertNil(ProfileNetwork.savedOptions(p, store: store))
        try FileManager.default.removeItem(at: url(p))
        XCTAssertEqual(mkfifo(url(p).path, 0o600), 0)
        XCTAssertNil(ProfileNetwork.savedOptions(p, store: store))
    }

    func testSavingReplacesALink() throws {
        let p = try makeProfile()
        let target = home.appendingPathComponent("victim.txt")
        try Data("keep".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: url(p), withDestinationURL: target)
        ProfileNetwork.save(["route 10.0.0.0 255.0.0.0"], for: p, store: store)
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "keep", "the file it pointed to is left alone")
        XCTAssertNotNil(ProfileNetwork.savedOptions(p, store: store))
    }

    #if os(macOS)
    /// Written at every connect, by the app too: the app must not reload for it.
    func testTheAppDoesNotReloadForIt() throws {
        let p = try makeProfile()
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: url(p).path))
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: store.dir(p.id).path + "/.network.json.1A2B.tmp"))
        XCTAssertTrue(ProfilesWatcher.isRelevant(path: store.dir(p.id).path + "/profile.json"))
    }
    #endif

    func testTheClaimsOfAProfile() throws {
        let p = try makeProfile(config: "client\nremote vpn.example.com 1194\nroute 192.0.2.0 255.255.255.0\n")
        func claims(live: Bool) -> NetworkClaims { ProfileNetwork.claims(for: p, store: store, live: live) { _ in [] } }
        // Only its own lines before it ever connected.
        XCTAssertEqual(claims(live: false).routes.map(\.description), ["192.0.2.0/24"])
        // After a connect: the config's lines and what the server pushed.
        ProfileNetwork.save(["route 10.0.0.0 255.0.0.0", "dhcp-option DNS 10.8.0.1"], for: p, store: store)
        XCTAssertEqual(claims(live: false).routes.map(\.description), ["10.0.0.0/8", "192.0.2.0/24"])
        XCTAssertEqual(claims(live: false).dnsServers, ["10.8.0.1"])
        // A log with a push: a tunnel that is up is read from it, one about to connect from the file
        // (its log may belong to an attempt that failed).
        try Data("PUSH: Received control message: 'PUSH_REPLY,route 172.16.0.0 255.240.0.0'\n".utf8).write(to: store.logURL(p.id))
        XCTAssertEqual(claims(live: true).routes.map(\.description), ["172.16.0.0/12", "192.0.2.0/24"])
        XCTAssertEqual(claims(live: false).routes.map(\.description), ["10.0.0.0/8", "192.0.2.0/24"])
        // No file: the log, whichever way.
        try FileManager.default.removeItem(at: url(p))
        XCTAssertEqual(claims(live: false).routes.map(\.description), ["172.16.0.0/12", "192.0.2.0/24"])
        // The config's pull filters apply to what the file remembers.
        try Data("client\nremote vpn.example.com 1194\npull-filter ignore \"route 10.\"\n".utf8).write(to: store.ovpnURL(p.id))
        ProfileNetwork.save(["route 10.0.0.0 255.0.0.0", "route 172.16.0.0 255.240.0.0"], for: p, store: store)
        XCTAssertEqual(claims(live: false).routes.map(\.description), ["172.16.0.0/12"])
    }
}
