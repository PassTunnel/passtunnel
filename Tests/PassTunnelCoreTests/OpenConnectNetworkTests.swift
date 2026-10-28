import Foundation
import XCTest

@testable import PassTunnelShared

/// openconnect's hook, the pure part (#183): what openconnect 9.21 hands it (`OpenConnectNetwork`), what it
/// changes (`OpenConnectPlan`), its record (`OpenConnectRecord`) and its report lines (`VPNHook`). The golden
/// cases are in Tests/Fixtures/openconnect-env.json.
final class OpenConnectNetworkTests: XCTestCase {
    static let fixtureURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Fixtures/openconnect-env.json")

    struct Case {
        var name: String
        var platform: OpenConnectNetwork.Platform
        var policy: OpenConnectPolicy
        var underlay: OpenConnectPlan.Underlay
        var entries: [[UInt8]]
        /// The case's own values, for the check that errors never repeat them.
        var values: [String]
        var raw: [String: Any]
    }

    static func gateway(_ text: String) -> OpenConnectPlan.Gateway {
        let words = text.split(separator: " ").map(String.init)
        return OpenConnectPlan.Gateway(address: words[0] == "link" ? nil : IPAddress(words[0]), interface: words[1])!
    }

    static func hexBytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var chars = Array(hex)
        while chars.count >= 2 {
            out.append(UInt8(String(chars[0..<2]), radix: 16)!)
            chars.removeFirst(2)
        }
        return out
    }

    static func loadCases() throws -> [Case] {
        let data = try Data(contentsOf: fixtureURL)
        let top = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let base = try XCTUnwrap(top["base"] as? [String: String])
        let cases = try XCTUnwrap(top["cases"] as? [[String: Any]])
        return try cases.map { c in
            var env = (c["base_none"] as? Bool) == true ? [:] : base
            var values: [String] = []
            for (key, value) in (c["env"] as? [String: Any]) ?? [:] {
                if let s = value as? String {
                    env[key] = s
                    values.append(s)
                } else {
                    env[key] = nil
                }
            }
            var entries = env.map { Array(($0.key + "=" + $0.value).utf8) }
            for (key, hex) in (c["env_hex"] as? [String: String]) ?? [:] {
                entries.removeAll { $0.starts(with: Array((key + "=").utf8)) }
                entries.append(Array((key + "=").utf8) + hexBytes(hex))
            }
            let policy = (c["policy"] as? [String: Bool]) ?? [:]
            var underlay = OpenConnectPlan.Underlay(ipv4: gateway("198.51.100.1 en0"))
            if let u = c["underlay"] as? [String: Any] {
                let attached = ((u["attached"] as? [String]) ?? []).map { text -> OpenConnectPlan.Attached in
                    let words = text.split(separator: " ").map(String.init)
                    return OpenConnectPlan.Attached(IPNetwork(words[0])!, interface: words[1])
                }
                underlay = OpenConnectPlan.Underlay(
                    ipv4: (u["ipv4"] as? String).map(gateway), ipv6: (u["ipv6"] as? String).map(gateway), attached: attached)
            }
            return Case(
                name: try XCTUnwrap(c["name"] as? String),
                platform: (c["platform"] as? String) == "linux" ? .linux : .macOS,
                policy: OpenConnectPolicy(
                    uid: 501, profileID: "acme", setRoutes: policy["set_routes"] ?? true, setDNS: policy["set_dns"] ?? true),
                underlay: underlay, entries: entries, values: values, raw: c)
        }
    }

    /// The event, plan and report of a case, or its error's description.
    static func run(_ c: Case) -> (event: OpenConnectNetwork.Event?, plan: OpenConnectPlan?, error: String?) {
        do {
            let event = try OpenConnectNetwork.parse(.init(entries: c.entries), platform: c.platform)
            guard let network = event.network else { return (event, nil, nil) }
            return (event, try OpenConnectPlan.connect(network, policy: c.policy, underlay: c.underlay), nil)
        } catch {
            return (nil, nil, String(describing: error))
        }
    }

    func testGoldenCases() throws {
        let cases = try Self.loadCases()
        XCTAssertGreaterThan(cases.count, 100)
        for c in cases {
            let (event, plan, error) = Self.run(c)
            if let expected = c.raw["error"] as? String {
                XCTAssertEqual(error, expected, c.name)
                continue
            }
            XCTAssertNil(error, c.name)
            XCTAssertEqual(event?.reason.rawValue, c.raw["event"] as? String, c.name)
            let changes = (c.raw["changes"] as? [String]) ?? []
            XCTAssertEqual(plan?.changes.map(\.text) ?? [], changes, c.name)
            if let report = c.raw["report"] as? String {
                guard let plan else { XCTFail("\(c.name): no plan"); continue }
                XCTAssertEqual(VPNHook.Report(plan).line, report + "\n", c.name)
            } else {
                XCTAssertNil(plan, c.name)
            }
        }
    }

    /// The description of a refusal names the variable and the rule, never the value: none of the values a
    /// case sets appears in it.
    func testErrorsNeverRepeatValues() throws {
        for c in try Self.loadCases() where c.raw["error"] != nil {
            guard let error = Self.run(c).error else { continue }
            for value in c.values where value.utf8.count >= 5 {
                XCTAssertFalse(error.contains(value), "\(c.name): \(error)")
            }
            XCTAssertTrue(error.utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7F }, c.name)
            let line = VPNHook.failureLine(error)
            XCTAssertEqual(line.utf8.filter { $0 == 0x0A }.count, 1)
            XCTAssertTrue(line.hasPrefix(VPNHook.failurePrefix) && line.hasSuffix("\n"))
        }
    }

    /// Every accepted network written back as openconnect's variables parses to the same network; every
    /// change of its plan parses back from its text; the report line parses back.
    func testAcceptedValuesValidateAgain() throws {
        var checked = 0
        for c in try Self.loadCases() {
            let (event, plan, _) = Self.run(c)
            guard let event, let network = event.network else { continue }
            let again = try OpenConnectNetwork.parse(.init(network.environment(reason: event.reason)), platform: c.platform)
            XCTAssertEqual(again, event, c.name)
            guard let plan else { continue }
            for change in plan.changes { XCTAssertEqual(OpenConnectPlan.Change(text: change.text), change, change.text) }
            let report = VPNHook.Report(plan)
            XCTAssertEqual(VPNHook.Report.parse(report.line[...]), report, c.name)
            XCTAssertEqual(VPNHook.Report.parse(report.line.dropLast()), report, c.name)
            checked += 1
        }
        XCTAssertGreaterThan(checked, 15)
    }

    // MARK: Environment

    static let minimal: [String: String] = [
        "reason": "connect", "TUNDEV": "utun3", "VPNGATEWAY": "192.0.2.10", "INTERNAL_IP4_MTU": "1400",
        "INTERNAL_IP4_ADDRESS": "10.11.0.2"
    ]

    func parse(_ env: [String: String], platform: OpenConnectNetwork.Platform = .macOS) throws -> OpenConnectNetwork {
        guard let network = try OpenConnectNetwork.parse(.init(env), platform: platform).network else {
            throw OpenConnectNetwork.Failure.missing("reason")
        }
        return network
    }

    func testRepeatedVariableIsRefusedOnlyWhenRead() throws {
        let entries = Self.minimal.map { Array("\($0.key)=\($0.value)".utf8) }
        let twice = entries + [Array("INTERNAL_IP4_ADDRESS=10.11.0.3".utf8)]
        XCTAssertThrowsError(try OpenConnectNetwork.parse(.init(entries: twice), platform: .macOS)) {
            XCTAssertEqual($0 as? OpenConnectNetwork.Failure, .duplicate("INTERNAL_IP4_ADDRESS"))
        }
        let banner = entries + [Array("CISCO_BANNER=a".utf8), Array("CISCO_BANNER=b".utf8)]
        XCTAssertNoThrow(try OpenConnectNetwork.parse(.init(entries: banner), platform: .macOS))
        // Entries that cannot be openconnect's are left out.
        let odd = entries + [Array("no equals sign".utf8), Array("=empty name".utf8), [0xFF, 0x3D, 0x31]]
        XCTAssertNoThrow(try OpenConnectNetwork.parse(.init(entries: odd), platform: .macOS))
    }

    func testOverlongValueIsRefusedBeforeParsing() {
        var env = Self.minimal
        env["CISCO_DEF_DOMAIN"] = String(repeating: "a.", count: OpenConnectNetwork.maxValueBytes)
        XCTAssertThrowsError(try parse(env)) { XCTAssertEqual($0 as? OpenConnectNetwork.Failure, .tooLong("CISCO_DEF_DOMAIN")) }
        // Ignored variables may be as long as they like.
        env["CISCO_DEF_DOMAIN"] = nil
        env["CISCO_BANNER"] = String(repeating: "\u{7}x\n", count: 100_000)
        XCTAssertNoThrow(try parse(env))
    }

    func testEveryControlByteIsRefused() {
        for byte in Array(0x00...0x1F) + [0x7F, 0x80, 0xFF] {
            var entries = Self.minimal.filter { $0.key != "TUNDEV" }.map { Array("\($0.key)=\($0.value)".utf8) }
            entries.append(Array("TUNDEV=utun3".utf8) + [UInt8(byte)])
            XCTAssertThrowsError(try OpenConnectNetwork.parse(.init(entries: entries), platform: .macOS), "\(byte)") {
                XCTAssertEqual($0 as? OpenConnectNetwork.Failure, .invalid("TUNDEV", "printable ASCII"))
            }
        }
    }

    func testListsAtTheirLimits() throws {
        var env = Self.minimal
        env["INTERNAL_IP6_ADDRESS"] = "2001:db8:1::2"
        env["INTERNAL_IP4_DNS"] = "10.11.0.53 10.11.0.54 2001:db8:1::53"
        env["CISCO_DEF_DOMAIN"] = (1...16).map { "d\($0).example.com" }.joined(separator: " ")
        env["CISCO_SPLIT_DNS"] = (1...16).map { "s\($0).example.com" }.joined(separator: ",")
        for (name, family) in [
            ("CISCO_SPLIT_INC", IPAddress.Family.ipv4), ("CISCO_SPLIT_EXC", .ipv4), ("CISCO_IPV6_SPLIT_INC", .ipv6),
            ("CISCO_IPV6_SPLIT_EXC", .ipv6)
        ] {
            env[name] = "1024"
            for i in 0..<1024 {
                let base = "\(name)_\(i)_"
                if family == .ipv4 {
                    env[base + "ADDR"] = "\(name.hasSuffix("INC") ? 10 : 172).\(i / 256).\(i % 256).0"
                    env[base + "MASK"] = "255.255.255.0"
                    env[base + "MASKLEN"] = "24"
                } else {
                    env[base + "ADDR"] = "2001:db8:\(name.hasSuffix("INC") ? "a" : "b"):\(String(i, radix: 16))::"
                    env[base + "MASKLEN"] = "64"
                }
            }
        }
        let network = try parse(env)
        XCTAssertEqual(network.ipv4Includes.count, 1024)
        XCTAssertEqual(network.ipv6Excludes.count, 1024)
        XCTAssertEqual(network.defaultDomains.count, 16)
        let underlay = OpenConnectPlan.Underlay(ipv4: Self.gateway("198.51.100.1 en0"), ipv6: Self.gateway("fe80::1 en0"))
        let policy = OpenConnectPolicy(uid: 501, profileID: "acme", setRoutes: true, setDNS: true)
        let plan = try OpenConnectPlan.connect(network, policy: policy, underlay: underlay)
        // 2,048 includes, the two assigned networks are none (no netmask), three DNS servers, 2,048 excludes.
        XCTAssertEqual(plan.tunnelRoutes.count, 2048 + 3)
        XCTAssertEqual(plan.changes.filter(\.isThroughGateway).count, 2048)
        XCTAssertEqual(plan.dns?.matchDomains.count, 32)
        var record = OpenConnectRecord(interface: "utun3")!
        for change in plan.changes {
            try record.append(.begin(change))
            try record.append(.owned(change))
        }
        try record.append(.status(.up))
        let text = try record.text()
        XCTAssertLessThan(text.utf8.count, OpenConnectRecord.maxBytes)
        XCTAssertEqual(OpenConnectRecord.parse(text), record)
        XCTAssertEqual(VPNHook.Report.parse(VPNHook.Report(plan).line[...]), VPNHook.Report(plan))

        env["CISCO_SPLIT_EXC"] = "1025"
        env["CISCO_SPLIT_EXC_1024_ADDR"] = "192.168.0.0"
        env["CISCO_SPLIT_EXC_1024_MASK"] = "255.255.0.0"
        env["CISCO_SPLIT_EXC_1024_MASKLEN"] = "16"
        XCTAssertThrowsError(try parse(env)) { XCTAssertEqual($0 as? OpenConnectNetwork.Failure, .tooMany("CISCO_SPLIT_EXC", 1024)) }
        env["CISCO_SPLIT_EXC"] = "1024"
        XCTAssertThrowsError(try parse(env)) { XCTAssertEqual($0 as? OpenConnectNetwork.Failure, .unexpected("CISCO_SPLIT_EXC")) }
    }

    func testTunnelInterfaceNames() {
        for name in ["utun0", "utun9", "utun10", "utun999"] { XCTAssertTrue(OpenConnectNetwork.isTunnelInterface(name, platform: .macOS), name) }
        for name in ["tun0", "tun99999"] { XCTAssertTrue(OpenConnectNetwork.isTunnelInterface(name, platform: .linux), name) }
        for name in ["utun", "utun00", "utun1000", "utun-1", "utun+1", "UTUN1", "utun1 ", "utun１", "tun0"] {
            XCTAssertFalse(OpenConnectNetwork.isTunnelInterface(name, platform: .macOS), name)
        }
        for name in ["tun", "tun01", "tun100000", "utun0", "tap0", "tun0\n"] {
            XCTAssertFalse(OpenConnectNetwork.isTunnelInterface(name, platform: .linux), name)
        }
    }

    // MARK: Addresses

    func testAddresses() {
        let good = [
            ("192.0.2.1", "192.0.2.1"), ("0.0.0.0", "0.0.0.0"), ("2001:DB8:0:0::53", "2001:db8::53"), ("::", "::"),
            ("::ffff:192.0.2.1", "::ffff:192.0.2.1"), ("1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0"), ("::2:3:4:5:6:7:8", "0:2:3:4:5:6:7:8"),
            ("2001:db8:0:0:0:0:0:1", "2001:db8::1"), ("fe80::1", "fe80::1"), ("1:2:3:4:5:6:192.0.2.1", "1:2:3:4:5:6:c000:201")
        ]
        for (text, canonical) in good { XCTAssertEqual(IPAddress(text)?.description, canonical, text) }
        let bad = [
            "", "1", "1.2.3", "1.2.3.4.5", "256.0.0.1", "01.2.3.4", "1.2.3.04", "1.2.3.4.", ".1.2.3.4", "0x1.2.3.4", "1.2.3.4/8",
            " 1.2.3.4", "1.2.3.4 ", "1::2::3", ":::", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "12345::", "fe80::1%en0", "[::1]",
            "::ffff:01.2.3.4", "1.2.3.4::", "::1.2.3", "g::", ":1::", "1::2:", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8",
            String(repeating: "1", count: 46)
        ]
        for text in bad { XCTAssertNil(IPAddress(text), text) }
        XCTAssertEqual(IPAddress("255.255.240.0")?.maskLength, 20)
        XCTAssertNil(IPAddress("255.0.255.0")?.maskLength)
        XCTAssertEqual(IPAddress("ffff:ffff:ffff:ffff::")?.maskLength, 64)
        XCTAssertEqual(IPAddress("10.11.12.13")?.masked(20).description, "10.11.0.0")
        XCTAssertEqual(IPAddress("2001:db8:ffff::5")?.masked(36).description, "2001:db8:f000::")
        XCTAssertEqual(IPAddress.mask(family: .ipv4, length: 0).description, "0.0.0.0")
        XCTAssertEqual(IPNetwork.halves(.ipv6).map(\.description), ["::/1", "8000::/1"])
        XCTAssertEqual(IPNetwork("10.0.0.0/8")?.description, "10.0.0.0/8")
        XCTAssertNil(IPNetwork("10.0.0.1/8"))
        XCTAssertNil(IPNetwork("10.0.0.0/08"))
        XCTAssertTrue(IPNetwork("10.0.0.0/8")!.contains(IPNetwork("10.11.0.0/24")!))
        XCTAssertFalse(IPNetwork("10.11.0.0/24")!.contains(IPNetwork("10.0.0.0/8")!))
    }

    func testDomains() {
        XCTAssertEqual(DomainName.normalize("Corp.Example.COM."), "corp.example.com")
        XCTAssertEqual(DomainName.normalize("_msdcs.example.com"), "_msdcs.example.com")
        for text in ["", ".", "a..b", "-x.example.com", "x-.example.com", "~corp", "a b", "ünicode.example", "*.example.com", "a\u{0}"] {
            XCTAssertNil(DomainName.normalize(text), text)
        }
    }

    // MARK: Changes and the record

    static let changes: [OpenConnectPlan.Change] = [
        .link(interface: "utun5", mtu: 1406),
        .address(interface: "utun5", IPAddress("10.11.0.2")!),
        .route(.init(IPNetwork("192.0.2.10/32")!, via: .gateway(gateway("198.51.100.1 en0")))),
        .route(.init(IPNetwork("::/1")!, via: .reject)),
        .route(.init(IPNetwork("0.0.0.0/1")!, via: .interface("utun5")))
    ]

    func testChangeTextIsStrict() {
        let refused = [
            "", "link", "link utun5 mtu 575", "link utun5 mtu 01406", "link en0 mtu 1406", "link utun5  mtu 1406", "link utun5 mtu 1406 ",
            "address utun5 0.0.0.0", "address utun5 010.11.0.2", "address utun5 2001:DB8::2", "route 10.0.0.1/8 interface utun5",
            "route 10.0.0.0/8 interface en0", "route 10.0.0.0/8 gateway 2001:db8::1 en0", "route 10.0.0.0/8 gateway 198.51.100.1",
            "route 10.0.0.0/8 gateway 198.51.100.1 en0;reboot", "route ::/1 reject now", "route ::/1 blackhole",
            "dns passtunnel-501-acme utun5 primary servers=- search=- match=-",
            "dns passtunnel-501-acme utun5 primary servers=10.0.0.53 search=-x.example.com match=-",
            "dns passtunnel-501-../x utun5 primary servers=10.0.0.53 search=- match=-",
            "dns passtunnel-0501-acme utun5 split servers=10.0.0.53 search=- match=-",
            "dns passtunnel-501-acme utun5 both servers=10.0.0.53 search=- match=-", "reboot"
        ]
        for text in refused { XCTAssertNil(OpenConnectPlan.Change(text: text), text) }
        XCTAssertNotNil(OpenConnectPlan.Change(text: "route 10.0.0.0/8 gateway link ppp0"))
        XCTAssertNotNil(
            OpenConnectPlan.Change(text: "dns passtunnel-501-my.profile_1 tun0 split servers=10.0.0.53,2001:db8::53 search=- match=example.com"))
    }

    func testRecordJournal() throws {
        var record = try XCTUnwrap(OpenConnectRecord(interface: "utun5"))
        let c = Self.changes
        try record.append(.begin(c[0]))
        XCTAssertThrowsError(try record.append(.begin(c[1])), "one change at a time")
        XCTAssertThrowsError(try record.append(.owned(c[1])), "the outcome of another change")
        XCTAssertThrowsError(try record.append(.status(.up)), "a status while a change is pending")
        try record.append(.owned(c[0]))
        try record.append(.begin(c[1]))
        try record.append(.existed(c[1]))
        try record.append(.begin(c[2]))
        try record.append(.owned(c[2]))
        try record.append(.begin(c[3]))
        try record.append(.failed(c[3]))
        try record.append(.begin(c[4]))
        // Killed during the last change: it may have been made, so it is reverted too, newest first.
        XCTAssertEqual(record.toRevert(sparing: []), [c[4], c[2], c[0]])
        XCTAssertEqual(record.applied, [c[0], c[1], c[2]])
        XCTAssertEqual(record.pending, c[4])
        XCTAssertThrowsError(try record.append(.reverted(c[0])), "another change is pending")
        try record.append(.reverted(c[4]))
        XCTAssertThrowsError(try record.append(.reverted(c[1])), "not the session's")
        XCTAssertThrowsError(try record.append(.reverted(c[4])), "already reverted")
        XCTAssertThrowsError(try record.append(.begin(c[0])), "already the session's")
        try record.append(.status(.failed("INTERNAL_IP4_DNS is not a list of IPv4 and IPv6 addresses")))
        XCTAssertThrowsError(try record.append(.status(.failed("two\nlines"))))
        XCTAssertThrowsError(try record.append(.status(.failed(""))))
        XCTAssertThrowsError(try record.append(.status(.failed(" padded"))))

        let text = try record.text()
        XCTAssertTrue(text.hasPrefix("passtunnel-network 1\ninterface utun5\n+ link utun5 mtu 1406\n= link utun5 mtu 1406\n"))
        let parsed = try XCTUnwrap(OpenConnectRecord.parse(text))
        XCTAssertEqual(parsed, record)
        XCTAssertEqual(parsed.toRevert(sparing: []), [c[2], c[0]])
        XCTAssertEqual(parsed.status, .failed("INTERNAL_IP4_DNS is not a list of IPv4 and IPv6 addresses"))

        let compact = try record.compacted()
        XCTAssertEqual(compact.toRevert(sparing: []), record.toRevert(sparing: []))
        XCTAssertEqual(compact.applied, record.applied)
        XCTAssertEqual(compact.status, record.status)
        XCTAssertEqual(OpenConnectRecord.parse(try compact.text()), compact)
    }

    /// A status, then a change begun and killed before its outcome (an attempt-reconnect): compacting keeps the
    /// status before the pending change, which a status cannot follow.
    func testCompactionWithAChangePendingAfterTheStatus() throws {
        let text = """
            passtunnel-network 1
            interface utun5
            + link utun5 mtu 1406
            = link utun5 mtu 1406
            + route 192.0.2.10/32 gateway 198.51.100.1 en0
            = route 192.0.2.10/32 gateway 198.51.100.1 en0
            status up
            - route 192.0.2.10/32 gateway 198.51.100.1 en0
            + route 192.0.2.10/32 gateway 203.0.113.1 en7

            """
        let record = try XCTUnwrap(OpenConnectRecord.parse(text))
        let compact = try record.compacted()
        XCTAssertEqual(
            try compact.text(),
            """
            passtunnel-network 1
            interface utun5
            + link utun5 mtu 1406
            = link utun5 mtu 1406
            status up
            + route 192.0.2.10/32 gateway 203.0.113.1 en7

            """)
        XCTAssertEqual(compact.pending, record.pending)
        XCTAssertEqual(compact.status, .up)
        XCTAssertEqual(compact.toRevert(sparing: []).map(\.text), ["route 192.0.2.10/32 gateway 203.0.113.1 en7", "link utun5 mtu 1406"])
        XCTAssertEqual(OpenConnectRecord.parse(try compact.text()), compact)
    }

    /// A change another live session holds (its own, pending or found there) is not reverted, pending or not;
    /// what is unique to this session is.
    func testRevertSparesWhatAnotherSessionHolds() throws {
        let reject = OpenConnectPlan.Change(text: "route ::/1 reject")!
        let server = OpenConnectPlan.Change(text: "route 192.0.2.10/32 gateway 198.51.100.1 en0")!
        let mine = OpenConnectPlan.Change(text: "route 0.0.0.0/1 interface utun5")!
        let link = OpenConnectPlan.Change(text: "link utun5 mtu 1406")!

        var a = OpenConnectRecord(interface: "utun5")!
        for change in [link, server, mine] {
            try a.append(.begin(change))
            try a.append(.owned(change))
        }
        try a.append(.begin(reject))  // killed: may or may not have been made, or have been there

        var b = OpenConnectRecord(interface: "utun6")!
        try b.append(.begin(reject))
        try b.append(.owned(reject))
        try b.append(.begin(server))
        try b.append(.existed(server))

        XCTAssertEqual(a.toRevert(sparing: []), [reject, mine, server, link])
        XCTAssertEqual(a.toRevert(sparing: [b]), [mine, link])
        var c = OpenConnectRecord(interface: "utun7")!
        try c.append(.begin(server))
        XCTAssertEqual(a.toRevert(sparing: [c]), [reject, mine, link], "pending in another session")
        var d = OpenConnectRecord(interface: "utun8")!
        try d.append(.begin(server))
        try d.append(.failed(server))
        try d.append(.begin(reject))
        try d.append(.owned(reject))
        try d.append(.reverted(reject))
        XCTAssertEqual(a.toRevert(sparing: [d]), [reject, mine, server, link], "failed or reverted there: not held")
    }

    func testCoverage() {
        func nets(_ list: [String]) -> [IPNetwork] { list.map { IPNetwork($0)! } }
        let v4 = IPNetwork("0.0.0.0/0")!
        let v6 = IPNetwork("::/0")!
        XCTAssertTrue(OpenConnectPlan.covers(nets(["0.0.0.0/1", "128.0.0.0/1"]), v4))
        XCTAssertTrue(OpenConnectPlan.covers(nets(["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1", "10.0.0.0/8"]), v4))
        XCTAssertTrue(OpenConnectPlan.covers(nets(["0.0.0.0/0"]), v4))
        XCTAssertFalse(OpenConnectPlan.covers(nets(["0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/4"]), v4))
        XCTAssertFalse(OpenConnectPlan.covers([], v4))
        XCTAssertTrue(OpenConnectPlan.covers(nets(["::/1", "8000::/2", "c000::/2"]), v6))
        XCTAssertFalse(OpenConnectPlan.covers(nets(["::/1", "8000::/2", "c000::/3", "e000::/4", "f000::/5"]), v6))
        // Every /16 but one of 1,024 /10s cannot cover; 1,024 hosts are quick.
        XCTAssertFalse(OpenConnectPlan.covers((0..<1024).map { IPNetwork("10.\($0 / 256).\($0 % 256).1/32")! }, v4))
        XCTAssertTrue(
            OpenConnectPlan.covers(
                (0..<1024).map { IPNetwork(address: IPAddress(bytes: [UInt8($0 >> 2), UInt8(($0 & 3) << 6), 0, 0])!, prefixLength: 10)! }, v4))
    }

    func testRecordParseIsStrict() throws {
        let good = "passtunnel-network 1\ninterface utun5\n+ link utun5 mtu 1406\n= link utun5 mtu 1406\nstatus up\n"
        XCTAssertNotNil(OpenConnectRecord.parse(good))
        let bad = [
            "", "passtunnel-network 1\n", "passtunnel-network 2\ninterface utun5\n", "passtunnel-network 1\ninterface en0\n",
            good.replacingOccurrences(of: "\n", with: "\r\n"), String(good.dropLast()), good + "\n", good + "status\n",
            good.replacingOccurrences(of: "= link", with: "~link"), good.replacingOccurrences(of: "+ link", with: "= link"),
            good + "- route ::/1 reject\n", good + "status failed \n", good + "status failed a\u{7}b\n", good + "\u{0}",
            "interface utun5\npasstunnel-network 1\n", good + "# comment\n"
        ]
        for text in bad { XCTAssertNil(OpenConnectRecord.parse(text), text) }
        XCTAssertNil(OpenConnectRecord.parse(good + String(repeating: "status up\n", count: OpenConnectRecord.maxBytes / 10)))
    }

    // MARK: attempt-reconnect and reconnect

    func network(_ extra: [String: String] = [:]) throws -> OpenConnectNetwork {
        var env = Self.minimal
        env["CISCO_SPLIT_EXC"] = "1"
        env["CISCO_SPLIT_EXC_0_ADDR"] = "192.168.0.0"
        env["CISCO_SPLIT_EXC_0_MASK"] = "255.255.0.0"
        env["CISCO_SPLIT_EXC_0_MASKLEN"] = "16"
        env["INTERNAL_IP4_DNS"] = "10.11.0.53"
        env.merge(extra) { $1 }
        return try parse(env)
    }

    static let policy = OpenConnectPolicy(uid: 501, profileID: "acme", setRoutes: true, setDNS: true)

    func setUp(_ n: OpenConnectNetwork, underlay: OpenConnectPlan.Underlay) throws -> OpenConnectRecord {
        var record = OpenConnectRecord(interface: n.interface)!
        for change in try OpenConnectPlan.connect(n, policy: Self.policy, underlay: underlay).changes {
            try record.append(.begin(change))
            try record.append(.owned(change))
        }
        try record.append(.status(.up))
        return record
    }

    func testRefreshFollowsTheGateway() throws {
        let n = try network()
        let wifi = OpenConnectPlan.Underlay(ipv4: Self.gateway("198.51.100.1 en0"))
        let record = try setUp(n, underlay: wifi)

        let same = OpenConnectPlan.refresh(n, policy: Self.policy, underlay: wifi, record: record)
        XCTAssertTrue(same.remove.isEmpty && same.add.isEmpty)

        let down = OpenConnectPlan.refresh(n, policy: Self.policy, underlay: .init(), record: record)
        XCTAssertTrue(down.remove.isEmpty && down.add.isEmpty, "no gateway right now: left as it is")

        let ethernet = OpenConnectPlan.Underlay(ipv4: Self.gateway("203.0.113.1 en7"))
        let moved = OpenConnectPlan.refresh(n, policy: Self.policy, underlay: ethernet, record: record)
        XCTAssertEqual(
            moved.remove.map(\.text),
            ["route 192.168.0.0/16 gateway 198.51.100.1 en0", "route 192.0.2.10/32 gateway 198.51.100.1 en0"])
        XCTAssertEqual(
            moved.add.map(\.text), ["route 192.0.2.10/32 gateway 203.0.113.1 en7", "route 192.168.0.0/16 gateway 203.0.113.1 en7"])

        // A route that was there already is not the session's: never removed, not added again.
        var shared = OpenConnectRecord(interface: "utun3")!
        for change in try OpenConnectPlan.connect(n, policy: Self.policy, underlay: wifi).changes {
            try shared.append(.begin(change))
            try shared.append(change.isThroughGateway ? .existed(change) : .owned(change))
        }
        let again = OpenConnectPlan.refresh(n, policy: Self.policy, underlay: wifi, record: shared)
        XCTAssertTrue(again.remove.isEmpty && again.add.isEmpty)
        XCTAssertEqual(OpenConnectPlan.refresh(n, policy: Self.policy, underlay: ethernet, record: shared).remove, [])
    }

    func testReconnectMatchesWhatConnectSetUp() throws {
        let n = try network()
        let wifi = OpenConnectPlan.Underlay(ipv4: Self.gateway("198.51.100.1 en0"))
        let record = try setUp(n, underlay: wifi)
        XCTAssertTrue(OpenConnectPlan.matches(n, policy: Self.policy, underlay: wifi, record: record))
        // Another gateway under the session changes only the routes around the tunnel.
        let ethernet = OpenConnectPlan.Underlay(ipv4: Self.gateway("203.0.113.1 en7"))
        XCTAssertTrue(OpenConnectPlan.matches(n, policy: Self.policy, underlay: ethernet, record: record))
        XCTAssertFalse(OpenConnectPlan.matches(try network(["INTERNAL_IP4_DNS": "10.11.0.54"]), policy: Self.policy, underlay: wifi, record: record))
        XCTAssertFalse(OpenConnectPlan.matches(try network(["INTERNAL_IP4_MTU": "1300"]), policy: Self.policy, underlay: wifi, record: record))
        let split = try network([
            "CISCO_SPLIT_INC": "1", "CISCO_SPLIT_INC_0_ADDR": "10.0.0.0", "CISCO_SPLIT_INC_0_MASK": "255.0.0.0",
            "CISCO_SPLIT_INC_0_MASKLEN": "8"
        ])
        XCTAssertFalse(OpenConnectPlan.matches(split, policy: Self.policy, underlay: wifi, record: record))
    }

    // MARK: Report lines

    func testFailureLineIsOneLine() {
        XCTAssertEqual(VPNHook.notSupportedLine, "passtunnel vpn-hook: setting up the network failed: not supported yet\n")
        for reason in [
            "a\nb", "a\r\npasstunnel vpn-hook: utun5 up: 10.0.0.2, 2 routes", "\u{0}", "", "   ", "é\u{2028}x", String(repeating: "x", count: 5000)
        ] {
            let line = VPNHook.failureLine(reason)
            XCTAssertTrue(line.hasPrefix(VPNHook.failurePrefix), reason)
            XCTAssertEqual(line.utf8.filter { $0 == 0x0A }.count, 1, reason)
            XCTAssertTrue(line.utf8.dropLast().allSatisfy { $0 >= 0x20 && $0 < 0x7F }, reason)
            XCTAssertLessThanOrEqual(line.utf8.count, VPNHook.failurePrefix.utf8.count + VPNHook.maxReasonBytes + 1)
            XCTAssertNil(VPNHook.Report.parse(line[...]), reason)
        }
    }

    func testReportParseIsStrict() {
        let good = "passtunnel vpn-hook: utun5 up: 10.11.0.2, 2 routes, full tunnel, IPv6 blocked, DNS 10.11.0.53, search example.com"
        XCTAssertNotNil(VPNHook.Report.parse(good[...]))
        let local = "passtunnel vpn-hook: utun5 up: 10.11.0.2, 1 route, 2 routes kept local, DNS 10.11.0.53, split DNS example.com"
        XCTAssertEqual(VPNHook.Report.parse(local[...])?.keptLocal, 2)
        for line in [
            local.replacingOccurrences(of: "2 routes kept", with: "0 routes kept"),
            local.replacingOccurrences(of: "2 routes kept", with: "1 routes kept"),
            local.replacingOccurrences(of: ", 2 routes kept local", with: ", 2 routes kept local, 2 routes kept local"),
            local.replacingOccurrences(of: "1 route, 2 routes kept local", with: "2 routes kept local, 1 route")
        ] {
            XCTAssertNil(VPNHook.Report.parse(line[...]), line)
        }
        let bad = [
            good.replacingOccurrences(of: "utun5", with: "en0"), good.replacingOccurrences(of: "2 routes", with: "2 route"),
            good.replacingOccurrences(of: "2 routes", with: "02 routes"), good.replacingOccurrences(of: "10.11.0.53", with: "10.11.0.053"),
            good.replacingOccurrences(of: "example.com", with: "Example.com"), good + ",", good + ", reboot", good + "\n\n",
            "passtunnel vpn-hook: utun5 up: 1 route, 10.11.0.2",
            "passtunnel vpn-hook: utun5 up: ", "x" + good,
            "passtunnel vpn-hook: utun5 up: 10.11.0.2, 1 route, IPv6 blocked, full tunnel"
        ]
        for line in bad {
            XCTAssertNil(VPNHook.Report.parse(line[...]), line)
        }
    }
}
