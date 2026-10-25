import XCTest
@testable import PassTunnelKit

/// `CIDR`, `NetworkClaims` and its overlap math, and what the OpenVPN config and a server's push say about
/// them. Addresses are examples only (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
final class NetworkClaimsTests: XCTestCase {
    func cidr(_ text: String) -> CIDR {
        guard let value = CIDR(text) else {
            XCTFail("not a network: \(text)")
            return CIDR("0.0.0.0/0")!
        }
        return value
    }

    // MARK: parsing and printing

    func testIPv4Networks() {
        XCTAssertEqual(cidr("10.0.0.0/8").description, "10.0.0.0/8")
        XCTAssertEqual(cidr("0.0.0.0/0").description, "0.0.0.0/0")
        XCTAssertEqual(cidr("255.255.255.255/32").description, "255.255.255.255/32")
        XCTAssertEqual(cidr("192.0.2.77").description, "192.0.2.77/32", "a bare address is a host route")
        XCTAssertTrue(cidr("192.0.2.77").isHost)
        // The host bits are cleared, as the routing table keeps it.
        XCTAssertEqual(cidr("10.1.2.3/8").description, "10.0.0.0/8")
        XCTAssertEqual(cidr("192.0.2.200/25").description, "192.0.2.128/25")
        XCTAssertEqual(cidr("10.1.2.3/8"), cidr("10.200.0.0/8"))
        XCTAssertEqual(cidr("10.0.0.0/8").address, "10.0.0.0")
    }

    func testIPv6Networks() {
        XCTAssertEqual(cidr("2001:db8::/32").description, "2001:db8::/32")
        XCTAssertEqual(cidr("2001:0DB8:0000:0000:0000:0000:0000:0001").description, "2001:db8::1/128")
        XCTAssertEqual(cidr("::").description, "::/128")
        XCTAssertEqual(cidr("::/0").description, "::/0")
        XCTAssertEqual(cidr("::1").description, "::1/128")
        XCTAssertEqual(cidr("8000::/1").description, "8000::/1")
        XCTAssertEqual(cidr("2001:db8:1234:5678:9abc:def0:1234:5678/64").description, "2001:db8:1234:5678::/64")
        XCTAssertEqual(cidr("1:2:3:4:5:6:7:8").description, "1:2:3:4:5:6:7:8/128")
        XCTAssertEqual(cidr("1:2:3:4:5:6:7::").description, "1:2:3:4:5:6:7:0/128", "one zero group is not compressed")
        XCTAssertEqual(cidr("::ffff:192.0.2.1").description, "::ffff:c000:201/128", "an embedded IPv4 address")
        XCTAssertEqual(cidr("64:ff9b::192.0.2.33").description, "64:ff9b::c000:221/128")
        // RFC 5952: the longest run of zero groups, the first of equals.
        XCTAssertEqual(cidr("2001:db8:0:0:1:0:0:1").description, "2001:db8::1:0:0:1/128")
        XCTAssertEqual(cidr("2001:0:0:1:0:0:0:1").description, "2001:0:0:1::1/128")
        XCTAssertEqual(cidr("2001:db8:0:1:1:1:1:1").description, "2001:db8:0:1:1:1:1:1/128")
    }

    func testRefusedText() {
        let refused = ["", "/", "/8", "10.0.0.0/", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/+8", "10.0.0.0/08", "10.0.0.0/8/9",
                       "10.0.0.0/ 8", "256.0.0.0/8", "10.0.0/8", "10.0.0.0.0/8", "10.0.0.01/8", "010.0.0.0/8", " 10.0.0.0/8",
                       "10.0.0.0/8 ", "10.0.0.-1/8", "1e1.0.0.0/8", "vpn.example.com", "example.com/24", "10.0.0.0:80",
                       "10.0.0.1%en0", "０.0.0.0/8", "10.0.0.0/1000",
                       "2001:db8::/129", "2001:db8::/", ":::", "1::2::3", "12345::", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7",
                       "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "fe80::1%en0", "[::1]", "::g", "2001:db8::/-1",
                       ":1::", "1::2:", ":1:2:3:4:5:6:7", "::1.2.3", "1.2.3.4::", "::1.2.3.4:5", "1:1.2.3.4::1",
                       "::ffff:192.0.2.256", "2001:db8::1/64/64"]
        for text in refused { XCTAssertNil(CIDR(text), "“\(text)”") }
        XCTAssertNil(CIDR.host("10.0.0.0/8"), "a host is an address alone")
        XCTAssertEqual(CIDR.host("10.0.0.1")?.description, "10.0.0.1/32")
    }

    func testNetmasks() {
        XCTAssertEqual(CIDR(address: "10.0.0.0", netmask: "255.0.0.0")?.description, "10.0.0.0/8")
        XCTAssertEqual(CIDR(address: "10.1.2.3", netmask: "255.0.0.0")?.description, "10.0.0.0/8")
        XCTAssertEqual(CIDR(address: "0.0.0.0", netmask: "0.0.0.0")?.description, "0.0.0.0/0")
        XCTAssertEqual(CIDR(address: "192.0.2.1", netmask: "255.255.255.255")?.description, "192.0.2.1/32")
        XCTAssertEqual(CIDR(address: "192.0.2.0", netmask: "255.255.255.254")?.description, "192.0.2.0/31")
        XCTAssertEqual(CIDR(address: "128.0.0.0", netmask: "128.0.0.0")?.description, "128.0.0.0/1")
        for mask in ["255.0.255.0", "0.255.255.255", "255.255.255.253", "255.255.255", "255.255.255.256", "ffff::", "24", ""] {
            XCTAssertNil(CIDR(address: "10.0.0.0", netmask: mask), mask)
        }
        XCTAssertNil(CIDR(address: "vpn_gateway", netmask: "255.0.0.0"))
        XCTAssertNil(CIDR(address: "2001:db8::", netmask: "255.0.0.0"))
    }

    func testOrderingAndCoding() throws {
        let sorted = ["2001:db8::/32", "10.0.0.0/16", "10.0.0.0/8", "::/0", "192.0.2.0/24", "0.0.0.0/0"].map(cidr).sorted()
        XCTAssertEqual(sorted.map(\.description), ["0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/16", "192.0.2.0/24", "::/0", "2001:db8::/32"])

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(["a": cidr("10.1.0.0/16"), "b": cidr("2001:db8::1")])
        XCTAssertEqual(String(decoding: data, as: UTF8.self), #"{"a":"10.1.0.0\/16","b":"2001:db8::1\/128"}"#)
        let back = try JSONDecoder().decode([String: CIDR].self, from: data)
        XCTAssertEqual(back["a"], cidr("10.1.0.0/16"))
        XCTAssertThrowsError(try JSONDecoder().decode([String: CIDR].self, from: Data(#"{"a":"nope"}"#.utf8)))
    }

    // MARK: containment

    func testContainmentBothWays() {
        let a = cidr("10.0.0.0/8"), b = cidr("10.9.0.0/16"), c = cidr("10.9.1.5/32"), d = cidr("11.0.0.0/8")
        XCTAssertTrue(a.contains(b) && a.contains(c) && b.contains(c) && a.contains(a))
        XCTAssertFalse(b.contains(a) || c.contains(a) || c.contains(b))
        XCTAssertTrue(a.overlaps(b) && b.overlaps(a) && a.overlaps(c) && c.overlaps(a) && a.overlaps(a))
        XCTAssertFalse(a.overlaps(d) || d.overlaps(a))
        XCTAssertEqual(a.intersection(b), b)
        XCTAssertEqual(b.intersection(a), b)
        XCTAssertEqual(a.intersection(a), a)
        XCTAssertNil(a.intersection(d))
    }

    func testBoundaries() {
        // Adjacent networks do not overlap, the first and last address of one are inside it.
        XCTAssertFalse(cidr("10.0.0.0/9").overlaps(cidr("10.128.0.0/9")))
        XCTAssertFalse(cidr("192.0.2.0/24").overlaps(cidr("192.0.3.0/24")))
        XCTAssertTrue(cidr("192.0.2.0/24").contains(cidr("192.0.2.0")))
        XCTAssertTrue(cidr("192.0.2.0/24").contains(cidr("192.0.2.255")))
        XCTAssertFalse(cidr("192.0.2.0/24").contains(cidr("192.0.3.0")))
        XCTAssertFalse(cidr("192.0.2.0/24").contains(cidr("192.0.1.255")))
        XCTAssertTrue(cidr("192.0.2.0/31").contains(cidr("192.0.2.1")))
        XCTAssertFalse(cidr("192.0.2.0/31").contains(cidr("192.0.2.2")))
        XCTAssertTrue(cidr("255.255.255.255").overlaps(cidr("255.255.255.255/32")))
        XCTAssertFalse(cidr("255.255.255.254").overlaps(cidr("255.255.255.255")))
        XCTAssertTrue(cidr("128.0.0.0/1").contains(cidr("255.255.255.255")))
        XCTAssertFalse(cidr("128.0.0.0/1").contains(cidr("127.255.255.255")))
        XCTAssertFalse(cidr("0.0.0.0/1").overlaps(cidr("128.0.0.0/1")))
    }

    func testDefaultRoutes() {
        let all = cidr("0.0.0.0/0")
        for text in ["10.0.0.0/8", "0.0.0.0/1", "128.0.0.0/1", "255.255.255.255", "0.0.0.0", "0.0.0.0/0"] {
            XCTAssertTrue(all.contains(cidr(text)), text)
            XCTAssertTrue(all.overlaps(cidr(text)), text)
            XCTAssertTrue(cidr(text).overlaps(all), text)
        }
        XCTAssertFalse(all.contains(cidr("::/0")), "the families are apart")
        XCTAssertFalse(all.overlaps(cidr("::1")))
        XCTAssertTrue(cidr("::/0").contains(cidr("2001:db8::1")))
        XCTAssertTrue(cidr("::/0").contains(cidr("::")))
        XCTAssertFalse(cidr("::/0").overlaps(cidr("10.0.0.1")))
        XCTAssertFalse(cidr("::ffff:10.0.0.1").overlaps(cidr("10.0.0.1")), "a mapped address is not the IPv4 one")
    }

    func testHostRoutes() {
        XCTAssertTrue(cidr("192.0.2.1").overlaps(cidr("192.0.2.1")))
        XCTAssertFalse(cidr("192.0.2.1").overlaps(cidr("192.0.2.2")))
        XCTAssertTrue(cidr("2001:db8::1").overlaps(cidr("2001:db8::1")))
        XCTAssertFalse(cidr("2001:db8::1").overlaps(cidr("2001:db8::2")))
        XCTAssertTrue(cidr("2001:db8::/32").contains(cidr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")))
        XCTAssertFalse(cidr("2001:db8::/32").contains(cidr("2001:db9::")))
        XCTAssertFalse(cidr("2001:db8::/32").contains(cidr("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff")))
    }

    func testIPv6PrefixesAroundTheHalfwayMark() {
        // The address is held as two 64-bit words: prefixes either side of 64, and exactly 64.
        XCTAssertTrue(cidr("2001:db8:0:1::/64").contains(cidr("2001:db8:0:1::5")))
        XCTAssertTrue(cidr("2001:db8:0:1::/64").contains(cidr("2001:db8:0:1:ffff:ffff:ffff:ffff")))
        XCTAssertFalse(cidr("2001:db8:0:1::/64").contains(cidr("2001:db8:0:2::")))
        XCTAssertTrue(cidr("2001:db8:0:1::/63").contains(cidr("2001:db8:0:0::/64")), "a /63 starts at an even /64")
        XCTAssertEqual(cidr("2001:db8:0:1::/63").description, "2001:db8::/63")
        XCTAssertFalse(cidr("2001:db8:0:2::/63").contains(cidr("2001:db8:0:1::/64")))
        XCTAssertTrue(cidr("2001:db8:0:0::/63").contains(cidr("2001:db8:0:1::/64")))
        XCTAssertFalse(cidr("2001:db8:0:0::/63").contains(cidr("2001:db8:0:2::/64")))
        XCTAssertTrue(cidr("2001:db8:0:1::/65").overlaps(cidr("2001:db8:0:1::/64")))
        XCTAssertTrue(cidr("2001:db8:0:1:8000::/65").overlaps(cidr("2001:db8:0:1:ffff::1")))
        XCTAssertFalse(cidr("2001:db8:0:1:8000::/65").overlaps(cidr("2001:db8:0:1:7fff:ffff:ffff:ffff")))
        XCTAssertFalse(cidr("2001:db8:0:1::/65").overlaps(cidr("2001:db8:0:1:8000::/65")))
        XCTAssertTrue(cidr("2001:db8::/127").contains(cidr("2001:db8::1")))
        XCTAssertFalse(cidr("2001:db8::/127").contains(cidr("2001:db8::2")))
        XCTAssertEqual(cidr("2001:db8::ffff/112").description, "2001:db8::/112")
        XCTAssertEqual(cidr("2001:db8:0:0:ffff::1/64").description, "2001:db8::/64")
        XCTAssertEqual(cidr("2001:db8:0:0:ffff::1/65").description, "2001:db8:0:0:8000::/65")
        XCTAssertEqual(cidr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/1").description, "8000::/1")
    }

    /// The same answers from a reference that compares address bits one by one, on random networks of
    /// both families (a fixed seed, so a failure repeats).
    func testRandomNetworksAgainstABitwiseReference() {
        var seed: UInt64 = 0x9E37_79B9_7F4A_7C15
        func next() -> UInt64 {
            seed &+= 0x9E37_79B9_7F4A_7C15
            var z = seed
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
        func bits(_ words: [UInt16]) -> [Bool] { words.flatMap { w in (0..<16).map { w >> (15 - $0) & 1 == 1 } } }
        // Few distinct values, so networks often share leading bits.
        func network(v6: Bool) -> (text: String, bits: [Bool], prefix: Int) {
            if v6 {
                let words = (0..<8).map { _ in UInt16([0x2001, 0x0db8, 0, 0xffff, 0x8000][Int(next() % 5)]) }
                let prefix = Int(next() % 129)
                return (words.map { String($0, radix: 16) }.joined(separator: ":") + "/\(prefix)", bits(words), prefix)
            }
            let octets = (0..<4).map { _ in UInt8([0, 10, 128, 192, 255][Int(next() % 5)]) }
            let prefix = Int(next() % 33)
            return (octets.map(String.init).joined(separator: ".") + "/\(prefix)", bits(octets.map { UInt16($0) << 8 })
                .enumerated().filter { $0.offset % 16 < 8 }.map(\.element), prefix)
        }
        for i in 0..<4000 {
            let v6 = i % 2 == 0
            let a = network(v6: v6), b = network(v6: v6)
            let shared = min(a.prefix, b.prefix)
            let expected = a.bits.prefix(shared) == b.bits.prefix(shared)
            let x = cidr(a.text), y = cidr(b.text)
            XCTAssertEqual(x.overlaps(y), expected, "\(a.text) \(b.text)")
            XCTAssertEqual(y.overlaps(x), expected, "\(b.text) \(a.text)")
            XCTAssertEqual(x.contains(y), expected && a.prefix <= b.prefix, "\(a.text) contains \(b.text)")
            XCTAssertEqual(x.intersection(y) != nil, expected)
            XCTAssertEqual(CIDR(x.description), x, "round trip of \(a.text)")
        }
    }

    // MARK: domains

    func testDomainNormalization() {
        XCTAssertEqual(NetworkClaims.normalizedDomain("example.com"), "example.com")
        XCTAssertEqual(NetworkClaims.normalizedDomain("Example.COM."), "example.com")
        XCTAssertEqual(NetworkClaims.normalizedDomain("  corp.example.com  "), "corp.example.com")
        XCTAssertEqual(NetworkClaims.normalizedDomain("~example.com"), "example.com", "a routing domain mark")
        XCTAssertEqual(NetworkClaims.normalizedDomain(".example.com"), "example.com")
        XCTAssertEqual(NetworkClaims.normalizedDomain("*.example.com"), "example.com")
        XCTAssertEqual(NetworkClaims.normalizedDomain("_ldap._tcp.example.com"), "_ldap._tcp.example.com")
        XCTAssertEqual(NetworkClaims.normalizedDomain("a-b.example.com"), "a-b.example.com")
        XCTAssertEqual(NetworkClaims.normalizedDomain("intranet"), "intranet")
        XCTAssertEqual(NetworkClaims.normalizedDomain(String(repeating: "a", count: 63) + ".com"), String(repeating: "a", count: 63) + ".com")
        let tooLong = Array(repeating: String(repeating: "a", count: 62), count: 4).joined(separator: ".")   // 251 + ".com"
        XCTAssertNotNil(NetworkClaims.normalizedDomain(tooLong))
        XCTAssertNil(NetworkClaims.normalizedDomain(tooLong + ".example"))
        for bad in ["", ".", "..", "~", "~.", "*", "example..com", "-example.com", "example-.com", "exa mple.com", "example.com/x",
                    "exam;ple.com", "example.com\n", "ex\u{7}ample.com", "bücher.example", String(repeating: "a", count: 64) + ".com",
                    "x..."] {
            XCTAssertNil(NetworkClaims.normalizedDomain(bad), "“\(bad)”")
        }
    }

    func testDomainsOverlapOnLabelBoundariesOnly() {
        XCTAssertTrue(NetworkClaims.domainsOverlap("example.com", "example.com"))
        XCTAssertTrue(NetworkClaims.domainsOverlap("corp.example.com", "example.com"))
        XCTAssertTrue(NetworkClaims.domainsOverlap("example.com", "corp.example.com"))
        XCTAssertTrue(NetworkClaims.domainsOverlap("a.b.example.com", "b.example.com"))
        XCTAssertTrue(NetworkClaims.domainsOverlap("example.com", "com"))
        XCTAssertFalse(NetworkClaims.domainsOverlap("notexample.com", "example.com"))
        XCTAssertFalse(NetworkClaims.domainsOverlap("example.com", "notexample.com"))
        XCTAssertFalse(NetworkClaims.domainsOverlap("example.com", "example.org"))
        XCTAssertFalse(NetworkClaims.domainsOverlap("example.com", "xample.com"))
        XCTAssertFalse(NetworkClaims.domainsOverlap("ample.com", "example.com"))
        XCTAssertFalse(NetworkClaims.domainsOverlap("example.com.evil.net", "example.com"))
        XCTAssertFalse(NetworkClaims.domainsOverlap("a.example.com", "b.example.com"), "siblings")
    }

    // MARK: claims

    func testRoutesAreSortedAndWithoutRepeats() {
        var claims = NetworkClaims()
        for text in ["192.0.2.0/24", "10.0.0.0/8", "10.9.0.0/16", "10.1.2.3/8", "2001:db8::/32", "192.0.2.0/24"] {
            claims.addRoute(cidr(text))
        }
        XCTAssertEqual(claims.routes.map(\.description), ["10.0.0.0/8", "10.9.0.0/16", "192.0.2.0/24", "2001:db8::/32"])
        XCTAssertEqual(claims.ipv4Routes.count, 3)
        XCTAssertEqual(claims.ipv6Routes.count, 1)
        XCTAssertFalse(claims.isEmpty)
        XCTAssertTrue(NetworkClaims().isEmpty)
    }

    func testWholeAddressSpaceIsAFullTunnel() {
        var v4 = NetworkClaims()
        v4.addRoute(cidr("0.0.0.0/0"))
        XCTAssertTrue(v4.fullTunnel)
        XCTAssertFalse(v4.fullTunnelIPv6)
        XCTAssertTrue(v4.routes.isEmpty)

        // The two halves OpenVPN adds for redirect-gateway def1, in either order, even with others between.
        for order in [["0.0.0.0/1", "128.0.0.0/1"], ["128.0.0.0/1", "10.0.0.0/8", "0.0.0.0/1"]] {
            var halves = NetworkClaims()
            order.forEach { halves.addRoute(cidr($0)) }
            XCTAssertTrue(halves.fullTunnel, "\(order)")
            XCTAssertEqual(halves.routes.map(\.description).filter { $0.hasSuffix("/1") }, [])
        }
        var one = NetworkClaims()
        one.addRoute(cidr("0.0.0.0/1"))
        XCTAssertFalse(one.fullTunnel, "half of the space is not all of it")
        XCTAssertEqual(one.routes.count, 1)

        var v6 = NetworkClaims()
        v6.addRoute(cidr("::/0"))
        XCTAssertTrue(v6.fullTunnelIPv6)
        XCTAssertFalse(v6.fullTunnel)
        var v6halves = NetworkClaims()
        v6halves.addRoute(cidr("::/1"))
        v6halves.addRoute(cidr("8000::/1"))
        XCTAssertTrue(v6halves.fullTunnelIPv6)
        var global = NetworkClaims()
        global.addRoute(cidr("2000::/3"))
        XCTAssertTrue(global.fullTunnelIPv6, "all global unicast addresses")
        var narrower = NetworkClaims()
        narrower.addRoute(cidr("2000::/4"))
        XCTAssertFalse(narrower.fullTunnelIPv6)
    }

    func testDNSServersAndNames() {
        var claims = NetworkClaims()
        for server in ["10.8.0.1", "10.8.0.1", "2001:db8::53", "0.0.0.0", "::", "dns.example.com", "10.8.0.0/24", "10.8.0.2:53", ""] {
            claims.addDNSServer(server)
        }
        XCTAssertEqual(claims.dnsServers, ["10.8.0.1", "2001:db8::53"])
        claims.addDNSDomain("Example.com.")
        claims.addDNSDomain("example.com")
        claims.addDNSDomain("bad name")
        claims.addSearchDomain("corp.example.com")
        claims.addSearchDomain("example.com")
        XCTAssertEqual(claims.dnsDomains, ["example.com"])
        XCTAssertEqual(claims.searchDomains, ["corp.example.com", "example.com"])
        XCTAssertEqual(claims.domains, ["corp.example.com", "example.com"])
    }

    func testLimits() {
        var claims = NetworkClaims()
        for i in 0..<(NetworkClaims.maxRoutes + 50) { claims.addRoute(cidr("10.\(i / 256).\(i % 256).0/24")) }
        XCTAssertEqual(claims.routes.count, NetworkClaims.maxRoutes)
        for i in 0..<100 {
            claims.addDNSServer("10.8.0.\(i + 1)")
            claims.addDNSDomain("d\(i).example.com")
            claims.addSearchDomain("s\(i).example.com")
        }
        XCTAssertEqual(claims.dnsServers.count, NetworkClaims.maxDNSServers)
        XCTAssertEqual(claims.dnsDomains.count, NetworkClaims.maxDomains)
        XCTAssertEqual(claims.searchDomains.count, NetworkClaims.maxDomains)
    }

    func testMerge() {
        var a = NetworkClaims(routes: [cidr("10.0.0.0/8")], dnsServers: ["10.8.0.1"], dnsDomains: ["example.com"])
        let b = NetworkClaims(routes: [cidr("10.0.0.0/8"), cidr("192.0.2.0/24")], fullTunnelIPv6: true, dnsServers: ["10.8.0.2"],
                              searchDomains: ["corp.example.com"])
        a.merge(b)
        XCTAssertEqual(a.routes.map(\.description), ["10.0.0.0/8", "192.0.2.0/24"])
        XCTAssertEqual(a.dnsServers, ["10.8.0.1", "10.8.0.2"])
        XCTAssertEqual(a.dnsDomains, ["example.com"])
        XCTAssertEqual(a.searchDomains, ["corp.example.com"])
        XCTAssertTrue(a.fullTunnelIPv6)
        XCTAssertFalse(a.fullTunnel)
    }

    // MARK: overlaps

    func claims(_ routes: [String] = [], full: Bool = false, full6: Bool = false, dns: [String] = [], split: [String] = [],
                search: [String] = []) -> NetworkClaims {
        NetworkClaims(routes: routes.map(cidr), fullTunnel: full, fullTunnelIPv6: full6, dnsServers: dns, dnsDomains: split,
                      searchDomains: search)
    }

    func testTheDesignExample() {
        // Work and Lab both send 10.0.0.0/8 and look up example.com; 10.9.0.0/16 is Lab's alone.
        let work = claims(["10.0.0.0/8", "192.0.2.0/24"], dns: ["10.8.0.1"], split: ["example.com"])
        let lab = claims(["10.0.0.0/8", "198.51.100.0/24"], dns: ["10.9.0.1"], split: ["example.com"])
        let found = NetworkClaims.overlaps(lab, work)
        XCTAssertEqual(found, [.route(cidr("10.0.0.0/8"), cidr("10.0.0.0/8")), .domain("example.com", "example.com")])
        let summary = OverlapSummary(found)
        XCTAssertEqual(summary.routes.map(\.description), ["10.0.0.0/8"])
        XCTAssertEqual(summary.domains, ["example.com"])
        XCTAssertFalse(summary.firstTakesAllTraffic || summary.secondTakesAllTraffic)
        XCTAssertFalse(summary.isEmpty)
        XCTAssertEqual(lab.overlaps(with: work), found)
    }

    func testRouteContainmentCountsBothWays() {
        let wide = claims(["10.0.0.0/8"]), narrow = claims(["10.9.0.0/16"]), apart = claims(["172.16.0.0/12"])
        XCTAssertEqual(NetworkClaims.overlaps(wide, narrow), [.route(cidr("10.0.0.0/8"), cidr("10.9.0.0/16"))])
        XCTAssertEqual(NetworkClaims.overlaps(narrow, wide), [.route(cidr("10.9.0.0/16"), cidr("10.0.0.0/8"))])
        XCTAssertEqual(OverlapSummary(NetworkClaims.overlaps(wide, narrow)).routes.map(\.description), ["10.9.0.0/16"],
                       "what both send is the narrower network")
        XCTAssertEqual(NetworkClaims.overlaps(wide, apart), [])
        XCTAssertEqual(NetworkClaims.overlaps(narrow, apart), [])
        // Host routes, and networks of the other family.
        XCTAssertEqual(NetworkClaims.overlaps(claims(["10.9.1.5/32"]), narrow).count, 1)
        XCTAssertEqual(NetworkClaims.overlaps(claims(["10.9.1.5/32"]), claims(["10.9.1.6/32"])), [])
        XCTAssertEqual(NetworkClaims.overlaps(claims(["10.0.0.0/8"]), claims(["2001:db8::/32"])), [])
        XCTAssertEqual(NetworkClaims.overlaps(claims(["2001:db8::/32"]), claims(["2001:db8:1::/48"])).count, 1)
        XCTAssertEqual(NetworkClaims.overlaps(claims(["2001:db8::/32"]), claims(["2001:db9::/32"])), [])
    }

    func testEveryPairIsReported() {
        let a = claims(["10.0.0.0/8", "10.1.0.0/16"]), b = claims(["10.1.2.0/24", "10.0.0.0/8"])
        let found = NetworkClaims.overlaps(a, b)
        XCTAssertEqual(found.count, 4)
        XCTAssertEqual(Set(OverlapSummary(found).routes.map(\.description)), ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"])
    }

    func testNothingClaimedNothingOverlaps() {
        XCTAssertEqual(NetworkClaims.overlaps(NetworkClaims(), NetworkClaims()), [])
        XCTAssertEqual(NetworkClaims.overlaps(NetworkClaims(), claims(["10.0.0.0/8"], full: true, dns: ["10.8.0.1"])), [])
        XCTAssertEqual(NetworkClaims.overlaps(claims(["10.0.0.0/8"]), NetworkClaims()), [])
        XCTAssertTrue(OverlapSummary([]).isEmpty)
    }

    func testFullTunnelMeetsAnything() {
        let full = claims(full: true)
        // Routes, names, a DNS server, another full tunnel: all collide.
        for other in [claims(["10.0.0.0/8"]), claims(split: ["example.com"]), claims(search: ["example.com"]),
                      claims(dns: ["10.8.0.1"]), claims(full: true)] {
            let found = NetworkClaims.overlaps(full, other)
            XCTAssertEqual(found, [.allTraffic(first: true, second: other.fullTunnel)], "\(other)")
            XCTAssertEqual(NetworkClaims.overlaps(other, full), [.allTraffic(first: other.fullTunnel, second: true)])
        }
        // Not with nothing, and an IPv4 tunnel is not met by IPv6 routes only.
        XCTAssertEqual(NetworkClaims.overlaps(full, NetworkClaims()), [])
        XCTAssertEqual(NetworkClaims.overlaps(full, claims(["2001:db8::/32"])), [])
        XCTAssertEqual(NetworkClaims.overlaps(claims(full6: true), claims(["10.0.0.0/8"])), [])
        XCTAssertEqual(NetworkClaims.overlaps(claims(full6: true), claims(["2001:db8::/32"])).count, 1)
        XCTAssertEqual(NetworkClaims.overlaps(claims(full: true), claims(full6: true)), [])
        XCTAssertEqual(NetworkClaims.overlaps(claims(full: true, full6: true), claims(full6: true)).count, 1)
        // A full tunnel next to specific claims reports the specifics too.
        let both = NetworkClaims.overlaps(claims(["10.0.0.0/8"], full: true), claims(["10.9.0.0/16"]))
        XCTAssertEqual(both, [.allTraffic(first: true, second: false), .route(cidr("10.0.0.0/8"), cidr("10.9.0.0/16"))])
        let summary = OverlapSummary(both)
        XCTAssertTrue(summary.firstTakesAllTraffic)
        XCTAssertFalse(summary.secondTakesAllTraffic)
    }

    func testDomainOverlaps() {
        let work = claims(split: ["example.com"], search: ["corp.work.example"])
        XCTAssertEqual(NetworkClaims.overlaps(work, claims(split: ["Example.com."])), [.domain("example.com", "example.com")])
        XCTAssertEqual(NetworkClaims.overlaps(work, claims(split: ["lab.example.com"])), [.domain("example.com", "lab.example.com")])
        XCTAssertEqual(NetworkClaims.overlaps(claims(split: ["lab.example.com"]), work), [.domain("lab.example.com", "example.com")])
        XCTAssertEqual(NetworkClaims.overlaps(work, claims(search: ["example.com"])), [.domain("example.com", "example.com")],
                       "search domains count as names too")
        XCTAssertEqual(NetworkClaims.overlaps(work, claims(split: ["notexample.com"])), [])
        XCTAssertEqual(NetworkClaims.overlaps(work, claims(split: ["example.org", "other.example"])), [])
        XCTAssertEqual(NetworkClaims.overlaps(work, claims(split: ["work.example"])).count, 1, "corp.work.example is inside work.example")
        // The same DNS server on its own is not a collision.
        XCTAssertEqual(NetworkClaims.overlaps(claims(dns: ["10.8.0.1"]), claims(dns: ["10.8.0.1"])), [])
        XCTAssertEqual(OverlapSummary(NetworkClaims.overlaps(work, claims(split: ["lab.example.com"]))).domains, ["lab.example.com"])
    }

    func testOverlapsAreSymmetricInSize() {
        let items = [claims(["10.0.0.0/8", "192.0.2.0/24"], split: ["example.com"]), claims(["10.9.0.0/16"], full: true),
                     claims(["2001:db8::/32"], full6: true, search: ["a.example.com"]), claims(dns: ["10.8.0.1"]), NetworkClaims()]
        for a in items {
            for b in items {
                XCTAssertEqual(NetworkClaims.overlaps(a, b).count, NetworkClaims.overlaps(b, a).count)
                XCTAssertEqual(OverlapSummary(NetworkClaims.overlaps(a, b)).routes, OverlapSummary(NetworkClaims.overlaps(b, a)).routes)
            }
        }
    }

    func testAtMostMaxOverlapsAreReported() {
        let many = NetworkClaims(routes: (0..<NetworkClaims.maxRoutes).map { cidr("10.\($0 / 256).\($0 % 256).0/24") })
        let all = NetworkClaims(routes: [cidr("10.0.0.0/8")])
        XCTAssertGreaterThan(NetworkClaims.maxRoutes, NetworkClaims.maxOverlaps)
        XCTAssertEqual(NetworkClaims.overlaps(all, many).count, NetworkClaims.maxOverlaps)
        XCTAssertEqual(NetworkClaims.overlaps(many, many).count, NetworkClaims.maxOverlaps)
    }
}

/// What a profile's own lines and its server's push make of `NetworkClaims`.
final class OVPNNetworkClaimsTests: XCTestCase {
    func claims(_ config: String, pushed: [String] = []) -> NetworkClaims {
        OVPNAnalyzer.networkClaims(config, pushed: pushed)
    }

    func routes(_ claims: NetworkClaims) -> [String] { claims.routes.map(\.description) }

    func testRoutesOfTheConfig() {
        let c = claims("""
        client
        remote vpn.example.com 1194
        route 10.0.0.0 255.0.0.0
        route 192.0.2.0 255.255.255.0 vpn_gateway 5
        route 198.51.100.7
        route 203.0.113.0 255.255.255.0 default
        route-ipv6 2001:db8::/32
        route-ipv6 2001:db8:1::/48 2001:db8:ffff::1 100
        """)
        XCTAssertEqual(routes(c), ["10.0.0.0/8", "192.0.2.0/24", "198.51.100.7/32", "203.0.113.0/24", "2001:db8::/32", "2001:db8:1::/48"])
        XCTAssertFalse(c.fullTunnel)
    }

    func testRoutesThatDoNotUseTheTunnelOrCannotBeRead() {
        let c = claims("""
        route 203.0.113.10 255.255.255.255 net_gateway
        route 203.0.113.11 255.255.255.255 remote_host
        route-ipv6 2001:db8:5::/48 net_gateway
        route vpn_gateway
        route net_gateway 255.0.0.0
        route remote_host
        route intranet.example.com
        route 10.0.0.0 255.0.255.0
        route 10.0.0.0 24
        route
        route-ipv6 2001:db8::1
        route-ipv6 intranet.example.com/64
        route-ipv6
        """)
        XCTAssertTrue(c.isEmpty, "\(c)")
    }

    func testDefaultRoutesAreFullTunnels() {
        XCTAssertTrue(claims("route 0.0.0.0 0.0.0.0").fullTunnel)
        XCTAssertTrue(claims("route 0.0.0.0 128.0.0.0\nroute 128.0.0.0 128.0.0.0").fullTunnel)
        XCTAssertTrue(claims("route-ipv6 ::/0").fullTunnelIPv6)
        XCTAssertTrue(claims("route-ipv6 ::/1\nroute-ipv6 8000::/1").fullTunnelIPv6)
    }

    func testRedirectGateway() {
        XCTAssertTrue(claims("redirect-gateway").fullTunnel)
        XCTAssertTrue(claims("redirect-gateway def1").fullTunnel)
        XCTAssertTrue(claims("redirect-gateway local def1 bypass-dhcp").fullTunnel)
        XCTAssertFalse(claims("redirect-gateway def1").fullTunnelIPv6)
        let both = claims("redirect-gateway ipv6 def1")
        XCTAssertTrue(both.fullTunnel && both.fullTunnelIPv6)
        let only6 = claims("redirect-gateway ipv6 !ipv4")
        XCTAssertFalse(only6.fullTunnel)
        XCTAssertTrue(only6.fullTunnelIPv6)
        XCTAssertTrue(claims("--redirect-gateway DEF1").fullTunnel, "the directive as OpenVPN reads it")
        XCTAssertTrue(claims("", pushed: ["redirect-gateway def1"]).fullTunnel)
        // redirect-private does not take everything.
        XCTAssertTrue(claims("redirect-private def1").isEmpty)
    }

    func testDNSOptions() {
        let c = claims("""
        dhcp-option DNS 10.8.0.1
        dhcp-option DNS6 2001:db8::53
        dhcp-option DOMAIN corp.example.com
        dhcp-option DOMAIN-SEARCH lab.example.com
        dhcp-option ADAPTER-DOMAIN-SUFFIX Example.ORG.
        dhcp-option DOMAIN-ROUTE example.com
        dhcp-option WINS 10.8.0.9
        dhcp-option DNS dns.example.com
        dhcp-option DISABLE-NBT
        dhcp-option PROXY_HTTP 10.0.0.9 3128
        """)
        XCTAssertEqual(c.dnsServers, ["10.8.0.1", "2001:db8::53"])
        XCTAssertEqual(c.searchDomains, ["corp.example.com", "lab.example.com", "example.org"])
        XCTAssertEqual(c.dnsDomains, ["example.com"])
    }

    func testOpenVPN27DNSOptions() {
        let c = claims("""
        dns server 1 address 10.8.0.1 10.8.0.2:53
        dns server 1 address [2001:db8::1]:53
        dns server 1 resolve-domains example.com corp.example.com
        dns server 1 dnssec yes
        dns server 1 transport DoH
        dns search-domains search.example.com
        dns domain nonsense
        dns
        dns server
        dns server 1 address
        """)
        XCTAssertEqual(c.dnsServers, ["10.8.0.1", "10.8.0.2", "2001:db8::1"])
        XCTAssertEqual(c.dnsDomains, ["example.com", "corp.example.com"])
        XCTAssertEqual(c.searchDomains, ["search.example.com"])
        XCTAssertEqual(OVPNAnalyzer.dnsAddress("2001:db8::1"), "2001:db8::1", "an IPv6 address has colons of its own")
        XCTAssertEqual(OVPNAnalyzer.dnsAddress("[::1]"), "::1")
        XCTAssertEqual(OVPNAnalyzer.dnsAddress("1.2.3.4:53"), "1.2.3.4")
    }

    func testPushedOptionsAddToTheConfigsOwn() {
        let c = claims("route 10.0.0.0 255.0.0.0\ndhcp-option DNS 10.8.0.1",
                       pushed: ["route 172.16.0.0 255.240.0.0", "route-ipv6 2001:db8::/32", "dhcp-option DNS 10.8.0.2",
                                "dhcp-option DOMAIN-ROUTE example.com", "dhcp-option DOMAIN corp.example.com",
                                "dns server 2 resolve-domains lab.example.com"])
        XCTAssertEqual(routes(c), ["10.0.0.0/8", "172.16.0.0/12", "2001:db8::/32"])
        XCTAssertEqual(c.dnsServers, ["10.8.0.1", "10.8.0.2"])
        XCTAssertEqual(c.dnsDomains, ["example.com", "lab.example.com"])
        XCTAssertEqual(c.searchDomains, ["corp.example.com"])
    }

    func testOnlyNetworkOptionsAreRead() {
        let c = claims("", pushed: ["ifconfig 10.8.0.6 255.255.255.0", "route-gateway 10.8.0.1", "auth-token SESS_ID_x", "ping 10",
                                    "block-outside-dns", "Route 10.0.0.0 255.0.0.0", "route-delay 5", "topology subnet", "", "   "])
        XCTAssertTrue(c.isEmpty)
        let tabs = claims("", pushed: ["route\t10.0.0.0\t255.0.0.0"])
        XCTAssertEqual(routes(tabs), ["10.0.0.0/8"])
        XCTAssertEqual(OVPNAnalyzer.maxPushedOptions, 1024)
        let flood = (0..<2000).map { "route 10.\($0 / 256).\($0 % 256).0 255.255.255.0" }
        XCTAssertEqual(claims("", pushed: flood).routes.count, 1024)
    }

    func testRouteNopullRefusesWhatIsPushed() {
        let config = "route-nopull\nroute 10.0.0.0 255.0.0.0\ndhcp-option DNS 10.8.0.5"
        let c = claims(config, pushed: ["route 172.16.0.0 255.240.0.0", "redirect-gateway def1", "dhcp-option DNS 10.8.0.1",
                                        "dns server 1 address 10.8.0.2"])
        XCTAssertEqual(routes(c), ["10.0.0.0/8"], "the config's own routes still count")
        XCTAssertEqual(c.dnsServers, ["10.8.0.5"])
        XCTAssertFalse(c.fullTunnel)
    }

    func testPullFilters() {
        let config = """
        pull-filter ignore "route 172."
        pull-filter ignore "redirect-gateway"
        pull-filter reject "dhcp-option DOMAIN"
        pull-filter accept "dhcp-option"
        """
        let c = claims(config, pushed: ["route 172.16.0.0 255.240.0.0", "route 172.20.0.0 255.255.0.0", "route 10.0.0.0 255.0.0.0",
                                        "redirect-gateway def1", "dhcp-option DNS 10.8.0.1", "dhcp-option DOMAIN corp.example.com",
                                        "dhcp-option DOMAIN-ROUTE example.com"])
        XCTAssertEqual(routes(c), ["10.0.0.0/8"])
        XCTAssertFalse(c.fullTunnel)
        XCTAssertEqual(c.dnsServers, ["10.8.0.1"])
        XCTAssertEqual(c.searchDomains, [], "rejected by the filter before the accept")
        XCTAssertEqual(c.dnsDomains, [], "DOMAIN-ROUTE starts with the rejected pattern too")
        // The first filter that matches decides, so an accept in front keeps what a later ignore drops.
        let accepted = claims("pull-filter accept \"route 172.16.\"\npull-filter ignore \"route\"",
                              pushed: ["route 172.16.0.0 255.240.0.0", "route 10.0.0.0 255.0.0.0"])
        XCTAssertEqual(routes(accepted), ["172.16.0.0/12"])
        // A pattern is a prefix of the whole option: it is case sensitive and not found inside it.
        XCTAssertEqual(routes(claims("pull-filter ignore \"ROUTE\"\npull-filter ignore \"10.0.0.0\"", pushed: ["route 10.0.0.0 255.0.0.0"])),
                       ["10.0.0.0/8"])
        XCTAssertEqual(claims("pull-filter ignore \"dns\"", pushed: ["dns server 1 address 10.8.0.2"]).dnsServers, [])
        XCTAssertEqual(claims("pull-filter bogus \"route\"\npull-filter ignore", pushed: ["route 10.0.0.0 255.0.0.0"]).routes.count, 1)
    }

    func testRouteNoexecAddsNoRoutes() {
        let c = claims("route-noexec\nroute 10.0.0.0 255.0.0.0\nredirect-gateway def1\ndhcp-option DNS 10.8.0.1",
                       pushed: ["route 172.16.0.0 255.240.0.0", "redirect-gateway def1", "route-ipv6 2001:db8::/32"])
        XCTAssertTrue(c.routes.isEmpty)
        XCTAssertFalse(c.fullTunnel)
        XCTAssertEqual(c.dnsServers, ["10.8.0.1"], "the DNS still is set")
    }

    func testTheConfigIsReadAsOpenVPNReadsIt() {
        let c = claims("""
        # route 10.0.0.0 255.0.0.0
        ; route 10.1.0.0 255.255.0.0
        <ca>
        route 10.2.0.0 255.255.0.0
        </ca>
        <connection>
        remote vpn.example.com
        route 10.3.0.0 255.255.0.0
        </connection>
        setenv opt route 10.4.0.0 255.255.0.0
        setenv route 10.5.0.0 255.255.0.0
        route "10.6.0.0" '255.255.0.0'
        --route 10.7.0.0 255.255.0.0
        ROUTE 10.8.0.0 255.255.0.0
        """)
        XCTAssertEqual(routes(c), ["10.3.0.0/16", "10.4.0.0/16", "10.6.0.0/16", "10.7.0.0/16", "10.8.0.0/16"])
        XCTAssertTrue(claims("").isEmpty)
        XCTAssertTrue(claims("\u{0}\u{1}garbage \"unterminated").isEmpty)
    }
}
