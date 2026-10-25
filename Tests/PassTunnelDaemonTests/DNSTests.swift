import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelDaemon
@testable import PassTunnelShared

// MARK: - Values

final class DNSSettingsTests: XCTestCase {
    func testAddresses() throws {
        let good = [("192.0.2.53", "192.0.2.53"), ("2001:DB8:0:0::53", "2001:db8::53"), ("198.51.100.1", "198.51.100.1"),
                    ("::ffff:192.0.2.1", "::ffff:192.0.2.1"), ("2001:db8::1:0:0:1", "2001:db8::1:0:0:1")]
        for (text, canonical) in good { XCTAssertEqual(try DNSSettings.address(text), canonical, text) }
        let bad = ["", "0.0.0.0", "::", "1.2.3", "256.1.1.1", "192.0.2.1;reboot", "192.0.2.1 198.51.100.1",
                   "fe80::1%eth0", "192.0.2.1:53", "[2001:db8::1]", "-192.0.2.1", "192.0.2.1\n", "192.0.2.1\u{0}x",
                   "vpn.example.com", "$(reboot)", String(repeating: "1", count: 100), " 192.0.2.1"]
        for text in bad {
            XCTAssertThrowsError(try DNSSettings.address(text), text) {
                XCTAssertEqual($0 as? DNSFailure, .invalid("DNS server", text))
            }
        }
    }

    func testDomains() throws {
        XCTAssertEqual(try DNSSettings.domain("Corp.Example.COM."), "corp.example.com")
        XCTAssertEqual(try DNSSettings.domain("_msdcs.example.com"), "_msdcs.example.com")
        XCTAssertEqual(try DNSSettings.domain("lan"), "lan")
        let label = String(repeating: "a", count: 63)
        XCTAssertEqual(try DNSSettings.domain(label + ".example.com"), label + ".example.com")
        let long = Array(repeating: label, count: 4).joined(separator: ".")      // 255 bytes
        let bad = ["", ".", "..", "a..b", "-x.example.com", "x-.example.com", "~corp.example.com", "corp example.com",
                   "exa$mple.com", "example.com/x", "ex\nample.com", "ünicode.example", label + "a.example.com", long,
                   "*.example.com", "example.com;reboot", "-", "\u{0}"]
        for text in bad {
            XCTAssertThrowsError(try DNSSettings.domain(text), text) {
                XCTAssertEqual($0 as? DNSFailure, .invalid("DNS domain", text))
            }
        }
    }

    func testInterfaces() throws {
        for name in ["tun0", "ppp0", "tap1", "ovpn-acme", "tun.1", "x"] { XCTAssertEqual(try DNSSettings.interface(name), name) }
        for name in ["", "-tun0", ".tun0", "tun0 ", "tun/0", "eth0:1", "tun0;x", String(repeating: "t", count: 16), "tün0"] {
            XCTAssertThrowsError(try DNSSettings.interface(name), name)
        }
    }

    func testCountsAndRepeats() throws {
        let settings = try DNSSettings(servers: ["192.0.2.1", "192.0.2.1", "2001:db8::1", "2001:DB8::1"],
                                       searchDomains: ["Example.com", "example.com."], fullTunnel: true)
        XCTAssertEqual(settings.servers, ["192.0.2.1", "2001:db8::1"])
        XCTAssertEqual(settings.searchDomains, ["example.com"])
        let nine = (1...9).map { "192.0.2.\($0)" }
        XCTAssertThrowsError(try DNSSettings(servers: nine, fullTunnel: true)) {
            XCTAssertEqual($0 as? DNSFailure, .tooMany("DNS servers", 8))
        }
        let domains = (1...17).map { "d\($0).example.com" }
        XCTAssertThrowsError(try DNSSettings(servers: ["192.0.2.1"], searchDomains: domains, fullTunnel: true))
        XCTAssertThrowsError(try DNSSettings(servers: ["192.0.2.1"], routingDomains: domains, fullTunnel: false))
    }

    func testFailuresQuoteOnlyPrintableText() {
        let text = String(describing: DNSFailure.invalid("DNS domain", "a\nb\u{1b}" + String(repeating: "x", count: 50)))
        XCTAssertEqual(text, "invalid DNS domain “a?b?" + String(repeating: "x", count: 28) + "”")
    }
}

// MARK: - OpenVPN's environment

final class OpenVPNDNSTests: XCTestCase {
    func settings(_ environment: [String: String]) throws -> DNSSettings? {
        try OpenVPNDNS.settings(environment: environment)
    }

    /// OpenVPN 2.7's `--dns-updown` environment (also 2.6's for pushed `dns` options).
    func testDNSOptions() throws {
        let split = try XCTUnwrap(try settings([
            "dev": "tun0", "script_type": "dns-up",
            "dns_search_domain_1": "corp.example.com", "dns_search_domain_2": "eu.example.com",
            "dns_server_1_address_1": "192.0.2.53", "dns_server_1_address_2": "2001:db8::53",
            "dns_server_1_port_2": "53", "dns_server_1_resolve_domain_1": "corp.example.com",
            "dns_server_1_resolve_domain_2": "example.net", "dns_server_1_dnssec": "optional",
        ]))
        XCTAssertEqual(split, try DNSSettings(servers: ["192.0.2.53", "2001:db8::53"],
                                              searchDomains: ["corp.example.com", "eu.example.com"],
                                              routingDomains: ["corp.example.com", "example.net"], fullTunnel: false))

        // dhcp-options turned into --dns by 2.7: no resolve domains, so every name goes through the tunnel;
        // a DOMAIN that was not pushed leaves a gap before the DOMAIN-SEARCH entries.
        let converted = try XCTUnwrap(try settings(["dns_server_1_address_1": "192.0.2.53", "dns_search_domain_3": "b.example.com",
                                                    "dns_search_domain_2": "a.example.com"]))
        XCTAssertEqual(converted.searchDomains, ["a.example.com", "b.example.com"])
        XCTAssertTrue(converted.fullTunnel)
    }

    func testFirstServerPlainDNSReaches() throws {
        let env = ["dns_server_1_address_1": "192.0.2.1", "dns_server_1_transport": "DoT",
                   "dns_server_2_address_1": "192.0.2.2", "dns_server_2_port_1": "853",
                   "dns_server_3_address_1": "192.0.2.3", "dns_server_3_transport": "plain", "dns_server_3_port_1": "53",
                   "dns_server_4_address_1": "192.0.2.4"]
        XCTAssertEqual(try settings(env)?.servers, ["192.0.2.3"])
        XCTAssertThrowsError(try settings(["dns_server_1_address_1": "192.0.2.1", "dns_server_1_transport": "DoH"])) {
            XCTAssertEqual($0 as? DNSFailure, .noUsableServer)
        }
    }

    /// OpenVPN 2.6's `--route-up` environment: `dhcp-option`s, in the order pushed.
    func testDHCPOptions() throws {
        let env = ["dev": "tun0", "script_type": "route-up",
                   "foreign_option_1": "dhcp-option DOMAIN corp.example.com",
                   "foreign_option_2": "dhcp-option DNS 192.0.2.53",
                   "foreign_option_3": "dhcp-option WINS 192.0.2.99",
                   "foreign_option_10": "dhcp-option DNS6 2001:db8::53",
                   "foreign_option_4": "dhcp-option DOMAIN-SEARCH example.net",
                   "foreign_option_5": "dhcp-option ADAPTER-DOMAIN-SUFFIX lan",
                   "foreign_option_6": "dhcp-option NTP 192.0.2.123 192.0.2.124"]
        XCTAssertEqual(try settings(env), try DNSSettings(servers: ["192.0.2.53", "2001:db8::53"],
                                                          searchDomains: ["corp.example.com", "example.net", "lan"],
                                                          fullTunnel: true))
        XCTAssertNil(try settings(["foreign_option_1": "dhcp-option DOMAIN corp.example.com", "dev": "tun0"]),
                     "no server: nothing to set up")
        XCTAssertNil(try settings(["dev": "tun0", "script_type": "route-up"]))
    }

    /// 2.6 with pushed `dns` options also copies them into foreign options: the `dns_*` ones win.
    func testDNSOptionsWinOverDHCPOptions() throws {
        let env = ["foreign_option_1": "dhcp-option DNS 192.0.2.1", "dns_server_1_address_1": "192.0.2.2"]
        XCTAssertEqual(try settings(env)?.servers, ["192.0.2.2"])
    }

    func testHostileValues() {
        let cases: [[String: String]] = [
            ["foreign_option_1": "dhcp-option DNS 192.0.2.1 198.51.100.1"],
            ["foreign_option_1": "dhcp-option DNS 192.0.2.1;reboot"],
            ["foreign_option_1": "dhcp-option DNS"],
            ["foreign_option_1": "dhcp-option DNS  192.0.2.1"],
            ["foreign_option_1": "dhcp-option DNS 192.0.2.1", "foreign_option_2": "dhcp-option DOMAIN -evil"],
            ["foreign_option_1": "dhcp-option DNS 192.0.2.1", "foreign_option_2": "dhcp-option DOMAIN a b"],
            ["foreign_option_1": "dhcp-option DNS 192.0.2.1", "foreign_option_2": "dhcp-option DOMAIN ~."],
            ["foreign_option_999": "dhcp-option DNS 192.0.2.1"],
            ["foreign_option_01": "dhcp-option DNS 192.0.2.1"],
            ["foreign_option_x": "dhcp-option DNS 192.0.2.1"],
            ["dns_server_1_address_1": "$(reboot)"],
            ["dns_server_1_address_1": "192.0.2.1\nnameserver 198.51.100.1"],
            ["dns_server_x_address_1": "192.0.2.1"],
            ["dns_server_1_address_65": "192.0.2.1"],
            ["dns_server_1_address_1": "192.0.2.1", "dns_search_domain_1": "corp.example.com\nnameserver 198.51.100.1"],
            ["dns_server_1_address_1": "192.0.2.1", "dns_server_1_resolve_domain_1": "--help"],
            (1...9).reduce(into: [:]) { env, i in env["dns_server_1_address_\(i)"] = "192.0.2.\(i)" },
        ]
        for env in cases {
            XCTAssertThrowsError(try settings(env), "\(env)")
        }
    }
}

// MARK: - Backends, against a fake root

/// A fake root below `base` owned by the test's user: /etc/resolv.conf, systemd-resolved's run
/// directory, and `resolvectl` and `resolvconf` as scripts that record how they were called.
class DNSTestCase: DaemonTestCase {
    var root: String { base + "/root" }
    var resolvConf: String { root + "/etc/resolv.conf" }
    var calls: String { base + "/calls" }
    var resolvectl: String { root + "/usr/bin/resolvectl" }
    var resolvconf: String { root + "/usr/sbin/resolvconf" }
    let indexes = IndexBox()
    var renameFails = false
    static let original = "# from the network\nnameserver 192.0.2.1\nsearch lan\noptions edns0\n"

    override func setUpWithError() throws {
        try super.setUpWithError()
        for dir in ["/etc", "/run/systemd/resolve", "/usr/bin", "/usr/sbin"] {
            try FileManager.default.createDirectory(atPath: root + dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o755])
        }
        try Self.original.write(toFile: resolvConf, atomically: false, encoding: .utf8)
        chmod(resolvConf, 0o644)
        try "nameserver 127.0.0.53\n".write(toFile: root + "/run/systemd/resolve/stub-resolv.conf", atomically: false, encoding: .utf8)
        indexes.set(["tun0": 7, "tun1": 8])
    }

    var system: DNSSystem {
        var system = DNSSystem()
        system.resolvConf = resolvConf
        system.resolvedTargets = [root + "/run/systemd/resolve/", root + "/usr/lib/systemd/resolv.conf"]
        system.resolvectl = [resolvectl]
        system.resolvconf = [resolvconf, root + "/sbin/resolvconf"]
        system.owner = me
        system.base = base
        let indexes = self.indexes
        system.interfaceIndex = { indexes.get($0) }
        if renameFails {
            system.renameFile = { _, _ in EBUSY }
        }
        return system
    }

    var applier: DNSApplier { DNSApplier(system: system, runRoot: runRoot) }

    /// A fake tool: logs `<name> <arguments>` (and its standard input) to `calls`; fails when
    /// `<base>/fail-<first argument>` exists.
    func makeFakeTool(_ path: String, name: String) throws {
        let script = """
        #!/bin/sh
        echo "\(name) $*" >> '\(calls)'
        if [ "$1" = "-a" ]; then cat >> '\(calls)'; fi
        if [ -e '\(base)/fail-'"$1" ]; then echo "Failed to set DNS: Link tun0 not managed" ; exit 1; fi
        exit 0

        """
        try script.write(toFile: path, atomically: false, encoding: .utf8)
        chmod(path, 0o755)
    }

    func useResolved() throws {
        unlink(resolvConf)
        XCTAssertEqual(symlink("../run/systemd/resolve/stub-resolv.conf", resolvConf), 0)
        try makeFakeTool(resolvectl, name: "resolvectl")
    }

    func session(_ id: String = "acme") throws -> SessionDirectory {
        try HelperCore(runRoot: runRoot).makeRunDir(profileID: id, uid: me)
    }

    func recorded(_ session: SessionDirectory) -> String? {
        try? String(contentsOfFile: session.path + "/" + DNSRecord.fileName, encoding: .utf8)
    }

    var callLog: String { (try? String(contentsOfFile: calls, encoding: .utf8)) ?? "" }
    var resolvConfText: String { (try? String(contentsOfFile: resolvConf, encoding: .utf8)) ?? "<none>" }

    static let full = try! DNSSettings(servers: ["192.0.2.53", "2001:db8::53"], searchDomains: ["corp.example.com"],
                                       fullTunnel: true)
    static let split = try! DNSSettings(servers: ["192.0.2.53"], searchDomains: ["corp.example.com"],
                                        routingDomains: ["example.net"], fullTunnel: false)
}

final class IndexBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: [String: UInt32] = [:]

    func set(_ new: [String: UInt32]) { lock.lock(); value = new; lock.unlock() }
    func get(_ name: String) -> UInt32? { lock.lock(); defer { lock.unlock() }; return value[name] }
}

final class DNSFileBackendTests: DNSTestCase {
    static let applied = """
    # PassTunnel tun0 begin: DNS of the VPN, removed when it disconnects
    nameserver 192.0.2.53
    nameserver 2001:db8::53
    search corp.example.com
    # PassTunnel tun0 end
    # from the network
    #PassTunnel tun0# nameserver 192.0.2.1
    #PassTunnel tun0# search lan
    options edns0

    """

    func testApplyAndRevert() throws {
        let session = try session()
        var before = stat()
        XCTAssertEqual(lstat(resolvConf, &before), 0)
        XCTAssertEqual(try applier.apply(Self.full, interface: "tun0", in: session), .file)
        XCTAssertEqual(resolvConfText, Self.applied)
        var after = stat()
        XCTAssertEqual(lstat(resolvConf, &after), 0)
        XCTAssertNotEqual(after.st_ino, before.st_ino, "replaced by rename, not rewritten")
        XCTAssertEqual(after.st_mode & 0o7777, 0o644)
        XCTAssertFalse(exists(resolvConf + ".passtunnel"))
        let digest = HelperCore.sha256Hex(Data(Self.applied.utf8))
        XCTAssertEqual(recorded(session), "passtunnel-dns 1\nfile\ntun0\n7\n\(digest)\nprevious\n")
        XCTAssertEqual(try String(contentsOfFile: session.path + "/dns.resolv.conf", encoding: .utf8), Self.original)
        var st = stat()
        XCTAssertEqual(lstat(session.path + "/dns", &st), 0)
        XCTAssertEqual(st.st_mode & 0o777, 0o600)

        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (/etc/resolv.conf)")
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertNil(recorded(session))
        XCTAssertFalse(exists(session.path + "/dns.resolv.conf"))
        XCTAssertNil(applier.revert(in: session), "nothing left to revert")
    }

    /// Without domains of its own the tunnel leaves the search list alone.
    func testSearchLinesStayWithoutDomains() throws {
        let session = try session()
        try applier.apply(try DNSSettings(servers: ["192.0.2.53"], fullTunnel: true), interface: "tun0", in: session)
        XCTAssertTrue(resolvConfText.contains("\nsearch lan\n"), resolvConfText)
        XCTAssertTrue(resolvConfText.contains("#PassTunnel tun0# nameserver 192.0.2.1\n"), resolvConfText)
        applier.revert(in: session)
        XCTAssertEqual(resolvConfText, Self.original)
    }

    /// Changed by someone else meanwhile: only the block and the marks go.
    func testRevertKeepsOtherChanges() throws {
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        try (resolvConfText + "options ndots:2\n").write(toFile: resolvConf, atomically: false, encoding: .utf8)
        applier.revert(in: session)
        XCTAssertEqual(resolvConfText, Self.original + "options ndots:2\n")
    }

    /// Replaced by someone else: theirs now, left alone.
    func testRevertLeavesAReplacedFileAlone() throws {
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        try "nameserver 198.51.100.1\n".write(toFile: resolvConf, atomically: true, encoding: .utf8)
        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (/etc/resolv.conf)")
        XCTAssertEqual(resolvConfText, "nameserver 198.51.100.1\n")
        XCTAssertNil(recorded(session))
    }

    func testNoResolvConfBefore() throws {
        unlink(resolvConf)
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        XCTAssertTrue(resolvConfText.hasPrefix("# PassTunnel tun0 begin"), resolvConfText)
        XCTAssertTrue(recorded(session)?.hasSuffix("\nnone\n") == true)
        applier.revert(in: session)
        XCTAssertFalse(exists(resolvConf))
    }

    /// A container bind-mounts its resolv.conf: rename fails with EBUSY, so it is rewritten in place.
    func testMountPointIsRewrittenInPlace() throws {
        renameFails = true
        let session = try session()
        var before = stat()
        XCTAssertEqual(lstat(resolvConf, &before), 0)
        try applier.apply(Self.full, interface: "tun0", in: session)
        XCTAssertEqual(resolvConfText, Self.applied)
        var after = stat()
        XCTAssertEqual(lstat(resolvConf, &after), 0)
        XCTAssertEqual(after.st_ino, before.st_ino)
        XCTAssertFalse(exists(resolvConf + ".passtunnel"))
        applier.revert(in: session)
        XCTAssertEqual(resolvConfText, Self.original)
    }

    func testTwoTunnels() throws {
        let one = try session("one"), two = try session("two")
        try applier.apply(Self.full, interface: "tun0", in: one)
        try applier.apply(try DNSSettings(servers: ["198.51.100.53"], fullTunnel: true), interface: "tun1", in: two)
        XCTAssertTrue(resolvConfText.hasPrefix("# PassTunnel tun1 begin"), resolvConfText)
        applier.revert(in: one)
        XCTAssertTrue(resolvConfText.hasPrefix("# PassTunnel tun1 begin"), resolvConfText)
        XCTAssertFalse(resolvConfText.contains("tun0"), resolvConfText)
        applier.revert(in: two)
        XCTAssertEqual(resolvConfText, Self.original)
    }

    /// A block of the same interface whose record went missing (a crash) is not carried on.
    func testStaleBlockIsReplaced() throws {
        let lost = try session("lost")
        try applier.apply(Self.full, interface: "tun0", in: lost)
        DNSRecord.remove(in: lost)
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        XCTAssertEqual(resolvConfText, Self.applied)
        applier.revert(in: session)
        XCTAssertEqual(resolvConfText, Self.original)
    }

    /// Applying again (2.6 runs `--route-up` again after a route delay) first reverts the earlier set-up.
    func testApplyingAgainRevertsFirst() throws {
        let session = try session()
        try applier.apply(try DNSSettings(servers: ["198.51.100.53"], fullTunnel: true), interface: "tun0", in: session)
        try applier.apply(Self.full, interface: "tun0", in: session)
        XCTAssertEqual(resolvConfText, Self.applied)
        applier.revert(in: session)
        XCTAssertEqual(resolvConfText, Self.original)
    }

    func testRefusals() throws {
        let session = try session()
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun9", in: session)) {
            XCTAssertEqual($0 as? DNSFailure, .noInterface("tun9"))
        }
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "-tun0", in: session))
        // A link that is not systemd-resolved's, with no resolvconf: never followed.
        unlink(resolvConf)
        try "nameserver 192.0.2.1\n".write(toFile: base + "/elsewhere", atomically: false, encoding: .utf8)
        XCTAssertEqual(symlink(base + "/elsewhere", resolvConf), 0)
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun0", in: session)) {
            XCTAssertEqual($0 as? DNSFailure, .unexpectedLink(resolvConf, base + "/elsewhere"))
        }
        XCTAssertEqual(try String(contentsOfFile: base + "/elsewhere", encoding: .utf8), "nameserver 192.0.2.1\n")
        XCTAssertNil(recorded(session))
        unlink(resolvConf)
        try FileManager.default.createDirectory(atPath: resolvConf, withIntermediateDirectories: false)
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun0", in: session)) {
            XCTAssertEqual($0 as? DNSFailure, .notARegularFile(resolvConf))
        }
        XCTAssertNil(recorded(session))
    }

    func testTextTransforms() {
        let previous = Array("nameserver 192.0.2.1\n nameserver x\nnameservers\nsearch\tlan\ndomain lan\n#nameserver y".utf8)
        let applied = ResolvConf.apply(Self.full, interface: "tun0", to: previous)
        let lines = String(decoding: applied, as: UTF8.self).components(separatedBy: "\n")
        XCTAssertEqual(Array(lines.suffix(6)), ["#PassTunnel tun0# nameserver 192.0.2.1", " nameserver x", "nameservers",
                                                "#PassTunnel tun0# search\tlan", "#PassTunnel tun0# domain lan", "#nameserver y"])
        XCTAssertEqual(ResolvConf.strip(applied, interface: "tun0"), previous)
        XCTAssertNil(ResolvConf.strip(previous, interface: "tun0"))
        XCTAssertNil(ResolvConf.strip(applied, interface: "tun00"), "another interface's block is not touched")
        // Bytes that are not UTF-8 survive.
        let binary: [UInt8] = [0x23, 0xFF, 0xFE, 0x0A] + Array("nameserver 192.0.2.1".utf8)
        XCTAssertEqual(ResolvConf.strip(ResolvConf.apply(Self.full, interface: "tun0", to: binary), interface: "tun0"), binary)
    }

    func testRecordParsing() {
        let digest = String(repeating: "a", count: 64)
        XCTAssertEqual(DNSRecord(text: "passtunnel-dns 1\nfile\ntun0\n7\n\(digest)\nprevious\n"),
                       DNSRecord(backend: .file, interface: "tun0", index: 7, written: digest, hadPrevious: true))
        XCTAssertEqual(DNSRecord(text: "passtunnel-dns 1\nresolved\ntun0\n7\n-\nnone\n"),
                       DNSRecord(backend: .resolved, interface: "tun0", index: 7))
        for bad in ["", "passtunnel-dns 2\nresolved\ntun0\n7\n-\nnone\n", "passtunnel-dns 1\nother\ntun0\n7\n-\nnone\n",
                    "passtunnel-dns 1\nresolved\n-tun0\n7\n-\nnone\n", "passtunnel-dns 1\nresolved\ntun0\n07\n-\nnone\n",
                    "passtunnel-dns 1\nresolved\ntun0\n7\n\(digest)\nnone\n", "passtunnel-dns 1\nfile\ntun0\n7\n-\nnone\n",
                    "passtunnel-dns 1\nfile\ntun0\n7\n\(digest.uppercased())\nnone\n", "passtunnel-dns 1\nresolved\ntun0\n7\n-\nnone\nx\n",
                    "passtunnel-dns 1\nresolved\ntun0\n7\n-\nnone"] {
            XCTAssertNil(DNSRecord(text: bad), bad)
        }
    }

    /// An unreadable record is removed, and changes nothing.
    func testBadRecordIsDropped() throws {
        let session = try session()
        try "passtunnel-dns 1\nfile\n../../etc\n".write(toFile: session.path + "/dns", atomically: false, encoding: .utf8)
        XCTAssertTrue(applier.revert(in: session)?.hasPrefix("removed an unreadable DNS record") == true)
        XCTAssertNil(recorded(session))
        XCTAssertEqual(resolvConfText, Self.original)
    }
}

final class DNSResolvedBackendTests: DNSTestCase {
    func testFullTunnel() throws {
        try useResolved()
        let session = try session()
        XCTAssertEqual(try applier.apply(Self.full, interface: "tun0", in: session), .resolved)
        XCTAssertEqual(callLog, """
        resolvectl dns tun0 192.0.2.53 2001:db8::53
        resolvectl domain tun0 corp.example.com ~.
        resolvectl default-route tun0 true

        """)
        XCTAssertEqual(recorded(session), "passtunnel-dns 1\nresolved\ntun0\n7\n-\nnone\n")
        XCTAssertEqual(try String(contentsOfFile: root + "/run/systemd/resolve/stub-resolv.conf", encoding: .utf8),
                       "nameserver 127.0.0.53\n", "the link is never written through")
        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (systemd-resolved)")
        XCTAssertTrue(callLog.hasSuffix("resolvectl revert tun0\n"), callLog)
    }

    func testSplitTunnel() throws {
        try useResolved()
        try applier.apply(Self.split, interface: "tun0", in: try session())
        XCTAssertEqual(callLog, """
        resolvectl dns tun0 192.0.2.53
        resolvectl domain tun0 corp.example.com ~example.net
        resolvectl default-route tun0 false

        """)
    }

    /// Its link gone, systemd-resolved has forgotten it; a new link of that name is someone else's.
    func testRevertOnlyTheSameLink() throws {
        try useResolved()
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        indexes.set([:])
        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (systemd-resolved)")
        indexes.set(["tun1": 8])
        try applier.apply(Self.full, interface: "tun1", in: session)
        indexes.set(["tun1": 9])
        applier.revert(in: session)
        XCTAssertFalse(callLog.contains("revert"), callLog)
        XCTAssertNil(recorded(session))
    }

    func testFailureRollsBack() throws {
        try useResolved()
        let session = try session()
        FileManager.default.createFile(atPath: base + "/fail-domain", contents: nil)
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun0", in: session)) {
            XCTAssertEqual(String(describing: $0), "resolvectl domain failed (status 1): Failed to set DNS: Link tun0 not managed")
        }
        XCTAssertTrue(callLog.hasSuffix("resolvectl revert tun0\n"), callLog)
        XCTAssertNil(recorded(session))
    }

    func testToolChecks() throws {
        try useResolved()
        let session = try session()
        chmod(resolvectl, 0o777)
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun0", in: session)) {
            guard case .untrustedTool(let path, let reason) = $0 as? DNSFailure else { return XCTFail("\($0)") }
            XCTAssertEqual(path, resolvectl)
            XCTAssertTrue(reason.contains("writable"), reason)
        }
        unlink(resolvectl)
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun0", in: session)) {
            XCTAssertEqual($0 as? DNSFailure, .missingTool("resolvectl", "systemd-resolved manages \(resolvConf)"))
        }
        XCTAssertEqual(callLog, "", "nothing ran")
        XCTAssertNil(recorded(session))
    }

    func testResolvedTargets() throws {
        try useResolved()
        XCTAssertEqual(try applier.chooseBackend().0, .resolved)
        unlink(resolvConf)
        XCTAssertEqual(symlink(root + "/run/systemd/resolve/resolv.conf", resolvConf), 0)
        XCTAssertEqual(try applier.chooseBackend().0, .resolved, "absolute, and not followed: it need not exist")
        unlink(resolvConf)
        XCTAssertEqual(symlink("../run/systemd/resolve/../../../elsewhere", resolvConf), 0)
        XCTAssertThrowsError(try applier.chooseBackend())
        XCTAssertEqual(DNSApplier.lexicalTarget(of: "/etc/resolv.conf", target: "../run/systemd/resolve/stub-resolv.conf"),
                       "/run/systemd/resolve/stub-resolv.conf")
        XCTAssertEqual(DNSApplier.lexicalTarget(of: "/etc/resolv.conf", target: "/run/./x/../resolvconf/resolv.conf"),
                       "/run/resolvconf/resolv.conf")
    }
}

final class DNSResolvconfBackendTests: DNSTestCase {
    func testApplyAndRevert() throws {
        try makeFakeTool(resolvconf, name: "resolvconf")
        let session = try session()
        let settings = try DNSSettings(servers: ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"],
                                       searchDomains: ["corp.example.com", "example.net"], fullTunnel: true)
        XCTAssertEqual(try applier.apply(settings, interface: "tun0", in: session), .resolvconf)
        XCTAssertEqual(callLog, """
        resolvconf -a tun0.passtunnel
        nameserver 192.0.2.1
        nameserver 192.0.2.2
        nameserver 192.0.2.3
        search corp.example.com example.net

        """)
        XCTAssertEqual(resolvConfText, Self.original, "resolvconf's to write")
        applier.revert(in: session)
        XCTAssertTrue(callLog.hasSuffix("resolvconf -d tun0.passtunnel\n"), callLog)
    }

    /// Debian's resolvconf links /etc/resolv.conf into its run directory.
    func testLinkedResolvConf() throws {
        try makeFakeTool(resolvconf, name: "resolvconf")
        unlink(resolvConf)
        XCTAssertEqual(symlink("../run/resolvconf/resolv.conf", resolvConf), 0)
        XCTAssertEqual(try applier.chooseBackend().0, .resolvconf)
    }

    /// systemd's resolvconf is resolvectl under another name: without systemd-resolved it does not
    /// count, and the file is used.
    func testSystemdStandInIsNotResolvconf() throws {
        try makeFakeTool(resolvectl, name: "resolvectl")
        XCTAssertEqual(symlink(resolvectl, resolvconf), 0)
        XCTAssertEqual(try applier.chooseBackend().0, .file)
    }
}

// MARK: - The hook

final class DNSHookTests: DNSTestCase {
    var output: [String] = []
    var parent: pid_t = 0

    func testInvocation() {
        XCTAssertTrue(DNSHook.isInvocation(["/usr/sbin/passtunneld", "dns-hook"]))
        XCTAssertTrue(DNSHook.isInvocation(["/run/passtunnel/1000/acme/dns-hook"]))
        XCTAssertTrue(DNSHook.isInvocation(["/run/passtunnel/1000/acme/dns-hook", "tun0", "1500", "0", "10.8.0.2", "255.255.255.0", "init"]))
        XCTAssertFalse(DNSHook.isInvocation(["/usr/sbin/passtunneld"]))
        XCTAssertFalse(DNSHook.isInvocation(["/usr/sbin/passtunneld", "--dns-hook"]))
        XCTAssertFalse(DNSHook.isInvocation(["/usr/sbin/passtunneld", "x", "dns-hook"]))
        XCTAssertFalse(DNSHook.isInvocation(["/usr/sbin/dns-hook-x"]))
    }

    /// A session directory whose recorded tool is `parent` (this process stands in for OpenVPN).
    func hookSession(_ id: String = "acme") throws -> SessionDirectory {
        let session = try session(id)
        parent = getpid()
        try "\(parent)\n\(me)\n/usr/sbin/openvpn\n\(profileDir(id))\n\(session.path)/mgmt.sock\n"
            .write(toFile: session.path + "/state", atomically: false, encoding: .utf8)
        return session
    }

    func options(in directory: String) -> DNSHook.Options {
        var options = DNSHook.Options()
        options.runRoot = runRoot
        options.ownExecutable = nil
        options.system = system
        options.effectiveUID = { 0 }
        options.workingDirectory = { directory }
        let parent = self.parent
        options.parent = { parent }
        options.isRecordedTool = { $0.pid == parent }
        output = []
        options.output = { [unowned self] in self.output.append($0) }
        return options
    }

    func run(_ environment: [String: String], in directory: String) -> Int32 {
        DNSHook.run(environment: environment, options: options(in: directory))
    }

    static let up27 = ["dev": "tun0", "script_type": "dns-up", "dns_server_1_address_1": "192.0.2.53",
                       "dns_server_1_address_2": "2001:db8::53", "dns_search_domain_1": "corp.example.com"]

    func testOpenVPN27() throws {
        let session = try hookSession()
        XCTAssertEqual(run(Self.up27, in: session.path), 0, "\(output)")
        XCTAssertEqual(output, ["DNS of tun0 set through /etc/resolv.conf: 192.0.2.53, 2001:db8::53; search corp.example.com"])
        XCTAssertEqual(resolvConfText, DNSFileBackendTests.applied)
        XCTAssertEqual(run(["dev": "tun0", "script_type": "dns-down"], in: session.path), 0)
        XCTAssertEqual(output, ["restored the DNS of tun0 (/etc/resolv.conf)"])
        XCTAssertEqual(resolvConfText, Self.original)
    }

    func testOpenVPN26() throws {
        let session = try hookSession()
        let up = ["dev": "tun0", "script_type": "route-up", "foreign_option_1": "dhcp-option DNS 192.0.2.53",
                  "foreign_option_2": "dhcp-option DOMAIN corp.example.com", "redirect_gateway": "2"]
        XCTAssertEqual(run(up, in: session.path), 0, "\(output)")
        XCTAssertTrue(resolvConfText.hasPrefix("# PassTunnel tun0 begin"), resolvConfText)
        XCTAssertEqual(run(["dev": "tun0", "script_type": "down", "script_context": "init"], in: session.path), 0)
        XCTAssertEqual(resolvConfText, Self.original)
    }

    func testNothingPushed() throws {
        let session = try hookSession()
        XCTAssertEqual(run(["dev": "tun0", "script_type": "route-up"], in: session.path), 0)
        XCTAssertEqual(output, ["the server named no DNS servers; DNS is left as it is"])
        XCTAssertEqual(run(["dev": "tun0", "script_type": "down"], in: session.path), 0)
        XCTAssertEqual(output, [])
        XCTAssertEqual(resolvConfText, Self.original)
    }

    /// Every failure says "setting DNS failed", which the client's log check turns into `setup_failed`.
    func testFailuresChangeNothing() throws {
        let session = try hookSession()
        var hostile = Self.up27
        hostile["dns_server_1_address_1"] = "192.0.2.53\nnameserver 198.51.100.66"
        var noDevice = Self.up27
        noDevice["dev"] = "tun9"
        var badDevice = Self.up27
        badDevice["dev"] = "../tun0"
        var varsFile = Self.up27
        varsFile["dns_vars_file"] = "/tmp/openvpn_dvf_x.tmp"
        var unknown = Self.up27
        unknown["script_type"] = "client-connect"
        for env in [hostile, noDevice, badDevice, varsFile, unknown] {
            XCTAssertEqual(run(env, in: session.path), 1, "\(env)")
            XCTAssertEqual(output.count, 1)
            XCTAssertTrue(output.first?.hasPrefix("setting DNS failed: ") == true, "\(output)")
            // In the session log, where the client stops the session with setup_failed, not connect_failed.
            let logged = "2026-10-25 12:00:00 " + DNSHook.logPrefix + (output.first ?? "")
            XCTAssertEqual(VPNLog.setupProblem(logged)?.allTraffic, true, logged)
            XCTAssertFalse(VPNLog.isFatal(logged), logged)
            XCTAssertEqual(resolvConfText, Self.original)
            XCTAssertNil(recorded(session))
        }
    }

    func testOnlyForItsOwnSession() throws {
        let session = try hookSession()
        for directory in [base, runRoot, runRoot + "/\(me)", session.path + "/x", runRoot + "/x/acme", runRoot + "/0\(me)/acme",
                          runRoot + "/\(me)/other"] {
            XCTAssertEqual(run(Self.up27, in: directory), 1, directory)
            XCTAssertTrue(output.first?.hasPrefix("setting DNS failed: not run by a PassTunnel session") == true, "\(output)")
        }
        // Started by something other than the session's tool.
        var options = options(in: session.path)
        options.parent = { 1 }
        XCTAssertEqual(DNSHook.run(environment: Self.up27, options: options), 1)
        XCTAssertEqual(output, ["setting DNS failed: not run by a PassTunnel session: it was not started by the session's tool"])
        options = self.options(in: session.path)
        options.isRecordedTool = { _ in false }
        XCTAssertEqual(DNSHook.run(environment: Self.up27, options: options), 1)
        // Without a record of its tool.
        unlink(session.path + "/state")
        XCTAssertEqual(run(Self.up27, in: session.path), 1)
        XCTAssertEqual(output, ["setting DNS failed: not run by a PassTunnel session: the session has no record of its tool"])
        // Not root.
        options = self.options(in: session.path)
        options.effectiveUID = { 1000 }
        XCTAssertEqual(DNSHook.run(environment: Self.up27, options: options), 1)
        XCTAssertEqual(output, ["setting DNS failed: the DNS hook must run as root"])
        XCTAssertEqual(resolvConfText, Self.original)
    }

    func testDownFailureIsReported() throws {
        let session = try hookSession()
        var options = options(in: session.path)
        options.effectiveUID = { 1000 }
        XCTAssertEqual(DNSHook.run(environment: ["dev": "tun0", "script_type": "dns-down"], options: options), 1)
        XCTAssertEqual(output, ["restoring DNS failed: the DNS hook must run as root"])
    }
}

// MARK: - The daemon

final class DaemonDNSTests: DNSTestCase {
    var hook: String { base + "/bin/passtunneld" }

    func makeDNSDaemon() throws -> Daemon {
        FileManager.default.createFile(atPath: hook, contents: Data("#!/bin/sh\nexit 0\n".utf8),
                                       attributes: [.posixPermissions: 0o755])
        let system = self.system, hook = self.hook
        return try makeDaemon {
            $0.dns = system
            $0.dnsHook = hook
        }
    }

    func log() -> String { (try? String(contentsOfFile: profileDir("acme") + "/vpn.log", encoding: .utf8)) ?? "" }

    func testOpenVPN26RunsTheHookAsRouteUpAndDown() throws {
        let daemon = try makeDNSDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startOpenVPN(start())).pid)
        let runDir = PT.sessionDir(uid: me, profileID: "acme", runRoot: runRoot)
        XCTAssertTrue(eventually { self.log().contains("fake openvpn") })
        XCTAssertTrue(log().contains("--auth-user-pass \(runDir)/auth --script-security 2 --route-up \(runDir)/dns-hook "
                                     + "--down \(runDir)/dns-hook --down-pre\n"), log())
        XCTAssertEqual(DNSApplier.readLink(runDir + "/dns-hook"), hook)
        XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, pid)
    }

    func testOpenVPN27RunsTheHookAsDNSUpdown() throws {
        try makeTool(version: "2.7.1")
        let daemon = try makeDNSDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startOpenVPN(start())).pid)
        let runDir = PT.sessionDir(uid: me, profileID: "acme", runRoot: runRoot)
        XCTAssertTrue(eventually { self.log().contains("fake openvpn") })
        XCTAssertTrue(log().contains("--auth-user-pass \(runDir)/auth --script-security 2 --dns-updown \(runDir)/dns-hook\n"), log())
        XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, pid)
    }

    /// What the hook recorded is reverted when the session ends without its hook doing so: stopped,
    /// died, or the daemon shut down.
    func testRevertedWhenTheSessionEnds() throws {
        let daemon = try makeDNSDaemon()
        for end in ["stop", "kill", "shutdown"] {
            let pid = try XCTUnwrap(try response(daemon.socketPath, .startOpenVPN(start())).pid, end)
            let session = try HelperCore(runRoot: runRoot).openRunDir(profileID: "acme", uid: me)
            try applier.apply(Self.full, interface: "tun0", in: session)      // as the hook would
            XCTAssertEqual(resolvConfText, DNSFileBackendTests.applied)
            switch end {
            case "stop": XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, pid)
            case "kill": kill(pid, SIGKILL)
            default: daemon.shutdown()
            }
            XCTAssertTrue(eventually { self.resolvConfText == Self.original }, end)
            XCTAssertTrue(eventually { !self.exists(session.path) }, end)
        }
    }

    /// A daemon killed during a session: the next one reverts what the session recorded.
    func testStartingDaemonRevertsWhatAnEarlierOneLeft() throws {
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        _ = try makeDNSDaemon()
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertFalse(exists(runRoot + "/\(me)"))
    }

    func testArguments() {
        let common = ["--config", "/c", "--verb", "3", "--management", "/m", "unix", "--management-client-user", "alice",
                      "--auth-nocache", "--remap-usr1", "SIGTERM", "--connect-retry-max", "3"]
        XCTAssertEqual(HelperCore.openVPNArguments(configPath: "/c", mgmtSocket: "/m", clientUser: "alice", authFile: nil,
                                                   dnsUpdown: "/r/dns-hook", hasDNSUpdown: false),
                       common + ["--script-security", "2", "--route-up", "/r/dns-hook", "--down", "/r/dns-hook", "--down-pre"])
        XCTAssertEqual(HelperCore.openVPNArguments(configPath: "/c", mgmtSocket: "/m", clientUser: "alice", authFile: nil,
                                                   dnsUpdown: "/r/dns-hook"),
                       common + ["--script-security", "2", "--dns-updown", "/r/dns-hook"], "as the Mac's")
    }
}
