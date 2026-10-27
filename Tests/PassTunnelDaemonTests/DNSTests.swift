import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelDaemon
@testable import PassTunnelShared

// MARK: - Values

final class DNSSettingsTests: XCTestCase {
    func testAddresses() throws {
        let good = [
            ("192.0.2.53", "192.0.2.53"), ("2001:DB8:0:0::53", "2001:db8::53"), ("198.51.100.1", "198.51.100.1"),
            ("::ffff:192.0.2.1", "::ffff:192.0.2.1"), ("2001:db8::1:0:0:1", "2001:db8::1:0:0:1")
        ]
        for (text, canonical) in good { XCTAssertEqual(try DNSSettings.address(text), canonical, text) }
        let bad = [
            "", "0.0.0.0", "::", "1.2.3", "256.1.1.1", "192.0.2.1;reboot", "192.0.2.1 198.51.100.1",
            "fe80::1%eth0", "192.0.2.1:53", "[2001:db8::1]", "-192.0.2.1", "192.0.2.1\n", "192.0.2.1\u{0}x",
            "vpn.example.com", "$(reboot)", String(repeating: "1", count: 100), " 192.0.2.1"
        ]
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
        let long = Array(repeating: label, count: 4).joined(separator: ".")  // 255 bytes
        let bad = [
            "", ".", "..", "a..b", "-x.example.com", "x-.example.com", "~corp.example.com", "corp example.com",
            "exa$mple.com", "example.com/x", "ex\nample.com", "ünicode.example", label + "a.example.com", long,
            "*.example.com", "example.com;reboot", "-", "\u{0}"
        ]
        for text in bad {
            XCTAssertThrowsError(try DNSSettings.domain(text), text) {
                XCTAssertEqual($0 as? DNSFailure, .invalid("DNS domain", text))
            }
        }
    }

    func testInterfaces() throws {
        for name in ["tun0", "ppp0", "tap1", "ovpn-acme", "tun.1", "x", "0x", "1.2"] {
            XCTAssertEqual(try DNSSettings.interface(name), name)
        }
        for name in ["", "-tun0", ".tun0", "tun0 ", "tun/0", "eth0:1", "tun0;x", String(repeating: "t", count: 16), "tün0"] {
            XCTAssertThrowsError(try DNSSettings.interface(name), name)
        }
        // Digits only: resolvectl (and others) read that as an interface index.
        for name in ["2", "10", "007", "4294967295"] {
            XCTAssertThrowsError(try DNSSettings.interface(name), name) {
                XCTAssertEqual($0 as? DNSFailure, .invalid("interface", name))
            }
        }
    }

    func testCountsAndRepeats() throws {
        let settings = try DNSSettings(
            servers: ["192.0.2.1", "192.0.2.1", "2001:db8::1", "2001:DB8::1"],
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
        let split = try XCTUnwrap(
            try settings([
                "dev": "tun0", "script_type": "dns-up",
                "dns_search_domain_1": "corp.example.com", "dns_search_domain_2": "eu.example.com",
                "dns_server_1_address_1": "192.0.2.53", "dns_server_1_address_2": "2001:db8::53",
                "dns_server_1_port_2": "53", "dns_server_1_resolve_domain_1": "corp.example.com",
                "dns_server_1_resolve_domain_2": "example.net", "dns_server_1_dnssec": "optional"
            ]))
        XCTAssertEqual(
            split,
            try DNSSettings(
                servers: ["192.0.2.53", "2001:db8::53"],
                searchDomains: ["corp.example.com", "eu.example.com"],
                routingDomains: ["corp.example.com", "example.net"], fullTunnel: false))

        // dhcp-options turned into --dns by 2.7: no resolve domains, so every name goes through the tunnel;
        // a DOMAIN that was not pushed leaves a gap before the DOMAIN-SEARCH entries.
        let converted = try XCTUnwrap(
            try settings([
                "dns_server_1_address_1": "192.0.2.53", "dns_search_domain_3": "b.example.com",
                "dns_search_domain_2": "a.example.com"
            ]))
        XCTAssertEqual(converted.searchDomains, ["a.example.com", "b.example.com"])
        XCTAssertTrue(converted.fullTunnel)
    }

    func testFirstServerPlainDNSReaches() throws {
        let env = [
            "dns_server_1_address_1": "192.0.2.1", "dns_server_1_transport": "DoT",
            "dns_server_2_address_1": "192.0.2.2", "dns_server_2_port_1": "853",
            "dns_server_3_address_1": "192.0.2.3", "dns_server_3_transport": "plain", "dns_server_3_port_1": "53",
            "dns_server_4_address_1": "192.0.2.4"
        ]
        XCTAssertEqual(try settings(env)?.servers, ["192.0.2.3"])
        XCTAssertThrowsError(try settings(["dns_server_1_address_1": "192.0.2.1", "dns_server_1_transport": "DoH"])) {
            XCTAssertEqual($0 as? DNSFailure, .noUsableServer)
        }
    }

    /// OpenVPN 2.6's `--route-up` environment: `dhcp-option`s, in the order pushed.
    func testDHCPOptions() throws {
        let env = [
            "dev": "tun0", "script_type": "route-up",
            "foreign_option_1": "dhcp-option DOMAIN corp.example.com",
            "foreign_option_2": "dhcp-option DNS 192.0.2.53",
            "foreign_option_3": "dhcp-option WINS 192.0.2.99",
            "foreign_option_10": "dhcp-option DNS6 2001:db8::53",
            "foreign_option_4": "dhcp-option DOMAIN-SEARCH example.net",
            "foreign_option_5": "dhcp-option ADAPTER-DOMAIN-SUFFIX lan",
            "foreign_option_6": "dhcp-option NTP 192.0.2.123 192.0.2.124"
        ]
        XCTAssertEqual(
            try settings(env),
            try DNSSettings(
                servers: ["192.0.2.53", "2001:db8::53"],
                searchDomains: ["corp.example.com", "example.net", "lan"],
                fullTunnel: true))
        XCTAssertNil(
            try settings(["foreign_option_1": "dhcp-option DOMAIN corp.example.com", "dev": "tun0"]),
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
            (1...9).reduce(into: [:]) { env, i in env["dns_server_1_address_\(i)"] = "192.0.2.\(i)" }
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
    /// A rewrite in place stops before cutting the file, as a writer that dies there leaves it.
    var truncateFails = false
    /// Runs right before PassTunnel checks the file it read and replaces it: another writer.
    var otherWriter: ((String) -> Void)?
    /// The fake /etc is read-only, as /etc is inside passtunnel.service.
    var readOnlyEtc = false
    static let original = "# from the network\nnameserver 192.0.2.1\nsearch lan\noptions edns0\n"

    override func setUpWithError() throws {
        try super.setUpWithError()
        for dir in ["/etc", "/run/systemd/resolve", "/usr/bin", "/usr/sbin"] {
            try FileManager.default.createDirectory(
                atPath: root + dir, withIntermediateDirectories: true,
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
        system.resolvconfConf = root + "/etc/resolvconf.conf"
        system.owner = me
        system.base = base
        let indexes = self.indexes
        system.interfaceIndex = { indexes.get($0) }
        if renameFails {
            system.renameFile = { _, _ in EBUSY }
        }
        if truncateFails {
            system.truncateFile = { _, _ in
                errno = EIO
                return -1
            }
        }
        if let otherWriter { system.willReplace = otherWriter }
        let etc = root + "/etc", readOnlyEtc = self.readOnlyEtc
        system.isReadOnly = { readOnlyEtc && $0 == etc }
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

    /// The file backend's baseline in the run root, as `ResolvConfBaseline` writes it.
    var baselinePath: String { runRoot + "/" + ResolvConfBaseline.fileName }
    var baselineText: String? { try? String(contentsOfFile: baselinePath, encoding: .utf8) }

    var callLog: String { (try? String(contentsOfFile: calls, encoding: .utf8)) ?? "" }
    var resolvConfText: String { (try? String(contentsOfFile: resolvConf, encoding: .utf8)) ?? "<none>" }

    static let full = try! DNSSettings(
        servers: ["192.0.2.53", "2001:db8::53"], searchDomains: ["corp.example.com"],
        fullTunnel: true)
    static let split = try! DNSSettings(
        servers: ["192.0.2.53"], searchDomains: ["corp.example.com"],
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
        XCTAssertEqual(recorded(session), "passtunnel-dns 2\nfile\ntun0\n7\n1\n192.0.2.53 2001:db8::53\ncorp.example.com\n")
        let digest = HelperCore.sha256Hex(Data(Self.applied.utf8))
        XCTAssertEqual(baselineText, "passtunnel-resolv-base 2\n\(digest)\n\(Self.original.utf8.count)\n-\n" + Self.original)
        var st = stat()
        for path in [session.path + "/dns", baselinePath] {
            XCTAssertEqual(lstat(path, &st), 0)
            XCTAssertEqual(st.st_mode & 0o777, 0o600, path)
        }

        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (/etc/resolv.conf)")
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertNil(recorded(session))
        XCTAssertFalse(exists(baselinePath))
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
        XCTAssertTrue(baselineText?.hasSuffix("\n-\n-\n") == true, baselineText ?? "<none>")
        applier.revert(in: session)
        XCTAssertFalse(exists(resolvConf))
        XCTAssertFalse(exists(baselinePath))
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

    /// Inside passtunnel.service /etc is read-only and the file a bind mount of its own: rewritten in
    /// place, nothing created next to it.
    func testReadOnlyEtcIsRewrittenInPlace() throws {
        readOnlyEtc = true
        let session = try session()
        var before = stat()
        XCTAssertEqual(lstat(resolvConf, &before), 0)
        try applier.apply(Self.full, interface: "tun0", in: session)
        XCTAssertEqual(resolvConfText, Self.applied)
        XCTAssertTrue(baselineText?.hasSuffix("\n-\n" + Self.original) == true, baselineText ?? "<none>")
        var after = stat()
        XCTAssertEqual(lstat(resolvConf, &after), 0)
        XCTAssertEqual(after.st_ino, before.st_ino)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root + "/etc"), ["resolv.conf"])
        // Shorter than what it replaces: cut to its length.
        try applier.apply(try DNSSettings(servers: ["192.0.2.53"], fullTunnel: true), interface: "tun0", in: session)
        XCTAssertTrue(resolvConfText.hasSuffix("options edns0\n"), resolvConfText)
        applier.revert(in: session)
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertEqual(lstat(resolvConf, &after), 0)
        XCTAssertEqual(after.st_ino, before.st_ino)
    }

    /// The file with only tun1's DNS in effect: what two tunnels give while tun1 is the newer one.
    static let appliedTun1 = """
        # PassTunnel tun1 begin: DNS of the VPN, removed when it disconnects
        nameserver 198.51.100.53
        search example.net
        # PassTunnel tun1 end
        # from the network
        #PassTunnel tun1# nameserver 192.0.2.1
        #PassTunnel tun1# search lan
        options edns0

        """
    static let tun1 = try! DNSSettings(servers: ["198.51.100.53"], searchDomains: ["example.net"], fullTunnel: true)

    /// Two tunnels at once: the newer one's DNS is in effect; the older one ending changes nothing, and
    /// the file's own servers never come back while a tunnel is up.
    func testTwoTunnelsOlderEndsFirst() throws {
        let one = try session("one"), two = try session("two")
        try applier.apply(Self.full, interface: "tun0", in: one)
        try applier.apply(Self.tun1, interface: "tun1", in: two)
        XCTAssertEqual(resolvConfText, Self.appliedTun1)
        XCTAssertEqual(applier.revert(in: one), "restored the DNS of tun0 (/etc/resolv.conf)")
        XCTAssertEqual(resolvConfText, Self.appliedTun1, "tun1 is still up: the file's own lines stay disabled")
        XCTAssertEqual(applier.revert(in: two), "restored the DNS of tun1 (/etc/resolv.conf)")
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertFalse(exists(baselinePath))
    }

    /// The newer one ending gives the older one's DNS back, never the file's own.
    func testTwoTunnelsNewerEndsFirst() throws {
        let one = try session("one"), two = try session("two")
        try applier.apply(Self.full, interface: "tun0", in: one)
        try applier.apply(Self.tun1, interface: "tun1", in: two)
        applier.revert(in: two)
        XCTAssertEqual(resolvConfText, Self.applied)
        applier.revert(in: one)
        XCTAssertEqual(resolvConfText, Self.original)
    }

    /// Three sessions ending in any order, with the file changed by someone else in between: every
    /// state is made from the baseline and the newest session left, and the change stays.
    func testOverlappingSessionsWithOutsideChange() throws {
        let one = try session("one"), two = try session("two"), three = try session("three")
        indexes.set(["tun0": 7, "tun1": 8, "tun2": 9])
        try applier.apply(Self.full, interface: "tun0", in: one)
        try applier.apply(Self.tun1, interface: "tun1", in: two)
        try applier.apply(try DNSSettings(servers: ["198.51.100.99"], fullTunnel: true), interface: "tun2", in: three)
        XCTAssertTrue(resolvConfText.hasPrefix("# PassTunnel tun2 begin"), resolvConfText)
        try (resolvConfText + "options ndots:2\n").write(toFile: resolvConf, atomically: false, encoding: .utf8)
        applier.revert(in: two)
        XCTAssertTrue(resolvConfText.hasPrefix("# PassTunnel tun2 begin"), resolvConfText)
        XCTAssertTrue(resolvConfText.contains("\n#PassTunnel tun2# nameserver 192.0.2.1\n"), resolvConfText)
        applier.revert(in: three)
        XCTAssertEqual(resolvConfText, Self.applied + "options ndots:2\n")
        applier.revert(in: one)
        XCTAssertEqual(resolvConfText, Self.original + "options ndots:2\n")
    }

    /// The hook (a process of its own) and the daemon (FortiGate) work on the same registry: anything
    /// with the run root's lock and its session directories. Here two appliers stand in for them.
    func testHookAndDaemonShareTheRegistry() throws {
        let hook = applier, daemon = DNSApplier(system: system, runRoot: runRoot)
        let openvpn = try session("openvpn"), forti = try session("forti")
        indexes.set(["tun0": 7, "ppp0": 8])
        try hook.apply(Self.full, interface: "tun0", in: openvpn)
        try daemon.apply(Self.tun1, interface: "ppp0", in: forti)
        XCTAssertEqual(hook.fileSessions().map(\.interface), ["ppp0", "tun0"])
        XCTAssertEqual(daemon.fileSessions(excluding: forti.path).map(\.interface), ["tun0"])
        hook.revert(in: openvpn)
        XCTAssertTrue(resolvConfText.hasPrefix("# PassTunnel ppp0 begin"), resolvConfText)
        XCTAssertFalse(resolvConfText.contains("\nnameserver 192.0.2.1\n"), resolvConfText)
        daemon.revert(in: forti)
        XCTAssertEqual(resolvConfText, Self.original)
    }

    /// The lock is the run root's, whoever holds it: a change waits for it, and gives up in time. A
    /// revert that cannot take it changes nothing (registry, baseline and file stay) and keeps the
    /// record, to be tried again.
    func testChangesWaitForTheLock() throws {
        let other = try session("other"), session = try session()
        var quick = applier
        quick.lockTimeout = 0.2
        var held = try applier.lock()
        XCTAssertThrowsError(try quick.apply(Self.full, interface: "tun0", in: session)) {
            XCTAssertEqual($0 as? DNSFailure, .busy)
        }
        close(held)
        XCTAssertNil(recorded(session))
        XCTAssertEqual(resolvConfText, Self.original)

        try applier.apply(Self.full, interface: "tun0", in: session)
        try applier.apply(Self.tun1, interface: "tun1", in: other)
        let before = (resolvConfText, baselineText, recorded(session))
        held = try applier.lock()
        let message = try XCTUnwrap(quick.revert(in: session))
        XCTAssertTrue(message.hasPrefix("could not restore DNS yet (another DNS change did not finish in time)"), message)
        XCTAssertTrue(message.hasSuffix("kept, to be restored later"), message)
        XCTAssertEqual(resolvConfText, before.0)
        XCTAssertEqual(baselineText, before.1)
        XCTAssertEqual(recorded(session), before.2, "still in the registry")
        XCTAssertNil(quick.recover(), "nothing without the lock either")
        close(held)
        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (/etc/resolv.conf)")
        XCTAssertEqual(resolvConfText, Self.appliedTun1)
        applier.revert(in: other)
        XCTAssertEqual(resolvConfText, Self.original)
    }

    /// A writer that died between rewriting the file in place and cutting it to its length (here the
    /// cut fails) leaves the start of the new file over the rest of the old one, with the old block's
    /// servers in it. The journal in the run root says what was under way: the next change finishes
    /// it, rather than taking the mixture for someone else's file.
    func testInterruptedRewriteIsFinished() throws {
        readOnlyEtc = true
        try "nameserver 192.0.2.1\n".write(toFile: resolvConf, atomically: false, encoding: .utf8)
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        let applied = resolvConfText
        truncateFails = true
        let message = try XCTUnwrap(applier.revert(in: session))
        XCTAssertTrue(message.hasPrefix("could not restore the DNS of tun0 (/etc/resolv.conf) yet: truncate"), message)
        let mixed = resolvConfText
        XCTAssertTrue(mixed.hasPrefix("nameserver 192.0.2.1\n"), mixed)
        XCTAssertTrue(mixed.contains("\nnameserver 2001:db8::53\n"), "the VPN's server is left: \(mixed)")
        XCTAssertEqual(mixed.utf8.count, applied.utf8.count)
        XCTAssertNotNil(recorded(session), "kept")
        XCTAssertTrue(baselineText?.contains("\n-\n") == false, "a change under way: \(baselineText ?? "<none>")")
        truncateFails = false
        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (/etc/resolv.conf)")
        XCTAssertEqual(resolvConfText, "nameserver 192.0.2.1\n")
        XCTAssertFalse(exists(baselinePath))
    }

    /// The same finished by `recover` (a starting daemon, the daemon's retries), with the session still
    /// registered, and then once no session uses the file any more.
    func testInterruptedRewriteIsFinishedByRecover() throws {
        readOnlyEtc = true
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        truncateFails = true
        applier.revert(in: session)
        truncateFails = false
        XCTAssertNotNil(recorded(session))
        XCTAssertEqual(applier.recover(), "finished an interrupted change of \(resolvConf)")
        XCTAssertEqual(resolvConfText, Self.applied, "the session is still registered")
        XCTAssertNil(applier.recover(), "nothing left to finish")
        DNSRecord.remove(in: session)
        XCTAssertEqual(applier.recover(), "restored \(resolvConf), which no session uses any more")
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertFalse(exists(baselinePath))
    }

    func testInterruptedChanges() {
        let previous = Array("abcdefgh".utf8), longer = Array("ABCDEFGHIJKL".utf8), shorter = Array("ABC".utf8)
        let cases: [([UInt8]?, [UInt8]?, [UInt8]?, Bool)] = [
            (previous, previous, longer, true), (longer, previous, longer, true),  // not begun, done
            (Array("ABCdefgh".utf8), previous, longer, true),  // in place, part way
            (Array("ABCDEFGHIJ".utf8), previous, longer, true),  // past the old end
            (Array("ABCdefgh".utf8), previous, shorter, true),  // written, not cut
            (Array("ABCdefgX".utf8), previous, shorter, false),  // and changed after
            (Array("xbcdefgh".utf8), previous, longer, false), (Array("ABCDEFGHIJKX".utf8), previous, longer, false),
            (Array("abcd".utf8), previous, longer, false),
            (nil, previous, nil, true), (nil, nil, longer, true), (longer, nil, longer, true),
            (Array("ABC".utf8), nil, longer, false), (nil, previous, longer, false), (previous, nil, nil, false)
        ]
        for (current, before, after, interrupted) in cases {
            XCTAssertEqual(
                ResolvConfBaseline.isInterrupted(current, previous: before, intended: after), interrupted,
                "\(String(decoding: current ?? [], as: UTF8.self)) \(String(decoding: after ?? [], as: UTF8.self))")
        }
    }

    /// The file a tunnel's block would make must be one PassTunnel can read back to restore it:
    /// refused before anything changes.
    func testOversizedResultIsRefused() throws {
        let large = "# " + String(repeating: "x", count: DNSApplier.maxResolvConfBytes - 30) + "\nnameserver 192.0.2.1\n"
        try large.write(toFile: resolvConf, atomically: false, encoding: .utf8)
        let session = try session()
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun0", in: session)) {
            XCTAssertEqual($0 as? DNSFailure, .wouldBeTooLarge(resolvConf))
        }
        XCTAssertEqual(resolvConfText, large)
        XCTAssertNil(recorded(session))
        XCTAssertFalse(exists(baselinePath))
    }

    /// Another writer replaces the file between PassTunnel reading and writing it: read again and
    /// worked out anew, their file the baseline now; replaced every time, PassTunnel gives up and
    /// leaves their file.
    func testReplacementBetweenReadAndWrite() throws {
        let session = try session()
        let theirs = "nameserver 198.51.100.1\n", path = resolvConf
        var replaced = 0
        otherWriter = { _ in
            replaced += 1
            if replaced == 1 { try? theirs.write(toFile: path, atomically: true, encoding: .utf8) }
        }
        try applier.apply(Self.full, interface: "tun0", in: session)
        XCTAssertTrue(resolvConfText.hasSuffix("# PassTunnel tun0 end\n#PassTunnel tun0# nameserver 198.51.100.1\n"), resolvConfText)
        applier.revert(in: session)
        XCTAssertEqual(resolvConfText, theirs)

        replaced = 0
        otherWriter = { _ in
            replaced += 1
            try? "nameserver 198.51.100.\(replaced)\n".write(toFile: path, atomically: true, encoding: .utf8)
        }
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun0", in: session)) {
            XCTAssertEqual($0 as? DNSFailure, .changedMeanwhile(path))
        }
        XCTAssertEqual(replaced, DNSApplier.writeAttempts)
        XCTAssertEqual(resolvConfText, "nameserver 198.51.100.\(replaced)\n", "theirs, untouched")
        XCTAssertNil(recorded(session))
        XCTAssertFalse(exists(baselinePath))
        // Changed in place (same file, other content) counts as well.
        replaced = 0
        otherWriter = { _ in
            replaced += 1
            if replaced == 1 { try? "nameserver 198.51.100.9\n".write(toFile: path, atomically: false, encoding: .utf8) }
        }
        try applier.apply(Self.full, interface: "tun0", in: session)
        XCTAssertTrue(resolvConfText.hasSuffix("#PassTunnel tun0# nameserver 198.51.100.9\n"), resolvConfText)
    }

    /// A session that crashed between its steps (its record gone, the baseline still there) is
    /// cleaned up by `recover`, as a starting daemon runs it.
    func testUnclaimedBaselineIsRestored() throws {
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        XCTAssertNil(applier.recover(), "claimed by a session")
        DNSRecord.remove(in: session)
        XCTAssertEqual(applier.recover(), "restored \(resolvConf), which no session uses any more")
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertFalse(exists(baselinePath))
        XCTAssertNil(applier.recover(), "nothing left")
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
        XCTAssertEqual(
            Array(lines.suffix(6)),
            [
                "#PassTunnel tun0# nameserver 192.0.2.1", " nameserver x", "nameservers",
                "#PassTunnel tun0# search\tlan", "#PassTunnel tun0# domain lan", "#nameserver y"
            ])
        XCTAssertEqual(ResolvConf.stripAll(applied), previous)
        XCTAssertNil(ResolvConf.stripAll(previous))
        // Blocks and marks of any interface go (one a crash left behind too); text that only looks like
        // them stays.
        let leftovers =
            ResolvConf.begin("tun7") + [0x0A] + Array("nameserver 198.51.100.7\n".utf8) + ResolvConf.end("tun7")
            + [0x0A] + ResolvConf.mark("ppp0") + Array("nameserver 192.0.2.9\n".utf8)
        let lookalikes =
            Array("# PassTunnel tun8 begin: DNS of the VPN, removed when it disconnects\nnameserver 192.0.2.8\n".utf8)
            + Array("#PassTunnel tun 0# x\n#PassTunnel -x# y\n#PassTunnel tun0#z\n".utf8)
        XCTAssertEqual(
            ResolvConf.stripAll(leftovers + lookalikes),
            Array("nameserver 192.0.2.9\n".utf8) + lookalikes, "a block without its end is not one")
        XCTAssertNil(ResolvConf.stripAll(lookalikes))
        // Bytes that are not UTF-8 survive.
        let binary: [UInt8] = [0x23, 0xFF, 0xFE, 0x0A] + Array("nameserver 192.0.2.1".utf8)
        XCTAssertEqual(ResolvConf.stripAll(ResolvConf.apply(Self.full, interface: "tun0", to: binary)), binary)
    }

    func testRecordParsing() throws {
        let full = try DNSSettings(servers: ["192.0.2.53", "2001:db8::53"], searchDomains: ["corp.example.com"], fullTunnel: true)
        let file = DNSRecord(backend: .file, interface: "tun0", index: 7, serial: 3, settings: full)
        XCTAssertEqual(file.text, "passtunnel-dns 2\nfile\ntun0\n7\n3\n192.0.2.53 2001:db8::53\ncorp.example.com\n")
        XCTAssertEqual(DNSRecord(text: file.text), file)
        XCTAssertEqual(
            DNSRecord(text: "passtunnel-dns 2\nfile\ntun0\n7\n1\n192.0.2.53\n-\n"),
            DNSRecord(
                backend: .file, interface: "tun0", index: 7, serial: 1,
                settings: try DNSSettings(servers: ["192.0.2.53"], fullTunnel: true)))
        XCTAssertEqual(
            DNSRecord(text: "passtunnel-dns 2\nresolved\ntun0\n7\n-\n-\n-\n"),
            DNSRecord(backend: .resolved, interface: "tun0", index: 7))
        for bad in [
            "", "passtunnel-dns 1\nresolved\ntun0\n7\n-\nnone\n", "passtunnel-dns 2\nother\ntun0\n7\n-\n-\n-\n",
            "passtunnel-dns 2\nresolved\n-tun0\n7\n-\n-\n-\n", "passtunnel-dns 2\nresolved\ntun0\n07\n-\n-\n-\n",
            "passtunnel-dns 2\nresolved\ntun0\n0\n-\n-\n-\n", "passtunnel-dns 2\nresolved\n7\n7\n-\n-\n-\n",
            "passtunnel-dns 2\nresolved\ntun0\n7\n1\n192.0.2.53\n-\n", "passtunnel-dns 2\nfile\ntun0\n7\n-\n-\n-\n",
            "passtunnel-dns 2\nfile\ntun0\n7\n0\n192.0.2.53\n-\n", "passtunnel-dns 2\nfile\ntun0\n7\n01\n192.0.2.53\n-\n",
            "passtunnel-dns 2\nfile\ntun0\n7\n1\n2001:DB8::53\n-\n", "passtunnel-dns 2\nfile\ntun0\n7\n1\n192.0.2.53  192.0.2.54\n-\n",
            "passtunnel-dns 2\nfile\ntun0\n7\n1\n192.0.2.53\nCorp.example.com\n",
            "passtunnel-dns 2\nfile\ntun0\n7\n1\n192.0.2.53\n~corp.example.com\n",
            "passtunnel-dns 2\nfile\ntun0\n7\n1\n192.0.2.53\n-\nx\n", "passtunnel-dns 2\nresolved\ntun0\n7\n-\n-\n-"
        ] {
            XCTAssertNil(DNSRecord(text: bad), bad)
        }
    }

    func testBaselineParsing() {
        let digest = String(repeating: "a", count: 64)
        let content: [UInt8] = Array("nameserver 192.0.2.1\n".utf8) + [0xFF, 0x0A]
        let after: [UInt8] = Array("nameserver 198.51.100.1\n".utf8)
        let states = [
            ResolvConfBaseline(written: digest, content: content),
            ResolvConfBaseline(written: digest, content: nil),
            ResolvConfBaseline(written: digest, content: []),
            ResolvConfBaseline(
                written: HelperCore.sha256Hex(Data(after)), content: content,
                pending: .init(previous: content + [0x41], intended: after)),
            ResolvConfBaseline(written: nil, content: nil, pending: .init(previous: after, intended: nil)),
            ResolvConfBaseline(written: HelperCore.sha256Hex(Data(after)), content: nil, pending: .init(previous: nil, intended: after))
        ]
        for state in states { XCTAssertEqual(ResolvConfBaseline(bytes: state.bytes), state, "\(state)") }
        XCTAssertEqual(
            String(decoding: states[3].bytes.prefix(99), as: UTF8.self),
            "passtunnel-resolv-base 2\n\(HelperCore.sha256Hex(Data(after)))\n23\n24 24\n")
        let head = "passtunnel-resolv-base 2\n\(digest)\n"
        for bad in [
            "", "passtunnel-resolv-base 1\n\(digest)\n0\n-\n", head + "0\n-\nx", head + "1\n-\n", head + "01\n-\nx",
            head + "-1\n-\n", head + "x\n-\n", "passtunnel-resolv-base 2\n\(digest.uppercased())\n0\n-\n",
            "passtunnel-resolv-base 2\nabc\n0\n-\n", head + "0\n1 1\nab", "passtunnel-resolv-base 2\n-\n0\n1 1\nab",
            head + "0\n1\na", head + "0\n-", head + "\(DNSApplier.maxResolvConfBytes + 1)\n-\n"
        ] {
            XCTAssertNil(ResolvConfBaseline(bytes: Array(bad.utf8)), bad)
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
        // The link by its index (tun0 is 7), never by its name.
        XCTAssertEqual(
            callLog,
            """
            resolvectl dns 7 192.0.2.53 2001:db8::53
            resolvectl domain 7 corp.example.com ~.
            resolvectl default-route 7 true

            """)
        XCTAssertEqual(recorded(session), "passtunnel-dns 2\nresolved\ntun0\n7\n-\n-\n-\n")
        XCTAssertEqual(
            try String(contentsOfFile: root + "/run/systemd/resolve/stub-resolv.conf", encoding: .utf8),
            "nameserver 127.0.0.53\n", "the link is never written through")
        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (systemd-resolved)")
        XCTAssertTrue(callLog.hasSuffix("resolvectl revert 7\n"), callLog)
    }

    func testSplitTunnel() throws {
        try useResolved()
        try applier.apply(Self.split, interface: "tun0", in: try session())
        XCTAssertEqual(
            callLog,
            """
            resolvectl dns 7 192.0.2.53
            resolvectl domain 7 corp.example.com ~example.net
            resolvectl default-route 7 false

            """)
    }

    /// Right before each call the recorded index must still name the interface, and no interface may
    /// be named like the index (newer resolvectl looks a number up as a name first).
    func testLinkIsCheckedBeforeEveryCall() throws {
        try useResolved()
        let session = try session()
        let tool = try XCTUnwrap(try applier.trustedTool(system.resolvectl))
        let record = DNSRecord(backend: .resolved, interface: "tun0", index: 7)
        indexes.set(["tun0": 9])  // replaced after apply looked it up
        XCTAssertThrowsError(try applier.commit(record, settings: Self.full, tool: tool, root: -1)) {
            XCTAssertEqual($0 as? DNSFailure, .interfaceChanged("tun0", 7))
        }
        indexes.set(["tun0": 7, "7": 3])  // someone named an interface "7"
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun0", in: session)) {
            XCTAssertEqual($0 as? DNSFailure, .interfaceChanged("tun0", 7))
            XCTAssertEqual(String(describing: $0), "tun0 is no longer interface 7, or another interface is named “7”")
        }
        XCTAssertEqual(callLog, "", "resolvectl never ran")
        XCTAssertNotNil(recorded(session), "its revert could not run either: kept, to try again")
        indexes.set([:])  // the link went: systemd-resolved forgot it
        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (systemd-resolved)")
        XCTAssertNil(recorded(session))
        // Set up, then the same: the revert does not run either, says why, and keeps the record.
        indexes.set(["tun0": 7])
        try applier.apply(Self.full, interface: "tun0", in: session)
        indexes.set(["tun0": 7, "7": 3])
        let message = try XCTUnwrap(applier.revert(in: session))
        XCTAssertTrue(message.hasPrefix("could not restore the DNS of tun0 (systemd-resolved) yet: tun0 is no longer"), message)
        XCTAssertFalse(callLog.contains("revert"), callLog)
        XCTAssertNotNil(recorded(session))
        indexes.set(["tun0": 7])
        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (systemd-resolved)")
        XCTAssertTrue(callLog.hasSuffix("resolvectl revert 7\n"), callLog)
        // Another interface named with digits, but not this index, is no problem.
        indexes.set(["tun0": 7])
        try applier.apply(Self.full, interface: "tun0", in: session)
        indexes.set(["tun0": 7, "8": 8])
        XCTAssertEqual(applier.revert(in: session), "restored the DNS of tun0 (systemd-resolved)")
        XCTAssertTrue(callLog.hasSuffix("resolvectl revert 7\n"), callLog)
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
        _ = FileManager.default.createFile(atPath: base + "/fail-domain", contents: nil)
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun0", in: session)) {
            XCTAssertEqual(String(describing: $0), "resolvectl domain failed (status 1): Failed to set DNS: Link tun0 not managed")
        }
        XCTAssertTrue(callLog.hasSuffix("resolvectl revert 7\n"), callLog)
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
        XCTAssertEqual(
            DNSApplier.lexicalTarget(of: "/etc/resolv.conf", target: "../run/systemd/resolve/stub-resolv.conf"),
            "/run/systemd/resolve/stub-resolv.conf")
        XCTAssertEqual(
            DNSApplier.lexicalTarget(of: "/etc/resolv.conf", target: "/run/./x/../resolvconf/resolv.conf"),
            "/run/resolvconf/resolv.conf")
    }
}

final class DNSResolvconfBackendTests: DNSTestCase {
    func testApplyAndRevert() throws {
        try makeFakeTool(resolvconf, name: "resolvconf")
        let session = try session()
        let settings = try DNSSettings(
            servers: ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"],
            searchDomains: ["corp.example.com", "example.net"], fullTunnel: true)
        XCTAssertEqual(try applier.apply(settings, interface: "tun0", in: session), .resolvconf)
        XCTAssertEqual(
            callLog,
            """
            resolvconf -a tun0.passtunnel-7
            nameserver 192.0.2.1
            nameserver 192.0.2.2
            nameserver 192.0.2.3
            search corp.example.com example.net

            """)
        XCTAssertEqual(resolvConfText, Self.original, "resolvconf's to write")
        applier.revert(in: session)
        XCTAssertTrue(callLog.hasSuffix("resolvconf -d tun0.passtunnel-7\n"), callLog)
    }

    /// Records are per link: a session that ends after a later one got its interface name (a crashed
    /// tool's reap racing a new tunnel) removes its own record, never the later one's.
    func testRecordsArePerLink() throws {
        try makeFakeTool(resolvconf, name: "resolvconf")
        let old = try session("old"), new = try session("new")
        try applier.apply(Self.full, interface: "tun0", in: old)
        indexes.set(["tun0": 12])
        try applier.apply(Self.full, interface: "tun0", in: new)
        applier.revert(in: old)
        XCTAssertTrue(callLog.contains("resolvconf -a tun0.passtunnel-7\n"), callLog)
        XCTAssertTrue(callLog.contains("resolvconf -a tun0.passtunnel-12\n"), callLog)
        XCTAssertTrue(callLog.hasSuffix("resolvconf -d tun0.passtunnel-7\n"), callLog)
        applier.revert(in: new)
        XCTAssertTrue(callLog.hasSuffix("resolvconf -d tun0.passtunnel-12\n"), callLog)
    }

    /// Debian's resolvconf links /etc/resolv.conf into its run directory.
    func testLinkedResolvConf() throws {
        try makeFakeTool(resolvconf, name: "resolvconf")
        unlink(resolvConf)
        XCTAssertEqual(symlink("../run/resolvconf/resolv.conf", resolvConf), 0)
        XCTAssertEqual(try applier.chooseBackend().0, .resolvconf)
    }

    /// openresolv writes /etc/resolv.conf in place unless `resolv_conf_mv` is set; then it renames a
    /// new file over it, which cannot work where /etc is read-only (inside passtunnel.service): refused
    /// there with a reason, never left to fail silently.
    func testOpenresolvThatReplacesTheFile() throws {
        try makeFakeTool(resolvconf, name: "resolvconf")
        try "# openresolv\nresolv_conf_mv=YES\n".write(toFile: root + "/etc/resolvconf.conf", atomically: false, encoding: .utf8)
        readOnlyEtc = true
        let session = try session()
        XCTAssertThrowsError(try applier.apply(Self.full, interface: "tun0", in: session)) {
            XCTAssertEqual($0 as? DNSFailure, .resolvconfReplaces(root + "/etc/resolvconf.conf", root + "/etc"))
            XCTAssertTrue(String(describing: $0).contains("remove resolv_conf_mv"), "\($0)")
        }
        XCTAssertEqual(callLog, "", "resolvconf did not run")
        XCTAssertNil(recorded(session))
        readOnlyEtc = false
        XCTAssertEqual(try applier.apply(Self.full, interface: "tun0", in: session), .resolvconf, "where /etc is writable")
        applier.revert(in: session)
        readOnlyEtc = true
        try "resolv_conf_mv=yes\nresolv_conf_mv=no\n".write(toFile: root + "/etc/resolvconf.conf", atomically: false, encoding: .utf8)
        XCTAssertEqual(try applier.apply(Self.full, interface: "tun0", in: session), .resolvconf, "in place: fine")
        applier.revert(in: session)
    }

    func testResolvConfMvSetting() throws {
        let path = base + "/resolvconf.conf"
        let cases: [(String, Bool)] = [
            ("resolv_conf_mv=yes\n", true), ("  resolv_conf_mv=\"Yes\" # rename\n", true), ("resolv_conf_mv=1", true),
            ("\tresolv_conf_mv='on';\n", true), ("resolv_conf_mv=true\n", true),
            ("# resolv_conf_mv=yes\n", false), ("resolv_conf_mv=no\n", false), ("resolv_conf_mv=\n", false),
            ("resolv_conf_mv=yes\nresolv_conf_mv=NO\n", false), ("resolv_conf=/etc/resolv.conf\n", false), ("", false)
        ]
        for (text, replaces) in cases {
            try text.write(toFile: path, atomically: false, encoding: .utf8)
            XCTAssertEqual(DNSApplier.replacesResolvConf(path), replaces, text)
        }
        XCTAssertFalse(DNSApplier.replacesResolvConf(base + "/none"))
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

    static let up27 = [
        "dev": "tun0", "script_type": "dns-up", "dns_server_1_address_1": "192.0.2.53",
        "dns_server_1_address_2": "2001:db8::53", "dns_search_domain_1": "corp.example.com"
    ]

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
        let up = [
            "dev": "tun0", "script_type": "route-up", "foreign_option_1": "dhcp-option DNS 192.0.2.53",
            "foreign_option_2": "dhcp-option DOMAIN corp.example.com", "redirect_gateway": "2"
        ]
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
        for directory in [
            base, runRoot, runRoot + "/\(me)", session.path + "/x", runRoot + "/x/acme", runRoot + "/0\(me)/acme",
            runRoot + "/\(me)/other"
        ] {
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

    func makeDNSDaemon(_ configure: (inout Daemon.Options) -> Void = { _ in }) throws -> Daemon {
        _ = FileManager.default.createFile(
            atPath: hook, contents: Data("#!/bin/sh\nexit 0\n".utf8),
            attributes: [.posixPermissions: 0o755])
        let system = self.system, hook = self.hook
        return try makeDaemon {
            $0.dns = system
            $0.dnsHook = hook
            configure(&$0)
        }
    }

    /// The daemon reaps a tool while the run root's lock is held elsewhere: the session's DNS cannot be
    /// restored yet, so its directory stays with the record only (no config, no auth file), the profile
    /// cannot start again over it, and the daemon tries again until it is restored.
    func testSessionWhoseDNSIsNotRestoredYetIsKept() throws {
        let daemon = try makeDNSDaemon {
            $0.dnsLockTimeout = 0.2
            $0.dnsRetryInterval = 0.3
        }
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startOpenVPN(start())).pid)
        let session = try HelperCore(runRoot: runRoot).openRunDir(profileID: "acme", uid: me)
        try applier.apply(Self.full, interface: "tun0", in: session)  // as the hook would
        let held = try applier.lock()
        kill(pid, SIGKILL)
        XCTAssertTrue(eventually { (try? self.response(daemon.socketPath, .status))?.running == [:] })
        XCTAssertTrue(
            eventually { PreviousInstance.entries(session.path) == [DNSRecord.fileName] },
            "\(PreviousInstance.entries(session.path))")
        XCTAssertEqual(resolvConfText, DNSFileBackendTests.applied)
        let refused = try response(daemon.socketPath, .startOpenVPN(start()))
        XCTAssertFalse(refused.ok)
        XCTAssertTrue(refused.error?.contains("not restored yet") == true, refused.error ?? "")
        close(held)
        XCTAssertTrue(eventually { self.resolvConfText == Self.original })
        XCTAssertTrue(eventually { !self.exists(session.path) })
        let again = try response(daemon.socketPath, .startOpenVPN(start()))
        XCTAssertTrue(again.ok, again.error ?? "")
        XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, again.pid)
    }

    /// A starting daemon that cannot restore what an earlier one left (here the lock is held) keeps
    /// the session's record and the baseline, removes everything else of the session (its secrets
    /// among it), and tries again until it is restored.
    func testStartingDaemonKeepsWhatItCouldNotRestore() throws {
        let session = try session()
        try "alice\npw123456\n".write(toFile: session.path + "/auth", atomically: false, encoding: .utf8)
        try applier.apply(Self.full, interface: "tun0", in: session)
        let held = try applier.lock()
        _ = try makeDNSDaemon {
            $0.dnsLockTimeout = 0.2
            $0.dnsRetryInterval = 0.3
        }
        XCTAssertEqual(PreviousInstance.entries(session.path), [DNSRecord.fileName])
        XCTAssertTrue(exists(baselinePath))
        XCTAssertEqual(resolvConfText, DNSFileBackendTests.applied)
        close(held)
        XCTAssertTrue(eventually { self.resolvConfText == Self.original })
        XCTAssertTrue(eventually { !self.exists(session.path) && !self.exists(self.baselinePath) })
    }

    /// The same when the file cannot be read (grown too large meanwhile): the baseline, the only copy
    /// of the file as it was, is never swept away, and is restored once it can be.
    func testStartingDaemonKeepsTheBaselineWhileRestoringFails() throws {
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        let applied = resolvConfText
        try (applied + String(repeating: "#\n", count: DNSApplier.maxResolvConfBytes))
            .write(toFile: resolvConf, atomically: false, encoding: .utf8)
        _ = try makeDNSDaemon { $0.dnsRetryInterval = 0.3 }
        XCTAssertTrue(exists(baselinePath))
        XCTAssertNotNil(recorded(session))
        try applied.write(toFile: resolvConf, atomically: false, encoding: .utf8)
        XCTAssertTrue(eventually { self.resolvConfText == Self.original })
        XCTAssertTrue(eventually { !self.exists(self.baselinePath) && !self.exists(session.path) })
    }

    func log() -> String { (try? String(contentsOfFile: profileDir("acme") + "/vpn.log", encoding: .utf8)) ?? "" }

    func testOpenVPN26RunsTheHookAsRouteUpAndDown() throws {
        let daemon = try makeDNSDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startOpenVPN(start())).pid)
        let runDir = PT.sessionDir(uid: me, profileID: "acme", runRoot: runRoot)
        XCTAssertTrue(eventually { self.log().contains("fake openvpn") })
        XCTAssertTrue(
            log().contains(
                "--auth-user-pass \(runDir)/auth --script-security 2 --route-up \(runDir)/dns-hook "
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
            try applier.apply(Self.full, interface: "tun0", in: session)  // as the hook would
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

    /// Overlapping sessions of an earlier daemon on the file backend: every one reverted, in whatever
    /// order the run root lists them, and the baseline is back.
    func testStartingDaemonRevertsOverlappingSessions() throws {
        indexes.set(["tun0": 7, "tun1": 8])
        try applier.apply(Self.full, interface: "tun0", in: try session("one"))
        try applier.apply(DNSFileBackendTests.tun1, interface: "tun1", in: try session("two"))
        _ = try makeDNSDaemon()
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertFalse(exists(baselinePath))
    }

    /// An earlier daemon died between the steps of a revert (the record gone, the file not restored):
    /// the baseline no session claims is restored.
    func testStartingDaemonRestoresAnUnclaimedBaseline() throws {
        let session = try session()
        try applier.apply(Self.full, interface: "tun0", in: session)
        DNSRecord.remove(in: session)
        _ = try makeDNSDaemon()
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertFalse(exists(baselinePath))
    }

    func testArguments() {
        let common =
            HelperCore.ignoredPushPrefixes.flatMap { ["--pull-filter", "ignore", $0] } + [
                "--server-poll-timeout", "10", "--config", "/c", "--verb", "3", "--management", "/m", "unix", "--management-client-user", "alice",
                "--auth-nocache", "--remap-usr1", "SIGTERM", "--connect-retry-max", "3", "--tls-version-min", "1.2"
            ]
        XCTAssertEqual(
            HelperCore.openVPNArguments(
                configPath: "/c", mgmtSocket: "/m", clientUser: "alice", authFile: nil,
                dnsUpdown: "/r/dns-hook", hasDNSUpdown: false),
            common + ["--script-security", "2", "--route-up", "/r/dns-hook", "--down", "/r/dns-hook", "--down-pre"])
        XCTAssertEqual(
            HelperCore.openVPNArguments(
                configPath: "/c", mgmtSocket: "/m", clientUser: "alice", authFile: nil,
                dnsUpdown: "/r/dns-hook"),
            common + ["--script-security", "2", "--dns-updown", "/r/dns-hook"], "as the Mac's")
    }
}
