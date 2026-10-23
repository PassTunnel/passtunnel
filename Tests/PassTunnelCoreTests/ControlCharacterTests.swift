import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

/// Hosts and other values that end up in a C call or in a line-based file: a NUL, a line break or any
/// other control character is refused before either sees it (C stops reading at a NUL; a line break
/// starts a new setting).
final class HostControlCharacterTests: XCTestCase {
    /// Characters that must never be accepted anywhere in a host.
    static let controls: [String] = [
        "\u{0}", "\n", "\r", "\t", "\u{0B}", "\u{0C}", "\u{1B}", "\u{1F}", "\u{7F}", "\u{85}", "\u{9F}",
        "\u{2028}", "\u{2029}", " ", "\u{A0}",
    ]

    func config(host: String) -> FortiConfig {
        FortiConfig(host: host, username: "alice", password: "pw", otp: "123456")
    }

    /// The input the FortiConfig fuzzer found, split into fields the way the harness does.
    func testFuzzerFindingIsRejected() throws {
        let data = try XCTUnwrap(Data(base64Encoded: "MjAwMTpkYjg6OjEAAAAAAAAADB8fZXIfcEBzcyB3H29yZB8f"))
        let parts = data.split(separator: 0x1F, maxSplits: 6, omittingEmptySubsequences: false)
        func field(_ i: Int) -> String { i < parts.count ? String(decoding: parts[i], as: UTF8.self) : "" }
        let host = field(0)
        XCTAssertEqual(host, "2001:db8::1" + String(repeating: "\u{0}", count: 7) + "\u{0C}")
        XCTAssertFalse(FortiConfig.isValidHost(host))
        let config = FortiConfig(host: host, port: Int(field(1)) ?? 443, username: field(2), password: field(3),
                                 otp: field(4).isEmpty ? nil : field(4), trustedCert: field(5))
        XCTAssertThrowsError(try config.render()) { XCTAssertEqual($0 as? FortiConfig.ValidationError, .invalidHost) }
    }

    func testControlCharactersAreRejectedOnEveryPath() {
        let bases = ["2001:db8::1", "fe80::1%en0", "::ffff:203.0.113.5", "203.0.113.5", "vpn.example.com"]
        for base in bases {
            XCTAssertTrue(FortiConfig.isValidHost(base), base)
            for c in Self.controls {
                for host in [base + c, c + base, base + c + "\nuser-cert = /tmp/x", base + c + "x"] {
                    XCTAssertFalse(FortiConfig.isValidHost(host), host.debugDescription)
                    XCTAssertThrowsError(try config(host: host).render(), host.debugDescription)
                }
            }
        }
        // The cases a C-level check alone lets through.
        for host in ["2001:db8::1\u{0}\nuser-cert = /tmp/x", "203.0.113.5\u{0}\npinentry = /tmp/x",
                     "vpn.example.com\u{0}x", "fe80::1%en0\npinentry = /tmp/x", "fe80::1%en0 x"] {
            XCTAssertFalse(FortiConfig.isValidHost(host), host.debugDescription)
        }
    }

    func testIPv6IsStrict() {
        for good in ["2001:db8::1", "2001:DB8::A", "::", "::1", "1:2:3:4:5:6:7:8", "::ffff:192.0.2.1",
                     "fe80::1%en0", "fe80::1%utun10", "fe80::1%4", "fe80::1%" + String(repeating: "a", count: 15)] {
            XCTAssertTrue(FortiConfig.isValidHost(good), good)
        }
        for bad in ["2001:db8::1::2", "2001:db8::g", "fe80::1%", "fe80::1%en0.x", "fe80::1%-x", "fe80::1%en0%en1",
                    "fe80::1%" + String(repeating: "a", count: 16), "fe80::1%en0/64", "[2001:db8::1]",
                    "2001:db8::1/64", "2001:db8::١", ":", "%en0", "2001:db8::1%en0=x", "2001:db8::1#x"] {
            XCTAssertFalse(FortiConfig.isValidHost(bad), bad)
        }
    }

    func testRenderedHostStaysOnItsLine() throws {
        for host in ["fe80::1%en0", "::ffff:192.0.2.1", "203.0.113.5"] {
            let lines = try config(host: host).render().split(separator: "\n")
            XCTAssertEqual(lines.filter { $0.hasPrefix("host = ") }, ["host = \(host)"])
            XCTAssertEqual(lines.count, 10)
        }
    }

    // MARK: health check host

    func testHealthCheckRejectsControlCharacters() {
        for base in ["10.0.0.5", "intranet.example.com:443", "[2001:db8::1]:22", "fe80::1%en0", "[fe80::1%en0]"] {
            XCTAssertNotNil(HealthCheck.parse(base), base)
            for c in Self.controls where c != " " && c != "\t" && c != "\n" && c != "\r" {
                // Whitespace at the ends is trimmed; inside, and every other control character, is refused.
                XCTAssertNil(HealthCheck.parse(base + c + "x"), (base + c).debugDescription)
                XCTAssertNil(HealthCheck.parse("x" + c + base), (c + base).debugDescription)
            }
            for c in ["\u{0}", "\u{1B}", "\u{7F}", "\u{9F}"] {
                XCTAssertNil(HealthCheck.parse(base + c), (base + c).debugDescription)
            }
        }
        XCTAssertNil(HealthCheck.parse("10.0.0.5\u{0}-c 100"))
    }

    func testHealthCheckHostIsNeverAnOption() {
        XCTAssertNil(HealthCheck.parse("[-c::1]"))
        XCTAssertNil(HealthCheck.parse("[-c::1]:22"))
        XCTAssertNil(HealthCheck.parse("-c::1"))
        XCTAssertEqual(HealthCheck.parse("[2001:db8::1]"), .icmp6(host: "2001:db8::1"))
    }

    // MARK: profile fields

    func testSettingHostRejectsInvalidValues() throws {
        for bad in ["2001:db8::1\u{0}\nuser-cert = /tmp/x", "fe80::1%en0\npinentry = /tmp/x", "vpn.example.com:443",
                    "https://vpn.example.com", "vpn example.com", "vpn.example.com\u{0}"] {
            var p = Profile(id: "acme", name: "Acme", type: .forti)
            XCTAssertThrowsError(try ProfileFields.set(&p, key: "host", value: bad), bad.debugDescription) {
                XCTAssertEqual($0 as? PTError, .invalidField("host"))
            }
            XCTAssertEqual(p.host, "")
        }
        var p = Profile(id: "acme", name: "Acme", type: .forti)
        try ProfileFields.set(&p, key: "host", value: " fe80::1%en0 ")
        XCTAssertEqual(p.host, "fe80::1%en0")
        try ProfileFields.set(&p, key: "host", value: "")
        XCTAssertEqual(p.host, "")
        XCTAssertThrowsError(try ProfileFields.set(&p, key: "health_host", value: "10.0.0.5\u{0}x"))
    }

    // MARK: OpenVPN configs

    func testSanitizerRejectsNULInRemoteAndPaths() {
        for line in ["remote vpn.example.com\u{0}x 1194", "remote \"vpn.example.com\u{0}\" 1194",
                     "ca \"/etc/ssl/cert.pem\u{0}x\"", "<ca>\u{0}"] {
            let config = "client\n" + line + "\nauth-user-pass\n"
            XCTAssertThrowsError(try OVPNSanitizer.sanitize(config), line.debugDescription) { error in
                XCTAssertTrue((error as? OVPNSanitizer.Failure)?.violations
                    .contains(Violation(line: 2, directive: "(line)", reason: "contains a NUL byte")) == true, "\(error)")
            }
        }
        // Inside an inline block too.
        XCTAssertThrowsError(try OVPNSanitizer.sanitize("client\n<ca>\nAB\u{0}CD\n</ca>\n"))
    }

    typealias Violation = OVPNSanitizer.Violation

    func testInlinerRefusesNULInFilePaths() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("PassTunnelTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
            .write(to: dir.appendingPathComponent("ca.crt"), atomically: true, encoding: .utf8)
        XCTAssertNoThrow(try OVPNInliner.inline("ca ca.crt\n", baseDir: dir))
        for path in ["ca.crt\u{0}", "ca.crt\u{0}x", "\"ca.crt\u{0}../x\""] {
            XCTAssertThrowsError(try OVPNInliner.inline("ca \(path)\n", baseDir: dir), path.debugDescription) { error in
                guard case .ovpnReferencedFile? = error as? PTError else { return XCTFail("\(error)") }
            }
        }
    }
}

// MARK: - Final checks on files written for root processes

final class RenderedFileCheckTests: XCTestCase {
    let good = "# Generated by PassTunnel. Do not edit.\nhost = vpn.example.com\nport = 443\nusername = alice\n"
        + "password = pw\nca-file = /etc/ssl/cert.pem\nset-routes = 1\nset-dns = 0\npppd-use-peerdns = 0\n"

    func assertUnsafe(_ text: String, lines: Int = 9, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try FortiConfig.checkRendered(text, lineCount: lines), text.debugDescription,
                             file: file, line: line) { error in
            guard case .unsafeOutput? = error as? FortiConfig.ValidationError else {
                return XCTFail("\(error)", file: file, line: line)
            }
        }
    }

    func testEveryRenderedConfigPassesTheCheck() throws {
        XCTAssertNoThrow(try FortiConfig.checkRendered(good, lineCount: 9))
        let full = FortiConfig(host: "fe80::1%en0", port: 10443, username: "a = b # c", password: "p@ss word",
                               otp: "123456", trustedCert: String(repeating: "AB", count: 32), setDNS: true)
        let text = try full.render()
        XCTAssertNoThrow(try FortiConfig.checkRendered(text, lineCount: 11))
        XCTAssertEqual(text.split(separator: "\n").compactMap { $0.hasPrefix("#") ? nil : $0.components(separatedBy: " = ")[0] },
                       FortiConfig.renderedKeys)
    }

    func testTheCheckRefusesWhatAValidatorGapWouldLetThrough() {
        assertUnsafe(good.replacingOccurrences(of: "vpn.example.com", with: "vpn.example.com\u{0}"))
        assertUnsafe(good.replacingOccurrences(of: "port = 443", with: "port = 443\r"))
        assertUnsafe(good.replacingOccurrences(of: "alice", with: "al\u{1B}ice"))
        assertUnsafe(good.replacingOccurrences(of: "pw", with: "p\u{7F}w"))
        // An extra line, even with an expected key, or a key render() never writes.
        assertUnsafe(good.replacingOccurrences(of: "host = vpn.example.com\n", with: "host = vpn.example.com\nuser-cert = /tmp/x\n"),
                     lines: 10)
        assertUnsafe(good.replacingOccurrences(of: "host = vpn.example.com\n", with: "host = vpn.example.com\nuser-cert = /tmp/x\n"))
        assertUnsafe(good.replacingOccurrences(of: "set-dns = 0", with: "pinentry = /tmp/x"))
        assertUnsafe(good.replacingOccurrences(of: "set-dns = 0\n", with: "set-dns = 0\nset-dns = 1\n"), lines: 10)
        assertUnsafe(good.replacingOccurrences(of: "port = 443\nusername", with: "username = alice\nport = 443\nusername"),
                     lines: 10)
        // Not "key = value".
        assertUnsafe(good.replacingOccurrences(of: "port = 443", with: "port=443"))
        assertUnsafe(good.replacingOccurrences(of: "port = 443", with: "port = "))
        assertUnsafe(good.replacingOccurrences(of: "port = 443", with: " port = 443"))
        assertUnsafe(good.replacingOccurrences(of: "port = 443", with: "443"))
        assertUnsafe(good.replacingOccurrences(of: "port = 443\n", with: "\n"))
        // Line count and the final line break.
        assertUnsafe(good, lines: 8)
        assertUnsafe(String(good.dropLast()))
        assertUnsafe(good + "\n", lines: 10)
    }

    func testHelperLineFilesAreChecked() throws {
        XCTAssertNoThrow(try HelperCore.checkLines(HelperCore.authFileText(username: "alice", secret: "pw123456"),
                                                   count: 2, file: "auth"))
        XCTAssertNoThrow(try HelperCore.checkLines("1\n2\n/x\n/y\n\n", count: 5, file: "state"))
        for bad in [HelperCore.authFileText(username: "alice\nbob", secret: "pw"),
                    HelperCore.authFileText(username: "alice", secret: "pw\u{0}x"),
                    HelperCore.authFileText(username: "alice", secret: "pw\r"),
                    "alice\npw"] {
            XCTAssertThrowsError(try HelperCore.checkLines(bad, count: 2, file: "auth"), bad.debugDescription) {
                XCTAssertEqual($0 as? HelperCore.Failure, .unsafeFile("auth"))
            }
        }
        XCTAssertThrowsError(try HelperCore.checkLines("1\n2\n/x\n/y\nz\n/s\n", count: 5, file: "state"))
    }
}

// MARK: - Saving and importing

final class HostValidationStoreTests: CoreTestCase {
    func testSaveRejectsInvalidHosts() throws {
        var p = try store.create(name: "Acme Forti", type: .forti)
        for bad in ["2001:db8::1\u{0}\nuser-cert = /tmp/x", "fe80::1%en0\npinentry = /tmp/x", " vpn.example.com",
                    "vpn.example.com:443"] {
            p.host = bad
            assertThrows(.invalidField("host")) { try store.save(p) }
        }
        p.host = "vpn.example.com"
        p.healthHost = "10.0.0.5\u{0}x"
        assertThrows(.invalidField("health_host")) { try store.save(p) }
        p.healthHost = "10.0.0.5"
        try store.save(p)
        XCTAssertEqual(try store.get(p.id).host, "vpn.example.com")
        assertThrows(.invalidField("host")) { _ = try store.update(p.id) { $0.host = "vpn.example.com\u{0}x" } }
        XCTAssertEqual(try store.get(p.id).host, "vpn.example.com")
    }

    func testImportShareRejectsInvalidHostsAndLeavesNothing() throws {
        for (key, value, field) in [("host", #"2001:db8::1\u0000\nuser-cert = /tmp/x"#, "host"),
                                    ("host", #"fe80::1%en0\npinentry = /tmp/x"#, "host"),
                                    ("host", "vpn.example.com\\u0000", "host"),
                                    ("health_host", #"10.0.0.5\u0000x"#, "health_host")] {
            let json = #"{"passtunnel_profile":1,"profile":{"name":"Acme","type":"forti","\#(key)":"\#(value)"}}"#
            let url = try write(json, name: "acme.passtunnel")
            assertThrows(.invalidField(field)) { _ = try store.importShare(url, name: nil) }
            XCTAssertTrue(store.list().isEmpty, json)
        }
    }
}

// MARK: - The helper

extension HelperCoreTests {
    func testPrepareFortiRejectsControlCharactersInHost() throws {
        for host in ["2001:db8::1\u{0}\nuser-cert = /tmp/x", "fe80::1%en0\npinentry = /tmp/x",
                     "203.0.113.5\u{0}\nset-dns = 1", "vpn.example.com\u{0}"] {
            let s = FortiStart(profileID: "acme", profileDir: acmeDir, host: host, username: "alice",
                               password: "pw", logPath: acmeDir + "/vpn.log")
            XCTAssertThrowsError(try core().prepareForti(s, uid: me), host.debugDescription) {
                XCTAssertEqual($0 as? FortiConfig.ValidationError, .invalidHost)
            }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: acmeRunDir))
    }

    func testPathsWithNULAreRejected() {
        assertFails(try self.core().openProfileDir(self.acmeDir + "\u{0}/x", profileID: "acme", uid: self.me)) {
            if case .outsideProfilesRoot = $0 { return true }; return false
        }
        for log in [acmeDir + "\u{0}/x/vpn.log", acmeDir + "/vpn\u{0}.log", acmeDir + "/vpn\n.log"] {
            assertFails(try self.core().prepareOpenVPN(self.openVPNStart(log: log), uid: self.me)) {
                if case .invalidLogPath = $0 { return true }; return false
            }
        }
    }
}

// MARK: - Connecting

extension ConnectionManagerTests {
    /// A host written into profile.json by something other than PassTunnel is refused before the helper
    /// is asked for anything.
    func testConnectRefusesAnInvalidHostOnDisk() async throws {
        let p = try store.create(name: "Acme Forti", type: .forti)
        let url = store.dir(p.id).appendingPathComponent("profile.json")
        var json = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        json["host"] = "fe80::1%en0\npinentry = /tmp/x"
        json["password_mode"] = "ask"
        json["username"] = "alice"
        try JSONSerialization.data(withJSONObject: json).write(to: url)
        XCTAssertEqual(try store.get(p.id).host, "fe80::1%en0\npinentry = /tmp/x")

        let m = makeManager()
        do {
            try await m.connect(p.id, given: [.password: "pw"])
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? PTError, .invalidField("host"))
        }
        XCTAssertTrue(helper.starts.isEmpty)
    }
}
