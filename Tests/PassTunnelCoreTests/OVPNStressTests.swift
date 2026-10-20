import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelShared

/// Hostile OpenVPN configs: the sanitizer is the last gate before the helper runs openvpn as root.
final class OVPNSanitizerFuzzTests: XCTestCase {
    func violations(_ text: String) -> [OVPNSanitizer.Violation] {
        do {
            _ = try OVPNSanitizer.sanitize(text)
            return []
        } catch let f as OVPNSanitizer.Failure {
            return f.violations
        } catch {
            XCTFail("unexpected error \(error)")
            return []
        }
    }

    /// Every way of writing a forbidden directive is caught, wherever it appears.
    func testEveryForbiddenDirectiveInEverySpelling() {
        let names = Array(OVPNSanitizer.forbiddenDirectives) + ["management", "management-client",
            "management-client-user", "management-hold", "log", "log-append"]
        for name in names {
            let spellings = [name, "--" + name, "---" + name, name.uppercased(), "\"\(name)\"", "'\(name)'",
                             "\t  " + name, "setenv opt " + name, "--setenv opt --" + name]
            for spelled in spellings {
                for ending in ["\n", "\r\n", ""] {
                    let text = "client\n\(spelled) /tmp/x\(ending)remote vpn.example.com 1194\n"
                    XCTAssertEqual(violations(text).map(\.line), [2], "\(spelled.debugDescription) \(ending.debugDescription)")
                }
            }
            XCTAssertEqual(violations("<connection>\nremote vpn.example.com\n\(name) /tmp/x\n</connection>\n").map(\.line),
                           [3], "inside <connection>: \(name)")
            XCTAssertEqual(violations("<\(name)>\nx\n</\(name)>\n").count, 1, "as a block: \(name)")
        }
    }

    /// Options that load code, write files or read root-only files although they are not "scripts".
    func testCodeLoadingFileWritingAndCredentialFileOptions() {
        let cases = [
            "show-pkcs11-ids /tmp/evil.dylib",           // dlopen()s the given provider as root
            "show-pkcs11-ids /tmp/evil.dylib 1",
            "genkey secret /etc/sudoers",                // writes (truncates) the file as root, then exits
            "genkey tls-crypt-v2-client /etc/x",
            "port-share 127.0.0.1 443 /etc/journal",     // writes journal files into a directory
            "socks-proxy proxy.example.com 1080 /var/root/creds",   // sends the file's first two lines to the proxy
            "socks-proxy proxy.example.com 1080 stdin",
            "auth-gen-token-secret /var/root/key",       // reads a file
        ]
        for line in cases {
            XCTAssertEqual(violations("client\n\(line)\n").map(\.line), [2], line)
            XCTAssertEqual(violations("client\n--\(line.uppercased())\n").count, 1, line)
        }
        XCTAssertTrue(violations("socks-proxy proxy.example.com 1080\nsocks-proxy proxy.example.com\n").isEmpty)
        XCTAssertTrue(violations("auth-gen-token-secret [inline]\n<auth-gen-token-secret>\nk\n</auth-gen-token-secret>\n").isEmpty)
        XCTAssertEqual(violations("<show-pkcs11-ids>\n/tmp/evil.dylib\n</show-pkcs11-ids>\n").count, 1)
    }

    func testScriptSecurityValues() {
        for ok in ["0", "1", "-1", "01"] { XCTAssertTrue(violations("script-security \(ok)\n").isEmpty, ok) }
        for bad in ["2", "3", "+2", "\"2\"", "'3'", "2 system", "99999999999999999999", "0x2", "two", ""] {
            XCTAssertEqual(violations("script-security \(bad)\n").count, 1, bad)
        }
    }

    func testCommentsBOMAndWhitespace() throws {
        let harmless = "\u{FEFF}# up /tmp/x\n;plugin x\n   #down\nremote vpn.example.com 1194 # up /tmp/x\n\n\r\n \t \n"
        XCTAssertEqual(try OVPNSanitizer.sanitize(harmless), harmless, "byte-for-byte when nothing is stripped")
        XCTAssertEqual(violations("\u{FEFF}up /tmp/x\n").count, 1, "BOM before a directive on line 1")
        XCTAssertEqual(violations("\u{FEFF}--up /tmp/x\r\n").count, 1)
        XCTAssertEqual(violations("remote vpn.example.com\rup /tmp/x\n").count, 0,
                       "a lone CR is whitespace: `up` is an argument of remote, as OpenVPN reads it")
        XCTAssertTrue(violations("").isEmpty)
        XCTAssertTrue(violations("\u{FEFF}").isEmpty)
    }

    func testQuotingAndEscapes() {
        XCTAssertTrue(violations("remote \"vpn example\" 1194\nverify-x509-name 'CN=Acme, O=Acme' subject\n").isEmpty)
        for line in ["\"up\" \"/tmp/x y\"", "u\\p /tmp/x", "\"--plugin\" x", "\\-\\-down x"] {
            XCTAssertEqual(violations(line + "\n").count, 1, line)
        }
        // A closing quote ends the token and a quote inside a word is a plain character, as in
        // OpenVPN's parser: these name the options "u" and `pl""ugin`, which OpenVPN rejects as unknown.
        XCTAssertTrue(violations("'u'p /tmp/x\npl\"\"ugin x\n").isEmpty)
        XCTAssertEqual(violations("remote 'vpn.example.com\n").map(\.reason), ["unterminated quote"])
    }

    func testLineLengthAndNULs() {
        let at = "remote " + String(repeating: "a", count: OVPNSanitizer.maxLineBytes - 7)
        XCTAssertEqual(at.utf8.count, OVPNSanitizer.maxLineBytes)
        XCTAssertTrue(violations(at + "\n").isEmpty, "exactly at the limit")
        XCTAssertEqual(violations(at + "a\n").count, 1, "one byte over: OpenVPN would split the line")
        XCTAssertEqual(violations("remote " + String(repeating: "ş", count: 130) + "\n").count, 1, "bytes, not characters")
        XCTAssertEqual(violations("<ca>\nabc\u{0}up\n</ca>\n").count, 1, "NUL inside a block")
        XCTAssertEqual(violations("\u{0}\n").count, 1)
    }

    func testNestedAndBrokenBlocks() throws {
        XCTAssertTrue(violations("<connection>\nremote vpn.example.com\n<ca>\nx\n</ca>\n</connection>\n").isEmpty)
        XCTAssertEqual(violations("<connection>\n<connection>\nup /tmp/x\n</connection>\n</connection>\n").map(\.line), [3])
        XCTAssertEqual(violations("<connection>\nremote vpn.example.com\n").map(\.reason), ["block is never closed"])
        XCTAssertEqual(violations("<ca>\n<cert>\nup /tmp/x\n</cert>\n").map(\.reason), ["block is never closed"],
                       "inner tags in a verbatim block are content")
        XCTAssertEqual(violations("<ca>\nx\n</ca>up /tmp/x\nplugin y\n").map(\.line), [4],
                       "the rest of a closing line is ignored, as by OpenVPN")
        XCTAssertEqual(violations("<ca>\nx\n\u{0B}\u{0C}\r </ca>\nup /tmp/x\n").map(\.line), [4])
        XCTAssertTrue(violations("</connection>\n< ca >\n").isEmpty, "not blocks; OpenVPN rejects them as unknown")
        XCTAssertEqual(violations("<static-challenge>\nx\n</static-challenge>\nup /tmp/x\n").map(\.line), [4])
    }

    func testHugeConfigIsCheckedQuickly() throws {
        var text = "client\n"
        for i in 0..<60_000 { text += i % 1000 == 0 ? "<ca>\nAAAA\n</ca>\n" : "verb 3\n" }
        let started = Date()
        XCTAssertEqual(try OVPNSanitizer.sanitize(text), text)
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
        XCTAssertEqual(violations(text + "plugin /tmp/x.so\n").count, 1)
    }
}

final class FortiConfigFuzzTests: XCTestCase {
    func config(_ change: (inout FortiConfig) -> Void) -> FortiConfig {
        var c = FortiConfig(host: "vpn.example.com", username: "alice", password: "pw", otp: "123456")
        change(&c)
        return c
    }

    func testInjectionAndInvalidValues() {
        let digest = String(repeating: "ab", count: 32)
        let bad: [(String, (inout FortiConfig) -> Void)] = [
            ("= in host", { $0.host = "vpn.example.com=x" }), ("host with port", { $0.host = "vpn.example.com:443" }),
            ("bracketed v6", { $0.host = "[2001:db8::1]" }), ("bad v6", { $0.host = "2001:db8::1::2" }),
            ("leading dot", { $0.host = ".example.com" }), ("leading dash", { $0.host = "-x.example.com" }),
            ("long host", { $0.host = String(repeating: "a", count: 254) }), ("unicode host", { $0.host = "vpn.exämple.com" }),
            ("newline in host", { $0.host = "vpn.example.com\nset-dns = 1" }),
            ("port 0", { $0.port = 0 }), ("port -1", { $0.port = -1 }), ("port 65536", { $0.port = 65536 }),
            ("port max", { $0.port = Int.max }),
            ("digest + newline", { $0.trustedCert = digest + "\nuser-cert = /tmp/x" }),
            ("digest + space", { $0.trustedCert = digest + " " }), ("short digest", { $0.trustedCert = "abcd" }),
            ("tab in user", { $0.username = "al\tice" }), ("CR in password", { $0.password = "pw\rpppd-plugin = x" }),
            ("NBSP edge", { $0.password = "\u{00A0}pw" }), ("long password", { $0.password = String(repeating: "x", count: 256) }),
            ("long code", { $0.otp = String(repeating: "1", count: 65) }), ("newline code", { $0.otp = "123\n456" }),
            ("DEL", { $0.username = "alice\u{7F}" }), ("empty user", { $0.username = "" }),
        ]
        for (label, change) in bad { XCTAssertThrowsError(try config(change).render(), label) }
    }

    func testOddButSafeValuesStayOnTheirLine() throws {
        let text = try config {
            $0.username = "a = b # c"
            $0.password = String(repeating: "x", count: 255)
            $0.otp = String(repeating: "1", count: 64)
            $0.host = "2001:db8::1"
        }.render()
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        XCTAssertEqual(lines.filter { $0.hasPrefix("username = ") }, ["username = a = b # c"])
        XCTAssertEqual(lines.count, 10, "header, 8 settings, final newline")
        XCTAssertNoThrow(try config { $0.username = "ålice şifre" }.render())
        // A zone id is part of a valid IPv6 literal for inet_pton and cannot leave its line.
        XCTAssertNoThrow(try config { $0.host = "fe80::1%en0" }.render())
        XCTAssertNoThrow(try config { $0.otp = "" }.render(), "empty code: omitted")
        XCTAssertFalse(try config { $0.otp = "" }.render().contains("otp"))
    }
}

/// Making configs self-contained reads files as the user; a hostile config must not use that to
/// carry the user's private files to a server.
final class OVPNInlinerStressTests: CoreTestCase {
    func dir(_ name: String) throws -> URL {
        let d = home.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    func testCredentialsFileOutsideTheConfigFolderIsRefused() throws {
        let configs = try dir("downloads")
        try Data("alice\nhunter2\n".utf8).write(to: home.appendingPathComponent("private-creds.txt"))
        try FileManager.default.createSymbolicLink(at: configs.appendingPathComponent("link.txt"),
                                                   withDestinationURL: home.appendingPathComponent("private-creds.txt"))
        for ref in ["../private-creds.txt", home.appendingPathComponent("private-creds.txt").path, "link.txt", "/etc/hosts"] {
            let text = "client\nhttp-proxy proxy.example.com 8080\nhttp-proxy-user-pass \(ref)\n"
            XCTAssertThrowsError(try OVPNInliner.inline(text, baseDir: configs), ref) { error in
                XCTAssertEqual(error as? PTError, .ovpnReferencedFile(ref), ref)
            }
        }
        // Next to the config (or below it) is fine.
        try FileManager.default.createDirectory(at: configs.appendingPathComponent("sub"), withIntermediateDirectories: true)
        try Data("bob\npw\n".utf8).write(to: configs.appendingPathComponent("sub/proxy.txt"))
        let out = try OVPNInliner.inline("http-proxy-user-pass sub/proxy.txt\n", baseDir: configs)
        XCTAssertEqual(out, "<http-proxy-user-pass>\nbob\npw\n</http-proxy-user-pass>\n")
    }

    func testCertificatesMayLiveElsewhere() throws {
        let configs = try dir("configs")
        let shared = try dir("shared")
        try Data("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n".utf8).write(to: shared.appendingPathComponent("ca.crt"))
        try FileManager.default.createSymbolicLink(at: configs.appendingPathComponent("ca-link.crt"),
                                                   withDestinationURL: shared.appendingPathComponent("ca.crt"))
        for ref in ["../shared/ca.crt", "ca-link.crt", shared.appendingPathComponent("ca.crt").path] {
            XCTAssertTrue(try OVPNInliner.inline("ca \(ref)\n", baseDir: configs).hasPrefix("<ca>\n-----BEGIN"), ref)
        }
    }

    func testSymlinkTricksAreRefused() throws {
        let configs = try dir("cfg")
        let fm = FileManager.default
        try fm.createSymbolicLink(atPath: configs.appendingPathComponent("zero.crt").path, withDestinationPath: "/dev/zero")
        try fm.createSymbolicLink(atPath: configs.appendingPathComponent("loop-a").path, withDestinationPath: "loop-b")
        try fm.createSymbolicLink(atPath: configs.appendingPathComponent("loop-b").path, withDestinationPath: "loop-a")
        try fm.createSymbolicLink(atPath: configs.appendingPathComponent("dir.crt").path, withDestinationPath: "/tmp")
        try fm.createSymbolicLink(atPath: configs.appendingPathComponent("gone.crt").path, withDestinationPath: "missing")
        XCTAssertEqual(mkfifo(configs.appendingPathComponent("fifo.crt").path, 0o600), 0)
        for name in ["zero.crt", "loop-a", "dir.crt", "gone.crt", "fifo.crt", "/dev/stdin", "../../../../../../dev/random"] {
            XCTAssertThrowsError(try OVPNInliner.inline("ca \(name)\n", baseDir: configs), name)
        }
    }

    func testBOMAndCRLFConfigsAreInlined() throws {
        let configs = try dir("win")
        try Data("CERT\r\n".utf8).write(to: configs.appendingPathComponent("ca.crt"))
        let text = "\u{FEFF}ca ca.crt\r\nremote vpn.example.com 1194\r\n"
        let out = try OVPNInliner.prepare(text, baseDir: configs)
        XCTAssertEqual(out, "<ca>\nCERT\n</ca>\nremote vpn.example.com 1194\n")
    }

    func testContentThatOpenVPNWouldReadAsTheBlockEndIsRefused() throws {
        let configs = try dir("end")
        for body in ["A\n</ca>\nB", "A\n  </CA>\nB", "A\n\r</ca>\nB", "A\n\u{0B}</ca>\nB"] {
            try Data(body.utf8).write(to: configs.appendingPathComponent("ca.crt"))
            XCTAssertThrowsError(try OVPNInliner.inline("ca ca.crt\n", baseDir: configs), body.debugDescription) {
                XCTAssertEqual($0 as? PTError, .ovpnReferencedFile("ca.crt"))
            }
        }
    }

    func testHostileImportCreatesNothing() throws {
        let configs = try dir("hostile")
        for text in ["client\nshow-pkcs11-ids /tmp/evil.dylib\n", "client\ngenkey secret /etc/x\n",
                     "client\nsocks-proxy p.example.com 1080 /etc/master.passwd\n", "client\nca /etc/does-not-exist\n"] {
            let url = configs.appendingPathComponent("acme.ovpn")
            try Data(text.utf8).write(to: url)
            XCTAssertThrowsError(try store.importOVPN(url, name: "Acme"), text)
        }
        XCTAssertEqual(store.list(), [])
    }
}
