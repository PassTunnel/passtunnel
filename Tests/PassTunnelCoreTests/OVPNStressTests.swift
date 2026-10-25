import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelVPNConfig

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

    /// A config that makes OpenVPN a server (which runs server-side hooks such as `client-crresponse` for
    /// any client that connects), or a standalone command, is refused however it is written.
    func testServerAndStandaloneModes() {
        let server = "mode server\ntls-server\ndev tun\nport 1194\nclient-crresponse \"/tmp/x y\"\n"
        XCTAssertEqual(violations(server).map(\.directive), ["mode", "tls-server", "client-crresponse"])
        XCTAssertEqual(violations("server 10.8.0.0 255.255.255.0\nserver-ipv6 2001:db8::/64\n").count, 2)
        for line in ["mode server", "--MODE server", "mode SERVER", "mode \"server\"", "mode", "mode p2p server",
                     "mode p2p x", "setenv opt mode server", "--setenv opt --mode server", "mode p2p\\ "] {
            XCTAssertEqual(violations("client\n\(line)\n").map(\.line), [2], line)
            XCTAssertEqual(violations("<connection>\nremote vpn.example.com\n\(line)\n</connection>\n").map(\.line), [3], line)
        }
        XCTAssertEqual(violations("<mode>\np2p\n</mode>\n").count, 1, "as a block")
        for ok in ["mode p2p", "--mode p2p", "MODE P2P", "mode 'p2p'", "setenv opt mode p2p"] {
            XCTAssertTrue(violations("client\n\(ok)\n").isEmpty, ok)
        }
        for line in ["mktun", "rmtun", "--mktun", "MKTUN", "setenv opt rmtun", "version", "help", "test-crypto",
                     "show-ciphers", "show-tls", "show-curves", "show-gateway 192.0.2.1", "inetd nowait",
                     "client-crresponse /tmp/x", "memstats /tmp/x"] {
            XCTAssertEqual(violations("client\n\(line)\n").map(\.line), [2], line)
        }
    }

    /// `dev` must be a device type: on macOS a `tap` device (or a `tun` device without utun) is opened as
    /// `/dev/<dev>`, so a name with a path or naming another device would be opened as root.
    func testDeviceNames() {
        for name in ["../private/tmp/x1", "tap/../../x1", "tun/x", "tun.1", "disk2", "rdisk0", "bpf0", "ttys000",
                     "TUN", "Tap0", "", "tun 0", "tun\\ 0", "tunç", "nul", "tu", "-tun", "\"tun0\" x", "tun\u{0301}"] {
            let line = name.hasPrefix("\"") || name.contains("\\") ? "dev \(name)" : "dev \"\(name)\""
            XCTAssertEqual(violations("client\n\(line)\n").map(\.directive), ["dev"], line)
            XCTAssertEqual(violations("client\nsetenv opt --DEV \"\(name)\"\n").map(\.directive), ["dev"], name)
            XCTAssertEqual(violations("<connection>\n\(line)\n</connection>\n").count, 1, line)
        }
        XCTAssertEqual(violations("dev\n").count, 1, "no name")
        XCTAssertEqual(violations("<dev>\ntun0\n</dev>\n").count, 1, "as a block")
        for name in ["tun", "tap", "utun", "null", "tun0", "tap12", "utun7", "tun-work", "tap_lab", "tunVPN"] {
            XCTAssertTrue(violations("client\ndev \(name)\ndev-type tap\n").isEmpty, name)
        }
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

    /// OpenVPN skips a BOM only at the start of the file. A U+FEFF that starts any other line is refused,
    /// so stripping the lines above it can never turn it into the file's BOM (a fuzzer finding).
    func testByteOrderMarkOnlyAtTheStartOfTheFile() throws {
        let found = "\u{FEFF}static-challenge \"Eode\" 1\n\u{FEFF}static-challenge \"Eode\""
        XCTAssertEqual(violations(found).map(\.line), [2])
        XCTAssertEqual(violations(found).map(\.reason), [OVPNSanitizer.misplacedBOM])
        XCTAssertEqual(violations("client\n\u{FEFF}up /tmp/x\n").map(\.line), [2])
        XCTAssertEqual(violations("client\n\u{FEFF}remote vpn.example.com\n").map(\.line), [2], "a harmless directive too")
        XCTAssertEqual(violations("client\n\u{FEFF}# note\n").map(\.line), [2], "a comment too")
        XCTAssertEqual(violations("client\n\u{FEFF}\n").map(\.line), [2], "a BOM alone")
        XCTAssertEqual(violations("<ca>\n\u{FEFF}-----BEGIN CERTIFICATE-----\n</ca>\n").map(\.line), [2], "inside a block")
        XCTAssertEqual(violations("<connection>\n\u{FEFF}remote vpn.example.com\n</connection>\n").map(\.line), [2])
        XCTAssertEqual(violations("\u{FEFF}\u{FEFF}client\n").map(\.line), [1], "a second BOM on the first line")
        XCTAssertTrue(violations("\u{FEFF}client\nremote vpn.example.com 1194\u{FEFF}\n").isEmpty,
                      "elsewhere U+FEFF is an ordinary character")
        XCTAssertEqual(try OVPNSanitizer.sanitize("\u{FEFF}static-challenge \"Code\" 1\nclient\n"), "client\n",
                       "the file's BOM goes with its stripped first line")
    }

    /// The fuzzer's property, with a BOM before any of the lines: whatever is accepted is accepted again
    /// unchanged, and only the first line may start with a BOM.
    func testIdempotentWithByteOrderMarks() throws {
        let pieces = ["static-challenge \"Code\" 1", "<static-challenge>\nx\n</static-challenge>", "client",
                      "# note", "", "<ca>\nx\n</ca>", "remote vpn.example.com"]
        for a in pieces { for b in pieces { for c in pieces {
            for mask in 0..<8 {
                let text = [a, b, c].enumerated()
                    .map { mask & (1 << $0.offset) != 0 ? "\u{FEFF}" + $0.element : $0.element }
                    .joined(separator: "\n")
                guard let once = try? OVPNSanitizer.sanitize(text) else {
                    XCTAssertTrue(mask > 1, "only a later BOM is refused: \(text.debugDescription)")
                    continue
                }
                XCTAssertTrue(mask <= 1, "a later BOM is refused: \(text.debugDescription)")
                XCTAssertEqual(try OVPNSanitizer.sanitize(once), once, text.debugDescription)
            }
        }}}
    }

    func testVerbosityAfterABOM() {
        XCTAssertEqual(OVPNSanitizer.verbosity(of: "\u{FEFF}verb 1\n"), 1, "the file's BOM is skipped, as by sanitize")
        XCTAssertNil(OVPNSanitizer.verbosity(of: "client\n\u{FEFF}verb 1\n"), "a later BOM is part of the name")
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

    /// OpenVPN rejects a backslash before anything but `\`, `"` or whitespace (outside single quotes)
    /// and aborts on that line; reading it as a literal could make the two parsers disagree, e.g.
    /// `<c\a>` would open a verbatim block for the sanitizer only.
    func testBadBackslashIsRejectedLikeOpenVPN() {
        for line in ["remote vpn\\.example.com", "<c\\a>", "verify-x509-name \"CN=Acme\\x\" name",
                     "remote \\'vpn.example.com'", "\\#remote x", "\\;remote x", "remote vpn.example.com\\",
                     "setenv opt foo\\q"] {
            XCTAssertEqual(violations(line + "\n").map(\.reason), [OVPNSanitizer.badBackslash], line)
        }
        // The escapes OpenVPN accepts, and backslashes inside single quotes (no escaping there).
        for line in ["remote vpn\\ example.com 1194", "verify-x509-name \"CN=Acme \\\"VPN\\\"\" name",
                     "verify-x509-name 'C:\\vpn\\x' name", "remote vpn\\\\.example.com",
                     "remote vpn.example.com\\\r", "remote \\\"vpn\" 1194"] {
            XCTAssertTrue(violations(line + "\n").isEmpty, line)
        }
        XCTAssertEqual(try OVPNSanitizer.sanitize("<ca>\nC:\\x\\y\n</ca>\n"), "<ca>\nC:\\x\\y\n</ca>\n",
                       "inline blocks are not tokenized")
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
            ("NUL in v6 host", { $0.host = "2001:db8::1\u{0}\nset-dns = 1" }),
            ("newline in zone id", { $0.host = "fe80::1%en0\nset-dns = 1" }),
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
        XCTAssertEqual(lines.count, 11, "header, 9 settings, final newline")
        XCTAssertNoThrow(try config { $0.username = "ålice şifre" }.render())
        // A zone id of ASCII letters and digits is accepted (checked in Swift: macOS inet_pton takes
        // any bytes after "%").
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

    /// A file saved with a BOM is embedded without it: inside the block it would start a later line.
    func testReferencedFileBOMIsNotEmbedded() throws {
        let configs = try dir("bom")
        try Data("\u{FEFF}CERT\r\n".utf8).write(to: configs.appendingPathComponent("ca.crt"))
        let out = try OVPNInliner.prepare("\u{FEFF}client\r\nca ca.crt\r\n", baseDir: configs)
        XCTAssertEqual(out, "client\n<ca>\nCERT\n</ca>\n")
    }

    /// The inliner keeps a later BOM line as it is, and the sanitizer's check refuses it.
    func testLaterBOMLineIsRefusedOnImport() throws {
        let configs = try dir("later-bom")
        try Data("CERT\n".utf8).write(to: configs.appendingPathComponent("ca.crt"))
        let text = "client\n\u{FEFF}ca ca.crt\n"
        XCTAssertEqual(try OVPNInliner.inline(text, baseDir: configs), text)
        XCTAssertThrowsError(try OVPNInliner.prepare(text, baseDir: configs)) {
            XCTAssertEqual($0 as? PTError, .ovpnNotAllowed(["line 2: (line) (\(OVPNSanitizer.misplacedBOM))"]))
        }
        XCTAssertEqual(OVPNAnalyzer.analyze("client\n\u{FEFF}remote vpn.example.com\n").remotes, [],
                       "the analyzer does not read the line either")
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

// MARK: - Inliner and sanitizer read lines alike

/// The inliner rewrites and strips configs before the sanitizer sees them: a line the two tokenized
/// differently could be rewritten into something the sanitizer never checked.
final class OVPNTokenizerParityTests: CoreTestCase {
    /// What the inliner must see for `line`: the sanitizer's tokens, nil when it has none or rejects the line.
    func expected(_ line: String) -> [String]? {
        guard case .success(let tokens) = OVPNSanitizer.tokenize(line), !tokens.isEmpty else { return nil }
        return tokens
    }

    static let samples = [
        "", "   ", "\t\r", "# ca ca.crt", "; ca ca.crt", "  # x", "ca ca.crt", "--ca ca.crt", "ca ca.crt # note",
        "ca ca.crt;x", "ca \"my ca.crt\"", "ca 'my ca.crt'", "ca my\\ ca.crt", "ca \"my \\\"ca\\\".crt\"",
        "ca my\\\\ca.crt", "ca 'back\\slash'", "ca c\\a.crt", "ca \\x", "ca ca.crt\\", "ca \"open",
        "ca 'open", "ca \"a\"\"b\"", "ca a\"b\"", "ca \\#x", "ca \\;x", "\\#ca x", "ca\u{0B}x\u{0C}y",
        "<ca>", "</ca>", "<auth-user-pass>", "--<auth-user-pass>", "auth-user-pass [inline]",
        "auth-user-pass\\q [inline]", "auth-user-pass\\ [inline]", "http-proxy-user-pass \"[inline]\"",
        "remote vpn.example.com 1194 \\u0041", "setenv opt up\\ /tmp/x", "key \"a b\" 'c d' e\\ f",
        "\u{FEFF}client", "ca ca.crt\u{00A0}x", "ca \"tab\there\"",
    ]

    func testSameTokensAsTheSanitizer() {
        for line in Self.samples {
            XCTAssertEqual(OVPNInliner.tokenize(line), expected(line), line.debugDescription)
        }
    }

    func testSameTokensForRandomLines() {
        var rng = SystemRandomNumberGenerator()
        let alphabet: [Character] = ["a", "b", " ", "\t", "\r", "\\", "\"", "'", "#", ";", "<", ">", "/", "\u{0B}"]
        for _ in 0..<5000 {
            let line = String((0..<Int.random(in: 0...12, using: &rng)).map { _ in alphabet.randomElement(using: &rng)! })
            XCTAssertEqual(OVPNInliner.tokenize(line), expected(line), line.debugDescription)
        }
    }

    func testBlockTagsAndEndsAlike() {
        for token in ["<ca>", "--<ca>", "<", "<>", "</ca>", "<a b>", "-<ca>", "<CA>"] {
            XCTAssertEqual(OVPNInliner.blockTag(token), OVPNSanitizer.blockTag(token), token)
        }
        for line in ["</ca>", "  </ca>", "\t\r</CA> x", "x</ca>", "</ca", "\u{0B}</ca>"] {
            XCTAssertEqual(OVPNInliner.isBlockEnd(line, tag: "ca"), OVPNSanitizer.isBlockEnd(line, tag: "ca"), line)
        }
    }

    /// OpenVPN refuses `\a`: the inliner used to read it as `a` and embed ca.crt, hiding the line.
    func testRejectedEscapeIsLeftForTheSanitizer() throws {
        let dir = home.appendingPathComponent("escape", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".utf8).write(to: dir.appendingPathComponent("ca.crt"))
        let text = "client\nca c\\a.crt\n"
        XCTAssertEqual(try OVPNInliner.inline(text, baseDir: dir), "client\nca c\\a.crt\n")
        XCTAssertThrowsError(try OVPNInliner.prepare(text, baseDir: dir)) { error in
            guard case .ovpnNotAllowed(let lines)? = error as? PTError else { return XCTFail("\(error)") }
            XCTAssertEqual(lines.count, 1)
            XCTAssertTrue(lines[0].hasPrefix("line 2:"), lines[0])
        }
        // Escapes OpenVPN accepts still work.
        try Data("x\n".utf8).write(to: dir.appendingPathComponent("my ca.crt"))
        XCTAssertEqual(try OVPNInliner.inline("ca my\\ ca.crt", baseDir: dir), "<ca>\nx\n</ca>")

        // The file's BOM does not hide a credential block on the first line.
        let first = OVPNInliner.strippingCredentials("\u{FEFF}<auth-user-pass>\nalice\npw\n</auth-user-pass>\nclient\n")
        XCTAssertEqual(first.text, "auth-user-pass\nclient\n")
        XCTAssertEqual(first.username, "alice")
        XCTAssertEqual(OVPNInliner.strippingCredentials("\u{FEFF}auth-user-pass [inline]\n").text, "auth-user-pass\n")

        // Credential stripping keeps a line it cannot read; the sanitizer then rejects it.
        let odd = "client\nauth-user-pass\\q [inline]\n"
        XCTAssertEqual(OVPNInliner.strippingCredentials(odd).text, odd)
        XCTAssertThrowsError(try OVPNSanitizer.sanitize(odd))
    }
}
