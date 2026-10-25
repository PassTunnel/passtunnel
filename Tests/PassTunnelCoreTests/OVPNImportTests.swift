import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelVPNConfig

/// Import review: which refused lines are skipped, what the stored config becomes, and that nothing is
/// written before `commit`. The helper's sanitizer itself is unchanged (its golden cases are in
/// fixtures/ovpn-sanitizer.json); these tests check that an import never stores what it would refuse.
final class OVPNImportTests: CoreTestCase {
    let caPEM = "-----BEGIN CERTIFICATE-----\nMIIBCA==\n-----END CERTIFICATE-----\n"

    func folder(_ ovpn: String, name: String = "work.ovpn", files: [String: String] = [:]) throws -> URL {
        let dir = home.appendingPathComponent("Downloads-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for (file, text) in files { try Data(text.utf8).write(to: dir.appendingPathComponent(file)) }
        let url = dir.appendingPathComponent(name)
        try Data(ovpn.utf8).write(to: url)
        return url
    }

    func report(_ text: String) throws -> OVPNImportReport { try OVPNImportReport.make(text, baseDir: nil) }

    // MARK: rules

    /// Every directive the sanitizer refuses is decided here: a new one must be added to one of the lists.
    func testEveryForbiddenDirectiveIsDecided() {
        let skipped: Set<String> = [
            "up", "down", "route-up", "route-pre-down", "ipchange", "iproute", "dns-updown",
            "daemon", "cd", "chroot", "user", "group", "writepid", "status", "tmp-dir", "tls-export-cert",
        ]
        let blocking: Set<String> = [
            "tls-verify", "auth-user-pass-verify", "tls-crypt-v2-verify",
            "plugin", "engine", "providers", "pkcs11-providers", "show-pkcs11-ids",
            "config", "capath", "dev-node", "replay-persist", "client-config-dir", "ifconfig-pool-persist",
            "learn-address", "client-connect", "client-disconnect", "port-share", "genkey",
        ]
        XCTAssertEqual(skipped.union(blocking), OVPNSanitizer.forbiddenDirectives)
        XCTAssertTrue(skipped.isDisjoint(with: blocking))
        for name in OVPNSanitizer.forbiddenDirectives.sorted() {
            let r = try? report("client\n\(name) /tmp/x\n")
            XCTAssertEqual(r?.skipped.map(\.directive) ?? [], skipped.contains(name) ? [name] : [], name)
            XCTAssertEqual(r?.blocking.map(\.directive) ?? [], skipped.contains(name) ? [] : [name], name)
        }
        XCTAssertEqual(Set(OVPNSkipRules.skippable.keys), skipped)
    }

    func testLogAndManagementFamilies() throws {
        for name in ["log", "log-append", "management", "management-hold", "management-query-passwords",
                     "management-client-user", "management-up-down", "--management-signal"] {
            let r = try report("client\n\(name) x\n")
            XCTAssertEqual(r.blocking, [], name)
            XCTAssertEqual(r.skipped.count, 1, name)
        }
        for name in ["management-external-key", "management-external-cert", "management-client-auth", "logfile",
                     "management-something-new"] {
            let r = try report("client\n\(name)\n")
            XCTAssertEqual(r.skipped, [], name)
            XCTAssertEqual(r.blocking.map(\.directive), [name], name)
            XCTAssertNil(r.config, name)
        }
        XCTAssertEqual(try report("management-external-key\n").blocking.first?.description,
                       "line 1: management-external-key (the private key would come from another program)")
    }

    func testScriptSecurity() throws {
        for keep in ["script-security 1", "script-security 0", "script-security -1"] {
            let r = try report("client\n\(keep)\n")
            XCTAssertEqual(r.skipped, [], keep)
            XCTAssertEqual(r.config, "client\n\(keep)\n", keep)
        }
        for skip in ["script-security 2", "script-security 3 system", "script-security", "script-security x",
                     "setenv opt script-security 2", "--script-security \"2\""] {
            let r = try report("client\n\(skip)\nremote vpn.example.com\n")
            XCTAssertEqual(r.skipped.map(\.reason), [.scriptSecurity], skip)
            XCTAssertEqual(r.blocking, [], skip)
            XCTAssertEqual(r.config, "client\n# PassTunnel skipped: \(skip)\nremote vpn.example.com\n", skip)
        }
    }

    func testSetenv() throws {
        let metadata = "client\nsetenv CLIENT_CERT 0\nsetenv IV_GUI_VER \"Acme 1.0\"\nsetenv UV_X y\nsetenv FRIENDLY_NAME Work\n"
        XCTAssertEqual(try report(metadata).config, metadata)
        XCTAssertEqual(try report(metadata).skipped, [])

        let r = try report("client\nsetenv PATH /tmp\nsetenv BASH_ENV /tmp/x\nsetenv opt up /tmp/x.sh\nsetenv opt block-outside-dns\n")
        XCTAssertEqual(r.skipped.map(\.directive), ["setenv PATH", "setenv BASH_ENV", "up"])
        XCTAssertEqual(r.skipped.map(\.reason), [.environment, .environment, .program])
        XCTAssertEqual(r.config, "client\n# PassTunnel skipped: setenv PATH /tmp\n# PassTunnel skipped: setenv BASH_ENV /tmp/x\n"
                       + "# PassTunnel skipped: setenv opt up /tmp/x.sh\nsetenv opt block-outside-dns\n")
    }

    func testInlineBlocks() throws {
        // Block contents are not directives: kept as they are.
        let inside = "client\n<ca>\nup /tmp/x.sh\nplugin /tmp/x.so\n</ca>\n"
        XCTAssertEqual(try report(inside).config, inside)
        // A block of a refused directive is never skipped.
        for tag in ["up", "plugin", "config", "management", "dns-updown"] {
            let r = try report("client\n<\(tag)>\n/tmp/x\n</\(tag)>\n")
            XCTAssertEqual(r.skipped, [], tag)
            XCTAssertEqual(r.blocking.map(\.directive), ["<\(tag)>"], tag)
        }
        // An unclosed block blocks the file, even when a skippable line is in it.
        let open = try report("client\n<connection>\nremote vpn.example.com\nup /tmp/x\n")
        XCTAssertEqual(open.skipped.map(\.line), [4])
        XCTAssertEqual(open.blocking.map(\.description), ["line 2: <connection> (block is never closed)"])
        XCTAssertNil(open.config)
    }

    func testConnectionBlocks() throws {
        let text = "client\n<connection>\nremote vpn.example.com 443 tcp\nup /tmp/x.sh\n</connection>\n"
            + "<connection>\nremote vpn2.example.com\n  route-up \"/tmp/y z\"\n</connection>\n"
        let r = try report(text)
        XCTAssertEqual(r.skipped.map(\.line), [4, 8])
        XCTAssertEqual(r.skipped.map(\.text), ["up /tmp/x.sh", "route-up \"/tmp/y z\""])
        let config = try XCTUnwrap(r.config)
        XCTAssertEqual(config, "client\n<connection>\nremote vpn.example.com 443 tcp\n# PassTunnel skipped: up /tmp/x.sh\n</connection>\n"
                       + "<connection>\nremote vpn2.example.com\n# PassTunnel skipped: route-up \"/tmp/y z\"\n</connection>\n")
        XCTAssertNoThrow(try OVPNSanitizer.sanitize(config))
        XCTAssertEqual(r.servers, [OVPNAnalyzer.Server(host: "vpn.example.com", port: "443", tcp: true),
                                   OVPNAnalyzer.Server(host: "vpn2.example.com", port: "1194", tcp: false)])
    }

    func testCRLFAndBOM() throws {
        let r = try report("\u{FEFF}up /tmp/x.sh\r\nclient\r\nremote vpn.example.com\r\ndown /tmp/y\r\n")
        XCTAssertEqual(r.skipped.map(\.line), [1, 4])
        XCTAssertEqual(r.skipped.map(\.text), ["up /tmp/x.sh", "down /tmp/y"])
        // Without a folder nothing is inlined, so the line endings are kept; the comments have none.
        XCTAssertEqual(r.config, "# PassTunnel skipped: up /tmp/x.sh\nclient\r\nremote vpn.example.com\r\n# PassTunnel skipped: down /tmp/y\n")

        let url = try folder("\u{FEFF}client\r\nca ca.crt\r\nup /tmp/x.sh\r\nremote vpn.example.com\r\n", files: ["ca.crt": caPEM])
        let draft = try store.analyzeOVPN(url)
        XCTAssertEqual(draft.skipped.map(\.line), [3])
        XCTAssertEqual(draft.report.config, "client\n<ca>\n\(caPEM)</ca>\n# PassTunnel skipped: up /tmp/x.sh\nremote vpn.example.com\n")
    }

    /// The comment never grows past what OpenVPN reads as one line, and shows no control characters.
    func testLongAndControlCharacterLines() throws {
        let long = "up /tmp/" + String(repeating: "a", count: OVPNSanitizer.maxLineBytes - 8)
        XCTAssertEqual(long.utf8.count, OVPNSanitizer.maxLineBytes)
        let r = try report("client\n\(long)\n")
        let comment = try XCTUnwrap(r.config?.components(separatedBy: "\n")[1])
        XCTAssertEqual(comment.utf8.count, OVPNSanitizer.maxLineBytes)
        XCTAssertTrue(comment.hasPrefix("# PassTunnel skipped: up /tmp/aaa"))
        XCTAssertTrue(comment.hasSuffix("…"))
        XCTAssertNoThrow(try OVPNSanitizer.sanitize(r.config ?? ""))

        let tooLong = try report("client\n" + long + "a\n")
        XCTAssertEqual(tooLong.blocking.map(\.directive), ["(line)"])

        let escape = try report("client\nup /tmp/\u{1B}[2Jx\u{202E}y\tz\n")
        XCTAssertEqual(escape.skipped.first?.text, "up /tmp/\u{FFFD}[2Jx\u{FFFD}y z")
        XCTAssertEqual(escape.config, "client\n# PassTunnel skipped: up /tmp/\u{FFFD}[2Jx\u{FFFD}y z\n")
    }

    func testBlockingAndSkippedTogether() throws {
        let r = try report("client\nscript-security 2\nup /tmp/x.sh\ntls-verify /tmp/check.sh\nplugin /tmp/p.so\nca /etc/ssl/ca.pem\n")
        XCTAssertEqual(r.skipped.map(\.line), [2, 3])
        XCTAssertEqual(r.blocking.map(\.description), [
            "line 4: tls-verify (not allowed)", "line 5: plugin (not allowed)",
            "line 6: ca (references an external file; embed it inline as <ca>…</ca>)",
        ])
        XCTAssertEqual(r.blocking.map(\.text), ["tls-verify /tmp/check.sh", "plugin /tmp/p.so", "ca /etc/ssl/ca.pem"])
        XCTAssertNil(r.config)
    }

    // MARK: report

    func testLineNumbersAreTheFilesAfterEmbedding() throws {
        let url = try folder("client\nca ca.crt\ntls-auth ta.key 1\nup /tmp/x.sh\nplugin /tmp/p.so\n",
                             files: ["ca.crt": caPEM, "ta.key": "-----BEGIN OpenVPN Static key V1-----\nab\n-----END OpenVPN Static key V1-----\n"])
        let draft = try store.analyzeOVPN(url)
        XCTAssertEqual(draft.skipped.map(\.line), [4])
        XCTAssertEqual(draft.blocking.map(\.description), ["line 5: plugin (not allowed)"])
        XCTAssertEqual(draft.report.certificates, [
            OVPNImportReport.Certificate(name: "ca", file: "ca.crt"),
            OVPNImportReport.Certificate(name: "tls-auth", file: "ta.key"),
        ])
    }

    func testAnEmbeddedFileWithLongLinesBlocksAtItsLine() throws {
        let long = String(repeating: "A", count: 300)
        let url = try folder("client\nremote vpn.example.com\nca ca.crt\n", files: ["ca.crt": "\(long)\n\(long)\n"])
        let draft = try store.analyzeOVPN(url)
        XCTAssertEqual(draft.blocking.map(\.description), ["line 3: (line) (longer than 254 characters)"])
        XCTAssertEqual(draft.blocking.map(\.text), ["ca ca.crt"])
    }

    func testCertificatesServersAndSignIn() throws {
        let text = """
        client
        remote vpn.example.com 1194
        remote 2001:db8::1 443 tcp-client
        proto tcp
        <ca>
        x
        </ca>
        <cert>
        x
        </cert>
        <key>
        x
        </key>
        <ca>
        y
        </ca>
        peer-fingerprint AB:CD
        auth-user-pass
        static-challenge "Code" 1
        """
        let r = try report(text)
        XCTAssertEqual(r.certificates.map(\.name), ["ca", "cert", "key", "peer-fingerprint"])
        XCTAssertTrue(r.certificates.allSatisfy { $0.file == nil })
        XCTAssertEqual(r.servers, [OVPNAnalyzer.Server(host: "vpn.example.com", port: "1194", tcp: true),
                                   OVPNAnalyzer.Server(host: "2001:db8::1", port: "443", tcp: true)])
        XCTAssertEqual(r.passwordMode, .keychain)
        XCTAssertEqual(r.otpMode, .ask)
        XCTAssertEqual(r.otpDelivery, .separate)
        XCTAssertEqual(r.needs, [.username, .password, .codeSecret])
        XCTAssertEqual(r.missing, [.username, .password, .codeSecret])
        XCTAssertEqual(r.missing(username: "alice", password: "pw", codeSecret: false), [.codeSecret])
        XCTAssertEqual(r.missing(username: " ", password: "", codeSecret: true), [.username, .password])

        let certOnly = try report("client\nremote vpn.example.com\n<pkcs12>\nAA==\n</pkcs12>\n")
        XCTAssertEqual(certOnly.needs, [])
        XCTAssertEqual(certOnly.certificates.map(\.name), ["pkcs12"])
    }

    func testInlineCredentialsAreReportedNotStored() throws {
        let url = try folder("client\nremote vpn.example.com\n<auth-user-pass>\nalice\ns3cret\n</auth-user-pass>\nup /tmp/x\n")
        let draft = try store.analyzeOVPN(url)
        XCTAssertEqual(draft.report.username, "alice")
        XCTAssertEqual(draft.report.password, "s3cret")
        XCTAssertEqual(draft.skipped.map(\.line), [7])
        XCTAssertEqual(draft.report.config, "client\nremote vpn.example.com\nauth-user-pass\n# PassTunnel skipped: up /tmp/x\n")
        XCTAssertEqual(draft.suggestedName, "work")
        XCTAssertEqual(draft.needs, [.name, .username, .password])
        XCTAssertEqual(draft.missing, [])
        XCTAssertEqual(draft.missing(name: " ", username: "alice", password: "", codeSecret: false), [.name, .password])
    }

    /// What was stored reads back unchanged: nothing left to skip, nothing blocking.
    func testStoredConfigIsStable() throws {
        let r = try report("client\nup /tmp/x\nsetenv PATH /x\nlog-append /tmp/l\nremote vpn.example.com\n")
        let config = try XCTUnwrap(r.config)
        let again = try report(config)
        XCTAssertEqual(again.config, config)
        XCTAssertEqual(again.skipped, [])
        XCTAssertEqual(again.blocking, [])
    }

    /// Random configs of allowed, skippable and blocking lines: whatever is reported, the stored text is
    /// what the sanitizer accepts, its other lines are untouched, and nothing is stored with a blocking line.
    func testRandomConfigsKeepTheGuarantees() throws {
        let pieces = [
            "client", "remote vpn.example.com 1194", "up /tmp/x", "--down \"/tmp/a b\"", "script-security 2",
            "script-security 1", "setenv PATH /tmp", "setenv CLIENT_CERT 0", "setenv opt route-up /x", "plugin /x.so",
            "tls-verify /x", "<ca>", "</ca>", "<connection>", "</connection>", "log /tmp/l", "management 127.0.0.1 1",
            "management-external-key", "ca /etc/x", "# up /tmp/x", "static-challenge \"c\" 1", "auth-user-pass",
            "<auth-user-pass>", "</auth-user-pass>", "alice", "user nobody", "daemon", "up\\q", "up 'x", "\r", "",
            "\u{FEFF}up /x", "dns-updown force", "\tchroot /tmp", "config /etc/x", "iproute /x",
        ]
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<3000 {
            let lines = (0..<Int.random(in: 0...12, using: &rng)).map { _ in pieces.randomElement(using: &rng)! }
            let text = lines.joined(separator: Bool.random(using: &rng) ? "\n" : "\r\n")
            let rules = OVPNSkipRules.apply(text)
            let before = OVPNInliner.lines(text), after = OVPNInliner.lines(rules.text)
            XCTAssertEqual(before.count, after.count, text.debugDescription)
            let skippedLines = Set(rules.skipped.map(\.line))
            for (i, line) in after.enumerated() where !skippedLines.contains(i + 1) {
                XCTAssertEqual(line, before[i], text.debugDescription)
            }
            for n in skippedLines {
                let comment = after[n - 1]
                XCTAssertTrue(comment.hasPrefix(OVPNSkipRules.marker), text.debugDescription)
                XCTAssertLessThanOrEqual(comment.utf8.count, OVPNSanitizer.maxLineBytes)
                XCTAssertEqual(OVPNSanitizer.tokens(of: comment), [])
            }
            if rules.blocking.isEmpty {
                XCTAssertNoThrow(try OVPNSanitizer.sanitize(rules.text), text.debugDescription)
                let report = try OVPNImportReport.make(text, baseDir: nil)
                let config = try XCTUnwrap(report.config, text.debugDescription)
                XCTAssertNoThrow(try OVPNSanitizer.sanitize(config), text.debugDescription)
                XCTAssertEqual(OVPNSkipRules.apply(rules.text), .init(text: rules.text, skipped: [], blocking: []))
            } else {
                XCTAssertThrowsError(try OVPNSanitizer.sanitize(text), text.debugDescription)
                XCTAssertNil(try OVPNImportReport.make(text, baseDir: nil).config)
            }
            if (try? OVPNSanitizer.sanitize(text)) != nil {
                XCTAssertEqual(rules, .init(text: text, skipped: [], blocking: []), text.debugDescription)
            }
        }
    }

    // MARK: analyze and commit

    /// The review reads the file and the ones it refers to; it creates no file, folder or Keychain item.
    func testAnalyzeWritesNothing() throws {
        let url = try folder("client\nca ca.crt\nremote vpn.example.com\n<auth-user-pass>\nalice\ns3cret\n</auth-user-pass>\nup /x\n",
                             files: ["ca.crt": caPEM])
        let before = try snapshot(home)
        let draft = try store.analyzeOVPN(url)
        XCTAssertEqual(try snapshot(home), before)
        XCTAssertFalse(FileManager.default.fileExists(atPath: AppPaths.default.profilesDir.path))
        XCTAssertFalse(Secrets.has("work", .password))
        XCTAssertEqual(draft.report.password, "s3cret")
        XCTAssertTrue(store.list().isEmpty)
    }

    func snapshot(_ dir: URL) throws -> [String: Data] {
        var out: [String: Data] = [:]
        let e = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil)
        while let url = e?.nextObject() as? URL {
            out[url.path] = (try? Data(contentsOf: url)) ?? Data()
        }
        return out
    }

    func testCommitStoresWhatWasReviewed() throws {
        let url = try folder("client\nremote vpn.example.com\nscript-security 2\nup /etc/openvpn/update-dns\n"
                             + "<auth-user-pass>\nalice\ns3cret\n</auth-user-pass>\n")
        let draft = try store.analyzeOVPN(url)
        XCTAssertEqual(draft.skipped.map(\.text), ["script-security 2", "up /etc/openvpn/update-dns"])
        let when = Date(timeIntervalSince1970: 1_800_000_000.7)
        let p = try store.commit(draft, now: when)
        XCTAssertEqual(p.id, "work")
        XCTAssertEqual(p.name, "work")
        XCTAssertEqual(p.username, "alice")
        XCTAssertEqual(p.passwordMode, .keychain)
        XCTAssertEqual(p.otpMode, .none)
        XCTAssertEqual(p.configSourceName, "work.ovpn")
        XCTAssertEqual(p.configImportedAt, Date(timeIntervalSince1970: 1_800_000_000))
        XCTAssertEqual(Secrets.get(p.id, .password), "s3cret")
        let stored = try String(contentsOf: store.ovpnURL(p.id))
        XCTAssertEqual(stored, "client\nremote vpn.example.com\n# PassTunnel skipped: script-security 2\n"
                       + "# PassTunnel skipped: up /etc/openvpn/update-dns\nauth-user-pass\n")
        XCTAssertNoThrow(try OVPNSanitizer.sanitize(stored))
        XCTAssertEqual(try mode(store.ovpnURL(p.id)), 0o600)
        XCTAssertEqual(try store.get(p.id), p)
    }

    func testCommitTakesTheReviewedValues() throws {
        let url = try folder("client\nremote vpn.example.com\nauth-user-pass\nstatic-challenge \"Code\" 1\n")
        let draft = try store.analyzeOVPN(url)
        XCTAssertEqual(draft.missing, [.username, .password, .codeSecret])
        let secret = try TOTP.decodeSecret("JBSWY3DPEHPK3PXP")
        let params = TOTPParams(digits: 8, period: 60, algorithm: .sha256)
        let p = try store.commit(draft, name: "  Acme VPN ", username: " alice ", password: "pw", totpSecret: secret, totp: params)
        XCTAssertEqual(p.name, "Acme VPN")
        XCTAssertEqual(p.id, "acme-vpn")
        XCTAssertEqual(p.username, "alice")
        XCTAssertEqual(p.otpMode, .totp)
        XCTAssertEqual(p.otpDelivery, .separate)
        XCTAssertEqual(p.totp, params)
        XCTAssertEqual(Secrets.get(p.id, .password), "pw")
        XCTAssertEqual(Secrets.get(p.id, .totp), "JBSWY3DPEHPK3PXP")
        // Kept in the stored config: the sanitizer removes it at connect time, the analyzer reads it there.
        XCTAssertTrue(try String(contentsOf: store.ovpnURL(p.id)).contains("static-challenge \"Code\" 1"))
    }

    func testCommitRefusals() throws {
        let blocked = try store.analyzeOVPN(try folder("client\nup /x\nplugin /tmp/p.so\n"))
        XCTAssertThrowsError(try store.commit(blocked)) { error in
            XCTAssertEqual(error as? PTError, .ovpnNotAllowed(["line 3: plugin (not allowed)"]))
        }
        let certOnly = try store.analyzeOVPN(try folder("client\nremote vpn.example.com\n", name: "cert.ovpn"))
        assertThrows(.invalidField("otp_mode")) { _ = try store.commit(certOnly, totpSecret: Data([1, 2, 3])) }
        let password = try store.analyzeOVPN(try folder("client\nauth-user-pass\n", name: "pw.ovpn"))
        assertThrows(.invalidSecret) { _ = try store.commit(password, totpSecret: Data()) }
        // A draft whose configuration was changed after the review is checked again.
        var report = password.report
        report.config = "client\nup /tmp/x\n"
        XCTAssertThrowsError(try store.commit(ImportDraft(source: password.source, report: report))) { error in
            guard case .ovpnNotAllowed = error as? PTError else { return XCTFail("\(error)") }
        }
        XCTAssertTrue(store.list().isEmpty)
        XCTAssertFalse(Secrets.has("cert", .totp))
    }

    func testImportSkipsAndRefusesLikeTheReview() throws {
        let p = try store.importOVPN(try folder("client\nremote vpn.example.com\ndaemon\nlog /var/log/x\n"), name: nil)
        XCTAssertEqual(try String(contentsOf: store.ovpnURL(p.id)),
                       "client\nremote vpn.example.com\n# PassTunnel skipped: daemon\n# PassTunnel skipped: log /var/log/x\n")
        XCTAssertThrowsError(try store.importOVPN(try folder("client\nconfig other.ovpn\n", name: "b.ovpn"), name: nil))
        XCTAssertEqual(store.list().map(\.id), [p.id])
    }
}
