import XCTest
@testable import PassTunnelShared

// MARK: - OVPNSanitizer

final class OVPNSanitizerTests: XCTestCase {
    static let cleanConfig = """
    # Acme VPN
    client
    dev tun
    proto udp
    remote vpn.example.com 1194
    resolv-retry infinite
    nobind
    persist-key
    persist-tun
    remote-cert-tls server
    auth-user-pass
    script-security 1
    setenv FORWARD_COMPATIBLE 1
    setenv opt block-outside-dns
    verb 3
    <ca>
    -----BEGIN CERTIFICATE-----
    MIIBszCCAVmgAwIBAgIUJ
    up /tmp/not-a-directive-inside-a-block
    -----END CERTIFICATE-----
    </ca>
    key-direction 1
    <tls-auth>
    -----BEGIN OpenVPN Static key V1-----
    0123456789abcdef
    -----END OpenVPN Static key V1-----
    </tls-auth>

    """

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

    func testCleanConfigPassesUnchanged() throws {
        XCTAssertEqual(try OVPNSanitizer.sanitize(Self.cleanConfig), Self.cleanConfig)
        let crlf = Self.cleanConfig.replacingOccurrences(of: "\n", with: "\r\n")
        XCTAssertEqual(try OVPNSanitizer.sanitize(crlf), crlf)
    }

    func testEachForbiddenDirective() {
        let cases = [
            "up /tmp/x.sh", "down /tmp/x.sh", "route-up /tmp/x", "route-pre-down /tmp/x", "ipchange /tmp/x",
            "learn-address /tmp/x", "client-connect /tmp/x", "client-disconnect /tmp/x", "tls-verify /tmp/x",
            "auth-user-pass-verify /tmp/x via-env", "plugin /tmp/evil.so", "script-security 2", "script-security 3",
            "management 127.0.0.1 7505", "management-query-passwords", "management-hold", "log /etc/passwd",
            "log-append /tmp/x", "daemon", "writepid /etc/x", "cd /", "chroot /tmp", "user nobody", "group nobody",
            "config /tmp/other.ovpn", "dns-updown /tmp/x", "dns-updown force", "status /etc/x", "dev-node /etc/x",
            "engine dynamic", "providers legacy", "pkcs11-providers /tmp/x.dylib", "tls-crypt-v2-verify /tmp/x",
            "iproute /tmp/ip", "tmp-dir /tmp", "replay-persist /etc/x", "tls-export-cert /tmp",
        ]
        for line in cases {
            let v = violations("client\n\(line)\n")
            XCTAssertEqual(v.count, 1, line)
            XCTAssertEqual(v.first?.line, 2, line)
        }
    }

    func testReportsAllViolationsWithLineNumbers() {
        let v = violations("client\nup /tmp/a\nremote vpn.example.com\ndown /tmp/b\n")
        XCTAssertEqual(v.map(\.line), [2, 4])
        XCTAssertEqual(v.map(\.directive), ["up", "down"])
        let failure = OVPNSanitizer.Failure(violations: v)
        XCTAssertTrue(failure.description.contains("line 2: up"))
        XCTAssertTrue(failure.description.contains("line 4: down"))
    }

    func testScriptSecurityLevels() {
        XCTAssertTrue(violations("script-security 0\n").isEmpty)
        XCTAssertTrue(violations("script-security 1\n").isEmpty)
        XCTAssertEqual(violations("script-security 2\n").count, 1)
        XCTAssertEqual(violations("script-security\n").count, 1)
        XCTAssertEqual(violations("script-security x\n").count, 1)
    }

    func testDashesCaseQuotesAndEscapes() {
        for line in ["--up /tmp/x", "---up /tmp/x", "UP /tmp/x", "  \t Up /tmp/x", "\"up\" /tmp/x",
                     "'up' /tmp/x", "\\up /tmp/x", "u\\p /tmp/x", "--Route-Up /tmp/x", "\u{FEFF}up /tmp/x",
                     "setenv opt up /tmp/x", "setenv opt setenv opt plugin /x", "--setenv opt --down /x",
                     "Management 127.0.0.1 1", "LOG-APPEND /tmp/x"] {
            XCTAssertEqual(violations(line + "\n").count, 1, line)
        }
    }

    func testCommentsAreIgnored() {
        let text = "# up /tmp/x\n; down /tmp/x\n   # plugin x\nremote vpn.example.com 1194 # up /tmp/x\n"
        XCTAssertEqual(try OVPNSanitizer.sanitize(text), text)
    }

    func testInlineBlocksKeptVerbatimAndChecked() throws {
        let text = "<ca>\nup /tmp/x\nplugin y\n</ca>\n"
        XCTAssertEqual(try OVPNSanitizer.sanitize(text), text)
        // Forbidden directive used as a block, block opened with dashes, unterminated block.
        XCTAssertEqual(violations("<up>\n#!/bin/sh\n</up>\n").count, 1)
        XCTAssertEqual(violations("--<plugin>\nx\n</plugin>\n").count, 1)
        XCTAssertEqual(violations("<ca>\nabc\n").map(\.reason), ["block is never closed"])
        // A block ends at the first line starting with its close tag, even with trailing text.
        XCTAssertEqual(violations("<ca>\nabc\n  </ca> trailing\nup /tmp/x\n").map(\.line), [4])
        XCTAssertEqual(violations("<ca>\nabc\n</CA>\nup /tmp/x\n").map(\.line), [4])
    }

    func testConnectionBlocksAreParsed() {
        XCTAssertTrue(violations("<connection>\nremote vpn.example.com 1194\n</connection>\n").isEmpty)
        XCTAssertEqual(violations("<connection>\nremote vpn.example.com\nup /tmp/x\n</connection>\n").map(\.line), [3])
    }

    func testStaticChallengeIsStripped() throws {
        let text = "client\nstatic-challenge \"Enter code\" 1\nremote vpn.example.com\n--Static-Challenge 'x' 0\n"
        XCTAssertEqual(try OVPNSanitizer.sanitize(text), "client\nremote vpn.example.com\n")
    }

    func testExternalFilesRejected() {
        XCTAssertEqual(violations("ca /etc/ssl/ca.pem\n").count, 1)
        XCTAssertEqual(violations("auth-user-pass /var/root/secret\n").count, 1)
        XCTAssertEqual(violations("tls-auth ta.key 1\n").count, 1)
        XCTAssertEqual(violations("http-proxy proxy.example.com 8080 /etc/creds\n").count, 1)
        XCTAssertTrue(violations("ca [inline]\nauth-user-pass\ndh none\nhttp-proxy p.example.com 8080 auto\n").isEmpty)
    }

    func testSetenvAllowlist() {
        XCTAssertTrue(violations("setenv CLIENT_CERT 0\nsetenv IV_GUI_VER Acme\nsetenv-safe X 1\n").isEmpty)
        XCTAssertEqual(violations("setenv BASH_ENV /tmp/x\n").count, 1)
        XCTAssertEqual(violations("setenv PATH /tmp\n").count, 1)
    }

    func testMalformedLines() {
        XCTAssertEqual(violations("remote \"vpn.example.com\n").count, 1)
        XCTAssertEqual(violations("remote " + String(repeating: "a", count: 300) + "\n").count, 1)
        XCTAssertEqual(violations("remote vpn.example.com\u{0}\n").count, 1)
    }
}

// MARK: - FortiConfig

final class FortiConfigTests: XCTestCase {
    let digest = String(repeating: "ab", count: 32)

    func config(_ change: (inout FortiConfig) -> Void = { _ in }) -> FortiConfig {
        var c = FortiConfig(host: "vpn.example.com", port: 443, username: "alice", password: "s3cret p#ss=word",
                            otp: "123456", trustedCert: digest, setDNS: true, setRoutes: false)
        change(&c)
        return c
    }

    func testRender() throws {
        let text = try config().render()
        XCTAssertEqual(text, """
        # Generated by PassTunnel. Do not edit.
        host = vpn.example.com
        port = 443
        username = alice
        password = s3cret p#ss=word
        otp = 123456
        trusted-cert = \(digest)
        set-routes = 0
        set-dns = 1
        pppd-use-peerdns = 1

        """)
        let noOptional = try config { $0.otp = nil; $0.trustedCert = "" }.render()
        XCTAssertFalse(noOptional.contains("otp"))
        XCTAssertFalse(noOptional.contains("trusted-cert"))
    }

    func testInjectionRejectedInEveryField() {
        let payloads = ["x\npppd-plugin = /tmp/evil", "x\rpppd-plugin = /tmp/evil", "x\u{0}y", "x\u{2028}y",
                        "x\u{85}y", "x\u{1b}[2J"]
        for p in payloads {
            XCTAssertThrowsError(try config { $0.username = p }.render(), "username \(p.debugDescription)")
            XCTAssertThrowsError(try config { $0.password = p }.render(), "password \(p.debugDescription)")
            XCTAssertThrowsError(try config { $0.otp = p }.render(), "otp \(p.debugDescription)")
            XCTAssertThrowsError(try config { $0.host = p }.render(), "host \(p.debugDescription)")
            XCTAssertThrowsError(try config { $0.trustedCert = p }.render(), "cert \(p.debugDescription)")
        }
    }

    func testRenderedConfigHasOnlyExpectedKeys() throws {
        let text = try config { $0.password = "a = b # c ; d" }.render()
        let keys = text.split(separator: "\n").filter { !$0.hasPrefix("#") }.map { $0.components(separatedBy: " = ")[0] }
        XCTAssertEqual(keys, ["host", "port", "username", "password", "otp", "trusted-cert", "set-routes", "set-dns",
                              "pppd-use-peerdns"])
    }

    func testFieldValidation() {
        XCTAssertThrowsError(try config { $0.port = 0 }.render())
        XCTAssertThrowsError(try config { $0.port = 65536 }.render())
        XCTAssertNoThrow(try config { $0.port = 65535 }.render())
        XCTAssertThrowsError(try config { $0.trustedCert = String(repeating: "a", count: 63) }.render())
        XCTAssertThrowsError(try config { $0.trustedCert = String(repeating: "g", count: 64) }.render())
        XCTAssertNoThrow(try config { $0.trustedCert = String(repeating: "A", count: 64) }.render())
        XCTAssertThrowsError(try config { $0.host = "vpn.example.com:443" }.render())
        XCTAssertThrowsError(try config { $0.host = "vpn example.com" }.render())
        XCTAssertThrowsError(try config { $0.host = "" }.render())
        XCTAssertThrowsError(try config { $0.username = "" }.render())
        XCTAssertThrowsError(try config { $0.password = " leading" }.render())
        XCTAssertThrowsError(try config { $0.password = "trailing\t" }.render())
        XCTAssertNoThrow(try config { $0.host = "2001:db8::1" }.render())
        XCTAssertThrowsError(try config { $0.host = "2001:db8::1:" }.render())
    }
}

// MARK: - Messages

final class HelperMessageTests: XCTestCase {
    func roundTrip(_ r: HelperRequest) throws -> HelperRequest {
        try HelperRequest(jsonData: try r.jsonData())
    }

    func testRequestRoundTrip() throws {
        let ovpn = HelperRequest.startOpenVPN(OpenVPNStart(
            profileID: "acme", profileDir: "/Users/alice/Library/Application Support/PassTunnel/profiles/acme",
            username: "alice", secret: "pw123456", logPath: "/x/vpn.log"))
        let forti = HelperRequest.startForti(FortiStart(
            profileID: "acme-forti", profileDir: "/d", host: "vpn.example.com", port: 10443, username: "alice",
            password: "pw", otp: "123456", trustedCert: "", setDNS: true, setRoutes: false, logPath: "/d/vpn.log"))
        for r in [ovpn, forti, .stop(profileID: "acme"), .status] {
            XCTAssertEqual(try roundTrip(r), r)
        }
    }

    func testWireFormat() throws {
        let json = String(decoding: try HelperRequest.stop(profileID: "acme").jsonData(), as: UTF8.self)
        XCTAssertEqual(json, #"{"profile_id":"acme","type":"stop"}"#)
        XCTAssertEqual(String(decoding: try HelperRequest.status.jsonData(), as: UTF8.self), #"{"type":"status"}"#)
        let start = String(decoding: try HelperRequest.startOpenVPN(OpenVPNStart(
            profileID: "a", profileDir: "/d", logPath: "/l")).jsonData(), as: UTF8.self)
        XCTAssertTrue(start.contains(#""type":"start_openvpn""#))
        XCTAssertFalse(start.contains("mgmt_port"))
        // Protocol-1 payloads with a management port still decode; the port is ignored.
        let legacy = try HelperRequest(jsonData: Data(#"{"type":"start_openvpn","profile_id":"a","profile_dir":"/d","mgmt_port":17505,"log_path":"/l"}"#.utf8))
        guard case .startOpenVPN(let o) = legacy else { return XCTFail() }
        XCTAssertEqual(o.mgmtPort, 17505)
        let reply = String(decoding: try HelperResponse.success(pid: 7, mgmtSocket: "/d/mgmt.sock").jsonData(), as: UTF8.self)
        XCTAssertEqual(reply, #"{"mgmt_socket":"\/d\/mgmt.sock","ok":true,"pid":7}"#)
        let decoded = try HelperRequest(jsonData: Data(#"{"type":"start_forti","profile_id":"f","profile_dir":"/d","host":"h","port":443,"username":"u","password":"p","trusted_cert":"","set_dns":false,"set_routes":true,"log_path":"/d/vpn.log"}"#.utf8))
        guard case .startForti(let f) = decoded else { return XCTFail() }
        XCTAssertNil(f.otp)
        XCTAssertThrowsError(try HelperRequest(jsonData: Data(#"{"type":"reboot"}"#.utf8)))
    }

    func testResponseRoundTrip() throws {
        for r in [HelperResponse.success(pid: 42), .failure("nope"), .success(running: ["acme": 7, "b": 9]),
                  .success(pid: 3, mgmtSocket: "/Users/alice/x/mgmt.sock"),
                  HelperResponse(ok: true)] {
            XCTAssertEqual(try HelperResponse(jsonData: try r.jsonData()), r)
        }
    }

    func testSecretsRedactedInDescriptions() {
        let s = OpenVPNStart(profileID: "a", profileDir: "/d", username: "alice", secret: "TOPSECRET",
                             logPath: "/l")
        XCTAssertFalse(String(describing: HelperRequest.startOpenVPN(s)).contains("TOPSECRET"))
        let f = FortiStart(profileID: "a", profileDir: "/d", host: "h", username: "alice", password: "TOPSECRET",
                           otp: "999999", logPath: "/l")
        XCTAssertFalse(f.description.contains("TOPSECRET"))
        XCTAssertFalse(f.description.contains("999999"))
    }
}

// MARK: - HelperCore path validation

final class HelperCoreTests: XCTestCase {
    var base: URL!
    var home: URL!
    var profiles: URL!
    var runRoot: URL!
    let me = getuid()
    let stranger: uid_t = getuid() + 4242

    override func setUpWithError() throws {
        // Short base: unix socket paths are limited to 103 bytes.
        var template = Array("/tmp/pt-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        base = URL(fileURLWithPath: String(cString: made))
        home = base.appendingPathComponent("home")
        profiles = home.appendingPathComponent(PT.profilesSubpath)
        runRoot = base.appendingPathComponent("run")
        try FileManager.default.createDirectory(at: profiles.appendingPathComponent("acme"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: runRoot, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try "client\nremote vpn.example.com 1194\nstatic-challenge \"Code\" 1\nauth-user-pass\n"
            .write(to: profiles.appendingPathComponent("acme/config.ovpn"), atomically: true, encoding: .utf8)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: base)
    }

    func core(dns: String? = nil) -> HelperCore {
        let homePath = home.path
        let me = self.me, stranger = self.stranger
        return HelperCore(runRoot: runRoot.path, dnsUpdownSource: dns,
                          homeDirectory: { uid in uid == me || uid == stranger ? homePath : nil },
                          userName: { uid in uid == me ? "alice" : nil })
    }

    var acmeDir: String { profiles.appendingPathComponent("acme").path }

    func openVPNStart(dir: String? = nil, id: String = "acme", log: String? = nil) -> OpenVPNStart {
        let d = dir ?? acmeDir
        return OpenVPNStart(profileID: id, profileDir: d, username: "alice", secret: "pw123456",
                            logPath: log ?? d + "/vpn.log")
    }

    func assertFails(_ expr: @autoclosure () throws -> Any, _ check: (HelperCore.Failure) -> Bool,
                     file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try expr()
            XCTFail("expected failure", file: file, line: line)
        } catch let f as HelperCore.Failure {
            XCTAssertTrue(check(f), "unexpected \(f)", file: file, line: line)
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
        }
    }

    func testValidProfileDir() throws {
        let dir = try core().openProfileDir(acmeDir, profileID: "acme", uid: me)
        XCTAssertTrue(dir.path.hasSuffix("/PassTunnel/profiles/acme"))
        XCTAssertFalse(dir.path.hasPrefix("/var/"), "home must be resolved (/var → /private/var)")
    }

    func testPrepareOpenVPN() throws {
        let plan = try core().prepareOpenVPN(openVPNStart(), uid: me)
        defer { close(plan.logFD); core().removeRunDir(profileID: "acme") }
        XCTAssertEqual(plan.tool, .openvpn)
        XCTAssertEqual(plan.runDir, runRoot.path + "/acme")
        XCTAssertEqual(plan.arguments, [
            "--config", plan.runDir + "/config.ovpn", "--management", plan.profileDir.path + "/mgmt.sock", "unix",
            "--management-client-user", "alice", "--auth-nocache",
            "--remap-usr1", "SIGTERM", "--connect-retry-max", "3", "--auth-user-pass", plan.runDir + "/auth",
            "--script-security", "1", "--dns-updown", "disable",
        ])
        let config = try String(contentsOfFile: plan.runDir + "/config.ovpn", encoding: .utf8)
        XCTAssertEqual(config, "client\nremote vpn.example.com 1194\nauth-user-pass\n")
        XCTAssertEqual(try String(contentsOfFile: plan.runDir + "/auth", encoding: .utf8), "alice\npw123456\n")
        for (path, mode) in [(plan.runDir, 0o700), (plan.runDir + "/auth", 0o600), (plan.runDir + "/config.ovpn", 0o600),
                             (acmeDir + "/vpn.log", 0o600)] {
            let attrs = try FileManager.default.attributesOfItem(atPath: path)
            XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, mode, path)
        }
        core().removeRunDir(profileID: "acme")
        XCTAssertFalse(FileManager.default.fileExists(atPath: plan.runDir))
    }

    func testPrepareOpenVPNStagesDNSScript() throws {
        let script = base.appendingPathComponent("dns-updown")
        try "#!/bin/sh\nexit 0\n".write(to: script, atomically: true, encoding: .utf8)
        let plan = try core(dns: script.path).prepareOpenVPN(openVPNStart(), uid: me)
        defer { close(plan.logFD) }
        XCTAssertEqual(plan.dnsUpdownPath, plan.runDir + "/dns-updown")
        XCTAssertEqual(Array(plan.arguments.suffix(4)), ["--script-security", "2", "--dns-updown", plan.runDir + "/dns-updown"])
        XCTAssertEqual(try String(contentsOfFile: plan.runDir + "/dns-updown", encoding: .utf8), "#!/bin/sh\nexit 0\n")
    }

    func testPrepareForti() throws {
        let s = FortiStart(profileID: "acme", profileDir: acmeDir, host: "vpn.example.com", username: "alice",
                           password: "pw", otp: "123456", logPath: acmeDir + "/vpn.log")
        let plan = try core().prepareForti(s, uid: me)
        defer { close(plan.logFD) }
        XCTAssertEqual(plan.tool, .openfortivpn)
        XCTAssertEqual(plan.arguments, ["-c", plan.runDir + "/openfortivpn.conf"])
        let text = try String(contentsOfFile: plan.runDir + "/openfortivpn.conf", encoding: .utf8)
        XCTAssertTrue(text.contains("otp = 123456\n"))
        var bad = s
        bad.username = "alice\npppd-plugin = /tmp/evil.so"
        XCTAssertThrowsError(try core().prepareForti(bad, uid: me)) { error in
            guard case .invalidValue(let field, _)? = error as? FortiConfig.ValidationError else { return XCTFail("\(error)") }
            XCTAssertEqual(field, "username")
        }
    }

    func testWrongOwnerIsRejected() {
        assertFails(try self.core().openProfileDir(self.acmeDir, profileID: "acme", uid: self.stranger)) {
            if case .wrongOwner(_, let expected, let actual) = $0 { return expected == self.stranger && actual == self.me }
            return false
        }
    }

    func testUnknownUserIsRejected() {
        assertFails(try self.core().openProfileDir(self.acmeDir, profileID: "acme", uid: 99_999)) { $0 == .unknownUser(99_999) }
    }

    func testSymlinkedProfileDirEscapeIsRejected() throws {
        let outside = base.appendingPathComponent("outside/acme2")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let link = profiles.appendingPathComponent("acme2")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)
        assertFails(try self.core().openProfileDir(link.path, profileID: "acme2", uid: self.me)) {
            if case .outsideProfilesRoot = $0 { return true }; return false
        }
    }

    func testSymlinkedProfilesRootIsRejected() throws {
        // Replace .../PassTunnel/profiles with a symlink to a directory elsewhere.
        let elsewhere = base.appendingPathComponent("elsewhere")
        try FileManager.default.moveItem(at: profiles, to: elsewhere)
        try FileManager.default.createSymbolicLink(at: profiles, withDestinationURL: elsewhere)
        assertFails(try self.core().openProfileDir(self.acmeDir, profileID: "acme", uid: self.me)) {
            if case .outsideProfilesRoot = $0 { return true }; return false
        }
    }

    func testDotDotAndForeignPathsAreRejected() {
        let escape = acmeDir + "/../../../../../../outside"
        assertFails(try self.core().openProfileDir(escape, profileID: "acme", uid: self.me)) {
            if case .outsideProfilesRoot = $0 { return true }; return false
        }
        assertFails(try self.core().openProfileDir("/etc", profileID: "acme", uid: self.me)) {
            if case .outsideProfilesRoot = $0 { return true }; return false
        }
        assertFails(try self.core().openProfileDir("relative/acme", profileID: "acme", uid: self.me)) {
            if case .notAbsolute = $0 { return true }; return false
        }
        assertFails(try self.core().openProfileDir(self.profiles.path, profileID: "acme", uid: self.me)) {
            if case .outsideProfilesRoot = $0 { return true }; return false
        }
    }

    func testProfileIDMustMatchDirectory() throws {
        try FileManager.default.createDirectory(at: profiles.appendingPathComponent("other"), withIntermediateDirectories: true)
        assertFails(try self.core().openProfileDir(self.acmeDir, profileID: "other", uid: self.me)) {
            if case .wrongDirectoryName = $0 { return true }; return false
        }
        for bad in ["", "..", ".hidden", "a/b", "../acme", "-x", String(repeating: "a", count: 65)] {
            assertFails(try self.core().openProfileDir(self.acmeDir, profileID: bad, uid: self.me)) {
                $0 == .invalidProfileID(bad)
            }
        }
    }

    func testSymlinkedOrHardLinkedConfigIsRejected() throws {
        let cfg = profiles.appendingPathComponent("acme/config.ovpn")
        let real = base.appendingPathComponent("real.ovpn")
        try FileManager.default.moveItem(at: cfg, to: real)
        try FileManager.default.createSymbolicLink(at: cfg, withDestinationURL: real)
        assertFails(try self.core().prepareOpenVPN(self.openVPNStart(), uid: self.me)) {
            if case .symlinkNotAllowed = $0 { return true }; return false
        }
        try FileManager.default.removeItem(at: cfg)
        try FileManager.default.linkItem(at: real, to: cfg)
        assertFails(try self.core().prepareOpenVPN(self.openVPNStart(), uid: self.me)) {
            if case .multipleLinks = $0 { return true }; return false
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: runRoot.path + "/acme"))
    }

    func testLogPathValidation() throws {
        for bad in ["/tmp/vpn.log", acmeDir + "/../vpn.log", acmeDir + "/config.ovpn", acmeDir + "/sub/vpn.log",
                    "vpn.log", acmeDir + "/.log"] {
            assertFails(try self.core().prepareOpenVPN(self.openVPNStart(log: bad), uid: self.me)) {
                if case .invalidLogPath = $0 { return true }; return false
            }
        }
    }

    func testExistingLogSymlinkIsReplacedNotFollowed() throws {
        let victim = base.appendingPathComponent("victim.txt")
        try "keep me".write(to: victim, atomically: true, encoding: .utf8)
        let logURL = profiles.appendingPathComponent("acme/vpn.log")
        try FileManager.default.createSymbolicLink(at: logURL, withDestinationURL: victim)
        let plan = try core().prepareOpenVPN(openVPNStart(), uid: me)
        _ = "hello\n".withCString { write(plan.logFD, $0, 6) }
        close(plan.logFD)
        XCTAssertEqual(try String(contentsOf: victim, encoding: .utf8), "keep me")
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: logURL.path)[.type] as? FileAttributeType, .typeRegular)
        XCTAssertEqual(try String(contentsOf: logURL, encoding: .utf8), "hello\n")
    }

    func testForbiddenConfigIsRejected() throws {
        try "client\nup /tmp/evil.sh\n".write(to: profiles.appendingPathComponent("acme/config.ovpn"),
                                             atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try core().prepareOpenVPN(openVPNStart(), uid: me)) { error in
            XCTAssertEqual((error as? OVPNSanitizer.Failure)?.violations.map(\.line), [2])
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: runRoot.path + "/acme"))
    }

    func testCredentialValidation() {
        var s = openVPNStart()
        s.username = "alice\nroot"
        assertFails(try self.core().prepareOpenVPN(s, uid: self.me)) { $0 == .invalidCredential("username") }
        s = openVPNStart()
        s.secret = "pw\r\nx"
        assertFails(try self.core().prepareOpenVPN(s, uid: self.me)) { $0 == .invalidCredential("password") }
    }

    // MARK: Management socket

    var socketPath: String { acmeDir + "/" + PT.mgmtSocketName }

    func makeSocketFile(_ path: String) throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        defer { close(fd) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: path.utf8)
            raw[path.utf8.count] = 0
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        XCTAssertEqual(rc, 0, String(cString: strerror(errno)))
    }

    func testStaleSocketIsRemovedAndReported() throws {
        try makeSocketFile(socketPath)
        XCTAssertTrue(FileManager.default.fileExists(atPath: socketPath))
        let plan = try core().prepareOpenVPN(openVPNStart(), uid: me)
        defer { close(plan.logFD) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: socketPath))
        XCTAssertEqual(plan.mgmtSocket, plan.profileDir.path + "/mgmt.sock")
        // Ownership fix-up and removal work through the directory descriptor.
        try makeSocketFile(socketPath)
        XCTAssertTrue(plan.profileDir.restrictSocket(PT.mgmtSocketName))
        let attrs = try FileManager.default.attributesOfItem(atPath: socketPath)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        try plan.profileDir.removeSocket(PT.mgmtSocketName)
        XCTAssertFalse(FileManager.default.fileExists(atPath: socketPath))
        XCTAssertNoThrow(try plan.profileDir.removeSocket(PT.mgmtSocketName))   // already gone
    }

    func testSymlinkOrFileAtSocketPathIsRefused() throws {
        let victim = base.appendingPathComponent("victim")
        try "keep".write(to: victim, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: socketPath, withDestinationPath: victim.path)
        assertFails(try self.core().prepareOpenVPN(self.openVPNStart(), uid: self.me)) {
            if case .symlinkNotAllowed = $0 { return true }; return false
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: victim.path))
        try FileManager.default.removeItem(atPath: socketPath)
        try "x".write(toFile: socketPath, atomically: true, encoding: .utf8)
        assertFails(try self.core().prepareOpenVPN(self.openVPNStart(), uid: self.me)) {
            if case .notASocket = $0 { return true }; return false
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: socketPath))
        XCTAssertFalse(FileManager.default.fileExists(atPath: runRoot.path + "/acme"))
    }

    func testSocketPathLengthAndClientUser() throws {
        let longID = String(repeating: "a", count: 60)
        let longDir = profiles.appendingPathComponent(longID)
        try FileManager.default.createDirectory(at: longDir, withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: acmeDir + "/config.ovpn", toPath: longDir.path + "/config.ovpn")
        assertFails(try self.core().prepareOpenVPN(self.openVPNStart(dir: longDir.path, id: longID), uid: self.me)) {
            if case .socketPathTooLong = $0 { return true }; return false
        }
        let noName = HelperCore(runRoot: runRoot.path, homeDirectory: { [home] _ in home!.path }, userName: { _ in nil })
        assertFails(try noName.prepareOpenVPN(self.openVPNStart(), uid: self.me)) { $0 == .unknownUser(self.me) }
    }

    func testRunRootSymlinkIsRejected() throws {
        let target = base.appendingPathComponent("target")
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        let link = base.appendingPathComponent("run-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let c = HelperCore(runRoot: link.path, homeDirectory: { _ in nil })
        assertFails(try c.makeRunDir(profileID: "acme")) { if case .symlinkNotAllowed = $0 { return true }; return false }
    }

    func testRunDirReplacesStaleDirectory() throws {
        let c = core()
        let dir = try c.makeRunDir(profileID: "acme")
        try "stale".write(toFile: dir + "/auth", atomically: true, encoding: .utf8)
        let again = try c.makeRunDir(profileID: "acme")
        XCTAssertEqual(dir, again)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir + "/auth"))
        c.removeRunDir(profileID: "acme")
    }
}
