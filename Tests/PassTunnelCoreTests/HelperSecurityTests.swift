import XCTest

@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

// MARK: - Request decoding (size, JSON, version, type)

final class HelperRequestDecodingTests: XCTestCase {
    func decodeError(_ json: String, file: StaticString = #filePath, line: UInt = #line) -> HelperCore.RequestError? {
        decodeError(Data(json.utf8), file: file, line: line)
    }

    func decodeError(_ data: Data, file: StaticString = #filePath, line: UInt = #line) -> HelperCore.RequestError? {
        do {
            _ = try HelperCore.decodeRequest(data)
            XCTFail("expected a request error", file: file, line: line)
            return nil
        } catch let e as HelperCore.RequestError {
            return e
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
            return nil
        }
    }

    func testValidRequestsDecode() throws {
        let requests: [HelperRequest] = [
            .startOpenVPN(
                OpenVPNStart(
                    profileID: "acme", profileDir: "/d", username: "alice", secret: "pw",
                    logPath: "/d/vpn.log")),
            .startForti(
                FortiStart(
                    profileID: "acme", profileDir: "/d", host: "vpn.example.com", username: "alice",
                    password: "pw", logPath: "/d/vpn.log")),
            .stop(profileID: "acme"), .status
        ]
        for r in requests {
            XCTAssertEqual(try HelperCore.decodeRequest(try r.jsonData()), r)
        }
        XCTAssertEqual(try HelperCore.decodeRequest(Data(#"{"type":"status","protocol_version":3}"#.utf8)), .status)
    }

    func testOversizeRequestIsRejected() throws {
        let limit = HelperCore.maxRequestBytes
        XCTAssertEqual(limit, 65536)
        // Exactly at the limit is fine (padding with JSON whitespace).
        var json = #"{"type":"status","protocol_version":3}"#
        json += String(repeating: " ", count: limit - json.utf8.count)
        XCTAssertEqual(try HelperCore.decodeRequest(Data(json.utf8)), .status)
        XCTAssertEqual(decodeError(json + " "), .tooLarge(limit + 1))
        XCTAssertEqual(decodeError(Data(count: 10 * limit)), .tooLarge(10 * limit))
        XCTAssertTrue(HelperCore.RequestError.tooLarge(limit + 1).description.contains("too large"))
    }

    func testMalformedJSONIsRejected() {
        for bad in ["", "not json", "{", #"{"type":"status""#, "[1,2]", #""status""#, "null", "42"] {
            XCTAssertEqual(decodeError(bad), .malformed, bad)
        }
        XCTAssertEqual(decodeError(Data([0x7B, 0xFF, 0xFE, 0x7D])), .malformed)
        XCTAssertTrue(HelperCore.RequestError.malformed.description.contains("Malformed"))
    }

    func testMissingOrUnknownTypeIsRejected() {
        XCTAssertEqual(decodeError(#"{"protocol_version":3}"#), .missingType)
        XCTAssertEqual(decodeError(#"{"profile_id":"acme","protocol_version":3}"#), .missingType)
        XCTAssertEqual(decodeError(#"{"type":5,"protocol_version":3}"#), .invalidField("type"))
        for t in ["reboot", "Stop", "STATUS", "start_shell", ""] {
            XCTAssertEqual(decodeError(#"{"type":"\#(t)","protocol_version":3}"#), .unknownType(t), t)
        }
        // Client-supplied text is made printable and shortened before it is echoed.
        let long = String(repeating: "x", count: 100)
        XCTAssertEqual(decodeError(#"{"type":"\#(long)","protocol_version":3}"#), .unknownType(String(repeating: "x", count: 32)))
        XCTAssertEqual(decodeError(#"{"type":"a\nb\u001b","protocol_version":3}"#), .unknownType("a?b?"))
        XCTAssertEqual(HelperCore.RequestError.unknownType("reboot").description, "Unknown request type “reboot”.")
    }

    func testProtocolVersionMismatchIsRejected() {
        XCTAssertEqual(PT.helperProtocolVersion, 3)
        for v in [0, 1, 2, 4, 99, -1] {
            XCTAssertEqual(
                decodeError(#"{"type":"status","protocol_version":\#(v)}"#),
                .versionMismatch(client: v, helper: 3), "\(v)")
        }
        // Clients from before the field speak protocol 2 at most.
        XCTAssertEqual(decodeError(#"{"type":"status"}"#), .versionMismatch(client: 2, helper: 3))
        XCTAssertEqual(
            decodeError(#"{"type":"start_openvpn","profile_id":"a","profile_dir":"/d","log_path":"/l"}"#),
            .versionMismatch(client: 2, helper: 3))
        // Version is checked before the type, so a newer client gets the clear message.
        XCTAssertEqual(
            decodeError(#"{"type":"start_wireguard","protocol_version":4}"#),
            .versionMismatch(client: 4, helper: 3))
        XCTAssertEqual(decodeError(#"{"type":"status","protocol_version":"2"}"#), .invalidField("protocol_version"))
        XCTAssertEqual(decodeError(#"{"type":"status","protocol_version":true}"#), .invalidField("protocol_version"))
        let msg = HelperCore.RequestError.versionMismatch(client: 4, helper: 3).description
        XCTAssertTrue(msg.contains("version") && msg.contains("4") && msg.contains("3"), msg)
    }

    func testMissingOrMistypedFieldsAreNamed() {
        XCTAssertEqual(decodeError(#"{"type":"stop","protocol_version":3}"#), .invalidField("profile_id"))
        XCTAssertEqual(
            decodeError(#"{"type":"start_openvpn","protocol_version":3,"profile_id":"a","log_path":"/l"}"#),
            .invalidField("profile_dir"))
        let forti =
            #"{"type":"start_forti","protocol_version":3,"profile_id":"f","profile_dir":"/d","host":"vpn.example.com","username":"u","password":"p","trusted_cert":"","set_dns":false,"set_routes":true,"log_path":"/d/vpn.log","port":"#
        XCTAssertEqual(decodeError(forti + #""443"}"#), .invalidField("port"))
        // Not representable: rejected by the JSON layer before a field is known; the value is not echoed.
        XCTAssertEqual(decodeError(forti + "1e30}"), .invalidField("request"))
        XCTAssertNoThrow(try HelperCore.decodeRequest(Data((forti + "443}").utf8)))
    }

    func testErrorsNeverEchoFieldValues() {
        let payloads = [
            #"{"type":"start_forti","protocol_version":3,"profile_id":"f","password":["TOPSECRET"]}"#,
            #"{"type":"start_openvpn","protocol_version":3,"profile_id":"a","profile_dir":"/d","log_path":"/l","secret":{"x":"TOPSECRET"}}"#,
            #"{"type":"start_openvpn","protocol_version":3,"profile_id":"a","profile_dir":"/d","log_path":"/l","username":7,"secret":"TOPSECRET"}"#
        ]
        for p in payloads {
            guard let e = decodeError(p) else { continue }
            XCTAssertFalse(e.description.contains("TOPSECRET"), e.description)
        }
    }
}

// MARK: - Profile IDs and file checks

#if os(macOS)
extension HelperCoreTests {
    func testMoreInvalidProfileIDs() throws {
        let lookalikes = [
            "\u{FF41}cme",  // fullwidth a
            "\u{0430}cme",  // Cyrillic a
            "acm\u{0435}",  // Cyrillic e
            "ac\u{200B}me",  // zero-width space
            "acme\u{0301}"  // combining accent
        ]
        // A directory with the lookalike name must not make it acceptable.
        try FileManager.default.createDirectory(
            at: profiles.appendingPathComponent(lookalikes[1]),
            withIntermediateDirectories: true)
        let bad =
            [
                "", "ac\u{0}me", "acme\u{0}", String(repeating: "a", count: 200), "acme.", "acme..", "acme ",
                " acme", "acme\t", "ac me", "acme\n"
            ] + lookalikes
        for id in bad {
            XCTAssertFalse(HelperCore.isValidProfileID(id), id.debugDescription)
            assertFails(
                try self.core().openProfileDir(
                    self.profiles.appendingPathComponent(id).path, profileID: id,
                    uid: self.me)
            ) { $0 == .invalidProfileID(id) }
            assertFails(try self.core().makeRunDir(profileID: id, uid: self.me)) { $0 == .invalidProfileID(id) }
        }
        for id in ["a", "acme", "acme.vpn", "Acme_2", "a-b", String(repeating: "a", count: 64)] {
            XCTAssertTrue(HelperCore.isValidProfileID(id), id)
        }
    }

    func testGroupOrWorldWritableProfileDirIsRejected() throws {
        for mode: mode_t in [0o757, 0o775, 0o777, 0o720] {
            XCTAssertEqual(chmod(acmeDir, mode), 0)
            assertFails(try self.core().openProfileDir(self.acmeDir, profileID: "acme", uid: self.me)) {
                if case .insecurePermissions = $0 { return true }; return false
            }
        }
        for mode: mode_t in [0o700, 0o755, 0o750] {
            XCTAssertEqual(chmod(acmeDir, mode), 0)
            XCTAssertNoThrow(try core().openProfileDir(acmeDir, profileID: "acme", uid: me), String(mode, radix: 8))
        }
    }

    func testConfigFIFOOrDirectoryIsRejected() throws {
        let cfg = acmeDir + "/config.ovpn"
        try FileManager.default.removeItem(atPath: cfg)
        XCTAssertEqual(mkfifo(cfg, 0o600), 0)
        // Must fail fast: nobody writes to the FIFO, a blocking open would hang the helper.
        assertFails(try self.core().prepareOpenVPN(self.openVPNStart(), uid: self.me)) {
            if case .notARegularFile = $0 { return true }; return false
        }
        try FileManager.default.removeItem(atPath: cfg)
        try FileManager.default.createDirectory(atPath: cfg, withIntermediateDirectories: false)
        assertFails(try self.core().prepareOpenVPN(self.openVPNStart(), uid: self.me)) {
            if case .notARegularFile = $0 { return true }; return false
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: acmeRunDir))
    }

    func testGroupOrWorldWritableConfigIsRejected() throws {
        let cfg = acmeDir + "/config.ovpn"
        for mode: mode_t in [0o620, 0o602, 0o666, 0o660] {
            XCTAssertEqual(chmod(cfg, mode), 0)
            assertFails(try self.core().prepareOpenVPN(self.openVPNStart(), uid: self.me)) {
                if case .insecurePermissions = $0 { return true }; return false
            }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: acmeRunDir))
        for mode: mode_t in [0o600, 0o644, 0o400] {
            XCTAssertEqual(chmod(cfg, mode), 0)
            let plan = try core().prepareOpenVPN(openVPNStart(), uid: me)
            close(plan.logFD)
        }
    }

    // MARK: Helper-side sanitizing

    func writeConfig(_ text: String) throws {
        let url = profiles.appendingPathComponent("acme/config.ovpn")
        try? FileManager.default.removeItem(at: url)
        try text.write(to: url, atomically: true, encoding: .utf8)
    }

    func testHelperResanitizesEveryDangerousDirective() throws {
        let dangerous = [
            "up /tmp/x.sh", "down /tmp/x.sh", "plugin /tmp/evil.so", "script-security 3", "script-security 2",
            "management 0.0.0.0 7505", "management /tmp/m.sock unix", "management-client-user root",
            "log /etc/x", "log-append /etc/x", "cd /", "config /tmp/other.ovpn", "setenv BASH_ENV /tmp/x",
            "setenv PATH /tmp", "setenv opt up /tmp/x", "--Up /tmp/x", "route-up /tmp/x", "dns-updown /tmp/x",
            "auth-user-pass /var/root/secret", "ca /etc/ssl/ca.pem", "writepid /etc/x", "user nobody",
            "mode server", "tls-server", "server 10.8.0.0 255.255.255.0", "client-crresponse /tmp/x",
            "setenv opt client-crresponse /tmp/x", "mktun", "dev ../tmp/x1",
            "proto tcp-server", "remote vpn.example.com 443 tcp6-server", "local 192.0.2.1 1194 tcp4-server"
        ]
        for line in dangerous {
            try writeConfig("client\nremote vpn.example.com 1194\n\(line)\n")
            XCTAssertThrowsError(try core().prepareOpenVPN(openVPNStart(), uid: me), line) { error in
                XCTAssertEqual((error as? OVPNSanitizer.Failure)?.violations.map(\.line), [3], line)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: acmeRunDir), line)
        }
        try writeConfig("client\n<plugin>\n/tmp/evil.so\n</plugin>\n")
        XCTAssertThrowsError(try core().prepareOpenVPN(openVPNStart(), uid: me)) { error in
            XCTAssertNotNil(error as? OVPNSanitizer.Failure)
        }
    }

    /// A config that would make OpenVPN wait for incoming connections is refused at start too, with the
    /// sanitizer's words (the same on the Mac and on Linux), before anything is prepared.
    func testHelperRefusesListeningModes() throws {
        for text in ["client\nauth-user-pass\n", "client\nproto tcp\nport 1194\n", ""] {
            try writeConfig(text)
            XCTAssertThrowsError(try core().prepareOpenVPN(openVPNStart(), uid: me), text) { error in
                XCTAssertEqual((error as? OVPNSanitizer.Failure)?.violations, [OVPNSanitizer.missingRemote], text)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: acmeRunDir), text)
        }
        try writeConfig("client\nremote vpn.example.com 1194 tcp-server\n")
        XCTAssertThrowsError(try core().prepareOpenVPN(openVPNStart(), uid: me)) { error in
            XCTAssertEqual((error as? OVPNSanitizer.Failure)?.violations.map(\.reason), [OVPNSanitizer.listeningReason])
        }
    }

    /// A stored profile that lowers TLS below 1.2 (imported before the floor existed) is refused at connect,
    /// before anything is prepared. A clean one runs with `--tls-version-min` after the config: 1.2, or the
    /// config's own 1.3.
    func testHelperEnforcesTheTLSFloor() throws {
        for line in [
            "tls-version-min 1.0", "tls-version-min 1.1 or-highest", "tls-version-max 1.1",
            "tls-cipher DEFAULT:@SECLEVEL=0", "tls-cert-profile insecure", "setenv opt tls-version-min 1.0"
        ] {
            try writeConfig("client\nremote vpn.example.com 1194\n\(line)\n")
            XCTAssertThrowsError(try core().prepareOpenVPN(openVPNStart(), uid: me), line) { error in
                XCTAssertEqual((error as? OVPNSanitizer.Failure)?.violations.map(\.line), [3], line)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: acmeRunDir), line)
        }
        for (line, floor) in [("", ["1.2"]), ("tls-version-min 1.2", ["1.2"]), ("tls-version-min 1.3", ["1.3"])] {
            try writeConfig("client\nremote vpn.example.com 1194\n\(line)\n")
            let plan = try core().prepareOpenVPN(openVPNStart(), uid: me)
            defer { close(plan.logFD); core().removeRunDir(profileID: "acme", uid: me) }
            let args = plan.arguments
            let index = try XCTUnwrap(args.firstIndex(of: "--tls-version-min"), line)
            XCTAssertGreaterThan(index, try XCTUnwrap(args.firstIndex(of: "--config")), line)
            XCTAssertEqual(Array(args[(index + 1)...].prefix(floor.count)), floor, line)
            XCTAssertEqual(args.filter { $0 == "--tls-version-min" }.count, 1, line)
        }
    }

    /// The pull filters come before `--config`: OpenVPN tries them in the order it reads them and the first
    /// match decides, so a profile's own `pull-filter accept verb` comes too late. Every spelling of a pushed
    /// `verb` OpenVPN's parser reads as `verb` starts with one of the ignored prefixes.
    func testPushedVerbIsIgnoredBeforeTheConfig() throws {
        try writeConfig("client\nremote vpn.example.com 1194\npull-filter accept verb\npull-filter accept \"\\\"verb\"\n")
        let plan = try core().prepareOpenVPN(openVPNStart(), uid: me)
        defer { close(plan.logFD); core().removeRunDir(profileID: "acme", uid: me) }
        let args = plan.arguments
        let config = try XCTUnwrap(args.firstIndex(of: "--config"))
        let filters = HelperCore.ignoredPushPrefixes.flatMap { ["--pull-filter", "ignore", $0] }
        XCTAssertEqual(Array(args.prefix(filters.count)), filters)
        XCTAssertLessThan(filters.count, config)
        XCTAssertEqual(args.filter { $0 == "--pull-filter" }.count, HelperCore.ignoredPushPrefixes.count)
        for pushed in ["verb 9", "\"verb\" 9", "'verb' 9", "\\ verb 9", "\\\tverb 9", "\"verb\"9", "verb"] {
            let tokens = try XCTUnwrap(OVPNSanitizer.tokens(of: pushed), pushed)
            XCTAssertEqual(tokens.first, "verb", pushed)
            XCTAssertTrue(HelperCore.ignoredPushPrefixes.contains { pushed.hasPrefix($0) }, pushed)
        }
        for other in ["route 10.0.0.0 255.0.0.0", "dhcp-option DNS 192.0.2.53", "ping 10", "\"route\" 10.0.0.0"] {
            XCTAssertFalse(HelperCore.ignoredPushPrefixes.contains { other.hasPrefix($0) }, other)
        }
    }

    /// Linux: a `dev` with a name of its own is checked against the kernel's devices before anything is
    /// prepared (a persistent device created earlier stays open to its owner). `dev tun` and `dev tap` are
    /// never checked: the kernel picks a free name. Without the check (the Mac) nothing changes.
    func testExistingDeviceIsRefused() throws {
        var checked: [String] = []
        var linux = core()
        linux.interfaceExists = { name in
            checked.append(name); return name == "tun5" || name == "tap-lab01234567"
        }
        for text in [
            "client\nremote vpn.example.com\ndev tun5\n", "client\nremote vpn.example.com\nsetenv opt dev tun5\n",
            "client\nremote vpn.example.com\ndev tun5\ndev tun\n",
            "client\nremote vpn.example.com\ndev tap-lab0123456789\ndev-type tap\n"
        ] {
            try writeConfig(text)
            assertFails(try linux.prepareOpenVPN(self.openVPNStart(), uid: self.me)) {
                $0 == .deviceExists("tun5") || $0 == .deviceExists("tap-lab01234567")
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: acmeRunDir), text)
        }
        XCTAssertEqual(
            HelperCore.Failure.deviceExists("tun5").description,
            "The network device tun5 already exists, and PassTunnel only connects through a device it creates. "
                + "Use “dev tun” or “dev tap” so that the system picks a free name, or a name no device has.")
        checked = []
        for dev in ["tun", "tap", "tun6"] {
            try writeConfig("client\nremote vpn.example.com\ndev \(dev)\n")
            let plan = try linux.prepareOpenVPN(openVPNStart(), uid: me)
            close(plan.logFD)
            linux.removeRunDir(profileID: "acme", uid: me)
        }
        XCTAssertEqual(checked, ["tun6"], "tun and tap are never checked")
        // The Mac does not check.
        try writeConfig("client\nremote vpn.example.com\ndev tun5\n")
        let plan = try core().prepareOpenVPN(openVPNStart(), uid: me)
        close(plan.logFD)
        core().removeRunDir(profileID: "acme", uid: me)
        // A device that cannot be checked refuses the start.
        linux.interfaceExists = { _ in throw HelperCore.Failure.system("if_nametoindex tun5", EMFILE) }
        assertFails(try linux.prepareOpenVPN(self.openVPNStart(), uid: self.me)) { $0 == .system("if_nametoindex tun5", EMFILE) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: acmeRunDir))
    }

    /// The names OpenVPN on Linux gives the kernel: all but `tun` and `tap`, each once, cut to 15 bytes.
    func testNamedDevices() {
        XCTAssertEqual(HelperCore.namedDevices("client\ndev tun\n"), [])
        XCTAssertEqual(HelperCore.namedDevices("dev tap\ndev-type tap\n"), [])
        XCTAssertEqual(HelperCore.namedDevices("client\n"), [])
        XCTAssertEqual(HelperCore.namedDevices("dev tun0\n--DEV tap1\nsetenv opt dev tun0\n"), ["tun0", "tap1"])
        XCTAssertEqual(HelperCore.namedDevices("dev null\ndev utun\ndev tun-work\n"), ["null", "utun", "tun-work"])
        XCTAssertEqual(HelperCore.namedDevices("dev tun0123456789abcdef\n"), ["tun0123456789ab"])
        XCTAssertEqual(HelperCore.namedDevices("<connection>\nremote vpn.example.com\ndev tun3\n</connection>\n"), ["tun3"])
        XCTAssertEqual(HelperCore.namedDevices("<ca>\ndev tun3\n</ca>\n# dev tun4\n"), [], "not directives")
    }

    func testHelperConfigIsExactlyTheSanitizedProfileFile() throws {
        let text =
            "# Acme\nclient\nremote vpn.example.com 1194\nstatic-challenge \"Code\" 1\nscript-security 1\n"
            + "<ca>\nup /tmp/inside-block-is-data\n</ca>\n"
        try writeConfig(text)
        // Extra keys in the request (a config or arguments of the client's choosing) are ignored.
        let start = openVPNStart()
        let json =
            #"{"type":"start_openvpn","protocol_version":3,"profile_id":"acme","profile_dir":"\#(start.profileDir)","#
            + #""username":"alice","secret":"pw","log_path":"\#(start.logPath)","#
            + #""config":"up /tmp/evil.sh","arguments":["--up","/tmp/evil.sh"],"executable":"/bin/sh"}"#
        guard case .startOpenVPN(let decoded) = try HelperCore.decodeRequest(Data(json.utf8)) else {
            return XCTFail("wrong request type")
        }
        let plan = try core().prepareOpenVPN(decoded, uid: me)
        defer { close(plan.logFD) }
        let written = try String(contentsOfFile: plan.runDir + "/config.ovpn", encoding: .utf8)
        XCTAssertEqual(written, try OVPNSanitizer.sanitize(text))
        XCTAssertFalse(written.contains("static-challenge"))
        XCTAssertFalse(plan.arguments.contains { $0.contains("evil") || $0 == "--up" })
        XCTAssertEqual(plan.tool, .openvpn)
    }
}
#endif

// MARK: - Forti field injection

extension FortiConfigTests {
    /// openfortivpn's parser: skip lines starting with '#', split at the first '=', trim spaces.
    func parseLikeOpenfortivpn(_ text: String) -> [(String, String)] {
        text.split(separator: "\n", omittingEmptySubsequences: true).compactMap { line in
            guard !line.hasPrefix("#"), let eq = line.firstIndex(of: "=") else { return nil }
            let trim: (Substring) -> String = { $0.trimmingCharacters(in: .whitespaces) }
            return (trim(line[..<eq]), trim(line[line.index(after: eq)...]))
        }
    }

    func testEqualsAndHashStayInsideTheirValue() throws {
        for value in ["a=b", "#alice", "alice#x", "=alice", "a = b # c", "alice;x", "x=pppd-plugin = /tmp/evil"] {
            let c = config {
                $0.username = value; $0.password = value
            }
            let pairs = parseLikeOpenfortivpn(try c.render())
            XCTAssertEqual(
                pairs.map(\.0),
                [
                    "host", "port", "username", "password", "otp", "ca-file", "trusted-cert",
                    "set-routes", "set-dns", "pppd-use-peerdns"
                ], value)
            XCTAssertEqual(pairs.first { $0.0 == "username" }?.1, value)
            XCTAssertEqual(pairs.first { $0.0 == "password" }?.1, value)
        }
    }

    func testHostRejectsSeparatorsCRAndSpaces() {
        for host in [
            "vpn.example.com=1", "vpn#example.com", "vpn.example.com\r", "\rvpn.example.com",
            " vpn.example.com", "vpn.example.com ", "vpn.example.com\nport = 1", "vpn.example.com;x",
            "[2001:db8::1]", "2001:db8::1 ", "vpn_example.com"
        ] {
            XCTAssertThrowsError(try config { $0.host = host }.render(), host.debugDescription) {
                XCTAssertEqual($0 as? FortiConfig.ValidationError, .invalidHost)
            }
        }
    }

    func testTrustedCertRejectsSeparatorsCRAndSpaces() {
        let d = String(repeating: "ab", count: 32)
        let d63 = String(d.dropFirst())
        let certs: [String] = [d + "=", "#" + d63, d + " ", " " + d, d + "\r", "=" + d63, d63 + "#", "sha256:" + d]
        for cert in certs {
            XCTAssertThrowsError(try config { $0.trustedCert = cert }.render(), cert.debugDescription) {
                XCTAssertEqual($0 as? FortiConfig.ValidationError, .invalidTrustedCert)
            }
        }
    }

    func testUsernameRejectsCRAndOuterWhitespace() {
        for u in [" alice", "alice ", "alice\r", "\ralice", "\talice", "alice\u{00A0}", "\u{3000}alice", "al\rice"] {
            XCTAssertThrowsError(try config { $0.username = u }.render(), u.debugDescription) {
                guard case .invalidValue(let field, _)? = $0 as? FortiConfig.ValidationError else {
                    return XCTFail("\($0)")
                }
                XCTAssertEqual(field, "username")
            }
        }
        XCTAssertNoThrow(try config { $0.username = "alice smith" }.render())
    }

    /// openfortivpn keeps 64 bytes of the user name (USERNAME_SIZE) and cuts off the rest without a
    /// word, so a longer one is refused. Counted in UTF-8 bytes: 33 × "ş" is 33 characters but 66 bytes.
    func testUsernameLimitIsOpenfortivpnsInBytes() {
        XCTAssertEqual(FortiConfig.maxUsernameBytes, 64)
        for u in [String(repeating: "a", count: 64), String(repeating: "ş", count: 32), String(repeating: "a", count: 62) + "é"] {
            XCTAssertNoThrow(try config { $0.username = u }.render(), u)
        }
        for u in [
            String(repeating: "a", count: 65), String(repeating: "ş", count: 33), String(repeating: "a", count: 63) + "é",
            String(repeating: "a", count: 255)
        ] {
            XCTAssertThrowsError(try config { $0.username = u }.render(), u) {
                guard case .invalidValue(let field, _)? = $0 as? FortiConfig.ValidationError else { return XCTFail("\($0)") }
                XCTAssertEqual(field, "username")
            }
        }
    }

    /// The other values stay within what openfortivpn keeps (config.h): host 253, password 256, code 64.
    func testOtherValuesStayWithinOpenfortivpnsBuffers() {
        XCTAssertLessThanOrEqual(FortiConfig.maxHostBytes, 253)
        XCTAssertLessThanOrEqual(FortiConfig.maxPasswordBytes, 256)
        XCTAssertLessThanOrEqual(FortiConfig.maxOTPBytes, 64)
        let label = String(repeating: "a", count: 63)
        let host253 = [label, label, label, String(repeating: "a", count: 61)].joined(separator: ".")
        XCTAssertEqual(host253.utf8.count, 253)
        XCTAssertNoThrow(try config { $0.host = host253 }.render())
        XCTAssertThrowsError(try config { $0.host = host253 + "a" }.render())
        XCTAssertNoThrow(try config { $0.password = String(repeating: "p", count: 255) }.render())
        XCTAssertThrowsError(try config { $0.password = String(repeating: "p", count: 256) }.render())
        XCTAssertNoThrow(try config { $0.otp = String(repeating: "1", count: 64) }.render())
        XCTAssertThrowsError(try config { $0.otp = String(repeating: "1", count: 65) }.render())
    }

    func testPortBounds() {
        for p in [Int.min, -1, 0, 65536, 70000, Int.max] {
            XCTAssertThrowsError(try config { $0.port = p }.render(), "\(p)") {
                XCTAssertEqual($0 as? FortiConfig.ValidationError, .invalidPort(p))
            }
        }
        for p in [1, 443, 10443, 65535] {
            XCTAssertNoThrow(try config { $0.port = p }.render(), "\(p)")
        }
    }
}

// MARK: - Supervisor policy

final class SessionPolicyTests: XCTestCase {
    typealias S = SessionPolicy.Session
    let alice: uid_t = 501, bob: uid_t = 502

    var sessions: [S] {
        [
            S(profileID: "acme", ownerUID: alice, pid: 100, mgmtSocket: PT.mgmtSocketPath(uid: 501, profileID: "acme")),
            S(profileID: "acme-forti", ownerUID: alice, pid: 101),
            S(profileID: "lab", ownerUID: bob, pid: 200, mgmtSocket: PT.mgmtSocketPath(uid: 502, profileID: "lab"))
        ]
    }

    func testStartForRunningIDIsRejected() {
        XCTAssertThrowsError(try SessionPolicy.checkStart(profileID: "acme", uid: alice, sessions: sessions)) {
            XCTAssertEqual($0 as? SessionPolicy.Denial, .alreadyRunning("acme", pid: 100))
        }
        XCTAssertNoThrow(try SessionPolicy.checkStart(profileID: "other", uid: alice, sessions: sessions))
    }

    func testSameIDForTwoUsersDoesNotCollide() throws {
        XCTAssertNoThrow(try SessionPolicy.checkStart(profileID: "acme", uid: bob, sessions: sessions))
        let both =
            sessions + [
                S(
                    profileID: "acme", ownerUID: bob, pid: 300,
                    mgmtSocket: PT.mgmtSocketPath(uid: 502, profileID: "acme"))
            ]
        XCTAssertEqual(SessionPolicy.visible(to: alice, sessions: both)["acme"], 100)
        XCTAssertEqual(SessionPolicy.visible(to: bob, sessions: both)["acme"], 300)
        XCTAssertEqual(SessionPolicy.stopDecision(profileID: "acme", uid: alice, sessions: both), .terminate(pid: 100))
        XCTAssertEqual(SessionPolicy.stopDecision(profileID: "acme", uid: bob, sessions: both), .terminate(pid: 300))
        XCTAssertEqual(SessionPolicy.sockets(visibleTo: bob, sessions: both)["acme"], PT.helperRunRoot + "/502/acme/mgmt.sock")
        XCTAssertNotEqual(Set(both.map(\.key)).count, Set(both.map(\.profileID)).count)
    }

    func testStatusIsScopedToCaller() {
        XCTAssertEqual(SessionPolicy.visible(to: alice, sessions: sessions), ["acme": 100, "acme-forti": 101])
        XCTAssertEqual(SessionPolicy.visible(to: bob, sessions: sessions), ["lab": 200])
        XCTAssertEqual(SessionPolicy.visible(to: 503, sessions: sessions), [:])
        XCTAssertEqual(SessionPolicy.visible(to: 0, sessions: sessions), [:], "root only sees its own sessions")
        XCTAssertEqual(
            SessionPolicy.sockets(visibleTo: alice, sessions: sessions),
            ["acme": PT.helperRunRoot + "/501/acme/mgmt.sock"])
        XCTAssertEqual(SessionPolicy.sockets(visibleTo: 503, sessions: sessions), [:])
    }

    /// Another user's session is invisible: `stop` of it is the same no-op as an unknown ID.
    func testStopIsScopedToCaller() {
        XCTAssertEqual(SessionPolicy.stopDecision(profileID: "lab", uid: alice, sessions: sessions), .notRunning)
        XCTAssertEqual(SessionPolicy.stopDecision(profileID: "lab", uid: 0, sessions: sessions), .notRunning)
        XCTAssertEqual(SessionPolicy.stopDecision(profileID: "lab", uid: bob, sessions: sessions), .terminate(pid: 200))
    }

    /// `stop` of an id that is not running stays a successful no-op, so disconnecting twice (or after
    /// the tool already exited) never shows an error.
    func testStopOfUnknownIDIsIdempotent() {
        XCTAssertEqual(SessionPolicy.stopDecision(profileID: "ghost", uid: alice, sessions: sessions), .notRunning)
        XCTAssertEqual(SessionPolicy.stopDecision(profileID: "acme", uid: alice, sessions: []), .notRunning)
    }

    func testPerUserSessionCap() throws {
        XCTAssertEqual(SessionPolicy.maxSessionsPerUser, 8)
        let full = (0..<8).map { S(profileID: "p\($0)", ownerUID: alice, pid: Int32(1000 + $0)) }
        XCTAssertNoThrow(try SessionPolicy.checkStart(profileID: "p7", uid: alice, sessions: Array(full.prefix(7))))
        XCTAssertThrowsError(try SessionPolicy.checkStart(profileID: "p8", uid: alice, sessions: full)) {
            XCTAssertEqual($0 as? SessionPolicy.Denial, .tooManySessions(limit: 8))
            XCTAssertEqual(String(describing: $0), "Too many active connections (limit 8). Disconnect one first.")
        }
        // Other users are not affected by alice's sessions, even with the same IDs.
        XCTAssertNoThrow(try SessionPolicy.checkStart(profileID: "p3", uid: bob, sessions: full))
        // An already-running id is reported as such even at the cap.
        XCTAssertThrowsError(try SessionPolicy.checkStart(profileID: "p3", uid: alice, sessions: full)) {
            XCTAssertEqual($0 as? SessionPolicy.Denial, .alreadyRunning("p3", pid: 1003))
        }
    }
}

// MARK: - Code signature checks

#if os(macOS)
final class CodeSignatureTests: XCTestCase {
    var dir: URL!
    var tool: String { dir.appendingPathComponent("tool").path }
    let identifier = "com.example.acme.tool"
    let marker = "ACME-SIGNATURE-MARKER-0123456789"

    @discardableResult
    func run(_ executable: String, _ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return -1 }
        p.waitUntilExit()
        return p.terminationStatus
    }

    override func setUpWithError() throws {
        let fm = FileManager.default
        guard fm.isExecutableFile(atPath: "/usr/bin/codesign"), fm.isExecutableFile(atPath: "/usr/bin/xcrun") else {
            throw XCTSkip("codesign or xcrun is not available")
        }
        dir = fm.temporaryDirectory.appendingPathComponent("pt-codesign-\(UUID().uuidString)")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let src = dir.appendingPathComponent("tool.c")
        try "#include <stdio.h>\nint main(void) { puts(\"\(marker)\"); return 0; }\n"
            .write(to: src, atomically: true, encoding: .utf8)
        guard run("/usr/bin/xcrun", ["clang", "-o", tool, src.path]) == 0, fm.fileExists(atPath: tool) else {
            throw XCTSkip("no C compiler available")
        }
    }

    override func tearDownWithError() throws {
        if let dir { try? FileManager.default.removeItem(at: dir) }
    }

    func adHocSign(_ path: String) throws {
        guard run("/usr/bin/codesign", ["-f", "-s", "-", "-i", identifier, path]) == 0 else {
            throw XCTSkip("ad-hoc signing failed")
        }
    }

    func status(_ path: String, _ requirement: String) -> OSStatus {
        do {
            try CodeSignature.verify(path: path, requirement: requirement)
            return errSecSuccess
        } catch let f as CodeSignature.Failure {
            return f.status
        } catch {
            XCTFail("unexpected \(error)")
            return -1
        }
    }

    var ownIdentifier: String { "identifier \"\(identifier)\"" }

    func testRequirementStringsCompile() {
        XCTAssertTrue(CodeSignature.isValidRequirement(PT.clientRequirement))
        XCTAssertTrue(CodeSignature.isValidRequirement(PT.teamRequirement))
        for id in [PT.openvpnIdentifier, PT.openfortivpnIdentifier, PT.dnsUpdownIdentifier] {
            XCTAssertTrue(CodeSignature.isValidRequirement(PT.toolRequirement(identifier: id)), id)
        }
        XCTAssertFalse(CodeSignature.isValidRequirement("identifier and"))
    }

    func testAdHocBinaryFailsOurRequirements() throws {
        try adHocSign(tool)
        // Positive control: the signature itself is intact, so failures below come from the requirement.
        XCTAssertEqual(status(tool, ownIdentifier), errSecSuccess)
        for req in [
            PT.toolRequirement(identifier: identifier), PT.toolRequirement(identifier: PT.openvpnIdentifier),
            PT.toolRequirement(identifier: PT.openfortivpnIdentifier), PT.clientRequirement, PT.teamRequirement
        ] {
            XCTAssertEqual(status(tool, req), errSecCSReqFailed, req)
        }
    }

    func testUnsignedBinaryFails() throws {
        guard run("/usr/bin/codesign", ["--remove-signature", tool]) == 0 else { throw XCTSkip("cannot strip signature") }
        for req in [ownIdentifier, PT.toolRequirement(identifier: PT.openvpnIdentifier), PT.clientRequirement] {
            XCTAssertEqual(status(tool, req), errSecCSUnsigned, req)
        }
        let missing = dir.appendingPathComponent("missing").path
        XCTAssertNotEqual(status(missing, ownIdentifier), errSecSuccess)
    }

    func testBinaryModifiedAfterSigningFails() throws {
        try adHocSign(tool)
        var data = try Data(contentsOf: URL(fileURLWithPath: tool))
        guard let range = data.range(of: Data(marker.utf8)) else { return XCTFail("marker not found") }
        data[range.lowerBound] ^= 0x20
        let modified = dir.appendingPathComponent("tool-modified").path
        XCTAssertTrue(FileManager.default.createFile(atPath: modified, contents: data, attributes: [.posixPermissions: 0o755]))
        XCTAssertNotEqual(status(modified, ownIdentifier), errSecSuccess)
        XCTAssertNotEqual(status(modified, PT.toolRequirement(identifier: identifier)), errSecSuccess)
        XCTAssertEqual(status(tool, ownIdentifier), errSecSuccess, "the untouched copy still validates")
    }
}
#endif

// MARK: - Secrets never printed

extension HelperMessageTests {
    func rendered(_ value: Any) -> [String] {
        var dumped = ""
        dump(value, to: &dumped)
        return [String(describing: value), String(reflecting: value), "\(value)", dumped]
    }

    func testSecretsRedactedInEveryRendering() {
        let scrv = "SCRV1:VE9QU0VDUkVU:OTg3NjU0"
        let o = OpenVPNStart(profileID: "acme", profileDir: "/d", username: "alice", secret: scrv, logPath: "/d/vpn.log")
        let f = FortiStart(
            profileID: "acme", profileDir: "/d", host: "vpn.example.com", username: "alice",
            password: "TOPSECRET", otp: "987654", logPath: "/d/vpn.log")
        let values: [Any] = [
            o, f, HelperRequest.startOpenVPN(o), HelperRequest.startForti(f), FortiConfig(f),
            [HelperRequest.startForti(f)]
        ]
        for v in values {
            for text in rendered(v) {
                for secret in [scrv, "VE9QU0VDUkVU", "TOPSECRET", "987654"] {
                    XCTAssertFalse(text.contains(secret), "\(secret) leaked in \(text)")
                }
                XCTAssertTrue(text.contains("alice"), text)  // non-secret fields stay visible
            }
        }
    }

    func testErrorMessagesDoNotContainSecrets() {
        var messages: [String] = []
        let secret = "TOPSECRET"
        for bad in [secret + "\n", " " + secret, String(repeating: secret, count: 40), secret + "\u{0}"] {
            for change in [{ (c: inout FortiConfig) in c.password = bad }, { $0.otp = bad }, { $0.username = bad }] {
                var c = FortiConfig(host: "vpn.example.com", username: "alice", password: "pw", otp: "1")
                change(&c)
                do { _ = try c.render(); XCTFail("accepted \(bad.debugDescription)") } catch { messages.append("\(error)") }
            }
            // OpenVPN credentials may contain spaces; only line breaks, NUL and length are refused.
            if bad.first == " " { continue }
            do { try HelperCore.checkCredential(bad, field: "password", maxBytes: 64); XCTFail() } catch {
                messages.append("\(error)")
                messages.append(error.localizedDescription)
            }
        }
        do { _ = try OVPNSanitizer.sanitize("auth-user-pass /tmp/\(secret)\nup \(secret)\n") } catch {
            messages.append("\(error)")
        }
        XCTAssertGreaterThan(messages.count, 10)
        for m in messages { XCTAssertFalse(m.contains(secret), m) }
    }
}
