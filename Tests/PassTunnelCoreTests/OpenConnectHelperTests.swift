import XCTest

@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

/// The helper's side of a Cisco AnyConnect session that needs no files: the request (protocol 4), its
/// checks, the environment and arguments, the session and policy records, and the hook stub's decisions.
final class OpenConnectRequestTests: XCTestCase {
    static let cookie = "EXAMPLE-COOKIE-3F2A@1234@ABCD"

    static func start(_ change: (inout OpenConnectStart) -> Void = { _ in }) -> OpenConnectStart {
        var s = OpenConnectStart(
            profileID: "acme", profileDir: "/d/acme", logPath: "/d/acme/vpn.log", host: "vpn.example.com", port: 8443,
            usergroup: "staff", connectURL: "https://vpn.example.com:8443/", resolve: "vpn.example.com:192.0.2.10",
            cookie: cookie, serverCert: examplePin, profileServerCert: examplePin, tlsOnly: false, setDNS: true, setRoutes: true)
        change(&s)
        return s
    }

    func config(_ change: (inout OpenConnectStart) -> Void = { _ in }) throws -> OpenConnectConfig {
        try HelperCore.openConnectConfig(Self.start(change), scriptPath: exampleHook)
    }

    // MARK: Wire format

    func testRequestRoundTripsThroughTheHelperDecoder() throws {
        for s in [
            Self.start(),
            Self.start {
                $0.resolve = nil; $0.host = "192.0.2.10"; $0.profileServerCert = ""
            }
        ] {
            let request = HelperRequest.startOpenConnect(s)
            XCTAssertEqual(try HelperCore.decodeRequest(try request.jsonData()), request)
        }
        let object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: try HelperRequest.startOpenConnect(Self.start()).jsonData()) as? [String: Any])
        XCTAssertEqual(
            Set(object.keys),
            [
                "type", "protocol_version", "profile_id", "profile_dir", "log_path", "host", "port", "usergroup", "connect_url",
                "resolve", "cookie", "server_cert", "profile_server_cert", "tls_only", "set_dns", "set_routes"
            ])
        XCTAssertEqual(object["type"] as? String, "start_openconnect")
        XCTAssertEqual(object["protocol_version"] as? Int, 4)
        XCTAssertEqual(object["connect_url"] as? String, "https://vpn.example.com:8443/")
        XCTAssertEqual(object["server_cert"] as? String, examplePin)
        XCTAssertEqual(object["port"] as? Int, 8443)
        // Without a resolve (an IP-address host) the key is left out, and a request without it decodes.
        let noResolve = String(decoding: try HelperRequest.startOpenConnect(Self.start { $0.resolve = nil }).jsonData(), as: UTF8.self)
        XCTAssertFalse(noResolve.contains("resolve"))
        // The request stays far below the helper's limit with the longest cookie.
        let longest = try HelperRequest.startOpenConnect(Self.start { $0.cookie = String(repeating: "C", count: 4096) }).jsonData()
        XCTAssertLessThan(longest.count, HelperCore.maxRequestBytes / 8)
    }

    func testMissingAndMistypedFieldsAreNamedNeverEchoed() throws {
        let full = try JSONSerialization.jsonObject(with: try HelperRequest.startOpenConnect(Self.start()).jsonData()) as! [String: Any]
        for key in [
            "profile_id", "profile_dir", "log_path", "host", "port", "usergroup", "connect_url", "cookie", "server_cert",
            "profile_server_cert", "tls_only", "set_dns", "set_routes"
        ] {
            var json = full
            json[key] = nil
            let data = try JSONSerialization.data(withJSONObject: json)
            XCTAssertThrowsError(try HelperCore.decodeRequest(data), key) {
                XCTAssertEqual($0 as? HelperCore.RequestError, .invalidField(key))
                XCTAssertFalse(String(describing: $0).contains(Self.cookie))
            }
        }
        for (key, value) in [("cookie", [Self.cookie] as Any), ("port", "443" as Any), ("tls_only", "yes" as Any)] {
            var json = full
            json[key] = value
            XCTAssertThrowsError(try HelperCore.decodeRequest(try JSONSerialization.data(withJSONObject: json)), key) {
                XCTAssertEqual($0 as? HelperCore.RequestError, .invalidField(key))
                XCTAssertFalse(String(describing: $0).contains(Self.cookie))
            }
        }
    }

    func testSecretAndServerValuesAreRedacted() {
        // The server chose connect_url, resolve and server_cert, and could have repeated the cookie in them.
        let s = Self.start {
            $0.connectURL = "https://vpn.example.com:8443/?\(Self.cookie)"
            $0.resolve = "vpn.example.com:\(Self.cookie)"
            $0.serverCert = Self.cookie
        }
        let request = HelperRequest.startOpenConnect(s)
        var dumped = ""
        dump(s, to: &dumped)
        for text in [s.description, s.debugDescription, String(describing: request), String(reflecting: request), dumped] {
            XCTAssertFalse(text.contains(Self.cookie), text)
            XCTAssertFalse(text.contains("192.0.2.10"), text)
        }
        XCTAssertTrue(s.description.contains("profileID: acme") && s.description.contains("host: vpn.example.com"))
    }

    // MARK: Checks

    func testValidRequests() throws {
        let c = try config()
        XCTAssertEqual(c.host, "vpn.example.com")
        XCTAssertEqual(c.port, 8443)
        XCTAssertEqual(c.serverCert, examplePin)
        XCTAssertEqual(c.resolveAddress, "192.0.2.10")
        XCTAssertEqual(c.scriptPath, exampleHook)
        // No profile pin: the key the sign-in accepted through the system CAs.
        XCTAssertNoThrow(try config { $0.profileServerCert = "" })
        XCTAssertNoThrow(try config { $0.usergroup = "" })
        XCTAssertEqual(
            try config {
                $0.port = 443; $0.connectURL = "https://vpn.example.com/"
            }.port, 443)
        XCTAssertTrue(try config { $0.tlsOnly = true }.tlsOnly)
        // IP-address hosts: no resolve.
        XCTAssertNil(
            try config {
                $0.host = "192.0.2.10"; $0.connectURL = "https://192.0.2.10:8443/"; $0.resolve = nil
            }.resolveAddress)
        XCTAssertNil(
            try config {
                $0.host = "2001:db8::1"; $0.connectURL = "https://[2001:db8::1]:8443/"; $0.resolve = nil
            }.resolveAddress)
    }

    /// Every field the helper refuses, each with what it throws; none of the errors carries the cookie.
    func testEveryInvalidFieldIsRefused() {
        typealias V = OpenConnectConfig.ValidationError
        typealias D = OpenConnectAuthResult.DestinationError
        let cases: [(String, (inout OpenConnectStart) -> Void, (Error) -> Bool)] = [
            ("profile ID", { $0.profileID = "../acme" }, { ($0 as? HelperCore.Failure) == .invalidProfileID("../acme") }),
            ("empty profile ID", { $0.profileID = "" }, { ($0 as? HelperCore.Failure) == .invalidProfileID("") }),
            ("user group", { $0.usergroup = "../x" }, { if case .invalidValue("user group", _)? = $0 as? V { return true } else { return false } }),
            (
                "user group line", { $0.usergroup = "a\nscript /tmp/x" },
                { if case .invalidValue("user group", _)? = $0 as? V { return true } else { return false } }
            ),
            ("profile pin", { $0.profileServerCert = "sha1:0123" }, { ($0 as? V) == .invalidServerCert }),
            ("profile pin prefix", { $0.profileServerCert = "pin-sha256:z5Gv" }, { ($0 as? V) == .invalidServerCert }),
            ("host", { $0.host = "vpn.example.com\nscript /tmp/x" }, { ($0 as? V) == .invalidHost }),
            ("host zone", { $0.host = "fe80::1%en0" }, { ($0 as? V) == .invalidHost }),
            ("port 0", { $0.port = 0 }, { ($0 as? V) == .invalidPort(0) }),
            ("port high", { $0.port = 65536 }, { ($0 as? V) == .invalidPort(65536) }),
            ("connect URL host", { $0.connectURL = "https://vpn.example.net:8443/" }, { ($0 as? D) == .otherServer }),
            ("connect URL port", { $0.connectURL = "https://vpn.example.com/" }, { ($0 as? D) == .otherServer }),
            ("connect URL path", { $0.connectURL = "https://vpn.example.com:8443/staff" }, { ($0 as? D) == .otherServer }),
            ("connect URL query", { $0.connectURL = "https://vpn.example.com:8443/?a=b" }, { ($0 as? D) == .otherServer }),
            ("connect URL user", { $0.connectURL = "https://alice@vpn.example.com:8443/" }, { ($0 as? D) == .otherServer }),
            ("connect URL scheme", { $0.connectURL = "http://vpn.example.com:8443/" }, { ($0 as? D) == .otherServer }),
            ("connect URL empty", { $0.connectURL = "" }, { $0 is OpenConnectAuthResult.ParseError }),
            ("connect URL line", { $0.connectURL = "https://vpn.example.com:8443/\n" }, { $0 is OpenConnectAuthResult.ParseError }),
            ("connect URL quote", { $0.connectURL = "https://vpn.example.com:8443/'" }, { $0 is OpenConnectAuthResult.ParseError }),
            (
                "connect URL long", { $0.connectURL = "https://vpn.example.com:8443/" + String(repeating: "a", count: 300) },
                { $0 is OpenConnectAuthResult.ParseError }
            ),
            ("resolve missing", { $0.resolve = nil }, { ($0 as? D) == .noResolvedAddress }),
            ("resolve other host", { $0.resolve = "vpn.example.net:192.0.2.10" }, { ($0 as? D) == .addressMismatch }),
            ("resolve not an address", { $0.resolve = "vpn.example.com:vpn.example.net" }, { ($0 as? D) == .addressMismatch }),
            ("resolve zone", { $0.resolve = "vpn.example.com:fe80::1%en0" }, { ($0 as? D) == .addressMismatch }),
            ("resolve empty", { $0.resolve = "" }, { $0 is OpenConnectAuthResult.ParseError }),
            ("resolve line", { $0.resolve = "vpn.example.com:192.0.2.10\nscript /tmp/x" }, { $0 is OpenConnectAuthResult.ParseError }),
            (
                "resolve for an address",
                {
                    $0.host = "192.0.2.10"; $0.connectURL = "https://192.0.2.10:8443/"; $0.resolve = "192.0.2.10:192.0.2.10"
                },
                { ($0 as? D) == .addressMismatch }
            ),
            ("cookie empty", { $0.cookie = "" }, { if case .invalidValue("cookie", _)? = $0 as? V { return true } else { return false } }),
            (
                "cookie long", { $0.cookie = String(repeating: "C", count: 4097) },
                { if case .invalidValue("cookie", _)? = $0 as? V { return true } else { return false } }
            ),
            (
                "cookie line", { $0.cookie = "abc\nscript /tmp/x" },
                { if case .invalidValue("cookie", _)? = $0 as? V { return true } else { return false } }
            ),
            ("cookie quote", { $0.cookie = "abc'def" }, { if case .invalidValue("cookie", _)? = $0 as? V { return true } else { return false } }),
            ("cookie equals", { $0.cookie = "=abc" }, { if case .invalidValue("cookie", _)? = $0 as? V { return true } else { return false } }),
            ("cookie blank", { $0.cookie = " abc" }, { if case .invalidValue("cookie", _)? = $0 as? V { return true } else { return false } }),
            ("cookie NUL", { $0.cookie = "abc\u{0}def" }, { if case .invalidValue("cookie", _)? = $0 as? V { return true } else { return false } }),
            ("server cert", { $0.serverCert = "sha256:00" }, { ($0 as? V) == .invalidServerCert }),
            ("server cert empty", { $0.serverCert = "" }, { ($0 as? V) == .invalidServerCert }),
            ("pin mismatch", { $0.serverCert = otherExamplePin }, { ($0 as? D) == .fingerprintMismatch })
        ]
        for (name, change, expected) in cases {
            var start = Self.start()
            change(&start)
            XCTAssertThrowsError(try HelperCore.openConnectConfig(start, scriptPath: exampleHook), name) { error in
                XCTAssertTrue(expected(error), "\(name): \(error)")
                XCTAssertFalse(String(describing: error).contains(Self.cookie), name)
                XCTAssertFalse(error.localizedDescription.contains(Self.cookie), name)
            }
        }
        // The hook path itself (it reaches `/bin/sh -c`).
        for bad in ["relative/vpn-hook", "/tmp/a b", "/tmp/$(x)", "/tmp/../vpn-hook", "/tmp/x;y", ""] {
            XCTAssertThrowsError(try HelperCore.openConnectConfig(Self.start(), scriptPath: bad), bad)
        }
    }

    func testLineCountFollowsTheRequest() throws {
        for s in [
            Self.start(), Self.start { $0.tlsOnly = true },
            Self.start {
                $0.host = "192.0.2.10"; $0.connectURL = "https://192.0.2.10:8443/"; $0.resolve = nil
            }
        ] {
            let text = try HelperCore.openConnectConfig(s, scriptPath: exampleHook).render()
            XCTAssertEqual(text.split(separator: "\n").count, HelperCore.openConnectLineCount(s))
            XCTAssertNoThrow(try OpenConnectConfig.checkRendered(text, lineCount: HelperCore.openConnectLineCount(s)))
        }
    }

    func testMacOSVersionGate() {
        var core = HelperCore(runRoot: "/nonexistent", homeDirectory: { _ in nil }, userName: { _ in nil })
        for (major, minor, patch, runs) in [
            (13, 0, 0, false), (14, 7, 6, false), (15, 3, 2, false), (15, 4, 0, true), (15, 4, 1, true), (26, 0, 0, true)
        ] {
            core.systemVersion = OperatingSystemVersion(majorVersion: major, minorVersion: minor, patchVersion: patch)
            if runs {
                XCTAssertNoThrow(try core.checkOpenConnectRuns(), "\(major).\(minor).\(patch)")
            } else {
                XCTAssertThrowsError(try core.checkOpenConnectRuns(), "\(major).\(minor).\(patch)") {
                    XCTAssertEqual($0 as? HelperCore.Failure, .requiresNewerMacOS(.openconnect, "15.4"))
                    XCTAssertEqual(String(describing: $0), "Cisco AnyConnect requires macOS 15.4 or later.")
                }
            }
        }
        core.systemVersion = nil  // Linux: not checked
        XCTAssertNoThrow(try core.checkOpenConnectRuns())
    }

    // MARK: Environment and arguments

    func testOpenConnectArgumentsAreTheConfigFileOnly() {
        XCTAssertEqual(
            HelperCore.openConnectArguments(configPath: "/var/run/passtunnel/501/acme/openconnect.conf"),
            [
                "--config=/var/run/passtunnel/501/acme/openconnect.conf"
            ])
    }

    func testEnvironmentIsBuiltNotInherited() {
        let leaks = [
            "https_proxy", "http_proxy", "HTTPS_PROXY", "ALL_PROXY", "no_proxy", "SSLKEYLOGFILE", "GNUTLS_DEBUG_LEVEL",
            "TPM_INTERFACE_TYPE", "GNUTLS_SYSTEM_PRIORITY_FILE", "P11_KIT_NO_USER_CONFIG", "OPENSSL_CONF", "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD", "HOME", "TMPDIR", "LANG"
        ]
        let before = HelperCore.Tool.allCases.map { HelperCore.environment(for: $0) }
        for name in leaks { setenv(name, "/tmp/pt-leak", 1) }
        defer { for name in leaks { unsetenv(name) } }
        XCTAssertEqual(HelperCore.Tool.allCases.map { HelperCore.environment(for: $0) }, before, "nothing comes from the process environment")

        XCTAssertEqual(HelperCore.environment(for: .openvpn), HelperCore.fixedEnvironment)
        XCTAssertEqual(HelperCore.environment(for: .openfortivpn), HelperCore.fixedEnvironment)
        let env = HelperCore.environment(for: .openconnect)
        #if os(macOS)
        XCTAssertEqual(
            env,
            [
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "OPENSSL_CONF=/dev/null",
                "OPENSSL_MODULES=/var/empty/passtunnel-none", "OPENSSL_ENGINES=/var/empty/passtunnel-none",
                "SSL_CERT_FILE=/etc/ssl/cert.pem", "SSL_CERT_DIR=/var/empty",
                "GNUTLS_SYSTEM_PRIORITY_FILE=/dev/null", "P11_KIT_NO_USER_CONFIG=1"
            ])
        #else
        XCTAssertEqual(env, ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "P11_KIT_NO_USER_CONFIG=1"])
        #endif
        let names = env.map { String($0.prefix { $0 != "=" }) }
        XCTAssertEqual(Set(names).count, names.count, "no variable twice")
        for name in [
            "https_proxy", "http_proxy", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "all_proxy", "SSLKEYLOGFILE", "GNUTLS_DEBUG_LEVEL",
            "TPM_INTERFACE_TYPE", "HOME", "LANG", "TMPDIR"
        ] {
            XCTAssertFalse(names.contains(name), name)
        }
        XCTAssertFalse(names.contains { $0.hasPrefix("DYLD_") || $0.hasPrefix("LD_") })
    }

    // MARK: Session records

    func testSessionStateRoundTrip() throws {
        let s = SessionState(
            pid: 4242, uid: 501, executable: "/private/var/run/passtunnel/tools/ab/Resources/bin/openconnect",
            profileDir: "/Users/alice/Library/Application Support/PassTunnel/profiles/acme", mgmtSocket: nil)
        XCTAssertEqual(SessionState.parse(try s.text()), s)
        let v = SessionState(pid: 7, uid: 0, executable: "/x/openvpn", profileDir: "/p", mgmtSocket: "/var/run/passtunnel/0/a/mgmt.sock")
        XCTAssertEqual(SessionState.parse(try v.text()), v)
        // A protocol-2 helper wrote three lines.
        XCTAssertEqual(SessionState.parse("42\n501\n/x/openvpn\n")?.executable, "/x/openvpn")
        for bad in ["", "x\n501\n/x\n", "1\n501\n/x\n", "42\nalice\n/x\n", "42\n501\n", "42\n501\n\n"] {
            XCTAssertNil(SessionState.parse(bad), bad.debugDescription)
        }
        // A field with a line break would shift the others: refused, never written.
        let shifted = SessionState(pid: 42, uid: 501, executable: "/x/openconnect\n0", profileDir: "/p", mgmtSocket: nil)
        XCTAssertThrowsError(try shifted.text())
    }

    func testPolicyRoundTripAndStrictParse() throws {
        let p = OpenConnectPolicy(uid: 501, profileID: "acme", setRoutes: true, setDNS: false)
        XCTAssertEqual(try p.text(), "uid=501\nprofile=acme\nset_routes=1\nset_dns=0\n")
        XCTAssertEqual(OpenConnectPolicy.parse(try p.text()), p)
        XCTAssertThrowsError(try OpenConnectPolicy(uid: 501, profileID: "a\nset_dns=1", setRoutes: false, setDNS: false).text())
        for bad in [
            "", "uid=501\nprofile=acme\nset_routes=1\nset_dns=0", "uid=0501\nprofile=acme\nset_routes=1\nset_dns=0\n",
            "uid=501\nprofile=../x\nset_routes=1\nset_dns=0\n", "uid=501\nprofile=acme\nset_routes=yes\nset_dns=0\n",
            "profile=acme\nuid=501\nset_routes=1\nset_dns=0\n", "uid=501\nprofile=acme\nset_routes=1\nset_dns=0\nset_dns=1\n",
            "uid=501\nprofile=acme\nset_routes=1\nset_dns=0\r\n"
        ] {
            XCTAssertNil(OpenConnectPolicy.parse(bad), bad.debugDescription)
        }
    }
}

// MARK: - vpn-hook

final class VPNHookTests: XCTestCase {
    func testModeNeedsBothTheStagedNameAndArgv0() {
        let hook = "/private/var/run/passtunnel/tools/" + String(repeating: "ab", count: 32) + "/Resources/bin/vpn-hook"
        let helper = "/Applications/PassTunnel.app/Contents/MacOS/PassTunnelHelper"
        let cases: [(String?, String?, VPNHook.Mode)] = [
            (helper, helper, .helper),
            (helper, "PassTunnelHelper", .helper),
            (helper, nil, .helper),
            (nil, nil, .helper),
            (nil, helper, .helper),
            // openconnect runs `/bin/sh -c <path>`: argv[0] is the path.
            (hook, hook, .hook),
            (hook, "vpn-hook", .hook),
            // The installed helper never becomes the hook, whatever argv[0] says (exec -a).
            (helper, "vpn-hook", .refused),
            (helper, "/tmp/vpn-hook", .refused),
            (nil, "vpn-hook", .refused),
            // The staged copy never becomes the helper.
            (hook, helper, .refused),
            (hook, nil, .refused),
            (hook, "vpn-hook-x", .refused),
            (helper, "vpn-hook/", .refused)
        ]
        for (executable, argv0, mode) in cases {
            XCTAssertEqual(VPNHook.mode(executablePath: executable, argv0: argv0), mode, "\(executable ?? "nil") \(argv0 ?? "nil")")
        }
    }

    func testDeadlines() {
        // Without a record nothing is up: the session is stopped at the deadline.
        XCTAssertFalse(VPNHook.reportedUp(runDir: "/var/empty/passtunnel-none"))
        XCTAssertEqual(VPNHook.setupDeadline, 60)
        XCTAssertEqual(VPNHook.reconnectDeadline, 120)
        XCTAssertEqual(OpenConnectHook.runLimit, 30)
        XCTAssertEqual(OpenConnectHook.toolLimit, 10)
    }

    // A fake process tree: 1 launchd, 100 the helper, 200 openconnect, 300 /bin/sh, 400 the hook.
    let root = "/private/var/run/passtunnel"
    var build: String { root + "/tools/" + String(repeating: "ab", count: 32) + "/Resources/bin" }
    var hook: String { build + "/vpn-hook" }
    var tool: String { build + "/openconnect" }
    var runDir: String { root + "/501/acme" }
    var executables: [pid_t: String] = [:]
    var parents: [pid_t: pid_t] = [:]
    var cwds: [pid_t: String] = [:]
    var states: [String: SessionState] = [:]

    override func setUp() {
        executables = [1: "/sbin/launchd", 100: "/Applications/PassTunnel.app/Contents/MacOS/PassTunnelHelper", 200: tool, 300: "/bin/sh", 400: hook]
        parents = [100: 1, 200: 100, 300: 200, 400: 300]
        cwds = [200: runDir, 300: runDir, 400: runDir]
        states = [runDir + "/state": SessionState(pid: 200, uid: 501, executable: tool, profileDir: "/p", mgmtSocket: nil)]
    }

    func session(hook: String? = nil, parent: pid_t = 300) -> VPNHook.Session? {
        let processes = VPNHook.Processes(
            executable: { [executables] in executables[$0] }, parent: { [parents] in parents[$0] },
            workingDirectory: { [cwds] in cwds[$0] })
        let states = states
        return VPNHook.session(hookExecutable: hook ?? self.hook, parent: parent, runRoot: root, processes: processes) { states[$0] }
    }

    func testSessionIsProvenThroughTheShellOrDirectly() {
        let expected = VPNHook.Session(toolPID: 200, runDir: runDir, ownerUID: 501, profileID: "acme")
        XCTAssertEqual(session(), expected)
        XCTAssertEqual(session(parent: 200), expected, "the shell replaced itself with the hook")
        for shell in ["/bin/bash", "/bin/dash", "/bin/zsh"] {
            executables[300] = shell
            XCTAssertEqual(session(), expected, shell)
        }
    }

    func testAnythingUnprovenIsRefused() {
        func refused(_ name: String, _ change: (VPNHookTests) -> Void, hook: String? = nil, parent: pid_t = 300) {
            setUp()
            change(self)
            XCTAssertNil(session(hook: hook, parent: parent), name)
        }
        // The hook is not the staged copy.
        refused("hook in the bundle", { _ in }, hook: "/Applications/PassTunnel.app/Contents/Resources/bin/vpn-hook")
        refused("hook elsewhere in the run root", { _ in }, hook: root + "/501/acme/vpn-hook")
        refused("bad build", { _ in }, hook: root + "/tools/XYZ/Resources/bin/vpn-hook")
        refused("short build", { _ in }, hook: root + "/tools/abc/Resources/bin/vpn-hook")
        refused("nested build", { _ in }, hook: root + "/tools/" + String(repeating: "ab", count: 32) + "/x/Resources/bin/vpn-hook")
        refused("other name", { _ in }, hook: build + "/PassTunnelHelper")
        // The parent is not that openconnect.
        refused("parent is another program", { $0.executables[300] = "/usr/bin/python3" })
        refused("shell from elsewhere", { $0.executables[300] = "/tmp/sh" })
        refused("shell's parent is not openconnect", { $0.parents[300] = 100 })
        refused(
            "openconnect of another build",
            { $0.executables[200] = self.root + "/tools/" + String(repeating: "cd", count: 32) + "/Resources/bin/openconnect" })
        refused("openconnect from the bundle", { $0.executables[200] = "/Applications/PassTunnel.app/Contents/Resources/bin/openconnect" })
        refused(
            "two shells",
            {
                $0.executables[200] = "/bin/sh"; $0.parents[200] = 150; $0.executables[150] = self.tool
            }, parent: 300)
        refused("parent gone", { $0.executables[300] = nil })
        refused("reparented to launchd", { $0.parents[300] = 1 })
        // Its working directory is not a session directory.
        refused("no working directory", { $0.cwds[200] = nil })
        refused("cwd outside the run root", { $0.cwds[200] = "/tmp/501/acme" })
        refused("cwd is the run root", { $0.cwds[200] = self.root })
        refused("cwd too deep", { $0.cwds[200] = self.runDir + "/x" })
        refused("cwd user only", { $0.cwds[200] = self.root + "/501" })
        refused("cwd uid not canonical", { $0.cwds[200] = self.root + "/0501/acme" })
        refused("cwd uid not a number", { $0.cwds[200] = self.root + "/alice/acme" })
        refused("cwd bad profile", { $0.cwds[200] = self.root + "/501/.acme" })
        refused("cwd in tools", { $0.cwds[200] = self.root + "/tools/x" })
        // Its state does not name it.
        refused("no state", { $0.states = [:] })
        refused(
            "state of another pid",
            { $0.states[$0.runDir + "/state"] = SessionState(pid: 201, uid: 501, executable: $0.tool, profileDir: "/p", mgmtSocket: nil) })
        refused(
            "state of another user",
            { $0.states[$0.runDir + "/state"] = SessionState(pid: 200, uid: 502, executable: $0.tool, profileDir: "/p", mgmtSocket: nil) })
        refused(
            "state of another tool",
            { $0.states[$0.runDir + "/state"] = SessionState(pid: 200, uid: 501, executable: "/x/openvpn", profileDir: "/p", mgmtSocket: nil) })
    }
}
