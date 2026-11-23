import XCTest

@testable import PassTunnelShared

/// OpenVPN's own macOS `dns-updown` (not in the repository; Homebrew's, the build bundles it) run against a stand-in
/// for `scutil` that keeps the store in a JSON file, with `dscacheutil` and `shlock` stubbed and the lock in a
/// temporary directory: what it writes is what `OpenVPNDNSSession` says it writes, and what it leaves behind is what
/// `OpenVPNDNS.settle` gives back. Skipped where the script (or python3 for the stand-in) is not there. Nothing
/// touches the system's configuration. Also: the helper's append to a session's log (`HelperCore.appendToLog`).
final class DNSScriptTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pt-dnsscript-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    static let wifi = OpenVPNDNSTests.wifi

    /// `scutil`'s commands the script uses (show, get, set, add, remove, list, d.init, d.add with `*` and `#`),
    /// against `FAKE_STORE`. The current dictionary starts empty, and `get` of a key that is not there keeps it, as a fresh
    /// `scutil` does (`d.show` prints `<dictionary> { }`, and still does after such a `get`: checked on a Mac, reading only).
    static let fakeScutil = #"""
        #!/usr/bin/python3 -I
        import json, os, re, sys
        path = os.environ["FAKE_STORE"]
        store = json.load(open(path))
        d = {}
        def copy(v): return json.loads(json.dumps(v))
        for line in sys.stdin.read().split("\n"):
            w = line.split()
            if not w: continue
            cmd, args = w[0], w[1:]
            if cmd == "show":
                v = store.get(args[0])
                if v is None: print("  No such key"); continue
                print("<dictionary> {")
                for k in sorted(v):
                    x = v[k]
                    if isinstance(x, list):
                        print("  %s : <array> {" % k)
                        for i, e in enumerate(x): print("    %d : %s" % (i, e))
                        print("  }")
                    else:
                        print("  %s : %s" % (k, x))
                print("}")
            elif cmd == "get":
                v = store.get(args[0])
                if v is None: print("  No such key")
                else: d = copy(v)
            elif cmd in ("set", "add"):
                if d is None: print("  %s: dictionary must be initialized." % cmd)
                elif cmd == "add" and args[0] in store: print("  key already exists")
                else: store[args[0]] = copy(d)
            elif cmd == "d.init":
                d = {}
            elif cmd == "d.add":
                if d is None: print("d.add: dictionary must be initialized."); continue
                key, rest = args[0], args[1:]
                array = numeric = False
                while rest and rest[0] in ("*", "#", "-", "?", "%"):
                    array |= rest[0] == "*"; numeric |= rest[0] == "#"; rest = rest[1:]
                if not array and not rest: print("d.add: no values."); continue
                vals = [int(r) if numeric else r for r in rest]
                d[key] = vals if array else vals[0]
            elif cmd == "remove":
                store.pop(args[0], None)
            elif cmd == "list":
                keys = sorted(k for k in store if re.fullmatch(args[0], k))
                if not keys: print("  no key.")
                for i, k in enumerate(keys): print("  subKey [%d] = %s" % (i, k))
        json.dump(store, open(path, "w"))

        """#

    /// The script, copied with every system path it runs replaced by a stand-in; nil (the test is skipped) without
    /// the script or python3.
    func stubbedScript() throws -> String {
        let candidates = [
            ProcessInfo.processInfo.environment["PASSTUNNEL_DNS_UPDOWN"], "/opt/homebrew/opt/openvpn/libexec/openvpn/dns-updown",
            "/usr/local/opt/openvpn/libexec/openvpn/dns-updown"
        ].compactMap { $0 }
        guard let source = candidates.first(where: { FileManager.default.isReadableFile(atPath: $0) }) else {
            throw XCTSkip("OpenVPN's dns-updown is not installed (Homebrew's openvpn, or PASSTUNNEL_DNS_UPDOWN)")
        }
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/python3"), (try? run("/usr/bin/python3", ["-I", "-c", "pass"])) == 0 else {
            throw XCTSkip("python3 is not there for the scutil stand-in")
        }
        let bin = dir.appendingPathComponent("bin").path
        let lock = dir.appendingPathComponent("lock").path
        try FileManager.default.createDirectory(atPath: bin, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: lock, withIntermediateDirectories: true)
        try HelperCore.writeNewFile(bin + "/scutil", Data(Self.fakeScutil.utf8), mode: 0o700)
        for stub in ["dscacheutil", "shlock"] {
            try HelperCore.writeNewFile(bin + "/" + stub, Data("#!/bin/bash\nexit 0\n".utf8), mode: 0o700)
        }
        var text = try String(contentsOfFile: source, encoding: .utf8)
        text = text.replacingOccurrences(of: "/usr/sbin/scutil", with: bin + "/scutil")
            .replacingOccurrences(of: "/usr/bin/dscacheutil", with: bin + "/dscacheutil")
            .replacingOccurrences(of: "/usr/bin/shlock", with: bin + "/shlock")
            .replacingOccurrences(of: "lockdir=/var/lock", with: "lockdir=" + lock)
        for system in ["/usr/sbin/scutil", "/usr/bin/dscacheutil", "/usr/bin/shlock", "/var/lock"] {
            XCTAssertFalse(text.contains(system), "\(system) is still run")
        }
        let script = dir.appendingPathComponent("dns-updown").path
        try HelperCore.writeNewFile(script, Data(text.utf8), mode: 0o700)
        return script
    }

    var storePath: String { dir.appendingPathComponent("store.json").path }

    func store() throws -> [String: DNSEntity] {
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: storePath))) as? [String: Any])
        return json.compactMapValues { value -> DNSEntity? in
            guard let d = value as? [String: Any] else { return nil }
            return d.compactMapValues { v -> PlistValue? in
                if let s = v as? String { return .string(s) }
                if let n = v as? Int { return .integer(n) }
                if let a = v as? [Any] { return .array(a.map { .string("\($0)") }) }
                return nil
            }
        }
    }

    func setStore(_ store: [String: [String: Any]]) throws {
        try JSONSerialization.data(withJSONObject: store).write(to: URL(fileURLWithPath: storePath))
    }

    func runScript(_ script: String, _ type: String, _ variables: [String: String]) throws {
        let env = variables.merging(["PATH": HelperCore.dnsScriptSearchPath, "FAKE_STORE": storePath, "script_type": type]) { $1 }
        XCTAssertEqual(try run("/bin/bash", [script], environment: env), 0, type)
    }

    /// The full branch: what it writes is the model's override (every address as sent, the search domains without
    /// those the script takes for repeats); with no network at the dns-down it is left; the helper gives it back.
    func testFullBranchAgainstTheModel() throws {
        let script = try stubbedScript()
        let variables = [
            "dev": "utun7", "dns_server_1_address_1": "10.8.0.1", "dns_server_1_address_2": "10.8.0.2",
            "dns_server_1_address_3": "10.8.0.1", "dns_search_domain_1": "labxexample.com", "dns_search_domain_2": "lab.example.com",
            "dns_search_domain_3": "labxexample.com", "dns_search_domain_4": "corp.example.com"
        ]
        let session = try XCTUnwrap(OpenVPNDNSSession(variables: variables))
        XCTAssertEqual(session.servers, ["10.8.0.1", "10.8.0.2", "10.8.0.1"])
        XCTAssertEqual(session.searchDomains, ["labxexample.com", "corp.example.com"])

        try setStore(["State:/Network/Global/IPv4": ["PrimaryService": Self.wifi]])
        try runScript(script, "dns-up", variables)
        let written = try XCTUnwrap(store()["Setup:/Network/Service/\(Self.wifi)/DNS"])
        XCTAssertEqual(written, session.overrideEntity)
        XCTAssertEqual(try store()["State:/Network/Service/openvpn-utun7/DnsBackup"], [:], "Wi-Fi had no DNS key: an empty backup")

        // The network goes away; the dns-down finds no primary service and leaves it.
        var now = try store().mapValues { entity in entity.mapValues(Self.json) }
        now["State:/Network/Global/IPv4"] = nil
        try setStore(now)
        try runScript(script, "dns-down", variables)
        let left = try store()
        XCTAssertEqual(left["Setup:/Network/Service/\(Self.wifi)/DNS"], session.overrideEntity)

        let system = FakeDNSSystem()
        system.preferences = [Self.wifi: [:]]
        system.services = [Self.wifi: session.overrideEntity]
        let settled = OpenVPNDNS.settle(OpenVPNDNSRecord(session: session, status: 0, service: Self.wifi), live: [], system: system)
        XCTAssertEqual(settled.restored.map(\.serviceID), [Self.wifi])
    }

    /// A normal end on a service without DNS of its own: the dns-down puts the empty backup back, `{}`, which is no
    /// DNS as the preferences hold; nothing for the helper to do.
    func testANormalEndLeavesAnEmptyDictionary() throws {
        let script = try stubbedScript()
        let variables = ["dev": "utun7", "dns_server_1_address_1": "10.8.0.1"]
        try setStore(["State:/Network/Global/IPv4": ["PrimaryService": Self.wifi]])
        try runScript(script, "dns-up", variables)
        try runScript(script, "dns-down", variables)
        let store = try store()
        XCTAssertEqual(store["Setup:/Network/Service/\(Self.wifi)/DNS"], [:])
        XCTAssertNil(store["State:/Network/Service/openvpn-utun7/DnsBackup"])
        let system = FakeDNSSystem()
        system.preferences = [Self.wifi: [:]]
        system.services = [Self.wifi: [:]]
        let session = try XCTUnwrap(OpenVPNDNSSession(variables: variables))
        XCTAssertEqual(
            OpenVPNDNS.settle(OpenVPNDNSRecord(session: session, status: 0, service: Self.wifi), live: [], system: system),
            OpenVPNDNS.Settlement(.done))
        XCTAssertEqual(system.writes, [])
    }

    /// No server the script can use (a DoT one only): its `exit 1` ends only the `$(…)` that runs it, and the
    /// script goes on: status 0, a backup, and the override without any server, as the model says.
    func testNoUsableServerAgainstTheModel() throws {
        let script = try stubbedScript()
        let variables = [
            "dev": "utun7", "dns_server_1_address_1": "10.8.0.1", "dns_server_1_transport": "DoT",
            "dns_search_domain_1": "corp.example.com"
        ]
        try setStore([
            "State:/Network/Global/IPv4": ["PrimaryService": Self.wifi],
            "Setup:/Network/Service/\(Self.wifi)/DNS": ["ServerAddresses": ["192.0.2.1"]]
        ])
        try runScript(script, "dns-up", variables)
        let session = try XCTUnwrap(OpenVPNDNSSession(variables: variables))
        XCTAssertEqual(session.servers, [])
        let written = try XCTUnwrap(store()["Setup:/Network/Service/\(Self.wifi)/DNS"])
        XCTAssertEqual(written, session.overrideEntity)
        XCTAssertEqual(try store()["State:/Network/Service/openvpn-utun7/DnsBackup"], ["ServerAddresses": OpenVPNDNSTests.strings(["192.0.2.1"])])

        let system = FakeDNSSystem()
        system.preferences = [Self.wifi: ["ServerAddresses": OpenVPNDNSTests.strings(["192.0.2.1"])]]
        system.services = [Self.wifi: written]
        let settled = OpenVPNDNS.settle(OpenVPNDNSRecord(session: session, status: 0, service: Self.wifi), live: [], system: system)
        XCTAssertEqual(settled.restored.map(\.settings), [["corp.example.com"]])
        XCTAssertEqual(system.services[Self.wifi], ["ServerAddresses": OpenVPNDNSTests.strings(["192.0.2.1"])])
    }

    /// The split branch: its `State:` key is the model's; its dns-down removes it whatever the network.
    func testSplitBranchAgainstTheModel() throws {
        let script = try stubbedScript()
        let variables = [
            "dev": "utun7", "dns_server_1_address_1": "10.8.0.1", "dns_server_1_resolve_domain_1": "corp.example.com",
            "dns_server_1_resolve_domain_2": "corpxexample.com", "dns_server_1_resolve_domain_3": "corp.example.com"
        ]
        let session = try XCTUnwrap(OpenVPNDNSSession(variables: variables))
        XCTAssertEqual(session.matchDomains, ["corp.example.com", "corpxexample.com"])
        try setStore(["State:/Network/Global/IPv4": ["PrimaryService": Self.wifi]])
        try runScript(script, "dns-up", variables)
        let key = try XCTUnwrap(store()["State:/Network/Service/openvpn-utun7/DNS"])
        XCTAssertEqual(key["ServerAddresses"]?.strings, session.servers)
        XCTAssertEqual(key["SupplementalMatchDomains"]?.strings, session.matchDomains)
        // No network at the dns-down: no primary service.
        try setStore(["State:/Network/Service/openvpn-utun7/DNS": key.mapValues(Self.json)])
        try runScript(script, "dns-down", variables)
        XCTAssertNil(try store()["State:/Network/Service/openvpn-utun7/DNS"])
    }

    static func json(_ v: PlistValue) -> Any {
        switch v {
        case .string(let s): return s
        case .integer(let n): return n
        case .array(let a): return a.map(json)
        default: return "\(v)"
        }
    }

    // MARK: The session's log

    /// What the helper appends to a session's log once it no longer holds it open: only to a `.log` file of the
    /// user in the profile directory a start would accept, never through a link.
    func testAppendToTheSessionsLog() throws {
        let home = dir.appendingPathComponent("home")
        let profile = home.appendingPathComponent(PT.profilesSubpath).appendingPathComponent("work")
        try FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let log = profile.appendingPathComponent("vpn.log").path
        try "start\n".write(toFile: log, atomically: true, encoding: .utf8)
        let core = HelperCore(runRoot: dir.appendingPathComponent("run").path, homeDirectory: { _ in home.path }, userName: { _ in "alice" })
        let owner = HelperCore.DNSOwner(profileDir: profile.path, logName: "vpn.log")
        XCTAssertTrue(core.appendToLog("note\n", owner: owner, profileID: "work", uid: getuid()))
        XCTAssertEqual(try String(contentsOfFile: log, encoding: .utf8), "start\nnote\n")

        XCTAssertFalse(core.appendToLog("x\n", owner: owner, profileID: "other", uid: getuid()), "another profile's directory")
        XCTAssertFalse(
            core.appendToLog("x\n", owner: HelperCore.DNSOwner(profileDir: profile.path, logName: "config.ovpn"), profileID: "work", uid: getuid()))
        XCTAssertFalse(core.appendToLog("x\n", owner: HelperCore.DNSOwner(profileDir: "/tmp", logName: "vpn.log"), profileID: "work", uid: getuid()))
        let elsewhere = dir.appendingPathComponent("elsewhere.log").path
        try "".write(toFile: elsewhere, atomically: true, encoding: .utf8)
        try FileManager.default.removeItem(atPath: log)
        try FileManager.default.createSymbolicLink(atPath: log, withDestinationPath: elsewhere)
        XCTAssertFalse(core.appendToLog("x\n", owner: owner, profileID: "work", uid: getuid()), "never through a link")
        XCTAssertEqual(try String(contentsOfFile: elsewhere, encoding: .utf8), "")
    }

    @discardableResult
    func run(_ executable: String, _ arguments: [String], environment: [String: String] = [:]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }
}
