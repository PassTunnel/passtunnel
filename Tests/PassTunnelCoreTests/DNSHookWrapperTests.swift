import XCTest
@testable import PassTunnelShared

/// The Mac's wrapper around OpenVPN's dns-updown and the record it keeps (`HelperCore+DNSHook`).
final class DNSHookWrapperTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pt-dnshook-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    static let record = """
        dev=utun7
        dns_search_domain_1=corp.example.com
        dns_server_1_address_1=192.0.2.53
        dns_server_1_address_2=2001:db8::53
        dns_server_1_port_2=53
        dns_server_1_resolve_domain_1=corp.example.com
        dns_server_1_dnssec=no
        dns_server_1_transport=plain
        dns_server_1_sni=dns.example.com

        """

    func testDownEnvironmentFromRecord() {
        let lines = Self.record.split(separator: "\n").map(String.init)
        XCTAssertEqual(HelperCore.dnsDownEnvironment(record: Self.record),
                       ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "script_type=dns-down"] + lines)
        XCTAssertNotNil(HelperCore.dnsDownEnvironment(record: "dev=utun7\ndns_server_2_address_1=198.51.100.1\n"
                                                      + "dns_search_domain_1=b\u{fc}cher.example\n"),
                        "OpenVPN lets non-ASCII through")
    }

    func testDownEnvironmentRefusesAnythingElse() {
        let base = "dev=utun7\ndns_server_1_address_1=192.0.2.53\n"
        XCTAssertNotNil(HelperCore.dnsDownEnvironment(record: base))
        let refused = [
            "", "dev=utun7\n", "dns_server_1_address_1=192.0.2.53\n", "dev=utun7\ndns_server_1_address_1=192.0.2.53",
            base + "PATH=/tmp\n", base + "BASH_ENV=/tmp/x\n", base + "dns_vars_file=/tmp/x\n", base + "script_type=dns-up\n",
            base + "SHELLOPTS=xtrace\n", base + "dns_server_1_other=x\n", base + "dns_search_domain_=x\n",
            base + "dns_server_x_address_1=192.0.2.1\n", base + "dns_server_1_address_12345=192.0.2.1\n",
            base + "dns_search_domain_1\n", base + "dev=utun8\n",
            base + "dns_search_domain_1=\n", base + "dns_search_domain_1=a b\n", base + "dns_search_domain_1=a;b\n",
            base + "dns_search_domain_1=$(id)\n", base + "dns_search_domain_1=`id`\n", base + "dns_search_domain_1=a\\nb\n",
            base + "dns_search_domain_1=a/b\n", base + "dns_search_domain_1='a'\n", base + "dns_search_domain_1=a*\n",
            base + "dns_search_domain_1=a=b\n", base + "dns_search_domain_1=a\tb\n", base + "dns_search_domain_1=a\rb\n",
            base + "dns_search_domain_1=" + String(repeating: "a", count: 256) + "\n",
            base + "\n",
        ]
        for record in refused {
            XCTAssertNil(HelperCore.dnsDownEnvironment(record: record), record.debugDescription)
        }
    }

    func testPendingDNSDown() throws {
        let path = dir.appendingPathComponent(HelperCore.dnsRecordName).path
        XCTAssertNil(try HelperCore.pendingDNSDown(runDir: dir.path), "nothing recorded")
        try Self.record.write(toFile: path, atomically: true, encoding: .utf8)
        XCTAssertEqual(try HelperCore.pendingDNSDown(runDir: dir.path), HelperCore.dnsDownEnvironment(record: Self.record))

        try "dev=utun7\n".write(toFile: path, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try HelperCore.pendingDNSDown(runDir: dir.path)) {
            XCTAssertEqual($0 as? HelperCore.Failure, .unsafeFile(HelperCore.dnsRecordName))
        }
        try Data([0x64, 0x65, 0x76, 0x3D, 0xFF, 0x0A]).write(to: URL(fileURLWithPath: path))
        XCTAssertThrowsError(try HelperCore.pendingDNSDown(runDir: dir.path), "not UTF-8")
        try Data(repeating: 0x61, count: HelperCore.maxDNSRecordBytes + 1).write(to: URL(fileURLWithPath: path))
        XCTAssertThrowsError(try HelperCore.pendingDNSDown(runDir: dir.path)) {
            XCTAssertEqual($0 as? HelperCore.Failure, .fileTooLarge(path))
        }

        try FileManager.default.removeItem(atPath: path)
        let target = dir.appendingPathComponent("elsewhere").path
        try Self.record.write(toFile: target, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: target)
        XCTAssertThrowsError(try HelperCore.pendingDNSDown(runDir: dir.path)) {
            XCTAssertEqual($0 as? HelperCore.Failure, .symlinkNotAllowed(path))
        }
        try FileManager.default.removeItem(atPath: path)
        XCTAssertEqual(link(target, path), 0)
        XCTAssertThrowsError(try HelperCore.pendingDNSDown(runDir: dir.path)) {
            XCTAssertEqual($0 as? HelperCore.Failure, .multipleLinks(path))
        }
    }

    func testHookText() {
        let lines = HelperCore.dnsHookText.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.first, "#!/bin/bash")
        XCTAssertEqual(lines.first { !$0.hasPrefix("#") }, "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "before anything runs")
        XCTAssertTrue(HelperCore.dnsHookText.hasSuffix("exit $status\n"))
    }

    #if os(macOS)
    /// Runs the wrapper against a stand-in for OpenVPN's script that only writes down what it got.
    func testHookRunsScriptWithFixedPathAndKeepsRecord() throws {
        let hook = dir.appendingPathComponent(HelperCore.dnsHookName).path
        try HelperCore.writeNewFile(hook, Data(HelperCore.dnsHookText.utf8), mode: 0o700)
        let script = """
            #!/bin/bash
            echo "$script_type $PATH $dns_server_1_address_1" >> "${0%/*}/ran"
            exit "${exit_with:-0}"

            """
        try HelperCore.writeNewFile(dir.appendingPathComponent("dns-updown").path, Data(script.utf8), mode: 0o700)
        let recordPath = dir.appendingPathComponent(HelperCore.dnsRecordName).path
        let ranPath = dir.appendingPathComponent("ran").path
        let openVPN = ["dev": "utun7", "dns_server_1_address_1": "192.0.2.53", "dns_search_domain_1": "corp.example.com",
                       "PATH": dir.path]

        XCTAssertEqual(try run(hook, openVPN.merging(["script_type": "dns-up", "exit_with": "3"]) { $1 }), 3,
                       "the script's status goes back to OpenVPN")
        XCTAssertEqual(try String(contentsOfFile: recordPath, encoding: .utf8),
                       "dev=utun7\ndns_search_domain_1=corp.example.com\ndns_server_1_address_1=192.0.2.53\n")
        let pending = try XCTUnwrap(HelperCore.pendingDNSDown(runDir: dir.path))
        XCTAssertEqual(pending, ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "script_type=dns-down", "dev=utun7",
                                 "dns_search_domain_1=corp.example.com", "dns_server_1_address_1=192.0.2.53"])

        XCTAssertEqual(try run(hook, openVPN.merging(["script_type": "dns-down", "exit_with": "4"]) { $1 }), 4)
        XCTAssertFalse(FileManager.default.fileExists(atPath: recordPath), "a dns-down ran: nothing is owed")
        XCTAssertNil(try HelperCore.pendingDNSDown(runDir: dir.path))

        // What the helper runs for a skipped dns-down: the script itself with the recorded variables.
        let env = Dictionary(uniqueKeysWithValues: pending.map { line -> (String, String) in
            let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
            return (parts[0], parts[1])
        })
        XCTAssertEqual(try run("/bin/bash", env, arguments: [dir.appendingPathComponent("dns-updown").path]), 0)

        XCTAssertEqual(try String(contentsOfFile: ranPath, encoding: .utf8), """
            dns-up /usr/bin:/bin:/usr/sbin:/sbin 192.0.2.53
            dns-down /usr/bin:/bin:/usr/sbin:/sbin 192.0.2.53
            dns-down /usr/bin:/bin:/usr/sbin:/sbin 192.0.2.53

            """)
    }

    private func run(_ executable: String, _ environment: [String: String], arguments: [String] = []) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = environment
        process.currentDirectoryURL = dir
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }
    #endif
}
