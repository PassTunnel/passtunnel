import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelDaemon
@testable import PassTunnelShared

/// What openfortivpn 1.21 and the pppd it runs print while a tunnel comes up, at openfortivpn's default
/// verbosity (example addresses and names only).
let fortiOutput = """
INFO:   Connected to gateway.
INFO:   Authenticated.
INFO:   Remote gateway has allocated a VPN.
Using interface ppp0
Connect: ppp0 <--> /dev/pts/1
INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54], ns_suffix [example.com;corp.example.com]
INFO:   Negotiation complete.
local  IP address 10.212.134.200
remote IP address 169.254.2.1
INFO:   Negotiation complete.
INFO:   Interface ppp0 is UP.
INFO:   Setting new routes...
INFO:   Tunnel is up and running.

"""

// MARK: - openfortivpn's lines

final class FortiOutputTests: XCTestCase {
    typealias Addresses = FortiOutput.Addresses

    func testAddresses() {
        XCTAssertEqual(FortiOutput.addresses("INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54], "
                                             + "ns_suffix [example.com;corp.example.com]"),
                       Addresses(local: "10.212.134.200", servers: ["198.51.100.53", "198.51.100.54"],
                                 domains: ["example.com", "corp.example.com"]))
        XCTAssertEqual(FortiOutput.addresses("INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 0.0.0.0]"),
                       Addresses(local: "10.212.134.200", servers: ["198.51.100.53"], domains: []))
        XCTAssertEqual(FortiOutput.addresses("INFO:   Got addresses: [10.212.134.200], ns [0.0.0.0, 0.0.0.0]")?.servers, [])
        // The values are checked later (`DNSSettings`); here only openfortivpn's shape counts.
        XCTAssertEqual(FortiOutput.addresses("INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54], "
                                             + "ns_suffix [-evil;x y]")?.domains, ["-evil", "x", "y"])
        for line in ["Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54]",
                     "WARN:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54]",
                     "ERROR:  x INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54]",
                     " INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54]",
                     "INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53]",
                     "INFO:   Got addresses: [10.212.134.200]",
                     "INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54",
                     "INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54, 198.51.100.55]"] {
            XCTAssertNil(FortiOutput.addresses(line), line)
        }
    }

    func testInterfaceAndTunnel() {
        XCTAssertEqual(FortiOutput.interface("INFO:   Interface ppp0 is UP."), "ppp0")
        XCTAssertEqual(FortiOutput.interface("INFO:   Interface ppp12 is UP."), "ppp12")
        for line in ["Interface ppp0 is UP.", "INFO:   Interface ppp0 is UP", "INFO:   Interface  is UP.",
                     "Remote message: INFO:   Interface ppp0 is UP."] {
            XCTAssertNil(FortiOutput.interface(line), line)
        }
        XCTAssertEqual(FortiOutput.pppdInterface("Using interface ppp0"), "ppp0")
        XCTAssertNil(FortiOutput.pppdInterface("Using interface "))
        XCTAssertTrue(FortiOutput.isUp("INFO:   Tunnel is up and running."))
        XCTAssertFalse(FortiOutput.isUp("INFO:   Tunnel is up and running. Not."))
        XCTAssertFalse(FortiOutput.isUp("Tunnel is up and running."))
    }

    func feed(_ text: String, into watch: inout FortiDNSWatch) -> [FortiDNSWatch.Event] {
        text.split(separator: "\n").map { watch.feed(String($0)) }.filter { $0 != .none }
    }

    func testWatchFollowsATunnelComingUp() {
        var watch = FortiDNSWatch()
        let addresses = Addresses(local: "10.212.134.200", servers: ["198.51.100.53", "198.51.100.54"],
                                  domains: ["example.com", "corp.example.com"])
        XCTAssertEqual(feed(fortiOutput, into: &watch), [.ready(addresses, interface: "ppp0")])
        XCTAssertEqual(watch.feed("INFO:   Tunnel is up and running."), .none, "once")
    }

    /// The tunnel reported up before the rest: wait for both, in any order.
    func testWatchWaitsForTheAddressesAndTheInterface() {
        var watch = FortiDNSWatch()
        XCTAssertEqual(watch.feed("INFO:   Tunnel is up and running."), .waiting)
        XCTAssertEqual(watch.missing, "the addresses it got and the interface it brought up")
        XCTAssertEqual(watch.feed("INFO:   Interface ppp1 is UP."), .waiting)
        XCTAssertEqual(watch.missing, "the addresses it got")
        XCTAssertEqual(watch.feed("INFO:   Got addresses: [10.212.134.201], ns [198.51.100.53, 0.0.0.0]"),
                       .ready(Addresses(local: "10.212.134.201", servers: ["198.51.100.53"], domains: []), interface: "ppp1"))
        var nothing = FortiDNSWatch()
        XCTAssertEqual(feed("INFO:   Interface ppp0 is UP.\nINFO:   Connected to gateway.\n", into: &nothing), [],
                       "nothing before the tunnel is up")
    }

    func testWatchRefusesTwoInterfaces() {
        var watch = FortiDNSWatch()
        let events = feed(fortiOutput.replacingOccurrences(of: "Using interface ppp0", with: "Using interface ppp3"), into: &watch)
        XCTAssertEqual(events, [.failed("pppd brought up ppp3, openfortivpn reported ppp0")])
    }
}

// MARK: - Copying the output

final class OutputCopierTests: DaemonTestCase {
    /// Runs a copier over `chunks` written into its pipe one after the other; the log file it wrote and
    /// the lines it handed over.
    func copy(_ chunks: [[UInt8]], logPath: String? = nil, between: (Int) -> Void = { _ in }) throws
        -> (log: [UInt8], lines: [String], copier: OutputCopier) {
        let path = logPath ?? base + "/copy.log"
        let log = open(path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(log, 0)
        let fds = try Sys.makePipe()
        let lines = LinesBox()
        let copier = OutputCopier(readFD: fds.read, logFD: log) { lines.append($0) }
        let done = DispatchSemaphore(value: 0)
        let thread = Thread {
            copier.run()
            done.signal()
        }
        thread.start()
        for (i, chunk) in chunks.enumerated() {
            _ = chunk.withUnsafeBytes { write(fds.write, $0.baseAddress, $0.count) }
            between(i)
        }
        close(fds.write)
        XCTAssertEqual(done.wait(timeout: .now() + 10), .success)
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return ([UInt8](data), lines.value, copier)
    }

    func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }

    func testCopiesEverythingAndSplitsLines() throws {
        let text = fortiOutput + "ERROR:  Could not authenticate to gateway.\r\nlast line without a break"
        // Cut anywhere, even inside a character: the log gets the bytes, the lines come out whole.
        let all = bytes(text)
        let chunks = stride(from: 0, to: all.count, by: 7).map { Array(all[$0..<min($0 + 7, all.count)]) }
        let (log, lines, _) = try copy(chunks)
        XCTAssertEqual(log, all)
        XCTAssertEqual(lines, text.components(separatedBy: "\n").map { $0.hasSuffix("\r") ? String($0.dropLast()) : $0 }
            .filter { !$0.isEmpty })
        XCTAssertEqual(lines.last, "last line without a break", "the end of the output ends the last line")
    }

    /// A line longer than the limit is copied into the log but not handed over, not even in pieces.
    func testVeryLongLines() throws {
        let long = String(repeating: "INFO:   Got addresses: ", count: 2000)    // ~46 KB, more than a pipe's chunk
        let text = "first\n" + long + "INFO:   Tunnel is up and running.\nafter\n" + long
        let (log, lines, _) = try copy([bytes(text)])
        XCTAssertEqual(log, bytes(text))
        XCTAssertEqual(lines, ["first", "after"])
        let exact = String(repeating: "x", count: OutputCopier.maxLineBytes)
        XCTAssertEqual(try copy([bytes(exact + "\n" + exact + "y\nz")]).lines, [exact, "z"])
    }

    /// A partial line is in the log at once; its line is handed over once it is complete.
    func testPartialLines() throws {
        let (log, lines, _) = try copy([bytes("INFO:   Connected"), bytes(" to gateway.\nINFO:   Tunnel")], between: { i in
            if i == 0 { usleep(200_000) }
        })
        XCTAssertEqual(lines, ["INFO:   Connected to gateway.", "INFO:   Tunnel"])
        XCTAssertEqual(log, bytes("INFO:   Connected to gateway.\nINFO:   Tunnel"))
    }

    /// The daemon's own lines never land inside one of the tool's, and none after the output ended.
    func testNotesStayOnTheirOwnLine() throws {
        let path = base + "/notes.log"
        let fd = open(path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
        let fds = try Sys.makePipe()
        let note = OutputCopier(readFD: fds.read, logFD: fd) { _ in }
        let done = DispatchSemaphore(value: 0)
        Thread { note.run(); done.signal() }.start()
        _ = "INFO:   half".withCString { write(fds.write, $0, strlen($0)) }
        XCTAssertTrue(eventually { ((try? String(contentsOfFile: path, encoding: .utf8)) ?? "") == "INFO:   half" })
        note.note("DNS of ppp0 set")
        _ = " a line\n".withCString { write(fds.write, $0, strlen($0)) }
        XCTAssertTrue(eventually { ((try? String(contentsOfFile: path, encoding: .utf8)) ?? "").hasSuffix(" a line\n") })
        note.note("again\nwith a line break")
        close(fds.write)
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
        note.note("after the end")
        XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8),
                       "INFO:   half\npasstunneld: DNS of ppp0 set\n a line\npasstunneld: again?with a line break\n")
    }

    /// The supervisor caps the log through its own descriptor while the copier appends: the copier
    /// goes on at the new end.
    func testLogCapping() throws {
        let path = base + "/capped.log"
        let capFD = open(path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
        defer { close(capFD) }
        let head = bytes(String(repeating: "h", count: 99) + "\n")
        let middle = bytes(String(repeating: "m", count: 99) + "\n")
        let tail = bytes(String(repeating: "t", count: 49) + "\n")
        let chunks = [head, Array(repeating: middle, count: 20).flatMap { $0 }, tail]
        let (log, lines, _) = try copy(chunks, logPath: path, between: { i in
            guard i == 1 else { return }
            XCTAssertTrue(self.eventually { (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) == 2100 })
            XCTAssertTrue(HelperCore.capLog(fd: capFD, maxBytes: 1000, keepBytes: 300, headBytes: 100))
        })
        let marker = bytes("[log trimmed by the helper at 0 MB; lines in between removed]\n")
        XCTAssertEqual(log, head + marker + Array(repeating: middle, count: 2).flatMap { $0 } + tail)
        XCTAssertEqual(lines.count, 22, "every line handed over, whatever the log kept")
    }

    func testLineSplitter() {
        var s = LineSplitter(maxBytes: 5)
        XCTAssertEqual(s.feed(bytes("ab")), [])
        XCTAssertEqual(s.feed(bytes("c\r\ndefgh\n12345")), ["abc", "defgh"])
        XCTAssertEqual(s.feed(bytes("6 too long\nok\n")), ["ok"])
        XCTAssertEqual(s.feed(bytes("rest")), [])
        XCTAssertEqual(s.finish(), "rest")
        XCTAssertNil(s.finish())
        XCTAssertEqual(s.feed(bytes("\n\n")), ["", ""])
        XCTAssertEqual(s.feed(bytes("123456")), [])
        XCTAssertNil(s.finish(), "too long, even at the end")
        XCTAssertEqual(s.feed([0x66, 0xFF, 0x0A]), ["f\u{FFFD}"])
    }
}

final class LinesBox: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []

    func append(_ line: String) { lock.lock(); lines.append(line); lock.unlock() }
    var value: [String] { lock.lock(); defer { lock.unlock() }; return lines }
}

// MARK: - The session's interface

final class SessionInterfaceTests: XCTestCase {
    /// ppp0 came after index 10, a ppp device with the session's address; eth0 and ppp9 were there before.
    func system(type: Int = 512, index: UInt32 = 50, addresses: [String] = ["10.212.134.200"]) -> InterfaceSystem {
        var system = InterfaceSystem()
        system.index = { ["ppp0": index, "ppp9": 9, "eth0": 2][$0] }
        system.hardwareType = { $0 == "eth0" ? 1 : type }
        system.ipv4Addresses = { $0 == "eth0" ? ["192.0.2.10"] : addresses }
        system.highestIndex = { 10 }
        return system
    }

    func check(_ name: String, _ system: InterfaceSystem, address: String = "10.212.134.200") throws -> String {
        try SessionInterface.check(name, address: address, createdAfter: 10, system: system)
    }

    func assertRefused(_ name: String, _ system: InterfaceSystem, address: String = "10.212.134.200",
                       _ expected: DNSFailure, line: UInt = #line) {
        XCTAssertThrowsError(try check(name, system, address: address), line: line) {
            XCTAssertEqual($0 as? DNSFailure, expected, line: line)
        }
    }

    func testTheSessionsPPPInterface() throws {
        XCTAssertEqual(try check("ppp0", system()), "ppp0")
        assertRefused("eth0", system(), .notSessionInterface("eth0", "it is not a ppp interface"))
        assertRefused("ppp1", system(), .noInterface("ppp1"))
        assertRefused("ppp0", system(type: 1), .notSessionInterface("ppp0", "it is not a ppp device"))
        assertRefused("ppp0", system(index: 10), .notSessionInterface("ppp0", "it existed before the session started"))
        assertRefused("ppp9", system(), .notSessionInterface("ppp9", "it existed before the session started"))
        assertRefused("ppp0", system(addresses: ["10.212.134.201"]),
                      .notSessionInterface("ppp0", "it does not have the session's address 10.212.134.200"))
        assertRefused("ppp0", system(addresses: []), address: "10.212.134.200",
                      .notSessionInterface("ppp0", "it does not have the session's address 10.212.134.200"))
        for name in ["ppp", "pppx", "ppp0;", "ppp0/../eth0", "PPP0", "ppp٣"] {
            XCTAssertThrowsError(try check(name, system()), name)
        }
    }

    /// The real system, read-only: loopback is no ppp device and existed before anything.
    func testTheRealInterfaces() {
        let system = InterfaceSystem()
        XCTAssertNotNil(system.index("lo"))
        XCTAssertEqual(system.hardwareType("lo"), 772)                    // ARPHRD_LOOPBACK
        XCTAssertTrue(system.ipv4Addresses("lo").contains("127.0.0.1"))
        XCTAssertGreaterThanOrEqual(system.highestIndex(), system.index("lo") ?? .max)
        XCTAssertNil(system.hardwareType("lo/../eth0"))
    }
}

// MARK: - The daemon

final class DaemonFortiDNSTests: DNSTestCase {
    let interfaces = InterfaceBox()

    override func setUpWithError() throws {
        try super.setUpWithError()
        indexes.set(["ppp0": 50])
        interfaces.set(index: ["ppp0": 50], type: 512, addresses: ["10.212.134.200"], highest: 10)
    }

    func makeFortiDaemon(reportWait: TimeInterval = 10) throws -> Daemon {
        let system = self.system, interfaces = self.interfaces
        return try makeDaemon {
            $0.dns = system
            $0.interfaces = interfaces.system
            $0.reportWait = reportWait
        }
    }

    /// openfortivpn as a script that prints `output`, then stays.
    func fakeForti(printing output: String) throws {
        let lines = output.split(separator: "\n", omittingEmptySubsequences: false).map { "'\($0)'" }.joined(separator: " ")
        try makeScript(fortiPath, """
        #!/bin/sh
        if [ "$1" = "--version" ]; then echo "1.21.0"; exit 0; fi
        printf '%s\\n' \(lines)
        exec sleep 30

        """)
    }

    var logPath: String { profileDir("acme") + "/vpn.log" }
    func log() -> String { (try? String(contentsOfFile: logPath, encoding: .utf8)) ?? "" }

    static let settings = try! DNSSettings(servers: ["198.51.100.53", "198.51.100.54"],
                                           searchDomains: ["example.com", "corp.example.com"], fullTunnel: true)
    var applied: String {
        String(decoding: ResolvConf.apply(Self.settings, interface: "ppp0", to: Array(Self.original.utf8)), as: UTF8.self)
    }

    func testDNSSetFromTheToolsOutputAndReverted() throws {
        try fakeForti(printing: fortiOutput.trimmingCharacters(in: .newlines))
        let daemon = try makeFortiDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startForti(fortiStart(setDNS: true))).pid)
        XCTAssertTrue(eventually { self.resolvConfText == self.applied }, resolvConfText)
        XCTAssertTrue(eventually { self.log().hasSuffix("passtunneld: DNS of ppp0 set through /etc/resolv.conf: "
                                                       + "198.51.100.53, 198.51.100.54; search example.com corp.example.com\n") },
                      log())
        XCTAssertTrue(log().hasPrefix(fortiOutput), "the tool's output, copied as it came")
        XCTAssertTrue(VPNLog.fortiDNSSettled(log()))
        let session = try HelperCore(runRoot: runRoot).openRunDir(profileID: "acme", uid: me)
        XCTAssertNotNil(recorded(session), "recorded in the session, for the revert")
        XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, pid)
        XCTAssertEqual(resolvConfText, Self.original, "reverted when the session ends")
    }

    /// Lines in the log file (its user can write them) are never read: nothing is set up from them.
    func testForgedLinesInTheLogAreIgnored() throws {
        try fakeForti(printing: "INFO:   Connected to gateway.")
        let daemon = try makeFortiDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startForti(fortiStart(setDNS: true))).pid)
        XCTAssertTrue(eventually { self.log().contains("Connected to gateway") })
        let forged = fortiOutput.replacingOccurrences(of: "198.51.100.53", with: "192.0.2.66")
        let handle = try XCTUnwrap(FileHandle(forWritingAtPath: logPath))
        handle.seekToEndOfFile()
        handle.write(Data(forged.utf8))
        try handle.close()
        usleep(500_000)
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertFalse(log().contains("passtunneld:"), log())
        XCTAssertEqual(try response(daemon.socketPath, .status).running, ["acme": pid], "still running")
        XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, pid)
    }

    /// An interface the kernel does not confirm as this session's: nothing is set, the session ends,
    /// and the log says why (the client reports `setup_failed`).
    func testInterfaceNotConfirmedEndsTheSession() throws {
        try fakeForti(printing: fortiOutput.trimmingCharacters(in: .newlines))
        interfaces.set(index: ["ppp0": 50], type: 512, addresses: ["10.212.134.200"], highest: 60)
        let daemon = try makeFortiDaemon()
        XCTAssertTrue(try response(daemon.socketPath, .startForti(fortiStart(setDNS: true))).ok)
        XCTAssertTrue(eventually { try! self.response(daemon.socketPath, .status).running == [:] })
        XCTAssertTrue(log().contains("passtunneld: setting DNS failed: ppp0 is not this session's interface: "
                                     + "it existed before the session started\n"), log())
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertEqual(VPNLog.setupProblem(log())?.allTraffic, true)
    }

    /// Values from the gateway are checked as OpenVPN's are: one bad value, nothing set.
    func testBadValuesEndTheSession() throws {
        try fakeForti(printing: fortiOutput.trimmingCharacters(in: .newlines)
                        .replacingOccurrences(of: "ns_suffix [example.com;corp.example.com]", with: "ns_suffix [-evil]"))
        let daemon = try makeFortiDaemon()
        XCTAssertTrue(try response(daemon.socketPath, .startForti(fortiStart(setDNS: true))).ok)
        XCTAssertTrue(eventually { try! self.response(daemon.socketPath, .status).running == [:] })
        XCTAssertTrue(log().contains("passtunneld: setting DNS failed: invalid DNS domain “-evil”\n"), log())
        XCTAssertEqual(resolvConfText, Self.original)
    }

    func testWithoutSetDNSNothingIsSet() throws {
        try fakeForti(printing: fortiOutput.trimmingCharacters(in: .newlines))
        let daemon = try makeFortiDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startForti(fortiStart(setDNS: false))).pid)
        XCTAssertTrue(eventually { self.log().contains("Tunnel is up and running") })
        usleep(300_000)
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertEqual(log(), fortiOutput)
        XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, pid)
    }

    func testNoServersLeavesDNSAlone() throws {
        try fakeForti(printing: fortiOutput.trimmingCharacters(in: .newlines)
                        .replacingOccurrences(of: "ns [198.51.100.53, 198.51.100.54], ns_suffix [example.com;corp.example.com]",
                                              with: "ns [0.0.0.0, 0.0.0.0]"))
        let daemon = try makeFortiDaemon()
        let pid = try XCTUnwrap(try response(daemon.socketPath, .startForti(fortiStart(setDNS: true))).pid)
        XCTAssertTrue(eventually { self.log().hasSuffix("passtunneld: the gateway named no DNS servers; DNS is left as it is\n") },
                      log())
        XCTAssertEqual(resolvConfText, Self.original)
        XCTAssertEqual(try response(daemon.socketPath, .stop(profileID: "acme")).pid, pid)
    }

    /// The tunnel up, but no interface reported: given up after the wait, and the session ends.
    func testMissingReportEndsTheSession() throws {
        try fakeForti(printing: fortiOutput.trimmingCharacters(in: .newlines)
                        .replacingOccurrences(of: "INFO:   Interface ppp0 is UP.\n", with: ""))
        let daemon = try makeFortiDaemon(reportWait: 0.3)
        XCTAssertTrue(try response(daemon.socketPath, .startForti(fortiStart(setDNS: true))).ok)
        XCTAssertTrue(eventually { try! self.response(daemon.socketPath, .status).running == [:] })
        XCTAssertTrue(log().contains("passtunneld: setting DNS failed: openfortivpn's tunnel is up, but it did not report "
                                     + "the interface it brought up\n"), log())
    }

    /// Reverted however the session ends: the tool dies, or the daemon stops.
    func testRevertedWhenTheToolDiesOrTheDaemonStops() throws {
        try fakeForti(printing: fortiOutput.trimmingCharacters(in: .newlines))
        let daemon = try makeFortiDaemon()
        for end in ["kill", "shutdown"] {
            let pid = try XCTUnwrap(try response(daemon.socketPath, .startForti(fortiStart(setDNS: true))).pid, end)
            XCTAssertTrue(eventually { self.resolvConfText == self.applied }, end)
            if end == "kill" { kill(pid, SIGKILL) } else { daemon.shutdown() }
            XCTAssertTrue(eventually { self.resolvConfText == Self.original }, end)
        }
    }

    /// A daemon that died with a FortiGate session up: the next one reverts its DNS.
    func testStartingDaemonRevertsAFortiGateSession() throws {
        let session = try session()
        try applier.apply(Self.settings, interface: "ppp0", in: session)
        XCTAssertEqual(resolvConfText, applied)
        _ = try makeFortiDaemon()
        XCTAssertEqual(resolvConfText, Self.original)
    }
}

/// The fake interfaces of `DaemonFortiDNSTests`, changeable while a daemon uses them.
final class InterfaceBox: @unchecked Sendable {
    private let lock = NSLock()
    private var index: [String: UInt32] = [:], type = 0, addresses: [String] = [], highest: UInt32 = 0

    func set(index: [String: UInt32], type: Int, addresses: [String], highest: UInt32) {
        lock.lock()
        (self.index, self.type, self.addresses, self.highest) = (index, type, addresses, highest)
        lock.unlock()
    }

    private func read<T>(_ body: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return body() }

    var system: InterfaceSystem {
        var system = InterfaceSystem()
        system.index = { name in self.read { self.index[name] } }
        system.hardwareType = { _ in self.read { self.type } }
        system.ipv4Addresses = { _ in self.read { self.addresses } }
        system.highestIndex = { self.read { self.highest } }
        return system
    }
}
