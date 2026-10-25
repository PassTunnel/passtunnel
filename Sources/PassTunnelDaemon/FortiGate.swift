import Foundation
#if canImport(Glibc)
import Glibc
#endif
import PassTunnelShared

// FortiGate sessions (docs/LINUX.md, "DNS"): the daemon reads openfortivpn's output itself, from a pipe
// only it and the tool hold, copies it into the session log, and sets the DNS openfortivpn reports
// there for the ppp interface. The log file belongs to the session's user and is never read back.

// MARK: - The tool's output

/// Splits output into lines at `\n` (a final `\r` dropped). A line longer than `maxBytes` is skipped
/// up to its end, never cut into pieces that could pass for lines of their own.
struct LineSplitter {
    let maxBytes: Int
    private var pending: [UInt8] = []
    private var overlong = false

    init(maxBytes: Int) {
        self.maxBytes = maxBytes
    }

    mutating func feed<C: Collection>(_ bytes: C) -> [String] where C.Element == UInt8 {
        var lines: [String] = []
        for byte in bytes {
            if byte == 0x0A {
                if !overlong { lines.append(Self.text(pending)) }
                pending.removeAll(keepingCapacity: true)
                overlong = false
            } else if !overlong {
                if pending.count < maxBytes {
                    pending.append(byte)
                } else {
                    overlong = true
                    pending.removeAll(keepingCapacity: true)
                }
            }
        }
        return lines
    }

    /// What is left when the output ends without a line break: the last line, unless it was too long.
    mutating func finish() -> String? {
        defer {
            pending.removeAll()
            overlong = false
        }
        return overlong || pending.isEmpty ? nil : Self.text(pending)
    }

    static func text(_ bytes: [UInt8]) -> String {
        String(decoding: bytes.last == 0x0D ? bytes.dropLast() : bytes[...], as: UTF8.self)
    }
}

/// Copies a tool's standard output and error, which go to a pipe only the daemon reads, into the
/// session log as they come (what the tool would have written there itself, so `HelperCore.capLog`
/// trims it as before), and hands every line to `line` on its own thread. Takes both descriptors and
/// closes them once every writer (the tool and what it started, pppd) has closed the pipe.
final class OutputCopier: @unchecked Sendable {
    static let maxLineBytes = 4096
    /// The prefix of the daemon's own lines in a session log.
    static let notePrefix = "passtunneld: "

    private let readFD: Int32
    private let logFD: Int32
    private let line: (String) -> Void
    private let lock = NSLock()
    private var atLineStart = true
    private var closed = false
    private var splitter = LineSplitter(maxBytes: OutputCopier.maxLineBytes)

    init(readFD: Int32, logFD: Int32, line: @escaping (String) -> Void) {
        self.readFD = readFD
        self.logFD = logFD
        self.line = line
    }

    func start(name: String) {
        let thread = Thread { self.run() }
        thread.name = name
        thread.start()
    }

    /// Copies until the end of the output (or a read error), then closes both descriptors.
    func run() {
        var buffer = [UInt8](repeating: 0, count: 64 << 10)
        while true {
            let n = read(readFD, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { break }
            let chunk = buffer[0..<n]
            lock.lock()
            Self.writeAll(logFD, chunk)
            atLineStart = chunk.last == 0x0A
            lock.unlock()
            for text in splitter.feed(chunk) { line(text) }
        }
        if let last = splitter.finish() { line(last) }
        lock.lock()
        closed = true
        close(readFD)
        close(logFD)
        lock.unlock()
    }

    /// A line of the daemon's own in the log ("passtunneld: …"), never inside a line of the tool's.
    /// Dropped once the output has ended.
    func note(_ text: String) {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        let line = (atLineStart ? "" : "\n") + Self.notePrefix + DaemonLog.oneLine(text) + "\n"
        Self.writeAll(logFD, Array(line.utf8)[...])
        atLineStart = true
    }

    /// The log is the user's file: a write that fails (a full disk) loses that output, never the tool.
    static func writeAll(_ fd: Int32, _ bytes: ArraySlice<UInt8>) {
        var offset = bytes.startIndex
        while offset < bytes.endIndex {
            let n = bytes[offset...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { return }
            offset += n
        }
    }
}

// MARK: - What openfortivpn says

/// The lines of openfortivpn (1.21 and later, at its default verbosity) and of the pppd it runs that
/// the DNS set-up follows, read only from their own output:
///
///     INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54], ns_suffix [example.com]
///     Using interface ppp0                                   (pppd)
///     INFO:   Interface ppp0 is UP.
///     INFO:   Tunnel is up and running.
///
/// The servers and `ns_suffix` (search domains, separated by `;`) are the gateway's; `ns_suffix` is
/// left out when the gateway names none, a server it names none of is `0.0.0.0`.
enum FortiOutput {
    struct Addresses: Equatable {
        /// The session's own address, which its ppp interface carries.
        var local: String
        var servers: [String]
        var domains: [String]
    }

    static let info = "INFO:   "

    static func addresses(_ line: String) -> Addresses? {
        let prefix = info + "Got addresses: ["
        guard line.hasPrefix(prefix), line.hasSuffix("]") else { return nil }
        let body = line.dropFirst(prefix.count).dropLast()
        guard let ns = body.range(of: "], ns [") else { return nil }
        var servers = body[ns.upperBound...]
        var domains: [String] = []
        if let suffix = servers.range(of: "], ns_suffix [") {
            domains = servers[suffix.upperBound...].split(whereSeparator: { $0 == ";" || $0 == " " }).map(String.init)
            servers = servers[..<suffix.lowerBound]
        }
        let list = servers.components(separatedBy: ", ")
        guard list.count == 2 else { return nil }
        return Addresses(local: String(body[..<ns.lowerBound]), servers: list.filter { $0 != "0.0.0.0" }, domains: domains)
    }

    /// "INFO:   Interface ppp0 is UP." → "ppp0".
    static func interface(_ line: String) -> String? {
        let prefix = info + "Interface ", suffix = " is UP."
        guard line.hasPrefix(prefix), line.hasSuffix(suffix), line.count > prefix.count + suffix.count else { return nil }
        return String(line.dropFirst(prefix.count).dropLast(suffix.count))
    }

    /// pppd: "Using interface ppp0" → "ppp0".
    static func pppdInterface(_ line: String) -> String? {
        let prefix = "Using interface "
        guard line.hasPrefix(prefix), line.count > prefix.count else { return nil }
        return String(line.dropFirst(prefix.count))
    }

    static func isUp(_ line: String) -> Bool {
        line == info + "Tunnel is up and running."
    }
}

/// Follows a FortiGate session's output for its DNS: the addresses openfortivpn got, the interface it
/// brought up and "Tunnel is up and running.", in any order. Once all three were seen: ready, once.
/// The tunnel up without the other two: waiting (`Supervisor` gives up after a while). pppd and
/// openfortivpn naming different interfaces: failed.
struct FortiDNSWatch {
    enum Event: Equatable {
        case none
        case waiting
        case ready(FortiOutput.Addresses, interface: String)
        case failed(String)
    }

    private(set) var addresses: FortiOutput.Addresses?
    private(set) var interface: String?
    private(set) var pppdInterface: String?
    private(set) var up = false
    private(set) var done = false

    mutating func feed(_ line: String) -> Event {
        guard !done else { return .none }
        if let a = FortiOutput.addresses(line) {
            addresses = a
        } else if let i = FortiOutput.pppdInterface(line) {
            pppdInterface = i
        } else if let i = FortiOutput.interface(line) {
            interface = i
        } else if FortiOutput.isUp(line) {
            up = true
        } else {
            return .none
        }
        guard up else { return .none }
        guard let addresses, let interface else { return .waiting }
        done = true
        if let pppdInterface, pppdInterface != interface {
            return .failed("pppd brought up \(pppdInterface), openfortivpn reported \(interface)")
        }
        return .ready(addresses, interface: interface)
    }

    /// What has not been reported yet, once the tunnel is up.
    var missing: String {
        [addresses == nil ? "the addresses it got" : nil, interface == nil ? "the interface it brought up" : nil]
            .compactMap { $0 }.joined(separator: " and ")
    }

    /// Done waiting: nothing more is followed.
    mutating func giveUp() {
        done = true
    }
}

// MARK: - The session's interface

/// The kernel's network interfaces, as the checks of a FortiGate session's interface see them;
/// replaced in tests.
public struct InterfaceSystem {
    public var index: (String) -> UInt32? = { name in
        let index = if_nametoindex(name)
        return index == 0 ? nil : index
    }
    /// The kind of device (`ARPHRD_*`, `/sys/class/net/<name>/type`).
    public var hardwareType: (String) -> Int? = InterfaceSystem.sysfsType
    /// Its IPv4 addresses (`getifaddrs`).
    public var ipv4Addresses: (String) -> [String] = { InterfaceSystem.addresses()[$0] ?? [] }
    /// The highest index of an interface there now (0 when none can be read).
    public var highestIndex: () -> UInt32 = InterfaceSystem.highest

    public init() {}

    static func sysfsType(_ name: String) -> Int? {
        guard (try? DNSSettings.interface(name)) != nil,
              let text = try? String(contentsOfFile: "/sys/class/net/\(name)/type", encoding: .utf8) else { return nil }
        return Int(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Every interface's IPv4 addresses, and every interface (with none) by name.
    static func addresses() -> [String: [String]] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return [:] }
        defer { freeifaddrs(first) }
        var out: [String: [String]] = [:]
        var entry = first
        while let e = entry {
            defer { entry = e.pointee.ifa_next }
            guard let cName = e.pointee.ifa_name else { continue }
            let name = String(cString: cName)
            out[name, default: []] += []
            guard let address = e.pointee.ifa_addr, address.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            var sin = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            if inet_ntop(AF_INET, &sin, &text, socklen_t(text.count)) != nil { out[name, default: []].append(String(cString: text)) }
        }
        return out
    }

    static func highest() -> UInt32 {
        addresses().keys.compactMap { name -> UInt32? in
            let index = if_nametoindex(name)
            return index == 0 ? nil : index
        }.max() ?? 0
    }
}

/// The interface openfortivpn reported ("Interface ppp0 is UP."), checked with the kernel before any
/// DNS is set for it: a ppp device named `pppN`, there now, created after the session started (a
/// higher index than any interface had then), and carrying the address openfortivpn got for this
/// session, which is how openfortivpn itself picks it out. So a line forged in the output (a gateway
/// may get text into it) cannot point the DNS at another interface.
enum SessionInterface {
    static let pppType = 512        // ARPHRD_PPP

    static func check(_ name: String, address: String, createdAfter indexAtStart: UInt32,
                      system: InterfaceSystem) throws -> String {
        let name = try DNSSettings.interface(name)
        guard name.hasPrefix("ppp"), name.count > 3, name.dropFirst(3).allSatisfy({ $0.isASCII && $0.isNumber }) else {
            throw DNSFailure.notSessionInterface(name, "it is not a ppp interface")
        }
        guard let index = system.index(name) else { throw DNSFailure.noInterface(name) }
        guard system.hardwareType(name) == pppType else {
            throw DNSFailure.notSessionInterface(name, "it is not a ppp device")
        }
        guard index > indexAtStart else {
            throw DNSFailure.notSessionInterface(name, "it existed before the session started")
        }
        guard system.ipv4Addresses(name).contains(address) else {
            throw DNSFailure.notSessionInterface(name, "it does not have the session's address \(HelperCore.printable(address))")
        }
        return name
    }
}

/// A DNS set-up handed to the DNS queue, which the session's end cancels: once cancelled it never
/// starts, and the end waits for one that already runs (then reverts what it did).
final class DNSTask: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}
