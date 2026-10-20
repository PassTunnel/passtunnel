import Foundation

/// Reachability probe used for health checks. Synchronous and blocking: call it off the main thread.
public enum HealthCheck {
    public enum Target: Equatable {
        case tcp(host: String, port: UInt16)
        case icmp(host: String)
        case icmp6(host: String)
    }

    /// "10.0.0.5" / "vpn.example.com" → ICMP, "fe80::1" → ICMPv6 (a bare IPv6 is never host:port),
    /// "host:port" / "[v6]:port" → TCP connect. Returns nil for empty or malformed input.
    public static func parse(_ raw: String) -> Target? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, !s.hasPrefix("-"), !s.contains(where: { $0.isWhitespace }) else { return nil }

        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return nil }
            let host = String(s[s.index(after: s.startIndex)..<close])
            guard !host.isEmpty, host.contains(":") else { return nil }
            let rest = s[s.index(after: close)...]
            if rest.isEmpty { return .icmp6(host: host) }
            guard rest.hasPrefix(":"), let port = portNumber(rest.dropFirst()) else { return nil }
            return .tcp(host: host, port: port)
        }

        let colons = s.filter { $0 == ":" }.count
        if colons == 0 { return .icmp(host: s) }
        if colons > 1 { return .icmp6(host: s) }
        let parts = s.split(separator: ":", omittingEmptySubsequences: false)
        guard !parts[0].isEmpty, let port = portNumber(parts[1]) else { return nil }
        return .tcp(host: String(parts[0]), port: port)
    }

    public static func check(_ host: String, timeout: TimeInterval = 3) -> (ok: Bool, ms: Int) {
        guard let target = parse(host) else { return (false, 0) }
        let t = max(0.2, timeout)
        switch target {
        case let .tcp(h, p): return tcp(host: h, port: p, timeout: t)
        case let .icmp(h): return ping("/sbin/ping", ["-n", "-q", "-c", "1", "-t", String(Int(t.rounded(.up))), h], timeout: t)
        case let .icmp6(h): return ping("/sbin/ping6", ["-n", "-q", "-c", "1", h], timeout: t)
        }
    }

    private static func portNumber<S: StringProtocol>(_ s: S) -> UInt16? {
        guard !s.isEmpty, s.allSatisfy(\.isASCII), let v = UInt16(s), v > 0 else { return nil }
        return v
    }

    // MARK: TCP

    private static func tcp(host: String, port: UInt16, timeout: TimeInterval) -> (ok: Bool, ms: Int) {
        let start = Date()
        let deadline = start.addingTimeInterval(timeout)
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &list) == 0, let first = list else { return (false, 0) }
        defer { freeaddrinfo(list) }

        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let entry = cursor {
            cursor = entry.pointee.ai_next
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { break }
            if connect(entry.pointee, timeout: remaining) {
                return (true, max(0, Int(Date().timeIntervalSince(start) * 1000)))
            }
        }
        return (false, 0)
    }

    private static func connect(_ entry: addrinfo, timeout: TimeInterval) -> Bool {
        let fd = socket(entry.ai_family, entry.ai_socktype, entry.ai_protocol)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        if Darwin.connect(fd, entry.ai_addr, entry.ai_addrlen) == 0 { return true }
        guard errno == EINPROGRESS else { return false }
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let rc = poll(&pfd, 1, Int32(max(1, timeout * 1000)))
        guard rc > 0 else { return false }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 else { return false }
        return err == 0
    }

    // MARK: ICMP

    /// Runs ping with a hard timeout: the process is killed if it outlives `timeout`.
    private static func ping(_ tool: String, _ args: [String], timeout: TimeInterval) -> (ok: Bool, ms: Int) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = args
        let out = Pipe()
        process.standardOutput = out
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }

        let start = Date()
        do { try process.run() } catch { return (false, 0) }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            if done.wait(timeout: .now() + 0.5) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                _ = done.wait(timeout: .now() + 0.5)
            }
            return (false, 0)
        }
        let elapsed = Int(Date().timeIntervalSince(start) * 1000)
        guard process.terminationStatus == 0 else { return (false, 0) }
        let text = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return (true, roundTripMS(text) ?? elapsed)
    }

    /// Extracts the average from "round-trip min/avg/max/stddev = 0.06/0.07/0.08/0.00 ms".
    static func roundTripMS(_ output: String) -> Int? {
        guard let line = output.split(separator: "\n").first(where: { $0.contains("round-trip") }),
              let eq = line.firstIndex(of: "=") else { return nil }
        let fields = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces).split(separator: "/")
        guard fields.count >= 2, let avg = Double(fields[1]) else { return nil }
        return Int(avg.rounded())
    }
}
