import Foundation
import PassTunnelKit

/// The health-check probe. Synchronous and blocking: call it off the main thread.
extension HealthCheck {
    public static func check(_ host: String, timeout: TimeInterval = 3) -> (ok: Bool, ms: Int) {
        guard let target = parse(host) else { return (false, 0) }
        let t = max(0.2, timeout)
        let seconds = Int(t.rounded(.up))
        switch target {
        case let .tcp(h, p): return tcp(host: h, port: p, timeout: t)
        case let .icmp(h):
            guard let command = pingCommand(h, ipv6: false, seconds: seconds) else { return (false, 0) }
            return ping(command.tool, command.arguments, timeout: t)
        case let .icmp6(h):
            guard let command = pingCommand(h, ipv6: true, seconds: seconds) else { return (false, 0) }
            return ping(command.tool, command.arguments, timeout: t)
        }
    }

    // MARK: TCP

    private static func tcp(host: String, port: UInt16, timeout: TimeInterval) -> (ok: Bool, ms: Int) {
        let start = Date()
        let deadline = start.addingTimeInterval(timeout)
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = POSIXSocket.stream
        hints.ai_protocol = Int32(IPPROTO_TCP)
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
        POSIXSocket.noSigPipe(fd)
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        if POSIXSocket.connect(fd, entry.ai_addr, entry.ai_addrlen) == 0 { return true }
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

    /// Where ping is on Linux: the first of these that exists (never looked up in PATH).
    static let linuxPingPaths = ["/usr/bin/ping", "/bin/ping", "/usr/sbin/ping", "/sbin/ping"]

    /// The ping that sends one echo request to `host` and waits at most `seconds` for the reply; nil
    /// when there is none. macOS: `ping` (`-t`: the whole run) and `ping6`. Linux (iputils): `-W` (the
    /// wait for the reply) and `-6` for IPv6.
    static func pingCommand(_ host: String, ipv6: Bool, seconds: Int,
                            isExecutable: (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) })
        -> (tool: String, arguments: [String])? {
        #if os(Linux)
        guard let tool = linuxPingPaths.first(where: isExecutable) else { return nil }
        return (tool, (ipv6 ? ["-6"] : []) + ["-n", "-q", "-c", "1", "-W", String(seconds), host])
        #else
        return ipv6 ? ("/sbin/ping6", ["-n", "-q", "-c", "1", host])
                    : ("/sbin/ping", ["-n", "-q", "-c", "1", "-t", String(seconds), host])
        #endif
    }

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

    /// Extracts the average from "round-trip min/avg/max/stddev = 0.06/0.07/0.08/0.00 ms" (macOS) or
    /// "rtt min/avg/max/mdev = 0.06/0.07/0.08/0.00 ms" (Linux, iputils).
    static func roundTripMS(_ output: String) -> Int? {
        guard let line = output.split(separator: "\n").first(where: { $0.contains("round-trip") || $0.hasPrefix("rtt ") }),
              let eq = line.firstIndex(of: "=") else { return nil }
        let fields = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces).split(separator: "/")
        // A round trip is under a minute (the probe times out long before); anything else is not a time.
        guard fields.count >= 2, let avg = Double(fields[1]), (0...60_000).contains(avg) else { return nil }
        return Int(avg.rounded())
    }
}
