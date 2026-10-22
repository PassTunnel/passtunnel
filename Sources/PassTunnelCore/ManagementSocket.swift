import Foundation

public enum ManagementError: Error, Equatable, LocalizedError {
    case pathTooLong(String)
    case connectFailed(String, Int32)
    case busy                       // another client holds the interface
    case timeout
    case closed                     // OpenVPN closed the connection
    case commandFailed(String)      // "ERROR: …" reply
    case unexpectedReply(String)

    public var errorDescription: String? {
        switch self {
        case .pathTooLong(let p):
            return String(localized: "The OpenVPN management socket path is too long: \(p)")
        case .connectFailed(let p, let e):
            let reason = String(cString: strerror(e))
            return String(localized: "Could not connect to \(p): \(reason)")
        case .busy: return String(localized: "The OpenVPN management interface is in use by another client.")
        case .timeout: return String(localized: "The OpenVPN management interface did not answer in time.")
        case .closed: return String(localized: "OpenVPN closed the management connection.")
        case .commandFailed(let m): return String(localized: "OpenVPN: \(m)")
        case .unexpectedReply(let r): return String(localized: "Unexpected reply from the OpenVPN management interface: \(r)")
        }
    }
}

/// Parsed reply of the `state` command: `<since>,<NAME>,<description>,<local IPv4>,<remote>,<rport>,…,<local IPv6>`.
public struct ManagementState: Equatable {
    public var name: String          // CONNECTING, WAIT, AUTH, GET_CONFIG, ASSIGN_IP, ADD_ROUTES, CONNECTED, RECONNECTING, EXITING…
    public var localIP: String       // tunnel IPv4, empty before ASSIGN_IP
    public var since: Date
    public var detail: String        // e.g. SUCCESS, or the reason for RECONNECTING
    public var remoteIP: String
    public var localIPv6: String

    public init(name: String, localIP: String, since: Date, detail: String = "", remoteIP: String = "",
                localIPv6: String = "") {
        self.name = name
        self.localIP = localIP
        self.since = since
        self.detail = detail
        self.remoteIP = remoteIP
        self.localIPv6 = localIPv6
    }

    public var isConnected: Bool { name == "CONNECTED" }

    /// Seconds since 1970 a state change can plausibly carry: 1970 up to 2100. OpenVPN writes the
    /// current time; anything else (`nan`, `inf`, `1e300`, a negative value) is a damaged reply or file.
    public static let plausibleEpochs: ClosedRange<TimeInterval> = 0...4_102_444_800

    /// Whether `since` lies in `plausibleEpochs` (false for non-finite values).
    public static func isPlausible(_ since: Date) -> Bool {
        plausibleEpochs.contains(since.timeIntervalSince1970)
    }
}

/// Minimal client for OpenVPN's management interface on a unix socket. One connection per command;
/// OpenVPN serves a single client at a time, so while another client (the app's
/// `PersistentManagementQuerier`) holds the interface, this one reports `.busy`.
public struct ManagementSocket {
    public let path: String
    /// Short retries while OpenVPN is starting up or another client is connected.
    public var connectAttempts = 5
    public var retryDelay: TimeInterval = 0.2

    public init(path: String) {
        self.path = path
    }

    /// Sends one command and returns its reply: the lines before `END` for multi-line replies, or the
    /// `SUCCESS: …` line. `ERROR: …` throws `.commandFailed`. Real-time `>` notifications are skipped.
    public func command(_ cmd: String, timeout: TimeInterval = 3) throws -> String {
        guard !cmd.contains("\n"), !cmd.contains("\r") else { throw ManagementError.unexpectedReply(cmd) }
        let deadline = Date().addingTimeInterval(timeout)
        var lastError = ManagementError.busy
        for attempt in 0..<max(1, connectAttempts) {
            if attempt > 0 {
                guard Date().addingTimeInterval(retryDelay) < deadline else { break }
                Thread.sleep(forTimeInterval: retryDelay)
            }
            let conn: Connection
            do {
                conn = try Connection(path: path)
            } catch let e as ManagementError {
                if case .connectFailed(_, let code) = e, [ECONNREFUSED, ENOENT, EAGAIN].contains(code) {
                    lastError = e
                    continue
                }
                throw e
            }
            defer { conn.close() }
            // The banner (">INFO:…") arrives at once unless another client is being served.
            let bannerDeadline = min(deadline, Date().addingTimeInterval(min(1, timeout / 2)))
            do {
                guard let line = try conn.readLine(until: bannerDeadline), line.hasPrefix(">INFO:") else {
                    lastError = .busy
                    continue
                }
            } catch ManagementError.timeout {
                lastError = .busy
                continue
            } catch ManagementError.closed {
                lastError = .busy
                continue
            }
            try conn.write(cmd + "\n", until: deadline)
            return try readReply(conn, until: deadline)
        }
        throw lastError
    }

    /// Current connection state (`state` command).
    public func state(timeout: TimeInterval = 3) throws -> ManagementState {
        try Self.parseState(command("state", timeout: timeout))
    }

    /// Parses the reply of `state` (the lines before `END`).
    public static func parseState(_ reply: String) throws -> ManagementState {
        let line = reply.split(whereSeparator: \.isNewline).map(String.init)
            .first { !$0.hasPrefix(">") && !$0.isEmpty } ?? ""
        let f = line.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard f.count >= 2, let epoch = TimeInterval(f[0]), ManagementState.plausibleEpochs.contains(epoch),
              !f[1].isEmpty else {
            throw ManagementError.unexpectedReply(line)
        }
        func field(_ i: Int) -> String { i < f.count ? f[i] : "" }
        return ManagementState(name: f[1], localIP: field(3), since: Date(timeIntervalSince1970: epoch),
                               detail: field(2), remoteIP: field(4), localIPv6: field(8))
    }

    private func readReply(_ conn: Connection, until deadline: Date) throws -> String {
        var lines: [String] = []
        while let line = try conn.readLine(until: deadline) {
            if line.hasPrefix(">") { continue }
            if lines.isEmpty, line.hasPrefix("SUCCESS:") { return line }
            if lines.isEmpty, line.hasPrefix("ERROR:") {
                throw ManagementError.commandFailed(line.dropFirst(6).trimmingCharacters(in: .whitespaces))
            }
            if line == "END" { return lines.joined(separator: "\n") }
            lines.append(line)
        }
        throw ManagementError.closed
    }

    // MARK: - Socket

    final class Connection {
        private var fd: Int32
        private var buffer = Data()

        init(path: String) throws {
            var addr = sockaddr_un()
            let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
            guard path.utf8.count < maxLen else { throw ManagementError.pathTooLong(path) }
            fd = socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else { throw ManagementError.connectFailed(path, errno) }
            var one: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            addr.sun_family = sa_family_t(AF_UNIX)
            withUnsafeMutableBytes(of: &addr.sun_path) { raw in
                raw.copyBytes(from: path.utf8)
                raw[path.utf8.count] = 0
            }
            addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard rc == 0 else {
                let e = errno
                Darwin.close(fd)
                fd = -1
                throw ManagementError.connectFailed(path, e)
            }
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        }

        deinit { close() }

        func close() {
            if fd >= 0 { Darwin.close(fd); fd = -1 }
        }

        /// Wakes a reader blocked on this connection (it then sees end of file) without closing the
        /// descriptor under it.
        func shutdown() {
            if fd >= 0 { _ = Darwin.shutdown(fd, SHUT_RDWR) }
        }

        /// Next line without its CR/LF, nil at EOF with nothing buffered.
        func readLine(until deadline: Date) throws -> String? {
            while true {
                if let nl = buffer.firstIndex(of: 0x0A) {
                    var lineData = buffer[buffer.startIndex..<nl]
                    buffer.removeSubrange(buffer.startIndex...nl)
                    if lineData.last == 0x0D { lineData = lineData.dropLast() }
                    return String(decoding: lineData, as: UTF8.self)
                }
                try waitFor(POLLIN, until: deadline)
                var chunk = [UInt8](repeating: 0, count: 4096)
                let n = read(fd, &chunk, chunk.count)
                if n > 0 {
                    buffer.append(chunk, count: n)
                } else if n == 0 {
                    if buffer.isEmpty { throw ManagementError.closed }
                    let rest = String(decoding: buffer, as: UTF8.self)
                    buffer.removeAll()
                    return rest
                } else if errno != EAGAIN && errno != EINTR {
                    throw ManagementError.closed
                }
            }
        }

        func write(_ text: String, until deadline: Date) throws {
            var bytes = Array(text.utf8)[...]
            while !bytes.isEmpty {
                try waitFor(POLLOUT, until: deadline)
                let n = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
                if n > 0 { bytes = bytes.dropFirst(n) }
                else if errno != EAGAIN && errno != EINTR { throw ManagementError.closed }
            }
        }

        private func waitFor(_ events: Int32, until deadline: Date) throws {
            while true {
                let ms = Int32(max(0, deadline.timeIntervalSinceNow * 1000).rounded(.up))
                if ms <= 0 { throw ManagementError.timeout }
                var p = pollfd(fd: fd, events: Int16(events), revents: 0)
                let rc = poll(&p, 1, ms)
                if rc > 0 { return }
                if rc == 0 { throw ManagementError.timeout }
                if errno != EINTR { throw ManagementError.closed }
            }
        }
    }
}
