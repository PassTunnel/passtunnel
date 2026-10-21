import Foundation

/// Reads the per-profile `vpn.log` written by openvpn / openfortivpn. The helper creates a fresh
/// log for every start, so the whole file describes the current (or last) session.
public enum VPNLog {
    static let maxReadBytes = 256 * 1024

    /// The log text, or "" when it does not exist. Only the last `maxReadBytes` are read.
    public static func read(_ url: URL) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let start = size > UInt64(maxReadBytes) ? size - UInt64(maxReadBytes) : 0
        try? handle.seek(toOffset: start)
        let data = (try? handle.readToEnd()) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    /// The first `maxBytes` of the log (start-up lines: tunnel device, pushed options). The helper keeps
    /// them when it trims a long log.
    public static func readHead(_ url: URL, maxBytes: Int = 64 * 1024) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
        defer { try? handle.close() }
        let data = (try? handle.read(upToCount: maxBytes)) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    /// Last `lines` non-empty lines, without OpenVPN's notes about our own management-socket polls
    /// (a few every poll, they would push the interesting lines out).
    public static func tail(_ text: String, lines: Int = 12) -> String {
        text.split(whereSeparator: \.isNewline)
            .filter { !isManagementChatter($0) }
            .suffix(lines).joined(separator: "\n")
    }

    static let managementChatter = ["MANAGEMENT: Client connected from ", "MANAGEMENT: Client disconnected",
                                    "MANAGEMENT: CMD '"]

    static func isManagementChatter(_ line: Substring) -> Bool {
        managementChatter.contains { line.contains($0) }
    }

    // MARK: tunnel set-up

    /// The tunnel interface the tool opened: OpenVPN "Opened utun device utun5", openfortivpn
    /// "Interface ppp0 is UP".
    public static func tunnelInterface(_ text: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            for (marker, prefix) in [("Opened utun device ", "utun"), ("Interface ", "ppp")] {
                guard let r = line.range(of: marker) else { continue }
                let name = line[r.upperBound...].prefix { $0.isLetter || $0.isNumber }
                if name.hasPrefix(prefix), name.count > prefix.count { return String(name) }
            }
        }
        return nil
    }

    /// OpenVPN: the server pushed `redirect-gateway`, or OpenVPN added the `0/1` + `128/1` routes.
    public static func pushedRedirectGateway(_ text: String) -> Bool {
        text.split(whereSeparator: \.isNewline).contains { line in
            (line.contains("PUSH_REPLY") && line.contains("redirect-gateway"))
                || (line.contains("route add -net 128.0.0.0 ") && line.contains(" 128.0.0.0"))
        }
    }

    /// Something OpenVPN set up for the tunnel failed. `allTraffic` problems (the DNS hook, or the
    /// routes that take all traffic) mean another VPN is in the way and the session is unusable;
    /// others (a single route) leave a working but incomplete tunnel.
    public struct SetupProblem: Equatable, Sendable {
        public var reason: String          // the log line, without its timestamp
        public var allTraffic: Bool
    }

    /// Destinations of the routes `redirect-gateway` adds (IPv4 `def1`, IPv6 `def1` and `!ipv4`).
    static let allTrafficDestinations: Set<String> = ["0.0.0.0", "128.0.0.0", "default", "::", "8000::",
                                                       "2000::", "3000::", "fc00::"]

    /// The first DNS-hook failure or all-traffic route failure, else the first other route failure.
    public static func setupProblem(_ text: String) -> SetupProblem? {
        var routeProblem: SetupProblem?
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = withoutTimestamp(raw)
            let lower = line.lowercased()
            if lower.contains("setting dns failed") || lower.contains("dns-updown failed")
                || (lower.contains("dns updown") && (lower.contains("failed") || lower.contains("error status"))) {
                return SetupProblem(reason: line, allTraffic: true)
            }
            if let destination = failedRouteDestination(line) {
                if allTrafficDestinations.contains(destination) { return SetupProblem(reason: line, allTraffic: true) }
                if routeProblem == nil { routeProblem = SetupProblem(reason: line, allTraffic: false) }
            } else if lower.contains("route add command failed"), routeProblem == nil {
                routeProblem = SetupProblem(reason: line, allTraffic: false)
            }
        }
        return routeProblem
    }

    /// `route`'s own error line, "add net 0.0.0.0: gateway 10.8.0.1: File exists" → "0.0.0.0".
    static func failedRouteDestination(_ line: String) -> String? {
        for kind in ["add net ", "add host "] {
            guard let start = line.range(of: kind), let gateway = line.range(of: ": gateway ", range: start.upperBound..<line.endIndex),
                  line[gateway.upperBound...].contains(": ") else { continue }
            return String(line[start.upperBound..<gateway.lowerBound])
        }
        return nil
    }

    /// Drops OpenVPN's "2026-01-01 10:00:00 " prefix.
    static func withoutTimestamp(_ line: Substring) -> String {
        let s = line.trimmingCharacters(in: .whitespaces)
        let parts = s.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        if parts.count == 3, parts[0].count == 10, parts[0].filter({ $0 == "-" }).count == 2,
           parts[1].count == 8, parts[1].filter({ $0 == ":" }).count == 2 {
            return String(parts[2])
        }
        return s
    }

    /// openfortivpn: "Tunnel is up and running" seen.
    public static func fortiIsUp(_ text: String) -> Bool {
        text.contains("Tunnel is up and running")
    }

    /// openfortivpn: first address of the last "Got addresses: [10.1.2.3], ns [...]" line.
    public static func fortiAddress(_ text: String) -> String? {
        guard let line = text.split(whereSeparator: \.isNewline).last(where: { $0.contains("Got addresses: [") }),
              let open = line.range(of: "Got addresses: [") else { return nil }
        let rest = line[open.upperBound...]
        guard let close = rest.firstIndex(of: "]") else { return nil }
        let ip = rest[..<close].split(separator: ",").first?.trimmingCharacters(in: .whitespaces) ?? ""
        return ip.isEmpty ? nil : ip
    }

    static let authFailureMarkers = [
        "AUTH_FAILED", "auth-failure", "Could not authenticate", "Authentication failed",
        "VPN credentials are incorrect", "Login failed", "Invalid credentials",
    ]

    /// True when the log shows the server rejected the credentials.
    public static func isAuthFailure(_ text: String) -> Bool {
        authFailureMarkers.contains { text.range(of: $0, options: .caseInsensitive) != nil }
    }

    static let fatalMarkers = [
        "Exiting due to fatal error", "Options error", "Cannot resolve host address",
        "Gateway certificate validation failed", "Could not connect to gateway", "PassTunnel: ",
    ]

    /// True when the log shows a non-authentication error the tool will not recover from.
    public static func isFatal(_ text: String) -> Bool {
        fatalMarkers.contains { text.contains($0) }
    }
}
