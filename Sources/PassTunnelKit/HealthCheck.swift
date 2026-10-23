import Foundation

/// Reachability probe used for health checks. The probe itself (`check`) is in PassTunnelCore.
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

    private static func portNumber<S: StringProtocol>(_ s: S) -> UInt16? {
        guard !s.isEmpty, s.allSatisfy(\.isASCII), let v = UInt16(s), v > 0 else { return nil }
        return v
    }
}
