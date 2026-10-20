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

    /// Last `lines` non-empty lines.
    public static func tail(_ text: String, lines: Int = 12) -> String {
        text.split(whereSeparator: \.isNewline).suffix(lines).joined(separator: "\n")
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
