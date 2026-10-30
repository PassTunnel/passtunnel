import Foundation
import PassTunnelVPNConfig

/// A Cisco AnyConnect server as users get it from their administrator, a URL such as
/// `https://vpn.example.com:8443/engineering`, split into the profile's `host`, `port` and `usergroup`.
public struct AnyConnectServer: Equatable, Sendable {
    /// Lowercased; an IPv6 literal without its brackets.
    public var host: String
    public var port: Int
    /// The URL path without its leading `/`; empty for none.
    public var usergroup: String

    public init(host: String, port: Int = 443, usergroup: String = "") {
        self.host = host
        self.port = port
        self.usergroup = usergroup
    }

    /// `https://host[:port][/usergroup]`, blanks around it ignored. `https://` may be left out, and its
    /// letters may be upper case; any other scheme is refused. The host follows the profile's rule
    /// (`OpenConnectAuthConfig.isValidHost`), an IPv6 literal in brackets (no zone id); the port is 1–65535
    /// in digits without a leading zero (443 when there is none); the path is empty, `/`, or `/` and a user
    /// group by its rule (`OpenConnectAuthConfig.isValidUsergroup`, kept as written). Nil for anything else:
    /// user info (`alice@`), a query or a fragment (`?`, `#`, even empty), percent escapes, whitespace or
    /// control characters inside.
    public static func parse(_ text: String) -> AnyConnectServer? {
        guard let split = OpenConnectServerAddress.split(text) else { return nil }
        guard split.path.isEmpty || OpenConnectAuthConfig.isValidUsergroup(split.path) else { return nil }
        return AnyConnectServer(host: split.host, port: split.port, usergroup: split.path)
    }
}

/// The part of a server address both openconnect types share: `[https://]host[:port][/path]`.
enum OpenConnectServerAddress {
    /// The lowercased host (an IPv6 literal without its brackets), the port (443 when none) and the path after
    /// the first `/` as written (empty for none); nil when the scheme, the host or the port is not one by
    /// `AnyConnectServer.parse`'s rules, or the text has `@ ? # %` anywhere. The path is not checked.
    static func split(_ text: String) -> (host: String, port: Int, path: String)? {
        var rest = Substring(text.trimmingCharacters(in: .whitespacesAndNewlines))
        guard !rest.isEmpty, !rest.contains(where: { "@?#%".contains($0) }) else { return nil }
        if let schemeEnd = rest.range(of: "://") {
            guard rest[..<schemeEnd.lowerBound].lowercased() == "https" else { return nil }
            rest = rest[schemeEnd.upperBound...]
        }
        let slash = rest.firstIndex(of: "/")
        let authority = rest[..<(slash ?? rest.endIndex)]
        let path = slash.map { rest[rest.index(after: $0)...] } ?? ""

        let host: Substring
        var portText: Substring?
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else { return nil }
            host = authority[authority.index(after: authority.startIndex)..<close]
            let after = authority[authority.index(after: close)...]
            if !after.isEmpty {
                guard after.hasPrefix(":") else { return nil }
                portText = after.dropFirst()
            }
            guard OpenConnectAuthConfig.isIPv6Literal(String(host)) else { return nil }
        } else {
            let parts = authority.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            host = parts[0]
            if parts.count == 2 { portText = parts[1] }
            // A colon left in the host is an IPv6 literal without brackets: its port could not be told apart.
            guard !host.contains(":"), OpenConnectAuthConfig.isValidHost(String(host)) else { return nil }
        }

        var port = 443
        if let portText {
            guard let first = portText.utf8.first, first != UInt8(ascii: "0"), portText.utf8.count <= 5,
                portText.utf8.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) }),
                let p = Int(portText), (1...65535).contains(p)
            else { return nil }
            port = p
        }
        return (host.lowercased(), port, String(path))
    }
}
