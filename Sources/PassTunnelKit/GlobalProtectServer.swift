import Foundation

/// A Palo Alto GlobalProtect portal (or, for a profile that skips the portal, gateway) as users get it from
/// their administrator, an address such as `vpn.example.com` or `https://vpn.example.com:8443`, split into the
/// profile's `host` and `port`.
public struct GlobalProtectServer: Equatable, Sendable {
    /// Lowercased; an IPv6 literal without its brackets.
    public var host: String
    public var port: Int

    public init(host: String, port: Int = 443) {
        self.host = host
        self.port = port
    }

    /// `[https://]host[:port]`, by `AnyConnectServer.parse`'s rules for the scheme, the host and the port, but
    /// without a path: a GlobalProtect address has none, so only an empty one or a lone `/` is taken. Nil for
    /// anything else, `/global-protect/…` or `/ssl-vpn/…` pasted from a browser included.
    public static func parse(_ text: String) -> GlobalProtectServer? {
        guard let split = OpenConnectServerAddress.split(text), split.path.isEmpty else { return nil }
        return GlobalProtectServer(host: split.host, port: split.port)
    }
}
