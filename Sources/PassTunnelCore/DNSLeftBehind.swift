import Foundation
import PassTunnelShared

/// A VPN's DNS left on a network service of the Mac: OpenVPN's DNS script set it, and no session of the script
/// is running to undo it (`OpenVPNDNS.leftBehind`). Every name lookup then goes to a server only that VPN
/// reaches, so no name resolves, the VPN server's own included (`host_not_found`). The helper gives back what
/// PassTunnel's sessions set (from their records, docs/ARCHITECTURE.md, "DNS script (macOS)"); this is a setting
/// nothing shows PassTunnel set, so it is reported (`diagnose`, a `host_not_found` failure), never changed.
public struct DNSLeftBehind: Codable, Equatable, Sendable {
    /// The network service ("Wi-Fi").
    public var service: String
    /// The VPN's DNS servers still set on it.
    public var servers: [String]

    public init(service: String, servers: [String]) {
        self.service = service
        self.servers = servers
    }

    /// The Mac's now; nil on Linux and when the system configuration cannot be read, empty when there is none.
    public static func current() -> [DNSLeftBehind]? {
        #if os(macOS)
        return OpenVPNDNS.leftBehind(system: MacOpenVPNDNSSystem())?.map { DNSLeftBehind(service: $0.service, servers: $0.servers) }
        #else
        return nil
        #endif
    }

    /// "This Mac’s DNS still points to a VPN’s DNS server (10.8.0.1 on Wi-Fi), which only that VPN can reach, so
    /// no name can be found. Restarting the Mac sets it back."
    public var sentence: String {
        let list = servers.joined(separator: ", ")
        return String(
            localized:
                "This Mac’s DNS still points to a VPN’s DNS server (\(list) on \(service)), which only that VPN can reach, so no name can be found. Restarting the Mac sets it back."
        )
    }
}
