import Foundation
import PassTunnelShared

/// A VPN's DNS left on a network service of the Mac: OpenVPN's DNS script set it, and no session of the script
/// is running to undo it (`OpenVPNDNS.leftBehind`). While the Mac uses that service (`inEffect`), every name lookup
/// goes to a server only that VPN reaches, so no name resolves, the VPN server's own included (`host_not_found`).
/// The helper gives back what PassTunnel's sessions set (from their records, docs/ARCHITECTURE.md, "DNS script
/// (macOS)"); this is a setting nothing shows PassTunnel set, so it is reported (`diagnose`, a `host_not_found`
/// failure while it is in effect), never changed.
public struct DNSLeftBehind: Codable, Equatable, Sendable {
    /// The network service ("Wi-Fi").
    public var service: String
    /// The VPN's DNS servers still set on it.
    public var servers: [String]
    /// The Mac uses it now: the service is the primary one, or the default resolver has those servers. Otherwise
    /// it matters only once that service is used again.
    public var inEffect: Bool

    public init(service: String, servers: [String], inEffect: Bool) {
        self.service = service
        self.servers = servers
        self.inEffect = inEffect
    }

    /// The Mac's now; nil on Linux and when the system configuration cannot be read, empty when there is none.
    public static func current() -> [DNSLeftBehind]? {
        #if os(macOS)
        return OpenVPNDNS.leftBehind(system: MacOpenVPNDNSSystem())?.map {
            DNSLeftBehind(service: $0.service, servers: $0.servers, inEffect: $0.inEffect)
        }
        #else
        return nil
        #endif
    }

    /// In effect: "This Mac’s DNS still points to a VPN’s DNS server (10.8.0.1 on Wi-Fi), which only that VPN can
    /// reach, so no name can be found. Restarting the Mac sets it back." Otherwise what happens once the service is
    /// used again.
    public var sentence: String {
        let list = servers.joined(separator: ", ")
        if inEffect {
            return String(
                localized:
                    "This Mac’s DNS still points to a VPN’s DNS server (\(list) on \(service)), which only that VPN can reach, so no name can be found. Restarting the Mac sets it back."
            )
        }
        return String(
            localized:
                "\(service) still has a VPN’s DNS server (\(list)), which only that VPN can reach. It is not in use now; once it is, no name can be found. Restarting the Mac sets it back."
        )
    }
}
