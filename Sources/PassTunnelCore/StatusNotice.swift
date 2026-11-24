import Foundation
import PassTunnelKit

/// Something the user should know about a connection that is up, shown beside its status (the app's detail view,
/// `status`, the MCP `get_status`, as `notices`). Display only: it comes from the session's log, part of which the
/// server writes, or from the profile's activity, so it decides nothing.
public enum StatusNotice: String, Codable, CaseIterable, Sendable {
    /// Palo Alto GlobalProtect: the gateway asked for a host information report (HIP), which PassTunnel never sends
    /// (docs/ARCHITECTURE.md, "HIP: never run, the user is told"); the gateway may limit what the tunnel reaches.
    /// From openconnect's three warning lines (`VPNLog.globalProtectHIPRequested`).
    case hipReportNotSent = "hip_report_not_sent"
    /// The server's name was not found when this connection was made, and it was reached at the address it had at
    /// its last successful connection (`LastKnownAddress`): the network's DNS was not answering then. From the
    /// activity's last `connected` event (`ActivityEvent.Kind.connected(viaLastKnownAddress:)`).
    case connectedThroughLastKnownAddress = "connected_through_last_known_address"

    /// The sentence a front end shows.
    public var message: String {
        switch self {
        case .hipReportNotSent:
            return String(
                localized: "The gateway asked for a host information report, which PassTunnel does not send. Access may be limited.")
        case .connectedThroughLastKnownAddress:
            return String(
                localized:
                    "The server’s name could not be found when connecting, so its last known address was used. This network’s DNS may not be working."
            )
        }
    }

    /// The notices for a session of `type` that is up, from its log (the tunnel run's, as the helper writes it).
    public static func of(_ type: VPNType, log: String) -> [StatusNotice] {
        guard type == .globalprotect, VPNLog.globalProtectHIPRequested(log) else { return [] }
        return [.hipReportNotSent]
    }
}

extension ConnectionManager {
    /// The notices of `id`'s connection while it is connected (`StatusNotice`); empty otherwise. Reads its log and,
    /// for the types that use a last known address, its activity.
    public func notices(_ id: String) -> [StatusNotice] {
        guard state(id).isConnected, let p = try? store.get(id), p.type.usesOpenConnect else { return [] }
        var notices = StatusNotice.of(p.type, log: VPNLog.read(store.logURL(id)))
        if LastKnownAddress.isSupported(p.type), ActivityEvent.lastConnection(in: activity(id))?.viaLastKnownAddress != nil {
            notices.append(.connectedThroughLastKnownAddress)
        }
        return notices
    }
}
