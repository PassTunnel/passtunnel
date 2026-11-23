import Foundation
import PassTunnelShared

/// The Mac's DNS after an OpenVPN session, as the helper reports it in the profile's log (`OpenVPNDNS.Note`,
/// docs/ARCHITECTURE.md, "DNS script (macOS)"), in the activity.
extension ConnectionManager {
    /// Records in the activity what the helper wrote into the profile's log about the Mac's DNS and the activity
    /// does not have yet since the last connect: when a connect ends (the notes of the start, before the tool
    /// ran), after a disconnect (the helper answers once the session's DNS is checked) and after a drop. With
    /// `failure`, also the VPN's DNS it found left behind (`ConnectionFailure.dnsLeftBehind`).
    func recordDNSNotes(_ id: String, failure: ConnectionFailure? = nil) {
        var kinds = Self.dnsEvents(in: VPNLog.read(store.logURL(id)))
        if let left = failure?.dnsLeftBehind {
            let kind = Self.dnsEvent(.leftBehind, service: left.service, settings: left.servers)
            if !kinds.contains(kind) { kinds.append(kind) }
        }
        guard !kinds.isEmpty else { return }
        for kind in Self.unrecorded(kinds, in: activity(id)) { record(id, kind) }
    }

    /// The helper's notes in a log, as activity events (a note it could not act on yet and one it left alone are
    /// both a VPN's DNS left behind).
    nonisolated static func dnsEvents(in log: String) -> [ActivityEvent.Kind] {
        OpenVPNDNS.Note.all(in: log).map { dnsEvent($0.kind, service: $0.service, settings: $0.settings) }
    }

    nonisolated static func dnsEvent(_ kind: OpenVPNDNS.Note.Kind, service: String, settings: [String]) -> ActivityEvent.Kind {
        let service = ActivityEvent.clean(service, limit: 64)
        let settings = settings.prefix(8).map { ActivityEvent.clean($0, limit: 255) }
        switch kind {
        case .restored: return .dnsRestored(service: service, settings: settings)
        case .notRestored, .leftBehind: return .dnsLeftBehind(service: service, settings: settings)
        }
    }

    /// `kinds` but those `events` (oldest first) already have since their last `connecting`, each counted once:
    /// the log is the session's, and another process may have recorded some of it.
    nonisolated static func unrecorded(_ kinds: [ActivityEvent.Kind], in events: [ActivityEvent]) -> [ActivityEvent.Kind] {
        let start = events.lastIndex { if case .connecting = $0.kind { return true } else { return false } }.map { $0 + 1 } ?? 0
        var seen = events[start...].map(\.kind)
        var out: [ActivityEvent.Kind] = []
        for kind in kinds {
            if let i = seen.firstIndex(of: kind) { seen.remove(at: i) } else { out.append(kind) }
        }
        return out
    }
}
