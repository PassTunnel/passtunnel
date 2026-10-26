import Foundation
import PassTunnelKit

/// Which profiles the menu bar shows (docs/APP.md, Menu bar): the badges of the status item and, in the new
/// interface, the rows of the panel. Kept apart from SwiftUI so it is tested.
public enum MenuBarProfiles {
    /// What a profile is doing, as far as the status item is concerned (`StatusKind` without the drop, which is
    /// `droppedUnseen`'s to tell).
    public enum Activity: Equatable {
        case connected, connecting, degraded, disconnected, error
    }

    /// The badge the status item of the new interface draws for a profile that needs attention.
    public enum Attention: Equatable {
        case connected, connecting
        /// Dropped and not seen yet: the badge carries the red dot.
        case dropped
    }

    /// The badge of the new interface's status item: connecting or connected (also with a problem, as connecting),
    /// or dropped and not seen yet. A profile that is merely disconnected, pinned or not, has none.
    public static func attention(_ activity: Activity, droppedUnseen: Bool) -> Attention? {
        switch activity {
        case .connected: return .connected
        case .connecting, .degraded: return .connecting
        case .disconnected, .error: return droppedUnseen ? .dropped : nil
        }
    }

    /// The profiles with a badge, in the order shown: the pinned ones, those that are not idle (connecting,
    /// connected, reconnecting, in trouble) and those that dropped without being seen yet.
    public static func badged(in profiles: [Profile], isIdle: (Profile) -> Bool, droppedUnseen: Set<String>) -> [Profile] {
        profiles.filter { $0.pinned || droppedUnseen.contains($0.id) || !isIdle($0) }
    }

    /// The panel's rows: the badged profiles, or every profile while none is pinned.
    public static func panel(in profiles: [Profile], badged: [Profile]) -> [Profile] {
        profiles.contains { $0.pinned } ? badged : profiles
    }
}
