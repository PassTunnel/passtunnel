import Foundation
import PassTunnelKit

/// Which profiles the menu bar shows (docs/APP.md, Menu bar): the badges of the status item and, in the new
/// interface, the rows of the panel. Kept apart from SwiftUI so it is tested.
public enum MenuBarProfiles {
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
