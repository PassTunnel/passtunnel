import Foundation
import PassTunnelKit

/// Which profile the copy items of the menu bar panel are for ("Copy Work code", "Copy Work password + code";
/// docs/APP.md, Menu bar): the default profile when it has a code, else the one that sent a code last, else the
/// first one with a code. Kept apart from SwiftUI so it is tested.
public enum CopyTarget {
    /// `profiles` in the order shown; `hasCode` tells which have a TOTP secret (shown or locked); `lastCodeSent`
    /// when a profile last sent a code (`ConnectionManager.lastCodeSent`), read only when the default does not
    /// decide. Nil when no profile has a code.
    public static func profile(
        in profiles: [Profile], defaultID: String?, hasCode: (Profile) -> Bool,
        lastCodeSent: (String) -> Date?
    ) -> Profile? {
        let candidates = profiles.filter(hasCode)
        if let defaultID, let p = candidates.first(where: { $0.id == defaultID }) { return p }
        var latest: (profile: Profile, sent: Date)?
        for p in candidates {
            // The earlier profile wins a tie.
            if let sent = lastCodeSent(p.id), sent > latest?.sent ?? .distantPast { latest = (p, sent) }
        }
        return latest?.profile ?? candidates.first
    }
}
