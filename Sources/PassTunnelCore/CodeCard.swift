import Foundation
import PassTunnelKit

/// The rules of the code card in the detail of the main window (docs/APP.md, Main window): when its codes
/// show, when a copy button says "Copied ✓", and when the next code starts. Kept apart from SwiftUI so it is tested.
public enum CodeCard {
    /// How long a click shows codes that are hidden or protected (decision D-5).
    public static let revealDuration: TimeInterval = 20
    /// How long a copy button says "Copied ✓".
    public static let copiedDuration: TimeInterval = 1.6

    /// Bullets instead of the codes: always while they are locked (stored encrypted and not unlocked), and while they
    /// are hidden (Settings → hide codes) or protected (stored encrypted, also once unlocked) unless a click revealed
    /// them less than `revealDuration` ago. Copying never reveals: only `revealedUntil` does.
    public static func isMasked(locked: Bool, hidden: Bool, protected: Bool, revealedUntil: Date?,
                                at now: Date) -> Bool {
        if locked { return true }
        guard hidden || protected else { return false }
        guard let revealedUntil else { return true }
        return now >= revealedUntil
    }

    /// When the TOTP window after the one at `date` starts: the time of the "Next" code, which is also the code a
    /// connect that waits for a fresh code sends (`ConnectionManager` waits into the next window).
    public static func nextWindow(_ params: TOTPParams, after date: Date) -> Date {
        let period = TimeInterval(max(1, params.period))
        return Date(timeIntervalSince1970: TimeInterval(TOTP.counter(params: params, at: date) + 1) * period)
    }

    /// A code or password + code the app copied, for the "Copied ✓" of the card's buttons.
    public struct Copy: Equatable, Sendable {
        public enum Kind: Sendable { case code, passwordAndCode }

        public var profileID: String
        public var kind: Kind
        public var at: Date
        /// The TOTP window of the copied code (`TOTP.counter`).
        public var window: UInt64

        public init(profileID: String, kind: Kind, at: Date, window: UInt64) {
            self.profileID = profileID
            self.kind = kind
            self.at = at
            self.window = window
        }

        /// The button for `kind` of profile `id` says "Copied ✓": for `copiedDuration` after the copy, and only while
        /// the copied code is still the current one (`window` is the TOTP window at `now`), so the label never refers
        /// to a code that changed.
        public func shows(_ kind: Kind, for id: String, window current: UInt64, at now: Date) -> Bool {
            guard profileID == id, self.kind == kind, window == current else { return false }
            let elapsed = now.timeIntervalSince(at)
            return elapsed >= 0 && elapsed < CodeCard.copiedDuration
        }
    }
}
