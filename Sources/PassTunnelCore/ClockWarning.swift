import Foundation
import PassTunnelKit

/// What the app says about a clock that is off (the banner above the detail, the card of a rejected sign-in):
/// which measurement is worth warning about, and how far off it says the clock is.
extension ClockOffset {
    /// A measurement older than this no longer warns: the clock may have been fixed since.
    public static let warningAge: TimeInterval = 3600

    /// The newest of `measurements` (every profile's, and the time server's) when it is under `maxAge` old and
    /// off by `warnSeconds` or more; nil when it is right, too old, or there is none. A newer right measurement
    /// ends the warning, whatever older ones said.
    public static func recentWarning(in measurements: [ClockOffset], now: Date, maxAge: TimeInterval = warningAge) -> ClockOffset? {
        guard let latest = measurements.max(by: { $0.checkedAt < $1.checkedAt }) else { return nil }
        let age = now.timeIntervalSince(latest.checkedAt)
        return latest.isWrong && age.isFinite && abs(age) < maxAge ? latest : nil
    }

    /// How far off, in the unit that fits: "48 s", "5 min", "3 h".
    public var offBy: String {
        let seconds = Int(min(offsetSeconds.magnitude, 1_000_000_000))
        if seconds < 120 { return String(localized: "\(seconds) s") }
        if seconds < 7200 { return String(localized: "\(seconds / 60) min") }
        return String(localized: "\(seconds / 3600) h")
    }

    /// "This Mac’s clock is 48 s behind."
    public var headline: String {
        isBehind
            ? String(localized: "This Mac’s clock is \(offBy) behind.")
            : String(localized: "This Mac’s clock is \(offBy) ahead.")
    }
}
