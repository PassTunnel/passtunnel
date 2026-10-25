import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// Which clock measurement warns, and how far off it says the clock is (`ClockWarning.swift`).
final class ClockWarningTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func measured(_ offset: Int, ago: TimeInterval = 60, _ source: ClockOffset.Source = .gateway) -> ClockOffset {
        ClockOffset(offsetSeconds: offset, source: source, server: "vpn.example.com", checkedAt: now.addingTimeInterval(-ago))
    }

    func testAWrongRecentMeasurementWarns() {
        let wrong = measured(48)
        XCTAssertEqual(ClockOffset.recentWarning(in: [wrong], now: now), wrong)
        XCTAssertEqual(ClockOffset.recentWarning(in: [measured(-15)], now: now)?.offsetSeconds, -15, "ahead counts too")
        XCTAssertNil(ClockOffset.recentWarning(in: [measured(14)], now: now), "under the threshold")
        XCTAssertNil(ClockOffset.recentWarning(in: [], now: now))
    }

    /// The last measurement decides: a newer right one ends the warning, a newer wrong one replaces it.
    func testTheNewestMeasurementDecides() {
        XCTAssertNil(ClockOffset.recentWarning(in: [measured(48, ago: 600), measured(2, ago: 30, .timeServer)], now: now))
        XCTAssertEqual(ClockOffset.recentWarning(in: [measured(2, ago: 900), measured(-90, ago: 30)], now: now)?.offsetSeconds, -90)
    }

    func testAMeasurementExpiresAfterAnHour() {
        XCTAssertNotNil(ClockOffset.recentWarning(in: [measured(48, ago: 3599)], now: now))
        XCTAssertNil(ClockOffset.recentWarning(in: [measured(48, ago: 3600)], now: now))
        XCTAssertNil(ClockOffset.recentWarning(in: [measured(48, ago: -3600)], now: now), "from the far future")
        XCTAssertNil(ClockOffset.recentWarning(in: [measured(48, ago: 5000)], now: now, maxAge: 60))
    }

    func testHowFarOff() {
        XCTAssertEqual(measured(48).offBy, "48 s")
        XCTAssertEqual(measured(-119).offBy, "119 s")
        XCTAssertEqual(measured(120).offBy, "2 min")
        XCTAssertEqual(measured(-3599).offBy, "59 min")
        XCTAssertEqual(measured(7200).offBy, "2 h")
        XCTAssertFalse(measured(Int.min).offBy.isEmpty, "never traps")
        XCTAssertFalse(measured(Int.max).offBy.isEmpty)
        XCTAssertEqual(measured(48).headline, "This Mac’s clock is 48 s behind.")
        XCTAssertEqual(measured(-48).headline, "This Mac’s clock is 48 s ahead.")
    }
}
