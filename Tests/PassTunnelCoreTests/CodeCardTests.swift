import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// The code card of the main window: when its codes are masked (decision D-5: a click shows them for 20 s,
/// copying never does), when a copy button says "Copied ✓", and when the next code starts.
final class CodeCardTests: XCTestCase {
    /// The start of a 30 s window.
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func masked(locked: Bool = false, hidden: Bool = false, protected: Bool = false,
                        revealed seconds: TimeInterval? = nil) -> Bool {
        CodeCard.isMasked(locked: locked, hidden: hidden, protected: protected,
                          revealedUntil: seconds.map { now.addingTimeInterval($0) }, at: now)
    }

    func testShownUnlessHiddenProtectedOrLocked() {
        XCTAssertFalse(masked())
        XCTAssertFalse(masked(revealed: 5), "a reveal changes nothing for a code that shows anyway")
        XCTAssertTrue(masked(hidden: true))
        XCTAssertTrue(masked(protected: true), "a protected code stays masked once unlocked, e.g. after a copy")
        XCTAssertTrue(masked(locked: true, protected: true))
    }

    func testAClickShowsAHiddenOrProtectedCodeFor20Seconds() {
        XCTAssertEqual(CodeCard.revealDuration, 20)
        XCTAssertFalse(masked(hidden: true, revealed: 20))
        XCTAssertFalse(masked(protected: true, revealed: 0.1))
        XCTAssertFalse(masked(hidden: true, protected: true, revealed: 3))
        // Over: masked again.
        XCTAssertTrue(masked(hidden: true, revealed: 0))
        XCTAssertTrue(masked(protected: true, revealed: -1))
    }

    func testALockedCodeIsMaskedWhateverTheReveal() {
        XCTAssertTrue(masked(locked: true, revealed: 20))
        XCTAssertTrue(masked(locked: true, protected: true, revealed: 20))
    }

    func testTheNextWindow() {
        let params = TOTPParams()
        let next = Date(timeIntervalSince1970: 1_800_000_030)
        XCTAssertEqual(CodeCard.nextWindow(params, after: now), next, "at the start of a window: the one after it")
        XCTAssertEqual(CodeCard.nextWindow(params, after: now.addingTimeInterval(29.9)), next)
        XCTAssertEqual(CodeCard.nextWindow(params, after: next), next.addingTimeInterval(30))
        XCTAssertEqual(CodeCard.nextWindow(TOTPParams(period: 60), after: now), Date(timeIntervalSince1970: 1_800_000_060))
        XCTAssertEqual(CodeCard.nextWindow(TOTPParams(period: 0), after: now), now.addingTimeInterval(1),
                       "a period below 1 s counts as 1 s, as for the codes")
        // The next window's code is the one after the current code.
        let secret = Data("12345678901234567890".utf8)
        XCTAssertEqual(TOTP.code(secret: secret, params: params, at: CodeCard.nextWindow(params, after: now)),
                       TOTP.code(secret: secret, params: params, at: now.addingTimeInterval(30)))
    }

    func testCopiedShowsOnTheButtonThatCopiedFor1Point6Seconds() {
        let window = TOTP.counter(params: TOTPParams(), at: now)
        let copy = CodeCard.Copy(profileID: "work", kind: .code, at: now, window: window)
        XCTAssertTrue(copy.shows(.code, for: "work", window: window, at: now))
        XCTAssertTrue(copy.shows(.code, for: "work", window: window, at: now.addingTimeInterval(1.5)))
        XCTAssertFalse(copy.shows(.code, for: "work", window: window, at: now.addingTimeInterval(1.6)))
        XCTAssertFalse(copy.shows(.code, for: "work", window: window, at: now.addingTimeInterval(-1)))
        XCTAssertFalse(copy.shows(.passwordAndCode, for: "work", window: window, at: now), "the other button")
        XCTAssertFalse(copy.shows(.code, for: "lab", window: window, at: now), "another profile")
    }

    func testCopiedClearsWhenTheCodeChanges() {
        let params = TOTPParams()
        let late = now.addingTimeInterval(29.5)
        let copy = CodeCard.Copy(profileID: "work", kind: .passwordAndCode, at: late,
                                 window: TOTP.counter(params: params, at: late))
        let after = late.addingTimeInterval(0.6)   // still within 1.6 s, but a new window
        XCTAssertTrue(copy.shows(.passwordAndCode, for: "work", window: TOTP.counter(params: params, at: late), at: late))
        XCTAssertFalse(copy.shows(.passwordAndCode, for: "work", window: TOTP.counter(params: params, at: after), at: after))
    }
}
