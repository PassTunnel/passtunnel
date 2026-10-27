import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

/// Which profile the menu bar panel's copy items are for: the default profile when it has a code, else the one that
/// sent a code last, else the first with a code.
final class CopyTargetTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    /// The profiles asked when they last sent a code.
    private var asked: [String] = []

    private func profile(_ id: String, code: Bool = true) -> Profile {
        var p = Profile(id: id, name: id.capitalized, type: .openvpn)
        p.otpMode = code ? .totp : .none
        return p
    }

    private var all: [Profile] { [profile("home", code: false), profile("work"), profile("lab"), profile("travel")] }

    /// The target's id, with codes sent `sent` seconds before `now`.
    private func target(
        _ profiles: [Profile]? = nil, defaultID: String? = nil,
        sent: [String: TimeInterval] = [:]
    ) -> String? {
        CopyTarget.profile(
            in: profiles ?? all, defaultID: defaultID, hasCode: { $0.otpMode == .totp },
            lastCodeSent: { id in
                self.asked.append(id)
                return sent[id].map { self.now.addingTimeInterval(-$0) }
            })?.id
    }

    func testTheDefaultProfileWhenItHasACode() {
        XCTAssertEqual(target(defaultID: "lab", sent: ["travel": 10]), "lab")
        XCTAssertEqual(asked, [], "the default decides without reading when codes were sent")
    }

    func testOtherwiseTheProfileThatSentACodeLast() {
        XCTAssertEqual(target(sent: ["work": 3600, "travel": 60, "lab": 600]), "travel")
        XCTAssertEqual(asked, ["work", "lab", "travel"], "only profiles with a code")
        // A default without a code, or one that no longer exists, does not count.
        XCTAssertEqual(target(defaultID: "home", sent: ["lab": 5]), "lab")
        XCTAssertEqual(target(defaultID: "gone", sent: ["lab": 5]), "lab")
        // A profile without a code is never the target, whatever it sent.
        XCTAssertEqual(target(sent: ["home": 1, "lab": 5]), "lab")
    }

    func testOtherwiseTheFirstProfileWithACode() {
        XCTAssertEqual(target(), "work")
        XCTAssertEqual(target(sent: ["home": 1]), "work")
        // Sent in the same window: the earlier in the list.
        XCTAssertEqual(target(sent: ["travel": 30, "lab": 30]), "lab")
    }

    func testNoneWithoutACode() {
        XCTAssertNil(target([profile("home", code: false)]))
        XCTAssertNil(target([], defaultID: "work"))
        XCTAssertNil(target([profile("home", code: false)], defaultID: "home", sent: ["home": 1]))
    }
}
