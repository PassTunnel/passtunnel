import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// Where a code read from a QR image goes: the profile it was asked for, a profile to pick, or, with no profile to
/// take it, a new profile.
final class ScannedCodeTargetTests: XCTestCase {
    private func profile(_ id: String, _ mode: PasswordMode = .keychain) -> Profile {
        var p = Profile(id: id, name: id.capitalized, type: .openvpn)
        p.passwordMode = mode
        return p
    }

    func testRequestedProfileWhileItExists() {
        let work = profile("work"), lab = profile("lab", .none)
        XCTAssertEqual(ScannedCodeTarget.route(requested: "work", profiles: [work, lab]), .profile("work"))
        // The profile it was asked for takes it even without a password (as before).
        XCTAssertEqual(ScannedCodeTarget.route(requested: "lab", profiles: [work, lab]), .profile("lab"))
        // Deleted meanwhile: the user picks one.
        XCTAssertEqual(ScannedCodeTarget.route(requested: "gone", profiles: [work, lab]), .choose([work]))
    }

    func testPicksAmongProfilesThatSignInWithAPassword() {
        let work = profile("work"), lab = profile("lab", .none), guest = profile("guest", .ask)
        XCTAssertEqual(ScannedCodeTarget.route(requested: nil, profiles: [work, lab, guest]), .choose([work, guest]))
    }

    func testNoProfileToTakeIt() {
        let certificateOnly = profile("lab", .none)
        for profiles in [[], [certificateOnly]] {
            XCTAssertEqual(ScannedCodeTarget.route(requested: nil, profiles: profiles), .newProfile)
        }
    }
}
