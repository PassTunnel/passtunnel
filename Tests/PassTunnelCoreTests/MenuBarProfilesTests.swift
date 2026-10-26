import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// Which profiles the menu bar badges and the panel's rows are for.
final class MenuBarProfilesTests: XCTestCase {
    private func profile(_ id: String, pinned: Bool = false) -> Profile {
        var p = Profile(id: id, name: id.capitalized, type: .openvpn)
        p.pinned = pinned
        return p
    }

    private func ids(_ profiles: [Profile]) -> [String] { profiles.map(\.id) }

    private func badged(_ profiles: [Profile], active: Set<String> = [], dropped: Set<String> = []) -> [Profile] {
        MenuBarProfiles.badged(in: profiles, isIdle: { !active.contains($0.id) }, droppedUnseen: dropped)
    }

    private func panel(_ profiles: [Profile], active: Set<String> = [], dropped: Set<String> = []) -> [String] {
        ids(MenuBarProfiles.panel(in: profiles, badged: badged(profiles, active: active, dropped: dropped)))
    }

    func testBadgesAreForPinnedActiveAndDroppedProfiles() {
        let all = [profile("home"), profile("work", pinned: true), profile("lab"), profile("travel")]
        XCTAssertEqual(ids(badged(all)), ["work"])
        XCTAssertEqual(ids(badged(all, active: ["lab"], dropped: ["travel"])), ["work", "lab", "travel"])
        XCTAssertEqual(ids(badged([profile("home")])), [])
    }

    func testPanelListsEverythingWhileNothingIsPinned() {
        let all = [profile("home"), profile("work"), profile("lab")]
        XCTAssertEqual(panel(all), ["home", "work", "lab"])
        XCTAssertEqual(panel(all, active: ["lab"], dropped: ["home"]), ["home", "work", "lab"])
        XCTAssertEqual(panel([]), [])
    }

    func testPanelListsThePinnedProfilesInOrder() {
        let all = [profile("home"), profile("work", pinned: true), profile("lab"), profile("travel", pinned: true)]
        XCTAssertEqual(panel(all), ["work", "travel"])
    }

    func testPanelAddsConnectingConnectedAndDroppedProfiles() {
        let all = [profile("home"), profile("work", pinned: true), profile("lab"), profile("travel")]
        XCTAssertEqual(panel(all, active: ["lab"]), ["work", "lab"])
        XCTAssertEqual(panel(all, dropped: ["home"]), ["home", "work"])
        XCTAssertEqual(panel(all, active: ["travel"], dropped: ["home"]), ["home", "work", "travel"])
    }

    func testAnUnpinnedProfileLeavesOnceItIsIdleAndSeen() {
        let all = [profile("home"), profile("work", pinned: true)]
        XCTAssertEqual(panel(all, active: ["home"]), ["home", "work"])
        XCTAssertEqual(panel(all), ["work"])
    }

    func testTheStatusItemOfTheNewInterfaceBadgesOnlyProfilesThatNeedAttention() {
        typealias A = MenuBarProfiles.Activity
        XCTAssertEqual(MenuBarProfiles.attention(.connected, droppedUnseen: false), .connected)
        XCTAssertEqual(MenuBarProfiles.attention(.connecting, droppedUnseen: false), .connecting)
        XCTAssertEqual(MenuBarProfiles.attention(.degraded, droppedUnseen: false), .connecting)
        XCTAssertEqual(MenuBarProfiles.attention(.disconnected, droppedUnseen: true), .dropped)
        XCTAssertEqual(MenuBarProfiles.attention(.error, droppedUnseen: true), .dropped)
        for activity in [A.disconnected, .error] {
            XCTAssertNil(MenuBarProfiles.attention(activity, droppedUnseen: false))
        }
    }

    func testAnActiveProfileKeepsItsBadgeWhateverItsDropFlag() {
        XCTAssertEqual(MenuBarProfiles.attention(.connected, droppedUnseen: true), .connected)
        XCTAssertEqual(MenuBarProfiles.attention(.connecting, droppedUnseen: true), .connecting)
    }
}
