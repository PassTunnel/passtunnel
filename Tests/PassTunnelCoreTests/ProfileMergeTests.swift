import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

/// The editor's Save applies only what the user changed on top of the stored profile.
final class ProfileMergeTests: CoreTestCase {
    func makeProfile() throws -> Profile {
        var p = try store.create(name: "Acme", type: .openvpn)
        p.username = "alice"
        p.healthHost = "10.0.0.5"
        p.otpMode = .totp
        try store.save(p)
        return p
    }

    func testEditorChangesAndConcurrentChangesBothSurvive() throws {
        let original = try makeProfile()

        // While the sheet is open, the CLI changes other fields (one of them nested).
        try store.update(original.id) {
            $0.username = "bob"
            $0.totp.period = 60
            $0.pinned = true
            $0.configSourceName = "acme.ovpn"
        }

        var edited = original
        edited.name = "Acme Corp"
        edited.totp.digits = 8
        edited.autoReconnect = true
        XCTAssertEqual(
            try ProfileMerge.changedFields(from: original, to: edited),
            ["auto_reconnect", "name", "totp.digits"])

        let saved = try store.update(original.id) {
            $0 = try ProfileMerge.merge(original: original, edited: edited, current: $0)
        }
        XCTAssertEqual(saved.name, "Acme Corp")
        XCTAssertEqual(saved.totp.digits, 8)
        XCTAssertTrue(saved.autoReconnect)
        XCTAssertEqual(saved.username, "bob")
        XCTAssertEqual(saved.totp.period, 60)
        XCTAssertTrue(saved.pinned)
        XCTAssertEqual(saved.configSourceName, "acme.ovpn")
        XCTAssertEqual(try store.get(original.id), saved)
    }

    func testTheEditorWinsOnTheFieldsItChanged() throws {
        let original = try makeProfile()
        try store.update(original.id) { $0.healthHost = "10.0.0.6" }
        var edited = original
        edited.healthHost = "10.0.0.7"
        let merged = try ProfileMerge.merge(original: original, edited: edited, current: try store.get(original.id))
        XCTAssertEqual(merged.healthHost, "10.0.0.7")
    }

    func testUnchangedEditorKeepsTheStoredProfile() throws {
        let original = try makeProfile()
        let current = try store.update(original.id) {
            $0.order = 7; $0.lastUsername = "carol"
        }
        XCTAssertEqual(try ProfileMerge.changedFields(from: original, to: original), [])
        XCTAssertEqual(try ProfileMerge.merge(original: original, edited: original, current: current), current)
    }

    func testClearingAnOptionalFieldRemovesIt() throws {
        var original = try makeProfile()
        original.configSourceName = "old.ovpn"
        try store.save(original)
        var edited = original
        edited.configSourceName = nil
        let current = try store.update(original.id) { $0.username = "dave" }
        let merged = try ProfileMerge.merge(original: original, edited: edited, current: current)
        XCTAssertNil(merged.configSourceName)
        XCTAssertEqual(merged.username, "dave")
    }

    func testIDStaysTheStoredOne() throws {
        let original = try makeProfile()
        var edited = original
        edited.id = "other"
        let merged = try ProfileMerge.merge(original: original, edited: edited, current: original)
        XCTAssertEqual(merged.id, original.id)
    }
}
