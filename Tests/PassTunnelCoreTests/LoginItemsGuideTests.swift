// macOS only, like LoginItemsGuide. Nothing here reads System Settings: the tables are made up or written to a
// temporary folder.
#if os(macOS)
import Foundation
import XCTest

@testable import PassTunnelCore

final class LoginItemsGuideTests: XCTestCase {
    private let settings = LoginItemsGuide.systemSettingsBundleID
    private let start = Date(timeIntervalSince1970: 1_800_000_000)
    private let statuses: [HelperStatus] = [.notRegistered, .notFound, .enabled, .requiresApproval]

    private func situation(
        status: HelperStatus = .requiresApproval, removed: Bool = false, frontmost: String? = LoginItemsGuide.systemSettingsBundleID,
        running: Bool = true
    ) -> LoginItemsGuide.Situation {
        .init(status: status, removedByUser: removed, frontmost: frontmost, systemSettingsRunning: running)
    }

    private func started(at now: Date? = nil) -> LoginItemsGuide {
        var guide = LoginItemsGuide()
        XCTAssertTrue(guide.start(status: .requiresApproval, now: now ?? start))
        return guide
    }

    func testStartsOnlyForAHelperWaitingForTheApproval() {
        for status in statuses {
            var guide = LoginItemsGuide()
            XCTAssertEqual(guide.start(status: status, now: start), status == .requiresApproval, "\(status)")
            XCTAssertEqual(guide.isActive, status == .requiresApproval)
        }
        var removed = LoginItemsGuide()
        XCTAssertFalse(removed.start(status: .requiresApproval, removedByUser: true, now: start))
        XCTAssertFalse(removed.isActive)
    }

    func testNeverShowsForAnEnabledHelper() {
        // Not started for it (Settings → Helper offers Open Login Items… for an enabled helper too)…
        var guide = LoginItemsGuide()
        XCTAssertFalse(guide.start(status: .enabled, now: start))
        XCTAssertFalse(guide.shows(situation(status: .enabled), now: start))
        // …and a started one ends as soon as the helper is turned on.
        guide = started()
        XCTAssertTrue(guide.shows(situation(), now: start))
        XCTAssertFalse(guide.shows(situation(status: .enabled), now: start.addingTimeInterval(1)))
        XCTAssertFalse(guide.isActive)
        // It stays ended when the status reads as waiting again (switched off later): only a new start shows it.
        XCTAssertFalse(guide.shows(situation(), now: start.addingTimeInterval(2)))
    }

    func testStartingForAnotherStatusEndsARunningGuide() {
        var guide = started()
        XCTAssertFalse(guide.start(status: .enabled, now: start))
        XCTAssertFalse(guide.isActive)
    }

    func testNothingShowsUntilStarted() {
        var guide = LoginItemsGuide()
        for status in statuses {
            XCTAssertFalse(guide.shows(situation(status: status), now: start))
        }
    }

    func testShowsOnlyWhileSystemSettingsIsInFront() {
        var guide = started()
        // System Settings is still opening: PassTunnel in front, not running yet.
        XCTAssertFalse(guide.shows(situation(frontmost: "com.furkanprlk.passtunnel", running: false), now: start))
        XCTAssertTrue(guide.isActive)
        XCTAssertTrue(guide.shows(situation(), now: start.addingTimeInterval(1)))
        // Another app in front hides it; the guide keeps running and shows again with System Settings.
        XCTAssertFalse(guide.shows(situation(frontmost: "com.apple.Safari"), now: start.addingTimeInterval(2)))
        XCTAssertFalse(guide.shows(situation(frontmost: nil), now: start.addingTimeInterval(3)))
        XCTAssertTrue(guide.isActive)
        XCTAssertTrue(guide.shows(situation(), now: start.addingTimeInterval(4)))
    }

    func testEndsWhenSystemSettingsQuitsAfterItWasSeen() {
        var guide = started()
        // Not seen yet: not running does not end it (System Settings is still launching).
        XCTAssertFalse(guide.shows(situation(frontmost: nil, running: false), now: start))
        XCTAssertTrue(guide.isActive)
        XCTAssertFalse(guide.sawSystemSettings)
        XCTAssertTrue(guide.shows(situation(), now: start.addingTimeInterval(1)))
        XCTAssertTrue(guide.sawSystemSettings)
        XCTAssertFalse(guide.shows(situation(frontmost: "com.apple.finder", running: false), now: start.addingTimeInterval(2)))
        XCTAssertFalse(guide.isActive)
        XCTAssertFalse(guide.shows(situation(), now: start.addingTimeInterval(3)))
    }

    func testEndsWhenTheHelperIsGoneOrRemoved() {
        for status in [HelperStatus.notRegistered, .notFound] {
            var guide = started()
            XCTAssertFalse(guide.shows(situation(status: status), now: start), "\(status)")
            XCTAssertFalse(guide.isActive)
        }
        var guide = started()
        XCTAssertFalse(guide.shows(situation(removed: true), now: start))
        XCTAssertFalse(guide.isActive)
    }

    func testEndsAfterTheTimeout() {
        var guide = started()
        XCTAssertEqual(guide.deadline, start.addingTimeInterval(LoginItemsGuide.timeout))
        XCTAssertTrue(guide.shows(situation(), now: start.addingTimeInterval(LoginItemsGuide.timeout - 1)))
        XCTAssertFalse(guide.shows(situation(), now: start.addingTimeInterval(LoginItemsGuide.timeout)))
        XCTAssertFalse(guide.isActive)
    }

    func testStartingAgainRestartsTheTimeout() {
        var guide = started()
        let later = start.addingTimeInterval(LoginItemsGuide.timeout - 10)
        XCTAssertTrue(guide.shows(situation(), now: start))
        XCTAssertTrue(guide.start(status: .requiresApproval, now: later))
        XCTAssertFalse(guide.sawSystemSettings)
        XCTAssertTrue(guide.shows(situation(), now: start.addingTimeInterval(LoginItemsGuide.timeout + 10)))
        XCTAssertFalse(guide.shows(situation(), now: later.addingTimeInterval(LoginItemsGuide.timeout)))
    }

    func testCloseEndsIt() {
        var guide = started()
        XCTAssertTrue(guide.shows(situation(), now: start))
        guide.close()
        XCTAssertFalse(guide.isActive)
        XCTAssertNil(guide.deadline)
        XCTAssertFalse(guide.shows(situation(), now: start.addingTimeInterval(1)))
    }

    // MARK: the heading in System Settings

    private let tables: [String: [String: String]] = [
        "en": ["Background App Activity": "Background App Activity", "Open at Login": "Open at Login"],
        "tr": ["Background App Activity": "Arka Plan Uygulama Etkinliği", "Open at Login": "Oturum Açıldığında Aç"],
        "de": ["Open at Login": "Beim Anmelden öffnen"]
    ]

    func testHeadingInTheSystemLanguage() {
        XCTAssertEqual(LoginItemsPane.backgroundHeading(tables: tables, languages: ["en-US"]), "Background App Activity")
        XCTAssertEqual(LoginItemsPane.backgroundHeading(tables: tables, languages: ["tr-TR", "en-US"]), "Arka Plan Uygulama Etkinliği")
    }

    func testNoHeadingWhenTheSystemLanguageHasNone() {
        // Not the English one for a German System Settings: the guide then describes the list instead.
        XCTAssertNil(LoginItemsPane.backgroundHeading(tables: tables, languages: ["de-DE", "en-US"]))
        XCTAssertNil(LoginItemsPane.backgroundHeading(tables: [:], languages: ["en"]))
        XCTAssertNil(LoginItemsPane.backgroundHeading(tables: ["en": ["Allow": "Allow"]], languages: ["en"]))
        XCTAssertNil(LoginItemsPane.backgroundHeading(tables: ["en": ["Allow in the Background": "  "]], languages: ["en"]))
    }

    func testUnmatchedLanguageGetsTheEnglishHeading() {
        // A system language the pane has no strings for: English, as System Settings falls back to, whatever the
        // order of the tables.
        for _ in 0..<5 {
            XCTAssertEqual(LoginItemsPane.backgroundHeading(tables: tables, languages: ["fr-FR"]), "Background App Activity")
        }
        XCTAssertEqual(LoginItemsPane.tableLanguage(available: ["tr", "en", "de"], languages: ["ja-JP"]), "en")
        XCTAssertEqual(LoginItemsPane.tableLanguage(available: ["tr", "en", "de"], languages: []), "en")
        XCTAssertEqual(LoginItemsPane.tableLanguage(available: ["tr", "en", "en_GB"], languages: ["en-GB"]), "en_GB")
        XCTAssertEqual(LoginItemsPane.tableLanguage(available: ["tr", "en"], languages: ["tr-TR", "en-US"]), "tr")
        XCTAssertEqual(LoginItemsPane.tableLanguage(available: ["zh_CN", "en"], languages: ["zh-Hans-CN"]), "zh_CN")
        XCTAssertNil(LoginItemsPane.tableLanguage(available: [], languages: ["en"]))
    }

    func testHeadingIsIsolatedFromTheSentence() {
        let arabic = "نشاط التطبيقات في الخلفية"
        let isolated = LoginItemsPane.isolated(arabic)
        XCTAssertEqual(isolated.unicodeScalars.first, "\u{2068}")
        XCTAssertEqual(isolated.unicodeScalars.last, "\u{2069}")
        XCTAssertEqual(String(isolated.unicodeScalars.dropFirst().dropLast()), arabic)
    }

    func testEdgeAwayFromTheSwitches() {
        XCTAssertEqual(LoginItemsGuide.edge(systemLanguages: ["en-US", "ar"]), .left)
        XCTAssertEqual(LoginItemsGuide.edge(systemLanguages: ["tr-TR"]), .left)
        XCTAssertEqual(LoginItemsGuide.edge(systemLanguages: ["ar-SA", "en"]), .right)
        XCTAssertEqual(LoginItemsGuide.edge(systemLanguages: ["he"]), .right)
        XCTAssertEqual(LoginItemsGuide.edge(systemLanguages: ["fa-IR"]), .right)
        XCTAssertEqual(LoginItemsGuide.edge(systemLanguages: []), .left)
    }

    func testEarlierHeadingAndTheNewestFirst() {
        let earlier = ["en": ["Allow in the Background": "Allow in the Background"]]
        XCTAssertEqual(LoginItemsPane.backgroundHeading(tables: earlier, languages: ["en"]), "Allow in the Background")
        let both = ["en": ["Allow in the Background": "Allow in the Background", "Background App Activity": "Background App Activity"]]
        XCTAssertEqual(LoginItemsPane.backgroundHeading(tables: both, languages: ["en"]), "Background App Activity")
    }

    func testReadsALoctable() throws {
        let bundle = try temporaryBundle()
        let plist: [String: Any] = [
            "en": ["Background App Activity": "Background App Activity", "%lld items": ["NSStringFormatSpecTypeKey": "x"]],
            "tr": ["Background App Activity": "Arka Plan Uygulama Etkinliği"]
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0)
        try data.write(to: bundle.appendingPathComponent("Contents/Resources/Localizable.loctable"))
        let read = LoginItemsPane.localizedTables(in: bundle)
        XCTAssertEqual(read["en"], ["Background App Activity": "Background App Activity"])
        XCTAssertEqual(read["tr"], ["Background App Activity": "Arka Plan Uygulama Etkinliği"])
    }

    func testReadsStringsFilesWhenThereIsNoLoctable() throws {
        let bundle = try temporaryBundle()
        let resources = bundle.appendingPathComponent("Contents/Resources")
        for (language, value) in [("en", "Allow in the Background"), ("tr", "Arka Planda İzin Ver")] {
            let folder = resources.appendingPathComponent("\(language).lproj")
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try Data("\"Allow in the Background\" = \"\(value)\";\n".utf8).write(to: folder.appendingPathComponent("Localizable.strings"))
        }
        let read = LoginItemsPane.localizedTables(in: bundle)
        XCTAssertEqual(read["tr"], ["Allow in the Background": "Arka Planda İzin Ver"])
        XCTAssertEqual(LoginItemsPane.backgroundHeading(tables: read, languages: ["en"]), "Allow in the Background")
    }

    func testNothingReadableGivesNoTables() throws {
        XCTAssertEqual(LoginItemsPane.localizedTables(in: try temporaryBundle()), [:])
        XCTAssertEqual(LoginItemsPane.localizedTables(in: URL(fileURLWithPath: "/nonexistent/LoginItems.appex")), [:])
    }

    private func temporaryBundle() throws -> URL {
        let bundle = FileManager.default.temporaryDirectory.appendingPathComponent("LoginItemsGuideTests-\(UUID().uuidString).appex")
        try FileManager.default.createDirectory(
            at: bundle.appendingPathComponent("Contents/Resources"), withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: bundle) }
        return bundle
    }
}
#endif
