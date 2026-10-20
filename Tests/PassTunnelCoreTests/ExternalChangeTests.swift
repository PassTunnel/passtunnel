import CoreServices
import XCTest
@testable import PassTunnelCore

/// Changes made by another process (the CLI) while the app runs: read-modify-write saves, the
/// support-directory watcher, and the helper hand-off arguments.
final class ExternalChangeTests: CoreTestCase {

    // MARK: ProfileStore.update

    func testUpdateKeepsFieldsChangedElsewhere() throws {
        let loaded = try store.create(name: "Acme", type: .openvpn)   // the app's copy

        var cli = try ProfileStore().get(loaded.id)                    // the CLI, later
        cli.otpMode = .totp
        cli.totp.period = 60
        cli.username = "alice"
        try ProfileStore().save(cli)

        let saved = try store.update(loaded.id) { $0.lastUsername = "bob" }
        XCTAssertEqual(saved.lastUsername, "bob")
        XCTAssertEqual(saved.otpMode, .totp)
        XCTAssertEqual(saved.totp.period, 60)
        XCTAssertEqual(saved.username, "alice")
        XCTAssertEqual(try store.get(loaded.id), saved)
    }

    func testUpdateValidatesAndKeepsTheID() throws {
        let p = try store.create(name: "Acme", type: .openvpn)
        let saved = try store.update(p.id) { $0.id = "other"; $0.pinned = true }
        XCTAssertEqual(saved.id, p.id)
        XCTAssertFalse(store.exists("other"))
        XCTAssertTrue(try store.get(p.id).pinned)

        assertThrows(.invalidField("totp.period")) { try store.update(p.id) { $0.totp.period = 0 } }
        XCTAssertEqual(try store.get(p.id).totp.period, 30, "nothing written when invalid")
        assertThrows(.profileNotFound("missing")) { try store.update("missing") { $0.pinned = true } }
    }

    // MARK: ProfilesWatcher

    func testRelevantPaths() {
        let dir = home.appendingPathComponent("profiles/acme").path
        XCTAssertTrue(ProfilesWatcher.isRelevant(path: dir + "/profile.json"))
        XCTAssertTrue(ProfilesWatcher.isRelevant(path: dir + "/config.ovpn"))
        XCTAssertTrue(ProfilesWatcher.isRelevant(path: dir))
        XCTAssertTrue(ProfilesWatcher.isRelevant(path: home.appendingPathComponent("config.json").path))
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: dir + "/vpn.log"))
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: dir + "/mgmt.sock"))
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: dir + "/.user-stopped"))
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: home.appendingPathComponent("profiles/.lock").path))
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: dir + "/.profile.json.0F1E2D3C.tmp"))
        XCTAssertTrue(ProfilesWatcher.isRelevant(path: dir + "/vpn.log",
                                                 flags: FSEventStreamEventFlags(kFSEventStreamEventFlagMustScanSubDirs)),
                      "dropped events: reload to be safe")
    }

    /// Profile edits, imports, deletes and preference changes from another process are reported;
    /// log output of a running VPN is not.
    func testWatcherReportsProfileChanges() throws {
        let p = try store.create(name: "Acme", type: .openvpn)
        let log = store.logURL(p.id)
        var calls = 0
        var expectation: XCTestExpectation?
        let watcher = ProfilesWatcher(paths: store.paths, latency: 0.05, debounce: 0.05) {
            calls += 1
            expectation?.fulfill()
        }
        XCTAssertTrue(watcher.start())
        defer { watcher.stop() }
        settle()
        calls = 0

        // VPN noise only.
        try Data("Initialization Sequence Completed\n".utf8).write(to: log)
        settle()
        XCTAssertEqual(calls, 0, "vpn.log writes must not cause reloads")

        func expectCall(_ label: String, _ change: () throws -> Void) rethrows {
            expectation = self.expectation(description: label)
            expectation?.assertForOverFulfill = false
            try change()
            wait(for: [expectation!], timeout: 5)
            expectation = nil
            settle()
        }
        try expectCall("set") { try ProfileStore().update(p.id) { $0.totp.period = 60 } }
        try expectCall("import") { _ = try ProfileStore().create(name: "Second", type: .forti) }
        try expectCall("preferences") { try ProfileStore().setDefault(p.id) }
        try expectCall("delete") { try ProfileStore().delete(p.id) }
    }

    func testStoppedWatcherIsSilent() throws {
        var calls = 0
        let watcher = ProfilesWatcher(paths: store.paths, latency: 0.05, debounce: 0.05) { calls += 1 }
        XCTAssertTrue(watcher.start())
        settle()
        calls = 0                                       // events from creating the directories
        watcher.stop()
        XCTAssertFalse(watcher.isRunning)
        _ = try store.create(name: "Acme", type: .openvpn)
        settle()
        XCTAssertEqual(calls, 0)
    }

    /// Lets pending FSEvents arrive and the debounce run.
    private func settle(_ seconds: TimeInterval = 0.8) {
        RunLoop.main.run(until: Date().addingTimeInterval(seconds))
    }

    // MARK: helper hand-off

    func testHelperHandOffArguments() {
        XCTAssertEqual(HelperHandoff.install.argument, "--install-helper")
        XCTAssertEqual(HelperHandoff.uninstall.argument, "--uninstall-helper")
        XCTAssertEqual(HelperHandoff.from(arguments: ["/Applications/PassTunnel.app/Contents/MacOS/PassTunnel",
                                                      "--install-helper"]), .install)
        XCTAssertEqual(HelperHandoff.from(arguments: ["PassTunnel", "-AppleLanguages", "(tr)", "--uninstall-helper"]),
                       .uninstall)
        XCTAssertNil(HelperHandoff.from(arguments: ["--install-helper"]), "argv[0] is the program")
        XCTAssertNil(HelperHandoff.from(arguments: ["PassTunnel", "--background"]))
        // Started with the argument, the binary must run as the app, not as the CLI.
        for action in HelperHandoff.allCases { XCTAssertFalse(CLICommand.isCommand(action.argument)) }
    }
}
