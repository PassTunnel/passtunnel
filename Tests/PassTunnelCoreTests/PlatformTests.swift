import Foundation
import XCTest
@testable import PassTunnelCLI
@testable import PassTunnelCore
@testable import PassTunnelKit
import PassTunnelShared

// The seams between the Mac and Linux (docs/LINUX.md): each platform's values and stand-ins, and the
// parts of the other platform's that build everywhere.

// MARK: - JSON values (MCP input)

final class JSONValueTests: XCTestCase {
    func parse(_ text: String) throws -> JSONValue { try JSONValue(parsing: Data(text.utf8)) }

    func testBooleansAreNeverNumbers() throws {
        XCTAssertEqual(try parse("true"), .bool(true))
        XCTAssertEqual(try parse("false"), .bool(false))
        XCTAssertEqual(try parse("1"), .integer(1))
        XCTAssertEqual(try parse("0"), .integer(0))
        XCTAssertEqual(try parse(#"[true, 1, false, 0]"#), .array([.bool(true), .integer(1), .bool(false), .integer(0)]))
    }

    func testNumbers() throws {
        XCTAssertEqual(try parse("5.0"), .integer(5))
        XCTAssertEqual(try parse("-0"), .integer(0))
        XCTAssertEqual(try parse("1e3"), .integer(1000))
        XCTAssertEqual(try parse("9223372036854775807"), .integer(.max))
        XCTAssertEqual(try parse("-9223372036854775808"), .integer(.min))
        XCTAssertEqual(try parse("2.5"), .number(2.5))
        XCTAssertEqual(try parse("9223372036854775808"), .number(9_223_372_036_854_775_808))
        XCTAssertEqual(try parse("1e300"), .number(1e300))
    }

    func testStringsNullsAndContainers() throws {
        XCTAssertEqual(try parse(#""true""#), .string("true"))
        XCTAssertEqual(try parse(#""1""#), .string("1"))
        XCTAssertEqual(try parse("null"), .null)
        XCTAssertEqual(try parse(#"{"a":{"b":[null,"x"]},"c":{}}"#),
                       .object(["a": .object(["b": .array([.null, .string("x")])]), "c": .object([:])]))
        XCTAssertEqual(try parse(#"{"a":1}"#).objectValue?["a"], .integer(1))
        XCTAssertNil(try parse("[]").objectValue)
        XCTAssertEqual(try parse(#""ç\n""#).stringValue, "ç\n")
    }

    func testInvalidJSONThrows() {
        for text in ["", "{", "{not json", "tru", "'a'", "{\"a\" 1}", "NaN", "\u{FF}", "1e999",
                     String(repeating: "[", count: 600) + String(repeating: "]", count: 600)] {
            XCTAssertThrowsError(try parse(text), text.debugDescription)
        }
    }

    /// Nested values are decoded once (containers are tried first), so deep nesting stays cheap.
    func testDeepNesting() throws {
        let objects = String(repeating: #"{"a":"#, count: 500) + "true" + String(repeating: "}", count: 500)
        var value = try parse(objects)
        for _ in 0..<500 { value = try XCTUnwrap(value.objectValue?["a"]) }
        XCTAssertEqual(value, .bool(true))
        let arrays = String(repeating: "[", count: 300) + "2.5" + String(repeating: "]", count: 300)
        XCTAssertNotNil(try parse(arrays))
    }

    /// Whatever the decoder does with a key given twice, it does not crash.
    func testDuplicateKeysDoNotCrash() throws {
        let value = try? parse(#"{"id":1,"id":"x","method":"ping"}"#)
        if let value { XCTAssertEqual(value.objectValue?["method"], .string("ping")) }
    }

    func testSerializableRoundTrip() throws {
        let value = try parse(#"{"a":[true,false,null,1,2.5,"s"],"b":{"c":9007199254740993}}"#)
        let data = try JSONSerialization.data(withJSONObject: value.serializable, options: [.sortedKeys])
        XCTAssertEqual(try JSONValue(parsing: data), value)
    }

    func testRequestIDs() {
        for id: JSONValue in [.string("a"), .integer(1), .integer(-5), .number(1e19)] {
            XCTAssertTrue(MCPServer.isValidID(id), "\(id)")
        }
        for id: JSONValue in [.null, .bool(true), .bool(false), .number(1.5), .number(.infinity), .number(.nan),
                              .array([]), .object([:])] {
            XCTAssertFalse(MCPServer.isValidID(id), "\(id)")
        }
        XCTAssertEqual(MCPServer.key(.integer(7)), "n:7")
        XCTAssertEqual(MCPServer.key(.string("7")), "s:7")
        XCTAssertNotEqual(MCPServer.key(.integer(7)), MCPServer.key(.string("7")))
    }
}

// MARK: - Secret stores

final class SecretStoreTests: CoreTestCase {
    override func tearDownWithError() throws {
        unsetenv("PASSTUNNEL_SECRET_STORE")
        useTestSecrets(service: service)
        try super.tearDownWithError()
    }

    func testMemoryStore() throws {
        let store = MemorySecretStore(service: service)
        XCTAssertNil(store.read("acme/password"))
        store.write("acme/password", Data("first".utf8))
        store.write("acme/password", Data("second".utf8))
        XCTAssertEqual(store.read("acme/password"), Data("second".utf8))
        XCTAssertNil(MemorySecretStore(service: service + "-other").read("acme/password"), "per service")
        store.remove("acme/password")
        store.remove("acme/password")
        XCTAssertNil(store.read("acme/password"))
        store.write("a/totp", Data("x".utf8))
        store.removeAll()
        XCTAssertNil(store.read("a/totp"))
    }

    func testSecretsUseTheMemoryStoreWhenAsked() throws {
        setenv("PASSTUNNEL_SECRET_STORE", "memory", 1)
        XCTAssertTrue(Secrets.store is MemorySecretStore)
        try Secrets.set("acme", .password, "pw")
        XCTAssertEqual(Secrets.get("acme", .password), "pw")
        XCTAssertTrue(try Secrets.exists("acme", .password))
        XCTAssertEqual(MemorySecretStore(service: service).read("acme/password"), Data("pw".utf8))
        Secrets.deleteAllInOverriddenService()
        XCTAssertFalse(Secrets.has("acme", .password))
    }

    func testUnconfiguredStoreRefusesWithAClearError() throws {
        let store: SecretStore = UnconfiguredSecretStore()
        XCTAssertThrowsError(try store.read("acme/password")) { XCTAssertTrue($0 is SecretStoreUnavailable) }
        XCTAssertThrowsError(try store.write("acme/password", Data())) { XCTAssertTrue($0 is SecretStoreUnavailable) }
        XCTAssertNoThrow(try store.remove("acme/password"), "nothing to remove: deleting profiles works")
        XCTAssertFalse((SecretStoreUnavailable().errorDescription ?? "").isEmpty)
        XCTAssertEqual(AutomationErrorCode.of(SecretStoreUnavailable()), .keychainError)
    }

    #if os(Linux)
    /// Without `PASSTUNNEL_SECRET_STORE`, Linux has no store yet: profiles can be made, listed and
    /// deleted, secrets cannot be saved, and what needs one says so.
    @MainActor func testLinuxWithoutAStore() async throws {
        unsetenv("PASSTUNNEL_SECRET_STORE")
        XCTAssertTrue(Secrets.store is UnconfiguredSecretStore)
        var p = try store.create(name: "Acme", type: .openvpn)
        p.passwordMode = .keychain
        p.otpMode = .totp
        try store.save(p)
        XCTAssertThrowsError(try Secrets.set(p.id, .password, "pw")) { XCTAssertTrue($0 is SecretStoreUnavailable) }
        XCTAssertFalse(Secrets.has(p.id, .password))
        XCTAssertThrowsError(try Secrets.exists(p.id, .password))

        let manager = ConnectionManager(store: store, helper: UnavailableHelperClient(), routes: { [] })
        let automation = AutomationService(store: store, manager: manager)
        let check = await automation.diagnose().profiles[0]
        XCTAssertNil(check.passwordSaved)
        XCTAssertNil(check.totpSaved)
        XCTAssertEqual(check.problems.filter { $0.code == AutomationErrorCode.keychainError.rawValue }.count, 1,
                       "once, not per secret: \(check.problems)")
        do {
            _ = try await manager.vault.secret(p, .totp, for: .code)
            XCTFail("expected an error")
        } catch {
            XCTAssertTrue(error is SecretStoreUnavailable, "\(error)")
        }
        try store.delete(p.id)
    }
    #endif
}

// MARK: - Combine stand-in

#if !canImport(Combine)
@MainActor
final class CombineStandInTests: XCTestCase {
    final class Model: ObservableObject {
        @Published private(set) var states: [String: Int] = [:]
        @Published var name: String?
        let events = PassthroughSubject<String, Never>()
        var seenWhileSetting: [String: Int]?

        func set(_ id: String, _ value: Int) { states[id] = value }
    }

    func testPublishedSendsTheCurrentValueThenEachNewOneBeforeItIsStored() {
        let m = Model()
        m.set("a", 1)
        var seen: [Int] = []
        var bag: Set<AnyCancellable> = []
        m.$states.compactMap { $0["a"] }.sink { value in
            seen.append(value)
            m.seenWhileSetting = m.states
        }.store(in: &bag)
        XCTAssertEqual(seen, [1], "the current value at once")
        m.set("a", 2)
        XCTAssertEqual(seen, [1, 2])
        XCTAssertEqual(m.seenWhileSetting?["a"], 1, "sent before the value is stored, like Combine")
        XCTAssertEqual(m.states["a"], 2)
        m.set("b", 3)
        XCTAssertEqual(seen, [1, 2, 2], "every change, like Combine (no removeDuplicates)")
        bag.removeAll()
        m.set("a", 4)
        XCTAssertEqual(seen, [1, 2, 2], "released: no more values")
    }

    func testCompactMapDropsNil() {
        let m = Model()
        var names: [String] = []
        let subscription = m.$name.compactMap { $0 }.sink { names.append($0) }
        m.name = "x"
        m.name = nil
        m.name = "y"
        XCTAssertEqual(names, ["x", "y"])
        subscription.cancel()
        m.name = "z"
        XCTAssertEqual(names, ["x", "y"])
    }

    func testSubjectAndCancelling() {
        let m = Model()
        var log: [String] = []
        var first: AnyCancellable?
        first = m.events.sink { value in
            log.append("1" + value)
            first?.cancel()
        }
        let second = m.events.sink { log.append("2" + $0) }
        m.events.send("a")
        m.events.send("b")
        XCTAssertEqual(log, ["1a", "2a", "2b"], "a subscriber may cancel while it is called")
        second.cancel()
        second.cancel()
        m.events.send("c")
        XCTAssertEqual(log, ["1a", "2a", "2b"])
        var bag: Set<AnyCancellable> = []
        m.events.sink { log.append("3" + $0) }.store(in: &bag)
        m.events.sink { log.append("4" + $0) }.store(in: &bag)
        XCTAssertEqual(bag.count, 2)
        m.events.send("d")
        XCTAssertEqual(log.suffix(2), ["3d", "4d"])
    }
}
#endif

// MARK: - Platform values and placeholders

final class PlatformValueTests: XCTestCase {
    func testPaths() {
        #if os(Linux)
        XCTAssertEqual(PT.profilesSubpath, ".local/share/passtunnel/profiles")
        XCTAssertEqual(PT.helperRunRoot, "/run/passtunnel")
        XCTAssertEqual(HelperCore.maxSocketPathBytes, 107)
        XCTAssertEqual(AppPaths.linuxSubpath + "/profiles", PT.profilesSubpath)
        #else
        XCTAssertEqual(PT.profilesSubpath, "Library/Application Support/PassTunnel/profiles")
        XCTAssertEqual(PT.helperRunRoot, "/var/run/passtunnel")
        XCTAssertEqual(HelperCore.maxSocketPathBytes, 103)
        #endif
        XCTAssertEqual(MemoryLayout.size(ofValue: sockaddr_un().sun_path), HelperCore.maxSocketPathBytes + 1)
        XCTAssertEqual(PT.mgmtSocketPath(uid: 501, profileID: "acme"), PT.helperRunRoot + "/501/acme/mgmt.sock")
    }

    func testDefaultSupportDirectory() {
        let saved = getenv("PASSTUNNEL_HOME").map { String(cString: $0) }
        defer { if let saved { setenv("PASSTUNNEL_HOME", saved, 1) } }
        unsetenv("PASSTUNNEL_HOME")
        let home = URL(fileURLWithPath: NSHomeDirectory())
        #if os(Linux)
        XCTAssertEqual(AppPaths.default.root.path, home.appendingPathComponent(".local/share/passtunnel").standardizedFileURL.path)
        #else
        XCTAssertTrue(AppPaths.default.root.path.hasSuffix("/Library/Application Support/PassTunnel"), AppPaths.default.root.path)
        #endif
        XCTAssertEqual(AppPaths.default.profilesDir.path, AppPaths.default.root.appendingPathComponent("profiles").path)
    }

    func testDevelopmentBuildVersion() {
        XCTAssertEqual(BuildVersion.development, "0.0.0-dev")
        XCTAssertEqual(BuildVersion.version, BuildVersion.development, "tests are not release builds")
        XCTAssertNil(BuildVersion.build)
        #if os(Linux)
        XCTAssertEqual(AppInfo.current.version, "0.0.0-dev")
        XCTAssertNil(AppInfo.current.build)
        XCTAssertFalse(AppInfo.current.inApplications)
        #endif
    }

    func testUnavailableHelper() async {
        do {
            _ = try await UnavailableHelperClient.shared.perform(.status, timeout: 1)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(error as? HelperClientError, .notInstalled)
            XCTAssertEqual(AutomationErrorCode.of(error), .helperNotInstalled)
        }
        do {
            try await UnavailableHelperClient.shared.ensureCompatible()
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(error as? HelperClientError, .notInstalled)
        }
        #if os(Linux)
        XCTAssertTrue(ConnectionManager.defaultHelper is UnavailableHelperClient)
        let report = await SystemHelperInspector().report()
        XCTAssertEqual(report.state, "not_installed")
        XCTAssertFalse(report.responding)
        XCTAssertTrue(VaultExpiry.systemSources.isEmpty, "nothing is decrypted on Linux yet")
        XCTAssertEqual(RoutingTable.ipv4Routes(), [])
        #endif
    }

    func testUnavailableAuthenticator() async {
        let auth = UnavailableAuthenticator()
        XCTAssertFalse(auth.isAvailable)
        XCTAssertThrowsError(try auth.createKey()) { XCTAssertEqual($0 as? PTError, .protectionUnavailable) }
        do {
            _ = try await auth.unlock(keyData: Data(), reason: "test")
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(error as? PTError, .protectionUnavailable, "never ProtectionKeyUnusable (that removes items)")
            XCTAssertEqual(AutomationErrorCode.of(error), .authUnavailable)
        }
        #if os(Linux)
        XCTAssertFalse(PlatformAuthenticator().isAvailable)
        #endif
    }

    /// Linux cannot ask for a confirmation: a secret the setting protects is refused, never used
    /// without it. On the Mac nothing changes here.
    @MainActor func testProtectedProfilesWithoutAConfirmation() throws {
        let vault = SecretVault(authenticator: UnavailableAuthenticator(), reuseWindow: { 60 },
                                destination: { _ in ProfileDestination(fingerprint: "f", host: "") })
        var p = Profile(id: "acme", name: "Acme", type: .openvpn)
        p.passwordMode = .keychain
        p.otpMode = .totp
        p.requireAuth = .connect
        XCTAssertNoThrow(try vault.refuseUnconfirmable(p, [.totp]), "connect protects the password only")
        #if os(Linux)
        XCTAssertThrowsError(try vault.refuseUnconfirmable(p, [.password, .totp])) {
            XCTAssertEqual($0 as? PTError, .protectionUnavailable)
        }
        #else
        XCTAssertNoThrow(try vault.refuseUnconfirmable(p, [.password, .totp]))
        #endif
        p.requireAuth = .off
        XCTAssertNoThrow(try vault.refuseUnconfirmable(p, [.password, .totp]))
    }
}

// MARK: - The CLI on Linux

final class CLIPlatformTests: XCTestCase {
    func testEnglishDurations() {
        XCTAssertEqual(CLIDurations.english(0), "0s")
        XCTAssertEqual(CLIDurations.english(59.9), "59s")
        XCTAssertEqual(CLIDurations.english(60), "1m")
        XCTAssertEqual(CLIDurations.english(3600), "1h")
        XCTAssertEqual(CLIDurations.english(4320), "1h 12m")
        XCTAssertEqual(CLIDurations.english(86_400), "1d")
        XCTAssertEqual(CLIDurations.english(2 * 86_400 + 3 * 3600 + 59), "2d 3h")
    }

    func testClipboardTool() {
        let tools: Set = ["/usr/bin/wl-copy", "/usr/bin/xclip"]
        let exists: (String) -> Bool = { tools.contains($0) }
        let path = "relative:/usr/local/bin:/usr/bin"
        XCTAssertEqual(CLIClipboard.tool(environment: ["PATH": path, "WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"],
                                         isExecutable: exists),
                       CLIClipboard.Tool(path: "/usr/bin/wl-copy", arguments: ["--foreground"]))
        XCTAssertEqual(CLIClipboard.tool(environment: ["PATH": path, "DISPLAY": ":0"], isExecutable: exists),
                       CLIClipboard.Tool(path: "/usr/bin/xclip", arguments: ["-quiet", "-selection", "clipboard"]))
        XCTAssertNil(CLIClipboard.tool(environment: ["PATH": path], isExecutable: exists), "no display")
        XCTAssertNil(CLIClipboard.tool(environment: ["PATH": "relative", "DISPLAY": ":0"], isExecutable: { _ in true }),
                     "only absolute PATH entries")
        XCTAssertNil(CLIClipboard.tool(environment: ["DISPLAY": ":0", "WAYLAND_DISPLAY": "w"], isExecutable: exists))
    }

    /// The code reaches the tool on standard input; a tool still serving the clipboard at the end is
    /// stopped (which empties the clipboard), one that has exited is left alone.
    func testServingStopsOnlyAToolThatStillOwnsTheClipboard() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pt-clip-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let got = dir.appendingPathComponent("got").path
        let owner = CLIClipboard.Tool(path: "/bin/sh", arguments: ["-c", "cat > '\(got)'; exec sleep 30"])
        var start = Date()
        XCTAssertEqual(CLIClipboard.serve(Data("123456".utf8), with: owner, lifetime: 0.5), 0)
        XCTAssertLessThan(Date().timeIntervalSince(start), 10, "stopped at the end of its lifetime")
        XCTAssertEqual(try String(contentsOfFile: got, encoding: .utf8), "123456")

        let replaced = CLIClipboard.Tool(path: "/bin/sh", arguments: ["-c", "cat > /dev/null"])
        start = Date()
        XCTAssertEqual(CLIClipboard.serve(Data("123456".utf8), with: replaced, lifetime: 30), 0)
        XCTAssertLessThan(Date().timeIntervalSince(start), 10, "returns as soon as the tool exits")
    }

    #if os(Linux)
    /// `helper install|uninstall` belong to the package on Linux.
    @MainActor func testHelperInstallIsThePackages() async {
        let runner = CLIRunner()
        let install = await runner.run(.helper(.install))
        XCTAssertEqual(install, AutomationExit.usage)
        let uninstall = await runner.run(.helper(.uninstall))
        XCTAssertEqual(uninstall, AutomationExit.usage)
    }
    #endif
}
