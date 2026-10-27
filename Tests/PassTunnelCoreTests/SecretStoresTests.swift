import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(Glibc)
import Glibc
#endif

// The Linux secret stores (docs/LINUX.md, Secrets). They build everywhere, so these run on the Mac
// too: the system tools are fakes (`FakeTools`), the file store is real, in a temp directory.

/// Records every call and answers like the real tools would: `secret-tool` over an in-memory keyring,
/// `systemd-creds` sealing the input together with its credential name.
final class FakeTools: ToolRunning {
    struct Call: Equatable {
        var path: String
        var arguments: [String]
        var environment: [String: String]
        var input: Data
        var timeout: TimeInterval
    }

    var calls: [Call] = []
    /// service → account → value
    var keyring: [String: [String: Data]] = [:]
    var systemdVersion = "systemd 257 (257.4-1)"
    /// Replaces the answer to a call (failures, timeouts).
    var override: ((Call) throws -> ToolOutput?)?
    private let lock = NSLock()

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data,
        timeout: TimeInterval
    ) throws -> ToolOutput {
        lock.lock()
        defer { lock.unlock() }
        let call = Call(path: path, arguments: arguments, environment: environment, input: input, timeout: timeout)
        calls.append(call)
        if let answer = try override?(call) { return answer }
        if path.hasSuffix("/secret-tool") { return secretTool(arguments, input) }
        if path.hasSuffix("/systemd-creds") { return systemdCreds(arguments, input) }
        return ToolOutput(status: 127, output: Data(), errorOutput: Data("unknown tool\n".utf8))
    }

    static func ok(_ output: Data = Data()) -> ToolOutput { ToolOutput(status: 0, output: output, errorOutput: Data()) }
    static func failed(_ status: Int32, _ message: String = "") -> ToolOutput {
        ToolOutput(status: status, output: Data(), errorOutput: Data(message.utf8))
    }

    private func attributes(_ words: ArraySlice<String>) -> [String: String] {
        var result: [String: String] = [:]
        var i = words.startIndex
        while i + 1 < words.endIndex {
            result[words[i]] = words[i + 1]
            i += 2
        }
        return result
    }

    private func secretTool(_ arguments: [String], _ input: Data) -> ToolOutput {
        guard let verb = arguments.first else { return Self.failed(2, "usage") }
        let words = arguments.dropFirst().filter { !$0.hasPrefix("--") }
        let attrs = attributes(words[...])
        guard let service = attrs["service"] else { return Self.failed(2, "usage") }
        switch verb {
        case "lookup":
            guard let value = keyring[service]?[attrs["account"] ?? ""] else { return Self.failed(1) }
            return Self.ok(value)
        case "store":
            guard arguments.contains(where: { $0.hasPrefix("--label=") }), let account = attrs["account"] else {
                return Self.failed(2, "secret-tool: must specify a label for the new item")
            }
            keyring[service, default: [:]][account] = input
            return Self.ok()
        case "clear":
            if let account = attrs["account"] {
                return keyring[service]?.removeValue(forKey: account) == nil ? Self.failed(1) : Self.ok()
            }
            let had = !(keyring[service] ?? [:]).isEmpty
            keyring[service] = nil
            return had ? Self.ok() : Self.failed(1)
        default:
            return Self.failed(2, "usage")
        }
    }

    private func systemdCreds(_ arguments: [String], _ input: Data) -> ToolOutput {
        if arguments == ["--version"] { return Self.ok(Data((systemdVersion + "\n+PAM +AUDIT\n").utf8)) }
        guard let name = arguments.first(where: { $0.hasPrefix("--name=") })?.dropFirst("--name=".count),
            arguments.suffix(2) == ["-", "-"]
        else { return Self.failed(1, "Failed to parse arguments") }
        switch arguments.first {
        case "encrypt":
            return Self.ok(Data(("SEALED " + name + " " + input.base64EncodedString() + "\n").utf8))
        case "decrypt":
            let parts = String(decoding: input, as: UTF8.self).split(separator: " ")
            guard parts.count == 3, parts[0] == "SEALED" else { return Self.failed(1, "Failed to decrypt") }
            guard parts[1] == name else {
                return Self.failed(1, "Embedded credential name '\(parts[1])' does not match filename '\(name)', refusing.")
            }
            return Self.ok(Data(base64Encoded: String(parts[2].trimmingCharacters(in: .newlines))) ?? Data())
        default:
            return Self.failed(1, "Unknown verb")
        }
    }
}

/// A temp support directory and a `SecretStoreSystem` with fakes for everything it takes from the system.
class SecretStoreTestCase: XCTestCase {
    var root: URL!
    var tools: FakeTools!
    /// Executables that exist.
    var executables: Set<String> = ["/usr/bin/secret-tool", "/usr/bin/systemd-creds"]
    var sockets: Set<String> = []
    var kdfCalls = 0

    override func setUpWithError() throws {
        try super.setUpWithError()
        var template = Array((FileManager.default.temporaryDirectory.path + "/pt-secrets-XXXXXX").utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        root = URL(fileURLWithPath: String(cString: made), isDirectory: true)
        tools = FakeTools()
        FileSecretStore.keys.forget()
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
        FileSecretStore.keys.forget()
        try super.tearDownWithError()
    }

    static let testParameters = ScryptParameters(logN: 4, r: 1, p: 1)

    /// The real scrypt on Linux; elsewhere a stand-in (SHA-256 of passphrase, salt and parameters).
    func deriveKey() -> FileSecretStore.DeriveKey {
        { [unowned self] passphrase, salt, parameters in
            self.kdfCalls += 1
            #if os(Linux)
            return try FileSecretStore.scrypt(passphrase, salt, parameters)
            #else
            var data = passphrase
            data.append(salt)
            data.append(contentsOf: [parameters.logN, parameters.r, parameters.p])
            return SymmetricKey(data: SHA256.hash(data: data))
            #endif
        }
    }

    func system(
        environment: [String: String]? = nil, isRoot: Bool = false,
        interaction: SecretStoreInteraction = .none
    ) -> SecretStoreSystem {
        SecretStoreSystem(
            service: "PassTunnelTests", paths: AppPaths(root: root),
            environment: environment ?? [
                "HOME": "/home/alice", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
                "PASSTUNNEL_HOME": root.path
            ],
            isRoot: isRoot, runner: tools, interaction: interaction,
            isExecutable: { [unowned self] in self.executables.contains($0) },
            isSocket: { [unowned self] in self.sockets.contains($0) },
            deriveKey: deriveKey(), scryptParameters: Self.testParameters)
    }

    func mode(_ path: String) -> Int {
        var st = stat()
        return stat(path, &st) == 0 ? Int(st.st_mode & 0o777) : -1
    }

    /// Values a store must give back byte for byte.
    static let awkwardValues: [String] = [
        "pw", "trailing space ", " leading", "trailing newline\n", "two\n\n", "crlf\r\n", "tab\tinside",
        "Şifre-ğüış-ÇÖ 🔐", "", "ptpl1:ptse1:x", "ptse1:" + String(repeating: "QUJD", count: 300), "nul\u{0}inside"
    ]
}

// MARK: - Choosing a store

final class SecretStoreSelectionTests: SecretStoreTestCase {
    func select(
        env: String? = nil, setting: SecretStoreChoice = .auto, recorded: SecretStoreChoice? = nil,
        detected: SecretStoreChoice = .file
    ) throws -> SecretStoreSelection {
        try SecretStoreSelection.resolve(environment: env, setting: setting, recorded: recorded) { detected }
    }

    func testOrder() throws {
        XCTAssertEqual(
            try select(env: "systemd-creds", setting: .file, recorded: .secretService),
            SecretStoreSelection(store: .systemdCreds, source: .environment))
        XCTAssertEqual(
            try select(env: "auto", setting: .file, recorded: .secretService),
            SecretStoreSelection(store: .file, source: .setting), "auto in the environment defers")
        XCTAssertEqual(
            try select(setting: .systemdCreds, recorded: .secretService),
            SecretStoreSelection(store: .systemdCreds, source: .setting))
        XCTAssertEqual(
            try select(recorded: .secretService, detected: .file),
            SecretStoreSelection(store: .secretService, source: .recorded), "found again over SSH")
        XCTAssertEqual(try select(detected: .systemdCreds), SecretStoreSelection(store: .systemdCreds, source: .auto))
    }

    func testUnknownEnvironmentValueIsRefused() {
        for value in ["keychain", "Memory2", "secretservice"] {
            XCTAssertThrowsError(try select(env: value)) {
                XCTAssertEqual(($0 as? SecretStoreUnavailable)?.message, SecretStoreUnavailable.unknownStore(value).message)
            }
        }
    }

    func testDetection() {
        func detect(root: Bool, _ available: Set<SecretStoreChoice>) -> SecretStoreChoice {
            SecretStoreSelection.detect(isRoot: root) { available.contains($0) }
        }
        XCTAssertEqual(detect(root: false, [.secretService, .systemdCreds, .file]), .secretService)
        XCTAssertEqual(detect(root: false, [.systemdCreds, .file]), .systemdCreds)
        XCTAssertEqual(detect(root: false, []), .file, "the fallback, even without a passphrase yet")
        XCTAssertEqual(detect(root: true, [.secretService, .systemdCreds]), .systemdCreds, "root never uses a keyring")
        XCTAssertEqual(detect(root: true, [.secretService]), .file)
    }

    /// Detection asks the real conditions: a session bus and an answering secret-tool; systemd 256+
    /// for `--user`.
    func testDetectionAsksTheTools() {
        let desktop = system()
        XCTAssertEqual(SecretStores.chosen(system: desktop).name, "secret-service")
        var ssh = system(environment: ["HOME": "/home/alice", "PASSTUNNEL_HOME": root.path])
        XCTAssertEqual(SecretStores.chosen(system: ssh).name, "systemd-creds")
        tools.systemdVersion = "systemd 255 (255.4-1ubuntu8)"
        XCTAssertEqual(SecretStores.chosen(system: ssh).name, "file", "no --user before systemd 256")
        ssh.isRoot = true
        XCTAssertEqual(SecretStores.chosen(system: ssh).name, "systemd-creds", "root uses the host key")
        executables = []
        XCTAssertEqual(SecretStores.chosen(system: system()).name, "file")
    }

    /// The first successful write records the store; later runs use it even where another would be
    /// detected, and a later write does not change it.
    func testTheStoreUsedIsRecorded() throws {
        let desktop = system()
        let chosen = SecretStores.chosen(system: desktop)
        XCTAssertEqual(chosen.name, "secret-service")
        XCTAssertNil(Preferences.load(paths: desktop.paths).secretStoreUsed)
        try chosen.remove("acme/password")
        XCTAssertNil(Preferences.load(paths: desktop.paths).secretStoreUsed, "only a write records")
        try chosen.write("acme/password", Data("pw".utf8))
        XCTAssertEqual(Preferences.load(paths: desktop.paths).secretStoreUsed, .secretService)

        let ssh = system(environment: ["HOME": "/home/alice", "PASSTUNNEL_HOME": root.path])
        let later = SecretStores.chosen(system: ssh)
        XCTAssertEqual(later.name, "secret-service")
        XCTAssertEqual(try later.selection.get().source, .recorded)
        XCTAssertThrowsError(try later.read("acme/password")) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .secretServiceNoBus, "says where the secret is, not “missing”")
        }

        var env = ssh.environment
        env["PASSTUNNEL_SECRET_STORE"] = "systemd-creds"
        try SecretStores.chosen(system: system(environment: env)).write("acme/totp", Data("JBSWY3DP".utf8))
        XCTAssertEqual(Preferences.load(paths: desktop.paths).secretStoreUsed, .secretService, "recorded once")
    }

    func testChoosingAStoreByName() throws {
        let paths = AppPaths(root: root)
        try SecretStores.choose(.file, paths: paths)
        var prefs = Preferences.load(paths: paths)
        XCTAssertEqual(prefs.secretStore, .file)
        XCTAssertEqual(prefs.secretStoreUsed, .file)
        XCTAssertEqual(try SecretStores.chosen(system: system()).selection.get(), SecretStoreSelection(store: .file, source: .setting))
        try SecretStores.choose(.auto, paths: paths)
        prefs = Preferences.load(paths: paths)
        XCTAssertEqual(prefs.secretStore, .auto)
        XCTAssertEqual(prefs.secretStoreUsed, .file, "auto keeps the store chosen before")
        XCTAssertEqual(try SecretStores.chosen(system: system()).selection.get(), SecretStoreSelection(store: .file, source: .recorded))
    }

    func testReport() throws {
        var report = SecretStores.report(system: system())
        XCTAssertEqual(report, SecretStoreReport(name: "secret-service", available: true, setting: "auto", chosenBy: "auto"))
        var env = system().environment
        env["PASSTUNNEL_SECRET_STORE"] = "file"
        report = SecretStores.report(system: system(environment: env))
        XCTAssertEqual(
            report,
            SecretStoreReport(
                name: "file", available: false, setting: "auto", chosenBy: "environment",
                error: SecretStoreUnavailable.noPassphrase.message))
        env["PASSTUNNEL_SECRET_STORE"] = "vault"
        report = SecretStores.report(system: system(environment: env))
        XCTAssertEqual(report.name, "vault")
        XCTAssertFalse(report.available)
        XCTAssertEqual(report.error, SecretStoreUnavailable.unknownStore("vault").message)
        let json = String(decoding: try AutomationJSON.encoder().encode(report), as: UTF8.self)
        XCTAssertTrue(json.contains("\"chosen_by\" : \"environment\""), json)
    }

    /// The Mac never sets these: its config.json stays as it was. Unknown values fall back.
    func testPreferences() throws {
        let plain = String(decoding: try JSONCoding.encode(Preferences()), as: UTF8.self)
        XCTAssertFalse(plain.contains("secret_store"), plain)
        var prefs = Preferences()
        prefs.secretStore = .systemdCreds
        prefs.secretStoreUsed = .file
        let data = try JSONCoding.encode(prefs)
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("\"secret_store_used\" : \"file\""))
        XCTAssertEqual(try JSONCoding.decode(Preferences.self, from: data), prefs)
        let odd = try JSONCoding.decode(Preferences.self, from: Data(#"{"secret_store":"vault","secret_store_used":"auto"}"#.utf8))
        XCTAssertEqual(odd.secretStore, .auto)
        XCTAssertNil(odd.secretStoreUsed)
    }
}

// MARK: - secret-service

final class SecretServiceStoreTests: SecretStoreTestCase {
    var store: SecretServiceStore { SecretServiceStore(service: "PassTunnelTests", system: system()) }

    func testRoundTripsEveryValueExactly() throws {
        for (i, value) in Self.awkwardValues.enumerated() {
            try store.write("p\(i)/password", Data(value.utf8))
        }
        for (i, value) in Self.awkwardValues.enumerated() {
            XCTAssertEqual(try store.read("p\(i)/password"), Data(value.utf8), value.debugDescription)
        }
        XCTAssertEqual(tools.keyring["PassTunnelTests"]?["p0/password"], Data("pw".utf8), "stored as is, not encoded")
    }

    /// Values only on standard input and output; fixed tool path; nothing but the bus, the runtime
    /// directory, HOME and LANG=C in the environment.
    func testValuesNeverInArgumentsOrEnvironment() throws {
        var env = system().environment
        env["PATH"] = "/tmp/evil:/usr/bin"
        env["DISPLAY"] = ":0"
        env["XDG_RUNTIME_DIR"] = "/run/user/1000"
        env["PASSTUNNEL_PASSPHRASE_FILE"] = "/home/alice/pp"
        let store = SecretServiceStore(service: "PassTunnelTests", system: system(environment: env))
        try store.write("acme/password", Data("hunter2".utf8))
        _ = try store.read("acme/password")
        try store.remove("acme/password")
        XCTAssertEqual(
            tools.calls.map(\.arguments),
            [
                ["store", "--label=PassTunnel (acme/password)", "service", "PassTunnelTests", "account", "acme/password"],
                ["lookup", "service", "PassTunnelTests", "account", "acme/password"],
                ["clear", "service", "PassTunnelTests", "account", "acme/password"]
            ])
        for call in tools.calls {
            XCTAssertEqual(call.path, "/usr/bin/secret-tool")
            XCTAssertEqual(
                call.environment,
                [
                    "LANG": "C", "HOME": "/home/alice", "XDG_RUNTIME_DIR": "/run/user/1000",
                    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"
                ])
            XCTAssertFalse(call.arguments.joined().contains("hunter2"))
        }
        XCTAssertEqual(tools.calls[0].input, Data("hunter2".utf8))
        XCTAssertEqual(tools.calls[1].input, Data())
    }

    func testSessionBus() {
        let found: (String) -> Bool = { $0 == "/run/user/1000/bus" }
        XCTAssertEqual(
            SecretServiceStore.toolEnvironment(["XDG_RUNTIME_DIR": "/run/user/1000"], isSocket: found),
            ["LANG": "C", "XDG_RUNTIME_DIR": "/run/user/1000", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"])
        XCTAssertNil(SecretServiceStore.toolEnvironment(["XDG_RUNTIME_DIR": "/run/user/1000", "HOME": "/root"], isSocket: { _ in false }))
        XCTAssertNil(SecretServiceStore.toolEnvironment(["DBUS_SESSION_BUS_ADDRESS": ""], isSocket: found))
        XCTAssertEqual(SecretServiceStore.busAddressEscaped("/run/user/1000/bus"), "/run/user/1000/bus")
        XCTAssertEqual(SecretServiceStore.busAddressEscaped("/tmp/a b;c=d"), "/tmp/a%20b%3Bc%3Dd")

        let noBus = SecretServiceStore(service: "s", system: system(environment: ["HOME": "/home/alice"]))
        XCTAssertThrowsError(try noBus.read("acme/password")) { XCTAssertEqual($0 as? SecretStoreUnavailable, .secretServiceNoBus) }
        XCTAssertEqual(noBus.unavailability(), .secretServiceNoBus)
        XCTAssertTrue(tools.calls.isEmpty, "nothing is run without a bus")
    }

    func testToolIsFoundAtFixedPathsOnly() {
        executables = ["/usr/local/bin/secret-tool"]
        XCTAssertNil(store.unavailability())
        XCTAssertEqual(tools.calls.last?.path, "/usr/local/bin/secret-tool")
        executables = ["/home/alice/bin/secret-tool", "/opt/bin/secret-tool"]
        XCTAssertEqual(store.unavailability(), .secretServiceToolMissing)
    }

    func testMissingErrorsAndRemoval() throws {
        XCTAssertNil(try store.read("acme/password"), "lookup exits 1 without a message: not found")
        XCTAssertNoThrow(try store.remove("acme/password"), "clear exits 1 without a message: nothing to remove")
        tools.override = { _ in FakeTools.failed(1, "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY\n") }
        XCTAssertThrowsError(try store.read("acme/password")) {
            XCTAssertEqual(
                ($0 as? SecretStoreUnavailable)?.message,
                SecretStoreUnavailable.secretServiceFailed("Cannot autolaunch D-Bus without X11 $DISPLAY").message)
        }
        XCTAssertThrowsError(try store.remove("acme/password"))
        XCTAssertThrowsError(try store.write("acme/password", Data("pw".utf8)))
        XCTAssertNotNil(store.unavailability(), "a probe that errs: not available")
        tools.override = { _ in FakeTools.failed(1) }
        XCTAssertThrowsError(try store.write("acme/password", Data("pw".utf8))) {
            XCTAssertEqual(($0 as? SecretStoreUnavailable)?.message, SecretStoreUnavailable.secretServiceFailed("exit status 1").message)
        }
    }

    /// A locked keyring waits for its password: long enough on a terminal, briefly otherwise, never
    /// forever; the probe never waits long.
    func testTimeouts() {
        tools.override = { call in throw ToolTimeout(seconds: Int(call.timeout)) }
        XCTAssertThrowsError(try store.read("acme/password")) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .secretServiceTimeout(15))
        }
        let terminal = SecretServiceStore(service: "s", system: system(interaction: SecretStoreInteraction(interactive: true, askPassphrase: nil)))
        XCTAssertThrowsError(try terminal.write("acme/password", Data("pw".utf8))) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .secretServiceTimeout(120))
        }
        XCTAssertEqual(store.unavailability(), .secretServiceTimeout(5))
        XCTAssertEqual(tools.calls.map(\.timeout), [15, 120, 5])
    }

    func testValuesItCannotCarry() {
        XCTAssertThrowsError(try store.write("acme/password", Data(repeating: 0x41, count: 8192))) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .secretServiceValueTooLong)
        }
        XCTAssertNoThrow(try store.write("acme/password", Data(repeating: 0x41, count: 8191)))
        XCTAssertThrowsError(try store.write("acme/password", Data([0xFF, 0xFE]))) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .secretServiceTextOnly)
        }
        XCTAssertEqual(tools.calls.count, 1, "refused before running anything")
    }

    func testRemoveAllClearsTheService() throws {
        try store.write("a/password", Data("1".utf8))
        try store.write("b/totp", Data("2".utf8))
        store.removeAll()
        XCTAssertEqual(tools.calls.last?.arguments, ["clear", "service", "PassTunnelTests"])
        XCTAssertNil(try store.read("a/password"))
    }
}

// MARK: - systemd-creds

final class SystemdCredsStoreTests: SecretStoreTestCase {
    func store(root isRoot: Bool = false) -> SystemdCredsStore { SystemdCredsStore(system: system(isRoot: isRoot)) }

    func testCredentialNames() {
        XCTAssertEqual(SystemdCredsStore.credentialName("acme/password"), "acme%2Fpassword")
        XCTAssertEqual(SystemdCredsStore.credentialName("acme-2/sekey"), "acme-2%2Fsekey")
        XCTAssertEqual(SystemdCredsStore.credentialName("../x:y Z"), "%2E%2E%2Fx%3Ay%20%5A")
        XCTAssertEqual(SystemdCredsStore.credentialName(""), "%")
        XCTAssertEqual(SystemdCredsStore.credentialName("ş"), "%C5%9F")
        XCTAssertNotEqual(SystemdCredsStore.credentialName("a%2Fb"), SystemdCredsStore.credentialName("a/b"))
    }

    func testVersions() {
        XCTAssertEqual(SystemdCredsStore.parseVersion(Data("systemd 257 (257.4-1)\n+PAM".utf8)), 257)
        XCTAssertEqual(SystemdCredsStore.parseVersion(Data("systemd 255 (255.4-1ubuntu8.4)".utf8)), 255)
        XCTAssertEqual(SystemdCredsStore.parseVersion(Data("systemd 256~rc3".utf8)), 256)
        XCTAssertNil(SystemdCredsStore.parseVersion(Data("something else".utf8)))
    }

    func testRoundTripsEveryValueExactly() throws {
        for (i, value) in Self.awkwardValues.enumerated() {
            try store().write("p\(i)/password", Data(value.utf8))
            XCTAssertEqual(try store().read("p\(i)/password"), Data(value.utf8), value.debugDescription)
        }
    }

    /// `--name` binds the content to its account; `--user` for a user, the system's key for root;
    /// values on standard input and output only.
    func testArgumentsAndFiles() throws {
        try store().write("acme/password", Data("hunter2".utf8))
        let dir = root.appendingPathComponent("secrets").path
        let file = dir + "/acme%2Fpassword.cred"
        XCTAssertEqual(mode(dir), 0o700)
        XCTAssertEqual(mode(file), 0o600)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir), ["acme%2Fpassword.cred"], "no temp file left")
        XCTAssertEqual(try store().read("acme/password"), Data("hunter2".utf8))
        let uses = tools.calls.filter { $0.arguments != ["--version"] }
        XCTAssertEqual(
            uses.map(\.arguments),
            [
                ["encrypt", "--name=acme%2Fpassword", "--user", "-", "-"],
                ["decrypt", "--name=acme%2Fpassword", "--newline=no", "--user", "-", "-"]
            ])
        XCTAssertEqual(uses[0].input, Data("hunter2".utf8))
        XCTAssertEqual(uses[1].input, try Data(contentsOf: URL(fileURLWithPath: file)))
        for call in tools.calls {
            XCTAssertEqual(call.path, "/usr/bin/systemd-creds")
            XCTAssertFalse(call.arguments.joined().contains("hunter2"))
            XCTAssertNil(call.environment["DBUS_SESSION_BUS_ADDRESS"])
            XCTAssertEqual(call.environment["LANG"], "C")
        }

        tools.calls = []
        try store(root: true).write("acme/totp", Data("JBSWY3DP".utf8))
        XCTAssertEqual(tools.calls.map(\.arguments), [["encrypt", "--name=acme%2Ftotp", "-", "-"]], "root: no version check, no --user")
    }

    func testARenamedFileDoesNotDecrypt() throws {
        try store().write("acme/password", Data("pw".utf8))
        let dir = root.appendingPathComponent("secrets")
        try FileManager.default.moveItem(
            at: dir.appendingPathComponent("acme%2Fpassword.cred"),
            to: dir.appendingPathComponent("other%2Fpassword.cred"))
        XCTAssertNil(try store().read("acme/password"))
        XCTAssertThrowsError(try store().read("other/password")) {
            XCTAssertTrue(($0 as? SecretStoreUnavailable)?.message.contains("does not match") == true, "\($0)")
        }
    }

    func testOlderSystemdIsUnavailableForUsers() {
        tools.systemdVersion = "systemd 255 (255.4-1ubuntu8)"
        XCTAssertEqual(store().unavailability(), .systemdCredsTooOld(255))
        XCTAssertThrowsError(try store().write("acme/password", Data("pw".utf8))) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .systemdCredsTooOld(255))
        }
        XCTAssertNil(store(root: true).unavailability())
        executables = []
        XCTAssertEqual(store(root: true).unavailability(), .systemdCredsToolMissing)
    }

    func testFailuresAndTimeouts() throws {
        try store().write("acme/password", Data("pw".utf8))
        tools.override = { call in call.arguments.first == "decrypt" ? FakeTools.failed(1, "Failed to decrypt credential: Bad message\n") : nil }
        XCTAssertThrowsError(try store().read("acme/password")) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .systemdCredsFailed("Failed to decrypt credential: Bad message"))
        }
        tools.override = { call in
            if call.arguments.first == "encrypt" { throw ToolTimeout(seconds: Int(call.timeout)) }
            return nil
        }
        XCTAssertThrowsError(try store().write("acme/totp", Data("x".utf8))) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .systemdCredsTimeout(30))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: store().url("acme/totp").path), "nothing written on failure")
    }

    func testRemove() throws {
        XCTAssertNoThrow(try store().remove("acme/password"), "nothing to remove")
        try store().write("acme/password", Data("pw".utf8))
        try store().remove("acme/password")
        XCTAssertNil(try store().read("acme/password"))
        try store().write("a/password", Data("1".utf8))
        store().removeAll()
        XCTAssertNil(try store().read("a/password"))
    }

    func testAnOpenDirectoryIsMadePrivate() throws {
        let dir = root.appendingPathComponent("secrets")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        try store().write("acme/password", Data("pw".utf8))
        XCTAssertEqual(mode(dir.path), 0o700, "made private again")
    }
}

// MARK: - file

final class FileSecretStoreTests: SecretStoreTestCase {
    var passphraseFile: URL { root.appendingPathComponent("passphrase") }

    func setPassphrase(_ text: String, mode: mode_t = 0o600) throws {
        try Data(text.utf8).write(to: passphraseFile)
        chmod(passphraseFile.path, mode)
    }

    func store(environment extra: [String: String] = [:], interaction: SecretStoreInteraction = .none) -> FileSecretStore {
        var env = ["PASSTUNNEL_HOME": root.path, "PASSTUNNEL_PASSPHRASE_FILE": passphraseFile.path]
        env.merge(extra) { $1 }
        return FileSecretStore(system: system(environment: env.filter { !$0.value.isEmpty }, interaction: interaction))
    }

    var fileURL: URL { root.appendingPathComponent("secrets.enc") }
    func fileBytes() throws -> Data { try Data(contentsOf: fileURL) }

    func testRoundTripsEveryValueExactly() throws {
        try setPassphrase("correct horse")
        for (i, value) in Self.awkwardValues.enumerated() { try store().write("p\(i)/password", Data(value.utf8)) }
        FileSecretStore.keys.forget()  // as a new process
        for (i, value) in Self.awkwardValues.enumerated() {
            XCTAssertEqual(try store().read("p\(i)/password"), Data(value.utf8), value.debugDescription)
        }
        XCTAssertNil(try store().read("nope/password"))
        XCTAssertEqual(kdfCalls, 2, "one key per process")
    }

    func testFormatAndPermissions() throws {
        try setPassphrase("correct horse")
        try store().write("acme/password", Data("hunter2".utf8))
        let first = try fileBytes()
        XCTAssertEqual(mode(fileURL.path), 0o600)
        XCTAssertEqual(first.prefix(4), Data("PTSF".utf8))
        XCTAssertEqual(Array(first[4..<9]), [1, 1, 4, 1, 1], "version, scrypt, log2 N, r, p")
        XCTAssertEqual(
            first.count, SecretsFile.headerSize + SecretsFile.tagSize + (try JSONEncoder().encode(["acme/password": Data("hunter2".utf8)])).count)
        XCTAssertNil(first.range(of: Data("hunter2".utf8)))
        XCTAssertNil(first.range(of: Data("acme".utf8)), "account names are encrypted too")

        try store().write("acme/totp", Data("JBSWY3DP".utf8))
        let second = try fileBytes()
        XCTAssertEqual(second.prefix(41), first.prefix(41), "same salt and parameters")
        XCTAssertNotEqual(second[41..<53], first[41..<53], "a new nonce on every write")
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: root.path).filter { $0.hasSuffix(".tmp") }
        XCTAssertEqual(leftovers, [], "written atomically")
        XCTAssertEqual(ScryptParameters.standard, ScryptParameters(logN: 17, r: 8, p: 1))
        XCTAssertEqual(ScryptParameters.standard.memory, 128 << 20)
    }

    func testWrongPassphrase() throws {
        try setPassphrase("correct horse")
        try store().write("acme/password", Data("pw".utf8))
        FileSecretStore.keys.forget()
        try setPassphrase("battery staple")
        XCTAssertThrowsError(try store().read("acme/password")) { XCTAssertEqual($0 as? SecretStoreUnavailable, .secretsFileUnreadable) }
        XCTAssertThrowsError(try store().write("acme/totp", Data("x".utf8))) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .secretsFileUnreadable, "never overwritten with another key")
        }
        XCTAssertEqual(kdfCalls, 2, "a failed passphrase is not tried again in the same process")
        FileSecretStore.keys.forget()
        try setPassphrase("correct horse\n")
        XCTAssertEqual(try store().read("acme/password"), Data("pw".utf8), "the file's final line break is not part of it")
    }

    func testTampering() throws {
        try setPassphrase("correct horse")
        try store().write("acme/password", Data("pw".utf8))
        let good = try fileBytes()
        for index in [10, 6, 45, SecretsFile.headerSize + 1, good.count - 1] {  // salt, log2 N, nonce, ciphertext, tag
            var bad = good
            bad[index] ^= 0x01
            try bad.write(to: fileURL)
            FileSecretStore.keys.forget()
            XCTAssertThrowsError(try store().read("acme/password"), "byte \(index)") {
                XCTAssertEqual($0 as? SecretStoreUnavailable, .secretsFileUnreadable, "byte \(index)")
            }
        }
        try good.write(to: fileURL)
        XCTAssertThrowsError(try store().read("acme/password"), "the failure is remembered for this process")
        FileSecretStore.keys.forget()
        XCTAssertEqual(try store().read("acme/password"), Data("pw".utf8))
        var tampered = good
        tampered[good.count - 1] ^= 0x01
        try tampered.write(to: fileURL)
        XCTAssertThrowsError(try store().read("acme/password"), "with the key already known") {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .secretsFileUnreadable)
        }
    }

    func testHeaderVersions() throws {
        try setPassphrase("correct horse")
        try store().write("acme/password", Data("pw".utf8))
        let good = try fileBytes()
        func with(_ index: Int, _ value: UInt8) throws {
            var bad = good
            bad[index] = value
            try bad.write(to: fileURL)
        }
        try with(4, 2)
        XCTAssertThrowsError(try store().read("acme/password")) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .newerSecretsFile(fileURL.path))
        }
        XCTAssertThrowsError(try store().write("acme/totp", Data("x".utf8)))
        XCTAssertEqual(try fileBytes()[4], 2, "a newer file is never overwritten")
        try with(4, 0)
        XCTAssertThrowsError(try store().read("acme/password")) { XCTAssertEqual($0 as? SecretStoreUnavailable, .notASecretsFile(fileURL.path)) }
        try with(5, 2)
        XCTAssertThrowsError(try store().read("acme/password")) { XCTAssertEqual($0 as? SecretStoreUnavailable, .notASecretsFile(fileURL.path)) }
        try with(6, 40)
        XCTAssertThrowsError(try store().read("acme/password"), "parameters beyond the limits are not run")
        try with(0, UInt8(ascii: "X"))
        XCTAssertThrowsError(try store().read("acme/password")) { XCTAssertEqual($0 as? SecretStoreUnavailable, .notASecretsFile(fileURL.path)) }
        try good.prefix(SecretsFile.headerSize + 5).write(to: fileURL)
        XCTAssertThrowsError(try store().read("acme/password")) { XCTAssertEqual($0 as? SecretStoreUnavailable, .notASecretsFile(fileURL.path)) }
        try Data().write(to: fileURL)
        XCTAssertThrowsError(try store().read("acme/password"))

        XCTAssertTrue(ScryptParameters(logN: 20, r: 8, p: 1).isAcceptable)
        XCTAssertFalse(ScryptParameters(logN: 21, r: 8, p: 1).isAcceptable)
        XCTAssertFalse(ScryptParameters(logN: 20, r: 8, p: 2).isAcceptable, "more than 1 GiB")
        XCTAssertFalse(ScryptParameters(logN: 0, r: 8, p: 1).isAcceptable)
    }

    func testPassphraseFileRules() throws {
        try setPassphrase("correct horse", mode: 0o640)
        XCTAssertThrowsError(try store().write("acme/password", Data("pw".utf8))) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .passphraseFile(passphraseFile.path))
        }
        XCTAssertNotNil(store().unavailability())
        try setPassphrase("correct horse", mode: 0o604)
        XCTAssertThrowsError(try store().write("acme/password", Data("pw".utf8)))
        try setPassphrase("\n\n")
        XCTAssertThrowsError(try store().write("acme/password", Data("pw".utf8))) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .noPassphraseEntered)
        }
        try setPassphrase(String(repeating: "x", count: FileSecretStore.maxPassphraseFileSize + 1))
        XCTAssertThrowsError(try store().write("acme/password", Data("pw".utf8)))
        XCTAssertThrowsError(
            try store(environment: ["PASSTUNNEL_PASSPHRASE_FILE": root.path]).write("acme/password", Data("pw".utf8)),
            "a directory")
        XCTAssertThrowsError(try store(environment: ["PASSTUNNEL_PASSPHRASE_FILE": root.path + "/missing"]).write("acme/password", Data("pw".utf8)))
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))
        try setPassphrase("correct horse")
        XCTAssertNil(store().unavailability())
        XCTAssertNoThrow(try store().write("acme/password", Data("pw".utf8)))
    }

    /// No terminal and no passphrase file: a clear error at once, never a wait. Reading with no file
    /// needs no passphrase.
    func testWithoutAPassphrase() throws {
        let unattended = store(environment: ["PASSTUNNEL_PASSPHRASE_FILE": ""])
        XCTAssertNil(try unattended.read("acme/password"))
        XCTAssertNoThrow(try unattended.remove("acme/password"))
        XCTAssertThrowsError(try unattended.write("acme/password", Data("pw".utf8))) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .noPassphrase)
        }
        XCTAssertEqual(unattended.unavailability(), .noPassphrase)
        try setPassphrase("correct horse")
        try store().write("acme/password", Data("pw".utf8))
        FileSecretStore.keys.forget()
        XCTAssertThrowsError(try unattended.read("acme/password")) { XCTAssertEqual($0 as? SecretStoreUnavailable, .noPassphrase) }
        XCTAssertThrowsError(try unattended.remove("acme/password")) { XCTAssertEqual($0 as? SecretStoreUnavailable, .noPassphrase) }
    }

    /// On a terminal: a new file asks twice; a wrong passphrase is asked again, three times at most.
    func testPrompts() throws {
        var answers: [String] = []
        var prompts: [String] = []
        let ask: (String) -> Data? = { prompt in
            prompts.append(prompt)
            return answers.isEmpty ? nil : Data(answers.removeFirst().utf8)
        }
        let terminal = store(
            environment: ["PASSTUNNEL_PASSPHRASE_FILE": ""],
            interaction: SecretStoreInteraction(interactive: true, askPassphrase: ask))
        XCTAssertNil(terminal.unavailability())

        answers = ["one", "two", "one", "uno", "a", "b"]
        XCTAssertThrowsError(try terminal.write("acme/password", Data("pw".utf8))) {
            XCTAssertEqual($0 as? SecretStoreUnavailable, .passphrasesDiffer)
        }
        XCTAssertEqual(prompts.count, 6)
        XCTAssertTrue(prompts[0].contains(fileURL.path), prompts[0])
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))

        answers = ["correct horse", "correct horse"]
        prompts = []
        try terminal.write("acme/password", Data("pw".utf8))
        try terminal.write("acme/totp", Data("JBSWY3DP".utf8))
        XCTAssertEqual(try terminal.read("acme/password"), Data("pw".utf8))
        XCTAssertEqual(prompts.count, 2, "asked twice for the new file, then never again in this process")

        FileSecretStore.keys.forget()
        answers = ["wrong", "correct horse"]
        prompts = []
        XCTAssertEqual(try terminal.read("acme/totp"), Data("JBSWY3DP".utf8))
        XCTAssertEqual(prompts.count, 2)
        XCTAssertNotEqual(prompts[0], prompts[1], "the second prompt says the first was wrong")

        FileSecretStore.keys.forget()
        answers = ["a", "b", "c", "correct horse"]
        XCTAssertThrowsError(try terminal.read("acme/totp")) { XCTAssertEqual($0 as? SecretStoreUnavailable, .secretsFileUnreadable) }
        XCTAssertEqual(answers, ["correct horse"], "three attempts")

        FileSecretStore.keys.forget()
        answers = []
        XCTAssertThrowsError(try terminal.read("acme/totp")) { XCTAssertEqual($0 as? SecretStoreUnavailable, .noPassphraseEntered) }
    }

    func testRemove() throws {
        try setPassphrase("correct horse")
        try store().write("acme/password", Data("pw".utf8))
        try store().write("acme/totp", Data("x".utf8))
        let before = try fileBytes()
        try store().remove("other/password")
        XCTAssertEqual(try fileBytes(), before, "nothing to remove: not rewritten")
        try store().remove("acme/password")
        XCTAssertNil(try store().read("acme/password"))
        XCTAssertEqual(try store().read("acme/totp"), Data("x".utf8))
        store(environment: ["PASSTUNNEL_HOME": ""]).removeAll()
        XCTAssertTrue(FileManager.default.fileExists(atPath: fileURL.path), "never outside a test's PASSTUNNEL_HOME")
        store().removeAll()
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))
    }

    /// Writers serialize on the lock: every item survives.
    func testConcurrentWriters() throws {
        try setPassphrase("correct horse")
        try store().write("seed/password", Data("0".utf8))
        let errors = NSMutableArray()
        DispatchQueue.concurrentPerform(iterations: 12) { i in
            do { try self.store().write("p\(i)/password", Data("\(i)".utf8)) } catch {
                errors.add(error)
            }
        }
        XCTAssertEqual(errors.count, 0, "\(errors)")
        for i in 0..<12 { XCTAssertEqual(try store().read("p\(i)/password"), Data("\(i)".utf8)) }
    }

    #if os(Linux)
    /// swift-crypto's scrypt is wired as RFC 7914 defines it (its second test vector).
    func testScryptVector() throws {
        let key = try FileSecretStore.scrypt(Data("password".utf8), Data("NaCl".utf8), ScryptParameters(logN: 10, r: 8, p: 16))
        let hex = key.withUnsafeBytes { Data($0) }.map { ($0 < 16 ? "0" : "") + String($0, radix: 16) }.joined()
        XCTAssertEqual(hex, "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162")
    }
    #endif
}

// MARK: - The tool runner

final class ToolRunnerTests: XCTestCase {
    let runner = SystemToolRunner()

    func testExactBytesInAndOut() throws {
        var input = Data("line\n\r\n trailing \u{0} Şğü 🔐".utf8)
        input.append(Data((0..<300_000).map { UInt8(truncatingIfNeeded: $0) }))
        let result = try runner.run("/bin/cat", [], environment: [:], input: input, timeout: 20)
        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(result.output, input, "more than the socket buffer, byte for byte")
        XCTAssertEqual(try runner.run("/bin/cat", [], environment: [:], input: Data(), timeout: 5).output, Data())
    }

    func testExactlyTheEnvironmentGiven() throws {
        let result = try runner.run("/usr/bin/env", [], environment: ["LANG": "C", "HOME": "/home/alice"], input: Data(), timeout: 5)
        let lines = Set(String(decoding: result.output, as: UTF8.self).split(separator: "\n").map(String.init))
        XCTAssertEqual(lines, ["LANG=C", "HOME=/home/alice"])
    }

    func testStatusAndErrorOutput() throws {
        let result = try runner.run(
            "/bin/sh", ["-c", "echo out; echo 'secret-tool: No such secret collection' >&2; exit 3"],
            environment: [:], input: Data(), timeout: 5)
        XCTAssertEqual(result.status, 3)
        XCTAssertEqual(result.output, Data("out\n".utf8))
        XCTAssertEqual(result.errorLine, "No such secret collection")
        XCTAssertEqual(try runner.run("/bin/sh", ["-c", "kill -9 $$"], environment: [:], input: Data(), timeout: 5).status, 128 + 9)
    }

    /// A tool that exits without reading its input does not end this process with SIGPIPE.
    func testToolThatIgnoresItsInput() throws {
        let result = try runner.run("/bin/sh", ["-c", "exit 0"], environment: [:], input: Data(count: 2 << 20), timeout: 10)
        XCTAssertEqual(result.status, 0)
    }

    func testTimeout() {
        let start = Date()
        XCTAssertThrowsError(try runner.run("/bin/sleep", ["30"], environment: [:], input: Data(), timeout: 0.5)) {
            XCTAssertEqual($0 as? ToolTimeout, ToolTimeout(seconds: 1))
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 5)
    }

    func testMissingTool() {
        XCTAssertThrowsError(try runner.run("/nonexistent/secret-tool", [], environment: [:], input: Data(), timeout: 5))
    }
}

// MARK: - A real Secret Service (opt-in)

/// Against a real Secret Service: only when `PASSTUNNEL_TEST_SECRET_SERVICE=1`, which only the CI step
/// that starts a throwaway session bus and keyring in its container sets (`dbus-run-session` with an
/// unlocked gnome-keyring). Never against a user's keyring: the items use a service of their own.
final class RealSecretServiceTests: XCTestCase {
    func testExactRoundTrips() throws {
        guard ProcessInfo.processInfo.environment["PASSTUNNEL_TEST_SECRET_SERVICE"] == "1" else {
            throw XCTSkip("set PASSTUNNEL_TEST_SECRET_SERVICE=1 inside a throwaway session bus to run")
        }
        var system = SecretStoreSystem.current(service: "PassTunnelTests-\(UUID().uuidString)")
        system.interaction = .none
        let store = SecretServiceStore(service: system.service, system: system)
        defer { store.removeAll() }
        XCTAssertNil(store.unavailability())
        for (i, value) in SecretStoreTestCase.awkwardValues.enumerated() {
            try store.write("p\(i)/password", Data(value.utf8))
            XCTAssertEqual(try store.read("p\(i)/password"), Data(value.utf8), value.debugDescription)
        }
        try store.write("p0/password", Data("replaced".utf8))
        XCTAssertEqual(try store.read("p0/password"), Data("replaced".utf8), "an existing item is replaced")
        try store.remove("p0/password")
        XCTAssertNil(try store.read("p0/password"))
        XCTAssertNoThrow(try store.remove("p0/password"))
        let long = Data(repeating: 0x61, count: SecretServiceStore.maxValueSize)
        try store.write("long/password", long)
        XCTAssertEqual(try store.read("long/password"), long)
    }
}
