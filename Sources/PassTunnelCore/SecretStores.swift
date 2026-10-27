import Foundation
import PassTunnelKit

#if canImport(Glibc)
import Glibc
#endif

// The secret stores of Linux (docs/LINUX.md, Secrets) and how one is chosen. Built everywhere, so the
// tests run on the Mac too; only Linux uses them (`Secrets.store`), the Mac keeps the Keychain.

/// A Linux secret store by name, or `auto` (the setting's default).
public enum SecretStoreChoice: String, CaseIterable, Codable, Sendable {
    case auto
    case secretService = "secret-service"
    case systemdCreds = "systemd-creds"
    case file

    /// The stores, without `auto`.
    public static let stores: [SecretStoreChoice] = [.secretService, .systemdCreds, .file]
}

/// How the store in use was chosen (`SecretStoreReport.chosenBy`).
public enum SecretStoreSource: String, Codable, Sendable {
    /// `PASSTUNNEL_SECRET_STORE`.
    case environment
    /// The setting `secret_store` (`passtunnel secret-store NAME`).
    case setting
    /// Where this user's secrets were first saved (`secret_store_used` in config.json).
    case recorded
    /// Detected, as nothing is set or recorded yet.
    case auto
}

/// What a process may ask of the user while it uses a store: set by the CLI on a terminal. The MCP
/// server and everything else run with `none`: no prompt, short waits.
public struct SecretStoreInteraction {
    /// Someone at a terminal waits for this command: a locked keyring gets time to be unlocked.
    public var interactive: Bool
    /// Shows the prompt and reads a line without echo (the passphrase of the file store); nil when
    /// nothing was read.
    public var askPassphrase: ((String) -> Data?)?

    public init(interactive: Bool, askPassphrase: ((String) -> Data?)?) {
        self.interactive = interactive
        self.askPassphrase = askPassphrase
    }

    public static let none = SecretStoreInteraction(interactive: false, askPassphrase: nil)
}

/// The store in use and how it was chosen: `secret_store` in `diagnose` (Linux) and the result of
/// `passtunnel secret-store` (docs/CLI-JSON.md).
public struct SecretStoreReport: Codable, Equatable {
    /// `secret-service`, `systemd-creds` or `file` (`memory` in debug builds' tests).
    public var name: String
    /// Whether it can be used from this process now.
    public var available: Bool
    /// The setting: `auto` or a store's name.
    public var setting: String
    /// `environment`, `setting`, `recorded` or `auto` (`SecretStoreSource`).
    public var chosenBy: String
    /// Why it is not available.
    public var error: String?
}

/// The store chosen from `PASSTUNNEL_SECRET_STORE`, then the setting, then the recorded store, then
/// what is available: for root systemd-creds, else the file; for other users secret-service, then
/// systemd-creds (`--user`), then the file.
struct SecretStoreSelection: Equatable {
    var store: SecretStoreChoice
    var source: SecretStoreSource

    static func resolve(
        environment: String?, setting: SecretStoreChoice, recorded: SecretStoreChoice?,
        detect: () -> SecretStoreChoice
    ) throws -> SecretStoreSelection {
        if let environment {
            guard let choice = SecretStoreChoice(rawValue: environment) else {
                throw SecretStoreUnavailable.unknownStore(environment)
            }
            if choice != .auto { return SecretStoreSelection(store: choice, source: .environment) }
        }
        if setting != .auto { return SecretStoreSelection(store: setting, source: .setting) }
        if let recorded, recorded != .auto { return SecretStoreSelection(store: recorded, source: .recorded) }
        return SecretStoreSelection(store: detect(), source: .auto)
    }

    static func detect(isRoot: Bool, isAvailable: (SecretStoreChoice) -> Bool) -> SecretStoreChoice {
        let candidates: [SecretStoreChoice] = isRoot ? [.systemdCreds] : [.secretService, .systemdCreds]
        return candidates.first(where: isAvailable) ?? .file
    }
}

/// What the stores take from the system, so tests can bring their own tools and environment.
struct SecretStoreSystem {
    var service: String
    var paths: AppPaths
    var environment: [String: String]
    var isRoot: Bool
    var runner: ToolRunning
    var interaction: SecretStoreInteraction
    var isExecutable: (String) -> Bool
    var isSocket: (String) -> Bool
    /// The file store's key derivation; nil where swift-crypto's scrypt is not built (the Mac).
    var deriveKey: FileSecretStore.DeriveKey?
    /// scrypt's cost for a new secrets file.
    var scryptParameters = ScryptParameters.standard
    /// Probes (the store detected, the systemd version) are asked once per process.
    var cachesProbes = false

    /// The variables the stores read (and pass on, in part, to their tools).
    static let environmentNames = [
        "HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "PASSTUNNEL_HOME",
        "PASSTUNNEL_SECRET_STORE", FileSecretStore.passphraseFileVariable
    ]

    /// This process: its environment now, its user, the support directory and `SecretStores.interaction`.
    static func current(service: String) -> SecretStoreSystem {
        #if os(Linux)
        let deriveKey: FileSecretStore.DeriveKey? = FileSecretStore.scrypt
        #else
        let deriveKey: FileSecretStore.DeriveKey? = nil
        #endif
        var environment: [String: String] = [:]
        for name in environmentNames { environment[name] = getenv(name).map { String(cString: $0) } }
        return SecretStoreSystem(
            service: service, paths: .default, environment: environment, isRoot: geteuid() == 0,
            runner: SystemToolRunner(), interaction: SecretStores.interaction,
            isExecutable: { FileManager.default.isExecutableFile(atPath: $0) },
            isSocket: { path in
                var st = stat()
                return stat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFSOCK
            },
            deriveKey: deriveKey, cachesProbes: true)
    }

    func store(_ choice: SecretStoreChoice) -> SecretStore {
        switch choice {
        case .secretService, .auto: return SecretServiceStore(service: service, system: self)
        case .systemdCreds: return SystemdCredsStore(system: self)
        case .file: return FileSecretStore(system: self)
        }
    }

    /// Why `choice` cannot be used from this process now; nil when it can.
    func unavailability(_ choice: SecretStoreChoice) -> SecretStoreUnavailable? {
        switch choice {
        case .secretService, .auto: return SecretServiceStore(service: service, system: self).unavailability()
        case .systemdCreds: return SystemdCredsStore(system: self).unavailability()
        case .file: return FileSecretStore(system: self).unavailability()
        }
    }
}

/// The store `Secrets` uses on Linux: the chosen one, or the reason there is none. After its first
/// successful write the store is recorded in config.json (`Preferences.secretStoreUsed`), so later
/// runs keep using it: secrets saved in a desktop session are still found over SSH.
struct ChosenSecretStore: SecretStore {
    let selection: Result<SecretStoreSelection, SecretStoreUnavailable>
    let system: SecretStoreSystem

    var name: String? { (try? selection.get())?.store.rawValue }

    private func backend() throws -> SecretStore { system.store(try selection.get().store) }

    func read(_ account: String) throws -> Data? { try backend().read(account) }

    func write(_ account: String, _ data: Data) throws {
        try backend().write(account, data)
        if case let .success(chosen) = selection { SecretStores.record(chosen.store, paths: system.paths) }
    }

    func remove(_ account: String) throws { try backend().remove(account) }

    func removeAll() { (try? backend())?.removeAll() }
}

public enum SecretStores {
    /// What this process may ask of the user (the CLI sets it on a terminal).
    public static var interaction = SecretStoreInteraction.none

    private static let lock = NSLock()
    /// The store detected for `auto`, by support directory and service (`cachesProbes`).
    private static var detected: [String: SecretStoreChoice] = [:]

    /// The store for `system`, chosen as `SecretStoreSelection` says.
    static func chosen(system: SecretStoreSystem) -> ChosenSecretStore {
        let prefs = Preferences.load(paths: system.paths)
        let selection = Result<SecretStoreSelection, Error> {
            try SecretStoreSelection.resolve(
                environment: environmentChoice(system), setting: prefs.secretStore,
                recorded: prefs.secretStoreUsed
            ) { detect(system) }
        }.mapError { $0 as? SecretStoreUnavailable ?? SecretStoreUnavailable($0.localizedDescription) }
        return ChosenSecretStore(selection: selection, system: system)
    }

    private static func environmentChoice(_ system: SecretStoreSystem) -> String? {
        system.environment["PASSTUNNEL_SECRET_STORE"].map { $0.trimmingCharacters(in: .whitespaces) }
            .flatMap { $0.isEmpty ? nil : $0 }
    }

    private static func detect(_ system: SecretStoreSystem) -> SecretStoreChoice {
        let key = system.paths.root.path + "\n" + system.service
        if system.cachesProbes {
            lock.lock()
            let known = detected[key]
            lock.unlock()
            if let known { return known }
        }
        let choice = SecretStoreSelection.detect(isRoot: system.isRoot) { system.unavailability($0) == nil }
        if system.cachesProbes {
            lock.lock()
            detected[key] = choice
            lock.unlock()
        }
        return choice
    }

    /// Records `store` as where this user's secrets are, unless one is recorded already. Best effort:
    /// the secret is saved either way.
    static func record(_ store: SecretStoreChoice, paths: AppPaths) {
        var prefs = Preferences.load(paths: paths)
        guard prefs.secretStoreUsed == nil, store != .auto else { return }
        prefs.secretStoreUsed = store
        try? prefs.save(paths: paths)
    }

    /// `passtunnel secret-store NAME`: the setting. A store named explicitly is recorded too, so a later
    /// `auto` keeps using it. Secrets saved in another store stay there.
    public static func choose(_ choice: SecretStoreChoice, paths: AppPaths = .default) throws {
        var prefs = Preferences.load(paths: paths)
        prefs.secretStore = choice
        if choice != .auto { prefs.secretStoreUsed = choice }
        try prefs.save(paths: paths)
    }

    /// The store in use, whether it is available, and how it was chosen.
    public static func report() -> SecretStoreReport {
        let service = Env.keychainService
        #if DEBUG
        if Env.secretStore == MemorySecretStore.name {
            return SecretStoreReport(
                name: MemorySecretStore.name, available: true,
                setting: Preferences.load().secretStore.rawValue,
                chosenBy: SecretStoreSource.environment.rawValue)
        }
        #endif
        return report(system: .current(service: service))
    }

    static func report(system: SecretStoreSystem) -> SecretStoreReport {
        let setting = Preferences.load(paths: system.paths).secretStore.rawValue
        let chosen = chosen(system: system)
        switch chosen.selection {
        case let .success(selection):
            let problem = system.unavailability(selection.store)
            return SecretStoreReport(
                name: selection.store.rawValue, available: problem == nil, setting: setting,
                chosenBy: selection.source.rawValue, error: problem?.message)
        case let .failure(error):
            return SecretStoreReport(
                name: environmentChoice(system) ?? "", available: false, setting: setting,
                chosenBy: SecretStoreSource.environment.rawValue, error: error.message)
        }
    }

    /// The name of the store in use, for messages ("file"); nil when none can be chosen.
    public static var nameInUse: String? {
        #if DEBUG
        if Env.secretStore == MemorySecretStore.name { return MemorySecretStore.name }
        #endif
        return chosen(system: .current(service: Env.keychainService)).name
    }
}

// MARK: - Errors

extension SecretStoreUnavailable {
    static func unknownStore(_ name: String) -> Self {
        Self(
            String(localized: "PASSTUNNEL_SECRET_STORE is “\(name)”, which is not a secret store (use auto, secret-service, systemd-creds or file)."))
    }

    static var secretServiceToolMissing: Self {
        Self(String(localized: "The Secret Service needs secret-tool (in the package libsecret-tools or libsecret), which was not found."))
    }

    static var secretServiceNoBus: Self {
        Self(
            String(
                localized:
                    "The Secret Service cannot be reached: there is no session bus here (for example over SSH). Use PassTunnel in your desktop session, or choose another store with “passtunnel secret-store”."
            ))
    }

    static func secretServiceTimeout(_ seconds: Int) -> Self {
        Self(String(localized: "The keyring did not answer within \(seconds) seconds. If it is locked, unlock it and try again."))
    }

    static func secretServiceFailed(_ message: String) -> Self {
        Self(String(localized: "The Secret Service failed: \(message)"))
    }

    static var secretServiceValueTooLong: Self {
        Self(String(localized: "The value is too long for the Secret Service (at most 8191 bytes)."))
    }

    static var secretServiceTextOnly: Self {
        Self(String(localized: "The Secret Service keeps text only, and the value is not UTF-8 text."))
    }

    static var systemdCredsToolMissing: Self {
        Self(String(localized: "systemd-creds was not found."))
    }

    static func systemdCredsTooOld(_ version: Int) -> Self {
        Self(String(localized: "systemd-creds encrypts credentials for a user from systemd 256 on; this system has systemd \(version)."))
    }

    static func systemdCredsTimeout(_ seconds: Int) -> Self {
        Self(String(localized: "systemd-creds did not answer within \(seconds) seconds."))
    }

    static func systemdCredsFailed(_ message: String) -> Self {
        Self(String(localized: "systemd-creds failed: \(message)"))
    }

    static func unsafeDirectory(_ path: String) -> Self {
        Self(String(localized: "The folder \(path) must belong to you and be accessible to you only."))
    }

    static var noPassphrase: Self {
        Self(
            String(
                localized:
                    "The secrets file is protected by a passphrase, which cannot be asked for here: run the command in a terminal, or set PASSTUNNEL_PASSPHRASE_FILE to a file that holds it."
            ))
    }

    static func passphraseFile(_ path: String) -> Self {
        Self(
            String(
                localized: "PASSTUNNEL_PASSPHRASE_FILE must name a regular file that belongs to you and that only you can read (chmod 600): \(path)"))
    }

    static var noPassphraseEntered: Self {
        Self(String(localized: "No passphrase was given."))
    }

    static var passphrasesDiffer: Self {
        Self(String(localized: "The passphrases do not match."))
    }

    static var secretsFileUnreadable: Self {
        Self(String(localized: "The secrets file cannot be decrypted: wrong passphrase, or the file was changed."))
    }

    static func notASecretsFile(_ path: String) -> Self {
        Self(String(localized: "\(path) is not a PassTunnel secrets file, or it is damaged."))
    }

    static func newerSecretsFile(_ path: String) -> Self {
        Self(String(localized: "\(path) was written by a newer version of PassTunnel."))
    }

    static var secretsFileBusy: Self {
        Self(String(localized: "Another PassTunnel process is changing the secrets file. Try again."))
    }

    static var fileStoreUnsupported: Self {
        Self(String(localized: "The secrets file cannot be used on this system."))
    }
}
