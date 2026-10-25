import Foundation
import PassTunnelKit

/// Items in the desktop keyring (GNOME Keyring, KDE Wallet, KeePassXC: any Secret Service) through
/// `secret-tool`, libsecret's command-line tool. Attributes `service=<service>` and
/// `account=<account>`, label "PassTunnel (<account>)", as the Keychain items on the Mac. Values go over
/// standard input and output only, exactly as stored: `secret-tool store` keeps the bytes it reads
/// (UTF-8 text, at most 8 KiB) and `lookup` writes them back unchanged when its output is not a
/// terminal, so no encoding is needed. Linux only (docs/LINUX.md); built everywhere for its tests.
struct SecretServiceStore: SecretStore {
    /// Where `secret-tool` is looked for, in this order (never in PATH).
    static let toolPaths = ["/usr/bin/secret-tool", "/bin/secret-tool", "/usr/local/bin/secret-tool"]
    /// `secret-tool store` reads at most 8192 bytes and cuts longer input off.
    static let maxValueSize = 8191
    /// An account no item has (accounts are "<id>/<kind>"): the availability probe looks it up.
    static let probeAccount = "probe"
    static let probeTimeout: TimeInterval = 5
    /// A locked keyring asks for its password on the desktop: time to answer it in a terminal
    /// session, a short wait otherwise (MCP, scripts), then a clear error instead of a hang.
    static let interactiveTimeout: TimeInterval = 120
    static let unattendedTimeout: TimeInterval = 15

    let service: String
    let system: SecretStoreSystem

    private var timeout: TimeInterval {
        system.interaction.interactive ? Self.interactiveTimeout : Self.unattendedTimeout
    }

    /// The environment `secret-tool` gets: the session bus, the runtime and home directories, `LANG=C`
    /// (messages in English), nothing else. Nil without a session bus: neither
    /// `DBUS_SESSION_BUS_ADDRESS` nor the bus socket in `XDG_RUNTIME_DIR`.
    static func toolEnvironment(_ environment: [String: String], isSocket: (String) -> Bool) -> [String: String]? {
        var env = ["LANG": "C"]
        if let home = environment["HOME"], !home.isEmpty { env["HOME"] = home }
        if let runtime = environment["XDG_RUNTIME_DIR"], runtime.hasPrefix("/") { env["XDG_RUNTIME_DIR"] = runtime }
        if let bus = environment["DBUS_SESSION_BUS_ADDRESS"], !bus.isEmpty {
            env["DBUS_SESSION_BUS_ADDRESS"] = bus
        } else if let runtime = env["XDG_RUNTIME_DIR"], isSocket(runtime + "/bus") {
            env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + busAddressEscaped(runtime + "/bus")
        } else {
            return nil
        }
        return env
    }

    /// A D-Bus address value: bytes outside `[-0-9A-Za-z_/.*]` as %XX.
    static func busAddressEscaped(_ value: String) -> String {
        let plain = Set("-_/.*0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".utf8)
        return value.utf8.map { byte -> String in
            if plain.contains(byte) { return String(UnicodeScalar(byte)) }
            let hex = String(byte, radix: 16, uppercase: true)
            return "%" + (hex.count == 1 ? "0" + hex : hex)
        }.joined()
    }

    /// Why the store cannot be used now; nil when a lookup works (it found an item or none).
    func unavailability() -> SecretStoreUnavailable? {
        do {
            _ = try lookup(Self.probeAccount, timeout: Self.probeTimeout)
            return nil
        } catch let error as SecretStoreUnavailable {
            return error
        } catch {
            return SecretStoreUnavailable(error.localizedDescription)
        }
    }

    // MARK: SecretStore

    func read(_ account: String) throws -> Data? {
        try lookup(account, timeout: timeout)
    }

    func write(_ account: String, _ data: Data) throws {
        guard data.count <= Self.maxValueSize else { throw SecretStoreUnavailable.secretServiceValueTooLong }
        guard String(data: data, encoding: .utf8) != nil else { throw SecretStoreUnavailable.secretServiceTextOnly }
        var result = try run(["store", "--label=PassTunnel (\(account))", "service", service, "account", account],
                             input: data, timeout: timeout)
        defer { result.wipe() }
        guard result.status == 0 else { throw SecretStoreUnavailable.secretServiceFailed(result.failure) }
    }

    /// `secret-tool clear` exits 1 without a message when nothing matched.
    func remove(_ account: String) throws {
        let result = try run(["clear", "service", service, "account", account], input: Data(), timeout: timeout)
        guard result.status == 0 || (result.status == 1 && result.errorLine.isEmpty) else {
            throw SecretStoreUnavailable.secretServiceFailed(result.failure)
        }
    }

    func removeAll() {
        _ = try? run(["clear", "service", service], input: Data(), timeout: timeout)
    }

    // MARK: secret-tool

    /// The value; nil when no item matches (`lookup` exits 1 without a message then).
    private func lookup(_ account: String, timeout: TimeInterval) throws -> Data? {
        var result = try run(["lookup", "service", service, "account", account], input: Data(), timeout: timeout)
        if result.status == 0 { return result.output }
        result.wipe()
        if result.status == 1 && result.errorLine.isEmpty { return nil }
        throw SecretStoreUnavailable.secretServiceFailed(result.failure)
    }

    private func run(_ arguments: [String], input: Data, timeout: TimeInterval) throws -> ToolOutput {
        guard let tool = Self.toolPaths.first(where: system.isExecutable) else {
            throw SecretStoreUnavailable.secretServiceToolMissing
        }
        guard let environment = Self.toolEnvironment(system.environment, isSocket: system.isSocket) else {
            throw SecretStoreUnavailable.secretServiceNoBus
        }
        do {
            return try system.runner.run(tool, arguments, environment: environment, input: input, timeout: timeout)
        } catch let timeout as ToolTimeout {
            throw SecretStoreUnavailable.secretServiceTimeout(timeout.seconds)
        } catch {
            throw SecretStoreUnavailable.secretServiceFailed(error.localizedDescription)
        }
    }
}
