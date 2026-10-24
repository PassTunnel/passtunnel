import Foundation
import PassTunnelKit
import PassTunnelShared

/// Locations of PassTunnel's files. Environment overrides are read at call time (never cached),
/// so tests can point everything at a temporary directory.
public struct AppPaths: Equatable {
    public let root: URL

    public init(root: URL) {
        self.root = root.standardizedFileURL
    }

    /// `~/Library/Application Support/PassTunnel` (Linux: `~/.local/share/passtunnel`, whatever
    /// `XDG_DATA_HOME` says, as the daemon expects it there), or `$PASSTUNNEL_HOME` when set.
    public static var `default`: AppPaths {
        if let home = Env.string("PASSTUNNEL_HOME") {
            return AppPaths(root: URL(fileURLWithPath: (home as NSString).expandingTildeInPath, isDirectory: true))
        }
        #if os(Linux)
        return AppPaths(root: URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            .appendingPathComponent(linuxSubpath, isDirectory: true))
        #else
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return AppPaths(root: base.appendingPathComponent("PassTunnel", isDirectory: true))
        #endif
    }

    /// The support directory below the home directory on Linux; `PT.profilesSubpath` is its `profiles`.
    static let linuxSubpath = ".local/share/passtunnel"

    public var configURL: URL { root.appendingPathComponent("config.json") }
    public var profilesDir: URL { root.appendingPathComponent("profiles", isDirectory: true) }
    /// Linux: the credential files of the systemd-creds store (`SystemdCredsStore`).
    public var secretsDirectory: URL { root.appendingPathComponent("secrets", isDirectory: true) }
    /// Linux: the encrypted file of the file store (`FileSecretStore`).
    public var secretsFileURL: URL { root.appendingPathComponent("secrets.enc") }

    public func profileDir(_ id: String) -> URL {
        profilesDir.appendingPathComponent(id, isDirectory: true)
    }

    /// Creates the support and profiles directories (0700) if needed.
    public func ensureDirectories() throws {
        try FileIO.makeDirectory(root)
        try FileIO.makeDirectory(profilesDir)
    }
}

/// Environment lookups, evaluated on every call.
enum Env {
    static func string(_ name: String) -> String? {
        guard let raw = getenv(name) else { return nil }
        let value = String(cString: raw).trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    static func int(_ name: String) -> Int? {
        string(name).flatMap { Int($0) }
    }

    /// Keychain service name: `$PASSTUNNEL_KEYCHAIN_SERVICE` or `PT.keychainService`. Also the service
    /// of the other secret stores.
    static var keychainService: String {
        string("PASSTUNNEL_KEYCHAIN_SERVICE") ?? PT.keychainService
    }

    /// `$PASSTUNNEL_SECRET_STORE`: on Linux a store's name or `auto` (`SecretStores`); `memory` selects
    /// the in-memory store in debug builds (tests); nil for the default.
    static var secretStore: String? {
        string("PASSTUNNEL_SECRET_STORE")
    }
}
