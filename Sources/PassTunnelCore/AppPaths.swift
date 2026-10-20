import Foundation
import PassTunnelShared

/// Locations of PassTunnel's files. Environment overrides are read at call time (never cached),
/// so tests can point everything at a temporary directory.
public struct AppPaths: Equatable {
    public let root: URL

    public init(root: URL) {
        self.root = root.standardizedFileURL
    }

    /// `~/Library/Application Support/PassTunnel`, or `$PASSTUNNEL_HOME` when set.
    public static var `default`: AppPaths {
        if let home = Env.string("PASSTUNNEL_HOME") {
            return AppPaths(root: URL(fileURLWithPath: (home as NSString).expandingTildeInPath, isDirectory: true))
        }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return AppPaths(root: base.appendingPathComponent("PassTunnel", isDirectory: true))
    }

    public var configURL: URL { root.appendingPathComponent("config.json") }
    public var profilesDir: URL { root.appendingPathComponent("profiles", isDirectory: true) }

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

    /// Keychain service name: `$PASSTUNNEL_KEYCHAIN_SERVICE` or `PT.keychainService`.
    static var keychainService: String {
        string("PASSTUNNEL_KEYCHAIN_SERVICE") ?? PT.keychainService
    }

    /// First management port handed out to OpenVPN profiles.
    static var mgmtBase: Int {
        if let v = int("PASSTUNNEL_MGMT_BASE"), (1...65535).contains(v) { return v }
        return 17505
    }
}
