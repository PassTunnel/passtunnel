import Foundation

public enum AppTheme: String, Codable, CaseIterable { case system, light, dark }

/// App preferences stored in `config.json`. Missing or unknown keys fall back to defaults.
public struct Preferences: Codable, Equatable {
    public var defaultProfile: String? = nil
    public var theme = AppTheme.system
    public var showLock = true
    public var notifyOnDrop = true
    public var sessionWarnMin = 30
    public var sessionNotifyMin = 10
    public var hotkeys = false
    public var autoType = false
    public var launchAtLogin = true
    public var autoUpdate = false

    public init() {}

    enum CodingKeys: String, CodingKey {
        case defaultProfile, theme, showLock, notifyOnDrop, sessionWarnMin, sessionNotifyMin
        case hotkeys, autoType, launchAtLogin, autoUpdate
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Preferences()
        defaultProfile = c.lenient(String.self, .defaultProfile).flatMap { $0.isEmpty ? nil : $0 }
        theme = c.lenientEnum(AppTheme.self, .theme) ?? d.theme
        showLock = c.lenient(Bool.self, .showLock) ?? d.showLock
        notifyOnDrop = c.lenient(Bool.self, .notifyOnDrop) ?? d.notifyOnDrop
        sessionWarnMin = c.lenient(Int.self, .sessionWarnMin) ?? d.sessionWarnMin
        sessionNotifyMin = c.lenient(Int.self, .sessionNotifyMin) ?? d.sessionNotifyMin
        hotkeys = c.lenient(Bool.self, .hotkeys) ?? d.hotkeys
        autoType = c.lenient(Bool.self, .autoType) ?? d.autoType
        launchAtLogin = c.lenient(Bool.self, .launchAtLogin) ?? d.launchAtLogin
        autoUpdate = c.lenient(Bool.self, .autoUpdate) ?? d.autoUpdate
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(defaultProfile, forKey: .defaultProfile)
        try c.encode(theme, forKey: .theme)
        try c.encode(showLock, forKey: .showLock)
        try c.encode(notifyOnDrop, forKey: .notifyOnDrop)
        try c.encode(sessionWarnMin, forKey: .sessionWarnMin)
        try c.encode(sessionNotifyMin, forKey: .sessionNotifyMin)
        try c.encode(hotkeys, forKey: .hotkeys)
        try c.encode(autoType, forKey: .autoType)
        try c.encode(launchAtLogin, forKey: .launchAtLogin)
        try c.encode(autoUpdate, forKey: .autoUpdate)
    }

    /// Missing or unreadable file → defaults (never throws).
    public static func load(paths: AppPaths = .default) -> Preferences {
        guard FileManager.default.fileExists(atPath: paths.configURL.path) else { return Preferences() }
        return (try? JSONCoding.read(Preferences.self, from: paths.configURL)) ?? Preferences()
    }

    public func save(paths: AppPaths = .default) throws {
        try paths.ensureDirectories()
        try JSONCoding.write(self, to: paths.configURL, mode: 0o600)
    }
}
