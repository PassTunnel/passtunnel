import Foundation

/// Light / dark mode of the app windows.
public enum AppAppearance: String, Codable, CaseIterable, Sendable { case system, light, dark }

/// App preferences stored in `config.json`. Missing or unknown keys fall back to defaults; the
/// legacy `theme` key is read into `appearance`.
public struct Preferences: Codable, Equatable {
    public var defaultProfile: String? = nil
    // General
    public var appearance = AppAppearance.system
    public var badgePalette = BadgePalette.pastel
    public var showLock = true
    public var hideCodes = false
    public var showInDock = false
    public var launchAtLogin = true
    public var autoUpdate = false
    // Notifications
    public var notifyOnDrop = true
    public var notifyHealth = true
    public var sessionNotifyMin = 10        // minutes before the session limit; 0 = off
    public var sessionWarnMin = 30
    // Shortcuts
    public var hotkeys = false
    public var autoType = false

    public init() {}

    enum CodingKeys: String, CodingKey {
        case defaultProfile, appearance, badgePalette, showLock, hideCodes, showInDock, launchAtLogin, autoUpdate
        case notifyOnDrop, notifyHealth, sessionNotifyMin, sessionWarnMin, hotkeys, autoType
        case theme   // legacy, read only
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Preferences()
        defaultProfile = c.lenient(String.self, .defaultProfile).flatMap { $0.isEmpty ? nil : $0 }
        appearance = c.lenientEnum(AppAppearance.self, .appearance)
            ?? c.lenientEnum(AppAppearance.self, .theme) ?? d.appearance
        badgePalette = c.lenientEnum(BadgePalette.self, .badgePalette) ?? d.badgePalette
        showLock = c.lenient(Bool.self, .showLock) ?? d.showLock
        hideCodes = c.lenient(Bool.self, .hideCodes) ?? d.hideCodes
        showInDock = c.lenient(Bool.self, .showInDock) ?? d.showInDock
        launchAtLogin = c.lenient(Bool.self, .launchAtLogin) ?? d.launchAtLogin
        autoUpdate = c.lenient(Bool.self, .autoUpdate) ?? d.autoUpdate
        notifyOnDrop = c.lenient(Bool.self, .notifyOnDrop) ?? d.notifyOnDrop
        notifyHealth = c.lenient(Bool.self, .notifyHealth) ?? d.notifyHealth
        sessionNotifyMin = max(0, c.lenient(Int.self, .sessionNotifyMin) ?? d.sessionNotifyMin)
        sessionWarnMin = c.lenient(Int.self, .sessionWarnMin) ?? d.sessionWarnMin
        hotkeys = c.lenient(Bool.self, .hotkeys) ?? d.hotkeys
        autoType = c.lenient(Bool.self, .autoType) ?? d.autoType
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(defaultProfile, forKey: .defaultProfile)
        try c.encode(appearance, forKey: .appearance)
        try c.encode(badgePalette, forKey: .badgePalette)
        try c.encode(showLock, forKey: .showLock)
        try c.encode(hideCodes, forKey: .hideCodes)
        try c.encode(showInDock, forKey: .showInDock)
        try c.encode(launchAtLogin, forKey: .launchAtLogin)
        try c.encode(autoUpdate, forKey: .autoUpdate)
        try c.encode(notifyOnDrop, forKey: .notifyOnDrop)
        try c.encode(notifyHealth, forKey: .notifyHealth)
        try c.encode(sessionNotifyMin, forKey: .sessionNotifyMin)
        try c.encode(sessionWarnMin, forKey: .sessionWarnMin)
        try c.encode(hotkeys, forKey: .hotkeys)
        try c.encode(autoType, forKey: .autoType)
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
