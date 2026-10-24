import Foundation
import PassTunnelKit

/// Light / dark mode of the app windows.
public enum AppAppearance: String, Codable, CaseIterable, Sendable { case system, light, dark }

/// App preferences stored in `config.json`. Missing or unknown keys fall back to defaults; the
/// legacy `theme` key is read into `appearance`. Unknown keys are ignored and dropped on the next save
/// (e.g. `auto_update` from before Sparkle, which keeps its own setting).
public struct Preferences: Codable, Equatable {
    public var defaultProfile: String? = nil
    // General
    public var appearance = AppAppearance.system
    public var badgePalette = BadgePalette.pastel
    public var showLock = true
    public var hideCodes = false
    public var showInDock = false
    public var launchAtLogin = true
    // Notifications
    public var notifyOnDrop = true
    public var notifyHealth = true
    public var sessionNotifyMin = 10        // minutes before the session limit; 0 = off
    public var sessionWarnMin = 30
    // Shortcuts
    public var hotkeys = false
    public var autoType = false
    // Security
    /// How long one confirmation (Touch ID or password) is valid for the same profile and action.
    public var authReuseMinutes = 1

    /// Choices offered for `authReuseMinutes`; other stored values fall back to the default.
    public static let authReuseChoices = [1, 5, 15]

    public var authReuseInterval: TimeInterval { TimeInterval(authReuseMinutes * 60) }

    // Secrets (Linux; the Mac never sets them, and they are written only when set)
    /// `secret_store`: where secrets are kept, `auto` or a store (`SecretStores`).
    public var secretStore = SecretStoreChoice.auto
    /// `secret_store_used`: the store secrets were first saved to (or that was chosen by name); `auto`
    /// keeps using it.
    public var secretStoreUsed: SecretStoreChoice?

    public init() {}

    enum CodingKeys: String, CodingKey {
        case defaultProfile, appearance, badgePalette, showLock, hideCodes, showInDock, launchAtLogin
        case notifyOnDrop, notifyHealth, sessionNotifyMin, sessionWarnMin, hotkeys, autoType, authReuseMinutes
        case secretStore, secretStoreUsed
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
        notifyOnDrop = c.lenient(Bool.self, .notifyOnDrop) ?? d.notifyOnDrop
        notifyHealth = c.lenient(Bool.self, .notifyHealth) ?? d.notifyHealth
        sessionNotifyMin = max(0, c.lenient(Int.self, .sessionNotifyMin) ?? d.sessionNotifyMin)
        sessionWarnMin = c.lenient(Int.self, .sessionWarnMin) ?? d.sessionWarnMin
        hotkeys = c.lenient(Bool.self, .hotkeys) ?? d.hotkeys
        autoType = c.lenient(Bool.self, .autoType) ?? d.autoType
        let reuse = c.lenient(Int.self, .authReuseMinutes) ?? d.authReuseMinutes
        authReuseMinutes = Self.authReuseChoices.contains(reuse) ? reuse : d.authReuseMinutes
        secretStore = c.lenientEnum(SecretStoreChoice.self, .secretStore) ?? d.secretStore
        secretStoreUsed = c.lenientEnum(SecretStoreChoice.self, .secretStoreUsed).flatMap { $0 == .auto ? nil : $0 }
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
        try c.encode(notifyOnDrop, forKey: .notifyOnDrop)
        try c.encode(notifyHealth, forKey: .notifyHealth)
        try c.encode(sessionNotifyMin, forKey: .sessionNotifyMin)
        try c.encode(sessionWarnMin, forKey: .sessionWarnMin)
        try c.encode(hotkeys, forKey: .hotkeys)
        try c.encode(autoType, forKey: .autoType)
        try c.encode(authReuseMinutes, forKey: .authReuseMinutes)
        if secretStore != .auto { try c.encode(secretStore, forKey: .secretStore) }
        try c.encodeIfPresent(secretStoreUsed, forKey: .secretStoreUsed)
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
