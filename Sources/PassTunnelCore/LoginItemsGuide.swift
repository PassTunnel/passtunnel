import Foundation

// macOS only: System Settings and its Login Items pane.
#if os(macOS)

/// Decides when the app's Login Items guide shows: a small floating panel with the row that turns the helper on
/// (the PassTunnel icon, its name and a switch drawn on), shown while System Settings is in front after PassTunnel
/// opened Login Items for the helper's approval. It is only a guide: nothing in System Settings is read,
/// scripted or clicked.
///
/// `start` begins it when Login Items open for a helper that waits for the approval, and never for any other
/// status. It ends by itself once the helper is no longer waiting (turned on, or gone), when the user removed it,
/// after `timeout`, and when System Settings quits after it was seen running; `close` ends it at once (the
/// panel's close button, the app quitting). While it runs, the panel shows only while System Settings is the
/// frontmost app.
public struct LoginItemsGuide: Equatable, Sendable {
    /// How long the guide waits for the approval; Open Login Items… starts it again.
    public static let timeout: TimeInterval = 5 * 60
    /// System Settings (and System Preferences before it).
    public static let systemSettingsBundleID = "com.apple.systempreferences"

    public struct Situation: Equatable, Sendable {
        public var status: HelperStatus
        /// `Preferences.helperRemoved`.
        public var removedByUser: Bool
        /// The bundle identifier of the frontmost app; nil when unknown.
        public var frontmost: String?
        /// System Settings runs.
        public var systemSettingsRunning: Bool

        public init(status: HelperStatus, removedByUser: Bool, frontmost: String?, systemSettingsRunning: Bool) {
            self.status = status
            self.removedByUser = removedByUser
            self.frontmost = frontmost
            self.systemSettingsRunning = systemSettingsRunning
        }
    }

    /// When the guide ends on its own; nil while it does not run.
    public private(set) var deadline: Date?
    /// System Settings was seen running since the guide started: from then on, quitting it ends the guide.
    public private(set) var sawSystemSettings = false

    public init() {}

    public var isActive: Bool { deadline != nil }

    /// Login Items were opened for the helper. Starts the guide (again, with a fresh `timeout`) when the helper
    /// waits for the approval; for any other status it does not run. True when it runs.
    @discardableResult
    public mutating func start(status: HelperStatus, removedByUser: Bool = false, now: Date = Date()) -> Bool {
        guard status == .requiresApproval, !removedByUser else {
            close()
            return false
        }
        deadline = now.addingTimeInterval(Self.timeout)
        sawSystemSettings = false
        return true
    }

    /// Ends the guide (the close button, the app quitting).
    public mutating func close() {
        deadline = nil
        sawSystemSettings = false
    }

    /// Whether the panel shows now; ends the guide when it is no longer needed.
    public mutating func shows(_ s: Situation, now: Date = Date()) -> Bool {
        guard let deadline else { return false }
        guard s.status == .requiresApproval, !s.removedByUser, now < deadline else {
            close()
            return false
        }
        if s.systemSettingsRunning {
            sawSystemSettings = true
        } else if sawSystemSettings {
            close()
            return false
        }
        return s.frontmost == Self.systemSettingsBundleID
    }
}

/// The heading System Settings shows above the list of background items in Login Items, read from System
/// Settings' own localized strings (a file read: no permission, nothing in System Settings is touched). Apple
/// renamed it between macOS versions, so the guide names it only when the running system has one of the known
/// headings, in the language System Settings shows; otherwise it describes the list instead.
public enum LoginItemsPane {
    /// The Login Items pane of System Settings (macOS 13 and later).
    public static let extensionURL = URL(fileURLWithPath: "/System/Library/ExtensionKit/Extensions/LoginItems.appex")

    /// Keys (English source strings) of the heading above the background items, newest first.
    /// "Background App Activity" is the section title on macOS 27 (read from the pane on 27.2);
    /// "Allow in the Background" is the one of earlier versions.
    public static let backgroundHeadingKeys = ["Background App Activity", "Allow in the Background"]

    /// The heading in the best of `languages` the pane has, or nil when that table has none of
    /// `backgroundHeadingKeys` (or there are no tables). `tables`: language → key → value.
    public static func backgroundHeading(tables: [String: [String: String]], languages: [String]) -> String? {
        guard !tables.isEmpty else { return nil }
        let best = Bundle.preferredLocalizations(from: Array(tables.keys), forPreferences: languages)
        guard let language = best.first, let table = tables[language] else { return nil }
        for key in backgroundHeadingKeys {
            if let value = table[key]?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty { return value }
        }
        return nil
    }

    /// The heading on this Mac, in the language System Settings shows (`systemLanguages`).
    public static func backgroundHeading(languages: [String] = systemLanguages) -> String? {
        backgroundHeading(tables: localizedTables(in: extensionURL), languages: languages)
    }

    /// The languages of the system, not the app's own (the user may run PassTunnel in another language).
    public static var systemLanguages: [String] {
        let global = UserDefaults.standard.persistentDomain(forName: UserDefaults.globalDomain)
        return global?["AppleLanguages"] as? [String] ?? Locale.preferredLanguages
    }

    /// The `Localizable` strings of a bundle as language → key → value: from `Localizable.loctable` (one file for
    /// every language), else from each `<language>.lproj/Localizable.strings`. Plural and other non-text entries are
    /// left out. Empty when there is nothing readable.
    public static func localizedTables(in bundle: URL) -> [String: [String: String]] {
        let resources = bundle.appendingPathComponent("Contents/Resources", isDirectory: true)
        var tables: [String: [String: String]] = [:]
        if let data = try? Data(contentsOf: resources.appendingPathComponent("Localizable.loctable")),
            let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        {
            for (language, entries) in plist {
                guard let entries = entries as? [String: Any] else { continue }
                let strings = entries.compactMapValues { $0 as? String }
                if !strings.isEmpty { tables[language] = strings }
            }
            if !tables.isEmpty { return tables }
        }
        let folders = (try? FileManager.default.contentsOfDirectory(at: resources, includingPropertiesForKeys: nil)) ?? []
        for folder in folders where folder.pathExtension == "lproj" {
            let file = folder.appendingPathComponent("Localizable.strings")
            guard let data = try? Data(contentsOf: file),
                let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
            else { continue }
            let strings = plist.compactMapValues { $0 as? String }
            if !strings.isEmpty { tables[folder.deletingPathExtension().lastPathComponent] = strings }
        }
        return tables
    }
}
#endif
