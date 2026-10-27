import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// The tabs of the Settings window (decision D-12): notifications and what About showed are on the General page.
/// Helper stays a tab of its own, where `passtunnel helper install|update|uninstall` hands over.
enum SettingsTab: String, CaseIterable, Identifiable {
    case general, shortcuts, helper, updates
    var id: String { rawValue }

    var title: String {
        switch self {
        case .general: return String(localized: "General")
        case .shortcuts: return String(localized: "Shortcuts")
        case .helper: return String(localized: "Helper")
        case .updates: return String(localized: "Updates")
        }
    }

    var symbol: String {
        switch self {
        case .general: return "gearshape"
        case .shortcuts: return "keyboard"
        case .helper: return "lock.shield"
        case .updates: return "arrow.triangle.2.circlepath"
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        TabView(selection: $model.settingsTab) {
            ForEach(SettingsTab.allCases) { tab in
                SettingsPane(tab: tab)
                    .tabItem { Label(tab.title, systemImage: tab.symbol) }
                    .tag(tab)
            }
        }
        .frame(width: 540)
    }
}

struct SettingsPane: View {
    let tab: SettingsTab

    var body: some View {
        switch tab {
        case .general: GeneralSettings()
        case .shortcuts: ShortcutSettings()
        case .helper: HelperSettings()
        case .updates: UpdateSettings()
        }
    }
}

// MARK: - Menu bar preview

/// Live preview of the menu bar title with sample badges in every state.
struct MenuBarPreview: View {
    let palette: BadgePalette

    var body: some View {
        HStack(spacing: 8) {
            ForEach([false, true], id: \.self) { dark in
                Image(
                    nsImage: MenuBarIcon.rendered(
                        badges: [
                            .init(text: "W", symbol: nil, tone: .connected),
                            .init(text: "H", symbol: nil, tone: .connecting),
                            .init(text: "L", symbol: nil, tone: .disconnected)
                        ],
                        palette: palette, dark: dark)
                )
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(dark ? Color(white: 0.16) : Color(white: 0.93), in: RoundedRectangle(cornerRadius: 5))
            }
        }
        .accessibilityLabel(String(localized: "Menu bar preview"))
    }
}

extension MenuBarIcon {
    /// Rasterized for a fixed appearance (settings preview, screenshots).
    static func rendered(badges: [Badge], palette: BadgePalette, dark: Bool, scale: CGFloat = 2) -> NSImage {
        rendered(image(badges: badges, palette: palette), dark: dark, scale: scale)
    }

    static func rendered(_ source: NSImage, dark: Bool, scale: CGFloat = 2) -> NSImage {
        let size = source.size
        let rep = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: Int(size.width * scale), pixelsHigh: Int(size.height * scale),
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        rep.size = size
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        NSAppearance(named: dark ? .darkAqua : .aqua)!.performAsCurrentDrawingAppearance {
            source.draw(in: NSRect(origin: .zero, size: size))
        }
        NSGraphicsContext.restoreGraphicsState()
        let out = NSImage(size: size)
        out.addRepresentation(rep)
        return out
    }
}

extension View {
    func settingsFooter() -> some View {
        self.font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct SettingLabel: View {
    let title: String
    let detail: String

    init(_ title: String, _ detail: String) {
        self.title = title
        self.detail = detail
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
            Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Shortcuts

struct ShortcutSettings: View {
    @EnvironmentObject private var model: AppModel
    @State private var trusted = AutoType.isTrusted
    var previewTrusted: Bool?
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        Form {
            Section {
                Toggle(String(localized: "Enable global shortcuts"), isOn: $model.prefs.hotkeys)
                ShortcutRow(
                    keys: Hotkeys.Action.toggleDefault.display,
                    title: String(localized: "Connect or disconnect the default profile")
                )
                .disabled(!model.prefs.hotkeys)
                ShortcutRow(
                    keys: Hotkeys.Action.code.display,
                    title: model.prefs.autoType
                        ? String(localized: "Type the current code")
                        : String(localized: "Copy the current code")
                )
                .disabled(!model.prefs.hotkeys)
            } footer: {
                Text(String(localized: "Shortcuts work in every app while PassTunnel is running."))
                    .settingsFooter()
            }

            Section(String(localized: "Default profile")) {
                Picker(String(localized: "Profile"), selection: $model.prefs.defaultProfile) {
                    Text(String(localized: "First in the list")).tag(String?.none)
                    if !model.profiles.isEmpty { Divider() }
                    ForEach(model.profiles) { p in
                        Text(p.name).tag(Optional(p.id))
                    }
                }
            }

            Section {
                Toggle(isOn: autoType) {
                    SettingLabel(
                        String(localized: "Type the code for me"),
                        String(localized: "\(Hotkeys.Action.code.display) types the current code into the focused field instead of copying it."))
                }
                if model.prefs.autoType && !(previewTrusted ?? trusted) {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: "hand.raised.fill")
                            .foregroundStyle(.orange)
                            .font(.title3)
                        VStack(alignment: .leading, spacing: 6) {
                            Text(String(localized: "PassTunnel needs Accessibility permission to type for you."))
                                .font(.callout.weight(.medium))
                            Text(
                                String(
                                    localized:
                                        "Turn on PassTunnel in System Settings → Privacy & Security → Accessibility. Until then, the code is copied instead."
                                )
                            )
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            Button(String(localized: "Open Accessibility Settings…")) { AutoType.openAccessibilitySettings() }
                                .controlSize(.small)
                        }
                    }
                    .padding(.vertical, 4)
                } else if model.prefs.autoType {
                    Label(String(localized: "Accessibility permission granted"), systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .font(.callout)
                }
            }
        }
        .formStyle(.grouped)
        .onReceive(timer) { _ in
            if previewTrusted == nil, model.prefs.autoType { trusted = AutoType.isTrusted }
        }
    }

    private var autoType: Binding<Bool> {
        Binding(
            get: { model.prefs.autoType },
            set: { on in
                model.prefs.autoType = on
                if on && !AutoType.isTrusted { AutoType.requestTrust() }
                trusted = AutoType.isTrusted
            })
    }
}

private struct ShortcutRow: View {
    let keys: String
    let title: String

    var body: some View {
        LabeledContent(title) {
            Text(keys)
                .font(.system(.body, design: .rounded).weight(.medium))
                .padding(.horizontal, 8)
                .padding(.vertical, 2)
                .background(Color.primary.opacity(0.07), in: RoundedRectangle(cornerRadius: 5))
                .overlay(RoundedRectangle(cornerRadius: 5).strokeBorder(Color.primary.opacity(0.12)))
        }
    }
}

// MARK: - Updates

struct UpdateSettings: View {
    var body: some View {
        if let updater = AppUpdater.shared {
            UpdateSettingsForm(updater: updater)
        } else {
            // Unbundled runs (`swift run`, screenshots): no updater, same layout.
            UpdateSettingsForm(updater: nil)
        }
    }
}

private struct UpdateSettingsForm: View {
    @ObservedObject private var updater: AppUpdater
    private let available: Bool

    init(updater: AppUpdater?) {
        _updater = ObservedObject(wrappedValue: updater ?? AppUpdater.placeholder)
        available = updater != nil
    }

    private var lastCheck: String {
        guard let date = updater.lastUpdateCheckDate else { return String(localized: "Never") }
        return date.formatted(date: .abbreviated, time: .shortened)
    }

    var body: some View {
        Form {
            Section {
                Toggle(
                    String(localized: "Check for updates automatically"),
                    isOn: Binding(
                        get: { updater.automaticallyChecksForUpdates },
                        set: { updater.setAutomaticallyChecks($0) })
                )
                .disabled(!available)
                LabeledContent(String(localized: "Current version"), value: AppInfo.versionString)
                LabeledContent(String(localized: "Last checked"), value: lastCheck)
                HStack {
                    Button(String(localized: "Check Now")) { updater.checkForUpdates() }
                        .disabled(!available || !updater.canCheckForUpdates)
                        .accessibilityIdentifier("updates.checkNow")
                    Spacer()
                }
            } footer: {
                Text(
                    String(
                        localized:
                            "PassTunnel looks for new versions on GitHub once a day and asks before installing one. Updates are signed and checked before they are installed."
                    )
                )
                .settingsFooter()
            }
            Section {
                Link(String(localized: "Open Releases Page"), destination: AppInfo.releasesURL)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - App info

enum AppInfo {
    /// GitHub "owner/name", stamped into Info.plist by build-app.sh from scripts/release.env; the
    /// literal is for unbundled runs (screenshots) and must match release.env (ProjectLinksTests).
    static let repository =
        Bundle.main.object(forInfoDictionaryKey: "PTGitHubRepository") as? String
        ?? "passtunnel/passtunnel"
    static let repositoryURL = URL(string: "https://github.com/\(repository)")!
    static let releasesURL = repositoryURL.appendingPathComponent("releases")
    /// The website's privacy page (`site/privacy/`, docs/WEBSITE.md); ProjectLinksTests checks it against the page.
    static let privacyURL = URL(string: "https://passtunnel.github.io/privacy/")!

    static var version: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0" }
    static var build: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0" }
    static var gitDescribe: String? { Bundle.main.object(forInfoDictionaryKey: "PTGitDescribe") as? String }

    static var versionString: String {
        String(localized: "Version \(version) (\(build))")
    }

    /// The app icon: from the bundle, or from `Resources/AppIcon.icns` of the source tree when run
    /// unbundled (`swift run`, screenshot rendering).
    static let appIcon: NSImage = {
        if let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
            let image = NSImage(contentsOf: url)
        {
            return image
        }
        var dir = Bundle.main.executableURL?.resolvingSymlinksInPath().deletingLastPathComponent()
        for _ in 0..<6 {
            guard let current = dir else { break }
            let candidate = current.appendingPathComponent("Resources/AppIcon.icns")
            if FileManager.default.fileExists(atPath: current.appendingPathComponent("Package.swift").path),
                let image = NSImage(contentsOf: candidate)
            {
                return image
            }
            dir = current.deletingLastPathComponent()
        }
        if Bundle.main.bundleURL.pathExtension == "app" { return NSApp.applicationIconImage }
        return NSWorkspace.shared.icon(for: .applicationBundle)
    }()
}
