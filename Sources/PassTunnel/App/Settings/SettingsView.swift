import AppKit
import PassTunnelCore
import SwiftUI

enum SettingsTab: String, CaseIterable, Identifiable {
    case general, notifications, shortcuts, helper, updates, about
    var id: String { rawValue }

    var title: String {
        switch self {
        case .general: return String(localized: "General")
        case .notifications: return String(localized: "Notifications")
        case .shortcuts: return String(localized: "Shortcuts")
        case .helper: return String(localized: "Helper")
        case .updates: return String(localized: "Updates")
        case .about: return String(localized: "About")
        }
    }

    var symbol: String {
        switch self {
        case .general: return "gearshape"
        case .notifications: return "bell.badge"
        case .shortcuts: return "keyboard"
        case .helper: return "lock.shield"
        case .updates: return "arrow.triangle.2.circlepath"
        case .about: return "info.circle"
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
        case .notifications: NotificationSettings()
        case .shortcuts: ShortcutSettings()
        case .helper: HelperSettings()
        case .updates: UpdateSettings()
        case .about: AboutSettings()
        }
    }
}

// MARK: - General

struct GeneralSettings: View {
    @EnvironmentObject private var model: AppModel
    @State private var cliLocation: URL? = CommandLineTool.installedLocation
    @State private var cliMessage: String?
    @State private var loginItemError: String?
    @State private var loginStatus: LoginItemStatus
    /// Screenshots: a fixed login item status instead of asking the system.
    private let previewLoginStatus: LoginItemStatus?
    private let loginTimer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    init(previewLoginStatus: LoginItemStatus? = nil) {
        self.previewLoginStatus = previewLoginStatus
        _loginStatus = State(initialValue: previewLoginStatus ?? LoginItem.status)
    }

    var body: some View {
        Form {
            Section {
                Toggle(isOn: launchAtLogin) {
                    SettingLabel(String(localized: "Launch at login"),
                                 String(localized: "Starts quietly in the menu bar, without opening the window."))
                }
                .disabled(loginStatus == .unavailable)
                loginStatusRow
                if let loginItemError {
                    Text(loginItemError).font(.caption).foregroundStyle(.red)
                }
                Toggle(String(localized: "Show in Dock"), isOn: $model.prefs.showInDock)
                Picker(String(localized: "Appearance"), selection: $model.prefs.appearance) {
                    Text(String(localized: "System")).tag(AppAppearance.system)
                    Text(String(localized: "Light")).tag(AppAppearance.light)
                    Text(String(localized: "Dark")).tag(AppAppearance.dark)
                }
                .pickerStyle(.segmented)
            } footer: {
                Text(String(localized: "PassTunnel keeps running in the menu bar when its window is closed."))
                    .settingsFooter()
            }

            Section(String(localized: "Menu bar")) {
                LabeledContent(String(localized: "Badge colors")) {
                    Picker(String(localized: "Badge colors"), selection: $model.prefs.badgePalette) {
                        ForEach(BadgePalette.allCases, id: \.self) { palette in
                            Text(palette.displayName).tag(palette)
                        }
                    }
                    .labelsHidden()
                    .fixedSize()
                }
                LabeledContent(String(localized: "Preview")) {
                    MenuBarPreview(palette: model.prefs.badgePalette, showLock: model.prefs.showLock)
                }
                Toggle(String(localized: "Show lock symbol"), isOn: $model.prefs.showLock)
            }

            Section {
                Toggle(String(localized: "Hide codes until copied"), isOn: $model.prefs.hideCodes)
            } header: {
                Text(String(localized: "Privacy"))
            } footer: {
                Text(String(localized: "Codes are shown as ••• ••• in the window and the menu. Clicking still copies them."))
                    .settingsFooter()
            }

            Section {
                Picker(String(localized: "Ask again after"), selection: $model.prefs.authReuseMinutes) {
                    ForEach(Preferences.authReuseChoices, id: \.self) { minutes in
                        Text(Self.reuseLabel(minutes)).tag(minutes)
                    }
                }
                .accessibilityIdentifier("settings.authReuse")
            } header: {
                Text(String(localized: "Security"))
            } footer: {
                Text(String(localized: "For profiles set to “\(ConfirmationWording.settingName)”, one confirmation with Touch ID or your Mac password is valid this long for the same profile. Sleep and locking the screen end it."))
                    .settingsFooter()
            }

            Section {
                LabeledContent {
                    Button(cliLocation == nil ? String(localized: "Install…") : String(localized: "Reinstall")) { installCLI() }
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(String(localized: "Command-line tool"))
                        Text(cliLocation.map { String(localized: "Installed at \($0.path)") }
                             ?? String(localized: "Not installed"))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                if let cliMessage {
                    Text(cliMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            } footer: {
                Text(String(localized: "Use “passtunnel connect”, “passtunnel code” and more from Terminal."))
                    .settingsFooter()
            }
        }
        .formStyle(.grouped)
        .frame(minHeight: 520)
        .onAppear(perform: refreshLoginStatus)
        .onReceive(loginTimer) { _ in
            // System Settings may approve or remove the item while this pane is open.
            if loginStatus == .requiresApproval { refreshLoginStatus() }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            refreshLoginStatus()
        }
    }

    @ViewBuilder private var loginStatusRow: some View {
        switch loginStatus {
        case .requiresApproval:
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Label(String(localized: "Needs approval in Login Items."),
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Button(String(localized: "Open Login Items…")) { LoginItem.openSystemSettings() }
                    .controlSize(.small)
            }
        case .unavailable:
            Text(String(localized: "Available when PassTunnel runs as an app from the Applications folder."))
                .font(.caption)
                .foregroundStyle(.secondary)
        case .enabled, .disabled:
            EmptyView()
        }
    }

    private var launchAtLogin: Binding<Bool> {
        Binding(get: { loginStatus == .enabled || loginStatus == .requiresApproval }, set: { on in
            loginItemError = nil
            guard previewLoginStatus == nil else {
                loginStatus = on ? .enabled : .disabled
                return
            }
            do {
                loginStatus = try LoginItem.setEnabled(on)
            } catch {
                loginItemError = String(localized: "Could not change the login item: \(error.localizedDescription)")
                loginStatus = LoginItem.status
            }
            model.prefs.launchAtLogin = loginStatus == .enabled || loginStatus == .requiresApproval
        })
    }

    private func refreshLoginStatus() {
        guard previewLoginStatus == nil else { return }
        loginStatus = LoginItem.status
        if loginStatus != .unavailable {
            let on = loginStatus == .enabled || loginStatus == .requiresApproval
            if model.prefs.launchAtLogin != on { model.prefs.launchAtLogin = on }
        }
    }

    static func reuseLabel(_ minutes: Int) -> String {
        switch minutes {
        case 1: return String(localized: "1 minute")
        case 5: return String(localized: "5 minutes")
        case 15: return String(localized: "15 minutes")
        default: return String(localized: "\(minutes) minutes")
        }
    }

    private func installCLI() {
        do {
            switch try CommandLineTool.install() {
            case .installed(let url):
                cliMessage = String(localized: "Installed. Try “passtunnel status” in Terminal.")
                cliLocation = url
            case .installedNeedsPath(let url):
                cliLocation = url
                cliMessage = String(localized: "Installed in \(url.deletingLastPathComponent().path), which is not on your PATH yet. Add this line to ~/.zprofile:\nexport PATH=\"$HOME/.local/bin:$PATH\"")
            }
        } catch {
            cliMessage = String(localized: "Could not install the command-line tool: \(error.localizedDescription)")
        }
    }
}

/// Live preview of the menu bar title with sample badges in every state.
struct MenuBarPreview: View {
    let palette: BadgePalette
    let showLock: Bool

    var body: some View {
        HStack(spacing: 8) {
            ForEach([false, true], id: \.self) { dark in
                Image(nsImage: MenuBarIcon.rendered(
                    badges: [
                        .init(text: "W", symbol: nil, tone: .connected),
                        .init(text: "H", symbol: nil, tone: .connecting),
                        .init(text: "L", symbol: nil, tone: .disconnected),
                    ],
                    palette: palette, showLock: showLock, locked: true, dark: dark))
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
    static func rendered(badges: [Badge], palette: BadgePalette, showLock: Bool, locked: Bool, dark: Bool, scale: CGFloat = 2) -> NSImage {
        let source = image(badges: badges, palette: palette, showLock: showLock, locked: locked)
        let size = source.size
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width * scale), pixelsHigh: Int(size.height * scale),
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

// MARK: - Notifications

struct NotificationSettings: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section {
                Toggle(isOn: $model.prefs.notifyOnDrop) {
                    SettingLabel(String(localized: "Unexpected disconnects"),
                                 String(localized: "When a connection drops without you disconnecting it, and when it comes back."))
                }
                Toggle(isOn: $model.prefs.notifyHealth) {
                    SettingLabel(String(localized: "Health check failures"),
                                 String(localized: "When a connected VPN stops reaching its health check host."))
                }
                Toggle(isOn: sessionEnabled) {
                    SettingLabel(String(localized: "Session limit"),
                                 String(localized: "Before a profile’s session limit ends the connection."))
                }
                if model.prefs.sessionNotifyMin > 0 {
                    Stepper(value: $model.prefs.sessionNotifyMin, in: 1...120) {
                        Text(String(localized: "Notify \(model.prefs.sessionNotifyMin) minutes before"))
                    }
                }
            } footer: {
                Text(String(localized: "PassTunnel asks for permission the first time it needs to show a notification."))
                    .settingsFooter()
            }
            Section {
                Button(String(localized: "Open Notification Settings…")) {
                    let id = Bundle.main.bundleIdentifier ?? ""
                    if let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=\(id)") {
                        NSWorkspace.shared.open(url)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var sessionEnabled: Binding<Bool> {
        Binding(get: { model.prefs.sessionNotifyMin > 0 },
                set: { model.prefs.sessionNotifyMin = $0 ? 10 : 0 })
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
                ShortcutRow(keys: Hotkeys.Action.toggleDefault.display,
                            title: String(localized: "Connect or disconnect the default profile"))
                    .disabled(!model.prefs.hotkeys)
                ShortcutRow(keys: Hotkeys.Action.code.display,
                            title: model.prefs.autoType ? String(localized: "Type the current code")
                                                        : String(localized: "Copy the current code"))
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
                    SettingLabel(String(localized: "Type the code for me"),
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
                            Text(String(localized: "Turn on PassTunnel in System Settings → Privacy & Security → Accessibility. Until then, the code is copied instead."))
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
        Binding(get: { model.prefs.autoType }, set: { on in
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

// MARK: - Updates (placeholder until Sparkle is integrated)

struct UpdateSettings: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section {
                Toggle(String(localized: "Check for updates automatically"), isOn: $model.prefs.autoUpdate)
                    .disabled(true)
                LabeledContent(String(localized: "Current version"), value: AppInfo.versionString)
                Button(String(localized: "Check Now")) {}
                    .disabled(true)
            } footer: {
                Text(String(localized: "Automatic updates arrive in a future version. Until then, new releases are published on GitHub."))
                    .settingsFooter()
            }
            Section {
                Link(String(localized: "Open Releases Page"), destination: AppInfo.releasesURL)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - About

enum AppInfo {
    static let repositoryURL = URL(string: "https://github.com/Furkanprlk/passtunnel")!
    static let releasesURL = URL(string: "https://github.com/Furkanprlk/passtunnel/releases")!
    static let issuesURL = URL(string: "https://github.com/Furkanprlk/passtunnel/issues")!

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
           let image = NSImage(contentsOf: url) {
            return image
        }
        var dir = Bundle.main.executableURL?.resolvingSymlinksInPath().deletingLastPathComponent()
        for _ in 0..<6 {
            guard let current = dir else { break }
            let candidate = current.appendingPathComponent("Resources/AppIcon.icns")
            if FileManager.default.fileExists(atPath: current.appendingPathComponent("Package.swift").path),
               let image = NSImage(contentsOf: candidate) {
                return image
            }
            dir = current.deletingLastPathComponent()
        }
        if Bundle.main.bundleURL.pathExtension == "app" { return NSApp.applicationIconImage }
        return NSWorkspace.shared.icon(for: .applicationBundle)
    }()
}

struct AboutSettings: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(nsImage: AppInfo.appIcon)
                .resizable()
                .frame(width: 96, height: 96)
                .accessibilityHidden(true)
            VStack(spacing: 4) {
                Text(verbatim: "PassTunnel").font(.title.weight(.bold))
                Text(AppInfo.versionString).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
            }
            Text(String(localized: "Connect your VPN without ever typing a one-time code again."))
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 340)
            HStack(spacing: 16) {
                Link(destination: AppInfo.repositoryURL) {
                    Label(String(localized: "Source Code"), systemImage: "chevron.left.forwardslash.chevron.right")
                }
                Link(destination: AppInfo.issuesURL) {
                    Label(String(localized: "Report an Issue"), systemImage: "exclamationmark.bubble")
                }
            }
            .padding(.top, 4)
            Text(String(localized: "Open source under the MIT License. Bundled VPN tools keep their own licenses (Settings → Helper)."))
                .font(.caption)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 360)
        }
        .padding(30)
        .frame(maxWidth: .infinity)
    }
}
