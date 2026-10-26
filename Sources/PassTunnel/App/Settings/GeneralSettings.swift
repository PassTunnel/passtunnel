import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// Settings → General (decision D-12), in the cards of the redesign and shared by both interfaces: General and
/// Connection as designed, then Notifications, Security, the menu bar badges (only while the current menu bar is in
/// use: the panel of the new interface has none, decision D-6) and Other. The footer holds what the About tab had.
struct GeneralSettings: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openURL) private var openURL
    @State private var cliLocation: URL? = CommandLineTool.installedLocation
    @State private var cliMessage: String?
    @State private var loginItemError: String?
    @State private var loginStatus: LoginItemStatus
    @State private var showLicenses = false
    /// Screenshots: a fixed login item status instead of asking the system.
    private let previewLoginStatus: LoginItemStatus?
    /// Screenshots: the whole page instead of the scrolling window.
    private let fullHeight: Bool
    private let licensesAvailable: Bool
    private let loginTimer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    /// The page's height in the Settings window; it scrolls below that.
    static let height: CGFloat = 600

    init(previewLoginStatus: LoginItemStatus? = nil, fullHeight: Bool = false,
         licensesAvailable: Bool = !BundledTools.licenseFiles().isEmpty) {
        self.previewLoginStatus = previewLoginStatus
        self.fullHeight = fullHeight
        self.licensesAvailable = licensesAvailable
        _loginStatus = State(initialValue: previewLoginStatus ?? LoginItem.status)
    }

    var body: some View {
        Group {
            if fullHeight {
                page
            } else {
                ScrollView { page }.frame(height: Self.height)
            }
        }
        .onAppear(perform: refreshLoginStatus)
        .onReceive(loginTimer) { _ in
            // System Settings may approve or remove the item while this pane is open.
            if loginStatus == .requiresApproval { refreshLoginStatus() }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            refreshLoginStatus()
        }
        .sheet(isPresented: $showLicenses) { LicensesView() }
    }

    private var page: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            general
            connection
            notifications
            security
            menuBar
            other
            footer
        }
        .padding(Spacing.l)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: cards

    private var general: some View {
        SettingsGroup(String(localized: "General"),
                      footer: String(localized: "A click shows a hidden code for \(Int(CodeCard.revealDuration)) seconds; copying never shows it.")
                          + " " + String(localized: "The clipboard is cleared only if it still holds what PassTunnel copied.")) {
            SettingsRow {
                SettingsSwitch(String(localized: "Open at login, in the menu bar"), isOn: launchAtLogin)
                    .disabled(loginStatus == .unavailable)
                loginStatusDetail
            }
            SettingsDivider()
            SettingsRow {
                SettingsSwitch(String(localized: "Show the Dock icon"), isOn: $model.prefs.showInDock)
            }
            SettingsDivider()
            SettingsRow {
                SettingsSwitch(String(localized: "Hide codes until clicked"), isOn: $model.prefs.hideCodes)
            }
            SettingsDivider()
            SettingsPickerRow(String(localized: "Clear copied code"), selection: $model.prefs.clearClipboardAfter,
                              identifier: "settings.clearClipboard") {
                ForEach(Preferences.clearClipboardChoices, id: \.self) { seconds in
                    Text(Self.clearLabel(seconds)).tag(seconds)
                }
            }
        }
    }

    private var connection: some View {
        SettingsGroup(String(localized: "Connection"),
                      footer: String(localized: "A code that was already sent is never sent again: PassTunnel always waits for the next one.")) {
            SettingsRow {
                SettingsSwitch(String(localized: "Wait for a fresh code"),
                               String(localized: "If the current code has \(Preferences.freshCodeSeconds) s or less left"),
                               isOn: $model.prefs.waitForFreshCode, identifier: "settings.waitForFreshCode")
            }
            SettingsDivider()
            SettingsRow {
                SettingsSwitch(String(localized: "Notify when a connection drops"), isOn: $model.prefs.notifyOnDrop)
            }
        }
    }

    private var notifications: some View {
        SettingsGroup(String(localized: "Notifications"),
                      footer: String(localized: "PassTunnel asks for permission the first time it needs to show a notification.")) {
            SettingsRow {
                SettingsSwitch(String(localized: "Health check failures"),
                               String(localized: "When a connected VPN stops reaching its health check host."),
                               isOn: $model.prefs.notifyHealth)
            }
            SettingsDivider()
            SettingsRow {
                SettingsSwitch(String(localized: "Session limit"),
                               String(localized: "Before a profile’s session limit ends the connection."),
                               isOn: sessionEnabled)
            }
            if model.prefs.sessionNotifyMin > 0 {
                SettingsDivider()
                SettingsRow {
                    Stepper(value: $model.prefs.sessionNotifyMin, in: 1...120) {
                        Text(String(localized: "Notify \(model.prefs.sessionNotifyMin) minutes before"))
                            .typography(.body)
                            .foregroundStyle(Palette.fg)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            SettingsDivider()
            SettingsRow {
                Button(String(localized: "Open Notification Settings…")) {
                    let id = Bundle.main.bundleIdentifier ?? ""
                    if let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=\(id)") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .buttonStyle(.secondaryCapsule(.compact))
            }
        }
    }

    private var security: some View {
        SettingsGroup(String(localized: "Security"),
                      footer: String(localized: "For profiles set to “\(ConfirmationWording.settingName)”, one confirmation with Touch ID or your Mac password is valid this long for the same profile. Sleep and locking the screen end it.")) {
            SettingsPickerRow(String(localized: "Ask again after"), selection: $model.prefs.authReuseMinutes,
                              identifier: "settings.authReuse") {
                ForEach(Preferences.authReuseChoices, id: \.self) { minutes in
                    Text(Self.reuseLabel(minutes)).tag(minutes)
                }
            }
        }
    }

    /// The badges of the menu bar, in the current interface and in the new one (which has no lock symbol).
    private var menuBar: some View {
        SettingsGroup(String(localized: "Menu bar")) {
            SettingsPickerRow(String(localized: "Badge colors"), selection: $model.prefs.badgePalette) {
                ForEach(BadgePalette.allCases, id: \.self) { palette in
                    Text(palette.displayName).tag(palette)
                }
            }
            SettingsDivider()
            SettingsRow {
                HStack(spacing: Spacing.s) {
                    SettingsRowTitle(String(localized: "Preview"))
                    MenuBarPreview(palette: model.prefs.badgePalette, showLock: model.prefs.showLock && !NewInterface.isEnabled)
                }
            }
            if !NewInterface.isEnabled {
                SettingsDivider()
                SettingsRow {
                    SettingsSwitch(String(localized: "Show lock symbol"), isOn: $model.prefs.showLock)
                }
            }
        }
    }

    private var other: some View {
        SettingsGroup(String(localized: "Other"),
                      footer: String(localized: "Use “passtunnel connect”, “passtunnel code” and more from Terminal.")) {
            SettingsRow {
                HStack(spacing: Spacing.s) {
                    SettingsRowTitle(String(localized: "Appearance"))
                    Picker(String(localized: "Appearance"), selection: $model.prefs.appearance) {
                        Text(String(localized: "System")).tag(AppAppearance.system)
                        Text(String(localized: "Light")).tag(AppAppearance.light)
                        Text(String(localized: "Dark")).tag(AppAppearance.dark)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                }
            }
            SettingsDivider()
            SettingsRow {
                HStack(spacing: Spacing.s) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(String(localized: "Command-line tool")).typography(.body).foregroundStyle(Palette.fg)
                        Text(cliLocation.map { String(localized: "Installed at \($0.path)") }
                             ?? String(localized: "Not installed"))
                            .typography(.hint)
                            .foregroundStyle(Palette.fg2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    Button(cliLocation == nil ? String(localized: "Install…") : String(localized: "Reinstall")) { installCLI() }
                        .buttonStyle(.secondaryCapsule(.compact))
                }
                if let cliMessage {
                    Text(cliMessage)
                        .typography(.hint)
                        .foregroundStyle(Palette.fg2)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
        }
    }

    /// Licenses (of the bundled tools, as in Helper), the privacy policy on the website, the source code, and the
    /// version.
    private var footer: some View {
        HStack(spacing: Spacing.m) {
            Button(String(localized: "Licenses")) { showLicenses = true }
                .disabled(!licensesAvailable)
            Button(String(localized: "Privacy policy")) { openURL(AppInfo.privacyURL) }
                .accessibilityAddTraits(.isLink)
            Button(String(localized: "Source code")) { openURL(AppInfo.repositoryURL) }
                .accessibilityAddTraits(.isLink)
            Text(AppInfo.versionString).textSelection(.enabled)
        }
        .buttonStyle(FooterLinkStyle())
        .typography(.body)
        .foregroundStyle(Palette.fg2)
        .padding(.horizontal, Spacing.xxs)
    }

    // MARK: open at login

    /// Under the switch: the approval System Settings still waits for, why the switch is off, or what failed.
    @ViewBuilder private var loginStatusDetail: some View {
        switch loginStatus {
        case .requiresApproval:
            HStack(spacing: Spacing.xs) {
                Label(String(localized: "Needs approval in Login Items."), systemImage: "exclamationmark.triangle.fill")
                    .typography(.hint)
                    .foregroundStyle(Palette.amber)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button(String(localized: "Open Login Items…")) { LoginItem.openSystemSettings() }
                    .buttonStyle(.secondaryCapsule(.small))
            }
        case .unavailable:
            SettingsHint(String(localized: "Available when PassTunnel runs as an app from the Applications folder."))
        case .enabled, .disabled:
            EmptyView()
        }
        if let loginItemError {
            Text(loginItemError).typography(.hint).foregroundStyle(Palette.red).fixedSize(horizontal: false, vertical: true)
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

    private var sessionEnabled: Binding<Bool> {
        Binding(get: { model.prefs.sessionNotifyMin > 0 },
                set: { model.prefs.sessionNotifyMin = $0 ? 10 : 0 })
    }

    // MARK: labels and actions

    static func reuseLabel(_ minutes: Int) -> String {
        switch minutes {
        case 1: return String(localized: "1 minute")
        case 5: return String(localized: "5 minutes")
        case 15: return String(localized: "15 minutes")
        default: return String(localized: "\(minutes) minutes")
        }
    }

    static func clearLabel(_ seconds: Int) -> String {
        switch seconds {
        case 30: return String(localized: "After 30 seconds")
        case 60: return String(localized: "After 1 minute")
        case 120: return String(localized: "After 2 minutes")
        default: return String(localized: "\(seconds) seconds")
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

// MARK: - components

/// A group of the page: the small uppercase label, a card of rows, and a note under the card.
private struct SettingsGroup<Rows: View>: View {
    let label: String
    var footer: String?
    @ViewBuilder var rows: Rows

    init(_ label: String, footer: String? = nil, @ViewBuilder rows: () -> Rows) {
        self.label = label
        self.footer = footer
        self.rows = rows()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel(label).padding(.leading, Spacing.xxs)
            EditorCard(spacing: 0, insets: EdgeInsets(top: 2, leading: 0, bottom: 2, trailing: 0)) { rows }
            if let footer {
                SettingsHint(footer).padding(.horizontal, Spacing.xxs)
            }
        }
    }
}

/// A row of a card, as the design draws them: at least 44 pt high, 14 pt in from the card's sides; anything after
/// the first view (a status, a message) goes under it.
private struct SettingsRow<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xxs) { content }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
    }
}

/// The hairline between two rows.
private struct SettingsDivider: View {
    var body: some View {
        Rectangle().fill(Palette.line).frame(height: Elevation.hairline).padding(.horizontal, 14)
    }
}

/// The words of a row whose control carries its own accessibility label.
private struct SettingsRowTitle: View {
    let title: String

    init(_ title: String) {
        self.title = title
    }

    var body: some View {
        Text(verbatim: title)
            .typography(.body)
            .foregroundStyle(Palette.fg)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityHidden(true)
    }
}

/// 12 pt `fg2` text under a row or a card.
private struct SettingsHint: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(verbatim: text)
            .typography(.hint)
            .foregroundStyle(Palette.fg2)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// The design's monochrome switch at the trailing edge, with the words (and a second line in `fg2`) before it.
private struct SettingsSwitch: View {
    let title: String
    let subtitle: String?
    @Binding var isOn: Bool
    /// `accessibilityIdentifier` of the switch.
    var identifier: String?

    init(_ title: String, _ subtitle: String? = nil, isOn: Binding<Bool>, identifier: String? = nil) {
        self.title = title
        self.subtitle = subtitle
        _isOn = isOn
        self.identifier = identifier
    }

    var body: some View {
        Toggle(isOn: $isOn) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: title).typography(.body).foregroundStyle(Palette.fg)
                if let subtitle {
                    Text(verbatim: subtitle).typography(.hint).foregroundStyle(Palette.fg2)
                }
            }
        }
        .toggleStyle(EditorSwitchStyle())
        .accessibilityIdentifier(identifier ?? "")
    }
}

/// A row with a popup at the trailing edge.
private struct SettingsPickerRow<Value: Hashable, Options: View>: View {
    let title: String
    @Binding var selection: Value
    var identifier: String?
    @ViewBuilder var options: Options

    init(_ title: String, selection: Binding<Value>, identifier: String? = nil, @ViewBuilder options: () -> Options) {
        self.title = title
        _selection = selection
        self.identifier = identifier
        self.options = options()
    }

    var body: some View {
        SettingsRow {
            HStack(spacing: Spacing.s) {
                SettingsRowTitle(title)
                Picker(title, selection: $selection) { options }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                    .accessibilityIdentifier(identifier ?? "")
            }
        }
    }
}

/// The footer's links: `fg2` words, underlined, without a button's shape.
private struct FooterLinkStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .underline()
            .lineLimit(1)
            .fixedSize()
            .contentShape(Rectangle())
            .contentShape(.focusEffect, RoundedRectangle(cornerRadius: 3, style: .continuous))
            .opacity(!isEnabled ? 0.38 : configuration.isPressed ? 0.6 : 1)
    }
}
