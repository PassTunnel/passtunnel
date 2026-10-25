import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

// The redesigned main window (behind `NewInterface`): profiles in a sidebar, the selected one in a detail view
// (ProfileDetailView.swift). Sheets, alerts and drag & drop import work as in `MainView`; there is no toast and no
// window subtitle.

struct MainSplitView: View {
    @EnvironmentObject private var model: AppModel
    @State private var dropTargeted = false

    var body: some View {
        NavigationSplitView {
            ProfileSidebar()
                .navigationSplitViewColumnWidth(min: 236, ideal: 272, max: 320)
        } detail: {
            Group {
                if model.profiles.isEmpty {
                    EmptyStateView()
                } else if let p = model.selection.flatMap(model.profile) {
                    ProfileDetailView(profile: p)
                } else {
                    Color.clear
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .modifier(HiddenWindowTitle())
        .overlay { if dropTargeted { DropHighlight() } }
        .onDrop(of: [.fileURL, .image], isTargeted: $dropTargeted) { ImportActions.handleDrop($0) }
        .background {
            Color.clear.sheet(item: $model.editor) { request in
                ProfileEditorView(profileID: request.profileID, newType: request.newType) {
                    model.editor = nil
                    if let id = request.profileID { model.forgetSecrets(id) }
                    model.reload()
                }
                .environmentObject(model)
            }
        }
        .background {
            Color.clear.sheet(item: $model.credentialRequest) { request in
                CredentialSheet(request: request).environmentObject(model)
            }
        }
        .background {
            Color.clear.sheet(isPresented: $model.showOnboarding) {
                OnboardingView().environmentObject(model)
            }
        }
        .alert(item: $model.alert) { alert in
            if alert.opensHelperSettings {
                return Alert(title: Text(alert.title), message: Text(alert.message),
                             primaryButton: .default(Text(String(localized: "Open Helper Settings"))) {
                                 model.settingsTab = .helper
                                 AppDelegate.shared?.showSettings()
                             },
                             secondaryButton: .cancel())
            }
            return Alert(title: Text(alert.title), message: Text(alert.message))
        }
        .profileDeleteConfirmation($model.pendingDelete) { model.delete($0) }
        .onAppear {
            model.markDropsSeen()
            selectWhenNone()
        }
        .onChange(of: model.profiles) { _ in selectWhenNone() }
        // No toast here: VoiceOver still hears what one would have said ("Code copied").
        .onChange(of: model.toast) { toast in
            guard let toast else { return }
            let info: [NSAccessibility.NotificationUserInfoKey: Any] = [
                .announcement: toast.text, .priority: NSAccessibilityPriorityLevel.high.rawValue,
            ]
            NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: info)
        }
    }

    /// The detail always shows a profile while there is one: the default profile, else the first.
    private func selectWhenNone() {
        guard model.selection.flatMap(model.profile) == nil, let p = model.defaultProfile else { return }
        model.selection = p.id
    }
}

/// The profile's name is the detail's title; the window keeps its title for the Window menu and Mission Control.
/// Before macOS 15 the toolbar shows it.
private struct HiddenWindowTitle: ViewModifier {
    func body(content: Content) -> some View {
        if #available(macOS 15, *) {
            content.toolbar(removing: .title)
        } else {
            content
        }
    }
}

// MARK: - Sidebar

/// Search, the profiles (drag to reorder), and a bottom bar with Add and Settings.
struct ProfileSidebar: View {
    @EnvironmentObject private var model: AppModel
    /// Renders on macOS 26 draw the sidebar outside a split view, where the search field would go to the toolbar;
    /// they draw it in its place themselves (RenderSnapshots).
    var previewWithoutSearch = false

    var body: some View {
        let items = model.filteredProfiles
        List(selection: $model.selection) {
            Section {
                ForEach(items) { p in
                    SidebarRow(profile: p)
                        .tag(p.id)
                }
                .onMove(perform: model.searchText.isEmpty ? { model.move(fromOffsets: $0, toOffset: $1) } : nil)
                if items.isEmpty && !model.searchText.isEmpty {
                    Text(String(localized: "No profiles match “\(model.searchText)”."))
                        .typography(.hint)
                        .foregroundStyle(Palette.fg2)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.vertical, Spacing.xs)
                }
            } header: {
                Text(String(localized: "Profiles"))
            }
        }
        .listStyle(.sidebar)
        .modifier(SidebarSearch(enabled: !previewWithoutSearch, text: $model.searchText))
        .contextMenu(forSelectionType: String.self) { ids in
            if let id = ids.first, let p = model.profile(id) {
                ProfileMenuItems(profile: p)
            }
        } primaryAction: { ids in
            // Return or double click: what the detail's main button does.
            if let id = ids.first, let p = model.profile(id) { model.runAction(p) }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            HStack {
                AddMenu()
                    .labelStyle(.iconOnly)
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                Spacer()
                SettingsGear()
            }
            .font(.system(size: 15))
            .foregroundStyle(Palette.fg)
            .padding(.horizontal, Spacing.m)
            .padding(.vertical, Spacing.xs)
        }
    }
}

/// Always there, at the top of the sidebar.
private struct SidebarSearch: ViewModifier {
    let enabled: Bool
    @Binding var text: String

    func body(content: Content) -> some View {
        if enabled {
            content.searchable(text: $text, placement: .sidebar, prompt: Text(String(localized: "Search profiles")))
        } else {
            content
        }
    }
}

private struct SettingsGear: View {
    var body: some View {
        Group {
            if #available(macOS 14, *) {
                SettingsLink { icon }
            } else {
                Button { AppDelegate.shared?.showSettings() } label: { icon }
            }
        }
        .buttonStyle(.borderless)
        .help(String(localized: "Settings"))
        .accessibilityLabel(String(localized: "Settings"))
        .accessibilityIdentifier("main.settings")
    }

    private var icon: some View {
        Image(systemName: "gearshape").frame(width: 28, height: 28).contentShape(Rectangle())
    }
}

/// Name, the status in the state's color with its dot, and the live code on the right. No icon and no buttons:
/// actions are in the detail, the context menu and the Profile menu.
struct SidebarRow: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile

    var body: some View {
        let status = model.displayStatus(profile)
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                // `primary` rather than `fg`: it turns white on a selected row's accent color on macOS 13 too.
                Text(verbatim: profile.name)
                    .typography(.bodyEmphasized)
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
                ProfileStatusRow(status: status, now: model.previewNow)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if model.hasCode(profile) {
                SidebarCode(profile: profile)
            }
        }
        .padding(.vertical, 5)
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: profile.name))
        .accessibilityValue(Text(verbatim: accessibilityValue(status)))
        .accessibilityIdentifier("profile.\(profile.id)")
    }

    /// "Connected · 1h 12m, 4 8 2, 9 1 3".
    private func accessibilityValue(_ status: DisplayStatus) -> String {
        var parts = [status.summary(at: model.now)]
        if model.hasCode(profile) {
            if model.isCodeLocked(profile) || model.prefs.hideCodes {
                parts.append(String(localized: "Code hidden"))
            } else if let c = model.code(for: profile, at: model.now) {
                parts.append(GroupedCodeText.spoken(c.code))
            }
        }
        return parts.joined(separator: ", ")
    }
}

/// The current code in 13 pt SF Mono, "••• •••" while it is locked or hidden. Copying is in the detail and the
/// menus.
private struct SidebarCode: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let date = model.previewNow ?? context.date
            let digits = max(6, profile.totp.digits)
            if model.isCodeLocked(profile) {
                code(String(repeating: "0", count: digits), hidden: true)
            } else if let c = model.code(for: profile, at: date) {
                code(c.code, hidden: model.prefs.hideCodes)
            }
        }
    }

    @ViewBuilder private func code(_ text: String, hidden: Bool) -> some View {
        if hidden {
            GroupedCodeText(code: text, hidden: true, style: .rowCode).rowForeground(Palette.fg3)
        } else {
            GroupedCodeText(code: text, style: .rowCode).foregroundStyle(.primary)
        }
    }
}

// MARK: - Commands

/// The Profile menu of the redesigned window: ⌘↩ runs the detail's main button, ⌘C copies the code, ⇧⌘C the
/// password and code, ⌘E edits. Off while a sheet is open; ⌘C in a text field never copies a code.
struct SplitWindowCommands: View {
    @ObservedObject var model: AppModel

    var body: some View {
        let selected = model.selection.flatMap(model.profile)
        let blocked = model.editor != nil || model.credentialRequest != nil || model.showOnboarding
        Button(String(localized: "Connect or Disconnect")) { selected.map(model.runAction) }
            .keyboardShortcut(.return, modifiers: [.command])
            .disabled(selected == nil || blocked)
        Button(String(localized: "Copy Code")) {
            if let p = selected, !Self.textFieldHasKey { model.copyCode(p) }
        }
        .keyboardShortcut("c")
        .disabled(selected.map(model.hasCode) != true || blocked)
        Button(String(localized: "Copy Password + Code")) { selected.map(model.copyPasswordAndCode) }
            .keyboardShortcut("c", modifiers: [.command, .shift])
            .disabled(selected?.passwordMode != .keychain || blocked)
        Button(String(localized: "Edit…")) { selected.map(model.edit) }
            .keyboardShortcut("e")
            .disabled(selected == nil || blocked)
    }

    /// ⌘C typed in a text field (the search field) with nothing selected: Edit → Copy is off then, and the key
    /// reaches Copy Code, which leaves it to the field.
    private static var textFieldHasKey: Bool {
        NSApp.currentEvent?.type == .keyDown && NSApp.keyWindow?.firstResponder is NSText
    }
}
