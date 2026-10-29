import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

// The main window: profiles in a sidebar, the selected one in a detail view (ProfileDetailView.swift), the first-run
// and add view without one (FirstRunView.swift), and the sheets, alerts and drag & drop import of the window. There is
// no toast, no window subtitle and no onboarding sheet.

struct MainSplitView: View {
    @EnvironmentObject private var model: AppModel
    @State private var dropTargeted = false
    /// Renders: whether the question about opening at login shows (nil: as it would).
    var previewLoginQuestion: Bool?

    var body: some View {
        NavigationSplitView {
            ProfileSidebar()
                .navigationSplitViewColumnWidth(min: 236, ideal: 272, max: 320)
        } detail: {
            SplitDetail(previewLoginQuestion: previewLoginQuestion)
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
            Color.clear.sheet(item: $model.overlapRequest) { request in
                OverlapSheet(request: request).environmentObject(model)
            }
        }
        .alert(item: $model.alert) { alert in
            if alert.opensHelperSettings {
                return Alert(
                    title: Text(alert.title), message: Text(alert.message),
                    primaryButton: .default(Text(String(localized: "Open Helper Settings"))) {
                        model.settingsTab = .helper
                        AppDelegate.shared?.showSettings()
                    },
                    secondaryButton: .cancel())
            }
            return Alert(title: Text(alert.title), message: Text(alert.message))
        }
        .profileDeleteConfirmation($model.pendingDelete) { model.delete($0) }
        .unsupportedDeleteConfirmation($model.pendingDeleteUnsupported) { model.delete($0) }
        .onAppear {
            model.markDropsSeen()
            selectWhenNone()
        }
        .onChange(of: model.profiles) { profiles in
            if model.hasNoProfiles { model.addingProfile = false }
            selectWhenNone()
        }
        // Selecting a profile (the sidebar, an import) closes the add view and leaves an import review (nothing was
        // written); Escape there selects one again, and so does the end of a review.
        .onChange(of: model.selection) { selection in
            if selection != nil {
                model.addingProfile = false
                model.importReview = nil
            }
        }
        .onChange(of: model.addingProfile) { adding in
            if !adding { selectWhenNone() }
        }
        .onChange(of: model.importReview == nil) { ended in if ended { selectWhenNone() } }
        // No toast here: VoiceOver still hears what one would have said ("Code copied").
        .onChange(of: model.toast) { toast in
            guard let toast else { return }
            let info: [NSAccessibility.NotificationUserInfoKey: Any] = [
                .announcement: toast.text, .priority: NSAccessibilityPriorityLevel.high.rawValue
            ]
            NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: info)
        }
    }

    /// The detail always shows a profile while there is one, the add view is closed and no import is under review:
    /// the default profile, else the first.
    private func selectWhenNone() {
        guard !model.addingProfile, model.importReview == nil, model.selection.flatMap(model.profile) == nil,
            model.selection.flatMap(model.unsupportedProfile) == nil, let p = model.defaultProfile
        else { return }
        model.selection = p.id
    }
}

/// The import under review (`AppModel.importReview`), the first-run view while there are no profiles, the add view
/// (`AppModel.addingProfile`), else the selected profile;
/// under it the question about opening at login, until it is answered.
struct SplitDetail: View {
    @EnvironmentObject private var model: AppModel
    var previewLoginQuestion: Bool?

    var body: some View {
        Group {
            if let review = model.importReview {
                ImportReviewView(review: review)
                    .id(ObjectIdentifier(review))
            } else if model.hasNoProfiles {
                FirstRunView(isFirstRun: true)
            } else if model.addingProfile {
                FirstRunView(isFirstRun: false)
            } else if let p = model.selection.flatMap(model.profile) {
                ProfileDetailView(profile: p)
            } else if let u = model.selection.flatMap(model.unsupportedProfile) {
                UnsupportedProfileDetail(profile: u)
            } else {
                Color.clear
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .safeAreaInset(edge: .bottom, spacing: 0) { OpenAtLoginQuestion(preview: previewLoginQuestion) }
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

/// Shown over the window while files or images are dragged over it.
struct DropHighlight: View {
    var body: some View {
        RoundedRectangle(cornerRadius: 12, style: .continuous)
            .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 3, dash: [8, 5]))
            .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay {
                Label(String(localized: "Drop to import"), systemImage: "square.and.arrow.down")
                    .font(.title3.weight(.semibold))
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(.regularMaterial, in: Capsule())
            }
            .padding(8)
            .allowsHitTesting(false)
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
        let unsupportedItems = model.filteredUnsupported
        List(selection: $model.selection) {
            Section {
                ForEach(items) { p in
                    SidebarRow(profile: p)
                        .tag(p.id)
                }
                .onMove(perform: model.searchText.isEmpty ? { model.move(fromOffsets: $0, toOffset: $1) } : nil)
                ForEach(unsupportedItems) { p in
                    UnsupportedSidebarRow(profile: p)
                        .tag(p.id)
                }
                if model.hasNoProfiles {
                    VStack(spacing: 2) {
                        Text(String(localized: "No profiles yet."))
                        Text(String(localized: "Add one to get started."))
                    }
                    .typography(.body)
                    .foregroundStyle(Palette.fg2)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 28)
                    .accessibilityElement(children: .combine)
                } else if items.isEmpty && unsupportedItems.isEmpty && !model.searchText.isEmpty {
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
            } else if let id = ids.first, let u = model.unsupportedProfile(id) {
                Button(String(localized: "Delete…"), role: .destructive) { model.pendingDeleteUnsupported = u }
            }
        } primaryAction: { ids in
            // Return or double click: what the detail's main button does (nothing where it is disabled).
            if let id = ids.first, let p = model.profile(id), model.displayStatus(p).allowsAction { model.runAction(p) }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            HStack {
                AddButton()
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

/// The sidebar's context menu.
struct ProfileMenuItems: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile

    var body: some View {
        let p = profile
        Button(String(localized: "Edit…")) { model.edit(p) }
            .disabled(model.editRefusal(p) != nil)
        Divider()
        Button(String(localized: "Copy Code")) { model.copyCode(p) }
            .disabled(model.code(for: p) == nil && !model.isCodeLocked(p))
        Button(String(localized: "Copy Password + Code")) { model.copyPasswordAndCode(p) }
            .disabled(p.passwordMode != .keychain)
        Divider()
        Button(String(localized: "Share…")) { model.share(p) }
        Button(String(localized: "Show Log")) { model.showLog(p) }
        Divider()
        Toggle(String(localized: "Pin to Menu Bar"), isOn: Binding(get: { p.pinned }, set: { _ in model.togglePin(p) }))
        Toggle(String(localized: "Default Profile"), isOn: Binding(get: { model.isDefault(p) }, set: { _ in model.makeDefault(p) }))
        Divider()
        Button(String(localized: "Delete…"), role: .destructive) { model.pendingDelete = p }
    }
}

/// Opens the add view in the detail; the File menu keeps the separate add and import items.
private struct AddButton: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Button {
            model.showAddView()
        } label: {
            Image(systemName: "plus").frame(width: 28, height: 28).contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .help(String(localized: "Add a VPN"))
        .accessibilityLabel(String(localized: "Add a VPN"))
        .accessibilityIdentifier("main.add")
    }
}

private struct SettingsGear: View {
    var body: some View {
        Group {
            if #available(macOS 14, *) {
                SettingsLink { icon }
            } else {
                Button {
                    AppDelegate.shared?.showSettings()
                } label: {
                    icon
                }
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
            // Not for a profile this Mac cannot connect: its row is the note ("Requires macOS 15.4 or later").
            if model.hasCode(profile), status.allowsAction {
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
            if model.codesMasked(profile, at: model.now) {
                parts.append(String(localized: "Code hidden"))
            } else if let c = model.code(for: profile, at: model.now) {
                parts.append(GroupedCodeText.spoken(c.code))
            }
        }
        return parts.joined(separator: ", ")
    }
}

/// The current code in 13 pt SF Mono, "••• •••" while the code card masks it (`AppModel.codesMasked`: locked, hidden or
/// protected, unless a click in the card shows it). Copying is in the detail and the menus.
private struct SidebarCode: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let date = model.previewNow ?? context.date
            let digits = max(6, profile.totp.digits)
            if model.codesMasked(profile, at: date) {
                code(String(repeating: "0", count: digits), hidden: true)
            } else if let c = model.code(for: profile, at: date) {
                code(c.code, hidden: false)
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

/// The Profile menu of the main window: ⌘↩ runs the detail's main button, ⌘C copies the code, ⇧⌘C the
/// password and code, ⌘E edits. Off while a sheet is open; ⌘C in a text field never copies a code.
struct SplitWindowCommands: View {
    @ObservedObject var model: AppModel

    var body: some View {
        let selected = model.selection.flatMap(model.profile)
        let blocked =
            model.editor != nil || model.credentialRequest != nil || model.importReview != nil
            || model.overlapRequest != nil
        Button(String(localized: "Connect or Disconnect")) { selected.map(model.runAction) }
            .keyboardShortcut(.return, modifiers: [.command])
            .disabled(selected.map { !model.displayStatus($0).allowsAction } ?? true || blocked)
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
            .disabled(selected.map { model.editRefusal($0) != nil } ?? true || blocked)
    }

    /// ⌘C typed in a text field (the search field) with nothing selected: Edit → Copy is off then, and the key
    /// reaches Copy Code, which leaves it to the field.
    private static var textFieldHasKey: Bool {
        NSApp.currentEvent?.type == .keyDown && NSApp.keyWindow?.firstResponder is NSText
    }
}
