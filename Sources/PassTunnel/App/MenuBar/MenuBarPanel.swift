import AppKit
import Carbon.HIToolbox
import PassTunnelCore
import PassTunnelKit
import SwiftUI

// The menu bar of the new interface (`NewInterface`, decision D-23): the shield glyph, and a panel with one switch
// per profile, the copy items and the app items (docs/APP.md, Menu bar). The current menu is `MenuBarMenu`.

/// The status item: the shield glyph, with a dot while a drop has not been seen, and its VoiceOver label
/// ("PassTunnel, 2 connected").
struct MenuBarShieldLabel: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(nsImage: MenuBarIcon.shield(dropped: !model.droppedUnseen.isEmpty))
            .accessibilityLabel(Text(MenuBarPanel.statusItemLabel(model)))
            .onAppear {
                AppDelegate.shared?.openMainWindowAction = { openWindow(id: "main") }
            }
            .background { SettingsOpenerRegistration() }
    }
}

extension AppModel {
    /// Profiles whose connection is up (with or without a problem).
    var connectedCount: Int { profiles.filter { state($0.id).isConnected }.count }

    /// The profile the panel's copy items are for (`CopyTarget`): the default profile, else the one that sent a code
    /// last, else the first with a code.
    var copyTarget: Profile? {
        CopyTarget.profile(in: profiles, defaultID: prefs.defaultProfile, hasCode: { hasCode($0) },
                           lastCodeSent: { previewStates == nil ? connections.lastCodeSent($0) : nil })
    }
}

/// What can be focused and used in the panel, in the order the arrow keys go through it.
private enum PanelItem: Hashable {
    case profile(String)
    case add, copyCode, copyPasswordAndCode, typeCode, open, settings, quit

    /// For UI automation (docs/APP.md, Accessibility).
    var identifier: String {
        switch self {
        case .profile(let id): return "menu.\(id).toggle"
        case .add: return "menu.add"
        case .copyCode: return "menu.copyCode"
        case .copyPasswordAndCode: return "menu.copyPasswordCode"
        case .typeCode: return "menu.typeCode"
        case .open: return "menu.open"
        case .settings: return "menu.settings"
        case .quit: return "menu.quit"
        }
    }
}

/// The panel under the shield (`.menuBarExtraStyle(.window)`, 330 pt wide; the window and its material are the
/// system's): a header with the number of connections, one row per profile (more than four scroll), the copy items for
/// `AppModel.copyTarget` (and "Type … code" while auto-type is on), then Open PassTunnel, Settings… and Quit. The
/// panel stays open after a switch; the other items close it first, as a menu would.
struct MenuBarPanel: View {
    @EnvironmentObject private var model: AppModel
    /// Pins the time and leaves out the keyboard handling (renders).
    var now: Date?

    @FocusState private var focus: PanelItem?
    @State private var hovered: PanelItem?
    @State private var window = PanelWindow()

    /// Rows shown before the list scrolls, and their minimum height.
    static let visibleRows = 4
    static let rowHeight: CGFloat = 44

    var body: some View {
        let profiles = model.profiles
        let target = model.copyTarget
        let actions = copyActions(target)
        VStack(alignment: .leading, spacing: 0) {
            header
            if profiles.isEmpty {
                Text(String(localized: "No VPN profiles yet"))
                    .typography(.body)
                    .foregroundStyle(Palette.fg2)
                    .padding(.horizontal, 10)
                    .frame(minHeight: 30)
                item(.add, String(localized: "Add a VPN…"))
            } else {
                rows(profiles)
            }
            separator
            if let target, !actions.isEmpty {
                ForEach(actions, id: \.self) { action in
                    switch action {
                    case .copyCode: item(.copyCode, String(localized: "Copy \(target.name) code"), shortcut: "⌘C")
                    case .copyPasswordAndCode:
                        item(.copyPasswordAndCode, String(localized: "Copy \(target.name) password + code"), shortcut: "⇧⌘C")
                    default: item(.typeCode, String(localized: "Type \(target.name) code"))
                    }
                }
                separator
            }
            item(.open, String(localized: "Open PassTunnel"))
            item(.settings, String(localized: "Settings…"), shortcut: "⌘,")
            item(.quit, String(localized: "Quit"), shortcut: "⌘Q")
        }
        .padding(6)
        .frame(width: 330)
        .background {
            if now == nil { PanelKeys(window: window, handle: handle) }
        }
        .onDisappear {
            guard now == nil else { return }
            focus = nil
            hovered = nil
            // The rows showed the drop; the dot on the shield goes with it.
            model.markDropsSeen()
        }
    }

    /// The status item's VoiceOver label: "PassTunnel, 2 connected", and the drop the dot stands for.
    static func statusItemLabel(_ model: AppModel) -> String {
        let connected = model.connectedCount
        let label = connected == 0 ? String(localized: "PassTunnel, not connected")
                                   : String(localized: "PassTunnel, \(connected) connected")
        return model.droppedUnseen.isEmpty ? label : String(localized: "\(label), a connection dropped")
    }

    // MARK: parts

    private var header: some View {
        let connected = model.connectedCount
        let title = connected == 0 ? "PassTunnel" : String(localized: "PassTunnel · \(connected) connected")
        return Text(title)
            .typography(.buttonSmall)
            .foregroundStyle(Palette.fg2)
            .padding(.horizontal, 10)
            .frame(maxWidth: .infinity, minHeight: 30, alignment: .leading)
            .accessibilityAddTraits(.isHeader)
    }

    private var separator: some View {
        Rectangle()
            .fill(Palette.line)
            .frame(height: Elevation.hairline)
            .padding(.vertical, 5)
            .padding(.horizontal, 10)
            .accessibilityHidden(true)
    }

    @ViewBuilder
    private func rows(_ profiles: [Profile]) -> some View {
        let list = VStack(spacing: 0) {
            ForEach(profiles) { row($0) }
        }
        if profiles.count > Self.visibleRows {
            ScrollViewReader { proxy in
                ScrollView { list }
                    // Half a row more, so the list shows it goes on.
                    .frame(height: (CGFloat(Self.visibleRows) + 0.5) * Self.rowHeight)
                    .onChange(of: focus) { item in
                        guard let item, case .profile = item else { return }
                        proxy.scrollTo(item)
                    }
            }
        } else {
            list
        }
    }

    /// Dot, name and status, the code, and the switch. For VoiceOver the row is a switch named "Connect Work" or
    /// "Disconnect Work", with the status and the code as its hint.
    private func row(_ p: Profile) -> some View {
        let status = model.displayStatus(p)
        let on = isOn(p)
        return chrome(.profile(p.id), minHeight: Self.rowHeight) {
            HStack(spacing: 10) {
                ProfileStatusDot(status: status, size: 8)
                VStack(alignment: .leading, spacing: 1) {
                    Text(p.name)
                        .typography(.bodyEmphasized)
                        .foregroundStyle(Palette.fg)
                        .fixedSize(horizontal: false, vertical: true)
                    PanelStatusText(status: status, now: now)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                PanelCode(profile: p, now: now)
                PanelSwitch(isOn: on)
            }
            .padding(.vertical, 5)
        }
        .id(PanelItem.profile(p.id))
        .accessibilityRepresentation {
            Toggle(isOn: Binding(get: { on }, set: { _ in toggle(p) })) {
                Text(on ? String(localized: "Disconnect \(p.name)") : String(localized: "Connect \(p.name)"))
            }
            .toggleStyle(.switch)
            .accessibilityHint(Text(hint(p, status)))
            .accessibilityIdentifier(PanelItem.profile(p.id).identifier)
        }
    }

    /// A menu item: the title, and its shortcut in `fg3`.
    private func item(_ item: PanelItem, _ title: String, shortcut: String? = nil) -> some View {
        chrome(item, minHeight: 30) {
            HStack(spacing: 10) {
                Text(title)
                    .typography(.body)
                    .foregroundStyle(Palette.fg)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                if let shortcut {
                    Text(verbatim: shortcut).typography(.body).foregroundStyle(Palette.fg3)
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(title))
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { activate(item) }
        .accessibilityIdentifier(item.identifier)
    }

    /// What rows and items share: the 8 pt rounded highlight under the pointer, a click, and keyboard focus with
    /// the system focus ring (arrow keys and Tab).
    private func chrome<Content: View>(_ item: PanelItem, minHeight: CGFloat,
                                       @ViewBuilder _ content: () -> Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: Radius.field, style: .continuous)
        return content()
            .padding(.horizontal, 10)
            .frame(maxWidth: .infinity, minHeight: minHeight, alignment: .leading)
            .background(shape.fill(hovered == item ? Palette.selection : .clear))
            .contentShape(shape)
            .onHover { inside in
                if inside {
                    hovered = item
                } else if hovered == item {
                    hovered = nil
                }
            }
            .onTapGesture {
                // A click leaves no focus ring behind; the keyboard brings it back.
                focus = nil
                activate(item)
            }
            .contentShape(.focusEffect, shape)
            .focusable()
            .focused($focus, equals: item)
    }

    // MARK: actions

    /// The copy items for `target`: the code, the password + code when the password is saved, and typing the code
    /// while auto-type is on (decision D-10).
    private func copyActions(_ target: Profile?) -> [PanelItem] {
        guard let target else { return [] }
        var actions: [PanelItem] = [.copyCode]
        if target.passwordMode == .keychain { actions.append(.copyPasswordAndCode) }
        if model.prefs.autoType { actions.append(.typeCode) }
        return actions
    }

    /// Everything the keyboard can reach, top to bottom.
    private var items: [PanelItem] {
        let profiles = model.profiles
        return (profiles.isEmpty ? [.add] : profiles.map { .profile($0.id) })
            + copyActions(model.copyTarget) + [.open, .settings, .quit]
    }

    /// The switch is on while the profile is connected or on its way there (connecting, or reconnecting after a
    /// drop); turning it off disconnects or cancels.
    private func isOn(_ p: Profile) -> Bool {
        model.state(p.id).isActive || model.reconnectInfo(p.id) != nil
    }

    private func toggle(_ p: Profile) {
        if isOn(p) {
            model.disconnect(p)
            return
        }
        model.connect(p)
        // The credential sheet lives in the main window. `connect` decides from the stored profile whether to ask.
        if model.credentialRequest != nil {
            window.dismiss()
            AppDelegate.shared?.showMainWindow()
        }
    }

    private func activate(_ item: PanelItem) {
        switch item {
        case .profile(let id):
            if let p = model.profile(id) { toggle(p) }
        case .add, .open:
            window.dismiss()
            AppDelegate.shared?.showMainWindow()
        case .copyCode, .copyPasswordAndCode, .typeCode:
            guard let p = model.copyTarget else { return NSSound.beep() }
            window.dismiss()
            if item == .copyCode {
                model.copyCode(p)
            } else if item == .copyPasswordAndCode {
                model.copyPasswordAndCode(p)
            } else {
                // Typing goes to the field that had the focus before the panel opened; let it get it back first.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { model.typeCode(p) }
            }
        case .settings:
            window.dismiss()
            AppDelegate.shared?.showSettings()
        case .quit:
            NSApp.terminate(nil)
        }
    }

    /// A key pressed while the panel is the key window; false lets the window have it.
    private func handle(_ key: PanelKey) -> Bool {
        let items = items
        switch key {
        case .up, .down:
            let step = key == .down ? 1 : -1
            if let focus, let i = items.firstIndex(of: focus) {
                self.focus = items[(i + step + items.count) % items.count]
            } else {
                focus = step > 0 ? items.first : items.last
            }
        case .activate:
            guard let focus else { return false }
            activate(focus)
        case .escape:
            window.dismiss()
        case .shortcut(let item):
            // Not offered for this profile (no code, no saved password): never the main menu's command instead.
            guard items.contains(item) else {
                NSSound.beep()
                return true
            }
            activate(item)
        }
        return true
    }

    private func hint(_ p: Profile, _ status: DisplayStatus) -> String {
        let date = now ?? Date()
        let summary = status.summary(at: date)
        if model.isCodeLocked(p) { return String(localized: "\(summary), code hidden") }
        guard let c = model.code(for: p, at: date) else { return summary }
        if model.prefs.hideCodes { return String(localized: "\(summary), code hidden") }
        return String(localized: "\(summary), code \(GroupedCodeText.spoken(c.code))")
    }
}

/// The row's status words in the state's color (11.5 medium), redrawn as often as they change.
private struct PanelStatusText: View {
    let status: DisplayStatus
    var now: Date?

    var body: some View {
        if let now {
            text(at: now)
        } else if let interval = status.refreshInterval {
            TimelineView(.periodic(from: .now, by: interval)) { text(at: $0.date) }
        } else {
            text(at: Date())
        }
    }

    private func text(at date: Date) -> some View {
        Text(status.summary(at: date))
            .typography(.rowStatus)
            .foregroundStyle(status.textColor)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// The row's code in SF Mono 13: `fg`, or "••• •••" in `fg3` while it is locked ("Confirm with Touch ID") or codes
/// are hidden (Settings). Nothing for a profile without a code.
private struct PanelCode: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    var now: Date?

    var body: some View {
        if let now {
            code(at: now)
        } else {
            // On the second, so a new code shows when its window starts.
            TimelineView(.periodic(from: Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down)), by: 1)) {
                code(at: $0.date)
            }
        }
    }

    @ViewBuilder private func code(at date: Date) -> some View {
        if model.isCodeLocked(profile) {
            GroupedCodeText(code: String(repeating: "0", count: max(6, profile.totp.digits)), hidden: true, style: .rowCode)
                .foregroundStyle(Palette.fg3)
        } else if let c = model.code(for: profile, at: date) {
            GroupedCodeText(code: c.code, hidden: model.prefs.hideCodes, style: .rowCode)
                .foregroundStyle(model.prefs.hideCodes ? Palette.fg3 : Palette.fg)
        }
    }
}

/// The row's switch, 38 × 22: `primary` when on, `fill2` with a hairline when off. The whole row is the control, so
/// the switch is only drawn: it takes no clicks and is hidden from VoiceOver.
private struct PanelSwitch: View {
    let isOn: Bool

    var body: some View {
        ZStack(alignment: isOn ? .trailing : .leading) {
            Capsule()
                .fill(isOn ? Palette.primary : Palette.fill2)
                .edge(Capsule(), isOn ? .clear : Palette.line)
            Circle()
                .fill(isOn ? Palette.onPrimary : .white)
                .shadow(color: .black.opacity(isOn ? 0 : 0.25), radius: 1.5, y: 1)
                .frame(width: 18, height: 18)
                .padding(2)
        }
        .frame(width: 38, height: 22)
        .animation(Motion.colorChange, value: isOn)
        .accessibilityHidden(true)
    }
}

// MARK: - keyboard

/// The keys the panel handles.
private enum PanelKey: Equatable {
    case up, down, activate, escape
    case shortcut(PanelItem)

    init?(_ event: NSEvent) {
        let modifiers = event.modifierFlags.intersection([.command, .shift, .option, .control])
        if modifiers.isEmpty {
            switch Int(event.keyCode) {
            case kVK_UpArrow: self = .up
            case kVK_DownArrow: self = .down
            case kVK_Return, kVK_ANSI_KeypadEnter, kVK_Space: self = .activate
            case kVK_Escape: self = .escape
            default: return nil
            }
            return
        }
        // By the character, as the menus match them, so other keyboard layouts work.
        switch (modifiers, event.charactersIgnoringModifiers?.lowercased()) {
        case (.command, "c"?): self = .shortcut(.copyCode)
        case ([.command, .shift], "c"?): self = .shortcut(.copyPasswordAndCode)
        case (.command, ","?): self = .shortcut(.settings)
        case (.command, "q"?): self = .shortcut(.quit)
        default: return nil
        }
    }
}

/// The panel's window once it is on screen, and closing it.
@MainActor
private final class PanelWindow {
    weak var window: NSWindow?

    /// Closes the panel the way a click on the shield does, so the next click opens it again: through the status
    /// item's button, whose action toggles the window. Closing the window itself would leave SwiftUI taking the
    /// panel for open, and the next click would only "close" it. Does nothing when the panel is not open.
    func dismiss() {
        guard let window, window.isVisible else { return }
        if let button = Self.toggleButton() {
            button.performClick(nil)
        } else {
            window.close()
        }
    }

    /// The window-style menu bar extra's button (SwiftUI's `toggleWindow:`); the current menu's has another action.
    private static func toggleButton() -> NSStatusBarButton? {
        let toggle = NSSelectorFromString("toggleWindow:")
        func find(in view: NSView?) -> NSStatusBarButton? {
            guard let view else { return nil }
            if let button = view as? NSStatusBarButton, button.action == toggle { return button }
            return view.subviews.lazy.compactMap { find(in: $0) }.first
        }
        return NSApp.windows.lazy.compactMap { find(in: $0.contentView) }.first
    }
}

/// The keyboard of the panel. A window-style menu bar extra has none of a menu's: ↑ and ↓ move between the rows and
/// items, Return and Space use the focused one, Escape closes the panel, and ⌘C, ⇧⌘C, ⌘, and ⌘Q run their items
/// whatever has the focus. A local event monitor for key presses in the panel's window, while it is the key window.
private struct PanelKeys: NSViewRepresentable {
    let window: PanelWindow
    let handle: (PanelKey) -> Bool

    func makeNSView(context: Context) -> MonitorView {
        let view = MonitorView()
        view.panel = window
        view.handle = handle
        return view
    }

    func updateNSView(_ view: MonitorView, context: Context) {
        view.panel = window
        view.handle = handle
    }

    static func dismantleNSView(_ view: MonitorView, coordinator: ()) {
        view.stop()
    }

    final class MonitorView: NSView {
        var panel: PanelWindow?
        var handle: ((PanelKey) -> Bool)?
        private var monitor: Any?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            stop()
            panel?.window = window
            guard window != nil else { return }
            monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
                guard let self, let window = self.window, event.window === window, window.isKeyWindow,
                      let key = PanelKey(event), self.handle?(key) == true else { return event }
                return nil
            }
        }

        func stop() {
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
        }

        /// Behind the panel's content, and never in the way of a click.
        override func hitTest(_ point: NSPoint) -> NSView? { nil }
    }
}

// MARK: - render

/// The panel as it opens under the menu bar, for the `menubar-panel` renders (RenderSnapshots): a strip of menu bar
/// with the shield (highlighted, as while the panel is open) over the desktop, and the panel on the material that
/// stands in for its window. The composition is a sample, not part of the app.
struct MenuBarPanelPreview: View {
    @EnvironmentObject private var model: AppModel
    let now: Date

    var body: some View {
        VStack(alignment: .trailing, spacing: 6) {
            Image(nsImage: MenuBarIcon.shield(dropped: !model.droppedUnseen.isEmpty))
                .renderingMode(.template)
                .foregroundStyle(Palette.fg)
                .frame(width: 26, height: 22)
                .background(Palette.selection, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                .padding(.trailing, 60)
                .frame(maxWidth: .infinity, minHeight: 30, alignment: .trailing)
                .background(.bar)
            MenuBarPanel(now: now)
                .materialGlass(in: RoundedRectangle(cornerRadius: Radius.panel, style: .continuous),
                               shadow: Elevation.floating)
                .padding(.trailing, 24)
        }
        .padding(.bottom, Spacing.xl)
        .frame(width: 440)
        .background(Color(nsColor: .underPageBackgroundColor))
    }
}
