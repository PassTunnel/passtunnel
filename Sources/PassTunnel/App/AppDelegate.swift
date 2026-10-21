import AppKit
import Combine
import PassTunnelCore
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    static private(set) weak var shared: AppDelegate?
    nonisolated static let showMainWindowNotification = Notification.Name("com.furkanprlk.passtunnel.showMainWindow")

    /// Set by SwiftUI views that have access to `openWindow` / `openSettings`.
    var openMainWindowAction: (() -> Void)?
    var openSettingsAction: (() -> Void)?
    private var bag = Set<AnyCancellable>()

    /// Started by the login item (or `--background`): stay in the menu bar, no main window.
    private(set) var launchedInBackground = false
    /// Until this moment, a main window that SwiftUI opens on its own is closed again.
    private var suppressMainWindowUntil: Date?

    override init() {
        super.init()
        Self.shared = self
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        // The flag is known now; the login-item Apple event only in didFinishLaunching.
        if LoginItem.isBackgroundLaunch(arguments: CommandLine.arguments, launchEvent: nil) {
            beginBackgroundLaunch()
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if !launchedInBackground,
           LoginItem.isBackgroundLaunch(arguments: [], launchEvent: NSAppleEventManager.shared().currentAppleEvent) {
            beginBackgroundLaunch()
        }
        if launchedInBackground {
            for window in NSApp.windows where Self.isMainWindow(window) { window.close() }
        }
        Notifier.shared.setUp()
        let center = NotificationCenter.default
        for name in [NSWindow.didBecomeKeyNotification, NSWindow.willCloseNotification, NSWindow.didMiniaturizeNotification] {
            center.publisher(for: name)
                .sink { [weak self] _ in
                    // willClose fires while the window is still visible.
                    DispatchQueue.main.async { self?.updateActivationPolicy() }
                }
                .store(in: &bag)
        }
        // ConnectionManager.start() observes sleep/wake itself (poll after 4 s, health, reconnect);
        // here the app only refreshes what it shows.
        NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didWakeNotification)
            .delay(for: .seconds(5), scheduler: DispatchQueue.main)
            .sink { _ in AppModel.shared?.reloadFromDisk() }
            .store(in: &bag)
        DistributedNotificationCenter.default().publisher(for: Self.showMainWindowNotification)
            .sink { [weak self] _ in self?.showMainWindow() }
            .store(in: &bag)
        // `passtunnel helper install|uninstall`: the CLI cannot register the helper itself.
        DistributedNotificationCenter.default().publisher(for: HelperHandoff.notification)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] note in
                guard let raw = note.object as? String, let action = HelperHandoff(rawValue: raw) else { return }
                self?.handleHelperHandoff(action)
            }
            .store(in: &bag)
        // `passtunnel debug drop ID` (test hook): drop over the management connection the app holds.
        DistributedNotificationCenter.default().publisher(for: DebugDrop.notification)
            .receive(on: DispatchQueue.main)
            .sink { note in
                guard let id = note.object as? String, let model = AppModel.shared else { return }
                Task { @MainActor in _ = try? await model.connections.simulateDrop(id) }
            }
            .store(in: &bag)
        // Confirmations (Touch ID before connecting or showing codes) end when the screen locks;
        // ConnectionManager ends them on sleep.
        DistributedNotificationCenter.default().publisher(for: Notification.Name("com.apple.screenIsLocked"))
            .receive(on: DispatchQueue.main)
            .sink { _ in AppModel.shared?.vault.reset() }
            .store(in: &bag)
        if let action = HelperHandoff.from(arguments: CommandLine.arguments) {
            DispatchQueue.main.async { self.handleHelperHandoff(action) }
        }

        if let model = AppModel.shared {
            apply(model.prefs)
            model.onPrefsChanged = { [weak self] old, new in self?.prefsChanged(old: old, new: new) }
        }
        Hotkeys.shared.handler = { action in
            guard let model = AppModel.shared else { return }
            switch action {
            case .toggleDefault: model.toggleDefault()
            case .code: model.copyOrTypeDefaultCode()
            }
        }
        DispatchQueue.main.async { self.updateActivationPolicy() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { showMainWindow() }
        return true
    }

    // MARK: windows

    private func beginBackgroundLaunch() {
        launchedInBackground = true
        suppressMainWindowUntil = Date().addingTimeInterval(5)
    }

    static func isMainWindow(_ window: NSWindow) -> Bool {
        window.identifier?.rawValue.hasPrefix("main") == true
    }

    /// Called by `MainWindowObserver` when the main window is created. Returns true if the window
    /// must not be shown (launch at login). Only the first window after launch is affected.
    func shouldSuppressMainWindow() -> Bool {
        guard let until = suppressMainWindowUntil else { return false }
        suppressMainWindowUntil = nil
        return Date() < until
    }

    /// The user asked for the window: never suppress it.
    func allowMainWindow() {
        suppressMainWindowUntil = nil
    }

    func showMainWindow() {
        allowMainWindow()
        NSApp.setActivationPolicy(.regular)
        if let window = NSApp.windows.first(where: Self.isMainWindow) {
            window.makeKeyAndOrderFront(nil)
        } else {
            openMainWindowAction?()
        }
        NSApp.activate(ignoringOtherApps: true)
        AppModel.shared?.markDropsSeen()
    }

    func showSettings() {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        if let openSettingsAction {
            openSettingsAction()
        } else {
            NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        }
    }

    /// Dock icon while a regular window is open; otherwise as configured.
    func updateActivationPolicy() {
        let hasWindow = NSApp.windows.contains { w in
            (w.isVisible || w.isMiniaturized) && w.styleMask.contains(.titled) && !(w is NSPanel) && w.level == .normal
        }
        let showDock = hasWindow || (AppModel.shared?.prefs.showInDock ?? false)
        let wanted: NSApplication.ActivationPolicy = showDock ? .regular : .accessory
        if NSApp.activationPolicy() != wanted { NSApp.setActivationPolicy(wanted) }
    }

    /// Shows Settings → Helper, where the pending action is started (install) or confirmed (removal).
    func handleHelperHandoff(_ action: HelperHandoff) {
        guard let model = AppModel.shared else { return }
        model.settingsTab = .helper
        model.pendingHelperAction = action
        showSettings()
    }

    // MARK: preferences

    private func prefsChanged(old: Preferences, new: Preferences) {
        apply(new)
    }

    private func apply(_ prefs: Preferences) {
        switch prefs.appearance {
        case .system: NSApp.appearance = nil
        case .light: NSApp.appearance = NSAppearance(named: .aqua)
        case .dark: NSApp.appearance = NSAppearance(named: .darkAqua)
        }
        if Hotkeys.shared.isEnabled != prefs.hotkeys { Hotkeys.shared.setEnabled(prefs.hotkeys) }
        updateActivationPolicy()
    }
}

/// Placed in the main window's content: hides the window SwiftUI opens at launch when the app was
/// started at login, before it is drawn on screen.
struct MainWindowObserver: NSViewRepresentable {
    final class ObserverView: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window, AppDelegate.shared?.shouldSuppressMainWindow() == true else { return }
            window.alphaValue = 0
            DispatchQueue.main.async {
                window.close()
                window.alphaValue = 1
                AppDelegate.shared?.updateActivationPolicy()
            }
        }
    }

    func makeNSView(context: Context) -> ObserverView { ObserverView() }
    func updateNSView(_ nsView: ObserverView, context: Context) {}
}
