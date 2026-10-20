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

    override init() {
        super.init()
        Self.shared = self
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
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

    func showMainWindow() {
        NSApp.setActivationPolicy(.regular)
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue.hasPrefix("main") == true }) {
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
