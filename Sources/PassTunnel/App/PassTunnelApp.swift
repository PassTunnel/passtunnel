import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// Entry point is `main.swift` (CLI check, single instance), which calls `PassTunnelApp.main()`.
struct PassTunnelApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model: AppModel

    init() {
        AppUpdater.start()
        _model = StateObject(wrappedValue: AppModel(connections: ConnectionManager(management: PersistentManagementQuerier())))
    }

    var body: some Scene {
        Window(Text(verbatim: "PassTunnel"), id: "main") {
            MainSplitView()
                .frame(minWidth: 820, idealWidth: 1080, minHeight: 560, idealHeight: 700)
                .environmentObject(model)
                .background { MainWindowObserver() }
        }
        .defaultSize(width: 1080, height: 700)
        .commands {
            CheckForUpdatesCommand()
            AppCommands(model: model)
        }

        // The activity of one profile, opened by "Show all" in the detail; not in the Window menu.
        Window(String(localized: "Activity"), id: ActivityLogWindow.id) {
            ActivityLogWindow()
                .environmentObject(model)
        }
        .defaultSize(width: 620, height: 460)
        .commandsRemoved()

        // The menu bar item: its status item (`MenuBarLabel`) and the panel under it.
        MenuBarExtra {
            MenuBarPanel()
                .environmentObject(model)
        } label: {
            MenuBarLabel()
                .environmentObject(model)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environmentObject(model)
        }
    }
}

struct AppCommands: Commands {
    @ObservedObject var model: AppModel

    /// "New Palo Alto GlobalProtect Profile (Experimental)…": a menu item has no room for the badge, so an experimental
    /// type says it in words.
    static func newProfileTitle(_ type: VPNType) -> String {
        type.isExperimental
            ? String(localized: "New \(type.displayName) Profile (\(ExperimentalLabel.title))…")
            : String(localized: "New \(type.displayName) Profile…")
    }

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button(String(localized: "New OpenVPN Profile…")) { model.newProfile(.openvpn) }
                .keyboardShortcut("n")
            Button(String(localized: "New FortiGate Profile…")) { model.newProfile(.forti) }
                .keyboardShortcut("n", modifiers: [.command, .shift])
            // Shown below macOS 15.4 too, disabled, with the reason as its tooltip (`AppModel.connectRefusal`).
            Button(String(localized: "New Cisco AnyConnect Profile…")) { model.newProfile(.anyconnect) }
                .keyboardShortcut("n", modifiers: [.command, .option])
                .disabled(model.connectRefusal(.anyconnect) != nil)
                .help(model.connectRefusal(.anyconnect)?.unavailableNote ?? "")
            // Labelled experimental (`VPNType.isExperimental`); disabled below macOS 15.4 like Cisco AnyConnect.
            Button(Self.newProfileTitle(.globalprotect)) { model.newProfile(.globalprotect) }
                .disabled(model.connectRefusal(.globalprotect) != nil)
                .help(model.connectRefusal(.globalprotect)?.unavailableNote ?? "")
            Divider()
            Button(String(localized: "Import .ovpn…")) { ImportActions.importOVPN() }
                .keyboardShortcut("i")
            Button(String(localized: "Import Shared Profile…")) { ImportActions.importShared() }
            Button(String(localized: "Add Code from QR…")) { ImportActions.addCodeFromQR(profileID: model.selection) }
        }
        CommandMenu(String(localized: "Profile")) {
            SplitWindowCommands(model: model)
            Divider()
            Button(String(localized: "Toggle Default Profile")) { model.toggleDefault() }
                .disabled(model.profiles.isEmpty)
        }
    }
}
