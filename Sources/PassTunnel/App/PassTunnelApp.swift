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
            MainView()
                .environmentObject(model)
                .frame(minWidth: 520, idealWidth: 600, minHeight: 360, idealHeight: 480)
                .background { MainWindowObserver() }
        }
        .defaultSize(width: 600, height: 500)
        .commands {
            CheckForUpdatesCommand()
            AppCommands(model: model)
        }

        MenuBarExtra {
            MenuBarMenu()
                .environmentObject(model)
        } label: {
            MenuBarLabel()
                .environmentObject(model)
        }
        .menuBarExtraStyle(.menu)

        Settings {
            SettingsView()
                .environmentObject(model)
        }
    }
}

struct AppCommands: Commands {
    @ObservedObject var model: AppModel

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button(String(localized: "New OpenVPN Profile…")) { model.newProfile(.openvpn) }
                .keyboardShortcut("n")
            Button(String(localized: "New FortiGate Profile…")) { model.newProfile(.forti) }
                .keyboardShortcut("n", modifiers: [.command, .shift])
            Divider()
            Button(String(localized: "Import .ovpn…")) { ImportActions.importOVPN() }
                .keyboardShortcut("i")
            Button(String(localized: "Import Shared Profile…")) { ImportActions.importShared() }
            Button(String(localized: "Add Code from QR…")) { ImportActions.addCodeFromQR(profileID: model.selection) }
        }
        CommandMenu(String(localized: "Profile")) {
            let selected = model.selection.flatMap(model.profile)
            Button(String(localized: "Connect or Disconnect")) { selected.map(model.primaryAction) }
                .keyboardShortcut(.return, modifiers: [.command])
                .disabled(selected == nil)
            Button(String(localized: "Copy Code")) { selected.map(model.copyCode) }
                .keyboardShortcut("c", modifiers: [.command, .shift])
                .disabled(selected.map(model.hasCode) != true)
            Button(String(localized: "Edit…")) { selected.map(model.edit) }
                .keyboardShortcut("e")
                .disabled(selected == nil)
            Divider()
            Button(String(localized: "Toggle Default Profile")) { model.toggleDefault() }
                .disabled(model.profiles.isEmpty)
        }
    }
}
