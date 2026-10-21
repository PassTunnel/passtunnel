import AppKit
import Combine
import PassTunnelCore
import SwiftUI

struct MenuBarLabel: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(nsImage: MenuBarIcon.image(for: model))
            .accessibilityLabel(Text(accessibilityText))
            .onAppear {
                AppDelegate.shared?.openMainWindowAction = { openWindow(id: "main") }
            }
            .background { SettingsOpenerRegistration() }
    }

    private var accessibilityText: String {
        let active = model.profiles.filter { model.statusKind($0) == .connected || model.statusKind($0) == .degraded }
        if active.isEmpty { return String(localized: "PassTunnel, not connected") }
        return String(localized: "PassTunnel, connected: \(active.map(\.name).joined(separator: ", "))")
    }
}

/// Publishes when a 30-second code window rolls over so the menu shows fresh codes.
@MainActor
final class CodeClock: ObservableObject {
    @Published private(set) var window = 0
    private var timer: Timer?

    init() {
        window = Self.currentWindow()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                let w = Self.currentWindow()
                if w != self.window { self.window = w }
            }
        }
    }

    private static func currentWindow() -> Int { Int(Date().timeIntervalSince1970) / 30 }
}

struct MenuBarMenu: View {
    @EnvironmentObject private var model: AppModel
    @StateObject private var clock = CodeClock()
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let profiles = model.profiles
        if profiles.isEmpty {
            Text(String(localized: "No VPN profiles yet"))
            Button(String(localized: "Add a VPN…")) { openMain() }
        } else if profiles.count <= 4 {
            ForEach(profiles) { p in
                Section {
                    ProfileMenuSection(profile: p, compact: false)
                } header: {
                    Text(header(p))
                }
            }
        } else {
            ForEach(profiles) { p in
                Menu(header(p)) {
                    ProfileMenuSection(profile: p, compact: true)
                }
            }
        }
        Divider()
        if model.prefs.autoType, let p = model.defaultProfile, model.hasCode(p) {
            Button(String(localized: "Type Code for \(p.name)")) { model.typeCode(p) }
            Divider()
        }
        Button(String(localized: "Open PassTunnel")) { openMain() }
            .keyboardShortcut("o")
        SettingsButton()
        Divider()
        Button(String(localized: "Quit PassTunnel")) { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    private func header(_ p: Profile) -> String {
        let status: String
        switch model.statusKind(p) {
        case .connected:
            if case .connected(_, let since?) = model.state(p.id) {
                status = String(localized: "Connected \(DurationFormat.since(since))")
            } else {
                status = String(localized: "Connected")
            }
        case .degraded:
            // As in the main window: a health outage, or a connection whose set-up is incomplete.
            status = model.isUnreachable(p.id) ? String(localized: "Not responding") : String(localized: "Setup incomplete")
        case .connecting: status = String(localized: "Connecting…")
        case .error: status = String(localized: "Failed")
        case .dropped: status = String(localized: "Dropped")
        case .disconnected: status = String(localized: "Not connected")
        }
        let marker = model.isDefault(p) ? " ★" : ""
        return "\(p.name)\(marker) — \(status)"
    }

    private func openMain() {
        AppDelegate.shared?.allowMainWindow()
        NSApp.setActivationPolicy(.regular)
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
        model.markDropsSeen()
    }
}

private struct ProfileMenuSection: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let compact: Bool

    var body: some View {
        let p = profile
        switch model.state(p.id) {
        case .disconnected:
            Button(String(localized: "Connect")) { model.connect(p); bringForwardIfAsking() }
        case .connecting:
            Button(String(localized: "Cancel Connecting")) { model.disconnect(p) }
        case .connected:
            Button(String(localized: "Disconnect")) { model.disconnect(p) }
        }
        if let c = model.code(for: p) {
            let shown = model.prefs.hideCodes ? CodeFormat.hidden(c.code.count) : CodeFormat.grouped(c.code)
            Button(String(localized: "Copy Code  \(shown)")) { model.copyCode(p) }
        }
    }

    /// The credential sheet lives in the main window. `connect` decides from the stored profile
    /// whether to ask, so look at its result rather than at this (possibly older) copy.
    private func bringForwardIfAsking() {
        if model.credentialRequest != nil { AppDelegate.shared?.showMainWindow() }
    }
}

private struct SettingsButton: View {
    var body: some View {
        if #available(macOS 14, *) {
            ModernSettingsButton()
        } else {
            Button(String(localized: "Settings…")) { AppDelegate.shared?.showSettings() }
                .keyboardShortcut(",")
        }
    }
}

@available(macOS 14, *)
private struct ModernSettingsButton: View {
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Button(String(localized: "Settings…")) {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)
            openSettings()
        }
        .keyboardShortcut(",")
    }
}

/// Hands `openSettings` (macOS 14+) to the app delegate for alerts and notifications.
private struct SettingsOpenerRegistration: View {
    var body: some View {
        if #available(macOS 14, *) {
            Registrar()
        }
    }

    @available(macOS 14, *)
    private struct Registrar: View {
        @Environment(\.openSettings) private var openSettings

        var body: some View {
            Color.clear.frame(width: 0, height: 0)
                .onAppear { AppDelegate.shared?.openSettingsAction = { openSettings() } }
        }
    }
}
