import AppKit
import Combine
import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// The status item: a badge for each profile that is connecting, connected or dropped, the shield while there are none,
/// and the panel's VoiceOver label ("PassTunnel, 2 connected").
struct MenuBarLabel: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(nsImage: MenuBarIcon.image(for: model))
            .accessibilityLabel(Text(MenuBarPanel.statusItemLabel(model)))
            .onAppear {
                AppDelegate.shared?.openMainWindowAction = { openWindow(id: "main") }
            }
            .background { SettingsOpenerRegistration() }
    }
}

/// Hands `openSettings` (macOS 14+) to the app delegate for alerts and notifications.
struct SettingsOpenerRegistration: View {
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
