import AppKit
import Combine
import Sparkle
import SwiftUI

/// App updates through Sparkle (feed and public key in Info.plist). Created only in GUI mode: the
/// `passtunnel` CLI and the screenshot renderer never start the updater.
@MainActor
final class AppUpdater: NSObject, ObservableObject {
    /// nil until the GUI starts it, and in copies without a feed (`swift run`, tests).
    static private(set) var shared: AppUpdater?

    @Published private(set) var canCheckForUpdates = false
    @Published private(set) var lastUpdateCheckDate: Date?
    @Published private(set) var automaticallyChecksForUpdates = false

    /// nil in the placeholder.
    private var controller: SPUStandardUpdaterController?
    private var bag = Set<AnyCancellable>()

    /// Stands in for the updater where there is none (unbundled runs): nothing checks, nothing changes.
    static let placeholder = AppUpdater(starting: false)

    /// Starts the updater when this is a bundled app with a feed URL. GUI mode only.
    static func start() {
        guard shared == nil, Bundle.main.bundleURL.pathExtension == "app",
              Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") != nil,
              Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") != nil else { return }
        shared = AppUpdater(starting: true)
    }

    private init(starting: Bool) {
        super.init()
        guard starting else {
            automaticallyChecksForUpdates = true   // the shipped default, for screenshots
            return
        }
        let controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: self)
        self.controller = controller
        let updater = controller.updater
        updater.publisher(for: \.canCheckForUpdates)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] in self?.canCheckForUpdates = $0 }
            .store(in: &bag)
        updater.publisher(for: \.lastUpdateCheckDate)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] in self?.lastUpdateCheckDate = $0 }
            .store(in: &bag)
        updater.publisher(for: \.automaticallyChecksForUpdates)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] in self?.automaticallyChecksForUpdates = $0 }
            .store(in: &bag)
    }

    func checkForUpdates() {
        guard let controller else { return }
        AppDelegate.shared?.bringToFront(activate: true)
        controller.checkForUpdates(nil)
    }

    func setAutomaticallyChecks(_ on: Bool) {
        controller?.updater.automaticallyChecksForUpdates = on
    }
}

extension AppUpdater: SPUStandardUserDriverDelegate {
    /// PassTunnel often runs in the menu bar only; a scheduled update is shown when it gets attention.
    nonisolated var supportsGentleScheduledUpdateReminders: Bool { true }

    nonisolated func standardUserDriverWillHandleShowingUpdate(_ handleShowingUpdate: Bool, forUpdate update: SUAppcastItem,
                                                               state: SPUUserUpdateState) {
        guard handleShowingUpdate else { return }
        // The update window needs a regular app (Dock icon) while it is open; a scheduled check does
        // not take the focus away from what the user is doing.
        let userInitiated = state.userInitiated
        DispatchQueue.main.async { AppDelegate.shared?.bringToFront(activate: userInitiated) }
    }

    nonisolated func standardUserDriverWillFinishUpdateSession() {
        DispatchQueue.main.async { AppDelegate.shared?.updateActivationPolicy() }
    }
}

/// "Check for Updates…" in the app menu.
struct CheckForUpdatesCommand: Commands {
    var body: some Commands {
        CommandGroup(after: .appInfo) {
            if let updater = AppUpdater.shared {
                CheckForUpdatesButton(updater: updater)
            }
        }
    }
}

private struct CheckForUpdatesButton: View {
    @ObservedObject var updater: AppUpdater

    var body: some View {
        Button(String(localized: "Check for Updates…")) { updater.checkForUpdates() }
            .disabled(!updater.canCheckForUpdates)
    }
}
