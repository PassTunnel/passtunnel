import AppKit
import PassTunnelCore
import PassTunnelKit

enum ShareActions {
    /// Saves `<id>.passtunnel` where the user chooses and reveals it in Finder.
    @MainActor static func export(profileID: String) {
        let store = ProfileStore()
        guard let profile = try? store.get(profileID) else {
            ImportActions.showError(String(localized: "The profile could not be shared."), PTError.profileNotFound(profileID))
            return
        }
        let panel = NSSavePanel()
        panel.title = String(localized: "Share “\(profile.name)”")
        panel.message = String(
            localized:
                "The file contains the profile’s settings and VPN configuration. It does not contain your username, password or one-time code secret."
        )
        panel.nameFieldStringValue = "\(profileID).\(ImportActions.shareExtension)"
        panel.allowedContentTypes = ImportActions.shareTypes
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try store.exportShare(profileID, to: url)
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } catch {
            ImportActions.showError(String(localized: "The profile could not be shared."), error)
        }
    }
}
