import AppKit
import PassTunnelCore
import PassTunnelKit
import UniformTypeIdentifiers

/// Import entry points used by the main window, the "+" menu, onboarding and drag & drop.
/// After a successful import the new profile's editor is opened via `openEditor`.
enum ImportActions {
    /// Posted after a profile was imported or saved; userInfo ["id": String, "profileID": String].
    static let didImport = Notification.Name("PassTunnelDidImport")
    /// The shell opens the editor for userInfo ["id"] (same value under "profileID").
    static let openEditor = Notification.Name("PassTunnelOpenEditor")

    static let ovpnExtensions: Set<String> = ["ovpn", "conf"]
    static let shareExtension = ShareFile.fileExtension

    static var ovpnTypes: [UTType] {
        ovpnExtensions.sorted().compactMap { UTType(filenameExtension: $0) }
    }

    /// The exported `com.furkanprlk.passtunnel.profile` (Info.plist), or the extension's dynamic type
    /// when the running copy is not a registered app (`swift run`).
    static var shareTypes: [UTType] {
        [UTType(ShareFile.typeIdentifier) ?? UTType(filenameExtension: shareExtension)].compactMap { $0 }
    }

    // MARK: OpenVPN

    @MainActor static func importOVPN() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Import OpenVPN Configuration")
        panel.message = String(localized: "Choose an .ovpn file. Certificates and keys it refers to are embedded automatically when they are in the same folder.")
        panel.allowedContentTypes = ovpnTypes
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        importOVPN(at: url)
    }

    @MainActor static func importOVPN(at url: URL) {
        do {
            let p = try ProfileStore().importOVPN(url, name: nil)
            finish(p.id)
        } catch {
            showError(String(localized: "The configuration could not be imported."), error)
        }
    }

    // MARK: share files

    @MainActor static func importShared() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Import Shared Profile")
        panel.message = String(localized: "Choose a .passtunnel file. You add your own username, password and code afterwards.")
        panel.allowedContentTypes = shareTypes
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        importShared(at: url)
    }

    @MainActor static func importShared(at url: URL) {
        do {
            let p = try ProfileStore().importShare(url, name: nil)
            finish(p.id)
        } catch {
            showError(String(localized: "The shared profile could not be imported."), error)
        }
    }

    // MARK: opened files

    /// Files opened from Finder, AirDrop, the Dock icon or `open` (`AppDelegate`): the same import as
    /// File → Import Shared Profile, one file at a time like its panel.
    @MainActor static func open(_ urls: [URL]) {
        guard let route = OpenedFiles.route(urls) else { return }
        switch route {
        case .importShare(let url):
            AppDelegate.shared?.showMainWindow()
            importShared(at: url)
        case .tooMany:
            NSApp.activate(ignoringOtherApps: true)
            showMessage(String(localized: "Open one shared profile at a time"),
                        String(localized: "Nothing was imported. Open the .passtunnel files one by one."))
        case .unsupported(let name):
            NSApp.activate(ignoringOtherApps: true)
            showMessage(String(localized: "“\(name)” is not a shared profile"),
                        String(localized: "PassTunnel opens .passtunnel files. To add an OpenVPN configuration, use File → Import .ovpn…"))
        }
    }

    // MARK: QR codes

    /// Picks an image with a QR code, then opens the editor of `profileID` (or of a profile the
    /// user chooses) with the code filled in. Nothing is saved until the user presses Save there.
    @MainActor static func addCodeFromQR(profileID: String?) {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Add Code from QR")
        panel.message = String(localized: "Choose a screenshot or photo of the QR code your VPN provider gave you.")
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        addCode(from: .file(url), profileID: profileID)
    }

    @MainActor static func addCode(from item: DroppedItem, profileID: String?) {
        let uri: OTPAuthURI
        do {
            switch item {
            case .file(let url):
                uri = try QRDecoder.otpAuth(inFile: url)
            case .image(let image):
                guard let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
                    throw QRDecoder.Failure.unreadableImage
                }
                uri = try QRDecoder.otpAuth(in: cg)
            }
        } catch {
            showError(String(localized: "No usable code was found."), error)
            return
        }
        let store = ProfileStore()
        let target: String?
        if let profileID, store.exists(profileID) {
            target = profileID
        } else {
            target = chooseProfile(for: uri, store: store)
        }
        guard let id = target else { return }
        pendingTOTP[id] = uri
        post(openEditor, id)
    }

    /// Scanned codes waiting for the editor of that profile to open.
    @MainActor private static var pendingTOTP: [String: OTPAuthURI] = [:]

    @MainActor static func takePendingTOTP(for profileID: String) -> OTPAuthURI? {
        pendingTOTP.removeValue(forKey: profileID)
    }

    @MainActor private static func chooseProfile(for uri: OTPAuthURI, store: ProfileStore) -> String? {
        let profiles = store.list().filter { $0.passwordMode != .none }
        guard !profiles.isEmpty else {
            let alert = NSAlert()
            alert.messageText = String(localized: "Add a VPN first")
            alert.informativeText = String(localized: "The code belongs to a VPN profile. Add or import the VPN, then add its code.")
            alert.runModal()
            return nil
        }
        let popup = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 260, height: 26), pullsDown: false)
        popup.addItems(withTitles: profiles.map(\.name))
        let issuer = uri.issuer.lowercased()
        if !issuer.isEmpty, let match = profiles.firstIndex(where: {
            $0.name.lowercased().contains(issuer) || issuer.contains($0.name.lowercased())
        }) {
            popup.selectItem(at: match)
        }
        popup.setAccessibilityLabel(String(localized: "VPN profile"))

        let alert = NSAlert()
        let label = [uri.issuer, uri.account].filter { !$0.isEmpty }.joined(separator: " · ")
        alert.messageText = String(localized: "Which VPN is this code for?")
        alert.informativeText = label.isEmpty
            ? String(localized: "The code is added when you save the profile.")
            : String(localized: "Code for “\(label)”. It is added when you save the profile.")
        alert.accessoryView = popup
        alert.addButton(withTitle: String(localized: "Continue"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let index = popup.indexOfSelectedItem
        return profiles.indices.contains(index) ? profiles[index].id : nil
    }

    // MARK: drag & drop

    enum DroppedItem {
        case file(URL)
        case image(NSImage)
    }

    /// Main window drop: .ovpn / .conf / .passtunnel files, or an image containing a QR code.
    static func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        loadItems(from: providers) { item in
            switch item {
            case .file(let url):
                let ext = url.pathExtension.lowercased()
                if ovpnExtensions.contains(ext) {
                    importOVPN(at: url)
                } else if ext == shareExtension {
                    importShared(at: url)
                } else {
                    addCode(from: item, profileID: nil)
                }
            case .image:
                addCode(from: item, profileID: nil)
            }
        }
    }

    /// Loads file URLs and images from drop providers and delivers each on the main actor.
    /// Returns false when nothing usable is offered.
    @discardableResult
    static func loadItems(from providers: [NSItemProvider],
                          _ handler: @escaping @MainActor (DroppedItem) -> Void) -> Bool {
        var accepted = false
        for provider in providers {
            if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
                accepted = true
                _ = provider.loadObject(ofClass: NSURL.self) { object, _ in
                    guard let url = (object as? NSURL) as URL? else { return }
                    Task { @MainActor in handler(.file(url)) }
                }
            } else if provider.canLoadObject(ofClass: NSImage.self) {
                accepted = true
                _ = provider.loadObject(ofClass: NSImage.self) { object, _ in
                    guard let image = object as? NSImage else { return }
                    Task { @MainActor in handler(.image(image)) }
                }
            }
        }
        return accepted
    }

    /// Editor drop zone: image files or image data; the QR decoder reports anything else.
    static func loadImages(from providers: [NSItemProvider],
                           _ handler: @escaping @MainActor (DroppedItem) -> Void) -> Bool {
        loadItems(from: providers, handler)
    }

    // MARK: helpers

    @MainActor private static func finish(_ id: String) {
        post(didImport, id)
        post(openEditor, id)
    }

    @MainActor private static func post(_ name: Notification.Name, _ id: String) {
        NotificationCenter.default.post(name: name, object: nil, userInfo: ["id": id, "profileID": id])
    }

    @MainActor static func showError(_ title: String, _ error: Error) {
        showMessage(title, error.localizedDescription)
    }

    @MainActor static func showMessage(_ title: String, _ message: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = title
        alert.informativeText = message
        alert.runModal()
    }
}
