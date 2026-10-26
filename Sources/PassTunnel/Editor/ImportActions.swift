import AppKit
import PassTunnelCore
import PassTunnelKit
import UniformTypeIdentifiers

/// Import entry points used by the main window, the File menu, files opened from Finder and drag & drop. An OpenVPN
/// configuration is reviewed in the window first; after a shared profile is imported its editor is opened via
/// `openEditor`.
enum ImportActions {
    /// Posted after a profile was imported or saved; userInfo ["id": String, "profileID": String].
    static let didImport = Notification.Name("PassTunnelDidImport")
    /// The shell opens the editor for userInfo ["id"] (same value under "profileID").
    static let openEditor = Notification.Name("PassTunnelOpenEditor")

    static let ovpnExtensions = OpenedFiles.ovpnExtensions
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

    /// The window reviews the file first (`review(_:in:)`).
    @MainActor static func importOVPN(at url: URL) {
        guard let model = AppModel.shared else { return }
        review(url, in: model)
    }

    /// Reads the file and shows its review in the main window (`ImportReviewView`); nothing is created before Add
    /// Profile there. A file with a line that blocks it is refused here, listing every such line.
    @MainActor static func review(_ url: URL, in model: AppModel) {
        do {
            let draft = try ProfileStore().analyzeOVPN(url)
            guard draft.blocking.isEmpty else { throw PTError.ovpnNotAllowed(draft.blocking.map(\.description)) }
            AppDelegate.shared?.showMainWindow()
            model.startImportReview(draft)
        } catch {
            showError(String(localized: "The configuration could not be imported."), error)
        }
    }

    /// The review added the profile: show it.
    @MainActor static func imported(_ id: String) {
        post(didImport, id)
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

    // MARK: either file

    /// Choose File… in the window's add view: an OpenVPN configuration or a shared profile, imported
    /// as the matching File menu item does.
    @MainActor static func importFile() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Add a VPN")
        panel.message = String(localized: "Choose an .ovpn or .passtunnel file.")
        panel.allowedContentTypes = ovpnTypes + shareTypes
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        if url.pathExtension.lowercased() == shareExtension {
            importShared(at: url)
        } else {
            importOVPN(at: url)
        }
    }

    // MARK: opened files

    /// Files opened from Finder, AirDrop, the Dock icon or `open` (`AppDelegate`), one at a time like the import
    /// panels: a shared profile is imported as File → Import Shared Profile does, an OpenVPN configuration goes into
    /// the review like File → Import .ovpn….
    @MainActor static func open(_ urls: [URL]) {
        guard let route = OpenedFiles.route(urls) else { return }
        switch route {
        case .importShare(let url):
            AppDelegate.shared?.showMainWindow()
            importShared(at: url)
        case .importOVPN(let url):
            importOVPN(at: url)
        case .tooMany:
            NSApp.activate(ignoringOtherApps: true)
            showMessage(String(localized: "Open one file at a time"),
                        String(localized: "Nothing was imported. Open the files one by one."))
        case .unsupported(let name):
            NSApp.activate(ignoringOtherApps: true)
            showMessage(String(localized: "PassTunnel cannot open “\(name)”"),
                        String(localized: "PassTunnel opens OpenVPN configurations (.ovpn or .conf) and shared profiles (.passtunnel)."))
        }
    }

    // MARK: QR codes

    /// Picks an image with a QR code, then opens the editor of `profileID` (or of a profile the
    /// user chooses) with the code filled in. Nothing is saved until the user presses Save there.
    @MainActor static func addCodeFromQR(profileID: String?) {
        guard let url = chooseQRImage() else { return }
        addCode(from: .file(url), profileID: profileID)
    }

    /// "Use a QR image" in the window's add view: a new profile with the code filled in (`startProfile`).
    @MainActor static func newProfileFromQR() {
        guard let url = chooseQRImage(), let uri = decode(.file(url)) else { return }
        startProfile(with: uri)
    }

    /// The first run's "Scan a QR code on screen" (macOS 14 and later): the QR code the user picks on screen
    /// (`ScreenQRScanner`) starts a new profile like a QR image does. Cancelling does nothing.
    @MainActor static func newProfileFromScreen() {
        guard #available(macOS 14, *) else { return }
        Task {
            do {
                guard let uri = try await ScreenQRScanner.shared.scan() else { return }
                startProfile(with: uri)
            } catch {
                showError(String(localized: "No usable code was found."), error)
            }
        }
    }

    @MainActor private static func chooseQRImage() -> URL? {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Add Code from QR")
        panel.message = String(localized: "Choose a screenshot or photo of the QR code your VPN provider gave you.")
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK else { return nil }
        return panel.url
    }

    @MainActor static func addCode(from item: DroppedItem, profileID: String?) {
        guard let uri = decode(item) else { return }
        let id: String
        switch ScannedCodeTarget.route(requested: profileID, profiles: ProfileStore().list()) {
        case .profile(let requested):
            id = requested
        case .choose(let profiles):
            guard let chosen = chooseProfile(profiles, for: uri) else { return }
            id = chosen
        case .newProfile:
            return startProfile(with: uri)
        }
        pendingTOTP[id] = uri
        post(openEditor, id)
    }

    /// The code in the image, or nil after saying why there is none.
    @MainActor private static func decode(_ item: DroppedItem) -> OTPAuthURI? {
        do {
            switch item {
            case .file(let url):
                return try QRDecoder.otpAuth(inFile: url)
            case .image(let image):
                guard let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
                    throw QRDecoder.Failure.unreadableImage
                }
                return try QRDecoder.otpAuth(in: cg)
            }
        } catch {
            showError(String(localized: "No usable code was found."), error)
            return nil
        }
    }

    /// Scanned codes waiting for the editor of that profile to open, and the one for a new profile.
    @MainActor private static var pendingTOTP: [String: OTPAuthURI] = [:]
    @MainActor private static var pendingNewProfileTOTP: OTPAuthURI?

    /// `profileID` nil: the code a new profile starts with (`startProfile`).
    @MainActor static func takePendingTOTP(for profileID: String?) -> OTPAuthURI? {
        guard let profileID else {
            defer { pendingNewProfileTOTP = nil }
            return pendingNewProfileTOTP
        }
        return pendingTOTP.removeValue(forKey: profileID)
    }

    @MainActor private static func chooseProfile(_ profiles: [Profile], for uri: OTPAuthURI) -> String? {
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
        alert.messageText = String(localized: "Which VPN is this code for?")
        alert.informativeText = codeNote(uri)
        alert.accessoryView = popup
        alert.addButton(withTitle: String(localized: "Continue"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let index = popup.indexOfSelectedItem
        return profiles.indices.contains(index) ? profiles[index].id : nil
    }

    /// "Code for “Acme · alice”. It is added when you save the profile."
    private static func codeNote(_ uri: OTPAuthURI) -> String {
        let label = [uri.issuer, uri.account].filter { !$0.isEmpty }.joined(separator: " · ")
        return label.isEmpty
            ? String(localized: "The code is added when you save the profile.")
            : String(localized: "Code for “\(label)”. It is added when you save the profile.")
    }

    // MARK: new profiles

    /// "Enter details by hand" in the window's add view: asks the VPN type, then opens a new profile's editor.
    @MainActor static func newProfileByHand() {
        guard let type = chooseType(for: nil) else { return }
        AppModel.shared?.newProfile(type)
    }

    /// A new profile that starts from a scanned code: asks the VPN type, then opens a new profile's editor with the
    /// code filled in and the issuer as its name (`EditorModel`). Nothing is saved until Add Profile.
    @MainActor static func startProfile(with uri: OTPAuthURI) {
        guard let type = chooseType(for: uri) else { return }
        pendingNewProfileTOTP = uri
        AppModel.shared?.newProfile(type)
    }

    /// OpenVPN or FortiGate; nil when cancelled.
    @MainActor private static func chooseType(for uri: OTPAuthURI?) -> VPNType? {
        let alert = NSAlert()
        if let uri {
            alert.messageText = String(localized: "What kind of VPN is this code for?")
            alert.informativeText = codeNote(uri)
        } else {
            alert.messageText = String(localized: "What kind of VPN is it?")
            alert.informativeText = String(localized: "You enter the server, user name, password and code secret next.")
        }
        let types = VPNType.allCases
        for type in types { alert.addButton(withTitle: type.displayName) }
        alert.addButton(withTitle: String(localized: "Cancel")).keyEquivalent = "\u{1b}"
        let index = alert.runModal().rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
        return types.indices.contains(index) ? types[index] : nil
    }

    // MARK: drag & drop

    enum DroppedItem {
        case file(URL)
        case image(NSImage)
    }

    /// Main window drop: .ovpn / .conf / .passtunnel files, or an image containing a QR code.
    /// While an import is under review, a QR code dropped anywhere on the window is its code secret.
    static func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        loadItems(from: providers) { item in
            switch item {
            case .file(let url):
                let ext = url.pathExtension.lowercased()
                if ovpnExtensions.contains(ext) {
                    importOVPN(at: url)
                } else if ext == shareExtension {
                    importShared(at: url)
                } else if let review = AppModel.shared?.importReview {
                    review.scanImage(at: url)
                } else {
                    addCode(from: item, profileID: nil)
                }
            case .image(let image):
                if let review = AppModel.shared?.importReview {
                    review.scanImage(image)
                } else {
                    addCode(from: item, profileID: nil)
                }
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
