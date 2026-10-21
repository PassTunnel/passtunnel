import AppKit
import PassTunnelCore
import SwiftUI

/// Renders editor states to PNG files offscreen (debug / screenshot path; the window is never shown).
/// Uses sample data only: no profile store, no Keychain.
enum EditorPreviewRenderer {
    struct State {
        let name: String
        let model: EditorModel
        var dark = false
        var height: CGFloat
        var showAdvanced = false
    }

    static let width: CGFloat = 580

    /// Well-known sample secret from authenticator documentation (not a real account).
    static let sampleSecret = "JBSWY3DPEHPK3PXP"

    @MainActor static func states() -> [State] {
        var out: [State] = []

        out.append(State(name: "editor-new-openvpn", model: EditorModel(preview: EditorModel.blank(.openvpn), isNew: true),
                         height: 1120))
        out.append(State(name: "editor-new-forti", model: EditorModel(preview: EditorModel.blank(.forti), isNew: true),
                         height: 1300))

        let forti = EditorModel(preview: EditorModel.blank(.forti), isNew: true)
        forti.draft.host = "https://vpn.example.com"
        forti.draft.trustedCert = "12:34"
        _ = forti.save()   // preview models only validate
        out.append(State(name: "editor-new-forti-errors", model: forti, height: 1450))

        out.append(State(name: "editor-totp", model: totpModel(), height: 1800, showAdvanced: true))
        out.append(State(name: "editor-totp-dark", model: totpModel(), dark: true, height: 1800, showAdvanced: true))

        let custom = totpModel()
        custom.templateChoice = .custom
        custom.draft.otpTemplate = "{password}-{code}"
        out.append(State(name: "editor-template-error", model: custom, height: 1800))

        let customOK = totpModel()
        customOK.templateChoice = .custom
        customOK.draft.otpTemplate = "{password}#{otp}"
        out.append(State(name: "editor-template-custom", model: customOK, height: 1800))

        let typing = totpModel()
        typing.newPassword = "new-secret"
        out.append(State(name: "editor-password-typing", model: typing, height: 1800))

        // "Confirm with Touch ID" set to always: the stored code stays hidden until confirmed.
        out.append(State(name: "editor-require-auth", model: protectedModel(), height: 1800))
        out.append(State(name: "editor-require-auth-dark", model: protectedModel(), dark: true, height: 1800))
        return out
    }

    @MainActor private static func totpModel() -> EditorModel {
        var p = Profile(id: "acme", name: "Acme VPN", type: .openvpn)
        p.icon = "building.2"
        p.badgeStyle = .both
        p.username = "alice"
        p.otpMode = .totp
        p.otpDelivery = .combined
        p.healthHost = "10.0.0.5"
        // Imported on 3 October of the current year (fixed so screenshots are stable).
        let calendar = Calendar.current
        let year = calendar.component(.year, from: Date())
        let imported = calendar.date(from: DateComponents(year: year, month: 10, day: 3, hour: 10)) ?? Date()
        p.configSourceName = "acme.ovpn"
        p.configImportedAt = imported
        let model = EditorModel(preview: p, isNew: false, passwordStored: true, configRemote: "vpn.example.com",
                                now: imported.addingTimeInterval(17 * 86_400))
        if let uri = try? OTPAuthURI("otpauth://totp/Acme:alice?secret=\(sampleSecret)&issuer=Acme") {
            model.apply(uri)
        }
        return model
    }

    /// A saved profile that asks for Touch ID before connecting and before showing its code.
    @MainActor private static func protectedModel() -> EditorModel {
        var p = Profile(id: "acme", name: "Acme VPN", type: .openvpn)
        p.icon = "building.2"
        p.badgeStyle = .both
        p.username = "alice"
        p.otpMode = .totp
        p.requireAuth = .always
        return EditorModel(preview: p, isNew: false, passwordStored: true, storedTOTPProtected: true,
                           configRemote: "vpn.example.com")
    }

    /// Writes one PNG per state into `dir` and returns their URLs.
    @MainActor @discardableResult
    static func renderAll(to dir: URL) -> [URL] {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var written: [URL] = []
        for state in states() {
            let url = dir.appendingPathComponent("\(state.name).png")
            if let data = render(state), (try? data.write(to: url)) != nil { written.append(url) }
        }
        return written
    }

    @MainActor static func render(_ state: State) -> Data? {
        let size = NSSize(width: width, height: state.height)
        let root = ProfileEditorView(model: state.model, showAdvanced: state.showAdvanced)
            .frame(width: size.width, height: size.height)
            .background(Color(nsColor: .windowBackgroundColor))
            .environment(\.colorScheme, state.dark ? .dark : .light)
        let hosting = NSHostingView(rootView: root)
        hosting.frame = NSRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: hosting.frame, styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.appearance = NSAppearance(named: state.dark ? .darkAqua : .aqua)
        window.contentView = hosting
        defer { window.contentView = nil; window.close() }

        hosting.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.3))   // let SwiftUI finish its first update
        hosting.layoutSubtreeIfNeeded()

        guard let rep = hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds) else { return nil }
        hosting.cacheDisplay(in: hosting.bounds, to: rep)
        return rep.representation(using: .png, properties: [:])
    }
}
