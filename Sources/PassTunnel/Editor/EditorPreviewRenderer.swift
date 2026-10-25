import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// Renders editor states to PNG files offscreen (debug / screenshot path; the window is never shown).
/// Uses sample data only: no profile store, no Keychain.
enum EditorPreviewRenderer {
    struct State {
        let name: String
        let model: EditorModel
        var dark = false
        var height: CGFloat = EditorPreviewRenderer.height
        var showAdvanced = false
    }

    /// The sheet's ideal size.
    static let width: CGFloat = 660
    static let height: CGFloat = 700

    /// Well-known sample secret from authenticator documentation (not a real account).
    static let sampleSecret = "JBSWY3DPEHPK3PXP"

    /// Imported on 3 October of the current year, rendered 17 days later at 10:00:07 (fixed so screenshots,
    /// codes included, are stable).
    private static let imported: Date = {
        let calendar = Calendar.current
        let year = calendar.component(.year, from: Date())
        return calendar.date(from: DateComponents(year: year, month: 10, day: 3, hour: 10)) ?? Date()
    }()
    private static let now = imported.addingTimeInterval(17 * 86_400 + 7)

    @MainActor static func states() -> [State] {
        var out: [State] = []

        for dark in [false, true] {
            out.append(State(name: "editor-new-openvpn\(dark ? "-dark" : "")",
                             model: EditorModel(preview: EditorModel.blank(.openvpn), isNew: true, now: now), dark: dark))
        }
        out.append(State(name: "editor-new-forti", model: EditorModel(preview: EditorModel.blank(.forti), isNew: true, now: now),
                         height: 920))

        let forti = EditorModel(preview: EditorModel.blank(.forti), isNew: true, now: now)
        forti.draft.host = "https://vpn.example.com"
        forti.draft.trustedCert = "12:34"
        _ = forti.save()   // preview models only validate
        out.append(State(name: "editor-new-forti-errors", model: forti, height: 1000))

        // A saved FortiGate profile.
        for dark in [false, true] {
            out.append(State(name: "editor-forti\(dark ? "-dark" : "")", model: fortiModel(), dark: dark, height: 960))
        }

        // A saved OpenVPN profile with a secret just scanned from a QR code.
        for dark in [false, true] {
            out.append(State(name: "editor-totp\(dark ? "-dark" : "")", model: totpModel(), dark: dark))
        }

        // The whole sheet for the website: a saved profile with its secret ("Work", as on the site). The height
        // keeps the 480 px wide site image a whole number of pixels high at 1x, 1.5x and 2x.
        for dark in [false, true] {
            out.append(State(name: "editor-one-time-code\(dark ? "-dark" : "")", model: workModel(), dark: dark,
                             height: 704))
        }

        // Everything under Advanced.
        for dark in [false, true] {
            out.append(State(name: "editor-advanced\(dark ? "-dark" : "")", model: totpModel(), dark: dark,
                             height: 1700, showAdvanced: true))
        }

        // Generate chosen, no secret yet.
        out.append(State(name: "editor-code-empty",
                         model: EditorModel(preview: workProfile(), isNew: false, passwordStored: true,
                                            configServer: "vpn.example.com:1194 · UDP", now: now)))

        // Scan QR on screen: waiting for the system's picker, and nothing found in what was picked.
        if #available(macOS 14, *) {
            let scanning = EditorModel(preview: workProfile(), isNew: false, passwordStored: true,
                                       configServer: "vpn.example.com:1194 · UDP", now: now)
            scanning.scanningScreen = true
            out.append(State(name: "editor-scan-screen", model: scanning))
            let nothing = EditorModel(preview: workProfile(), isNew: false, passwordStored: true,
                                      configServer: "vpn.example.com:1194 · UDP", now: now)
            nothing.scanError = ScreenQRScanner.ScanError.noCodeOnScreen.localizedDescription
            out.append(State(name: "editor-scan-screen-none", model: nothing))
        }

        let separate = workModel()
        separate.formatChoice = .separate
        out.append(State(name: "editor-separate", model: separate))

        let custom = totpModel()
        custom.formatChoice = .custom
        custom.draft.otpTemplate = "{password}-{code}"
        _ = custom.save()
        out.append(State(name: "editor-template-error", model: custom))

        let customOK = totpModel()
        customOK.formatChoice = .custom
        customOK.draft.otpTemplate = "{password}#{otp}"
        out.append(State(name: "editor-template-custom", model: customOK))

        let typing = totpModel()
        typing.newPassword = "new-secret"
        out.append(State(name: "editor-password-typing", model: typing))

        // "Confirm with Touch ID" on: the stored code stays hidden until confirmed.
        for dark in [false, true] {
            out.append(State(name: "editor-require-auth\(dark ? "-dark" : "")", model: protectedModel(.always), dark: dark))
        }
        // Set to ask before connecting only (the CLI's middle level): the switch is on, with a footnote.
        out.append(State(name: "editor-require-auth-connect", model: protectedModel(.connect)))

        // "Connect at login" on while PassTunnel itself does not open at login: the switch says so.
        for dark in [false, true] {
            out.append(State(name: "editor-connect-at-login\(dark ? "-dark" : "")",
                             model: workModel(opensAtLogin: false), dark: dark, height: 820))
        }
        // On for a profile that asks before connecting: a notification at login offers the connection instead.
        let asking = protectedModel(.always)
        asking.draft.connectAtLogin = true
        out.append(State(name: "editor-connect-at-login-asks", model: asking, height: 820))
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
        p.configSourceName = "acme.ovpn"
        p.configImportedAt = imported
        let model = EditorModel(preview: p, isNew: false, passwordStored: true,
                                configServer: "vpn.example.com:1194 · UDP", now: now)
        if let uri = try? OTPAuthURI("otpauth://totp/Acme:alice?secret=\(sampleSecret)&issuer=Acme") {
            model.apply(uri)
        }
        return model
    }

    private static func workProfile() -> Profile {
        var p = Profile(id: "work", name: "Work", type: .openvpn)
        p.username = "alice"
        p.otpMode = .totp
        p.otpDelivery = .combined
        p.autoReconnect = true
        p.connectAtLogin = true
        p.configSourceName = "Work.ovpn"
        p.configImportedAt = imported
        return p
    }

    @MainActor private static func workModel(opensAtLogin: Bool = true) -> EditorModel {
        EditorModel(preview: workProfile(), isNew: false, passwordStored: true,
                    storedTOTP: try? TOTP.decodeSecret(sampleSecret), configServer: "vpn.example.com:1194 · UDP",
                    opensAtLogin: opensAtLogin, now: now)
    }

    @MainActor private static func fortiModel() -> EditorModel {
        var p = Profile(id: "office", name: "Office", type: .forti)
        p.host = "vpn.example.com"
        p.port = 443
        p.trustedCert = String(repeating: "3f", count: 32)
        p.username = "alice"
        p.otpMode = .totp
        p.otpDelivery = .separate
        return EditorModel(preview: p, isNew: false, passwordStored: true, storedTOTP: try? TOTP.decodeSecret(sampleSecret),
                           now: now)
    }

    /// A saved profile protected by "Confirm with Touch ID" at `level`.
    @MainActor private static func protectedModel(_ level: AuthRequirement) -> EditorModel {
        var p = Profile(id: "acme", name: "Acme VPN", type: .openvpn)
        p.icon = "building.2"
        p.badgeStyle = .both
        p.username = "alice"
        p.otpMode = .totp
        p.requireAuth = level
        // At `connect` with a saved password the TOTP secret stays plain, so its code shows.
        return EditorModel(preview: p, isNew: false, passwordStored: true,
                           storedTOTP: level == .always ? nil : try? TOTP.decodeSecret(sampleSecret),
                           storedTOTPProtected: level == .always, configServer: "vpn.example.com:1194 · UDP", now: now)
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

        let rep: NSBitmapImageRep
        if let scale = RenderSnapshots.scaleOverride {
            rep = RenderSnapshots.bitmap(size, scale: scale)
        } else {
            guard let cached = hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds) else { return nil }
            rep = cached
        }
        hosting.cacheDisplay(in: hosting.bounds, to: rep)
        return rep.representation(using: .png, properties: [:])
    }
}
