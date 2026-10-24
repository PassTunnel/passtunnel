import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// `PASSTUNNEL_RENDER=<dir> PassTunnel` renders the main screens to PNGs offscreen and exits.
/// Uses a throwaway support directory and Keychain service; nothing is shown on screen and no
/// VPN, helper or system setting is touched. Handy for README screenshots and design checks.
/// `PASSTUNNEL_RENDER_SCALE=4` renders at that backing scale instead of 2 (the website uses 4).
@MainActor
enum RenderSnapshots {
    /// Backing scale from `PASSTUNNEL_RENDER_SCALE` (1–8), if set.
    static let scaleOverride: CGFloat? = {
        guard let raw = ProcessInfo.processInfo.environment["PASSTUNNEL_RENDER_SCALE"], let value = Double(raw),
              (1...8).contains(value) else { return nil }
        return CGFloat(value)
    }()

    static var scale: CGFloat { scaleOverride ?? 2 }

    static func bitmap(_ size: CGSize, scale: CGFloat) -> NSBitmapImageRep {
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int((size.width * scale).rounded()),
                                   pixelsHigh: Int((size.height * scale).rounded()),
                                   bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                   colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        rep.size = size
        return rep
    }

    static func run(outputDirectory: String) -> Int32 {
        let out = URL(fileURLWithPath: (outputDirectory as NSString).expandingTildeInPath, isDirectory: true)
        try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)

        // Isolated storage: a temp support dir and a throwaway Keychain service.
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("PassTunnelRender-\(UUID().uuidString)")
        let service = "PassTunnelRender-\(UUID().uuidString)"
        setenv("PASSTUNNEL_HOME", home.path, 1)
        setenv("PASSTUNNEL_KEYCHAIN_SERVICE", service, 1)
        let paths = AppPaths.default
        let store = ProfileStore(paths: paths)
        var created: [String] = []
        defer {
            for id in created { for kind in SecretKind.allCases { Secrets.delete(id, kind) } }
            try? FileManager.default.removeItem(at: home)
        }

        do {
            // Empty state first, before any profile exists.
            let emptyModel = AppModel(paths: paths, connections: ConnectionManager(), live: false)
            emptyModel.previewStates = [:]
            emptyModel.previewErrors = [:]
            for dark in [false, true] {
                snapshot(MainView().environmentObject(emptyModel), size: CGSize(width: 600, height: 560),
                         dark: dark, to: out, name: "main-empty", window: true)
            }

            // The design system (App/Design): every token and base component, also with Increase Contrast.
            for contrast in [false, true] {
                Palette.previewIncreasedContrast = contrast
                for dark in [false, true] {
                    snapshot(DesignGallery(isDark: dark, isContrast: contrast), size: nil, dark: dark, to: out,
                             name: contrast ? "components-contrast" : "components")
                }
            }
            Palette.previewIncreasedContrast = false

            // Every status a profile can show in the redesigned views (DisplayStatus), in the render's language.
            let statusNow = Date(timeIntervalSince1970: 1_800_000_000)
            for dark in [false, true] {
                snapshot(ProfileStatusGallery(now: statusNow), size: nil, dark: dark, to: out, name: "profile-status")
            }

            let sample = try makeSampleProfiles(store)
            created = sample.ids
            var prefs = Preferences.load(paths: paths)
            prefs.defaultProfile = sample.ids.first
            try prefs.save(paths: paths)

            let model = AppModel(paths: paths, connections: ConnectionManager(), live: false)
            let now = Date(timeIntervalSince1970: (Date().timeIntervalSince1970 / 30).rounded(.down) * 30 + 7)
            model.previewNow = now
            model.previewStates = sample.states(now)
            model.previewErrors = sample.errors
            model.previewUnreachable = sample.unreachable
            model.setPreviewDropped(sample.dropped)
            model.previewHelperStatus = .enabled
            model.refreshHelperStatus()
            model.selection = sample.ids.first

            for dark in [false, true] {
                snapshot(MainView().environmentObject(model), size: CGSize(width: 680, height: 470),
                         dark: dark, to: out, name: "main", window: true)
            }
            model.prefs.hideCodes = true
            snapshot(MainView().environmentObject(model), size: CGSize(width: 680, height: 470),
                     dark: false, to: out, name: "main-hidden-codes", window: true)
            model.prefs.hideCodes = false

            // "Confirm with Touch ID" protecting the TOTP secret: the first row's code is locked until confirmed
            // (no Secure Enclave key is made for screenshots).
            if let first = sample.ids.first {
                model.previewLockedCodes = [first]
                for dark in [false, true] {
                    snapshot(MainView().environmentObject(model), size: CGSize(width: 680, height: 470),
                             dark: dark, to: out, name: "main-code-locked", window: true)
                }
                model.previewLockedCodes = []
            }

            if let needy = model.profiles.first(where: { !$0.needs.isEmpty }) {
                let req = CredentialRequest(profile: needy, needs: needy.needs)
                for dark in [false, true] {
                    snapshot(CredentialSheet(request: req).environmentObject(model), size: nil,
                             dark: dark, to: out, name: "credential-sheet")
                }
            }

            // Menu bar titles for every palette, on light and dark menu bars (the main window marked drops seen).
            model.setPreviewDropped(sample.dropped)
            for palette in BadgePalette.allCases {
                model.prefs.badgePalette = palette
                let badges = MenuBarIcon.badges(for: model)
                for dark in [false, true] {
                    let img = MenuBarIcon.rendered(badges: badges, palette: palette, showLock: true,
                                                   locked: true, dark: dark, scale: max(4, scale))
                    let view = Image(nsImage: img)
                        .padding(.horizontal, 10)
                        .frame(height: 30)
                        .background(dark ? Color(white: 0.12) : Color(white: 0.95))
                    snapshot(view, size: nil, dark: dark, to: out, name: "menubar-\(palette.rawValue)")
                    // The badges alone on a transparent background, at the render scale.
                    let bare = MenuBarIcon.rendered(badges: badges, palette: palette, showLock: true,
                                                    locked: true, dark: dark, scale: scale)
                    if let rep = bare.representations.first as? NSBitmapImageRep,
                       let png = rep.representation(using: .png, properties: [:]) {
                        try? png.write(to: out.appendingPathComponent("menubar-badges-\(palette.rawValue)\(dark ? "-dark" : "").png"))
                    }
                }
            }
            model.prefs.badgePalette = .pastel

            // Settings tabs.
            model.prefs.autoType = true
            for tab in SettingsTab.allCases {
                for dark in [false, true] {
                    let pane = tabView(tab, model: model)
                    snapshot(pane.frame(width: 540).environmentObject(model), size: nil, dark: dark, to: out,
                             name: "settings-\(tab.rawValue)", window: true)
                }
            }
            snapshot(GeneralSettings(previewLoginStatus: .requiresApproval).frame(width: 540).environmentObject(model),
                     size: nil, dark: false, to: out, name: "settings-general-login-approval", window: true)

            // Onboarding.
            for (i, status) in [HelperStatus.enabled, .notRegistered, .enabled].enumerated() {
                model.previewHelperStatus = status
                model.refreshHelperStatus()
                for dark in [false, true] {
                    snapshot(OnboardingView(step: i).environmentObject(model), size: nil, dark: dark, to: out,
                             name: "onboarding-\(i + 1)")
                }
            }
            model.previewHelperStatus = .requiresApproval
            model.refreshHelperStatus()
            snapshot(OnboardingView(step: 1).environmentObject(model), size: nil, dark: false, to: out,
                     name: "onboarding-2-approval")
        } catch {
            FileHandle.standardError.write(Data("render failed: \(error.localizedDescription)\n".utf8))
            return 1
        }

        _ = EditorPreviewRenderer.renderAll(to: out.appendingPathComponent("editor", isDirectory: true))
        print(out.path)
        return 0
    }

    @ViewBuilder
    private static func tabView(_ tab: SettingsTab, model: AppModel) -> some View {
        switch tab {
        case .general: GeneralSettings(previewLoginStatus: .enabled)
        case .shortcuts: ShortcutSettings(previewTrusted: false)
        case .helper:
            let real = BundledTools.load()
            HelperSettings(tools: real.isEmpty ? BundledTools.parse(sampleNotices) : real)
        default: SettingsPane(tab: tab)
        }
    }

    // MARK: sample data

    struct Sample {
        var ids: [String]
        var states: (Date) -> [String: ConnectionState]
        var errors: [String: String]
        var unreachable: Set<String>
        var dropped: Set<String>
    }

    private static func makeSampleProfiles(_ store: ProfileStore) throws -> Sample {
        func make(_ name: String, _ type: VPNType, _ edit: (inout Profile) -> Void) throws -> Profile {
            var p = try store.create(name: name, type: type)
            edit(&p)
            try store.save(p)
            return p
        }
        let secret = "JBSWY3DPEHPK3PXP"
        let work = try make("Work", .openvpn) {
            $0.username = "sam"
            $0.otpMode = .totp
            $0.pinned = true
            $0.icon = "briefcase.fill"
            $0.badgeStyle = .letter
        }
        try Secrets.set(work.id, .totp, secret)
        try Secrets.set(work.id, .password, "sample-password")
        let lab = try make("Data Center", .forti) {
            $0.username = "sam.ops"
            $0.otpMode = .totp
            $0.host = "gw.example.net"
            $0.icon = "server.rack"
            $0.badgeStyle = .icon
            $0.healthHost = "10.20.0.1"
        }
        try Secrets.set(lab.id, .totp, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        let home = try make("Home Lab", .openvpn) {
            $0.passwordMode = .none
            $0.icon = "house.fill"
            $0.badgeStyle = .both
        }
        let staging = try make("Staging", .forti) {
            $0.username = "deploy"
            $0.otpMode = .totp
            $0.host = "staging.example.net"
        }
        try Secrets.set(staging.id, .totp, "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U")
        let client = try make("Partner Network", .openvpn) {
            $0.username = ""
            $0.lastUsername = "s.guest"
            $0.passwordMode = .ask
            $0.otpMode = .ask
        }
        try Secrets.set(client.id, .totp, "KRUGS4ZANFZSAYJAORSXG5A")
        let travel = try make("Travel", .openvpn) {
            $0.username = "sam"
            $0.otpMode = .totp
            $0.icon = "airplane"
            $0.badgeStyle = .icon
            $0.pinned = true
        }
        try Secrets.set(travel.id, .totp, "ONSWG4TFORZWK5DUMVZXIIDTMVRXEZLU")

        return Sample(
            ids: [work.id, lab.id, home.id, staging.id, client.id, travel.id],
            states: { now in [
                work.id: .connected(ip: "10.8.0.6", since: now.addingTimeInterval(-(72 * 60 + 14))),
                lab.id: .connected(ip: "172.16.4.21", since: now.addingTimeInterval(-540)),
                staging.id: .connecting(String(localized: "Authenticating…")),
            ] },
            errors: [client.id: String(localized: "The server rejected the sign-in. Check the user name, password and one-time code.")],
            unreachable: [lab.id],
            dropped: [travel.id]
        )
    }

    private static let sampleNotices = """
    openvpn          2.7.7      GPL-2.0 (with OpenSSL linking exception)
                     https://openvpn.net/community-downloads/

    openfortivpn     1.24.1     GPL-3.0 (with OpenSSL linking exception)
                     https://github.com/adrienverge/openfortivpn

    lz4              1.10.0     BSD-2-Clause
                     https://github.com/lz4/lz4

    openssl@3        3.6.4      Apache-2.0
                     https://www.openssl.org/source/
    """

    // MARK: rendering

    /// Hosts the view in an offscreen window (never ordered in) so AppKit-backed controls render too.
    /// `size == nil` uses the view's fitting size.
    static func snapshot<V: View>(_ view: V, size: CGSize?, dark: Bool, to dir: URL, name: String, window titled: Bool = false) {
        let appearance = NSAppearance(named: dark ? .darkAqua : .aqua)!
        let host = NSHostingView(rootView: AnyView(view))
        host.appearance = appearance
        var frame = NSRect(origin: .zero, size: size ?? host.fittingSize)
        if frame.width < 1 || frame.height < 1 { frame.size = host.fittingSize }
        let style: NSWindow.StyleMask = titled ? [.titled, .closable, .miniaturizable, .resizable] : [.borderless]
        let window = NSWindow(contentRect: frame, styleMask: style, backing: .buffered, defer: false)
        window.appearance = appearance
        window.isReleasedWhenClosed = false
        if titled, #available(macOS 14, *) {
            // Lets .navigationTitle / .toolbar reach the NSWindow as they do in a scene, in both
            // appearances so light and dark renders have the same size.
            host.sceneBridgingOptions = [.title, .toolbars]
            // Offscreen, the content view sits below the title bar already; no extra inset.
            host.safeAreaRegions = []
            window.toolbarStyle = .unified
        }
        window.contentView = host
        if size == nil {
            host.layoutSubtreeIfNeeded()
            let fit = host.fittingSize
            window.setContentSize(fit)
            frame.size = fit
        }
        host.frame = NSRect(origin: .zero, size: frame.size)
        for _ in 0..<4 {
            host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.08))
        }
        host.display()

        if titled {
            // The bridged toolbar grows the title bar after creation; fill the area below it.
            host.frame = window.contentLayoutRect
            for _ in 0..<2 {
                host.layoutSubtreeIfNeeded()
                RunLoop.current.run(until: Date().addingTimeInterval(0.05))
            }
        }
        let size = titled ? (host.superview?.bounds.size ?? frame.size) : frame.size
        func bitmap(_ size: CGSize) -> NSBitmapImageRep { Self.bitmap(size, scale: scale) }
        let content = bitmap(host.bounds.size)
        host.cacheDisplay(in: host.bounds, to: content)
        var titleBar: NSBitmapImageRep?
        var titleBarHeight: CGFloat = 0
        if titled, let frameView = host.superview {
            // The frame view supplies the title bar and toolbar strip above the content.
            titleBarHeight = max(0, size.height - host.bounds.height)
            // Toolbar glass (the platter behind toolbar items) needs the window server and draws as an
            // opaque white capsule offscreen; leave it out so light and dark look alike.
            hideToolbarGlass(in: frameView)
            let rep = bitmap(size)
            frameView.cacheDisplay(in: frameView.bounds, to: rep)
            titleBar = rep
        }

        let rep = bitmap(size)
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        let full = NSRect(origin: .zero, size: size)
        appearance.performAsCurrentDrawingAppearance {
            NSColor.windowBackgroundColor.setFill()
            full.fill()
            content.draw(in: NSRect(x: 0, y: 0, width: size.width, height: size.height - titleBarHeight), from: .zero,
                         operation: .sourceOver, fraction: 1, respectFlipped: false, hints: nil)
            if let titleBar, titleBarHeight > 0 {
                let strip = NSRect(x: 0, y: size.height - titleBarHeight, width: size.width, height: titleBarHeight)
                NSColor.windowBackgroundColor.setFill()
                strip.fill()
                titleBar.draw(in: strip, from: strip, operation: .sourceOver, fraction: 1, respectFlipped: false, hints: nil)
                NSColor.separatorColor.setFill()
                NSRect(x: 0, y: strip.minY, width: size.width, height: 0.5).fill()
            }
        }
        NSGraphicsContext.restoreGraphicsState()

        let file = dir.appendingPathComponent("\(name)\(dark ? "-dark" : "").png")
        if let png = rep.representation(using: .png, properties: [:]) {
            try? png.write(to: file)
        }
        window.contentView = nil
        window.close()
    }

    private static func hideToolbarGlass(in view: NSView) {
        if String(describing: type(of: view)) == "NSToolbarPlatterView" {
            view.isHidden = true
            return
        }
        for sub in view.subviews { hideToolbarGlass(in: sub) }
    }
}
