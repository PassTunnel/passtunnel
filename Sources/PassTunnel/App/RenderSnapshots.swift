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
                snapshot(MenuBarPanelPreview(now: Date()).environmentObject(emptyModel), size: nil, dark: dark, to: out,
                         name: "menubar-panel-empty")
            }
            renderFirstRun(emptyModel, to: out)

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
            // "Hide codes until clicked", with the first code clicked: it shows for 20 s, the others stay hidden.
            model.prefs.hideCodes = true
            if let first = model.profiles.first { model.revealCodes(first) }
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
            let approval = GeneralSettings(previewLoginStatus: .requiresApproval, fullHeight: true, licensesAvailable: true)
            snapshot(approval.frame(width: 540).environmentObject(model),
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

            renderSplitWindow(model, sample: sample, store: store, now: now, to: out)
            try renderImportReview(model, home: home, store: store, now: now, to: out)

            // The menu bar of the new interface (NewInterface). Pinned Work and Travel with the connected, connecting
            // and dropped ones (four of six listed, badges for them); Home Lab dropped without being pinned; nothing
            // pinned or active (all listed, the shield); nothing pinned but some connected (all six, so the list
            // scrolls); then three (connected, Touch ID to connect with the code locked, dropped) with auto-type on.
            // Last, as it deletes sample profiles. Without an authenticator, turning on "Confirm with Touch ID"
            // encrypts nothing and makes no Secure Enclave key.
            let panel = AppModel(paths: paths, connections: ConnectionManager(authenticator: UnavailableAuthenticator()),
                                 live: false)
            panel.previewNow = now
            panel.previewStates = sample.states(now)
            panel.previewErrors = sample.errors
            panel.previewUnreachable = sample.unreachable
            panel.setPreviewDropped(sample.dropped)
            panel.prefs.autoType = false
            let (work, home, staging, travel) = (sample.ids[0], sample.ids[2], sample.ids[3], sample.ids[5])
            func pin(_ ids: [String]) throws {
                for id in sample.ids { try store.update(id) { $0.pinned = ids.contains(id) } }
                panel.reload()
            }
            for dark in [false, true] {
                snapshot(MenuBarPanelPreview(now: now).environmentObject(panel), size: nil, dark: dark, to: out,
                         name: "menubar-panel-pinned")
            }
            try pin([work])
            panel.previewStates = sample.states(now).filter { $0.key == work }
            panel.previewErrors = [:]
            panel.previewUnreachable = []
            panel.setPreviewDropped([home])
            for dark in [false, true] {
                snapshot(MenuBarPanelPreview(now: now).environmentObject(panel), size: nil, dark: dark, to: out,
                         name: "menubar-panel-dropped")
            }
            try pin([])
            panel.previewStates = [:]
            panel.setPreviewDropped([])
            for dark in [false, true] {
                snapshot(MenuBarPanelPreview(now: now).environmentObject(panel), size: nil, dark: dark, to: out,
                         name: "menubar-panel-idle")
            }
            panel.previewStates = sample.states(now)
            panel.previewErrors = sample.errors
            panel.previewUnreachable = sample.unreachable
            panel.setPreviewDropped(sample.dropped)
            for dark in [false, true] {
                snapshot(MenuBarPanelPreview(now: now).environmentObject(panel), size: nil, dark: dark, to: out,
                         name: "menubar-panel-scroll")
            }
            try pin([work, staging, travel])
            for id in sample.ids where ![work, staging, travel].contains(id) { try store.delete(id) }
            try store.update(staging) { $0.requireAuth = .always }
            panel.reload()
            panel.previewStates = sample.states(now).filter { $0.key == work }
            panel.previewErrors = [:]
            panel.previewLockedCodes = [staging]
            panel.prefs.autoType = true
            for dark in [false, true] {
                snapshot(MenuBarPanelPreview(now: now).environmentObject(panel), size: nil, dark: dark, to: out,
                         name: "menubar-panel")
            }
        } catch {
            FileHandle.standardError.write(Data("render failed: \(error.localizedDescription)\n".utf8))
            return 1
        }

        _ = EditorPreviewRenderer.renderAll(to: out.appendingPathComponent("editor", isDirectory: true))
        print(out.path)
        return 0
    }

    /// The redesigned window (behind `NewInterface`, not on the website yet), once per state of the selected profile:
    /// `main-split` connected, `-waiting` for a fresh code, `-dropped` and reconnecting, `-off`, `-failed`; then the
    /// code card's other states on the first profile: `-locked`, `-hidden`, `-copied`, `-narrow` (the smallest window,
    /// cards stacked) and `-template` (a custom code format). Sets its own overrides and leaves the model and the
    /// profiles as it found them.
    private static func renderSplitWindow(_ model: AppModel, sample: Sample, store: ProfileStore, now: Date, to out: URL) {
        let ids = sample.ids   // work, lab, home, staging, client, travel
        let configs = [ids[0]: "client\nremote vpn.example.com 1194 udp\n",
                       ids[2]: "client\nproto tcp\nremote 203.0.113.10 443\n",
                       ids[5]: "client\nremote vpn2.example.com 1194\nremote vpn3.example.com 1194\n"]
        for (id, text) in configs { try? Data(text.utf8).write(to: store.ovpnURL(id)) }
        // A connect waits into the next window: shown 3.6 s before it starts.
        let nextWindow = CodeCard.nextWindow(TOTPParams(), after: now)
        let waitingNow = nextWindow.addingTimeInterval(-3.6)
        model.previewCodeWaits = [ids[3]: nextWindow.addingTimeInterval(0.25)]
        model.previewReconnecting = [ids[5]: ReconnectInfo(attempt: 1, maxAttempts: 3, at: now)]
        model.previewActivity = sampleActivity(ids, now: now, waitingNow: waitingNow)
        let selection = model.selection
        func render(_ suffix: String, size: CGSize = CGSize(width: 1080, height: 700)) {
            for dark in [false, true] {
                snapshot(SplitWindowRender().environmentObject(model), size: size, dark: dark, to: out,
                         name: "main-split\(suffix)", window: true)
            }
        }
        let shown = [(ids[0], ""), (ids[3], "-waiting"), (ids[5], "-dropped"), (ids[2], "-off"), (ids[4], "-failed")]
        for (id, suffix) in shown {
            model.selection = id
            model.previewNow = suffix == "-waiting" ? waitingNow : now
            render(suffix)
        }
        model.previewNow = now

        model.selection = ids[0]
        model.previewLockedCodes = [ids[0]]
        render("-locked")
        model.previewLockedCodes = []
        model.prefs.hideCodes = true
        render("-hidden")
        model.prefs.hideCodes = false
        model.setPreviewCopy(CodeCard.Copy(profileID: ids[0], kind: .code, at: now,
                                           window: TOTP.counter(params: TOTPParams(), at: now)))
        render("-copied")
        model.setPreviewCopy(nil)
        render("-narrow", size: CGSize(width: 820, height: 640))
        let template = model.profile(ids[0])?.otpTemplate ?? OTPTemplatePreset.append.rawValue
        try? store.update(ids[0]) { $0.otpTemplate = "{otp}-{password}" }
        model.reload()
        render("-template")
        try? store.update(ids[0]) { $0.otpTemplate = template }
        model.reload()

        // The add view the sidebar's + opens (`add-vpn`), and the question about opening at login under the detail
        // once there is a profile (`main-split-login`).
        let helper = model.previewHelperStatus
        model.previewHelperStatus = .enabled
        model.refreshHelperStatus()
        model.selection = nil
        model.addingProfile = true
        for dark in [false, true] {
            snapshot(SplitWindowRender().environmentObject(model), size: CGSize(width: 1080, height: 700),
                     dark: dark, to: out, name: "add-vpn", window: true)
        }
        model.addingProfile = false
        model.previewHelperStatus = helper
        model.refreshHelperStatus()
        model.selection = ids[0]
        for dark in [false, true] {
            snapshot(SplitWindowRender(loginQuestion: true).environmentObject(model), size: CGSize(width: 1080, height: 700),
                     dark: dark, to: out, name: "main-split-login", window: true)
        }
        // The window "Show all" opens: the connected profile's whole activity, only its errors, and a profile without any.
        func renderActivityLog(_ id: String, _ name: String, errorsOnly: Bool = false) {
            guard let profile = model.profile(id) else { return }
            model.previewNow = now
            for dark in [false, true] {
                let content = ActivityLogContent(model: model, profile: profile, errorsOnly: errorsOnly)
                    .navigationTitle(profile.name)
                    .navigationSubtitle(String(localized: "Activity"))
                snapshot(content.environmentObject(model), size: CGSize(width: 620, height: 460), dark: dark, to: out,
                         name: name, window: true)
            }
        }
        renderActivityLog(ids[0], "activity-log")
        renderActivityLog(ids[5], "activity-log-errors", errorsOnly: true)
        renderActivityLog(ids[2], "activity-log-empty")
        renderErrorStates(model, ids: ids, now: now, to: out)

        model.selection = selection
        model.previewCodeWaits = [:]
        model.previewReconnecting = [:]
        model.previewActivity = [:]
        model.setPreviewDropped(sample.dropped)
    }

    /// The error states of the redesigned window (ClockBanner.swift, FailureCards.swift, OverlapSheet.swift), light and
    /// dark: `error-rejected-clock` (Work, a sign-in the server rejected, the gateway's clock 48 s behind, with the banner),
    /// `error-rejected` (the clock not checked yet), `error-rejected-clock-ok` (the time server says the clock is right),
    /// `error-unreachable` (Home Lab, the next try in 18 s), `-offline`, `-ended`, `error-host-not-found`, `error-other`
    /// (a failure with the tool's reason), `error-clock-banner` (a connected profile) and `overlap-sheet`. Sets its own
    /// overrides and leaves the model as it found it.
    private static func renderErrorStates(_ model: AppModel, ids: [String], now: Date, to out: URL) {
        let (work, dataCenter, homeLab, staging, travel) = (ids[0], ids[1], ids[2], ids[3], ids[5])
        let states = model.previewStates
        let errors = model.previewErrors
        let activity = model.previewActivity
        let before = model.selection
        defer {
            model.previewStates = states
            model.previewErrors = errors
            model.previewActivity = activity
            model.previewFailures = FailurePreview()
            model.selection = before
        }
        // The profile under test is not connected; the others keep their states.
        func render(_ name: String, profile: String, failure: ConnectionFailure?, error: String,
                    retry: UnreachableRetry? = nil, network: NetworkStatus = .unknown, clocks: [ClockOffset] = [],
                    events: [ActivityEvent] = [], size: CGSize = CGSize(width: 1080, height: 700)) {
            model.previewStates = states?.filter { $0.key != profile }
            model.previewErrors = (errors ?? [:]).merging([profile: error]) { $1 }
            model.previewActivity = [profile: events]
            model.previewFailures = FailurePreview(failures: failure.map { [profile: $0] } ?? [:],
                                                   retries: retry.map { [profile: $0] } ?? [:], network: network, clocks: clocks)
            model.selection = profile
            for dark in [false, true] {
                snapshot(SplitWindowRender().environmentObject(model), size: size, dark: dark, to: out, name: name, window: true)
            }
        }
        func event(_ ago: TimeInterval, _ kind: ActivityEvent.Kind) -> ActivityEvent { ActivityEvent(at: now.addingTimeInterval(-ago), kind) }
        func clock(_ offset: Int, _ source: ClockOffset.Source, _ server: String) -> ClockOffset {
            ClockOffset(offsetSeconds: offset, source: source, server: server, checkedAt: now.addingTimeInterval(-4))
        }

        // Sign-in rejected: the code was fresh (22 s left), the clock behind (the gateway's time), and the password.
        var rejected = ConnectionFailure(kind: .authRejected, at: now.addingTimeInterval(-2), reply: "AUTH_FAILED",
                                         credentialsSent: true, codeSent: true, codeSecondsLeft: 22)
        let rejectedError = PTError.authFailed("").localizedDescription
        let sent = ActivityEvent.Kind.sending(.init(username: "sam", password: true, code: true, codePrefix: "604", secondsLeft: 22,
                                                    format: OTPTemplatePreset.append.rawValue))
        let rejectedEvents = [event(5, .connecting(host: "vpn.example.com", port: 1194, transport: "udp")), event(3, sent),
                              event(2, .rejected(reply: "AUTH_FAILED"))]
        let behind = clock(48, .gateway, "vpn.example.com")
        rejected.clock = behind
        render("error-rejected-clock", profile: work, failure: rejected, error: rejectedError, clocks: [behind], events: rejectedEvents)
        rejected.clock = nil
        render("error-rejected", profile: work, failure: rejected, error: rejectedError, events: rejectedEvents)
        let right = clock(2, .timeServer, "time.apple.com")
        rejected.clock = right
        render("error-rejected-clock-ok", profile: work, failure: rejected, error: rejectedError, clocks: [right], events: rejectedEvents)

        // Server unreachable: three tries, the next in 18 s; then offline; then the tries are over.
        let timeout = "Connection timed out"
        let failure = ConnectionFailure(kind: .unreachable, at: now.addingTimeInterval(-12), reason: timeout, tries: 3)
        let unreachableError = PTError.serverUnreachable(server: "203.0.113.10:443", reason: timeout, log: "").localizedDescription
        let unreachableEvents = [event(42, .connecting(host: "203.0.113.10", port: 443, transport: "tcp")),
                                 event(12, .unreachable(tries: 3, reason: timeout)), event(12, .nextTry(at: now.addingTimeInterval(18)))]
        let wifi = NetworkStatus(online: true, interface: .wifi)
        func retry(next: TimeInterval?, waiting: Bool = false) -> UnreachableRetry {
            UnreachableRetry(tries: 3, maxTries: 5, nextTryAt: next.map { now.addingTimeInterval($0) }, waitingForNetwork: waiting,
                             firstFailedAt: now.addingTimeInterval(-42), lastFailedAt: now.addingTimeInterval(-12))
        }
        render("error-unreachable", profile: homeLab, failure: failure, error: unreachableError, retry: retry(next: 18), network: wifi,
               events: unreachableEvents)
        render("error-unreachable-offline", profile: homeLab, failure: failure, error: unreachableError,
               retry: retry(next: nil, waiting: true), network: NetworkStatus(online: false), events: unreachableEvents)
        render("error-unreachable-ended", profile: homeLab, failure: failure, error: unreachableError, network: wifi,
               events: unreachableEvents)

        // A name that was not found, and another failure with the tool's reason.
        render("error-host-not-found", profile: staging, failure: ConnectionFailure(kind: .hostNotFound, at: now),
               error: PTError.hostNotFound(server: "staging.example.net:443", log: "").localizedDescription,
               events: [event(4, .connecting(host: "staging.example.net", port: 443, transport: "tcp")),
                        event(2, .failed(kind: .hostNotFound, reason: nil, credentialsSent: false))])
        render("error-other", profile: travel, failure: ConnectionFailure(kind: .failed, at: now, reason: "Connection reset by peer"),
               error: String(localized: "The VPN connection could not be established. See the log for details."),
               events: [event(4, .connecting(host: "vpn2.example.com", port: 1194, transport: "udp")),
                        event(2, .failed(kind: .failed, reason: "Connection reset by peer", credentialsSent: false))])

        // The banner over a profile that is connected.
        model.previewStates = states
        model.previewErrors = errors
        model.previewActivity = activity
        model.previewFailures = FailurePreview(clocks: [behind])
        model.selection = work
        for dark in [false, true] {
            snapshot(SplitWindowRender().environmentObject(model), size: CGSize(width: 1080, height: 700), dark: dark, to: out,
                     name: "error-clock-banner", window: true)
        }
        model.previewFailures = FailurePreview(clocks: [behind])
        model.selection = work
        for dark in [false, true] {
            snapshot(SplitWindowRender().environmentObject(model), size: CGSize(width: 820, height: 640), dark: dark, to: out,
                     name: "error-clock-banner-narrow", window: true)
        }

        // "Data Center overlaps with Work": the same network and the same names, behind different DNS servers.
        let theirs = NetworkClaims(routes: [CIDR("10.0.0.0/8")!], dnsServers: ["10.8.0.1"], dnsDomains: ["example.com"])
        let mine = NetworkClaims(routes: [CIDR("10.0.0.0/8")!, CIDR("10.9.0.0/16")!], dnsServers: ["10.9.0.1"], dnsDomains: ["example.com"])
        if let p = model.profile(dataCenter) {
            let overlap = ProfileOverlap(profileID: work, name: "Work", overlaps: mine.overlaps(with: theirs), mine: mine, theirs: theirs)
            for dark in [false, true] {
                snapshot(OverlapSheet(request: OverlapRequest(profile: p, overlaps: [overlap]))
                            .background(Palette.background).environmentObject(model),
                         size: nil, dark: dark, to: out, name: "overlap-sheet")
            }
        }
    }

    /// The activity of the sample profiles, matching their states: Work connected (sent just before it came up, after
    /// an earlier session), Staging waiting for a code, Travel dropped, Partner Network rejected.
    private static func sampleActivity(_ ids: [String], now: Date, waitingNow: Date) -> [String: [ActivityEvent]] {
        func event(_ ago: TimeInterval, _ kind: ActivityEvent.Kind) -> ActivityEvent {
            ActivityEvent(at: now.addingTimeInterval(-ago), kind)
        }
        func sending(_ user: String, code prefix: String, left: Int? = 22) -> ActivityEvent.Kind {
            .sending(.init(username: user, password: true, code: true, codePrefix: prefix, secondsLeft: left,
                           format: OTPTemplatePreset.append.rawValue))
        }
        let up: TimeInterval = 72 * 60 + 14
        let work: [ActivityEvent] = [
            event(26 * 3600 + 60, .connecting(host: "vpn.example.com", port: 1194, transport: "udp")),
            event(26 * 3600 + 58, sending("sam", code: "318")),
            event(26 * 3600 + 56, .authAccepted),
            event(26 * 3600 + 55, .connected(address: "10.8.0.6")),
            event(25 * 3600, .linkDropped(willReconnect: true)),
            event(25 * 3600 - 20, .reconnecting(attempt: 1, of: 3)),
            event(25 * 3600 - 24, .waitingForCode(reason: .expiring, seconds: 4, codePrefix: "771")),
            event(25 * 3600 - 29, sending("sam", code: "204", left: 25)),
            event(25 * 3600 - 31, .connected(address: "10.8.0.6")),
            event(24 * 3600 + 1800, .disconnectedByUser),
            event(up + 5, .connecting(host: "vpn.example.com", port: 1194, transport: "udp")),
            event(up + 3, .waitingForCode(reason: .used, seconds: 9, codePrefix: "604")),
            event(up + 2, sending("sam", code: "604")),
            event(up + 1, .authAccepted),
            event(up, .connected(address: "10.8.0.6")),
        ]
        let travel: [ActivityEvent] = [
            event(3 * 3600 + 40, .connecting(host: "vpn2.example.com", port: 1194, transport: "udp")),
            event(3 * 3600 + 37, .unreachable(tries: 3, reason: "Connection refused")),
            event(3 * 3600 + 36, .nextTry(at: now.addingTimeInterval(-(3 * 3600 + 6)))),
            event(3 * 3600 + 5, .connecting(host: "vpn2.example.com", port: 1194, transport: "udp")),
            event(3 * 3600 + 3, sending("sam", code: "482")),
            event(3 * 3600 + 1, .connected(address: "10.8.1.14")),
            event(30, .linkDropped(willReconnect: true)),
            event(25, .reconnecting(attempt: 1, of: 3)),
        ]
        let staging: [ActivityEvent] = [
            ActivityEvent(at: waitingNow.addingTimeInterval(-1), .connecting(host: "staging.example.net", port: 443, transport: "tcp")),
            ActivityEvent(at: waitingNow, .waitingForCode(reason: .expiring, seconds: 4, codePrefix: "482")),
        ]
        let partner: [ActivityEvent] = [
            event(95, .connecting(host: "203.0.113.20", port: 1194, transport: "udp")),
            event(93, .sending(.init(username: "s.guest", password: true, code: false))),
            event(92, .rejected(reply: "AUTH_FAILED")),
        ]
        return [ids[0]: work, ids[3]: staging, ids[4]: partner, ids[5]: travel]
    }

    /// The redesigned window without profiles (behind `NewInterface`, not on the website yet): `first-run` with the
    /// helper card before the helper is installed, `first-run-approval` while macOS waits for its approval.
    private static func renderFirstRun(_ model: AppModel, to out: URL) {
        for (status, name) in [(HelperStatus.notRegistered, "first-run"), (.requiresApproval, "first-run-approval")] {
            model.previewHelperStatus = status
            model.refreshHelperStatus()
            for dark in status == .notRegistered ? [false, true] : [false] {
                snapshot(SplitWindowRender().environmentObject(model), size: CGSize(width: 1080, height: 700),
                         dark: dark, to: out, name: name, window: true)
            }
        }
        model.previewHelperStatus = nil
    }

    /// The import review of the redesigned window (`ImportReviewView`), light and dark: `import-review` as designed
    /// (two lines skipped, the code secret missing), `-ready` with the secret added, `-certificate` for a
    /// certificate-only file whose keys come from files next to it, and `-narrow` at the window's smallest size, where
    /// the columns stack. Nothing is added; the model is left as it was found.
    private static func renderImportReview(_ model: AppModel, home: URL, store: ProfileStore, now: Date,
                                           to out: URL) throws {
        let downloads = home.appendingPathComponent("Downloads", isDirectory: true)
        try FileManager.default.createDirectory(at: downloads, withIntermediateDirectories: true)
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBCA==\n-----END CERTIFICATE-----\n"
        let work = "client\ndev tun\nremote vpn.example.com 1194 udp\nscript-security 2\nup /etc/openvpn/update-dns\n"
            + "<ca>\n\(pem)</ca>\n<cert>\n\(pem)</cert>\n<key>\n-----BEGIN PRIVATE KEY-----\nMIIBCC==\n"
            + "-----END PRIVATE KEY-----\n</key>\n<auth-user-pass>\nalice\nsample-password\n</auth-user-pass>\n"
            + "static-challenge \"Enter code\" 1\n"
        let files: [String: Data] = [
            "work.ovpn": Data(work.utf8),
            "home-lab.ovpn": Data("client\nremote 203.0.113.10 443 tcp\nca ca.crt\npkcs12 home.p12\ntls-crypt ta.key\n".utf8),
            "ca.crt": Data(pem.utf8),
            "home.p12": Data([0, 1, 2, 3]),
            "ta.key": Data("-----BEGIN OpenVPN Static key V1-----\n0123abcd\n-----END OpenVPN Static key V1-----\n".utf8),
        ]
        for (name, data) in files { try data.write(to: downloads.appendingPathComponent(name)) }

        let selection = model.selection
        defer {
            model.importReview = nil
            model.selection = selection
        }
        func render(_ file: String, _ name: String, size: CGSize = CGSize(width: 1080, height: 700),
                    edit: (ImportReviewModel) -> Void = { _ in }) throws {
            let review = ImportReviewModel(draft: try store.analyzeOVPN(downloads.appendingPathComponent(file)))
            review.previewNow = now
            edit(review)
            model.selection = nil
            model.importReview = review
            for dark in [false, true] {
                snapshot(SplitWindowRender().environmentObject(model), size: size, dark: dark, to: out, name: name,
                         window: true)
            }
        }
        try render("work.ovpn", "import-review") { $0.name = "Work" }
        try render("work.ovpn", "import-review-ready") {
            $0.name = "Work"
            $0.apply(.secret(Data("12345678901234567890".utf8)))
        }
        try render("home-lab.ovpn", "import-review-certificate")
        try render("work.ovpn", "import-review-narrow", size: CGSize(width: 820, height: 560)) { $0.name = "Work" }
    }

    @ViewBuilder
    private static func tabView(_ tab: SettingsTab, model: AppModel) -> some View {
        switch tab {
        // The whole page, not the scrolling window; the menu bar card as the interface in use shows it.
        case .general: GeneralSettings(previewLoginStatus: .enabled, fullHeight: true, licensesAvailable: true)
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

/// The redesigned window for the renders. On macOS 26 the window server draws the glass sidebar, and offscreen its
/// rows stay blank: there the render lays the window's own sidebar and detail out as the window does (the sidebar
/// 272 pt wide, 8 pt in, on the list's flat background instead of glass, its search field drawn in place).
private struct SplitWindowRender: View {
    @EnvironmentObject private var model: AppModel
    /// The question about opening at login under the detail.
    var loginQuestion = false

    var body: some View {
        if #available(macOS 26, *) {
            let shape = RoundedRectangle(cornerRadius: Radius.panel, style: .continuous)
            HStack(spacing: 0) {
                ProfileSidebar(previewWithoutSearch: true)
                    .safeAreaInset(edge: .top, spacing: 0) { searchField }
                    .frame(width: 272)
                    .clipShape(shape)
                    .edge(shape, Palette.glassEdge, width: Elevation.glassEdge)
                    .padding(8)
                SplitDetail(previewLoginQuestion: loginQuestion)
            }
        } else {
            MainSplitView(previewLoginQuestion: loginQuestion)
        }
    }

    /// As macOS 26 draws the sidebar's search field.
    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
            Text(String(localized: "Search profiles"))
            Spacer(minLength: 0)
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 10)
        .frame(height: 28)
        .background(Palette.card, in: Capsule())
        .edge(Capsule(), Palette.line)
        .padding(.horizontal, 10)
        .padding(.vertical, 9)
    }
}
