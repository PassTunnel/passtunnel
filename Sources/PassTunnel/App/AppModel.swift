import AppKit
import Combine
import PassTunnelCore
import PassTunnelShared
import SwiftUI

struct EditorRequest: Identifiable {
    let id = UUID()
    var profileID: String?
    var newType: VPNType?
}

struct CredentialRequest: Identifiable {
    let id = UUID()
    let profile: Profile
    let needs: [CredentialField]
}

struct ToastMessage: Identifiable, Equatable {
    let id = UUID()
    let text: String
    var symbol = "checkmark.circle.fill"
}

struct AppAlert: Identifiable {
    let id = UUID()
    let title: String
    let message: String
    var opensHelperSettings = false
}

/// App-wide state shared by the main window, menu bar, settings and hotkeys.
@MainActor
final class AppModel: ObservableObject {
    static private(set) var shared: AppModel!

    let store: ProfileStore
    let connections: ConnectionManager
    let paths: AppPaths

    @Published private(set) var profiles: [Profile] = []
    @Published var prefs: Preferences {
        didSet { if prefs != oldValue { prefsChanged(from: oldValue) } }
    }
    @Published var selection: String?
    @Published var searchText = ""
    @Published var editor: EditorRequest?
    @Published var credentialRequest: CredentialRequest?
    @Published var toast: ToastMessage?
    @Published var alert: AppAlert?
    @Published var pendingDelete: Profile?
    @Published var showOnboarding = false
    @Published var settingsTab: SettingsTab = .general
    @Published private(set) var droppedUnseen: Set<String> = []
    @Published private(set) var helperStatus: HelperStatus = .notRegistered
    /// The registered helper is running but speaks another protocol version (left from another app version).
    @Published private(set) var helperOutdated = false
    private var checkingHelperVersion = false
    /// Set when the CLI asked the app to install or remove the helper; Settings → Helper consumes it.
    @Published var pendingHelperAction: HelperHandoff?

    /// Render/preview overrides; when set, they replace the live connection data.
    var previewStates: [String: ConnectionState]?
    var previewErrors: [String: String]?
    var previewHelperStatus: HelperStatus?
    var previewNow: Date?

    private var secretCache: [String: Data] = [:]
    private var missingSecret: Set<String> = []
    private var bag = Set<AnyCancellable>()
    private var toastTask: Task<Void, Never>?
    private var reloadTimer: Timer?
    private var watcher: ProfilesWatcher?
    var onPrefsChanged: ((Preferences, Preferences) -> Void)?

    static let onboardingKey = "PTOnboardingDone"

    init(paths: AppPaths = .default, connections: ConnectionManager, live: Bool = true) {
        self.paths = paths
        self.store = ProfileStore(paths: paths)
        self.connections = connections
        self.prefs = Preferences.load(paths: paths)
        Self.shared = self
        reload()
        connections.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
            .store(in: &bag)
        guard live else { return }
        connections.start()
        showOnboarding = !UserDefaults.standard.bool(forKey: Self.onboardingKey)
        refreshHelperStatus()
        connections.events
            .receive(on: DispatchQueue.main)
            .sink { [weak self] in self?.handle($0) }
            .store(in: &bag)
        NotificationCenter.default.publisher(for: ImportActions.didImport)
            .sink { [weak self] note in
                guard let self else { return }
                self.reload()
                if let id = note.userInfo?["profileID"] as? String { self.selection = id }
                if self.showOnboarding && !self.profiles.isEmpty { self.finishOnboarding() }
            }
            .store(in: &bag)
        NotificationCenter.default.publisher(for: ImportActions.openEditor)
            .sink { [weak self] note in
                guard let self else { return }
                self.reload()
                let request = EditorRequest(profileID: note.userInfo?["profileID"] as? String, newType: nil)
                // A sheet that is still closing (onboarding) would swallow the new one.
                if let closed = self.onboardingClosedAt, Date().timeIntervalSince(closed) < 1 {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.editor = request }
                } else {
                    self.editor = request
                }
            }
            .store(in: &bag)
        // The CLI can change profiles, secrets and preferences while the app runs: reload when the
        // files change, when the CLI says so (Keychain items), when the app becomes active, and
        // every few seconds as a fallback.
        watcher = ProfilesWatcher(paths: paths) { [weak self] in
            MainActor.assumeIsolated { self?.reloadFromDisk() }
        }
        watcher?.start()
        DistributedNotificationCenter.default().publisher(for: ProfileChangeSignal.name)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in self?.reloadFromDisk() }
            .store(in: &bag)
        NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
            .sink { [weak self] _ in self?.reloadFromDisk() }
            .store(in: &bag)
        reloadTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.reloadFromDisk() }
        }
    }

    // MARK: data

    /// Re-reads the profiles and their TOTP secrets. Cheap when nothing changed (no UI update),
    /// so it is safe to call after the app's own writes.
    func reload() {
        let fresh = store.list()
        let secretsChanged = refreshSecrets(for: fresh)
        if fresh != profiles {
            profiles = fresh
        } else if secretsChanged {
            objectWillChange.send()
        }
        if let sel = selection, !fresh.contains(where: { $0.id == sel }) { selection = nil }
    }

    /// Picks up changes made by the CLI (profiles, Keychain items, preferences). Editor sheets keep
    /// their own copy, so in-app edits in progress are not discarded.
    func reloadFromDisk() {
        reload()
        let diskPrefs = Preferences.load(paths: paths)
        if diskPrefs != prefs { prefs = diskPrefs }
        refreshHelperStatus()
    }

    /// Rebuilds the TOTP secret cache from the Keychain; true when anything differs from before
    /// (a secret saved, replaced or removed by the CLI).
    @discardableResult
    private func refreshSecrets(for list: [Profile]) -> Bool {
        var cache: [String: Data] = [:]
        var missing: Set<String> = []
        for p in list where p.otpMode != .none {
            if let raw = Secrets.get(p.id, .totp), let data = try? TOTP.decodeSecret(raw) {
                cache[p.id] = data
            } else {
                missing.insert(p.id)
            }
        }
        let changed = cache != secretCache || missing != missingSecret
        secretCache = cache
        missingSecret = missing
        return changed
    }

    /// The profile as stored right now, or nil when it was deleted. Actions use this, never the
    /// copy a view captured: the CLI may have changed the profile since. Refreshes the UI when the
    /// stored version differs from the one shown.
    func storedProfile(_ p: Profile) -> Profile? {
        let fresh = try? store.get(p.id)
        if fresh != profile(p.id) { reload() }
        return fresh
    }

    func profile(_ id: String) -> Profile? { profiles.first { $0.id == id } }

    var filteredProfiles: [Profile] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return profiles }
        return profiles.filter {
            $0.name.localizedCaseInsensitiveContains(q) || $0.id.localizedCaseInsensitiveContains(q)
                || $0.username.localizedCaseInsensitiveContains(q) || $0.host.localizedCaseInsensitiveContains(q)
        }
    }

    var defaultProfile: Profile? {
        if let id = prefs.defaultProfile, let p = profile(id) { return p }
        return profiles.first
    }

    func isDefault(_ p: Profile) -> Bool { prefs.defaultProfile == p.id }

    private func prefsChanged(from old: Preferences) {
        do { try prefs.save(paths: paths) } catch { showError(error) }
        onPrefsChanged?(old, prefs)
    }

    func refreshHelperStatus() {
        if let previewHelperStatus { helperStatus = previewHelperStatus; return }
        guard Bundle.main.bundleIdentifier != nil else { helperStatus = .notFound; return }
        let s = HelperInstaller.status
        let changed = s != helperStatus
        if changed { helperStatus = s }
        if s != .enabled {
            helperOutdated = false
        } else if changed || helperOutdated {
            checkHelperVersion()
        }
    }

    /// Asks the running helper for its protocol version and build; a mismatch means it must be updated
    /// (Settings → Helper → Update Helper re-registers it from this copy of the app).
    func checkHelperVersion() {
        guard previewHelperStatus == nil, !checkingHelperVersion else { return }
        checkingHelperVersion = true
        Task {
            let outdated = try? await HelperClient.shared.isOutdated()
            checkingHelperVersion = false
            if let outdated { helperOutdated = outdated }
        }
    }

    // MARK: connection state

    func state(_ id: String) -> ConnectionState {
        if let previewStates { return previewStates[id] ?? .disconnected }
        return connections.states[id] ?? .disconnected
    }

    func error(_ id: String) -> String? {
        if let previewErrors { return previewErrors[id] }
        return connections.lastError[id]
    }

    /// Connected, but part of the tunnel set-up failed.
    func warning(_ id: String) -> String? {
        if previewStates != nil { return nil }
        return connections.warnings[id]
    }

    func isUnreachable(_ id: String) -> Bool {
        if previewStates != nil { return previewUnreachable.contains(id) }
        return connections.health[id] == .unreachable
    }
    var previewUnreachable: Set<String> = []
    var previewReconnecting: [String: ReconnectInfo] = [:]

    func reconnectInfo(_ id: String) -> ReconnectInfo? {
        if previewStates != nil { return previewReconnecting[id] }
        return connections.reconnecting[id]
    }

    /// Log excerpt for the last error: from the connection manager, else the log file.
    func errorLog(_ id: String) -> String? {
        if previewStates == nil, let log = connections.lastErrorLog[id], !log.isEmpty { return log }
        return logTail(id)
    }

    var now: Date { previewNow ?? Date() }

    /// Profiles shown as badges in the menu bar.
    var menuBarProfiles: [Profile] {
        profiles.filter { p in
            if p.pinned || droppedUnseen.contains(p.id) { return true }
            if case .disconnected = state(p.id) { return false }
            return true
        }
    }

    func markDropsSeen() {
        if !droppedUnseen.isEmpty { droppedUnseen.removeAll() }
    }

    func setPreviewDropped(_ ids: Set<String>) { droppedUnseen = ids }

    // MARK: codes

    private func totpSecret(_ p: Profile) -> Data? {
        if let s = secretCache[p.id] { return s }
        if missingSecret.contains(p.id) { return nil }
        guard let raw = Secrets.get(p.id, .totp), let data = try? TOTP.decodeSecret(raw) else {
            missingSecret.insert(p.id)
            return nil
        }
        secretCache[p.id] = data
        return data
    }

    func hasCode(_ p: Profile) -> Bool { p.otpMode == .totp && totpSecret(p) != nil }

    /// Current code for profiles with a stored TOTP secret (also used for `.ask` profiles to prefill),
    /// for display. Uses the latest loaded settings even when the caller holds an older copy.
    func code(for p: Profile, at date: Date = Date()) -> (code: String, remaining: Int)? {
        let p = previewStates == nil ? (profile(p.id) ?? p) : p
        guard p.otpMode != .none, let secret = totpSecret(p) else { return nil }
        return (TOTP.code(secret: secret, params: p.totp, at: date), TOTP.remaining(params: p.totp, at: date))
    }

    /// Code for an action (copy, type, connect sheet): computed from the stored profile and the
    /// Keychain item as they are now, bypassing every cache.
    func currentCode(for p: Profile, at date: Date = Date()) -> String? {
        guard let stored = storedProfile(p), stored.otpMode != .none,
              let raw = Secrets.get(stored.id, .totp), let secret = try? TOTP.decodeSecret(raw) else { return nil }
        return TOTP.code(secret: secret, params: stored.totp, at: date)
    }

    func forgetSecrets(_ id: String) {
        secretCache[id] = nil
        missingSecret.remove(id)
    }

    // MARK: actions

    func primaryAction(_ p: Profile) {
        switch state(p.id) {
        case .disconnected: connect(p)
        case .connecting, .connected: disconnect(p)
        }
    }

    func connect(_ p: Profile) {
        droppedUnseen.remove(p.id)
        guard let p = storedProfile(p) else { return showError(PTError.profileNotFound(p.id)) }
        let needs = p.needs
        if !needs.isEmpty {
            credentialRequest = CredentialRequest(profile: p, needs: needs)
            return
        }
        connect(p, given: [:])
    }

    /// `given` holds what the credential sheet asked for. The profile is re-read first; if it now
    /// needs something that was not asked (changed by the CLI meanwhile), the sheet is shown again.
    func connect(_ p: Profile, given: [CredentialField: String]) {
        guard let p = storedProfile(p) else { return showError(PTError.profileNotFound(p.id)) }
        let unanswered = p.needs.filter { (given[$0] ?? "").trimmingCharacters(in: .whitespaces).isEmpty }
        if !unanswered.isEmpty {
            let request = CredentialRequest(profile: p, needs: p.needs)
            // Let a sheet that is still closing go away first.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { self.credentialRequest = request }
            return
        }
        if let user = given[.username], !user.isEmpty, user != p.lastUsername {
            // Only this field: never write back a whole copy that may be older than the file.
            _ = try? store.update(p.id) { $0.lastUsername = user }
            reload()
        }
        Task {
            do {
                try await connections.connect(p.id, given: given)
            } catch {
                handleConnectError(error, profile: p)
            }
        }
    }

    func disconnect(_ p: Profile) {
        droppedUnseen.remove(p.id)
        Task {
            do { try await connections.disconnect(p.id) } catch { showError(error) }
        }
    }

    func toggleDefault() {
        guard let p = defaultProfile else {
            NSSound.beep()
            return
        }
        primaryAction(p)
    }

    private func handleConnectError(_ error: Error, profile p: Profile) {
        if let h = error as? HelperClientError {
            switch h {
            case .notInstalled, .requiresApproval, .notFound, .versionMismatch, .buildMismatch:
                if h.meansOutdatedHelper { helperOutdated = true }
                alert = AppAlert(title: String(localized: "The helper is not ready"),
                                 message: h.localizedDescription, opensHelperSettings: true)
                return
            default: break
            }
        }
        if error is CancellationError || (error as? PTError) == .connectCancelled { return }
        // Other failures are shown in the row (ConnectionManager.lastError); surface them when no window is open.
        if !NSApp.windows.contains(where: { $0.isVisible && $0.identifier?.rawValue.hasPrefix("main") == true }) {
            Notifier.shared.post(title: String(localized: "Could not connect \(p.name)"),
                                 body: error.localizedDescription, profileID: p.id)
        }
    }

    func copyCode(_ p: Profile) {
        guard let c = currentCode(for: p) else {
            showToast(String(localized: "No code available"), symbol: "exclamationmark.circle.fill")
            return
        }
        Pasteboard.copy(c, concealed: true)
        showToast(String(localized: "Code copied"))
    }

    func copyPasswordAndCode(_ p: Profile) {
        guard let p = storedProfile(p) else { return showError(PTError.profileNotFound(p.id)) }
        guard let password = Secrets.get(p.id, .password) else {
            showToast(String(localized: "No password saved in Keychain"), symbol: "exclamationmark.circle.fill")
            return
        }
        let otp = currentCode(for: p)
        let composed = OTPComposer.compose(password: password, otp: otp, delivery: .combined,
                                           template: p.otpTemplate, type: p.type)
        Pasteboard.copy(composed.secret, concealed: true)
        showToast(String(localized: "Password and code copied"))
    }

    /// Hotkey / menu action: types the code when auto-type is on and permitted, else copies it.
    func copyOrTypeDefaultCode() {
        guard let p = profiles.first(where: { $0.id == prefs.defaultProfile && hasCode($0) })
            ?? profiles.first(where: hasCode) else {
            NSSound.beep()
            return
        }
        if prefs.autoType { typeCode(p) } else { copyCode(p) }
    }

    func typeCode(_ p: Profile) {
        guard let c = currentCode(for: p) else { NSSound.beep(); return }
        guard AutoType.isTrusted else {
            AutoType.requestTrust()
            Notifier.shared.post(title: String(localized: "Allow PassTunnel to type codes"),
                                 body: String(localized: "Turn on PassTunnel in System Settings → Privacy & Security → Accessibility."),
                                 profileID: nil)
            Pasteboard.copy(c, concealed: true)
            return
        }
        AutoType.type(c)
    }

    func showLog(_ p: Profile) {
        let url = store.logURL(p.id)
        guard FileManager.default.fileExists(atPath: url.path) else {
            showToast(String(localized: "No log yet"), symbol: "doc.text.magnifyingglass")
            return
        }
        let console = URL(fileURLWithPath: "/System/Applications/Utilities/Console.app")
        if FileManager.default.fileExists(atPath: console.path) {
            NSWorkspace.shared.open([url], withApplicationAt: console, configuration: NSWorkspace.OpenConfiguration())
        } else {
            NSWorkspace.shared.open(url)
        }
    }

    func logTail(_ id: String, lines: Int = 12) -> String? {
        let tail = VPNLog.tail(VPNLog.read(store.logURL(id)), lines: lines)
        return tail.isEmpty ? nil : tail
    }

    func togglePin(_ p: Profile) {
        let pinned = !p.pinned   // what the user sees flipped, even if the file changed meanwhile
        update(p) { $0.pinned = pinned }
    }

    func makeDefault(_ p: Profile) {
        prefs.defaultProfile = isDefault(p) ? nil : p.id
    }

    func delete(_ p: Profile) {
        Task {
            if state(p.id).isActive { _ = try? await connections.disconnect(p.id) }
            do {
                try store.delete(p.id)
                prefs = Preferences.load(paths: paths)
            } catch { showError(error) }
            reload()
        }
    }

    func share(_ p: Profile) { ShareActions.export(profileID: p.id) }

    func edit(_ p: Profile) { editor = EditorRequest(profileID: p.id, newType: nil) }

    func newProfile(_ type: VPNType) { editor = EditorRequest(profileID: nil, newType: type) }

    func move(fromOffsets source: IndexSet, toOffset destination: Int) {
        var list = profiles
        list.move(fromOffsets: source, toOffset: destination)
        for (i, p) in list.enumerated() where p.order != i {
            do { try store.update(p.id) { $0.order = i } } catch { showError(error) }
        }
        reload()
    }

    /// Changes one profile on top of the stored version (read-modify-write).
    private func update(_ p: Profile, _ change: (inout Profile) -> Void) {
        do { try store.update(p.id, change) } catch { showError(error) }
        reload()
    }

    // MARK: feedback

    func showToast(_ text: String, symbol: String = "checkmark.circle.fill") {
        toastTask?.cancel()
        withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) { toast = ToastMessage(text: text, symbol: symbol) }
        toastTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 1_600_000_000)
            guard !Task.isCancelled else { return }
            withAnimation(.easeOut(duration: 0.25)) { self?.toast = nil }
        }
    }

    func showError(_ error: Error) {
        alert = AppAlert(title: String(localized: "Something went wrong"), message: error.localizedDescription)
    }

    private var onboardingClosedAt: Date?
    /// Onboarding step 3 "Start PassTunnel at login": nil until the user has seen the checkbox.
    @Published var onboardingStartAtLogin: Bool?

    func finishOnboarding() {
        UserDefaults.standard.set(true, forKey: Self.onboardingKey)
        if showOnboarding {
            onboardingClosedAt = Date()
            applyOnboardingLoginChoice()
        }
        showOnboarding = false
    }

    /// Registers the login item when the user left "Start PassTunnel at login" checked. Nothing is
    /// registered when the step was never shown (onboarding closed by an import from elsewhere).
    private func applyOnboardingLoginChoice() {
        guard let startAtLogin = onboardingStartAtLogin else { return }
        onboardingStartAtLogin = nil
        guard startAtLogin else {
            prefs.launchAtLogin = false
            return
        }
        do {
            let status = try LoginItem.setEnabled(true)
            if status != .unavailable { prefs.launchAtLogin = status == .enabled || status == .requiresApproval }
        } catch {
            alert = AppAlert(title: String(localized: "Launch at login could not be turned on"),
                             message: error.localizedDescription + "\n\n"
                                 + String(localized: "You can turn it on later in Settings → General."))
        }
    }

    // MARK: events

    private func handle(_ event: ConnectionEvent) {
        switch event {
        case .dropped(let id, _):
            droppedUnseen.insert(id)
        case .reconnected(let id):
            droppedUnseen.remove(id)
        default:
            break
        }
        Notifier.shared.handle(event, model: self)
    }
}

enum Pasteboard {
    static func copy(_ text: String, concealed: Bool) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
        if concealed {
            // Clipboard managers honour this marker and skip the entry.
            pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        }
    }
}
