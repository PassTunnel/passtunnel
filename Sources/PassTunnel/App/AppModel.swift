import AppKit
import Combine
import PassTunnelCore
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
        NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
            .sink { [weak self] _ in self?.reloadFromDisk() }
            .store(in: &bag)
        // The CLI can change profiles and preferences while the app runs.
        reloadTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.reloadFromDisk() }
        }
    }

    // MARK: data

    func reload() {
        let fresh = store.list()
        if fresh != profiles { profiles = fresh }
        secretCache.removeAll()
        missingSecret.removeAll()
        if let sel = selection, !fresh.contains(where: { $0.id == sel }) { selection = nil }
    }

    /// Picks up changes made by the CLI without discarding in-app edits.
    func reloadFromDisk() {
        let fresh = store.list()
        if fresh != profiles {
            profiles = fresh
            secretCache.removeAll()
            missingSecret.removeAll()
        }
        let diskPrefs = Preferences.load(paths: paths)
        if diskPrefs != prefs { prefs = diskPrefs }
        refreshHelperStatus()
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
        if s != helperStatus { helperStatus = s }
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

    /// Current code for profiles with a stored TOTP secret (also used for `.ask` profiles to prefill).
    func code(for p: Profile, at date: Date = Date()) -> (code: String, remaining: Int)? {
        guard p.otpMode != .none, let secret = totpSecret(p) else { return nil }
        return (TOTP.code(secret: secret, params: p.totp, at: date), TOTP.remaining(params: p.totp, at: date))
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
        let needs = p.needs
        if !needs.isEmpty {
            credentialRequest = CredentialRequest(profile: p, needs: needs)
            return
        }
        connect(p, given: [:])
    }

    func connect(_ p: Profile, given: [CredentialField: String]) {
        if let user = given[.username], !user.isEmpty, user != p.lastUsername {
            var updated = p
            updated.lastUsername = user
            try? store.save(updated)
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
            case .notInstalled, .requiresApproval, .notFound, .versionMismatch:
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
        guard let c = code(for: p, at: Date()) else {
            showToast(String(localized: "No code available"), symbol: "exclamationmark.circle.fill")
            return
        }
        Pasteboard.copy(c.code, concealed: true)
        showToast(String(localized: "Code copied"))
    }

    func copyPasswordAndCode(_ p: Profile) {
        guard let password = Secrets.get(p.id, .password) else {
            showToast(String(localized: "No password saved in Keychain"), symbol: "exclamationmark.circle.fill")
            return
        }
        let otp = code(for: p, at: Date())?.code
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
        guard let c = code(for: p, at: Date()) else { NSSound.beep(); return }
        guard AutoType.isTrusted else {
            AutoType.requestTrust()
            Notifier.shared.post(title: String(localized: "Allow PassTunnel to type codes"),
                                 body: String(localized: "Turn on PassTunnel in System Settings → Privacy & Security → Accessibility."),
                                 profileID: nil)
            Pasteboard.copy(c.code, concealed: true)
            return
        }
        AutoType.type(c.code)
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
        update(p) { $0.pinned.toggle() }
    }

    func makeDefault(_ p: Profile) {
        prefs.defaultProfile = isDefault(p) ? nil : p.id
    }

    func delete(_ p: Profile) {
        Task {
            if state(p.id).isActive { try? await connections.disconnect(p.id) }
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
        for (i, var p) in list.enumerated() where p.order != i {
            p.order = i
            do { try store.save(p) } catch { showError(error) }
        }
        reload()
    }

    private func update(_ p: Profile, _ change: (inout Profile) -> Void) {
        var copy = p
        change(&copy)
        do { try store.save(copy) } catch { showError(error) }
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

    func finishOnboarding() {
        UserDefaults.standard.set(true, forKey: Self.onboardingKey)
        if showOnboarding { onboardingClosedAt = Date() }
        showOnboarding = false
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
