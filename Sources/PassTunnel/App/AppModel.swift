import AppKit
import Combine
import PassTunnelCLI
import PassTunnelCore
import PassTunnelKit
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

/// Feedback such as "Code copied", which the main window has VoiceOver announce (the window shows no toast).
struct ToastMessage: Identifiable, Equatable {
    let id = UUID()
    let text: String
}

struct AppAlert: Identifiable {
    let id = UUID()
    let title: String
    let message: String
    var opensHelperSettings = false
    /// A connect waits for the helper's approval (`HelperPendingConnect`): Open Login Items… and Cancel Connecting.
    var waitsForHelper = false
}

/// Who asked `AppModel.installHelper` to register the helper.
enum HelperInstallOrigin {
    /// Install Helper (Settings → Helper, the first-run card) or a `passtunnel helper install` hand-off.
    case button
    /// `HelperAutoInstall`; `userActed`: right after the user acted in PassTunnel.
    case automatic(userActed: Bool)
}

/// App-wide state shared by the main window, menu bar, settings and hotkeys.
@MainActor
final class AppModel: ObservableObject {
    static private(set) var shared: AppModel!

    let store: ProfileStore
    let connections: ConnectionManager
    let paths: AppPaths

    @Published private(set) var profiles: [Profile] = []
    /// Profiles of a VPN type this version does not know (a newer PassTunnel's): listed, deletable, nothing else.
    @Published private(set) var unsupported: [UnsupportedProfile] = []
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
    @Published var pendingDeleteUnsupported: UnsupportedProfile?
    /// The .ovpn under review in the window's detail (`ImportReviewView`); nil when none. Selecting a
    /// profile leaves it, as Cancel does: nothing was written.
    @Published var importReview: ImportReviewModel?
    @Published var settingsTab: SettingsTab = .general
    @Published private(set) var droppedUnseen: Set<String> = []
    @Published private(set) var helperStatus: HelperStatus = .notRegistered
    /// The registered helper is running but speaks another protocol version (left from another app version).
    @Published private(set) var helperOutdated = false
    /// How the running helper relates to this copy's (older, newer…); nil while unknown.
    @Published private(set) var helperRelation: HelperBuild.Relation?
    private var checkingHelperVersion = false
    /// `HelperInstaller.update` is running (Settings → Helper, or the automatic update).
    @Published private(set) var helperUpdating = false
    /// Why the last helper update failed; cleared when the next one starts.
    @Published private(set) var helperUpdateError: String?
    private var helperAutoUpdate = HelperAutoUpdate()
    /// The helper is outdated and updates itself once the active sessions end.
    @Published private(set) var helperUpdateWaiting = false
    /// `HelperInstaller.update` runs as the repair of a helper that does not answer.
    @Published private(set) var helperRepairing = false
    /// A registration is running (Install Helper, or the automatic install).
    @Published private(set) var helperInstalling = false
    /// Why the last registration failed, as macOS said it; cleared when the next one starts.
    @Published private(set) var helperInstallError: String?
    /// The helper is enabled but does not answer (`HelperAnswerWatch`).
    @Published private(set) var helperNotAnswering = false
    private var helperAnswers = HelperAnswerWatch()
    /// A helper call failed without an answer after the helper had answered: it is asked again (`helperCallFailed`).
    private var helperRecheck = false
    private var helperAutoInstall = HelperAutoInstall()
    /// A Connect waiting for the helper's approval (only with `Preferences.autoInstallHelper`).
    @Published private(set) var pendingConnect = HelperPendingConnect()
    /// Set when the CLI asked the app to install or remove the helper; Settings → Helper consumes it.
    @Published var pendingHelperAction: HelperHandoff?

    /// Render/preview overrides; when set, they replace the live connection data.
    var previewStates: [String: ConnectionState]?
    var previewErrors: [String: String]?
    var previewHelperStatus: HelperStatus?
    var previewNow: Date?
    /// Render overrides for the failure cards and the clock banner (FailureCards.swift).
    var previewFailures = FailurePreview()
    /// Render override: the notices of connected profiles (`notices`).
    var previewNotices: [String: [StatusNotice]] = [:]
    /// A connect that waits for the answer to "Lab overlaps with Work" (`OverlapSheet`).
    @Published var overlapRequest: OverlapRequest?

    private var secretCache: [String: Data] = [:]
    private var missingSecret: Set<String> = []
    /// Profiles whose TOTP secret is stored encrypted ("Confirm with Touch ID"): its code shows only while
    /// the vault has it unlocked.
    private var protectedTOTP: Set<String> = []
    /// Render override: profiles whose code is shown locked.
    var previewLockedCodes: Set<String> = []
    private var bag = Set<AnyCancellable>()
    private var reloadTimer: Timer?
    private var watcher: ProfilesWatcher?
    var onPrefsChanged: ((Preferences, Preferences) -> Void)?

    /// Set once "Open PassTunnel at login?" is answered (`OpenAtLoginQuestion`); the onboarding sheet of earlier
    /// versions set it too, so it is not asked again after an update.
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
        connections.vault.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
            .store(in: &bag)
        guard live else { return }
        // A server that does not answer is tried again (Core: `UnreachableRetry`).
        connections.retriesUnreachable = true
        connections.start()
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
            }
            .store(in: &bag)
        NotificationCenter.default.publisher(for: ImportActions.openEditor)
            .sink { [weak self] note in
                guard let self else { return }
                self.reload()
                let id = note.userInfo?["profileID"] as? String
                // An imported profile this version or this Mac cannot edit (`unsupported`, `editRefusal`) is
                // selected instead.
                if let id, self.unsupportedProfile(id) != nil || self.profile(id).flatMap(self.editRefusal) != nil {
                    self.selection = id
                    return
                }
                self.editor = EditorRequest(profileID: id, newType: nil)
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
        // Nothing of a profile this Mac cannot connect (Cisco AnyConnect below macOS 15.4) is read or unlocked.
        let usable = connections.profilesWithUsableSecrets(fresh)
        // A "Confirm with Touch ID" setting edited by hand: encrypt what it protects (no prompt).
        for p in usable where p.requireAuth != .off { vault.reconcile(p) }
        // Server settings changed (editor, CLI, a file edit): secrets confirmed for the old ones are dropped.
        connections.revalidateDestinations(fresh)
        let secretsChanged = refreshSecrets(for: usable)
        if fresh != profiles {
            profiles = fresh
        } else if secretsChanged {
            objectWillChange.send()
        }
        let unknown = store.listUnsupported()
        if unknown != unsupported { unsupported = unknown }
        if let sel = selection, !fresh.contains(where: { $0.id == sel }), !unknown.contains(where: { $0.id == sel }) { selection = nil }
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
        var protected: Set<String> = []
        for p in list where p.otpMode != .none {
            if Secrets.isProtected(p.id, .totp) {
                protected.insert(p.id)
            } else if let raw = Secrets.get(p.id, .totp), let data = try? TOTP.decodeSecret(raw) {
                cache[p.id] = data
            } else {
                missing.insert(p.id)
            }
        }
        let changed = cache != secretCache || missing != missingSecret || protected != protectedTOTP
        secretCache = cache
        missingSecret = missing
        protectedTOTP = protected
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

    func unsupportedProfile(_ id: String) -> UnsupportedProfile? { unsupported.first { $0.id == id } }

    /// Why this Mac cannot connect profiles of `type` (`ConnectionManager.connectRefusal`: Cisco AnyConnect below
    /// macOS 15.4, for the manager's `systemVersion`), nil when it can. Such a profile is listed with the note, and
    /// connecting, editing and creating one are refused with the message before anything is asked or run; deleting
    /// and sharing it still work.
    func connectRefusal(_ type: VPNType) -> PTError? { connections.connectRefusal(type) }

    /// "Copy Password + Code" can be offered: a password in the Keychain, of a profile this Mac can connect.
    func canCopyPassword(_ p: Profile) -> Bool { p.passwordMode == .keychain && connectRefusal(p.type) == nil }

    /// Why the editor does not open on `p`: `connectRefusal` of its type, and for a type the editor has no fields
    /// for (`editableTypes`) that it needs a newer PassTunnel.
    func editRefusal(_ p: Profile) -> PTError? {
        connectRefusal(p.type) ?? (Self.editableTypes.contains(p.type) ? nil : .unsupportedProfileType(p.type.rawValue))
    }

    /// The types the editor has the fields for, and the type lists offer (Add VPN, the editor's type picker, the File
    /// menu), in `VPNType.connectable`'s order: every type, Palo Alto GlobalProtect (#233) included.
    static let editableTypes = VPNType.connectable

    /// Nothing to show in the sidebar: the first-run view takes the window.
    var hasNoProfiles: Bool { profiles.isEmpty && unsupported.isEmpty }

    var filteredProfiles: [Profile] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return profiles }
        return profiles.filter {
            $0.name.localizedCaseInsensitiveContains(q) || $0.id.localizedCaseInsensitiveContains(q)
                || $0.username.localizedCaseInsensitiveContains(q) || $0.host.localizedCaseInsensitiveContains(q)
        }
    }

    var filteredUnsupported: [UnsupportedProfile] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return unsupported }
        return unsupported.filter { $0.name.localizedCaseInsensitiveContains(q) || $0.id.localizedCaseInsensitiveContains(q) }
    }

    var defaultProfile: Profile? {
        if let id = prefs.defaultProfile, let p = profile(id) { return p }
        return profiles.first
    }

    func isDefault(_ p: Profile) -> Bool { prefs.defaultProfile == p.id }

    private func prefsChanged(from old: Preferences) {
        do { try prefs.save(paths: paths) } catch { showError(error) }
        // Turned off (here or in config.json): a connect waiting for the approval is dropped.
        if old.autoInstallHelper && !prefs.autoInstallHelper { cancelPendingConnect() }
        // Turning "Hide codes until clicked" on or off starts again from hidden codes.
        if prefs.hideCodes != old.hideCodes && !revealedCodes.isEmpty { revealedCodes = [:] }
        onPrefsChanged?(old, prefs)
    }

    func refreshHelperStatus() {
        if let previewHelperStatus { helperStatus = previewHelperStatus; return }
        guard Bundle.main.bundleIdentifier != nil else { helperStatus = .notFound; return }
        let s = HelperInstaller.status
        let changed = s != helperStatus
        if changed { helperStatus = s }
        // A failed install's error describes the status it left; any other status replaces it.
        if changed, helperInstallError != nil { helperInstallError = nil }
        if s != .enabled {
            helperOutdated = false
            helperRelation = nil
            helperRecheck = false
            helperAnswers.reset()
            if helperNotAnswering { helperNotAnswering = false }
        } else if changed || ((helperOutdated || helperRelation == nil || helperRecheck) && helperAnswers.shouldAsk()) {
            // Asked again while it has not answered (since a failed call): `HelperAnswerWatch` tells slow from
            // not answering, and asks less often once it has decided.
            checkHelperVersion()
        }
        helperStateChanged()
    }

    /// A helper call failed without an answer (a connect): ask again on the next refreshes, showing the last
    /// known state until `HelperAnswerWatch` decides.
    private func helperCallFailed(_ error: Error) {
        guard let e = error as? HelperClientError else { return }
        switch e {
        case .timeout, .unavailable:
            helperRecheck = true
            checkHelperVersion()
        default:
            break
        }
    }

    /// Settings → Helper opened, or a Connect: ask a helper that has not answered right away, without waiting
    /// for `HelperAnswerWatch.retryInterval`.
    func askHelperNow() {
        guard helperStatus == .enabled, helperNotAnswering || helperRelation == nil || helperRecheck else { return }
        checkHelperVersion()
    }

    /// The automatic update, else the automatic repair; then a connect waiting for the helper.
    private func helperStateChanged() {
        if !autoUpdateHelperIfIdle() { autoInstallHelper(.refresh, userActed: false) }
        advancePendingConnect()
    }

    /// Asks the running helper for its protocol version and build; a mismatch means it must be updated
    /// (Settings → Helper → Update Helper re-registers it from this copy of the app).
    func checkHelperVersion() {
        guard previewHelperStatus == nil, !checkingHelperVersion else { return }
        checkingHelperVersion = true
        Task {
            let (result, answered) = await HelperClient.shared.relationAndAnswer()
            switch result {
            case .success(let relation):
                helperRelation = relation
                helperOutdated = relation != .current
            case .failure(let error):
                // A helper that gave its protocol version answered, even if a later question failed.
                if !answered { helperAnswers.failed(error) }
            }
            if answered {
                helperAnswers.answered()
                helperRecheck = false
            }
            if helperAnswers.notAnswering != helperNotAnswering { helperNotAnswering = helperAnswers.notAnswering }
            checkingHelperVersion = false
            helperStateChanged()
        }
    }

    /// The helper answered since it was last enabled or replaced (render overrides count as answered): only
    /// then does Settings → Helper say "Installed and running".
    var helperAnswered: Bool { previewHelperStatus != nil || helperRelation != nil }

    /// A real app bundle in /Applications: the only copy that installs or repairs the helper on its own.
    private var bundledInApplications: Bool {
        Bundle.main.bundleURL.pathExtension == "app" && Bundle.main.bundleIdentifier != nil
            && HelperSessions.isInApplicationsFolder(Bundle.main.bundlePath)
    }

    /// Registers the helper (`HelperInstaller.registerRetrying`) for Install Helper in Settings → Helper and on
    /// the first-run card, a `passtunnel helper install` hand-off, and the automatic install. Afterwards macOS
    /// usually waits for the approval: Login Items open after a button, after the automatic install only when
    /// `HelperAutoInstall.opensLoginItems` allows it. An install by the user clears `Preferences.helperRemoved`.
    @discardableResult
    func installHelper(_ origin: HelperInstallOrigin) async -> Bool {
        guard !helperInstalling, !helperUpdating else { return false }
        helperInstalling = true
        helperInstallError = nil
        var failure: String?
        do {
            try await HelperInstaller.registerRetrying()
        } catch {
            failure = error.localizedDescription
        }
        helperInstalling = false
        if failure == nil, case .button = origin, prefs.helperRemoved { prefs.helperRemoved = false }
        refreshHelperStatus()
        // After the refresh, which clears an error of an earlier status.
        helperInstallError = failure
        if helperStatus == .requiresApproval {
            switch origin {
            case .button:
                HelperInstaller.openSystemSettingsLoginItems()
            case .automatic(let userActed):
                // Not when the switch was turned off while macOS registered it.
                if prefs.autoInstallHelper, helperAutoInstall.opensLoginItems(userActed: userActed) {
                    HelperInstaller.openSystemSettingsLoginItems()
                }
            }
        }
        return failure == nil
    }

    /// Settings → Helper → Remove (also for `passtunnel helper uninstall`, carried out there). The helper is
    /// marked removed first, so a refresh during the unregister never repairs it, and stays so until the user
    /// installs it (`Preferences.helperRemoved`); a failed removal restores the mark.
    func removeHelper() async throws {
        let wasRemoved = prefs.helperRemoved
        if !wasRemoved { prefs.helperRemoved = true }
        cancelPendingConnect()
        do {
            try await HelperInstaller.unregister()
        } catch {
            if !wasRemoved { prefs.helperRemoved = false }
            throw error
        }
        refreshHelperStatus()
    }

    /// The "Install and repair the helper automatically" switch. Turning it on is the user's go-ahead for the
    /// state as it is now (a missing helper is installed at once) and lifts an earlier removal.
    func setAutoInstallHelper(_ on: Bool) {
        guard prefs.autoInstallHelper != on else { return }
        var changed = prefs
        changed.autoInstallHelper = on
        if on { changed.helperRemoved = false }
        prefs = changed
        if on { autoInstallHelper(.switchedOn, userActed: true) }
    }

    /// The automatic install and repair (`HelperAutoInstall`: nothing unless `Preferences.autoInstallHelper`
    /// is on). Returns what it started.
    @discardableResult
    func autoInstallHelper(_ trigger: HelperAutoInstall.Trigger, userActed: Bool) -> HelperAutoInstall.Action {
        guard previewHelperStatus == nil else { return .none }
        // The process listing only while a repair could still be decided.
        let repairable =
            prefs.autoInstallHelper && !prefs.helperRemoved && helperStatus == .enabled && helperNotAnswering
            && helperAutoInstall.mayStillRepair(relation: helperRelation) && bundledInApplications
        let situation = HelperAutoInstall.Situation(
            enabled: prefs.autoInstallHelper, removedByUser: prefs.helperRemoved, status: helperStatus,
            notAnswering: helperNotAnswering, relation: helperRelation,
            activeSessions: repairable
                ? connections.states.values.filter(\.isActive).count + HelperSessions.runningToolCount() : 0,
            busy: helperInstalling || helperUpdating,
            inApplicationsFolder: HelperSessions.isInApplicationsFolder(Bundle.main.bundlePath),
            bundled: Bundle.main.bundleURL.pathExtension == "app" && Bundle.main.bundleIdentifier != nil)
        let action = helperAutoInstall.next(situation, trigger: trigger)
        switch action {
        case .none:
            break
        case .register:
            Task {
                guard await installHelper(.automatic(userActed: userActed)) else { return helperInstallFailed() }
                if helperStatus == .requiresApproval, let id = pendingConnect.profileID, let p = profile(id) {
                    showWaitingForApproval(p)
                }
            }
        case .repair:
            Task { await updateHelper(repair: true) }
        }
        return action
    }

    /// An automatic install failed: a connect waiting for it is dropped, with the error macOS gave.
    private func helperInstallFailed() {
        guard let id = cancelPendingConnect() else { return }
        let title = String(localized: "The helper could not be installed")
        let message = helperInstallError ?? ""
        if mainWindowVisible {
            alert = AppAlert(title: title, message: message, opensHelperSettings: true)
        } else {
            Notifier.shared.post(title: title, body: message, profileID: id)
        }
    }

    /// With the automatic install on, a Connect the user pressed while the helper is missing installs it, and
    /// one while it waits for the approval waits too; the connect starts once the helper is ready. False:
    /// connect as before (switch off, a copy outside /Applications, a removed helper, an install already tried).
    private func waitsForHelper(_ p: Profile) -> Bool {
        guard previewHelperStatus == nil, prefs.autoInstallHelper, !prefs.helperRemoved, bundledInApplications,
            connectRefusal(p.type) == nil
        else { return false }
        refreshHelperStatus()
        switch helperStatus {
        case .enabled:
            return false
        case .requiresApproval:
            // Never registered again (approval pending, or switched off in Login Items): Login Items are offered.
            pendingConnect.start(p.id)
            showWaitingForApproval(p)
            return true
        case .notRegistered, .notFound:
            if !helperInstalling, autoInstallHelper(.connect, userActed: true) != .register { return false }
            pendingConnect.start(p.id)
            return true
        }
    }

    /// "Turn on the helper to connect" in the window (Open Login Items… / Cancel Connecting), or as a
    /// notification when the window is not visible.
    private func showWaitingForApproval(_ p: Profile) {
        let title = String(localized: "Turn on the helper to connect")
        let message = String(
            localized:
                "Turn on PassTunnel in System Settings → General → Login Items. \(p.name) connects if you do within \(Int(HelperPendingConnect.timeout / 60)) minutes."
        )
        if mainWindowVisible {
            alert = AppAlert(title: title, message: message, waitsForHelper: true)
        } else {
            Notifier.shared.post(title: title, body: message, profileID: p.id)
        }
    }

    /// Cancel Connecting (the alert, Settings → Helper, the first-run card), and whatever else ends a connect
    /// waiting for the helper. Returns its profile.
    @discardableResult
    func cancelPendingConnect() -> String? {
        if alert?.waitsForHelper == true { alert = nil }
        return pendingConnect.cancel()
    }

    /// Starts the waiting connect once the helper is ready, or drops it after `HelperPendingConnect.timeout`.
    private func advancePendingConnect() {
        guard pendingConnect.isWaiting else { return }
        let ready = helperStatus == .enabled && helperRelation == .current && !helperUpdating && !helperInstalling
        let outcome = pendingConnect.next(ready: ready)
        if outcome != .none, alert?.waitsForHelper == true { alert = nil }
        switch outcome {
        case .none:
            break
        case .connect(let id):
            guard let p = profile(id) else { break }
            // The credential sheet lives in the main window, which a Connect from the menu bar may not have open.
            if !p.needs.isEmpty && !mainWindowVisible { AppDelegate.shared?.showMainWindow() }
            connect(p)
        case .expired(let id):
            let title = String(localized: "\(profile(id)?.name ?? id) was not connected")
            let wait = HelperPendingConnect.waitingFor(status: helperStatus, outdated: helperOutdated)
            let message: String
            switch wait {
            case .approval:
                message = String(
                    localized:
                        "The helper was not turned on within \(Int(HelperPendingConnect.timeout / 60)) minutes. Turn on PassTunnel in System Settings → General → Login Items, then connect again."
                )
            case .install:
                message = String(localized: "The helper is not installed. Install it in Settings → Helper, then connect again.")
            case .update:
                message = String(localized: "The helper needs an update. Update it in Settings → Helper, then connect again.")
            case .answer:
                message = String(localized: "The helper does not answer. Repair it in Settings → Helper, then connect again.")
            }
            if mainWindowVisible {
                alert = AppAlert(title: title, message: message, opensHelperSettings: wait != .approval)
            } else {
                Notifier.shared.post(title: title, body: message, profileID: id)
            }
        }
    }

    /// Re-registers the helper from this copy of the app (`HelperInstaller.update`); active
    /// connections stop. Used by Settings → Helper → Update Helper and Repair Helper, the automatic
    /// update and the automatic repair (`repair`: of a helper that does not answer).
    func updateHelper(repair: Bool = false) async {
        guard !helperUpdating, !helperInstalling else { return }
        helperUpdating = true
        helperRepairing = repair
        helperUpdateError = nil
        // The new registration is asked afresh.
        helperAnswers.reset()
        helperNotAnswering = false
        do {
            try await HelperInstaller.update()
        } catch {
            helperUpdateError = error.localizedDescription
        }
        helperUpdating = false
        helperRepairing = false
        refreshHelperStatus()
        checkHelperVersion()
    }

    /// The helper can start a connection: approved, answering with this copy's build, not being updated.
    private var helperReady: Bool {
        guard helperStatus == .enabled else { return false }
        // The first question may have gone unanswered while launchd was still starting the helper.
        if helperRelation == nil { checkHelperVersion() }
        return helperRelation == .current && !helperUpdating
    }

    /// Opened at login: connects the profiles set to connect at login (`LoginConnector`) once the helper (after an
    /// automatic update, if one is due) and the network are ready.
    func connectAtLogin() {
        // The manager watches the network path (`NWPathMonitor`) while it runs.
        let connector = LoginConnector(
            manager: connections,
            readiness: { [weak self] in
                LoginConnector.Readiness(
                    helper: self?.helperReady ?? false,
                    network: self?.connections.networkStatus.online == true)
            }, notify: { Notifier.shared.post($0) })
        Task { await connector.run() }
    }

    /// After the app was updated, the helper still runs the previous build. Update it right away when
    /// no PassTunnel session is active (no approval needed), else as soon as the last one ends. Only
    /// an older helper, and only from /Applications (`HelperAutoUpdate`); anything else is left to
    /// Settings → Helper, which asks first.
    /// True when it started an update.
    @discardableResult
    private func autoUpdateHelperIfIdle() -> Bool {
        guard previewHelperStatus == nil, Bundle.main.bundleURL.pathExtension == "app" else { return false }
        let outdated = helperStatus == .enabled && helperOutdated
        let sessions =
            outdated
            ? connections.states.values.filter(\.isActive).count + HelperSessions.runningToolCount()
            : 0
        let situation = HelperAutoUpdate.Situation(
            status: helperStatus, outdated: checkingHelperVersion && !helperOutdated ? nil : helperOutdated,
            helperIsOlder: helperRelation == .older, activeSessions: sessions, updating: helperUpdating,
            inApplicationsFolder: HelperSessions.isInApplicationsFolder(Bundle.main.bundlePath))
        let action = helperAutoUpdate.next(situation)
        if helperAutoUpdate.waiting != helperUpdateWaiting { helperUpdateWaiting = helperAutoUpdate.waiting }
        switch action {
        case .none, .wait(notify: false):
            break
        case .wait(notify: true):
            Notifier.shared.post(
                title: String(localized: "The helper needs an update"),
                body: String(localized: "It updates itself when all VPN connections are disconnected. Until then, new connections cannot start."),
                profileID: nil)
        case .update:
            Task { await updateHelper() }
            return true
        }
        return false
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
    /// Render override: connects waiting for a fresh code until then (`ConnectionManager.codeWaitUntil`).
    var previewCodeWaits: [String: Date] = [:]
    /// Render override: the activity of each profile (`activityEvents`).
    var previewActivity: [String: [ActivityEvent]] = [:]
    /// The profile whose activity the log window shows (`ActivityLogWindow`); nil when none was asked for.
    @Published var activityLogProfile: String?

    func reconnectInfo(_ id: String) -> ReconnectInfo? {
        if previewStates != nil { return previewReconnecting[id] }
        return connections.reconnecting[id]
    }

    var now: Date { previewNow ?? Date() }

    /// The pinned profiles and those that are active or dropped unseen (`MenuBarProfiles.badged`).
    var menuBarProfiles: [Profile] {
        MenuBarProfiles.badged(
            in: profiles,
            isIdle: { p in
                if case .disconnected = state(p.id) { return true }
                return false
            }, droppedUnseen: droppedUnseen)
    }

    /// Profiles listed in the menu bar panel: `menuBarProfiles`, or all while none is pinned.
    var panelProfiles: [Profile] {
        MenuBarProfiles.panel(in: profiles, badged: menuBarProfiles)
    }

    func markDropsSeen() {
        if !droppedUnseen.isEmpty { droppedUnseen.removeAll() }
    }

    func setPreviewDropped(_ ids: Set<String>) { droppedUnseen = ids }

    // MARK: codes

    private func totpSecret(_ p: Profile) -> Data? {
        guard connectRefusal(p.type) == nil else { return nil }
        if protectedTOTP.contains(p.id) {
            return vault.available(p.id, .totp).flatMap { try? TOTP.decodeSecret($0) }
        }
        if let s = secretCache[p.id] { return s }
        if missingSecret.contains(p.id) { return nil }
        guard let raw = Secrets.get(p.id, .totp), let data = try? TOTP.decodeSecret(raw) else {
            missingSecret.insert(p.id)
            return nil
        }
        secretCache[p.id] = data
        return data
    }

    /// The profile has a TOTP secret (shown, or locked behind a confirmation). Never for a profile this Mac cannot
    /// connect (`connectRefusal`), whose secrets are not read.
    func hasCode(_ p: Profile) -> Bool {
        guard connectRefusal(p.type) == nil, p.otpMode == .totp else { return false }
        return protectedTOTP.contains(p.id) || previewLockedCodes.contains(p.id) || totpSecret(p) != nil
    }

    /// Current code for profiles with a stored TOTP secret (also used for `.ask` profiles to prefill),
    /// for display. Uses the latest loaded settings even when the caller holds an older copy.
    /// Nil while the code is locked (`isCodeLocked`).
    func code(for p: Profile, at date: Date = Date()) -> (code: String, remaining: Int)? {
        let p = previewStates == nil ? (profile(p.id) ?? p) : p
        guard p.otpMode != .none, !isCodeLocked(p), let secret = totpSecret(p) else { return nil }
        return (TOTP.code(secret: secret, params: p.totp, at: date), TOTP.remaining(params: p.totp, at: date))
    }

    /// Code for an action (copy, type, connect sheet): computed from the stored profile and the
    /// Keychain item as they are now, bypassing every cache.
    func currentCode(for p: Profile, at date: Date = Date()) -> String? {
        guard let stored = storedProfile(p), connectRefusal(stored.type) == nil, stored.otpMode != .none,
            let raw = vault.available(stored.id, .totp), let secret = try? TOTP.decodeSecret(raw)
        else { return nil }
        return TOTP.code(secret: secret, params: stored.totp, at: date)
    }

    func forgetSecrets(_ id: String) {
        secretCache[id] = nil
        missingSecret.remove(id)
    }

    // MARK: confirmation (Touch ID / password)

    var vault: SecretVault { connections.vault }

    /// The TOTP secret of `p` is stored encrypted and not unlocked: its code is hidden; clicking it asks
    /// (`revealCodes`).
    func isCodeLocked(_ p: Profile) -> Bool {
        if connectRefusal(p.type) != nil { return false }
        if previewStates != nil { return previewLockedCodes.contains(p.id) }
        return protectedTOTP.contains(p.id) && !vault.isUnlocked(p.id, .totp)
    }

    // MARK: code card

    /// Until when a click in the detail's code card shows the codes of a profile that hides them (decision D-5).
    @Published private(set) var revealedCodes: [String: Date] = [:]
    /// The last code or password + code copied, for the "Copied ✓" of the code card.
    @Published private(set) var lastCopy: CodeCard.Copy?

    /// The TOTP secret of `p` is stored encrypted ("Confirm with Touch ID"), unlocked or not.
    func isCodeProtected(_ p: Profile) -> Bool {
        if previewStates != nil { return previewLockedCodes.contains(p.id) }
        return protectedTOTP.contains(p.id)
    }

    /// The window shows bullets instead of the codes of `p` at `date` (`CodeCard.isMasked`).
    func codesMasked(_ p: Profile, at date: Date) -> Bool {
        CodeCard.isMasked(
            locked: isCodeLocked(p), hidden: prefs.hideCodes, protected: isCodeProtected(p),
            revealedUntil: revealedCodes[p.id], at: date)
    }

    /// A click on the code card's masked code: shows the codes of `p` there for 20 s, after the confirmation when
    /// they are locked. A cancel does nothing.
    func revealCodes(_ p: Profile) {
        guard let stored = storedProfile(p), !refusesSecrets(stored) else { return }
        whenUnlocked(stored, [.totp], .code) { [self] _ in
            let now = Date()
            revealedCodes = revealedCodes.filter { $0.value > now }
            revealedCodes[stored.id] = now.addingTimeInterval(CodeCard.revealDuration)
        }
    }

    /// Render override for "Copied ✓".
    func setPreviewCopy(_ copy: CodeCard.Copy?) { lastCopy = copy }

    /// Runs `body` once the secrets `kinds` of `p` are readable: at once when they are stored in plain
    /// text or unlocked, else after the user confirms (which decrypts them). `body` gets whether a
    /// prompt was shown. A cancel does nothing; a failure is shown.
    /// A profile this Mac cannot connect (`connectRefusal`): none of its secrets is read or unlocked; says why.
    private func refusesSecrets(_ p: Profile) -> Bool {
        guard let refusal = connectRefusal(p.type) else { return false }
        showRefusal(refusal)
        return true
    }

    private func whenUnlocked(
        _ p: Profile, _ kinds: Set<SecretKind>, _ action: UserPresenceAction,
        _ body: @escaping (_ prompted: Bool) -> Void
    ) {
        guard vault.needsPrompt(p, kinds) else { return body(false) }
        Task {
            do {
                try await vault.unlock(p, kinds, for: action)
                body(true)
            } catch {
                handleConfirmationError(error)
            }
        }
    }

    /// Cancelling is silent; anything else (no GUI session, Touch ID locked out, undecryptable item) is shown.
    private func handleConfirmationError(_ error: Error) {
        if error is CancellationError || (error as? PTError) == .userConfirmationCancelled { return }
        if case PTError.userConfirmationFailed = error {
            alert = AppAlert(title: String(localized: "Confirmation failed"), message: error.localizedDescription)
        } else {
            showError(error)
        }
        reload()
    }

    /// The main window is open and on screen: not closed, minimized, hidden, on another Space or covered
    /// by other windows.
    var mainWindowVisible: Bool {
        NSApp.windows.contains(where: {
            $0.isVisible && $0.occlusionState.contains(.visible) && $0.identifier?.rawValue.hasPrefix("main") == true
        })
    }

    // MARK: actions

    func primaryAction(_ p: Profile) {
        switch state(p.id) {
        case .disconnected: connect(p)
        case .connecting, .connected: disconnect(p)
        }
    }

    /// A profile whose tunnel overlaps with one that is connected asks first (`OverlapSheet`); `startConnect` goes on
    /// from the answer.
    func connect(_ p: Profile) {
        askHelperNow()
        if waitsForHelper(p) { return }
        connectUnlessOverlapping(p)
    }

    /// Protected secrets are decrypted (the user confirms) by `ConnectionManager.connect`; when a
    /// credential sheet is needed, before it, so the sheet and the connect after it share the confirmation.
    func startConnect(_ p: Profile) {
        droppedUnseen.remove(p.id)
        guard let p = storedProfile(p) else { return showError(PTError.profileNotFound(p.id)) }
        // The type as stored now (a pending overlap sheet may hold an older copy): refused before any confirmation.
        do { try ConnectionManager.checkConnectable(p, macOS: connections.systemVersion) } catch { return showError(error) }
        let needs = p.needs
        guard !needs.isEmpty else { return connect(p, given: [:]) }
        whenUnlocked(p, SecretVault.kinds(for: .connect, p), .connect) { [self] prompted in
            credentialRequest = CredentialRequest(profile: p, needs: needs)
            // The sheet lives in the main window (asked from the menu bar, a shortcut or a notification).
            if prompted && !mainWindowVisible { AppDelegate.shared?.showMainWindow() }
        }
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
        let wasActive = state(p.id).isActive
        Task {
            do {
                try await connections.connect(p.id, given: given)
                if !wasActive { announceConnected(p.id, .user) }
            } catch {
                handleConnectError(error, profile: p)
            }
        }
    }

    /// "Connected to <Profile>" (`ConnectionNotice.announcesConnect`); reconnects come as events instead.
    private func announceConnected(_ id: String, _ origin: ConnectionNotice.ConnectOrigin) {
        guard state(id).isConnected,
            ConnectionNotice.announcesConnect(origin, mainWindowVisible: mainWindowVisible)
        else { return }
        Notifier.shared.post(ConnectionNotice.connected(noticeSubject(id), profileID: id))
    }

    /// The Stop action of a drop notification: ends the automatic reconnect, an attempt under way
    /// included, like Cancel Connecting. Does nothing once the reconnect is over (an older notification).
    func stopReconnecting(_ id: String) {
        guard connections.reconnecting[id] != nil, let p = profile(id) else { return }
        disconnect(p)
    }

    func disconnect(_ p: Profile) {
        droppedUnseen.remove(p.id)
        if pendingConnect.profileID == p.id { cancelPendingConnect() }
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
        helperCallFailed(error)
        if let h = error as? HelperClientError {
            switch h {
            case .notInstalled, .requiresApproval, .notFound, .versionMismatch, .buildMismatch:
                if h.meansOutdatedHelper { helperOutdated = true }
                alert = AppAlert(
                    title: String(localized: "The helper is not ready"),
                    message: h.localizedDescription, opensHelperSettings: true)
                return
            default: break
            }
        }
        if error is CancellationError || (error as? PTError) == .connectCancelled { return }
        if (error as? PTError) == .userConfirmationCancelled { return }
        // Other failures are shown in the row (ConnectionManager.lastError); surface them when no window is open.
        if !mainWindowVisible {
            Notifier.shared.post(
                title: String(localized: "Could not connect \(p.name)"),
                body: error.localizedDescription, profileID: p.id)
        }
    }

    func copyCode(_ p: Profile) {
        guard let stored = storedProfile(p) else { return showError(PTError.profileNotFound(p.id)) }
        if refusesSecrets(stored) { return }
        whenUnlocked(stored, [.totp], .code) { [self] _ in
            guard let c = currentCode(for: stored) else {
                showToast(String(localized: "No code available"))
                return
            }
            copySecret(c)
            lastCopy = CodeCard.Copy(
                profileID: stored.id, kind: .code, at: Date(),
                window: TOTP.counter(params: stored.totp))
            showToast(String(localized: "Code copied"))
        }
    }

    /// Every code and password + code the app copies: cleared after the time chosen in Settings
    /// (`Preferences.clearClipboardAfter`) if the pasteboard still holds it.
    private func copySecret(_ text: String) {
        Pasteboard.copySecret(text, clearingAfter: TimeInterval(prefs.clearClipboardAfter))
    }

    func copyPasswordAndCode(_ p: Profile) {
        guard let p = storedProfile(p) else { return showError(PTError.profileNotFound(p.id)) }
        if refusesSecrets(p) { return }
        whenUnlocked(p, [.password, .totp], .code) { [self] _ in
            guard let password = vault.available(p.id, .password) else {
                showToast(String(localized: "No password saved in Keychain"))
                return
            }
            let otp = currentCode(for: p)
            let composed = OTPComposer.compose(
                password: password, otp: otp, delivery: .combined,
                template: p.otpTemplate, type: p.type)
            copySecret(composed.secret)
            lastCopy = CodeCard.Copy(
                profileID: p.id, kind: .passwordAndCode, at: Date(),
                window: TOTP.counter(params: p.totp))
            showToast(String(localized: "Password and code copied"))
        }
    }

    /// Hotkey / menu action: types the code when auto-type is on and permitted, else copies it.
    func copyOrTypeDefaultCode() {
        guard
            let p = profiles.first(where: { $0.id == prefs.defaultProfile && hasCode($0) })
                ?? profiles.first(where: hasCode)
        else {
            NSSound.beep()
            return
        }
        if prefs.autoType { typeCode(p) } else { copyCode(p) }
    }

    func typeCode(_ p: Profile) {
        guard let stored = storedProfile(p), connectRefusal(stored.type) == nil else { NSSound.beep(); return }
        whenUnlocked(stored, [.totp], .code) { [self] prompted in
            guard prompted else { return type(stored) }
            // Let the focus go back to the field the code is for once the system prompt has closed.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { self.type(stored) }
        }
    }

    private func type(_ p: Profile) {
        guard let c = currentCode(for: p) else { NSSound.beep(); return }
        guard AutoType.isTrusted else {
            AutoType.requestTrust()
            Notifier.shared.post(
                title: String(localized: "Allow PassTunnel to type codes"),
                body: String(localized: "Turn on PassTunnel in System Settings → Privacy & Security → Accessibility."),
                profileID: nil)
            copySecret(c)
            return
        }
        AutoType.type(c)
    }

    func showLog(_ p: Profile) {
        let url = store.logURL(p.id)
        guard FileManager.default.fileExists(atPath: url.path) else {
            showToast(String(localized: "No log yet"))
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
        let pinned = !p.pinned  // what the user sees flipped, even if the file changed meanwhile
        update(p) { $0.pinned = pinned }
    }

    func makeDefault(_ p: Profile) {
        prefs.defaultProfile = isDefault(p) ? nil : p.id
    }

    func delete(_ p: Profile) {
        if pendingConnect.profileID == p.id { cancelPendingConnect() }
        Task {
            if state(p.id).isActive { _ = try? await connections.disconnect(p.id) }
            do {
                try store.delete(p.id)
                prefs = Preferences.load(paths: paths)
            } catch { showError(error) }
            reload()
        }
    }

    /// Removes the profile directory and the Keychain items under its id; the file itself is never read as a profile.
    func delete(_ p: UnsupportedProfile) {
        do {
            try store.delete(p.id)
            prefs = Preferences.load(paths: paths)
        } catch { showError(error) }
        reload()
    }

    func share(_ p: Profile) { ShareActions.export(profileID: p.id) }

    func edit(_ p: Profile) {
        if let refusal = editRefusal(p) { return showRefusal(refusal) }
        editor = EditorRequest(profileID: p.id, newType: nil)
    }

    func newProfile(_ type: VPNType) {
        if let refusal = connectRefusal(type) { return showRefusal(refusal) }
        editor = EditorRequest(profileID: nil, newType: type)
    }

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

    func showToast(_ text: String) {
        toast = ToastMessage(text: text)
    }

    /// "Requires macOS 15.4 or later" / "Cisco AnyConnect requires macOS 15.4 or later." (`connectRefusal`).
    func showRefusal(_ refusal: PTError) {
        alert = AppAlert(
            title: refusal.unavailableNote ?? String(localized: "Something went wrong"), message: refusal.localizedDescription)
    }

    func showError(_ error: Error) {
        alert = AppAlert(title: String(localized: "Something went wrong"), message: error.localizedDescription)
    }

    /// Shows the review of `draft` in the window's detail instead of a profile or the add view (a new one
    /// replaces a review still open).
    func startImportReview(_ draft: ImportDraft) {
        importReview = ImportReviewModel(draft: draft)
        addingProfile = false
        selection = nil
    }

    /// The window's detail shows the add view ("Add a VPN", `FirstRunView`): the sidebar's +.
    @Published var addingProfile = false

    /// The window asks "Open PassTunnel at login?" once the first profile is there (decision D-18), until it is
    /// answered (`onboardingKey`): Yes registers the login item, No turns launch at login off.
    func answerOpenAtLogin(_ open: Bool) {
        UserDefaults.standard.set(true, forKey: Self.onboardingKey)
        guard open else {
            prefs.launchAtLogin = false
            return
        }
        do {
            let status = try LoginItem.setEnabled(true)
            if status != .unavailable { prefs.launchAtLogin = status == .enabled || status == .requiresApproval }
        } catch {
            alert = AppAlert(
                title: String(localized: "Launch at login could not be turned on"),
                message: error.localizedDescription + "\n\n"
                    + String(localized: "You can turn it on later in Settings → General."))
        }
    }

    // MARK: events

    private func handle(_ event: ConnectionEvent) {
        switch event {
        case .dropped(let id, _), .droppedWhileAsleep(let id), .destinationChanged(let id, false):
            droppedUnseen.insert(id)
        case .reconnected(let id):
            droppedUnseen.remove(id)
        default:
            break
        }
        Notifier.shared.handle(event, model: self)
    }

    /// What a notification about `id` says about the profile.
    func noticeSubject(_ id: String) -> ConnectionNotice.Subject {
        guard let p = profile(id) else { return ConnectionNotice.Subject(name: id) }
        return ConnectionNotice.Subject(p, state: state(id), store: store)
    }
}
