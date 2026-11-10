import Foundation

/// Decides when the app installs (registers) or repairs the helper on its own. Off unless the user turned
/// on "Install and repair the helper automatically" (`Preferences.autoInstallHelper`); `HelperAutoUpdate`,
/// which replaces an older helper after an app update, does not depend on it.
///
/// Only a bundled copy in /Applications acts on its own (registering points the root helper at the
/// registering copy). A helper the user removed (`Preferences.helperRemoved`) is not installed again, and
/// one waiting for the approval in Login Items (never approved, or switched off there) is never registered
/// again: macOS's approval stays with the user. Installing happens only when someone is there to approve:
/// on the first-run screen, when the switch is turned on, or on a Connect the user pressed in the app. A
/// helper that macOS lists as enabled but that does not answer (`HelperAnswerWatch`) is registered again
/// (`HelperInstaller.update`, which stops it) only while no PassTunnel session is active. One automatic
/// attempt of each per app launch, so a failure is left to the buttons instead of looping.
public struct HelperAutoInstall: Equatable, Sendable {
    public enum Trigger: Equatable, Sendable {
        /// The first-run screen shows the helper card.
        case firstRun
        /// The user turned the switch on.
        case switchedOn
        /// The user pressed Connect in the app (window, menu bar, shortcut, a notification's Connect).
        case connect
        /// A status refresh nobody asked for.
        case refresh
    }

    public enum Action: Equatable, Sendable {
        case none
        /// Run `HelperInstaller.register(using:)`.
        case register
        /// Run `HelperInstaller.update` (unregister, then register).
        case repair
    }

    public struct Situation: Equatable, Sendable {
        /// `Preferences.autoInstallHelper`.
        public var enabled: Bool
        /// `Preferences.helperRemoved`.
        public var removedByUser: Bool
        public var status: HelperStatus
        /// Enabled, but does not answer (`HelperAnswerWatch.notAnswering`).
        public var notAnswering: Bool
        /// Active PassTunnel sessions on this Mac, from any user or process (see `HelperSessions`).
        public var activeSessions: Int
        /// An install, update or repair is running.
        public var busy: Bool
        /// The app runs from /Applications (`HelperSessions.isInApplicationsFolder`).
        public var inApplicationsFolder: Bool
        /// A real app bundle (not a bare binary or a test build).
        public var bundled: Bool

        public init(
            enabled: Bool, removedByUser: Bool, status: HelperStatus, notAnswering: Bool, activeSessions: Int, busy: Bool,
            inApplicationsFolder: Bool, bundled: Bool
        ) {
            self.enabled = enabled
            self.removedByUser = removedByUser
            self.status = status
            self.notAnswering = notAnswering
            self.activeSessions = activeSessions
            self.busy = busy
            self.inApplicationsFolder = inApplicationsFolder
            self.bundled = bundled
        }
    }

    public private(set) var registerAttempted = false
    public private(set) var repairAttempted = false
    /// System Settings was opened by an automatic path once already.
    public private(set) var openedLoginItems = false

    public init() {}

    public mutating func next(_ s: Situation, trigger: Trigger) -> Action {
        guard s.enabled, !s.removedByUser, s.inApplicationsFolder, s.bundled, !s.busy else { return .none }
        switch s.status {
        case .notRegistered, .notFound:
            // `.notFound` too: macOS 27.0.1 reported a valid helper that was never registered that way, and
            // this is a bundled copy in /Applications (`HelperInstaller.canAttemptInstall`).
            guard trigger != .refresh, !registerAttempted else { return .none }
            registerAttempted = true
            return .register
        case .enabled:
            guard s.notAnswering, s.activeSessions == 0, !repairAttempted else { return .none }
            repairAttempted = true
            return .repair
        case .requiresApproval:
            return .none
        }
    }

    /// Whether an automatic registration that left the helper waiting for the approval may open Login
    /// Items: only right after the user acted in PassTunnel (`userActed`: a Connect, the switch, or the
    /// first-run screen in front), and once per launch.
    public mutating func opensLoginItems(userActed: Bool) -> Bool {
        guard userActed, !openedLoginItems else { return false }
        openedLoginItems = true
        return true
    }
}

/// Tells a helper that does not answer from one that is slow. macOS may list the helper as enabled while
/// launchd cannot start it (a moved or damaged bundle, for one); a single unanswered question proves
/// nothing (launchd may still be starting it, or the Mac is busy). So "not answering" needs
/// `failuresNeeded` questions in a row without any answer (`HelperClient` timeouts or refused
/// connections), the first and the last at least `minimumSpan` apart. Any answer, or another status,
/// starts over.
public struct HelperAnswerWatch: Equatable, Sendable {
    public static let failuresNeeded = 3
    public static let minimumSpan: TimeInterval = 30

    public private(set) var failures = 0
    private var firstFailure: Date?
    private var lastFailure: Date?

    public init() {}

    public var notAnswering: Bool {
        guard failures >= Self.failuresNeeded, let firstFailure, let lastFailure else { return false }
        return lastFailure.timeIntervalSince(firstFailure) >= Self.minimumSpan
    }

    /// The helper answered (whatever it said).
    public mutating func answered() { self = Self() }

    /// The status is not `.enabled`, or the helper was just replaced.
    public mutating func reset() { self = Self() }

    /// One question failed with `error`. Only a timeout or a refused connection counts as no answer; an
    /// invalid reply came from a helper that runs, and a status error means the status changed meanwhile.
    public mutating func failed(_ error: Error, at now: Date = Date()) {
        guard let e = error as? HelperClientError else { return }
        switch e {
        case .timeout, .unavailable:
            if failures == 0 { firstFailure = now }
            failures += 1
            lastFailure = now
        case .notInstalled, .requiresApproval, .notFound:
            reset()
        case .badResponse, .versionMismatch, .buildMismatch:
            answered()
        }
    }
}

/// A Connect the user pressed while the helper was missing or waiting for the approval: it starts once
/// the helper is ready, without a second click. It is dropped after `timeout`, when the user cancels it
/// or does something else with the profile, and when the automatic install is turned off. One at a
/// time: a Connect of another profile replaces it.
public struct HelperPendingConnect: Equatable, Sendable {
    public static let timeout: TimeInterval = 5 * 60

    public enum Outcome: Equatable, Sendable {
        case none
        /// The helper is ready: connect this profile now.
        case connect(String)
        /// The approval did not come in time: tell the user.
        case expired(String)
    }

    public private(set) var profileID: String?
    public private(set) var deadline: Date?

    public init() {}

    public var isWaiting: Bool { profileID != nil }

    public mutating func start(_ id: String, now: Date = Date()) {
        profileID = id
        deadline = now.addingTimeInterval(Self.timeout)
    }

    /// Drops the waiting connect, if any; returns its profile.
    @discardableResult
    public mutating func cancel() -> String? {
        let id = profileID
        profileID = nil
        deadline = nil
        return id
    }

    /// Drops the waiting connect when it is for `id` (the user disconnected, deleted… that profile).
    @discardableResult
    public mutating func cancel(profile id: String) -> Bool {
        guard profileID == id else { return false }
        cancel()
        return true
    }

    /// `ready`: the helper is enabled, answers with this copy's build and is not being replaced.
    public mutating func next(ready: Bool, now: Date = Date()) -> Outcome {
        guard let id = profileID, let deadline else { return .none }
        if ready {
            cancel()
            return .connect(id)
        }
        if now >= deadline {
            cancel()
            return .expired(id)
        }
        return .none
    }
}
