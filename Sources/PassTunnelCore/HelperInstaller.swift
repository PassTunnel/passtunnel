import Foundation
import ServiceManagement
import PassTunnelShared

public enum HelperStatus: String, Sendable {
    case notRegistered, enabled, requiresApproval, notFound
}

/// Registers and unregisters the helper daemon. `SMAppServiceRegistrar` in the app; tests use a fake.
public protocol HelperRegistrar: Sendable {
    var status: HelperStatus { get }
    func register() throws
    func unregister() async throws
}

public struct SMAppServiceRegistrar: HelperRegistrar {
    public init() {}

    public var service: SMAppService { SMAppService.daemon(plistName: PT.helperPlistName) }

    public var status: HelperStatus {
        switch service.status {
        case .notRegistered: return .notRegistered
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .notFound
        @unknown default: return .notFound
        }
    }

    public func register() throws { try service.register() }
    public func unregister() async throws { try await service.unregister() }
}

public enum HelperInstallError: Error, Equatable, LocalizedError {
    /// macOS kept refusing the registration ("Operation not permitted") after every retry.
    case notPermitted(String)
    /// The helper is switched off in System Settings → General → Login Items.
    case deniedByUser

    public var errorDescription: String? {
        switch self {
        case .notPermitted(let reason):
            return String(localized: "macOS did not allow PassTunnel to install the helper (\(reason)). Click Install Helper to try again.")
        case .deniedByUser:
            return String(localized: "The helper is turned off in System Settings → General → Login Items. Turn on PassTunnel there.")
        }
    }
}

/// Registers the helper daemon with launchd via SMAppService. The user approves it once in
/// System Settings → General → Login Items.
public enum HelperInstaller {
    public static var service: SMAppService { SMAppServiceRegistrar().service }
    public static var status: HelperStatus { SMAppServiceRegistrar().status }

    /// Pauses between register attempts that macOS refused with "Operation not permitted" (≈ 6.5 s).
    public static let retryDelays: [TimeInterval] = [0.5, 1, 2, 3]
    /// How long `update` waits for the old registration to go away before registering again.
    public static let unregisterWait: TimeInterval = 1.5
    static let statusPollInterval: TimeInterval = 0.25

    public typealias Sleeper = @Sendable (TimeInterval) async -> Void
    public static let realSleep: Sleeper = { seconds in
        try? await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
    }

    /// Registers the daemon once. Afterwards the status is usually `.requiresApproval`.
    public static func register() throws {
        do {
            try SMAppServiceRegistrar().register()
        } catch let error where classify(error) == .alreadyRegistered {
            return
        }
    }

    /// Registers the daemon, retrying while macOS refuses with "Operation not permitted": right after
    /// an unregister, launchd may still be tearing the old job down and refuses for a few seconds.
    /// Throws `HelperInstallError.notPermitted` when every retry failed, `.deniedByUser` at once.
    public static func register(using registrar: HelperRegistrar, retryDelays: [TimeInterval] = retryDelays,
                                sleep: Sleeper = realSleep) async throws {
        var attempt = 0
        while true {
            do {
                try registrar.register()
                return
            } catch {
                switch classify(error) {
                case .alreadyRegistered:
                    return
                case .deniedByUser:
                    throw HelperInstallError.deniedByUser
                case .notPermitted:
                    guard attempt < retryDelays.count else {
                        throw HelperInstallError.notPermitted(error.localizedDescription)
                    }
                    await sleep(retryDelays[attempt])
                    attempt += 1
                case .jobNotFound, .other:
                    throw error
                }
            }
        }
    }

    /// `register(using:)` with the real SMAppService.
    public static func registerRetrying() async throws {
        try await register(using: SMAppServiceRegistrar())
    }

    public static func unregister() async throws {
        try await SMAppServiceRegistrar().unregister()
        HelperClient.shared.invalidate()
    }

    /// Replaces a helper left running from another app version: unregistering stops it (launchd sends
    /// SIGTERM, which stops its tunnels), registering again points launchd at this copy. Waits for the
    /// old registration to go away, then registers with `register(using:)`'s retries. Callers decide
    /// whether this copy may take over (`HelperAutoUpdate`, or the user's confirmation).
    public static func update(using registrar: HelperRegistrar = SMAppServiceRegistrar(),
                              retryDelays: [TimeInterval] = retryDelays, unregisterWait: TimeInterval = unregisterWait,
                              sleep: Sleeper = realSleep) async throws {
        do {
            try await registrar.unregister()
        } catch let error where classify(error) == .jobNotFound {
            // Already gone: just register.
        }
        HelperClient.shared.invalidate()
        var waited: TimeInterval = 0
        while registrar.status == .enabled, waited < unregisterWait {
            await sleep(statusPollInterval)
            waited += statusPollInterval
        }
        try await register(using: registrar, retryDelays: retryDelays, sleep: sleep)
    }

    public static func openSystemSettingsLoginItems() {
        SMAppService.openSystemSettingsLoginItems()
    }

    // MARK: errors

    enum Failure: Equatable { case notPermitted, deniedByUser, alreadyRegistered, jobNotFound, other }

    /// SMAppService reports its own codes (`kSMError…`, `SMAppServiceErrorDomain`) and POSIX ones
    /// (EPERM, in either domain); the underlying error is checked too.
    static func classify(_ error: Error) -> Failure {
        let ns = error as NSError
        let posix = ns.domain == NSPOSIXErrorDomain
        let serviceManagement = ns.domain == "SMAppServiceErrorDomain" || ns.domain.contains("ServiceManagement")
        if (posix || serviceManagement) && ns.code == Int(EPERM) { return .notPermitted }
        if !posix {
            switch ns.code {
            case kSMErrorLaunchDeniedByUser: return .deniedByUser
            case kSMErrorAlreadyRegistered: return .alreadyRegistered
            case kSMErrorJobNotFound: return .jobNotFound
            default: break
            }
        }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError {
            let inner = classify(underlying)
            if inner != .other { return inner }
        }
        return .other
    }
}

/// Helper install / update / removal requested by the CLI but carried out by the app: SMAppService
/// refuses (or misattributes) registrations from a process started in Terminal, so `passtunnel helper
/// install|uninstall` opens the app with `argument`, or, when it already runs, posts `notification`
/// with the raw value as the object. The app then shows Settings → Helper and starts the action
/// there. Any local process can make the request, so install and update are only carried out by a
/// copy in /Applications, and replacing or removing a running helper always asks the user first
/// (replacing a newer helper with a warning). `update` replaces an outdated helper.
public enum HelperHandoff: String, CaseIterable, Sendable {
    case install, update, uninstall

    public static let notification = Notification.Name("com.furkanprlk.passtunnel.helperHandoff")

    /// Launch argument, e.g. `--install-helper` (not a CLI command, so the binary starts as the app).
    public var argument: String { "--\(rawValue)-helper" }

    public static func from(arguments: [String]) -> HelperHandoff? {
        allCases.first { arguments.dropFirst().contains($0.argument) }
    }

    /// The app's answer to a request, posted as `replyNotification` with `reply(_:)` as the object, so
    /// the waiting CLI can tell a pending confirmation or a refusal from a slow app. Only what the CLI
    /// prints depends on it: whether the action happened, the CLI reads from the helper itself.
    public static let replyNotification = Notification.Name("com.furkanprlk.passtunnel.helperHandoffReply")

    public enum Outcome: String, Sendable {
        /// The app asks the user to confirm (replacing or removing a running helper).
        case asking
        /// The user cancelled.
        case declined
        /// Not carried out: this copy is not in /Applications.
        case refused
    }

    public func reply(_ outcome: Outcome) -> String { "\(rawValue):\(outcome.rawValue)" }

    /// The outcome in a reply to this action; nil for anything else (another action, garbage).
    public func outcome(ofReply object: Any?) -> Outcome? {
        guard let text = object as? String, text.hasPrefix(rawValue + ":") else { return nil }
        return Outcome(rawValue: String(text.dropFirst(rawValue.count + 1)))
    }

    public func postReply(_ outcome: Outcome) {
        DistributedNotificationCenter.default().postNotificationName(
            Self.replyNotification, object: reply(outcome), userInfo: nil, deliverImmediately: true)
    }
}

/// How `passtunnel helper install|uninstall` waits for the app: until the helper is in the wanted
/// state, the app reports a decline or refusal, or the deadline passes. While the app asks the user
/// (`Outcome.asking`), the deadline moves out to `confirmationTimeout`, so a slow click does not
/// make the CLI give up on an update that then succeeds.
public struct HelperHandoffWait: Sendable {
    public enum Result: Equatable, Sendable { case done, declined, refused, timedOut }

    public static let confirmationTimeout: TimeInterval = 600

    public let action: HelperHandoff
    public private(set) var deadline: Date
    public private(set) var asking = false
    private var answer: HelperHandoff.Outcome?

    public init(action: HelperHandoff, timeout: TimeInterval, now: Date = Date()) {
        self.action = action
        deadline = now.addingTimeInterval(timeout)
    }

    /// Takes one reply notification's object. True when the app just started asking the user.
    @discardableResult
    public mutating func received(_ object: Any?, now: Date = Date()) -> Bool {
        guard let outcome = action.outcome(ofReply: object) else { return false }
        answer = outcome
        guard outcome == .asking, !asking else { return false }
        asking = true
        deadline = max(deadline, now.addingTimeInterval(Self.confirmationTimeout))
        return true
    }

    /// The result once there is one; nil: keep waiting. `done`: the helper is in the wanted state.
    public func result(done: Bool, now: Date = Date()) -> Result? {
        if done { return .done }
        switch answer {
        case .declined?: return .declined
        case .refused?: return .refused
        case .asking?, nil: return now > deadline ? .timedOut : nil
        }
    }
}
