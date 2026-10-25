import Foundation
import PassTunnelKit

/// "Connect at login" (`Profile.connectAtLogin`), run once when the app was opened at login: waits until the
/// helper and the network are ready (at most `readinessTimeout`), then goes through those profiles in the sidebar
/// order. One that can connect without asking is connected, one at a time; one that needs a confirmation (Touch ID
/// or the Mac password) or asks for something gets a notification to click instead, since nobody expects a prompt
/// at login. The app posts the notifications; this decides them.
@MainActor
public final class LoginConnector {
    /// What connecting needs that may not be there yet right after login.
    public struct Readiness: Equatable, Sendable {
        /// The helper is installed, approved, answers and is this copy's build.
        public var helper: Bool
        /// The Mac has a network path (it is online).
        public var network: Bool

        public init(helper: Bool, network: Bool) {
            self.helper = helper
            self.network = network
        }

        public var isReady: Bool { helper && network }
    }

    /// What happened to one profile.
    public enum Outcome: Equatable, Sendable {
        case connected
        /// It needs a confirmation or asks for something: offered in a notification.
        case offered
        /// Connected or connecting already (another process, or a session the helper kept running).
        case alreadyActive
        /// The user cancelled the attempt (disconnected meanwhile).
        case cancelled
        case failed(reason: String)
    }

    public struct Step: Equatable, Sendable {
        public var profileID: String
        public var outcome: Outcome

        public init(_ profileID: String, _ outcome: Outcome) {
            self.profileID = profileID
            self.outcome = outcome
        }
    }

    /// How long the helper and the network get after login before the profiles are given up on.
    public nonisolated static let readinessTimeout: TimeInterval = 90
    nonisolated static let readinessInterval: TimeInterval = 1

    private let manager: ConnectionManager
    private let clock: ConnectionClock
    private let readiness: () -> Readiness
    private let notify: (ConnectionNotice) -> Void

    public init(manager: ConnectionManager, clock: ConnectionClock = SystemClock(),
                readiness: @escaping () -> Readiness, notify: @escaping (ConnectionNotice) -> Void) {
        self.manager = manager
        self.clock = clock
        self.readiness = readiness
        self.notify = notify
    }

    /// Returns what happened to each profile, in order. Nothing is waited for when no profile is set to connect
    /// at login.
    @discardableResult
    public func run(timeout: TimeInterval = LoginConnector.readinessTimeout) async -> [Step] {
        let ids = manager.store.list().filter(\.connectAtLogin).map(\.id)
        guard !ids.isEmpty else { return [] }
        let deadline = clock.now().addingTimeInterval(timeout)
        var ready = readiness()
        while !ready.isReady && clock.now() < deadline {
            do { try await clock.sleep(Self.readinessInterval) } catch { return [] }
            ready = readiness()
        }
        await manager.refresh()
        var steps: [Step] = []
        for id in ids {
            // Read again: the switch may have been turned off, or the profile deleted, while it waited.
            guard let p = try? manager.store.get(id), p.connectAtLogin else { continue }
            steps.append(Step(id, await handle(p, ready: ready)))
        }
        return steps
    }

    private func handle(_ p: Profile, ready: Readiness) async -> Outcome {
        if manager.state(p.id).isActive { return .alreadyActive }
        guard ready.isReady else {
            let reason = ready.helper ? String(localized: "This Mac is offline.")
                                      : String(localized: "The PassTunnel helper is not ready.")
            notify(.notConnectedAtLogin(subject(p), reason: reason, profileID: p.id))
            return .failed(reason: reason)
        }
        guard p.unattended, !manager.vault.requiresConfirmation(p) else { return offer(p) }
        do {
            try await manager.connect(p.id, interactive: false)
        } catch PTError.confirmationRequired {
            return offer(p)
        } catch {
            if error is CancellationError || (error as? PTError) == .connectCancelled { return .cancelled }
            notify(.notConnectedAtLogin(subject(p), reason: error.localizedDescription, profileID: p.id))
            return .failed(reason: error.localizedDescription)
        }
        guard manager.state(p.id).isConnected else { return .cancelled }
        // PassTunnel connected on its own: always announced (`ConnectionNotice.announcesConnect`).
        notify(.connected(subject(p), profileID: p.id))
        return .connected
    }

    private func offer(_ p: Profile) -> Outcome {
        notify(.offeredAtLogin(subject(p), profileID: p.id))
        return .offered
    }

    private func subject(_ p: Profile) -> ConnectionNotice.Subject {
        ConnectionNotice.Subject(p, state: manager.state(p.id), store: manager.store)
    }
}
