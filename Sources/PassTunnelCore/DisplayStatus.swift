import Foundation
import PassTunnelKit

/// The one status a profile shows in the app's views (sidebar row, detail header, menu bar panel):
/// worked out from what `ConnectionManager` reports, and worded as the design words it. Kept apart from
/// SwiftUI so it is tested; the app adds the icon and the color. (`ProfileStatus` is what the CLI and the MCP
/// server report.)
public enum DisplayStatus: Equatable, Sendable {
    /// Not connected.
    case off
    /// Not connected, and connecting asks for Touch ID or the Mac password first ("Confirm with Touch ID").
    case protected
    /// On the way; `phase` as `ConnectionManager.Phase` words it ("Signing in…").
    case connecting(phase: String)
    /// Connecting, but waiting for the next TOTP window before sending a code (`codeWaitUntil`).
    case waitingForCode(until: Date)
    case connected(Connection)
    /// Connected, but part of the network setup failed (`ConnectionManager.warnings`).
    case setupIncomplete(Connection, warning: String)
    /// Connected, but the health check host does not answer (`HealthState.unreachable`).
    case notResponding(Connection)
    /// Connected according to the last known state or the log: another client holds the management
    /// interface (`ConnectionManager.statusUnavailable`).
    case statusUnavailable(Connection)
    /// Dropped, and the automatic reconnect is under way. `freshCode`: the profile sends a TOTP code, and
    /// the reconnect sends a new one.
    case reconnecting(ReconnectInfo, freshCode: Bool)
    /// Dropped, and not reconnecting automatically; shown until the user has seen it.
    case dropped
    /// The last connect failed.
    case failed(Failure)

    /// A connection that is up.
    public struct Connection: Equatable, Sendable {
        /// When it connected; nil when unknown.
        public var since: Date?
        /// The tunnel address; "" when unknown.
        public var address: String

        public init(since: Date?, address: String) {
            self.since = since
            self.address = address
        }
    }

    /// Why the last connect failed (`ConnectionFailure.Kind`): the reasons the app words and shows a card for
    /// each, else the error as `ConnectionManager.lastError` words it.
    public enum Failure: Equatable, Sendable {
        /// The error as `ConnectionManager.lastError` words it.
        case message(String)
        /// The server refused the sign-in; PassTunnel did not retry it.
        case signInRejected
        /// The server's name could not be resolved.
        case hostNotFound
        /// The server did not answer. `retry`: the tries that follow, while there are any (`UnreachableRetry`);
        /// nil once they ended.
        case unreachable(retry: UnreachableRetry?)

        /// The reason `failure` gives for the last error; the error's own words when the kind has no case.
        init(_ failure: ConnectionFailure?, error: String) {
            switch failure?.kind {
            case .authRejected?: self = .signInRejected
            case .hostNotFound?: self = .hostNotFound
            case .unreachable?: self = .unreachable(retry: nil)
            default: self = .message(error)
            }
        }
    }

    /// What Core reports about one profile, as the app reads it.
    public struct Facts: Equatable, Sendable {
        public var state: ConnectionState
        /// `ConnectionManager.reconnecting`: an automatic reconnect after a drop is pending or running.
        public var reconnect: ReconnectInfo?
        /// `ConnectionManager.codeWaitUntil`: a connect waits for a fresh code until then.
        public var codeWaitUntil: Date?
        /// `ConnectionManager.lastError`.
        public var lastError: String?
        /// `ConnectionManager.warnings`.
        public var warning: String?
        /// The health check host does not answer (`ConnectionManager.health` is `.unreachable`).
        public var notResponding: Bool
        /// `ConnectionManager.statusUnavailable` holds the profile.
        public var statusUnavailable: Bool
        /// The connection dropped and the user has not looked since (the app's own bookkeeping).
        public var droppedUnseen: Bool
        /// Connecting asks for a confirmation first (`asksToConnect(_:)`).
        public var asksToConnect: Bool
        /// The profile sends a code from its TOTP secret.
        public var usesCode: Bool
        /// `ConnectionManager.failures`: why the last connect failed, typed.
        public var failure: ConnectionFailure?
        /// `ConnectionManager.unreachableRetries`: a server that did not answer is tried again.
        public var retry: UnreachableRetry?

        public init(
            state: ConnectionState = .disconnected, reconnect: ReconnectInfo? = nil, codeWaitUntil: Date? = nil,
            lastError: String? = nil, warning: String? = nil, notResponding: Bool = false,
            statusUnavailable: Bool = false, droppedUnseen: Bool = false, asksToConnect: Bool = false,
            usesCode: Bool = false, failure: ConnectionFailure? = nil, retry: UnreachableRetry? = nil
        ) {
            self.state = state
            self.reconnect = reconnect
            self.codeWaitUntil = codeWaitUntil
            self.lastError = lastError
            self.warning = warning
            self.notResponding = notResponding
            self.statusUnavailable = statusUnavailable
            self.droppedUnseen = droppedUnseen
            self.asksToConnect = asksToConnect
            self.usesCode = usesCode
            self.failure = failure
            self.retry = retry
        }

        /// The facts about `p`; what follows from its settings is filled in.
        public init(
            _ p: Profile, state: ConnectionState, reconnect: ReconnectInfo? = nil, codeWaitUntil: Date? = nil,
            lastError: String? = nil, warning: String? = nil, notResponding: Bool = false,
            statusUnavailable: Bool = false, droppedUnseen: Bool = false, failure: ConnectionFailure? = nil,
            retry: UnreachableRetry? = nil
        ) {
            self.init(
                state: state, reconnect: reconnect, codeWaitUntil: codeWaitUntil, lastError: lastError,
                warning: warning, notResponding: notResponding, statusUnavailable: statusUnavailable,
                droppedUnseen: droppedUnseen, asksToConnect: Facts.asksToConnect(p), usesCode: p.otpMode == .totp,
                failure: failure, retry: retry)
        }

        /// What `m` reports about `p` now. `droppedUnseen` is the app's to tell.
        @MainActor
        public init(_ p: Profile, in m: ConnectionManager, droppedUnseen: Bool = false) {
            let id = p.id
            self.init(
                p, state: m.state(id), reconnect: m.reconnecting[id], codeWaitUntil: m.codeWaitUntil[id],
                lastError: m.lastError[id], warning: m.warnings[id], notResponding: m.health[id] == .unreachable,
                statusUnavailable: m.statusUnavailable.contains(id), droppedUnseen: droppedUnseen,
                failure: m.failures[id], retry: m.unreachableRetries[id])
        }

        /// The profile's "Confirm with Touch ID" setting asks before connecting: either level, since the redesign
        /// shows both as one switch (decision D-4), and only when connecting uses a stored secret.
        public static func asksToConnect(_ p: Profile) -> Bool {
            p.requireAuth != .off && p.usesStoredSecrets
        }
    }

    /// The status the facts give when several apply: a connection that is up wins (it may come with a
    /// problem, the worst one shown); then an automatic reconnect, which covers its own attempts and their
    /// failures until it ends; then a connect under way; then the last failure, an unseen drop, and the
    /// state at rest. A server that does not answer is shown as such while its tries go on, also during one.
    public init(_ f: Facts) {
        if case .connected(let ip, let since) = f.state {
            let c = Connection(since: since, address: ip)
            if f.notResponding {
                self = .notResponding(c)
            } else if let warning = f.warning {
                self = .setupIncomplete(c, warning: warning)
            } else if f.statusUnavailable {
                self = .statusUnavailable(c)
            } else {
                self = .connected(c)
            }
        } else if let reconnect = f.reconnect {
            self = .reconnecting(reconnect, freshCode: f.usesCode)
        } else if let until = f.codeWaitUntil {
            self = .waitingForCode(until: until)
        } else if let retry = f.retry {
            self = .failed(.unreachable(retry: retry))
        } else if case .connecting(let phase) = f.state {
            self = .connecting(phase: phase)
        } else if let error = f.lastError {
            self = .failed(Failure(f.failure, error: error))
        } else if f.droppedUnseen {
            self = .dropped
        } else {
            self = f.asksToConnect ? .protected : .off
        }
    }

    // MARK: action

    /// The main button of the detail for a status; Return, a double click and ⌘↩ do the same.
    public enum Action: CaseIterable, Sendable {
        case connect, cancel, disconnect, stop, tryAgain

        public var title: String {
            switch self {
            case .connect: return String(localized: "Connect")
            case .cancel: return String(localized: "Cancel")
            case .disconnect: return String(localized: "Disconnect")
            case .stop: return String(localized: "Stop")
            case .tryAgain: return String(localized: "Try again")
            }
        }

        /// Connect and Try again start a connection; the others end the connection, the attempt under way or the
        /// automatic reconnect.
        public var connects: Bool { self == .connect || self == .tryAgain }
    }

    /// Connect at rest (also after a drop), Cancel on the way, Disconnect once up (whatever its problem), Stop
    /// while it reconnects on its own or tries an unreachable server again, Try again after a failure.
    public var action: Action {
        switch self {
        case .off, .protected, .dropped: return .connect
        case .connecting, .waitingForCode: return .cancel
        case .connected, .setupIncomplete, .notResponding, .statusUnavailable: return .disconnect
        case .reconnecting, .failed(.unreachable(retry: .some)): return .stop
        case .failed: return .tryAgain
        }
    }

    // MARK: wording

    /// The short form, for sidebar rows and the menu bar panel: "Connected · 1h 12m".
    public func summary(at now: Date) -> String {
        switch self {
        case .off: return String(localized: "Disconnected")
        case .protected: return String(localized: "Touch ID to connect")
        case .connecting: return String(localized: "Connecting…")
        case .waitingForCode(let until):
            return String(localized: "Waiting for a fresh code · \(Self.seconds(until: until, now: now)) s")
        case .connected(let c):
            return Self.joined(String(localized: "Connected"), c.since.map { Self.uptime(since: $0, now: now) })
        case .setupIncomplete: return Self.joined(String(localized: "Connected"), String(localized: "setup incomplete"))
        case .notResponding: return Self.joined(String(localized: "Connected"), String(localized: "not responding"))
        case .statusUnavailable: return Self.joined(String(localized: "Connected"), String(localized: "status unavailable"))
        case .reconnecting: return String(localized: "Dropped, reconnecting…")
        case .dropped: return String(localized: "Connection dropped")
        case .failed(.message): return String(localized: "Couldn’t connect")
        case .failed(.signInRejected): return String(localized: "Sign-in rejected")
        case .failed(.hostNotFound): return String(localized: "Server not found")
        case .failed(.unreachable(let retry)):
            return retry == nil ? String(localized: "Unreachable") : String(localized: "Unreachable, retrying")
        }
    }

    /// The long form, for the detail's status line: "Connected · 1h 12m · 10.8.0.6". `server` names where a
    /// connect goes ("vpn.example.com:1194"; "" when unknown).
    public func line(at now: Date, server: String = "") -> String {
        switch self {
        case .off, .dropped: return summary(at: now)
        case .protected: return String(localized: "Disconnected · asks for Touch ID")
        case .connecting(let phase):
            if !server.isEmpty { return String(localized: "Connecting to \(server)…") }
            return phase.isEmpty ? String(localized: "Connecting…") : phase
        case .waitingForCode(let until):
            return String(localized: "Waiting for a fresh code · sends in \(Self.seconds(until: until, now: now)) s")
        case .connected(let c): return Self.connectedLine(c, now: now, nil)
        case .setupIncomplete(let c, _): return Self.connectedLine(c, now: now, String(localized: "setup incomplete"))
        case .notResponding(let c): return Self.connectedLine(c, now: now, String(localized: "not responding"))
        case .statusUnavailable(let c): return Self.connectedLine(c, now: now, String(localized: "status unavailable"))
        case .reconnecting(let r, let freshCode):
            // After a failed attempt, the wait for the next one counts down.
            let wait = Self.seconds(until: r.at, now: now)
            if r.attempt > 1 && wait > 0 { return String(localized: "Dropped · next try in \(wait) s") }
            return freshCode
                ? String(localized: "Dropped, reconnecting with a fresh code…")
                : String(localized: "Dropped, reconnecting…")
        case .failed(.message(let message)):
            let text = message.trimmingCharacters(in: .whitespacesAndNewlines)
            return text.isEmpty ? summary(at: now) : text
        case .failed(.signInRejected): return String(localized: "Sign-in rejected by the server")
        case .failed(.hostNotFound): return String(localized: "Can’t find the server")
        case .failed(.unreachable(let retry)):
            let words = String(localized: "Can’t reach the server")
            guard let retry else { return words }
            if retry.waitingForNetwork { return Self.joined(words, String(localized: "waiting for the network")) }
            if let at = retry.nextTryAt, case let wait = Self.seconds(until: at, now: now), wait > 0 {
                return Self.joined(words, String(localized: "next try in \(wait) s"))
            }
            return Self.joined(words, String(localized: "trying again…"))
        }
    }

    /// How long a connection has been up, as the design words it: "1h 12m", "8 min", "just now".
    public static func uptime(since: Date, now: Date) -> String {
        let seconds = wholeSeconds(now.timeIntervalSince(since), .down)
        let hours = seconds / 3600
        let minutes = seconds % 3600 / 60
        if hours > 0 { return String(localized: "\(hours)h \(minutes)m") }
        if minutes > 0 { return String(localized: "\(minutes) min") }
        return String(localized: "just now")
    }

    /// Whole seconds left until `until`, rounded up, never negative.
    static func seconds(until: Date, now: Date) -> Int {
        wholeSeconds(until.timeIntervalSince(now), .up)
    }

    /// `interval` in whole seconds; 0 when negative or not a number, and never too large for an `Int`.
    private static func wholeSeconds(_ interval: TimeInterval, _ rule: FloatingPointRoundingRule) -> Int {
        guard interval.isFinite, interval > 0 else { return 0 }
        return Int(min(interval, 1e12).rounded(rule))
    }

    private static func connectedLine(_ c: Connection, now: Date, _ problem: String?) -> String {
        joined(String(localized: "Connected"), c.since.map { uptime(since: $0, now: now) }, c.address, problem)
    }

    /// The parts that are known, joined with " · ".
    private static func joined(_ parts: String?...) -> String {
        parts.compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
    }
}
