import Foundation
import PassTunnelKit

/// A user notification about a connection: which `ConnectionEvent` gives which notification, and
/// when "Connected to <Profile>" is shown. Worked out here, apart from UserNotifications, so the app
/// (`Notifier`) only posts it.
public struct ConnectionNotice: Equatable, Sendable {
    /// The buttons a notification offers.
    public enum Actions: Equatable, Sendable {
        /// "Connect": connects the profile, asking for any confirmation it needs.
        case connect
        /// "Stop": ends the automatic reconnect that is under way, like Cancel Connecting.
        case stop
    }

    public var title: String
    public var body: String
    public var profileID: String
    public var actions: Actions?
    /// Clicking the notification connects the profile; otherwise a click shows the profile.
    public var connectOnClick: Bool

    public init(title: String, body: String, profileID: String, actions: Actions? = nil, connectOnClick: Bool = false) {
        self.title = title
        self.body = body
        self.profileID = profileID
        self.actions = actions
        self.connectOnClick = connectOnClick
    }

    /// What a notification says about the profile it is about.
    public struct Subject: Equatable, Sendable {
        public var name: String
        /// The profile sends a one-time code from its TOTP secret, so a reconnect waits for a fresh one.
        public var usesCode: Bool
        /// The tunnel address while connected; "" when unknown.
        public var address: String
        /// The server (`ProfileDestination.host`); "" when unknown.
        public var server: String

        public init(name: String, usesCode: Bool = false, address: String = "", server: String = "") {
            self.name = name
            self.usesCode = usesCode
            self.address = address
            self.server = server
        }

        /// `p` in `state`: the address only while connected, the server as the confirmation prompt names it.
        public init(_ p: Profile, state: ConnectionState, store: ProfileStore) {
            var address = ""
            if case .connected(let ip, _) = state { address = ip }
            self.init(
                name: p.name, usesCode: p.otpMode == .totp, address: address,
                server: ProfileDestination.of(p, store: store).host)
        }
    }

    /// Who started a connect that succeeded.
    public enum ConnectOrigin: Equatable, Sendable {
        /// The user, from the main window, the menu bar, a shortcut or a notification.
        case user
        /// PassTunnel on its own (a reconnect).
        case automatic
    }

    /// Whether a successful connect gets "Connected to <Profile>": always when PassTunnel connected on
    /// its own; when the user did, only while the main window is not visible, since the window shows it.
    public static func announcesConnect(_ origin: ConnectOrigin, mainWindowVisible: Bool) -> Bool {
        origin == .automatic || !mainWindowVisible
    }

    /// "Connected to Work" / "10.8.0.6 · vpn.example.com".
    public static func connected(_ s: Subject, profileID: String) -> ConnectionNotice {
        ConnectionNotice(
            title: String(localized: "Connected to \(s.name)"),
            body: [s.address, s.server].filter { !$0.isEmpty }.joined(separator: " · "),
            profileID: profileID)
    }

    /// Connect at login, for a profile that needs a confirmation or asks for something: offered instead of a
    /// prompt nobody expects at login. A click connects (and asks).
    public static func offeredAtLogin(_ s: Subject, profileID: String) -> ConnectionNotice {
        ConnectionNotice(
            title: String(localized: "“\(s.name)” is set to connect at login"),
            body: String(localized: "Click to connect."),
            profileID: profileID, actions: .connect, connectOnClick: true)
    }

    /// Connect at login did not connect the profile: `reason` is the error, or what was not ready in time.
    public static func notConnectedAtLogin(_ s: Subject, reason: String, profileID: String) -> ConnectionNotice {
        ConnectionNotice(
            title: String(localized: "Could not connect “\(s.name)” at login"), body: reason,
            profileID: profileID, actions: .connect)
    }

    /// The notification for `event`, or nil when `prefs` turn that kind off. Drops, reconnects and
    /// failed reconnects follow `notifyOnDrop`, health `notifyHealth`, the session limit
    /// `sessionNotifyMin`. A drop while asleep and a changed destination are always shown: they replace
    /// the automatic reconnect the user turned on.
    public static func forEvent(_ event: ConnectionEvent, _ s: Subject, prefs: Preferences) -> ConnectionNotice? {
        switch event {
        case .dropped(let id, true):
            guard prefs.notifyOnDrop else { return nil }
            return ConnectionNotice(
                title: String(localized: "\(s.name) dropped"),
                body: s.usesCode
                    ? String(localized: "Reconnecting with a fresh code…")
                    : String(localized: "Reconnecting…"),
                profileID: id, actions: .stop)
        case .dropped(let id, false):
            guard prefs.notifyOnDrop else { return nil }
            return ConnectionNotice(
                title: String(localized: "\(s.name) dropped"),
                body: String(localized: "It will not reconnect automatically."),
                profileID: id, actions: .connect)
        case .reconnected(let id):
            // A reconnect is an automatic connect (`announcesConnect`).
            guard prefs.notifyOnDrop else { return nil }
            return connected(s, profileID: id)
        case .reconnectFailed(let id, let reason):
            guard prefs.notifyOnDrop else { return nil }
            return ConnectionNotice(
                title: String(localized: "Could not reconnect \(s.name)"), body: reason,
                profileID: id, actions: .connect)
        case .unreachable(let id):
            guard prefs.notifyHealth else { return nil }
            return ConnectionNotice(
                title: String(localized: "\(s.name) is not responding"),
                body: String(localized: "The VPN is connected, but the health check host cannot be reached."),
                profileID: id)
        case .reachableAgain(let id):
            guard prefs.notifyHealth else { return nil }
            return ConnectionNotice(
                title: String(localized: "\(s.name) is responding again"),
                body: String(localized: "The health check host can be reached again."), profileID: id)
        case .sessionEnding(let id, let minutes):
            guard prefs.sessionNotifyMin > 0 else { return nil }
            return ConnectionNotice(
                title: String(localized: "\(s.name) session is ending"),
                body: String(localized: "The session limit is reached in \(minutes) minutes."),
                profileID: id)
        case .droppedWhileAsleep(let id):
            return ConnectionNotice(
                title: String(localized: "“\(s.name)” disconnected while the Mac was asleep."),
                body: String(localized: "Click to reconnect."),
                profileID: id, actions: .connect, connectOnClick: true)
        case .destinationChanged(let id, true):
            // The forced reconnect of a health outage, not done: the old tunnel is still up. Connecting
            // on click would do nothing while it is; a click shows the profile.
            return ConnectionNotice(
                title: String(localized: "“\(s.name)” server settings changed"),
                body: String(
                    localized: "It is still connected to the server you confirmed, which is not responding. Reconnect to confirm the new settings."),
                profileID: id)
        case .destinationChanged(let id, false):
            return ConnectionNotice(
                title: String(localized: "“\(s.name)” was not reconnected"),
                body: String(localized: "Its server settings changed after you confirmed the connection. Click to connect and confirm again."),
                profileID: id, actions: .connect, connectOnClick: true)
        }
    }
}
