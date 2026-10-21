import Foundation
import PassTunnelCore
import UserNotifications

/// Local notifications for connection events. Authorization is requested the first time one is needed.
@MainActor
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Notifier()

    static let connectAction = "connect"
    static let reconnectCategory = "reconnect"
    /// userInfo key: clicking the notification itself connects (and confirms) the profile.
    nonisolated static let connectOnClickKey = "connectOnClick"

    private var authorization: Task<Bool, Never>?

    /// UNUserNotificationCenter needs a real app bundle (it traps otherwise).
    private var available: Bool { Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app" }

    func setUp() {
        guard available else { return }
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let connect = UNNotificationAction(identifier: Self.connectAction, title: String(localized: "Connect"), options: [])
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Self.reconnectCategory, actions: [connect], intentIdentifiers: [], options: []),
        ])
    }

    func handle(_ event: ConnectionEvent, model: AppModel) {
        let prefs = model.prefs
        func name(_ id: String) -> String { model.profile(id)?.name ?? id }
        switch event {
        case .dropped(let id, let reconnecting):
            guard prefs.notifyOnDrop else { return }
            post(title: String(localized: "\(name(id)) disconnected"),
                 body: reconnecting ? String(localized: "The connection dropped unexpectedly. Reconnecting…")
                                    : String(localized: "The connection dropped unexpectedly."),
                 profileID: id, category: reconnecting ? nil : Self.reconnectCategory)
        case .reconnected(let id):
            guard prefs.notifyOnDrop else { return }
            post(title: String(localized: "\(name(id)) reconnected"),
                 body: String(localized: "The connection is back."), profileID: id)
        case .reconnectFailed(let id, let reason):
            guard prefs.notifyOnDrop else { return }
            post(title: String(localized: "Could not reconnect \(name(id))"),
                 body: reason, profileID: id, category: Self.reconnectCategory)
        case .unreachable(let id):
            guard prefs.notifyHealth else { return }
            post(title: String(localized: "\(name(id)) is not responding"),
                 body: String(localized: "The VPN is connected, but the health check host cannot be reached."),
                 profileID: id)
        case .reachableAgain(let id):
            guard prefs.notifyHealth else { return }
            post(title: String(localized: "\(name(id)) is responding again"),
                 body: String(localized: "The health check host can be reached again."), profileID: id)
        case .sessionEnding(let id, let minutes):
            guard prefs.sessionNotifyMin > 0 else { return }
            post(title: String(localized: "\(name(id)) session is ending"),
                 body: String(localized: "The session limit is reached in \(minutes) minutes."), profileID: id)
        case .droppedWhileAsleep(let id):
            // Replaces the automatic reconnect the user turned on, so it is shown even without drop notifications.
            post(title: String(localized: "“\(name(id))” disconnected while the Mac was asleep."),
                 body: String(localized: "Click to reconnect."),
                 profileID: id, category: Self.reconnectCategory, connectOnClick: true)
        case .destinationChanged(let id, true):
            // The forced reconnect of a health outage, not done: the old tunnel is still up. Connecting
            // on click would do nothing while it is; a click shows the profile.
            post(title: String(localized: "“\(name(id))” server settings changed"),
                 body: String(localized: "It is still connected to the server you confirmed, which is not responding. Reconnect to confirm the new settings."),
                 profileID: id)
        case .destinationChanged(let id, false):
            // Replaces the automatic reconnect too: shown even without drop notifications.
            post(title: String(localized: "“\(name(id))” was not reconnected"),
                 body: String(localized: "Its server settings changed after you confirmed the connection. Click to connect and confirm again."),
                 profileID: id, category: Self.reconnectCategory, connectOnClick: true)
        }
    }

    func post(title: String, body: String, profileID: String?, category: String? = nil, connectOnClick: Bool = false) {
        guard available else { return }
        Task {
            guard await authorized() else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            if let category { content.categoryIdentifier = category }
            if let profileID {
                content.userInfo = ["profileID": profileID, Self.connectOnClickKey: connectOnClick]
                content.threadIdentifier = profileID
            }
            let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
            try? await UNUserNotificationCenter.current().add(request)
        }
    }

    private func authorized() async -> Bool {
        if let authorization { return await authorization.value }
        let task = Task { () -> Bool in
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()
            switch settings.authorizationStatus {
            case .authorized, .provisional: return true
            case .denied: return false
            default: return (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
            }
        }
        authorization = task
        let ok = await task.value
        if !ok { authorization = nil }   // ask again later if the user changes their mind
        return ok
    }

    // MARK: UNUserNotificationCenterDelegate

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let info = response.notification.request.content.userInfo
        let id = info["profileID"] as? String
        let connectOnClick = info[Self.connectOnClickKey] as? Bool == true
        let action = response.actionIdentifier
        Task { @MainActor in
            defer { completionHandler() }
            guard let model = AppModel.shared else { return }
            if action == Self.connectAction || (action == UNNotificationDefaultActionIdentifier && connectOnClick),
               let id, let p = model.profile(id) {
                model.connect(p)
            } else if action == UNNotificationDefaultActionIdentifier {
                model.selection = id
                AppDelegate.shared?.showMainWindow()
            }
        }
    }
}
