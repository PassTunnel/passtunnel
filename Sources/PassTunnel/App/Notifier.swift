import Foundation
import PassTunnelCore
import UserNotifications

/// Local notifications for connection events. Authorization is requested the first time one is needed.
@MainActor
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Notifier()

    static let connectAction = "connect"
    static let stopAction = "stop"
    /// Category with a Connect action.
    static let reconnectCategory = "reconnect"
    /// Category with a Stop action, for a drop while the automatic reconnect runs.
    static let reconnectingCategory = "reconnecting"
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
        let stop = UNNotificationAction(identifier: Self.stopAction, title: String(localized: "Stop"), options: [])
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Self.reconnectCategory, actions: [connect], intentIdentifiers: [], options: []),
            UNNotificationCategory(identifier: Self.reconnectingCategory, actions: [stop], intentIdentifiers: [], options: [])
        ])
    }

    /// Which event gives which notification is decided by `ConnectionNotice`.
    func handle(_ event: ConnectionEvent, model: AppModel) {
        guard let notice = ConnectionNotice.forEvent(event, model.noticeSubject(event.profileID), prefs: model.prefs)
        else { return }
        post(notice)
    }

    func post(_ notice: ConnectionNotice) {
        let category: String?
        switch notice.actions {
        case .connect: category = Self.reconnectCategory
        case .stop: category = Self.reconnectingCategory
        case nil: category = nil
        }
        post(
            title: notice.title, body: notice.body, profileID: notice.profileID, category: category,
            connectOnClick: notice.connectOnClick)
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
        if !ok { authorization = nil }  // ask again later if the user changes their mind
        return ok
    }

    // MARK: UNUserNotificationCenterDelegate

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let info = response.notification.request.content.userInfo
        let id = info["profileID"] as? String
        let connectOnClick = info[Self.connectOnClickKey] as? Bool == true
        let action = response.actionIdentifier
        Task { @MainActor in
            defer { completionHandler() }
            guard let model = AppModel.shared else { return }
            if action == Self.stopAction {
                if let id { model.stopReconnecting(id) }
            } else if action == Self.connectAction || (action == UNNotificationDefaultActionIdentifier && connectOnClick),
                let id, let p = model.profile(id)
            {
                model.connect(p)
                // A profile that asks for something (connect at login offers those too): the sheet is in the main window.
                if model.credentialRequest != nil { AppDelegate.shared?.showMainWindow() }
            } else if action == UNNotificationDefaultActionIdentifier {
                model.selection = id
                AppDelegate.shared?.showMainWindow()
            }
        }
    }
}
