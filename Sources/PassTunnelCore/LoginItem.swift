// macOS only: "Open at login" (SMAppService).
#if os(macOS)
import Foundation
import ServiceManagement

public enum LoginItemStatus: String, Sendable {
    case enabled, requiresApproval, disabled
    /// Not running from an app bundle (`swift run`, tests): login items cannot be registered.
    case unavailable
}

/// "Open at login" via `SMAppService.mainApp`, and detection of launches that came from it.
public enum LoginItem {
    /// Command-line flag with the same effect as a login launch: start in the menu bar only.
    public static let backgroundArgument = "--background"

    public static var isAvailable: Bool { Bundle.main.bundleURL.pathExtension == "app" }

    public static var status: LoginItemStatus {
        guard isAvailable else { return .unavailable }
        switch SMAppService.mainApp.status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notRegistered, .notFound: return .disabled
        @unknown default: return .disabled
        }
    }

    /// Registers or unregisters the app as a login item. Returns the resulting status.
    @discardableResult
    public static func setEnabled(_ on: Bool) throws -> LoginItemStatus {
        guard isAvailable else { return .unavailable }
        let service = SMAppService.mainApp
        do {
            if on { try service.register() } else { try service.unregister() }
        } catch let error as NSError where on && error.code == kSMErrorAlreadyRegistered {
            // Already there; status tells whether it still needs approval.
        } catch let error as NSError where !on && (error.code == kSMErrorJobNotFound || service.status == .notRegistered) {
            // Nothing to remove.
        }
        return status
    }

    public static func openSystemSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    /// The main window asks "Open PassTunnel at login?" once there is a profile, until the user answers, and only
    /// while the login item is off: not when it is on or waits for approval, nor when it cannot be registered. `status`
    /// is read only when the rest holds.
    public static func asksAfterFirstProfile(
        answered: Bool, hasProfiles: Bool,
        status: @autoclosure () -> LoginItemStatus
    ) -> Bool {
        !answered && hasProfiles && status() == .disabled
    }

    /// True when the app was started by the login item (the launch Apple event carries
    /// `keyAELaunchedAsLogInItem`) or with `--background`.
    public static func isBackgroundLaunch(arguments: [String], launchEvent: NSAppleEventDescriptor?) -> Bool {
        if arguments.dropFirst().contains(backgroundArgument) { return true }
        guard let event = launchEvent,
            event.eventClass == AEEventClass(kCoreEventClass),
            event.eventID == AEEventID(kAEOpenApplication),
            let property = event.paramDescriptor(forKeyword: AEKeyword(keyAEPropData))
        else { return false }
        return property.enumCodeValue == OSType(keyAELaunchedAsLogInItem)
    }
}
#endif
