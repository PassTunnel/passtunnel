import AppKit
import Carbon.HIToolbox

/// Global hotkeys through Carbon's RegisterEventHotKey (works without Accessibility permission).
@MainActor
final class Hotkeys {
    static let shared = Hotkeys()

    enum Action: UInt32, CaseIterable {
        case toggleDefault = 1
        case code = 2

        var keyCode: UInt32 {
            switch self {
            case .toggleDefault: return UInt32(kVK_ANSI_V)
            case .code: return UInt32(kVK_ANSI_C)
            }
        }

        static let modifiers = UInt32(controlKey | optionKey)

        /// Display form, e.g. "⌃⌥V".
        var display: String {
            switch self {
            case .toggleDefault: return "⌃⌥V"
            case .code: return "⌃⌥C"
            }
        }
    }

    var handler: ((Action) -> Void)?
    private var refs: [EventHotKeyRef] = []
    private var eventHandler: EventHandlerRef?
    private(set) var failed: [Action] = []
    private static let signature: OSType = 0x5054_4E4C   // "PTNL"

    var isEnabled: Bool { !refs.isEmpty }

    func setEnabled(_ enabled: Bool) {
        unregister()
        guard enabled else { return }
        installHandlerIfNeeded()
        failed = []
        for action in Action.allCases {
            var ref: EventHotKeyRef?
            let id = EventHotKeyID(signature: Self.signature, id: action.rawValue)
            let status = RegisterEventHotKey(action.keyCode, Action.modifiers, id, GetApplicationEventTarget(), 0, &ref)
            if status == noErr, let ref { refs.append(ref) } else { failed.append(action) }
        }
    }

    private func unregister() {
        refs.forEach { UnregisterEventHotKey($0) }
        refs.removeAll()
    }

    private func installHandlerIfNeeded() {
        guard eventHandler == nil else { return }
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(GetApplicationEventTarget(), { _, event, _ -> OSStatus in
            var id = EventHotKeyID()
            let status = GetEventParameter(event, EventParamName(kEventParamDirectObject), EventParamType(typeEventHotKeyID),
                                           nil, MemoryLayout<EventHotKeyID>.size, nil, &id)
            guard status == noErr, id.signature == Hotkeys.signature, let action = Hotkeys.Action(rawValue: id.id) else {
                return OSStatus(eventNotHandledErr)
            }
            DispatchQueue.main.async { MainActor.assumeIsolated { Hotkeys.shared.handler?(action) } }
            return noErr
        }, 1, &spec, nil, &eventHandler)
    }
}
