import AppKit
import ApplicationServices

/// Types text into the focused app with synthetic keyboard events. Needs Accessibility permission.
enum AutoType {
    static var isTrusted: Bool { AXIsProcessTrusted() }

    /// Shows the system prompt that adds PassTunnel to the Accessibility list.
    static func requestTrust() {
        let key = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String
        _ = AXIsProcessTrustedWithOptions([key: true] as CFDictionary)
    }

    static func openAccessibilitySettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
            NSWorkspace.shared.open(url)
        }
    }

    /// Posts one unicode key down/up pair per character. Modifier flags are cleared explicitly so a
    /// hotkey that is still held (⌃⌥) does not change what is typed.
    static func type(_ text: String) {
        guard isTrusted else { return }
        let source = CGEventSource(stateID: .combinedSessionState)
        // Give the user a moment to release the hotkey's modifiers.
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 0.15) {
            for unit in text.utf16 {
                var char = unit
                for down in [true, false] {
                    guard let event = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: down) else { continue }
                    event.flags = []
                    event.keyboardSetUnicodeString(stringLength: 1, unicodeString: &char)
                    event.post(tap: .cghidEventTap)
                }
                usleep(8_000)
            }
        }
    }
}
