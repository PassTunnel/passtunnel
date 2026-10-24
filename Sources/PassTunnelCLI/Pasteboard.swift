#if canImport(AppKit)
import AppKit

/// The general pasteboard for codes and passwords: the app's and `passtunnel code --copy`'s. How long
/// a copied secret stays is `Preferences.clearClipboardAfter`. Tests pass a pasteboard of their own.
public enum Pasteboard {
    /// nspasteboard.org markers: clipboard managers skip concealed entries and do not keep transient ones.
    static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    static let transientType = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    /// Copies a secret (`copySecret`) and clears it again after `seconds`, unless something else was
    /// copied meanwhile.
    public static func copySecret(_ text: String, clearingAfter seconds: TimeInterval,
                                  on pasteboard: NSPasteboard = .general) {
        let count = copySecret(text, on: pasteboard)
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { clear(ifUnchangedSince: count, on: pasteboard) }
    }

    /// Puts a secret on the pasteboard for this Mac only (not Universal Clipboard), marked concealed
    /// and transient. Returns the pasteboard's change count after the copy.
    @discardableResult
    public static func copySecret(_ text: String, on pasteboard: NSPasteboard = .general) -> Int {
        pasteboard.prepareForNewContents(with: .currentHostOnly)
        pasteboard.setString(text, forType: .string)
        pasteboard.setString("", forType: concealedType)
        pasteboard.setString("", forType: transientType)
        return pasteboard.changeCount
    }

    /// Empties the pasteboard unless something else was copied after `changeCount`.
    public static func clear(ifUnchangedSince changeCount: Int, on pasteboard: NSPasteboard = .general) {
        if pasteboard.changeCount == changeCount { pasteboard.clearContents() }
    }
}
#endif
