#if canImport(AppKit)
import AppKit

/// The general pasteboard for codes and passwords: the app's and `passtunnel code --copy`'s.
public enum Pasteboard {
    /// How long a copied code (or password + code) stays on the pasteboard.
    public static let secretLifetime: TimeInterval = 30
    /// nspasteboard.org markers: clipboard managers skip concealed entries and do not keep transient ones.
    static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    static let transientType = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    /// `concealed`: a secret (`copySecret`), cleared again after `secretLifetime`.
    public static func copy(_ text: String, concealed: Bool) {
        guard concealed else {
            let pb = NSPasteboard.general
            pb.clearContents()
            pb.setString(text, forType: .string)
            return
        }
        let count = copySecret(text)
        DispatchQueue.main.asyncAfter(deadline: .now() + secretLifetime) { clear(ifUnchangedSince: count) }
    }

    /// Puts a secret on the general pasteboard for this Mac only (not Universal Clipboard), marked
    /// concealed and transient. Returns the pasteboard's change count after the copy.
    @discardableResult
    public static func copySecret(_ text: String) -> Int {
        let pb = NSPasteboard.general
        pb.prepareForNewContents(with: .currentHostOnly)
        pb.setString(text, forType: .string)
        pb.setString("", forType: concealedType)
        pb.setString("", forType: transientType)
        return pb.changeCount
    }

    /// Empties the pasteboard unless something else was copied after `changeCount`.
    public static func clear(ifUnchangedSince changeCount: Int) {
        let pb = NSPasteboard.general
        if pb.changeCount == changeCount { pb.clearContents() }
    }
}
#endif
