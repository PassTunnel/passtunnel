import AppKit
import PassTunnelCore
import PassTunnelKit

/// A TOTP secret as the user hands it over: an otpauth link (which brings digits, period and algorithm) or a bare
/// secret. Read the same way by the profile editor and the import review.
enum CodeSecretInput {
    case link(OTPAuthURI)
    case secret(Data)

    /// "Paste": an image file or an image on the pasteboard (a QR code), else text (a link, Base32 or hex). nil when
    /// the pasteboard holds none of these; throws when what it holds is not a usable code.
    static func fromPasteboard(_ pb: NSPasteboard = .general) throws -> CodeSecretInput? {
        if let urls = pb.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL],
            let url = urls.first
        {
            return try fromImage(at: url)
        }
        if let image = NSImage(pasteboard: pb) { return try fromImage(image) }
        guard let text = pb.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines),
            !text.isEmpty
        else { return nil }
        return try fromText(text)
    }

    static func fromText(_ text: String) throws -> CodeSecretInput {
        if text.lowercased().hasPrefix("otpauth") { return .link(try OTPAuthURI(text)) }
        return .secret(try TOTP.decodeSecret(text))
    }

    /// The QR code in an image file.
    static func fromImage(at url: URL) throws -> CodeSecretInput {
        .link(try QRDecoder.otpAuth(inFile: url))
    }

    static func fromImage(_ image: NSImage) throws -> CodeSecretInput {
        guard let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            throw QRDecoder.Failure.unreadableImage
        }
        return .link(try QRDecoder.otpAuth(in: cg))
    }

    /// What to say when "Paste" finds nothing usable.
    static var nothingToPaste: String {
        String(localized: "Copy the secret, an otpauth:// link or a screenshot of the QR code first.")
    }
}
