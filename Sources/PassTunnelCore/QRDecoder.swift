import CoreGraphics
import Foundation
import ImageIO
import Vision

/// Finds QR codes in images (screenshots, photos, clipboard images) and turns an
/// `otpauth://` QR code into an `OTPAuthURI`.
public enum QRDecoder {
    public enum Failure: Error, Equatable, LocalizedError {
        case unreadableImage
        case noCode
        case notOTPAuth
        case migrationExport

        public var errorDescription: String? {
            switch self {
            case .unreadableImage:
                return String(localized: "The image could not be read.")
            case .noCode:
                return String(localized: "No QR code was found in the image.")
            case .notOTPAuth:
                return String(localized: "The QR code does not contain an otpauth:// link.")
            case .migrationExport:
                return String(localized: "This is an authenticator export code with several accounts. Export a single account, or use the QR code your VPN provider showed when you set up the code.")
            }
        }
    }

    /// Text payloads of every QR code in the image, in Vision's order. Throws `.noCode` when none.
    public static func payloads(in image: CGImage) throws -> [String] {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        let handler = VNImageRequestHandler(cgImage: image, options: [:])
        do { try handler.perform([request]) } catch { throw Failure.unreadableImage }
        let found = (request.results ?? []).compactMap(\.payloadStringValue).filter { !$0.isEmpty }
        guard !found.isEmpty else { throw Failure.noCode }
        return found
    }

    /// Any format ImageIO reads (PNG, JPEG, TIFF, HEIC, GIF, …); the first frame is used.
    public static func payloads(inImageData data: Data) throws -> [String] {
        try payloads(in: cgImage(from: data))
    }

    public static func payloads(inFile url: URL) throws -> [String] {
        guard let data = try? Data(contentsOf: url) else { throw Failure.unreadableImage }
        return try payloads(inImageData: data)
    }

    /// The first `otpauth://` payload parsed; other payloads are ignored. Errors from `OTPAuthURI`
    /// (e.g. HOTP, missing secret) are passed through.
    public static func otpAuth(from payloads: [String]) throws -> OTPAuthURI {
        let trimmed = payloads.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        if let uri = trimmed.first(where: { $0.lowercased().hasPrefix("otpauth://") }) {
            return try OTPAuthURI(uri)
        }
        if trimmed.contains(where: { $0.lowercased().hasPrefix("otpauth-migration://") }) {
            throw Failure.migrationExport
        }
        throw Failure.notOTPAuth
    }

    public static func otpAuth(in image: CGImage) throws -> OTPAuthURI {
        try otpAuth(from: payloads(in: image))
    }

    public static func otpAuth(inImageData data: Data) throws -> OTPAuthURI {
        try otpAuth(from: payloads(inImageData: data))
    }

    public static func otpAuth(inFile url: URL) throws -> OTPAuthURI {
        try otpAuth(from: payloads(inFile: url))
    }

    static func cgImage(from data: Data) throws -> CGImage {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              CGImageSourceGetCount(source) > 0,
              let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
            throw Failure.unreadableImage
        }
        return image
    }
}
