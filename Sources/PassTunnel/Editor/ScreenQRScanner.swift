import AppKit
import CoreGraphics
import PassTunnelCore
import PassTunnelKit
@preconcurrency import ScreenCaptureKit

/// "Scan QR on screen" (macOS 14 and later): reads an authenticator's `otpauth://` QR code from the window or display
/// the user picks in the system's content picker (`SCContentSharingPicker`), which needs no Screen Recording
/// permission. Only when the picker cannot capture the pick does it offer, after saying why, one picture of each
/// display instead, which needs that permission. Pictures are decoded in memory and never written anywhere.
@available(macOS 14.0, *)
@MainActor
final class ScreenQRScanner: NSObject, SCContentSharingPickerObserver {
    static let shared = ScreenQRScanner()

    enum ScanError: LocalizedError {
        case noCodeOnScreen
        /// Screen Recording is not allowed (the system asked, or it was turned off before).
        case notAllowed

        var errorDescription: String? {
            switch self {
            case .noCodeOnScreen:
                return String(localized: "No QR code was found on the screen. Make sure the whole code is visible, then scan again.")
            case .notAllowed:
                return String(localized: "Allow PassTunnel to record the screen in System Settings → Privacy & Security, then scan again.")
            }
        }
    }

    private enum Pick {
        case content(SCContentFilter)
        case cancelled
        case failed
    }

    private var pending: CheckedContinuation<Pick, Never>?

    /// The link of the first authenticator QR code found; nil when the user cancelled. Throws what went wrong
    /// otherwise (no code, not an `otpauth://` link, an HOTP or migration link, no permission).
    func scan() async throws -> OTPAuthURI? {
        switch await pick() {
        case .cancelled:
            return nil
        case .content(let filter):
            let image: CGImage
            do {
                image = try await Self.capture(filter)
            } catch {
                return try await scanDisplaysAfterAsking()
            }
            return try Self.decode([image])
        case .failed:
            return try await scanDisplaysAfterAsking()
        }
    }

    // MARK: the system picker

    private func pick() async -> Pick {
        guard pending == nil else { return .cancelled }  // one scan at a time
        let picker = SCContentSharingPicker.shared
        var configuration = SCContentSharingPickerConfiguration()
        configuration.allowedPickerModes = [.singleWindow, .singleDisplay]
        configuration.allowsChangingSelectedContent = false
        if let id = Bundle.main.bundleIdentifier { configuration.excludedBundleIDs = [id] }
        picker.defaultConfiguration = configuration
        picker.add(self)
        picker.isActive = true
        let result = await withCheckedContinuation { continuation in
            pending = continuation
            picker.present()
        }
        picker.isActive = false
        picker.remove(self)
        return result
    }

    private func finish(_ result: Pick) {
        pending?.resume(returning: result)
        pending = nil
    }

    nonisolated func contentSharingPicker(_ picker: SCContentSharingPicker, didCancelFor stream: SCStream?) {
        DispatchQueue.main.async { MainActor.assumeIsolated { self.finish(.cancelled) } }
    }

    nonisolated func contentSharingPicker(
        _ picker: SCContentSharingPicker, didUpdateWith filter: SCContentFilter,
        for stream: SCStream?
    ) {
        DispatchQueue.main.async { MainActor.assumeIsolated { self.finish(.content(filter)) } }
    }

    nonisolated func contentSharingPickerStartDidFailWithError(_ error: Error) {
        DispatchQueue.main.async { MainActor.assumeIsolated { self.finish(.failed) } }
    }

    // MARK: capture

    /// One picture of what `filter` shows, at full resolution, without the pointer. Kept in memory only.
    private static func capture(_ filter: SCContentFilter) async throws -> CGImage {
        let configuration = SCStreamConfiguration()
        let size = filter.contentRect.size
        if size.width > 0, size.height > 0 {
            let scale = CGFloat(max(1, filter.pointPixelScale))
            configuration.width = Int((size.width * scale).rounded())
            configuration.height = Int((size.height * scale).rounded())
        }
        configuration.captureResolution = .best
        configuration.showsCursor = false
        return try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
    }

    private static func decode(_ images: [CGImage]) throws -> OTPAuthURI {
        do {
            return try QRDecoder.otpAuth(inAny: images)
        } catch QRDecoder.Failure.noCode {
            throw ScanError.noCodeOnScreen
        }
    }

    /// The picker could not capture what was picked (or did not start): says why a picture of each display needs
    /// Screen Recording permission, then takes them if the user agrees and macOS allows it. nil: the user said no.
    private func scanDisplaysAfterAsking() async throws -> OTPAuthURI? {
        let alert = NSAlert()
        alert.messageText = String(localized: "Scan your screens instead?")
        alert.informativeText = String(
            localized:
                "macOS did not let PassTunnel capture what you picked. PassTunnel can take one picture of each screen instead and read the QR code from it. This needs Screen Recording permission, which macOS asks for the first time. The pictures stay in memory and are never saved or sent."
        )
        alert.addButton(withTitle: String(localized: "Scan Screens"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        // The first time, macOS shows its own request; once allowed, the next scan works.
        guard CGPreflightScreenCaptureAccess() || CGRequestScreenCaptureAccess() else { throw ScanError.notAllowed }

        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        let me = ProcessInfo.processInfo.processIdentifier
        let own = content.applications.filter { $0.processID == me }
        var images: [CGImage] = []
        for display in content.displays {
            images.append(
                try await Self.capture(
                    SCContentFilter(
                        display: display, excludingApplications: own,
                        exceptingWindows: [])))
        }
        return try Self.decode(images)
    }
}
