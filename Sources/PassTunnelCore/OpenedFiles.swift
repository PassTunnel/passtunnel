import Foundation
import PassTunnelKit

/// What the app does with files it is asked to open (Finder, AirDrop, the Dock icon, `open`). The app
/// declares only `.passtunnel`, but "Open With" and `open -a` can hand it anything. Like the import panels,
/// one file at a time, through the same import.
public enum OpenedFiles: Equatable {
    case importShare(URL)
    /// An OpenVPN configuration (`.ovpn`, `.conf`): the redesigned window reviews it, as File → Import .ovpn…
    /// does there.
    case importOVPN(URL)
    /// More than one file: nothing is imported.
    case tooMany(Int)
    /// Neither (by extension; the import itself checks the contents).
    case unsupported(String)

    /// Extensions of OpenVPN configurations.
    public static let ovpnExtensions: Set<String> = ["ovpn", "conf"]

    /// nil when there is nothing to open.
    public static func route(_ urls: [URL]) -> OpenedFiles? {
        guard let url = urls.first else { return nil }
        guard urls.count == 1 else { return .tooMany(urls.count) }
        guard url.isFileURL else { return .unsupported(url.absoluteString) }
        let ext = url.pathExtension.lowercased()
        if ext == ShareFile.fileExtension { return .importShare(url) }
        if ovpnExtensions.contains(ext) { return .importOVPN(url) }
        return .unsupported(url.lastPathComponent)
    }
}
