import Foundation
import PassTunnelKit

/// What the app does with files it is asked to open (Finder, AirDrop, the Dock icon, `open`). The app
/// declares only `.passtunnel`, but "Open With" and `open -a` can hand it anything. Like File → Import
/// Shared Profile, one file at a time, through the same import.
public enum OpenedFiles: Equatable {
    case importShare(URL)
    /// More than one file: nothing is imported.
    case tooMany(Int)
    /// Not a share file (by extension; the import itself checks the contents).
    case unsupported(String)

    /// nil when there is nothing to open.
    public static func route(_ urls: [URL]) -> OpenedFiles? {
        guard let url = urls.first else { return nil }
        guard urls.count == 1 else { return .tooMany(urls.count) }
        guard url.isFileURL, url.pathExtension.lowercased() == ShareFile.fileExtension else {
            return .unsupported(url.isFileURL ? url.lastPathComponent : url.absoluteString)
        }
        return .importShare(url)
    }
}
