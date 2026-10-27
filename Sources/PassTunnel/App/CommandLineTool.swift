import Foundation

/// Installs the `passtunnel` symlink that points at the app's executable.
enum CommandLineTool {
    static let name = "passtunnel"
    static let systemDir = URL(fileURLWithPath: "/usr/local/bin", isDirectory: true)
    static var userDir: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin", isDirectory: true)
    }

    enum Result: Equatable {
        case installed(URL)
        case installedNeedsPath(URL)  // ~/.local/bin is not on PATH yet
    }

    static var executable: URL? { Bundle.main.executableURL?.resolvingSymlinksInPath() }

    /// Where the tool currently points at this app, if anywhere.
    static var installedLocation: URL? {
        guard let exe = executable else { return nil }
        for dir in [systemDir, userDir] {
            let link = dir.appendingPathComponent(name)
            if let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: link.path),
                URL(fileURLWithPath: dest, relativeTo: dir).resolvingSymlinksInPath() == exe
            {
                return link
            }
        }
        return nil
    }

    static func install() throws -> Result {
        guard let exe = executable else { throw CocoaError(.fileNoSuchFile) }
        let fm = FileManager.default
        if fm.isWritableFile(atPath: systemDir.path) {
            let link = systemDir.appendingPathComponent(name)
            if (try? replaceLink(at: link, to: exe)) != nil { return .installed(link) }
        }
        try fm.createDirectory(at: userDir, withIntermediateDirectories: true)
        let link = userDir.appendingPathComponent(name)
        try replaceLink(at: link, to: exe)
        let path = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":").map(String.init)
        let onPath = path.contains(userDir.path) || path.contains("~/.local/bin") || loginShellPathContains(userDir.path)
        return onPath ? .installed(link) : .installedNeedsPath(link)
    }

    private static func replaceLink(at link: URL, to target: URL) throws {
        let fm = FileManager.default
        if let attrs = try? fm.attributesOfItem(atPath: link.path) {
            // Only replace our own symlink, never a real file someone put there.
            guard attrs[.type] as? FileAttributeType == .typeSymbolicLink else { throw CocoaError(.fileWriteFileExists) }
            try fm.removeItem(at: link)
        }
        try fm.createSymbolicLink(at: link, withDestinationURL: target)
    }

    /// GUI apps get a minimal PATH; look at the user's shell profile files for a hint instead.
    private static func loginShellPathContains(_ dir: String) -> Bool {
        let home = FileManager.default.homeDirectoryForCurrentUser
        for file in [".zprofile", ".zshrc", ".bash_profile", ".bashrc", ".profile", ".config/fish/config.fish"] {
            if let text = try? String(contentsOf: home.appendingPathComponent(file), encoding: .utf8),
                text.contains(".local/bin") || text.contains(dir)
            {
                return true
            }
        }
        return false
    }
}
