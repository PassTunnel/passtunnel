import Foundation
import PassTunnelShared

/// Where the helper's app bundle is. launchd starts the helper by a path relative to the bundle
/// (`BundleProgram`), and the user can move the app while the helper runs (from Downloads into
/// Applications, say): a path worked out once at launch then names a place where nothing is any more
/// (#309). So the bundle's files are located from the kernel's current path of the running executable
/// (`proc_pidpath`, which follows a rename of the bundle) each time they are needed.
enum HelperBundle {
    /// The helper's own executable as the kernel reports it now (not argv[0], which is relative).
    /// Throws when the kernel gives no absolute path.
    static func currentExecutablePath() throws -> String {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(getpid(), &buf, UInt32(buf.count))
        guard n > 0 else { throw HelperCore.Failure.system("locate the helper's executable", errno) }
        let path = String(cString: buf)
        guard path.hasPrefix("/") else { throw HelperCore.Failure.notAbsolute(path) }
        return path
    }

    /// The executable's path at launch, for `HelperImage` and the build number (both checked against the
    /// running image), with the old fallbacks when the kernel gives none.
    static var executablePath: String {
        (try? currentExecutablePath()) ?? Bundle.main.executablePath ?? CommandLine.arguments[0]
    }

    /// The app's `Contents`, above `Contents/MacOS/PassTunnelHelper`, where it is now. The tools are run
    /// from a staged copy (`ToolStager`), never from here.
    static func currentContentsDir() throws -> String {
        contentsDir(ofExecutable: try currentExecutablePath())
    }

    /// `executable`'s `Contents` (two levels up).
    static func contentsDir(ofExecutable executable: String) -> String {
        let macOS = (executable as NSString).deletingLastPathComponent
        return (macOS as NSString).deletingLastPathComponent
    }

    /// OpenVPN's DNS script, `Contents/Resources/bin/dns-updown`, where the bundle is now.
    static func currentDNSUpdownPath() throws -> String {
        (try currentContentsDir() as NSString).appendingPathComponent("Resources/bin/dns-updown")
    }
}
