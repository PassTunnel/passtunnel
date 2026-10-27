import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto  // swift-crypto: the same API, outside Apple platforms
#endif

/// Identity of a helper build: the SHA-256 of the helper executable. The helper computes it once at
/// launch (so a running helper keeps reporting the build it was started from, even after the app
/// bundle was replaced on disk); the app hashes the helper inside its own bundle. Different values
/// mean the running helper is not the one this copy of the app ships, even with the same protocol.
/// Which of the two is newer comes from the build numbers (`relation`), never from the digests.
public enum HelperBuild {
    /// Executable name of the helper, next to the app's executable in `Contents/MacOS`.
    public static let executableName = "PassTunnelHelper"

    /// Hex SHA-256 of the file at `path`, nil when it cannot be read.
    public static func digest(ofFile path: String) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        do {
            // nil (or empty) at the end of the file.
            while let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty {
                hasher.update(data: chunk)
            }
        } catch {
            return nil
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// The running process's executable, as the kernel reports it (symlinks resolved); Foundation's
    /// answer elsewhere than on the Mac.
    public static var currentExecutablePath: String? {
        #if os(macOS)
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(getpid(), &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : Bundle.main.executablePath
        #else
        return Bundle.main.executablePath
        #endif
    }

    /// The helper that ships next to `executable` (`Contents/MacOS/PassTunnelHelper`).
    public static func bundledHelperPath(nextTo executable: String) -> String {
        ((executable as NSString).deletingLastPathComponent as NSString).appendingPathComponent(executableName)
    }

    /// Digest of the helper shipped with the running app or CLI; nil when there is none (tests, a
    /// bare `swift build`), in which case builds are not compared.
    public static let bundled: String? = currentExecutablePath.flatMap { digest(ofFile: bundledHelperPath(nextTo: $0)) }

    #if os(Linux)
    /// Executable name of the Linux daemon. It hashes itself (`/proc/self/exe`) once at start and
    /// reports the digest in `hello` (docs/LINUX.md).
    public static let daemonExecutableName = "passtunneld"

    /// The daemon installed together with the `passtunnel` at `executable` (symlinks resolved):
    /// `<prefix>/sbin/passtunneld` for `<prefix>/bin/passtunnel` (the packages' /usr, the tarball's
    /// /usr/local), else `passtunneld` in the same directory (a development build). Nil when neither
    /// is a file.
    public static func installedDaemonPath(nextTo executable: String) -> String? {
        let real = HelperCore.realPath(executable) ?? executable
        let dir = (real as NSString).deletingLastPathComponent
        let candidates = [
            ((dir as NSString).deletingLastPathComponent as NSString).appendingPathComponent("sbin/" + daemonExecutableName),
            (dir as NSString).appendingPathComponent(daemonExecutableName)
        ]
        return candidates.first { path in
            var st = stat()
            return stat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG
        }
    }

    /// Digest of the daemon installed with the running `passtunnel`: what the running daemon must
    /// report, as `bundled` is on the Mac. A difference means the daemon still runs an earlier binary
    /// (restart it) or comes from another installation. Nil when there is none (tests), in which case
    /// builds are not compared.
    public static let installedDaemon: String? =
        currentExecutablePath
        .flatMap(installedDaemonPath(nextTo:)).flatMap(digest(ofFile:))
    #endif

    /// True unless both builds are known and differ.
    public static func matches(helper: String, expected: String?) -> Bool {
        guard let expected else { return true }
        return helper == expected
    }

    // MARK: - Build numbers

    /// `CFBundleVersion` (the build number, which only grows between releases) of the app bundle whose
    /// `Contents/MacOS` holds `executable`; nil outside a bundle or when it is not a number.
    public static func buildNumber(ofBundleContaining executable: String) -> Int? {
        let contents = ((executable as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent
        let plist = (contents as NSString).appendingPathComponent("Info.plist")
        guard let data = FileManager.default.contents(atPath: plist),
            let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
            let value = dict["CFBundleVersion"] as? String
        else { return nil }
        return Int(value.trimmingCharacters(in: .whitespaces))
    }

    /// Build number of the running app or CLI; nil outside a bundle.
    public static let bundledNumber: Int? = currentExecutablePath.flatMap { buildNumber(ofBundleContaining: $0) }

    /// How a running helper relates to the one a copy of the app ships.
    public enum Relation: Equatable, Sendable {
        /// The same build (or builds are not compared: no bundled helper).
        case current
        /// An earlier protocol or build number, or a helper too old to report its build number:
        /// replacing it is an upgrade.
        case older
        /// Another build with the same build number, or the app's own number is unknown.
        case different
        /// A later protocol or build number: replacing it would install an older helper.
        case newer
    }

    /// Compares the running helper (`helper…`, as it reports itself) with the app's bundled helper.
    public static func relation(
        helperProtocol: Int, helperDigest: String?, helperNumber: Int?,
        appProtocol: Int = PT.helperProtocolVersion,
        appDigest: String?, appNumber: Int?
    ) -> Relation {
        if helperProtocol < appProtocol { return .older }
        if helperProtocol > appProtocol { return .newer }
        guard let appDigest, helperDigest != appDigest else { return .current }
        guard let appNumber else { return .different }
        guard let helperNumber else { return .older }
        if helperNumber < appNumber { return .older }
        if helperNumber > appNumber { return .newer }
        return .different
    }
}
