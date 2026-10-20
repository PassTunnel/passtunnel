import CryptoKit
import Foundation

/// Identity of a helper build: the SHA-256 of the helper executable. The helper computes it once at
/// launch (so a running helper keeps reporting the build it was started from, even after the app
/// bundle was replaced on disk); the app hashes the helper inside its own bundle. Different values
/// mean the running helper is not the one this copy of the app ships, even with the same protocol.
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

    /// The running process's executable, as the kernel reports it (symlinks resolved).
    public static var currentExecutablePath: String? {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(getpid(), &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : Bundle.main.executablePath
    }

    /// The helper that ships next to `executable` (`Contents/MacOS/PassTunnelHelper`).
    public static func bundledHelperPath(nextTo executable: String) -> String {
        ((executable as NSString).deletingLastPathComponent as NSString).appendingPathComponent(executableName)
    }

    /// Digest of the helper shipped with the running app or CLI; nil when there is none (tests, a
    /// bare `swift build`), in which case builds are not compared.
    public static let bundled: String? = currentExecutablePath.flatMap { digest(ofFile: bundledHelperPath(nextTo: $0)) }

    /// True unless both builds are known and differ.
    public static func matches(helper: String, expected: String?) -> Bool {
        guard let expected else { return true }
        return helper == expected
    }
}
