import Foundation
import PassTunnelShared

enum HelperBundle {
    /// The helper's own executable, as the kernel reports it (not argv[0]).
    static var executablePath: String {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(getpid(), &buf, UInt32(buf.count))
        if n > 0 { return String(cString: buf) }
        return Bundle.main.executablePath ?? CommandLine.arguments[0]
    }

    /// The app's `Contents`, above `Contents/MacOS/PassTunnelHelper`. The tools are run from a staged
    /// copy (`ToolStager`), never from here.
    static var contentsDir: String {
        let macOS = (executablePath as NSString).deletingLastPathComponent
        return (macOS as NSString).deletingLastPathComponent
    }

    /// `Contents/Resources/bin`.
    static var toolsDir: String {
        (contentsDir as NSString).appendingPathComponent("Resources/bin")
    }

    static var dnsUpdownPath: String {
        (toolsDir as NSString).appendingPathComponent("dns-updown")
    }
}
