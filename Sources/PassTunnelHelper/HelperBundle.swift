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

    /// `Contents/Resources/bin` next to `Contents/MacOS/PassTunnelHelper`.
    static var toolsDir: String {
        let macOS = (executablePath as NSString).deletingLastPathComponent
        let contents = (macOS as NSString).deletingLastPathComponent
        return (contents as NSString).appendingPathComponent("Resources/bin")
    }

    static func toolPath(_ tool: HelperCore.Tool) -> String {
        (toolsDir as NSString).appendingPathComponent(tool.rawValue)
    }

    static var dnsUpdownPath: String {
        (toolsDir as NSString).appendingPathComponent("dns-updown")
    }
}
