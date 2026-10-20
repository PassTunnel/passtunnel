import Foundation
import Security
import PassTunnelShared

enum CodeSignature {
    struct Failure: Error, CustomStringConvertible {
        let path: String
        let status: OSStatus
        var description: String {
            let msg = SecCopyErrorMessageString(status, nil) as String? ?? "error \(status)"
            return "Code signature check failed for \((path as NSString).lastPathComponent): \(msg)"
        }
    }

    /// Validates the static signature of the file at `path` (Mach-O, or a script signed in its
    /// extended attributes) against `requirement`.
    static func verify(path: String, requirement: String) throws {
        var code: SecStaticCode?
        var status = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
        guard status == errSecSuccess, let code else { throw Failure(path: path, status: status) }

        var req: SecRequirement?
        status = SecRequirementCreateWithString(requirement as CFString, [], &req)
        guard status == errSecSuccess, let req else { throw Failure(path: path, status: status) }

        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        status = SecStaticCodeCheckValidity(code, flags, req)
        guard status == errSecSuccess else { throw Failure(path: path, status: status) }
    }
}

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
