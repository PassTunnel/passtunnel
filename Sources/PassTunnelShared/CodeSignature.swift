import Foundation
import Security

/// Static code-signature validation used by the helper before it launches a bundled tool.
/// Pure (no helper state), so it can be unit-tested against throwaway binaries.
public enum CodeSignature {
    public struct Failure: Error, Equatable, CustomStringConvertible {
        public let path: String
        public let status: OSStatus
        public var description: String {
            let msg = SecCopyErrorMessageString(status, nil) as String? ?? "error \(status)"
            return "Code signature check failed for \((path as NSString).lastPathComponent): \(msg)"
        }
    }

    /// Validates the static signature of the file at `path` (Mach-O, or a script signed in its
    /// extended attributes) against `requirement`, with strict validation of every architecture.
    public static func verify(path: String, requirement: String) throws {
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

    /// True if `requirement` compiles (catches typos in the requirement strings themselves).
    public static func isValidRequirement(_ requirement: String) -> Bool {
        var req: SecRequirement?
        return SecRequirementCreateWithString(requirement as CFString, [], &req) == errSecSuccess && req != nil
    }
}
