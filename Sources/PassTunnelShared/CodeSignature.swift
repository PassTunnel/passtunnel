// macOS only: code signatures (Security). No Linux counterpart; passtunneld trusts root-owned paths (docs/LINUX.md).
#if os(macOS)
import Foundation
import Security

/// Code-signature validation used by the helper before it launches a bundled tool (static, by path)
/// and before it lets the started tool run (dynamic, by pid).
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
    /// Returns the cdhash (lowercase hex) of the validated signature.
    @discardableResult
    public static func verify(path: String, requirement: String) throws -> String {
        var code: SecStaticCode?
        var status = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
        guard status == errSecSuccess, let code else { throw Failure(path: path, status: status) }

        var req: SecRequirement?
        status = SecRequirementCreateWithString(requirement as CFString, [], &req)
        guard status == errSecSuccess, let req else { throw Failure(path: path, status: status) }

        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        status = SecStaticCodeCheckValidity(code, flags, req)
        guard status == errSecSuccess else { throw Failure(path: path, status: status) }
        return try cdhash(of: code, path: path)
    }

    /// Validates the code that process `pid` runs, as the kernel loaded it, against `requirement`.
    /// Unlike `verify(path:)` this cannot be raced by swapping the file: Security also checks that
    /// the code on disk is what the kernel mapped (`errSecCSStaticCodeChanged` otherwise; if the file
    /// was unlinked, finding the process's code by its path already fails, with ESRCH). The caller
    /// must keep `pid` from being reused, e.g. by checking its own unreaped child. `path` only names
    /// the code in errors. Returns the cdhash (lowercase hex) of the code that was validated, which is
    /// the kernel's for the process; the file at `path` may have been replaced since.
    @discardableResult
    public static func verify(pid: pid_t, path: String, requirement: String) throws -> String {
        var code: SecCode?
        var status = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code)
        guard status == errSecSuccess, let code else { throw Failure(path: path, status: status) }

        var req: SecRequirement?
        status = SecRequirementCreateWithString(requirement as CFString, [], &req)
        guard status == errSecSuccess, let req else { throw Failure(path: path, status: status) }

        // kSecCSCheckAllArchitectures does not apply to running code (only the loaded slice counts).
        status = SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), req)
        guard status == errSecSuccess else { throw Failure(path: path, status: status) }

        // The static code the validation used (and matched against the kernel's cdhash), as cached
        // in `code`; it is not read from disk again.
        var staticCode: SecStaticCode?
        status = SecCodeCopyStaticCode(code, [], &staticCode)
        guard status == errSecSuccess, let staticCode else { throw Failure(path: path, status: status) }
        return try cdhash(of: staticCode, path: path)
    }

    /// `kSecCodeInfoUnique`: the cdhash of the code directory in use, as `codesign -dvvv` prints it (`CDHash=`).
    static func cdhash(of code: SecStaticCode, path: String) throws -> String {
        var info: CFDictionary?
        let status = SecCodeCopySigningInformation(code, [], &info)
        guard status == errSecSuccess else { throw Failure(path: path, status: status) }
        guard let unique = (info as? [String: Any])?[kSecCodeInfoUnique as String] as? Data, !unique.isEmpty else {
            throw Failure(path: path, status: errSecCSUnsigned)
        }
        return unique.map { String(format: "%02x", $0) }.joined()
    }

    /// True if `requirement` compiles (catches typos in the requirement strings themselves).
    public static func isValidRequirement(_ requirement: String) -> Bool {
        var req: SecRequirement?
        return SecRequirementCreateWithString(requirement as CFString, [], &req) == errSecSuccess && req != nil
    }
}
#endif
