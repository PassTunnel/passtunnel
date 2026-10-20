import Foundation
import Security

/// Errors thrown by PassTunnelCore. `localizedDescription` / `errorDescription` is user-readable.
public enum PTError: Error, Equatable, LocalizedError {
    case profileNotFound(String)
    case invalidProfileID(String)
    case emptyName
    case invalidField(String)              // field name, e.g. "totp.digits"
    case wrongProfileType(String)          // profile id
    case fileError(String)                 // path or short reason
    case fileTooLarge(String)
    case invalidFile(String)               // unreadable / malformed JSON or text
    case keychain(Int32)                   // OSStatus
    case invalidSecret
    case invalidOTPAuthURI(String)         // reason
    case hotpNotSupported
    case invalidTemplate(String)           // reason
    case unsupportedShareFile
    case noFreePort

    public var errorDescription: String? {
        switch self {
        case .profileNotFound(let id):
            return String(localized: "Profile “\(id)” was not found.")
        case .invalidProfileID(let id):
            return String(localized: "“\(id)” is not a valid profile identifier.")
        case .emptyName:
            return String(localized: "The profile name cannot be empty.")
        case .invalidField(let field):
            return String(localized: "The value of “\(field)” is not valid.")
        case .wrongProfileType(let id):
            return String(localized: "This action is not available for the VPN type of profile “\(id)”.")
        case .fileError(let detail):
            return String(localized: "A file operation failed: \(detail)")
        case .fileTooLarge(let name):
            return String(localized: "The file “\(name)” is too large.")
        case .invalidFile(let name):
            return String(localized: "The file “\(name)” could not be read or is damaged.")
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return String(localized: "Keychain error: \(message)")
        case .invalidSecret:
            return String(localized: "The TOTP secret is not valid Base32 or hex.")
        case .invalidOTPAuthURI(let reason):
            return String(localized: "The otpauth link is not valid: \(reason)")
        case .hotpNotSupported:
            return String(localized: "Counter-based (HOTP) codes are not supported. Only time-based (TOTP) codes can be used.")
        case .invalidTemplate(let reason):
            return String(localized: "The code template is not valid: \(reason)")
        case .unsupportedShareFile:
            return String(localized: "This is not a PassTunnel profile file, or it was made by a newer version.")
        case .noFreePort:
            return String(localized: "No free management port is left for a new OpenVPN profile.")
        }
    }
}
