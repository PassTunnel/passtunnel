import Foundation

#if canImport(Security)
import Security
#endif

/// Errors thrown by PassTunnelCore. `localizedDescription` / `errorDescription` is user-readable.
public enum PTError: Error, Equatable, LocalizedError {
    case profileNotFound(String)
    case invalidProfileID(String)
    case emptyName
    case invalidField(String)  // field name, e.g. "totp.digits"
    case wrongProfileType(String)  // profile id
    case unsupportedProfileType(String)  // the `type` of a profile written by a newer version
    case fileError(String)  // path or short reason
    case fileTooLarge(String)
    case invalidFile(String)  // unreadable / malformed JSON or text
    case keychain(Int32)  // OSStatus
    case invalidSecret
    case invalidOTPAuthURI(String)  // reason
    case hotpNotSupported
    case invalidTemplate(String)  // reason
    case unsupportedShareFile
    case ovpnReferencedFile(String)  // path that is missing, unreadable or not embeddable
    case ovpnNotAllowed([String])  // sanitizer violations, e.g. "line 3: up (not allowed)"
    // connecting
    case missingPassword(String)  // profile id: no password in the Keychain
    case missingTOTPSecret(String)  // profile id: no TOTP secret in the Keychain
    case missingCredential(CredentialField)  // `.ask` value not supplied by the caller
    case missingConfig(String)  // profile id: OpenVPN profile without config.ovpn
    case missingHost(String)  // profile id: FortiGate profile without a host
    case usernameTooLong(maxBytes: Int)  // FortiGate user name longer than openfortivpn keeps
    case helperFailed(String)  // the helper refused the request
    case authFailed(String)  // log tail
    case connectFailed(String)  // the VPN tool exited; log tail
    case toolUnsupported(reason: String, log: String)  // dyld stopped the VPN tool ("Symbol not found: _x"); log tail
    case serverUnreachable(server: String, reason: String, log: String)  // no answer, refused, no route: nothing sent; log tail
    case hostNotFound(server: String, log: String)  // the server's name did not resolve; log tail
    case connectTimeout(Int)  // seconds
    case connectCancelled
    case otherVPNActive(String)  // interface of the VPN that already takes all traffic
    case setupFailed(reason: String, log: String)  // DNS hook or all-traffic routes failed; log tail
    // Cisco AnyConnect
    case anyConnectRequiresMacOS(String)  // the macOS openconnect needs ("15.4"): refused before anything runs
    case anyConnectToolUnavailable(String)  // Linux: the distribution's openconnect is missing, untrusted or older than 9.01; why
    // Palo Alto GlobalProtect
    case globalProtectRequiresMacOS(String)  // the macOS openconnect needs ("15.4"): refused before anything runs
    /// The portal or the gateway asked for single sign-on (SAML), which PassTunnel does not support; log tail. Whether
    /// anything was sent is the failure's `credentialsSent` (at the portal nothing was; at a gateway behind it, the
    /// portal's sign-in was).
    case ssoRequired(log: String)
    /// openconnect did not trust the key of the gateway the portal sent the sign-in to: the gateway (`host:port`, IPv6 in
    /// brackets, as the redacted log names it), openconnect's reason, and the pin of the key it saw when it printed one;
    /// log tail. The portal's sign-in was sent by then.
    case gatewayCertificateRejected(gateway: String, reason: String, pin: String?, log: String)
    case hostScanRequired(log: String)  // the server asked for a CSD host scan, which PassTunnel never runs; log tail
    /// openconnect did not trust the server's certificate (or key): its reason, and the pin of the key it saw
    /// (`pin-sha256:…`, openconnect's own hint) when it printed one; log tail. Nothing was sent.
    case serverCertificateRejected(reason: String, pin: String?, log: String)
    case signInNeedsMoreAnswers(log: String)  // the server asked for more than the password and the code; log tail
    case signInUnusable(String)  // the sign-in succeeded but cannot be used (another server, malformed output); fixed text
    // confirming the user (Touch ID / password) before stored secrets are used
    case userConfirmationCancelled
    case userConfirmationFailed(String)  // localized reason
    case confirmationRequired  // protected secrets, but asking is not possible now (automatic reconnect)
    case protectionUnavailable  // no Secure Enclave (Linux: no confirmation yet): the protection cannot be used
    case protectedSecretUnreadable(SecretKind)  // encrypted item that cannot be decrypted (key lost or data damaged)

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
        case .unsupportedProfileType(let type):
            return String(
                localized:
                    "This profile uses the VPN type “\(type)”, which needs a newer PassTunnel. Update PassTunnel to use it. It can still be deleted."
            )
        case .fileError(let detail):
            return String(localized: "A file operation failed: \(detail)")
        case .fileTooLarge(let name):
            return String(localized: "The file “\(name)” is too large.")
        case .invalidFile(let name):
            return String(localized: "The file “\(name)” could not be read or is damaged.")
        case .keychain(let status):
            #if canImport(Security)
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            #else
            let message = "OSStatus \(status)"
            #endif
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
        case .ovpnReferencedFile(let path):
            return String(
                localized:
                    "The OpenVPN configuration refers to “\(path)”, which is missing or cannot be embedded. Keep the referenced files next to the .ovpn file."
            )
        case .ovpnNotAllowed(let violations):
            let list = violations.joined(separator: "\n")
            return String(localized: "The OpenVPN configuration contains settings PassTunnel does not allow for security reasons:\n\(list)")
        case .missingPassword:
            return String(localized: "No password is saved in the Keychain for this profile. Add it in the profile editor.")
        case .missingTOTPSecret:
            return String(localized: "No TOTP secret is saved in the Keychain for this profile. Add it in the profile editor.")
        case .missingCredential(let field):
            switch field {
            case .username: return String(localized: "A user name is required to connect.")
            case .password: return String(localized: "A password is required to connect.")
            case .otp: return String(localized: "A one-time code is required to connect.")
            }
        case .missingConfig:
            return String(localized: "This profile has no OpenVPN configuration file. Choose one in the profile editor.")
        case .missingHost:
            return String(localized: "This profile has no server address. Enter one in the profile editor.")
        case .usernameTooLong(let maxBytes):
            return String(localized: "The user name is too long for FortiGate: at most \(maxBytes) bytes (characters such as ş or é count as 2).")
        case .helperFailed(let reason):
            return String(localized: "The PassTunnel helper could not start the connection: \(reason)")
        case .authFailed:
            return String(localized: "The server rejected the sign-in. Check the user name, password and one-time code.")
        case .connectFailed:
            return String(localized: "The VPN connection could not be established. See the log for details.")
        case .toolUnsupported(let reason, _):
            return String(
                localized: "This VPN tool does not run on this version of macOS (\(reason)). Check for a PassTunnel update.")
        case let .serverUnreachable(server, reason, _):
            if server.isEmpty { return String(localized: "The server could not be reached: \(reason). Your sign-in was not sent.") }
            return String(localized: "The server \(server) could not be reached: \(reason). Your sign-in was not sent.")
        case let .hostNotFound(server, _):
            if server.isEmpty {
                return String(localized: "The server’s name could not be found. Check the server address and the network connection.")
            }
            return String(localized: "The server name \(server) could not be found. Check the server address and the network connection.")
        case .connectTimeout(let seconds):
            return String(localized: "The VPN did not connect within \(seconds) seconds.")
        case .connectCancelled:
            return String(localized: "The connection attempt was cancelled.")
        case .otherVPNActive(let interface):
            return String(localized: "Another VPN is already routing all traffic (\(interface)). Disconnect it first.")
        case .setupFailed(let reason, _):
            return String(localized: "The tunnel came up, but setting up the network failed, so it was disconnected: \(reason)")
        case .anyConnectRequiresMacOS(let version):
            return String(localized: "Cisco AnyConnect requires macOS \(version) or later.")
        case .anyConnectToolUnavailable(let reason):
            return String(localized: "Cisco AnyConnect cannot be used here: \(reason)")
        case .globalProtectRequiresMacOS(let version):
            return String(localized: "Palo Alto GlobalProtect requires macOS \(version) or later.")
        case .ssoRequired:
            return String(localized: "This server signs in with single sign-on (SAML), which PassTunnel does not support.")
        case .gatewayCertificateRejected(_, let reason, _, _):
            return String(localized: "The gateway’s certificate was not trusted (\(reason)).")
        case .hostScanRequired:
            return String(
                localized:
                    "The server requires a host scan (Cisco Secure Desktop), which PassTunnel does not run. Your sign-in was not sent.")
        case .serverCertificateRejected(let reason, _, _):
            return String(localized: "The server’s certificate was not trusted (\(reason)). Your sign-in was not sent.")
        case .signInNeedsMoreAnswers:
            return String(
                localized:
                    "The server asked for more than the password and the one-time code. Check how the profile sends the code.")
        case .signInUnusable(let reason):
            return String(localized: "The sign-in cannot be used: \(reason)")
        case .userConfirmationCancelled:
            return String(localized: "Cancelled.")
        case .userConfirmationFailed(let reason):
            return String(localized: "PassTunnel could not confirm it’s you: \(reason)")
        case .confirmationRequired:
            return String(localized: "Reconnecting needs your confirmation (Touch ID or your Mac password): connect it again yourself.")
        case .protectionUnavailable:
            #if os(Linux)
            return String(
                localized:
                    "PassTunnel cannot ask for a confirmation on this system yet, so it does not use profiles set to ask for one (require_auth).")
            #else
            return String(localized: "This Mac has no Secure Enclave, so the saved secrets cannot be protected with Touch ID or your Mac password.")
            #endif
        case .protectedSecretUnreadable(let kind):
            switch kind {
            case .password:
                return String(
                    localized:
                        "The saved password cannot be decrypted: its key is from another Mac, or the item was damaged. Enter the password again in the profile editor."
                )
            case .totp:
                return String(
                    localized:
                        "The saved TOTP secret cannot be decrypted: its key is from another Mac, or the item was damaged. Add the secret again in the profile editor."
                )
            }
        }
    }
}

extension PTError {
    /// Log excerpt attached to connection failures (empty for other errors).
    public var logTail: String {
        switch self {
        case .authFailed(let tail), .connectFailed(let tail), .setupFailed(_, let tail), .serverUnreachable(_, _, let tail),
            .hostNotFound(_, let tail), .toolUnsupported(_, let tail), .hostScanRequired(let tail),
            .serverCertificateRejected(_, _, let tail), .signInNeedsMoreAnswers(let tail), .ssoRequired(let tail),
            .gatewayCertificateRejected(_, _, _, let tail):
            return tail
        default: return ""
        }
    }
}

extension PTError {
    /// The short note a list shows beside a profile of a type this system cannot connect (the full sentence is
    /// the error's description): "Requires macOS 15.4 or later", or for a type this version does not connect yet
    /// "Needs a newer PassTunnel". Nil for any other error (Linux refuses no type up front for its macOS: the
    /// distribution's openconnect is checked when connecting).
    public var unavailableNote: String? {
        switch self {
        case .anyConnectRequiresMacOS(let version), .globalProtectRequiresMacOS(let version):
            return String(localized: "Requires macOS \(version) or later")
        case .unsupportedProfileType: return UnsupportedProfile.statusText
        default: return nil
        }
    }
}
