import CryptoKit
import Foundation
import LocalAuthentication
import PassTunnelKit
import Security

/// A profile's protection key as created: the private key's opaque data (for the Secure Enclave, its
/// wrapped blob) and the public key secrets are encrypted to.
public struct ProtectionKey {
    public var data: Data
    public var publicKey: P256.KeyAgreement.PublicKey

    public init(data: Data, publicKey: P256.KeyAgreement.PublicKey) {
        self.data = data
        self.publicKey = publicKey
    }
}

/// A protection key the user has unlocked (confirmed) for a series of key agreements.
public protocol UnlockedProtectionKey: AnyObject {
    /// The public key of the private key that was unlocked (checked against the stored record).
    var publicKey: P256.KeyAgreement.PublicKey { get }
    func sharedSecret(with peer: P256.KeyAgreement.PublicKey) async throws -> SharedSecret
}

/// The key data could not be used (e.g. a Secure Enclave key from another Mac).
public struct ProtectionKeyUnusable: Error {
    public init() {}
}

/// Owns the private half of the protection keys and asks the person at the Mac before using it:
/// Touch ID, with the login password (or an Apple Watch) as the fallback. Decrypting a protected
/// secret *is* the confirmation. `SecureEnclaveAuthenticator` in the app and the CLI; a software
/// P-256 key in tests.
public protocol UserAuthenticator: AnyObject {
    /// False when keys cannot be created (no Secure Enclave, e.g. in a virtual machine).
    var isAvailable: Bool { get }
    /// A new key-agreement key whose private half can only be used after the user confirms.
    /// Creating it asks nothing. Throws `PTError.protectionUnavailable` when that is not possible.
    func createKey() throws -> ProtectionKey
    /// The public key of stored key data, without asking (using the key is what asks). Throws
    /// `ProtectionKeyUnusable` when the data is not a key this Mac can use.
    func publicKey(keyData: Data) throws -> P256.KeyAgreement.PublicKey
    /// Asks the user ("PassTunnel is trying to `reason`") and returns the key ready for use.
    /// Throws `PTError.userConfirmationCancelled` / `.userConfirmationFailed`, or
    /// `ProtectionKeyUnusable` when the key data cannot be used.
    func unlock(keyData: Data, reason: String) async throws -> UnlockedProtectionKey
}

/// CryptoKit Secure Enclave P-256 key-agreement keys with the access control
/// `[.privateKeyUsage, .userPresence]`: Touch ID or the login password (an Apple Watch where set up),
/// so adding or removing a fingerprint never makes the key unusable. The private key never leaves
/// the Secure Enclave; what is stored (`dataRepresentation`) is a blob only this Mac's Secure Enclave
/// can use. No Keychain access group, entitlement or provisioning profile is involved.
public final class SecureEnclaveAuthenticator: UserAuthenticator {
    public init() {}

    public var isAvailable: Bool { SecureEnclave.isAvailable }

    private static func accessControl() -> SecAccessControl? {
        SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                        [.privateKeyUsage, .userPresence], nil)
    }

    public func createKey() throws -> ProtectionKey {
        guard isAvailable, let access = Self.accessControl(),
              let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: false, accessControl: access) else {
            throw PTError.protectionUnavailable
        }
        return ProtectionKey(data: key.dataRepresentation, publicKey: key.publicKey)
    }

    /// Loading the wrapped blob needs no confirmation; only key agreements do.
    public func publicKey(keyData: Data) throws -> P256.KeyAgreement.PublicKey {
        guard isAvailable, let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData) else {
            throw ProtectionKeyUnusable()
        }
        return key.publicKey
    }

    /// One `LAContext` is confirmed first (`evaluateAccessControl` for a key exchange with the key's own
    /// access control), then handed to the key, so all key agreements of this unlock share one prompt.
    /// `touchIDAuthenticationAllowableReuseDuration` stays 0: it would accept a recent Touch ID unlock of
    /// the Mac instead of a prompt, which is what this protects against. Repeats within the reuse window
    /// are served from `SecretVault`'s memory instead.
    public func unlock(keyData: Data, reason: String) async throws -> UnlockedProtectionKey {
        guard let access = Self.accessControl() else { throw PTError.protectionUnavailable }
        let context = LAContext()
        context.localizedReason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0
        do {
            guard try await context.evaluateAccessControl(access, operation: .useKeyKeyExchange, localizedReason: reason) else {
                throw PTError.userConfirmationFailed(String(localized: "the confirmation failed."))
            }
        } catch {
            throw Self.map(error)
        }
        guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData,
                                                                         authenticationContext: context) else {
            throw ProtectionKeyUnusable()
        }
        return Unlocked(key: key)
    }

    private final class Unlocked: UnlockedProtectionKey {
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        init(key: SecureEnclave.P256.KeyAgreement.PrivateKey) { self.key = key }

        var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }

        func sharedSecret(with peer: P256.KeyAgreement.PublicKey) async throws -> SharedSecret {
            let key = self.key
            // Off the main thread: the Secure Enclave call blocks (and would show UI if it had to ask).
            return try await Task.detached(priority: .userInitiated) {
                do { return try key.sharedSecretFromKeyAgreement(with: peer) } catch {
                    if (error as NSError).domain == LAError.errorDomain { throw SecureEnclaveAuthenticator.map(error) }
                    throw ProtectionKeyUnusable()
                }
            }.value
        }
    }

    /// LocalAuthentication errors → `PTError`. Only the user's own cancel is a silent cancel; a
    /// system cancel (e.g. no window server, as over SSH) is reported like any other failure.
    static func map(_ error: Error?) -> Error {
        if let error, error is PTError || error is ProtectionKeyUnusable { return error }
        guard let error else { return PTError.userConfirmationFailed(String(localized: "the confirmation failed.")) }
        let ns = error as NSError
        guard ns.domain == LAError.errorDomain, let code = LAError.Code(rawValue: ns.code) else {
            return PTError.userConfirmationFailed(error.localizedDescription)
        }
        switch code {
        case .userCancel, .appCancel, .userFallback:
            return PTError.userConfirmationCancelled
        case .notInteractive, .systemCancel:
            return PTError.userConfirmationFailed(String(localized: "the confirmation cannot be shown in this session (for example over SSH). Use PassTunnel on the Mac itself."))
        case .biometryLockout:
            return PTError.userConfirmationFailed(String(localized: "Touch ID is locked after too many attempts. Unlock it with your Mac password, then try again."))
        case .passcodeNotSet:
            return PTError.userConfirmationFailed(String(localized: "this Mac user has no login password."))
        case .authenticationFailed:
            return PTError.userConfirmationFailed(String(localized: "the confirmation failed."))
        default:
            return PTError.userConfirmationFailed(error.localizedDescription)
        }
    }
}

/// How the setting is named: "Confirm with Touch ID", or "Confirm with your password" on a Mac without
/// Touch ID (no built-in sensor and no Touch ID keyboard; the confirmation is then the login password).
public enum ConfirmationWording {
    /// `LAContext.biometryType` is set by `canEvaluatePolicy`, whatever it returns.
    public static let hasTouchID: Bool = {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType != .none
    }()

    public static var settingName: String {
        hasTouchID ? String(localized: "Confirm with Touch ID") : String(localized: "Confirm with your password")
    }
}

/// What a confirmation is for; chooses the sentence in the system prompt.
public enum UserPresenceAction: String, CaseIterable, Sendable {
    /// Connecting (main window, menu bar, shortcut, notification, CLI `connect`/`toggle`).
    case connect
    /// Showing, copying or typing the live code (or password + code); CLI `code`.
    case code
    /// Lowering `requireAuth` (editor or `passtunnel set`).
    case lowerProtection

    /// The end of the system prompt's sentence "PassTunnel is trying to …". `host`: the server a
    /// connect sends the secrets to (from the profile as it is when the prompt is shown).
    public func reason(_ name: String, host: String = "") -> String {
        switch self {
        case .connect:
            let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
            if host.isEmpty { return String(localized: "connect to “\(name)”") }
            return String(localized: "connect to “\(name)” (\(host))")
        case .code: return String(localized: "show the code for “\(name)”")
        case .lowerProtection: return String(localized: "change the confirmation setting for “\(name)”")
        }
    }
}
