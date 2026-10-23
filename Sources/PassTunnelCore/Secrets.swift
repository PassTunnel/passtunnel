import Foundation
import PassTunnelKit
import PassTunnelShared
import Security

/// Generic-password Keychain items: service `PT.keychainService` (or `$PASSTUNNEL_KEYCHAIN_SERVICE`),
/// account "<profileID>/<kind>". Values are stored as UTF-8: plain text, or a `SecretEnvelope` for
/// profiles with "Confirm with Touch ID" (read those through `SecretVault`).
public enum Secrets {
    static func account(_ profileID: String, _ kind: SecretKind) -> String { "\(profileID)/\(kind.rawValue)" }
    /// The profile's protection key record (`ProtectionKeyRecord`): a Secure Enclave–wrapped private
    /// key and its public key. Not a `SecretKind`: it is never read or written as a secret value.
    static func keyAccount(_ profileID: String) -> String { "\(profileID)/sekey" }

    private static func baseQuery(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Env.keychainService,
            kSecAttrAccount as String: account,
        ]
    }

    // MARK: values

    /// The secret in plain text; nil when there is none or when it is stored encrypted
    /// (`isProtected`; `SecretVault` decrypts those).
    public static func get(_ profileID: String, _ kind: SecretKind) -> String? {
        guard let raw = raw(profileID, kind), !SecretEnvelope.isEnvelope(raw) else { return nil }
        return SecretEnvelope.decodePlain(raw)
    }

    /// Whether an item exists, plain or encrypted.
    public static func has(_ profileID: String, _ kind: SecretKind) -> Bool {
        raw(profileID, kind) != nil
    }

    /// The item is stored encrypted to the profile's protection key.
    public static func isProtected(_ profileID: String, _ kind: SecretKind) -> Bool {
        raw(profileID, kind).map(SecretEnvelope.isEnvelope) ?? false
    }

    /// Stores `value` in plain text (escaped if it could be mistaken for an envelope).
    public static func set(_ profileID: String, _ kind: SecretKind, _ value: String) throws {
        try setRaw(profileID, kind, SecretEnvelope.encodePlain(value))
    }

    public static func delete(_ profileID: String, _ kind: SecretKind) {
        try? remove(account(profileID, kind))
    }

    /// Removes every item of the profile (secrets and protection key). Used before a new profile takes
    /// an id, so it never inherits items left behind by a profile removed outside the app (or after
    /// a reinstall). Throws when an item cannot be removed.
    static func deleteAll(_ profileID: String) throws {
        for kind in SecretKind.allCases { try remove(account(profileID, kind)) }
        try remove(keyAccount(profileID))
    }

    /// The stored text as is: plain (possibly escaped) or an envelope.
    static func raw(_ profileID: String, _ kind: SecretKind) -> String? {
        read(account(profileID, kind))
    }

    static func setRaw(_ profileID: String, _ kind: SecretKind, _ text: String) throws {
        try write(account(profileID, kind), text)
    }

    // MARK: protection key

    static func protectionKey(_ profileID: String) -> String? { read(keyAccount(profileID)) }

    static func setProtectionKey(_ profileID: String, _ text: String) throws { try write(keyAccount(profileID), text) }

    public static func deleteProtectionKey(_ profileID: String) {
        try? remove(keyAccount(profileID))
    }

    // MARK: items

    private static func read(_ account: String) -> String? {
        readData(account).flatMap { String(data: $0, encoding: .utf8) }
    }

    private static func readData(_ account: String) -> Data? {
        var q = baseQuery(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    /// Always delete, then add: an item that already exists may have been created by another app
    /// (with an access list that lets it read the value), and updating it in place would put the
    /// secret there. The added item gets the default access list, which trusts only PassTunnel. When
    /// the old item cannot be removed, nothing is written. When the new item cannot be added, the
    /// previous value (read before the delete) is added back the same way, so a transient failure
    /// does not lose it.
    private static func write(_ account: String, _ value: String) throws {
        var previous = readData(account)
        defer { _ = previous?.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        try remove(account)
        let status = add(account, Data(value.utf8))
        guard status == errSecSuccess else {
            if let previous { _ = add(account, previous) }
            throw PTError.keychain(status)
        }
    }

    /// Adds a new item (never updates one).
    private static func add(_ account: String, _ data: Data) -> OSStatus {
        var add = baseQuery(account)
        add[kSecValueData as String] = data
        add[kSecAttrLabel as String] = "PassTunnel (\(account))"
        // Only the data-protection keychain honors this; the file-based login keychain used here
        // ignores it (its items never sync, but can be copied with the keychain file). Kept for a move
        // to the data-protection keychain.
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        #if DEBUG
        if let addOverride { return addOverride(add as CFDictionary) }
        #endif
        return SecItemAdd(add as CFDictionary, nil)
    }

    #if DEBUG
    /// Tests: replaces SecItemAdd (to make an add fail).
    static var addOverride: ((CFDictionary) -> OSStatus)?
    #endif

    /// Deletes every item for `account` (legacy keychains may delete one match per call).
    private static func remove(_ account: String) throws {
        for _ in 0..<maxDeletes {
            let status = SecItemDelete(baseQuery(account) as CFDictionary)
            if status == errSecItemNotFound { return }
            guard status == errSecSuccess else { throw KeychainItemNotReplaced(account: account, status: status) }
        }
        throw KeychainItemNotReplaced(account: account, status: errSecDuplicateItem)
    }

    private static let maxDeletes = 16

    /// Test cleanup: removes every item of the current (overridden) service.
    /// Refuses to touch the production service.
    static func deleteAllInOverriddenService() {
        let service = Env.keychainService
        guard service != PT.keychainService else { return }
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        // Legacy keychains may delete one match per call.
        for _ in 0..<100 where SecItemDelete(q as CFDictionary) == errSecSuccess {}
    }
}

/// An existing Keychain item could not be removed before a new value was written (or before a new
/// profile took its id), so nothing was written to it.
public struct KeychainItemNotReplaced: Error, Equatable, LocalizedError {
    public var account: String
    public var status: OSStatus

    public var errorDescription: String? {
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        return String(localized: "The Keychain item “PassTunnel (\(account))” could not be replaced (\(message)), so nothing was saved. Delete it in Keychain Access, then try again.")
    }
}
