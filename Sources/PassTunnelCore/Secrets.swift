import Foundation
import PassTunnelShared
import Security

public enum SecretKind: String, CaseIterable { case password, totp }

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
        SecItemDelete(baseQuery(account(profileID, kind)) as CFDictionary)
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
        SecItemDelete(baseQuery(keyAccount(profileID)) as CFDictionary)
    }

    // MARK: items

    private static func read(_ account: String) -> String? {
        var q = baseQuery(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func write(_ account: String, _ value: String) throws {
        let data = Data(value.utf8)
        let q = baseQuery(account)
        let status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw PTError.keychain(status) }

        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrLabel as String] = "PassTunnel (\(account))"
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw PTError.keychain(addStatus) }
    }

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
