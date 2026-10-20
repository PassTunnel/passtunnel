import Foundation
import PassTunnelShared
import Security

public enum SecretKind: String, CaseIterable { case password, totp }

/// Generic-password Keychain items: service `PT.keychainService` (or `$PASSTUNNEL_KEYCHAIN_SERVICE`),
/// account "<profileID>/<kind>". Values are stored as UTF-8.
public enum Secrets {
    static func account(_ profileID: String, _ kind: SecretKind) -> String { "\(profileID)/\(kind.rawValue)" }

    private static func baseQuery(_ profileID: String, _ kind: SecretKind) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Env.keychainService,
            kSecAttrAccount as String: account(profileID, kind),
        ]
    }

    public static func get(_ profileID: String, _ kind: SecretKind) -> String? {
        var q = baseQuery(profileID, kind)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public static func has(_ profileID: String, _ kind: SecretKind) -> Bool {
        get(profileID, kind) != nil
    }

    public static func set(_ profileID: String, _ kind: SecretKind, _ value: String) throws {
        let data = Data(value.utf8)
        let q = baseQuery(profileID, kind)
        let status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw PTError.keychain(status) }

        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrLabel as String] = "PassTunnel (\(account(profileID, kind)))"
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw PTError.keychain(addStatus) }
    }

    public static func delete(_ profileID: String, _ kind: SecretKind) {
        SecItemDelete(baseQuery(profileID, kind) as CFDictionary)
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
