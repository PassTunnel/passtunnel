import Foundation
import PassTunnelKit
import PassTunnelShared
#if canImport(Security)
import Security
#endif

/// Secret items: service `PT.keychainService` (or `$PASSTUNNEL_KEYCHAIN_SERVICE`), account
/// "<profileID>/<kind>", in the `SecretStore` of this platform (`Secrets.store`). Values are stored as
/// UTF-8: plain text, or a `SecretEnvelope` for profiles with "Confirm with Touch ID" (read those
/// through `SecretVault`).
public enum Secrets {
    static func account(_ profileID: String, _ kind: SecretKind) -> String { "\(profileID)/\(kind.rawValue)" }
    /// The profile's protection key record (`ProtectionKeyRecord`): a Secure Enclave–wrapped private
    /// key and its public key. Not a `SecretKind`: it is never read or written as a secret value.
    static func keyAccount(_ profileID: String) -> String { "\(profileID)/sekey" }

    /// Where the items are, chosen on every call: the Keychain on the Mac; on Linux the store
    /// `SecretStores` chooses (secret-service, systemd-creds or file). Debug builds only (tests): the
    /// in-memory store with `PASSTUNNEL_SECRET_STORE=memory`. A release build has no in-memory store
    /// (Linux refuses the value as an unknown store, the Mac ignores it), so a stray variable can never
    /// make `secret` report a password saved that is gone when the process ends.
    static var store: SecretStore {
        let service = Env.keychainService
        #if DEBUG
        if Env.secretStore == MemorySecretStore.name { return MemorySecretStore(service: service) }
        #endif
        #if canImport(Security)
        return KeychainSecretStore(service: service)
        #else
        return SecretStores.chosen(system: .current(service: service))
        #endif
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

    /// `has`, but a store that cannot be read throws instead of answering no (`SecretStoreUnavailable`).
    static func exists(_ profileID: String, _ kind: SecretKind) throws -> Bool {
        try read(account(profileID, kind)) != nil
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
        try? store.remove(account(profileID, kind))
    }

    /// Removes every item of the profile (secrets and protection key). Used before a new profile takes
    /// an id, so it never inherits items left behind by a profile removed outside the app (or after
    /// a reinstall). Throws when an item cannot be removed.
    static func deleteAll(_ profileID: String) throws {
        let store = self.store
        for kind in SecretKind.allCases { try store.remove(account(profileID, kind)) }
        try store.remove(keyAccount(profileID))
    }

    /// The stored text as is: plain (possibly escaped) or an envelope.
    static func raw(_ profileID: String, _ kind: SecretKind) -> String? {
        try? read(account(profileID, kind))
    }

    static func setRaw(_ profileID: String, _ kind: SecretKind, _ text: String) throws {
        try store.write(account(profileID, kind), Data(text.utf8))
    }

    // MARK: protection key

    static func protectionKey(_ profileID: String) -> String? { try? read(keyAccount(profileID)) }

    static func setProtectionKey(_ profileID: String, _ text: String) throws {
        try store.write(keyAccount(profileID), Data(text.utf8))
    }

    public static func deleteProtectionKey(_ profileID: String) {
        try? store.remove(keyAccount(profileID))
    }

    // MARK: items

    private static func read(_ account: String) throws -> String? {
        try store.read(account).flatMap { String(data: $0, encoding: .utf8) }
    }

    #if DEBUG && canImport(Security)
    /// Tests: replaces SecItemAdd in the Keychain store (to make an add fail).
    static var addOverride: ((CFDictionary) -> OSStatus)?
    #endif

    /// Test cleanup: removes every item of the current (overridden) service.
    /// Refuses to touch the production service.
    static func deleteAllInOverriddenService() {
        guard Env.keychainService != PT.keychainService else { return }
        store.removeAll()
    }
}

// MARK: - Stores

/// Where secret items live: raw values by account under one service. `Secrets` is the API; a store
/// only reads, writes and removes items, so each platform's storage brings its own rules for them.
protocol SecretStore {
    /// The item's bytes; nil when there is none. Throws when the store cannot be read at all.
    func read(_ account: String) throws -> Data?
    /// Stores `data` as the item, replacing any existing one. Throws when it was not stored.
    func write(_ account: String, _ data: Data) throws
    /// Removes the item; nothing to do when there is none. Throws when it exists and stays.
    func remove(_ account: String) throws
    /// Removes every item of the service (test cleanup).
    func removeAll()
}

#if DEBUG
/// Items kept in this process only, never written anywhere: tests on every platform
/// (`PASSTUNNEL_SECRET_STORE=memory`). Debug builds only, so no shipped binary can select it. Values
/// are overwritten before they are dropped (best effort).
struct MemorySecretStore: SecretStore {
    static let name = "memory"
    let service: String

    private static let lock = NSLock()
    /// service → account → value
    private static var items: [String: [String: Data]] = [:]

    private func locked<T>(_ body: (inout [String: Data]) -> T) -> T {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        return body(&Self.items[service, default: [:]])
    }

    func read(_ account: String) -> Data? {
        locked { $0[account] }
    }

    func write(_ account: String, _ data: Data) {
        locked { items in
            Self.wipe(&items[account])
            items[account] = data
        }
    }

    func remove(_ account: String) {
        locked { items in
            Self.wipe(&items[account])
            items[account] = nil
        }
    }

    func removeAll() {
        locked { items in
            for account in Array(items.keys) { Self.wipe(&items[account]) }
            items.removeAll()
        }
    }

    private static func wipe(_ data: inout Data?) {
        _ = data?.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
    }
}
#endif

/// The secret store cannot be used (on Linux: a tool missing or failing, no session bus, a locked
/// keyring that did not answer, no passphrase, a file that does not decrypt); `message` says which.
/// `keychain_error`, like a failing Keychain.
public struct SecretStoreUnavailable: Error, Equatable, LocalizedError {
    public var message: String

    public init(_ message: String) {
        self.message = message
    }

    public var errorDescription: String? { message }
}

#if canImport(Security)
/// Generic-password items in the login keychain. Values are written by deleting the item, then adding
/// it (never `SecItemUpdate`), with the previous value put back when the add fails.
struct KeychainSecretStore: SecretStore {
    let service: String

    private func baseQuery(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    /// Nil also when the item cannot be read.
    func read(_ account: String) -> Data? {
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
    func write(_ account: String, _ data: Data) throws {
        var previous = read(account)
        defer { _ = previous?.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        try remove(account)
        let status = add(account, data)
        guard status == errSecSuccess else {
            if let previous { _ = add(account, previous) }
            throw PTError.keychain(status)
        }
    }

    /// Adds a new item (never updates one).
    private func add(_ account: String, _ data: Data) -> OSStatus {
        var add = baseQuery(account)
        add[kSecValueData as String] = data
        add[kSecAttrLabel as String] = "PassTunnel (\(account))"
        // Only the data-protection keychain honors this; the file-based login keychain used here
        // ignores it (its items never sync, but can be copied with the keychain file). Kept for a move
        // to the data-protection keychain.
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        #if DEBUG
        if let override = Secrets.addOverride { return override(add as CFDictionary) }
        #endif
        return SecItemAdd(add as CFDictionary, nil)
    }

    /// Deletes every item for `account` (legacy keychains may delete one match per call).
    func remove(_ account: String) throws {
        for _ in 0..<Self.maxDeletes {
            let status = SecItemDelete(baseQuery(account) as CFDictionary)
            if status == errSecItemNotFound { return }
            guard status == errSecSuccess else { throw KeychainItemNotReplaced(account: account, status: status) }
        }
        throw KeychainItemNotReplaced(account: account, status: errSecDuplicateItem)
    }

    private static let maxDeletes = 16

    func removeAll() {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        // Legacy keychains may delete one match per call.
        for _ in 0..<100 where SecItemDelete(q as CFDictionary) == errSecSuccess {}
    }
}
#endif

/// An existing Keychain item could not be removed before a new value was written (or before a new
/// profile took its id), so nothing was written to it.
public struct KeychainItemNotReplaced: Error, Equatable, LocalizedError {
    public var account: String
    public var status: Int32                // OSStatus

    public var errorDescription: String? {
        #if canImport(Security)
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        #else
        let message = "OSStatus \(status)"
        #endif
        return String(localized: "The Keychain item “PassTunnel (\(account))” could not be replaced (\(message)), so nothing was saved. Delete it in Keychain Access, then try again.")
    }
}
