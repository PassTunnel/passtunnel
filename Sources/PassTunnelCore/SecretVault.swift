import CryptoKit
import Foundation
import PassTunnelKit
#if canImport(AppKit)
import AppKit
#endif

/// Profile secrets protected by "Confirm with Touch ID" (`Profile.requireAuth`).
///
/// Protected secrets are stored encrypted (`SecretEnvelope`) to a per-profile protection key whose
/// private half is in the Secure Enclave and usable only after the user confirms (Touch ID or the login
/// password). Decrypting is the confirmation: there is no separate yes/no check to bypass.
///
/// - `connect`: the saved password is encrypted; the TOTP secret stays readable so live codes need no
///   prompt. Without a saved password, the TOTP secret is encrypted instead (otherwise the setting
///   would protect nothing), and its code is hidden until confirmed, as with `always`.
/// - `always`: both are encrypted.
///
/// Decrypted values are kept in memory for the reuse window (`Preferences.authReuseMinutes`) per
/// profile, so a credential sheet or an immediate retry does not ask twice; sleep and screen lock end
/// that early. Each decrypted value remembers the destination (`ProfileDestination`) the profile had
/// when the user confirmed; `forgetUnlessBound` drops it once the server settings change. Writing a
/// secret to a protected profile only needs the public key: no prompt.
@MainActor
public final class SecretVault: ObservableObject {
    private struct Entry {
        var bytes: [UInt8]
        var at: Date
        var destination: String        // `ProfileDestination.fingerprint` when the user confirmed
    }

    private let authenticator: UserAuthenticator
    private let now: () -> Date
    private let reuseWindow: () -> TimeInterval
    private let destination: (Profile) -> ProfileDestination
    /// Decrypted values; not `@Published` itself so `forget` can overwrite the bytes in place.
    private var cache: [String: [SecretKind: Entry]] = [:]
    /// Bumped whenever `cache` changes, for views showing whether codes are unlocked.
    @Published private var revision = 0
    private var inFlight: [String: Task<Void, Error>] = [:]

    /// `reuseWindow` is read on every check, so a changed preference applies at once. `destination`
    /// reads where a profile sends its secrets (shown in the prompt and bound to what is decrypted).
    public init(authenticator: UserAuthenticator = SecureEnclaveAuthenticator(),
                now: @escaping () -> Date = Date.init,
                reuseWindow: @escaping () -> TimeInterval = { Preferences.load().authReuseInterval },
                destination: @escaping (Profile) -> ProfileDestination = { ProfileDestination.of($0, store: ProfileStore()) }) {
        self.authenticator = authenticator
        self.now = now
        self.reuseWindow = reuseWindow
        self.destination = destination
    }

    /// The protection can be turned on (this Mac has a Secure Enclave).
    public var isAvailable: Bool { authenticator.isAvailable }

    // MARK: policy

    /// The secrets the profile's setting encrypts.
    public nonisolated static func protectedKinds(_ p: Profile) -> Set<SecretKind> {
        switch p.requireAuth {
        case .off: return []
        case .connect: return p.passwordMode == .keychain ? [.password] : [.totp]
        case .always: return [.password, .totp]
        }
    }

    /// The stored secrets connecting uses.
    public nonisolated static func usedKinds(_ p: Profile) -> Set<SecretKind> {
        var kinds: Set<SecretKind> = []
        if p.passwordMode == .keychain { kinds.insert(.password) }
        if p.otpMode == .totp { kinds.insert(.totp) }
        return kinds
    }

    public nonisolated static func kinds(for action: UserPresenceAction, _ p: Profile) -> Set<SecretKind> {
        switch action {
        case .connect: return usedKinds(p)
        case .code: return [.totp]
        case .lowerProtection: return Set(SecretKind.allCases)
        }
    }

    /// True when changing the setting from `old` to `new` weakens it (always → connect, anything → off).
    public nonisolated static func lowersProtection(from old: AuthRequirement, to new: AuthRequirement) -> Bool {
        new < old
    }

    // MARK: state

    /// The decrypted `kind` of profile `id` is in memory and within the reuse window.
    public func isUnlocked(_ id: String, _ kind: SecretKind) -> Bool {
        guard let entry = cache[id]?[kind] else { return false }
        let age = now().timeIntervalSince(entry.at)
        return age >= 0 && age < reuseWindow()
    }

    /// Some decrypted value of profile `id` is in memory (whether or not still within the window).
    public func hasDecrypted(_ id: String) -> Bool { cache[id] != nil }

    /// Whether `kind` is stored encrypted.
    public func isProtected(_ id: String, _ kind: SecretKind) -> Bool { Secrets.isProtected(id, kind) }

    /// True when using `kinds` of `p` would ask the user now: one of them is stored encrypted and not
    /// unlocked. Reconciles the stored form with the setting first (`reconcile`).
    public func needsPrompt(_ p: Profile, _ kinds: Set<SecretKind>) -> Bool {
        reconcile(p)
        return kinds.contains { Secrets.isProtected(p.id, $0) && !isUnlocked(p.id, $0) }
    }

    public func needsPrompt(_ p: Profile, for action: UserPresenceAction) -> Bool {
        needsPrompt(p, Self.kinds(for: action, p))
    }

    /// Connecting `p` needs a confirmation (ignoring the reuse window): a secret it uses is encrypted.
    public func requiresConfirmation(_ p: Profile) -> Bool {
        Self.usedKinds(p).contains { Secrets.isProtected(p.id, $0) }
    }

    /// The secret without asking: the plain item, or the decrypted value while unlocked. Nil when
    /// there is none or it is locked.
    public func available(_ id: String, _ kind: SecretKind) -> String? {
        if let plain = Secrets.get(id, kind) { return plain }
        guard isUnlocked(id, kind), let entry = cache[id]?[kind] else { return nil }
        return String(decoding: entry.bytes, as: UTF8.self)
    }

    // MARK: reading

    /// The secret, decrypting (and asking) when needed. Nil when no item exists. Without `prompt`, a
    /// locked secret throws `PTError.confirmationRequired` instead of asking.
    public func secret(_ p: Profile, _ kind: SecretKind, for action: UserPresenceAction, prompt: Bool = true) async throws -> String? {
        reconcile(p)
        guard Secrets.has(p.id, kind) else { return nil }
        if let value = available(p.id, kind) { return value }
        guard prompt else { throw PTError.confirmationRequired }
        try await unlock(p, [kind], for: action)
        return available(p.id, kind)
    }

    /// Asks once and decrypts every encrypted secret of `p` into memory for the reuse window, unless
    /// `kinds` are all readable already. `fresh` asks even then (lowering the setting).
    /// Concurrent calls for the same profile share one prompt.
    public func unlock(_ p: Profile, _ kinds: Set<SecretKind>, for action: UserPresenceAction, fresh: Bool = false) async throws {
        if !fresh, let running = inFlight[p.id] { try await running.value }
        guard fresh || needsPrompt(p, kinds) else { return }
        let task = Task { @MainActor in try await self.decryptAll(p, action: action, requireKey: false) }
        inFlight[p.id] = task
        defer { if inFlight[p.id] == task { inFlight[p.id] = nil } }
        try await task.value
    }

    public func unlock(_ p: Profile, for action: UserPresenceAction) async throws {
        try await unlock(p, Self.kinds(for: action, p), for: action)
    }

    /// One prompt, then every encrypted item of `p` is decrypted into the cache. With no encrypted item
    /// and `requireKey`, the key is still used once (a confirmation with nothing to decrypt).
    private func decryptAll(_ p: Profile, action: UserPresenceAction, requireKey: Bool) async throws {
        prune()
        let id = p.id
        let encrypted = SecretKind.allCases.compactMap { kind in Secrets.raw(id, kind).flatMap { SecretEnvelope.isEnvelope($0) ? (kind, $0) : nil } }
        guard !encrypted.isEmpty || requireKey else { return }
        guard let record = Secrets.protectionKey(id).flatMap(ProtectionKeyRecord.decode), let recipient = record.publicKey else {
            if let first = encrypted.first { throw PTError.protectedSecretUnreadable(first.0) }
            return   // no key and nothing encrypted: nothing to protect
        }
        // The record names the key secrets were encrypted to; a key that is not the one it names
        // (record replaced or damaged) is never used: checked before asking when the key data can
        // be read without a confirmation, and again on the unlocked key.
        if let actual = try? authenticator.publicKey(keyData: record.key), actual.x963Representation != record.pub {
            throw ProtectionKeyMismatch(profileID: id)
        }
        // Read before the prompt: the server it names is the one the user confirms.
        let target = destination(p)
        let unlocked: UnlockedProtectionKey
        do {
            unlocked = try await authenticator.unlock(keyData: record.key, reason: action.reason(p.name, host: target.host))
        } catch is ProtectionKeyUnusable {
            throw discardUnusableKey(id, encrypted.map(\.0))
        }
        guard unlocked.publicKey.x963Representation == record.pub else { throw ProtectionKeyMismatch(profileID: id) }
        if encrypted.isEmpty {
            // Nothing to decrypt: use the key once so the confirmation is real.
            _ = try await sharedSecret(unlocked, P256.KeyAgreement.PrivateKey().publicKey, id: id, kinds: [])
            return
        }
        var values: [SecretKind: Entry] = cache[id] ?? [:]
        let at = now()
        for (kind, raw) in encrypted {
            guard let parsed = SecretEnvelope.parse(raw) else { throw PTError.protectedSecretUnreadable(kind) }
            let shared = try await sharedSecret(unlocked, parsed.ephemeral, id: id, kinds: encrypted.map(\.0))
            let text = try SecretEnvelope.open(parsed, shared: shared, recipient: recipient,
                                               account: Secrets.account(id, kind), kind: kind)
            values[kind] = Entry(bytes: Array(text.utf8), at: at, destination: target.fingerprint)
        }
        cache[id] = values
        revision += 1
    }

    private func sharedSecret(_ key: UnlockedProtectionKey, _ peer: P256.KeyAgreement.PublicKey, id: String,
                              kinds: [SecretKind]) async throws -> SharedSecret {
        do { return try await key.sharedSecret(with: peer) } catch is ProtectionKeyUnusable {
            throw discardUnusableKey(id, kinds)
        }
    }

    /// The key cannot be used on this Mac (Secure Enclave keys do not move to another Mac): the
    /// encrypted items can never be read again. They and the key record are removed, so the user can
    /// enter the secrets again (a new key is made then). Returns the error to report.
    private func discardUnusableKey(_ id: String, _ kinds: [SecretKind]) -> PTError {
        for kind in kinds { Secrets.delete(id, kind) }
        Secrets.deleteProtectionKey(id)
        reset(id)
        return .protectedSecretUnreadable(kinds.first ?? .password)
    }

    // MARK: writing

    /// Brings items in line with a setting that was changed outside the app and the CLI (e.g.
    /// `require_auth` edited in profile.json): a secret the setting protects but that is still plain is
    /// encrypted now (public key only, no prompt). The other way round, encrypted items of a profile set
    /// to `off` stay encrypted, so reading them asks, until the setting is lowered properly
    /// (`applyProtection`). Best effort: without a Secure Enclave nothing changes. Returns whether
    /// anything was encrypted.
    @discardableResult
    public func reconcile(_ p: Profile) -> Bool {
        guard p.requireAuth != .off else { return false }
        var changed = false
        for kind in Self.protectedKinds(p).sorted(by: { $0.rawValue < $1.rawValue }) {
            guard let raw = Secrets.raw(p.id, kind), !SecretEnvelope.isEnvelope(raw) else { continue }
            do { try store(p, kind, SecretEnvelope.decodePlain(raw)) } catch { return changed }
            changed = true
        }
        return changed
    }

    /// Stores a new secret: encrypted when the profile's setting protects `kind` (public key only, no
    /// prompt; the key is made if needed), otherwise in plain text.
    public func store(_ p: Profile, _ kind: SecretKind, _ value: String) throws {
        forget(p.id, kind)
        guard Self.protectedKinds(p).contains(kind) else { return try Secrets.set(p.id, kind, value) }
        let recipient = try ensureKey(p.id)
        try Secrets.setRaw(p.id, kind, try SecretEnvelope.seal(value, to: recipient, account: Secrets.account(p.id, kind)))
    }

    /// Brings the stored items of `new` in line with its setting after a change from `old` (nil: a new
    /// profile). Encrypting needs no prompt. Anything that leaves a secret it uses unencrypted
    /// (lowering the setting, or `connect` moving the protection from the TOTP secret to a newly
    /// saved password) needs a successful decrypt first, which is the confirmation; lowering the setting
    /// asks even when nothing is encrypted yet. Throws `PTError.protectionUnavailable` when the setting
    /// is turned on without a Secure Enclave, and leaves everything unchanged on a cancel.
    public func applyProtection(from old: Profile?, to new: Profile) async throws {
        let id = new.id
        let wanted = Self.protectedKinds(new)
        let used = Self.usedKinds(new)
        let lowering = Self.lowersProtection(from: old?.requireAuth ?? .off, to: new.requireAuth)
        if new.requireAuth != .off { _ = try ensureKey(id) }

        var toDecrypt: [SecretKind] = []
        var toEncrypt: [SecretKind] = []
        for kind in SecretKind.allCases {
            guard let raw = Secrets.raw(id, kind) else { continue }
            if SecretEnvelope.isEnvelope(raw) {
                if !wanted.contains(kind) && (used.contains(kind) || new.requireAuth == .off) { toDecrypt.append(kind) }
            } else if wanted.contains(kind) {
                toEncrypt.append(kind)
            }
        }

        if !toDecrypt.isEmpty || (lowering && Secrets.protectionKey(id) != nil) {
            let p = old ?? new
            if lowering || toDecrypt.contains(where: { !isUnlocked(id, $0) }) {
                // Fresh: the reuse window never covers weakening the protection.
                let task = Task { @MainActor in try await self.decryptAll(p, action: .lowerProtection, requireKey: true) }
                try await task.value
            }
            for kind in toDecrypt {
                guard let value = available(id, kind) else { throw PTError.protectedSecretUnreadable(kind) }
                try Secrets.set(id, kind, value)
            }
        }
        for kind in toEncrypt {
            guard let value = Secrets.get(id, kind) else { continue }
            try store(new, kind, value)
        }
        if new.requireAuth == .off && !SecretKind.allCases.contains(where: { Secrets.isProtected(id, $0) }) {
            Secrets.deleteProtectionKey(id)
        }
    }

    /// The profile's protection public key, made (and its record stored) when there is none. Throws
    /// `ProtectionKeyMismatch` instead of encrypting to a public key the stored key does not have.
    /// Key data that cannot be loaded here (another Mac's) is left to the decrypt, which removes it.
    private func ensureKey(_ id: String) throws -> P256.KeyAgreement.PublicKey {
        if let record = Secrets.protectionKey(id).flatMap(ProtectionKeyRecord.decode), let pub = record.publicKey {
            if let actual = try? authenticator.publicKey(keyData: record.key),
               actual.x963Representation != record.pub {
                throw ProtectionKeyMismatch(profileID: id)
            }
            return pub
        }
        guard authenticator.isAvailable else { throw PTError.protectionUnavailable }
        let key = try authenticator.createKey()
        let record = ProtectionKeyRecord(key: key.data, pub: key.publicKey.x963Representation)
        try Secrets.setProtectionKey(id, try record.encoded())
        return key.publicKey
    }

    // MARK: forgetting

    /// Drops the decrypted values of `id` that were confirmed for another destination than
    /// `fingerprint` (the server settings changed since). Returns whether any were dropped.
    @discardableResult
    public func forgetUnlessBound(_ id: String, to fingerprint: String) -> Bool {
        let stale = (cache[id] ?? [:]).filter { $0.value.destination != fingerprint }.map(\.key)
        for kind in stale { forget(id, kind) }
        return !stale.isEmpty
    }

    /// `forgetUnlessBound` with the destination `p` has now; nothing is read unless values are held.
    @discardableResult
    public func forgetUnlessBound(_ p: Profile) -> Bool {
        guard cache[p.id] != nil else { return false }
        return forgetUnlessBound(p.id, to: destination(p).fingerprint)
    }

    /// Drops decrypted values past the reuse window (overwriting them first, best effort).
    public func prune() {
        let stale = cache.flatMap { id, kinds in kinds.keys.filter { !isUnlocked(id, $0) }.map { (id, $0) } }
        for (id, kind) in stale { forget(id, kind) }
    }

    /// Forgets every decrypted value (sleep, screen lock).
    public func reset() {
        for id in Array(cache.keys) { reset(id) }
    }

    /// Forgets the decrypted values of one profile.
    public func reset(_ id: String) {
        for kind in SecretKind.allCases { forget(id, kind) }
    }

    private func forget(_ id: String, _ kind: SecretKind) {
        guard cache[id]?[kind] != nil else { return }
        _ = cache[id]?[kind]?.bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
        cache[id]?[kind] = nil
        if cache[id]?.isEmpty == true { cache[id] = nil }
        revision += 1
    }
}

/// The profile's protection key record names a public key its private key does not have (the record
/// was replaced or damaged): PassTunnel neither encrypts to it nor decrypts with it.
public struct ProtectionKeyMismatch: Error, Equatable, LocalizedError {
    public var profileID: String

    public var errorDescription: String? {
        String(localized: "The protection key of profile “\(profileID)” does not match its Keychain record, so PassTunnel did not use it. Another app may have replaced the record. Delete the profile and set it up again.")
    }
}

/// Ends the reuse window of a `SecretVault` when the screen locks or the Mac goes to sleep, as the app
/// does. For processes that live on without the app's delegate (`passtunnel mcp`). The centers are
/// injectable for tests; the observers go away with the instance.
@MainActor
public final class VaultExpiry {
    /// Posted (distributed) when the screen locks.
    public static let screenLockedNotification = Notification.Name("com.apple.screenIsLocked")

    private let observers: [(NotificationCenter, NSObjectProtocol)]

    /// `screenLock`: where `screenLockedNotification` arrives; `sleep`: where `sleepNotification` does.
    public init(vault: SecretVault, screenLock: NotificationCenter = DistributedNotificationCenter.default(),
                sleep: NotificationCenter = VaultExpiry.workspaceCenter,
                sleepNotification: Notification.Name = VaultExpiry.willSleepNotification) {
        observers = [(screenLock, Self.screenLockedNotification), (sleep, sleepNotification)].map { center, name in
            (center, center.addObserver(forName: name, object: nil, queue: .main) { [weak vault] _ in
                MainActor.assumeIsolated { vault?.reset() }
            })
        }
    }

    deinit {
        for (center, token) in observers { center.removeObserver(token) }
    }

    #if canImport(AppKit)
    public nonisolated static var workspaceCenter: NotificationCenter { NSWorkspace.shared.notificationCenter }
    public nonisolated static let willSleepNotification = NSWorkspace.willSleepNotification
    #else
    public nonisolated static var workspaceCenter: NotificationCenter { .default }
    public nonisolated static let willSleepNotification = Notification.Name("NSWorkspaceWillSleepNotification")
    #endif
}
