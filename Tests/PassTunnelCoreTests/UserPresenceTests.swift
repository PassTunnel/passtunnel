import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

#if canImport(Combine)
import Combine
#endif
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif
#if canImport(Security)
import Security
#endif

/// Stands in for the Secure Enclave: a software P-256 key behind the same protocol. Each `unlock` is
/// one "prompt"; results are consumed in order (none left = confirmed).
final class FakeAuthenticator: UserAuthenticator, @unchecked Sendable {
    private let lock = NSLock()
    private var _results: [Error?] = []
    private var _reasons: [String] = []
    private var _created = 0
    /// False: like a Mac without a Secure Enclave.
    var isAvailable = true
    /// Seconds each prompt stays open (real time).
    var delay: TimeInterval = 0
    /// False: the public key of stored key data cannot be read without unlocking it.
    var canReadPublicKey = true
    /// Thrown by `publicKey(keyData:)` instead of reading it (another error than `ProtectionKeyUnusable`).
    var publicKeyError: Error?
    /// False: making a key fails, as `SecureEnclaveAuthenticator.createKey` does.
    var canCreateKeys = true

    var results: [Error?] {
        get { lock.lock(); defer { lock.unlock() }; return _results }
        set { lock.lock(); _results = newValue; lock.unlock() }
    }

    /// Errors of the unlocked key's key agreements, consumed in order (none left = it works).
    private var _keyErrors: [Error?] = []
    var keyErrors: [Error?] {
        get { lock.lock(); defer { lock.unlock() }; return _keyErrors }
        set { lock.lock(); _keyErrors = newValue; lock.unlock() }
    }

    /// Key data that loads (its public key reads) but fails once confirmed, as a key that cannot be used.
    private var _deadKeys: Set<Data> = []
    var deadKeys: Set<Data> {
        get { lock.lock(); defer { lock.unlock() }; return _deadKeys }
        set { lock.lock(); _deadKeys = newValue; lock.unlock() }
    }

    fileprivate func nextKeyError() -> Error? {
        lock.lock(); defer { lock.unlock() }
        return _keyErrors.isEmpty ? nil : _keyErrors.removeFirst()
    }

    var reasons: [String] { lock.lock(); defer { lock.unlock() }; return _reasons }
    var calls: Int { reasons.count }
    var keysCreated: Int { lock.lock(); defer { lock.unlock() }; return _created }

    func createKey() throws -> ProtectionKey {
        guard isAvailable, canCreateKeys else { throw PTError.protectionUnavailable }
        let key = P256.KeyAgreement.PrivateKey()
        lock.lock(); _created += 1; lock.unlock()
        return ProtectionKey(data: key.rawRepresentation, publicKey: key.publicKey)
    }

    func publicKey(keyData: Data) throws -> P256.KeyAgreement.PublicKey {
        if let publicKeyError { throw publicKeyError }
        guard canReadPublicKey, let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: keyData) else { throw ProtectionKeyUnusable() }
        return key.publicKey
    }

    func unlock(keyData: Data, reason: String) async throws -> UnlockedProtectionKey {
        let result: Error? = {
            lock.lock(); defer { lock.unlock() }
            _reasons.append(reason)
            return _results.isEmpty ? nil : _results.removeFirst()
        }()
        if delay > 0 { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
        if let result { throw result }
        if deadKeys.contains(keyData) { throw ProtectionKeyUnusable(NSError(domain: "ExampleDomain", code: -1)) }
        guard let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: keyData) else { throw ProtectionKeyUnusable() }
        return Unlocked(key: key, owner: self)
    }

    private final class Unlocked: UnlockedProtectionKey {
        let key: P256.KeyAgreement.PrivateKey
        let owner: FakeAuthenticator
        init(key: P256.KeyAgreement.PrivateKey, owner: FakeAuthenticator) {
            self.key = key
            self.owner = owner
        }
        var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }
        func sharedSecret(with peer: P256.KeyAgreement.PublicKey) async throws -> SharedSecret {
            if let error = owner.nextKeyError() { throw error }
            return try key.sharedSecretFromKeyAgreement(with: peer)
        }
    }
}

// MARK: - Connecting

extension ConnectionManagerTests {
    /// An OpenVPN profile with plain secrets, then switched to `requirement` the way the editor and the
    /// CLI do it (encrypting needs no prompt).
    @discardableResult
    func makeProtected(
        _ name: String = "Acme VPN", _ requirement: AuthRequirement = .connect, in m: ConnectionManager,
        otp: OTPMode = .none, autoReconnect: Bool = false, healthHost: String = ""
    ) async throws -> Profile {
        let plain = try makeOpenVPN(name, otp: otp, autoReconnect: autoReconnect, healthHost: healthHost)
        var p = plain
        p.requireAuth = requirement
        try await m.vault.applyProtection(from: plain, to: p)
        try store.save(p)
        return p
    }

    func startedSecret(_ id: String) -> String? {
        helper.starts.compactMap { r -> String? in
            if case .startOpenVPN(let s) = r, s.profileID == id { return s.secret }
            return nil
        }.last
    }

    func testConnectDecryptsThePasswordWithOnePrompt() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m, otp: .totp)
        XCTAssertTrue(Secrets.isProtected(p.id, .password))
        XCTAssertNil(Secrets.get(p.id, .password), "no plain copy left")
        XCTAssertFalse(Secrets.isProtected(p.id, .totp), "connect keeps the TOTP secret readable for live codes")
        XCTAssertEqual(authenticator.calls, 0, "encrypting needs only the public key")

        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertEqual(authenticator.reasons, ["connect to “Acme VPN” (vpn.example.com)"], "names the server")
        XCTAssertEqual(startedSecret(p.id), "pw" + (try code(at: t0)))
    }

    func testAlwaysEncryptsBothAndStillAsksOnce() async throws {
        let m = makeManager()
        let p = try await makeProtected("Acme", .always, in: m, otp: .totp)
        XCTAssertTrue(Secrets.isProtected(p.id, .password))
        XCTAssertTrue(Secrets.isProtected(p.id, .totp))
        try await m.connect(p.id)
        XCTAssertEqual(authenticator.calls, 1)
        XCTAssertEqual(startedSecret(p.id), "pw" + (try code(at: t0)))
        XCTAssertTrue(m.vault.isUnlocked(p.id, .totp), "the code is shown for the reuse window")
    }

    func testConnectWithoutASavedPasswordEncryptsTheTOTPSecret() async throws {
        let m = makeManager()
        var plain = try makeOpenVPN("Acme", otp: .totp)
        plain.passwordMode = .ask
        Secrets.delete(plain.id, .password)
        try store.save(plain)
        var p = plain
        p.requireAuth = .connect
        try await m.vault.applyProtection(from: plain, to: p)
        try store.save(p)
        XCTAssertTrue(Secrets.isProtected(p.id, .totp), "otherwise the setting would protect nothing")
        XCTAssertTrue(m.vault.needsPrompt(p, for: .code), "its code is locked like with always")

        try await m.connect(p.id, given: [.password: "typed"])
        XCTAssertEqual(authenticator.calls, 1)
        XCTAssertEqual(startedSecret(p.id), "typed" + (try code(at: t0)))
    }

    func testCancelStartsNothingAndShowsNoError() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m, otp: .totp)
        authenticator.results = [PTError.userConfirmationCancelled]
        do {
            try await m.connect(p.id)
            XCTFail("expected a cancel")
        } catch {
            XCTAssertEqual(error as? PTError, .userConfirmationCancelled)
        }
        XCTAssertEqual(helper.starts.count, 0)
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertNil(m.lastError[p.id])
        XCTAssertTrue(events.isEmpty)
        XCTAssertNil(m.usedCode(p.id), "no code was spent")

        try await m.connect(p.id)  // a cancel is not a confirmation
        XCTAssertEqual(authenticator.calls, 2)
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    func testFailureIsReportedNeverBypassed() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m)
        let reason = "the confirmation cannot be shown in this session (for example over SSH). Use PassTunnel on the Mac itself."
        authenticator.results = [PTError.userConfirmationFailed(reason)]
        do {
            try await m.connect(p.id)
            XCTFail("expected a failure")
        } catch {
            XCTAssertEqual(error as? PTError, .userConfirmationFailed(reason))
        }
        XCTAssertEqual(helper.starts.count, 0)
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertTrue(m.lastError[p.id]?.contains("SSH") == true, "shown like any connect failure")
    }

    func testOneConfirmationCoversTheReuseWindowOnly() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m)
        try await m.connect(p.id)
        try await m.disconnect(p.id)
        try await clock.sleep(50)
        try await m.connect(p.id)  // within 60 s: no second prompt
        XCTAssertEqual(authenticator.calls, 1)
        try await m.disconnect(p.id)

        try await clock.sleep(61)
        await m.refresh()  // the poll drops the expired plain text
        XCTAssertFalse(m.vault.isUnlocked(p.id, .password))
        try await m.connect(p.id)
        XCTAssertEqual(authenticator.calls, 2)
        try await m.disconnect(p.id)

        prefs.authReuseMinutes = 5  // read on every check
        try await clock.sleep(200)
        try await m.connect(p.id)
        XCTAssertEqual(authenticator.calls, 2)
        XCTAssertEqual(helper.starts.count, 4)
        XCTAssertEqual(startedSecret(p.id), "pw")
    }

    func testAutoReconnectAfterADropDoesNotAsk() async throws {
        let m = makeManager()
        let p = try await makeProtected("Acme", .always, in: m, otp: .totp, autoReconnect: true)
        try await m.connect(p.id)
        try await clock.sleep(300)  // long past the reuse window
        await m.refresh()
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(events.first, .dropped(profileID: p.id, willReconnect: true))
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events.last, .reconnected(profileID: p.id))
        XCTAssertEqual(authenticator.calls, 1, "the session's secrets are kept for its reconnects")
        XCTAssertEqual(helper.starts.count, 2)
        XCTAssertTrue(startedSecret(p.id)?.hasPrefix("pw") == true)

        // A user disconnect ends the session: the next connect asks.
        try await m.disconnect(p.id)
        try await m.connect(p.id)
        XCTAssertEqual(authenticator.calls, 2)
    }

    func testHealthForcedReconnectDoesNotAsk() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m, autoReconnect: true, healthHost: "10.0.0.5")
        try await m.connect(p.id)
        try await clock.sleep(300)
        healthResults = [false, false]
        await m.runHealthChecks()
        await m.runHealthChecks()
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events.last, .reconnected(profileID: p.id))
        XCTAssertEqual(authenticator.calls, 1)
        XCTAssertEqual(helper.starts.count, 2)
    }

    func testReconnectOfASessionConfirmedElsewhereNeverPrompts() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m, autoReconnect: true)
        // Started by the CLI: this process never had the secrets.
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        await m.refresh()
        XCTAssertTrue(m.state(p.id).isConnected)
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events.last, .reconnectFailed(profileID: p.id, reason: PTError.confirmationRequired.localizedDescription))
        XCTAssertEqual(authenticator.calls, 0, "no prompt out of the blue")
        XCTAssertEqual(helper.starts.count, 0)
    }

    func testWakeAsksTheUserInsteadOfReconnecting() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m, autoReconnect: true)
        let plain = try makeOpenVPN("Plain", autoReconnect: true)
        try await m.connect(p.id)
        try await m.connect(plain.id)
        m.handleWillSleep()
        XCTAssertFalse(m.vault.isUnlocked(p.id, .password), "sleep ends the reuse window")
        helper.simulateExit(p.id)
        helper.simulateExit(plain.id)
        await m.handleDidWake()
        await waitUntil { self.events.contains(.reconnected(profileID: plain.id)) }

        XCTAssertEqual(
            events.filter { $0.profileID == p.id }, [.droppedWhileAsleep(profileID: p.id)],
            "no prompt out of the blue and no automatic reconnect")
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertNil(m.reconnecting[p.id])
        XCTAssertEqual(authenticator.calls, 1)

        // The notification's action connects, which asks.
        try await m.connect(p.id)
        XCTAssertEqual(authenticator.calls, 2)
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    func testANewSecretIsEncryptedWithoutAPrompt() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m)
        try m.vault.store(p, .password, "new-password")
        XCTAssertTrue(Secrets.isProtected(p.id, .password))
        XCTAssertEqual(authenticator.calls, 0)
        try await m.connect(p.id)
        XCTAssertEqual(startedSecret(p.id), "new-password")
        XCTAssertEqual(authenticator.calls, 1)
    }

    func testHandEditedSettingEncryptsBeforeTheFirstUse() async throws {
        var p = try makeOpenVPN("Acme", otp: .totp)
        p.requireAuth = .always  // as if profile.json was edited: secrets still plain
        try store.save(p)
        XCTAssertNotNil(Secrets.get(p.id, .password))
        let m = makeManager()
        try await m.connect(p.id)
        XCTAssertTrue(Secrets.isProtected(p.id, .password))
        XCTAssertTrue(Secrets.isProtected(p.id, .totp))
        XCTAssertEqual(authenticator.calls, 1, "encrypted without a prompt, then decrypted with one")
        XCTAssertEqual(startedSecret(p.id), "pw" + (try code(at: t0)))
    }

    func testUnusableKeyKeepsTheSecretAndEnteringItAgainMakesANewKey() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m)
        // As after moving to another Mac: the wrapped key blob is useless here.
        var record = try XCTUnwrap(Secrets.protectionKey(p.id).flatMap(ProtectionKeyRecord.decode))
        record.key = Data("not a key".utf8)
        let recordText = try record.encoded()
        try Secrets.setProtectionKey(p.id, recordText)
        let stored = Secrets.raw(p.id, .password)

        do {
            try await m.connect(p.id)
            XCTFail("expected an error")
        } catch {
            let unusable = try XCTUnwrap(error as? ProtectionKeyUnusable, "\(error)")
            XCTAssertEqual(unusable.profileName, "Acme VPN")
            XCTAssertEqual(unusable.kinds, [.password])
            XCTAssertTrue(error.localizedDescription.contains("enter its password again in the profile editor"), error.localizedDescription)
        }
        XCTAssertEqual(helper.starts.count, 0)
        XCTAssertEqual(Secrets.raw(p.id, .password), stored, "nothing is removed: the failure may pass")
        XCTAssertEqual(Secrets.protectionKey(p.id), recordText)
        XCTAssertTrue(m.lastError[p.id]?.contains("were kept") == true)

        // Entering it again replaces the item and, as nothing else needs the old key, the key.
        try m.vault.store(p, .password, "pw2")
        XCTAssertTrue(Secrets.isProtected(p.id, .password))
        XCTAssertNotEqual(Secrets.protectionKey(p.id), recordText)
        try await m.connect(p.id)
        XCTAssertEqual(startedSecret(p.id), "pw2")
    }
}

// MARK: - Vault, envelope, settings and fields

final class SecretVaultTests: CoreTestCase {
    var now = Date(timeIntervalSince1970: 1_700_000_000)
    var window: TimeInterval = 60
    var auth: FakeAuthenticator!
    let totp = "JBSWY3DPEHPK3PXP"

    override func setUpWithError() throws {
        try super.setUpWithError()
        auth = FakeAuthenticator()
        now = Date(timeIntervalSince1970: 1_700_000_000)
        window = 60
    }

    @MainActor func makeVault() -> SecretVault {
        SecretVault(authenticator: auth, now: { [unowned self] in self.now }, reuseWindow: { [unowned self] in self.window })
    }

    /// A stored profile with plain secrets (`password` nil: asked each time).
    func makeProfile(_ name: String = "Acme", password: String? = "pw", otp: Bool = true) throws -> Profile {
        var p = try store.create(name: name, type: .openvpn)
        p.passwordMode = password == nil ? .ask : .keychain
        p.otpMode = otp ? .totp : .none
        try store.save(p)
        if let password { try Secrets.set(p.id, .password, password) }
        if otp { try Secrets.set(p.id, .totp, totp) }
        return p
    }

    @MainActor func change(_ p: Profile, to requirement: AuthRequirement, in vault: SecretVault) async throws -> Profile {
        var new = p
        new.requireAuth = requirement
        try await vault.applyProtection(from: p, to: new)
        try store.save(new)
        return new
    }

    // MARK: envelope

    func testEnvelopeRoundTripAndBinding() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let sealed = try SecretEnvelope.seal("pässword", to: key.publicKey, account: "acme/password")
        XCTAssertTrue(sealed.hasPrefix("ptse1:"))
        XCTAssertTrue(SecretEnvelope.isEnvelope(sealed))
        XCTAssertNotEqual(
            try SecretEnvelope.seal("pässword", to: key.publicKey, account: "acme/password"), sealed,
            "a fresh ephemeral key every time")
        let parsed = try XCTUnwrap(SecretEnvelope.parse(sealed))
        let shared = try key.sharedSecretFromKeyAgreement(with: parsed.ephemeral)
        XCTAssertEqual(
            try SecretEnvelope.open(
                parsed, shared: shared, recipient: key.publicKey,
                account: "acme/password", kind: .password), "pässword")
        // Moved to another item: the account is authenticated.
        XCTAssertThrowsError(
            try SecretEnvelope.open(
                parsed, shared: shared, recipient: key.publicKey,
                account: "acme/totp", kind: .totp)
        ) { error in
            XCTAssertEqual(error as? PTError, .protectedSecretUnreadable(.totp))
        }
        // Another key.
        let other = P256.KeyAgreement.PrivateKey()
        let wrong = try other.sharedSecretFromKeyAgreement(with: parsed.ephemeral)
        XCTAssertThrowsError(
            try SecretEnvelope.open(
                parsed, shared: wrong, recipient: key.publicKey,
                account: "acme/password", kind: .password))
    }

    func testEnvelopeVersionAndMarker() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let sealed = try SecretEnvelope.seal("x", to: key.publicKey, account: "a/password")
        let blob = try XCTUnwrap(Data(base64Encoded: String(sealed.dropFirst(6))))
        XCTAssertEqual(blob.first, 1)
        XCTAssertEqual(blob.count, 1 + 65 + 12 + 1 + 16)
        var newer = blob
        newer[0] = 2
        XCTAssertNil(SecretEnvelope.parse("ptse1:" + newer.base64EncodedString()), "unknown version")
        XCTAssertTrue(SecretEnvelope.isEnvelope("ptse2:AAAA"), "a newer format is recognized, not read as plain text")
        XCTAssertNil(SecretEnvelope.parse("ptse2:" + blob.base64EncodedString()))
        XCTAssertNil(SecretEnvelope.parse("ptse1:not base64!"))
        XCTAssertNil(SecretEnvelope.parse("ptse1:" + Data(blob.prefix(40)).base64EncodedString()), "truncated")
    }

    func testPlainValuesThatLookLikeEnvelopesStayPlain() throws {
        for value in ["ptse1:hello", "ptpl1:x", "ptsecret", "plain"] {
            try Secrets.set("acme", .password, value)
            XCTAssertFalse(Secrets.isProtected("acme", .password), value)
            XCTAssertEqual(Secrets.get("acme", .password), value)
        }
    }

    @MainActor func testTamperedItemIsAClearError() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .connect, in: vault)
        var raw = try XCTUnwrap(Secrets.raw(p.id, .password))
        var blob = try XCTUnwrap(Data(base64Encoded: String(raw.dropFirst(6))))
        blob[blob.count - 20] ^= 0x01
        raw = "ptse1:" + blob.base64EncodedString()
        try Secrets.setRaw(p.id, .password, raw)
        do {
            _ = try await vault.secret(p, .password, for: .connect)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(error as? PTError, .protectedSecretUnreadable(.password))
        }
        XCTAssertEqual(Secrets.raw(p.id, .password), raw, "kept: the key still works, so it is not a lost key")
    }

    // MARK: key failures

    /// The encrypted items and the key record of `p`, to check that nothing changed.
    func storedItems(_ p: Profile) -> [String?] {
        [Secrets.raw(p.id, .password), Secrets.raw(p.id, .totp), Secrets.protectionKey(p.id)]
    }

    @MainActor func testKeyThatFailsToUnlockKeepsEverythingAndATryAgainWorks() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        let before = storedItems(p)
        let underlying = NSError(domain: "ExampleDomain", code: 42, userInfo: [NSLocalizedDescriptionKey: "The key was refused."])
        auth.results = [ProtectionKeyUnusable(underlying)]
        do {
            _ = try await vault.secret(p, .password, for: .connect)
            XCTFail("expected an error")
        } catch {
            let unusable = try XCTUnwrap(error as? ProtectionKeyUnusable, "\(error)")
            XCTAssertEqual(unusable.profileName, "Acme")
            XCTAssertEqual(Set(unusable.kinds), [.password, .totp])
            XCTAssertEqual(unusable.reason, "The key was refused. (ExampleDomain 42)")
            let text = error.localizedDescription
            XCTAssertTrue(text.contains("The saved secrets were kept"), text)
            XCTAssertTrue(text.contains("enter its password and add its TOTP secret again"), text)
            XCTAssertTrue(text.hasSuffix("Details: The key was refused. (ExampleDomain 42)"), text)
        }
        XCTAssertEqual(storedItems(p), before, "nothing removed")
        XCTAssertFalse(vault.isUnlocked(p.id, .password))

        // Any other error is passed on as it is, and changes nothing either.
        auth.results = [NSError(domain: "ExampleDomain", code: 7)]
        do {
            _ = try await vault.secret(p, .password, for: .connect)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual((error as NSError).code, 7)
        }
        XCTAssertEqual(storedItems(p), before)

        let password = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(password, "pw")
        XCTAssertEqual(vault.available(p.id, .totp), totp)
        XCTAssertEqual(auth.calls, 3)
    }

    @MainActor func testKeyAgreementFailureKeepsEverythingAndATryAgainWorks() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .connect, in: vault)
        let before = storedItems(p)
        auth.keyErrors = [ProtectionKeyUnusable(CocoaError(.featureUnsupported))]
        do {
            _ = try await vault.secret(p, .password, for: .connect)
            XCTFail("expected an error")
        } catch {
            let unusable = try XCTUnwrap(error as? ProtectionKeyUnusable, "\(error)")
            XCTAssertEqual(unusable.kinds, [.password])
            XCTAssertTrue(unusable.reason?.hasSuffix("(NSCocoaErrorDomain \(CocoaError.featureUnsupported.rawValue))") == true, "\(unusable)")
            XCTAssertTrue(error.localizedDescription.contains("enter its password again"), error.localizedDescription)
        }
        XCTAssertEqual(storedItems(p), before, "nothing removed")
        XCTAssertNil(vault.available(p.id, .password))

        let password = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(password, "pw")
        XCTAssertEqual(auth.calls, 2)
        XCTAssertFalse(ConnectionManager.isRetryable(ProtectionKeyUnusable()), "a reconnect cannot ask, so it does not retry")
        XCTAssertEqual(ConnectionFailure.of(ProtectionKeyUnusable(), log: nil, handed: nil, at: now).kind, .configuration)
    }

    /// Makes the stored key data of `id` unloadable here, as another Mac's; returns the record's text.
    @discardableResult
    func makeKeyUnloadable(_ id: String) throws -> String {
        var record = try XCTUnwrap(Secrets.protectionKey(id).flatMap(ProtectionKeyRecord.decode))
        record.key = Data("not a key".utf8)
        let text = try record.encoded()
        try Secrets.setProtectionKey(id, text)
        return text
    }

    @MainActor func testPartialReentryWithAnUnloadableKeyChangesNothing() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        try makeKeyUnloadable(p.id)
        let before = storedItems(p)

        // The TOTP secret still needs the stored key, which may never open again: nothing is written.
        XCTAssertThrowsError(try vault.store(p, .password, "pw2")) { error in
            XCTAssertEqual((error as? ProtectionKeyUnusable)?.kinds, [.password, .totp], "\(error)")
            XCTAssertTrue(error.localizedDescription.contains("enter its password and add its TOTP secret again"))
        }
        XCTAssertEqual(storedItems(p), before)
        XCTAssertEqual(auth.keysCreated, 1)

        // Both together: nothing needs the old key any more, so they get a new one.
        try vault.store(p, [.password: "pw3", .totp: totp])
        XCTAssertNotEqual(Secrets.protectionKey(p.id), before[2])
        XCTAssertTrue(Secrets.isProtected(p.id, .password))
        XCTAssertTrue(Secrets.isProtected(p.id, .totp))
        XCTAssertEqual(auth.keysCreated, 2)
        let password = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(password, "pw3")
        XCTAssertEqual(vault.available(p.id, .totp), totp)
        XCTAssertEqual(auth.calls, 1)

        // A partial store with a key that loads uses it; a full one always makes a new key.
        let current = Secrets.protectionKey(p.id)
        try vault.store(p, .password, "pw4")
        XCTAssertEqual(Secrets.protectionKey(p.id), current)
        try vault.store(p, [.password: "pw5", .totp: totp])
        XCTAssertNotEqual(Secrets.protectionKey(p.id), current)
        XCTAssertEqual(auth.keysCreated, 3)
        vault.reset()
        let latest = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(latest, "pw5")
    }

    @MainActor func testKeyThatLoadsButCannotBeUsedIsReplacedByAFullReentry() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        let record = try XCTUnwrap(Secrets.protectionKey(p.id).flatMap(ProtectionKeyRecord.decode))
        auth.deadKeys = [record.key]  // its public key reads; only using it fails
        let before = storedItems(p)
        do {
            _ = try await vault.secret(p, .password, for: .connect)
            XCTFail("expected an error")
        } catch {
            XCTAssertTrue(error is ProtectionKeyUnusable, "\(error)")
        }
        XCTAssertEqual(storedItems(p), before)

        try vault.store(p, [.password: "pw2", .totp: totp])
        XCTAssertNotEqual(Secrets.protectionKey(p.id), before[2])
        let password = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(password, "pw2")
        XCTAssertEqual(vault.available(p.id, .totp), totp)
    }

    @MainActor func testSingleSecretProfileIsRepairedByEnteringItAgain() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(otp: false), to: .connect, in: vault)
        let record = try XCTUnwrap(Secrets.protectionKey(p.id).flatMap(ProtectionKeyRecord.decode))
        auth.deadKeys = [record.key]
        do {
            _ = try await vault.secret(p, .password, for: .connect)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual((error as? ProtectionKeyUnusable)?.kinds, [.password], "\(error)")
        }
        try vault.store(p, .password, "pw2")  // the single-kind store, as `passtunnel secret` uses it
        let password = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(password, "pw2")
    }

    /// Lowering needs a real confirmation, so a key that cannot be used refuses it; a profile that
    /// stores no secret is not asked to enter one.
    @MainActor func testLoweringWithAnUnusableKeyIsRefusedWithoutAskingForUnusedSecrets() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(password: nil, otp: false), to: .connect, in: vault)
        let record = try XCTUnwrap(Secrets.protectionKey(p.id).flatMap(ProtectionKeyRecord.decode))
        auth.deadKeys = [record.key]
        var off = p
        off.requireAuth = .off
        do {
            try await vault.applyProtection(from: p, to: off)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual((error as? ProtectionKeyUnusable)?.kinds, [], "\(error)")
            XCTAssertFalse(error.localizedDescription.contains("another Mac"), error.localizedDescription)
        }
        XCTAssertNotNil(Secrets.protectionKey(p.id))
    }

    /// A save that changes something else than the setting gets the ordinary hint.
    @MainActor func testUnusableKeyWithoutASettingChangeGetsTheOrdinaryHint() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(password: nil), to: .connect, in: vault)
        XCTAssertTrue(Secrets.isProtected(p.id, .totp))
        try makeKeyUnloadable(p.id)
        var saved = p
        saved.passwordMode = .keychain  // the TOTP secret leaves the protection: it is decrypted
        do {
            try await vault.applyProtection(from: p, to: saved)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual((error as? ProtectionKeyUnusable)?.changingSetting, false, "\(error)")
            XCTAssertTrue(error.localizedDescription.contains("first add its TOTP secret again"), error.localizedDescription)
        }
    }

    @MainActor func testUnloadableKeyNeverTakesAPlainSecret() async throws {
        let vault = makeVault()
        var p = try await change(try makeProfile(), to: .connect, in: vault)
        XCTAssertEqual([Secrets.isProtected(p.id, .password), Secrets.isProtected(p.id, .totp)], [true, false])
        try makeKeyUnloadable(p.id)
        let before = storedItems(p)

        // Raising the setting would encrypt the TOTP secret to the stored key: refused, it stays plain.
        var always = p
        always.requireAuth = .always
        do {
            try await vault.applyProtection(from: p, to: always)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual((error as? ProtectionKeyUnusable)?.changingSetting, true, "\(error)")
            // The setting is named by the editor's switch on the Mac and as require_auth on Linux.
            #if os(macOS)
            let setting = "Require"
            #else
            let setting = "require_auth"
            #endif
            XCTAssertTrue(error.localizedDescription.contains("save without changing “\(setting)"), error.localizedDescription)
        }
        XCTAssertEqual(storedItems(p), before)
        XCTAssertEqual(Secrets.get(p.id, .totp), totp)

        // The same setting edited by hand: reconcile leaves it plain too.
        p.requireAuth = .always
        try store.save(p)
        XCTAssertFalse(vault.reconcile(p))
        XCTAssertEqual(storedItems(p), before)
        XCTAssertEqual(Secrets.get(p.id, .totp), totp)
    }

    #if canImport(Security)
    @MainActor func testFullReentryThatFailsHalfwayCanBeRepeated() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        try makeKeyUnloadable(p.id)
        let before = storedItems(p)
        defer { Secrets.addOverride = nil }
        var failed = false
        Secrets.addOverride = { query in
            let account = (query as NSDictionary)[kSecAttrAccount as String] as? String
            if !failed && account == "\(p.id)/totp" {
                failed = true
                return errSecIO
            }
            return SecItemAdd(query, nil)
        }
        XCTAssertThrowsError(try vault.store(p, [.password: "pw2", .totp: totp]))
        XCTAssertTrue(failed)
        XCTAssertEqual(storedItems(p), before, "the record is written last; the password was put back")

        Secrets.addOverride = nil
        try vault.store(p, [.password: "pw3", .totp: totp])
        let password = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(password, "pw3")
        XCTAssertEqual(vault.available(p.id, .totp), totp)
    }

    /// A healthy profile whose new key record cannot be written keeps its items, readable with the old key.
    @MainActor func testFailedKeyRecordWritePutsTheItemsBack() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        let before = storedItems(p)
        defer { Secrets.addOverride = nil }
        var failed = false
        Secrets.addOverride = { query in
            let account = (query as NSDictionary)[kSecAttrAccount as String] as? String
            if !failed && account == "\(p.id)/sekey" {
                failed = true
                return errSecIO
            }
            return SecItemAdd(query, nil)
        }
        XCTAssertThrowsError(try vault.store(p, [.password: "pw2", .totp: totp]))
        XCTAssertTrue(failed)
        XCTAssertEqual(storedItems(p), before)
        let password = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(password, "pw")
    }

    /// An item or a record that exists but cannot be read is never left behind with a new key.
    @MainActor func testUnreadableItemOrRecordStopsTheStore() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        let before = storedItems(p)
        defer { Secrets.readOverride = nil }

        Secrets.readOverride = { $0 == "\(p.id)/totp" ? errSecInteractionNotAllowed : nil }
        XCTAssertThrowsError(try vault.store(p, .password, "pw2")) { error in
            XCTAssertEqual(error as? PTError, .keychain(errSecInteractionNotAllowed))
        }
        Secrets.readOverride = { $0 == "\(p.id)/sekey" ? errSecInteractionNotAllowed : nil }
        XCTAssertThrowsError(try vault.store(p, [.password: "pw2", .totp: totp])) { error in
            XCTAssertEqual(error as? PTError, .keychain(errSecInteractionNotAllowed))
        }
        Secrets.readOverride = nil
        XCTAssertEqual(storedItems(p), before, "nothing written")
        XCTAssertEqual(auth.keysCreated, 1)

        try vault.store(p, .password, "pw3")
        try vault.store(p, [.password: "pw4", .totp: totp])
        let password = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(password, "pw4")
        XCTAssertEqual(vault.available(p.id, .totp), totp)
    }
    #endif

    /// Another error of the key data than `ProtectionKeyUnusable` is reported as it is, and nothing is
    /// encrypted to the record's unchecked public key.
    @MainActor func testOtherKeyDataErrorsStopTheStore() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        let before = storedItems(p)
        auth.publicKeyError = PTError.protectionUnavailable
        XCTAssertThrowsError(try vault.store(p, .password, "pw2")) { XCTAssertEqual($0 as? PTError, .protectionUnavailable) }
        XCTAssertEqual(storedItems(p), before)

        // With nothing encrypted either.
        Secrets.delete(p.id, .password)
        Secrets.delete(p.id, .totp)
        XCTAssertThrowsError(try vault.store(p, .password, "pw2")) { XCTAssertEqual($0 as? PTError, .protectionUnavailable) }
        XCTAssertFalse(Secrets.has(p.id, .password))
        XCTAssertEqual(Secrets.protectionKey(p.id), before[2])
    }

    /// A full replacement that cannot make a new key uses the stored one when it loads and matches.
    @MainActor func testFullReplacementWithoutANewKeyUsesAHealthyStoredKey() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(otp: false), to: .connect, in: vault)
        let record = Secrets.protectionKey(p.id)
        auth.canCreateKeys = false
        try vault.store(p, .password, "pw2")
        XCTAssertEqual(Secrets.protectionKey(p.id), record)
        let password = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(password, "pw2")

        // Not when the stored key data cannot be loaded: then there is no key to use.
        try makeKeyUnloadable(p.id)
        let before = storedItems(p)
        XCTAssertThrowsError(try vault.store(p, .password, "pw3")) { XCTAssertEqual($0 as? PTError, .protectionUnavailable) }
        XCTAssertEqual(storedItems(p), before)
    }

    // MARK: migration

    @MainActor func testTurningOnEncryptsWithoutAPromptAndOffDecryptsWithOne() async throws {
        let vault = makeVault()
        var p = try makeProfile()
        p = try await change(p, to: .connect, in: vault)
        XCTAssertEqual([Secrets.isProtected(p.id, .password), Secrets.isProtected(p.id, .totp)], [true, false])
        XCTAssertNotNil(Secrets.protectionKey(p.id))
        p = try await change(p, to: .always, in: vault)
        XCTAssertEqual([Secrets.isProtected(p.id, .password), Secrets.isProtected(p.id, .totp)], [true, true])
        XCTAssertEqual(auth.calls, 0)
        XCTAssertEqual(auth.keysCreated, 1, "one key per profile")

        p = try await change(p, to: .connect, in: vault)  // the TOTP secret leaves the protection
        XCTAssertEqual(auth.reasons, ["change the confirmation setting for “Acme”"])
        XCTAssertEqual(Secrets.get(p.id, .totp), totp)
        XCTAssertTrue(Secrets.isProtected(p.id, .password))

        p = try await change(p, to: .off, in: vault)
        XCTAssertEqual(auth.calls, 2, "lowering always asks, even inside the reuse window")
        XCTAssertEqual(Secrets.get(p.id, .password), "pw")
        XCTAssertNil(Secrets.protectionKey(p.id), "the key is removed with the last encrypted item")
    }

    @MainActor func testCancelledLoweringChangesNothing() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        let before = [Secrets.raw(p.id, .password), Secrets.raw(p.id, .totp)]
        auth.results = [PTError.userConfirmationCancelled]
        var off = p
        off.requireAuth = .off
        do {
            try await vault.applyProtection(from: p, to: off)
            XCTFail("expected a cancel")
        } catch {
            XCTAssertEqual(error as? PTError, .userConfirmationCancelled)
        }
        XCTAssertEqual([Secrets.raw(p.id, .password), Secrets.raw(p.id, .totp)], before)
        XCTAssertNotNil(Secrets.protectionKey(p.id))
    }

    @MainActor func testLoweringAsksEvenWithNothingEncrypted() async throws {
        let vault = makeVault()
        var p = try makeProfile(password: "pw", otp: false)
        p = try await change(p, to: .connect, in: vault)
        Secrets.delete(p.id, .password)  // key, but no encrypted item
        _ = try await change(p, to: .off, in: vault)
        XCTAssertEqual(auth.calls, 1, "the key is used once so the confirmation is real")
        XCTAssertNil(Secrets.protectionKey(p.id))
    }

    @MainActor func testWithoutASecureEnclaveItCannotBeTurnedOn() async throws {
        auth.isAvailable = false
        let vault = makeVault()
        XCTAssertFalse(vault.isAvailable)
        let p = try makeProfile()
        var on = p
        on.requireAuth = .connect
        do {
            try await vault.applyProtection(from: p, to: on)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(error as? PTError, .protectionUnavailable)
        }
        XCTAssertEqual(Secrets.get(p.id, .password), "pw", "nothing changed, nothing silently degraded")
        XCTAssertNil(Secrets.protectionKey(p.id))
    }

    @MainActor func testReconcileEncryptsPlainSecretsTheSettingProtects() async throws {
        let vault = makeVault()
        var p = try makeProfile()
        p.requireAuth = .connect
        try store.save(p)  // edited by hand, not through applyProtection
        XCTAssertTrue(vault.reconcile(p))
        XCTAssertTrue(Secrets.isProtected(p.id, .password))
        XCTAssertFalse(Secrets.isProtected(p.id, .totp), "connect leaves the TOTP secret readable")
        XCTAssertFalse(vault.reconcile(p), "nothing left to do")
        XCTAssertEqual(auth.calls, 0)
        let password = try await vault.secret(p, .password, for: .connect)
        XCTAssertEqual(password, "pw")
        XCTAssertEqual(auth.calls, 1)

        // Without a Secure Enclave nothing changes (and nothing fails).
        auth.isAvailable = false
        var q = try makeProfile("Other")
        q.requireAuth = .always
        try store.save(q)
        XCTAssertFalse(vault.reconcile(q))
        XCTAssertEqual(Secrets.get(q.id, .password), "pw")
    }

    @MainActor func testEncryptedWhileOffStaysProtected() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        var off = p
        off.requireAuth = .off
        try store.save(off)  // turned off by hand: no decrypt happened
        XCTAssertFalse(vault.reconcile(off))
        XCTAssertTrue(vault.needsPrompt(off, for: .connect), "still asks: the items are still encrypted")
        XCTAssertTrue(vault.requiresConfirmation(off))
        let password = try await vault.secret(off, .password, for: .connect)
        XCTAssertEqual(password, "pw")
        XCTAssertEqual(auth.calls, 1)
        XCTAssertTrue(Secrets.isProtected(p.id, .password), "left as is until it is turned off properly")
        XCTAssertTrue(Secrets.isProtected(p.id, .totp))
        XCTAssertNotNil(Secrets.protectionKey(p.id))
    }

    @MainActor func testDeletingTheProfileDeletesItsKey() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        XCTAssertNotNil(Secrets.protectionKey(p.id))
        try store.delete(p.id)
        XCTAssertNil(Secrets.protectionKey(p.id))
        XCTAssertFalse(Secrets.has(p.id, .password))
    }

    // MARK: policy

    @MainActor func testCodesAreLockedOnlyWhenTheirSecretIsEncrypted() async throws {
        let vault = makeVault()
        let connectOnly = try await change(try makeProfile("A"), to: .connect, in: vault)
        let always = try await change(try makeProfile("B"), to: .always, in: vault)

        XCTAssertFalse(vault.needsPrompt(connectOnly, for: .code))
        let plainCode = try await vault.secret(connectOnly, .totp, for: .code)
        XCTAssertEqual(plainCode, totp)
        XCTAssertEqual(auth.calls, 0)

        XCTAssertTrue(vault.needsPrompt(always, for: .code))
        XCTAssertNil(vault.available(always.id, .totp))
        do {
            _ = try await vault.secret(always, .totp, for: .code, prompt: false)
            XCTFail("expected confirmationRequired")
        } catch {
            XCTAssertEqual(error as? PTError, .confirmationRequired)
        }
        try await vault.unlock(always, for: .code)
        XCTAssertEqual(auth.reasons, ["show the code for “B”"])
        XCTAssertEqual(vault.available(always.id, .totp), totp)
        XCTAssertFalse(vault.needsPrompt(always, for: .connect), "one prompt unlocks the whole profile")
        try await vault.unlock(always, for: .code)
        XCTAssertEqual(auth.calls, 1)

        now = now.addingTimeInterval(60)
        XCTAssertTrue(vault.needsPrompt(always, for: .code), "locked again when the window ends")
        XCTAssertNil(vault.available(always.id, .totp))
    }

    @MainActor func testConcurrentRequestsShareOnePrompt() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        auth.delay = 0.2
        async let first: Void = vault.unlock(p, for: .connect)
        async let second: Void = vault.unlock(p, for: .code)
        _ = try await (first, second)
        XCTAssertEqual(auth.calls, 1)
    }

    @MainActor func testResetEndsTheWindow() async throws {
        let vault = makeVault()
        let p = try await change(try makeProfile(), to: .always, in: vault)
        try await vault.unlock(p, for: .connect)
        vault.reset()
        XCTAssertTrue(vault.needsPrompt(p, for: .connect))
        XCTAssertTrue(vault.needsPrompt(p, for: .code))
    }

    func testProtectedKinds() {
        var p = Profile(id: "a", name: "A", type: .openvpn)
        p.otpMode = .totp
        XCTAssertEqual(SecretVault.protectedKinds(p), [])
        p.requireAuth = .connect
        XCTAssertEqual(SecretVault.protectedKinds(p), [.password])
        p.passwordMode = .ask
        XCTAssertEqual(SecretVault.protectedKinds(p), [.totp])
        p.requireAuth = .always
        XCTAssertEqual(SecretVault.protectedKinds(p), [.password, .totp])
        XCTAssertTrue(p.usesStoredSecrets)
        p.otpMode = .none
        XCTAssertFalse(p.usesStoredSecrets)
        XCTAssertTrue(SecretVault.lowersProtection(from: .always, to: .connect))
        XCTAssertTrue(SecretVault.lowersProtection(from: .connect, to: .off))
        XCTAssertFalse(SecretVault.lowersProtection(from: .off, to: .always))
        XCTAssertFalse(SecretVault.lowersProtection(from: .connect, to: .connect))
    }

    #if os(macOS)
    func testLocalAuthenticationErrorsMap() {
        func map(_ code: LAError.Code) -> PTError? {
            SecureEnclaveAuthenticator.map(NSError(domain: LAError.errorDomain, code: code.rawValue)) as? PTError
        }
        XCTAssertEqual(map(.userCancel), .userConfirmationCancelled)
        XCTAssertEqual(map(.appCancel), .userConfirmationCancelled)
        for code in [LAError.Code.systemCancel, .notInteractive, .biometryLockout, .passcodeNotSet, .authenticationFailed] {
            guard case .userConfirmationFailed(let reason)? = map(code) else { return XCTFail("\(code)") }
            XCTAssertFalse(reason.isEmpty)
        }
        XCTAssertTrue(SecureEnclaveAuthenticator.map(ProtectionKeyUnusable()) is ProtectionKeyUnusable)
    }

    /// Errors of the key itself: LocalAuthentication's are worded as the prompt's, anything else is
    /// reported with its text, domain and code, whatever it is.
    func testKeyErrorsKeepTheUnderlyingError() {
        XCTAssertEqual(
            SecureEnclaveAuthenticator.keyError(NSError(domain: LAError.errorDomain, code: LAError.Code.userCancel.rawValue)) as? PTError,
            .userConfirmationCancelled)
        let ns = NSError(domain: "ExampleDomain", code: -3, userInfo: [NSLocalizedDescriptionKey: "Refused."])
        XCTAssertEqual(SecureEnclaveAuthenticator.keyError(ns) as? ProtectionKeyUnusable, ProtectionKeyUnusable(ns))
        XCTAssertEqual(ProtectionKeyUnusable(ns).reason, "Refused. (ExampleDomain -3)")
        let swiftError = CryptoKitError.underlyingCoreCryptoError(error: -5)
        let reason = ProtectionKeyUnusable(swiftError).reason ?? ""
        XCTAssertTrue(reason.hasPrefix("underlyingCoreCryptoError(error: -5) ("), reason)
        XCTAssertTrue(reason.contains("CryptoKitError"), reason)
        XCTAssertNil(ProtectionKeyUnusable().reason)
        XCTAssertFalse(ProtectionKeyUnusable().localizedDescription.contains("Details"))
    }
    #endif

    // MARK: settings and fields

    func testProfileFieldsParseAndValidateRequireAuth() throws {
        var p = Profile(id: "a", name: "A", type: .openvpn)
        XCTAssertTrue(ProfileFields.keys(for: .openvpn).contains("require_auth"))
        XCTAssertEqual(ProfileFields.value(p, key: "require_auth"), "off")
        try ProfileFields.set(&p, key: "require_auth", value: "always")
        XCTAssertEqual(p.requireAuth, .always)
        try ProfileFields.set(&p, key: "require-auth", value: " CONNECT ")
        XCTAssertEqual(p.requireAuth, .connect)
        try ProfileFields.set(&p, key: "auth", value: "off")
        XCTAssertEqual(p.requireAuth, .off)
        for bad in ["yes", "true", "", "touchid"] {
            XCTAssertThrowsError(try ProfileFields.set(&p, key: "require_auth", value: bad)) { error in
                XCTAssertEqual(error as? PTError, .invalidField("require_auth"))
            }
        }
        XCTAssertEqual(p.requireAuth, .off)
    }

    func testOldProfileWithoutTheKeyDecodesAsOff() throws {
        let old = try JSONCoding.decode(Profile.self, from: Data(#"{"id":"acme","name":"Acme","type":"openvpn"}"#.utf8))
        XCTAssertEqual(old.requireAuth, .off)
        let newer = try JSONCoding.decode(
            Profile.self,
            from: Data(#"{"id":"acme","name":"Acme","type":"openvpn","require_auth":"sometimes"}"#.utf8))
        XCTAssertEqual(newer.requireAuth, .off, "unknown values fall back to off")
        var p = old
        p.requireAuth = .always
        XCTAssertEqual(try JSONCoding.decode(Profile.self, from: try JSONCoding.encode(p)).requireAuth, .always)
        let text = String(decoding: try JSONCoding.encode(p), as: UTF8.self)
        XCTAssertTrue(text.contains("require_auth"), text)
    }

    func testReuseMinutesPreference() throws {
        XCTAssertEqual(Preferences().authReuseMinutes, 1)
        XCTAssertEqual(Preferences().authReuseInterval, 60)
        func decode(_ json: String) throws -> Preferences {
            try JSONCoding.decode(Preferences.self, from: Data(json.utf8))
        }
        XCTAssertEqual(try decode("{}").authReuseMinutes, 1)
        XCTAssertEqual(try decode(#"{"auth_reuse_minutes":15}"#).authReuseMinutes, 15)
        XCTAssertEqual(try decode(#"{"auth_reuse_minutes":7}"#).authReuseMinutes, 1, "only the offered choices")
        var prefs = Preferences()
        prefs.authReuseMinutes = 5
        XCTAssertEqual(try JSONCoding.decode(Preferences.self, from: try JSONCoding.encode(prefs)).authReuseMinutes, 5)
    }

    /// Share files leave the setting out: it is the user's own choice, like pinning.
    func testShareFileLeavesTheSettingOut() throws {
        var p = try store.create(name: "Acme", type: .forti)
        p.host = "vpn.example.com"
        p.requireAuth = .always
        try store.save(p)
        let url = home.appendingPathComponent("acme.passtunnel")
        try store.exportShare(p.id, to: url)
        XCTAssertFalse(try String(contentsOf: url, encoding: .utf8).contains("require_auth"))
        XCTAssertEqual(try store.importShare(url, name: "Copy").requireAuth, .off)
    }
}
