import PassTunnelShared
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelVPNConfig

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(Security)
import Security
#endif

// MARK: - Secrets bound to the destination

extension ConnectionManagerTests {
    func writeConfig(_ p: Profile, remote: String) throws {
        try Data("client\nremote \(remote) 1194\nauth-user-pass\n".utf8).write(to: store.ovpnURL(p.id))
    }

    /// A FortiGate profile with a saved password, protected with `requirement`.
    func makeProtectedForti(_ requirement: AuthRequirement = .connect, in m: ConnectionManager) async throws -> Profile {
        var plain = try store.create(name: "Acme Forti", type: .forti)
        plain.host = "vpn.example.com"
        plain.username = "alice"
        plain.autoReconnect = true
        plain.healthHost = "10.0.0.5"
        try store.save(plain)
        try Secrets.set(plain.id, .password, "pw")
        var p = plain
        p.requireAuth = requirement
        try await m.vault.applyProtection(from: plain, to: p)
        try store.save(p)
        helper.startLog = "INFO:   Got addresses: [10.212.134.200], ns [10.0.0.1]\nINFO:   Tunnel is up and running.\n"
        return p
    }

    func testChangedServerIsNotReconnectedWithTheSessionSecrets() async throws {
        let m = makeManager()
        let p = try await makeProtected("Acme", .always, in: m, otp: .totp, autoReconnect: true)
        try await m.connect(p.id)
        try await clock.sleep(300)  // past the reuse window: only the session's secrets are left
        try writeConfig(p, remote: "vpn2.example.com")
        await m.refresh()  // the poll sees the change
        helper.simulateExit(p.id)
        await m.refresh()

        XCTAssertEqual(events, [.destinationChanged(profileID: p.id)])
        XCTAssertNil(m.reconnecting[p.id], "no automatic reconnect")
        XCTAssertEqual(helper.starts.count, 1)
        XCTAssertEqual(authenticator.calls, 1, "no prompt out of the blue")

        // Connecting again asks, and the prompt names the new server.
        try await m.connect(p.id)
        XCTAssertEqual(authenticator.reasons.last, "connect to “Acme” (vpn2.example.com)")
        XCTAssertEqual(helper.starts.count, 2)
    }

    func testUnchangedServerKeepsReconnectingWithoutAPrompt() async throws {
        let m = makeManager()
        let p = try await makeProtected("Acme", .always, in: m, otp: .totp, autoReconnect: true)
        try await m.connect(p.id)
        try await clock.sleep(300)
        // Settings that do not decide where the secrets go.
        try store.update(p.id) {
            $0.name = "Acme Office"; $0.healthHost = "10.0.0.9"; $0.sessionLimitMin = 600
        }
        await m.refresh()
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events, [.dropped(profileID: p.id, willReconnect: true), .reconnected(profileID: p.id)])
        XCTAssertEqual(authenticator.calls, 1)
        XCTAssertEqual(helper.starts.count, 2)
    }

    /// The drop is handled before any poll saw the change: the reconnect itself refuses.
    func testReconnectRefusesAChangeTheWatcherHasNotSeenYet() async throws {
        let m = makeManager()
        let p = try await makeProtected("Acme", .always, in: m, otp: .totp, autoReconnect: true, healthHost: "10.0.0.5")
        try await m.connect(p.id)
        try await clock.sleep(300)
        try writeConfig(p, remote: "vpn2.example.com")
        healthResults = [false, false]
        await m.runHealthChecks()
        await m.runHealthChecks()  // outage: forced reconnect
        await waitUntil { self.events.contains(.destinationChanged(profileID: p.id)) }
        XCTAssertFalse(
            events.contains {
                if case .reconnectFailed = $0 { return true }; return false
            })
        XCTAssertEqual(helper.starts.count, 1, "nothing sent to the new server")
        XCTAssertEqual(authenticator.calls, 1)
    }

    func testHealthOutageAfterAChangeLeavesTheTunnelAlone() async throws {
        let m = makeManager()
        let p = try await makeProtectedForti(in: m)
        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
        try await clock.sleep(300)
        try store.update(p.id) {
            $0.host = "vpn2.example.com"; $0.trustedCert = String(repeating: "a", count: 64)
        }
        await m.refresh()
        healthResults = [false, false]
        await m.runHealthChecks()
        await m.runHealthChecks()
        XCTAssertEqual(events, [.unreachable(profileID: p.id), .destinationChanged(profileID: p.id, stillConnected: true)])
        XCTAssertEqual(helper.stops, [], "not stopped for a reconnect that cannot happen")
        XCTAssertTrue(m.state(p.id).isConnected, "the old tunnel is still up")
        XCTAssertEqual(helper.starts.count, 1)
        XCTAssertEqual(authenticator.calls, 1)
    }

    func testConnectAfterAChangeAsksAgainWithinTheReuseWindow() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m)
        try await m.connect(p.id)
        try await m.disconnect(p.id)
        try writeConfig(p, remote: "vpn2.example.com")
        try await m.connect(p.id)  // still within 60 s, but another server
        XCTAssertEqual(authenticator.calls, 2)
        XCTAssertEqual(authenticator.reasons.last, "connect to “Acme VPN” (vpn2.example.com)")

        try await m.disconnect(p.id)
        try await m.connect(p.id)  // unchanged now: the window applies again
        XCTAssertEqual(authenticator.calls, 2)
    }

    func testConfirmationsAreDroppedWhenTheFilesChange() async throws {
        let m = makeManager()
        let p = try await makeProtected("Acme", .always, in: m, otp: .totp)
        try await m.vault.unlock(p, for: .code)
        XCTAssertTrue(m.vault.isUnlocked(p.id, .totp))
        m.revalidateDestinations()
        XCTAssertTrue(m.vault.isUnlocked(p.id, .totp), "nothing changed")
        try writeConfig(p, remote: "vpn2.example.com")
        m.revalidateDestinations()
        XCTAssertFalse(m.vault.isUnlocked(p.id, .totp))
        XCTAssertFalse(m.vault.isUnlocked(p.id, .password))
    }

    // MARK: the helper re-reads config.ovpn

    func testStartRequestCarriesTheHashOfTheCheckedConfig() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        try await m.connect(p.id)
        guard case .startOpenVPN(let s) = helper.starts.first else { return XCTFail("no start") }
        let data = try Data(contentsOf: store.ovpnURL(p.id))
        XCTAssertEqual(s.configSHA256, HelperCore.sha256Hex(data))
        XCTAssertEqual(s.configSHA256, ProfileDestination.of(p, store: store).configSHA256)
    }

    /// The file is replaced between the app's check (and the user's confirmation) and the helper's read.
    func testConfigSwappedBeforeTheHelperReadsItIsRefused() async throws {
        let m = makeManager()
        let p = try await makeProtected("Acme", .always, in: m)
        var swapped = false
        helper.onStart = { [store] _ in
            guard !swapped else { return }
            swapped = true
            try? Data("client\nremote vpn2.example.com 1194\nauth-user-pass\n".utf8).write(to: store.ovpnURL(p.id))
        }
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? DestinationChangedError, DestinationChangedError(host: "vpn.example.com"))
        }
        XCTAssertEqual(helper.running, [:], "nothing started")
        XCTAssertEqual(m.state(p.id), .disconnected)
        XCTAssertEqual(m.lastError[p.id], DestinationChangedError(host: "").localizedDescription)
        XCTAssertFalse(ConnectionManager.isRetryable(DestinationChangedError(host: "")))

        // Connecting again confirms the new server.
        try await m.connect(p.id)
        XCTAssertEqual(authenticator.calls, 2)
        XCTAssertEqual(authenticator.reasons.last, "connect to “Acme” (vpn2.example.com)")
        XCTAssertTrue(m.state(p.id).isConnected)
    }

    func testConfigSwappedDuringAnAutomaticReconnectStopsIt() async throws {
        let m = makeManager()
        let p = try await makeProtected("Acme", .always, in: m, otp: .totp, autoReconnect: true)
        try await m.connect(p.id)
        try await clock.sleep(300)
        helper.onStart = { [store] _ in
            try? Data("client\nremote vpn2.example.com 1194\nauth-user-pass\n".utf8).write(to: store.ovpnURL(p.id))
        }
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { self.events.contains(.destinationChanged(profileID: p.id)) }
        XCTAssertEqual(events, [.dropped(profileID: p.id, willReconnect: true), .destinationChanged(profileID: p.id)])
        XCTAssertNil(m.reconnecting[p.id])
        XCTAssertEqual(helper.starts.count, 2, "one refused attempt, no retries")
        XCTAssertEqual(helper.running, [:])
        XCTAssertEqual(authenticator.calls, 1, "no prompt out of the blue")
    }

    func testDestinationFingerprint() throws {
        var forti = Profile(id: "acme", name: "Acme", type: .forti)
        forti.host = "vpn.example.com"
        let base = ProfileDestination.of(forti, store: store)
        XCTAssertEqual(base.host, "vpn.example.com")
        XCTAssertEqual(base.fingerprint.count, 64)
        var same = forti
        same.name = "Renamed"
        same.setDNS.toggle()
        same.host = " VPN.example.com "
        XCTAssertEqual(ProfileDestination.of(same, store: store).fingerprint, base.fingerprint)
        let changes: [(inout Profile) -> Void] = [
            { $0.host = "vpn2.example.com" }, { $0.port = 10443 }, { $0.trustedCert = String(repeating: "b", count: 64) }
        ]
        for change in changes {
            var other = forti
            change(&other)
            XCTAssertNotEqual(ProfileDestination.of(other, store: store).fingerprint, base.fingerprint)
        }

        // The trusted certificate as typed or pasted ("AB:CD:…") and as the editor saves it (lowercase
        // hex) is the same destination.
        let hex = (0..<32).map { String(format: "%02x", $0 * 7 % 256) }.joined()
        var saved = forti
        saved.trustedCert = hex
        let pinned = ProfileDestination.of(saved, store: store).fingerprint
        XCTAssertNotEqual(pinned, base.fingerprint)
        let pairs = stride(from: 0, to: 64, by: 2).map { hex.dropFirst($0).prefix(2).uppercased() }
        for typed in [pairs.joined(separator: ":"), " " + pairs.joined(separator: " ") + "\n", hex.uppercased()] {
            var other = forti
            other.trustedCert = typed
            XCTAssertEqual(ProfileDestination.of(other, store: store).fingerprint, pinned, typed)
        }

        let ovpn = try makeOpenVPN()
        let before = ProfileDestination.of(ovpn, store: store)
        XCTAssertEqual(before.host, "vpn.example.com")
        try Data("client\nremote vpn.example.com 1194\nauth-user-pass\n\n".utf8).write(to: store.ovpnURL(ovpn.id))
        XCTAssertNotEqual(ProfileDestination.of(ovpn, store: store).fingerprint, before.fingerprint, "every byte counts")
        try Data("client\nremote vpn.example.com 1194\nremote vpn2.example.com\nauth-user-pass\n".utf8).write(to: store.ovpnURL(ovpn.id))
        XCTAssertEqual(ProfileDestination.of(ovpn, store: store).host, "vpn.example.com +1 more", "the prompt shows there are others")
        try FileManager.default.removeItem(at: store.ovpnURL(ovpn.id))
        XCTAssertEqual(ProfileDestination.of(ovpn, store: store).host, "")
    }
}

// MARK: - Keychain items, protection key, new profiles, share files

final class SecretHardeningTests: CoreTestCase {
    var auth: FakeAuthenticator!

    override func setUpWithError() throws {
        try super.setUpWithError()
        auth = FakeAuthenticator()
    }

    // The Keychain's own rules (macOS).
    #if os(macOS)
    func label(_ account: String) -> String? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service!,
            kSecAttrAccount as String: account, kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return (out as? [String: Any])?[kSecAttrLabel as String] as? String
    }

    func plant(_ account: String, _ value: String) {
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service!,
            kSecAttrAccount as String: account, kSecAttrLabel as String: "planted",
            kSecValueData as String: Data(value.utf8)
        ]
        XCTAssertEqual(SecItemAdd(add as CFDictionary, nil), errSecSuccess)
    }

    /// An item someone else created first is removed and created anew, never written into.
    func testWritingReplacesAnExistingItem() throws {
        plant("acme/password", "x")
        try Secrets.set("acme", .password, "s3cret")
        XCTAssertEqual(label("acme/password"), "PassTunnel (acme/password)")
        XCTAssertEqual(Secrets.get("acme", .password), "s3cret")
        try Secrets.set("acme", .password, "again")  // and again over its own item
        XCTAssertEqual(Secrets.get("acme", .password), "again")
    }
    #endif

    @MainActor func makeVault() -> SecretVault {
        SecretVault(authenticator: auth, reuseWindow: { 60 })
    }

    @MainActor func protectedProfile(_ vault: SecretVault) async throws -> Profile {
        var p = try store.create(name: "Acme", type: .openvpn)
        p.otpMode = .totp
        try store.save(p)
        try Secrets.set(p.id, .password, "pw")
        var protected = p
        protected.requireAuth = .always
        try await vault.applyProtection(from: p, to: protected)
        try store.save(protected)
        return protected
    }

    /// Replaces the record's public key with another key's: as if the record had been planted.
    func swapRecordPublicKey(_ id: String) throws {
        var record = try XCTUnwrap(Secrets.protectionKey(id).flatMap(ProtectionKeyRecord.decode))
        record.pub = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        try Secrets.setProtectionKey(id, try record.encoded())
    }

    @MainActor func testKeyRecordForAnotherKeyIsNeverUsed() async throws {
        let vault = makeVault()
        let p = try await protectedProfile(vault)
        let stored = Secrets.raw(p.id, .password)
        try swapRecordPublicKey(p.id)

        do {
            _ = try await vault.secret(p, .password, for: .connect)
            XCTFail("expected a mismatch")
        } catch {
            XCTAssertEqual(error as? ProtectionKeyMismatch, ProtectionKeyMismatch(profileID: p.id))
        }
        XCTAssertEqual(auth.calls, 0, "refused before asking")
        XCTAssertEqual(Secrets.raw(p.id, .password), stored, "nothing removed")

        XCTAssertThrowsError(try vault.store(p, .totp, "JBSWY3DPEHPK3PXP")) { error in
            XCTAssertTrue(error is ProtectionKeyMismatch)
        }
        XCTAssertFalse(Secrets.has(p.id, .totp), "nothing encrypted to the unknown key")
    }

    @MainActor func testUnlockedKeyIsCheckedAgainstTheRecord() async throws {
        let vault = makeVault()
        let p = try await protectedProfile(vault)
        try swapRecordPublicKey(p.id)
        auth.canReadPublicKey = false  // only the unlocked key tells
        do {
            _ = try await vault.secret(p, .password, for: .connect)
            XCTFail("expected a mismatch")
        } catch {
            XCTAssertTrue(error is ProtectionKeyMismatch, "\(error)")
        }
        XCTAssertEqual(auth.calls, 1)
        XCTAssertFalse(vault.isUnlocked(p.id, .password))
    }

    func testNewProfileDoesNotInheritOrphanedItems() throws {
        try Secrets.set("acme", .password, "left over")
        try Secrets.set("acme", .totp, "JBSWY3DPEHPK3PXP")
        try Secrets.setProtectionKey("acme", "{}")
        let p = try store.create(name: "Acme", type: .openvpn)
        XCTAssertEqual(p.id, "acme")
        XCTAssertFalse(Secrets.has(p.id, .password))
        XCTAssertFalse(Secrets.has(p.id, .totp))
        XCTAssertNil(Secrets.protectionKey(p.id))

        // Imports create their profiles the same way; an existing profile keeps its items.
        try Secrets.set("acme-2", .password, "left over")
        try Secrets.set(p.id, .password, "mine")
        let imported = try store.importOVPN(try write("client\nremote vpn.example.com\nauth-user-pass\n", name: "Acme.ovpn"), name: nil)
        XCTAssertEqual(imported.id, "acme-2")
        XCTAssertFalse(Secrets.has(imported.id, .password))
        XCTAssertEqual(Secrets.get(p.id, .password), "mine")
    }

    // MARK: share files and inline credentials

    let signIn = "<auth-user-pass>\nalice\ns3cret pw\n</auth-user-pass>\n"
    let proxy = "http-proxy proxy.example.com 8080\n<http-proxy-user-pass>\nbob\nproxy-pw\n</http-proxy-user-pass>\n"
    let key = "<key>\n-----BEGIN PRIVATE KEY-----\nMIIBCC==\n-----END PRIVATE KEY-----\n</key>\n"

    func testImportMovesAnInlineSignInToTheProfileAndKeychain() throws {
        let url = try write("client\nremote vpn.example.com 1194\n" + signIn + key, name: "acme.ovpn")
        let p = try store.importOVPN(url, name: nil)
        XCTAssertEqual(p.username, "alice")
        XCTAssertEqual(p.passwordMode, .keychain)
        XCTAssertEqual(try store.get(p.id).username, "alice")
        XCTAssertEqual(Secrets.get(p.id, .password), "s3cret pw")
        let config = try String(contentsOf: store.ovpnURL(p.id), encoding: .utf8)
        XCTAssertFalse(config.contains("s3cret"))
        XCTAssertFalse(config.contains("alice"))
        XCTAssertFalse(config.contains("<auth-user-pass>"))
        XCTAssertTrue(config.contains("\nauth-user-pass\n"))
        XCTAssertTrue(config.contains("<key>"), "keys stay")
        XCTAssertNoThrow(try OVPNSanitizer.sanitize(config))

        // Replacing the config of a profile stores no sign-in either (the editor offers it instead).
        try store.setOVPN(p.id, from: try write("client\nremote vpn2.example.com\n" + signIn, name: "new.ovpn"))
        XCTAssertFalse(try String(contentsOf: store.ovpnURL(p.id), encoding: .utf8).contains("s3cret"))
    }

    func testShareFilesNeverContainUserNamesOrPasswords() throws {
        var p = try store.create(name: "Acme", type: .openvpn)
        p.username = "alice"
        try store.save(p)
        // As stored by older versions, which kept the blocks.
        try Data(("client\nremote vpn.example.com 1194\nauth-user-pass [inline]\n" + signIn + proxy + key).utf8)
            .write(to: store.ovpnURL(p.id))
        let url = home.appendingPathComponent("acme.passtunnel")
        try store.exportShare(p.id, to: url)
        let raw = try String(contentsOf: url, encoding: .utf8)
        XCTAssertFalse(raw.contains("alice"))
        let shared = try ShareFile.read(from: url)
        let config = String(decoding: try XCTUnwrap(shared.files["config.ovpn"]), as: UTF8.self)
        for secret in ["alice", "s3cret", "bob", "proxy-pw", "user-pass>", "[inline]"] {
            XCTAssertFalse(config.contains(secret), secret)
        }
        XCTAssertTrue(config.contains("http-proxy proxy.example.com 8080"))
        XCTAssertTrue(config.contains("<key>"), "keys are part of a share, as documented")
        XCTAssertTrue(config.contains("\nauth-user-pass"))
        XCTAssertNoThrow(try OVPNSanitizer.sanitize(config))
    }

    func testImportingAShareDropsAnEmbeddedSignIn() throws {
        let config = "client\nremote vpn.example.com 1194\n" + signIn
        let share = ShareFile(profile: Profile(id: "x", name: "Acme", type: .openvpn), files: ["config.ovpn": Data(config.utf8)])
        let url = home.appendingPathComponent("old.passtunnel")
        try share.write(to: url)
        let p = try store.importShare(url, name: nil)
        XCTAssertEqual(p.username, "")
        XCTAssertFalse(Secrets.has(p.id, .password), "someone else's sign-in is not kept")
        XCTAssertFalse(try String(contentsOf: store.ovpnURL(p.id), encoding: .utf8).contains("s3cret"))
    }

    func testStrippingCredentials() {
        let plain = "client\r\nremote vpn.example.com\r\n<ca>\r\n<auth-user-pass>\r\n</ca>\r\n"
        let untouched = OVPNInliner.strippingCredentials(plain)
        XCTAssertEqual(untouched.text, plain, "byte for byte when there is nothing to remove")
        XCTAssertEqual(untouched.removed, [])

        let text =
            "client\n--auth-user-pass [inline]\n<auth-user-pass>\r\nalice\r\npw\r\n</auth-user-pass>\n"
            + "http-proxy-user-pass [inline]\n" + proxy + "remote vpn.example.com\n"
        let all = OVPNInliner.strippingCredentials(text)
        XCTAssertEqual(all.text, "client\nauth-user-pass\nauth-user-pass\nhttp-proxy proxy.example.com 8080\nremote vpn.example.com\n")
        XCTAssertEqual(all.username, "alice")
        XCTAssertEqual(all.password, "pw")
        XCTAssertEqual(all.removed, [.authUserPass, .httpProxyUserPass])

        let signInOnly = OVPNInliner.strippingCredentials(text, blocks: [.authUserPass])
        XCTAssertTrue(signInOnly.text.contains("<http-proxy-user-pass>\nbob\nproxy-pw\n</http-proxy-user-pass>"))
        XCTAssertFalse(signInOnly.text.contains("alice"))

        let unterminated = OVPNInliner.strippingCredentials("client\n<auth-user-pass>\nalice\npw\n")
        XCTAssertEqual(unterminated.text, "client\nauth-user-pass")
    }
}
