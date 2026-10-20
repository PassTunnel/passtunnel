import Foundation
import XCTest
@testable import PassTunnelCore
import PassTunnelShared

final class PathsAndSlugTests: CoreTestCase {
    func testEnvironmentIsReadAtCallTime() {
        let other = home.appendingPathComponent("other")
        setenv("PASSTUNNEL_HOME", other.path, 1)
        XCTAssertEqual(AppPaths.default.root.path, other.standardizedFileURL.path)
        XCTAssertEqual(AppPaths.default.configURL.lastPathComponent, "config.json")
        XCTAssertEqual(AppPaths.default.profileDir("acme").path, other.appendingPathComponent("profiles/acme").path)
        setenv("PASSTUNNEL_HOME", home.path, 1)
        XCTAssertEqual(Env.keychainService, service)
        XCTAssertNotEqual(Env.keychainService, PT.keychainService)
    }

    func testSlug() {
        XCTAssertEqual(Slug.make("Acme"), "acme")
        XCTAssertEqual(Slug.make("Şirket VPN İç Ağ"), "sirket-vpn-ic-ag")
        XCTAssertEqual(Slug.make("IĞDIR ÇÖZÜM ışık"), "igdir-cozum-isik")
        XCTAssertEqual(Slug.make("  Acme -- Prod (EU) "), "acme-prod-eu")
        XCTAssertEqual(Slug.make("Café Zoë"), "cafe-zoe")
        XCTAssertEqual(Slug.make("../../etc/passwd"), "etc-passwd")
        XCTAssertEqual(Slug.make("!!!"), "")
        XCTAssertEqual(Slug.make(String(repeating: "a", count: 100)).count, Slug.maxIDLength)
        XCTAssertEqual(Slug.make("Acme Office VPN With A Long Name"), "acme-office-vpn-with-a-l")
        XCTAssertEqual(Slug.suffixed(String(repeating: "a", count: 24), 2), String(repeating: "a", count: 22) + "-2")
        XCTAssertEqual(Slug.suffixed("acme-office-vpn-with-a-l", 12), "acme-office-vpn-with-12")
        XCTAssertTrue(Slug.isValid(String(repeating: "a", count: 40)))   // older, longer ids still load
        XCTAssertTrue(Slug.isValid("acme-2"))
        for bad in ["", "-a", "a-", "a--b", "A", "a/b", "..", "a b", "ş"] { XCTAssertFalse(Slug.isValid(bad), bad) }
    }
}

final class ModelTests: CoreTestCase {
    func decode(_ json: String) throws -> Profile {
        try JSONCoding.decode(Profile.self, from: Data(json.utf8))
    }

    func testMinimalFileDecodesWithDefaults() throws {
        let p = try decode(#"{"id":"acme","name":"Acme","type":"openvpn"}"#)
        var expected = Profile(id: "acme", name: "Acme", type: .openvpn)
        expected.otpDelivery = .combined
        XCTAssertEqual(p, expected)
        XCTAssertEqual(p.port, 443)
        XCTAssertTrue(p.setRoutes)
        XCTAssertEqual(p.otpTemplate, "{password}{otp}")
        XCTAssertEqual(try decode("{}").type, .openvpn)
    }

    func testUnknownValuesAndKeysAreTolerated() throws {
        let p = try decode(#"{"id":"x","name":"X","type":"forti","badge_style":"sparkle","otp_mode":"push","port":"oops","future_key":[1,2],"totp":{"digits":8}}"#)
        XCTAssertEqual(p.type, .forti)
        XCTAssertEqual(p.badgeStyle, .letter)
        XCTAssertEqual(p.otpMode, .none)
        XCTAssertEqual(p.port, 443)
        XCTAssertEqual(p.totp, TOTPParams(digits: 8, period: 30, algorithm: .sha1))
        XCTAssertEqual(p.otpDelivery, .separate)
    }

    func testLegacyOTPFormat() throws {
        XCTAssertEqual(try decode(#"{"type":"openvpn","otp_format":"scrv1"}"#).otpDelivery, .separate)
        let p = try decode(#"{"type":"openvpn","otp_format":"append"}"#)
        XCTAssertEqual(p.otpDelivery, .combined)
        XCTAssertEqual(p.otpTemplate, "{password}{otp}")
        XCTAssertEqual(try decode(#"{"otp_format":"scrv1","otp_delivery":"combined"}"#).otpDelivery, .combined)
    }

    func testEncodingIsSnakeCaseSortedAndRoundTrips() throws {
        var p = Profile(id: "acme", name: "Acme", type: .forti)
        p.setDNS = true
        p.mgmtPort = 27505
        p.trustedCert = "abc"
        p.totp = TOTPParams(digits: 7, period: 60, algorithm: .sha512)
        let data = try JSONCoding.encode(p)
        let text = String(data: data, encoding: .utf8)!
        XCTAssertTrue(text.contains(#""set_dns" : true"#))
        XCTAssertTrue(text.contains(#""mgmt_port" : 27505"#))
        XCTAssertTrue(text.contains(#""otp_delivery""#))
        XCTAssertFalse(text.contains("otp_format"))
        XCTAssertFalse(text.contains("display_badge"))
        XCTAssertLessThan(text.range(of: "\"badge\"")!.lowerBound, text.range(of: "\"type\"")!.lowerBound)
        XCTAssertEqual(try JSONCoding.decode(Profile.self, from: data), p)
    }

    func testDisplayBadge() {
        var p = Profile(id: "acme", name: "acme", type: .openvpn)
        XCTAssertEqual(p.displayBadge, "A")
        p.name = "  şirket"
        XCTAssertEqual(p.displayBadge, "Ş")
        p.badge = "AC"
        XCTAssertEqual(p.displayBadge, "AC")
        p.badge = ""; p.name = ""
        XCTAssertEqual(p.displayBadge, "?")
    }

    func testNeedsAndUnattended() {
        var p = Profile(id: "acme", name: "Acme", type: .openvpn)
        XCTAssertEqual(p.needs, [.username])
        XCTAssertFalse(p.unattended)
        p.username = "alice"
        p.otpMode = .totp
        XCTAssertEqual(p.needs, [])
        XCTAssertTrue(p.unattended)
        p.passwordMode = .ask
        p.otpMode = .ask
        XCTAssertEqual(p.needs, [.password, .otp])
        p.username = ""
        XCTAssertEqual(p.needs, [.username, .password, .otp])
        p.passwordMode = .none
        XCTAssertEqual(p.needs, [])
        XCTAssertTrue(p.unattended)
    }

    func testErrorsHaveMessages() {
        let all: [PTError] = [.profileNotFound("acme"), .invalidProfileID("x"), .emptyName, .invalidField("port"),
                              .wrongProfileType("acme"), .fileError("/x"), .fileTooLarge("x"), .invalidFile("x"),
                              .keychain(-25300), .invalidSecret, .invalidOTPAuthURI("x"), .hotpNotSupported,
                              .invalidTemplate("x"), .unsupportedShareFile,
                              .missingPassword("a"), .missingTOTPSecret("a"), .missingCredential(.otp),
                              .missingConfig("a"), .missingHost("a"), .helperFailed("x"), .authFailed("x"),
                              .connectFailed("x"), .connectTimeout(60), .connectCancelled]
        for e in all {
            XCTAssertFalse((e.errorDescription ?? "").isEmpty)
            XCTAssertFalse(e.localizedDescription.contains("PassTunnelCore.PTError"))
        }
        XCTAssertTrue(PTError.profileNotFound("acme").localizedDescription.contains("acme"))
    }
}

final class JSONAndPreferencesTests: CoreTestCase {
    func testAtomicWriteSetsModeAndLeavesNoTemp() throws {
        let url = home.appendingPathComponent("sub/file.json")
        try JSONCoding.write(["a_b": 1], to: url, mode: 0o600)
        XCTAssertEqual(try mode(url), 0o600)
        try JSONCoding.write(["a_b": 2], to: url, mode: 0o644)
        XCTAssertEqual(try mode(url), 0o644)
        XCTAssertEqual(try JSONCoding.read([String: Int].self, from: url), ["a_b": 2])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: url.deletingLastPathComponent().path), ["file.json"])
    }

    func testPreferencesDefaults() throws {
        let p = Preferences.load()
        XCTAssertEqual(p, Preferences())
        XCTAssertNil(p.defaultProfile)
        XCTAssertEqual(p.sessionWarnMin, 30)
        XCTAssertEqual(p.sessionNotifyMin, 10)
        XCTAssertFalse(p.hotkeys)
        XCTAssertFalse(p.autoType)
        XCTAssertTrue(p.launchAtLogin)
        XCTAssertFalse(p.autoUpdate)
    }

    func testPreferencesPartialFileAndRoundTrip() throws {
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try Data(#"{"default_profile":"acme","session_warn_min":45,"theme":"neon","hotkeys":true}"#.utf8)
            .write(to: AppPaths.default.configURL)
        var p = Preferences.load()
        XCTAssertEqual(p.defaultProfile, "acme")
        XCTAssertEqual(p.sessionWarnMin, 45)
        XCTAssertEqual(p.appearance, .system)
        XCTAssertTrue(p.hotkeys)
        XCTAssertTrue(p.launchAtLogin)
        p.appearance = .dark
        p.autoType = true
        try p.save()
        XCTAssertEqual(Preferences.load(), p)
        let text = try String(contentsOf: AppPaths.default.configURL)
        XCTAssertTrue(text.contains("\"launch_at_login\""))
        XCTAssertTrue(text.contains("\"session_notify_min\""))
    }

    func testPreferencesNewFieldsAndLegacyTheme() throws {
        let d = Preferences()
        XCTAssertEqual(d.badgePalette, .pastel)
        XCTAssertEqual(d.appearance, .system)
        XCTAssertTrue(d.showLock)
        XCTAssertFalse(d.hideCodes)
        XCTAssertFalse(d.showInDock)
        XCTAssertTrue(d.notifyOnDrop)
        XCTAssertTrue(d.notifyHealth)
        XCTAssertEqual(d.sessionNotifyMin, 10)

        try Data(#"{"theme":"dark","badge_palette":"earth","hide_codes":true,"notify_health":false,"session_notify_min":-4}"#.utf8)
            .write(to: AppPaths.default.configURL)
        var p = Preferences.load()
        XCTAssertEqual(p.appearance, .dark)
        XCTAssertEqual(p.badgePalette, .earth)
        XCTAssertTrue(p.hideCodes)
        XCTAssertFalse(p.notifyHealth)
        XCTAssertEqual(p.sessionNotifyMin, 0)

        // "appearance" wins over the legacy key; unknown palettes fall back.
        try Data(#"{"theme":"dark","appearance":"light","badge_palette":"neon","show_in_dock":true}"#.utf8)
            .write(to: AppPaths.default.configURL)
        p = Preferences.load()
        XCTAssertEqual(p.appearance, .light)
        XCTAssertEqual(p.badgePalette, .pastel)
        XCTAssertTrue(p.showInDock)
        try p.save()
        let text = try String(contentsOf: AppPaths.default.configURL)
        XCTAssertTrue(text.contains(#""appearance" : "light""#))
        XCTAssertFalse(text.contains("theme"))
        XCTAssertEqual(Preferences.load(), p)
    }

    func testBadgePalettes() {
        XCTAssertEqual(BadgePalette.allCases.map(\.rawValue), ["pastel", "vivid", "soft", "candy", "earth"])
        for palette in BadgePalette.allCases {
            let colors = BadgeTone.allCases.map(palette.color)
            XCTAssertEqual(Set(colors).count, 3, "\(palette)")
            XCTAssertFalse(palette.displayName.isEmpty)
        }
        XCTAssertEqual(RGBColor(52, 199, 89).hex, "#34C759")
        XCTAssertEqual(RGBColor(255, 0, 0).components.red, 1)
    }

    func testCorruptPreferencesFallBackToDefaults() throws {
        try Data("not json".utf8).write(to: AppPaths.default.configURL)
        XCTAssertEqual(Preferences.load(), Preferences())
    }
}

final class SecretsTests: CoreTestCase {
    func testRoundTripUpdateDelete() throws {
        XCTAssertNil(Secrets.get("acme", .password))
        try Secrets.set("acme", .password, "first")
        XCTAssertEqual(Secrets.get("acme", .password), "first")
        try Secrets.set("acme", .password, "second")
        XCTAssertEqual(Secrets.get("acme", .password), "second")
        XCTAssertNil(Secrets.get("acme", .totp))
        try Secrets.set("acme", .totp, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(Secrets.get("acme", .totp), "JBSWY3DPEHPK3PXP")
        Secrets.delete("acme", .password)
        XCTAssertNil(Secrets.get("acme", .password))
        XCTAssertEqual(Secrets.get("acme", .totp), "JBSWY3DPEHPK3PXP")
    }

    func testTurkishAndUnicodeValues() throws {
        let value = "Şifre-ğüşıöç-İĞÜŞÖÇ-€-🔒"
        try Secrets.set("acme", .password, value)
        XCTAssertEqual(Secrets.get("acme", .password), value)
    }

    func testUsesOverriddenService() throws {
        try Secrets.set("acme", .password, "x")
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service!,
                                kSecAttrAccount as String: "acme/password",
                                kSecReturnData as String: true]
        var out: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(q as CFDictionary, &out), errSecSuccess)
        XCTAssertEqual(out as? Data, Data("x".utf8))
    }
}

final class OVPNAnalyzerTests: CoreTestCase {
    func testCertificateOnly() {
        let a = OVPNAnalyzer.analyze("""
        client
        dev tun
        # auth-user-pass
        ; static-challenge "Code" 1
        remote vpn.example.com 1194 udp
        <ca>
        auth-user-pass
        remote evil.example.com
        </ca>
        """)
        XCTAssertEqual(a.passwordMode, .none)
        XCTAssertEqual(a.otpMode, .none)
        XCTAssertEqual(a.otpDelivery, .combined)
        XCTAssertEqual(a.remote, "vpn.example.com")
    }

    func testPasswordOnly() {
        let a = OVPNAnalyzer.analyze("client\r\n  auth-user-pass\r\nremote 203.0.113.5 443 tcp\r\nremote vpn2.example.com\r\n")
        XCTAssertEqual(a.passwordMode, .keychain)
        XCTAssertEqual(a.otpMode, .none)
        XCTAssertEqual(a.otpDelivery, .combined)
        XCTAssertEqual(a.remote, "203.0.113.5")
    }

    func testStaticChallenge() {
        let a = OVPNAnalyzer.analyze("""
        <tls-auth>
        -----BEGIN OpenVPN Static key V1-----
        remote nope.example.com
        -----END OpenVPN Static key V1-----
        </tls-auth>
        AUTH-USER-PASS
        static-challenge "Enter code" 1
        <connection>
        remote vpn.example.com 1194
        </connection>
        """)
        XCTAssertEqual(a.passwordMode, .keychain)
        XCTAssertEqual(a.otpMode, .ask)
        XCTAssertEqual(a.otpDelivery, .separate)
        XCTAssertEqual(a.remote, "vpn.example.com")
    }

    func testNoRemote() {
        XCTAssertEqual(OVPNAnalyzer.analyze("").remote, "")
    }
}

final class ProfileStoreTests: CoreTestCase {
    func testCreateAssignsUniqueIDs() throws {
        let a = try store.create(name: "Acme", type: .openvpn)
        let b = try store.create(name: "acme", type: .openvpn)
        let f = try store.create(name: "ACME", type: .forti)
        let c = try store.create(name: "Şirket İç", type: .openvpn)
        XCTAssertEqual([a.id, b.id, f.id, c.id], ["acme", "acme-2", "acme-3", "sirket-ic"])
        XCTAssertEqual([a.mgmtPort, b.mgmtPort, f.mgmtPort, c.mgmtPort], [0, 0, 0, 0])
        XCTAssertEqual(a.otpDelivery, .combined)
        XCTAssertEqual(f.otpDelivery, .separate)
        XCTAssertEqual([a.order, b.order, f.order, c.order], [0, 1, 2, 3])
        XCTAssertEqual(try store.get("acme-2"), b)
        XCTAssertEqual(try store.create(name: "%%%", type: .forti).id, "profile")
    }

    func testLongNamesGiveShortUniqueIDs() throws {
        let name = "Acme Corporation Headquarters Office VPN"
        var ids: [String] = []
        for _ in 0..<12 { ids.append(try store.create(name: name, type: .openvpn).id) }
        XCTAssertEqual(Set(ids).count, ids.count)
        XCTAssertTrue(ids.allSatisfy { $0.count <= Slug.maxIDLength && Slug.isValid($0) }, "\(ids)")
        XCTAssertEqual(ids[0], "acme-corporation-headqua")
        XCTAssertEqual(ids[1], "acme-corporation-headq-2")
        XCTAssertEqual(ids[11], "acme-corporation-head-12")
    }

    func testLegacyMgmtPortStillDecodes() throws {
        var p = try store.create(name: "Acme", type: .openvpn)
        XCTAssertEqual(p.mgmtPort, 0)
        p.mgmtPort = 17505
        try store.save(p)
        XCTAssertEqual(try store.get("acme").mgmtPort, 17505)
    }

    func testListSortedByOrderThenName() throws {
        var z = try store.create(name: "Zulu", type: .forti)
        var a = try store.create(name: "Alpha", type: .forti)
        var m = try store.create(name: "Mike", type: .forti)
        z.order = 0; a.order = 1; m.order = 1
        try store.save(z); try store.save(a); try store.save(m)
        XCTAssertEqual(store.list().map(\.id), ["zulu", "alpha", "mike"])
    }

    func testListSkipsDamagedAndIDFollowsDirectory() throws {
        _ = try store.create(name: "Acme", type: .openvpn)
        let broken = store.dir("broken")
        try FileManager.default.createDirectory(at: broken, withIntermediateDirectories: true)
        try Data("{".utf8).write(to: broken.appendingPathComponent("profile.json"))
        let moved = store.dir("moved")
        try FileManager.default.createDirectory(at: moved, withIntermediateDirectories: true)
        try Data(#"{"id":"other","name":"","type":"forti"}"#.utf8).write(to: moved.appendingPathComponent("profile.json"))
        XCTAssertEqual(store.list().map(\.id), ["acme", "moved"])
        XCTAssertEqual(try store.get("moved").name, "moved")
    }

    func testSaveValidation() throws {
        var p = try store.create(name: "Acme", type: .openvpn)
        p.name = "Acme Prod"
        p.username = "alice"
        try store.save(p)
        XCTAssertEqual(try store.get("acme"), p)

        var bad = p; bad.name = "  "
        assertThrows(.emptyName) { try store.save(bad) }
        bad = p; bad.totp.digits = 9
        assertThrows(.invalidField("totp.digits")) { try store.save(bad) }
        bad = p; bad.port = 0
        assertThrows(.invalidField("port")) { try store.save(bad) }
        bad = p; bad.id = "../evil"
        assertThrows(.invalidProfileID("../evil")) { try store.save(bad) }
        bad = p; bad.otpMode = .totp; bad.otpTemplate = "{password}"
        XCTAssertThrowsError(try store.save(bad))
        bad.otpDelivery = .separate
        XCTAssertNoThrow(try store.save(bad))
        assertThrows(.emptyName) { _ = try store.create(name: " \n", type: .openvpn) }
    }

    func testGetErrors() {
        assertThrows(.profileNotFound("nope")) { _ = try store.get("nope") }
        assertThrows(.invalidProfileID("../x")) { _ = try store.get("../x") }
        assertThrows(.profileNotFound("nope")) { try store.delete("nope") }
    }

    func testDeleteRemovesDirSecretsAndDefault() throws {
        let a = try store.create(name: "Acme", type: .openvpn)
        let b = try store.create(name: "Beta", type: .openvpn)
        try Secrets.set(a.id, .password, "pw")
        try Secrets.set(a.id, .totp, "JBSWY3DPEHPK3PXP")
        try Secrets.set(b.id, .password, "keep")
        try store.setDefault(a.id)
        XCTAssertEqual(store.defaultID, "acme")
        try store.delete(a.id)
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.dir(a.id).path))
        XCTAssertNil(Secrets.get(a.id, .password))
        XCTAssertNil(Secrets.get(a.id, .totp))
        XCTAssertEqual(Secrets.get(b.id, .password), "keep")
        XCTAssertNil(store.defaultID)
        XCTAssertNil(Preferences.load().defaultProfile)
    }

    func testDefaultProfile() throws {
        XCTAssertNil(store.defaultID)
        assertThrows(.profileNotFound("acme")) { try store.setDefault("acme") }
        _ = try store.create(name: "Acme", type: .forti)
        try store.setDefault("acme")
        XCTAssertEqual(store.defaultID, "acme")
        try store.setDefault(nil)
        XCTAssertNil(store.defaultID)
    }

    func testFilePermissions() throws {
        let p = try store.create(name: "Acme", type: .openvpn)
        let src = try write("client\nremote vpn.example.com\n", name: "in.ovpn")
        try store.setOVPN(p.id, from: src)
        XCTAssertEqual(try mode(store.ovpnURL(p.id)), 0o600)
        XCTAssertEqual(try mode(store.dir(p.id)), 0o700)
        XCTAssertEqual(try String(contentsOf: store.ovpnURL(p.id)), "client\nremote vpn.example.com\n")
        let f = try store.create(name: "Forti", type: .forti)
        assertThrows(.wrongProfileType("forti")) { try store.setOVPN(f.id, from: src) }
    }

    func testImportOVPN() throws {
        let url = try write("client\nauth-user-pass\nstatic-challenge \"Code\" 1\nremote vpn.example.com 1194\n",
                            name: "Acme Office.ovpn")
        let p = try store.importOVPN(url, name: nil)
        XCTAssertEqual(p.id, "acme-office")
        XCTAssertEqual(p.name, "Acme Office")
        XCTAssertEqual(p.passwordMode, .keychain)
        XCTAssertEqual(p.otpMode, .ask)
        XCTAssertEqual(p.otpDelivery, .separate)
        XCTAssertEqual(try store.get(p.id), p)
        XCTAssertEqual(try mode(store.ovpnURL(p.id)), 0o600)

        let cert = try write("client\nremote vpn.example.com\n<key>\nauth-user-pass\n</key>\n", name: "c.ovpn")
        let q = try store.importOVPN(cert, name: "Cert Only")
        XCTAssertEqual(q.id, "cert-only")
        XCTAssertEqual(q.passwordMode, .none)
        XCTAssertEqual(q.mgmtPort, 0)
    }

    func testShareRoundTrip() throws {
        var p = try store.create(name: "Acme", type: .openvpn)
        p.username = "alice"; p.lastUsername = "alice"; p.pinned = true; p.order = 7
        p.otpMode = .totp; p.totp = TOTPParams(digits: 8, period: 60, algorithm: .sha256)
        p.otpTemplate = "{password}:{otp}"; p.healthHost = "10.0.0.5"; p.badge = "AC"
        try store.save(p)
        let ovpn = "client\nremote vpn.example.com\n<key>\nsecret\n</key>\n"
        try store.setOVPN(p.id, from: try write(ovpn, name: "in.ovpn"))
        try Secrets.set(p.id, .password, "hunter2")

        let shareURL = home.appendingPathComponent("acme.passtunnel")
        try store.exportShare(p.id, to: shareURL)
        XCTAssertEqual(try mode(shareURL), 0o600)
        let text = try String(contentsOf: shareURL)
        XCTAssertTrue(text.contains(#""passtunnel_profile" : 1"#))
        for key in ["\"username\"", "last_username", "\"order\"", "mgmt_port", "\"pinned\"", "alice", "hunter2"] {
            XCTAssertFalse(text.contains(key), key)
        }
        XCTAssertTrue(text.contains(Data(ovpn.utf8).base64EncodedString()))

        let q = try store.importShare(shareURL, name: nil)
        XCTAssertEqual(q.id, "acme-2")
        XCTAssertEqual(q.name, "Acme")
        XCTAssertEqual(q.username, "")
        XCTAssertFalse(q.pinned)
        XCTAssertEqual(q.mgmtPort, 0)
        XCTAssertEqual(q.totp, p.totp)
        XCTAssertEqual(q.otpTemplate, "{password}:{otp}")
        XCTAssertEqual(q.healthHost, "10.0.0.5")
        XCTAssertEqual(q.badge, "AC")
        XCTAssertEqual(try String(contentsOf: store.ovpnURL(q.id)), ovpn)
        XCTAssertEqual(try mode(store.ovpnURL(q.id)), 0o600)
        XCTAssertNil(Secrets.get(q.id, .password))

        XCTAssertEqual(try store.importShare(shareURL, name: "Acme Copy").id, "acme-copy")
    }

    func testImportShareIgnoresUnknownFileNames() throws {
        let payload = Data("pwned".utf8).base64EncodedString()
        let json = """
        {"passtunnel_profile":1,
         "profile":{"id":"../../evil","name":"Evil","type":"openvpn","mgmt_port":7505,"username":"bob"},
         "files":{"../../escape.txt":"\(payload)","profile.json":"\(payload)","config.ovpn":"\(Data("client\n".utf8).base64EncodedString())"}}
        """
        let url = try write(json, name: "evil.passtunnel")
        let p = try store.importShare(url, name: nil)
        XCTAssertEqual(p.id, "evil")
        XCTAssertEqual(p.mgmtPort, 0)
        XCTAssertEqual(p.username, "")
        let files = try FileManager.default.contentsOfDirectory(atPath: store.dir(p.id).path).sorted()
        XCTAssertEqual(files, ["config.ovpn", "profile.json"])
        XCTAssertEqual(try store.get(p.id).name, "Evil")
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent("escape.txt").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.dir("x").deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("escape.txt").path))
    }

    func testImportShareRejectsOtherFiles() throws {
        let wrong = try write(#"{"passtunnel_profile":2,"profile":{"name":"A","type":"forti"}}"#, name: "a.json")
        assertThrows(.unsupportedShareFile) { _ = try store.importShare(wrong, name: nil) }
        let plain = try write(#"{"name":"A"}"#, name: "b.json")
        assertThrows(.unsupportedShareFile) { _ = try store.importShare(plain, name: nil) }
        let garbage = try write("hello", name: "c.json")
        assertThrows(.unsupportedShareFile) { _ = try store.importShare(garbage, name: nil) }
        XCTAssertTrue(store.list().isEmpty)
    }

    func testFortiShare() throws {
        var p = try store.create(name: "Acme Forti", type: .forti)
        p.host = "vpn.example.com"; p.port = 10443; p.trustedCert = "ab12"; p.setDNS = true; p.setRoutes = false
        try store.save(p)
        let url = home.appendingPathComponent("f.passtunnel")
        try store.exportShare(p.id, to: url)
        let q = try store.importShare(url, name: nil)
        XCTAssertEqual(q.type, .forti)
        XCTAssertEqual([q.host, String(q.port), q.trustedCert], ["vpn.example.com", "10443", "ab12"])
        XCTAssertTrue(q.setDNS)
        XCTAssertFalse(q.setRoutes)
        XCTAssertEqual(q.otpDelivery, .separate)
        XCTAssertEqual(q.mgmtPort, 0)
    }
}

final class HealthCheckTests: CoreTestCase {
    func testParse() {
        XCTAssertEqual(HealthCheck.parse("10.0.0.5"), .icmp(host: "10.0.0.5"))
        XCTAssertEqual(HealthCheck.parse("vpn.example.com"), .icmp(host: "vpn.example.com"))
        XCTAssertEqual(HealthCheck.parse("vpn.example.com:443"), .tcp(host: "vpn.example.com", port: 443))
        XCTAssertEqual(HealthCheck.parse("fe80::1"), .icmp6(host: "fe80::1"))
        XCTAssertEqual(HealthCheck.parse("2001:db8::1:443"), .icmp6(host: "2001:db8::1:443"))
        XCTAssertEqual(HealthCheck.parse("::1"), .icmp6(host: "::1"))
        XCTAssertEqual(HealthCheck.parse("[2001:db8::1]:443"), .tcp(host: "2001:db8::1", port: 443))
        XCTAssertEqual(HealthCheck.parse("[::1]"), .icmp6(host: "::1"))
        for bad in ["", "  ", "-c 5 host", "host:", "host:0", "host:70000", "host:abc", "[::1]:", "[::1", "[]:80", "a b"] {
            XCTAssertNil(HealthCheck.parse(bad), bad)
        }
    }

    func testRoundTripParsing() {
        XCTAssertEqual(HealthCheck.roundTripMS("round-trip min/avg/max/stddev = 0.067/12.6/0.067/0.000 ms"), 13)
        XCTAssertNil(HealthCheck.roundTripMS("nothing"))
    }

    func testTCPOpenAndClosed() throws {
        let (fd4, port4) = try listen(AF_INET)
        defer { close(fd4) }
        let r = HealthCheck.check("127.0.0.1:\(port4)", timeout: 2)
        XCTAssertTrue(r.ok)
        XCTAssertGreaterThanOrEqual(r.ms, 0)

        if let (fd6, port6) = try? listen(AF_INET6) {
            defer { close(fd6) }
            XCTAssertTrue(HealthCheck.check("[::1]:\(port6)", timeout: 2).ok)
        }

        let (fdc, closedPort) = try listen(AF_INET)
        close(fdc)
        let start = Date()
        XCTAssertFalse(HealthCheck.check("127.0.0.1:\(closedPort)", timeout: 2).ok)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2.5)
    }

    func testICMPLoopback() {
        XCTAssertTrue(HealthCheck.check("127.0.0.1", timeout: 3).ok)
        XCTAssertTrue(HealthCheck.check("::1", timeout: 3).ok)
    }

    func testICMPHardTimeout() {
        let start = Date()
        XCTAssertFalse(HealthCheck.check("192.0.2.1", timeout: 1).ok)   // TEST-NET-1, never answers
        XCTAssertLessThan(Date().timeIntervalSince(start), 3)
        XCTAssertFalse(HealthCheck.check("", timeout: 1).ok)
    }

    private func listen(_ family: Int32) throws -> (Int32, UInt16) {
        let fd = socket(family, SOCK_STREAM, 0)
        guard fd >= 0 else { throw PTError.fileError("socket") }
        var rc: Int32
        if family == AF_INET {
            var a = sockaddr_in()
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            a.sin_family = sa_family_t(AF_INET)
            a.sin_addr.s_addr = inet_addr("127.0.0.1")
            rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        } else {
            var a = sockaddr_in6()
            a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            a.sin6_family = sa_family_t(AF_INET6)
            a.sin6_addr = in6addr_loopback
            rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        }
        guard rc == 0, Darwin.listen(fd, 4) == 0 else { close(fd); throw PTError.fileError("bind") }
        var storage = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        _ = withUnsafeMutablePointer(to: &storage) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            getsockname(fd, $0, &len) } }
        let port: UInt16 = withUnsafePointer(to: &storage) { ptr in
            family == AF_INET
                ? ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin_port) }
                : ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin6_port) }
        }
        return (fd, port)
    }
}
