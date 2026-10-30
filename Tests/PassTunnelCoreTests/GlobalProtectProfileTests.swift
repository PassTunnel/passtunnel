import Foundation
import XCTest

@testable import PassTunnelCLI
@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

private let pin = "pin-sha256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk="
private let gatewayPin = "pin-sha256:VIvehxhDt2KjN5O2MU6TnoXZFEsHIwCppUURj1ynWsE="
private let otherPin = "pin-sha256:/+9qLXvY4QvSoKy/ojXS6HTlG1iniUJkmUyKWlahaLE="
private let macOS153 = OperatingSystemVersion(majorVersion: 15, minorVersion: 3, patchVersion: 9)
private let macOS154 = OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0)

/// Palo Alto GlobalProtect profiles in the model, the store and share files (G2): they are listed, kept,
/// edited with `passtunnel set`, shared and deleted, and refused before anything when connecting, which this
/// version does not do yet. The golden cases are in fixtures/ (FixtureTests).
final class GlobalProtectProfileTests: CoreTestCase {
    func makeGlobalProtect(_ name: String = "Acme GlobalProtect") throws -> Profile {
        var p = try store.create(name: name, type: .globalprotect)
        p.host = "vpn.example.com"
        p.port = 8443
        p.gateway = "US East"
        p.serverCert = pin
        p.gatewayServerCert = gatewayPin
        p.tlsOnly = true
        try store.save(p)
        return p
    }

    func storedJSON(_ id: String) throws -> [String: Any] {
        try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: store.profileURL(id))) as? [String: Any])
    }

    // MARK: model

    func testDefaults() throws {
        let p = try store.create(name: "Acme", type: .globalprotect)
        XCTAssertEqual(p.otpDelivery, .separate, "the code is the second answer, as for Cisco AnyConnect")
        XCTAssertEqual(p.port, 443)
        XCTAssertEqual([p.gateway, p.serverCert, p.gatewayServerCert], ["", "", ""])
        XCTAssertFalse(p.skipPortal, "the portal first")
        XCTAssertFalse(p.tlsOnly, "ESP by default")
        XCTAssertEqual(try store.get(p.id), p)
        XCTAssertEqual(VPNType(rawValue: "globalprotect"), .globalprotect)
        XCTAssertEqual(VPNType.globalprotect.defaultOTPDelivery, .separate)
        XCTAssertEqual(VPNType.allCases, [.openvpn, .forti, .anyconnect, .globalprotect])
    }

    /// The one source of the label: only Palo Alto GlobalProtect, and nothing stores it.
    func testOnlyGlobalProtectIsExperimental() throws {
        XCTAssertEqual(VPNType.allCases.filter(\.isExperimental), [.globalprotect])
        let p = try makeGlobalProtect()
        XCTAssertFalse(String(decoding: try Data(contentsOf: store.profileURL(p.id)), as: UTF8.self).contains("experimental"))
        XCTAssertFalse(String(decoding: try ShareFile(profile: p).data(), as: UTF8.self).contains("experimental"))
    }

    func testTheKeysAreWrittenOnlyForTheirType() throws {
        let gp = try makeGlobalProtect()
        let json = try storedJSON(gp.id)
        XCTAssertEqual(json["type"] as? String, "globalprotect")
        XCTAssertEqual(json["gateway"] as? String, "US East")
        XCTAssertEqual(json["skip_portal"] as? Bool, false)
        XCTAssertEqual(json["server_cert"] as? String, pin)
        XCTAssertEqual(json["gateway_server_cert"] as? String, gatewayPin)
        XCTAssertEqual(json["tls_only"] as? Bool, true)
        for key in ["usergroup", "authgroup"] { XCTAssertNil(json[key], "Cisco AnyConnect's alone: \(key)") }

        // The other types' files are as before: none of the new keys, whatever the profile holds.
        let before: [VPNType: Set<String>] = [
            .openvpn: try keys(of: .openvpn, gp: false), .forti: try keys(of: .forti, gp: false),
            .anyconnect: try keys(of: .anyconnect, gp: false)
        ]
        for type in [VPNType.openvpn, .forti, .anyconnect] {
            XCTAssertEqual(try keys(of: type, gp: true), before[type], "\(type)")
            for key in ["gateway", "skip_portal", "gateway_server_cert"] {
                XCTAssertFalse(before[type]?.contains(key) ?? true, "\(type) \(key)")
            }
        }
        XCTAssertEqual(before[.anyconnect]?.isSuperset(of: ["usergroup", "authgroup", "server_cert", "tls_only"]), true)
    }

    /// The keys a save writes for a profile of `type`, with the GlobalProtect fields set (`gp`) or not.
    private func keys(of type: VPNType, gp: Bool) throws -> Set<String> {
        var p = Profile(id: "keys-\(type.rawValue)", name: "K", type: type)
        if gp {
            p.gateway = "US East"
            p.skipPortal = true
            p.gatewayServerCert = gatewayPin
        }
        return Set(try XCTUnwrap(try JSONSerialization.jsonObject(with: try JSONCoding.encode(p)) as? [String: Any]).keys)
    }

    func testSaveChecksEveryField() throws {
        let p = try makeGlobalProtect()
        let bad: [(String, (inout Profile) -> Void)] = [
            ("host", { $0.host = "fe80::1%en0" }),
            ("host", { $0.host = "vpn.example.com/global-protect" }),
            ("host", { $0.host = "vpn.example.com:8443" }),
            ("gateway", { $0.gateway = " US East" }),
            ("gateway", { $0.gateway = "=US East" }),
            ("gateway", { $0.gateway = "US\nservercert pin-sha256:x" }),
            ("gateway", { $0.gateway = String(repeating: "a", count: 256) }),
            ("server_cert", { $0.serverCert = "PIN-SHA256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk=" }),
            ("server_cert", { $0.serverCert = "pin-sha256:z5Gv" }),
            ("gateway_server_cert", { $0.gatewayServerCert = " " + gatewayPin }),
            ("gateway_server_cert", { $0.gatewayServerCert = "sha256:abcd" }),
            ("username", { $0.username = "=alice" }),
            ("username", { $0.username = String(repeating: "a", count: 256) }),
            ("password_mode", { $0.passwordMode = .none }),
            (
                "otp_template",
                {
                    $0.otpMode = .totp
                    $0.otpDelivery = .combined
                    $0.otpTemplate = "{password}\r{otp}"
                }
            )
        ]
        for (field, change) in bad {
            var q = p
            change(&q)
            assertThrows(.invalidField(field)) { try store.save(q) }
        }
        XCTAssertEqual(try store.get(p.id), p, "nothing saved")

        // Cisco AnyConnect's fields are not this type's: never checked, never written.
        var q = p
        q.usergroup = "../x"
        q.authgroup = "a\u{0}b"
        q.otpTemplate = "{password}\n{otp}"  // not used: the code is sent apart
        q.username = "  alice  "
        q.host = "2001:DB8::1"
        q.gateway = String(repeating: "a", count: 255)
        try store.save(q)
        XCTAssertEqual(try store.get(p.id).usergroup, "")
    }

    func testFieldsAreSetAndShown() throws {
        var p = try makeGlobalProtect()
        let openConnectKeys = [
            "host", "port", "usergroup", "authgroup", "gateway", "skip_portal", "trusted_cert", "server_cert",
            "gateway_server_cert", "tls_only", "set_dns", "set_routes"
        ]
        XCTAssertEqual(
            ProfileFields.keys(for: .globalprotect).filter(openConnectKeys.contains),
            ["host", "port", "gateway", "skip_portal", "server_cert", "gateway_server_cert", "tls_only", "set_dns", "set_routes"])
        XCTAssertEqual(
            ProfileFields.keys(for: .anyconnect).filter(openConnectKeys.contains),
            ["host", "port", "usergroup", "authgroup", "server_cert", "tls_only", "set_dns", "set_routes"], "unchanged")
        for type in [VPNType.openvpn, .forti, .anyconnect] {
            for key in ["gateway", "skip_portal", "gateway_server_cert"] {
                XCTAssertFalse(ProfileFields.keys(for: type).contains(key), "\(type) \(key)")
                var other = Profile(id: "other", name: "Other", type: type)
                assertThrows(.wrongProfileType("other")) { try ProfileFields.set(&other, key: key, value: "x") }
            }
        }
        for key in ["usergroup", "authgroup", "trusted_cert"] {
            assertThrows(.wrongProfileType(p.id)) { try ProfileFields.set(&p, key: key, value: "x") }
        }

        try ProfileFields.set(&p, key: "Gateway", value: "  Avrupa (İstanbul) ")
        XCTAssertEqual(p.gateway, "Avrupa (İstanbul)")
        try ProfileFields.set(&p, key: "skip-portal", value: "yes")
        XCTAssertTrue(p.skipPortal)
        try ProfileFields.set(&p, key: "gateway_server_cert", value: " PIN-SHA256:/+9qLXvY4QvSoKy/ojXS6HTlG1iniUJkmUyKWlahaLE= ")
        XCTAssertEqual(p.gatewayServerCert, otherPin)
        try ProfileFields.set(&p, key: "server_cert", value: "")
        XCTAssertEqual(
            ["gateway", "skip_portal", "server_cert", "gateway_server_cert"].map { ProfileFields.value(p, key: $0) },
            ["Avrupa (İstanbul)", "true", "", otherPin])
        assertThrows(.invalidField("gateway_server_cert")) { try ProfileFields.set(&p, key: "gateway_server_cert", value: "pin-sha256:x") }
        assertThrows(.invalidField("gateway")) { try ProfileFields.set(&p, key: "gateway", value: "=x") }
        assertThrows(.invalidField("username")) { try ProfileFields.set(&p, key: "username", value: "=alice") }
        try store.save(p)
        XCTAssertEqual(try store.get(p.id), p)
    }

    /// A save keeps the keys a newer version added to the type; a change of the type drops them and this type's
    /// keys (`server_cert` and `tls_only` stay: Cisco AnyConnect has them too).
    func testUnknownKeysAndTypeChanges() throws {
        let p = try makeGlobalProtect()
        var json = try storedJSON(p.id)
        json["future_option"] = "on"
        try JSONSerialization.data(withJSONObject: json).write(to: store.profileURL(p.id))
        try store.update(p.id) { $0.gateway = "US West" }
        XCTAssertEqual(try storedJSON(p.id)["future_option"] as? String, "on")

        try store.update(p.id) { $0.type = .anyconnect }
        let changed = try storedJSON(p.id)
        for key in ["future_option", "gateway", "skip_portal", "gateway_server_cert"] { XCTAssertNil(changed[key], key) }
        XCTAssertEqual(changed["server_cert"] as? String, pin)
        XCTAssertEqual(changed["tls_only"] as? Bool, true)
    }

    // MARK: share files

    func testShareFileRoundTripIsVersion2() throws {
        var p = try makeGlobalProtect()
        p.skipPortal = true
        p.username = "alice"
        try store.save(p)
        let url = home.appendingPathComponent("gp.passtunnel")
        try store.exportShare(p.id, to: url)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        XCTAssertEqual(json["passtunnel_profile"] as? Int, 2, "as Cisco AnyConnect: every reader of version 2 refuses a type it does not know")
        XCTAssertEqual(ShareFile.currentVersion, 2)
        XCTAssertEqual(ShareFile.version(for: .globalprotect), 2)
        let shared = try XCTUnwrap(json["profile"] as? [String: Any])
        XCTAssertNil(shared["username"])
        XCTAssertNil(shared["usergroup"])
        let q = try store.importShare(url, name: nil)
        XCTAssertEqual(q.type, .globalprotect)
        XCTAssertEqual(
            [q.host, String(q.port), q.gateway, q.serverCert, q.gatewayServerCert],
            ["vpn.example.com", "8443", "US East", pin, gatewayPin])
        XCTAssertTrue(q.skipPortal)
        XCTAssertTrue(q.tlsOnly)
        XCTAssertEqual(q.otpDelivery, .separate)
        XCTAssertEqual(q.username, "", "a per-user field")
    }

    func testImportNormalizesThePinsAndRefusesBadFields() throws {
        func share(_ profile: String) throws -> URL {
            try write("{\"passtunnel_profile\": 2, \"profile\": {\"name\": \"A\", \"type\": \"globalprotect\", \(profile)}}", name: "s.passtunnel")
        }
        let q = try store.importShare(
            try share(
                "\"server_cert\": \" PIN-SHA256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk=\\n\", "
                    + "\"gateway_server_cert\": \"PIN-SHA256:VIvehxhDt2KjN5O2MU6TnoXZFEsHIwCppUURj1ynWsE= \", "
                    + "\"usergroup\": \"../x\", \"authgroup\": \"a\\u0000b\""), name: nil)
        XCTAssertEqual([q.serverCert, q.gatewayServerCert], [pin, gatewayPin])
        let saved = try store.get(q.id)
        XCTAssertEqual([saved.usergroup, saved.authgroup], ["", ""], "Cisco AnyConnect's keys are not this type's: never written")
        try store.delete(q.id)
        let refused: [(String, String)] = [
            ("\"server_cert\": \"sha256:abcd\"", "server_cert"),
            ("\"gateway_server_cert\": \"pin-sha256:x\"", "gateway_server_cert"),
            ("\"gateway\": \"US\\u0000East\"", "gateway"),
            ("\"gateway\": \"=US East\"", "gateway"),
            ("\"host\": \"vpn.example.com:8443\"", "host"),
            ("\"password_mode\": \"none\"", "password_mode")
        ]
        for (profile, field) in refused {
            assertThrows(.invalidField(field)) { _ = try store.importShare(try share(profile), name: nil) }
        }
        XCTAssertEqual(store.list(), [], "nothing left behind")
    }

    // MARK: destination

    func testDestinationFingerprint() throws {
        let p = try makeGlobalProtect()
        let base = ProfileDestination.of(p, store: store)
        XCTAssertEqual(base.host, "vpn.example.com")
        XCTAssertNil(base.configSHA256)
        // The gateway is the portal's to offer; the rest is not where the credentials go.
        let same: [(inout Profile) -> Void] = [
            { $0.host = " VPN.Example.com " }, { $0.gateway = "US West" }, { $0.gateway = "" }, { $0.tlsOnly.toggle() },
            { $0.setDNS.toggle() }, { $0.setRoutes.toggle() }, { $0.username = "bob" }, { $0.usergroup = "x" },
            { $0.authgroup = "x" }, { $0.trustedCert = "ab12" },
            { $0.serverCert = " PIN-SHA256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk=\n" },
            { $0.gatewayServerCert = "PIN-SHA256:VIvehxhDt2KjN5O2MU6TnoXZFEsHIwCppUURj1ynWsE=" }
        ]
        for (n, change) in same.enumerated() {
            var q = p
            change(&q)
            XCTAssertEqual(ProfileDestination.of(q, store: store).fingerprint, base.fingerprint, "change \(n)")
        }
        let other: [(inout Profile) -> Void] = [
            { $0.host = "vpn2.example.com" }, { $0.port = 443 }, { $0.skipPortal = true }, { $0.serverCert = otherPin },
            { $0.serverCert = "" }, { $0.gatewayServerCert = otherPin }, { $0.gatewayServerCert = "" },
            {
                $0.serverCert = gatewayPin
                $0.gatewayServerCert = pin
            }
        ]
        for (n, change) in other.enumerated() {
            var q = p
            change(&q)
            XCTAssertNotEqual(ProfileDestination.of(q, store: store).fingerprint, base.fingerprint, "change \(n)")
        }
        // A Cisco AnyConnect profile with the same server and pin is another destination.
        var ac = Profile(id: p.id, name: p.name, type: .anyconnect)
        ac.host = p.host
        ac.port = p.port
        ac.serverCert = p.serverCert
        XCTAssertNotEqual(ProfileDestination.of(ac, store: store).fingerprint, base.fingerprint)
    }

    /// The fields hashed, in order: the version tag, the type, host, port, `skip_portal`, the two pins.
    func testDestinationGolden() {
        var p = Profile(id: "acme", name: "Acme", type: .globalprotect)
        p.host = "vpn.example.com"
        // SHA-256 of "passtunnel-destination-1\0globalprotect\0vpn.example.com\0443\0false\0\0\0".
        XCTAssertEqual(
            ProfileDestination.of(p, store: store).fingerprint, "2344cf47d670a89e26f4adff4908cd3482d184d97e61f7969966ae68981badff")
        var forti = Profile(id: "acme", name: "Acme", type: .forti)
        forti.host = "vpn.example.com"
        XCTAssertEqual(
            ProfileDestination.of(forti, store: store).fingerprint, "e8c4decb3733523dac388906fc2fe5680234bb7b6f0f114d16f9c622b7e7a3ec",
            "unchanged")
    }

    // MARK: addresses

    func testServerAddresses() {
        XCTAssertEqual(GlobalProtectServer.parse("vpn.example.com"), GlobalProtectServer(host: "vpn.example.com"))
        XCTAssertEqual(GlobalProtectServer.parse(" HTTPS://GW.Example.com:4443/ "), GlobalProtectServer(host: "gw.example.com", port: 4443))
        XCTAssertEqual(GlobalProtectServer.parse("https://[2001:DB8::1]"), GlobalProtectServer(host: "2001:db8::1"))
        for text in [
            "https://vpn.example.com/global-protect/login.esp", "https://gw.example.com/ssl-vpn/", "https://gw.example.com/gateway",
            "https://vpn.example.com//", "http://vpn.example.com", "https://alice@vpn.example.com", "https://vpn.example.com:0",
            "2001:db8::1", ""
        ] {
            XCTAssertNil(GlobalProtectServer.parse(text), text)
        }
        // Cisco AnyConnect's addresses are as before.
        XCTAssertEqual(
            AnyConnectServer.parse("https://vpn.example.com:8443/engineering"),
            AnyConnectServer(host: "vpn.example.com", port: 8443, usergroup: "engineering"))
        XCTAssertNil(AnyConnectServer.parse("https://vpn.example.com//engineering"))
    }

    // MARK: connecting

    @MainActor func testConnectRefusal() {
        // Below macOS 15.4 as Cisco AnyConnect is, with the type's name.
        for macOS in [OperatingSystemVersion(majorVersion: 13, minorVersion: 0, patchVersion: 0), macOS153] {
            let refusal = ConnectionManager.connectRefusal(.globalprotect, macOS: macOS)
            XCTAssertEqual(refusal, .globalProtectRequiresMacOS("15.4"))
            XCTAssertEqual(refusal?.localizedDescription, "Palo Alto GlobalProtect requires macOS 15.4 or later.")
            XCTAssertEqual(refusal?.unavailableNote, "Requires macOS 15.4 or later")
            XCTAssertEqual(refusal.map(AutomationErrorCode.of), .configInvalid)
            XCTAssertEqual(ConnectionFailure.of(refusal!, log: nil, handed: nil, at: Date()).kind, .toolUnsupported)
        }
        // Connected from macOS 15.4 on (#231).
        for macOS in [macOS154, OperatingSystemVersion(majorVersion: 26, minorVersion: 0, patchVersion: 0)] {
            XCTAssertNil(ConnectionManager.connectRefusal(.globalprotect, macOS: macOS))
        }
        // Linux: refused as a type that needs a newer PassTunnel until passtunneld runs it (#234).
        let linux = ConnectionManager.connectRefusal(.globalprotect, macOS: nil)
        XCTAssertEqual(linux, .unsupportedProfileType("globalprotect"))
        XCTAssertEqual(linux?.unavailableNote, UnsupportedProfile.statusText)
        XCTAssertEqual(linux.map(AutomationErrorCode.of), .configInvalid)
        // The same sentence as the helper's refusal (protocol 5), and the same name everywhere.
        for (type, proto, refusal) in [
            (VPNType.globalprotect, OpenConnectProtocol.gp, PTError.globalProtectRequiresMacOS("15.4")),
            (.anyconnect, .anyconnect, .anyConnectRequiresMacOS("15.4"))
        ] {
            XCTAssertEqual(refusal.localizedDescription, HelperCore.Failure.requiresNewerMacOS(proto.displayName, "15.4").description)
            XCTAssertEqual(CLIRunner.typeName(type), proto.displayName)
        }
        XCTAssertEqual(VPNType.connectable, [.openvpn, .forti, .anyconnect, .globalprotect])
        XCTAssertTrue(VPNType.globalprotect.isConnectable)
        // The other types are as before.
        XCTAssertEqual(ConnectionManager.connectRefusal(.anyconnect, macOS: macOS153), .anyConnectRequiresMacOS("15.4"))
        for type in VPNType.connectable where type != .globalprotect {
            XCTAssertNil(ConnectionManager.connectRefusal(type, macOS: macOS154), "\(type)")
            XCTAssertNil(ConnectionManager.connectRefusal(type, macOS: nil), "\(type)")
        }
    }

    /// Listed as an ordinary profile of a known type; connectable on macOS 15.4, with the refusal on Linux.
    func testItIsListedWithTheRefusal() throws {
        let p = try makeGlobalProtect()
        XCTAssertEqual(store.list().map(\.id), [p.id])
        XCTAssertEqual(store.listUnsupported(), [])
        let mac = ProfileSummary(p, isDefault: false, connectRefusal: ConnectionManager.connectRefusal(p.type, macOS: macOS154))
        XCTAssertEqual(mac.type, "globalprotect")
        XCTAssertNil(mac.needsNewerVersion, "a known type")
        XCTAssertNil(mac.connectRefusal)
        XCTAssertNoThrow(try ConnectionManager.checkConnectable(p, macOS: macOS154))
        let linux = ProfileSummary(p, isDefault: false, connectRefusal: ConnectionManager.connectRefusal(p.type, macOS: nil))
        XCTAssertEqual(linux.connectRefusal?.code, "config_invalid")
        XCTAssertThrowsError(try ConnectionManager.checkConnectable(p, macOS: nil)) {
            XCTAssertEqual($0 as? PTError, .unsupportedProfileType("globalprotect"))
        }
    }
}

extension ConnectionManagerTests {
    /// Nothing is asked, read, run or sent for a Palo Alto GlobalProtect profile this system does not connect: below
    /// macOS 15.4, and on Linux until passtunneld runs it (#234).
    func testGlobalProtectIsRefusedBeforeAnything() async throws {
        for macOS in [macOS153, nil] {
            var p = try store.create(name: "Acme GlobalProtect \(String(describing: macOS?.minorVersion))", type: .globalprotect)
            p.host = "vpn.example.com"
            p.username = "alice"
            p.otpMode = .totp
            p.requireAuth = .connect
            try store.save(p)
            try Secrets.set(p.id, .password, "hunter2-pw")
            try Secrets.set(p.id, .totp, totpSecret)
            let m = makeManager()
            m.systemVersion = macOS
            let requestsBefore = helper.requests.count
            let expected = ConnectionManager.connectRefusal(.globalprotect, macOS: macOS)
            XCTAssertNotNil(expected)
            let attempts: [() async throws -> Void] = [
                { try await m.connect(p.id) },
                { try await m.connect(p.id, followOnly: true) },
                { try await m.connect(p.id, interactive: false) },
                { _ = try await m.checkCanStart(p.id) }
            ]
            for (n, attempt) in attempts.enumerated() {
                do {
                    try await attempt()
                    XCTFail("attempt \(n) went ahead")
                } catch {
                    XCTAssertEqual(error as? PTError, expected, "attempt \(n)")
                }
            }
            XCTAssertEqual(authenticator.calls, 0, "no Touch ID")
            XCTAssertFalse(m.vault.isUnlocked(p.id, .password))
            XCTAssertEqual(helper.requests.count, requestsBefore, "the helper was not asked anything")
            XCTAssertEqual(m.state(p.id), .disconnected)
        }
    }
}

extension AnyConnectCLITests {
    /// `list`, `show`, `set` and `diagnose` handle a Palo Alto GlobalProtect profile; `connect` refuses it on Linux
    /// and `add` does not make one yet.
    func testGlobalProtectInTheCommand() async throws {
        var p = try store.create(name: "Acme GP", type: .globalprotect)
        p.host = "vpn.example.com"
        try store.save(p)

        let set = try await run(
            .set(
                id: p.id,
                assignments: [
                    .init(key: "gateway", value: "US East"), .init(key: "skip_portal", value: "yes"),
                    .init(key: "gateway_server_cert", value: gatewayPin)
                ]), macOS: macOS154)
        XCTAssertEqual(set.code, 0, set.err)
        let stored = try store.get(p.id)
        XCTAssertEqual([stored.gateway, stored.gatewayServerCert], ["US East", gatewayPin])
        XCTAssertTrue(stored.skipPortal)
        let wrong = try await run(.set(id: p.id, assignments: [.init(key: "authgroup", value: "Employees")]), macOS: macOS154)
        XCTAssertNotEqual(wrong.code, 0)

        let show = try await run(.show(id: p.id, json: false), macOS: macOS154)
        XCTAssertEqual(show.code, 0, show.err)
        for row in ["gateway", "skip_portal", "gateway_server_cert", "server_cert", "tls_only"] {
            XCTAssertTrue(show.out.contains(row), row)
        }
        XCTAssertFalse(show.out.contains("usergroup"))

        let list = try await run(.list(json: false, quiet: false), macOS: macOS154)
        let line = try XCTUnwrap(list.out.split(separator: "\n").first { $0.contains(p.id) }.map(String.init))
        XCTAssertTrue(line.contains("Palo Alto GlobalProtect"), line)
        XCTAssertFalse(line.contains(UnsupportedProfile.statusText), line)
        let linuxList = try await run(.list(json: false, quiet: false), macOS: nil)
        let linuxLine = try XCTUnwrap(linuxList.out.split(separator: "\n").first { $0.contains(p.id) }.map(String.init))
        XCTAssertTrue(linuxLine.contains(UnsupportedProfile.statusText), linuxLine)
        let json = try await run(.list(json: true, quiet: false), macOS: macOS153)
        let entry = try XCTUnwrap(json.jsonArray?.first { $0["id"] as? String == p.id })
        XCTAssertEqual(entry["type"] as? String, "globalprotect")
        XCTAssertNil(entry["needs_newer_version"])
        XCTAssertEqual((entry["connect_refusal"] as? [String: Any])?["message"] as? String, "Palo Alto GlobalProtect requires macOS 15.4 or later.")

        let connect = try await run(.connect(id: p.id), macOS: nil)
        XCTAssertNotEqual(connect.code, 0)
        XCTAssertTrue(helper.starts.isEmpty, "nothing started")

        XCTAssertThrowsError(try CLICommand.parse(["add", "Acme", "--type", "globalprotect"]), "not offered by add yet (#232)")
    }
}
