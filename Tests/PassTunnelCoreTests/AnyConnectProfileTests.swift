import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelVPNConfig

private let pin = "pin-sha256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk="
private let otherPin = "pin-sha256:/+9qLXvY4QvSoKy/ojXS6HTlG1iniUJkmUyKWlahaLE="

/// Cisco AnyConnect profiles in the model, the store and share files. This version does not connect them yet:
/// they are listed, kept, edited with `passtunnel set`, shared and deleted.
final class AnyConnectProfileTests: CoreTestCase {
    func makeAnyConnect(_ name: String = "Acme AnyConnect") throws -> Profile {
        var p = try store.create(name: name, type: .anyconnect)
        p.host = "vpn.example.com"
        p.port = 8443
        p.usergroup = "engineering"
        p.authgroup = "Employees"
        p.serverCert = pin
        p.tlsOnly = true
        try store.save(p)
        return p
    }

    // MARK: model

    func testDefaults() throws {
        let p = try store.create(name: "Acme", type: .anyconnect)
        XCTAssertEqual(p.otpDelivery, .separate, "the code is the second answer")
        XCTAssertEqual(p.port, 443)
        XCTAssertEqual([p.usergroup, p.authgroup, p.serverCert], ["", "", ""])
        XCTAssertFalse(p.tlsOnly, "DTLS by default")
        XCTAssertEqual(try store.get(p.id), p)
        XCTAssertEqual(VPNType.anyconnect.defaultOTPDelivery, .separate)
        XCTAssertEqual(VPNType.forti.defaultOTPDelivery, .separate)
        XCTAssertEqual(VPNType.openvpn.defaultOTPDelivery, .combined)
    }

    func testTheNewKeysAreWrittenOnlyForTheirType() throws {
        let ac = try makeAnyConnect()
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: store.profileURL(ac.id))) as? [String: Any])
        XCTAssertEqual(json["usergroup"] as? String, "engineering")
        XCTAssertEqual(json["authgroup"] as? String, "Employees")
        XCTAssertEqual(json["server_cert"] as? String, pin)
        XCTAssertEqual(json["tls_only"] as? Bool, true)
        XCTAssertEqual(json["type"] as? String, "anyconnect")

        var forti = try store.create(name: "Acme Forti", type: .forti)
        forti.usergroup = "engineering"  // not a FortiGate setting: never written
        try store.save(forti)
        let fortiJSON = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: store.profileURL(forti.id))) as? [String: Any])
        for key in ["usergroup", "authgroup", "server_cert", "tls_only"] { XCTAssertNil(fortiJSON[key], key) }
    }

    func testSaveChecksEveryField() throws {
        let p = try makeAnyConnect()
        let bad: [(String, (inout Profile) -> Void)] = [
            ("host", { $0.host = "fe80::1%en0" }),
            ("host", { $0.host = "vpn.example.com/engineering" }),
            ("usergroup", { $0.usergroup = "/engineering" }),
            ("usergroup", { $0.usergroup = "a/../b" }),
            ("usergroup", { $0.usergroup = String(repeating: "a", count: 256) }),
            ("authgroup", { $0.authgroup = " Employees" }),
            ("authgroup", { $0.authgroup = "a\nservercert pin-sha256:x" }),
            ("server_cert", { $0.serverCert = "PIN-SHA256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk=" }),
            ("server_cert", { $0.serverCert = "pin-sha256:z5Gv" }),
            ("username", { $0.username = "=alice" }),
            ("username", { $0.username = String(repeating: "a", count: 256) }),
            ("password_mode", { $0.passwordMode = .none }),
            (
                "otp_template",
                {
                    $0.otpMode = .totp
                    $0.otpDelivery = .combined
                    $0.otpTemplate = "{password}\n{otp}"
                }
            )
        ]
        for (field, change) in bad {
            var q = p
            change(&q)
            assertThrows(.invalidField(field)) { try store.save(q) }
        }
        XCTAssertEqual(try store.get(p.id), p, "nothing saved")

        // A template the code is not composed with is not checked; the user name is checked as it is sent.
        var q = p
        q.otpTemplate = "{password}\n{otp}"
        q.username = "  alice  "
        q.host = "2001:DB8::1"
        try store.save(q)
    }

    func testFieldsAreSetAndShown() throws {
        var p = try makeAnyConnect()
        XCTAssertEqual(
            ProfileFields.keys(for: .anyconnect).filter {
                ["host", "port", "usergroup", "authgroup", "trusted_cert", "server_cert", "tls_only"].contains($0)
            },
            ["host", "port", "usergroup", "authgroup", "server_cert", "tls_only"])
        XCTAssertFalse(ProfileFields.keys(for: .forti).contains("server_cert"))
        XCTAssertFalse(ProfileFields.keys(for: .openvpn).contains("usergroup"))
        try ProfileFields.set(&p, key: "server-cert", value: " PIN-SHA256:/+9qLXvY4QvSoKy/ojXS6HTlG1iniUJkmUyKWlahaLE= ")
        XCTAssertEqual(p.serverCert, otherPin)
        try ProfileFields.set(&p, key: "tls_only", value: "off")
        XCTAssertEqual(ProfileFields.value(p, key: "tls_only"), "false")
        try store.save(p)
        XCTAssertEqual(try store.get(p.id).serverCert, otherPin)
    }

    // MARK: share files

    func testShareFileRoundTripIsVersion2() throws {
        let p = try makeAnyConnect()
        let url = home.appendingPathComponent("ac.passtunnel")
        try store.exportShare(p.id, to: url)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        XCTAssertEqual(json["passtunnel_profile"] as? Int, 2, "older versions refuse it instead of importing it as OpenVPN")
        let q = try store.importShare(url, name: nil)
        XCTAssertEqual(q.type, .anyconnect)
        XCTAssertEqual(
            [q.host, String(q.port), q.usergroup, q.authgroup, q.serverCert], ["vpn.example.com", "8443", "engineering", "Employees", pin])
        XCTAssertTrue(q.tlsOnly)
        XCTAssertEqual(q.otpDelivery, .separate)

        // OpenVPN and FortiGate files stay version 1, as every older reader takes them.
        var forti = try store.create(name: "Acme Forti", type: .forti)
        forti.host = "vpn.example.com"
        try store.save(forti)
        try store.exportShare(forti.id, to: url)
        let fortiJSON = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        XCTAssertEqual(fortiJSON["passtunnel_profile"] as? Int, 1)
        XCTAssertNil((fortiJSON["profile"] as? [String: Any])?["usergroup"])
    }

    func testImportNormalizesThePinAndRefusesBadFields() throws {
        func share(_ profile: String) throws -> URL {
            try write("{\"passtunnel_profile\": 2, \"profile\": {\"name\": \"A\", \"type\": \"anyconnect\", \(profile)}}", name: "s.passtunnel")
        }
        let q = try store.importShare(try share("\"server_cert\": \" PIN-SHA256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk=\\n\""), name: nil)
        XCTAssertEqual(q.serverCert, pin)
        try store.delete(q.id)
        let refused: [(String, String)] = [
            ("\"server_cert\": \"sha256:abcd\"", "server_cert"),
            ("\"usergroup\": \"../x\"", "usergroup"),
            ("\"authgroup\": \"a\\u0000b\"", "authgroup"),
            ("\"host\": \"vpn.example.com:8443\"", "host"),
            ("\"password_mode\": \"none\"", "password_mode")
        ]
        for (profile, field) in refused {
            assertThrows(.invalidField(field)) { _ = try store.importShare(try share(profile), name: nil) }
        }
        XCTAssertEqual(store.list(), [], "nothing left behind")
    }

    func testAnOlderReaderRefusesVersion2() throws {
        // What 1.1.4 and earlier check (version 1 only): the file is refused, never read as OpenVPN.
        let data = try ShareFile(profile: try makeAnyConnect()).data()
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertGreaterThan(try XCTUnwrap(json["passtunnel_profile"] as? Int), 1)
        // A profile replaced after `init` still gets the version its type needs.
        var share = ShareFile(profile: Profile(id: "a", name: "A", type: .openvpn))
        share.profile = Profile(id: "a", name: "A", type: .anyconnect)
        let replaced = try XCTUnwrap(try JSONSerialization.jsonObject(with: try share.data()) as? [String: Any])
        XCTAssertEqual(replaced["passtunnel_profile"] as? Int, 2)
    }

    // MARK: destination

    func testDestinationFingerprint() throws {
        let p = try makeAnyConnect()
        let base = ProfileDestination.of(p, store: store)
        XCTAssertEqual(base.host, "vpn.example.com")
        XCTAssertNil(base.configSHA256)
        let same: [(inout Profile) -> Void] = [
            { $0.host = " VPN.Example.com " }, { $0.authgroup = "Contractors" }, { $0.tlsOnly.toggle() },
            { $0.setDNS.toggle() }, { $0.username = "bob" }, { $0.trustedCert = "ab12" },
            { $0.serverCert = " PIN-SHA256:z5GvjHUMCuD4zeB6PcpafVA6OZks+c8PGxSAuAx0Hgk=\n" }
        ]
        for change in same {
            var q = p
            change(&q)
            XCTAssertEqual(ProfileDestination.of(q, store: store).fingerprint, base.fingerprint)
        }
        let other: [(inout Profile) -> Void] = [
            { $0.host = "vpn2.example.com" }, { $0.port = 443 }, { $0.usergroup = "sales" }, { $0.usergroup = "" },
            { $0.serverCert = otherPin }, { $0.serverCert = "" }
        ]
        for change in other {
            var q = p
            change(&q)
            XCTAssertNotEqual(ProfileDestination.of(q, store: store).fingerprint, base.fingerprint)
        }
        // Another type with the same host and port is another destination.
        var forti = Profile(id: p.id, name: p.name, type: .forti)
        forti.host = p.host
        forti.port = p.port
        XCTAssertNotEqual(ProfileDestination.of(forti, store: store).fingerprint, base.fingerprint)
    }

    /// The fingerprint of the existing types did not change (secrets confirmed for them stay bound).
    func testExistingDestinationsAreUnchanged() {
        var forti = Profile(id: "acme", name: "Acme", type: .forti)
        forti.host = "vpn.example.com"
        // SHA-256 of "passtunnel-destination-1\0forti\0vpn.example.com\0443\0\0".
        XCTAssertEqual(
            ProfileDestination.of(forti, store: store).fingerprint, "e8c4decb3733523dac388906fc2fe5680234bb7b6f0f114d16f9c622b7e7a3ec")
    }

    // MARK: not connected yet

    func testListedAsNeedingANewerVersion() throws {
        let p = try makeAnyConnect()
        let open = try store.create(name: "Acme OpenVPN", type: .openvpn)
        XCTAssertEqual(store.list().map(\.id).sorted(), [p.id, open.id].sorted())
        XCTAssertEqual(store.listUnsupported(), [])
        let summary = ProfileSummary(p, isDefault: false)
        XCTAssertEqual(summary.type, "anyconnect")
        XCTAssertEqual(summary.needsNewerVersion, true)
        XCTAssertNil(ProfileSummary(open, isDefault: false).needsNewerVersion)
        let shown = UnsupportedProfile(p)  // how the app lists it
        XCTAssertEqual([shown.id, shown.name, shown.type], [p.id, "Acme AnyConnect", "anyconnect"])
        XCTAssertEqual(shown.order, p.order)
        XCTAssertEqual(shown.error, .unsupportedProfileType("anyconnect"))
        XCTAssertEqual(VPNType.connectable, [.openvpn, .forti])
        XCTAssertThrowsError(try ConnectionManager.checkConnectable(p)) {
            XCTAssertEqual($0 as? PTError, .unsupportedProfileType("anyconnect"))
            XCTAssertEqual(AutomationErrorCode.of($0), .configInvalid)
        }
        XCTAssertNoThrow(try ConnectionManager.checkConnectable(open))
    }
}

extension ConnectionManagerTests {
    func testAnAnyConnectProfileIsRefusedBeforeAnySecretIsUsed() async throws {
        let m = makeManager()
        var plain = try store.create(name: "Acme AnyConnect", type: .anyconnect)
        plain.host = "vpn.example.com"
        plain.username = "alice"
        plain.otpMode = .totp
        try store.save(plain)
        try Secrets.set(plain.id, .password, "pw")
        try Secrets.set(plain.id, .totp, totpSecret)
        var p = plain
        p.requireAuth = .connect
        try await m.vault.applyProtection(from: plain, to: p)
        try store.save(p)

        for attempt in 0..<2 {
            do {
                if attempt == 0 { try await m.connect(p.id) } else { _ = try await m.checkCanStart(p.id) }
                XCTFail("connected")
            } catch {
                XCTAssertEqual(error as? PTError, .unsupportedProfileType("anyconnect"))
            }
        }
        XCTAssertEqual(authenticator.calls, 0, "no confirmation asked, nothing decrypted")
        XCTAssertFalse(m.vault.isUnlocked(p.id, .password))
        XCTAssertTrue(helper.starts.isEmpty, "nothing sent to the helper")
        XCTAssertEqual(m.state(p.id), .disconnected)
        await m.refresh()
        XCTAssertEqual(m.state(p.id), .disconnected)
    }
}
