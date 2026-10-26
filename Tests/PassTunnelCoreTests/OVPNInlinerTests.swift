import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelVPNConfig

final class OVPNInlinerTests: CoreTestCase {
    let caPEM = "-----BEGIN CERTIFICATE-----\nMIIBCA==\n-----END CERTIFICATE-----\n"
    let certPEM = "-----BEGIN CERTIFICATE-----\nMIIBCB==\n-----END CERTIFICATE-----\n"
    let keyPEM = "-----BEGIN PRIVATE KEY-----\nMIIBCC==\n-----END PRIVATE KEY-----\n"
    let taKey = "-----BEGIN OpenVPN Static key V1-----\n0123abcd\n-----END OpenVPN Static key V1-----\n"

    /// A folder like the ones VPN admins hand out: client.ovpn plus separate key files.
    func makeFolder(_ ovpn: String, extra: [String: Data] = [:]) throws -> URL {
        let dir = home.appendingPathComponent("download-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let files: [String: Data] = [
            "ca.crt": Data(caPEM.utf8), "client.crt": Data(certPEM.utf8),
            "client key.pem": Data(keyPEM.utf8), "ta.key": Data(taKey.utf8),
        ].merging(extra) { $1 }
        for (name, data) in files { try data.write(to: dir.appendingPathComponent(name)) }
        let url = dir.appendingPathComponent("client.ovpn")
        try Data(ovpn.utf8).write(to: url)
        return url
    }

    func testMultiFileConfigIsInlined() throws {
        let url = try makeFolder("""
        client\r
        dev tun\r
        remote vpn.example.com 1194 udp\r
        # ca commented.crt\r
        ca ca.crt\r
        cert client.crt\r
        key "client key.pem"\r
        tls-auth ta.key 1\r
        auth-user-pass creds.txt\r
        askpass pass.txt\r
        dh none\r
        """)
        let p = try store.importOVPN(url, name: "Acme")
        XCTAssertEqual(p.passwordMode, .keychain)
        let text = try String(contentsOf: store.ovpnURL(p.id))
        XCTAssertFalse(text.contains("\r"))
        XCTAssertTrue(text.contains("<ca>\n\(caPEM)</ca>\n"))
        XCTAssertTrue(text.contains("<cert>\n\(certPEM)</cert>\n"))
        XCTAssertTrue(text.contains("<key>\n\(keyPEM)</key>\n"))
        XCTAssertTrue(text.contains("<tls-auth>\n\(taKey)</tls-auth>\nkey-direction 1\n"))
        XCTAssertTrue(text.contains("\nauth-user-pass\n"))
        XCTAssertTrue(text.contains("# ca commented.crt"))
        XCTAssertTrue(text.contains("dh none"))
        for gone in ["ca.crt\n", "client.crt", "client key.pem", "ta.key", "creds.txt", "askpass"] {
            XCTAssertFalse(text.contains(gone), gone)
        }
        XCTAssertNoThrow(try OVPNSanitizer.sanitize(text))
        XCTAssertEqual(try mode(store.ovpnURL(p.id)), 0o600)
    }

    func testTLSAuthWithoutDirectionAndSecret() throws {
        let url = try makeFolder("client\ntls-auth ta.key\nsecret ta.key 0\ntls-crypt ta.key\n")
        let text = try OVPNInliner.inline(try String(contentsOf: url), baseDir: url.deletingLastPathComponent())
        XCTAssertTrue(text.hasPrefix("client\n<tls-auth>\n\(taKey)</tls-auth>\n<secret>\n\(taKey)</secret>\nkey-direction 0\n<tls-crypt>"))
        XCTAssertEqual(text.components(separatedBy: "key-direction").count, 2)
    }

    func testPKCS12IsBase64() throws {
        let p12 = Data((0..<300).map { UInt8($0 % 256) })
        let url = try makeFolder("client\npkcs12 bundle.p12\nremote vpn.example.com\n", extra: ["bundle.p12": p12])
        let text = try OVPNInliner.prepare(try String(contentsOf: url), baseDir: url.deletingLastPathComponent())
        let start = text.range(of: "<pkcs12>\n")!.upperBound
        let end = text.range(of: "\n</pkcs12>")!.lowerBound
        let b64 = String(text[start..<end])
        XCTAssertTrue(b64.components(separatedBy: "\n").allSatisfy { $0.count <= 64 })
        XCTAssertEqual(Data(base64Encoded: b64, options: .ignoreUnknownCharacters), p12)
    }

    func testUpwardAndAbsolutePathsAllowedWhenTheyExist() throws {
        let shared = home.appendingPathComponent("shared", isDirectory: true)
        try FileManager.default.createDirectory(at: shared, withIntermediateDirectories: true)
        try Data(caPEM.utf8).write(to: shared.appendingPathComponent("root.crt"))
        let absKey = home.appendingPathComponent("abs.key")
        try Data(keyPEM.utf8).write(to: absKey)
        let url = try makeFolder("client\nca ../shared/root.crt\nkey \(absKey.path)\nremote vpn.example.com\n")
        let p = try store.importOVPN(url, name: nil)
        let text = try String(contentsOf: store.ovpnURL(p.id))
        XCTAssertTrue(text.contains("<ca>\n\(caPEM)</ca>"))
        XCTAssertTrue(text.contains("<key>\n\(keyPEM)</key>"))
    }

    func testMissingReferencedFileCreatesNothing() throws {
        let url = try makeFolder("client\nca ca.crt\ncert missing.crt\n")
        assertThrows(.ovpnReferencedFile("missing.crt")) { _ = try store.importOVPN(url, name: "Acme") }
        let upward = try makeFolder("client\nca ../../nowhere/ca.crt\n")
        assertThrows(.ovpnReferencedFile("../../nowhere/ca.crt")) { _ = try store.importOVPN(upward, name: "Acme") }
        XCTAssertTrue(store.list().isEmpty)
        XCTAssertTrue(PTError.ovpnReferencedFile("missing.crt").localizedDescription.contains("missing.crt"))
    }

    func testDevicesDirectoriesAndLargeFilesRefused() throws {
        let link = home.appendingPathComponent("zero.key")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "/dev/zero")
        let big = Data(repeating: 0x41, count: OVPNInliner.maxReferencedFileSize + 1)
        let url = try makeFolder("client\n", extra: ["big.crt": big])
        let base = url.deletingLastPathComponent()
        assertThrows(.ovpnReferencedFile("/dev/zero")) { _ = try OVPNInliner.inline("key /dev/zero\n", baseDir: base) }
        assertThrows(.ovpnReferencedFile(link.path)) { _ = try OVPNInliner.inline("key \(link.path)\n", baseDir: base) }
        assertThrows(.ovpnReferencedFile("..")) { _ = try OVPNInliner.inline("ca ..\n", baseDir: base) }
        assertThrows(.fileTooLarge("big.crt")) { _ = try OVPNInliner.inline("ca big.crt\n", baseDir: base) }
        assertThrows(.ovpnReferencedFile(".")) { _ = try OVPNInliner.inline("crl-verify . dir\n", baseDir: base) }
    }

    func testFileThatWouldCloseTheBlockIsRefused() throws {
        let url = try makeFolder("client\nca evil.crt\n", extra: ["evil.crt": Data("x\n</ca>\nup /tmp/x.sh\n".utf8)])
        assertThrows(.ovpnReferencedFile("evil.crt")) { _ = try store.importOVPN(url, name: nil) }
    }

    func testForbiddenDirectiveIsRejectedWithClearError() throws {
        let url = try makeFolder("client\nca ca.crt\nscript-security 2\nup /tmp/x.sh\nplugin /tmp/x.so\ntls-verify /tmp/v.sh\n"
                                 + "remote vpn.example.com\n")
        XCTAssertThrowsError(try store.importOVPN(url, name: "Acme")) { error in
            guard case .ovpnNotAllowed(let violations) = error as? PTError else { return XCTFail("\(error)") }
            // Line numbers of the file as written (ca.crt is embedded above them); skipped lines are not listed.
            XCTAssertEqual(violations, ["line 5: plugin (not allowed)", "line 6: tls-verify (not allowed)"])
            XCTAssertTrue(error.localizedDescription.contains("plugin"))
        }
        XCTAssertTrue(store.list().isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.dir("acme").path))
    }

    func testInlineConfigIsKeptAsIs() throws {
        let original = "client\nremote vpn.example.com\n<ca>\nca ca.crt\n</ca>\n<connection>\nremote vpn2.example.com\n</connection>\nauth-user-pass\n"
        XCTAssertEqual(try OVPNInliner.inline(original, baseDir: home), original)
        XCTAssertEqual(try OVPNInliner.inline("ca [inline]\n<ca>\nx\n</ca>\n", baseDir: home), "ca [inline]\n<ca>\nx\n</ca>\n")
    }

    func testSetOVPNInlinesAndChecks() throws {
        let p = try store.create(name: "Acme", type: .openvpn)
        let good = try makeFolder("client\nca ca.crt\nremote vpn.example.com\n")
        try store.setOVPN(p.id, from: good)
        XCTAssertTrue(try String(contentsOf: store.ovpnURL(p.id)).contains("<ca>"))
        let bad = try makeFolder("client\ndown /tmp/x.sh\n")
        XCTAssertThrowsError(try store.setOVPN(p.id, from: bad))
        XCTAssertTrue(try String(contentsOf: store.ovpnURL(p.id)).contains("<ca>"))
    }

    func testShareImportRejectsUnsafeConfig() throws {
        let ovpn = Data("client\nca /etc/ssl/cert.pem\n".utf8).base64EncodedString()
        let url = try write(#"{"passtunnel_profile":1,"profile":{"name":"Acme","type":"openvpn"},"files":{"config.ovpn":"\#(ovpn)"}}"#,
                            name: "acme.passtunnel")
        XCTAssertThrowsError(try store.importShare(url, name: nil)) { error in
            guard case .ovpnNotAllowed = error as? PTError else { return XCTFail("\(error)") }
        }
        XCTAssertTrue(store.list().isEmpty)
    }
}
