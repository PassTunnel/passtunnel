import Foundation
import XCTest
@testable import PassTunnelCore

final class ProfileStoreStressTests: CoreTestCase {
    func testConcurrentCreatesGetUniqueIDs() throws {
        let ids = Locked<[String]>([])
        DispatchQueue.concurrentPerform(iterations: 24) { _ in
            if let p = try? ProfileStore().create(name: "Acme VPN", type: .openvpn) { ids.mutate { $0.append(p.id) } }
        }
        XCTAssertEqual(ids.value.count, 24)
        XCTAssertEqual(Set(ids.value).count, 24)
        XCTAssertEqual(Set(store.list().map(\.order)).count, 24, "orders are unique too")
    }

    func testConcurrentUpdatesLoseNothing() throws {
        let p = try store.create(name: "Acme", type: .openvpn)
        DispatchQueue.concurrentPerform(iterations: 40) { _ in
            _ = try? ProfileStore().update(p.id) { $0.sessionLimitMin += 1 }
        }
        XCTAssertEqual(try store.get(p.id).sessionLimitMin, 40)
    }

    /// `passtunnel rm` while the app writes one field (e.g. the remembered user name) must not bring
    /// the deleted profile back.
    func testDeleteDuringUpdateDoesNotResurrectTheProfile() throws {
        let p = try store.create(name: "Acme", type: .openvpn)
        try Secrets.set(p.id, .password, "pw")
        let deleted = DispatchSemaphore(value: 0)
        let deleter = DispatchGroup()
        _ = try? store.update(p.id) { profile in
            DispatchQueue.global().async(group: deleter) {
                try? ProfileStore().delete(p.id)
                deleted.signal()
            }
            _ = deleted.wait(timeout: .now() + 0.2)   // returns at once without the lock, times out with it
            profile.lastUsername = "bob"
        }
        deleter.wait()
        XCTAssertFalse(store.exists(p.id))
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.dir(p.id).path))
        XCTAssertNil(Secrets.get(p.id, .password))
        XCTAssertEqual(store.list(), [])
    }

    func testListWhileDeletingNeverCrashes() throws {
        for i in 0..<30 { _ = try store.create(name: "Acme \(i)", type: .forti) }
        let ids = store.list().map(\.id)
        DispatchQueue.concurrentPerform(iterations: 2) { worker in
            if worker == 0 {
                for id in ids { try? ProfileStore().delete(id) }
            } else {
                for _ in 0..<50 { _ = ProfileStore().list() }
            }
        }
        XCTAssertEqual(store.list(), [])
    }

    func testCorruptAndHandEditedFiles() throws {
        let good = try store.create(name: "Good", type: .openvpn)
        let bad = try store.create(name: "Bad", type: .openvpn)
        try Data("{\"name\": \"Bad\", ".utf8).write(to: store.profileURL(bad.id))
        XCTAssertEqual(store.list().map(\.id), [good.id], "damaged entries are skipped")
        XCTAssertThrowsError(try store.get(bad.id)) { XCTAssertEqual($0 as? PTError, .invalidFile("profile.json")) }
        XCTAssertThrowsError(try store.update(bad.id) { $0.pinned = true })
        XCTAssertNoThrow(try store.delete(bad.id), "a damaged profile can still be removed")

        // Wrong types, unknown keys, nulls and a foreign id: tolerated, the directory name wins.
        try Data("""
        {"id": "../../etc", "name": 42, "type": "wireguard", "port": "443", "totp": null, "otp_mode": "TOTP",
         "future_key": {"a": [1, 2]}, "session_limit_min": -5}
        """.utf8).write(to: store.profileURL(good.id))
        let p = try store.get(good.id)
        XCTAssertEqual(p.id, good.id)
        XCTAssertEqual(p.name, good.id)
        XCTAssertEqual(p.type, .openvpn)
        XCTAssertEqual(p.port, 443)
        XCTAssertEqual(p.otpMode, .none)
        XCTAssertEqual(p.totp, TOTPParams())
        XCTAssertThrowsError(try store.update(good.id) { $0.pinned = true }, "an invalid stored value is not written back") {
            XCTAssertEqual($0 as? PTError, .invalidField("session_limit_min"))
        }
    }

    func testMissingDirectoriesAndBadIDs() throws {
        XCTAssertEqual(store.list(), [])
        assertThrows(.profileNotFound("acme")) { _ = try store.get("acme") }
        for id in ["", "..", "../acme", "acme/..", "a/b", "Acme", "acme-", "-acme", "a--b", "acme ", "ac me", "şirket",
                   "acme\u{0}", String(repeating: "a", count: 65)] {
            assertThrows(.invalidProfileID(id)) { _ = try store.get(id) }
            assertThrows(.invalidProfileID(id)) { try store.delete(id) }
            assertThrows(.invalidProfileID(id)) { try store.save(Profile(id: id, name: "X", type: .openvpn)) }
            XCTAssertFalse(store.exists(id))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent("acme").path))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: home.path).filter { $0 != "profiles" }, [])
    }

    func testUnicodeNamesAndSlugCollisions() throws {
        for name in ["日本語 VPN", "🔥🔥", "Ünïcödé Ağ", "شبكة", "   Spaces   ", "../../etc/passwd", "CON", ".", "-"] {
            let p = try store.create(name: name, type: .openvpn)
            XCTAssertTrue(Slug.isValid(p.id), "\(name) → \(p.id)")
            XCTAssertLessThanOrEqual(p.id.count, Slug.maxIDLength)
            XCTAssertEqual(try store.get(p.id).name, name.trimmingCharacters(in: .whitespaces))
        }
        XCTAssertTrue(store.exists("etc-passwd"))
        assertThrows(.emptyName) { _ = try store.create(name: " \n\t", type: .openvpn) }

        let long = "Acme Corporation Remote Access Gateway"
        let ids = try (0..<12).map { _ in try store.create(name: long, type: .forti).id }
        XCTAssertEqual(Set(ids).count, 12)
        XCTAssertTrue(ids.allSatisfy { Slug.isValid($0) && $0.count <= Slug.maxIDLength }, "\(ids)")
    }

    func testHundredProfiles() throws {
        let ids = try (0..<100).map { _ in try store.create(name: "Acme", type: .openvpn).id }
        XCTAssertEqual(Set(ids).count, 100)
        XCTAssertEqual(ids.first, "acme")
        XCTAssertEqual(ids.last, "acme-100")
        XCTAssertEqual(store.list().map(\.id), ids, "listed in creation order")
    }

    func testExternalEditIsSeenByEveryRead() throws {
        let p = try store.create(name: "Acme", type: .openvpn)
        var edited = p
        edited.username = "alice"
        edited.totp.period = 60
        try JSONCoding.write(edited, to: store.profileURL(p.id), mode: 0o600)   // another process
        XCTAssertEqual(try store.get(p.id).username, "alice")
        XCTAssertEqual(store.list().first?.totp.period, 60)
        XCTAssertEqual(try store.update(p.id) { $0.pinned = true }.username, "alice")
    }
}

final class ShareFileStressTests: CoreTestCase {
    func share(_ json: String) throws -> URL { try write(json, name: "x-\(UUID().uuidString).passtunnel") }

    func testExportNeverContainsSecretsOrPersonalFields() throws {
        var p = try store.create(name: "Acme", type: .openvpn)
        p.username = "alice-user"
        p.lastUsername = "bob-last"
        p.otpMode = .totp
        p.pinned = true
        try store.save(p)
        try Data("client\nremote vpn.example.com 1194\n".utf8).write(to: store.ovpnURL(p.id))
        try Secrets.set(p.id, .password, "Pa55-word-XYZ")
        try Secrets.set(p.id, .totp, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        let out = home.appendingPathComponent("acme.passtunnel")
        try store.exportShare(p.id, to: out)
        let text = try String(contentsOf: out, encoding: .utf8)
        for secret in ["Pa55-word-XYZ", "GEZDGNBVGY3TQOJQ", "12345678901234567890", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA",
                       "alice-user", "bob-last", "\"pinned\"", "\"order\"", "configImportedAt", "config_imported_at"] {
            XCTAssertFalse(text.contains(secret), secret)
        }
        XCTAssertEqual(try mode(out), 0o600)
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    func testHostileShareFilesAreRejectedAndCreateNothing() throws {
        let up = Data("client\nup /tmp/x.sh\n".utf8).base64EncodedString()
        let ext = Data("client\nca /etc/ssl/cert.pem\n".utf8).base64EncodedString()
        let notUTF8 = Data([0x63, 0xFF, 0xFE, 0x0A]).base64EncodedString()
        let cases: [(String, PTError?)] = [
            ("{}", .unsupportedShareFile),
            ("[]", .unsupportedShareFile),
            ("not json", .unsupportedShareFile),
            ("{\"passtunnel_profile\": 2, \"profile\": {\"name\": \"A\"}}", .unsupportedShareFile),
            ("{\"passtunnel_profile\": 0, \"profile\": {\"name\": \"A\"}}", .unsupportedShareFile),
            ("{\"passtunnel_profile\": \"1\", \"profile\": {\"name\": \"A\"}}", .unsupportedShareFile),
            ("{\"passtunnel_profile\": 1}", .unsupportedShareFile),
            ("{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"A\"}, \"files\": {\"config.ovpn\": \"\(up)\"}}", nil),
            ("{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"A\"}, \"files\": {\"config.ovpn\": \"\(ext)\"}}", nil),
            ("{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"A\"}, \"files\": {\"config.ovpn\": \"\(notUTF8)\"}}",
             .invalidFile("config.ovpn")),
            ("{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"A\", \"totp\": {\"period\": 0}}}", .invalidField("totp.period")),
            ("{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"A\", \"port\": 70000}}", .invalidField("port")),
            ("{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"A\", \"otp_mode\": \"totp\", \"otp_template\": \"{password}\"}}", nil),
        ]
        for (json, expected) in cases {
            XCTAssertThrowsError(try store.importShare(try share(json), name: nil), json) { error in
                if let expected { XCTAssertEqual(error as? PTError, expected, json) }
            }
        }
        XCTAssertEqual(store.list(), [], "nothing left behind")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: store.paths.profilesDir.path).filter { !$0.hasPrefix(".") }, [])
    }

    func testOversizedShareFiles() throws {
        let big = home.appendingPathComponent("big.passtunnel")
        try Data(count: ShareFile.maxSize + 1).write(to: big)
        assertThrows(.fileTooLarge("big.passtunnel")) { _ = try store.importShare(big, name: nil) }

        // A config just over the limit, still inside a share file under 4 MB.
        let ovpn = Data(("client\n" + String(repeating: "# padding padding padding\n", count: ProfileStore.maxOVPNSize / 26 + 10)).utf8)
        let json = "{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"A\"}, \"files\": {\"config.ovpn\": \"\(ovpn.base64EncodedString())\"}}"
        assertThrows(.fileTooLarge("config.ovpn")) { _ = try store.importShare(try share(json), name: nil) }
        XCTAssertEqual(store.list(), [])
    }

    func testPathsAndIDsFromTheFileAreNeverUsed() throws {
        let ovpn = Data("client\nremote vpn.example.com 1194\n".utf8).base64EncodedString()
        let json = """
        {"passtunnel_profile": 1,
         "profile": {"id": "../../escape", "name": "../../Escape", "type": "openvpn", "config_source_name": "../../x.ovpn",
                     "session_limit_min": -10, "username": "mallory", "pinned": true},
         "files": {"config.ovpn": "\(ovpn)", "../../evil.sh": "\(ovpn)", "/tmp/evil": "\(ovpn)", "profile.json": "\(ovpn)"}}
        """
        let p = try store.importShare(try share(json), name: nil)
        XCTAssertEqual(p.id, "escape")
        XCTAssertEqual(p.sessionLimitMin, 0)
        XCTAssertEqual(p.username, "", "per-user fields are not taken from a share file")
        XCTAssertFalse(p.pinned)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: store.dir(p.id).path).sorted(),
                       ["config.ovpn", "profile.json"])
        XCTAssertEqual(try store.get(p.id).name, "../../Escape")
        let all = FileManager.default.enumerator(atPath: home.path)?.allObjects as? [String] ?? []
        XCTAssertFalse(all.contains { $0.hasSuffix("evil.sh") || $0.hasSuffix("evil") })
        XCTAssertFalse(FileManager.default.fileExists(atPath: "/tmp/evil"))
    }
}

final class CLIInputStressTests: XCTestCase {
    func parse(_ args: [String]) throws -> CLICommand { try CLICommand.parse(args) }

    func assertUsage(_ args: [String], file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try parse(args), "\(args)", file: file, line: line) {
            XCTAssertTrue($0 is CLIUsageError, "\($0)", file: file, line: line)
        }
    }

    /// Exit code 2 (usage) for every malformed command line.
    func testMalformedCommandLines() {
        for args in [["frobnicate"], ["Status"], ["CONNECT"], ["show"], ["set"], ["set", "acme"], ["set", "acme", "=x"],
                     ["set", "acme", "username=alice", "--pinned=true"], ["set", "--bogus", "acme", "a=b"],
                     ["add"], ["add", "--type"], ["add", "Acme", "--type", ""], ["add", "Acme", "--type", "wireguard", "-x"],
                     ["add", "Acme", "-t", "forti", "--weird"], ["import"], ["import", "a", "b"], ["import", "--name"],
                     ["export"], ["export", "acme", "-o"], ["rm"], ["rm", "a", "b"], ["secret", "acme"],
                     ["secret", "acme", "otp"], ["secret", "acme", "totp", "extra"], ["log"], ["pin"], ["unpin", "a", "b"],
                     ["helper", "start"], ["completion"], ["completion", "powershell"], ["code", "--copy=1"],
                     ["status", "a", "b"], ["disconnect", "--all", "acme"], ["toggle", "-x"], ["default", "a", "b"],
                     ["list", "extra"], ["help", "a", "b"]] {
            assertUsage(args)
        }
    }

    func testOddButValidCommandLines() throws {
        XCTAssertEqual(try parse(["set", "acme", "otp_template={password}=={otp}", "badge=-", "session_limit=-5"]),
                       .set(id: "acme", assignments: [.init(key: "otp_template", value: "{password}=={otp}"),
                                                      .init(key: "badge", value: "-"), .init(key: "session_limit", value: "-5")]))
        XCTAssertEqual(try parse(["import", "--name=", "a.ovpn"]), .importFile(path: "a.ovpn", name: ""))
        XCTAssertEqual(try parse(["import", "--", "--name"]), .importFile(path: "--name", name: nil))
        XCTAssertEqual(try parse(["add", "--type", "forti", "--type", "openvpn", "Acme"]), .add(name: "Acme", type: .openvpn),
                       "the last --type wins")
        XCTAssertEqual(try parse(["add", "-t", "FortiGate", "Şirket", "VPN"]), .add(name: "Şirket VPN", type: .forti))
        XCTAssertEqual(try parse(["connect", "-"]), .connect(id: "-"))
        XCTAssertEqual(try parse(["secret", "acme", "TOTP"]), .secret(id: "acme", kind: .totp))
        XCTAssertEqual(try parse(["off", "--all"]), .disconnect(id: nil, all: true))
        XCTAssertEqual(try parse(["status", "-h"]), .help(command: "status"))
        XCTAssertEqual(try parse(["import", "--", "-h"]), .importFile(path: "-h", name: nil), "-h after -- is a file")
    }

    /// `printf 'pw\r\n' | passtunnel secret acme password` must store "pw". Swift treats "\r\n" as
    /// one Character, so `hasSuffix("\n")` does not see it.
    func testPipedInputLosesOnlyItsLineBreak() {
        let cases: [(String, String)] = [
            ("pw", "pw"), ("pw\n", "pw"), ("pw\r\n", "pw"), ("pw\r", "pw"), ("pw\n\n", "pw"), ("pw\r\n\r\n", "pw"),
            ("pw \n", "pw "), ("\tpw\n", "\tpw"), ("p\r\nw\r\n", "p\r\nw"), ("\n", ""), ("\r\n", ""), ("", ""),
            ("şifre🔥\r\n", "şifre🔥"),
        ]
        for (input, expected) in cases {
            XCTAssertEqual(CLICommand.trimmingFinalLineBreaks(input), expected, input.debugDescription)
            XCTAssertEqual(Array(CLICommand.trimmingFinalLineBreaks(input).utf8), Array(expected.utf8), input.debugDescription)
        }
    }
}

/// Minimal thread-safe box for concurrency tests.
final class Locked<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: T
    init(_ value: T) { _value = value }
    var value: T { lock.lock(); defer { lock.unlock() }; return _value }
    func mutate(_ body: (inout T) -> Void) { lock.lock(); body(&_value); lock.unlock() }
}
