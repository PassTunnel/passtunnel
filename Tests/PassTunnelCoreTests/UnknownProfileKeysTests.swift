import Foundation
import XCTest

@testable import PassTunnelCLI
@testable import PassTunnelCore
@testable import PassTunnelKit

/// Keys a newer PassTunnel added to a profile of a type this version knows survive every save here (#200), are never
/// shared, and go with a change of the type. Golden cases: fixtures/profile-json.json, profile-merge.json and
/// share-files.json.
final class UnknownProfileKeysTests: CoreTestCase {
    /// An OpenVPN profile.json as a newer version might write it: keys this version has no field for.
    static let newerJSON = """
        {"id": "acme", "name": "Acme", "type": "openvpn", "username": "alice",
         "future_option": "on", "future_proxy": {"host_name": "proxy.example.com", "port": 8080},
         "future_big": 9007199254740993, "future_max": 18446744073709551615,
         "future_list": [true, 1, 1.5, null, "x"]}
        """

    func writeNewer(_ json: String = newerJSON) throws {
        try FileIO.makeDirectory(store.dir("acme"))
        try Data(json.utf8).write(to: store.profileURL("acme"))
    }

    func storedText() throws -> String { String(decoding: try Data(contentsOf: store.profileURL("acme")), as: UTF8.self) }

    func stored() throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: store.profileURL("acme"))) as? [String: Any])
    }

    /// The newer keys are in profile.json, with their values as written (integers exact).
    func assertKept(file: StaticString = #filePath, line: UInt = #line) throws {
        let object = try stored()
        XCTAssertEqual(object["future_option"] as? String, "on", file: file, line: line)
        let proxy = try XCTUnwrap(object["future_proxy"] as? [String: Any], file: file, line: line)
        XCTAssertEqual(proxy["host_name"] as? String, "proxy.example.com", file: file, line: line)
        XCTAssertEqual(proxy["port"] as? Int, 8080, file: file, line: line)
        XCTAssertEqual((object["future_list"] as? [Any])?.count, 5, file: file, line: line)
        let text = try storedText()
        XCTAssertTrue(text.contains("9007199254740993"), text, file: file, line: line)
        XCTAssertTrue(text.contains("18446744073709551615"), text, file: file, line: line)
        XCTAssertTrue(text.contains("[\n    true,\n    1,\n    1.5,\n    null,\n    \"x\"\n  ]"), text, file: file, line: line)
    }

    func assertNoNewerKeys(_ object: [String: Any], file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(object.keys.filter { $0.hasPrefix("future") }, [], file: file, line: line)
    }

    // MARK: saves

    func testASaveWritesThemBack() throws {
        try writeNewer()
        let p = try store.get("acme")
        XCTAssertFalse(p.unknownKeys.isEmpty)
        try store.save(p)
        try assertKept()
        XCTAssertEqual(try store.get("acme"), p)
        // Written back as read: the second save writes the same bytes.
        let first = try storedText()
        try store.save(try store.get("acme"))
        XCTAssertEqual(try storedText(), first)
    }

    func testUpdatesSetOVPNAndPinningKeepThem() throws {
        try writeNewer()
        try store.update("acme") {
            $0.name = "Acme Prod"
            $0.lastUsername = "alice"
        }
        try assertKept()
        let config = try write("client\nremote vpn.example.com 1194\n<ca>\nx\n</ca>\n", name: "acme.ovpn")
        try store.setOVPN("acme", from: config)
        try assertKept()
        var p = try store.get("acme")
        p.pinned = true
        try store.save(p)
        try assertKept()
        XCTAssertEqual(try stored()["name"] as? String, "Acme Prod")
        XCTAssertEqual(try stored()["pinned"] as? Bool, true)
        XCTAssertEqual(try stored()["config_source_name"] as? String, "acme.ovpn")
    }

    func testSettingTheDefaultLeavesTheFileAlone() throws {
        try writeNewer()
        let before = try Data(contentsOf: store.profileURL("acme"))
        try store.setDefault("acme")
        XCTAssertEqual(try Data(contentsOf: store.profileURL("acme")), before)
    }

    /// The editor's Save (`EditorModel.save`): a merge onto the stored profile, which has the newer keys, also
    /// ones a newer version added while the sheet was open.
    func testTheEditorsMergeKeepsTheStoredProfilesKeys() throws {
        try writeNewer()
        let original = try store.get("acme")
        var edited = original
        edited.name = "Acme Corp"
        XCTAssertEqual(try ProfileMerge.changedFields(from: original, to: edited), ["name"])
        var object = try stored()
        object["future_mode"] = "fast"
        try JSONSerialization.data(withJSONObject: object).write(to: store.profileURL("acme"))
        let saved = try store.update("acme") {
            $0 = try ProfileMerge.merge(original: original, edited: edited, current: $0)
        }
        XCTAssertEqual(saved.name, "Acme Corp")
        try assertKept()
        XCTAssertEqual(try stored()["future_mode"] as? String, "fast")
    }

    func testChangingTheTypeDropsThem() throws {
        try writeNewer()
        let p = try store.update("acme") {
            $0.type = .forti
            $0.host = "vpn.example.com"
        }
        XCTAssertTrue(p.unknownKeys.isEmpty)
        assertNoNewerKeys(try stored())
        XCTAssertEqual(try stored()["type"] as? String, "forti")

        // The same through the editor's merge.
        try writeNewer()
        let original = try store.get("acme")
        var edited = original
        edited.type = .forti
        edited.host = "vpn.example.com"
        let merged = try store.update("acme") { $0 = try ProfileMerge.merge(original: original, edited: edited, current: $0) }
        XCTAssertEqual(merged.type, .forti)
        assertNoNewerKeys(try stored())
    }

    // MARK: CLI

    @MainActor
    func testCLISetAndPinKeepThem() async throws {
        try writeNewer()
        let set = await runCLI(.set(id: "acme", assignments: [.init(key: "name", value: "Acme Prod"), .init(key: "auto_reconnect", value: "no")]))
        XCTAssertEqual(set.code, 0, set.err)
        try assertKept()
        XCTAssertEqual(try stored()["name"] as? String, "Acme Prod")
        let pin = await runCLI(.pin(id: "acme"))
        XCTAssertEqual(pin.code, 0, pin.err)
        try assertKept()
        let show = await runCLI(.show(id: "acme", json: false))
        XCTAssertFalse(show.out.contains("future"), show.out)
    }

    // MARK: share files

    func testExportLeavesThemOutAndImportIgnoresThem() throws {
        try writeNewer()
        let url = home.appendingPathComponent("acme.passtunnel")
        try store.exportShare("acme", to: url)
        let text = try String(contentsOf: url, encoding: .utf8)
        XCTAssertFalse(text.contains("future"), text)

        let incoming = try write(
            """
            {"passtunnel_profile": 1, "future_top": 1,
             "profile": {"name": "Shared", "type": "forti", "host": "vpn.example.com", "future_option": "on"}}
            """, name: "shared.passtunnel")
        let share = try ShareFile.read(from: incoming)
        XCTAssertTrue(share.profile.unknownKeys.isEmpty)
        let imported = try store.importShare(incoming, name: nil)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: store.profileURL(imported.id))) as? [String: Any])
        assertNoNewerKeys(object)
        XCTAssertEqual(object["host"] as? String, "vpn.example.com")
    }

    // MARK: odd keys

    /// A key that differs from a known one, or another unknown one, only in case and underscores is not kept: the
    /// snake_case strategy would write both under one name, and a file with a key twice may not be read again.
    func testKeysTheKeyStrategyWouldMergeAreDropped() throws {
        try writeNewer(
            """
            {"id": "acme", "name": "Acme", "type": "forti", "sessionlimitmin": 5, "fooBAR": 1, "foo_bar": 2, "future_ok": 3}
            """)
        try store.save(try store.get("acme"))
        let text = try storedText()
        XCTAssertEqual(text.components(separatedBy: "\"foo_bar\"").count, 2, text)
        XCTAssertFalse(text.contains("sessionlimitmin"), text)
        let object = try stored()
        XCTAssertEqual(object["session_limit_min"] as? Int, 0)
        XCTAssertEqual(object["future_ok"] as? Int, 3)
        XCTAssertEqual(try store.get("acme").name, "Acme")
    }

    /// Runs `command` in the CLI runner with standard output and error captured.
    @MainActor
    private func runCLI(_ command: CLICommand) async -> (code: Int32, out: String, err: String) {
        let out = Pipe(), err = Pipe()
        let savedOut = dup(1), savedErr = dup(2)
        dup2(out.fileHandleForWriting.fileDescriptor, 1)
        dup2(err.fileHandleForWriting.fileDescriptor, 2)
        let code = await CLIRunner(options: CLIOptions(noInput: true)).run(command)
        dup2(savedOut, 1)
        dup2(savedErr, 2)
        close(savedOut)
        close(savedErr)
        try? out.fileHandleForWriting.close()
        try? err.fileHandleForWriting.close()
        let text = { (pipe: Pipe) in String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self) }
        return (code, text(out), text(err))
    }
}
