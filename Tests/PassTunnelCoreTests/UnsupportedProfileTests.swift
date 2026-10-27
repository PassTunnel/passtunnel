import Foundation
import XCTest

@testable import PassTunnelCLI
@testable import PassTunnelCore
@testable import PassTunnelKit

/// A profile of a VPN type this version does not know (written by a newer PassTunnel) is kept as it is, listed as
/// needing a newer version, and refused by everything but delete.
final class UnsupportedProfileTests: CoreTestCase {
    /// What a newer version might write: a type of its own and keys this version has no field for.
    static let futureJSON = """
        {
          "id": "future",
          "name": "Future VPN",
          "order": 5,
          "type": "anyconnect",
          "host": "vpn.example.com",
          "username": "alice",
          "auth_group": "staff",
          "profile_xml": {"servers": ["a", "b"], "retries": 3},
          "set_dns": true
        }

        """

    /// Writes `futureJSON` as profile `id` and returns its bytes.
    @discardableResult
    func writeFuture(_ id: String = "future", json: String = futureJSON) throws -> Data {
        try paths.ensureDirectories()
        try FileIO.makeDirectory(store.dir(id))
        let data = Data(json.utf8)
        try data.write(to: store.profileURL(id))
        return data
    }

    var paths: AppPaths { store.paths }

    // MARK: reading

    func testAnUnknownTypeIsNotReadAsOpenVPN() throws {
        let data = Data(Self.futureJSON.utf8)
        XCTAssertThrowsError(try JSONCoding.decode(Profile.self, from: data)) { error in
            XCTAssertEqual(error as? PTError, .unsupportedProfileType("anyconnect"))
        }
        // No type at all is an old OpenVPN profile, as before.
        XCTAssertEqual(try JSONCoding.decode(Profile.self, from: Data("{\"name\": \"Old\"}".utf8)).type, .openvpn)
        XCTAssertEqual(try JSONCoding.decode(Profile.self, from: Data("{\"type\": \"forti\"}".utf8)).type, .forti)
    }

    func testListedApartFromTheProfiles() throws {
        try writeFuture()
        let known = try store.create(name: "Known", type: .openvpn)
        XCTAssertEqual(store.list().map(\.id), [known.id])
        let listed = store.listUnsupported()
        XCTAssertEqual(listed.map(\.id), ["future"])
        XCTAssertEqual(listed.first?.name, "Future VPN")
        XCTAssertEqual(listed.first?.type, "anyconnect")
        XCTAssertEqual(listed.first?.order, 5)
        XCTAssertNil(store.unsupportedProfile(known.id))
        XCTAssertNotNil(store.unsupportedProfile("future"))
        XCTAssertNil(store.unsupportedProfile("../future"))
    }

    func testDamagedAndUntypedFilesAreNotUnsupported() throws {
        try writeFuture("broken", json: "{not json")
        try writeFuture("untyped", json: "{\"name\": \"Old\"}")
        try writeFuture("number", json: "{\"name\": \"N\", \"type\": 3}")
        XCTAssertEqual(store.listUnsupported(), [])
        // A `type` that is not even a string is read as before.
        XCTAssertEqual(store.list().map(\.id), ["number", "untyped"])
    }

    func testTheNameFallsBackToTheID() throws {
        try writeFuture("nameless", json: "{\"type\": \"anyconnect\", \"name\": \"  \"}")
        XCTAssertEqual(store.listUnsupported().map(\.name), ["nameless"])
    }

    // MARK: kept as it is

    func testTheFileSurvivesSavesOfOtherProfilesByteForByte() throws {
        let original = try writeFuture()
        var other = try store.create(name: "Other", type: .openvpn)
        other.pinned = true
        try store.save(other)
        _ = try store.update(other.id) { $0.name = "Renamed" }
        try store.setDefault(other.id)
        let second = try store.create(name: "Second", type: .forti)
        try store.delete(second.id)
        XCTAssertEqual(try Data(contentsOf: store.profileURL("future")), original)
        // Same object, unknown keys and all.
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: original) as? NSDictionary)
        let stored = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: store.profileURL("future"))) as? NSDictionary)
        XCTAssertEqual(stored, object)
        XCTAssertEqual(stored["auth_group"] as? String, "staff")
    }

    func testNothingButDeleteWorks() throws {
        let original = try writeFuture()
        let expected = PTError.unsupportedProfileType("anyconnect")
        assertThrows(expected) { _ = try store.get("future") }
        assertThrows(expected) { _ = try store.update("future") { $0.pinned = true } }
        assertThrows(expected) { try store.save(Profile(id: "future", name: "Overwrite", type: .openvpn)) }
        assertThrows(expected) { try store.setDefault("future") }
        assertThrows(expected) { try store.exportShare("future", to: home.appendingPathComponent("out.passtunnel")) }
        assertThrows(expected) { _ = try store.setOVPN("future", from: home.appendingPathComponent("x.ovpn")) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent("out.passtunnel").path))
        XCTAssertEqual(try Data(contentsOf: store.profileURL("future")), original)

        try store.delete("future")
        XCTAssertEqual(store.listUnsupported(), [])
        XCTAssertFalse(store.exists("future"))
    }

    func testDeleteClearsTheDefault() throws {
        try writeFuture()
        var prefs = Preferences.load(paths: paths)
        prefs.defaultProfile = "future"
        try prefs.save(paths: paths)
        try store.delete("future")
        XCTAssertNil(Preferences.load(paths: paths).defaultProfile)
    }

    // MARK: share files

    func testAShareFileOfAnUnknownTypeIsRefused() throws {
        let json = "{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"A\", \"type\": \"anyconnect\", \"host\": \"vpn.example.com\"}}"
        let url = try write(json, name: "future.passtunnel")
        try paths.ensureDirectories()
        assertThrows(.unsupportedProfileType("anyconnect")) { _ = try store.importShare(url, name: nil) }
        XCTAssertThrowsError(try ShareFile.decode(Data(json.utf8))) { error in
            XCTAssertEqual(error as? PTError, .unsupportedProfileType("anyconnect"))
        }
        XCTAssertEqual(store.list(), [])
        XCTAssertEqual(store.listUnsupported(), [])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: paths.profilesDir.path).filter { !$0.hasPrefix(".") }, [])
    }

    func testAShareFileOfAKnownOrMissingTypeStillImports() throws {
        let forti = try write("{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"F\", \"type\": \"forti\"}}", name: "f.passtunnel")
        XCTAssertEqual(try store.importShare(forti, name: nil).type, .forti)
        let bare = try write("{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"B\"}}", name: "b.passtunnel")
        XCTAssertEqual(try store.importShare(bare, name: nil).type, .openvpn)
    }

    // MARK: words

    func testTheMessageSaysItNeedsANewerVersionAndCanBeDeleted() {
        let text = PTError.unsupportedProfileType("anyconnect").localizedDescription
        XCTAssertTrue(text.contains("anyconnect"), text)
        XCTAssertTrue(text.contains("needs a newer PassTunnel"), text)
        XCTAssertTrue(text.contains("deleted"), text)
        XCTAssertEqual(AutomationErrorCode.of(PTError.unsupportedProfileType("anyconnect")), .configInvalid)
    }

    // MARK: CLI

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

    @MainActor
    func testCLIListShowsItAndEverythingElseRefuses() async throws {
        let original = try writeFuture()
        _ = try store.create(name: "Known", type: .openvpn)

        let list = await runCLI(.list(json: false, quiet: false))
        XCTAssertEqual(list.code, 0)
        XCTAssertTrue(list.out.contains("future"), list.out)
        XCTAssertTrue(list.out.contains("Needs a newer PassTunnel"), list.out)
        XCTAssertTrue(list.out.contains("known"), list.out)

        let quiet = await runCLI(.list(json: false, quiet: true))
        XCTAssertEqual(quiet.out.split(separator: "\n").sorted(), ["future", "known"])

        let json = await runCLI(.list(json: true, quiet: false))
        let rows = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.out.utf8)) as? [[String: Any]])
        let row = try XCTUnwrap(rows.first { $0["id"] as? String == "future" })
        XCTAssertEqual(row["type"] as? String, "anyconnect")
        XCTAssertEqual(row["needs_newer_version"] as? Bool, true)
        XCTAssertNil(rows.first { $0["id"] as? String == "known" }?["needs_newer_version"])

        let refused: [CLICommand] = [
            .connect(id: "future"), .toggle(id: "future"), .show(id: "future", json: false),
            .set(id: "future", assignments: [.init(key: "name", value: "x")]), .export(id: "future", output: "\(home.path)/f.passtunnel"),
            .pin(id: "future"), .code(id: "future", copy: false, json: false), .setDefault(id: "future")
        ]
        for command in refused {
            let result = await runCLI(command)
            XCTAssertEqual(result.code, AutomationExit.error, "\(command)")
            XCTAssertTrue(result.err.contains("needs a newer PassTunnel"), "\(command): \(result.err)")
        }
        let asJSON = await runCLI(.connect(id: "future", json: true))
        let error = try XCTUnwrap((JSONSerialization.jsonObject(with: Data(asJSON.out.utf8)) as? [String: Any])?["error"] as? [String: Any])
        XCTAssertEqual(error["code"] as? String, "config_invalid")
        XCTAssertTrue((error["message"] as? String)?.contains("needs a newer PassTunnel") == true)

        XCTAssertEqual(try Data(contentsOf: store.profileURL("future")), original)
        XCTAssertFalse(FileManager.default.fileExists(atPath: "\(home.path)/f.passtunnel"))

        let share = try write(
            "{\"passtunnel_profile\": 1, \"profile\": {\"name\": \"A\", \"type\": \"anyconnect\"}}", name: "future.passtunnel")
        let imported = await runCLI(.importFile(path: share.path, name: nil))
        XCTAssertEqual(imported.code, AutomationExit.error)
        XCTAssertTrue(imported.err.contains("needs a newer PassTunnel"), imported.err)
        XCTAssertEqual(store.list().map(\.id), ["known"])

        let removed = await runCLI(.remove(id: "future", yes: true))
        XCTAssertEqual(removed.code, 0, removed.err)
        XCTAssertTrue(removed.out.contains("Future VPN"), removed.out)
        XCTAssertEqual(store.listUnsupported(), [])
    }
}

extension MCPServerTests {
    func testMCPListsAProfileOfANewerTypeAndRefusesIt() async throws {
        try makeOpenVPN()
        let future = store.dir("future")
        try FileIO.makeDirectory(future)
        let original = Data(UnsupportedProfileTests.futureJSON.utf8)
        try original.write(to: store.profileURL("future"))
        let server = makeServer(allowConnect: true)

        let list = try await structured(server, "list_profiles")
        let rows = try XCTUnwrap(list["profiles"] as? [[String: Any]])
        XCTAssertEqual(rows.map { $0["id"] as? String }, ["acme", "future"])
        XCTAssertEqual(rows[1]["type"] as? String, "anyconnect")
        XCTAssertEqual(rows[1]["needs_newer_version"] as? Bool, true)
        XCTAssertEqual(rows[1]["name"] as? String, "Future VPN")
        XCTAssertNil(rows[0]["needs_newer_version"])

        for (tool, arguments) in [
            ("connect", ["profile_id": "future"]), ("get_status", ["profile_id": "future"]),
            ("disconnect", ["profile_id": "future"]), ("get_logs", ["profile_id": "future"])
        ] {
            let result = try await callTool(server, tool, arguments)
            XCTAssertEqual(result["isError"] as? Bool, true, tool)
            XCTAssertEqual(errorCode(result), "config_invalid", tool)
            let text = ((result["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
            XCTAssertTrue(text.contains("needs a newer PassTunnel"), "\(tool): \(text)")
        }
        XCTAssertTrue(helper.starts.isEmpty)
        XCTAssertEqual(try Data(contentsOf: store.profileURL("future")), original)
    }
}
