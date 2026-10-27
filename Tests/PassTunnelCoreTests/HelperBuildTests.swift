import PassTunnelShared
import XCTest

@testable import PassTunnelCore

final class HelperBuildTests: XCTestCase {
    func testDigestIsTheFileSHA256() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("helper-build-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data("abc".utf8).write(to: url)
        XCTAssertEqual(
            HelperBuild.digest(ofFile: url.path),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        // Larger than one read chunk.
        let big = Data(repeating: 0x61, count: (1 << 20) + 3)
        try big.write(to: url)
        let first = HelperBuild.digest(ofFile: url.path)
        XCTAssertEqual(first?.count, 64)
        var changed = big
        changed[changed.count - 1] = 0x62
        try changed.write(to: url)
        XCTAssertNotEqual(HelperBuild.digest(ofFile: url.path), first)
        XCTAssertNil(HelperBuild.digest(ofFile: url.path + "-missing"))
    }

    func testBundledHelperSitsNextToTheAppExecutable() {
        XCTAssertEqual(
            HelperBuild.bundledHelperPath(nextTo: "/Applications/PassTunnel.app/Contents/MacOS/PassTunnel"),
            "/Applications/PassTunnel.app/Contents/MacOS/PassTunnelHelper")
    }

    func testBuildsCompareOnlyWhenTheBundledOneIsKnown() {
        XCTAssertTrue(HelperBuild.matches(helper: "aa", expected: "aa"))
        XCTAssertFalse(HelperBuild.matches(helper: "aa", expected: "bb"))
        XCTAssertTrue(HelperBuild.matches(helper: "aa", expected: nil))
    }

    func testBuildNumberComesFromTheBundleInfoPlist() throws {
        let app = FileManager.default.temporaryDirectory.appendingPathComponent("pt-build-\(UUID().uuidString)/PassTunnel.app")
        defer { try? FileManager.default.removeItem(at: app.deletingLastPathComponent()) }
        let macOS = app.appendingPathComponent("Contents/MacOS")
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
        let helper = macOS.appendingPathComponent("PassTunnelHelper").path
        XCTAssertNil(HelperBuild.buildNumber(ofBundleContaining: helper), "no Info.plist")
        let plist = app.appendingPathComponent("Contents/Info.plist")
        for (value, expected) in [("214", 214), (" 7 ", 7), ("1.2", nil), ("__BUILD_NUMBER__", nil)] as [(String, Int?)] {
            let data = try PropertyListSerialization.data(fromPropertyList: ["CFBundleVersion": value], format: .xml, options: 0)
            try data.write(to: plist)
            XCTAssertEqual(HelperBuild.buildNumber(ofBundleContaining: helper), expected, value)
        }
        XCTAssertNil(HelperBuild.buildNumber(ofBundleContaining: "/nonexistent/X.app/Contents/MacOS/X"))
    }

    func testRelation() {
        let v = PT.helperProtocolVersion
        func rel(
            _ digest: String?, _ number: Int?, proto: Int = PT.helperProtocolVersion,
            app: String? = "aa", appNumber: Int? = 10
        ) -> HelperBuild.Relation {
            HelperBuild.relation(
                helperProtocol: proto, helperDigest: digest, helperNumber: number,
                appDigest: app, appNumber: appNumber)
        }
        XCTAssertEqual(rel("aa", 10), .current)
        XCTAssertEqual(rel("aa", 99), .current, "same binary: numbers do not matter")
        XCTAssertEqual(rel("bb", 10, app: nil), .current, "no bundled helper (tests, swift build): not compared")
        XCTAssertEqual(rel("bb", 9), .older)
        XCTAssertEqual(rel("bb", nil), .older, "a helper that does not report its number predates it")
        XCTAssertEqual(rel("bb", 11), .newer)
        XCTAssertEqual(rel("bb", 10), .different)
        XCTAssertEqual(rel("bb", 9, appNumber: nil), .different, "own number unknown: never treated as an upgrade")
        XCTAssertEqual(rel(nil, nil, proto: v - 1), .older)
        XCTAssertEqual(rel(nil, nil, proto: v + 1), .newer)
        XCTAssertEqual(rel(nil, nil, proto: v + 1, app: nil, appNumber: nil), .newer)
    }

    func testResponseCarriesTheBuildNumberOptionally() throws {
        var r = HelperResponse.success(running: [:])
        r.helperBuild = 214
        let json = String(decoding: try r.jsonData(), as: UTF8.self)
        XCTAssertTrue(json.contains("\"helper_build\":214"), json)
        XCTAssertEqual(try HelperResponse(jsonData: r.jsonData()).helperBuild, 214)
        // From a helper that predates the field.
        XCTAssertNil(try HelperResponse(jsonData: Data(#"{"ok":true,"running":{}}"#.utf8)).helperBuild)
        XCTAssertFalse(String(decoding: try HelperResponse.success().jsonData(), as: UTF8.self).contains("helper_build"))
    }

    func testBuildMismatchMeansUpdate() {
        XCTAssertTrue(HelperClientError.buildMismatch.meansOutdatedHelper)
        XCTAssertTrue(HelperClientError.versionMismatch(helper: 2, app: 3).meansOutdatedHelper)
        XCTAssertFalse(HelperClientError.notInstalled.meansOutdatedHelper)
        XCTAssertFalse((HelperClientError.buildMismatch.errorDescription ?? "").isEmpty)
    }
}
