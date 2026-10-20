import XCTest
@testable import PassTunnelCore
import PassTunnelShared

final class HelperBuildTests: XCTestCase {
    func testDigestIsTheFileSHA256() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("helper-build-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data("abc".utf8).write(to: url)
        XCTAssertEqual(HelperBuild.digest(ofFile: url.path),
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
        XCTAssertEqual(HelperBuild.bundledHelperPath(nextTo: "/Applications/PassTunnel.app/Contents/MacOS/PassTunnel"),
                       "/Applications/PassTunnel.app/Contents/MacOS/PassTunnelHelper")
    }

    func testBuildsCompareOnlyWhenTheBundledOneIsKnown() {
        XCTAssertTrue(HelperBuild.matches(helper: "aa", expected: "aa"))
        XCTAssertFalse(HelperBuild.matches(helper: "aa", expected: "bb"))
        XCTAssertTrue(HelperBuild.matches(helper: "aa", expected: nil))
    }

    func testBuildMismatchMeansUpdate() {
        XCTAssertTrue(HelperClientError.buildMismatch.meansOutdatedHelper)
        XCTAssertTrue(HelperClientError.versionMismatch(helper: 2, app: 3).meansOutdatedHelper)
        XCTAssertFalse(HelperClientError.notInstalled.meansOutdatedHelper)
        XCTAssertFalse((HelperClientError.buildMismatch.errorDescription ?? "").isEmpty)
    }
}
