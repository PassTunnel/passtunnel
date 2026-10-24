import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// Isolates every test: temp support dir and a private Keychain service (in memory on Linux).
class CoreTestCase: XCTestCase {
    var home: URL!
    var service: String!

    override func setUpWithError() throws {
        try super.setUpWithError()
        home = FileManager.default.temporaryDirectory
            .appendingPathComponent("PassTunnelTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        service = "PassTunnelTests-\(UUID().uuidString)"
        setenv("PASSTUNNEL_HOME", home.path, 1)
        useTestSecrets(service: service)
        XCTAssertEqual(AppPaths.default.root.path, home.standardizedFileURL.path)
    }

    override func tearDownWithError() throws {
        Secrets.deleteAllInOverriddenService()
        try? FileManager.default.removeItem(at: home)
        try super.tearDownWithError()
    }

    var store: ProfileStore { ProfileStore() }

    func write(_ text: String, name: String) throws -> URL {
        let url = home.appendingPathComponent(name)
        try Data(text.utf8).write(to: url)
        return url
    }

    func mode(_ url: URL) throws -> Int {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs[.posixPermissions] as! NSNumber).intValue & 0o777
    }

    func assertThrows(_ expected: PTError, file: StaticString = #filePath, line: UInt = #line,
                      _ body: () throws -> Void) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual(error as? PTError, expected, file: file, line: line)
        }
    }
}
