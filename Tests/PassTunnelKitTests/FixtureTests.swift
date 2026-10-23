import Foundation
import XCTest

/// Runs every golden case in `fixtures/` (see fixtures/README.md) against PassTunnelKit. The Android
/// port runs a pinned copy of the same files, so a failure here means the two would drift.
final class FixtureTests: XCTestCase {
    static let directory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("fixtures", isDirectory: true)

    func load(_ name: String) throws -> [String: JSON] {
        let data = try Data(contentsOf: Self.directory.appendingPathComponent(name))
        guard let top = try JSON.parse(data).object else { throw FixtureError("\(name): not an object") }
        return top
    }

    func testEveryFixtureFileIsKnown() throws {
        let files = try FileManager.default.contentsOfDirectory(atPath: Self.directory.path)
            .filter { $0.hasSuffix(".json") }.sorted()
        XCTAssertEqual(files, FixtureRunner.groups.keys.sorted())
    }

    func testFixtures() throws {
        var total = 0
        for (file, groups) in FixtureRunner.groups.sorted(by: { $0.key < $1.key }) {
            let top = try load(file)
            XCTAssertNotNil(top["about"]?.string, "\(file): about")
            XCTAssertEqual(Set(top.keys).subtracting(["about"]), Set(groups.keys), "\(file): groups")
            for (groupName, group) in groups.sorted(by: { $0.key < $1.key }) {
                let cases = top[groupName]?.array ?? []
                XCTAssertFalse(cases.isEmpty, "\(file) \(groupName): no cases")
                for (index, value) in cases.enumerated() {
                    guard let c = value.object else { XCTFail("\(file) \(groupName)[\(index)]: not an object"); continue }
                    let label = "\(file) \(groupName)[\(index)] \(c["name"]?.string ?? "")"
                    let inputs = c.filter { group.inputs.contains($0.key) }
                    let expected = c.filter { !group.inputs.contains($0.key) && $0.key != "name" && $0.key != "note" }
                    XCTAssertFalse(expected.isEmpty, "\(label): no expected values")
                    do {
                        let actual = try group.run(inputs)
                        XCTAssertEqual(JSON.object(actual), JSON.object(expected), label)
                    } catch {
                        XCTFail("\(label): \(error)")
                    }
                    total += 1
                }
            }
        }
        XCTAssertGreaterThan(total, 0)
    }
}
