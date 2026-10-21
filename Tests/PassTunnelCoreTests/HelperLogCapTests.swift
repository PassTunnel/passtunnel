import XCTest
import PassTunnelShared

/// The helper trims a running tool's log once it gets too large.
final class HelperLogCapTests: XCTestCase {
    var path: String!
    var fd: Int32 = -1

    override func setUpWithError() throws {
        path = FileManager.default.temporaryDirectory.appendingPathComponent("pt-log-\(UUID().uuidString).log").path
        fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_APPEND, 0o600)
        XCTAssertGreaterThanOrEqual(fd, 0)
    }

    override func tearDownWithError() throws {
        close(fd)
        unlink(path)
    }

    func append(_ text: String) {
        _ = text.withCString { write(fd, $0, strlen($0)) }
    }

    var contents: String { (try? String(contentsOfFile: path, encoding: .utf8)) ?? "" }

    func testSmallLogIsLeftAlone() {
        append("line 1\nline 2\n")
        XCTAssertFalse(HelperCore.capLog(fd: fd, maxBytes: 100, keepBytes: 50, headBytes: 10))
        XCTAssertEqual(contents, "line 1\nline 2\n")
    }

    func testLargeLogKeepsWholeLinesFromTheStartAndTheEnd() {
        append("Opened utun device utun7\n")
        for i in 0..<200 { append("2026-01-01 10:00:00 line \(i)\n") }
        XCTAssertTrue(HelperCore.capLog(fd: fd, maxBytes: 1000, keepBytes: 300, headBytes: 40))
        let lines = contents.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines[0], "Opened utun device utun7", "whole head lines only")
        XCTAssertTrue(lines[1].hasPrefix("[log trimmed by the helper"), lines[1])
        XCTAssertFalse(lines[1].contains("PassTunnel: "), "would read as a start failure")
        XCTAssertTrue(lines[2].hasPrefix("2026-01-01 10:00:00 line "), "starts at a whole line: \(lines[2])")
        XCTAssertEqual(lines.last, "2026-01-01 10:00:00 line 199")
        XCTAssertLessThan(contents.utf8.count, 450)

        // The tool keeps appending through its descriptor.
        append("after\n")
        XCTAssertTrue(contents.hasSuffix("line 199\nafter\n"))
        XCTAssertFalse(HelperCore.capLog(fd: fd, maxBytes: 1000, keepBytes: 300, headBytes: 40))
    }

    func testWithoutHead() {
        for i in 0..<200 { append("2026-01-01 10:00:00 line \(i)\n") }
        XCTAssertTrue(HelperCore.capLog(fd: fd, maxBytes: 1000, keepBytes: 300, headBytes: 0))
        XCTAssertTrue(contents.hasPrefix("[log trimmed by the helper"))
    }

    func testDefaultLimits() {
        XCTAssertEqual(HelperCore.maxLogBytes, 5 * 1024 * 1024)
        XCTAssertLessThan(HelperCore.keptLogBytes + HelperCore.keptLogHeadBytes, HelperCore.maxLogBytes)
    }
}
