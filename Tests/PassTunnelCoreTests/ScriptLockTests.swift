import XCTest

@testable import PassTunnelShared

/// OpenVPN's script lock as the helper takes it (`ScriptLock`), in a directory of its own: `shlock`'s protocol, a
/// stale lock, and whatever someone puts into the world-writable directory, never followed, never a hang.
final class ScriptLockTests: XCTestCase {
    var dir: URL!
    var path: String { dir.appendingPathComponent("openvpn-dns-updown.lock").path }

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pt-lock-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    /// A clock that moves only when the lock pauses: a wait of seconds takes none.
    final class Clock {
        var now = Date(timeIntervalSince1970: 0)
        var pauses = 0
    }

    func acquire(_ clock: Clock = Clock(), pid: pid_t = getpid(), wait: TimeInterval = 1) -> ScriptLock.Held? {
        ScriptLock.acquire(
            path: path, pid: pid, wait: wait, now: { clock.now },
            pause: {
                clock.pauses += 1
                clock.now.addTimeInterval($0)
            })
    }

    func testTakesAFreeLockAndGivesItBack() throws {
        let held = try XCTUnwrap(acquire())
        XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8), "\(getpid())\n", "shlock's format: the pid as text")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["openvpn-dns-updown.lock"], "no temporary file left")
        held.release()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }

    /// Held by a process that runs (launchd here): waited for, then a failed try, in bounded time.
    func testALiveHolderMakesItAFailedTry() throws {
        try "1\n".write(toFile: path, atomically: true, encoding: .utf8)
        let clock = Clock()
        XCTAssertNil(acquire(clock, wait: 3))
        XCTAssertTrue((29...31).contains(clock.pauses), "\(clock.pauses)")
        XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8), "1\n", "never removed")
    }

    /// Held by a process that is gone: stale, taken.
    func testAStaleLockIsTaken() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try process.run()
        process.waitUntilExit()
        try "\(process.processIdentifier)\n".write(toFile: path, atomically: true, encoding: .utf8)
        let held = try XCTUnwrap(acquire())
        XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8), "\(getpid())\n")
        held.release()
    }

    /// What anyone can put there: a link, a fifo, a big file, words, a negative pid. Nothing is followed, read past a
    /// few bytes or removed, and the try ends in time.
    func testWhatOthersPutThereIsNeverFollowedNorRemoved() throws {
        let target = dir.appendingPathComponent("target").path
        try "0\n".write(toFile: target, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: target)
        XCTAssertNil(acquire())
        XCTAssertEqual(try String(contentsOfFile: target, encoding: .utf8), "0\n")
        try FileManager.default.removeItem(atPath: path)

        XCTAssertEqual(mkfifo(path, 0o600), 0)
        XCTAssertNil(acquire(), "a fifo: not opened for long, not waited on")
        try FileManager.default.removeItem(atPath: path)

        for planted in [String(repeating: "1", count: 100), "not a pid\n", "-5\n", "0\n", ""] {
            try planted.write(toFile: path, atomically: true, encoding: .utf8)
            XCTAssertNil(acquire(), planted)
            XCTAssertTrue(FileManager.default.fileExists(atPath: path), planted)
            try FileManager.default.removeItem(atPath: path)
        }
        // A file where the helper's temporary file goes is removed, not written through.
        let temp = dir.appendingPathComponent(".passtunnel-shlock.\(getpid())").path
        try FileManager.default.createSymbolicLink(atPath: temp, withDestinationPath: target)
        let held = try XCTUnwrap(acquire())
        XCTAssertEqual(try String(contentsOfFile: target, encoding: .utf8), "0\n")
        held.release()
    }

    /// A lock someone replaced after it was taken is not removed by its release.
    func testReleaseRemovesOnlyItsOwnLock() throws {
        let held = try XCTUnwrap(acquire())
        try FileManager.default.removeItem(atPath: path)
        try "1\n".write(toFile: path, atomically: true, encoding: .utf8)
        held.release()
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
    }

    /// No directory: no run of the script ever took the lock (it makes the directory first); none is needed. A
    /// directory that is a link is refused.
    func testTheDirectory() throws {
        XCTAssertNotNil(ScriptLock.acquire(path: dir.path + "/missing/openvpn-dns-updown.lock", wait: 0))
        let link = dir.appendingPathComponent("link").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: dir.path)
        XCTAssertNil(ScriptLock.acquire(path: link + "/openvpn-dns-updown.lock", wait: 0))
    }
}
