import XCTest

@testable import PassTunnelShared

/// OpenVPN's script lock as the helper takes it (`ScriptLock`), in a directory of its own: `shlock`'s rules, as
/// `/usr/bin/shlock` keeps them, for whatever is in the world-writable directory. Time is the test's own clock
/// (the lock's file times are read once), so nothing depends on how long a run takes.
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

    /// A clock that moves only when the lock pauses.
    final class Clock {
        var now: Date
        var pauses = 0

        init(_ now: Date) { self.now = now }
    }

    /// The second the entry at `path` last changed (its ctime), as the clock's start: "now" is then that very second.
    func changeTime() -> Date {
        var st = stat()
        XCTAssertEqual(lstat(path, &st), 0)
        return Date(timeIntervalSince1970: TimeInterval(ScriptLock.changeSeconds(st)))
    }

    func acquire(_ clock: Clock, pid: pid_t = getpid(), wait: TimeInterval = 3) -> ScriptLock.Held? {
        ScriptLock.acquire(
            path: path, pid: pid, wait: wait, now: { clock.now },
            pause: {
                clock.pauses += 1
                clock.now.addTimeInterval($0)
            })
    }

    func testTakesAFreeLockAndGivesItBack() throws {
        let held = try XCTUnwrap(acquire(Clock(Date())))
        XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8), "\(getpid())\n", "shlock's format: the pid as text")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["openvpn-dns-updown.lock"], "no temporary file left")
        held.release()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }

    /// Held by a process that runs (launchd here): valid, never removed; the try fails once `wait` has passed.
    func testALiveHolderIsWaitedFor() throws {
        try "1\n".write(toFile: path, atomically: true, encoding: .utf8)
        let clock = Clock(changeTime().addingTimeInterval(10))
        XCTAssertNil(acquire(clock, wait: 0.5))
        XCTAssertGreaterThan(clock.pauses, 0)
        XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8), "1\n")
    }

    /// Invalid (no pid above 0, or one of a process that is gone): kept while its status changed in this second, as
    /// it may still be being written, removed and taken from the next second on, as `shlock` does.
    func testAnInvalidLockGoesAfterItsSecond() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try process.run()
        process.waitUntilExit()
        for content in ["junk\n", "", "0\n", "-5\n", "\(process.processIdentifier)\n", String(repeating: "7", count: 100)] {
            try content.write(toFile: path, atomically: true, encoding: .utf8)
            let start = changeTime()
            XCTAssertNil(acquire(Clock(start), wait: 0), "\(content.debugDescription): written this second")
            XCTAssertTrue(FileManager.default.fileExists(atPath: path))
            let clock = Clock(start)
            let held = try XCTUnwrap(acquire(clock, wait: 3), content.debugDescription)
            XCTAssertGreaterThanOrEqual(clock.now.timeIntervalSince(start), 1, "not before its second has passed")
            XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8), "\(getpid())\n")
            held.release()
        }
    }

    /// What anyone can put there instead of a file: a link and a fifo are invalid locks, and only their name goes (the
    /// link's target stays as it is); a directory is never removed.
    func testWhatOthersPutThereIsNeverFollowed() throws {
        let target = dir.appendingPathComponent("target").path
        try "0\n".write(toFile: target, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: target)
        var clock = Clock(changeTime())
        XCTAssertNil(acquire(clock, wait: 0))
        clock = Clock(changeTime())
        let held = try XCTUnwrap(acquire(clock))
        XCTAssertEqual(try String(contentsOfFile: target, encoding: .utf8), "0\n", "never written through")
        held.release()

        XCTAssertEqual(mkfifo(path, 0o600), 0)
        clock = Clock(changeTime())
        let fifo = try XCTUnwrap(acquire(clock), "a fifo: not waited on, removed")
        fifo.release()

        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
        clock = Clock(changeTime().addingTimeInterval(60))
        XCTAssertNil(acquire(clock, wait: 0.5))
        var isDirectory: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) && isDirectory.boolValue)
        try FileManager.default.removeItem(atPath: path)

        // A file where the helper's temporary file goes is removed, not written through.
        let temp = dir.appendingPathComponent(".passtunnel-shlock.\(getpid())").path
        try FileManager.default.createSymbolicLink(atPath: temp, withDestinationPath: target)
        let again = try XCTUnwrap(acquire(Clock(Date())))
        XCTAssertEqual(try String(contentsOfFile: target, encoding: .utf8), "0\n")
        again.release()
    }

    /// A lock someone replaced after it was taken is not removed by its release.
    func testReleaseRemovesOnlyItsOwnLock() throws {
        let held = try XCTUnwrap(acquire(Clock(Date())))
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
