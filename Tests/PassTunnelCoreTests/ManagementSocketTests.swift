import XCTest
@testable import PassTunnelCore

/// A scripted OpenVPN-like management server on a unix socket. Each accepted connection is handed
/// to the next handler in order.
final class FakeManagementServer {
    let path: String
    private var listenFD: Int32 = -1
    private let handlers: [(Int32) -> Void]
    private let done = DispatchSemaphore(value: 0)

    init(path: String, startDelay: TimeInterval = 0, handlers: [(Int32) -> Void]) {
        self.path = path
        self.handlers = handlers
        DispatchQueue.global().asyncAfter(deadline: .now() + startDelay) { self.run() }
    }

    private func run() {
        listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: path.utf8)
            raw[path.utf8.count] = 0
        }
        _ = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        listen(listenFD, 4)
        for handler in handlers {
            let c = accept(listenFD, nil, nil)
            guard c >= 0 else { break }
            var one: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            handler(c)
            close(c)
        }
        close(listenFD)
        done.signal()
    }

    func wait() { _ = done.wait(timeout: .now() + 5) }

    static func send(_ fd: Int32, _ text: String) {
        _ = text.withCString { write(fd, $0, strlen($0)) }
    }

    static func readLine(_ fd: Int32) -> String {
        var out: [UInt8] = []
        var b: UInt8 = 0
        while read(fd, &b, 1) == 1, b != 0x0A { out.append(b) }
        return String(decoding: out, as: UTF8.self)
    }

    static let banner = ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n"

    /// Banner, expect `command`, send `reply`.
    static func answering(_ command: String, with reply: String) -> (Int32) -> Void {
        return { fd in
            send(fd, banner)
            let got = readLine(fd)
            XCTAssertEqual(got, command)
            send(fd, reply)
        }
    }
}

final class ManagementSocketTests: XCTestCase {
    var dir: String!

    override func setUpWithError() throws {
        var template = Array("/tmp/pt-mgmt-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        dir = String(cString: made)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: dir)
    }

    var sockPath: String { dir + "/mgmt.sock" }

    func waitForSocket() {
        for _ in 0..<100 where !FileManager.default.fileExists(atPath: sockPath) { usleep(10_000) }
    }

    // MARK: Parser

    func testParseConnectedState() throws {
        let s = try ManagementSocket.parseState("1700000000,CONNECTED,SUCCESS,10.8.0.6,203.0.113.5,1194,,,fd00::6")
        XCTAssertEqual(s.name, "CONNECTED")
        XCTAssertEqual(s.localIP, "10.8.0.6")
        XCTAssertEqual(s.since, Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertEqual(s.detail, "SUCCESS")
        XCTAssertEqual(s.remoteIP, "203.0.113.5")
        XCTAssertEqual(s.localIPv6, "fd00::6")
        XCTAssertTrue(s.isConnected)
    }

    func testParseEarlyStatesAndNoise() throws {
        let s = try ManagementSocket.parseState(">LOG:1700000001,,noise\n1700000002,WAIT,,,,,,")
        XCTAssertEqual(s.name, "WAIT")
        XCTAssertEqual(s.localIP, "")
        XCTAssertFalse(s.isConnected)
        XCTAssertEqual(try ManagementSocket.parseState("1700000003,AUTH").name, "AUTH")
    }

    func testParseRejectsGarbage() {
        for bad in ["", "END", "hello", "x,CONNECTED", "1700000000,"] {
            XCTAssertThrowsError(try ManagementSocket.parseState(bad), bad)
        }
    }

    /// A non-finite or absurd timestamp is a damaged reply: refused here, so no later duration
    /// computation can trap on it.
    func testParseRejectsNonFiniteAndImplausibleTimestamps() {
        for epoch in ["nan", "NaN", "inf", "-inf", "infinity", "1e300", "-1e300", "1e20", "-1", "4102444801"] {
            XCTAssertThrowsError(try ManagementSocket.parseState("\(epoch),CONNECTED,SUCCESS,10.8.0.6,,,,,"), epoch)
        }
        XCTAssertEqual(try ManagementSocket.parseState("0,WAIT").since, Date(timeIntervalSince1970: 0))
        XCTAssertEqual(try ManagementSocket.parseState("4102444800,WAIT").since, Date(timeIntervalSince1970: 4_102_444_800))
    }

    // MARK: Client

    func testStateCommand() throws {
        let server = FakeManagementServer(path: sockPath, handlers: [
            FakeManagementServer.answering("state", with:
                ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.6,203.0.113.5,1194,,\r\n" +
                "1700000000,CONNECTED,SUCCESS,10.8.0.6,203.0.113.5,1194,,\r\nEND\r\n"),
        ])
        waitForSocket()
        let state = try ManagementSocket(path: sockPath).state()
        XCTAssertEqual(state.name, "CONNECTED")
        XCTAssertEqual(state.localIP, "10.8.0.6")
        server.wait()
    }

    func testSuccessAndErrorReplies() throws {
        let server = FakeManagementServer(path: sockPath, handlers: [
            FakeManagementServer.answering("signal SIGTERM", with: ">LOG:x\r\nSUCCESS: signal SIGTERM thrown\r\n"),
            FakeManagementServer.answering("bogus", with: "ERROR: unknown command, enter 'help' for more options\r\n"),
        ])
        waitForSocket()
        let m = ManagementSocket(path: sockPath)
        XCTAssertEqual(try m.command("signal SIGTERM"), "SUCCESS: signal SIGTERM thrown")
        XCTAssertThrowsError(try m.command("bogus")) { error in
            XCTAssertEqual(error as? ManagementError, .commandFailed("unknown command, enter 'help' for more options"))
        }
        server.wait()
    }

    func testRetriesWhileSocketAppears() throws {
        let server = FakeManagementServer(path: sockPath, startDelay: 0.3, handlers: [
            FakeManagementServer.answering("state", with: "1700000000,CONNECTING,,,,,,\r\nEND\r\n"),
        ])
        XCTAssertEqual(try ManagementSocket(path: sockPath).state(timeout: 3).name, "CONNECTING")
        server.wait()
    }

    func testRetriesWhenAnotherClientIsServed() throws {
        // First connection gets no banner (OpenVPN is busy with another client) and is dropped.
        let server = FakeManagementServer(path: sockPath, handlers: [
            { _ in usleep(1_700_000) },
            FakeManagementServer.answering("state", with: "1700000000,CONNECTED,SUCCESS,10.8.0.9,,,,\r\nEND\r\n"),
        ])
        waitForSocket()
        var m = ManagementSocket(path: sockPath)
        m.retryDelay = 0.05
        XCTAssertEqual(try m.state(timeout: 4).localIP, "10.8.0.9")
        server.wait()
    }

    func testBusyAndMissingSocket() {
        var m = ManagementSocket(path: dir + "/missing.sock")
        m.retryDelay = 0.05
        XCTAssertThrowsError(try m.command("state", timeout: 1)) { error in
            guard case .connectFailed(_, let code)? = error as? ManagementError else { return XCTFail("\(error)") }
            XCTAssertEqual(code, ENOENT)
        }
        XCTAssertThrowsError(try ManagementSocket(path: "/" + String(repeating: "x", count: 120)).command("state")) {
            XCTAssertEqual($0 as? ManagementError, .pathTooLong("/" + String(repeating: "x", count: 120)))
        }
        XCTAssertThrowsError(try m.command("state\nsignal SIGTERM"))
    }

    func testTimeoutWhenNoReply() throws {
        let server = FakeManagementServer(path: sockPath, handlers: [
            { fd in
                FakeManagementServer.send(fd, FakeManagementServer.banner)
                _ = FakeManagementServer.readLine(fd)
                usleep(800_000)
            },
        ])
        waitForSocket()
        XCTAssertThrowsError(try ManagementSocket(path: sockPath).command("state", timeout: 0.5)) {
            XCTAssertEqual($0 as? ManagementError, .timeout)
        }
        server.wait()
    }
}
