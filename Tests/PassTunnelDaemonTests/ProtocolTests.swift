import Foundation
import XCTest

@testable import PassTunnelDaemon
@testable import PassTunnelShared

// MARK: - Messages

final class DaemonCallTests: XCTestCase {
    func parse(_ text: String) throws -> DaemonCall { try DaemonCall.parse(Data(text.utf8)) }

    func failure(_ text: String, file: StaticString = #filePath, line: UInt = #line) -> DaemonCall.Failure? {
        do {
            _ = try parse(text)
            XCTFail("expected a failure for \(text)", file: file, line: line)
            return nil
        } catch {
            return error as? DaemonCall.Failure
        }
    }

    func testHello() throws {
        XCTAssertEqual(try parse(#"{"op":"hello"}"#), .hello)
        XCTAssertEqual(try parse(" {\t\"op\" : \"hello\" , \"extra\": [1, {\"a\": \"}\"}] } "), .hello)
        XCTAssertEqual(try parse(#"{"op":"hello"}"#), .hello, "escaped keys and values")
        XCTAssertEqual(String(decoding: DaemonProtocol.helloLine, as: UTF8.self), "{\"op\":\"hello\"}\n")
    }

    /// The request reaches `HelperCore.decodeRequest` byte for byte as the client wrote it.
    func testPerformCarriesTheRequestBytes() throws {
        let request = HelperRequest.startOpenVPN(
            OpenVPNStart(
                profileID: "acme", profileDir: "/home/alice/x",
                username: "alice", secret: "p\"w}{\\",
                logPath: "/home/alice/x/vpn.log"))
        let line = try DaemonProtocol.performLine(request)
        XCTAssertEqual(line.last, 0x0A)
        guard case .perform(let data) = try DaemonCall.parse(line.dropLast()) else { return XCTFail("not perform") }
        XCTAssertEqual(data, try request.jsonData())
        XCTAssertEqual(try HelperCore.decodeRequest(data), request)

        let spaced = #"{ "request" : { "type": "status", "protocol_version": 5 } , "op": "perform" }"#
        guard case .perform(let raw) = try parse(spaced) else { return XCTFail("not perform") }
        XCTAssertEqual(String(decoding: raw, as: UTF8.self), #"{ "type": "status", "protocol_version": 5 }"#)
        XCTAssertEqual(try HelperCore.decodeRequest(raw), .status)
        // Whatever the request is, it is HelperCore's to judge.
        guard case .perform(let scalar) = try parse(#"{"op":"perform","request":42}"#) else { return XCTFail("not perform") }
        XCTAssertThrowsError(try HelperCore.decodeRequest(scalar)) {
            XCTAssertEqual($0 as? HelperCore.RequestError, .malformed)
        }
    }

    func testMalformedMessages() {
        for bad in [
            "", "hello", "[]", #""op""#, "{", #"{"op":"hello""#, #"{"op":1}"#, #"{"op":null}"#, "{}",
            #"{"request":{}}"#, #"{"op":"hello","op":"perform"}"#, #"{"op":"perform","request":1,"request":2}"#
        ] {
            XCTAssertEqual(failure(bad), .malformed, bad)
        }
        XCTAssertEqual(failure(#"{"op":"perform"}"#), .missingRequest)
        XCTAssertEqual(failure(#"{"op":"reboot"}"#), .unknownOperation("reboot"))
        XCTAssertEqual(failure(#"{"op":"a\nb\u001b"}"#), .unknownOperation("a?b?"), "echoed printable only")
        XCTAssertEqual(
            failure(#"{"op":"\#(String(repeating: "x", count: 100))"}"#),
            .unknownOperation(String(repeating: "x", count: 32)))
    }

    func testMembers() {
        let text = #"{"a":"x\"}","b":[1,[2,{"c":"]"}]],"d":true,"e":null,"f":-1.5e3,"g":{}}"#
        let bytes = [UInt8](text.utf8)
        guard let members = JSONMembers.of(bytes) else { return XCTFail("no members") }
        func value(_ key: String) -> String? { members[key].map { String(decoding: bytes[$0], as: UTF8.self) } }
        XCTAssertEqual(value("a"), #""x\"}""#)
        XCTAssertEqual(value("b"), #"[1,[2,{"c":"]"}]]"#)
        XCTAssertEqual(value("d"), "true")
        XCTAssertEqual(value("e"), "null")
        XCTAssertEqual(value("f"), "-1.5e3")
        XCTAssertEqual(value("g"), "{}")
        XCTAssertNil(JSONMembers.of([UInt8](#"{"a":1} x"#.utf8)), "trailing text")
        XCTAssertNil(JSONMembers.of([UInt8](#"{"a":"#.utf8)))
        XCTAssertEqual(JSONMembers.of([UInt8]("{}".utf8))?.isEmpty, true)
    }

    func testLogLinesStayOneLine() {
        XCTAssertEqual(DaemonLog.oneLine("start of a\nb\r\u{1b}[31m refused"), "start of a?b??[31m refused")
        XCTAssertEqual(DaemonLog.oneLine("profil “acme”"), "profil “acme”")
    }

    func testHelloEncoding() throws {
        let hello = DaemonHello(build: "ab12", buildNumber: 214)
        XCTAssertEqual(
            String(decoding: try hello.jsonData(), as: UTF8.self),
            #"{"build":"ab12","build_number":214,"protocol":5}"#)
        XCTAssertEqual(
            String(decoding: try DaemonHello(build: "ab12").jsonData(), as: UTF8.self),
            #"{"build":"ab12","protocol":5}"#, "no number in development builds")
        XCTAssertEqual(
            try DaemonHello(jsonData: Data(#"{"protocol":5,"build":"x"}"#.utf8)),
            DaemonHello(protocolVersion: 5, build: "x"))
    }
}

// MARK: - Lines with deadlines

final class LineIOTests: XCTestCase {
    var pair: [Int32] = [-1, -1]

    override func setUpWithError() throws {
        XCTAssertEqual(socketpair(AF_UNIX, Sys.streamType, 0, &pair), 0)
        _ = fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK)
    }

    override func tearDown() {
        pair.filter { $0 >= 0 }.forEach { close($0) }
    }

    func send(_ text: String) {
        _ = text.withCString { Sys.send(pair[1], $0, strlen($0)) }
    }

    func read(limit: Int = 16, timeout: TimeInterval = 1) -> LineIO.ReadResult {
        LineIO.readLine(pair[0], limit: limit, deadline: Date().addingTimeInterval(timeout))
    }

    func testLines() {
        send("hello\nignored")
        XCTAssertEqual(read(), .line(Data("hello".utf8)))
    }

    func testLimit() {
        send(String(repeating: "x", count: 16) + "\n")
        XCTAssertEqual(read(), .line(Data(String(repeating: "x", count: 16).utf8)), "exactly the limit")
        send(String(repeating: "y", count: 17) + "\n")
        XCTAssertEqual(read(), .tooLarge)
    }

    func testLimitWithoutNewline() {
        send(String(repeating: "z", count: 40))
        XCTAssertEqual(read(), .tooLarge, "refused once past the limit, without waiting for a newline")
    }

    func testEndOfFileEndsTheLine() {
        send("{}")
        shutdown(pair[1], Int32(SHUT_WR))
        XCTAssertEqual(read(), .line(Data("{}".utf8)))
    }

    func testClosedWithoutData() {
        close(pair[1])
        pair[1] = -1
        XCTAssertEqual(read(), .closed)
    }

    /// A client that sends nothing, or sends slowly, is dropped at the deadline.
    func testDeadline() {
        let start = Date()
        XCTAssertEqual(read(timeout: 0.3), .timedOut)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
        let done = DispatchSemaphore(value: 0)
        let writer = Thread { [pair] in
            for _ in 0..<10 {
                _ = "x".withCString { Sys.send(pair[1], $0, 1) }
                usleep(100_000)
            }
            done.signal()
        }
        writer.start()
        XCTAssertEqual(read(limit: 1000, timeout: 0.5), .timedOut, "a byte now and then does not extend it")
        done.wait()
    }

    func testWrite() {
        _ = fcntl(pair[1], F_SETFL, fcntl(pair[1], F_GETFL) | O_NONBLOCK)
        XCTAssertTrue(LineIO.write(pair[1], Data("ok\n".utf8), deadline: Date().addingTimeInterval(1)))
        XCTAssertEqual(read(), .line(Data("ok".utf8)))
        // Nobody reads: the socket buffer fills and the deadline ends the write.
        let big = Data(count: 8 << 20)
        let start = Date()
        XCTAssertFalse(LineIO.write(pair[1], big, deadline: Date().addingTimeInterval(0.3)))
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
        close(pair[0])
        pair[0] = -1
        XCTAssertFalse(
            LineIO.write(pair[1], Data("gone\n".utf8), deadline: Date().addingTimeInterval(1)),
            "a closed peer, without SIGPIPE")
    }
}

// MARK: - Access

final class AccessTests: XCTestCase {
    let member: uid_t = 1000, outsider: uid_t = 1001, unknown: uid_t = 1002
    let groupID: gid_t = 990

    func users(group: Bool = true) -> UserDatabase {
        let member = self.member, outsider = self.outsider, groupID = self.groupID
        return UserDatabase(
            name: { uid in uid == member ? "alice" : uid == outsider ? "bob" : uid == 0 ? "root" : nil },
            home: { _ in "/home/x" },
            // The member's group is a supplementary one; the outsider's primary group has the same
            // name elsewhere, which does not count.
            groups: { uid in uid == member ? [1000, groupID] : uid == outsider ? [1001, 27] : nil },
            groupID: { group && $0 == Access.groupName ? groupID : nil })
    }

    let startRequest = HelperRequest.startOpenVPN(OpenVPNStart(profileID: "acme", profileDir: "/d", logPath: "/d/vpn.log"))
    let fortiRequest = HelperRequest.startForti(
        FortiStart(
            profileID: "f", profileDir: "/d", host: "vpn.example.com",
            username: "alice", password: "pw", logPath: "/d/vpn.log"))

    func testRootAndMembersMayStart() {
        for request in [startRequest, fortiRequest] {
            XCTAssertEqual(Access.decide(request, uid: 0, users: users()), .allowed)
            XCTAssertEqual(Access.decide(request, uid: 0, users: users(group: false)), .allowed, "root needs no group")
            XCTAssertEqual(Access.decide(request, uid: member, users: users()), .allowed)
        }
    }

    func testOthersMayNotStart() {
        for uid in [outsider, unknown] {
            guard case .refused(let reason) = Access.decide(startRequest, uid: uid, users: users()) else {
                return XCTFail("uid \(uid) allowed")
            }
            XCTAssertTrue(reason.contains("“passtunnel”") && reason.contains("usermod -aG passtunnel"), reason)
            XCTAssertNotEqual(Access.decide(fortiRequest, uid: uid, users: users()), .allowed)
        }
        guard case .refused(let reason) = Access.decide(startRequest, uid: outsider, users: users()) else { return }
        XCTAssertTrue(reason.contains("bob"), reason)
        guard case .refused(let noGroup) = Access.decide(startRequest, uid: member, users: users(group: false)) else {
            return XCTFail("allowed without the group")
        }
        XCTAssertTrue(noGroup.contains("does not exist"), noGroup)
    }

    /// Status and stop only ever see the caller's own sessions, so everyone may ask.
    func testStatusAndStopAreForEveryone() {
        for uid in [0, member, outsider, unknown] {
            XCTAssertEqual(Access.decide(.status, uid: uid, users: users()), .allowed)
            XCTAssertEqual(Access.decide(.stop(profileID: "acme"), uid: uid, users: users()), .allowed)
        }
    }

    func testSystemDatabase() {
        // Root's groups come from the real database; it exists everywhere.
        XCTAssertEqual(UserDatabase.system.name(0), "root")
        XCTAssertEqual(UserDatabase.system.groups(0)?.contains(0), true)
        XCTAssertNotNil(UserDatabase.system.groupID("root"))
        XCTAssertNil(UserDatabase.system.groupID("passtunnel-no-such-group"))
        XCTAssertTrue(Access.mayStart(uid: 0, users: .system))
    }

    func testPeerCredentials() {
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, Sys.streamType, 0, &pair), 0)
        defer { pair.forEach { close($0) } }
        let caller = Caller.of(socket: pair[0])
        XCTAssertEqual(caller, Caller(uid: geteuid(), gid: getegid(), pid: getpid()))
    }
}

// MARK: - Versions

final class ToolVersionTests: XCTestCase {
    func testParsing() {
        let cases: [(String, ToolVersion?)] = [
            ("2.6.9", ToolVersion(2, 6, 9)), ("2.6.14", ToolVersion(2, 6, 14)), ("2.7.0", ToolVersion(2, 7, 0)),
            ("2.7_rc2", ToolVersion(2, 7, 0)), ("2.6_git", ToolVersion(2, 6, 0)), ("2.5", ToolVersion(2, 5, 0)),
            ("1.21.0-dirty", ToolVersion(1, 21, 0)), ("10.0.1.4", ToolVersion(10, 0, 1)),
            ("2", nil), ("x2.6", nil), ("", nil), (".6.1", nil), ("9999999.1", nil)
        ]
        for (text, expected) in cases {
            XCTAssertEqual(ToolVersion(parsing: Substring(text)), expected, text)
        }
        XCTAssertLessThan(ToolVersion(2, 6, 9), ToolVersion(2, 6, 10))
        XCTAssertLessThan(ToolVersion(2, 5, 11), ToolVersion(2, 6, 0))
        XCTAssertEqual(ToolVersion(2, 7).description, "2.7.0")
    }

    func testOpenVPNOutput() {
        let ubuntu = """
            OpenVPN 2.6.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
            library versions: OpenSSL 3.0.13 30 Jan 2024, LZO 2.10
            DCO version: N/A
            Originally developed by James Yonan
            """
        XCTAssertEqual(ToolSpec.openVPNVersion(ubuntu), ToolVersion(2, 6, 9))
        XCTAssertEqual(ToolSpec.openVPNVersion("\nOpenVPN 2.7_rc2 aarch64-unknown-linux-gnu [SSL]\n"), ToolVersion(2, 7, 0))
        XCTAssertNil(ToolSpec.openVPNVersion("openvpn: command not found"))
        XCTAssertNil(ToolSpec.openVPNVersion(""))
        XCTAssertEqual(ToolSpec.openvpn.minimum, ToolVersion(2, 6, 0))
        XCTAssertEqual(ToolSpec.openvpn.candidates, ["/usr/sbin/openvpn", "/usr/bin/openvpn"])
    }
}
