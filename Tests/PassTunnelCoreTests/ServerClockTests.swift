import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

#if canImport(Network)
import Network
import Security
#endif
#if canImport(Glibc)
import Glibc
#endif

/// Stands in for `ServerClock`: records what it was asked and answers what it is told; never the network.
final class FakeServerClock: ClockChecking, @unchecked Sendable {
    struct GatewayCall: Equatable {
        var host: String
        var port: Int
        var trustedCert: String?
    }

    private let lock = NSLock()
    private var _gatewayCalls: [GatewayCall] = []
    private var _timeServerCalls = 0
    var gatewayResult: Result<ClockOffset, Error> = .failure(ServerClock.Failure.timedOut)
    var timeServerResult: Result<ClockOffset, Error> = .failure(ServerClock.Failure.timedOut)

    var gatewayCalls: [GatewayCall] { locked { _gatewayCalls } }
    var timeServerCalls: Int { locked { _timeServerCalls } }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    func gateway(host: String, port: Int, trustedCert: String?, timeout: TimeInterval) async throws -> ClockOffset {
        try locked {
            _gatewayCalls.append(GatewayCall(host: host, port: port, trustedCert: trustedCert))
            return gatewayResult
        }.get()
    }

    func timeServer(timeout: TimeInterval) async throws -> ClockOffset {
        try locked {
            _timeServerCalls += 1
            return timeServerResult
        }.get()
    }
}

/// `ServerClock` and `SNTP`: fixed packets and headers, a UDP server and (on the Mac) a TLS server on
/// 127.0.0.1 started by the test. Nothing here contacts another host.
final class ServerClockTests: XCTestCase {
    // MARK: SNTP packets

    let nonce: UInt64 = 0x0123_4567_89AB_CDEF

    /// An NTP timestamp of a time after 1970 and before 2036.
    static func ntp(_ unix: TimeInterval) -> UInt64 {
        let seconds = UInt64(unix + SNTP.ntpToUnix)
        let fraction = UInt64(((unix - unix.rounded(.down)) * 4_294_967_296).rounded(.down))
        return seconds << 32 | fraction
    }

    /// A server's reply: LI 0, version 4, mode 4, stratum 2 unless changed.
    static func reply(origin: UInt64, received: UInt64, transmitted: UInt64, first: UInt8 = 0x24, stratum: UInt8 = 2) -> [UInt8] {
        var p = [UInt8](repeating: 0, count: 48)
        p[0] = first
        p[1] = stratum
        for (offset, value) in [(24, origin), (32, received), (40, transmitted)] {
            for i in 0..<8 { p[offset + i] = UInt8(truncatingIfNeeded: value >> (56 - 8 * i)) }
        }
        return p
    }

    func testTheRequestCarriesOnlyTheNonce() {
        let packet = SNTP.request(nonce: nonce)
        XCTAssertEqual(packet.count, 48)
        XCTAssertEqual(packet[0], 0x23, "LI 0, version 4, client")
        XCTAssertEqual(Array(packet[40..<48]), [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        XCTAssertEqual(Array(packet[1..<40]), [UInt8](repeating: 0, count: 39), "no clock, no identity")
    }

    func testAValidReply() throws {
        let t = 1_792_921_262.25
        let bytes = Self.reply(origin: nonce, received: Self.ntp(t), transmitted: Self.ntp(t + 0.5))
        let reply = try XCTUnwrap(SNTP.parse(bytes, nonce: nonce))
        XCTAssertEqual(reply.received, t, accuracy: 1e-6)
        XCTAssertEqual(reply.transmitted, t + 0.5, accuracy: 1e-6)
        XCTAssertNotNil(SNTP.parse(bytes + [0, 0, 0, 0], nonce: nonce), "extension fields after the header")
        XCTAssertNotNil(
            SNTP.parse(Self.reply(origin: nonce, received: Self.ntp(t), transmitted: Self.ntp(t), first: 0x1C), nonce: nonce),
            "version 3")

        // T1 = 1000, T2 = 1050, T3 = 1050.5, T4 = 1001: the server is 49.75 s ahead.
        let offset = SNTP.offset(
            sent: Date(timeIntervalSince1970: 1000), reply: SNTP.Reply(received: 1050, transmitted: 1050.5),
            received: Date(timeIntervalSince1970: 1001))
        XCTAssertEqual(offset, 49.75)
    }

    func testRepliesThatAreNotAValidAnswerAreIgnored() {
        let t = Self.ntp(1_792_921_262)
        let cases: [(String, [UInt8])] = [
            ("short", Array(Self.reply(origin: nonce, received: t, transmitted: t).prefix(47))),
            ("another request's", Self.reply(origin: nonce &+ 1, received: t, transmitted: t)),
            ("no origin", Self.reply(origin: 0, received: t, transmitted: t)),
            ("a client's packet", Self.reply(origin: nonce, received: t, transmitted: t, first: 0x23)),
            ("broadcast", Self.reply(origin: nonce, received: t, transmitted: t, first: 0x25)),
            ("unsynchronized", Self.reply(origin: nonce, received: t, transmitted: t, first: 0xE4)),
            ("version 2", Self.reply(origin: nonce, received: t, transmitted: t, first: 0x14)),
            ("kiss-o'-death", Self.reply(origin: nonce, received: t, transmitted: t, stratum: 0)),
            ("stratum 16", Self.reply(origin: nonce, received: t, transmitted: t, stratum: 16)),
            ("no receive time", Self.reply(origin: nonce, received: 0, transmitted: t)),
            ("no transmit time", Self.reply(origin: nonce, received: t, transmitted: 0)),
            ("sent before received", Self.reply(origin: nonce, received: t, transmitted: t - (1 << 32)))
        ]
        for (name, bytes) in cases { XCTAssertNil(SNTP.parse(bytes, nonce: nonce), name) }
    }

    /// The 32-bit seconds wrap in 2036; a value with the top bit clear is after that, not in 1900.
    func testTheNextEra() {
        XCTAssertEqual(SNTP.unixSeconds(UInt64(2_208_988_800) << 32), 0)
        XCTAssertEqual(SNTP.unixSeconds(UInt64(0x8000_0000) << 32), 2_147_483_648 - 2_208_988_800)
        XCTAssertEqual(SNTP.unixSeconds(0 << 32 | 1), 2_085_978_496 + 1 / 4_294_967_296, accuracy: 1e-6, "2036-02-07T06:28:16Z")
        XCTAssertEqual(SNTP.unixSeconds(UInt64(100) << 32), 2_085_978_596)
    }

    // MARK: SNTP against a local server

    /// A UDP server on 127.0.0.1 that answers the first request (within `wait` ms) with every packet
    /// `answer` returns.
    final class LocalSNTPServer: @unchecked Sendable {
        let fd: Int32
        let port: UInt16
        private let done = DispatchSemaphore(value: 0)

        init(wait: Int32 = 5000, answer: @escaping (_ request: [UInt8]) -> [[UInt8]]) throws {
            let sock = socket(AF_INET, POSIXSocket.datagram, 0)
            guard sock >= 0 else { throw XCTSkip("no socket") }
            var address = sockaddr_in()
            address.sin_family = sa_family_t(AF_INET)
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let bound = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    TestSocket.bind(sock, $0, length) == 0 && getsockname(sock, $0, &length) == 0
                }
            }
            guard bound else { POSIXSocket.close(sock); throw XCTSkip("bind failed") }
            fd = sock
            port = UInt16(bigEndian: address.sin_port)
            let done = self.done
            Thread.detachNewThread {
                defer { done.signal() }
                var pfd = pollfd(fd: sock, events: Int16(POLLIN), revents: 0)
                guard poll(&pfd, 1, wait) > 0 else { return }
                var buffer = [UInt8](repeating: 0, count: 512)
                var from = sockaddr_storage()
                var fromLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
                let n = withUnsafeMutablePointer(to: &from) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(sock, &buffer, buffer.count, 0, $0, &fromLength) }
                }
                guard n > 0 else { return }
                for packet in answer(Array(buffer[0..<n])) {
                    _ = withUnsafePointer(to: &from) { pointer in
                        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(sock, packet, packet.count, 0, $0, fromLength) }
                    }
                }
            }
        }

        func stop() {
            _ = done.wait(timeout: .now() + 6)
            POSIXSocket.close(fd)
        }
    }

    static func nonce(of request: [UInt8]) -> UInt64 {
        (40..<48).reduce(UInt64(0)) { $0 << 8 | UInt64(request[$1]) }
    }

    /// A reply for another request comes first and is ignored; the server's clock is 100 s ahead.
    func testAsksOnceAndKeepsOnlyTheMatchingReply() async throws {
        var request: [UInt8] = []
        let server = try LocalSNTPServer { r in
            request = r
            let now = Date().timeIntervalSince1970 + 100
            let nonce = Self.nonce(of: r)
            return [
                Self.reply(origin: nonce &+ 1, received: Self.ntp(now - 500), transmitted: Self.ntp(now - 500)),
                Self.reply(origin: nonce, received: Self.ntp(now), transmitted: Self.ntp(now))
            ]
        }
        defer { server.stop() }
        let measured = try await SNTP.query(host: "127.0.0.1", port: server.port, timeout: 3)
        XCTAssertEqual(Double(measured.offsetSeconds), 100, accuracy: 1)
        XCTAssertEqual(measured.source, .timeServer)
        XCTAssertEqual(measured.server, "127.0.0.1")
        XCTAssertEqual(request.count, 48)
        XCTAssertEqual(request[0], 0x23)
        XCTAssertEqual(Array(request[1..<40]), [UInt8](repeating: 0, count: 39))
    }

    func testNoValidReplyTimesOut() async throws {
        let server = try LocalSNTPServer { r in
            [Self.reply(origin: Self.nonce(of: r), received: 1, transmitted: 1, stratum: 0), [0x24, 0x02]]
        }
        defer { server.stop() }
        do {
            _ = try await SNTP.query(host: "127.0.0.1", port: server.port, timeout: 0.5)
            XCTFail("expected a timeout")
        } catch {
            XCTAssertEqual(error as? ServerClock.Failure, .timedOut)
        }
    }

    func testAPortNothingListensOnFails() async throws {
        let server = try LocalSNTPServer(wait: 0) { _ in [] }
        let port = server.port
        server.stop()  // closed: the request is answered with "port unreachable", or not at all
        do {
            _ = try await SNTP.query(host: "127.0.0.1", port: port, timeout: 1)
            XCTFail("expected a failure")
        } catch let failure as ServerClock.Failure {
            switch failure {
            case .connectionFailed, .timedOut: break
            default: XCTFail("unexpected \(failure)")
            }
        }
    }

    // MARK: the gateway request

    func testTheGatewayRequestIsAHeadWithNothingElse() {
        let request = ServerClock.headRequest(host: "vpn.example.com", port: 10443)
        XCTAssertEqual(
            request,
            "HEAD / HTTP/1.1\r\nHost: vpn.example.com:10443\r\nUser-Agent: PassTunnel\r\nAccept: */*\r\n"
                + "Connection: close\r\n\r\n")
        for word in ["cookie", "authorization", "alice", "SVPNCOOKIE"] {
            XCTAssertFalse(request.lowercased().contains(word.lowercased()), word)
        }
        XCTAssertEqual(ServerClock.hostHeader("vpn.example.com", port: 443), "vpn.example.com")
        XCTAssertEqual(ServerClock.hostHeader("198.51.100.7", port: 8443), "198.51.100.7:8443")
        XCTAssertEqual(ServerClock.hostHeader("2001:db8::1", port: 443), "[2001:db8::1]")
        XCTAssertEqual(ServerClock.hostHeader("fe80::1%en0", port: 10443), "[fe80::1]:10443")
    }

    func testTheGatewayAnswer() {
        let sent = Date(timeIntervalSince1970: 1_792_921_200)
        let received = sent.addingTimeInterval(1)
        let head = Data("HTTP/1.1 302 Found\r\nDate: Sun, 25 Oct 2026 09:41:02 GMT\r\nLocation: /remote/login".utf8)
        XCTAssertEqual(
            try ServerClock.gatewayResult(head: head, sent: sent, received: received, host: "vpn.example.com").get(),
            ClockOffset(offsetSeconds: 62, source: .gateway, server: "vpn.example.com", checkedAt: received))
        XCTAssertEqual(
            ServerClock.gatewayResult(
                head: Data("HTTP/1.1 200 OK\r\nServer: x".utf8), sent: sent, received: received,
                host: "vpn.example.com"), .failure(.noDate))
        XCTAssertEqual(
            ServerClock.gatewayResult(head: Data([0x15, 0x03, 0x03]), sent: sent, received: received, host: "vpn.example.com"),
            .failure(.invalidReply))
        XCTAssertEqual(
            ServerClock.gatewayResult(head: Data(), sent: sent, received: received, host: "vpn.example.com"),
            .failure(.invalidReply))
    }

    // MARK: the system's time server

    func testTheTimeServerOfTheSystem() {
        #if os(Linux)
        XCTAssertNil(ServerClock.timeServerHost(read: { _ in nil }, list: { _ in [] }))
        #else
        XCTAssertEqual(ServerClock.timeServerHost(read: { _ in nil }, list: { _ in [] }), "time.apple.com")
        #endif

        let files = [
            "/etc/systemd/timesyncd.conf": "[Time]\n#NTP=\n#FallbackNTP=ntp.example.org\n",
            "/etc/systemd/timesyncd.conf.d/20-site.conf": "[Time]\nNTP=ntp1.example.com ntp2.example.com\n",
            "/etc/systemd/timesyncd.conf.d/10-old.conf": "[Time]\nNTP=old.example.com\n",
            "/etc/chrony/chrony.conf": "pool 2.pool.example.org iburst\n"
        ]
        func read(_ path: String) -> String? { files[path] }
        func list(_ path: String) -> [String] {
            path == ServerClock.timesyncdDropIns ? ["20-site.conf", "10-old.conf", "README"] : []
        }
        XCTAssertEqual(ServerClock.configuredTimeServer(read: read, list: list), "ntp1.example.com", "the last drop-in wins")
        XCTAssertEqual(
            ServerClock.configuredTimeServer(read: { $0 == "/etc/chrony/chrony.conf" ? files[$0] : nil }, list: { _ in [] }),
            "2.pool.example.org")
        XCTAssertNil(
            ServerClock.configuredTimeServer(read: { $0 == "/etc/systemd/timesyncd.conf" ? files[$0] : nil }, list: { _ in [] }),
            "only commented out")
    }

    func testTimesyncdAndNTPConfigurations() {
        XCTAssertEqual(ServerClock.timesyncdServer(["[Time]\nNTP=a.example.com b.example.com\n"]), "a.example.com")
        XCTAssertEqual(ServerClock.timesyncdServer(["[Time]\nNTP=a.example.com\n", "[Time]\nNTP=\n"]), nil, "an empty NTP= clears it")
        XCTAssertEqual(ServerClock.timesyncdServer(["[Time]\nFallbackNTP=f.example.com\n"]), "f.example.com")
        XCTAssertEqual(ServerClock.timesyncdServer(["[Other]\nNTP=a.example.com\n"]), nil, "outside [Time]")
        XCTAssertEqual(ServerClock.timesyncdServer(["[Time]\n NTP = -bad a.example.com\n"]), "a.example.com", "never an option")
        XCTAssertEqual(
            ServerClock.ntpConfServer("# server old.example.com\nserver 127.127.1.0\nserver ntp.example.com iburst\n"),
            "ntp.example.com")
        XCTAssertEqual(ServerClock.ntpConfServer("driftfile /var/lib/ntp/drift\npool 198.51.100.123\n"), "198.51.100.123")
        XCTAssertNil(ServerClock.ntpConfServer("servers ntp.example.com\nserver\nserver bad/name\n"))
    }

    // MARK: the gateway over TLS (Network: Apple platforms)

    #if canImport(Network)
    static func httpDate(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "GMT")
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return f.string(from: date)
    }

    /// A gateway whose clock is 120 s ahead, answering a HEAD request like a FortiGate's portal.
    static func gateway(identity: SecIdentity) throws -> LocalTLSServer {
        try LocalTLSServer(identity: identity) { request in
            guard request.range(of: Data("\r\n\r\n".utf8)) != nil else { return nil }
            let date = httpDate(Date().addingTimeInterval(120))
            return Data("HTTP/1.1 302 Found\r\nLocation: /remote/login\r\nDate: \(date)\r\nContent-Length: 0\r\n\r\n".utf8)
        }
    }

    func testReadsTheTimeOfAGatewayWithItsTrustedCertificate() async throws {
        let (identity, digest) = try LocalTLSServer.testIdentity()
        let server = try Self.gateway(identity: identity)
        defer { server.stop() }
        let port = Int(try await server.start())

        let measured = try await ServerClock().gateway(
            host: "127.0.0.1", port: port, trustedCert: TLSFingerprint.display(digest),
            timeout: 5)
        XCTAssertEqual(Double(measured.offsetSeconds), 120, accuracy: 2)
        XCTAssertEqual(measured.source, .gateway)
        XCTAssertEqual(measured.server, "127.0.0.1")
        XCTAssertTrue(measured.isWrong)
        let request = String(decoding: server.received, as: UTF8.self)
        XCTAssertEqual(request, ServerClock.headRequest(host: "127.0.0.1", port: port), "one request, nothing else")
    }

    /// A certificate that is not the profile's (and that the system does not trust): nothing is sent.
    func testSendsNothingToAnUntrustedGateway() async throws {
        let (identity, _) = try LocalTLSServer.testIdentity()
        let server = try Self.gateway(identity: identity)
        defer { server.stop() }
        let port = Int(try await server.start())

        for pin in [String(repeating: "ab", count: 32), nil] {
            do {
                _ = try await ServerClock().gateway(host: "127.0.0.1", port: port, trustedCert: pin, timeout: 5)
                XCTFail("trusted a self-signed certificate (pin: \(pin ?? "none"))")
            } catch {
                XCTAssertEqual(error as? ServerClock.Failure, .untrusted, "pin: \(pin ?? "none")")
            }
        }
        XCTAssertEqual(server.received, Data(), "no request reached it")
    }

    func testRejectsBadGatewayInputWithoutConnecting() async {
        for (host, port, expected) in [
            ("https://vpn.example.com", 443, ServerClock.Failure.invalidHost), ("", 443, .invalidHost),
            ("127.0.0.1", 0, .invalidPort), ("127.0.0.1", 70000, .invalidPort)
        ] {
            do {
                _ = try await ServerClock().gateway(host: host, port: port, trustedCert: nil, timeout: 1)
                XCTFail("expected \(expected)")
            } catch {
                XCTAssertEqual(error as? ServerClock.Failure, expected)
            }
        }
    }
    #else
    func testTheGatewayIsNotAskedOnLinux() async {
        do {
            _ = try await ServerClock().gateway(host: "127.0.0.1", port: 443, trustedCert: nil, timeout: 1)
            XCTFail("expected unavailable")
        } catch {
            XCTAssertEqual(error as? ServerClock.Failure, .unavailable)
        }
    }
    #endif
}
