import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

/// Why a connect failed (`ConnectionFailure`, `VPNLog.verdict`): tool logs of OpenVPN and openfortivpn as the
/// Mac and Linux write them. What `ConnectionManager` does with them is in `ConnectionManagerTests`.
final class ConnectionFailureTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: fixtures

    /// One failed (or slow) attempt and what its log says.
    struct Fixture {
        var name: String
        var log: String
        var kind: ConnectionFailure.Kind?
        var reason: String?
        var credentialsSent: Bool
        var tries = 1
    }

    static let openVPNStart = """
        2026-10-25 09:41:00 OpenVPN 2.6.14 aarch64-apple-darwin24.0.0 [SSL (OpenSSL)] [LZO] [LZ4] [PKCS11] [MH/RECVDA] [AEAD]
        2026-10-25 09:41:00 library versions: OpenSSL 3.5.0 8 Apr 2025, LZO 2.10
        2026-10-25 09:41:00 MANAGEMENT: unix domain socket listening on /var/run/passtunnel/501/acme/mgmt.sock

        """

    static let linuxStart = """
        2026-10-25 09:41:00 OpenVPN 2.6.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
        2026-10-25 09:41:00 library versions: OpenSSL 3.0.13 30 Jan 2024, LZO 2.10
        2026-10-25 09:41:00 MANAGEMENT: unix domain socket listening on /run/passtunnel/1000/acme/mgmt.sock

        """

    static let fixtures: [Fixture] = [
        Fixture(
            name: "macOS UDP, no answer",
            log: openVPNStart + """
                2026-10-25 09:41:00 TCP/UDP: Preserving recently used remote address: [AF_INET]203.0.113.10:1194
                2026-10-25 09:41:00 Socket Buffers: R=[786896->786896] S=[9216->9216]
                2026-10-25 09:41:00 UDPv4 link local: (not bound)
                2026-10-25 09:41:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194
                2026-10-25 09:42:00 TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)
                2026-10-25 09:42:00 TLS Error: TLS handshake failed
                2026-10-25 09:42:00 SIGTERM[soft,tls-error] received, process exiting
                """, kind: .unreachable, reason: "TLS key negotiation failed to occur within 60 seconds", credentialsSent: false),
        Fixture(
            name: "Linux UDP, port closed",
            log: linuxStart + """
                2026-10-25 09:41:00 UDPv4 link local: (not bound)
                2026-10-25 09:41:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194
                2026-10-25 09:41:00 read UDPv4 [ECONNREFUSED]: Connection refused (fd=3,code=111)
                2026-10-25 09:41:02 read UDPv4 [ECONNREFUSED]: Connection refused (fd=3,code=111)
                """, kind: .unreachable, reason: "Connection refused", credentialsSent: false),
        Fixture(
            name: "macOS, no network",
            log: openVPNStart + """
                2026-10-25 09:41:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194
                2026-10-25 09:41:00 write UDPv4 []: No route to host (fd=4,code=65)
                """, kind: .unreachable, reason: "No route to host", credentialsSent: false),
        Fixture(
            name: "Linux TCP, refused",
            log: linuxStart + """
                2026-10-25 09:41:00 TCP/UDP: Preserving recently used remote address: [AF_INET]203.0.113.10:443
                2026-10-25 09:41:00 Attempting to establish TCP connection with [AF_INET]203.0.113.10:443
                2026-10-25 09:41:00 TCP: connect to [AF_INET]203.0.113.10:443 failed: Connection refused
                2026-10-25 09:41:00 SIGTERM[connection failed(soft),connection-failed] received, process exiting
                """, kind: .unreachable, reason: "Connection refused", credentialsSent: false),
        Fixture(
            name: "macOS TCP, timed out twice",
            log: openVPNStart + """
                2026-10-25 09:41:00 Attempting to establish TCP connection with [AF_INET]203.0.113.10:443
                2026-10-25 09:42:15 TCP: connect to [AF_INET]203.0.113.10:443 failed: Operation timed out
                2026-10-25 09:42:16 Attempting to establish TCP connection with [AF_INET]203.0.113.11:443
                2026-10-25 09:43:31 TCP: connect to [AF_INET]203.0.113.11:443 failed: Operation timed out
                """, kind: .unreachable, reason: "Operation timed out", credentialsSent: false, tries: 2),
        Fixture(
            name: "Linux TCP, timed out",
            log: linuxStart + """
                2026-10-25 09:41:00 Attempting to establish TCP connection with [AF_INET]203.0.113.10:443
                2026-10-25 09:43:10 TCP: connect to [AF_INET]203.0.113.10:443 failed: Connection timed out
                """, kind: .unreachable, reason: "Connection timed out", credentialsSent: false),
        Fixture(
            name: "macOS, name not found",
            log: openVPNStart + """
                2026-10-25 09:41:00 RESOLVE: Cannot resolve host address: vpn.example.com:1194 (nodename nor servname provided, or not known)
                2026-10-25 09:41:00 RESOLVE: Cannot resolve host address: vpn.example.com:1194 (nodename nor servname provided, or not known)
                2026-10-25 09:41:00 Could not determine IPv4/IPv6 protocol
                2026-10-25 09:41:00 SIGTERM[soft,Could not determine IPv4/IPv6 protocol] received, process exiting
                """, kind: .hostNotFound, reason: "nodename nor servname provided, or not known", credentialsSent: false),
        Fixture(
            name: "Linux, name not found",
            log: linuxStart + """
                2026-10-25 09:41:00 RESOLVE: Cannot resolve host address: vpn.example.com:1194 (Name or service not known)
                """, kind: .hostNotFound, reason: "Name or service not known", credentialsSent: false),
        Fixture(
            name: "Linux, no DNS",
            log: linuxStart + """
                2026-10-25 09:41:00 RESOLVE: Cannot resolve host address: vpn.example.com:1194 (Temporary failure in name resolution)
                """, kind: .hostNotFound, reason: "Temporary failure in name resolution", credentialsSent: false),
        Fixture(
            name: "second remote resolved, then no answer",
            log: openVPNStart + """
                2026-10-25 09:41:00 RESOLVE: Cannot resolve host address: vpn1.example.com:1194 (nodename nor servname provided, or not known)
                2026-10-25 09:41:01 UDPv4 link remote: [AF_INET]203.0.113.12:1194
                2026-10-25 09:42:01 TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)
                """, kind: .unreachable, reason: "TLS key negotiation failed to occur within 60 seconds", credentialsSent: false),
        Fixture(
            name: "sign-in rejected",
            log: openVPNStart + """
                2026-10-25 09:41:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194
                2026-10-25 09:41:01 TLS: Initial packet from [AF_INET]203.0.113.10:1194, sid=0a1b2c3d 4e5f6a7b
                2026-10-25 09:41:01 VERIFY OK: depth=1, CN=Acme CA
                2026-10-25 09:41:01 VERIFY OK: depth=0, CN=vpn.example.com
                2026-10-25 09:41:01 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 2048 bits RSA, signature: RSA-SHA256, peer temp key: 253 bits X25519
                2026-10-25 09:41:01 [vpn.example.com] Peer Connection Initiated with [AF_INET]203.0.113.10:1194
                2026-10-25 09:41:02 SENT CONTROL [vpn.example.com]: 'PUSH_REQUEST' (status=1)
                2026-10-25 09:41:02 AUTH: Received control message: AUTH_FAILED
                2026-10-25 09:41:02 SIGTERM[soft,auth-failure] received, process exiting
                """, kind: .authRejected, reason: nil, credentialsSent: true),
        Fixture(
            name: "server certificate refused",
            log: openVPNStart + """
                2026-10-25 09:41:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194
                2026-10-25 09:41:01 TLS: Initial packet from [AF_INET]203.0.113.10:1194, sid=0a1b2c3d 4e5f6a7b
                2026-10-25 09:41:01 VERIFY ERROR: depth=0, error=certificate has expired: CN=vpn.example.com, serial=4096
                2026-10-25 09:41:01 OpenSSL: error:0A000086:SSL routines::certificate verify failed:
                2026-10-25 09:41:01 TLS_ERROR: BIO read tls_read_plaintext error
                2026-10-25 09:41:01 TLS Error: TLS handshake failed
                """, kind: .configuration, reason: "certificate has expired", credentialsSent: false),
        Fixture(
            name: "options error",
            log: linuxStart + """
                2026-10-25 09:41:00 Options error: --cert fails with 'client.crt': No such file or directory (errno=2)
                2026-10-25 09:41:00 Options error: Please correct these errors.
                2026-10-25 09:41:00 Use --help for more information.
                """, kind: .configuration, reason: "--cert fails with 'client.crt': No such file or directory (errno=2)", credentialsSent: false),
        Fixture(
            name: "reached, then quiet",
            log: openVPNStart + """
                2026-10-25 09:41:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194
                2026-10-25 09:41:01 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 2048 bits RSA
                2026-10-25 09:41:01 [vpn.example.com] Peer Connection Initiated with [AF_INET]203.0.113.10:1194
                2026-10-25 09:41:02 read UDPv4 [ECONNREFUSED]: Connection refused (fd=3,code=111)
                """, kind: nil, reason: nil, credentialsSent: true),
        Fixture(
            name: "openfortivpn macOS, refused",
            log: """
                ERROR:  connect: Connection refused
                INFO:   Closed connection to gateway.
                """, kind: .unreachable, reason: "Connection refused", credentialsSent: false),
        Fixture(
            name: "openfortivpn Linux, timed out",
            log: """
                ERROR:  connect: Connection timed out
                INFO:   Closed connection to gateway.
                """, kind: .unreachable, reason: "Connection timed out", credentialsSent: false),
        Fixture(
            name: "openfortivpn macOS, name not found",
            log: """
                ERROR:  getaddrinfo: nodename nor servname provided, or not known
                """, kind: .hostNotFound, reason: "nodename nor servname provided, or not known", credentialsSent: false),
        Fixture(
            name: "openfortivpn Linux, name not found",
            log: """
                ERROR:  getaddrinfo: Name or service not known
                """, kind: .hostNotFound, reason: "Name or service not known", credentialsSent: false),
        Fixture(
            name: "openfortivpn, sign-in rejected",
            log: """
                INFO:   Connected to gateway.
                ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.
                INFO:   Closed connection to gateway.
                """, kind: .authRejected, reason: nil, credentialsSent: true),
        Fixture(
            name: "openfortivpn, untrusted gateway",
            log: """
                ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist. If you trust it, rerun with:
                ERROR:      --trusted-cert 5f0e8d1c2b3a49586776a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0
                ERROR:  or add this line to your config file:
                ERROR:      trusted-cert = 5f0e8d1c2b3a49586776a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0
                """, kind: .configuration, reason: "Gateway certificate validation failed", credentialsSent: false),
        Fixture(
            name: "dyld, a symbol this macOS lacks",
            log: """
                dyld[4242]: Symbol not found: _strchrnul
                  Referenced from: <3C3A9F0E-1D6B-3C2E-9E4A-0B6E1C9A7F21> /var/run/passtunnel/run/Frameworks/libidn2.0.dylib (built for macOS 26.0 which is newer than running OS)
                  Expected in:     <5F2B8E1A-6C4D-3A9B-8E7F-2D1C0B9A8E76> /usr/lib/libSystem.B.dylib
                """, kind: .toolUnsupported, reason: "Symbol not found: _strchrnul", credentialsSent: false),
        Fixture(
            name: "dyld, a library this macOS lacks",
            log: """
                dyld[4242]: Library not loaded: /usr/lib/libexample.1.dylib
                  Referenced from: <3C3A9F0E-1D6B-3C2E-9E4A-0B6E1C9A7F21> /var/run/passtunnel/run/Resources/bin/openvpn
                  Reason: tried: '/usr/lib/libexample.1.dylib' (no such file)
                """, kind: .toolUnsupported, reason: "Library not loaded: /usr/lib/libexample.1.dylib", credentialsSent: false),
        Fixture(
            name: "dyld before macOS 12",
            log: """
                dyld: Symbol not found: _strchrnul
                  Referenced from: /var/run/passtunnel/run/Resources/bin/openvpn
                """, kind: .toolUnsupported, reason: "Symbol not found: _strchrnul", credentialsSent: false),
        Fixture(
            name: "a plugin dlopen fails (not dyld stopping the tool)",
            log: openVPNStart + """
                2026-10-25 09:41:00 PLUGIN_INIT: could not load plugin shared object /tmp/x.so: dlopen(/tmp/x.so, 0x0001): Library not loaded: /usr/lib/libexample.1.dylib
                2026-10-25 09:41:00 Exiting due to fatal error
                """, kind: nil, reason: nil, credentialsSent: false)
    ]

    func testFixtures() {
        for f in Self.fixtures {
            let verdict = VPNLog.verdict(f.log)
            XCTAssertEqual(verdict?.kind, f.kind, f.name)
            XCTAssertEqual(verdict?.reason, f.reason, f.name)
            XCTAssertEqual(VPNLog.credentialsSent(f.log), f.credentialsSent, f.name)
            if f.kind == .unreachable { XCTAssertEqual(VPNLog.tries(f.log), f.tries, f.name) }
        }
    }

    /// The Mac's and Linux's words for the same thing give the same kind.
    func testMacAndLinuxLinesClassifyTheSame() {
        func kind(_ name: String) -> ConnectionFailure.Kind? {
            VPNLog.verdict(Self.fixtures.first { $0.name == name }!.log)?.kind
        }
        XCTAssertEqual(kind("macOS TCP, timed out twice"), kind("Linux TCP, timed out"))
        XCTAssertEqual(kind("macOS, name not found"), kind("Linux, name not found"))
        XCTAssertEqual(kind("openfortivpn macOS, name not found"), kind("openfortivpn Linux, name not found"))
        XCTAssertEqual(kind("openfortivpn macOS, refused"), kind("openfortivpn Linux, timed out"))
    }

    /// dyld's lines count only as the log's first (it writes them before the tool can write anything):
    /// later ones can be a server's words, which openfortivpn prints. Not a fatal marker either: the
    /// connect takes it only once the tool is gone (`ConnectionManagerTests`).
    func testDyldStoppingTheToolIsTheFirstLine() {
        let symbol = Self.fixtures.first { $0.name == "dyld, a symbol this macOS lacks" }!.log
        XCTAssertFalse(VPNLog.isFatal(symbol))
        XCTAssertFalse(VPNLog.attempted(symbol) && VPNLog.credentialsSent(symbol))
        XCTAssertEqual(VPNLog.toolLoadFailure("\n  \n" + symbol), "Symbol not found: _strchrnul")
        XCTAssertNil(VPNLog.toolLoadFailure("INFO:   Connected to gateway.\n" + symbol), "a server's words")
        XCTAssertNotEqual(VPNLog.verdict("INFO:   Connected to gateway.\n" + symbol)?.kind, .toolUnsupported)
        XCTAssertNil(VPNLog.toolLoadFailure("PassTunnel: something\n" + symbol))
        XCTAssertNil(VPNLog.toolLoadFailure("dyld[12]: some other note\n"))
        XCTAssertNil(VPNLog.toolLoadFailure("dyld[x]: Symbol not found: _a\n"), "not dyld's prefix")
        XCTAssertNil(VPNLog.toolLoadFailure("libdyld: Symbol not found: _a\n"))
        XCTAssertFalse(VPNLog.isFatal(Self.openVPNStart))
    }

    func testAttemptedTellsAServerThatIsNotThereFromASilentLog() {
        XCTAssertTrue(VPNLog.attempted(Self.openVPNStart + "2026-10-25 09:41:00 UDPv4 link remote: [AF_INET]203.0.113.10:1194\n"))
        XCTAssertTrue(VPNLog.attempted("2026-10-25 09:41:00 TCP connection established with [AF_INET]203.0.113.10:443\n"))
        XCTAssertFalse(VPNLog.attempted(Self.openVPNStart))
        XCTAssertFalse(VPNLog.attempted(""))
    }

    // MARK: from the error

    func testFailureFromTheErrorAndTheLog() {
        let rejected = Self.fixtures.first { $0.name == "sign-in rejected" }!.log
        let handed = ConnectionFailure.Handed(code: true, codeSecondsLeft: 22)
        var f = ConnectionFailure.of(PTError.authFailed("…"), log: rejected, handed: handed, at: t0)
        XCTAssertEqual(
            f,
            ConnectionFailure(
                kind: .authRejected, at: t0, reply: "AUTH_FAILED", credentialsSent: true,
                codeSent: true, codeSecondsLeft: 22))
        XCTAssertEqual(f.details, "The server answered: AUTH_FAILED. The code was sent with 22 s left. Not retried, to avoid a lockout.")

        let refused = Self.fixtures.first { $0.name == "Linux TCP, refused" }!.log
        f = ConnectionFailure.of(
            PTError.serverUnreachable(server: "vpn.example.com:443", reason: "Connection refused", log: ""),
            log: refused, handed: handed, at: t0)
        XCTAssertEqual(
            f,
            ConnectionFailure(
                kind: .unreachable, at: t0, reason: "Connection refused", credentialsSent: false,
                codeSent: false, tries: 1), "nothing sent, so no code used up")

        f = ConnectionFailure.of(
            PTError.connectTimeout(60), log: Self.fixtures.first { $0.name == "reached, then quiet" }!.log,
            handed: handed, at: t0)
        XCTAssertEqual(f.kind, .timeout)
        XCTAssertTrue(f.codeSent)

        f = ConnectionFailure.of(PTError.setupFailed(reason: "setting DNS failed", log: ""), log: "", handed: nil, at: t0)
        XCTAssertEqual(f, ConnectionFailure(kind: .setup, at: t0, reason: "setting DNS failed", credentialsSent: true))

        let options = Self.fixtures.first { $0.name == "options error" }!.log
        XCTAssertEqual(ConnectionFailure.of(PTError.connectFailed("…"), log: options, handed: nil, at: t0).kind, .configuration)
        XCTAssertEqual(ConnectionFailure.of(PTError.connectFailed("…"), log: "something else\n", handed: nil, at: t0).kind, .failed)
        let dyld = Self.fixtures.first { $0.name == "dyld, a symbol this macOS lacks" }!.log
        f = ConnectionFailure.of(PTError.toolUnsupported(reason: "Symbol not found: _strchrnul", log: ""), log: dyld, handed: handed, at: t0)
        XCTAssertEqual(f, ConnectionFailure(kind: .toolUnsupported, at: t0, reason: "Symbol not found: _strchrnul"))
        XCTAssertNil(f.details)
        XCTAssertEqual(ConnectionFailure.of(PTError.connectFailed("…"), log: dyld, handed: nil, at: t0).kind, .toolUnsupported)
        XCTAssertEqual(AutomationErrorCode.of(PTError.toolUnsupported(reason: "x", log: "")), .connectFailed)
        XCTAssertEqual(PTError.toolUnsupported(reason: "x", log: "tail").logTail, "tail")
        XCTAssertEqual(ConnectionFailure.of(PTError.missingPassword("acme"), log: nil, handed: nil, at: t0).kind, .configuration)
        XCTAssertEqual(ConnectionFailure.of(PTError.connectCancelled, log: nil, handed: nil, at: t0).kind, .cancelled)
        XCTAssertEqual(ConnectionFailure.of(PTError.userConfirmationCancelled, log: nil, handed: nil, at: t0).kind, .cancelled)
        XCTAssertEqual(ConnectionFailure.of(HelperClientError.notInstalled, log: nil, handed: nil, at: t0).kind, .failed)
        // A log that is not this attempt's is not read: before the tool ran, no log is passed.
        XCTAssertFalse(ConnectionFailure.of(PTError.missingConfig("acme"), log: nil, handed: nil, at: t0).credentialsSent)
    }

    @MainActor
    func testJSONShape() throws {
        let f = ConnectionFailure(
            kind: .authRejected, at: t0, reply: "AUTH_FAILED", credentialsSent: true, codeSent: true,
            codeSecondsLeft: 22)
        let text = String(decoding: try AutomationJSON.encoder(pretty: false).encode(f), as: UTF8.self)
        XCTAssertEqual(
            text,
            #"{"at":"2023-11-14T22:13:20Z","code_seconds_left":22,"code_sent":true,"credentials_sent":true,"kind":"auth_rejected","reply":"AUTH_FAILED"}"#
        )
        let report = ErrorReport(ConnectFailedError(PTError.authFailed("tail"), failure: f))
        XCTAssertEqual(report.code, "credentials_rejected")
        XCTAssertEqual(report.failure, f)
        XCTAssertNil(ErrorReport(PTError.authFailed("tail")).failure)
        XCTAssertEqual(AutomationErrorCode.of(PTError.serverUnreachable(server: "", reason: "x", log: "")), .serverUnreachable)
        XCTAssertEqual(AutomationErrorCode.of(PTError.hostNotFound(server: "", log: "")), .hostNotFound)
        XCTAssertEqual(AutomationErrorCode.serverUnreachable.exitCode, AutomationExit.connectFailed)
        XCTAssertEqual(AutomationErrorCode.hostNotFound.exitCode, AutomationExit.connectFailed)
        XCTAssertTrue(
            ConnectionManager.isRetryable(PTError.serverUnreachable(server: "", reason: "x", log: "")),
            "an unreachable server may answer later")
        XCTAssertFalse(ConnectionManager.isRetryable(PTError.authFailed("")), "a rejected sign-in stops at once")
    }

    func testMessages() {
        XCTAssertEqual(
            PTError.serverUnreachable(server: "vpn.example.com:443", reason: "Connection refused", log: "").localizedDescription,
            "The server vpn.example.com:443 could not be reached: Connection refused. Your sign-in was not sent.")
        XCTAssertEqual(
            PTError.hostNotFound(server: "vpn.example.com:1194", log: "").localizedDescription,
            "The server name vpn.example.com:1194 could not be found. Check the server address and the network connection.")
        XCTAssertEqual(PTError.serverUnreachable(server: "", reason: "x", log: "tail").logTail, "tail")
    }
}
