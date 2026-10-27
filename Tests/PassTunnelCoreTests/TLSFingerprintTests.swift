import Foundation
import XCTest

@testable import PassTunnelCore

#if os(macOS)
import Network
import Security
#endif

/// Uses only a TLS server on 127.0.0.1 started by the test; never contacts other hosts.
final class TLSFingerprintTests: XCTestCase {
    func testNormalizeAndDisplay() {
        let hex = String(repeating: "ab", count: 32)
        XCTAssertEqual(TLSFingerprint.normalize(hex.uppercased()), hex)
        XCTAssertEqual(TLSFingerprint.normalize(TLSFingerprint.display(hex)), hex)
        XCTAssertEqual(TLSFingerprint.normalize(" AB:" + String(repeating: "ab", count: 31) + " "), hex)
        XCTAssertNil(TLSFingerprint.normalize("ab:cd"))
        XCTAssertNil(TLSFingerprint.normalize(String(repeating: "zz", count: 32)))
        XCTAssertEqual(TLSFingerprint.display("ab01ff"), "AB:01:FF")
        XCTAssertEqual(
            TLSFingerprint.sha256Hex(Data("abc".utf8)),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    // Reading a certificate is macOS only (Network).
    #if os(macOS)
    func testRejectsBadInputWithoutConnecting() async {
        for (host, port, expected) in [
            ("https://vpn.example.com", 443, TLSFingerprint.Failure.invalidHost),
            ("", 443, .invalidHost), ("127.0.0.1", 0, .invalidPort)
        ] {
            do {
                _ = try await TLSFingerprint.fetch(host: host, port: port, timeout: 1)
                XCTFail("expected \(expected)")
            } catch {
                XCTAssertEqual(error as? TLSFingerprint.Failure, expected)
            }
        }
    }

    func testClosedLocalPortFails() async throws {
        let port = try Self.unusedLocalPort()
        do {
            _ = try await TLSFingerprint.fetch(host: "127.0.0.1", port: port, timeout: 3)
            XCTFail("expected a failure")
        } catch let failure as TLSFingerprint.Failure {
            switch failure {
            case .connectionFailed, .timedOut: break
            default: XCTFail("unexpected \(failure)")
            }
        }
    }

    func testReadsLeafCertificateFromLocalServer() async throws {
        let (identity, expected) = try LocalTLSServer.testIdentity()
        let server = try LocalTLSServer(identity: identity)
        defer { server.stop() }
        let port = try await server.start()

        let fingerprint = try await TLSFingerprint.fetch(host: "127.0.0.1", port: Int(port), timeout: 5)
        XCTAssertEqual(fingerprint, expected)
        XCTAssertEqual(fingerprint.count, 64)
    }

    // MARK: helpers

    static func run(_ tool: String, _ args: [String]) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw XCTSkip("\(tool) \(args.first ?? "") failed") }
    }

    /// A port on 127.0.0.1 that nothing listens on (bound, then released).
    static func unusedLocalPort() throws -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw XCTSkip("no socket") }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, len) == 0 && getsockname(fd, $0, &len) == 0
            }
        }
        guard bound else { throw XCTSkip("bind failed") }
        return Int(UInt16(bigEndian: addr.sin_port))
    }
    #endif
}

#if os(macOS)
/// TLS listener on 127.0.0.1 with the given identity; accepts connections, keeps what they send and,
/// with `respond`, answers it.
final class LocalTLSServer: @unchecked Sendable {
    let listener: NWListener
    let queue = DispatchQueue(label: "tls-test-server")
    private var connections: [NWConnection] = []
    private var started = false  // touched only on `queue`
    /// What a connection sent so far → the answer to send (and then close), or nil to keep reading.
    private let respond: ((Data) -> Data?)?
    private var receivedData = Data()  // touched only on `queue`

    /// Everything the clients sent after the handshake.
    var received: Data { queue.sync { receivedData } }

    init(identity: SecIdentity, respond: ((Data) -> Data?)? = nil) throws {
        self.respond = respond
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, sec_identity_create(identity)!)
        let params = NWParameters(tls: tls)
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: params)
    }

    func start() async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<UInt16, Error>) in
            listener.newConnectionHandler = { [weak self] conn in
                guard let self else { return }
                self.connections.append(conn)
                conn.start(queue: self.queue)
                self.read(conn, sofar: Data())
            }
            listener.stateUpdateHandler = { [weak self] state in
                guard let self, !self.started else { return }
                switch state {
                case .ready:
                    self.started = true
                    c.resume(returning: self.listener.port?.rawValue ?? 0)
                case .failed(let error):
                    self.started = true
                    c.resume(throwing: error)
                default: break
                }
            }
            listener.start(queue: queue)
        }
    }

    private func read(_ conn: NWConnection, sofar: Data) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            var all = sofar
            if let data {
                all.append(data)
                self.receivedData.append(data)
                if let reply = self.respond?(all) {
                    conn.send(content: reply, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
                    return
                }
            }
            if isComplete || error != nil { return }
            self.read(conn, sofar: all)
        }
    }

    func stop() {
        queue.sync {
            connections.forEach { $0.cancel() }
            listener.cancel()
        }
    }

    /// A throwaway self-signed identity for "localhost", made with openssl and imported in memory only
    /// (never into a keychain), and its certificate's SHA-256. Skips without openssl or before macOS 15.
    static func testIdentity() throws -> (identity: SecIdentity, sha256: String) {
        guard #available(macOS 15, *) else { throw XCTSkip("in-memory PKCS#12 import needs macOS 15") }
        let openssl = "/usr/bin/openssl"
        guard FileManager.default.isExecutableFile(atPath: openssl) else { throw XCTSkip("openssl not available") }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("tlsfp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let key = dir.appendingPathComponent("key.pem").path
        let cert = dir.appendingPathComponent("cert.pem").path
        let der = dir.appendingPathComponent("cert.der").path
        let p12 = dir.appendingPathComponent("id.p12").path
        try TLSFingerprintTests.run(
            openssl,
            [
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                "-days", "1", "-subj", "/CN=localhost"
            ])
        try TLSFingerprintTests.run(openssl, ["x509", "-in", cert, "-outform", "der", "-out", der])
        try TLSFingerprintTests.run(openssl, ["pkcs12", "-export", "-in", cert, "-inkey", key, "-out", p12, "-passout", "pass:test"])
        let digest = TLSFingerprint.sha256Hex(try Data(contentsOf: URL(fileURLWithPath: der)))

        var items: CFArray?
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: "test",
            kSecImportToMemoryOnly as String: true
        ]
        let status = SecPKCS12Import(
            try Data(contentsOf: URL(fileURLWithPath: p12)) as CFData,
            options as CFDictionary, &items)
        guard status == errSecSuccess,
            let first = (items as? [[String: Any]])?.first,
            let identityRef = first[kSecImportItemIdentity as String]
        else {
            throw XCTSkip("could not import the test identity (\(status))")
        }
        return (identityRef as! SecIdentity, digest)
    }
}
#endif
