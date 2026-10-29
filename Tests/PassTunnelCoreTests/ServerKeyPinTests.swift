import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelVPNConfig

#if os(macOS)
import Security
#endif

/// openconnect's `pin-sha256:` of a certificate (`ServerKeyPin`), against golden certificates in
/// Tests/Fixtures/certificates (self-signed, for vpn.example.com, made with OpenSSL; `rsa2048-v1.pem` with LibreSSL's
/// `x509 -req`, a version 1 certificate without the `[0]` version field). Each expected pin is what
///
///     openssl x509 -in F -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
///
/// gives, and also what openconnect 9.21 (the bundled build, Homebrew's bottle) printed as its
/// `--servercert pin-sha256:…` hint when it was run with `--authenticate --non-inter` against `openssl s_server`
/// on 127.0.0.1 with that certificate (all five matched).
final class ServerKeyPinTests: XCTestCase {
    static let fixtures = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures/certificates")

    static let golden: [(file: String, pin: String)] = [
        ("rsa2048.pem", "pin-sha256:B9S1MyM7eI6e0MBVCfgWo0zkSVpzyFfkmueG8/HAbiY="),
        ("ec-p256.pem", "pin-sha256:E86EpKhiszwwyqu937GB+mox53WHxoGiVhwY7ZXxrwQ="),
        ("ec-p384.pem", "pin-sha256:nXT1cZ7l6V0Nl3/IN60buPbTAKGDxN6gRKMoqLbp2m8="),
        ("ed25519.pem", "pin-sha256:sbhmxkrZTvZRV3GtFsBZeNKW9lfLQNnXhrEu80mpiFQ="),
        ("rsa2048-v1.pem", "pin-sha256:3jdTgn1+mRWHyipZS9DXeJWf2QU/ekGCuJoFjRnOsmo=")
    ]

    /// The DER inside a PEM file's first CERTIFICATE block.
    static func der(_ file: String) throws -> Data {
        let pem = try String(contentsOf: fixtures.appendingPathComponent(file), encoding: .utf8)
        let body = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") && !$0.isEmpty }.joined()
        return try XCTUnwrap(Data(base64Encoded: body), file)
    }

    func testGoldenPins() throws {
        for (file, pin) in Self.golden {
            let der = try Self.der(file)
            XCTAssertEqual(ServerKeyPin.pin(certificate: der), pin, file)
            XCTAssertTrue(OpenConnectPin.isValid(pin), file)
        }
    }

    /// The pin is the hash of the SubjectPublicKeyInfo element exactly, tag and length included.
    func testTheElementIsTheWholeSubjectPublicKeyInfo() throws {
        let der = try Self.der("ec-p256.pem")
        let spki = try XCTUnwrap(ServerKeyPin.subjectPublicKeyInfo(certificate: der))
        // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (65-byte point) }: 91 bytes.
        XCTAssertEqual(spki.count, 91)
        XCTAssertEqual(Array(spki.prefix(4)), [0x30, 0x59, 0x30, 0x13])
        XCTAssertNotNil(der.range(of: spki))
        XCTAssertEqual(ServerKeyPin.pin(subjectPublicKeyInfo: spki), "pin-sha256:E86EpKhiszwwyqu937GB+mox53WHxoGiVhwY7ZXxrwQ=")
        // RSA: SEQUENCE (long form length 0x0122) holding rsaEncryption and the key.
        let rsa = try XCTUnwrap(ServerKeyPin.subjectPublicKeyInfo(certificate: try Self.der("rsa2048.pem")))
        XCTAssertEqual(Array(rsa.prefix(4)), [0x30, 0x82, 0x01, 0x22])
        XCTAssertEqual(rsa.count, 0x0122 + 4)
        // The version 1 certificate starts its tbsCertificate with the serial number.
        let v1 = try Self.der("rsa2048-v1.pem")
        XCTAssertNotEqual(v1[v1.startIndex + 8], 0xA0)
        XCTAssertEqual(try Self.der("rsa2048.pem")[8], 0xA0)
    }

    func testAnythingButOneCertificateIsRefused() throws {
        let der = try Self.der("ec-p256.pem")
        let bytes = [UInt8](der)
        func refused(_ b: [UInt8], _ what: String, line: UInt = #line) {
            XCTAssertNil(ServerKeyPin.subjectPublicKeyInfo(certificate: Data(b)), what, line: line)
        }
        refused([], "empty")
        refused([0x30], "a tag alone")
        refused([0x30, 0x00], "an empty SEQUENCE")
        refused([0x30, 0x80, 0x00, 0x00], "indefinite length")
        refused([0x30, 0x81, 0x05, 1, 2, 3, 4, 5], "a long form length under 128")
        refused([0x30, 0x82, 0x00, 0x80] + Array(repeating: 0, count: 128), "a length with a leading zero byte")
        refused([0x30, 0x85, 1, 0, 0, 0, 0], "a five-byte length")
        refused([0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF], "a length past the end")
        refused([0x1F, 0x01, 0x00], "a multi-byte tag")
        for cut in [1, 2, 10, bytes.count / 2, bytes.count - 1] { refused(Array(bytes.prefix(cut)), "cut at \(cut)") }
        refused(bytes + [0x00], "a byte after the certificate")
        refused(bytes + bytes, "two certificates")
        var wrongTag = bytes
        wrongTag[0] = 0x31
        refused(wrongTag, "a SET")
        // The serial number's tag (after the 3-byte version field at 8) made a SEQUENCE: the fields no longer line up.
        var noSerial = bytes
        XCTAssertEqual(noSerial[13], 0x02)
        noSerial[13] = 0x30
        refused(noSerial, "no serial number")
        XCTAssertNil(ServerKeyPin.pin(certificate: Data("not a certificate".utf8)))
        for count in [0, 1, 7, 64, 1000] {
            var rng = SystemRandomNumberGenerator()
            let noise = (0..<count).map { _ in UInt8.random(in: 0...255, using: &rng) }
            _ = ServerKeyPin.subjectPublicKeyInfo(certificate: Data(noise))  // never traps
        }
    }

    /// Every truncation and every single-byte change of a real certificate either reads a SubjectPublicKeyInfo inside
    /// the bytes or is refused; none traps.
    func testMutationsNeverReadOutOfBounds() throws {
        for (file, _) in Self.golden {
            let bytes = [UInt8](try Self.der(file))
            for cut in 0..<bytes.count { XCTAssertNil(ServerKeyPin.subjectPublicKeyInfo(certificate: Data(bytes.prefix(cut)))) }
            for i in stride(from: 0, to: min(bytes.count, 400), by: 1) {
                for value: UInt8 in [0x00, 0x7F, 0x80, 0x81, 0x84, 0xFF] {
                    var b = bytes
                    b[i] = value
                    if let spki = ServerKeyPin.subjectPublicKeyInfo(certificate: Data(b)) {
                        XCTAssertNotNil(Data(b).range(of: spki))
                    }
                }
            }
        }
    }

    #if os(macOS)
    /// "Fetch Fingerprint" of a Cisco AnyConnect profile against a TLS server on 127.0.0.1 (started here): the pin of
    /// the key, as the openssl command line works it out from the same certificate.
    func testFetchesTheServerKeyPinFromALocalServer() async throws {
        let (identity, _) = try LocalTLSServer.testIdentity()
        var certificate: SecCertificate?
        XCTAssertEqual(SecIdentityCopyCertificate(identity, &certificate), errSecSuccess)
        let der = SecCertificateCopyData(try XCTUnwrap(certificate)) as Data
        let expected = try Self.opensslPin(der)
        XCTAssertEqual(ServerKeyPin.pin(certificate: der), expected)

        let server = try LocalTLSServer(identity: identity)
        defer { server.stop() }
        let port = try await server.start()
        let pin = try await TLSFingerprint.fetchServerKeyPin(host: "127.0.0.1", port: Int(port), timeout: 5)
        XCTAssertEqual(pin, expected)
        XCTAssertTrue(OpenConnectPin.isValid(pin))
        XCTAssertTrue(server.received.isEmpty, "nothing was sent after the handshake")
    }

    func testFetchRefusesWhatIsNoServerWithoutConnecting() async {
        for (host, port, expected) in [
            ("https://vpn.example.com", 443, TLSFingerprint.Failure.invalidHost), ("", 443, .invalidHost),
            ("fe80::1%en0", 443, .invalidHost), ("127.0.0.1", 0, .invalidPort), ("127.0.0.1", 70000, .invalidPort)
        ] {
            do {
                _ = try await TLSFingerprint.fetchServerKeyPin(host: host, port: port, timeout: 1)
                XCTFail("expected \(expected)")
            } catch {
                XCTAssertEqual(error as? TLSFingerprint.Failure, expected)
            }
        }
    }

    /// `openssl x509 -pubkey`: the PUBLIC KEY block, which is the SubjectPublicKeyInfo's DER in base64, hashed.
    static func opensslPin(_ der: Data) throws -> String {
        let openssl = "/usr/bin/openssl"
        guard FileManager.default.isExecutableFile(atPath: openssl) else { throw XCTSkip("openssl not available") }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("spki-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let cert = dir.appendingPathComponent("cert.der")
        try der.write(to: cert)
        // LibreSSL prints the key on standard output whatever -out says.
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: openssl)
        process.arguments = ["x509", "-inform", "der", "-in", cert.path, "-pubkey", "-noout"]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw XCTSkip("openssl x509 -pubkey failed") }
        let pem = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(pem.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        let body = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") && !$0.isEmpty }.joined()
        return ServerKeyPin.pin(subjectPublicKeyInfo: try XCTUnwrap(Data(base64Encoded: body)))
    }
    #endif
}
