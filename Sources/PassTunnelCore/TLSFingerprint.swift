#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto   // swift-crypto: the same API, outside Apple platforms
#endif
import Foundation
#if os(macOS)
import Network
import Security
#endif
import PassTunnelKit
import PassTunnelVPNConfig

/// Reads a TLS server's leaf certificate and returns its SHA-256 digest, the format openfortivpn
/// expects for `trusted-cert`. The certificate is never trusted and no application data is sent:
/// the handshake is aborted as soon as the certificate has been seen. Reading it (`fetch`, the
/// editor's) is macOS only (Network); the digest formats are used everywhere (`ProfileDestination`).
public enum TLSFingerprint {
    public enum Failure: Error, Equatable, LocalizedError {
        case invalidHost
        case invalidPort
        case timedOut
        case noCertificate
        case connectionFailed(String)

        public var errorDescription: String? {
            switch self {
            case .invalidHost:
                return String(localized: "Enter a valid gateway address first.")
            case .invalidPort:
                return String(localized: "The port must be between 1 and 65535.")
            case .timedOut:
                return String(localized: "The gateway did not answer in time.")
            case .noCertificate:
                return String(localized: "The gateway did not present a certificate.")
            case .connectionFailed(let reason):
                return String(localized: "Could not reach the gateway: \(reason)")
            }
        }
    }

    #if os(macOS)
    /// 64 lowercase hex characters (SHA-256 of the DER-encoded leaf certificate).
    public static func fetch(host: String, port: Int, timeout: TimeInterval = 10) async throws -> String {
        let h = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard FortiConfig.isValidHost(h) else { throw Failure.invalidHost }
        guard (1...65535).contains(port), let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            throw Failure.invalidPort
        }

        let queue = DispatchQueue(label: "passtunnel.tls-fingerprint")
        let probe = Probe()
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
            let ref = sec_trust_copy_ref(trust).takeRetainedValue()
            if let chain = SecTrustCopyCertificateChain(ref) as? [SecCertificate], let leaf = chain.first {
                probe.fingerprint = sha256Hex(SecCertificateCopyData(leaf) as Data)
            }
            complete(false)   // never trust it; we only wanted to look
        }, queue)
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = max(1, Int(timeout.rounded(.up)))
        let connection = NWConnection(host: NWEndpoint.Host(h), port: nwPort,
                                      using: NWParameters(tls: tls, tcp: tcp))

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
                probe.continuation = continuation
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        probe.finish(connection, fallback: .noCertificate)
                    case .failed(let error), .waiting(let error):
                        probe.finish(connection, fallback: .connectionFailed(error.localizedDescription))
                    case .cancelled:
                        probe.finish(connection, fallback: .timedOut)
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + timeout) {
                    probe.finish(connection, fallback: .timedOut)
                }
            }
        } onCancel: {
            queue.async { probe.finish(connection, fallback: .timedOut) }
        }
    }
    #endif

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Accepts "AB:CD:…", spaces or plain hex; returns 64 lowercase hex characters, or nil.
    public static func normalize(_ text: String) -> String? {
        let hex = text.filter { !$0.isWhitespace && $0 != ":" }.lowercased()
        return FortiConfig.isValidDigest(hex) ? hex : nil
    }

    /// "ab:cd:…" grouped in pairs, upper case, for showing to people.
    public static func display(_ hex: String) -> String {
        var pairs: [String] = []
        var current = ""
        for c in hex.uppercased() {
            current.append(c)
            if current.count == 2 { pairs.append(current); current = "" }
        }
        if !current.isEmpty { pairs.append(current) }
        return pairs.joined(separator: ":")
    }

    #if os(macOS)
    /// Single-use result holder; all access happens on the probe's serial queue.
    private final class Probe: @unchecked Sendable {
        var fingerprint: String?
        var continuation: CheckedContinuation<String, Error>?

        func finish(_ connection: NWConnection, fallback: Failure) {
            guard let c = continuation else { return }
            continuation = nil
            connection.stateUpdateHandler = nil
            connection.cancel()
            if let fingerprint { c.resume(returning: fingerprint) } else { c.resume(throwing: fallback) }
        }
    }
    #endif
}
