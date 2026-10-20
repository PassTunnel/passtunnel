import Foundation

extension HelperCore {
    /// Largest request the helper accepts. Real requests are well under 8 KiB.
    public static let maxRequestBytes = 1 << 16

    public enum RequestError: Error, Equatable, LocalizedError, CustomStringConvertible {
        case tooLarge(Int)
        case malformed
        case missingType
        case unknownType(String)
        case versionMismatch(client: Int, helper: Int)
        case invalidField(String)

        public var description: String {
            switch self {
            case .tooLarge(let n): return "Request too large (\(n) bytes, limit \(HelperCore.maxRequestBytes))."
            case .malformed: return "Malformed request: not a JSON object."
            case .missingType: return "Malformed request: no request type."
            case .unknownType(let t): return "Unknown request type “\(t)”."
            case .versionMismatch(let c, let h):
                return "Protocol version mismatch (app \(c), helper \(h)). Reinstall the helper from PassTunnel."
            case .invalidField(let f): return "Invalid request: field “\(f)” is missing or has the wrong type."
            }
        }
        public var errorDescription: String? { description }
    }

    private struct Envelope: Decodable {
        let type: String?
        let protocolVersion: Int?
        enum CodingKeys: String, CodingKey { case type, protocolVersion = "protocol_version" }
    }

    /// Decodes a request as received over XPC: size cap, JSON object, protocol version (a missing
    /// version is accepted for clients that predate the field), known type, then the typed payload.
    /// Error messages name fields only, never values (requests carry passwords).
    public static func decodeRequest(_ data: Data) throws -> HelperRequest {
        guard data.count <= maxRequestBytes else { throw RequestError.tooLarge(data.count) }
        guard (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else { throw RequestError.malformed }
        let envelope: Envelope
        do {
            envelope = try HelperJSON.decoder.decode(Envelope.self, from: data)
        } catch {
            throw RequestError.invalidField(fieldName(error) ?? "type")
        }
        if let v = envelope.protocolVersion, v != PT.helperProtocolVersion {
            throw RequestError.versionMismatch(client: v, helper: PT.helperProtocolVersion)
        }
        guard let type = envelope.type else { throw RequestError.missingType }
        guard HelperRequest.Kind(rawValue: type) != nil else { throw RequestError.unknownType(printable(type)) }
        do {
            return try HelperRequest(jsonData: data)
        } catch {
            throw RequestError.invalidField(fieldName(error) ?? "request")
        }
    }

    /// The JSON key a decoding error refers to (always one of our own coding keys).
    static func fieldName(_ error: Error) -> String? {
        guard let e = error as? DecodingError else { return nil }
        switch e {
        case .keyNotFound(let key, _): return key.stringValue
        case .typeMismatch(_, let c), .valueNotFound(_, let c), .dataCorrupted(let c):
            return c.codingPath.last?.stringValue
        @unknown default: return nil
        }
    }

    /// Client-supplied text echoed in an error: printable ASCII only, at most 32 characters.
    static func printable(_ s: String) -> String {
        String(String.UnicodeScalarView(s.unicodeScalars.prefix(32).map { (0x20...0x7E).contains($0.value) ? $0 : "?" }))
    }
}
