// Linux only: the protocol of passtunneld, the root daemon (docs/LINUX.md, "The daemon protocol").
#if os(Linux)
import Foundation

/// One request per connection to `PT.daemonSocketPath()`, one JSON object on one line each way, each
/// line at most `maxLineBytes` (the newline not counted):
///
/// - `{"op":"hello"}` → `DaemonHello`
/// - `{"op":"perform","request":<HelperRequest>}` → `HelperResponse`; the daemon decodes the request
///   with `HelperCore.decodeRequest`, as the Mac's helper does.
public enum DaemonProtocol {
    public static let maxLineBytes = HelperCore.maxRequestBytes

    /// The `hello` line, newline included.
    public static let helloLine = Data(#"{"op":"hello"}"#.utf8) + Data([0x0A])

    /// The `perform` line of `request`, newline included. The request's own encoding is embedded as it
    /// is, so the daemon decodes exactly what `HelperRequest.jsonData()` wrote.
    public static func performLine(_ request: HelperRequest) throws -> Data {
        Data(#"{"op":"perform","request":"#.utf8) + (try request.jsonData()) + Data("}\n".utf8)
    }
}

/// The reply to `hello`: the daemon's protocol (`PT.helperProtocolVersion`), its build (hex SHA-256
/// of its executable, `HelperBuild`) and its build number, when it was built with one.
public struct DaemonHello: Codable, Equatable, Sendable {
    public var protocolVersion: Int
    public var build: String
    public var buildNumber: Int?

    public init(protocolVersion: Int = PT.helperProtocolVersion, build: String, buildNumber: Int? = nil) {
        self.protocolVersion = protocolVersion
        self.build = build
        self.buildNumber = buildNumber
    }

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol", build, buildNumber = "build_number"
    }

    public func jsonData() throws -> Data { try HelperJSON.encoder.encode(self) }
    public init(jsonData: Data) throws { self = try HelperJSON.decoder.decode(DaemonHello.self, from: jsonData) }
}
#endif
