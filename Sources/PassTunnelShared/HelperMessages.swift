import Foundation

/// Start an OpenVPN profile. `secret` is the password with the OTP already formatted in.
/// The management interface is the unix socket `<profileDir>/mgmt.sock` (returned in
/// `HelperResponse.mgmtSocket`); `mgmtPort` is ignored and only kept so protocol-1 payloads decode.
public struct OpenVPNStart: Codable, Equatable, CustomStringConvertible, CustomDebugStringConvertible,
                            CustomReflectable {
    public var profileID: String
    public var profileDir: String
    public var mgmtPort: Int?
    public var username: String?
    public var secret: String?
    public var logPath: String

    public init(profileID: String, profileDir: String, mgmtPort: Int? = nil,
                username: String? = nil, secret: String? = nil, logPath: String) {
        self.profileID = profileID
        self.profileDir = profileDir
        self.mgmtPort = mgmtPort
        self.username = username
        self.secret = secret
        self.logPath = logPath
    }

    enum CodingKeys: String, CodingKey {
        case profileID = "profile_id", profileDir = "profile_dir", mgmtPort = "mgmt_port"
        case username, secret, logPath = "log_path"
    }

    public var description: String {
        "OpenVPNStart(profileID: \(profileID), profileDir: \(profileDir), "
            + "username: \(username ?? "nil"), secret: \(secret == nil ? "nil" : "<redacted>"), logPath: \(logPath))"
    }
    public var debugDescription: String { description }

    /// Keeps `dump()` and other Mirror-based printing from revealing the secret.
    public var customMirror: Mirror {
        Mirror(self, children: ["profileID": profileID, "profileDir": profileDir, "username": username as Any,
                                "secret": secret == nil ? "nil" : "<redacted>", "logPath": logPath])
    }
}

/// Start a FortiGate SSL VPN profile through openfortivpn.
public struct FortiStart: Codable, Equatable, CustomStringConvertible, CustomDebugStringConvertible,
                          CustomReflectable {
    public var profileID: String
    public var profileDir: String
    public var host: String
    public var port: Int
    public var username: String
    public var password: String
    public var otp: String?
    public var trustedCert: String
    public var setDNS: Bool
    public var setRoutes: Bool
    public var logPath: String

    public init(profileID: String, profileDir: String, host: String, port: Int = 443,
                username: String, password: String, otp: String? = nil, trustedCert: String = "",
                setDNS: Bool = false, setRoutes: Bool = true, logPath: String) {
        self.profileID = profileID
        self.profileDir = profileDir
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.otp = otp
        self.trustedCert = trustedCert
        self.setDNS = setDNS
        self.setRoutes = setRoutes
        self.logPath = logPath
    }

    enum CodingKeys: String, CodingKey {
        case profileID = "profile_id", profileDir = "profile_dir", host, port, username, password, otp
        case trustedCert = "trusted_cert", setDNS = "set_dns", setRoutes = "set_routes", logPath = "log_path"
    }

    public var description: String {
        "FortiStart(profileID: \(profileID), profileDir: \(profileDir), host: \(host), port: \(port), "
            + "username: \(username), password: <redacted>, otp: \(otp == nil ? "nil" : "<redacted>"), "
            + "trustedCert: \(trustedCert), setDNS: \(setDNS), setRoutes: \(setRoutes), logPath: \(logPath))"
    }
    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: ["profileID": profileID, "profileDir": profileDir, "host": host, "port": port,
                                "username": username, "password": "<redacted>",
                                "otp": otp == nil ? "nil" : "<redacted>", "trustedCert": trustedCert,
                                "setDNS": setDNS, "setRoutes": setRoutes, "logPath": logPath])
    }
}

/// Request sent to the helper. Encoded as a flat JSON object with a `type` discriminator and the
/// sender's protocol version, e.g. `{"profile_id":"acme","protocol_version":2,"type":"stop"}`.
/// Use `jsonData()` / `init(jsonData:)` so both sides agree on the encoder settings; the helper
/// decodes through `HelperCore.decodeRequest`, which also enforces size and version.
public enum HelperRequest: Codable, Equatable {
    case startOpenVPN(OpenVPNStart)
    case startForti(FortiStart)
    case stop(profileID: String)
    case status

    enum Kind: String, Codable {
        case startOpenVPN = "start_openvpn", startForti = "start_forti", stop, status
    }

    private enum TypeKey: String, CodingKey { case type, protocolVersion = "protocol_version" }
    private enum StopKeys: String, CodingKey { case profileID = "profile_id" }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: TypeKey.self)
        switch try c.decode(Kind.self, forKey: .type) {
        case .startOpenVPN: self = .startOpenVPN(try OpenVPNStart(from: decoder))
        case .startForti: self = .startForti(try FortiStart(from: decoder))
        case .stop:
            let s = try decoder.container(keyedBy: StopKeys.self)
            self = .stop(profileID: try s.decode(String.self, forKey: .profileID))
        case .status: self = .status
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: TypeKey.self)
        try c.encode(PT.helperProtocolVersion, forKey: .protocolVersion)
        switch self {
        case .startOpenVPN(let s):
            try c.encode(Kind.startOpenVPN, forKey: .type)
            try s.encode(to: encoder)
        case .startForti(let s):
            try c.encode(Kind.startForti, forKey: .type)
            try s.encode(to: encoder)
        case .stop(let id):
            try c.encode(Kind.stop, forKey: .type)
            var s = encoder.container(keyedBy: StopKeys.self)
            try s.encode(id, forKey: .profileID)
        case .status:
            try c.encode(Kind.status, forKey: .type)
        }
    }

    public func jsonData() throws -> Data { try HelperJSON.encoder.encode(self) }
    public init(jsonData: Data) throws { self = try HelperJSON.decoder.decode(HelperRequest.self, from: jsonData) }
}

/// Reply from the helper. `running` maps profile IDs to pids (only for `status`); `mgmtSocket` is the
/// OpenVPN management socket path (only for `startOpenVPN`).
public struct HelperResponse: Codable, Equatable {
    public var ok: Bool
    public var error: String?
    public var pid: Int32?
    public var running: [String: Int32]?
    public var mgmtSocket: String?

    enum CodingKeys: String, CodingKey { case ok, error, pid, running, mgmtSocket = "mgmt_socket" }

    public init(ok: Bool, error: String? = nil, pid: Int32? = nil, running: [String: Int32]? = nil,
                mgmtSocket: String? = nil) {
        self.ok = ok
        self.error = error
        self.pid = pid
        self.running = running
        self.mgmtSocket = mgmtSocket
    }

    public static func success(pid: Int32? = nil, running: [String: Int32]? = nil,
                               mgmtSocket: String? = nil) -> HelperResponse {
        HelperResponse(ok: true, pid: pid, running: running, mgmtSocket: mgmtSocket)
    }

    public static func failure(_ message: String) -> HelperResponse {
        HelperResponse(ok: false, error: message)
    }

    public func jsonData() throws -> Data { try HelperJSON.encoder.encode(self) }
    public init(jsonData: Data) throws { self = try HelperJSON.decoder.decode(HelperResponse.self, from: jsonData) }
}

enum HelperJSON {
    static var encoder: JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return e
    }
    static var decoder: JSONDecoder { JSONDecoder() }
}
