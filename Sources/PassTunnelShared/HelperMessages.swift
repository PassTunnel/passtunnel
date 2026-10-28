import Foundation
import PassTunnelVPNConfig

/// Start an OpenVPN profile. `secret` is the password with the OTP already formatted in.
/// The management interface is the unix socket `PT.mgmtSocketPath(uid:profileID:)` in the helper's
/// root-owned session directory (returned in `HelperResponse.mgmtSocket`); `mgmtPort` is ignored and
/// only kept so protocol-1 payloads decode. `configSHA256` is the hex SHA-256 of the exact config.ovpn
/// the app checked (`ProfileDestination`): the helper refuses to start any other file
/// (`HelperResponse.ErrorCode.configChanged`). Optional, so requests of older apps still decode.
public struct OpenVPNStart: Codable, Equatable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    public var profileID: String
    public var profileDir: String
    public var mgmtPort: Int?
    public var username: String?
    public var secret: String?
    public var logPath: String
    public var configSHA256: String?

    public init(
        profileID: String, profileDir: String, mgmtPort: Int? = nil,
        username: String? = nil, secret: String? = nil, logPath: String, configSHA256: String? = nil
    ) {
        self.profileID = profileID
        self.profileDir = profileDir
        self.mgmtPort = mgmtPort
        self.username = username
        self.secret = secret
        self.logPath = logPath
        self.configSHA256 = configSHA256
    }

    enum CodingKeys: String, CodingKey {
        case profileID = "profile_id", profileDir = "profile_dir", mgmtPort = "mgmt_port"
        case username, secret, logPath = "log_path", configSHA256 = "config_sha256"
    }

    public var description: String {
        "OpenVPNStart(profileID: \(profileID), profileDir: \(profileDir), "
            + "username: \(username ?? "nil"), secret: \(secret == nil ? "nil" : "<redacted>"), logPath: \(logPath), "
            + "configSHA256: \(configSHA256 ?? "nil"))"
    }
    public var debugDescription: String { description }

    /// Keeps `dump()` and other Mirror-based printing from revealing the secret.
    public var customMirror: Mirror {
        Mirror(
            self,
            children: [
                "profileID": profileID, "profileDir": profileDir, "username": username as Any,
                "secret": secret == nil ? "nil" : "<redacted>", "logPath": logPath,
                "configSHA256": configSHA256 as Any
            ])
    }
}

/// Start a FortiGate SSL VPN profile through openfortivpn.
public struct FortiStart: Codable, Equatable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
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

    public init(
        profileID: String, profileDir: String, host: String, port: Int = 443,
        username: String, password: String, otp: String? = nil, trustedCert: String = "",
        setDNS: Bool = false, setRoutes: Bool = true, logPath: String
    ) {
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
        Mirror(
            self,
            children: [
                "profileID": profileID, "profileDir": profileDir, "host": host, "port": port,
                "username": username, "password": "<redacted>",
                "otp": otp == nil ? "nil" : "<redacted>", "trustedCert": trustedCert,
                "setDNS": setDNS, "setRoutes": setRoutes, "logPath": logPath
            ])
    }
}

extension FortiConfig {
    public init(_ start: FortiStart) {
        self.init(
            host: start.host, port: start.port, username: start.username, password: start.password,
            otp: start.otp, trustedCert: start.trustedCert, setDNS: start.setDNS, setRoutes: start.setRoutes)
    }
}

/// Start a Cisco AnyConnect profile through openconnect (protocol 4). The user's own `openconnect
/// --authenticate` run signed in; this carries what it returned (`OpenConnectAuthResult`) and the profile's
/// own fields, from which the helper renders `<run>/openconnect.conf` (docs/ARCHITECTURE.md, "Helper
/// protocol 4"). The helper trusts none of it: every field is checked again
/// (`HelperCore.prepareOpenConnect`). `connectURL`, `resolve` and `serverCert` are the sign-in's
/// `CONNECT_URL`, `RESOLVE` (nil for an IP-address host) and `FINGERPRINT`; `profileServerCert` is the
/// profile's own pin (normalized) or empty. `usergroup` is the profile's, checked but not used: the tunnel
/// run connects without it. `cookie` is a bearer secret, and the server chose `connectURL`, `resolve` and
/// `serverCert`, so it could have repeated the cookie in them: no description or mirror shows any of the
/// four.
public struct OpenConnectStart: Codable, Equatable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    public var profileID: String
    public var profileDir: String
    public var logPath: String
    public var host: String
    public var port: Int
    public var usergroup: String
    public var connectURL: String
    public var resolve: String?
    public var cookie: String
    public var serverCert: String
    public var profileServerCert: String
    public var tlsOnly: Bool
    public var setDNS: Bool
    public var setRoutes: Bool

    public init(
        profileID: String, profileDir: String, logPath: String, host: String, port: Int = 443, usergroup: String = "",
        connectURL: String, resolve: String?, cookie: String, serverCert: String, profileServerCert: String = "",
        tlsOnly: Bool = false, setDNS: Bool = false, setRoutes: Bool = true
    ) {
        self.profileID = profileID
        self.profileDir = profileDir
        self.logPath = logPath
        self.host = host
        self.port = port
        self.usergroup = usergroup
        self.connectURL = connectURL
        self.resolve = resolve
        self.cookie = cookie
        self.serverCert = serverCert
        self.profileServerCert = profileServerCert
        self.tlsOnly = tlsOnly
        self.setDNS = setDNS
        self.setRoutes = setRoutes
    }

    enum CodingKeys: String, CodingKey {
        case profileID = "profile_id", profileDir = "profile_dir", logPath = "log_path", host, port, usergroup
        case connectURL = "connect_url", resolve, cookie, serverCert = "server_cert"
        case profileServerCert = "profile_server_cert", tlsOnly = "tls_only", setDNS = "set_dns", setRoutes = "set_routes"
    }

    public var description: String {
        "OpenConnectStart(profileID: \(profileID), profileDir: \(profileDir), logPath: \(logPath), host: \(host), "
            + "port: \(port), usergroup: \(usergroup), connectURL: <redacted>, resolve: \(resolve == nil ? "nil" : "<redacted>"), "
            + "cookie: <redacted>, serverCert: <redacted>, profileServerCert: \(profileServerCert.isEmpty ? "<none>" : profileServerCert), "
            + "tlsOnly: \(tlsOnly), setDNS: \(setDNS), setRoutes: \(setRoutes))"
    }
    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(
            self,
            children: [
                "profileID": profileID, "profileDir": profileDir, "logPath": logPath, "host": host, "port": port,
                "usergroup": usergroup, "connectURL": "<redacted>", "resolve": resolve == nil ? "nil" : "<redacted>",
                "cookie": "<redacted>", "serverCert": "<redacted>",
                "profileServerCert": profileServerCert.isEmpty ? "<none>" : profileServerCert,
                "tlsOnly": tlsOnly, "setDNS": setDNS, "setRoutes": setRoutes
            ])
    }
}

/// Request sent to the helper. Encoded as a flat JSON object with a `type` discriminator and the
/// sender's protocol version, e.g. `{"profile_id":"acme","protocol_version":4,"type":"stop"}`.
/// Use `jsonData()` / `init(jsonData:)` so both sides agree on the encoder settings; the helper
/// decodes through `HelperCore.decodeRequest`, which also enforces size and version.
public enum HelperRequest: Codable, Equatable {
    case startOpenVPN(OpenVPNStart)
    case startForti(FortiStart)
    /// Protocol 4. The Linux daemon refuses it until it runs openconnect (#187).
    case startOpenConnect(OpenConnectStart)
    case stop(profileID: String)
    case status

    enum Kind: String, Codable {
        case startOpenVPN = "start_openvpn", startForti = "start_forti", startOpenConnect = "start_openconnect", stop, status
    }

    private enum TypeKey: String, CodingKey { case type, protocolVersion = "protocol_version" }
    private enum StopKeys: String, CodingKey { case profileID = "profile_id" }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: TypeKey.self)
        switch try c.decode(Kind.self, forKey: .type) {
        case .startOpenVPN: self = .startOpenVPN(try OpenVPNStart(from: decoder))
        case .startForti: self = .startForti(try FortiStart(from: decoder))
        case .startOpenConnect: self = .startOpenConnect(try OpenConnectStart(from: decoder))
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
        case .startOpenConnect(let s):
            try c.encode(Kind.startOpenConnect, forKey: .type)
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

/// Reply from the helper. `running` maps the caller's profile IDs to pids and `mgmtSockets` maps
/// its OpenVPN profile IDs to their management sockets (only for `status`); `mgmtSocket` is the
/// socket of a just-started OpenVPN (only for `startOpenVPN`). `helperBuild` is the build number
/// (`CFBundleVersion`) of the app the answering helper was started from, in every reply; helpers
/// before it was added omit it (an optional key, so the protocol version stays the same).
/// `errorCode` names failures the app handles specially (`ErrorCode`); also optional.
/// The network of an openconnect session as its hook recorded it (`HelperCore.tunnelStatus`): in the
/// `status` reply, the only source a client takes "connected" and "the set-up failed" from. Protocol 4
/// (no released helper speaks it yet), an optional key: a reply without it is read as before.
public struct TunnelStatus: Codable, Equatable, Sendable {
    public enum State: String, Codable, Sendable {
        /// openconnect runs, the hook has not reported yet.
        case settingUp = "setting_up"
        case up
        /// openconnect re-establishes the connection; up again after the hook verified the network.
        case reconnecting
        /// The hook's set-up failed; it reverted it, and the session is being stopped.
        case failed
        /// The record could not be read right now (the hook is writing it).
        case unknown
    }

    public var state: State
    /// failed: the hook's reason (printable ASCII, names variables and rules, never values).
    public var reason: String?
    /// The tunnel interface the hook set up ("utun5").
    public var interface: String?

    public init(state: State, reason: String? = nil, interface: String? = nil) {
        self.state = state
        self.reason = reason
        self.interface = interface
    }

    /// up or reconnecting: the network was set up and is held.
    public var isUp: Bool { state == .up || state == .reconnecting }
}

public struct HelperResponse: Codable, Equatable {
    public var ok: Bool
    public var error: String?
    public var errorCode: String?
    public var pid: Int32?
    public var running: [String: Int32]?
    public var mgmtSocket: String?
    public var mgmtSockets: [String: String]?
    public var helperBuild: Int?
    /// `status`: profile ID → the network of the caller's own openconnect sessions (`TunnelStatus`).
    public var tunnels: [String: TunnelStatus]?

    public enum ErrorCode {
        /// config.ovpn is not the file the app checked (`OpenVPNStart.configSHA256`). Not retryable:
        /// the user confirms the new settings by connecting again.
        public static let configChanged = "config_changed"
    }

    enum CodingKeys: String, CodingKey {
        case ok, error, errorCode = "error_code", pid, running, mgmtSocket = "mgmt_socket", mgmtSockets = "mgmt_sockets"
        case helperBuild = "helper_build", tunnels
    }

    public init(
        ok: Bool, error: String? = nil, pid: Int32? = nil, running: [String: Int32]? = nil,
        mgmtSocket: String? = nil, mgmtSockets: [String: String]? = nil
    ) {
        self.ok = ok
        self.error = error
        self.pid = pid
        self.running = running
        self.mgmtSocket = mgmtSocket
        self.mgmtSockets = mgmtSockets
    }

    public static func success(
        pid: Int32? = nil, running: [String: Int32]? = nil,
        mgmtSocket: String? = nil, mgmtSockets: [String: String]? = nil, tunnels: [String: TunnelStatus]? = nil
    ) -> HelperResponse {
        var response = HelperResponse(ok: true, pid: pid, running: running, mgmtSocket: mgmtSocket, mgmtSockets: mgmtSockets)
        response.tunnels = tunnels
        return response
    }

    public static func failure(_ message: String, code: String? = nil) -> HelperResponse {
        var response = HelperResponse(ok: false, error: message)
        response.errorCode = code
        return response
    }

    /// A failed start, with the `ErrorCode` of errors the app handles specially.
    public static func failure(_ error: Error) -> HelperResponse {
        failure(String(describing: error), code: (error as? HelperCore.Failure)?.code)
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
