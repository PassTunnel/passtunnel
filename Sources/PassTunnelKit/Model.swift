import Foundation
import PassTunnelVPNConfig

public enum VPNType: String, Codable, CaseIterable { case openvpn, forti }
public enum PasswordMode: String, Codable, CaseIterable { case keychain, ask, none }  // none = certificate only
public enum OTPMode: String, Codable, CaseIterable { case none, totp, ask }

/// How the one-time code reaches the server.
/// combined → one secret built from `otpTemplate` (e.g. "{password}{otp}")
/// separate → code sent on its own: OpenVPN static-challenge (SCRV1), Forti `otp =` field
public enum OTPDelivery: String, Codable, CaseIterable { case combined, separate }

/// Templates the UI offers; any template containing "{otp}" is valid.
public enum OTPTemplatePreset: String, CaseIterable {
    case append = "{password}{otp}", prepend = "{otp}{password}", colon = "{password}:{otp}", comma = "{password},{otp}"
}

public enum BadgeStyle: String, Codable, CaseIterable { case letter, icon, both }

/// When PassTunnel asks the user to confirm (Touch ID, the Mac password or an Apple Watch) before it
/// uses the profile's stored secrets. Ordered from weakest to strongest.
public enum AuthRequirement: String, Codable, CaseIterable, Comparable {
    case off
    /// Before connecting.
    case connect
    /// Before connecting and before showing, copying or typing the code.
    case always

    private var rank: Int { Self.allCases.firstIndex(of: self) ?? 0 }
    public static func < (a: AuthRequirement, b: AuthRequirement) -> Bool { a.rank < b.rank }
}
public enum TOTPAlgorithm: String, Codable, CaseIterable { case sha1, sha256, sha512 }
public enum CredentialField: String, Codable {
    case username, password, otp

    /// Localized name, e.g. for "This profile asks for: …".
    public var displayName: String {
        switch self {
        case .username: return String(localized: "user name")
        case .password: return String(localized: "password")
        case .otp: return String(localized: "one-time code")
        }
    }
}

/// A secret a profile can have stored (on the Mac, the Keychain item "<profileID>/<kind>").
public enum SecretKind: String, CaseIterable { case password, totp }

public struct TOTPParams: Codable, Equatable {
    public var digits = 6
    public var period = 30
    public var algorithm = TOTPAlgorithm.sha1

    public init(digits: Int = 6, period: Int = 30, algorithm: TOTPAlgorithm = .sha1) {
        self.digits = digits
        self.period = period
        self.algorithm = algorithm
    }

    enum CodingKeys: String, CodingKey { case digits, period, algorithm }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        digits = c.lenient(Int.self, .digits) ?? 6
        period = c.lenient(Int.self, .period) ?? 30
        algorithm = c.lenientEnum(TOTPAlgorithm.self, .algorithm) ?? .sha1
    }
}

public struct Profile: Codable, Identifiable, Equatable {
    public var id: String  // slug, unique, immutable
    public var name: String
    public var type: VPNType
    public var order = 0
    // appearance
    public var badge = ""  // empty → first letter of name
    public var icon = ""  // SF Symbol name
    public var badgeStyle = BadgeStyle.letter
    public var pinned = false
    // authentication
    public var username = ""  // empty → ask each time (remember lastUsername)
    public var lastUsername = ""
    public var passwordMode = PasswordMode.keychain
    public var otpMode = OTPMode.none
    public var totp = TOTPParams()
    /// Confirmation before the stored secrets are used (only matters when `usesStoredSecrets`).
    public var requireAuth = AuthRequirement.off
    // behaviour
    public var sessionLimitMin = 0
    public var autoReconnect = false
    /// Connected when PassTunnel opens at login (the app's login item); a per-user choice, like `pinned`.
    public var connectAtLogin = false
    public var healthHost = ""  // "10.0.0.5" (ICMP) or "host:port" (TCP) or "[v6]:port"
    public var otpDelivery = OTPDelivery.combined
    public var otpTemplate = OTPTemplatePreset.append.rawValue
    // OpenVPN
    public var mgmtPort = 0
    /// File name the configuration was imported from ("acme.ovpn"); nil for older profiles.
    public var configSourceName: String?
    /// When the current configuration was imported; nil for older profiles.
    public var configImportedAt: Date?
    // FortiGate
    public var host = ""
    public var port = 443
    public var trustedCert = ""
    public var setDNS = false
    public var setRoutes = true

    public init(id: String, name: String, type: VPNType) {
        self.id = id
        self.name = name
        self.type = type
    }

    // MARK: derived

    /// Badge text shown in the menu: `badge`, or the first letter of the name.
    public var displayBadge: String {
        let b = badge.trimmingCharacters(in: .whitespacesAndNewlines)
        if !b.isEmpty { return b }
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let first = n.first else { return "?" }
        return String(first).uppercased()
    }

    /// Throws `PTError.usernameTooLong` for a FortiGate user name (trimmed, as it is sent) longer than
    /// openfortivpn keeps: it would cut the name off and the sign-in would fail without a reason.
    public static func checkUsername(_ username: String, type: VPNType) throws {
        guard type == .forti else { return }
        let sent = username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard sent.utf8.count <= FortiConfig.maxUsernameBytes else {
            throw PTError.usernameTooLong(maxBytes: FortiConfig.maxUsernameBytes)
        }
    }

    /// Throws `PTError.invalidField` for a gateway host (`host`) or health-check host (`health_host`)
    /// that is set but not usable: one with a port, a scheme, whitespace or control characters. Both are
    /// checked exactly as stored, because that is what connecting and probing use.
    public func checkHosts() throws {
        if !host.isEmpty, !FortiConfig.isValidHost(host) { throw PTError.invalidField("host") }
        if !healthHost.isEmpty, HealthCheck.parse(healthHost) == nil { throw PTError.invalidField("health_host") }
    }

    /// What must be asked from the user before connecting. Empty for certificate-only profiles.
    public var needs: [CredentialField] {
        if passwordMode == .none { return [] }
        var out: [CredentialField] = []
        if username.trimmingCharacters(in: .whitespaces).isEmpty { out.append(.username) }
        if passwordMode == .ask { out.append(.password) }
        if otpMode == .ask { out.append(.otp) }
        return out
    }

    /// True when the profile can connect without asking anything (required for auto-reconnect).
    public var unattended: Bool { needs.isEmpty }

    /// True when connecting or showing the code uses a secret from the Keychain (a saved password or
    /// a TOTP secret): only then does `requireAuth` matter.
    public var usesStoredSecrets: Bool { passwordMode == .keychain || otpMode == .totp }

    // MARK: coding

    enum CodingKeys: String, CodingKey {
        case id, name, type, order, badge, icon, badgeStyle, pinned
        case username, lastUsername, passwordMode, otpMode, totp, requireAuth
        case sessionLimitMin, autoReconnect, connectAtLogin, healthHost, otpDelivery, otpTemplate
        case mgmtPort, host, port, trustedCert, setRoutes
        case configSourceName, configImportedAt
        case setDNS = "setDns"  // matches "set_dns" under the snake_case strategies
        case otpFormat  // legacy, read only
    }

    /// Keys left out of share files.
    static let shareExcludedKeys: Set<CodingKeys> = [
        .username, .lastUsername, .order, .mgmtPort, .pinned, .configImportedAt,
        .requireAuth, .connectAtLogin
    ]

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = c.lenient(String.self, .id) ?? ""
        name = c.lenient(String.self, .name) ?? ""
        // A type this version does not know (written by a newer one) is not read as OpenVPN: the profile
        // would be shown, and saved, as something it is not (`UnsupportedProfile`).
        if let raw = c.lenient(String.self, .type), VPNType(rawValue: raw) == nil { throw PTError.unsupportedProfileType(raw) }
        type = c.lenientEnum(VPNType.self, .type) ?? .openvpn
        order = c.lenient(Int.self, .order) ?? 0
        badge = c.lenient(String.self, .badge) ?? ""
        icon = c.lenient(String.self, .icon) ?? ""
        badgeStyle = c.lenientEnum(BadgeStyle.self, .badgeStyle) ?? .letter
        pinned = c.lenient(Bool.self, .pinned) ?? false
        username = c.lenient(String.self, .username) ?? ""
        lastUsername = c.lenient(String.self, .lastUsername) ?? ""
        passwordMode = c.lenientEnum(PasswordMode.self, .passwordMode) ?? .keychain
        otpMode = c.lenientEnum(OTPMode.self, .otpMode) ?? .none
        totp = c.lenient(TOTPParams.self, .totp) ?? TOTPParams()
        requireAuth = c.lenientEnum(AuthRequirement.self, .requireAuth) ?? .off
        sessionLimitMin = c.lenient(Int.self, .sessionLimitMin) ?? 0
        autoReconnect = c.lenient(Bool.self, .autoReconnect) ?? false
        connectAtLogin = c.lenient(Bool.self, .connectAtLogin) ?? false
        healthHost = c.lenient(String.self, .healthHost) ?? ""
        mgmtPort = c.lenient(Int.self, .mgmtPort) ?? 0
        host = c.lenient(String.self, .host) ?? ""
        port = c.lenient(Int.self, .port) ?? 443
        trustedCert = c.lenient(String.self, .trustedCert) ?? ""
        setDNS = c.lenient(Bool.self, .setDNS) ?? false
        setRoutes = c.lenient(Bool.self, .setRoutes) ?? true
        configSourceName = c.lenient(String.self, .configSourceName).flatMap { $0.isEmpty ? nil : $0 }
        configImportedAt = c.lenientDate(.configImportedAt)

        let template = c.lenient(String.self, .otpTemplate)
        otpTemplate = (template?.isEmpty == false) ? template! : OTPTemplatePreset.append.rawValue
        if let delivery = c.lenientEnum(OTPDelivery.self, .otpDelivery) {
            otpDelivery = delivery
        } else if let legacy = c.lenient(String.self, .otpFormat) {
            // Files written before otp_delivery existed: scrv1 → separate, append → combined.
            otpDelivery = legacy.lowercased() == "scrv1" ? .separate : .combined
        } else {
            otpDelivery = type == .forti ? .separate : .combined
        }
    }

    public func encode(to encoder: Encoder) throws {
        let forShare = encoder.userInfo[.passTunnelShareExport] as? Bool == true
        var c = encoder.container(keyedBy: CodingKeys.self)
        func put<T: Encodable>(_ value: T, _ key: CodingKeys) throws {
            if forShare && Profile.shareExcludedKeys.contains(key) { return }
            try c.encode(value, forKey: key)
        }
        try put(id, .id); try put(name, .name); try put(type, .type); try put(order, .order)
        try put(badge, .badge); try put(icon, .icon); try put(badgeStyle, .badgeStyle); try put(pinned, .pinned)
        try put(username, .username); try put(lastUsername, .lastUsername)
        try put(passwordMode, .passwordMode); try put(otpMode, .otpMode); try put(totp, .totp)
        try put(requireAuth, .requireAuth)
        try put(sessionLimitMin, .sessionLimitMin); try put(autoReconnect, .autoReconnect)
        try put(connectAtLogin, .connectAtLogin)
        try put(healthHost, .healthHost); try put(otpDelivery, .otpDelivery); try put(otpTemplate, .otpTemplate)
        try put(mgmtPort, .mgmtPort); try put(host, .host); try put(port, .port)
        try put(trustedCert, .trustedCert); try put(setDNS, .setDNS); try put(setRoutes, .setRoutes)
        if let configSourceName { try put(configSourceName, .configSourceName) }
        if let configImportedAt { try put(Profile.dateFormatter.string(from: configImportedAt), .configImportedAt) }
    }

    /// ISO 8601 (UTC) for dates in profile.json.
    static let dateFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()
}

extension CodingUserInfoKey {
    /// When true, `Profile.encode` omits per-user fields (share-file export).
    static let passTunnelShareExport = CodingUserInfoKey(rawValue: "passtunnel.shareExport")!
}

extension KeyedDecodingContainer {
    /// Missing key, null or wrong type → nil instead of an error.
    package func lenient<T: Decodable>(_ type: T.Type, _ key: Key) -> T? {
        (try? decodeIfPresent(type, forKey: key)) ?? nil
    }

    /// ISO 8601 string or seconds since 1970; anything else → nil.
    package func lenientDate(_ key: Key) -> Date? {
        if let text = lenient(String.self, key) { return Profile.dateFormatter.date(from: text) }
        if let seconds = lenient(Double.self, key), seconds.isFinite, seconds > 0 { return Date(timeIntervalSince1970: seconds) }
        return nil
    }

    /// Unknown raw values (e.g. written by a newer version) → nil.
    package func lenientEnum<T: RawRepresentable>(_ type: T.Type, _ key: Key) -> T? where T.RawValue == String {
        lenient(String.self, key).flatMap { T(rawValue: $0) }
    }
}
