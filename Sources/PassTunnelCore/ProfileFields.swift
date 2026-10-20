import Foundation

/// Text access to the editable profile fields, keyed like the JSON file (`passtunnel set ID key=value`,
/// `passtunnel show ID`).
public enum ProfileFields {
    /// Settable keys in editor order. Aliases are accepted by `set` (see `canonicalKey`).
    public static let keys = [
        "name", "badge", "icon", "badge_style", "pinned", "order",
        "username", "password_mode", "otp_mode", "digits", "period", "algorithm", "otp_delivery", "otp_template",
        "session_limit_min", "auto_reconnect", "health_host",
        "host", "port", "trusted_cert", "set_dns", "set_routes",
    ]

    static let fortiOnly: Set<String> = ["host", "port", "trusted_cert", "set_dns", "set_routes"]

    static let aliases = [
        "totp.digits": "digits", "totp_digits": "digits", "totp.period": "period", "totp_period": "period",
        "totp.algorithm": "algorithm", "totp_algorithm": "algorithm", "session_limit": "session_limit_min",
        "badge_letter": "badge", "user": "username", "template": "otp_template", "delivery": "otp_delivery",
        "dns": "set_dns", "routes": "set_routes", "health": "health_host", "cert": "trusted_cert",
    ]

    /// Lowercased, dashes → underscores, aliases resolved; nil for unknown keys.
    public static func canonicalKey(_ key: String) -> String? {
        let k = key.lowercased().replacingOccurrences(of: "-", with: "_")
        let resolved = aliases[k] ?? k
        return keys.contains(resolved) ? resolved : nil
    }

    /// Keys that apply to a profile of `type`.
    public static func keys(for type: VPNType) -> [String] {
        type == .forti ? keys : keys.filter { !fortiOnly.contains($0) }
    }

    /// Sets one field from text. Throws `PTError.invalidField(key)` for unknown keys or bad values and
    /// `.wrongProfileType` for FortiGate-only keys on an OpenVPN profile. Range checks that need the
    /// whole profile happen in `ProfileStore.save`.
    public static func set(_ p: inout Profile, key rawKey: String, value raw: String) throws {
        guard let key = canonicalKey(rawKey) else { throw PTError.invalidField(rawKey) }
        if fortiOnly.contains(key) && p.type != .forti { throw PTError.wrongProfileType(p.id) }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        func bad() -> PTError { .invalidField(key) }
        func int() throws -> Int { guard let v = Int(value) else { throw bad() }; return v }
        func bool() throws -> Bool { guard let v = parseBool(value) else { throw bad() }; return v }
        func choice<E: RawRepresentable>(_: E.Type) throws -> E where E.RawValue == String {
            guard let v = E(rawValue: value.lowercased()) else { throw bad() }
            return v
        }

        switch key {
        case "name":
            guard !value.isEmpty else { throw PTError.emptyName }
            p.name = value
        case "badge": p.badge = value
        case "icon": p.icon = value
        case "badge_style": p.badgeStyle = try choice(BadgeStyle.self)
        case "pinned": p.pinned = try bool()
        case "order": p.order = try int()
        case "username": p.username = value
        case "password_mode":
            let mode = try choice(PasswordMode.self)
            if mode == .none && p.type != .openvpn { throw bad() }
            p.passwordMode = mode
        case "otp_mode": p.otpMode = try choice(OTPMode.self)
        case "digits":
            let v = try int()
            guard (6...8).contains(v) else { throw bad() }
            p.totp.digits = v
        case "period":
            let v = try int()
            guard (1...600).contains(v) else { throw bad() }
            p.totp.period = v
        case "algorithm":
            guard let v = TOTPAlgorithm(rawValue: value.lowercased().replacingOccurrences(of: "-", with: "")) else { throw bad() }
            p.totp.algorithm = v
        case "otp_delivery": p.otpDelivery = try choice(OTPDelivery.self)
        case "otp_template":
            let preset = OTPTemplatePreset.allCases.first { "\($0)" == value.lowercased() }
            let template = preset?.rawValue ?? raw
            try OTPComposer.validate(template: template)
            p.otpTemplate = template
        case "session_limit_min":
            let v = try int()
            guard v >= 0 else { throw bad() }
            p.sessionLimitMin = v
        case "auto_reconnect": p.autoReconnect = try bool()
        case "health_host":
            guard value.isEmpty || HealthCheck.parse(value) != nil else { throw bad() }
            p.healthHost = value
        case "host": p.host = value
        case "port":
            let v = try int()
            guard (1...65535).contains(v) else { throw bad() }
            p.port = v
        case "trusted_cert": p.trustedCert = value
        case "set_dns": p.setDNS = try bool()
        case "set_routes": p.setRoutes = try bool()
        default: throw bad()
        }
    }

    /// Current value of a canonical key as text (as `set` accepts it).
    public static func value(_ p: Profile, key: String) -> String {
        switch key {
        case "name": return p.name
        case "badge": return p.badge
        case "icon": return p.icon
        case "badge_style": return p.badgeStyle.rawValue
        case "pinned": return String(p.pinned)
        case "order": return String(p.order)
        case "username": return p.username
        case "password_mode": return p.passwordMode.rawValue
        case "otp_mode": return p.otpMode.rawValue
        case "digits": return String(p.totp.digits)
        case "period": return String(p.totp.period)
        case "algorithm": return p.totp.algorithm.rawValue
        case "otp_delivery": return p.otpDelivery.rawValue
        case "otp_template": return p.otpTemplate
        case "session_limit_min": return String(p.sessionLimitMin)
        case "auto_reconnect": return String(p.autoReconnect)
        case "health_host": return p.healthHost
        case "host": return p.host
        case "port": return String(p.port)
        case "trusted_cert": return p.trustedCert
        case "set_dns": return String(p.setDNS)
        case "set_routes": return String(p.setRoutes)
        default: return ""
        }
    }

    public static func parseBool(_ s: String) -> Bool? {
        switch s.lowercased() {
        case "true", "yes", "on", "1", "y": return true
        case "false", "no", "off", "0", "n": return false
        default: return nil
        }
    }
}
