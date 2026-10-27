import Foundation
import PassTunnelKit
import PassTunnelVPNConfig

/// A JSON value that keeps booleans, numbers and null apart (unlike `JSONSerialization`).
enum JSON: Equatable, Codable, CustomStringConvertible {
    case null, bool(Bool), number(Double), string(String), array([JSON]), object([String: JSON])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let n = try? c.decode(Double.self) {
            self = .number(n)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([JSON].self) {
            self = .array(a)
        } else {
            self = .object(try c.decode([String: JSON].self))
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .number(let n): try c.encode(n)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }

    var description: String {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return (try? e.encode(self)).map { String(decoding: $0, as: UTF8.self) } ?? "?"
    }

    var string: String? { if case .string(let s) = self { return s }; return nil }
    var int: Int? { if case .number(let n) = self, n.rounded() == n { return Int(exactly: n) }; return nil }
    var double: Double? { if case .number(let n) = self { return n }; return nil }
    var object: [String: JSON]? { if case .object(let o) = self { return o }; return nil }
    var array: [JSON]? { if case .array(let a) = self { return a }; return nil }

    /// Parses JSON text (Foundation's parser) into a `JSON`.
    static func parse(_ data: Data) throws -> JSON { try JSONDecoder().decode(JSON.self, from: data) }

    /// Serializes for Foundation APIs that take JSON data.
    func data() throws -> Data { try JSONEncoder().encode(self) }
}

struct FixtureError: Error, CustomStringConvertible {
    var description: String
    init(_ d: String) { description = d }
}

/// Runs one case of a fixture group: the inputs are the case's keys listed in `inputs`, the result is
/// every output key the case must state (all other keys but `name` and `note`).
enum FixtureRunner {
    struct Group {
        let inputs: Set<String>
        let run: ([String: JSON]) throws -> [String: JSON]
    }

    /// file name → group name → how to run it.
    static let groups: [String: [String: Group]] = [
        "totp.json": [
            "code": Group(inputs: ["secret_hex", "digits", "period", "algorithm", "time"], run: totpCode),
            "remaining": Group(inputs: ["period", "time"], run: totpRemaining),
            "decode_secret": Group(inputs: ["input"], run: decodeSecret),
            "base32_encode": Group(inputs: ["hex"], run: base32Encode)
        ],
        "otpauth.json": [
            "parse": Group(inputs: ["uri"], run: otpauth)
        ],
        "codes.json": [
            "presets": Group(inputs: ["preset"], run: preset),
            "validate_template": Group(inputs: ["template"], run: validateTemplate),
            "compose": Group(inputs: ["password", "otp", "delivery", "template", "type"], run: compose)
        ],
        "ovpn-sanitizer.json": [
            "tokens": Group(inputs: ["line"], run: tokens),
            "sanitize": Group(inputs: ["config"], run: sanitize),
            "verbosity": Group(inputs: ["config"], run: verbosity)
        ],
        "ovpn-analyzer.json": [
            "analyze": Group(inputs: ["config"], run: analyze)
        ],
        "ovpn-inliner.json": [
            "inline": Group(inputs: ["config", "files", "binary_files"], run: { try inline($0, prepare: false) }),
            "prepare": Group(inputs: ["config", "files", "binary_files"], run: { try inline($0, prepare: true) }),
            "strip_credentials": Group(inputs: ["config", "blocks"], run: stripCredentials)
        ],
        "ovpn-import.json": [
            "review": Group(inputs: ["config", "files", "binary_files"], run: review)
        ],
        "share-files.json": [
            "decode": Group(inputs: ["file"], run: shareDecode),
            "encode": Group(inputs: ["profile", "files"], run: shareEncode)
        ],
        "slugs.json": [
            "make": Group(inputs: ["profile_name", "max_length"], run: slugMake),
            "suffixed": Group(inputs: ["base", "n"], run: slugSuffixed),
            "is_valid": Group(inputs: ["id"], run: slugValid)
        ],
        "profile-merge.json": [
            "merge": Group(inputs: ["original", "edited", "current"], run: merge)
        ],
        "profile-fields.json": [
            "set": Group(inputs: ["type", "key", "value"], run: fieldsSet)
        ]
    ]

    // MARK: inputs

    static func str(_ c: [String: JSON], _ key: String) throws -> String {
        guard let s = c[key]?.string else { throw FixtureError("\(key) must be a string") }
        return s
    }

    static func int(_ c: [String: JSON], _ key: String) throws -> Int {
        guard let n = c[key]?.int else { throw FixtureError("\(key) must be an integer") }
        return n
    }

    static func optionalString(_ c: [String: JSON], _ key: String) throws -> String? {
        switch c[key] {
        case nil, .null?: return nil
        case .string(let s)?: return s
        default: throw FixtureError("\(key) must be a string or null")
        }
    }

    static func hexData(_ s: String) throws -> Data {
        let bytes = Array(s.utf8)
        guard bytes.count % 2 == 0 else { throw FixtureError("odd-length hex \(s)") }
        var out = Data()
        var i = 0
        while i < bytes.count {
            guard let b = UInt8(String(decoding: bytes[i..<(i + 2)], as: UTF8.self), radix: 16) else {
                throw FixtureError("bad hex \(s)")
            }
            out.append(b)
            i += 2
        }
        return out
    }

    static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    static func profile(_ value: JSON?) throws -> Profile {
        guard let value else { throw FixtureError("missing profile") }
        return try JSONCoding.decoder().decode(Profile.self, from: try value.data())
    }

    static func encoded(_ p: Profile) throws -> JSON { try JSON.parse(try JSONCoding.encode(p)) }

    // MARK: outputs

    static func error(_ e: Error) -> [String: JSON] {
        guard let pt = e as? PTError else { return ["error": .object(["kind": .string("other: \(e)")])] }
        func kind(_ k: String, _ detail: String? = nil) -> [String: JSON] {
            var o: [String: JSON] = ["kind": .string(k)]
            if let detail { o["detail"] = .string(detail) }
            return ["error": .object(o)]
        }
        switch pt {
        case .invalidSecret: return kind("invalid_secret")
        case .invalidOTPAuthURI(let reason): return kind("invalid_otpauth_uri", reason)
        case .hotpNotSupported: return kind("hotp_not_supported")
        case .invalidTemplate(let reason): return kind("invalid_template", reason)
        case .unsupportedShareFile: return kind("unsupported_share_file")
        case .ovpnReferencedFile(let path): return kind("ovpn_referenced_file", path)
        case .fileTooLarge(let name): return kind("file_too_large", name)
        case .invalidFile(let name): return kind("invalid_file", name)
        case .invalidField(let field): return kind("invalid_field", field)
        case .emptyName: return kind("empty_name")
        case .wrongProfileType(let id): return kind("wrong_profile_type", id)
        case .ovpnNotAllowed(let violations):
            return ["error": .object(["kind": .string("ovpn_not_allowed"), "violations": .array(violations.map { .string($0) })])]
        default: return kind("other: \(pt)")
        }
    }

    static func optional(_ s: String?) -> JSON { s.map { .string($0) } ?? .null }

    // MARK: TOTP

    static func totpParams(_ c: [String: JSON]) throws -> TOTPParams {
        guard let algorithm = TOTPAlgorithm(rawValue: try str(c, "algorithm")) else { throw FixtureError("algorithm") }
        return TOTPParams(digits: try int(c, "digits"), period: try int(c, "period"), algorithm: algorithm)
    }

    static func time(_ c: [String: JSON]) throws -> Date {
        guard let t = c["time"]?.double else { throw FixtureError("time must be a number") }
        return Date(timeIntervalSince1970: t)
    }

    static func totpCode(_ c: [String: JSON]) throws -> [String: JSON] {
        let code = TOTP.code(secret: try hexData(try str(c, "secret_hex")), params: try totpParams(c), at: try time(c))
        return ["code": .string(code)]
    }

    static func totpRemaining(_ c: [String: JSON]) throws -> [String: JSON] {
        let left = TOTP.remaining(params: TOTPParams(period: try int(c, "period")), at: try time(c))
        return ["remaining": .number(Double(left))]
    }

    static func decodeSecret(_ c: [String: JSON]) throws -> [String: JSON] {
        do { return ["hex": .string(hex(try TOTP.decodeSecret(try str(c, "input"))))] } catch { return Self.error(error) }
    }

    static func base32Encode(_ c: [String: JSON]) throws -> [String: JSON] {
        ["base32": .string(TOTP.base32Encode(try hexData(try str(c, "hex"))))]
    }

    // MARK: otpauth

    static func otpauth(_ c: [String: JSON]) throws -> [String: JSON] {
        do {
            let u = try OTPAuthURI(try str(c, "uri"))
            return [
                "label": .string(u.label), "account": .string(u.account), "issuer": .string(u.issuer),
                "secret_hex": .string(hex(u.secret)), "digits": .number(Double(u.params.digits)),
                "period": .number(Double(u.params.period)), "algorithm": .string(u.params.algorithm.rawValue)
            ]
        } catch {
            return Self.error(error)
        }
    }

    // MARK: codes

    static func preset(_ c: [String: JSON]) throws -> [String: JSON] {
        let name = try str(c, "preset")
        guard let p = OTPTemplatePreset.allCases.first(where: { "\($0)" == name }) else { throw FixtureError("preset \(name)") }
        return ["template": .string(p.rawValue)]
    }

    static func validateTemplate(_ c: [String: JSON]) throws -> [String: JSON] {
        do {
            try OTPComposer.validate(template: try str(c, "template"))
            return ["valid": .bool(true)]
        } catch {
            return Self.error(error)
        }
    }

    static func compose(_ c: [String: JSON]) throws -> [String: JSON] {
        guard let delivery = OTPDelivery(rawValue: try str(c, "delivery")),
            let type = VPNType(rawValue: try str(c, "type"))
        else { throw FixtureError("delivery or type") }
        let r = OTPComposer.compose(
            password: try str(c, "password"), otp: try optionalString(c, "otp"),
            delivery: delivery, template: try str(c, "template"), type: type)
        return ["secret": .string(r.secret), "separate_otp": optional(r.separateOTP)]
    }

    // MARK: OpenVPN

    static func tokens(_ c: [String: JSON]) throws -> [String: JSON] {
        guard let t = OVPNSanitizer.tokens(of: try str(c, "line")) else { return ["tokens": .null] }
        return ["tokens": .array(t.map { .string($0) })]
    }

    static func sanitize(_ c: [String: JSON]) throws -> [String: JSON] {
        do {
            return ["output": .string(try OVPNSanitizer.sanitize(try str(c, "config")))]
        } catch let f as OVPNSanitizer.Failure {
            return [
                "violations": .array(
                    f.violations.map {
                        .object(["line": .number(Double($0.line)), "directive": .string($0.directive), "reason": .string($0.reason)])
                    })
            ]
        }
    }

    static func verbosity(_ c: [String: JSON]) throws -> [String: JSON] {
        ["verb": OVPNSanitizer.verbosity(of: try str(c, "config")).map { .number(Double($0)) } ?? .null]
    }

    static func analyze(_ c: [String: JSON]) throws -> [String: JSON] {
        let text = try str(c, "config")
        let a = OVPNAnalyzer.analyze(text)
        return [
            "password_mode": .string(a.passwordMode.rawValue), "otp_mode": .string(a.otpMode.rawValue),
            "otp_delivery": .string(a.otpDelivery.rawValue), "remote": .string(a.remote),
            "remotes": .array(a.remotes.map { .string($0) }),
            "server_description": .string(OVPNAnalyzer.serverDescription(text)),
            "redirects_gateway": OVPNAnalyzer.redirectsGateway(text).map { .bool($0) } ?? .null
        ]
    }

    /// The referenced files are written to a fresh temporary folder: `config/` is the config's folder,
    /// so "../x" names a file next to it.
    static func inline(_ c: [String: JSON], prepare: Bool) throws -> [String: JSON] {
        try withConfigFolder(c) { base in
            let text = try str(c, "config")
            let out = prepare ? try OVPNInliner.prepare(text, baseDir: base) : try OVPNInliner.inline(text, baseDir: base)
            return ["output": .string(out)]
        }
    }

    /// `OVPNImportReport.make` with the files in a temporary folder, as `inline`.
    static func review(_ c: [String: JSON]) throws -> [String: JSON] {
        try withConfigFolder(c) { base in
            let r = try OVPNImportReport.make(try str(c, "config"), baseDir: base)
            func line(_ number: Int, _ directive: String, _ text: String, _ reason: String) -> JSON {
                .object([
                    "line": .number(Double(number)), "directive": .string(directive), "text": .string(text),
                    "reason": .string(reason)
                ])
            }
            return [
                "stored": optional(r.config),
                "skipped": .array(r.skipped.map { line($0.line, $0.directive, $0.text, $0.reason.rawValue) }),
                "blocking": .array(r.blocking.map { line($0.line, $0.directive, $0.text, $0.reason) }),
                "servers": .array(
                    r.servers.map {
                        .object(["host": .string($0.host), "port": .string($0.port), "tcp": .bool($0.tcp)])
                    }),
                "certificates": .array(r.certificates.map { .object(["name": .string($0.name), "file": optional($0.file)]) }),
                "password_mode": .string(r.passwordMode.rawValue), "otp_mode": .string(r.otpMode.rawValue),
                "otp_delivery": .string(r.otpDelivery.rawValue),
                "username": optional(r.username), "password": optional(r.password),
                "needs": .array(r.needs.map { .string($0.rawValue) })
            ]
        }
    }

    /// Writes `files` and `binary_files` into `config/` of a fresh temporary folder and runs `body` with it;
    /// a `PTError` it throws is the case's `error`.
    static func withConfigFolder(_ c: [String: JSON], _ body: (URL) throws -> [String: JSON]) throws -> [String: JSON] {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("passtunnel-fixtures-\(UUID().uuidString)")
        let base = root.appendingPathComponent("config", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        func write(_ files: JSON?, decode: (String) throws -> Data) throws {
            for (path, value) in files?.object ?? [:] {
                guard let text = value.string, !path.hasPrefix("/") else { throw FixtureError("file \(path)") }
                let url = base.appendingPathComponent(path).standardizedFileURL
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                try decode(text).write(to: url)
            }
        }
        try write(c["files"]) { Data($0.utf8) }
        try write(c["binary_files"]) {
            guard let d = Data(base64Encoded: $0) else { throw FixtureError("base64") }
            return d
        }
        do {
            return try body(base)
        } catch let e as PTError {
            return error(e)
        }
    }

    static func stripCredentials(_ c: [String: JSON]) throws -> [String: JSON] {
        var blocks = Set(OVPNInliner.CredentialBlock.allCases)
        if let names = c["blocks"]?.array {
            blocks = Set(
                try names.map {
                    guard let b = $0.string.flatMap(OVPNInliner.CredentialBlock.init(rawValue:)) else { throw FixtureError("block") }
                    return b
                })
        }
        let r = OVPNInliner.strippingCredentials(try str(c, "config"), blocks: blocks)
        return [
            "output": .string(r.text), "username": optional(r.username), "password": optional(r.password),
            "removed": .array(r.removed.map(\.rawValue).sorted().map { .string($0) })
        ]
    }

    // MARK: share files

    static func shareDecode(_ c: [String: JSON]) throws -> [String: JSON] {
        let data: Data
        switch c["file"] {
        case .string(let text)?: data = Data(text.utf8)
        case let value?: data = try value.data()
        case nil: throw FixtureError("file")
        }
        do {
            let share = try ShareFile.decode(data)
            var files: [String: JSON] = [:]
            for (name, content) in share.files {
                guard let text = String(data: content, encoding: .utf8) else { throw FixtureError("\(name) is not UTF-8") }
                files[name] = .string(text)
            }
            return ["profile": try encoded(share.profile), "files": .object(files)]
        } catch let e as PTError {
            return error(e)
        }
    }

    static func shareEncode(_ c: [String: JSON]) throws -> [String: JSON] {
        var files: [String: Data] = [:]
        for (name, value) in c["files"]?.object ?? [:] {
            guard let text = value.string else { throw FixtureError("file \(name)") }
            files[name] = Data(text.utf8)
        }
        let data = try ShareFile(profile: try profile(c["profile"]), files: files).data()
        return ["file": try JSON.parse(data)]
    }

    // MARK: slugs

    static func slugMake(_ c: [String: JSON]) throws -> [String: JSON] {
        let name = try str(c, "profile_name")
        let id = c["max_length"] == nil ? Slug.make(name) : Slug.make(name, maxLength: try int(c, "max_length"))
        return ["id": .string(id)]
    }

    static func slugSuffixed(_ c: [String: JSON]) throws -> [String: JSON] {
        ["id": .string(Slug.suffixed(try str(c, "base"), try int(c, "n")))]
    }

    static func slugValid(_ c: [String: JSON]) throws -> [String: JSON] {
        ["valid": .bool(Slug.isValid(try str(c, "id")))]
    }

    // MARK: profiles

    static func merge(_ c: [String: JSON]) throws -> [String: JSON] {
        let original = try profile(c["original"]), edited = try profile(c["edited"])
        let merged = try ProfileMerge.merge(original: original, edited: edited, current: try profile(c["current"]))
        return [
            "merged": try encoded(merged),
            "changed_fields": .array(try ProfileMerge.changedFields(from: original, to: edited).map { .string($0) })
        ]
    }

    static func fieldsSet(_ c: [String: JSON]) throws -> [String: JSON] {
        guard let type = VPNType(rawValue: try str(c, "type")) else { throw FixtureError("type") }
        var p = Profile(id: "acme", name: "Acme", type: type)
        let key = try str(c, "key")
        do {
            try ProfileFields.set(&p, key: key, value: try str(c, "value"))
        } catch {
            return Self.error(error)
        }
        guard let canonical = ProfileFields.canonicalKey(key) else { throw FixtureError("key \(key)") }
        return ["canonical_key": .string(canonical), "stored": .string(ProfileFields.value(p, key: canonical))]
    }
}
