import Foundation
import PassTunnelVPNConfig

/// What an .ovpn file holds and what importing it would store, for the review before the profile is
/// added. Made from the file's text and the files it refers to; nothing is written.
public struct OVPNImportReport: Equatable {
    /// The configuration to store: referenced files embedded, skipped lines left as comments
    /// (`OVPNSkipRules`), an inline `<auth-user-pass>` block removed. nil when a line blocks the import.
    public var config: String?
    /// Lines left out, numbered as in the file.
    public var skipped: [OVPNSkipRules.Skipped]
    /// Lines that refuse the file, numbered as in the file (a line of an embedded file counts as the line
    /// that referred to it). Empty when the file can be imported.
    public var blocking: [OVPNSkipRules.Blocking]
    /// Every `remote`, in file order.
    public var servers: [OVPNAnalyzer.Server]
    public var certificates: [Certificate]
    public var passwordMode: PasswordMode
    public var otpMode: OTPMode
    public var otpDelivery: OTPDelivery
    /// From an inline `<auth-user-pass>` block, which is never stored with the configuration.
    public var username: String?
    public var password: String?

    /// Something that identifies the server or this client, found in the configuration.
    public struct Certificate: Equatable, Sendable {
        /// The directive: "ca", "cert", "key", "pkcs12", "extra-certs", "tls-auth", "tls-crypt",
        /// "tls-crypt-v2", "secret", "crl-verify" or "peer-fingerprint".
        public var name: String
        /// The file it was embedded from, as the configuration names it; nil when it is inside the file.
        public var file: String?

        public init(name: String, file: String?) {
            self.name = name
            self.file = file
        }
    }

    /// What a new profile needs before it can connect without asking.
    public enum Field: String, CaseIterable, Sendable {
        case name, username, password
        case codeSecret = "code_secret"
    }

    /// The sign-in fields the profile needs, in the order to ask for them: a user name and a password when
    /// the configuration signs in with them (`auth-user-pass`), and the code secret when the server asks for
    /// a one-time code (`static-challenge`; nothing in a configuration says that a code is added to the
    /// password, so that one is the user's choice). The name is the caller's (it comes from the file name).
    public var needs: [Field] {
        var fields: [Field] = []
        if passwordMode != .none { fields += [.username, .password] }
        if otpMode == .ask { fields.append(.codeSecret) }
        return fields
    }

    /// `needs` that are still empty with these values.
    public func missing(username: String?, password: String?, codeSecret: Bool) -> [Field] {
        needs.filter { field in
            switch field {
            case .name: return false
            case .username: return (username ?? "").trimmingCharacters(in: .whitespaces).isEmpty
            case .password: return (password ?? "").isEmpty
            case .codeSecret: return !codeSecret
            }
        }
    }

    /// `needs` the file does not fill in.
    public var missing: [Field] { missing(username: username, password: password, codeSecret: false) }

    /// Blocks whose content `certificates` lists.
    static let certificateBlocks: Set<String> = [
        "ca", "cert", "key", "pkcs12", "extra-certs", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret",
        "crl-verify", "peer-fingerprint",
    ]

    /// Reads `text` as an import would: files it refers to are embedded from `baseDir` (none when nil),
    /// then every line the helper's sanitizer refuses is skipped or blocks (`OVPNSkipRules`). Throws only
    /// what embedding a file throws (`ovpnReferencedFile`, `fileTooLarge`); blocking lines are reported.
    public static func make(_ text: String, baseDir: URL?) throws -> OVPNImportReport {
        let original = OVPNInliner.lines(text)
        let inlined = try baseDir.map { try OVPNInliner.inlineMapped(text, baseDir: $0) }
            ?? OVPNInliner.Inlined(text: text, origins: Array(original.indices.map { $0 + 1 }), embedded: [])
        let rules = OVPNSkipRules.apply(inlined.text)

        func origin(_ line: Int) -> Int {
            inlined.origins.indices.contains(line - 1) ? inlined.origins[line - 1] : line
        }
        func shown(_ line: Int) -> String {
            original.indices.contains(line - 1) ? OVPNSkipRules.displayText(original[line - 1], firstLine: line == 1) : ""
        }
        let skipped = rules.skipped.map { s -> OVPNSkipRules.Skipped in
            let line = origin(s.line)
            return OVPNSkipRules.Skipped(line: line, directive: s.directive, text: shown(line), reason: s.reason)
        }
        var blocking: [OVPNSkipRules.Blocking] = []
        var seen = Set<OVPNSkipRules.Blocking>()
        for b in rules.blocking {
            let line = origin(b.line)
            let entry = OVPNSkipRules.Blocking(line: line, directive: b.directive, text: shown(line), reason: b.reason)
            if seen.insert(entry).inserted { blocking.append(entry) }   // several lines of one embedded file
        }

        let stripped = OVPNInliner.strippingCredentials(rules.text, blocks: [.authUserPass])
        let analysis = OVPNAnalyzer.analyze(stripped.text)
        return OVPNImportReport(
            config: blocking.isEmpty ? stripped.text : nil,
            skipped: skipped,
            blocking: blocking,
            servers: OVPNAnalyzer.servers(stripped.text),
            certificates: certificates(in: rules.text, origins: inlined.origins, embedded: inlined.embedded),
            passwordMode: analysis.passwordMode,
            otpMode: analysis.otpMode,
            otpDelivery: analysis.otpDelivery,
            username: stripped.username,
            password: stripped.password)
    }

    /// The certificate and key blocks of `text` (the inlined configuration) in file order, each once, with
    /// the file it was embedded from; a `peer-fingerprint` line counts too.
    static func certificates(in text: String, origins: [Int],
                             embedded: [(line: Int, directive: String, path: String)]) -> [Certificate] {
        var found: [Certificate] = []
        for (item, index) in OVPNAnalyzer.scan(text) {
            let name: String
            switch item {
            case .block(let tag) where certificateBlocks.contains(tag):
                name = tag
            case .directive(let words, _) where words[0] == "peer-fingerprint" && words.count > 1
                && words[1].lowercased() != "[inline]":
                name = "peer-fingerprint"
            default:
                continue
            }
            guard !found.contains(where: { $0.name == name }) else { continue }
            let line = origins.indices.contains(index) ? origins[index] : index + 1
            let file = embedded.first { $0.line == line && $0.directive == name }?.path
            found.append(Certificate(name: name, file: file))
        }
        return found
    }
}
