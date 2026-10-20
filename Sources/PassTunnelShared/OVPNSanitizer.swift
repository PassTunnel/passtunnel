import Foundation

/// Checks an OpenVPN client config before the helper runs it as root.
///
/// The parser mirrors OpenVPN's own tokenizer (quotes, backslash escapes, `#`/`;` comments, a leading
/// `--` on option names, `<tag>…</tag>` inline blocks, `setenv opt` prefixes) and errs on the strict
/// side wherever the two could disagree: option names are compared case-insensitively with every
/// leading dash removed, and block ends are detected more liberally than OpenVPN does.
public enum OVPNSanitizer {
    public struct Violation: Equatable, CustomStringConvertible {
        public let line: Int
        public let directive: String
        public let reason: String

        public init(line: Int, directive: String, reason: String) {
            self.line = line
            self.directive = directive
            self.reason = reason
        }

        public var description: String { "line \(line): \(directive) (\(reason))" }
    }

    public struct Failure: Error, Equatable, LocalizedError, CustomStringConvertible {
        public let violations: [Violation]
        public var description: String {
            "The OpenVPN config contains directives that are not allowed: "
                + violations.map(\.description).joined(separator: "; ")
        }
        public var errorDescription: String? { description }
    }

    /// Directives that run programs, load code, write files as root or override the helper's settings.
    public static let forbiddenDirectives: Set<String> = [
        "up", "down", "route-up", "route-pre-down", "ipchange", "learn-address",
        "client-connect", "client-disconnect", "tls-verify", "auth-user-pass-verify",
        "tls-crypt-v2-verify", "plugin", "dns-updown", "iproute",
        "daemon", "writepid", "cd", "chroot", "user", "group", "config",
        "status", "replay-persist", "tmp-dir", "tls-export-cert", "dev-node",
        "client-config-dir", "ifconfig-pool-persist",
        "engine", "providers", "pkcs11-providers", "capath",
        "show-pkcs11-ids",      // loads the given PKCS#11 provider library
        "genkey",               // writes a key file (truncating it) at the given path
        "port-share",           // server only; writes journal files into a directory
    ]

    /// Prefix families: `management*`, `log*`.
    public static let forbiddenPrefixes = ["management", "log"]

    /// Removed silently: the app answers challenges itself.
    public static let strippedDirectives: Set<String> = ["static-challenge"]

    /// Directives whose first argument is a file. Only inline content is accepted, because the helper
    /// would otherwise read arbitrary paths as root.
    public static let fileDirectives: Set<String> = [
        "ca", "cert", "key", "dh", "pkcs12", "extra-certs", "tls-auth", "tls-crypt", "tls-crypt-v2",
        "secret", "crl-verify", "auth-user-pass", "http-proxy-user-pass", "askpass", "auth-gen-token-secret",
    ]

    /// `setenv` names that are client metadata only. Anything else could steer the shell that runs
    /// the DNS script (e.g. BASH_ENV, PATH).
    static let allowedSetenvNames: Set<String> = [
        "CLIENT_CERT", "FORWARD_COMPATIBLE", "PUSH_PEER_INFO", "FRIENDLY_NAME",
        "ALLOW_PASSWORD_SAVE", "SERVER_POLL_TIMEOUT", "GENERIC_CONFIG",
    ]

    /// OpenVPN reads config lines with a 256-byte buffer and silently splits longer ones.
    public static let maxLineBytes = 254

    /// Returns the sanitized config, or throws `Failure` listing every offending line.
    /// A config without stripped directives is returned byte-for-byte unchanged.
    public static func sanitize(_ text: String) throws -> String {
        var violations: [Violation] = []
        var keep: [Bool] = []
        let lines = splitLines(text)
        keep = Array(repeating: true, count: lines.count)

        var i = 0
        var blockStack: [(tag: String, line: Int, verbatim: Bool)] = []
        while i < lines.count {
            let lineNo = i + 1
            var raw = lines[i].content
            if i == 0, raw.hasPrefix("\u{FEFF}") { raw.removeFirst() }

            if lines[i].content.utf8.count > maxLineBytes {
                violations.append(Violation(line: lineNo, directive: "(line)",
                                            reason: "longer than \(maxLineBytes) characters"))
                i += 1
                continue
            }
            if raw.unicodeScalars.contains(where: { $0.value == 0 }) {
                violations.append(Violation(line: lineNo, directive: "(line)", reason: "contains a NUL byte"))
                i += 1
                continue
            }

            // Inside a verbatim block: only look for its end.
            if let top = blockStack.last, top.verbatim {
                if isBlockEnd(raw, tag: top.tag) { blockStack.removeLast() }
                i += 1
                continue
            }
            // Inside a parsed block (<connection>): its end, or a regular directive.
            if let top = blockStack.last, isBlockEnd(raw, tag: top.tag) {
                blockStack.removeLast()
                i += 1
                continue
            }

            let tokens: [String]
            switch tokenize(raw) {
            case .failure(let reason):
                violations.append(Violation(line: lineNo, directive: "(line)", reason: reason))
                i += 1
                continue
            case .success(let t):
                tokens = t
            }
            guard !tokens.isEmpty else { i += 1; continue }

            if tokens.count == 1, let tag = blockTag(tokens[0]) {
                let name = normalize(tag)
                if let reason = forbiddenReason(name, args: []) {
                    violations.append(Violation(line: lineNo, directive: "<\(tag)>", reason: reason))
                }
                if strippedDirectives.contains(name) {
                    // Strip the whole block; mark lines below once its end is found.
                    keep[i] = false
                    var j = i + 1
                    while j < lines.count, !isBlockEnd(lines[j].content, tag: tag) { keep[j] = false; j += 1 }
                    if j < lines.count { keep[j] = false; i = j + 1; continue }
                }
                blockStack.append((tag: tag, line: lineNo, verbatim: name != "connection"))
                i += 1
                continue
            }

            switch check(tokens) {
            case .ok: break
            case .strip: keep[i] = false
            case .violation(let name, let reason):
                violations.append(Violation(line: lineNo, directive: name, reason: reason))
            }
            i += 1
        }
        for open in blockStack {
            violations.append(Violation(line: open.line, directive: "<\(open.tag)>", reason: "block is never closed"))
        }

        if !violations.isEmpty { throw Failure(violations: violations) }
        if !keep.contains(false) { return text }
        var out = ""
        for (n, line) in lines.enumerated() where keep[n] {
            out += line.content
            if line.hasNewline { out += "\n" }
        }
        return out
    }

    // MARK: - Directive rules

    enum Verdict: Equatable { case ok, strip, violation(String, String) }

    static func check(_ tokens: [String]) -> Verdict {
        let name = normalize(tokens[0])
        let args = Array(tokens.dropFirst())

        // `setenv opt <directive …>` makes OpenVPN treat the rest as a (optional) directive.
        if name == "setenv", let first = args.first, first.lowercased() == "opt" {
            let rest = Array(args.dropFirst())
            if rest.isEmpty { return .ok }
            return check(rest)
        }
        if name == "setenv" {
            guard let varName = args.first else { return .ok }
            if allowedSetenvNames.contains(varName) || varName.hasPrefix("IV_") || varName.hasPrefix("UV_") {
                return .ok
            }
            return .violation("setenv \(varName)", "only client metadata variables may be set")
        }
        if strippedDirectives.contains(name) { return .strip }
        if let reason = forbiddenReason(name, args: args) { return .violation(name, reason) }
        return .ok
    }

    static func forbiddenReason(_ name: String, args: [String]) -> String? {
        if forbiddenDirectives.contains(name) { return "not allowed" }
        if forbiddenPrefixes.contains(where: { name.hasPrefix($0) }) { return "managed by PassTunnel" }
        if name == "script-security" {
            guard let level = args.first.flatMap({ Int($0) }) else { return "invalid level" }
            return level > 1 ? "level above 1 allows scripts" : nil
        }
        if fileDirectives.contains(name), let file = args.first, !isInlineMarker(file) {
            if name == "dh", file.lowercased() == "none" { return nil }
            return "references an external file; embed it inline as <\(name)>…</\(name)>"
        }
        if name == "socks-proxy", args.count >= 3 {
            // `socks-proxy host port authfile`: the file's first two lines go to the proxy.
            return "references an external credentials file"
        }
        if name == "http-proxy", args.count >= 3 {
            let auth = args[2].lowercased()
            if !["auto", "auto-nct", "[inline]"].contains(auth) {
                return "references an external credentials file; embed it inline"
            }
        }
        return nil
    }

    static func isInlineMarker(_ s: String) -> Bool { s.lowercased() == "[inline]" }

    /// Lowercased with all leading dashes removed (OpenVPN itself only strips one `--`).
    static func normalize(_ token: String) -> String {
        String(token.drop(while: { $0 == "-" })).lowercased()
    }

    /// `<tag>` as OpenVPN recognizes it after stripping a leading `--`.
    static func blockTag(_ token: String) -> String? {
        var t = Substring(token)
        if t.hasPrefix("--"), t.count >= 3 { t = t.dropFirst(2) }
        guard t.count > 2, t.first == "<", t.last == ">" else { return nil }
        let inner = t.dropFirst().dropLast()
        guard !inner.hasPrefix("/") else { return nil }
        return String(inner)
    }

    /// OpenVPN ends a block at the first line that, after leading whitespace, starts with `</tag>`
    /// (case-sensitive). Matching case-insensitively ends it no later than OpenVPN does.
    static func isBlockEnd(_ line: String, tag: String) -> Bool {
        let trimmed = line.drop(while: { isSpace($0) })
        return trimmed.lowercased().hasPrefix("</\(tag.lowercased())>")
    }

    // MARK: - Tokenizer (mirrors OpenVPN's parse_line)

    enum TokenizeResult { case success([String]), failure(String) }

    static func isSpace(_ c: Character) -> Bool {
        c.unicodeScalars.allSatisfy(isSpace)
    }

    static func isSpace(_ s: Unicode.Scalar) -> Bool {
        switch s.value {
        case 0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D: return true
        default: return false
        }
    }

    static func tokenize(_ line: String) -> TokenizeResult {
        enum State { case initial, unquoted, quoted, squoted }
        var tokens: [String] = []
        var cur = String.UnicodeScalarView()
        var state = State.initial
        var backslash = false

        for c in line.unicodeScalars {
            if !backslash, c == "\\", state != .squoted {
                backslash = true
                continue
            }
            switch state {
            case .initial:
                if !isSpace(c) {
                    if !backslash, c == "#" || c == ";" { return .success(tokens) }
                    if !backslash, c == "\"" { state = .quoted }
                    else if !backslash, c == "'" { state = .squoted }
                    else { cur.append(c); state = .unquoted }
                }
            case .unquoted:
                if !backslash, isSpace(c) {
                    tokens.append(String(cur)); cur = .init(); state = .initial
                } else {
                    cur.append(c)
                }
            case .quoted:
                if !backslash, c == "\"" {
                    tokens.append(String(cur)); cur = .init(); state = .initial
                } else {
                    cur.append(c)
                }
            case .squoted:
                if c == "'" {
                    tokens.append(String(cur)); cur = .init(); state = .initial
                } else {
                    cur.append(c)
                }
            }
            backslash = false
        }
        switch state {
        case .initial: break
        case .unquoted: tokens.append(String(cur))
        case .quoted, .squoted: return .failure("unterminated quote")
        }
        return .success(tokens)
    }

    // MARK: - Lines

    struct Line { var content: String; var hasNewline: Bool }

    /// Splits on "\n" only (as fgets does); "\r" stays in the content and is whitespace to the tokenizer.
    static func splitLines(_ text: String) -> [Line] {
        var result: [Line] = []
        let bytes = Array(text.utf8)
        var start = 0
        for (idx, b) in bytes.enumerated() where b == 0x0A {
            result.append(Line(content: String(decoding: bytes[start..<idx], as: UTF8.self), hasNewline: true))
            start = idx + 1
        }
        if start < bytes.count {
            result.append(Line(content: String(decoding: bytes[start...], as: UTF8.self), hasNewline: false))
        }
        return result
    }
}
