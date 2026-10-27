import Foundation

/// Checks an OpenVPN client config before the helper runs it as root.
///
/// A denylist: it refuses every directive that runs a program, loads code, reads or writes a file the
/// config names, or makes OpenVPN anything but a client connection (a server, a standalone command, a
/// peer that waits for incoming connections), checked against the option parser of OpenVPN 2.4 to 2.7.
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

        /// Line 0 is the file as a whole (`missingRemote`).
        public var description: String {
            line == 0 ? "\(directive) (\(reason))" : "line \(line): \(directive) (\(reason))"
        }
    }

    public struct Failure: Error, Equatable, LocalizedError, CustomStringConvertible {
        public let violations: [Violation]
        public var description: String {
            "The OpenVPN config contains directives that are not allowed: "
                + violations.map(\.description).joined(separator: "; ")
        }
        public var errorDescription: String? { description }
    }

    /// Directives that run programs, load code, write files as root, override the helper's settings, or
    /// make OpenVPN something other than a client connection.
    public static let forbiddenDirectives: Set<String> = [
        "up", "down", "route-up", "route-pre-down", "ipchange", "learn-address",
        "client-connect", "client-disconnect", "client-crresponse", "tls-verify", "auth-user-pass-verify",
        "tls-crypt-v2-verify", "plugin", "dns-updown", "iproute",
        "daemon", "writepid", "cd", "chroot", "user", "group", "config",
        "status", "replay-persist", "tmp-dir", "tls-export-cert", "dev-node",
        "client-config-dir", "ifconfig-pool-persist",
        "engine", "providers", "pkcs11-providers", "capath",
        "show-pkcs11-ids",      // loads the given PKCS#11 provider library
        "genkey",               // writes a key file (truncating it) at the given path
        "port-share",           // server only; writes journal files into a directory
        "memstats",             // 2.6 on Linux: creates, truncates and finally deletes the given file
        "setcon",               // Linux: changes the process's SELinux context, like user/group
        // Server modes: OpenVPN would accept connections and run the server-side hooks.
        "server", "server-ipv6", "server-bridge", "tls-server", "inetd",
        // Standalone modes: a one-off command, or a change that outlives the session, instead of connecting.
        "mktun", "rmtun", "help", "version", "test-crypto",
        "show-ciphers", "show-digests", "show-engines", "show-tls", "show-curves", "show-groups",
        "show-gateway", "show-net", "show-net-up", "show-adapters", "show-valid-subnets", "allow-nonadmin",
        // Windows builds: the folder system programs are run from, and the service's internal options.
        "win-sys", "service", "msg-channel",
    ]

    /// The only `mode` OpenVPN may run in: `mode server` is a server.
    static let allowedMode = "p2p"

    /// `dev` names: OpenVPN's device types, optionally followed by a unit number or name. On macOS (and the
    /// BSDs) OpenVPN opens `/dev/<dev>` for a `tap` device or when utun is not available, so any other name
    /// could open an arbitrary device or file as root.
    static let devicePrefixes = ["tun", "tap", "utun", "null"]

    /// Protocols that make OpenVPN listen for a TCP connection instead of making one (`proto`, the third
    /// argument of `remote` and `local`, `proto-force`). OpenVPN compares them case-sensitively; any case
    /// is refused here.
    static let listeningProtocols: Set<String> = ["tcp-server", "tcp4-server", "tcp6-server"]

    static let listeningReason = "waits for incoming connections; PassTunnel only connects to a server"

    /// The violation of a config without any `remote`: over UDP OpenVPN then waits for a peer to reach it
    /// instead of connecting out (over TCP that takes a listening protocol, refused on its own line).
    /// Reported as line 0, the file as a whole.
    public static let missingRemote = Violation(
        line: 0, directive: "remote",
        reason: "missing; without a server to connect to, OpenVPN waits for incoming connections")

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

    // MARK: TLS floor

    /// The oldest TLS version the control channel may use. The helper also passes it to OpenVPN after the
    /// config (`tlsVersionFloor(of:)`).
    public static let minimumTLSVersion = "1.2"

    /// The values `tls-version-min` and `tls-version-max` may have. OpenVPN compares them exactly.
    static let allowedTLSVersions: Set<String> = ["1.2", "1.3"]

    /// `tls-cert-profile` values: `legacy` (OpenVPN's default) sets OpenSSL's security level 1,
    /// `preferred` 2, `suiteb` 3. `insecure` sets level 0, which allows TLS 1.0 and 1.1 again.
    static let allowedCertProfiles: Set<String> = ["legacy", "preferred", "suiteb"]

    /// TLS 1.3 suites `tls-ciphersuites` may list (OpenVPN turns `-` into `_`): the ones that encrypt with a
    /// full-length tag. Not the integrity-only suites (no encryption) nor `TLS_AES_128_CCM_8_SHA256`.
    static let allowedTLS13Suites: Set<String> = [
        "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_SHA256",
    ]

    /// Words in a `tls-cipher` element that select suites without encryption (`eNULL`, `NULL-SHA`), without
    /// authentication (`aNULL`, `ADH`, `AECDH`, the `…_anon_…` names), export suites (`EXP`, `EXPORT`), or
    /// the suites `ALL` leaves out (`COMPLEMENTOFALL`, `COMPLEMENTOFDEFAULT`). Compared in upper case.
    static let weakCipherWords = ["NULL", "EXP", "ADH", "AECDH", "ANON", "COMPLEMENTOF"]

    /// The lowest `@SECLEVEL` a `tls-cipher` list may set: OpenVPN's default (`tls-cert-profile legacy`).
    /// Level 0 allows TLS 1.0 and 1.1 and the suites above.
    static let minimumSecurityLevel = 1

    static let tlsVersionReason = "PassTunnel requires TLS 1.2 or later; only 1.2 or 1.3 is allowed"
    static let securityLevelReason =
        "lowers OpenSSL's security level below 1, which allows TLS older than 1.2; only @SECLEVEL=1 to 5 is allowed"
    static let weakCipherReason = "selects cipher suites without encryption or authentication, or export suites"
    static let tls13SuiteReason =
        "only TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_128_CCM_SHA256 are allowed"
    static let certProfileReason =
        "only legacy, preferred or suiteb is allowed; insecure allows TLS older than 1.2"

    /// The arguments of the `--tls-version-min` the helper passes after the config, which then overrides
    /// the config's own: `1.2`, or `1.3` (with `or-highest` if given) when the config's last
    /// `tls-version-min` asks for 1.3, so the floor never lowers what the config sets. Reads lines as
    /// `verbosity(of:)` does.
    public static func tlsVersionFloor(of text: String) -> [String] {
        var floor = [minimumTLSVersion]
        forEachDirective(in: text) { tokens in
            guard normalize(tokens[0]) == "tls-version-min" else { return }
            let args = Array(tokens.dropFirst())
            floor = args == ["1.3"] || args == ["1.3", "or-highest"] ? args : [minimumTLSVersion]
        }
        return floor
    }

    /// Why a TLS directive could let the control channel use less than TLS 1.2 or weaken OpenSSL's
    /// checks; nil when it cannot. An inline block named after one of them (no arguments) is refused too.
    static func tlsReason(_ name: String, args: [String]) -> String? {
        switch name {
        case "tls-version-min":
            // `or-highest` only matters for a version OpenVPN does not know, which is refused anyway.
            let valid = (args.count == 1 || (args.count == 2 && args[1] == "or-highest"))
                && allowedTLSVersions.contains(args[0])
            return valid ? nil : tlsVersionReason
        case "tls-version-max":
            return args.count == 1 && allowedTLSVersions.contains(args[0]) ? nil : tlsVersionReason
        case "tls-cert-profile":
            return args.count == 1 && allowedCertProfiles.contains(args[0]) ? nil : certProfileReason
        case "tls-ciphersuites":
            guard args.count == 1 else { return tls13SuiteReason }
            let suites = args[0].split(separator: ":", omittingEmptySubsequences: false)
            let valid = suites.allSatisfy {
                allowedTLS13Suites.contains($0.replacingOccurrences(of: "-", with: "_").uppercased())
            }
            return valid ? nil : tls13SuiteReason
        case "tls-cipher":
            guard args.count == 1 else { return weakCipherReason }
            return cipherListReason(args[0])
        default:
            return nil
        }
    }

    /// Checks an OpenSSL cipher list (TLS 1.2 and older) as OpenSSL splits it: elements separated by `:`,
    /// `,`, `;` or spaces. Every `@SECLEVEL` must be exactly `@SECLEVEL=` and one digit from 1 to 5
    /// (a misspelling is refused too); elements that add suites must not name a weak word. Elements that
    /// remove suites (`!…`, `-…`) may.
    static func cipherListReason(_ list: String) -> String? {
        let elements = list.uppercased().split(whereSeparator: { ":,; \t".contains($0) })
        let prefix = Array("@SECLEVEL=".utf8)
        for element in elements where element.contains("SECLEVEL") {
            let bytes = Array(element.utf8)
            guard bytes.count == prefix.count + 1, bytes.starts(with: prefix),
                  (UInt8(ascii: "0") + UInt8(minimumSecurityLevel)...UInt8(ascii: "5")).contains(bytes[prefix.count])
            else { return securityLevelReason }
        }
        for element in elements where element.first != "!" && element.first != "-" {
            if weakCipherWords.contains(where: { element.contains($0) }) { return weakCipherReason }
        }
        return nil
    }

    /// Returns the sanitized config, or throws `Failure` listing every offending line, and
    /// `missingRemote` when no line names a server to connect to.
    /// A config without stripped directives is returned byte-for-byte unchanged.
    public static func sanitize(_ text: String) throws -> String {
        var violations: [Violation] = []
        var hasRemote = false
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
            // OpenVPN skips a BOM only at the start of the file. Anywhere else it would be part of the
            // first token, and once an earlier line was stripped the line could become the first one.
            if raw.hasPrefix("\u{FEFF}") {
                violations.append(Violation(line: lineNo, directive: "(line)", reason: misplacedBOM))
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

            if isRemote(tokens) { hasRemote = true }
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
        if !hasRemote { violations.append(missingRemote) }

        if !violations.isEmpty { throw Failure(violations: violations) }
        if !keep.contains(false) { return text }
        var out = ""
        for (n, line) in lines.enumerated() where keep[n] {
            out += line.content
            if line.hasNewline { out += "\n" }
        }
        return out
    }

    /// The `verb` level the config sets (the last one wins, as in OpenVPN), or nil when it sets none.
    /// Reads lines as `sanitize` does: inline blocks are skipped, `setenv opt verb …` counts.
    public static func verbosity(of text: String) -> Int? {
        var level: Int?
        forEachDirective(in: text) { tokens in
            if normalize(tokens[0]) == "verb", tokens.count >= 2, let n = Int(tokens[1]) { level = max(0, n) }
        }
        return level
    }

    /// Every `dev` name the config sets, in file order, read as `verbosity(of:)` reads lines. OpenVPN
    /// uses the last one; all of them are listed, so a check of each errs on the strict side.
    public static func deviceNames(of text: String) -> [String] {
        var names: [String] = []
        forEachDirective(in: text) { tokens in
            if normalize(tokens[0]) == "dev", tokens.count == 2 { names.append(tokens[1]) }
        }
        return names
    }

    /// Calls `body` with the tokens of every directive line outside verbatim inline blocks (lines in a
    /// `<connection>` block count), without a `setenv opt` prefix.
    static func forEachDirective(in text: String, _ body: ([String]) -> Void) {
        var block: (tag: String, verbatim: Bool)?
        for (index, line) in splitLines(text).enumerated() {
            var content = line.content
            if index == 0, content.hasPrefix("\u{FEFF}") { content.removeFirst() }
            if let b = block {
                if isBlockEnd(content, tag: b.tag) { block = nil; continue }
                if b.verbatim { continue }
            }
            guard case .success(var tokens) = tokenize(content), !tokens.isEmpty else { continue }
            if tokens.count == 1, let tag = blockTag(tokens[0]) {
                block = (tag: tag, verbatim: normalize(tag) != "connection")
                continue
            }
            if normalize(tokens[0]) == "setenv", tokens.count >= 3, tokens[1].lowercased() == "opt" {
                tokens.removeFirst(2)
            }
            body(tokens)
        }
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
        if name == "mode" {
            return args.count == 1 && args[0].lowercased() == allowedMode ? nil : "only mode p2p is allowed"
        }
        if name == "dev" {
            guard args.count == 1, isDeviceName(args[0]) else {
                return "must be tun, tap, utun or null, optionally followed by letters, digits, - or _"
            }
            return nil
        }
        // A protocol is the first argument of `proto` and `proto-force`, the third of `remote` and `local`.
        let protocolIndex = ["proto": 0, "proto-force": 0, "remote": 2, "local": 2][name]
        if let index = protocolIndex, args.indices.contains(index), listeningProtocols.contains(args[index].lowercased()) {
            return listeningReason
        }
        if fileDirectives.contains(name), let file = args.first, !isInlineMarker(file) {
            if name == "dh", file.lowercased() == "none" { return nil }
            return "references an external file; embed it inline as <\(name)>…</\(name)>"
        }
        if let reason = tlsReason(name, args: args) { return reason }
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

    /// A `remote` OpenVPN certainly takes as a server to connect to: a host, then optionally a port and a
    /// protocol. Unlike the checks for refused directives, this one is exact, as OpenVPN's parser is: one
    /// leading `--` on the line, case-sensitive names, one `setenv opt` prefix and no `--` after it. OpenVPN
    /// refuses the other spellings, or after `setenv opt` only warns and goes on without the line.
    static func isRemote(_ tokens: [String]) -> Bool {
        var tokens = tokens
        if let first = tokens.first, first.hasPrefix("--"), first.utf8.count >= 3 { tokens[0] = String(first.dropFirst(2)) }
        if tokens.count >= 2, tokens[0] == "setenv", tokens[1] == "opt" { tokens.removeFirst(2) }
        return tokens.first == "remote" && (2...4).contains(tokens.count)
    }

    /// A device type in lowercase, as OpenVPN compares it, then only ASCII letters, digits, `-` and `_`:
    /// no `/` or `.`, so the name can never become a path.
    static func isDeviceName(_ s: String) -> Bool {
        let bytes = Array(s.utf8)
        guard let prefix = devicePrefixes.first(where: { bytes.starts(with: $0.utf8) }) else { return false }
        return bytes.dropFirst(prefix.utf8.count).allSatisfy {
            switch $0 {
            case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "_"): return true
            default: return false
            }
        }
    }

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

    /// The tokens of one line exactly as `sanitize` reads them, for code in the app that must agree
    /// with it (`OVPNInliner`). Empty for blank and comment lines, nil for lines OpenVPN rejects
    /// (bad escape, unterminated quote; `sanitize` reports those).
    public static func tokens(of line: String) -> [String]? {
        guard case .success(let tokens) = tokenize(line) else { return nil }
        return tokens
    }

    /// `blockTag` and `isBlockEnd` for the app's parsers.
    public static func inlineBlockTag(_ token: String) -> String? { blockTag(token) }
    public static func isInlineBlockEnd(_ line: String, tag: String) -> Bool { isBlockEnd(line, tag: tag) }

    static func isSpace(_ c: Character) -> Bool {
        c.unicodeScalars.allSatisfy(isSpace)
    }

    static func isSpace(_ s: Unicode.Scalar) -> Bool {
        switch s.value {
        case 0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D: return true
        default: return false
        }
    }

    static let badBackslash = "a backslash may only escape \\, \" or whitespace"
    static let misplacedBOM = "starts with a byte order mark (only the first line of the file may)"

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
            // OpenVPN aborts on any other escape; reading it as a literal would let the two disagree.
            if backslash, c != "\\", c != "\"", !isSpace(c) { return .failure(badBackslash) }
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
        if backslash { return .failure(badBackslash) }
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
