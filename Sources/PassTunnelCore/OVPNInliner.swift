import Foundation
import PassTunnelShared

/// Makes an .ovpn self-contained: directives that point at files (`ca ca.crt`, `tls-auth ta.key 1`, …)
/// are replaced by inline blocks, because the helper only accepts inline content.
public enum OVPNInliner {
    public static let maxReferencedFileSize = 1024 * 1024

    /// Directives whose first argument is a file that becomes `<name>…</name>`.
    static let inlinable: Set<String> = [
        "ca", "cert", "key", "dh", "pkcs12", "extra-certs", "tls-auth", "tls-crypt", "tls-crypt-v2",
        "secret", "crl-verify", "http-proxy-user-pass",
    ]
    /// Binary files, embedded as base64.
    static let binary: Set<String> = ["pkcs12"]
    /// Directives whose optional second argument is a key direction.
    static let keyDirectionDirectives: Set<String> = ["tls-auth", "secret"]

    /// Inlines every referenced file, resolving relative paths against `baseDir`.
    /// `auth-user-pass <file>` loses its path (PassTunnel supplies credentials) and `askpass` is dropped.
    /// Line endings are normalised to "\n".
    public static func inline(_ text: String, baseDir: URL) throws -> String {
        var out: [String] = []
        var verbatimTag: String?

        for rawLine in text.components(separatedBy: "\n") {
            var line = rawLine
            if line.hasSuffix("\r") { line.removeLast() }

            if let tag = verbatimTag {
                out.append(line)
                if isBlockEnd(line, tag: tag) { verbatimTag = nil }
                continue
            }
            guard let tokens = tokenize(line), let first = tokens.first else {
                out.append(line)   // blank, comment, or malformed (the sanitizer reports the latter)
                continue
            }
            if tokens.count == 1, let tag = blockTag(first) {
                if tag.lowercased() != "connection" { verbatimTag = tag }
                out.append(line)
                continue
            }

            let name = String(first.drop(while: { $0 == "-" })).lowercased()
            let args = Array(tokens.dropFirst())
            let fileArg = args.first.flatMap { $0.lowercased() == "[inline]" ? nil : $0 }

            switch name {
            case "askpass":
                continue
            case "auth-user-pass":
                out.append(fileArg == nil ? line : "auth-user-pass")
                continue
            case "dh" where fileArg?.lowercased() == "none":
                out.append(line)
                continue
            default:
                break
            }
            guard inlinable.contains(name), let path = fileArg else {
                out.append(line)
                continue
            }
            if name == "crl-verify", args.count > 1, args[1].lowercased() == "dir" {
                throw PTError.ovpnReferencedFile(path)   // a CRL directory cannot be embedded
            }

            let data = try readReferenced(path, baseDir: baseDir)
            let body: String
            if binary.contains(name) {
                body = data.base64EncodedString(options: .lineLength64Characters)
                    .replacingOccurrences(of: "\r\n", with: "\n")
            } else {
                guard let s = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
                    throw PTError.ovpnReferencedFile(path)
                }
                body = s.replacingOccurrences(of: "\r\n", with: "\n").trimmingCharacters(in: .newlines)
                // The content must not close the block early.
                if body.components(separatedBy: "\n").contains(where: { isBlockEnd($0, tag: name) }) {
                    throw PTError.ovpnReferencedFile(path)
                }
            }
            out.append("<\(name)>")
            out.append(body)
            out.append("</\(name)>")
            if keyDirectionDirectives.contains(name), args.count > 1 {
                out.append("key-direction \(args[1])")
            }
        }
        return out.joined(separator: "\n")
    }

    /// Inlines, then runs the helper's sanitizer so a config that would be refused at connect time
    /// is refused now. Returns the inlined (not stripped) text to store.
    public static func prepare(_ text: String, baseDir: URL?) throws -> String {
        let inlined = try baseDir.map { try inline(text, baseDir: $0) } ?? text
        try check(inlined)
        return inlined
    }

    /// Throws `PTError.ovpnNotAllowed` with every violation the sanitizer finds.
    public static func check(_ text: String) throws {
        do {
            _ = try OVPNSanitizer.sanitize(text)
        } catch let failure as OVPNSanitizer.Failure {
            throw PTError.ovpnNotAllowed(failure.violations.map(\.description))
        }
    }

    // MARK: files

    static func readReferenced(_ path: String, baseDir: URL) throws -> Data {
        let url = path.hasPrefix("/")
            ? URL(fileURLWithPath: path)
            : baseDir.appendingPathComponent(path)
        let resolved = url.standardizedFileURL.resolvingSymlinksInPath()
        let p = resolved.path
        guard !(p == "/dev" || p.hasPrefix("/dev/")) else { throw PTError.ovpnReferencedFile(path) }
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: p) else {
            throw PTError.ovpnReferencedFile(path)
        }
        guard attrs[.type] as? FileAttributeType == .typeRegular else { throw PTError.ovpnReferencedFile(path) }
        if let size = attrs[.size] as? NSNumber, size.intValue > maxReferencedFileSize {
            throw PTError.fileTooLarge(path)
        }
        return try FileIO.read(resolved, maxSize: maxReferencedFileSize)
    }

    // MARK: parsing (same rules as OpenVPN: quotes, backslash escapes, `#`/`;` comments)

    /// nil for blank/comment lines and unterminated quotes.
    static func tokenize(_ line: String) -> [String]? {
        var tokens: [String] = []
        var cur = ""
        var inToken = false
        var quote: Character?
        var escaped = false
        for c in line {
            if escaped { cur.append(c); escaped = false; inToken = true; continue }
            if c == "\\" && quote != "'" { escaped = true; continue }
            if let q = quote {
                if c == q { quote = nil; tokens.append(cur); cur = ""; inToken = false } else { cur.append(c) }
                continue
            }
            if c == " " || c == "\t" || c == "\r" || c == "\u{0B}" || c == "\u{0C}" {
                if inToken { tokens.append(cur); cur = ""; inToken = false }
                continue
            }
            if !inToken && (c == "#" || c == ";") { break }
            if !inToken && (c == "\"" || c == "'") { quote = c; continue }
            cur.append(c)
            inToken = true
        }
        if quote != nil { return nil }
        if inToken { tokens.append(cur) }
        return tokens.isEmpty ? nil : tokens
    }

    static func blockTag(_ token: String) -> String? {
        var t = Substring(token)
        if t.hasPrefix("--"), t.count >= 3 { t = t.dropFirst(2) }
        guard t.count > 2, t.first == "<", t.last == ">", !t.dropFirst().hasPrefix("/") else { return nil }
        return String(t.dropFirst().dropLast())
    }

    static func isBlockEnd(_ line: String, tag: String) -> Bool {
        line.drop(while: { $0 == " " || $0 == "\t" }).lowercased().hasPrefix("</\(tag.lowercased())>")
    }
}
