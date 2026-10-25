import Foundation
import PassTunnelVPNConfig

/// Makes an .ovpn self-contained: directives that point at files (`ca ca.crt`, `tls-auth ta.key 1`, …)
/// are replaced by inline blocks, because the helper only accepts inline content.
public enum OVPNInliner {
    public static let maxReferencedFileSize = 1024 * 1024

    /// Directives whose first argument is a file that becomes `<name>…</name>`.
    static let inlinable: Set<String> = [
        "ca", "cert", "key", "dh", "pkcs12", "extra-certs", "tls-auth", "tls-crypt", "tls-crypt-v2",
        "secret", "crl-verify", "http-proxy-user-pass",
    ]
    /// Credentials that OpenVPN sends to a server named in the config. Only taken from the config's own
    /// folder, so a hostile config cannot have the user's other files (e.g. `../../.git-credentials`) sent out.
    static let credentialFiles: Set<String> = ["http-proxy-user-pass"]
    /// Binary files, embedded as base64.
    static let binary: Set<String> = ["pkcs12"]
    /// Directives whose optional second argument is a key direction.
    static let keyDirectionDirectives: Set<String> = ["tls-auth", "secret"]

    /// Inlines every referenced file, resolving relative paths against `baseDir`.
    /// `auth-user-pass <file>` loses its path (PassTunnel supplies credentials) and `askpass` is dropped.
    /// Line endings are normalised to "\n".
    public static func inline(_ text: String, baseDir: URL) throws -> String {
        try inlineMapped(text, baseDir: baseDir).text
    }

    /// `inline`'s result with where each of its lines came from, so a report on the inlined text can name
    /// the lines of the file as the user wrote it.
    struct Inlined {
        var text: String
        /// For every line of `text` (split at "\n"), the 1-based number of the line of the original it came
        /// from; the lines of an embedded file count as the line that referenced it.
        var origins: [Int]
        /// The files embedded, in file order: the directive and the path as written, and its line.
        var embedded: [(line: Int, directive: String, path: String)]
    }

    static func inlineMapped(_ text: String, baseDir: URL) throws -> Inlined {
        var out: [String] = []
        var origins: [Int] = []
        var embedded: [(line: Int, directive: String, path: String)] = []
        var verbatimTag: String?
        func emit(_ s: String, from line: Int) {
            out.append(s)
            origins.append(contentsOf: repeatElement(line, count: lines(s).count))
        }

        for (index, rawLine) in lines(text).enumerated() {
            let lineNo = index + 1
            var line = rawLine
            if line.hasSuffix("\r") { line.removeLast() }
            if index == 0, line.hasPrefix("\u{FEFF}") { line.removeFirst() }   // UTF-8 BOM (Windows editors)

            if let tag = verbatimTag {
                emit(line, from: lineNo)
                if isBlockEnd(line, tag: tag) { verbatimTag = nil }
                continue
            }
            guard let tokens = tokenize(line), let first = tokens.first else {
                emit(line, from: lineNo)   // blank, comment, or malformed (the sanitizer reports the latter)
                continue
            }
            if tokens.count == 1, let tag = blockTag(first) {
                if tag.lowercased() != "connection" { verbatimTag = tag }
                emit(line, from: lineNo)
                continue
            }

            let name = String(first.drop(while: { $0 == "-" })).lowercased()
            let args = Array(tokens.dropFirst())
            let fileArg = args.first.flatMap { $0.lowercased() == "[inline]" ? nil : $0 }

            switch name {
            case "askpass":
                continue
            case "auth-user-pass":
                emit(fileArg == nil ? line : "auth-user-pass", from: lineNo)
                continue
            case "dh" where fileArg?.lowercased() == "none":
                emit(line, from: lineNo)
                continue
            default:
                break
            }
            guard inlinable.contains(name), let path = fileArg else {
                emit(line, from: lineNo)
                continue
            }
            if name == "crl-verify", args.count > 1, args[1].lowercased() == "dir" {
                throw PTError.ovpnReferencedFile(path)   // a CRL directory cannot be embedded
            }

            let data = try readReferenced(path, baseDir: baseDir, insideBaseDir: credentialFiles.contains(name))
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
                if lines(body).contains(where: { isBlockEnd($0, tag: name) }) {
                    throw PTError.ovpnReferencedFile(path)
                }
            }
            emit("<\(name)>", from: lineNo)
            emit(body, from: lineNo)
            emit("</\(name)>", from: lineNo)
            if keyDirectionDirectives.contains(name), args.count > 1 {
                emit("key-direction \(args[1])", from: lineNo)
            }
            embedded.append((line: lineNo, directive: name, path: path))
        }
        return Inlined(text: out.joined(separator: "\n"), origins: origins, embedded: embedded)
    }

    /// Inlines, then runs the helper's sanitizer so a config that would be refused at connect time
    /// is refused now. Returns the inlined (not stripped) text to store.
    public static func prepare(_ text: String, baseDir: URL?) throws -> String {
        let inlined = try baseDir.map { try inline(text, baseDir: $0) } ?? text
        try check(inlined)
        return inlined
    }

    // MARK: credentials

    /// Inline blocks whose content is a user name and a password (one per line).
    public enum CredentialBlock: String, CaseIterable {
        /// The VPN sign-in. PassTunnel always supplies it itself (`--auth-user-pass`).
        case authUserPass = "auth-user-pass"
        /// Credentials for the HTTP proxy (embedded from a file on import).
        case httpProxyUserPass = "http-proxy-user-pass"
    }

    public struct StrippedCredentials: Equatable {
        public var text: String
        /// From the `<auth-user-pass>` block, when it was removed and had them.
        public var username: String?
        public var password: String?
        /// Which blocks were found and removed.
        public var removed: Set<CredentialBlock>
    }

    /// Removes the `blocks` from a config, so no user name or password is stored or shared with it.
    /// A removed `<auth-user-pass>` leaves a bare `auth-user-pass` line (the config still signs in with
    /// a user name and password, which PassTunnel supplies), and `auth-user-pass [inline]` becomes
    /// `auth-user-pass`; `http-proxy-user-pass [inline]` lines go with their block. Other blocks are
    /// kept verbatim. Without any of these, `text` is returned unchanged.
    public static func strippingCredentials(_ text: String, blocks: Set<CredentialBlock> = Set(CredentialBlock.allCases)) -> StrippedCredentials {
        var result = StrippedCredentials(text: text, removed: [])
        var out: [String] = []
        var verbatimTag: String?
        var removing: (block: CredentialBlock, lines: [String])?
        var changed = false

        for rawLine in lines(text) {
            var line = rawLine
            if line.hasSuffix("\r") { line.removeLast() }
            if let current = removing {
                if isBlockEnd(line, tag: current.block.rawValue) {
                    finish(current.block, current.lines, into: &result, out: &out)
                    removing = nil
                } else {
                    removing?.lines.append(line)
                }
                continue
            }
            if let tag = verbatimTag {
                out.append(rawLine)
                if isBlockEnd(line, tag: tag) { verbatimTag = nil }
                continue
            }
            guard let tokens = tokenize(line), let first = tokens.first else {
                out.append(rawLine)
                continue
            }
            if tokens.count == 1, let tag = blockTag(first) {
                if let block = CredentialBlock(rawValue: tag.lowercased()), blocks.contains(block) {
                    removing = (block, [])
                    changed = true
                    continue
                }
                if tag.lowercased() != "connection" { verbatimTag = tag }
                out.append(rawLine)
                continue
            }
            let name = String(first.drop(while: { $0 == "-" })).lowercased()
            let inlineArg = tokens.count > 1 && tokens[1].lowercased() == "[inline]"
            if inlineArg, let block = CredentialBlock(rawValue: name), blocks.contains(block) {
                changed = true
                if block == .authUserPass { out.append("auth-user-pass") }
                continue
            }
            out.append(rawLine)
        }
        // An unterminated block is dropped with everything after it: none of it is kept.
        if let current = removing { finish(current.block, current.lines, into: &result, out: &out) }
        if changed { result.text = out.joined(separator: "\n") }
        return result
    }

    private static func finish(_ block: CredentialBlock, _ lines: [String], into result: inout StrippedCredentials,
                               out: inout [String]) {
        result.removed.insert(block)
        guard block == .authUserPass else { return }
        out.append("auth-user-pass")
        // As OpenVPN reads it: the first line is the user name, the second the password.
        if let user = lines.first?.trimmingCharacters(in: .whitespaces), !user.isEmpty, result.username == nil {
            result.username = user
        }
        if lines.count > 1, !lines[1].isEmpty, result.password == nil { result.password = lines[1] }
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

    static func readReferenced(_ path: String, baseDir: URL, insideBaseDir: Bool = false) throws -> Data {
        // No file name has a NUL; the file system calls below would read only the part before it.
        guard !path.utf8.contains(0) else { throw PTError.ovpnReferencedFile(path) }
        let url = path.hasPrefix("/")
            ? URL(fileURLWithPath: path)
            : baseDir.appendingPathComponent(path)
        let resolved = url.standardizedFileURL.resolvingSymlinksInPath()
        let p = resolved.path
        guard !(p == "/dev" || p.hasPrefix("/dev/")) else { throw PTError.ovpnReferencedFile(path) }
        if insideBaseDir {
            let base = baseDir.standardizedFileURL.resolvingSymlinksInPath().path
            guard p.hasPrefix(base.hasSuffix("/") ? base : base + "/") else { throw PTError.ovpnReferencedFile(path) }
        }
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: p) else {
            throw PTError.ovpnReferencedFile(path)
        }
        guard attrs[.type] as? FileAttributeType == .typeRegular else { throw PTError.ovpnReferencedFile(path) }
        if let size = attrs[.size] as? NSNumber, size.intValue > maxReferencedFileSize {
            throw PTError.fileTooLarge(path)
        }
        return try FileIO.read(resolved, maxSize: maxReferencedFileSize)
    }

    // MARK: parsing (`OVPNSanitizer`'s, so the two never read a line differently)

    /// `text` split at every "\n", as `components(separatedBy: "\n")` splits it on Apple platforms: the
    /// "\n" of "\r\n" too (the line keeps the "\r"), and a final "\n" leaves an empty last line.
    /// Foundation on Linux keeps "\r\n" whole, because it is a single Character.
    static func lines(_ text: String) -> [String] {
        text.unicodeScalars.split(separator: "\n", omittingEmptySubsequences: false).map { String(Substring($0)) }
    }

    /// nil for blank and comment lines and for lines OpenVPN rejects (bad backslash escape,
    /// unterminated quote): those are kept as they are and the sanitizer reports them.
    static func tokenize(_ line: String) -> [String]? {
        guard let tokens = OVPNSanitizer.tokens(of: line), !tokens.isEmpty else { return nil }
        return tokens
    }

    static func blockTag(_ token: String) -> String? {
        OVPNSanitizer.inlineBlockTag(token)
    }

    static func isBlockEnd(_ line: String, tag: String) -> Bool {
        OVPNSanitizer.isInlineBlockEnd(line, tag: tag)
    }
}
