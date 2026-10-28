import Foundation

/// What the user's `openconnect --authenticate` run printed on standard output, parsed strictly. openconnect
/// 9.21 (main.c 2403–2425) prints exactly
///
///     COOKIE='<cookie>'
///     HOST='<address it connected to>'
///     CONNECT_URL='https://<host>[:<port>]/'
///     FINGERPRINT='pin-sha256:<base64>'
///     RESOLVE='<host>:<address>'
///
/// in this order, the last line as `RESOLVE=` without a line break when it has no address. Its progress
/// messages go to standard error in this mode. The values are not escaped, so each must be printable ASCII
/// without `'`. Anything else, an unknown, repeated, missing or reordered key, fails.
///
/// The cookie is a bearer secret: no description, mirror or error of this type includes it.
public struct OpenConnectAuthResult: Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let cookie: String
    /// `HOST`: the numeric address the run connected to (an IPv6 address in brackets).
    public let host: String
    /// `CONNECT_URL`: where the session continues.
    public let connectURL: String
    /// `FINGERPRINT`: the server key the run accepted, a full `pin-sha256:` pin.
    public let fingerprint: String
    /// `RESOLVE`: `<host>:<address>`, or empty when openconnect printed none.
    public let resolve: String

    public static let keys = ["COOKIE", "HOST", "CONNECT_URL", "FINGERPRINT", "RESOLVE"]
    public static let maxOutputBytes = 8192
    public static let maxHostBytes = 255
    public static let maxConnectURLBytes = 300
    public static let maxResolveBytes = 300

    public enum ParseError: Error, Equatable, LocalizedError, CustomStringConvertible {
        case tooLong
        /// The output is not the expected lines; the reason names the key, never a value.
        case malformed(String)
        case invalidValue(key: String, reason: String)

        public var description: String {
            switch self {
            case .tooLong: return "The sign-in output is longer than \(OpenConnectAuthResult.maxOutputBytes) bytes."
            case .malformed(let r): return "The sign-in output is not in the expected form: \(r)."
            case .invalidValue(let k, let r): return "The sign-in output has an invalid \(k): \(r)."
            }
        }
        public var errorDescription: String? { description }
    }

    /// Why a sign-in that succeeded cannot be used for the profile's tunnel.
    public enum DestinationError: Error, Equatable, LocalizedError, CustomStringConvertible {
        /// The sign-in ended on another server (another host or port, or a path): refused in Phase 1.
        case otherServer(connectURL: String)
        case fingerprintMismatch
        case noResolvedAddress
        case addressMismatch

        public var description: String {
            switch self {
            case .otherServer(let url):
                return "The server sent the sign-in to another server (\(url)); PassTunnel connects only to the profile's server."
            case .fingerprintMismatch: return "The sign-in reached a server key other than the profile's pinned key."
            case .noResolvedAddress: return "The sign-in did not report the address it connected to."
            case .addressMismatch: return "The sign-in reported an address that does not belong to the profile's server."
            }
        }
        public var errorDescription: String? { description }
    }

    /// The fields, each checked as `parse` checks it (so the helper can rebuild and check a result it was sent).
    public init(cookie: String, host: String, connectURL: String, fingerprint: String, resolve: String) throws {
        guard OpenConnectSyntax.isValidCookie(cookie) else {
            throw ParseError.invalidValue(
                key: "COOKIE",
                reason: "not 1–\(OpenConnectConfig.maxCookieBytes) bytes of printable ASCII without surrounding blanks or a leading =")
        }
        try Self.checkPrintable(host, key: "HOST", maxBytes: Self.maxHostBytes, allowEmpty: false)
        try Self.checkPrintable(connectURL, key: "CONNECT_URL", maxBytes: Self.maxConnectURLBytes, allowEmpty: false)
        guard OpenConnectPin.isValid(fingerprint) else {
            throw ParseError.invalidValue(key: "FINGERPRINT", reason: "not a full pin-sha256: pin")
        }
        try Self.checkPrintable(resolve, key: "RESOLVE", maxBytes: Self.maxResolveBytes, allowEmpty: true)
        self.cookie = cookie
        self.host = host
        self.connectURL = connectURL
        self.fingerprint = fingerprint
        self.resolve = resolve
    }

    public var description: String {
        "OpenConnectAuthResult(cookie: <redacted>, host: \(host), connectURL: \(connectURL), fingerprint: \(fingerprint), "
            + "resolve: \(resolve))"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(
            self,
            children: [
                "cookie": "<redacted>", "host": host, "connectURL": connectURL, "fingerprint": fingerprint, "resolve": resolve
            ])
    }

    public static func parse(_ output: String) throws -> OpenConnectAuthResult { try parse(Array(output.utf8)) }

    public static func parse(_ output: [UInt8]) throws -> OpenConnectAuthResult {
        guard output.count <= maxOutputBytes else { throw ParseError.tooLong }
        var pos = 0
        var values: [String] = []
        for key in keys {
            let prefix = Array("\(key)=".utf8)
            guard output[pos...].starts(with: prefix) else { throw ParseError.malformed("\(key) is missing or out of order") }
            pos += prefix.count
            if key == "RESOLVE", output[pos...].first != UInt8(ascii: "'") {
                // `RESOLVE=`, printed without a line break; accept one anyway.
                guard output[pos...].isEmpty || Array(output[pos...]) == [0x0A] else {
                    throw ParseError.malformed("RESOLVE has no quoted value and is not the end")
                }
                pos = output.count
                values.append("")
                continue
            }
            guard output[pos...].first == UInt8(ascii: "'") else { throw ParseError.malformed("\(key) has no quoted value") }
            pos += 1
            guard let close = output[pos...].firstIndex(of: UInt8(ascii: "'")) else {
                throw ParseError.malformed("\(key) has no closing quote")
            }
            let value = output[pos..<close]
            guard value.allSatisfy({ (0x20...0x7E).contains($0) }) else {
                throw ParseError.invalidValue(key: key, reason: "not printable ASCII on one line")
            }
            guard output[(close + 1)...].first == 0x0A else { throw ParseError.malformed("\(key) is not followed by a line break") }
            // openconnect prints an empty RESOLVE unquoted; a quoted one always has `host:address`.
            guard key != "RESOLVE" || !value.isEmpty else { throw ParseError.malformed("RESOLVE is quoted but empty") }
            pos = close + 2
            values.append(String(decoding: value, as: UTF8.self))
        }
        guard pos == output.count else { throw ParseError.malformed("there is more after RESOLVE") }
        return try OpenConnectAuthResult(
            cookie: values[0], host: values[1], connectURL: values[2], fingerprint: values[3], resolve: values[4])
    }

    /// The text openconnect 9.21 prints for this result (`parse` reads it back).
    public var output: String {
        "COOKIE='\(cookie)'\nHOST='\(host)'\nCONNECT_URL='\(connectURL)'\nFINGERPRINT='\(fingerprint)'\n"
            + (resolve.isEmpty ? "RESOLVE=" : "RESOLVE='\(resolve)'\n")
    }

    /// Checks that the sign-in ended at the profile's server, and returns the address for the tunnel run's
    /// `resolve` (nil when the profile's host is an IP address).
    ///
    /// - `CONNECT_URL` must be exactly `https://<host>[:<port>]/` for the profile's host (compared without
    ///   regard to case; an IPv6 literal in brackets) and port (left out when it is 443, as openconnect prints
    ///   it). No user info, query, fragment or path: AnyConnect connects without the user group, which only
    ///   the sign-in URL carries. Another host (load balancing) is refused in Phase 1.
    /// - `FINGERPRINT` must equal `serverCert` when the profile has a pin.
    /// - For a host name, `RESOLVE` must be `<that host>:<IP address>` and `HOST` that same address (in
    ///   brackets for IPv6). For an IP-address host, `RESOLVE`'s address and `HOST` must be that address
    ///   (any spelling of it). An empty `RESOLVE` fails.
    public func checkDestination(host profileHost: String, port: Int, serverCert: String) throws -> String? {
        guard serverCert.isEmpty || OpenConnectPin.isValid(serverCert) else { throw OpenConnectConfig.ValidationError.invalidServerCert }
        let (resolveAddress, address) = try Self.checkDestination(
            host: profileHost, port: port, connectURL: connectURL, resolve: resolve.isEmpty ? nil : resolve, requireResolve: true)
        guard serverCert.isEmpty || fingerprint == serverCert else { throw DestinationError.fingerprintMismatch }
        // HOST is the address openconnect connected to, as RESOLVE has it (an IPv6 address in brackets).
        guard let address, host == (OpenConnectSyntax.isIPv6Literal(address) ? "[\(address)]" : address) else {
            throw DestinationError.addressMismatch
        }
        return resolveAddress
    }

    /// The shared part of the check, also run by the helper on a start request (which carries no `HOST`,
    /// and no `resolve` for an IP-address host): `connectURL` and `resolve` for the profile's host and port.
    /// Returns the address for the root file's `resolve` (nil for an IP-address host) and the address
    /// `resolve` named (nil when there was none).
    static func checkDestination(
        host profileHost: String, port: Int, connectURL: String, resolve: String?, requireResolve: Bool
    ) throws -> (resolveAddress: String?, address: String?) {
        guard OpenConnectSyntax.isValidHost(profileHost) else { throw OpenConnectConfig.ValidationError.invalidHost }
        guard (1...65535).contains(port) else { throw OpenConnectConfig.ValidationError.invalidPort(port) }
        let expected = OpenConnectSyntax.serverURL(host: profileHost, port: port, usergroup: "")
        guard connectURL.lowercased() == expected else { throw DestinationError.otherServer(connectURL: connectURL) }

        let literalHost = OpenConnectSyntax.isIPLiteral(profileHost)
        guard let resolve else {
            guard literalHost && !requireResolve else { throw DestinationError.noResolvedAddress }
            return (nil, nil)
        }
        // openconnect prints its host name as the URL has it (an IPv6 literal in brackets), then the address.
        let namePrefix = OpenConnectSyntax.urlHost(profileHost) + ":"
        guard resolve.lowercased().hasPrefix(namePrefix) else { throw DestinationError.addressMismatch }
        let address = String(resolve.dropFirst(namePrefix.count))
        guard OpenConnectSyntax.isIPLiteral(address) else { throw DestinationError.addressMismatch }
        if literalHost {
            guard let want = OpenConnectSyntax.ipBytes(profileHost), OpenConnectSyntax.ipBytes(address) == want else {
                throw DestinationError.addressMismatch
            }
            return (nil, address)
        }
        return (address, address)
    }

    /// The root run's configuration for this sign-in (`checkDestination` first): the profile's host and port,
    /// this cookie, this `FINGERPRINT` as the only trusted key, and the address the sign-in used.
    public func tunnelConfig(host: String, port: Int, serverCert: String, scriptPath: String, tlsOnly: Bool) throws -> OpenConnectConfig {
        let address = try checkDestination(host: host, port: port, serverCert: serverCert)
        let config = OpenConnectConfig(
            host: host, port: port, cookie: cookie, serverCert: fingerprint, resolveAddress: address, scriptPath: scriptPath,
            tlsOnly: tlsOnly)
        try config.validate()
        return config
    }

    /// The helper's side of `tunnelConfig`: the root configuration from a start request's fields, with
    /// `connectURL` and `resolve` checked as `checkDestination` does (`resolve` is the sign-in's `RESOLVE`
    /// for a host name and nil for an IP-address host; `serverCert` the `FINGERPRINT` the sign-in accepted).
    public static func tunnelConfig(
        host: String, port: Int, connectURL: String, resolve: String?, cookie: String, serverCert: String, scriptPath: String,
        tlsOnly: Bool
    ) throws -> OpenConnectConfig {
        try checkPrintable(connectURL, key: "CONNECT_URL", maxBytes: maxConnectURLBytes, allowEmpty: false)
        if let resolve { try checkPrintable(resolve, key: "RESOLVE", maxBytes: maxResolveBytes, allowEmpty: false) }
        let (address, _) = try checkDestination(host: host, port: port, connectURL: connectURL, resolve: resolve, requireResolve: false)
        if OpenConnectSyntax.isIPLiteral(host), resolve != nil {
            // The client sends no resolve for an IP-address host.
            throw DestinationError.addressMismatch
        }
        let config = OpenConnectConfig(
            host: host, port: port, cookie: cookie, serverCert: serverCert, resolveAddress: address, scriptPath: scriptPath,
            tlsOnly: tlsOnly)
        try config.validate()
        return config
    }

    static func checkPrintable(_ s: String, key: String, maxBytes: Int, allowEmpty: Bool) throws {
        let bytes = s.utf8
        guard allowEmpty || !bytes.isEmpty else { throw ParseError.invalidValue(key: key, reason: "empty") }
        guard bytes.count <= maxBytes else { throw ParseError.invalidValue(key: key, reason: "longer than \(maxBytes) bytes") }
        guard bytes.allSatisfy({ (0x20...0x7E).contains($0) && $0 != UInt8(ascii: "'") }) else {
            throw ParseError.invalidValue(key: key, reason: "not printable ASCII without '")
        }
    }
}

/// Standard input for the sign-in run: one answer per line. openconnect gives the first line to the first
/// password field (`passwd-on-stdin`) and the next line to every later prompt (`non-inter`); it reads each
/// line with `fgets` into 4,096 bytes including the line break, removes only the LF (a CR would stay part
/// of the answer) and stops at a NUL. Layouts: `.combined` delivery is one line (the composed secret),
/// `.separate` two (the password, then the code).
public enum OpenConnectAnswers {
    public static let maxLineBytes = 4095

    /// The answers as bytes, each followed by "\n". Each must be 1–4,095 bytes without LF, CR or NUL; the
    /// error names the answer's position, never its value.
    public static func stdin(_ answers: [String]) throws -> [UInt8] {
        guard !answers.isEmpty else {
            throw OpenConnectConfig.ValidationError.invalidValue(field: "sign-in answers", reason: "there are none")
        }
        var out: [UInt8] = []
        for (n, answer) in answers.enumerated() {
            let field = "sign-in answer \(n + 1)"
            let bytes = Array(answer.utf8)
            guard !bytes.isEmpty else { throw OpenConnectConfig.ValidationError.invalidValue(field: field, reason: "empty") }
            guard bytes.count <= maxLineBytes else {
                throw OpenConnectConfig.ValidationError.invalidValue(field: field, reason: "longer than \(maxLineBytes) bytes")
            }
            guard !bytes.contains(where: { $0 == 0x0A || $0 == 0x0D || $0 == 0 }) else {
                throw OpenConnectConfig.ValidationError.invalidValue(field: field, reason: "contains a line break or NUL")
            }
            out += bytes
            out.append(0x0A)
        }
        return out
    }

    /// `.separate`: line 1 the password, line 2 the one-time code.
    public static func separate(password: String, code: String) throws -> [UInt8] { try stdin([password, code]) }

    /// `.combined`: the composed secret (password and code in the profile's template) on one line.
    public static func combined(_ secret: String) throws -> [UInt8] { try stdin([secret]) }
}
