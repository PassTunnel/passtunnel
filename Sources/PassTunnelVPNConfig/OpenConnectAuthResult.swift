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
/// The cookie is a bearer secret, and the server chooses every other value too, so it could repeat the
/// cookie in any of them: no description, mirror or error of this type includes any value of the output,
/// only fixed text, key names and whether a value is present.
///
/// Trust model: `HOST`, `RESOLVE` and `FINGERPRINT` are written by openconnect itself, from the address it
/// connected to and the key it verified (`RESOLVE` from the `getaddrinfo` result it used, `FINGERPRINT`
/// from the certificate the TLS handshake checked); neither the server nor a network attacker can set them.
/// The checks below bind the tunnel run to that address and that key, so DNS or a key change between the
/// two runs cannot move the tunnel elsewhere. They do not protect against the requesting user: the start
/// request comes from the user's own process, which can already define a profile for any host, so the
/// address it reports cannot be verified independently in pure code (and no address range is refused:
/// tests run against a server on loopback).
///
/// Palo Alto GlobalProtect (`protocol: .gp`) prints the same five lines for the server the run ended on: after
/// the portal's hop, the gateway, often another host than the profile's. The cookie is then
/// `GlobalProtectCookie`'s shape, taken unchanged by the tunnel run, and the destination check binds the tunnel
/// to `CONNECT_URL`'s server (`checkDestination(host:port:skipPortal:profileServerCert:profileGatewayServerCert:)`).
public struct OpenConnectAuthResult: Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The protocol the sign-in ran, which decides the cookie's shape and the destination rules.
    public let `protocol`: OpenConnectProtocol
    /// `COOKIE` as openconnect printed it: for Cisco AnyConnect the bare `webvpn` value, or the STRAP form
    /// (`OpenConnectCookie`); for GlobalProtect `authcookie=…&…&computer=…` (`GlobalProtectCookie`).
    public let cookie: String
    /// The tunnel run's `cookie` option for it, which the helper is sent: for Cisco AnyConnect the value under
    /// its name (`OpenConnectCookie.tunnelOption`), for GlobalProtect the cookie unchanged.
    public let tunnelCookie: String
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
        /// The sign-in ended on another server (another host or port, or a path): refused for Cisco AnyConnect
        /// and for a GlobalProtect sign-in that skips the portal.
        case otherServer
        /// The key the sign-in accepted is not the profile's pinned key (for GlobalProtect: not one of its two).
        case fingerprintMismatch
        case noResolvedAddress
        case addressMismatch

        public var description: String {
            switch self {
            case .otherServer:
                return "The server sent the sign-in to another server; PassTunnel connects only to the profile's server."
            case .fingerprintMismatch: return "The sign-in reached a server key other than the profile's pinned key."
            case .noResolvedAddress: return "The sign-in did not report the address it connected to."
            case .addressMismatch: return "The sign-in reported an address that does not belong to the profile's server."
            }
        }
        public var errorDescription: String? { description }
    }

    /// Where a checked sign-in's tunnel goes: `CONNECT_URL`'s server (for Cisco AnyConnect always the
    /// profile's) and the address for the tunnel run's `resolve` (nil for an IP-address host). The host may be
    /// the server's choice (a GlobalProtect gateway), so the description shows no value.
    public struct Destination: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        /// A host name (lowercase) or an IP literal without brackets.
        public let host: String
        public let port: Int
        public let resolveAddress: String?

        public var description: String {
            "Destination(host: <redacted>, port: \(port), resolveAddress: \(resolveAddress == nil ? "nil" : "<redacted>"))"
        }
        public var debugDescription: String { description }
        public var customMirror: Mirror {
            Mirror(self, children: ["host": "<redacted>", "port": port, "resolveAddress": resolveAddress == nil ? "nil" : "<redacted>"])
        }
    }

    /// The fields, each checked as `parse` checks it (so the helper can rebuild and check a result it was sent).
    public init(
        protocol: OpenConnectProtocol = .anyconnect, cookie: String, host: String, connectURL: String, fingerprint: String, resolve: String
    ) throws {
        let tunnelCookie: String
        switch `protocol` {
        case .anyconnect:
            guard let option = OpenConnectCookie.tunnelOption(printed: cookie) else {
                throw ParseError.invalidValue(
                    key: "COOKIE",
                    reason: "neither a cookie value (cookie octets without ') nor openconnect's STRAP form, "
                        + "or longer than \(OpenConnectConfig.maxCookieBytes) bytes under its name")
            }
            tunnelCookie = option
        case .gp:
            guard GlobalProtectCookie.isValidTunnelOption(cookie) else {
                throw ParseError.invalidValue(
                    key: "COOKIE",
                    reason: "not openconnect's GlobalProtect cookie (authcookie, user and computer, URL-encoded, in its order), "
                        + "or longer than \(OpenConnectConfig.maxCookieBytes) bytes")
            }
            tunnelCookie = cookie
        }
        try Self.checkPrintable(host, key: "HOST", maxBytes: Self.maxHostBytes, allowEmpty: false)
        try Self.checkPrintable(connectURL, key: "CONNECT_URL", maxBytes: Self.maxConnectURLBytes, allowEmpty: false)
        guard OpenConnectPin.isValid(fingerprint) else {
            throw ParseError.invalidValue(key: "FINGERPRINT", reason: "not a full pin-sha256: pin")
        }
        try Self.checkPrintable(resolve, key: "RESOLVE", maxBytes: Self.maxResolveBytes, allowEmpty: true)
        self.protocol = `protocol`
        self.cookie = cookie
        self.tunnelCookie = tunnelCookie
        self.host = host
        self.connectURL = connectURL
        self.fingerprint = fingerprint
        self.resolve = resolve
    }

    /// Fixed placeholders only (see the type's note): every value came from the server's side.
    public var description: String {
        "OpenConnectAuthResult(cookie: <redacted>, host: <redacted>, connectURL: <redacted>, fingerprint: <redacted>, "
            + "resolve: \(resolve.isEmpty ? "<none>" : "<redacted>"))"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(
            self,
            children: [
                "cookie": "<redacted>", "host": "<redacted>", "connectURL": "<redacted>", "fingerprint": "<redacted>",
                "resolve": resolve.isEmpty ? "<none>" : "<redacted>"
            ])
    }

    public static func parse(_ output: String, protocol: OpenConnectProtocol = .anyconnect) throws -> OpenConnectAuthResult {
        try parse(Array(output.utf8), protocol: `protocol`)
    }

    public static func parse(_ output: [UInt8], protocol: OpenConnectProtocol = .anyconnect) throws -> OpenConnectAuthResult {
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
            protocol: `protocol`, cookie: values[0], host: values[1], connectURL: values[2], fingerprint: values[3], resolve: values[4])
    }

    /// The text openconnect 9.21 prints for this result (`parse` reads it back).
    public var output: String {
        "COOKIE='\(cookie)'\nHOST='\(host)'\nCONNECT_URL='\(connectURL)'\nFINGERPRINT='\(fingerprint)'\n"
            + (resolve.isEmpty ? "RESOLVE=" : "RESOLVE='\(resolve)'\n")
    }

    /// Checks that a Cisco AnyConnect sign-in ended at the profile's server, and returns the address for the
    /// tunnel run's `resolve` (nil when the profile's host is an IP address).
    ///
    /// - `CONNECT_URL` must be `https://<host>[:<port>]/` as openconnect prints it: the profile's host
    ///   (a name compared without regard to case; an IP literal compared as an address, an IPv6 literal in
    ///   brackets), the profile's port (left out when it is 443), and no user info, query, fragment or path
    ///   (AnyConnect connects without the user group, which only the sign-in URL carries). Another host
    ///   (load balancing) is refused in Phase 1.
    /// - `FINGERPRINT` must equal `profileServerCert` when the profile has a pin.
    /// - For a host name, `RESOLVE` must be `<that host>:<IP address>` and `HOST` that same address (in
    ///   brackets for IPv6). For an IP-address host, `RESOLVE`'s address and `HOST` must be that address
    ///   (any spelling of it). An empty `RESOLVE` fails.
    public func checkDestination(host profileHost: String, port: Int, profileServerCert: String) throws -> String? {
        try checkDestination(
            host: profileHost, port: port, skipPortal: false, profileServerCert: profileServerCert, profileGatewayServerCert: ""
        ).resolveAddress
    }

    /// Checks where the sign-in ended, by its protocol's rules, and returns the server the tunnel goes to with
    /// the address for its `resolve`.
    ///
    /// - Cisco AnyConnect: as `checkDestination(host:port:profileServerCert:)`; `skipPortal` must be false and
    ///   `profileGatewayServerCert` empty. The destination is the profile's host and port.
    /// - GlobalProtect: `CONNECT_URL` (`https://<host>[:<port>]/`, no path) names the profile's server (a gateway
    ///   on the portal's host, `skipPortal`, the no-portal fallback) or, without `skipPortal`, another server: the
    ///   gateway the portal sent the run to. That this server came only as the portal's hop (the run's requests
    ///   named at most the profile's server and then this one) is read from the run's standard error by the
    ///   caller, not here. `RESOLVE` and `HOST` are checked against `CONNECT_URL`'s host as for Cisco AnyConnect
    ///   against the profile's, and `FINGERPRINT` must be one of the profile's pins (`profileServerCert`,
    ///   `profileGatewayServerCert`) when it has any. The destination is `CONNECT_URL`'s host (lowercase, an IPv6
    ///   literal without brackets) and port.
    public func checkDestination(
        host profileHost: String, port: Int, skipPortal: Bool, profileServerCert: String, profileGatewayServerCert: String
    ) throws -> Destination {
        typealias E = OpenConnectConfig.ValidationError
        let destinationHost: String
        let destinationPort: Int
        switch self.protocol {
        case .anyconnect:
            guard !skipPortal else { throw E.invalidValue(field: "skip portal", reason: OpenConnectConfig.globalProtectOnly) }
            guard profileGatewayServerCert.isEmpty else {
                throw E.invalidValue(field: "gateway server certificate", reason: OpenConnectConfig.globalProtectOnly)
            }
            (destinationHost, destinationPort) = (profileHost, port)
        case .gp:
            guard OpenConnectSyntax.isValidHost(profileHost) else { throw E.invalidHost }
            guard (1...65535).contains(port) else { throw E.invalidPort(port) }
            guard let url = OpenConnectSyntax.parseServerURL(connectURL.lowercased()), url.path.isEmpty else {
                throw DestinationError.otherServer
            }
            let sameHost =
                OpenConnectSyntax.isIPLiteral(profileHost)
                ? OpenConnectSyntax.ipBytes(url.host) == OpenConnectSyntax.ipBytes(profileHost) : url.host == profileHost.lowercased()
            // Another server only as the portal's hop, which a sign-in to the gateway alone never makes.
            guard (sameHost && url.port == port) || !skipPortal else { throw DestinationError.otherServer }
            (destinationHost, destinationPort) = (url.host, url.port)
        }
        let (resolveAddress, address) = try Self.checkDestination(
            host: destinationHost, port: destinationPort, connectURL: connectURL, resolve: resolve.isEmpty ? nil : resolve,
            fingerprint: fingerprint, pins: [profileServerCert, profileGatewayServerCert], client: true)
        // HOST is the address openconnect connected to, as RESOLVE has it (an IPv6 address in brackets).
        guard let address, host == (OpenConnectSyntax.isIPv6Literal(address) ? "[\(address)]" : address) else {
            throw DestinationError.addressMismatch
        }
        return Destination(host: destinationHost, port: destinationPort, resolveAddress: resolveAddress)
    }

    /// The check shared by the client (`checkDestination`) and the helper (the static `tunnelConfig`, whose
    /// request carries no `HOST`, and no `resolve` for an IP-address host), for the server the tunnel goes to
    /// (`host`, `port`). `pins`: the profile's pins, each empty or full; when any is set, `fingerprint` must be
    /// one of them. Returns the address for the root file's `resolve` (nil for an IP-address host) and the
    /// address `resolve` named (nil when none).
    static func checkDestination(
        host profileHost: String, port: Int, connectURL: String, resolve: String?, fingerprint: String, pins: [String], client: Bool
    ) throws -> (resolveAddress: String?, address: String?) {
        typealias E = OpenConnectConfig.ValidationError
        guard OpenConnectSyntax.isValidHost(profileHost) else { throw E.invalidHost }
        guard (1...65535).contains(port) else { throw E.invalidPort(port) }
        guard pins.allSatisfy({ $0.isEmpty || OpenConnectPin.isValid($0) }) else { throw E.invalidServerCert }
        guard OpenConnectPin.isValid(fingerprint) else { throw E.invalidServerCert }

        let literalHost = OpenConnectSyntax.isIPLiteral(profileHost)
        guard let url = OpenConnectSyntax.parseServerURL(connectURL.lowercased()), url.port == port, url.path.isEmpty else {
            throw DestinationError.otherServer
        }
        if literalHost {
            guard let want = OpenConnectSyntax.ipBytes(profileHost), OpenConnectSyntax.ipBytes(url.host) == want else {
                throw DestinationError.otherServer
            }
        } else {
            guard url.host == profileHost.lowercased() else { throw DestinationError.otherServer }
        }
        let pinned = pins.filter { !$0.isEmpty }
        guard pinned.isEmpty || pinned.contains(fingerprint) else { throw DestinationError.fingerprintMismatch }

        guard let resolve else {
            // The client always has openconnect's RESOLVE; the helper gets none for an IP-address host.
            guard literalHost && !client else { throw DestinationError.noResolvedAddress }
            return (nil, nil)
        }
        // The helper is sent a resolve only for a host name.
        guard client || !literalHost else { throw DestinationError.addressMismatch }
        // openconnect prints its host name as the URL has it (an IPv6 literal in brackets), then the address.
        let namePrefix = OpenConnectSyntax.urlHost(profileHost) + ":"
        guard resolve.lowercased().hasPrefix(namePrefix) else { throw DestinationError.addressMismatch }
        let address = String(resolve.dropFirst(namePrefix.count))
        guard OpenConnectSyntax.isIPLiteral(address) else { throw DestinationError.addressMismatch }
        if literalHost {
            guard OpenConnectSyntax.ipBytes(address) == OpenConnectSyntax.ipBytes(profileHost) else { throw DestinationError.addressMismatch }
            return (nil, address)
        }
        return (address, address)
    }

    /// The root run's configuration for a Cisco AnyConnect sign-in (`checkDestination` first): the profile's
    /// host and port, this cookie under its name (`tunnelCookie`), this `FINGERPRINT` as the only trusted key,
    /// and the address the sign-in used.
    public func tunnelConfig(host: String, port: Int, profileServerCert: String, scriptPath: String, tlsOnly: Bool) throws
        -> OpenConnectConfig
    {
        try tunnelConfig(
            host: host, port: port, skipPortal: false, profileServerCert: profileServerCert, profileGatewayServerCert: "",
            scriptPath: scriptPath, tlsOnly: tlsOnly, disableIPv6: false)
    }

    /// The root run's configuration for this sign-in, by its protocol (`checkDestination` first): the
    /// destination's host and port (for GlobalProtect the gateway's), `tunnelCookie`, this `FINGERPRINT` as the
    /// only trusted key, and the address the sign-in used. `disableIPv6` is for GlobalProtect only.
    public func tunnelConfig(
        host: String, port: Int, skipPortal: Bool, profileServerCert: String, profileGatewayServerCert: String, scriptPath: String,
        tlsOnly: Bool, disableIPv6: Bool
    ) throws -> OpenConnectConfig {
        let destination = try checkDestination(
            host: host, port: port, skipPortal: skipPortal, profileServerCert: profileServerCert,
            profileGatewayServerCert: profileGatewayServerCert)
        let config = OpenConnectConfig(
            protocol: self.protocol, host: destination.host, port: destination.port, cookie: tunnelCookie, serverCert: fingerprint,
            resolveAddress: destination.resolveAddress, scriptPath: scriptPath, tlsOnly: tlsOnly, disableIPv6: disableIPv6)
        try config.validate()
        return config
    }

    /// The helper's side of `tunnelConfig` for Cisco AnyConnect: the root configuration from a start request's
    /// fields, checked as `checkDestination` does. `resolve` is the sign-in's `RESOLVE` for a host name and nil
    /// for an IP-address host; `serverCert` the `FINGERPRINT` the sign-in accepted; `profileServerCert` the
    /// profile's own pin (normalized) or empty, which `serverCert` must then equal. See the type's note for
    /// what this binding does and does not protect against.
    public static func tunnelConfig(
        host: String, port: Int, connectURL: String, resolve: String?, cookie: String, serverCert: String, profileServerCert: String,
        scriptPath: String, tlsOnly: Bool
    ) throws -> OpenConnectConfig {
        try tunnelConfig(
            protocol: .anyconnect, host: host, port: port, connectURL: connectURL, resolve: resolve, cookie: cookie,
            serverCert: serverCert, profileServerCert: profileServerCert, profileGatewayServerCert: "", scriptPath: scriptPath,
            tlsOnly: tlsOnly, disableIPv6: false)
    }

    /// The helper's side of `tunnelConfig`, by protocol. `host` and `port` are the server the tunnel connects to
    /// (for GlobalProtect the gateway the sign-in ended on), which `connectURL` must name exactly; `cookie` the
    /// tunnel run's option (`OpenConnectCookie`'s or `GlobalProtectCookie`'s shape); `serverCert` must equal
    /// `profileServerCert` or `profileGatewayServerCert` when either is set (the latter empty for Cisco
    /// AnyConnect); `disableIPv6` for GlobalProtect only. The rest as for Cisco AnyConnect.
    public static func tunnelConfig(
        protocol: OpenConnectProtocol, host: String, port: Int, connectURL: String, resolve: String?, cookie: String,
        serverCert: String, profileServerCert: String, profileGatewayServerCert: String, scriptPath: String, tlsOnly: Bool,
        disableIPv6: Bool
    ) throws -> OpenConnectConfig {
        guard `protocol` == .gp || profileGatewayServerCert.isEmpty else {
            throw OpenConnectConfig.ValidationError.invalidValue(
                field: "gateway server certificate", reason: OpenConnectConfig.globalProtectOnly)
        }
        try checkPrintable(connectURL, key: "CONNECT_URL", maxBytes: maxConnectURLBytes, allowEmpty: false)
        if let resolve { try checkPrintable(resolve, key: "RESOLVE", maxBytes: maxResolveBytes, allowEmpty: false) }
        let (address, _) = try checkDestination(
            host: host, port: port, connectURL: connectURL, resolve: resolve, fingerprint: serverCert,
            pins: [profileServerCert, profileGatewayServerCert], client: false)
        let config = OpenConnectConfig(
            protocol: `protocol`, host: host, port: port, cookie: cookie, serverCert: serverCert, resolveAddress: address,
            scriptPath: scriptPath, tlsOnly: tlsOnly, disableIPv6: disableIPv6)
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
