import Foundation
import PassTunnelKit
import PassTunnelVPNConfig

#if canImport(Glibc)
import Glibc
#endif

/// Palo Alto GlobalProtect: what openconnect 9.21 (and 9.01–9.12 where they differ) writes while signing in to a
/// portal and its gateway, and in the tunnel run (docs/ARCHITECTURE.md, "Palo Alto GlobalProtect backend"). The
/// sign-in's standard error is partly the servers' text (form messages, labels), so, as for Cisco AnyConnect
/// (`VPNLog+OpenConnect.swift`), only whole LF lines of printable ASCII in openconnect's exact wording count, and
/// the server's text can only make a verdict more careful (sent, refused, unusable), never less.
extension VPNLog {
    // MARK: requests

    /// A request openconnect logged before sending it: `POST https://<host>[:<port>]/<path>` (http.c 893–899).
    struct GlobalProtectRequest: Equatable {
        /// Lowercase; an IPv6 literal without brackets.
        var host: String
        var port: Int
        /// What follows the `/` after the host, to the end of the line.
        var path: String

        /// The portal's prelogin and the gateway's: the only requests that carry no credentials
        /// (auth-globalprotect.c 685–700).
        var isPrelogin: Bool { VPNLog.globalProtectPreloginPaths.contains(path) }
        var isGatewayPrelogin: Bool { path.hasPrefix("ssl-vpn/prelogin.esp?") && isPrelogin }
        var isPortalConfig: Bool { path == "global-protect/getconfig.esp" }
        var isGatewayLogin: Bool { path == "ssl-vpn/login.esp" }

        func isServer(host other: String, port otherPort: Int) -> Bool {
            port == otherPort && VPNLog.sameHost(host, other)
        }
    }

    static let globalProtectPreloginPaths: Set<String> = [
        "global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac",
        "global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux",
        "ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac",
        "ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux"
    ]

    /// Every `POST https://` in `text`, wherever it stands (a prompt is printed without a line break, so a request
    /// can follow it on the same line), in order; nil for one that does not read as a request to a server (cut off
    /// at the end of the text, or not a host and port).
    static func globalProtectRequests(_ text: Substring) -> [GlobalProtectRequest?] {
        var out: [GlobalProtectRequest?] = []
        var rest = text[...]
        while let r = rest.range(of: openConnectPost) {
            let after = rest[r.upperBound...]
            guard let end = after.firstIndex(of: "\n") else {
                out.append(nil)  // the line is not complete
                break
            }
            out.append(parseRequest(after[..<end]))
            rest = after[end...]
        }
        return out
    }

    static func globalProtectRequests(_ text: String) -> [GlobalProtectRequest?] { globalProtectRequests(text[...]) }

    /// `<host>[:<port>]/<path>` as http.c prints it: the host as openconnect holds it (an IPv6 literal in brackets),
    /// the port only when it is not 443.
    private static func parseRequest(_ s: Substring) -> GlobalProtectRequest? {
        guard let slash = s.firstIndex(of: "/") else { return nil }
        let authority = s[..<slash]
        let path = String(s[s.index(after: slash)...])
        var host: Substring
        var portText: Substring?
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else { return nil }
            host = authority[authority.index(after: authority.startIndex)..<close]
            let after = authority[authority.index(after: close)...]
            if !after.isEmpty {
                guard after.hasPrefix(":") else { return nil }
                portText = after.dropFirst()
            }
            guard OpenConnectAuthConfig.isIPv6Literal(String(host)) else { return nil }
        } else {
            let parts = authority.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            host = parts[0]
            if parts.count == 2 { portText = parts[1] }
            guard OpenConnectAuthConfig.isValidHost(String(host)) else { return nil }
        }
        var port = 443
        if let portText {
            guard (1...5).contains(portText.count), portText.utf8.allSatisfy({ (48...57).contains($0) }), let p = Int(portText),
                (1...65535).contains(p)
            else { return nil }
            port = p
        }
        return GlobalProtectRequest(host: host.lowercased(), port: port, path: path)
    }

    /// Two spellings of one host: names without regard to case, IP literals as addresses.
    static func sameHost(_ a: String, _ b: String) -> Bool {
        if let x = ipBytes(a), let y = ipBytes(b) { return x == y }
        return a.lowercased() == b.lowercased()
    }

    private static func ipBytes(_ s: String) -> [UInt8]? {
        var v4 = in_addr()
        if s.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return withUnsafeBytes(of: &v4) { Array($0) } }
        var v6 = in6_addr()
        if !s.contains("%"), s.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 { return withUnsafeBytes(of: &v6) { Array($0) } }
        return nil
    }

    // MARK: credentials sent

    /// Whether the password or a code can have left this computer (docs/ARCHITECTURE.md, "Failures (G4)"): any
    /// request that is not a prelogin (`…/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=<Mac|Linux>`,
    /// `…/ssl-vpn/prelogin.esp?…`), wherever it stands. A portal and a gateway prelogin of the no-portal fallback are
    /// two requests and still none sent; a redirected prelogin is printed with the redirect's path and so counts
    /// as sent, as does a request cut off at the end. Count it over the whole of standard error as it came: a
    /// caller with only part of it must take the credentials as sent.
    public static func globalProtectCredentialsSent(_ text: String) -> Bool {
        globalProtectRequests(text).contains { $0?.isPrelogin != true }
    }

    // MARK: where the sign-in went

    /// The two-server rule (docs/ARCHITECTURE.md, "Where the sign-in may go"): the run's requests name the
    /// profile's server (`host`, `port`) and the server the sign-in ended on (`destination`, `CONNECT_URL`'s), and
    /// nothing else. When the two differ (the portal's hop, without `skip_portal`), the profile's server gets only
    /// `global-protect/…` requests and the other one only `ssl-vpn/…` requests, all after the portal's
    /// `getconfig.esp`. A request that does not read as one fails the rule. Read from the whole of standard error
    /// as it came.
    static func globalProtectRouteIsAllowed(
        _ text: String, host: String, port: Int, destination: OpenConnectAuthResult.Destination
    ) -> Bool {
        let requests = globalProtectRequests(text)
        let sameServer = destination.port == port && sameHost(destination.host, host)
        var portalConfig = false
        for request in requests {
            guard let request else { return false }
            if request.isServer(host: host, port: port) {
                if !sameServer {
                    guard request.path.hasPrefix("global-protect/") else { return false }
                    if request.isPortalConfig { portalConfig = true }
                }
            } else if request.isServer(host: destination.host, port: destination.port) {
                guard portalConfig, request.path.hasPrefix("ssl-vpn/") else { return false }
            } else {
                return false
            }
        }
        return true
    }

    /// The server the run went to after the portal, as `<host>`/`<port>` of its first request to another server
    /// than the profile's (`host`, `port`); nil when it went nowhere else. Read from the redacted text: a host that
    /// held a secret is masked and reads as no request.
    static func globalProtectOtherServer(_ text: String, host: String, port: Int) -> GlobalProtectRequest? {
        for case let request? in globalProtectRequests(text) where !request.isServer(host: host, port: port) {
            return request
        }
        return nil
    }

    // MARK: standard input's second part

    /// What the sign-in's standard error so far says about the second part of standard input (`GlobalProtectAnswers`).
    public enum GlobalProtectSecondPart: Equatable, Sendable {
        /// Nothing yet: keep standard input open.
        case pending
        /// The second sign-in shows: a gateway prelogin after the portal's `getconfig.esp`. Its answers are written
        /// once the first code's window has ended too.
        case due
        /// None can follow: close standard input without it.
        case none
    }

    /// Reads the complete lines of the sign-in's standard error so far, in order (docs/ARCHITECTURE.md, "The answers,
    /// and the second code"). `host`, `port`: the profile's server. `.none` as soon as one of these shows:
    /// - a request the two-server rule refuses so far (`globalProtectRouteIsAllowed`): before the portal's
    ///   `getconfig.esp` any server but the profile's; after it, the first `ssl-vpn/…` request names the gateway, and
    ///   every later request must be an `ssl-vpn/…` one to that server; or a request that does not read as one;
    /// - `Unexpected 512 result from server` (http.c 986–988: a refused password or code) answering the portal's
    ///   `getconfig.esp`, or a `login.esp` after a gateway prelogin (not the refusal of openconnect's replay of the
    ///   portal's answer, which leads to the second sign-in);
    /// - openconnect asking for the gateway: the portal lists two or more (`N gateway servers available:`) and
    ///   the profile names none (`gateway` empty), or `Auth choice "<gateway>" not available` (or `matches multiple
    ///   options`, main.c 2664–2700) for the profile's gateway.
    ///
    /// `.due` when, after all lines, the latest request is that gateway's prelogin
    /// (`POST https://<gateway>/ssl-vpn/prelogin.esp…`, after the portal's `getconfig.esp`) and openconnect has
    /// printed a prompt after it (an unfinished last line: it waits for the answer). The server's text can stand among
    /// these lines (a form's message), so the caller also waits until standard error has not changed for a while
    /// (`GlobalProtectSignIn.promptQuietTime`): text that only looks like the second sign-in is followed by
    /// openconnect's own next request, which then decides. `.pending` otherwise.
    public static func globalProtectSecondPart(_ text: String, gateway: String, host: String, port: Int) -> GlobalProtectSecondPart {
        var portalConfig = false
        var gatewayPrelogin = false
        var destination: GlobalProtectRequest?
        var last: GlobalProtectRequest?
        for line in openConnectLines(text) {
            if line.contains(openConnectPost) {
                for request in globalProtectRequests(line + "\n") {
                    guard let request else { return .none }
                    if let destination {
                        guard request.isServer(host: destination.host, port: destination.port), request.path.hasPrefix("ssl-vpn/") else {
                            return .none
                        }
                    } else if portalConfig && request.path.hasPrefix("ssl-vpn/") {
                        destination = request
                    } else {
                        guard request.isServer(host: host, port: port) else { return .none }
                    }
                    if request.isPortalConfig { portalConfig = true }
                    if request.isGatewayPrelogin { gatewayPrelogin = true }
                    last = request
                }
                continue
            }
            if line == "Unexpected 512 result from server" {
                if last?.isPortalConfig == true { return .none }
                if last?.isGatewayLogin == true && gatewayPrelogin { return .none }
            }
            if gateway.isEmpty, let count = gatewayCount(line), count >= 2 { return .none }
            if !gateway.isEmpty, line == "Auth choice \"\(gateway)\" not available" || line == "Auth choice \"\(gateway)\" matches multiple options" {
                return .none
            }
        }
        guard let destination, let last, portalConfig, last.isGatewayPrelogin,
            last.isServer(host: destination.host, port: destination.port), !text.isEmpty, !text.hasSuffix("\n")
        else { return .pending }
        return .due
    }

    // MARK: the portal's gateways

    /// The most gateway labels a failure carries, and the longest label.
    public static let maxGatewayLabels = 32
    public static let maxGatewayLabelBytes = 64

    /// `N` of openconnect's `N gateway servers available:` (auth-globalprotect.c 578).
    static func gatewayCount(_ line: Substring) -> Int? {
        let suffix = " gateway servers available:"
        guard line.hasSuffix(suffix) else { return nil }
        let digits = line.dropLast(suffix.count)
        guard (1...4).contains(digits.count), digits.utf8.allSatisfy({ (48...57).contains($0) }) else { return nil }
        return Int(digits)
    }

    /// The portal's gateways as openconnect listed them: the last `N gateway servers available:` line and the N lines
    /// after it, each `  <label> (<host>)` with ` [priority P]` or ` [unprioritized]` after it (9.20 and later;
    /// 9.01–9.12 print neither). `count` is N; `labels` the labels in that order, only when every one of the N lines
    /// reads as one, printable ASCII of 1–`maxGatewayLabelBytes` bytes, and N is at most `maxGatewayLabels`
    /// (else nil: the front ends point to the log). Read from the redacted text: the labels are the portal's, and a
    /// secret the server repeated in one is masked. nil when the run listed no gateways.
    public static func globalProtectGateways(_ text: String) -> (count: Int, labels: [String]?)? {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).dropLast()
        guard let at = lines.lastIndex(where: { isPrintable($0) && gatewayCount($0) != nil }), let count = gatewayCount(lines[at]) else {
            return nil
        }
        let entries = lines[(at + 1)...].prefix(count)
        guard count <= maxGatewayLabels, entries.count == count else { return (count, nil) }
        var labels: [String] = []
        for entry in entries {
            guard isPrintable(entry), let label = gatewayLabel(entry) else { return (count, nil) }
            labels.append(label)
        }
        return (count, labels)
    }

    /// `  <label> (<host>)[ [priority P]| [unprioritized]]` → the label.
    static func gatewayLabel(_ line: Substring) -> String? {
        guard line.hasPrefix("  ") else { return nil }
        var rest = line.dropFirst(2)
        if rest.hasSuffix(" [unprioritized]") {
            rest = rest.dropLast(" [unprioritized]".count)
        } else if rest.hasSuffix("]"), let open = rest.range(of: " [priority ", options: .backwards) {
            var number = rest[open.upperBound..<rest.index(before: rest.endIndex)]
            if number.hasPrefix("-") { number = number.dropFirst() }
            guard (1...10).contains(number.count), number.utf8.allSatisfy({ (48...57).contains($0) }) else { return nil }
            rest = rest[..<open.lowerBound]
        }
        guard rest.hasSuffix(")"), let open = rest.range(of: " (", options: .backwards) else { return nil }
        let host = rest[open.upperBound..<rest.index(before: rest.endIndex)]
        let label = rest[..<open.lowerBound]
        guard !host.isEmpty, !host.contains(" "), (1...maxGatewayLabelBytes).contains(label.utf8.count) else { return nil }
        return String(label)
    }

    private static func isPrintable(_ line: Substring) -> Bool { line.utf8.allSatisfy { (0x20...0x7E).contains($0) } }

    /// openconnect asked for the gateway and none was chosen: the portal listed two or more and the profile names
    /// none, or the profile's gateway is not among them (or names several).
    static func globalProtectAskedForGateway(_ lines: [Substring], gateway: String) -> Bool {
        if gateway.isEmpty {
            return lines.contains { (gatewayCount($0) ?? 0) >= 2 }
        }
        return lines.contains {
            $0 == "Auth choice \"\(gateway)\" not available" || $0 == "Auth choice \"\(gateway)\" matches multiple options"
        }
    }

    // MARK: single sign-on

    /// openconnect's command-line tool has no web view: a SAML prelogin ends the sign-in with this line
    /// (auth-globalprotect.c 151–154; 9.01 and 9.12 write `:field_name`).
    static let globalProtectSAMLLines: Set<String> = [
        "When SAML authentication is complete, specify destination form field by appending field_name to login URL.",
        "When SAML authentication is complete, specify destination form field by appending :field_name to login URL."
    ]

    /// The server asked for single sign-on (SAML), wherever the line stands.
    public static func globalProtectSSORequired(_ text: String) -> Bool {
        openConnectLines(text).contains { globalProtectSAMLLines.contains(String($0)) }
    }

    // MARK: the gateway's key

    /// The gateway's certificate or key was refused (docs/ARCHITECTURE.md, "Trust: two keys"): in the lines after
    /// the first request to `gateway` (the server the run went to after the portal) and before a TLS session with
    /// it, openconnect's `Certificate from VPN server "<that host>" failed verification.` with its
    /// `    --servercert pin-sha256:…` hint, or `None of the N fingerprint(s) specified via --servercert match
    /// server's certificate: pin-sha256:…`. The reason and the hinted pin as for the portal
    /// (`openConnectCertificateFailure`); nil otherwise.
    static func globalProtectGatewayCertificateFailure(
        _ text: String, gateway: GlobalProtectRequest
    ) -> (reason: String, pin: String?)? {
        var after: [Substring] = []
        var seen = false
        for line in openConnectLines(text) {
            if !seen {
                if line.contains(openConnectPost),
                    globalProtectRequests(line + "\n").contains(where: { $0?.isServer(host: gateway.host, port: gateway.port) == true })
                {
                    seen = true
                }
                continue
            }
            if line.hasPrefix("Connected to HTTPS on ") { break }
            if line.hasPrefix("Certificate from VPN server \""), line.hasSuffix("\" failed verification.") {
                let named = line.dropFirst("Certificate from VPN server \"".count).dropLast("\" failed verification.".count)
                let host = named.hasPrefix("[") && named.hasSuffix("]") ? named.dropFirst().dropLast() : named
                guard sameHost(String(host), gateway.host) else { return nil }
            }
            after.append(line)
        }
        return openConnectCertificateFailure(after)
    }

    // MARK: failures

    /// Why a GlobalProtect sign-in run that did not end with a session cookie failed (docs/ARCHITECTURE.md,
    /// "Failures (G4)"), from its whole redacted standard error and exit status. `credentialsSent`: the caller's
    /// verdict over the complete output (`globalProtectCredentialsSent`, or true with only part of it). `gateway`:
    /// the profile's. `host`, `port`: the profile's server. `server` names it in messages. In this order:
    /// 1. dyld stopped openconnect: `toolUnsupported`;
    /// 2. the SAML line: `ssoRequired` (whether anything was sent is the caller's `credentialsSent`);
    /// 3. once sent: openconnect asked for the gateway (`invalidField("gateway")`, the labels from
    ///    `globalProtectGateways`), the gateway's key refused (`gatewayCertificateRejected`), else `authFailed`;
    /// 4. before anything was sent: from the lines before the first TLS session the portal's certificate
    ///    (`serverCertificateRejected`), its name (`hostNotFound`), no answer (`serverUnreachable`); "Server is
    ///    neither a GlobalProtect portal nor a gateway." (`invalidField("host")`); "User input required in
    ///    non-interactive mode" (`signInNeedsMoreAnswers`); else `connectFailed`.
    /// CSD's host scan lines are not read: they are Cisco AnyConnect's (`auth.c`).
    static func globalProtectSignInError(
        _ text: String, status: Int32, credentialsSent: Bool, gateway: String, host: String, port: Int, server: String
    ) -> PTError {
        let tail = tail(text)
        if status > 128, let reason = toolLoadFailure(text) { return .toolUnsupported(reason: reason, log: tail) }
        let lines = openConnectLines(text)
        if lines.contains(where: { globalProtectSAMLLines.contains(String($0)) }) { return .ssoRequired(log: tail) }
        if credentialsSent {
            if globalProtectAskedForGateway(lines, gateway: gateway) { return .invalidField("gateway") }
            if let other = globalProtectOtherServer(text, host: host, port: port),
                let failure = globalProtectGatewayCertificateFailure(text, gateway: other)
            {
                return .gatewayCertificateRejected(
                    gateway: OpenConnectAuthConfig.isIPv6Literal(other.host) ? "[\(other.host)]:\(other.port)" : "\(other.host):\(other.port)",
                    reason: failure.reason, pin: failure.pin, log: tail)
            }
            return .authFailed(tail)
        }
        let early = openConnectBeforeServer(text)
        if let failure = openConnectCertificateFailure(early) {
            return .serverCertificateRejected(reason: failure.reason, pin: failure.pin, log: tail)
        }
        if let verdict = openConnectUnreached(early) {
            if verdict.kind == .hostNotFound { return .hostNotFound(server: server, log: tail) }
            return .serverUnreachable(server: server, reason: verdict.reason ?? "no connection", log: tail)
        }
        if lines.contains(where: { $0 == "Server is neither a GlobalProtect portal nor a gateway." }) { return .invalidField("host") }
        if lines.contains(where: { $0 == "User input required in non-interactive mode" }) {
            return .signInNeedsMoreAnswers(log: tail)
        }
        return .connectFailed(tail)
    }

    /// The reason a failure shows for a server that is not a GlobalProtect portal or gateway.
    public static var notGlobalProtectServer: String { String(localized: "This server is not a GlobalProtect portal or gateway") }

    // MARK: the tunnel run (display only)

    /// openconnect's warning when the gateway asked for a host information report (HIP) it does not send
    /// (gpst.c 913–937, once per run): the three lines, whole, in this wording. Display only: the notice
    /// (`StatusNotice.hipReportNotSent`) decides nothing, since the log is partly the server's.
    public static func globalProtectHIPRequested(_ text: String) -> Bool {
        let lines = openConnectLines(text)
        let prefix = "WARNING: Server asked us to submit HIP report with md5sum "
        for i in lines.indices.dropLast(2) where lines[i].hasPrefix(prefix) && lines[i].hasSuffix(".") {
            let sum = lines[i].dropFirst(prefix.count).dropLast()
            guard sum.count == 32, sum.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { continue }
            if lines[i + 1] == "    VPN connectivity may be disabled or limited without HIP report submission.",
                lines[i + 2] == "    You need to provide a --csd-wrapper argument with the HIP report submission script."
            {
                return true
            }
        }
        return false
    }
}
