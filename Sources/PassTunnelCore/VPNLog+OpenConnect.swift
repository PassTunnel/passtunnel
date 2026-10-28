import Foundation
import PassTunnelKit
import PassTunnelShared
import PassTunnelVPNConfig

/// Cisco AnyConnect: what openconnect 9.21 and PassTunnel's own hook write (docs/ARCHITECTURE.md, "Supervision
/// and log"). Two runs: the user's sign-in (`openconnect --authenticate`, its standard error, which
/// `AnyConnectSignIn` writes to the profile's log) and the helper's tunnel run (its log, which the helper
/// replaces when it starts the tunnel).
extension VPNLog {
    // MARK: the tunnel run

    /// What the hook (`vpn-hook`) last said about the session's network.
    public enum OpenConnectHookState: Equatable, Sendable {
        /// `passtunnel vpn-hook: utun5 up: …` (`VPNHook.Report`): the network is set up; connected.
        case up(VPNHook.Report)
        /// `passtunnel vpn-hook: setting up the network failed: <reason>`: the hook reverted what it had done
        /// and stopped openconnect (`PTError.setupFailed`).
        case failed(reason: String)
    }

    /// The last success or failure line of the hook, nil when there is none yet. Only whole lines that start
    /// with the hook's prefix count, and a success line only in exactly the form the hook writes
    /// (`VPNHook.Report.parse`); openconnect's own lines put a text of their own first.
    public static func openConnectHook(_ text: String) -> OpenConnectHookState? {
        var state: OpenConnectHookState?
        for line in text.split(whereSeparator: \.isNewline) where line.hasPrefix(VPNHook.linePrefix) {
            if line.hasPrefix(VPNHook.failurePrefix) {
                state = .failed(reason: String(line.dropFirst(VPNHook.failurePrefix.count)))
            } else if let report = VPNHook.Report.parse(line) {
                state = .up(report)
            }
        }
        return state
    }

    /// The hook's report when the session's network is up now (its last line is the success line).
    public static func openConnectReport(_ text: String) -> VPNHook.Report? {
        if case .up(let report) = openConnectHook(text) { return report }
        return nil
    }

    /// The session is up: the hook's last line is its success line. openconnect's own "Configured as …" is
    /// printed before the hook runs and marks nothing.
    public static func openConnectIsUp(_ text: String) -> Bool { openConnectReport(text) != nil }

    /// The first address the hook reported, "" when it reported none.
    public static func openConnectAddress(_ text: String) -> String? {
        openConnectReport(text).map { $0.addresses.first?.description ?? "" }
    }

    /// openconnect's last words when the server ended the session (main.c 2479–2521): the cookie was
    /// refused (exit 2) or the server terminated the session (exit 1). A new connect signs in afresh.
    static let openConnectServerEnded = ["Cookie was rejected by server; exiting.", "Session terminated by server; exiting."]

    /// The line (one of `openConnectServerEnded`) when the log has it.
    public static func openConnectServerEnd(_ text: String) -> String? {
        text.split(whereSeparator: \.isNewline).lazy.map { $0.trimmingCharacters(in: .whitespaces) }
            .first { openConnectServerEnded.contains($0) }
    }

    // MARK: the sign-in run

    /// Every request openconnect makes while signing in is logged before it is sent, as
    /// `POST https://<host>[:<port>]/<path>` (http.c 894). The first is the initial request
    /// (`<config-auth type="init">`), which carries no credentials; a form is only submitted, with the
    /// password and the code, in a later one. So the credentials can have left this computer only when there
    /// is a second (a redirect or a retried request counts too: on the safe side, the code is then treated as
    /// spent). Counted wherever it stands, since a prompt for a text field (printed without a line break,
    /// main.c 2706) can come first on the line. A server's own text can add such text after its first answer
    /// but never remove any, so it can only make this say "sent".
    public static func openConnectPosts(_ text: String) -> Int {
        text.components(separatedBy: openConnectPost).count - 1
    }

    static let openConnectPost = "POST https://"

    public static func openConnectCredentialsSent(_ text: String) -> Bool { openConnectPosts(text) >= 2 }

    /// The lines up to the first TLS session with the server ("Connected to HTTPS on …"): openconnect's own
    /// words only. After it, the server's text (form errors, messages, labels) is printed too and could
    /// imitate any line, so certificate and network failures are read from these lines alone.
    static func openConnectBeforeServer(_ text: String) -> [Substring] {
        var lines: [Substring] = []
        for line in text.split(whereSeparator: \.isNewline) {
            if line.hasPrefix("Connected to HTTPS on ") { break }
            lines.append(line)
        }
        return lines
    }

    /// openconnect refuses a server that asks for a CSD host scan when it has no `csd-wrapper` (auth.c
    /// 1176–1187), which PassTunnel never gives it.
    static let openConnectHostScanMarkers = [
        "Server asked us to run CSD hostscan", "Server asked us to download and run a 'Cisco Secure Desktop' trojan",
        "Running the 'Cisco Secure Desktop' trojan"
    ]

    /// The server's certificate or key was refused: openconnect's reason ("signer not found",
    /// "certificate expired"; "not the pinned key" when a pin did not match) and the pin of the key it saw,
    /// from its hint (`--servercert pin-sha256:…`, main.c 2613–2626). nil when the lines before the TLS
    /// session say nothing of the kind. With a pin openconnect still prints "Server certificate verify
    /// failed: …" for the CA check it then ignores, so that line alone is no failure.
    static func openConnectCertificateFailure(_ lines: [Substring]) -> (reason: String, pin: String?)? {
        var reason: String?
        var pin: String?
        var failed = false
        for raw in lines {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if let r = line.range(of: "Server certificate verify failed: ") {
                reason = String(line[r.upperBound...])
            } else if line.hasPrefix("None of the "), let r = line.range(of: " match server's certificate: ") {
                failed = true
                reason = "not the pinned key"
                let hint = String(line[r.upperBound...])
                if OpenConnectPin.isValid(hint) { pin = hint }
            } else if line.hasPrefix("Certificate from VPN server "), line.hasSuffix(" failed verification.") {
                failed = true
            } else if line.hasPrefix("--servercert ") {
                let hint = String(line.dropFirst("--servercert ".count))
                if OpenConnectPin.isValid(hint) { pin = hint }
            } else if line == "SSL connection failure: Error in the certificate." {
                failed = true
            }
        }
        guard failed else { return nil }
        return (reason ?? "certificate not trusted", pin)
    }

    /// The server was not reached, from the lines before the TLS session: its name did not resolve
    /// ("getaddrinfo failed for host 'vpn.example.com': nodename nor servname provided, or not known",
    /// ssl.c 410), or nothing answered ("Failed to connect to 192.0.2.10:443: Connection refused", ssl.c 514;
    /// "Failed to open HTTPS connection to …", http.c), or the TLS handshake failed ("SSL connection failure:
    /// …"). nil when they show nothing of the kind.
    static func openConnectUnreached(_ lines: [Substring]) -> Verdict? {
        var verdict: Verdict?
        for raw in lines {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("getaddrinfo failed for host "), let r = line.range(of: "': ") {
                return Verdict(kind: .hostNotFound, reason: String(line[r.upperBound...]))
            }
            if line.hasPrefix("Failed to connect to "), !line.hasPrefix("Failed to connect to host "),
                let r = line.range(of: ": ", options: .backwards)
            {
                verdict = Verdict(kind: .unreachable, reason: String(line[r.upperBound...]))
            } else if line.hasPrefix("SSL connection failure: ") {
                verdict = Verdict(kind: .unreachable, reason: String(line.dropFirst("SSL connection failure: ".count)))
            } else if line.hasPrefix("Failed to open HTTPS connection to ") || line.hasPrefix("Failed to connect to host ") {
                verdict = verdict ?? Verdict(kind: .unreachable, reason: "no connection")
            }
        }
        return verdict
    }

    /// Why a sign-in run that did not end with a session cookie failed, from its standard error (`text`, as
    /// written to the log) and its exit status (128 + the signal when one ended it). `server` names the
    /// server in messages ("vpn.example.com:8443"). In this order:
    /// 1. dyld stopped openconnect (`toolUnsupported`);
    /// 2. the server asked for a host scan (`hostScanRequired`);
    /// 3. before any TLS session with the server: its certificate refused (`serverCertificateRejected`), its
    ///    name not found (`hostNotFound`), no answer (`serverUnreachable`), all with nothing sent;
    /// 4. the group named in the profile is not among the server's ("Auth choice … not available");
    /// 5. the server asked for more answers than it was given ("User input required in non-interactive
    ///    mode"): `authFailed` after a submitted form (typically a wrong password, answered with a new form),
    ///    `signInNeedsMoreAnswers` before;
    /// 6. after a submitted form (`openConnectCredentialsSent`), `authFailed`, unless the run ended on a
    ///    connection that failed (`connectFailed`);
    /// 7. anything else: `connectFailed`.
    static func openConnectSignInError(_ text: String, status: Int32, server: String) -> PTError {
        let tail = tail(text)
        if status > 128, let reason = toolLoadFailure(text) { return .toolUnsupported(reason: reason, log: tail) }
        if openConnectHostScanMarkers.contains(where: { text.contains($0) }) { return .hostScanRequired(log: tail) }
        let early = openConnectBeforeServer(text)
        if let failure = openConnectCertificateFailure(early) {
            return .serverCertificateRejected(reason: failure.reason, pin: failure.pin, log: tail)
        }
        let sent = openConnectCredentialsSent(text)
        if !sent, let verdict = openConnectUnreached(early) {
            if verdict.kind == .hostNotFound { return .hostNotFound(server: server, log: tail) }
            return .serverUnreachable(server: server, reason: verdict.reason ?? "no connection", log: tail)
        }
        if !sent, text.split(whereSeparator: \.isNewline).contains(where: { $0.hasPrefix("Auth choice \"") && $0.hasSuffix("\" not available") }) {
            return .invalidField("authgroup")
        }
        if text.contains("User input required in non-interactive mode") {
            return sent ? .authFailed(tail) : .signInNeedsMoreAnswers(log: tail)
        }
        guard sent else { return .connectFailed(tail) }
        // After the second request: did its connection fail (a redirect elsewhere, a closed connection)?
        if let first = text.range(of: openConnectPost), let second = text[first.upperBound...].range(of: openConnectPost),
            text[second.upperBound...].contains("Failed to open HTTPS connection to ")
        {
            return .connectFailed(tail)
        }
        return .authFailed(tail)
    }
}
