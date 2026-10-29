import Foundation
import PassTunnelKit
import PassTunnelShared
import PassTunnelVPNConfig

/// Cisco AnyConnect: what openconnect 9.21 and PassTunnel's own hook write (docs/ARCHITECTURE.md, "Supervision
/// and log"). Two runs: the user's sign-in (`openconnect --authenticate`, its standard error, which
/// `AnyConnectSignIn` writes to the profile's log) and the helper's tunnel run (its log, which the helper
/// replaces when it starts the tunnel).
///
/// A server chooses part of what openconnect prints (form errors and messages, the CONNECT reply's status
/// line, which may hold a CR), so none of this decides anything a server could gain from: whether the
/// tunnel is up or its set-up failed comes from the helper (`TunnelStatus`, from the hook's root-owned
/// record), and the sign-in's lines are read only in the exact form openconnect writes them, as whole
/// LF-terminated lines, mostly from before the first TLS session.
extension VPNLog {
    // MARK: lines

    /// The log's complete lines, split at LF only, without the ones that hold any other control byte or anything
    /// but printable ASCII: those are text a server sent (a CR could make a line look like two), never a line of
    /// openconnect's or the hook's own that is read here. What follows the last LF is not a line yet (the
    /// tool was writing it, or a server's text ends there) and is never read.
    static func openConnectLines(_ text: String) -> [Substring] {
        text.split(separator: "\n", omittingEmptySubsequences: false).dropLast().filter { line in
            line.utf8.allSatisfy { (0x20...0x7E).contains($0) }
        }
    }

    // MARK: the tunnel run (display only)

    /// What the hook's last line says, for display (the address shown, the routes and DNS kept for the
    /// overlap check): never whether the session is up, which is `TunnelStatus`. Only whole lines of printable
    /// ASCII that start with the hook's prefix count, a success line only in exactly the form the hook writes
    /// (`VPNHook.Report.parse`).
    public enum OpenConnectHookState: Equatable, Sendable {
        case up(VPNHook.Report)
        case failed(reason: String)
    }

    public static func openConnectHook(_ text: String) -> OpenConnectHookState? {
        var state: OpenConnectHookState?
        for line in openConnectLines(text) where line.hasPrefix(VPNHook.linePrefix) {
            if line.hasPrefix(VPNHook.failurePrefix) {
                state = .failed(reason: String(line.dropFirst(VPNHook.failurePrefix.count)))
            } else if let report = VPNHook.Report.parse(line) {
                state = .up(report)
            }
        }
        return state
    }

    /// The hook's report in the log, for display, when its last line is the success line and (when given) it
    /// names `interface`, the one the helper reported.
    public static func openConnectReport(_ text: String, interface: String? = nil) -> VPNHook.Report? {
        guard case .up(let report) = openConnectHook(text), interface == nil || report.interface == interface else { return nil }
        return report
    }

    /// The log's last line is the hook's success line (display only: the activity's "disconnected" wording).
    public static func openConnectIsUp(_ text: String) -> Bool { openConnectReport(text) != nil }

    /// The address to show for a session the helper reports up on `interface`: the first one of the hook's
    /// line, "" when the log has none for that interface.
    public static func openConnectAddress(_ text: String, interface: String?) -> String {
        openConnectReport(text, interface: interface)?.addresses.first?.description ?? ""
    }

    // MARK: the sign-in run

    /// Every request openconnect makes while signing in is logged before it is sent, as
    /// `POST https://<host>[:<port>]/<path>` (http.c 894). The first is the initial request
    /// (`<config-auth type="init">`), which carries no credentials; a form is only submitted, with the
    /// password and the code, in a later one. So the credentials can have left this computer only when there
    /// is a second (a redirect or a retried request counts too: on the safe side, the code is then treated as
    /// spent). Counted wherever it stands, since a prompt for a text field (printed without a line break,
    /// main.c 2706) can come first on the line. A server's own text can add such text after its first answer
    /// but never remove any, so it can only make this say "sent". Count it over the whole output: a caller
    /// that has only part of it must take the credentials as sent.
    public static func openConnectPosts(_ text: String) -> Int {
        text.components(separatedBy: openConnectPost).count - 1
    }

    static let openConnectPost = "POST https://"

    public static func openConnectCredentialsSent(_ text: String) -> Bool { openConnectPosts(text) >= 2 }

    /// The lines up to the first TLS session with the server ("Connected to HTTPS on …", gnutls.c): only
    /// openconnect's own words, since nothing of the server's has been read yet. Certificate and network
    /// failures are read from these lines alone.
    static func openConnectBeforeServer(_ text: String) -> [Substring] {
        var lines: [Substring] = []
        for line in openConnectLines(text) {
            if line.hasPrefix("Connected to HTTPS on ") { break }
            lines.append(line)
        }
        return lines
    }

    /// openconnect refuses a server that asks for a CSD host scan when it has no `csd-wrapper` (auth.c
    /// 1176–1187), which PassTunnel never gives it: each message as the two whole lines it prints.
    static let openConnectHostScanMessages: [(String, String)] = [
        ("Error: Server asked us to run CSD hostscan.", "You need to provide a suitable --csd-wrapper argument."),
        (
            "Error: Server asked us to download and run a 'Cisco Secure Desktop' trojan.",
            "This facility is disabled by default for security reasons, so you may wish to enable it."
        )
    ]

    static func openConnectAskedForHostScan(_ lines: [Substring]) -> Bool {
        zip(lines, lines.dropFirst()).contains { pair in
            openConnectHostScanMessages.contains { pair.0 == $0.0 && pair.1 == $0.1 }
        }
    }

    /// What follows "None of the <n>" in openconnect's line for a pin that did not match (main.c 2613).
    static let openConnectPinMismatch = " fingerprint(s) specified via --servercert match server's certificate: "

    /// The server's certificate or key was refused: openconnect's reason ("signer not found",
    /// "certificate expired"; "not the pinned key" when a pin did not match) and the pin of the key it saw,
    /// from its hint (`--servercert pin-sha256:…`, main.c 2613–2626). nil when the lines before the TLS
    /// session say nothing of the kind. With a pin openconnect still prints "Server certificate verify
    /// failed: …" for the CA check it then ignores, so that line alone is no failure.
    static func openConnectCertificateFailure(_ lines: [Substring]) -> (reason: String, pin: String?)? {
        var reason: String?
        var pin: String?
        var failed = false
        for line in lines {
            if line.hasPrefix("Server certificate verify failed: ") {
                reason = String(line.dropFirst("Server certificate verify failed: ".count))
            } else if line.hasPrefix("None of the "), let r = line.range(of: openConnectPinMismatch) {
                failed = true
                reason = "not the pinned key"
                let hint = String(line[r.upperBound...])
                if OpenConnectPin.isValid(hint) { pin = hint }
            } else if line.hasPrefix("Certificate from VPN server \""), line.hasSuffix("\" failed verification.") {
                failed = true
            } else if line.hasPrefix("    --servercert ") {
                let hint = String(line.dropFirst("    --servercert ".count))
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
        for line in lines {
            if line.hasPrefix("getaddrinfo failed for host '"), let r = line.range(of: "': ") {
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

    /// Why a sign-in run that did not end with a session cookie failed, from its standard error (`text`, the
    /// whole of it, redacted) and its exit status (128 + the signal when one ended it). `credentialsSent`: the
    /// caller's verdict over the complete output (`openConnectCredentialsSent`, or true when it has only part
    /// of it). `authgroup`: the profile's group. `server` names the server in messages
    /// ("vpn.example.com:8443"). In this order:
    /// 1. dyld stopped openconnect (`toolUnsupported`: it never ran);
    /// 2. once a form may have been submitted, `authFailed` whatever else the output says: the server's
    ///    text is in it by then, and nothing is retried or reported as unsent that may have used the code
    ///    (a host scan asked for only then is a refused sign-in too);
    /// 3. the server asked for a host scan, in openconnect's two exact lines (`hostScanRequired`);
    /// 4. before any TLS session with the server: its certificate refused (`serverCertificateRejected`), its
    ///    name not found (`hostNotFound`), no answer (`serverUnreachable`);
    /// 5. the profile's group not among the server's (`Auth choice "<group>" not available`, main.c 2697);
    /// 6. the server asked for more answers than it was given ("User input required in non-interactive
    ///    mode", main.c 2718): `signInNeedsMoreAnswers`;
    /// 7. anything else: `connectFailed`.
    /// Steps 3–7 come before any form was submitted: nothing was sent.
    static func openConnectSignInError(
        _ text: String, status: Int32, credentialsSent: Bool, authgroup: String, server: String
    ) -> PTError {
        let tail = tail(text)
        if status > 128, let reason = toolLoadFailure(text) { return .toolUnsupported(reason: reason, log: tail) }
        if credentialsSent { return .authFailed(tail) }
        let lines = openConnectLines(text)
        if openConnectAskedForHostScan(lines) { return .hostScanRequired(log: tail) }
        let early = openConnectBeforeServer(text)
        if let failure = openConnectCertificateFailure(early) {
            return .serverCertificateRejected(reason: failure.reason, pin: failure.pin, log: tail)
        }
        if let verdict = openConnectUnreached(early) {
            if verdict.kind == .hostNotFound { return .hostNotFound(server: server, log: tail) }
            return .serverUnreachable(server: server, reason: verdict.reason ?? "no connection", log: tail)
        }
        if !authgroup.isEmpty, lines.contains(where: { $0 == "Auth choice \"\(authgroup)\" not available" }) {
            return .invalidField("authgroup")
        }
        if lines.contains(where: { $0 == "User input required in non-interactive mode" }) {
            return .signInNeedsMoreAnswers(log: tail)
        }
        return .connectFailed(tail)
    }
}
