import Foundation
import PassTunnelVPNConfig

/// Reads an .ovpn file and guesses how the profile authenticates.
public enum OVPNAnalyzer {
    public typealias Result = (passwordMode: PasswordMode, otpMode: OTPMode, otpDelivery: OTPDelivery, remote: String,
                               remotes: [String])

    /// No `auth-user-pass` → certificate only (password none, otp none).
    /// `static-challenge` → otp ask, delivery separate. Otherwise delivery combined.
    /// `remotes` are the hosts of every `remote` directive in file order (`<connection>` blocks included),
    /// `remote` the first of them ("" if none). Lines are read as OpenVPN reads them (`directives`).
    public static func analyze(_ text: String) -> Result {
        var hasAuth = false
        var hasChallenge = false
        var remotes: [String] = []

        for words in directives(text) {
            switch words[0] {
            case "auth-user-pass": hasAuth = true
            case "static-challenge": hasChallenge = true
            case "remote":
                if words.count > 1 { remotes.append(words[1]) }
            default: break
            }
        }

        let remote = remotes.first ?? ""
        guard hasAuth else { return (.none, .none, .combined, remote, remotes) }
        if hasChallenge { return (.keychain, .ask, .separate, remote, remotes) }
        return (.keychain, .none, .combined, remote, remotes)
    }

    /// The server to show for a config: the first `remote` host, followed by "+N more" when OpenVPN
    /// may connect to others (it tries them in order, or shuffled with `remote-random`); "" if none.
    public static func serverDescription(_ remotes: [String]) -> String {
        guard let first = remotes.first else { return "" }
        let others = remotes.count - 1
        if others == 0 { return first }
        return String(localized: "\(first) +\(others) more")
    }

    /// `serverDescription` of the config's `remote` hosts.
    public static func serverDescription(_ text: String) -> String {
        serverDescription(analyze(text).remotes)
    }

    /// The first server OpenVPN tries, with its port and transport.
    public struct Endpoint: Equatable, Sendable {
        public var host: String
        /// As written in the config ("1194"); OpenVPN's default when none is given.
        public var port: String
        public var tcp: Bool
        /// How many more `remote` lines follow the first.
        public var others: Int

        public init(host: String, port: String, tcp: Bool, others: Int) {
            self.host = host
            self.port = port
            self.tcp = tcp
            self.others = others
        }

        /// "vpn.example.com:1194", "[2001:db8::1]:1194".
        public var address: String { Self.address(host: host, port: port) }

        /// `address`, followed by "+N more" when there are other `remote` lines.
        public var server: String { others > 0 ? String(localized: "\(address) +\(others) more") : address }

        /// A server as host:port, an IPv6 address in brackets (also for FortiGate's gateway).
        public static func address(host: String, port: String) -> String {
            host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
        }
    }

    /// The first `remote` and how it is reached: `remote host [port] [proto]`, else the `port` / `rport` and
    /// `proto` lines in effect for it (those in its `<connection>` block first, then the ones outside any block,
    /// the last of each winning), else OpenVPN's defaults, 1194 and UDP. nil when there is no `remote`.
    public static func endpoint(_ text: String) -> Endpoint? {
        let all = servers(text)
        guard let first = all.first else { return nil }
        return Endpoint(host: first.host, port: first.port, tcp: first.tcp, others: all.count - 1)
    }

    /// One `remote` line and how it is reached.
    public struct Server: Equatable, Sendable {
        public var host: String
        /// As written in the config ("1194"); OpenVPN's default when none is given.
        public var port: String
        public var tcp: Bool

        public init(host: String, port: String, tcp: Bool) {
            self.host = host
            self.port = port
            self.tcp = tcp
        }
    }

    /// Every `remote` in file order (`<connection>` blocks included), each with the port and transport
    /// `endpoint` would give it.
    public static func servers(_ text: String) -> [Server] {
        var remotes: [(words: [String], connection: Int?)] = []
        var ports: [Int?: String] = [:]
        var protos: [Int?: String] = [:]
        for line in scopedDirectives(text) {
            let words = line.words
            switch words[0] {
            case "remote" where words.count > 1:
                remotes.append(line)
            case "port" where words.count > 1, "rport" where words.count > 1:
                ports[line.connection] = words[1]
            case "proto" where words.count > 1:
                protos[line.connection] = words[1]
            default: break
            }
        }
        return remotes.map { remote in
            let words = remote.words
            let port = words.count > 2 ? words[2] : ports[remote.connection] ?? ports[nil] ?? "1194"
            let proto = words.count > 3 ? words[3] : protos[remote.connection] ?? protos[nil] ?? "udp"
            return Server(host: words[1], port: port, tcp: proto.lowercased().hasPrefix("tcp"))
        }
    }

    /// The first server as the editor shows it: "vpn.example.com:1194 · UDP", "vpn.example.com:443 +1 more · TCP",
    /// "[2001:db8::1]:1194 · UDP"; "" when there is no `remote`.
    public static func endpointDescription(_ text: String) -> String {
        guard let endpoint = endpoint(text) else { return "" }
        return "\(endpoint.server) · \(endpoint.tcp ? "TCP" : "UDP")"   // protocol names stay untranslated
    }

    /// Whether the profile sends all traffic through the tunnel: true with a local `redirect-gateway`,
    /// false when pushed routes are refused (`route-nopull`, `pull-filter ignore "redirect-gateway…"`),
    /// nil when it depends on what the server pushes.
    public static func redirectsGateway(_ text: String) -> Bool? {
        var refusesPush = false
        for words in directives(text) {
            switch words[0] {
            case "redirect-gateway": return true
            case "route-nopull": refusesPush = true
            case "pull-filter":
                if words.count > 2, words[1].lowercased() == "ignore",
                   "redirect-gateway".hasPrefix(words[2].lowercased()) {
                    refusesPush = true
                }
            default: break
            }
        }
        return refusesPush ? false : nil
    }

    /// Directive lines as tokens, read with `OVPNSanitizer`'s tokenizer so the two (and OpenVPN) never
    /// read a line differently: quotes and backslash escapes resolved, comments (`#`, `;`) dropped,
    /// lines OpenVPN rejects skipped. The directive is lowercased without leading dashes, as the
    /// sanitizer checks it. The contents of inline blocks such as `<ca>…</ca>` are skipped;
    /// `<connection>` blocks are read. `setenv opt <directive …>` yields the directive, which OpenVPN
    /// applies only when its name is exact (no dashes, lowercase) and otherwise ignores.
    static func directives(_ text: String) -> [[String]] {
        scopedDirectives(text).map(\.words)
    }

    /// `directives`, each with the `<connection>` block it is in (the blocks numbered from 0 in file order; nil
    /// outside them).
    static func scopedDirectives(_ text: String) -> [(words: [String], connection: Int?)] {
        scan(text).compactMap { line in
            guard case .directive(let words, let connection) = line.item else { return nil }
            return (words: words, connection: connection)
        }
    }

    /// What `scan` finds on a line: a directive (read as `directives` reads it), or the start of an inline
    /// block (its tag normalized like a directive name: "ca", "connection").
    enum Item: Equatable {
        case directive(words: [String], connection: Int?)
        case block(String)
    }

    /// The directive lines and block starts of `text` with their 0-based line index; block contents other than
    /// `<connection>`'s, comments and lines OpenVPN rejects are left out.
    static func scan(_ text: String) -> [(item: Item, index: Int)] {
        var out: [(item: Item, index: Int)] = []
        var blocks: [(tag: String, verbatim: Bool)] = []
        var connection: Int?
        var connections = 0
        for (index, rawLine) in OVPNInliner.lines(text).enumerated() {
            var line = rawLine
            if index == 0, line.hasPrefix("\u{FEFF}") { line.removeFirst() }   // UTF-8 BOM
            if let top = blocks.last {
                if OVPNSanitizer.isInlineBlockEnd(line, tag: top.tag) {
                    blocks.removeLast()
                    if !top.verbatim { connection = nil }
                    continue
                }
                if top.verbatim { continue }
            }
            guard var words = OVPNSanitizer.tokens(of: line), !words.isEmpty else { continue }
            if words.count == 1, let tag = OVPNSanitizer.inlineBlockTag(words[0]) {
                let name = normalize(tag)
                let verbatim = name != "connection"
                blocks.append((tag: tag, verbatim: verbatim))
                if !verbatim {
                    connection = connections
                    connections += 1
                }
                out.append((item: .block(name), index: index))
                continue
            }
            if words.count > 2, normalize(words[0]) == "setenv", words[1].lowercased() == "opt" {
                words.removeFirst(2)
                guard words[0] == normalize(words[0]) else { continue }
            }
            words[0] = normalize(words[0])
            out.append((item: .directive(words: words, connection: connection), index: index))
        }
        return out
    }

    /// `OVPNSanitizer`'s directive name: lowercased, all leading dashes removed.
    static func normalize(_ token: String) -> String {
        String(token.drop(while: { $0 == "-" })).lowercased()
    }
}
