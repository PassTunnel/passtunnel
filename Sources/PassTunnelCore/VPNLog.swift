import Foundation

/// Reads the per-profile `vpn.log` written by openvpn / openfortivpn. The helper creates a fresh
/// log for every start, so the whole file describes the current (or last) session.
public enum VPNLog {
    static let maxReadBytes = 256 * 1024

    /// The log text, or "" when it does not exist. Only the last `maxReadBytes` are read.
    public static func read(_ url: URL) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let start = size > UInt64(maxReadBytes) ? size - UInt64(maxReadBytes) : 0
        try? handle.seek(toOffset: start)
        let data = (try? handle.readToEnd()) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    /// The first `maxBytes` of the log (start-up lines: tunnel device, pushed options). The helper keeps
    /// them when it trims a long log.
    public static func readHead(_ url: URL, maxBytes: Int = 64 * 1024) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
        defer { try? handle.close() }
        let data = (try? handle.read(upToCount: maxBytes)) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    /// Last `lines` non-empty lines, without OpenVPN's notes about our own management-socket polls
    /// (a few every poll, they would push the interesting lines out).
    public static func tail(_ text: String, lines: Int = 12) -> String {
        text.split(whereSeparator: \.isNewline)
            .filter { !isManagementChatter($0) }
            .suffix(lines).joined(separator: "\n")
    }

    static let managementChatter = ["MANAGEMENT: Client connected from ", "MANAGEMENT: Client disconnected",
                                    "MANAGEMENT: CMD '"]

    static func isManagementChatter(_ line: Substring) -> Bool {
        managementChatter.contains { line.contains($0) }
    }

    // MARK: tunnel set-up

    /// The tunnel interface the tool opened: OpenVPN "Opened utun device utun5", openfortivpn
    /// "Interface ppp0 is UP".
    public static func tunnelInterface(_ text: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            for (marker, prefix) in [("Opened utun device ", "utun"), ("Interface ", "ppp")] {
                guard let r = line.range(of: marker) else { continue }
                let name = line[r.upperBound...].prefix { $0.isLetter || $0.isNumber }
                if name.hasPrefix(prefix), name.count > prefix.count { return String(name) }
            }
        }
        return nil
    }

    /// OpenVPN: the server pushed `redirect-gateway`, or OpenVPN added the `0/1` + `128/1` routes.
    public static func pushedRedirectGateway(_ text: String) -> Bool {
        text.split(whereSeparator: \.isNewline).contains { line in
            (line.contains("PUSH_REPLY") && line.contains("redirect-gateway"))
                || (line.contains("route add -net 128.0.0.0 ") && line.contains(" 128.0.0.0"))
        }
    }

    /// Something OpenVPN set up for the tunnel failed. `allTraffic` problems (the DNS hook, or the
    /// routes that take all traffic) mean another VPN is in the way and the session is unusable;
    /// others (a single route) leave a working but incomplete tunnel.
    public struct SetupProblem: Equatable, Sendable {
        public var reason: String          // the log line, without its timestamp
        public var allTraffic: Bool
    }

    /// Destinations of the routes `redirect-gateway` adds (IPv4 `def1`, IPv6 `def1` and `!ipv4`).
    static let allTrafficDestinations: Set<String> = ["0.0.0.0", "128.0.0.0", "default", "::", "8000::",
                                                       "2000::", "3000::", "fc00::"]

    /// The first DNS-hook failure or all-traffic route failure, else the first other route failure.
    /// Not counted (`File exists` that means the route is already there the way OpenVPN wants it):
    /// - a route this session already added successfully: OpenVPN adds the server's host route up to
    ///   three times (from `redirect-gateway`, from a config `route <server> … net_gateway`, and from the
    ///   same route pushed by the server); only the first one can succeed;
    /// - the host route to the server via the original default gateway (`isLeftoverServerRoute`);
    /// and the "route add command failed" line that follows either.
    public static func setupProblem(_ text: String) -> SetupProblem? {
        let servers = remoteAddresses(text)
        let gateway = defaultGateway(text)
        var routeProblem: SetupProblem?
        var skipCommandFailure = false
        var command: RouteCommand?           // the last `/sbin/route add …` OpenVPN ran
        var added: Set<String> = []          // RouteCommand.key of routes added in this session
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = withoutTimestamp(raw)
            let lower = line.lowercased()
            if lower.contains("setting dns failed") || lower.contains("dns-updown failed")
                || (lower.contains("dns updown") && (lower.contains("failed") || lower.contains("error status"))) {
                return SetupProblem(reason: line, allTraffic: true)
            }
            if line.hasPrefix("/sbin/route ") {
                skipCommandFailure = false
                command = RouteCommand(line)
            }
            if let route = failedRoute(line) {
                let key = RouteCommand.key(route.destination, after: command)
                if route.error.lowercased().contains("file exists"), added.contains(key)
                    || isLeftoverServerRoute(route, servers: servers, defaultGateway: gateway) {
                    skipCommandFailure = true
                    continue
                }
                if allTrafficDestinations.contains(route.destination) { return SetupProblem(reason: line, allTraffic: true) }
                if routeProblem == nil { routeProblem = SetupProblem(reason: line, allTraffic: false) }
            } else if let destination = addedRouteDestination(line) {
                added.insert(RouteCommand.key(destination, after: command))
            } else if lower.contains("route add command failed") {
                if skipCommandFailure {
                    skipCommandFailure = false
                    continue
                }
                if routeProblem == nil { routeProblem = SetupProblem(reason: line, allTraffic: false) }
            }
        }
        return routeProblem
    }

    /// "/sbin/route add -net 203.0.113.10 192.0.2.1 255.255.255.255" → destination and mask, so the
    /// same destination with another mask counts as another route.
    struct RouteCommand: Equatable {
        var destination: String
        var mask: String

        init(destination: String, mask: String) {
            self.destination = destination
            self.mask = mask
        }

        init?(_ line: String) {
            let tokens = line.split(separator: " ").map(String.init)
            guard let add = tokens.firstIndex(of: "add") else { return nil }
            var positional: [String] = []
            var mask = ""
            var i = add + 1
            while i < tokens.count {
                let t = tokens[i]
                if t == "-netmask" || t == "-prefixlen", i + 1 < tokens.count {
                    mask = tokens[i + 1]
                    i += 2
                    continue
                }
                if !t.hasPrefix("-") { positional.append(t) }
                i += 1
            }
            guard let destination = positional.first else { return nil }
            self.destination = destination
            self.mask = mask.isEmpty && positional.count >= 3 ? positional[2] : mask
        }

        /// Identity of the route `route` reported on: with the mask of the command it belongs to.
        static func key(_ destination: String, after command: RouteCommand?) -> String {
            guard let command, command.destination == destination else { return destination }
            return destination + "/" + command.mask
        }
    }

    /// `route`'s success line, "add net 10.20.0.0: gateway 10.8.0.1" → "10.20.0.0".
    static func addedRouteDestination(_ line: String) -> String? {
        for kind in ["add net ", "add host "] {
            guard line.hasPrefix(kind), let gateway = line.range(of: ": gateway ") else { continue }
            guard !line[gateway.upperBound...].contains(": ") else { return nil }
            return String(line[line.index(line.startIndex, offsetBy: kind.count)..<gateway.lowerBound])
        }
        return nil
    }

    /// A failed `route add`, parsed from `route`'s own error line.
    struct FailedRoute: Equatable {
        var destination: String
        var gateway: String
        var error: String
    }

    /// "add net 0.0.0.0: gateway 10.8.0.1: File exists" → ("0.0.0.0", "10.8.0.1", "File exists").
    static func failedRoute(_ line: String) -> FailedRoute? {
        for kind in ["add net ", "add host "] {
            guard let start = line.range(of: kind),
                  let gateway = line.range(of: ": gateway ", range: start.upperBound..<line.endIndex),
                  let error = line.range(of: ": ", range: gateway.upperBound..<line.endIndex) else { continue }
            return FailedRoute(destination: String(line[start.upperBound..<gateway.lowerBound]),
                               gateway: String(line[gateway.upperBound..<error.lowerBound]),
                               error: String(line[error.upperBound...]))
        }
        return nil
    }

    /// With `redirect-gateway`, OpenVPN first adds a host route to the server via the original default
    /// gateway. A session that was killed without cleaning up (e.g. an older helper unregistered while
    /// connected) leaves that route behind, so the next connect gets "File exists" for it. The route
    /// that is there already is the one OpenVPN wanted, so this is harmless. Counted as harmless only
    /// when the destination is the server this session connected to and the gateway is the default
    /// gateway OpenVPN found (when the log names it).
    static func isLeftoverServerRoute(_ route: FailedRoute, servers: Set<String>, defaultGateway: String?) -> Bool {
        guard route.error.lowercased().contains("file exists"), servers.contains(route.destination) else { return false }
        guard let defaultGateway else { return true }
        return route.gateway == defaultGateway
    }

    /// Addresses of the server OpenVPN talked to: "TCP connection established with [AF_INET]203.0.113.10:443",
    /// "UDPv4 link remote: [AF_INET]203.0.113.10:1194", "Peer Connection Initiated with [AF_INET]…".
    public static func remoteAddresses(_ text: String) -> Set<String> {
        let markers = ["link remote: ", "connection established with ", "Peer Connection Initiated with "]
        var out: Set<String> = []
        for line in text.split(whereSeparator: \.isNewline) {
            guard let marker = markers.lazy.compactMap({ line.range(of: $0) }).first else { continue }
            var rest = line[marker.upperBound...]
            if let family = rest.range(of: "]"), rest.hasPrefix("[AF_INET") { rest = rest[family.upperBound...] }
            var address = String(rest.prefix { !$0.isWhitespace && $0 != "," })
            if let colon = address.lastIndex(of: ":"), address[address.index(after: colon)...].allSatisfy(\.isNumber),
               address.index(after: colon) < address.endIndex {
                address = String(address[..<colon])
            }
            if address.hasPrefix("::ffff:"), address.contains(".") { address.removeFirst(7) }
            if !address.isEmpty { out.insert(address) }
        }
        return out
    }

    /// "ROUTE_GATEWAY 192.168.1.1/255.255.255.0 IFACE=en0 HWADDR=…" → "192.168.1.1".
    static func defaultGateway(_ text: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            guard let r = line.range(of: "ROUTE_GATEWAY ") else { continue }
            let value = line[r.upperBound...].prefix { !$0.isWhitespace && $0 != "/" }
            if !value.isEmpty, value.first?.isNumber == true { return String(value) }
        }
        return nil
    }

    /// Drops OpenVPN's "2026-01-01 10:00:00 " prefix.
    static func withoutTimestamp(_ line: Substring) -> String {
        let s = line.trimmingCharacters(in: .whitespaces)
        let parts = s.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        if parts.count == 3, parts[0].count == 10, parts[0].filter({ $0 == "-" }).count == 2,
           parts[1].count == 8, parts[1].filter({ $0 == ":" }).count == 2 {
            return String(parts[2])
        }
        return s
    }

    // MARK: OpenVPN state from the log

    static let openVPNRestartMarkers = ["SIGUSR1[", "SIGHUP[", "SIGTERM[", "Restart pause", "Inactivity timeout",
                                        "Connection reset, restarting"]

    /// OpenVPN: the tunnel came up ("Initialization Sequence Completed") and has not restarted since.
    /// Only a fallback for when the management interface cannot be read.
    public static func openVPNIsUp(_ text: String) -> Bool {
        var up = false
        for line in text.split(whereSeparator: \.isNewline) {
            if line.contains("Initialization Sequence Completed") {
                up = true
            } else if openVPNRestartMarkers.contains(where: { line.contains($0) }) {
                up = false
            }
        }
        return up
    }

    /// OpenVPN's tunnel address from the last "/sbin/ifconfig utun6 10.8.0.6 …" (or
    /// "net_addr_v4_add: 10.8.0.6/24 dev utun6") line.
    public static func openVPNLocalIP(_ text: String) -> String? {
        var found: String?
        for line in text.split(whereSeparator: \.isNewline) {
            var candidate: Substring?
            if let r = line.range(of: "/sbin/ifconfig utun") {
                let tokens = line[r.upperBound...].split(separator: " ")
                if tokens.count >= 2 { candidate = tokens[1] }
            } else if let r = line.range(of: "net_addr_v4_add: ") {
                candidate = line[r.upperBound...].prefix { $0 != "/" && $0 != " " }
            }
            if let c = candidate, c.contains("."), c.allSatisfy({ $0.isNumber || $0 == "." }) { found = String(c) }
        }
        return found
    }

    /// openfortivpn: "Tunnel is up and running" seen.
    public static func fortiIsUp(_ text: String) -> Bool {
        text.contains("Tunnel is up and running")
    }

    /// openfortivpn: first address of the last "Got addresses: [10.1.2.3], ns [...]" line.
    public static func fortiAddress(_ text: String) -> String? {
        guard let line = text.split(whereSeparator: \.isNewline).last(where: { $0.contains("Got addresses: [") }),
              let open = line.range(of: "Got addresses: [") else { return nil }
        let rest = line[open.upperBound...]
        guard let close = rest.firstIndex(of: "]") else { return nil }
        let ip = rest[..<close].split(separator: ",").first?.trimmingCharacters(in: .whitespaces) ?? ""
        return ip.isEmpty ? nil : ip
    }

    static let authFailureMarkers = [
        "AUTH_FAILED", "auth-failure", "Could not authenticate", "Authentication failed",
        "VPN credentials are incorrect", "Login failed", "Invalid credentials",
    ]

    /// True when the log shows the server rejected the credentials.
    public static func isAuthFailure(_ text: String) -> Bool {
        authFailureMarkers.contains { text.range(of: $0, options: .caseInsensitive) != nil }
    }

    static let fatalMarkers = [
        "Exiting due to fatal error", "Options error", "Cannot resolve host address",
        "Gateway certificate validation failed", "Could not connect to gateway", "PassTunnel: ",
    ]

    /// True when the log shows a non-authentication error the tool will not recover from.
    public static func isFatal(_ text: String) -> Bool {
        fatalMarkers.contains { text.contains($0) }
    }
}
