import Foundation
import PassTunnelKit
import PassTunnelShared

/// Another profile whose tunnel claims some of what this one's does (`NetworkClaims`).
public struct ProfileOverlap: Equatable, Sendable {
    public var profileID: String
    public var name: String
    /// Everything both claim; never empty.
    public var overlaps: [NetworkClaims.Overlap]
    /// What the profile being connected claims, and what the other one does: the DNS servers of each are
    /// there for a message that names them.
    public var mine: NetworkClaims
    public var theirs: NetworkClaims

    public init(
        profileID: String, name: String, overlaps: [NetworkClaims.Overlap], mine: NetworkClaims,
        theirs: NetworkClaims
    ) {
        self.profileID = profileID
        self.name = name
        self.overlaps = overlaps
        self.mine = mine
        self.theirs = theirs
    }

    /// The overlaps as the lists a message shows: the shared networks and names, and who carries all traffic
    /// (`first` is the profile being connected).
    public var summary: OverlapSummary { OverlapSummary(overlaps) }
}

/// What each profile's tunnel takes over, for the check that runs before a connect: from the profile's
/// config, what its server pushed (OpenVPN) or the gateway handed out and the routing table showed
/// (FortiGate) the last time it connected. That is kept in `profiles/<id>/network.json`, because the
/// check runs before the new tunnel exists: a first connect has nothing but the config's own lines.
public enum ProfileNetwork {
    public static let fileName = "network.json"
    static let version = 1
    static let maxFileSize = 256 * 1024

    /// The file: the options the last connect saw (in OpenVPN's push syntax, whatever the tool), and the
    /// destination they belong to (`ProfileDestination.fingerprint`), so a changed server or config makes
    /// them stale. Plain data, written only by the profile owner's process.
    struct Saved: Codable, Equatable {
        var version: Int
        var destination: String
        var options: [String]
    }

    // MARK: File

    /// The saved options, nil unless the file is there, ours (a regular file of this user, no access for
    /// group or others, not a link), sound, and written for the profile's destination as it is now.
    static func savedOptions(_ p: Profile, store: ProfileStore) -> [String]? {
        guard let data = readOwned(store.dir(p.id).appendingPathComponent(fileName)),
            let saved = try? JSONCoding.decode(Saved.self, from: data, name: fileName), saved.version == version,
            saved.options.count <= VPNLog.maxPushedOptions, saved.options.allSatisfy(VPNLog.isNetworkOption),
            saved.destination == ProfileDestination.of(p, store: store).fingerprint
        else { return nil }
        return saved.options
    }

    /// The file's bytes when it passes the checks of `savedOptions`' first line; nil otherwise.
    static func readOwned(_ url: URL) -> Data? {
        // O_NONBLOCK: a fifo left in its place must not make the open wait for a writer.
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(),
            info.st_mode & 0o077 == 0, info.st_size >= 0, info.st_size <= maxFileSize
        else { return nil }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n >= 0, data.count + n <= maxFileSize else { return nil }
            if n == 0 { return data }
            data.append(contentsOf: buffer[0..<n])
        }
    }

    /// Writes `options` for the profile's current destination: atomically, 0600. A failure is ignored: the
    /// cache only makes the next check better.
    static func save(_ options: [String], for p: Profile, store: ProfileStore) {
        let saved = Saved(
            version: version, destination: ProfileDestination.of(p, store: store).fingerprint,
            options: Array(options.prefix(VPNLog.maxPushedOptions)))
        try? JSONCoding.write(saved, to: store.dir(p.id).appendingPathComponent(fileName), mode: 0o600)
    }

    // MARK: Collecting

    /// The network options the tunnel of `p` brought up, from its log (and for FortiGate the routing table;
    /// `tunnelRoutes` is given the interface). nil when the log says nothing about it.
    static func observedOptions(
        _ p: Profile, store: ProfileStore,
        tunnelRoutes: (String) -> [RoutingTable.Route]
    ) -> [String]? {
        let log = VPNLog.readHead(store.logURL(p.id), maxBytes: 256 * 1024)
        switch p.type {
        case .openvpn:
            return VPNLog.pushedOptions(log)
        case .forti:
            var options = p.setDNS ? VPNLog.fortiOptions(log) : []
            if p.setRoutes, let interface = VPNLog.tunnelInterface(log) {
                let own = VPNLog.fortiAddress(log)
                let routes = tunnelRoutes(interface).filter { !($0.prefixLength == 32 && $0.destination == own) }
                if !routes.isEmpty { options = (options ?? []) + routes.compactMap(option) }
            }
            return options
        case .anyconnect:
            // The hook's success line: the interface, whether all traffic goes through it, and the DNS it
            // set; the routes through that interface from the routing table, as for FortiGate.
            let current = VPNLog.read(store.logURL(p.id))
            guard let report = VPNLog.openConnectReport(current) ?? VPNLog.openConnectReport(log) else { return nil }
            return anyConnectOptions(report, routes: p.setRoutes ? tunnelRoutes(report.interface) : [])
        case .globalprotect:
            return nil  // not connected by this version (`ConnectionManager.connectRefusal`)
        }
    }

    /// What a Cisco AnyConnect tunnel takes over, as the options OpenVPN would push for it (one form for
    /// every tool): `redirect-gateway` for a full tunnel (with `ipv6` when it has an IPv6 address, `!ipv4`
    /// when it has no IPv4 one), its DNS servers, search domains (`DOMAIN`) and split DNS domains
    /// (`DOMAIN-ROUTE`), and the routes through its interface but its own addresses.
    static func anyConnectOptions(_ report: VPNHook.Report, routes: [RoutingTable.Route]) -> [String] {
        var options: [String] = []
        if report.fullTunnel {
            let v4 = report.addresses.contains { $0.family == .ipv4 }
            let v6 = report.addresses.contains { $0.family == .ipv6 }
            options.append("redirect-gateway def1" + (v4 ? "" : " !ipv4") + (v6 ? " ipv6" : ""))
        }
        for server in report.dnsServers.prefix(NetworkClaims.maxDNSServers) { options.append("dhcp-option DNS \(server)") }
        for domain in report.searchDomains.prefix(NetworkClaims.maxDomains) { options.append("dhcp-option DOMAIN \(domain)") }
        for domain in report.splitDNSDomains.prefix(NetworkClaims.maxDomains) { options.append("dhcp-option DOMAIN-ROUTE \(domain)") }
        let own = Set(report.addresses.map(\.description))
        for route in routes where !(own.contains(route.destination) && (route.prefixLength == 32 || route.prefixLength == 128)) {
            if let option = option(route) { options.append(option) }
        }
        return Array(options.filter(VPNLog.isNetworkOption).prefix(VPNLog.maxPushedOptions))
    }

    /// A route as the option that would push it.
    static func option(_ route: RoutingTable.Route) -> String? {
        guard let network = CIDR("\(route.destination)/\(route.prefixLength)") else { return nil }
        guard !network.isIPv6 else { return "route-ipv6 \(network)" }
        let mask: UInt32 = network.prefixLength == 0 ? 0 : UInt32.max << UInt32(32 - network.prefixLength)
        return "route \(network.address) \((0..<4).map { String(mask >> UInt32(24 - 8 * $0) & 255) }.joined(separator: "."))"
    }

    /// Remembers what the tunnel of `p`, which just came up, takes over.
    static func record(_ p: Profile, store: ProfileStore, tunnelRoutes: (String) -> [RoutingTable.Route]) {
        guard let options = observedOptions(p, store: store, tunnelRoutes: tunnelRoutes) else { return }
        save(options, for: p, store: store)
    }

    // MARK: Claims

    /// What `p` takes over: its config's lines (FortiGate: whether it sets routes and DNS at all) and the
    /// options of the last connect. `live`: the tunnel is up now, so its log comes first, the file second;
    /// otherwise (a profile about to connect, whose log may be a failed attempt's) the file comes first.
    static func claims(
        for p: Profile, store: ProfileStore, live: Bool,
        tunnelRoutes: (String) -> [RoutingTable.Route]
    ) -> NetworkClaims {
        switch p.type {
        case .openvpn:
            let config = (try? String(contentsOf: store.ovpnURL(p.id), encoding: .utf8)) ?? ""
            let saved = savedOptions(p, store: store)
            let logged = VPNLog.pushedOptions(VPNLog.readHead(store.logURL(p.id), maxBytes: 256 * 1024))
            let pushed = live ? (logged ?? saved) : (saved ?? logged)
            return OVPNAnalyzer.networkClaims(config, pushed: pushed ?? [])
        case .forti:
            // A tunnel that is up and has no file (it came up before this was kept) is read now.
            let options = savedOptions(p, store: store) ?? (live ? observedOptions(p, store: store, tunnelRoutes: tunnelRoutes) : nil)
            return OVPNAnalyzer.networkClaims("", pushed: options ?? [])
        case .anyconnect:
            // As FortiGate: a tunnel that is up and has no file is read now.
            let options = savedOptions(p, store: store) ?? (live ? observedOptions(p, store: store, tunnelRoutes: tunnelRoutes) : nil)
            return OVPNAnalyzer.networkClaims("", pushed: options ?? [])
        case .globalprotect:
            return OVPNAnalyzer.networkClaims("", pushed: savedOptions(p, store: store) ?? [])  // not connected yet
        }
    }

    /// The profiles in `others` whose claims meet those of `p`, in the order given.
    static func overlaps(
        of p: Profile, with others: [Profile], store: ProfileStore,
        tunnelRoutes: (String) -> [RoutingTable.Route]
    ) -> [ProfileOverlap] {
        let mine = claims(for: p, store: store, live: false, tunnelRoutes: tunnelRoutes)
        guard !mine.isEmpty else { return [] }
        return others.compactMap { other in
            let theirs = claims(for: other, store: store, live: true, tunnelRoutes: tunnelRoutes)
            let found = NetworkClaims.overlaps(mine, theirs)
            return found.isEmpty
                ? nil
                : ProfileOverlap(
                    profileID: other.id, name: other.name, overlaps: found,
                    mine: mine, theirs: theirs)
        }
    }
}

// MARK: - Words

extension ProfileOverlap {
    /// How many items of a list a line shows.
    static let shownItems = 5

    /// The lines that tell the user about this overlap, in their language (the first one is the headline,
    /// the others are indented by the caller). `connecting` is the name of the profile being connected.
    /// The wording must be checked on a Mac before it ships (decision D-22): it says only that the traffic
    /// can go through one tunnel, not which, because a duplicate route stays with the tunnel that came
    /// first while a narrower one wins over a broader one.
    public func messageLines(connecting: String) -> [String] {
        let summary = summary
        var lines = [String(localized: "Warning: \(connecting) overlaps with \(name).")]
        if summary.firstTakesAllTraffic && summary.secondTakesAllTraffic {
            lines.append(String(localized: "Both send all traffic through their tunnel."))
        } else if summary.firstTakesAllTraffic {
            lines.append(String(localized: "\(connecting) sends all traffic through its tunnel."))
        } else if summary.secondTakesAllTraffic {
            lines.append(String(localized: "\(name) sends all traffic through its tunnel."))
        }
        if !summary.routes.isEmpty {
            lines.append(String(localized: "Both send these networks through their tunnel: \(Self.list(summary.routes.map(\.description)))"))
        }
        if !summary.domains.isEmpty {
            lines.append(String(localized: "Both look up these names through their tunnel: \(Self.list(summary.domains))"))
        }
        lines.append(String(localized: "That traffic can only go through one of the two tunnels."))
        return lines
    }

    static func list(_ items: [String]) -> String {
        let shown = items.prefix(shownItems).joined(separator: ", ")
        let more = items.count - shownItems
        return more > 0 ? String(localized: "\(shown) +\(more) more") : shown
    }
}
