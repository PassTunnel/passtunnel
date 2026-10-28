import Foundation

/// What openconnect's hook changes for a session, computed from the checked network (`OpenConnectNetwork`),
/// the session's `policy` and the default gateways before the tunnel (docs/ARCHITECTURE.md, "The hook",
/// step 4). Pure: the hook applies the changes in order, one at a time, journaling each in the session's
/// record (`OpenConnectRecord`) before it is made; a revert undoes them newest first. Each change has one
/// line of text (`Change.text`), which is also how the record stores it.
public struct OpenConnectPlan: Equatable, Sendable {
    /// The next hop of a default route: an address on an interface, or the interface alone (a link
    /// without a gateway address).
    public struct Gateway: Hashable, Sendable, CustomStringConvertible {
        public let address: IPAddress?
        public let interface: String

        /// nil for an interface name that is not one (`isInterfaceName`) or an address no gateway has
        /// (`IPAddress.isSpecial`).
        public init?(address: IPAddress?, interface: String) {
            guard Self.isInterfaceName(interface), address.map({ !$0.isSpecial && !$0.isIPv4Embedded }) ?? true else { return nil }
            self.address = address
            self.interface = interface
        }

        /// `198.51.100.1 en0`, `fe80::1 en0` (a link-local next hop needs its interface), `link ppp0`.
        public var description: String { address.map { "\($0) \(interface)" } ?? "link \(interface)" }

        /// 1 to 15 (`IFNAMSIZ` - 1) ASCII letters, digits, `_`, `-` and `.`, starting with a letter or digit, not
        /// digits only (as `DNSSettings.interface`).
        public static func isInterfaceName(_ name: String) -> Bool {
            let bytes = Array(name.utf8)
            func alphanumeric(_ c: UInt8) -> Bool { (c >= 0x61 && c <= 0x7A) || (c >= 0x41 && c <= 0x5A) || IPAddress.isDigit(c) }
            guard (1...15).contains(bytes.count), alphanumeric(bytes[0]), !bytes.allSatisfy(IPAddress.isDigit) else { return false }
            return bytes.allSatisfy { alphanumeric($0) || $0 == 0x5F || $0 == 0x2D || $0 == 0x2E }
        }
    }

    /// A network directly attached to an interface (an on-link prefix of the routing table).
    public struct Attached: Hashable, Sendable {
        public let network: IPNetwork
        public let interface: String

        public init(_ network: IPNetwork, interface: String) {
            self.network = network
            self.interface = interface
        }
    }

    /// The network under the tunnel, as the routing table says: the default gateway of each family (the hook
    /// never replaces `default`, so it is still the original gateway on a later run) and the networks
    /// attached to the Mac's interfaces (the local networks, which stay local).
    public struct Underlay: Equatable, Sendable {
        public var ipv4: Gateway?
        public var ipv6: Gateway?
        public var attached: [Attached]

        public init(ipv4: Gateway? = nil, ipv6: Gateway? = nil, attached: [Attached] = []) {
            self.ipv4 = ipv4
            self.ipv6 = ipv6
            self.attached = attached
        }

        /// The local networks that keep a route of the server's out of the tunnel: not on the tunnel's own
        /// interface, not link-local (`fe80::/10`, every interface has one) and not of length 0.
        func local(tunnel: String) -> [IPNetwork] {
            let linkLocal = IPNetwork("fe80::/10")!
            return attached.filter { $0.interface != tunnel && $0.network.prefixLength > 0 && !linkLocal.contains($0.network) }
                .map(\.network)
        }

        /// The gateway of `family` if traffic can leave through it: its address (if any) of that family,
        /// and not the tunnel's own interface.
        func usable(_ family: IPAddress.Family, tunnel: String) -> Gateway? {
            guard let gateway = family == .ipv4 ? ipv4 : ipv6, gateway.interface != tunnel,
                gateway.address.map({ $0.family == family }) ?? true
            else { return nil }
            return gateway
        }
    }

    /// Where a route sends its traffic.
    public enum Via: Hashable, Sendable {
        /// Into the tunnel.
        case interface(String)
        /// Around the tunnel, through the original gateway.
        case gateway(Gateway)
        /// Nowhere: refused at once (`EHOSTUNREACH`), so a program falls back to the other family without
        /// waiting. macOS: a `-reject` route through the loopback interface; Linux: an `unreachable` route.
        case reject
    }

    public struct Route: Hashable, Sendable {
        public let network: IPNetwork
        public let via: Via

        public init(_ network: IPNetwork, via: Via) {
            self.network = network
            self.via = via
        }
    }

    /// The session's DNS: on the Mac the dynamic keys `State:/Network/Service/<service>/DNS` (and the
    /// interface's addresses under `/IPv4`, `/IPv6`), on Linux `DNSApplier`.
    public struct DNS: Hashable, Sendable {
        /// `passtunnel-<uid>-<profile id>`.
        public let service: String
        public let interface: String
        /// Every name is resolved through the tunnel (`OverridePrimary`): only for a full tunnel.
        public let primary: Bool
        public let servers: [IPAddress]
        /// `SearchDomains`: `CISCO_DEF_DOMAIN`.
        public let searchDomains: [String]
        /// `SupplementalMatchDomains`: the names resolved through the tunnel when it is not primary,
        /// `CISCO_SPLIT_DNS` and `CISCO_DEF_DOMAIN`.
        public let matchDomains: [String]

        public init(service: String, interface: String, primary: Bool, servers: [IPAddress], searchDomains: [String], matchDomains: [String]) {
            self.service = service
            self.interface = interface
            self.primary = primary
            self.servers = servers
            self.searchDomains = searchDomains
            self.matchDomains = matchDomains
        }

        /// The service ID of a session.
        public static func service(uid: uid_t, profileID: String) -> String { "passtunnel-\(uid)-\(profileID)" }
    }

    /// One change to the system, undone by its revert.
    public enum Change: Hashable, Sendable, CustomStringConvertible {
        /// The interface's MTU, and up (macOS `ifconfig utunN mtu M up`).
        case link(interface: String, mtu: Int)
        /// A host address on the interface (`/32`, `/128`; macOS `ifconfig utunN inet A A netmask
        /// 255.255.255.255`, `inet6 A prefixlen 128`). Networks are routes of their own.
        case address(interface: String, IPAddress)
        case route(Route)
        case dns(DNS)

        public var description: String { text }

        /// The change as one line of the record, without the line break:
        ///
        ///     link utun5 mtu 1400
        ///     address utun5 10.0.0.2
        ///     route 0.0.0.0/1 interface utun5
        ///     route 192.0.2.10/32 gateway 198.51.100.1 en0
        ///     route 192.0.2.10/32 gateway link en0
        ///     route ::/1 reject
        ///     dns passtunnel-501-acme utun5 primary servers=10.0.0.53,2001:db8::53 search=example.com match=-
        ///
        /// Every value in it was checked, so no field holds a blank or a line break.
        public var text: String {
            switch self {
            case .link(let interface, let mtu): return "link \(interface) mtu \(mtu)"
            case .address(let interface, let address): return "address \(interface) \(address)"
            case .route(let route):
                switch route.via {
                case .interface(let name): return "route \(route.network) interface \(name)"
                case .gateway(let gateway): return "route \(route.network) gateway \(gateway)"
                case .reject: return "route \(route.network) reject"
                }
            case .dns(let dns):
                func list(_ items: [String]) -> String { items.isEmpty ? "-" : items.joined(separator: ",") }
                return "dns \(dns.service) \(dns.interface) \(dns.primary ? "primary" : "split")"
                    + " servers=\(list(dns.servers.map(\.description))) search=\(list(dns.searchDomains)) match=\(list(dns.matchDomains))"
            }
        }

        /// Exactly `text`'s form, every value checked again.
        public init?(text: String) {
            let words = text.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
            guard let kind = words.first else { return nil }
            switch kind {
            case "link":
                guard words.count == 4, OpenConnectRecord.isInterface(words[1]), words[2] == "mtu",
                    let mtu = OpenConnectNetwork.decimal(words[3], max: OpenConnectNetwork.mtuRange.upperBound),
                    OpenConnectNetwork.mtuRange.contains(mtu)
                else { return nil }
                self = .link(interface: words[1], mtu: mtu)
            case "address":
                guard words.count == 3, OpenConnectRecord.isInterface(words[1]), let address = IPAddress(words[2]), !address.isSpecial,
                    !address.isIPv4Embedded,
                    address.description == words[2]
                else { return nil }
                self = .address(interface: words[1], address)
            case "route":
                guard words.count >= 3, let network = IPNetwork(words[1]), network.description == words[1], !network.isIPv4Embedded else {
                    return nil
                }
                switch (words[2], words.count) {
                case ("interface", 4):
                    guard OpenConnectRecord.isInterface(words[3]) else { return nil }
                    self = .route(Route(network, via: .interface(words[3])))
                case ("reject", 3):
                    self = .route(Route(network, via: .reject))
                case ("gateway", 5):
                    let address = words[3] == "link" ? nil : IPAddress(words[3])
                    guard words[3] == "link" || (address?.description == words[3] && address?.family == network.family),
                        let gateway = Gateway(address: address, interface: words[4])
                    else { return nil }
                    self = .route(Route(network, via: .gateway(gateway)))
                default: return nil
                }
            case "dns":
                guard words.count == 7, Self.isService(words[1]), OpenConnectRecord.isInterface(words[2]),
                    words[3] == "primary" || words[3] == "split",
                    let servers = Self.list(words[4], key: "servers", { IPAddress($0).flatMap { $0.isUnspecified || $0.isIPv4Embedded ? nil : $0 } }),
                    !servers.isEmpty, servers.count <= OpenConnectNetwork.maxDNSServers,
                    let search = Self.list(words[5], key: "search", DomainName.normalize),
                    let match = Self.list(words[6], key: "match", DomainName.normalize),
                    search.count <= OpenConnectNetwork.maxDomains, match.count <= 2 * OpenConnectNetwork.maxDomains
                else { return nil }
                self = .dns(
                    DNS(
                        service: words[1], interface: words[2], primary: words[3] == "primary", servers: servers, searchDomains: search,
                        matchDomains: match))
            default:
                return nil
            }
            guard self.text == text else { return nil }
        }

        /// `key=a,b` or `key=-`, each item parsed by `item`.
        static func list<T>(_ word: String, key: String, _ item: (String) -> T?) -> [T]? {
            guard word.hasPrefix(key + "=") else { return nil }
            let value = word.dropFirst(key.count + 1)
            if value == "-" { return [] }
            var out: [T] = []
            for part in value.split(separator: ",", omittingEmptySubsequences: false) {
                guard let parsed = item(String(part)) else { return nil }
                out.append(parsed)
            }
            return out
        }

        /// `passtunnel-<uid>-<profile id>`.
        static func isService(_ s: String) -> Bool {
            let parts = s.split(separator: "-", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count == 3, parts[0] == "passtunnel", let uid = UInt32(parts[1]), String(uid) == parts[1] else { return false }
            return HelperCore.isValidProfileID(String(parts[2]))
        }

        /// A route around the tunnel: it depends on the default gateway, which may change under a session.
        public var isThroughGateway: Bool {
            if case .route(let route) = self, case .gateway = route.via { return true }
            return false
        }
    }

    /// Why no plan could be made.
    public enum Failure: Error, Equatable, Sendable, CustomStringConvertible {
        /// A route would capture the VPN server's address, and there is no default gateway of its family to
        /// keep it reachable around the tunnel.
        case noGateway(IPAddress.Family)

        public var description: String {
            switch self {
            case .noGateway(let family):
                let name = family == .ipv4 ? "IPv4" : "IPv6"
                return "there is no \(name) default route to keep the VPN server reachable outside the tunnel"
            }
        }
    }

    public let interface: String
    public let changes: [Change]
    /// Every family that has an address sends all its traffic into the tunnel (and routes are set).
    public let fullTunnel: Bool
    /// Families without an address whose traffic is refused, since the other family is a full tunnel.
    public let blocked: [IPAddress.Family]
    /// Routes into the tunnel the server asked for that were left out because they lie inside a local
    /// network (`Underlay.attached`).
    public let keptLocal: Int

    public var addresses: [IPAddress] {
        changes.compactMap { if case .address(_, let a) = $0 { return a } else { return nil } }
    }

    public var dns: DNS? {
        changes.lazy.compactMap { if case .dns(let d) = $0 { return d } else { return nil } }.first
    }

    /// Routes into the tunnel.
    public var tunnelRoutes: [Route] {
        changes.compactMap { if case .route(let r) = $0, case .interface = r.via { return r } else { return nil } }
    }

    // MARK: connect

    /// What `connect` applies, in this order:
    /// 1. the interface: MTU and up, then its addresses (host addresses only);
    /// 2. with `set_routes`, decided per family. A family with an address is a full tunnel when the server's
    ///    includes are none or cover every address together (`0.0.0.0/0`, or `0/1` and `128/1`, …): then the
    ///    two halves of its space (`0/1` and `128/1`, `::/1` and `8000::/1`, never `default`) go into the tunnel.
    ///    Otherwise its includes, then the assigned network (when the server gave one, `/1` to `/31` or `/127`)
    ///    and, with `set_dns`, a host route to each DNS server of the family, where no include holds them; but
    ///    none of these that lies inside a local network (`Underlay.attached`): local networks stay local, and
    ///    such a route is counted in `keptLocal` instead. The excludes of the family go through its original
    ///    gateway (left out when it has none). A family without an address while the other one is a full tunnel
    ///    is blocked: reject routes for both halves of its space, and every include, exclude and DNS route the
    ///    server gave for it is ignored, so nothing makes a hole in the block. Then, first of all routes, a host
    ///    route to `VPNGATEWAY` through the original gateway of its family whenever one of the routes into the
    ///    tunnel or a reject route would capture it (not for a server on this machine). A destination is routed
    ///    once, in the order server host route, reject routes, excludes, routes into the tunnel: the first wins
    ///    (an exclude over an include of the same network);
    /// 3. with `set_dns` and DNS servers (but those of a blocked family): DNS, primary for a full tunnel,
    ///    otherwise for the split DNS and default domains only (none at all when there are no such domains).
    public static func connect(_ network: OpenConnectNetwork, policy: OpenConnectPolicy, underlay: Underlay) throws -> OpenConnectPlan {
        let built = build(network, policy: policy, underlay: underlay)
        if let family = built.missingGateway { throw Failure.noGateway(family) }
        return built.plan
    }

    /// Whether `networks` together hold every address of `space`.
    static func covers(_ networks: [IPNetwork], _ space: IPNetwork) -> Bool {
        let relevant = networks.filter { $0.contains(space) || space.contains($0) }
        if relevant.contains(where: { $0.contains(space) }) { return true }
        guard !relevant.isEmpty, let (low, high) = space.split() else { return false }
        return covers(relevant, low) && covers(relevant, high)
    }

    /// The plan, and the family of the VPN server's address when its host route is needed but that family
    /// has no usable gateway (then the plan has no such route).
    static func build(_ n: OpenConnectNetwork, policy: OpenConnectPolicy, underlay: Underlay) -> (
        plan: OpenConnectPlan, missingGateway: IPAddress.Family?
    ) {
        let tunnel = n.interface
        var changes: [Change] = [.link(interface: tunnel, mtu: n.mtu)]
        for assigned in [n.ipv4, n.ipv6] {
            if let assigned { changes.append(.address(interface: tunnel, assigned.address)) }
        }

        let families: [IPAddress.Family] = [.ipv4, .ipv6]
        var full: [IPAddress.Family: Bool] = [:]
        var blocked: [IPAddress.Family] = []
        var keptLocal = 0
        var missingGateway: IPAddress.Family?
        if policy.setRoutes {
            let local = underlay.local(tunnel: tunnel)
            var excludes: [Route] = []
            var rejects: [Route] = []
            var inside: [Route] = []
            for family in families {
                guard let assigned = n.assigned(family) else { continue }
                let includes = n.includes(family)
                let space = IPNetwork(address: IPAddress.mask(family: family, length: 0), prefixLength: 0)!
                if includes.isEmpty || covers(includes, space) {
                    full[family] = true
                    inside += IPNetwork.halves(family).map { Route($0, via: .interface(tunnel)) }
                } else {
                    full[family] = false
                    var wanted = includes
                    // The assigned network and the DNS servers, unless an include holds them already.
                    var more: [IPNetwork] = []
                    if let net = assigned.network, net.prefixLength > 0, net.prefixLength < family.bits { more.append(net) }
                    if policy.setDNS { more += n.dnsServers.filter { $0.family == family }.map(IPNetwork.host) }
                    wanted += more.filter { net in !includes.contains { $0.contains(net) } }
                    for net in wanted {
                        if local.contains(where: { $0.contains(net) }) {
                            keptLocal += 1
                        } else {
                            inside.append(Route(net, via: .interface(tunnel)))
                        }
                    }
                }
                if let gateway = underlay.usable(family, tunnel: tunnel) {
                    excludes += n.excludes(family).map { Route($0, via: .gateway(gateway)) }
                }
            }
            for family in families where n.assigned(family) == nil && full[family == .ipv4 ? .ipv6 : .ipv4] == true {
                blocked.append(family)
                rejects += IPNetwork.halves(family).map { Route($0, via: .reject) }
            }

            var routes: [Route] = []
            let server = n.gateway
            if !server.isLoopback, (rejects + inside).contains(where: { $0.network.contains(server) }) {
                if let gateway = underlay.usable(server.family, tunnel: tunnel) {
                    routes.append(Route(.host(server), via: .gateway(gateway)))
                } else {
                    missingGateway = server.family
                }
            }
            // Rejects come before anything the server sent, so nothing of the server's removes the block.
            var seen = Set(routes.map(\.network))
            for route in rejects + excludes + inside where seen.insert(route.network).inserted {
                routes.append(route)
            }
            changes += routes.map { .route($0) }
        }

        let assignedFamilies = families.filter { n.assigned($0) != nil }
        let fullTunnel = policy.setRoutes && assignedFamilies.allSatisfy { full[$0] == true }
        // A blocked family's DNS servers cannot be reached: they are left out.
        let servers = n.dnsServers.filter { !blocked.contains($0.family) }
        if policy.setDNS, !servers.isEmpty {
            var match: [String] = []
            if !fullTunnel {
                for domain in n.splitDNSDomains + n.defaultDomains where !match.contains(domain) { match.append(domain) }
            }
            if fullTunnel || !match.isEmpty {
                changes.append(
                    .dns(
                        DNS(
                            service: DNS.service(uid: policy.uid, profileID: policy.profileID), interface: tunnel, primary: fullTunnel,
                            servers: servers, searchDomains: n.defaultDomains, matchDomains: match)))
            }
        }
        return (
            OpenConnectPlan(interface: tunnel, changes: changes, fullTunnel: fullTunnel, blocked: blocked, keptLocal: keptLocal),
            missingGateway
        )
    }

    init(interface: String, changes: [Change], fullTunnel: Bool, blocked: [IPAddress.Family], keptLocal: Int) {
        self.interface = interface
        self.changes = changes
        self.fullTunnel = fullTunnel
        self.blocked = blocked
        self.keptLocal = keptLocal
    }

    // MARK: attempt-reconnect, reconnect

    /// What `attempt-reconnect` changes: the routes around the tunnel (the VPN server's host route and the
    /// excludes) follow the default gateway, which may have changed under the session (another network).
    /// Per family that has a usable gateway now: the session's own routes through another gateway are removed
    /// (`remove`, newest first), then the routes `connect` would add now and the record does not hold are added
    /// (`add`). A family without a gateway right now (the network is down while openconnect retries) is left
    /// as it is.
    public static func refresh(
        _ n: OpenConnectNetwork, policy: OpenConnectPolicy, underlay: Underlay, record: OpenConnectRecord
    ) -> (remove: [Change], add: [Change]) {
        let wanted = build(n, policy: policy, underlay: underlay).plan.changes.filter(\.isThroughGateway)
        let applied = Set(record.applied)
        let owned = record.owned
        var remove: [Change] = []
        var add: [Change] = []
        for family in [IPAddress.Family.ipv4, .ipv6] where underlay.usable(family, tunnel: n.interface) != nil {
            let mine = wanted.filter { Self.family(of: $0) == family }
            remove += owned.reversed().filter { $0.isThroughGateway && Self.family(of: $0) == family && !mine.contains($0) }
            add += mine.filter { !applied.contains($0) }
        }
        return (remove, add)
    }

    /// Whether `reconnect` finds what `connect` set up: the same changes, but for the routes around the tunnel,
    /// which follow the gateway (`refresh`). openconnect refuses a reconnect with another address or netmask
    /// itself (`library.c` 676–712); anything else that differs fails the reconnect, and the session is stopped
    /// for a new connect to set up afresh.
    public static func matches(_ n: OpenConnectNetwork, policy: OpenConnectPolicy, underlay: Underlay, record: OpenConnectRecord) -> Bool {
        let wanted = Set(build(n, policy: policy, underlay: underlay).plan.changes.filter { !$0.isThroughGateway })
        return wanted == Set(record.applied.filter { !$0.isThroughGateway })
    }

    static func family(of change: Change) -> IPAddress.Family? {
        if case .route(let route) = change { return route.network.family }
        return nil
    }
}
