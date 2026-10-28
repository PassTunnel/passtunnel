import Foundation

/// What the hook reads from and changes on the Mac, behind a protocol: the hook's logic (`OpenConnectHook`)
/// runs against a fake in the tests, which records every command and every DNS write, and against
/// `MacOpenConnectSystem` in the hook and the helper (docs/ARCHITECTURE.md, "The hook", steps 4 and 7).
/// The changes are the plan's (`OpenConnectPlan.Change`); how each one is made is `OpenConnectCommand`'s
/// argument lists and `OpenConnectDNSSettings`' keys, both pure and tested to the byte.
public protocol OpenConnectSystem: AnyObject {
    /// The interface's index; nil when there is no such interface.
    func interfaceIndex(_ name: String) -> UInt32?
    /// The addresses on an interface (empty when there is none).
    func interfaceAddresses(_ name: String) -> [IPAddress]
    /// The networks attached to the Mac's interfaces (`OpenConnectPlan.Underlay.attached`).
    func attachedNetworks() -> [OpenConnectPlan.Attached]
    /// Every IPv4 and IPv6 route of the routing table; nil when it cannot be read.
    func routes() -> [KernelRoute]?
    /// Runs one program from its fixed path with its argument list, for at most `timeout` seconds.
    func run(_ command: OpenConnectCommand, timeout: TimeInterval) -> OpenConnectCommand.Result
    /// Writes a session's dynamic DNS keys (and removes those `settings` leaves out), all at once.
    func setDNS(_ settings: OpenConnectDNSSettings) -> Bool
    /// Removes a session's dynamic DNS keys; true also when there were none.
    func removeDNS(service: String) -> Bool
}

/// A route of the routing table, as the hook compares it with the routes it adds.
public struct KernelRoute: Equatable, Sendable {
    public var network: IPNetwork
    /// The next hop's address (`RTF_GATEWAY`); nil for a route to an interface.
    public var gateway: IPAddress?
    /// The interface the route leaves through (`lo0` for a reject route).
    public var interface: String
    /// `RTF_REJECT` or `RTF_BLACKHOLE`.
    public var reject: Bool
    /// `RTF_IFSCOPE`: only for traffic bound to the interface; an unscoped route of the same destination is
    /// another entry.
    public var scoped: Bool
    /// Made by the kernel for a destination in use or a neighbour (`RTF_WASCLONED`, `RTF_LLINFO`): an added
    /// route replaces it, so it never stands in the way.
    public var cloned: Bool

    public init(
        network: IPNetwork, gateway: IPAddress? = nil, interface: String, reject: Bool = false, scoped: Bool = false, cloned: Bool = false
    ) {
        self.network = network
        self.gateway = gateway
        self.interface = interface
        self.reject = reject
        self.scoped = scoped
        self.cloned = cloned
    }

    /// The entry a `route add` of `route` makes.
    public init(_ route: OpenConnectPlan.Route) {
        switch route.via {
        case .interface(let name): self.init(network: route.network, interface: name)
        case .gateway(let gateway): self.init(network: route.network, gateway: gateway.address, interface: gateway.interface)
        case .reject:
            let loopback = route.network.family == .ipv4 ? IPAddress("127.0.0.1") : IPAddress("::1")
            self.init(network: route.network, gateway: loopback, interface: "lo0", reject: true)
        }
    }

    /// Whether a `route add` of this destination would find this entry in its way: an unscoped route the
    /// kernel does not replace by itself.
    public var holdsDestination: Bool { !scoped && !cloned }

    /// Whether this entry is `route` as the hook adds it: the same destination and the same next hop (the
    /// interface, the gateway on its interface, or a reject route).
    public func `is`(_ route: OpenConnectPlan.Route) -> Bool {
        guard network == route.network, holdsDestination else { return false }
        switch route.via {
        case .interface(let name): return gateway == nil && !reject && interface == name
        case .gateway(let next): return gateway == next.address && !reject && interface == next.interface
        case .reject: return reject
        }
    }
}

/// One program the hook runs: a fixed absolute path and an argument list, never a shell. `effect` says what
/// it changes, for the tests' fake system; the real system runs `executable` with `arguments` and nothing else.
public struct OpenConnectCommand: Equatable, Sendable {
    public static let ifconfig = "/sbin/ifconfig"
    public static let route = "/sbin/route"

    public enum Effect: Equatable, Sendable {
        case link(interface: String, mtu: Int)
        case linkDown(interface: String)
        case addAddress(interface: String, IPAddress)
        case deleteAddress(interface: String, IPAddress)
        case addRoute(OpenConnectPlan.Route)
        case deleteRoute(OpenConnectPlan.Route)
    }

    /// How a run ended: the exit status (nil: it did not start, or was killed at its time limit) and the
    /// start of what it printed, as one line (`VPNHook.oneLine`).
    public struct Result: Equatable, Sendable {
        public var status: Int32?
        public var output: String

        public init(status: Int32?, output: String = "") {
            self.status = status
            self.output = output
        }

        public var succeeded: Bool { status == 0 }

        /// `exit status 1: <output>`, `timed out`.
        public var summary: String {
            let head = status.map { "exit status \($0)" } ?? "did not finish"
            return output.isEmpty ? head : head + ": " + output
        }
    }

    public let executable: String
    public let arguments: [String]
    public let effect: Effect

    /// The command as one line, for the golden tests and the failure reasons.
    public var line: String { ([executable] + arguments).joined(separator: " ") }

    /// `ifconfig utun5 mtu 1406 up`.
    public static func link(_ interface: String, mtu: Int) -> OpenConnectCommand {
        OpenConnectCommand(executable: ifconfig, arguments: [interface, "mtu", String(mtu), "up"], effect: .link(interface: interface, mtu: mtu))
    }

    /// `ifconfig utun5 down`: the tunnel carries nothing more before openconnect closes it.
    public static func linkDown(_ interface: String) -> OpenConnectCommand {
        OpenConnectCommand(executable: ifconfig, arguments: [interface, "down"], effect: .linkDown(interface: interface))
    }

    /// A host address: `ifconfig utun5 inet 10.0.0.2 10.0.0.2 netmask 255.255.255.255` (a point-to-point
    /// link to itself) or `ifconfig utun5 inet6 2001:db8::2 prefixlen 128`.
    public static func addAddress(_ interface: String, _ address: IPAddress) -> OpenConnectCommand {
        let a = address.description
        let arguments =
            address.family == .ipv4
            ? [interface, "inet", a, a, "netmask", "255.255.255.255"] : [interface, "inet6", a, "prefixlen", "128"]
        return OpenConnectCommand(executable: ifconfig, arguments: arguments, effect: .addAddress(interface: interface, address))
    }

    /// `ifconfig utun5 inet 10.0.0.2 delete`, `ifconfig utun5 inet6 2001:db8::2 delete`.
    public static func deleteAddress(_ interface: String, _ address: IPAddress) -> OpenConnectCommand {
        OpenConnectCommand(
            executable: ifconfig, arguments: [interface, address.family == .ipv4 ? "inet" : "inet6", address.description, "delete"],
            effect: .deleteAddress(interface: interface, address))
    }

    /// `route -n add <destination> <next hop>`:
    ///
    ///     route -n add -inet -net 0.0.0.0 -netmask 128.0.0.0 -interface utun5
    ///     route -n add -inet -host 192.0.2.10 198.51.100.1
    ///     route -n add -inet -host 192.0.2.10 -interface ppp0                       (a gateway link without an address)
    ///     route -n add -inet6 -net 2001:db8:: -prefixlen 32 fe80::1%en0             (a link-local next hop names its interface)
    ///     route -n add -inet6 -net :: -prefixlen 1 ::1 -reject
    public static func addRoute(_ route: OpenConnectPlan.Route) -> OpenConnectCommand {
        var arguments = ["-n", "add"] + destination(route.network)
        switch route.via {
        case .interface(let name):
            arguments += ["-interface", name]
        case .gateway(let gateway):
            if let address = gateway.address {
                arguments.append(address.isLinkLocal && address.family == .ipv6 ? "\(address)%\(gateway.interface)" : address.description)
            } else {
                arguments += ["-interface", gateway.interface]
            }
        case .reject:
            arguments += [route.network.family == .ipv4 ? "127.0.0.1" : "::1", "-reject"]
        }
        return OpenConnectCommand(executable: Self.route, arguments: arguments, effect: .addRoute(route))
    }

    /// `route -n delete <destination>`: the hook checks the routing table first that the entry there is
    /// still the one it added (`KernelRoute.is`), so the next hop is left out.
    public static func deleteRoute(_ route: OpenConnectPlan.Route) -> OpenConnectCommand {
        OpenConnectCommand(executable: Self.route, arguments: ["-n", "delete"] + destination(route.network), effect: .deleteRoute(route))
    }

    /// `-inet -host A`, `-inet -net A -netmask M`, `-inet6 -host A`, `-inet6 -net A -prefixlen L`: always
    /// the family and the length spelled out, never a class or a name.
    static func destination(_ network: IPNetwork) -> [String] {
        let family = network.family == .ipv4 ? "-inet" : "-inet6"
        if network.prefixLength == network.family.bits { return [family, "-host", network.address.description] }
        if network.family == .ipv4 {
            return [family, "-net", network.address.description, "-netmask", IPAddress.mask(family: .ipv4, length: network.prefixLength).description]
        }
        return [family, "-net", network.address.description, "-prefixlen", String(network.prefixLength)]
    }
}

/// A session's DNS as dynamic keys of the system configuration (`SCDynamicStore`), never a `Setup:` key:
/// `State:/Network/Service/passtunnel-<uid>-<profile id>/DNS`, and for a full tunnel `/IPv4` and `/IPv6` (for
/// the families the tunnel has an address of). They disappear on restart and are removed by the revert.
///
/// How the DNS wins (configd's IPMonitor builds the resolver configuration from the `State:` services):
/// - **Split tunnel:** the `DNS` entity alone, with `SupplementalMatchDomains`: a resolver for those domains,
///   whatever the primary service is (what OpenVPN's own macOS `dns-updown` writes for its split DNS).
/// - **Full tunnel:** the service is made the primary one, whose `DNS` entity becomes the default resolver
///   (`State:/Network/Global/DNS`, resolver #1 of `scutil --dns`). IPMonitor elects the primary service among
///   those with a router: `OverridePrimary` = 1 ranks a service first, but a service without `Router` is not
///   eligible and keeps only scoped settings (as the system's own `utun` services, which carry
///   `PrimaryRank Scoped`, show in `scutil`). So the `IPv4`/`IPv6` entities name the tunnel as the router: the
///   tunnel's own address on its point-to-point link (`Router`), with `Addresses`, the host mask and
///   `InterfaceName`. OpenVPN's `dns-updown` gets the same result by rewriting the primary service's `Setup:`
///   DNS, which PassTunnel never does: a crash would leave it changed for good.
public struct OpenConnectDNSSettings: Equatable, Sendable {
    /// A property list value, as the keys hold them.
    public enum Value: Equatable, Sendable {
        case string(String)
        case strings([String])
        case number(Int)
        case numbers([Int])
    }

    public let service: String
    /// Every key and its dictionary.
    public let values: [String: [String: Value]]

    public static func key(service: String, entity: String) -> String { "State:/Network/Service/\(service)/\(entity)" }

    /// The keys of a service, all of which a revert removes.
    public static func keys(service: String) -> [String] { ["IPv4", "IPv6", "DNS"].map { key(service: service, entity: $0) } }

    /// The keys `keys(service:)` holds that this set-up leaves out, removed when it is written.
    public var removedKeys: [String] { Self.keys(service: service).filter { values[$0] == nil } }

    /// For `dns` on a tunnel with `addresses`:
    /// - `DNS`: `ServerAddresses`; `SearchDomains` when there are any; `SupplementalMatchDomains` when the DNS is
    ///   not primary (the names resolved through the tunnel).
    /// - only when the DNS is primary (a full tunnel): `IPv4` with `Addresses`, `SubnetMasks`
    ///   (`255.255.255.255`), `Router` (the tunnel's address), `InterfaceName` and `OverridePrimary` = 1, and
    ///   `IPv6` likewise with `PrefixLength` (128), for each family the tunnel has an address of.
    public init(_ dns: OpenConnectPlan.DNS, addresses: [IPAddress]) {
        service = dns.service
        var values: [String: [String: Value]] = [:]
        if dns.primary {
            for family in [IPAddress.Family.ipv4, .ipv6] {
                let own = addresses.filter { $0.family == family }
                guard let first = own.first else { continue }
                var entity: [String: Value] = [
                    "Addresses": .strings(own.map(\.description)), "Router": .string(first.description),
                    "InterfaceName": .string(dns.interface), "OverridePrimary": .number(1)
                ]
                if family == .ipv4 {
                    entity["SubnetMasks"] = .strings(own.map { _ in "255.255.255.255" })
                } else {
                    entity["PrefixLength"] = .numbers(own.map { _ in 128 })
                }
                values[Self.key(service: dns.service, entity: family == .ipv4 ? "IPv4" : "IPv6")] = entity
            }
        }
        var entity: [String: Value] = ["ServerAddresses": .strings(dns.servers.map(\.description))]
        if !dns.searchDomains.isEmpty { entity["SearchDomains"] = .strings(dns.searchDomains) }
        if !dns.primary, !dns.matchDomains.isEmpty { entity["SupplementalMatchDomains"] = .strings(dns.matchDomains) }
        values[Self.key(service: dns.service, entity: "DNS")] = entity
        self.values = values
    }
}

extension OpenConnectPlan.Underlay {
    /// The underlay the routing table and the interfaces give, for a tunnel on `tunnel`: per family the
    /// unscoped default route, unless it leaves through the tunnel itself (a service the system made primary
    /// for a full tunnel's DNS); then the one scoped default route (`RTF_IFSCOPE`) of another interface that is
    /// no tunnel, if there is exactly one. The attached networks come from the interfaces' own addresses.
    public init(routes: [KernelRoute], attached: [OpenConnectPlan.Attached], tunnel: String) {
        func defaultGateway(_ family: IPAddress.Family) -> OpenConnectPlan.Gateway? {
            let defaults = routes.filter { $0.network.family == family && $0.network.prefixLength == 0 && !$0.reject && !$0.cloned }
            if let main = defaults.first(where: { !$0.scoped }), main.interface != tunnel {
                return OpenConnectPlan.Gateway(address: main.gateway, interface: main.interface)
            }
            let others = defaults.filter {
                $0.scoped && $0.interface != tunnel && !$0.interface.hasPrefix("utun") && !$0.interface.hasPrefix("ipsec")
            }
            guard let only = others.first, others.allSatisfy({ $0.gateway == only.gateway && $0.interface == only.interface }) else {
                return nil
            }
            return OpenConnectPlan.Gateway(address: only.gateway, interface: only.interface)
        }
        self.init(ipv4: defaultGateway(.ipv4), ipv6: defaultGateway(.ipv6), attached: attached)
    }
}
