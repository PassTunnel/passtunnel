import Foundation
import PassTunnelShared

#if canImport(Glibc)
import Glibc
#endif

/// Linux as openconnect's hook sees it (`OpenConnectSystem`, docs/LINUX.md, "Cisco AnyConnect"): the routing
/// table from rtnetlink dumps (`Netlink`, read only, no privileges, no program run, the kernel's own fields:
/// table, type, metric, next hops), the interfaces from `if_nametoindex`, sysfs (MTU and flags) and
/// `getifaddrs`, changes through iproute2's `ip` from a fixed, checked path with argument lists
/// (`OpenConnectCommand.Tools.linux`, `ToolRunner`: the fixed environment, no shell, its own process group, a
/// time limit), and DNS through `DNSApplier`, unchanged: the same backends, record and lock as OpenVPN's DNS
/// hook. One system serves one session: its directory holds `DNSApplier`'s record.
public final class LinuxOpenConnectSystem: OpenConnectSystem {
    /// Where distributions keep `ip`; the first that exists is used, once it passes `TrustedPath`.
    public static let ipCandidates = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"]

    /// What the kernel says; replaced in tests.
    public struct Kernel {
        public var interfaceIndex: (String) -> UInt32? = { name in
            let index = if_nametoindex(name)
            return index == 0 ? nil : index
        }
        /// MTU and `IFF_UP` (`/sys/class/net/<name>/mtu`, `/flags`).
        public var link: (String) -> (mtu: Int, up: Bool)? = LinuxOpenConnectSystem.sysfsLink
        /// Every address of every interface (`getifaddrs`).
        public var addresses: () -> [InterfaceAddress] = LinuxOpenConnectSystem.interfaceAddresses
        /// The routing table's routes (rtnetlink); nil when it cannot be read.
        public var routes: () -> [KernelRoute]? = LinuxOpenConnectSystem.kernelRoutes
        /// Runs a program from its path with its arguments, for at most a time; nil when it did not start.
        public var run: (String, [String], TimeInterval) -> ToolRunner.Result? = { path, arguments, timeout in
            ToolRunner.run(path, arguments: arguments, timeout: timeout)
        }

        public init() {}
    }

    /// An address on an interface, with what `getifaddrs` says of the interface.
    public struct InterfaceAddress: Equatable {
        public var name: String
        public var address: IPAddress
        public var prefixLength: Int?
        public var up: Bool
        public var loopback: Bool
        public var pointToPoint: Bool

        public init(name: String, address: IPAddress, prefixLength: Int?, up: Bool, loopback: Bool = false, pointToPoint: Bool = false) {
            self.name = name
            self.address = address
            self.prefixLength = prefixLength
            self.up = up
            self.loopback = loopback
            self.pointToPoint = pointToPoint
        }
    }

    let session: SessionDirectory?
    let dns: DNSApplier
    let kernel: Kernel
    /// The checked `ip`, or why there is none.
    let ip: Result<String, IPFailure>
    public private(set) var dnsFailure: String?

    /// The system for the session in `session` (nil: no DNS can be changed or removed, as for a run that
    /// proved no session); `ip` is looked for among `ipCandidates`, checked with `TrustedPath` (`owner`, `base`:
    /// root and `/`, but in tests).
    public init(
        session: SessionDirectory?, dns: DNSApplier, kernel: Kernel = Kernel(), ipCandidates: [String] = LinuxOpenConnectSystem.ipCandidates,
        owner: uid_t = 0, base: String = "/"
    ) {
        self.session = session
        self.dns = dns
        self.kernel = kernel
        self.ip = Self.checkedIP(ipCandidates, owner: owner, base: base)
    }

    /// Why there is no `ip` to run.
    struct IPFailure: Error, CustomStringConvertible {
        let description: String
    }

    /// The first of `candidates` that exists, resolved and checked as a tool is.
    static func checkedIP(_ candidates: [String], owner: uid_t, base: String) -> Result<String, IPFailure> {
        guard let candidate = candidates.first(where: { access($0, F_OK) == 0 }) else {
            return .failure(
                IPFailure(
                    description: "ip is not installed (none of \(candidates.joined(separator: ", ")) exists). "
                        + "Install the distribution's iproute2 package."))
        }
        guard let real = HelperCore.realPath(candidate) else {
            return .failure(
                IPFailure(description: String(describing: ToolFailure.untrusted(name: "ip", path: candidate, reason: "its path cannot be resolved.")))
            )
        }
        do {
            try TrustedPath.check(real, owner: owner, base: base)
        } catch {
            return .failure(
                IPFailure(description: String(describing: ToolFailure.untrusted(name: "ip", path: real, reason: String(describing: error)))))
        }
        return .success(real)
    }

    public var tools: OpenConnectCommand.Tools {
        switch ip {
        case .success(let path): return .linux(ip: path)
        case .failure: return .linux(ip: Self.ipCandidates[0])
        }
    }

    // MARK: Interfaces

    public func interfaceIndex(_ name: String) -> UInt32? { kernel.interfaceIndex(name) }

    public func interfaceLink(_ name: String) -> (mtu: Int, up: Bool)? {
        guard OpenConnectPlan.Gateway.isInterfaceName(name) else { return nil }
        return kernel.link(name)
    }

    public func interfaceAddresses(_ name: String) -> [IPAddress] {
        kernel.addresses().filter { $0.name == name }.map(\.address)
    }

    /// The networks of the addresses of every interface that is up, but loopback and point-to-point links
    /// (tunnels, whose address is no network this computer is on): the prefixes the kernel puts on-link for
    /// them, from the interfaces' own addresses, not from the routing table, which another session's routes
    /// into its tunnel could mimic.
    public func attachedNetworks() -> [OpenConnectPlan.Attached] {
        Self.attached(kernel.addresses())
    }

    static func attached(_ addresses: [InterfaceAddress]) -> [OpenConnectPlan.Attached] {
        var out: [OpenConnectPlan.Attached] = []
        for entry in addresses where entry.up && !entry.loopback && !entry.pointToPoint {
            guard let length = entry.prefixLength, length > 0, length < entry.address.family.bits,
                let network = IPNetwork(address: entry.address.masked(length), prefixLength: length)
            else { continue }
            let attached = OpenConnectPlan.Attached(network, interface: entry.name)
            if !out.contains(attached) { out.append(attached) }
        }
        return out
    }

    public func routes() -> [KernelRoute]? { kernel.routes() }

    // MARK: Programs

    /// Runs `command` if it is the checked `ip` (nothing else is ever run), with its argument list, for at most
    /// `timeout`; its output, as one line of at most 200 bytes, goes into a failure's reason.
    public func run(_ command: OpenConnectCommand, timeout: TimeInterval) -> OpenConnectCommand.Result {
        let path: String
        switch ip {
        case .failure(let reason): return .init(status: nil, output: VPNHook.oneLine(String(describing: reason), maxBytes: 200))
        case .success(let checked): path = checked
        }
        guard command.executable == path else { return .init(status: nil, output: "not the checked ip") }
        guard let result = kernel.run(path, command.arguments, timeout) else { return .init(status: nil, output: "could not be started") }
        let text = result.output.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\t", with: " ")
        let output = text.utf8.allSatisfy { $0 == 0x20 } ? "" : VPNHook.oneLine(text, maxBytes: 200)
        return .init(status: result.status, output: output)
    }

    // MARK: DNS

    /// `DNSApplier`'s settings for the plan's DNS: a full tunnel's servers take every name (the default route of
    /// systemd-resolved's link, `~.`); otherwise the match domains are routing domains (`~domain`), resolved
    /// through the tunnel and never searched. The search domains are searched in either case. On the
    /// resolvconf and file backends, which cannot route names, every name goes through the tunnel.
    static func settings(_ dns: OpenConnectPlan.DNS) throws -> DNSSettings {
        try DNSSettings(
            servers: dns.servers.map(\.description), searchDomains: dns.searchDomains,
            routingDomains: dns.primary ? [] : dns.matchDomains, fullTunnel: dns.primary)
    }

    /// The service a session's DNS is written under: only this session's (`passtunnel-<uid>-<profile ID>`).
    func isOwnService(_ service: String) -> Bool {
        guard let session else { return false }
        let profileID = (session.path as NSString).lastPathComponent
        return service == OpenConnectPlan.DNS.service(uid: session.ownerUID, profileID: profileID)
    }

    public func setDNS(_ settings: OpenConnectDNSSettings) -> Bool {
        dnsFailure = nil
        guard let session, isOwnService(settings.service) else {
            dnsFailure = "the DNS settings are not this session's"
            return false
        }
        do {
            try dns.apply(Self.settings(settings.dns), interface: settings.dns.interface, in: session)
            return true
        } catch {
            dnsFailure = "setting DNS failed: " + String(describing: error)
            return false
        }
    }

    /// Whether the session's DNS is still in effect as it was set up: `DNSApplier`'s record is there, for this
    /// tunnel with the index it has now, and what the system resolves with says so (`DNSApplier.verify`: the
    /// link's servers, domains and default route as systemd-resolved reports them, the servers in the
    /// resolv.conf resolvconf writes, or `/etc/resolv.conf` still exactly as PassTunnel wrote it). Anything
    /// that differs or cannot be established fails openconnect's reconnect check.
    public func hasDNS(_ settings: OpenConnectDNSSettings) -> Bool {
        dnsFailure = nil
        guard let session, isOwnService(settings.service), let record = try? DNSRecord.load(in: session),
            record.interface == settings.dns.interface, kernel.interfaceIndex(record.interface) == record.index,
            let wanted = try? Self.settings(settings.dns)
        else { return false }
        if let mismatch = dns.verify(wanted, in: session) {
            dnsFailure = mismatch
            return false
        }
        return true
    }

    /// Reverts the session's DNS (`DNSApplier.revert(in:)`): true once nothing is recorded any more. Why a
    /// revert did not finish goes to standard error (the hook's: the session log; the daemon's: the journal).
    public func removeDNS(service: String) -> Bool {
        guard let session, isOwnService(service) else { return false }
        let message = dns.revert(in: session)
        guard DNSRecord.isRecorded(in: session) else { return true }
        if let message { DaemonLog.info("\(service): \(message)") }
        return false
    }

    // MARK: The kernel

    /// `IFF_UP`, `IFF_LOOPBACK`, `IFF_POINTOPOINT` (`linux/if.h`).
    static let up: UInt32 = 0x1, loopback: UInt32 = 0x8, pointToPoint: UInt32 = 0x10

    /// MTU and `IFF_UP` from sysfs (`/sys/class/net/<name>/mtu`, `/sys/class/net/<name>/flags`, hexadecimal).
    static func sysfsLink(_ name: String) -> (mtu: Int, up: Bool)? {
        guard OpenConnectPlan.Gateway.isInterfaceName(name),
            let mtuText = try? String(contentsOfFile: "/sys/class/net/\(name)/mtu", encoding: .utf8),
            let flagsText = try? String(contentsOfFile: "/sys/class/net/\(name)/flags", encoding: .utf8),
            let mtu = Int(mtuText.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return nil }
        let hex = flagsText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hex.hasPrefix("0x"), let flags = UInt32(hex.dropFirst(2), radix: 16) else { return nil }
        return (mtu, flags & Self.up != 0)
    }

    /// Every IPv4 and IPv6 address of every interface (`getifaddrs`), with its prefix length and the
    /// interface's flags.
    static func interfaceAddresses() -> [InterfaceAddress] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return [] }
        defer { freeifaddrs(first) }
        var out: [InterfaceAddress] = []
        var cursor = first
        while let entry = cursor?.pointee {
            defer { cursor = entry.ifa_next }
            guard let name = entry.ifa_name, let sa = entry.ifa_addr, let address = address(sa) else { continue }
            let flags = entry.ifa_flags
            out.append(
                InterfaceAddress(
                    name: String(cString: name), address: address,
                    prefixLength: entry.ifa_netmask.flatMap { Self.address($0)?.maskLength },
                    up: flags & Self.up != 0, loopback: flags & Self.loopback != 0,
                    pointToPoint: flags & Self.pointToPoint != 0))
        }
        return out
    }

    /// The address of a `sockaddr_in` or `sockaddr_in6`; nil for another family.
    static func address(_ sa: UnsafeMutablePointer<sockaddr>) -> IPAddress? {
        switch Int32(sa.pointee.sa_family) {
        case AF_INET:
            return sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { pointer in
                withUnsafeBytes(of: pointer.pointee.sin_addr) { IPAddress(bytes: Array($0)) }
            }
        case AF_INET6:
            return sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { pointer in
                withUnsafeBytes(of: pointer.pointee.sin6_addr) { IPAddress(bytes: Array($0)) }
            }
        default:
            return nil
        }
    }

    /// The routes of every table (`Netlink.dump`), the main table's as `KernelRoute.linux` gives them; nil when
    /// the dump fails.
    static func kernelRoutes() -> [KernelRoute]? {
        var routes: [Netlink.Route] = []
        let read = Netlink.dump(Netlink.getRoute) { type, body in
            if type == Netlink.newRoute, routes.count < maxRoutes, let route = Netlink.Route(body) { routes.append(route) }
        }
        guard read else { return nil }
        return KernelRoute.linux(routes) { index in
            var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
            return if_indextoname(UInt32(bitPattern: index), &name) != nil ? String(cString: name) : nil
        }
    }

    /// At most this many routes are read: a client's tables are far smaller.
    static let maxRoutes = 100_000
}
