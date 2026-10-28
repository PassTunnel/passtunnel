// macOS only: the routing socket's dump, the interfaces, the tools and the system configuration.
#if os(macOS)
import Foundation
import SystemConfiguration

/// The Mac as the hook sees it (`OpenConnectSystem`): the routing table from `sysctl` (`NET_RT_DUMP`, read
/// only), the interfaces from `getifaddrs`, changes through `/sbin/ifconfig` and `/sbin/route` with argument
/// lists (`Spawner`, a fixed environment, no shell, a time limit) and DNS through `SCDynamicStore` (dynamic
/// `State:` keys of PassTunnel's own services only).
public final class MacOpenConnectSystem: OpenConnectSystem {
    /// The only environment the tools get: never the hook's, which holds the server's values.
    static let toolEnvironment = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"]
    /// The most of a tool's output kept for a failure's reason.
    static let maxOutputBytes = 4096

    public init() {}

    public func interfaceIndex(_ name: String) -> UInt32? {
        let index = if_nametoindex(name)
        return index == 0 ? nil : index
    }

    public func interfaceAddresses(_ name: String) -> [IPAddress] {
        Self.interfaces().filter { $0.name == name }.map(\.address)
    }

    /// The networks of the addresses of every interface that is up, but loopback and point-to-point links
    /// (tunnels, whose address is no network the Mac is on): the prefixes the kernel puts on-link for them.
    public func attachedNetworks() -> [OpenConnectPlan.Attached] {
        var out: [OpenConnectPlan.Attached] = []
        for entry in Self.interfaces() where entry.up && !entry.loopback && !entry.pointToPoint {
            guard let length = entry.netmask?.maskLength, length > 0, length < entry.address.family.bits,
                let network = IPNetwork(address: entry.address, prefixLength: length)
            else { continue }
            let attached = OpenConnectPlan.Attached(network, interface: entry.name)
            if !out.contains(attached) { out.append(attached) }
        }
        return out
    }

    public func routes() -> [KernelRoute]? {
        guard let v4 = Self.dump(AF_INET), let v6 = Self.dump(AF_INET6) else { return nil }
        return KernelRoute.parseDump(v4) + KernelRoute.parseDump(v6)
    }

    public func run(_ command: OpenConnectCommand, timeout: TimeInterval) -> OpenConnectCommand.Result {
        Self.runTool(command.executable, command.arguments, timeout: timeout)
    }

    public func setDNS(_ settings: OpenConnectDNSSettings) -> Bool {
        guard OpenConnectPlan.Change.isService(settings.service), let store = Self.store() else { return false }
        let values = NSMutableDictionary()
        for (key, entity) in settings.values { values[key] = Self.propertyList(entity) }
        let present = Self.presentKeys(store, settings.removedKeys)
        return SCDynamicStoreSetMultiple(store, values, present.isEmpty ? nil : present as CFArray, nil)
    }

    public func hasDNS(_ settings: OpenConnectDNSSettings) -> Bool {
        guard OpenConnectPlan.Change.isService(settings.service), let store = Self.store(),
            let present = SCDynamicStoreCopyMultiple(store, Array(settings.values.keys) as CFArray, nil) as? [String: Any]
        else { return false }
        return settings.values.allSatisfy { key, entity in
            (present[key] as? NSDictionary)?.isEqual(to: Self.propertyList(entity) as? [AnyHashable: Any] ?? [:]) ?? false
        }
    }

    public func removeDNS(service: String) -> Bool {
        guard OpenConnectPlan.Change.isService(service), let store = Self.store() else { return false }
        let present = Self.presentKeys(store, OpenConnectDNSSettings.keys(service: service))
        guard !present.isEmpty else { return true }
        return SCDynamicStoreSetMultiple(store, nil, present as CFArray, nil) && Self.presentKeys(store, present).isEmpty
    }

    // MARK: Routing table

    /// The kernel's routing table of one family (`NET_RT_DUMP`); nil when it cannot be read.
    static func dump(_ family: Int32) -> [UInt8]? {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, family, NET_RT_DUMP, 0]
        for _ in 0..<3 {
            var length = 0
            guard sysctl(&mib, 6, nil, &length, nil, 0) == 0 else { return nil }
            length += length / 4 + 4096  // the table may grow between the two calls
            var buffer = [UInt8](repeating: 0, count: length)
            if sysctl(&mib, 6, &buffer, &length, nil, 0) == 0 { return Array(buffer.prefix(length)) }
            guard errno == ENOMEM else { return nil }
        }
        return nil
    }

    // MARK: Interfaces

    struct InterfaceAddress {
        var name: String
        var address: IPAddress
        var netmask: IPAddress?
        var up: Bool
        var loopback: Bool
        var pointToPoint: Bool
    }

    static func interfaces() -> [InterfaceAddress] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return [] }
        defer { freeifaddrs(first) }
        var out: [InterfaceAddress] = []
        var cursor = first
        while let entry = cursor?.pointee {
            defer { cursor = entry.ifa_next }
            guard let sa = entry.ifa_addr, let address = address(sa) else { continue }
            let flags = Int32(entry.ifa_flags)
            out.append(
                InterfaceAddress(
                    name: String(cString: entry.ifa_name), address: address,
                    netmask: entry.ifa_netmask.flatMap { mask(of: $0, family: address.family) },
                    up: flags & IFF_UP != 0, loopback: flags & IFF_LOOPBACK != 0, pointToPoint: flags & IFF_POINTOPOINT != 0))
        }
        return out
    }

    /// An IPv4 or IPv6 socket address, without the scope the kernel embeds in a link-local IPv6 address.
    static func address(_ sa: UnsafeMutablePointer<sockaddr>) -> IPAddress? {
        let length = Int(sa.pointee.sa_len)
        let bytes = [UInt8](UnsafeRawBufferPointer(start: UnsafeRawPointer(sa), count: max(length, 2)))
        return KernelRoute.address(bytes[...], family: sa.pointee.sa_family)
    }

    static func mask(of sa: UnsafeMutablePointer<sockaddr>, family: IPAddress.Family) -> IPAddress? {
        let length = Int(sa.pointee.sa_len)
        let bytes = [UInt8](UnsafeRawBufferPointer(start: UnsafeRawPointer(sa), count: max(length, 0)))
        return KernelRoute.mask(bytes[...], family: family)
    }

    // MARK: Tools

    /// Runs `executable` with `arguments` (`Spawner.spawn`: its own process group, no inherited descriptor, stdin
    /// `/dev/null`, its output into a pipe) for at most `timeout`, then kills it.
    static func runTool(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> OpenConnectCommand.Result {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { return .init(status: nil, output: "no pipe") }
        let (readFD, writeFD) = (fds[0], fds[1])
        _ = fcntl(readFD, F_SETFD, FD_CLOEXEC)
        _ = fcntl(writeFD, F_SETFD, FD_CLOEXEC)
        _ = fcntl(readFD, F_SETFL, O_NONBLOCK)
        let pid: pid_t
        do {
            pid = try Spawner.spawn(
                executable: executable, arguments: arguments, environment: toolEnvironment, workingDirectory: "/", outputFD: writeFD)
        } catch {
            close(readFD)
            close(writeFD)
            return .init(status: nil, output: VPNHook.oneLine(String(describing: error)))
        }
        close(writeFD)
        defer { close(readFD) }

        let deadline = Date().addingTimeInterval(timeout)
        var output: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: 1024)
        var reading = true
        var status: Int32?
        var exited = false
        while !(exited && !reading) {
            let left = deadline.timeIntervalSinceNow
            if left <= 0 { break }
            if reading {
                var pfd = pollfd(fd: readFD, events: Int16(POLLIN), revents: 0)
                if poll(&pfd, 1, Int32(min(left, 0.05) * 1000) + 1) > 0 {
                    let n = read(readFD, &buffer, buffer.count)
                    if n > 0 {
                        output += buffer[0..<min(n, max(0, maxOutputBytes - output.count))]
                    } else if n == 0 || (errno != EINTR && errno != EAGAIN) {
                        reading = false
                    }
                } else if exited {
                    // A child of the tool that keeps the pipe open does not hold the hook up.
                    reading = false
                }
            } else {
                usleep(2_000)
            }
            if !exited {
                var raw: Int32 = 0
                let r = waitpid(pid, &raw, WNOHANG)
                if r == pid {
                    exited = true
                    status = raw & 0x7f == 0 ? (raw >> 8) & 0xff : 128 + (raw & 0x7f)
                } else if r < 0, errno != EINTR {
                    exited = true
                }
            }
        }
        if !exited {
            kill(-pid, SIGKILL)
            kill(pid, SIGKILL)
            var raw: Int32 = 0
            while waitpid(pid, &raw, 0) == -1, errno == EINTR {}
            return .init(status: nil, output: "stopped at its time limit")
        }
        let text = String(decoding: output.map { $0 == 0x0A || $0 == 0x09 ? 0x20 : $0 }, as: UTF8.self)
        return .init(status: status, output: text.utf8.allSatisfy({ $0 == 0x20 }) ? "" : VPNHook.oneLine(text, maxBytes: 200))
    }

    // MARK: System configuration

    static func store() -> SCDynamicStore? {
        SCDynamicStoreCreate(nil, "PassTunnel vpn-hook" as CFString, nil, nil)
    }

    /// The keys of `keys` the store holds.
    static func presentKeys(_ store: SCDynamicStore, _ keys: [String]) -> [String] {
        guard !keys.isEmpty, let values = SCDynamicStoreCopyMultiple(store, keys as CFArray, nil) as? [String: Any] else { return [] }
        return keys.filter { values[$0] != nil }
    }

    static func propertyList(_ entity: [String: OpenConnectDNSSettings.Value]) -> NSDictionary {
        let out = NSMutableDictionary()
        for (key, value) in entity {
            switch value {
            case .string(let s): out[key] = s as NSString
            case .strings(let list): out[key] = list as NSArray
            case .number(let n): out[key] = NSNumber(value: n)
            case .numbers(let list): out[key] = list.map { NSNumber(value: $0) } as NSArray
            }
        }
        return out
    }
}

extension KernelRoute {
    /// The routes of a `NET_RT_DUMP` buffer: `rt_msghdr` records, each followed by its socket addresses
    /// (padded to 4 bytes). Records of another family, without a destination or with a mask that is not
    /// contiguous are left out; an IPv6 link-local address loses the scope the kernel embeds in it.
    static func parseDump(_ buf: [UInt8]) -> [KernelRoute] {
        let headerSize = MemoryLayout<rt_msghdr>.size
        var out: [KernelRoute] = []
        var offset = 0
        while offset + headerSize <= buf.count {
            let header = buf.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: rt_msghdr.self) }
            let length = Int(header.rtm_msglen)
            guard length >= headerSize, offset + length <= buf.count else { break }
            defer { offset += length }
            guard header.rtm_version == RTM_VERSION else { continue }
            var p = offset + headerSize
            var addresses: [Int: ArraySlice<UInt8>] = [:]
            for i in 0..<Int(RTAX_MAX) where header.rtm_addrs & (1 << i) != 0 {
                guard p < offset + length else { break }
                let saLength = Int(buf[p])
                addresses[i] = buf[p..<min(p + max(saLength, 1), offset + length)]
                p += saLength > 0 ? 1 + ((saLength - 1) | 3) : 4
            }
            guard let dst = addresses[Int(RTAX_DST)], dst.count >= 2, let destination = address(dst, family: sa_family_t(dst[dst.startIndex + 1]))
            else { continue }
            let flags = header.rtm_flags
            let family = destination.family
            var prefix = family.bits
            if flags & RTF_HOST == 0, let maskBytes = addresses[Int(RTAX_NETMASK)] {
                guard let length = mask(maskBytes, family: family)?.maskLength else { continue }
                prefix = length
            } else if flags & RTF_HOST == 0, destination.isUnspecified {
                prefix = 0
            }
            guard let network = IPNetwork(address: destination, prefixLength: prefix), network.address == destination else { continue }
            var gateway: IPAddress?
            if flags & RTF_GATEWAY != 0, let g = addresses[Int(RTAX_GATEWAY)], g.count >= 2 {
                gateway = address(g, family: sa_family_t(g[g.startIndex + 1]))
            }
            var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
            let interface = if_indextoname(UInt32(header.rtm_index), &name) != nil ? String(cString: name) : ""
            out.append(
                KernelRoute(
                    network: network, gateway: gateway, interface: interface, reject: flags & (RTF_REJECT | RTF_BLACKHOLE) != 0,
                    scoped: flags & RTF_IFSCOPE != 0, cloned: flags & (RTF_WASCLONED | RTF_LLINFO) != 0))
        }
        return out
    }

    /// The address in a `sockaddr_in` or `sockaddr_in6` (bytes from its start); nil for another family or a
    /// short one. A link-local IPv6 address has the kernel's embedded scope (bytes 2–3) cleared.
    static func address(_ sa: ArraySlice<UInt8>, family: sa_family_t) -> IPAddress? {
        let bytes = Array(sa)
        switch Int32(family) {
        case AF_INET:
            guard bytes.count >= 8 else { return nil }
            return IPAddress(bytes: Array(bytes[4..<8]))
        case AF_INET6:
            guard bytes.count >= 24 else { return nil }
            var raw = Array(bytes[8..<24])
            // fe80::/10, and multicast of interface- or link-local scope (ff01::/16, ff02::/16).
            if (raw[0] == 0xFE && raw[1] & 0xC0 == 0x80) || (raw[0] == 0xFF && (raw[1] & 0x0F == 1 || raw[1] & 0x0F == 2)) {
                raw[2] = 0
                raw[3] = 0
            }
            return IPAddress(bytes: raw)
        default:
            return nil
        }
    }

    /// A netmask socket address, which the kernel shortens to its last nonzero byte (and may give without a
    /// family): the bytes after the header, missing ones zero.
    static func mask(_ sa: ArraySlice<UInt8>, family: IPAddress.Family) -> IPAddress? {
        let bytes = Array(sa)
        let (start, count) = family == .ipv4 ? (4, 4) : (8, 16)
        return IPAddress(bytes: (start..<(start + count)).map { $0 < bytes.count ? bytes[$0] : 0 })
    }
}
#endif
