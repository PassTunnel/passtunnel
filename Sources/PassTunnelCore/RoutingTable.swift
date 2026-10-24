#if canImport(Darwin)
import Darwin
#endif
import Foundation

/// Read-only view of the IPv4 routing table (`sysctl` `NET_RT_DUMP`, no external commands). Linux has
/// no reader yet (docs/LINUX.md): no routes, so the other-VPN check finds nothing there.
public enum RoutingTable {
    public struct Route: Equatable, Sendable {
        public var destination: String       // dotted quad
        public var prefixLength: Int
        public var interface: String         // e.g. "utun4", "en0"
        public var scoped: Bool              // RTF_IFSCOPE: only used for traffic bound to the interface

        public init(destination: String, prefixLength: Int, interface: String, scoped: Bool = false) {
            self.destination = destination
            self.prefixLength = prefixLength
            self.interface = interface
            self.scoped = scoped
        }

        /// `default`, `0/1` or `128/1`: a route that captures all traffic (OpenVPN's `redirect-gateway`).
        public var capturesAllTraffic: Bool {
            (destination == "0.0.0.0" && prefixLength <= 1) || (destination == "128.0.0.0" && prefixLength == 1)
        }
    }

    /// Current IPv4 routes; empty if the table cannot be read.
    public static func ipv4Routes() -> [Route] {
        #if os(macOS)
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0]
        var len = 0
        guard sysctl(&mib, 6, nil, &len, nil, 0) == 0, len > 0 else { return [] }
        len += len / 8                                   // the table may grow between the two calls
        var buf = [UInt8](repeating: 0, count: len)
        guard sysctl(&mib, 6, &buf, &len, nil, 0) == 0 else { return [] }
        return parse(Array(buf.prefix(len)))
        #else
        return []
        #endif
    }

    #if os(macOS)
    /// Parses a `NET_RT_DUMP` buffer: `rt_msghdr` records, each followed by its socket addresses.
    static func parse(_ buf: [UInt8]) -> [Route] {
        let headerSize = MemoryLayout<rt_msghdr>.size
        var out: [Route] = []
        var offset = 0
        buf.withUnsafeBytes { raw in
            while offset + headerSize <= raw.count {
                let hdr = raw.loadUnaligned(fromByteOffset: offset, as: rt_msghdr.self)
                let length = Int(hdr.rtm_msglen)
                guard length >= headerSize, offset + length <= raw.count else { break }
                defer { offset += length }
                guard hdr.rtm_version == RTM_VERSION else { continue }
                var p = offset + headerSize
                var addresses: [Int: ArraySlice<UInt8>] = [:]
                for i in 0..<Int(RTAX_MAX) where hdr.rtm_addrs & (1 << i) != 0 {
                    guard p < offset + length else { break }
                    let saLen = Int(raw[p])
                    addresses[i] = buf[p..<min(p + saLen, offset + length)]
                    p += saLen > 0 ? 1 + ((saLen - 1) | 3) : 4   // sockaddrs are padded to 4 bytes
                }
                guard let dst = addresses[Int(RTAX_DST)], dst.count >= 2, dst[dst.startIndex + 1] == UInt8(AF_INET) else {
                    continue
                }
                let prefix: Int
                if let mask = addresses[Int(RTAX_NETMASK)] {
                    prefix = ipv4Bytes(mask).reduce(0) { $0 + $1.nonzeroBitCount }
                } else {
                    prefix = 32
                }
                var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
                let iface = if_indextoname(UInt32(hdr.rtm_index), &name) != nil ? String(cString: name) : ""
                out.append(Route(destination: ipv4Bytes(dst).map(String.init).joined(separator: "."),
                                 prefixLength: prefix, interface: iface,
                                 scoped: hdr.rtm_flags & RTF_IFSCOPE != 0))
            }
        }
        return out
    }

    /// The four address bytes of a (possibly truncated) `sockaddr_in`; missing bytes are zero.
    static func ipv4Bytes(_ sa: ArraySlice<UInt8>) -> [UInt8] {
        let bytes = Array(sa)
        return (4..<8).map { $0 < bytes.count ? bytes[$0] : 0 }
    }
    #endif
}

/// Finds another VPN that already routes all traffic, before a profile that does the same connects:
/// OpenVPN would fail to add its routes ("File exists"), the DNS hook would refuse, and on disconnect
/// OpenVPN would delete the other tunnel's `0/1` and `128/1` routes.
public enum FullTunnelCheck {
    static let vpnInterfacePrefixes = ["utun", "ppp", "ipsec", "tun", "tap"]

    public static func isVPNInterface(_ name: String) -> Bool {
        vpnInterfacePrefixes.contains { name.hasPrefix($0) && name.dropFirst($0.count).allSatisfy(\.isNumber) }
    }

    /// The VPN interface that carries all traffic, unless it belongs to `own` (PassTunnel's sessions).
    public static func foreignFullTunnel(in routes: [RoutingTable.Route], own: Set<String>) -> String? {
        routes.first { $0.capturesAllTraffic && !$0.scoped && isVPNInterface($0.interface) && !own.contains($0.interface) }?
            .interface
    }
}
