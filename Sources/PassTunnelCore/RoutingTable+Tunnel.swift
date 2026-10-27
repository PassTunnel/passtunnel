import Foundation
import PassTunnelKit

extension RoutingTable {
    /// The routes through `interface` that stand for networks the tunnel serves, read like `trafficRoutes`
    /// (no external commands, no privileges): on the Mac the IPv4 table, on Linux the IPv4 and IPv6 routes of
    /// the main table. For tunnels whose tool does not log what it routes (openfortivpn); empty if the
    /// routes cannot be read.
    public static func routes(onInterface interface: String) -> [Route] {
        guard !interface.isEmpty else { return [] }
        #if os(macOS)
        return Array(servedRoutes(in: ipv4Routes(), interface: interface).prefix(maxInterfaceRoutes))
        #elseif os(Linux)
        return linuxRoutes(onInterface: interface)
        #else
        return []
        #endif
    }

    /// At most this many routes of the main table are read, and this many kept for the interface.
    static let maxRoutesRead = 100_000
    static let maxInterfaceRoutes = 4096

    /// `routes` that go out of `interface` and are not about the link itself: not interface-scoped, and
    /// not link-local (the tunnel's peer address, `169.254.0.0/16`, `fe80::/10`), multicast or broadcast.
    static func servedRoutes(in routes: [Route], interface: String) -> [Route] {
        let local = ["169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "fe80::/10", "ff00::/8"].compactMap(CIDR.init)
        return routes.filter { route in
            guard route.interface == interface, !route.scoped,
                let network = CIDR("\(route.destination)/\(route.prefixLength)")
            else { return false }
            return !local.contains { $0.contains(network) }
        }
    }

    /// The main table's unicast routes through the link named `name`.
    static func linuxRoutes(onInterface name: String, routes: [Netlink.Route], links: [Int32: Netlink.Link]) -> [Route] {
        var out: [Route] = []
        for route in routes where route.table == Netlink.mainTable && route.type == Netlink.unicast {
            for index in route.interfaces {
                guard let link = links[index], link.name == name,
                    let destination = Netlink.address(route.destination, family: route.family)
                else { continue }
                out.append(
                    Route(
                        destination: destination, prefixLength: route.prefixLength, interface: name,
                        tunnelDevice: link.isTunnel))
            }
        }
        return Array(servedRoutes(in: out, interface: name).prefix(maxInterfaceRoutes))
    }

    #if os(Linux)
    static func linuxRoutes(onInterface name: String) -> [Route] {
        var routes: [Netlink.Route] = []
        var links: [Int32: Netlink.Link] = [:]
        let read = Netlink.dump(Netlink.getRoute) { type, body in
            if type == Netlink.newRoute, routes.count < maxRoutesRead, let r = Netlink.Route(body) { routes.append(r) }
        }
        guard read else { return [] }
        _ = Netlink.dump(Netlink.getLink) { type, body in
            if type == Netlink.newLink, let l = Netlink.Link(body) { links[l.index] = l }
        }
        return linuxRoutes(onInterface: name, routes: routes, links: links)
    }
    #endif
}
