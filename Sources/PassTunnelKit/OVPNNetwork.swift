import Foundation

extension OVPNAnalyzer {
    /// The options a server can push that say what the tunnel takes over. Anything else (keys, tokens,
    /// addresses, timers) is never kept from a push.
    public static let networkOptions: Set<String> = ["route", "route-ipv6", "redirect-gateway", "dhcp-option", "dns"]

    /// What a profile's tunnel takes over: the `route`, `route-ipv6`, `redirect-gateway`, `dhcp-option` and
    /// `dns` lines of the config, and the options the server pushed (`pushed`, each one option as the
    /// server sent it: "route 10.0.0.0 255.0.0.0", "dhcp-option DNS 10.8.0.1"; see `VPNLog.pushedOptions`).
    /// The config decides what of the push counts, as OpenVPN does:
    /// - `route-nopull` refuses everything pushed that is a route, a redirect or DNS;
    /// - `pull-filter ignore|reject PATTERN` drops a pushed option that starts with PATTERN, `accept`
    ///   keeps it; the first filter that matches decides;
    /// - `route-noexec` means no route is added, from the config or the server: no routes, no full tunnel.
    /// Routes that do not go through the tunnel (`net_gateway`, `remote_host` as gateway) and names that
    /// are not addresses are left out. A push can only add; nothing here is trusted beyond being parsed.
    public static func networkClaims(_ config: String, pushed: [String] = []) -> NetworkClaims {
        var routesPulled = true
        var routesAdded = true
        var filters: [(accept: Bool, pattern: String)] = []
        let lines = directives(config)
        for words in lines {
            switch words[0] {
            case "route-nopull": routesPulled = false
            case "route-noexec": routesAdded = false
            case "pull-filter":
                if words.count > 2 {
                    let action = words[1].lowercased()
                    if ["accept", "ignore", "reject"].contains(action) { filters.append((action == "accept", words[2])) }
                }
            default: break
            }
        }

        var claims = NetworkClaims()
        for words in lines where networkOptions.contains(words[0]) {
            apply(words, to: &claims, routesAdded: routesAdded)
        }
        guard routesPulled else { return claims }
        for option in pushed.prefix(maxPushedOptions) {
            let words = option.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard let name = words.first, networkOptions.contains(name) else { continue }
            if let filter = filters.first(where: { option.hasPrefix($0.pattern) }), !filter.accept { continue }
            apply(words, to: &claims, routesAdded: routesAdded)
        }
        return claims
    }

    /// More pushed options than this are not read (a server can send as many as it likes).
    static let maxPushedOptions = 1024

    /// One option, already split into words (the directive first, lowercase).
    private static func apply(_ words: [String], to claims: inout NetworkClaims, routesAdded: Bool) {
        let gatewaysOutsideTunnel: Set<String> = ["net_gateway", "remote_host"]
        switch words[0] {
        case "route":
            // route NETWORK [NETMASK [GATEWAY [METRIC]]]; the default mask is a host, "default" is the same.
            guard routesAdded, words.count > 1 else { return }
            if words.count > 3, gatewaysOutsideTunnel.contains(words[3]) { return }
            let mask = words.count > 2 && words[2] != "default" ? words[2] : "255.255.255.255"
            if let route = CIDR(address: words[1], netmask: mask) { claims.addRoute(route) }
        case "route-ipv6":
            // route-ipv6 NETWORK/BITS [GATEWAY [METRIC]]
            guard routesAdded, words.count > 1, words[1].contains("/") else { return }
            if words.count > 2, gatewaysOutsideTunnel.contains(words[2]) { return }
            if let route = CIDR(words[1]) { claims.addRoute(route) }
        case "redirect-gateway":
            guard routesAdded else { return }
            let flags = Set(words.dropFirst().map { $0.lowercased() })
            if !flags.contains("!ipv4") { claims.fullTunnel = true }
            if flags.contains("ipv6") { claims.fullTunnelIPv6 = true }
        case "dhcp-option":
            guard words.count > 2 else { return }
            switch words[1].uppercased() {
            case "DNS", "DNS6": claims.addDNSServer(dnsAddress(words[2]))
            case "DOMAIN-ROUTE": claims.addDNSDomain(words[2])
            case "DOMAIN", "DOMAIN-SEARCH", "ADAPTER-DOMAIN-SUFFIX": claims.addSearchDomain(words[2])
            default: break
            }
        case "dns":
            // dns server N address A[:PORT] …, dns server N resolve-domains D …, dns search-domains D …
            if words.count > 4, words[1] == "server" {
                switch words[3] {
                case "address": words[4...].forEach { claims.addDNSServer(dnsAddress($0)) }
                case "resolve-domains": words[4...].forEach { claims.addDNSDomain($0) }
                default: break
                }
            } else if words.count > 2, words[1] == "search-domains" {
                words[2...].forEach { claims.addSearchDomain($0) }
            }
        default:
            break
        }
    }

    /// An address from a `dns server N address` list: "10.0.0.1", "10.0.0.1:53", "[2001:db8::1]:53",
    /// "2001:db8::1". Anything else comes back as it is, and is refused by the caller.
    static func dnsAddress(_ text: String) -> String {
        if text.hasPrefix("["), let close = text.firstIndex(of: "]") {
            return String(text[text.index(after: text.startIndex)..<close])
        }
        if text.filter({ $0 == ":" }).count == 1, let colon = text.firstIndex(of: ":") {
            return String(text[..<colon])
        }
        return text
    }
}
