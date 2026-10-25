import Foundation
import PassTunnelKit

/// What the tools' logs say about the network a tunnel takes over (`ProfileNetwork`). Both are
/// server-controlled text, so lines and options are length-limited, only the options that matter are
/// kept, and nothing is trusted beyond what `NetworkClaims` parses from it.
extension VPNLog {
    /// OpenVPN logs the server's push at `--verb 3` (its `D_PUSH` level; PassTunnel runs with 3 unless the
    /// config says otherwise, capped at 4) as
    ///
    ///     PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0,dhcp-option DNS 10.8.0.1,…'
    ///
    /// after the log's timestamp. A configuration with a lower `verb` leaves it out.
    static let pushedMarker = "PUSH: Received control message: '"
    /// A longer line is not read.
    static let maxPushLine = 16 * 1024
    /// Longer options are dropped, and at most this many are kept.
    static let maxOptionLength = 512
    static let maxPushedOptions = 1024

    /// The options of the last push in `text` that say what the tunnel takes over
    /// (`OVPNAnalyzer.networkOptions`), each as the server sent it; nil when the log has no push at all
    /// (not connected yet, or a `verb` below 3), [] when the push said nothing about routes or DNS.
    /// A push too big for one message comes as several (`push-continue 1` on all but the last): they are
    /// one push. A later push (after a restart) replaces an earlier one.
    public static func pushedOptions(_ text: String) -> [String]? {
        var found = false
        var options: [String] = []
        var continued = false
        for line in text.split(whereSeparator: \.isNewline) {
            guard line.utf8.count <= maxPushLine, let marker = line.range(of: pushedMarker) else { continue }
            let rest = line[marker.upperBound...]
            guard let close = rest.lastIndex(of: "'") else { continue }
            let body = rest[..<close]
            guard body == "PUSH_REPLY" || body.hasPrefix("PUSH_REPLY,") else { continue }
            if !continued { options = [] }
            found = true
            continued = false
            for element in body.split(separator: ",", omittingEmptySubsequences: true).dropFirst() {
                let option = element.trimmingCharacters(in: .whitespaces)
                if option == "push-continue 1" {
                    continued = true
                } else if isNetworkOption(option), options.count < maxPushedOptions {
                    options.append(option)
                }
            }
        }
        return found ? options : nil
    }

    /// A pushed option worth keeping: one of the network options, plain printable ASCII, not too long.
    static func isNetworkOption(_ option: String) -> Bool {
        guard option.utf8.count <= maxOptionLength, option.utf8.allSatisfy({ $0 >= 0x20 && $0 < 0x7F }),
              let name = option.split(separator: " ").first else { return false }
        return OVPNAnalyzer.networkOptions.contains(String(name))
    }

    /// openfortivpn says which DNS servers and search domains the gateway handed out in
    ///
    ///     INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54], ns_suffix [example.com;corp.example.com]
    ///
    /// (`0.0.0.0` stands for no server). As the options OpenVPN would push for them, so both tools share
    /// one form; nil when the log has no such line. Its routes are not logged at its default verbosity
    /// (`RoutingTable.routes(onInterface:)` has them).
    public static func fortiOptions(_ text: String) -> [String]? {
        guard let line = text.split(whereSeparator: \.isNewline).last(where: { $0.contains("Got addresses: [") }),
              line.utf8.count <= maxPushLine,
              let ns = line.range(of: "], ns [") else { return nil }
        var servers = line[ns.upperBound...]
        var domains: [Substring] = []
        if let suffix = servers.range(of: "], ns_suffix [") {
            var names = servers[suffix.upperBound...]
            if names.hasSuffix("]") { names = names.dropLast() }
            domains = names.split(whereSeparator: { $0 == ";" || $0 == " " || $0 == "," })
            servers = servers[..<suffix.lowerBound]
        } else if servers.hasSuffix("]") {
            servers = servers.dropLast()
        }
        var options: [String] = []
        for server in servers.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) })
        where CIDR.host(server) != nil && server != "0.0.0.0" && options.count < NetworkClaims.maxDNSServers {
            options.append("dhcp-option DNS \(server)")
        }
        for domain in domains where NetworkClaims.normalizedDomain(String(domain)) != nil
            && options.count < NetworkClaims.maxDNSServers + NetworkClaims.maxDomains {
            options.append("dhcp-option DOMAIN \(domain)")
        }
        return options
    }
}
