import Foundation
import PassTunnelShared

/// The DNS a tunnel brings: servers and domains, every value checked, since they come from the VPN
/// server (pushed by it, or logged by the tool from what it sent) and end up in root's hands
/// (docs/LINUX.md, "DNS"). Independent of the tool that reported them: `OpenVPNDNS` builds one from
/// OpenVPN's environment, FortiGate sessions from what openfortivpn prints (`FortiOutput`).
public struct DNSSettings: Equatable, Sendable {
    public static let maxServers = 8
    public static let maxDomains = 16

    /// IPv4 and IPv6 addresses, in the canonical form `inet_ntop` gives them.
    public let servers: [String]
    /// Domains names are searched in and resolved through the tunnel (resolv.conf's `search`).
    public let searchDomains: [String]
    /// Domains only resolved through the tunnel, never searched (systemd-resolved's `~domain`): split
    /// DNS as OpenVPN's `dns server N resolve-domains` asks for it.
    public let routingDomains: [String]
    /// Every name is resolved through the tunnel (systemd-resolved: the link is the default route,
    /// with the routing domain `~.`); otherwise only its domains are.
    public let fullTunnel: Bool

    /// Checks and normalizes every value, dropping repeats: addresses must parse (`inet_pton`), domains
    /// be plain host names. More than `maxServers` servers or `maxDomains` domains of a kind is refused.
    public init(servers: [String], searchDomains: [String] = [], routingDomains: [String] = [],
                fullTunnel: Bool) throws {
        self.servers = try Self.unique(servers.map(Self.address), limit: Self.maxServers, kind: "DNS servers")
        self.searchDomains = try Self.unique(searchDomains.map(Self.domain), limit: Self.maxDomains,
                                             kind: "search domains")
        self.routingDomains = try Self.unique(routingDomains.map(Self.domain), limit: Self.maxDomains,
                                              kind: "DNS routing domains")
        self.fullTunnel = fullTunnel
    }

    private static func unique(_ values: [String], limit: Int, kind: String) throws -> [String] {
        var seen = Set<String>()
        let result = values.filter { seen.insert($0).inserted }
        guard result.count <= limit else { throw DNSFailure.tooMany(kind, limit) }
        return result
    }

    // MARK: - Values

    /// An IPv4 or IPv6 address in canonical form. The unspecified address, scopes (`%eth0`), ports
    /// and anything else is refused.
    public static func address(_ text: String) throws -> String {
        // Hex digits, dots and colons only: some inet_pton accept a scope, none of them needs more.
        guard (2...45).contains(text.utf8.count), text.utf8.allSatisfy({ c in
            (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) || (c >= 0x41 && c <= 0x46) || c == 0x2E || c == 0x3A
        }) else {
            throw DNSFailure.invalid("DNS server", text)
        }
        // in6_addr is large enough for either family.
        var bytes = [UInt8](repeating: 0, count: MemoryLayout<in6_addr>.size)
        for family in [AF_INET, AF_INET6] where inet_pton(family, text, &bytes) == 1 {
            let length = family == AF_INET ? MemoryLayout<in_addr>.size : MemoryLayout<in6_addr>.size
            var buffer = [CChar](repeating: 0, count: 64)
            guard bytes.prefix(length).contains(where: { $0 != 0 }),
                  inet_ntop(family, bytes, &buffer, socklen_t(buffer.count)) != nil else { break }
            return String(cString: buffer)
        }
        throw DNSFailure.invalid("DNS server", text)
    }

    /// A plain host name, lowercased and without a final dot: at most 253 bytes in labels of 1 to 63
    /// ASCII letters, digits, `-` and `_`, none starting or ending with `-`. Nothing a tool could take
    /// for an option (`-x`), a routing marker (`~`) or anything but a name.
    public static func domain(_ text: String) throws -> String {
        var name = text.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...253).contains(name.utf8.count), labels.allSatisfy(isLabel) else {
            throw DNSFailure.invalid("DNS domain", text)
        }
        return name
    }

    private static func isLabel(_ label: Substring) -> Bool {
        guard (1...63).contains(label.utf8.count), label.first != "-", label.last != "-" else { return false }
        return label.utf8.allSatisfy { c in
            (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c == 0x2D || c == 0x5F   // a-z 0-9 - _
        }
    }

    /// A network interface name as Linux allows it, narrowed to what tunnels are called: 1 to 15
    /// (`IFNAMSIZ` - 1) ASCII letters, digits, `_`, `-` and `.`, starting with a letter or digit.
    public static func interface(_ text: String) throws -> String {
        let bytes = Array(text.utf8)
        guard (1...15).contains(bytes.count), let first = bytes.first, isAlphanumeric(first),
              bytes.allSatisfy({ isAlphanumeric($0) || $0 == 0x5F || $0 == 0x2D || $0 == 0x2E }) else {
            throw DNSFailure.invalid("interface", text)
        }
        return text
    }

    private static func isAlphanumeric(_ c: UInt8) -> Bool {
        (c >= 0x61 && c <= 0x7A) || (c >= 0x41 && c <= 0x5A) || (c >= 0x30 && c <= 0x39)
    }
}

/// Why DNS could not be set up (or reverted). Values from the server are quoted only after
/// `HelperCore.printable` (printable ASCII, at most 32 characters).
public enum DNSFailure: Error, Equatable, CustomStringConvertible {
    case invalid(String, String)
    case tooMany(String, Int)
    case noUsableServer
    case noInterface(String)
    case unexpectedLink(String, String)
    case notARegularFile(String)
    case tooLarge(String)
    case untrustedTool(String, String)
    case missingTool(String, String)
    case toolFailed(String, Int32, String)
    case system(String, Int32)
    case notRoot
    case notASession(String)
    case unknownPhase(String)
    case varsFile
    case busy
    case detached(String)
    case resolvconfReplaces(String, String)
    /// FortiGate: the interface openfortivpn named is not this session's (`SessionInterface`).
    case notSessionInterface(String, String)
    /// FortiGate: openfortivpn's tunnel came up without it saying what DNS needs.
    case notReported(String)

    public var description: String {
        switch self {
        case .invalid(let what, let value): return "invalid \(what) “\(HelperCore.printable(value))”"
        case .tooMany(let what, let limit): return "more than \(limit) \(what)"
        case .noUsableServer:
            return "no DNS server PassTunnel can use (only DNS over TLS or HTTPS, or a port other than 53)"
        case .noInterface(let name): return "there is no interface \(name)"
        case .unexpectedLink(let path, let target):
            return "\(path) is a link to \(HelperCore.printable(target)), which PassTunnel does not change"
        case .notARegularFile(let path): return "\(path) is not a regular file owned by root"
        case .tooLarge(let path): return "\(path) is too large"
        case .untrustedTool(let path, let reason): return "refusing to run \(path): \(reason)"
        case .missingTool(let tool, let why): return "\(why), but \(tool) is not installed"
        case .toolFailed(let tool, let status, let output):
            let first = output.split(whereSeparator: \.isNewline).first
            let message = first.map { ": " + DaemonLog.oneLine(String($0.prefix(200))) } ?? ""
            return "\(tool) failed (status \(status))\(message)"
        case .system(let what, let err): return "\(what): \(String(cString: strerror(err)))"
        case .notRoot: return "the DNS hook must run as root"
        case .notASession(let reason): return "not run by a PassTunnel session: \(reason)"
        case .unknownPhase(let type): return "unknown script_type “\(HelperCore.printable(type))”"
        case .varsFile: return "OpenVPN passed the DNS settings in a file, which it only does when it drops privileges"
        case .busy: return "another DNS change did not finish in time"
        case .detached(let path):
            return "\(path) was replaced after passtunneld started, and its sandbox still holds the old file: "
                + "restart passtunnel.service"
        case .resolvconfReplaces(let config, let directory):
            return "openresolv is set to replace /etc/resolv.conf (resolv_conf_mv in \(config)), which it cannot do "
                + "here, where \(directory) is read-only: remove resolv_conf_mv, so that it writes the file in place"
        case .notSessionInterface(let name, let reason): return "\(name) is not this session's interface: \(reason)"
        case .notReported(let what): return "openfortivpn's tunnel is up, but it did not report \(what)"
        }
    }
}
