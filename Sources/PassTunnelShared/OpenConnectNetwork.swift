import Foundation

/// What openconnect hands its hook, checked (docs/ARCHITECTURE.md, "The hook", step 3). openconnect runs
/// the hook as root with the server's values in its environment (`prepare_script_env`, `script.c` 294–432 of
/// openconnect 9.21): most of them are the server's text as it sent it, so every value used here is parsed
/// by a strict rule and written back in canonical form, and one bad value fails the whole set-up. Pure: the
/// macOS hook (#183) and `passtunneld` (#187) share it, and it is tested everywhere.
///
/// Errors name the variable and the rule, never the value (`Failure`). Variables the hook does not need
/// (`CISCO_BANNER`, `CISCO_PROXY_PAC`, `CISCO_CSTP_OPTIONS`, `IDLE_TIMEOUT`, `INTERNAL_IP4_NBNS`,
/// `LOG_LEVEL`, and everything that is not openconnect's) are never read.
public struct OpenConnectNetwork: Equatable, Sendable {
    /// Where the hook runs: the tunnel interface's name differs.
    public enum Platform: Sendable {
        case macOS, linux
    }

    /// openconnect's `reason`.
    public enum Reason: String, CaseIterable, Sendable {
        case preInit = "pre-init"
        case connect
        case disconnect
        case attemptReconnect = "attempt-reconnect"
        case reconnect
    }

    /// What one run of the hook is about.
    ///
    /// - `pre-init` (before the interface exists) and `disconnect` (revert from the record) read nothing but
    ///   `reason`: nothing else is needed, and a revert must never fail on what the server sent.
    /// - `connect`, `attempt-reconnect` and `reconnect` need the whole network, checked. openconnect 9.21
    ///   builds the environment once, before `connect` (`library.c` 1567), so the later two see the same
    ///   values.
    public enum Event: Equatable, Sendable {
        case preInit
        case connect(OpenConnectNetwork)
        case attemptReconnect(OpenConnectNetwork)
        case reconnect(OpenConnectNetwork)
        case disconnect

        public var reason: Reason {
            switch self {
            case .preInit: return .preInit
            case .connect: return .connect
            case .attemptReconnect: return .attemptReconnect
            case .reconnect: return .reconnect
            case .disconnect: return .disconnect
            }
        }

        public var network: OpenConnectNetwork? {
            switch self {
            case .connect(let n), .attemptReconnect(let n), .reconnect(let n): return n
            case .preInit, .disconnect: return nil
            }
        }
    }

    /// An address the server assigned, with the network it is in when the server said.
    public struct Assigned: Equatable, Sendable {
        public let address: IPAddress
        /// IPv4: from `INTERNAL_IP4_NETADDR`/`NETMASKLEN`; IPv6: from `INTERNAL_IP6_NETMASK`. nil: none given.
        public let network: IPNetwork?

        public init(address: IPAddress, network: IPNetwork?) {
            self.address = address
            self.network = network
        }
    }

    /// The tunnel interface (`TUNDEV`).
    public let interface: String
    /// The address openconnect connected to (`VPNGATEWAY`).
    public let gateway: IPAddress
    public let ipv4: Assigned?
    public let ipv6: Assigned?
    /// `INTERNAL_IP4_MTU`, for both families.
    public let mtu: Int
    /// `INTERNAL_IP4_DNS`: IPv4 and IPv6, at most 3, repeats dropped.
    public let dnsServers: [IPAddress]
    /// `CISCO_DEF_DOMAIN`, split on blanks: at most 16, repeats dropped.
    public let defaultDomains: [String]
    /// `CISCO_SPLIT_DNS`, split on commas: at most 16, repeats dropped.
    public let splitDNSDomains: [String]
    /// The split lists, in openconnect's order, each at most 1,024.
    public let ipv4Includes: [IPNetwork]
    public let ipv4Excludes: [IPNetwork]
    public let ipv6Includes: [IPNetwork]
    public let ipv6Excludes: [IPNetwork]
    /// `VPNPID`, when set: openconnect's pid (the session check proves the pid by itself).
    public let vpnPID: Int32?

    public init(
        interface: String, gateway: IPAddress, ipv4: Assigned?, ipv6: Assigned?, mtu: Int, dnsServers: [IPAddress] = [],
        defaultDomains: [String] = [], splitDNSDomains: [String] = [], ipv4Includes: [IPNetwork] = [],
        ipv4Excludes: [IPNetwork] = [], ipv6Includes: [IPNetwork] = [], ipv6Excludes: [IPNetwork] = [], vpnPID: Int32? = nil
    ) {
        self.interface = interface
        self.gateway = gateway
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.mtu = mtu
        self.dnsServers = dnsServers
        self.defaultDomains = defaultDomains
        self.splitDNSDomains = splitDNSDomains
        self.ipv4Includes = ipv4Includes
        self.ipv4Excludes = ipv4Excludes
        self.ipv6Includes = ipv6Includes
        self.ipv6Excludes = ipv6Excludes
        self.vpnPID = vpnPID
    }

    public func assigned(_ family: IPAddress.Family) -> Assigned? { family == .ipv4 ? ipv4 : ipv6 }
    public func includes(_ family: IPAddress.Family) -> [IPNetwork] { family == .ipv4 ? ipv4Includes : ipv6Includes }
    public func excludes(_ family: IPAddress.Family) -> [IPNetwork] { family == .ipv4 ? ipv4Excludes : ipv6Excludes }

    // MARK: Limits

    public static let maxDNSServers = 3
    public static let maxDomains = 16
    public static let maxSplitRoutes = 1024
    public static let mtuRange = 576...9000
    /// IPv6 needs links of at least this MTU (RFC 8200).
    public static let minIPv6MTU = 1280
    /// A longer value of a variable the hook reads is refused before it is parsed.
    public static let maxValueBytes = 8192

    // MARK: Failures

    /// Why the environment was refused. The description names the variable and the rule, never the value:
    /// the values are the server's, and the description goes into the session's log.
    public enum Failure: Error, Equatable, CustomStringConvertible, Sendable {
        case missing(String)
        case invalid(String, String)
        case tooLong(String)
        case duplicate(String)
        case tooMany(String, Int)
        case inconsistent(String, String)
        /// A variable of a split list that the count does not cover (the list's count variable).
        case unexpected(String)
        case noAddress
        case mtuTooSmallForIPv6

        public var description: String {
            switch self {
            case .missing(let name): return "\(name) is not set"
            case .invalid(let name, let rule): return "\(name) is not \(rule)"
            case .tooLong(let name): return "\(name) is longer than \(OpenConnectNetwork.maxValueBytes) bytes"
            case .duplicate(let name): return "\(name) is set more than once"
            case .tooMany(let name, let limit): return "\(name) holds more than \(limit) entries"
            case .inconsistent(let name, let other): return "\(name) does not agree with \(other)"
            case .unexpected(let count): return "a variable of the \(count) list has an index the count does not cover"
            case .noAddress: return "neither INTERNAL_IP4_ADDRESS nor INTERNAL_IP6_ADDRESS is set"
            case .mtuTooSmallForIPv6: return "INTERNAL_IP4_MTU is below \(OpenConnectNetwork.minIPv6MTU), too small for IPv6"
            }
        }
    }

    // MARK: Environment

    /// openconnect's environment as the hook got it: variable names (ASCII) and their raw bytes. Built
    /// from the process's `NAME=VALUE` entries, or a dictionary in tests.
    public struct Environment: Sendable {
        var values: [String: [UInt8]] = [:]
        var repeated: Set<String> = []

        /// From `NAME=VALUE` entries (`environ`). An entry without `=` or with a name that is not
        /// printable ASCII cannot be openconnect's and is left out; a name given twice is noted, and
        /// refused if the hook reads it.
        public init(entries: [[UInt8]]) {
            for entry in entries {
                guard let eq = entry.firstIndex(of: 0x3D), eq > 0 else { continue }
                let name = entry[..<eq]
                guard name.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else { continue }
                let key = String(decoding: name, as: UTF8.self)
                if values[key] != nil { repeated.insert(key) }
                values[key] = Array(entry[(eq + 1)...])
            }
        }

        public init(_ dictionary: [String: String]) {
            self.init(entries: dictionary.map { Array(($0.key + "=").utf8) + Array($0.value.utf8) })
        }

        public var names: Dictionary<String, [UInt8]>.Keys { values.keys }

        /// The value of `name` as ASCII text: nil when it is not set; throws when it is set twice, is
        /// longer than `maxValueBytes` or holds a byte outside 0x20–0x7E (a control byte, a byte of
        /// UTF-8 or another encoding).
        func text(_ name: String) throws -> String? {
            guard let bytes = values[name] else { return nil }
            guard !repeated.contains(name) else { throw Failure.duplicate(name) }
            guard bytes.count <= OpenConnectNetwork.maxValueBytes else { throw Failure.tooLong(name) }
            guard bytes.allSatisfy({ $0 >= 0x20 && $0 < 0x7F }) else { throw Failure.invalid(name, "printable ASCII") }
            return String(decoding: bytes, as: UTF8.self)
        }

        func required(_ name: String) throws -> String {
            guard let text = try text(name) else { throw Failure.missing(name) }
            return text
        }
    }

    // MARK: Parsing

    /// The event of one hook run: `reason`, and for the reasons that need it the whole network, checked.
    public static func parse(_ env: Environment, platform: Platform) throws -> Event {
        let reasonText = try env.required("reason")
        guard let reason = Reason(rawValue: reasonText) else {
            throw Failure.invalid("reason", "one of " + Reason.allCases.map(\.rawValue).joined(separator: ", "))
        }
        switch reason {
        case .preInit: return .preInit
        case .disconnect: return .disconnect
        case .connect: return .connect(try network(env, platform: platform))
        case .attemptReconnect: return .attemptReconnect(try network(env, platform: platform))
        case .reconnect: return .reconnect(try network(env, platform: platform))
        }
    }

    /// Every variable the set-up uses, checked in a fixed order; the first failure is thrown.
    static func network(_ env: Environment, platform: Platform) throws -> OpenConnectNetwork {
        let interface = try env.required("TUNDEV")
        guard isTunnelInterface(interface, platform: platform) else {
            throw Failure.invalid("TUNDEV", platform == .macOS ? "a tunnel interface utun0 to utun999" : "a tunnel interface tun0 to tun99999")
        }
        let gateway = try hostAddress(env.required("VPNGATEWAY"), name: "VPNGATEWAY", allowLoopback: true)

        let ipv4 = try parseIPv4(env)
        let ipv6 = try parseIPv6(env)
        guard ipv4 != nil || ipv6 != nil else { throw Failure.noAddress }

        let mtuText = try env.required("INTERNAL_IP4_MTU")
        guard let mtu = decimal(mtuText, max: mtuRange.upperBound), mtuRange.contains(mtu) else {
            throw Failure.invalid("INTERNAL_IP4_MTU", "a number from \(mtuRange.lowerBound) to \(mtuRange.upperBound)")
        }
        if ipv6 != nil, mtu < minIPv6MTU { throw Failure.mtuTooSmallForIPv6 }

        var servers: [IPAddress] = []
        if let text = try env.text("INTERNAL_IP4_DNS") {
            let words = text.split(separator: " ")
            guard words.count <= maxDNSServers else { throw Failure.tooMany("INTERNAL_IP4_DNS", maxDNSServers) }
            for word in words {
                guard let address = IPAddress(String(word)), !address.isUnspecified else {
                    throw Failure.invalid("INTERNAL_IP4_DNS", "a list of IPv4 and IPv6 addresses")
                }
                if !servers.contains(address) { servers.append(address) }
            }
        }

        let defaultDomains = try domains(env.text("CISCO_DEF_DOMAIN"), name: "CISCO_DEF_DOMAIN", separator: " ")
        let splitDNS = try domains(env.text("CISCO_SPLIT_DNS"), name: "CISCO_SPLIT_DNS", separator: ",")

        let v4Includes = try splitList(env, count: "CISCO_SPLIT_INC", family: .ipv4)
        let v4Excludes = try splitList(env, count: "CISCO_SPLIT_EXC", family: .ipv4)
        let v6Includes = try splitList(env, count: "CISCO_IPV6_SPLIT_INC", family: .ipv6)
        let v6Excludes = try splitList(env, count: "CISCO_IPV6_SPLIT_EXC", family: .ipv6)

        var pid: Int32?
        if let text = try env.text("VPNPID") {
            guard let value = decimal(text, max: Int(Int32.max)), value > 1 else {
                throw Failure.invalid("VPNPID", "a process ID")
            }
            pid = Int32(value)
        }

        return OpenConnectNetwork(
            interface: interface, gateway: gateway, ipv4: ipv4, ipv6: ipv6, mtu: mtu, dnsServers: servers,
            defaultDomains: defaultDomains, splitDNSDomains: splitDNS, ipv4Includes: v4Includes, ipv4Excludes: v4Excludes,
            ipv6Includes: v6Includes, ipv6Excludes: v6Excludes, vpnPID: pid)
    }

    /// `utun0`–`utun999` on the Mac, `tun0`–`tun99999` on Linux, without leading zeros.
    public static func isTunnelInterface(_ name: String, platform: Platform) -> Bool {
        let (prefix, max) = platform == .macOS ? ("utun", 999) : ("tun", 99_999)
        guard name.hasPrefix(prefix) else { return false }
        return decimal(String(name.dropFirst(prefix.count)), max: max) != nil
    }

    /// An address an interface may take or a host may have: not unspecified, multicast or the like
    /// (`IPAddress.isSpecial`); loopback only where `allowLoopback` (a VPN server on this machine).
    static func hostAddress(_ text: String, name: String, family: IPAddress.Family? = nil, allowLoopback: Bool = false) throws
        -> IPAddress
    {
        let rule = family == .ipv4 ? "an IPv4 host address" : family == .ipv6 ? "an IPv6 host address" : "a host address"
        guard let address = IPAddress(text), family == nil || address.family == family,
            !address.isSpecial || (allowLoopback && address.isLoopback)
        else { throw Failure.invalid(name, rule) }
        return address
    }

    /// `INTERNAL_IP4_ADDRESS` and, all three or none, `INTERNAL_IP4_NETMASK`, `_NETMASKLEN`, `_NETADDR`
    /// (openconnect sets them only when the netmask parsed and is contiguous, `script.c` 313–340).
    static func parseIPv4(_ env: Environment) throws -> Assigned? {
        let mask = try env.text("INTERNAL_IP4_NETMASK")
        let length = try env.text("INTERNAL_IP4_NETMASKLEN")
        let netaddr = try env.text("INTERNAL_IP4_NETADDR")
        guard let text = try env.text("INTERNAL_IP4_ADDRESS") else {
            for (name, value) in [("INTERNAL_IP4_NETMASK", mask), ("INTERNAL_IP4_NETMASKLEN", length), ("INTERNAL_IP4_NETADDR", netaddr)]
            where value != nil {
                throw Failure.inconsistent(name, "INTERNAL_IP4_ADDRESS")
            }
            return nil
        }
        let address = try hostAddress(text, name: "INTERNAL_IP4_ADDRESS", family: .ipv4)
        guard mask != nil || length != nil || netaddr != nil else { return Assigned(address: address, network: nil) }
        guard let mask else { throw Failure.missing("INTERNAL_IP4_NETMASK") }
        guard let length else { throw Failure.missing("INTERNAL_IP4_NETMASKLEN") }
        guard let netaddr else { throw Failure.missing("INTERNAL_IP4_NETADDR") }
        guard let maskAddress = IPAddress(mask), maskAddress.family == .ipv4, let maskLength = maskAddress.maskLength else {
            throw Failure.invalid("INTERNAL_IP4_NETMASK", "a contiguous IPv4 netmask")
        }
        guard let prefix = decimal(length, max: 32) else { throw Failure.invalid("INTERNAL_IP4_NETMASKLEN", "a length from 0 to 32") }
        guard prefix == maskLength else { throw Failure.inconsistent("INTERNAL_IP4_NETMASKLEN", "INTERNAL_IP4_NETMASK") }
        guard let net = IPAddress(netaddr), net.family == .ipv4 else {
            throw Failure.invalid("INTERNAL_IP4_NETADDR", "an IPv4 address")
        }
        guard net == address.masked(prefix) else { throw Failure.inconsistent("INTERNAL_IP4_NETADDR", "INTERNAL_IP4_ADDRESS") }
        return Assigned(address: address, network: IPNetwork(address: net, prefixLength: prefix))
    }

    /// `INTERNAL_IP6_ADDRESS` and `INTERNAL_IP6_NETMASK` (`<address>/<length>`, the server's text); openconnect
    /// sets the first from the second when the server sent only that (`script.c` 343–353). Both: the same
    /// address.
    static func parseIPv6(_ env: Environment) throws -> Assigned? {
        let text = try env.text("INTERNAL_IP6_ADDRESS")
        let address = try text.map { try hostAddress($0, name: "INTERNAL_IP6_ADDRESS", family: .ipv6) }
        guard let netmask = try env.text("INTERNAL_IP6_NETMASK") else {
            return address.map { Assigned(address: $0, network: nil) }
        }
        let parts = netmask.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let length = decimal(String(parts[1]), max: 128) else {
            throw Failure.invalid("INTERNAL_IP6_NETMASK", "an IPv6 address with a length from 0 to 128")
        }
        let inNetmask = try hostAddress(String(parts[0]), name: "INTERNAL_IP6_NETMASK", family: .ipv6)
        if let address, address != inNetmask { throw Failure.inconsistent("INTERNAL_IP6_ADDRESS", "INTERNAL_IP6_NETMASK") }
        return Assigned(address: inNetmask, network: IPNetwork(address: inNetmask, prefixLength: length))
    }

    /// The domains of `text` split on `separator` (blanks around each are dropped, and empty entries),
    /// each a plain host name (`DomainName`), at most `maxDomains` once repeats are dropped.
    static func domains(_ text: String?, name: String, separator: Character) throws -> [String] {
        guard let text else { return [] }
        var out: [String] = []
        for entry in text.split(separator: separator) {
            let trimmed = entry.trimmingCharacters(in: CharacterSet(charactersIn: " "))
            if trimmed.isEmpty { continue }
            guard let domain = DomainName.normalize(trimmed) else { throw Failure.invalid(name, "a list of plain domain names") }
            if !out.contains(domain) { out.append(domain) }
            guard out.count <= maxDomains else { throw Failure.tooMany(name, maxDomains) }
        }
        return out
    }

    /// A split list: the count (`CISCO_SPLIT_INC`; none is 0), then `<count>_<n>_ADDR` and `_MASKLEN` for
    /// every n below it (and IPv4's `_MASK`), no other variable under `<count>_`. IPv4 entries are
    /// openconnect's normalized text (`inet_ntop`, host bits cleared, mask and length agreeing,
    /// `script.c` 220–247), and must still be; IPv6's `_ADDR` is the server's text up to the `/`
    /// (`script.c` 138–142), parsed here and with its host bits cleared.
    static func splitList(_ env: Environment, count countName: String, family: IPAddress.Family) throws -> [IPNetwork] {
        var count = 0
        if let text = try env.text(countName) {
            guard let n = decimal(text, max: 99_999) else { throw Failure.invalid(countName, "a count") }
            guard n <= maxSplitRoutes else { throw Failure.tooMany(countName, maxSplitRoutes) }
            count = n
        }
        let fields: Set<String> = family == .ipv4 ? ["ADDR", "MASK", "MASKLEN"] : ["ADDR", "MASKLEN"]
        let prefix = countName + "_"
        for name in env.names where name.hasPrefix(prefix) {
            let rest = name.dropFirst(prefix.count).split(separator: "_", maxSplits: 1, omittingEmptySubsequences: false)
            guard rest.count == 2, let index = decimal(String(rest[0]), max: 99_999), index < count, fields.contains(String(rest[1]))
            else { throw Failure.unexpected(countName) }
        }
        var out: [IPNetwork] = []
        for index in 0..<count {
            let base = "\(prefix)\(index)_"
            let addrText = try env.required(base + "ADDR")
            let lengthText = try env.required(base + "MASKLEN")
            guard let length = decimal(lengthText, max: family.bits) else {
                throw Failure.invalid(base + "MASKLEN", "a length from 0 to \(family.bits)")
            }
            guard let address = IPAddress(addrText), address.family == family else {
                throw Failure.invalid(base + "ADDR", family == .ipv4 ? "an IPv4 address" : "an IPv6 address")
            }
            if family == .ipv4 {
                let maskText = try env.required(base + "MASK")
                guard let mask = IPAddress(maskText), mask.family == .ipv4, let maskLength = mask.maskLength else {
                    throw Failure.invalid(base + "MASK", "a contiguous IPv4 netmask")
                }
                guard maskLength == length else { throw Failure.inconsistent(base + "MASKLEN", base + "MASK") }
                guard address.masked(length) == address else { throw Failure.inconsistent(base + "ADDR", base + "MASK") }
            }
            // An exclude of every address would send everything around the tunnel.
            if length == 0, countName.hasSuffix("EXC") {
                throw Failure.invalid(base + "MASKLEN", "a length from 1 to \(family.bits) (an exclude of every address)")
            }
            out.append(IPNetwork(address: address, prefixLength: length)!)
        }
        return out
    }

    /// ASCII digits without leading zeros (`08` is refused), at most `max`.
    static func decimal(_ text: String, max: Int) -> Int? {
        let bytes = Array(text.utf8)
        guard (1...10).contains(bytes.count), bytes.allSatisfy(IPAddress.isDigit), bytes.count == 1 || bytes[0] != 0x30 else {
            return nil
        }
        let value = bytes.reduce(0) { $0 * 10 + Int($1 - 0x30) }
        return value <= max ? value : nil
    }

    // MARK: Writing back

    /// The variables openconnect would set for this network, in canonical form: parsing them again gives
    /// the same network (the tests and the fuzzer check it).
    public func environment(reason: Reason = .connect) -> [String: String] {
        var env: [String: String] = [
            "reason": reason.rawValue, "TUNDEV": interface, "VPNGATEWAY": gateway.description, "INTERNAL_IP4_MTU": String(mtu)
        ]
        if let ipv4 {
            env["INTERNAL_IP4_ADDRESS"] = ipv4.address.description
            if let network = ipv4.network {
                env["INTERNAL_IP4_NETMASK"] = IPAddress.mask(family: .ipv4, length: network.prefixLength).description
                env["INTERNAL_IP4_NETMASKLEN"] = String(network.prefixLength)
                env["INTERNAL_IP4_NETADDR"] = network.address.description
            }
        }
        if let ipv6 {
            env["INTERNAL_IP6_ADDRESS"] = ipv6.address.description
            if let network = ipv6.network { env["INTERNAL_IP6_NETMASK"] = "\(ipv6.address)/\(network.prefixLength)" }
        }
        if !dnsServers.isEmpty { env["INTERNAL_IP4_DNS"] = dnsServers.map(\.description).joined(separator: " ") }
        if !defaultDomains.isEmpty { env["CISCO_DEF_DOMAIN"] = defaultDomains.joined(separator: " ") }
        if !splitDNSDomains.isEmpty { env["CISCO_SPLIT_DNS"] = splitDNSDomains.joined(separator: ",") }
        let lists: [(String, [IPNetwork])] = [
            ("CISCO_SPLIT_INC", ipv4Includes), ("CISCO_SPLIT_EXC", ipv4Excludes), ("CISCO_IPV6_SPLIT_INC", ipv6Includes),
            ("CISCO_IPV6_SPLIT_EXC", ipv6Excludes)
        ]
        for (name, list) in lists where !list.isEmpty {
            env[name] = String(list.count)
            for (index, network) in list.enumerated() {
                env["\(name)_\(index)_ADDR"] = network.address.description
                env["\(name)_\(index)_MASKLEN"] = String(network.prefixLength)
                if network.family == .ipv4 {
                    env["\(name)_\(index)_MASK"] = IPAddress.mask(family: .ipv4, length: network.prefixLength).description
                }
            }
        }
        if let vpnPID { env["VPNPID"] = String(vpnPID) }
        return env
    }
}
