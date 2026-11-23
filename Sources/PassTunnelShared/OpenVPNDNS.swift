import Foundation

/// A property list value, as the system configuration keeps it.
public indirect enum PlistValue: Equatable, Sendable {
    case string(String)
    case integer(Int)
    case real(Double)
    case bool(Bool)
    case data(Data)
    case date(Date)
    case array([PlistValue])
    case dictionary([String: PlistValue])

    /// The value as a list of strings; nil unless it is an array of strings only.
    public var strings: [String]? {
        guard case .array(let items) = self else { return nil }
        var out: [String] = []
        for item in items {
            guard case .string(let s) = item else { return nil }
            out.append(s)
        }
        return out
    }
}

/// A `DNS` entity of the system configuration: a service's (`Setup:/Network/Service/<id>/DNS`), a backup
/// OpenVPN's script keeps, or what the network preferences hold.
public typealias DNSEntity = [String: PlistValue]

/// What OpenVPN's macOS `dns-updown` sets for one session, worked out from the variables of its dns-up (the
/// record `HelperCore.dnsHookText` keeps) the way the script does (docs/ARCHITECTURE.md, "DNS script (macOS)").
public struct OpenVPNDNSSession: Equatable, Sendable {
    public var dev: String
    /// The addresses of the first server the script can use (`find_compat_profile`: plain transport, no DNSSEC,
    /// only port 53), in order; empty when there is none, and the script then sets nothing.
    public var servers: [String]
    /// `dns_search_domain_<i>` up to the first gap, each once.
    public var searchDomains: [String]
    /// That server's `resolve_domain_<i>`: not empty, the script's split branch (its own `State:` key and the
    /// search domains on the primary service); empty, its full branch (the primary service's `Setup:` DNS
    /// replaced).
    public var matchDomains: [String]

    public var isSplit: Bool { !matchDomains.isEmpty }

    public init(dev: String, servers: [String], searchDomains: [String] = [], matchDomains: [String] = []) {
        self.dev = dev
        self.servers = servers
        self.searchDomains = searchDomains
        self.matchDomains = matchDomains
    }

    /// From the recorded variables (`HelperCore.dnsVariables`); nil without a `dev` the keys can name.
    public init?(variables v: [String: String]) {
        guard let dev = v["dev"], OpenVPNDNS.isDeviceName(dev) else { return nil }
        func list(_ name: (Int) -> String) -> [String] {
            var out: [String] = []
            var i = 1
            while i <= OpenVPNDNS.maxIndex, let value = v[name(i)], !value.isEmpty {
                if !out.contains(value) { out.append(value) }
                i += 1
            }
            return out
        }
        // `find_compat_profile` and `only_standard_server_ports`.
        var server: Int?
        var n = 1
        while n <= OpenVPNDNS.maxIndex, let first = v["dns_server_\(n)_address_1"], !first.isEmpty {
            let transport = v["dns_server_\(n)_transport"] ?? ""
            let dnssec = v["dns_server_\(n)_dnssec"] ?? ""
            var standardPorts = true
            var i = 1
            while i <= OpenVPNDNS.maxIndex, let a = v["dns_server_\(n)_address_\(i)"], !a.isEmpty {
                let port = v["dns_server_\(n)_port_\(i)"] ?? ""
                if !port.isEmpty && port != "53" { standardPorts = false }
                i += 1
            }
            if (transport.isEmpty || transport == "plain") && (dnssec.isEmpty || dnssec == "no") && standardPorts {
                server = n
                break
            }
            n += 1
        }
        self.dev = dev
        guard let n = server else {
            servers = []
            searchDomains = []
            matchDomains = []
            return
        }
        servers = list { "dns_server_\(n)_address_\($0)" }
        searchDomains = list { "dns_search_domain_\($0)" }
        matchDomains = list { "dns_server_\(n)_resolve_domain_\($0)" }
    }

    /// The `Setup:` DNS the full branch writes on the primary service: the servers, the search domains (an empty
    /// list when there are none) and `SearchOrder` 5000.
    public var overrideEntity: DNSEntity {
        [
            "ServerAddresses": .array(servers.map(PlistValue.string)),
            "SearchDomains": .array(searchDomains.map(PlistValue.string)),
            "SearchOrder": .integer(OpenVPNDNS.scriptSearchOrder)
        ]
    }
}

/// What the helper reads and changes of the Mac's DNS for OpenVPN's script, behind a protocol: the logic
/// (`OpenVPNDNS`) runs against a fake in the tests and against `MacOpenVPNDNSSystem` in the helper (and, for
/// reading only, in the app).
public protocol OpenVPNDNSSystem: AnyObject {
    /// Every `Setup:/Network/Service/<id>/DNS` of the dynamic store, by service ID; nil when the store cannot be
    /// read.
    func serviceDNS() -> [String: DNSEntity]?
    /// The `DNS` entity the network preferences hold for the service.
    func preferencesDNS(service: String) -> OpenVPNDNS.Preferences
    /// Writes the service's `Setup:` DNS in the dynamic store, or removes it (`nil`); true when the store took it.
    func setServiceDNS(service: String, _ entity: DNSEntity?) -> Bool
    /// The script's backups (`State:/Network/Service/openvpn-<dev>/DnsBackup`) by `dev`; nil when the store cannot
    /// be read.
    func scriptBackups() -> [String: DNSEntity]?
    func removeScriptBackup(dev: String) -> Bool
    /// The split branch's keys (`State:/Network/Service/openvpn-<dev>/DNS`) by `dev`; nil when the store cannot be
    /// read.
    func tunnelDNS() -> [String: DNSEntity]?
    func removeTunnelDNS(dev: String) -> Bool
    /// Whether a network interface of that name exists now.
    func interfaceExists(_ name: String) -> Bool
    /// The service's name in the network preferences ("Wi-Fi"); nil when it has none.
    func serviceName(_ service: String) -> String?
}

/// Gives the Mac its DNS back after an OpenVPN session (docs/ARCHITECTURE.md, "DNS script (macOS)"). OpenVPN's
/// script restores the primary service's DNS at dns-down only while that service is still primary and still has
/// the VPN's servers; with no network then, or another primary service, it leaves the VPN's DNS where it put it.
/// The helper does not trust its exit status: once the session has ended it looks for what the script set for
/// that session (`OpenVPNDNSSession`, from the record) and puts back what the network preferences hold.
public enum OpenVPNDNS {
    /// `SearchOrder` of the script's full branch.
    public static let scriptSearchOrder = 5000
    /// The highest index the record's names can carry (`HelperCore.isDNSVariableName`: four digits).
    static let maxIndex = 9999

    /// What the network preferences hold for a service's DNS.
    public enum Preferences: Equatable, Sendable {
        /// A `DNS` entity (as the preferences keep it; `normalized` gives what configd publishes of it).
        case entity(DNSEntity)
        /// None: no such service, or no `DNS` entity.
        case none
        /// The preferences cannot be read.
        case unreadable
    }

    /// One service the helper gave its DNS back.
    public struct Restored: Equatable, Sendable {
        public var serviceID: String
        /// The service's name ("Wi-Fi"), or its ID when it has none.
        public var service: String
        /// What was still set: the VPN's servers, or for the split branch its search domains.
        public var settings: [String]

        public init(serviceID: String, service: String, settings: [String]) {
            self.serviceID = serviceID
            self.service = service
            self.settings = settings
        }
    }

    /// How settling a session's DNS went.
    public enum Settlement: Equatable, Sendable {
        /// Nothing of the session is left (`restored`: what the helper put back for it).
        case done(restored: [Restored])
        /// The session's DNS is in the backup of another session of the script that is running: when that one
        /// ends, the script puts it back on a service, and the helper looks again then.
        case parked(restored: [Restored])
        /// Something could not be read or put back: the record stays, and the helper tries again.
        case failed(reason: String, restored: [Restored], left: [Restored])
    }

    /// A DNS entity as configd publishes it: entries that are dictionaries left out (`flatten` makes keys of
    /// them), and an empty or inactive entity (`__INACTIVE__`) as none.
    public static func normalized(_ entity: DNSEntity?) -> DNSEntity? {
        guard var e = entity, e["__INACTIVE__"] == nil else { return nil }
        for (key, value) in e { if case .dictionary = value { e[key] = nil } }
        return e.isEmpty ? nil : e
    }

    public static func normalized(_ preferences: Preferences) -> DNSEntity? {
        if case .entity(let e) = preferences { return normalized(e) }
        return nil
    }

    /// The entity with an empty `SearchDomains` left out: the script writes one when the server sent no search
    /// domains.
    static func withoutEmptySearchDomains(_ e: DNSEntity) -> DNSEntity {
        var e = e
        if e["SearchDomains"]?.strings == [] { e["SearchDomains"] = nil }
        return e
    }

    /// Whether `entity` is exactly what the script's full branch wrote for `session`.
    public static func isOverride(_ entity: DNSEntity, of session: OpenVPNDNSSession) -> Bool {
        !session.servers.isEmpty && withoutEmptySearchDomains(entity) == withoutEmptySearchDomains(session.overrideEntity)
    }

    /// Whether `entity` has the shape of the script's full branch: `ServerAddresses` (not empty), `SearchOrder` 5000,
    /// `SearchDomains` or not, and nothing else.
    public static func isScriptOverride(_ entity: DNSEntity) -> Bool {
        guard entity["SearchOrder"] == .integer(scriptSearchOrder), let servers = entity["ServerAddresses"]?.strings, !servers.isEmpty
        else { return false }
        if let domains = entity["SearchDomains"], domains.strings == nil { return false }
        return Set(entity.keys).isSubset(of: ["ServerAddresses", "SearchDomains", "SearchOrder"])
    }

    /// `utun7`: the only `dev` the keys are built from.
    public static func isDeviceName(_ s: String) -> Bool {
        (1...15).contains(s.utf8.count)
            && s.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("A"..."Z").contains($0) || ("0"..."9").contains($0) }
    }

    /// A service ID as the system configuration names services (a UUID, or another ID of letters, digits and `-`).
    public static func isServiceID(_ s: String) -> Bool {
        (1...64).contains(s.utf8.count)
            && s.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("A"..."Z").contains($0) || ("0"..."9").contains($0) || $0 == "-" }
    }

    // MARK: Settling a session

    /// Looks for what the script set for `session`, now that it has ended, and puts back what the network
    /// preferences hold where it is still set:
    /// - full branch: every service whose `Setup:` DNS is exactly the session's override (`isOverride`), unless a
    ///   session in `live` set the same one (it may be that one's, which its own end settles); the session's own
    ///   backup once its tunnel is gone (a stale one makes every later dns-up of the script fail); and a backup of
    ///   another session that holds the override (`parked`).
    /// - split branch: its `State:` key once its tunnel is gone, and every service whose search domains still start
    ///   with the session's while the rest of its DNS is what the preferences hold, unless a session in `live` has
    ///   search domains there too.
    /// A service whose DNS is anything else (changed by someone in the meantime) is left as it is.
    public static func settle(_ session: OpenVPNDNSSession, live: [OpenVPNDNSSession], system: OpenVPNDNSSystem) -> Settlement {
        guard !session.servers.isEmpty else { return .done(restored: []) }
        guard let services = system.serviceDNS() else {
            return .failed(reason: "the system configuration cannot be read", restored: [], left: [])
        }
        var restored: [Restored] = []
        var left: [Restored] = []
        var failure: String?
        var parked = false
        let tunnelGone = !system.interfaceExists(session.dev) && !live.contains { $0.dev == session.dev }

        func put(_ id: String, _ current: DNSEntity, settings: [String]) {
            let entry = Restored(serviceID: id, service: name(of: id, system: system), settings: settings)
            switch restore(id, current: current, system: system) {
            case .restored: restored.append(entry)
            case .unchanged: break
            case .failed(let reason):
                failure = failure ?? reason
                left.append(entry)
            }
        }

        if !session.isSplit {
            let held = live.contains { !$0.isSplit && $0.servers == session.servers && $0.searchDomains == session.searchDomains }
            for (id, entity) in services.sorted(by: { $0.key < $1.key }) where isServiceID(id) && isOverride(entity, of: session) && !held {
                put(id, entity, settings: session.servers)
            }
            guard let backups = system.scriptBackups() else {
                return .failed(reason: "the system configuration cannot be read", restored: restored, left: left)
            }
            if backups[session.dev] != nil, tunnelGone {
                if !system.removeScriptBackup(dev: session.dev) { failure = failure ?? "its backup could not be removed" }
            }
            parked =
                !held
                && backups.contains { dev, backup in
                    dev != session.dev && isOverride(normalized(backup) ?? [:], of: session)
                }
        } else {
            guard let tunnels = system.tunnelDNS() else {
                return .failed(reason: "the system configuration cannot be read", restored: restored, left: left)
            }
            if let entity = tunnels[session.dev], tunnelGone, entity["ServerAddresses"]?.strings == session.servers,
                entity["SupplementalMatchDomains"]?.strings == session.matchDomains
            {
                if !system.removeTunnelDNS(dev: session.dev) {
                    failure = failure ?? "its split DNS could not be removed"
                    left.append(Restored(serviceID: "", service: "openvpn-\(session.dev)", settings: session.matchDomains))
                }
            }
            if !session.searchDomains.isEmpty {
                let liveDomains = Set(live.flatMap { $0.isSplit ? $0.searchDomains : [] })
                for (id, entity) in services.sorted(by: { $0.key < $1.key }) where isServiceID(id) {
                    guard let domains = entity["SearchDomains"]?.strings, domains.starts(with: session.searchDomains),
                        liveDomains.isDisjoint(with: domains)
                    else { continue }
                    let preferences = system.preferencesDNS(service: id)
                    if preferences == .unreadable {
                        failure = failure ?? "the network preferences cannot be read"
                        continue
                    }
                    var rest = entity
                    rest["SearchDomains"] = nil
                    var configured = normalized(preferences) ?? [:]
                    configured["SearchDomains"] = nil
                    // Anything else changed too: someone else set it since.
                    guard rest == configured else { continue }
                    put(id, entity, settings: session.searchDomains)
                }
            }
        }
        if let failure { return .failed(reason: failure, restored: restored, left: left) }
        return parked ? .parked(restored: restored) : .done(restored: restored)
    }

    enum Outcome: Equatable {
        case restored, unchanged
        case failed(String)
    }

    /// Puts back what the preferences hold for service `id`, whose `Setup:` DNS is `current`: the preferences'
    /// entity, or no key when they hold none; then reads it back. `unchanged` when it is that already, or when
    /// it is no longer `current` (someone changed it since it was read).
    static func restore(_ id: String, current: DNSEntity, system: OpenVPNDNSSystem) -> Outcome {
        let preferences = system.preferencesDNS(service: id)
        if preferences == .unreadable { return .failed("the network preferences cannot be read") }
        let target = normalized(preferences)
        if normalized(current) == target { return .unchanged }
        guard let now = system.serviceDNS() else { return .failed("the system configuration cannot be read") }
        guard normalized(now[id]) == normalized(current) else { return .unchanged }
        guard system.setServiceDNS(service: id, target) else { return .failed("the system configuration did not take the change") }
        guard let after = system.serviceDNS() else { return .failed("the system configuration cannot be read") }
        return normalized(after[id]) == target ? .restored : .failed("the change did not hold")
    }

    static func name(of id: String, system: OpenVPNDNSSystem) -> String {
        let name = system.serviceName(id).map(cleanName) ?? ""
        return name.isEmpty ? id : name
    }

    /// A service name for one log line: no control characters or quotation marks, at most 64 characters.
    static func cleanName(_ name: String) -> String {
        let scalars = name.unicodeScalars.map { c -> Character in
            c.properties.generalCategory == .control || c == "“" || c == "”" || c == "\"" ? " " : Character(c)
        }
        let s = String(scalars).trimmingCharacters(in: .whitespaces)
        return s.count > 64 ? String(s.prefix(64)) : s
    }

    // MARK: Left behind

    /// A service whose DNS the script set and nothing will put back: what `leftBehind` reports.
    public struct LeftBehind: Equatable, Sendable {
        public var serviceID: String
        public var service: String
        public var servers: [String]

        public init(serviceID: String, service: String, servers: [String]) {
            self.serviceID = serviceID
            self.service = service
            self.servers = servers
        }
    }

    /// The services whose `Setup:` DNS has the shape the script's full branch writes (`isScriptOverride`), differs
    /// from what the preferences hold, while no session of the script is redirecting DNS (no backup of a tunnel that
    /// is there): a VPN's DNS left behind. Nothing shows whose it is, so it is only reported, never changed. Nil when
    /// the store cannot be read.
    public static func leftBehind(system: OpenVPNDNSSystem) -> [LeftBehind]? {
        guard let services = system.serviceDNS(), let backups = system.scriptBackups() else { return nil }
        if backups.keys.contains(where: { isDeviceName($0) && system.interfaceExists($0) }) { return [] }
        var out: [LeftBehind] = []
        for (id, entity) in services.sorted(by: { $0.key < $1.key }) where isServiceID(id) && isScriptOverride(entity) {
            let preferences = system.preferencesDNS(service: id)
            guard preferences != .unreadable, normalized(preferences) != normalized(entity) else { continue }
            let servers = (entity["ServerAddresses"]?.strings ?? []).filter(Note.isSetting)
            out.append(LeftBehind(serviceID: id, service: name(of: id, system: system), servers: servers))
        }
        return out
    }

    // MARK: Log lines

    /// A line the helper writes into a session's log about the Mac's DNS, which the app reads back
    /// (`ConnectionManager`, the activity).
    public struct Note: Equatable, Sendable {
        public enum Kind: Equatable, Sendable {
            /// The helper put the service's own DNS back.
            case restored
            /// It could not, and tries again.
            case notRestored
            /// The script's DNS without a session that set it: reported, not changed (`leftBehind`).
            case leftBehind
        }

        public var kind: Kind
        public var service: String
        public var settings: [String]
        /// Why it could not (`notRestored`).
        public var reason: String?

        public init(_ kind: Kind, service: String, settings: [String], reason: String? = nil) {
            self.kind = kind
            self.service = cleanName(service)
            self.settings = settings.filter(Self.isSetting)
            self.reason = reason
        }

        static let prefix = "PassTunnel helper: "
        static let restoredHead = "restored the DNS of “"
        static let restoredTail = "”, which still used the VPN's "
        static let notRestoredHead = "could not restore the DNS of “"
        static let notRestoredTail = "”, which still uses the VPN's "
        static let notRestoredEnd = "; trying again"
        static let leftHead = "the DNS of “"
        static let leftTail = "” still uses "
        static let leftEnd =
            ", set by OpenVPN's DNS script with no session running to undo it; left as it is, as nothing shows that PassTunnel set it"

        /// An address or a domain name as the line lists it (`HelperCore.isDNSValueScalar`'s characters).
        static func isSetting(_ s: String) -> Bool {
            !s.isEmpty && s.utf8.count <= 255 && s.unicodeScalars.allSatisfy(HelperCore.isDNSValueScalar)
        }

        /// The line, without its line break. Not "PassTunnel: ", which the app reads as a failed start.
        public var line: String {
            let list = settings.joined(separator: ", ")
            switch kind {
            case .restored:
                return Self.prefix + Self.restoredHead + service + Self.restoredTail + list
            case .notRestored:
                let why = reason.map { " (" + VPNHook.oneLine($0, maxBytes: 200) + ")" } ?? ""
                return Self.prefix + Self.notRestoredHead + service + Self.notRestoredTail + list + Self.notRestoredEnd + why
            case .leftBehind:
                return Self.prefix + Self.leftHead + service + Self.leftTail + list + Self.leftEnd
            }
        }

        /// The note a log line is; nil for any other line.
        public init?(line: String) {
            guard line.hasPrefix(Self.prefix) else { return nil }
            let rest = String(line.dropFirst(Self.prefix.count))
            // The name is the text between the head and the last tail (a name holds no quotation marks).
            func split(_ text: String, head: String, tail: String) -> (String, String)? {
                guard text.hasPrefix(head), let r = text.range(of: tail, options: .backwards) else { return nil }
                let start = text.index(text.startIndex, offsetBy: head.count)
                guard r.lowerBound >= start else { return nil }
                return (String(text[start..<r.lowerBound]), String(text[r.upperBound...]))
            }
            func settings(_ list: String) -> [String] { list.components(separatedBy: ", ") }
            if let parts = split(rest, head: Self.restoredHead, tail: Self.restoredTail) {
                self.init(.restored, service: parts.0, settings: settings(parts.1))
            } else if let parts = split(rest, head: Self.notRestoredHead, tail: Self.notRestoredTail),
                let end = parts.1.range(of: Self.notRestoredEnd)
            {
                var reason = String(parts.1[end.upperBound...])
                if reason.hasPrefix(" (") && reason.hasSuffix(")") { reason = String(reason.dropFirst(2).dropLast()) }
                self.init(
                    .notRestored, service: parts.0, settings: settings(String(parts.1[..<end.lowerBound])),
                    reason: reason.isEmpty ? nil : reason)
            } else if rest.hasSuffix(Self.leftEnd),
                let parts = split(String(rest.dropLast(Self.leftEnd.count)), head: Self.leftHead, tail: Self.leftTail)
            {
                self.init(.leftBehind, service: parts.0, settings: settings(parts.1))
            } else {
                return nil
            }
            if self.service.isEmpty || self.settings.isEmpty { return nil }
        }

        /// Every note in `log`, in order.
        public static func all(in log: String) -> [Note] {
            log.split(whereSeparator: \.isNewline).compactMap { Note(line: String($0)) }
        }
    }
}
