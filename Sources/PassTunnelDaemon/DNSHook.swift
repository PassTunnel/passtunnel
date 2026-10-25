import Foundation
import PassTunnelShared

/// The DNS OpenVPN hands its hook in the environment (docs/LINUX.md, "DNS"). Every value comes from the
/// server or the profile and is checked by `DNSSettings`; at most `maxIndex` entries of a kind are read.
public enum OpenVPNDNS {
    static let maxIndex = 64
    static let maxForeignOptions = 256

    /// The `--dns` settings when there are any (`dns_*`: everything on OpenVPN 2.7, which turns pushed
    /// `dhcp-option`s into them; on 2.6 what the server pushed with `dns`), else the `dhcp-option`s of
    /// OpenVPN 2.6 (`foreign_option_N`: `DNS`, `DNS6`, `DOMAIN`, `DOMAIN-SEARCH`,
    /// `ADAPTER-DOMAIN-SUFFIX`). Nil when no server is named. Every name goes through the tunnel unless
    /// the server names the domains its server resolves (`dns server N resolve-domains`), as OpenVPN's
    /// own DNS scripts and the Mac do.
    public static func settings(environment: [String: String]) throws -> DNSSettings? {
        if environment.keys.contains(where: { $0.hasPrefix("dns_server_") || $0.hasPrefix("dns_search_domain_") }) {
            return try dnsOptions(environment)
        }
        return try dhcpOptions(environment)
    }

    /// `dns_search_domain_<i>`, `dns_server_<n>_address_<m>`, `…_port_<m>`, `…_resolve_domain_<m>` and
    /// `…_transport`. The first server (they come in order of priority) that plain DNS on port 53
    /// reaches is used.
    static func dnsOptions(_ environment: [String: String]) throws -> DNSSettings? {
        var search: [Int: String] = [:]
        var addresses: [Int: [Int: String]] = [:], ports: [Int: [Int: String]] = [:]
        var resolveDomains: [Int: [Int: String]] = [:], transports: [Int: String] = [:]
        for (key, value) in environment where key.hasPrefix("dns_") {
            let parts = key.split(separator: "_", omittingEmptySubsequences: false).map(String.init)
            if parts.count == 4, parts[1] == "search", parts[2] == "domain" {
                search[try index(parts[3], key)] = value
            } else if parts.count >= 4, parts[1] == "server" {
                let n = try index(parts[2], key)
                switch parts[3...].joined(separator: "_") {
                case let rest where rest.hasPrefix("address_") && parts.count == 5:
                    addresses[n, default: [:]][try index(parts[4], key)] = value
                case let rest where rest.hasPrefix("port_") && parts.count == 5:
                    ports[n, default: [:]][try index(parts[4], key)] = value
                case let rest where rest.hasPrefix("resolve_domain_") && parts.count == 6:
                    resolveDomains[n, default: [:]][try index(parts[5], key)] = value
                case "transport":
                    transports[n] = value
                default:
                    continue     // dnssec, sni and whatever later versions add
                }
            }
        }
        guard !addresses.isEmpty else { return nil }
        let usable = addresses.keys.sorted().first { n in
            let transport = transports[n]?.lowercased() ?? "plain"
            return transport == "plain" && (ports[n] ?? [:]).values.allSatisfy { $0 == "53" }
        }
        guard let n = usable else { throw DNSFailure.noUsableServer }
        let routing = ordered(resolveDomains[n] ?? [:])
        return try DNSSettings(servers: ordered(addresses[n]!), searchDomains: ordered(search), routingDomains: routing,
                               fullTunnel: routing.isEmpty)
    }

    /// `foreign_option_<i>` = `dhcp-option <TYPE> <value>`; other types (WINS, NTP, …) are not DNS.
    static func dhcpOptions(_ environment: [String: String]) throws -> DNSSettings? {
        var servers: [Int: String] = [:], domains: [Int: String] = [:]
        for (key, value) in environment where key.hasPrefix("foreign_option_") {
            let i = try index(String(key.dropFirst("foreign_option_".count)), key, limit: maxForeignOptions)
            let words = value.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
            guard words.count >= 2, words[0] == "dhcp-option" else { continue }
            switch words[1] {
            case "DNS", "DNS6":
                guard words.count == 3 else { throw DNSFailure.invalid("dhcp-option", value) }
                servers[i] = words[2]
            case "DOMAIN", "DOMAIN-SEARCH", "ADAPTER-DOMAIN-SUFFIX":
                guard words.count == 3 else { throw DNSFailure.invalid("dhcp-option", value) }
                domains[i] = words[2]
            default:
                continue
            }
        }
        guard !servers.isEmpty else { return nil }
        return try DNSSettings(servers: ordered(servers), searchDomains: ordered(domains), fullTunnel: true)
    }

    /// An index as OpenVPN writes them: 1 to `limit`, digits only.
    static func index(_ text: String, _ key: String, limit: Int = maxIndex) throws -> Int {
        guard (1...3).contains(text.utf8.count), text.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
              let i = Int(text), String(i) == text, (1...limit).contains(i) else {
            throw DNSFailure.invalid("variable", key)
        }
        return i
    }

    static func ordered(_ values: [Int: String]) -> [String] {
        values.keys.sorted().map { values[$0]! }
    }
}

/// `passtunneld dns-hook`: the daemon's executable run by OpenVPN as root, as `--dns-updown` (2.7) or
/// `--route-up` and `--down` (2.6), through the session directory's `dns-hook` link (docs/LINUX.md,
/// "DNS"). It never starts a daemon, takes its lock or touches its socket. It acts only for the session
/// it was started in: its working directory must be a session directory of the run root whose recorded
/// tool (`state`) is its parent process. It sets up DNS (`DNSApplier`, recording what it does in that
/// directory) or reverts what the session recorded. Its output goes to the session's log, where a
/// failure ("setting DNS failed") makes the client stop the session (`PTError.setupFailed`).
public enum DNSHook {
    static let logPrefix = "passtunneld dns-hook: "

    /// `passtunneld dns-hook`, or the executable started under the hook's name. Arguments OpenVPN adds
    /// (`--down` appends the device, MTU, addresses and "init") are ignored: everything comes from the
    /// environment.
    public static func isInvocation(_ arguments: [String]) -> Bool {
        if arguments.count >= 2, arguments[1] == "dns-hook" { return true }
        return arguments.first.map { ($0 as NSString).lastPathComponent } == HelperCore.dnsHookName
    }

    struct Options {
        var runRoot = PT.helperRunRoot
        /// Checked with `TrustedPath`, as the daemon checks itself when it starts. Nil only in tests.
        var ownExecutable: String? = "/proc/self/exe"
        var system = DNSSystem()
        var effectiveUID: () -> uid_t = { geteuid() }
        var workingDirectory: () -> String? = { FileManager.default.currentDirectoryPath }
        var parent: () -> pid_t = { getppid() }
        /// The recorded tool is still the process the daemon started (`PreviousInstance.isAlive`: the same
        /// boot, start time and executable); replaced in tests.
        var isRecordedTool: (PreviousInstance.State) -> Bool = PreviousInstance.isAlive
        var output: (String) -> Void = { line in
            let text = DNSHook.logPrefix + DaemonLog.oneLine(line) + "\n"
            _ = text.withCString { write(1, $0, strlen($0)) }
        }
    }

    /// Runs the hook; returns its exit status.
    public static func main(environment: [String: String]) -> Int32 {
        run(environment: environment, options: Options())
    }

    enum Phase { case up, down }

    static func run(environment: [String: String], options: Options) -> Int32 {
        let phase: Phase
        switch environment["script_type"] ?? "" {
        case "dns-up", "route-up", "up": phase = .up
        case "dns-down", "down": phase = .down
        default:
            options.output("setting DNS failed: \(DNSFailure.unknownPhase(environment["script_type"] ?? ""))")
            return 1
        }
        do {
            guard options.effectiveUID() == 0 else { throw DNSFailure.notRoot }
            if let own = options.ownExecutable {
                guard let real = HelperCore.realPath(own) else { throw DNSFailure.untrustedTool(own, "its path cannot be resolved.") }
                do { try TrustedPath.check(real) } catch { throw DNSFailure.untrustedTool(real, String(describing: error)) }
            }
            guard environment["dns_vars_file"] == nil else { throw DNSFailure.varsFile }
            let session = try Self.session(options)
            let applier = DNSApplier(system: options.system, runRoot: options.runRoot)
            switch phase {
            case .up:
                guard let settings = try OpenVPNDNS.settings(environment: environment) else {
                    options.output("the server named no DNS servers; DNS is left as it is")
                    return 0
                }
                let interface = try DNSSettings.interface(environment["dev"] ?? "")
                let backend = try applier.apply(settings, interface: interface, in: session)
                options.output(describe(settings, interface: interface, backend: backend))
            case .down:
                if let message = applier.revert(in: session) { options.output(message) }
            }
            return 0
        } catch {
            options.output((phase == .up ? "setting DNS failed: " : "restoring DNS failed: ") + String(describing: error))
            return 1
        }
    }

    /// The session the hook runs for: its working directory, `<runRoot>/<uid>/<profile ID>`, a
    /// root-owned session directory whose recorded tool is the hook's parent.
    static func session(_ options: Options) throws -> SessionDirectory {
        guard let cwd = options.workingDirectory(), cwd.hasPrefix(options.runRoot + "/") else {
            throw DNSFailure.notASession("it does not run in a session directory")
        }
        let parts = cwd.dropFirst(options.runRoot.count + 1).split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2, let uid = uid_t(parts[0]), String(uid) == parts[0], HelperCore.isValidProfileID(parts[1]) else {
            throw DNSFailure.notASession("it does not run in a session directory")
        }
        let session: SessionDirectory
        do {
            session = try HelperCore(runRoot: options.runRoot).openRunDir(profileID: parts[1], uid: uid)
        } catch {
            throw DNSFailure.notASession(String(describing: error))
        }
        guard let state = PreviousInstance.readState(session.path + "/" + Supervisor.stateFileName), state.uid == uid else {
            throw DNSFailure.notASession("the session has no record of its tool")
        }
        guard state.pid == options.parent(), options.isRecordedTool(state) else {
            throw DNSFailure.notASession("it was not started by the session's tool")
        }
        return session
    }

    static func describe(_ settings: DNSSettings, interface: String, backend: DNSBackend) -> String {
        var text = "DNS of \(interface) set through \(backend.name): " + settings.servers.joined(separator: ", ")
        if !settings.searchDomains.isEmpty { text += "; search " + settings.searchDomains.joined(separator: " ") }
        if !settings.routingDomains.isEmpty { text += "; only for " + settings.routingDomains.joined(separator: " ") }
        return text
    }
}
