import Foundation
import PassTunnelKit

/// The words of the MCP texts that differ between the Mac and Linux (docs/LINUX.md, Commands that
/// differ): the machine, and what a protected profile needs. Linux cannot ask for a confirmation yet,
/// so it refuses protected profiles with `auth_unavailable`. The Mac's texts stay exactly as they are
/// listed in MCP directories.
enum MCPWording {
    /// Palo Alto GlobalProtect ships labelled experimental (`VPNType.isExperimental`), the same on both systems.
    static let instructionsExperimental =
        "Palo Alto GlobalProtect is experimental: its profiles have experimental=true. A connected one can have notices (hip_report_not_sent: the gateway asked for a host information report, which PassTunnel does not send, so access may be limited); tell the user. A sign-in that needs single sign-on fails with sso_required."
    #if os(Linux)
    static let thisMachines = "this computer's"
    static let theMachines = "this computer's"
    static let theMachine = "this computer"
    static let listProtected =
        "protected=true means connecting is refused on Linux for now (auth_unavailable): there is no confirmation to ask for yet."
    static let connectProtected = "A protected profile cannot be connected on Linux yet: it is refused with auth_unavailable."
    static let instructionsProtected = "A protected profile cannot be connected on Linux yet: connect refuses it with auth_unavailable."
    static let timeout = "How long to wait for the connection."
    static let timeServer = "the NTP server this computer is set up with"
    static let diagnoseTools = ""
    static let anyConnectPlatform =
        "Cisco AnyConnect needs the distribution's openconnect 9.01 or later, Palo Alto GlobalProtect 9.11 or later: when it is missing or older, connect is refused with config_invalid before the one-time code is used."
    static let instructionsAnyConnect =
        "Cisco AnyConnect needs the distribution's openconnect 9.01 or later, Palo Alto GlobalProtect 9.11 or later; connect says why when it is missing or too old."
    #else
    static let thisMachines = "this Mac's"
    static let theMachines = "the Mac's"
    static let theMachine = "the Mac"
    static let listProtected = "protected=true means connecting asks the user for Touch ID on the Mac."
    static let connectProtected = "If the profile is protected, the user must confirm with Touch ID on the Mac: tell them a prompt is waiting."
    static let instructionsProtected =
        "A protected profile shows a Touch ID prompt on the Mac that the user must confirm; tell the user to look for it."
    static let timeout = "How long to wait for the connection (after the Touch ID confirmation)."
    static let timeServer = "Apple's time server (time.apple.com)"
    static let diagnoseTools =
        "; also whether each VPN tool bundled with the app starts on this macOS version (run with --version; nothing is contacted), and whether a VPN's DNS servers are still set on a network service with no VPN session to undo them (no name resolves then)"
    static let anyConnectPlatform =
        "Cisco AnyConnect and Palo Alto GlobalProtect need macOS 15.4 or later: on an older macOS they are refused with config_invalid before anything is asked or sent, and list_profiles shows that as connect_refusal."
    static let instructionsAnyConnect =
        "Cisco AnyConnect and Palo Alto GlobalProtect need macOS 15.4 or later; a profile that cannot be connected here says why in connect_refusal."
    #endif
}

/// The tools of `passtunnel mcp`. Read-only by default (`list_profiles`, `get_status`, `get_logs`,
/// `diagnose`); `connect` and `disconnect` exist only with `--allow-connect`. There is deliberately
/// no tool that returns a code or a secret, and none that creates, changes or deletes a profile.
/// Arguments are checked strictly: unknown keys, wrong types and profile ids that are not valid ids
/// are refused before anything is read.
@MainActor
final class MCPTools {
    let service: AutomationService
    let allowConnect: Bool
    private let log: (String) -> Void
    /// Connects started with `wait: false`, still running.
    private var background: [Task<Void, Never>] = []

    static let defaultTimeout = 60
    static let maxTimeout = 600
    static let defaultLogLines = 50

    init(service: AutomationService, allowConnect: Bool, log: @escaping (String) -> Void) {
        self.service = service
        self.allowConnect = allowConnect
        self.log = log
    }

    private var store: ProfileStore { service.store }
    private var manager: ConnectionManager { service.manager }

    // MARK: definitions

    struct Tool {
        var name: String
        var title: String
        var description: String
        var input: [String: Any]
        var output: [String: Any]
        var readOnly: Bool
        var destructive = false
    }

    /// In a fixed order, so clients can cache the list.
    var available: [Tool] {
        allowConnect ? Self.readTools + Self.connectTools : Self.readTools
    }

    func isAvailable(_ name: String) -> Bool { available.contains { $0.name == name } }

    /// `tools/list` entries for `version` (title and outputSchema from 2025-06-18, annotations from
    /// 2025-03-26).
    func definitions(version: String) -> [[String: Any]] {
        available.map { tool in
            var d: [String: Any] = ["name": tool.name, "description": tool.description, "inputSchema": tool.input]
            if version >= "2025-03-26" {
                var a: [String: Any] = ["title": tool.title, "readOnlyHint": tool.readOnly, "openWorldHint": !tool.readOnly]
                if !tool.readOnly {
                    a["destructiveHint"] = tool.destructive
                    a["idempotentHint"] = true
                }
                d["annotations"] = a
            }
            if MCPServer.supportsStructuredContent(version) {
                d["title"] = tool.title
                d["outputSchema"] = tool.output
            }
            return d
        }
    }

    static let readTools: [Tool] = [
        Tool(
            name: "list_profiles", title: "List VPN profiles",
            description:
                "Lists the VPN profiles configured in PassTunnel with their current state. Call it first: the id of each profile is the profile_id the other tools take. Use get_status instead for the tunnel address of a connected profile or why its last connect failed, and diagnose to check a profile's configuration and saved credentials. A profile with connect_refusal cannot be connected on this system, such as Cisco AnyConnect or Palo Alto GlobalProtect on an older macOS. connect would fail with that same code and message, so tell the user the message instead. needs_newer_version=true marks a profile saved by a newer PassTunnel: get_status leaves it out, and the tools that take a profile_id refuse it with config_invalid. experimental=true marks a profile of an experimental type (Palo Alto GlobalProtect). type code marks a code-only profile: it has no VPN and only shows a one-time code in PassTunnel (these tools never return codes), and connect refuses it with invalid_argument. \(MCPWording.listProtected)",
            input: Schema.object([:]), output: Schema.object(["profiles": Schema.array(Schema.profileSummary)], required: ["profiles"]),
            readOnly: true),
        Tool(
            name: "get_status", title: "Get connection status",
            description:
                "Reports the connection state of every VPN profile, or of one: disconnected, connecting or connected. Use it to answer whether a VPN is up, which tunnel address it has and since when, or why its last connect failed (failure). Use get_logs instead when failure does not explain enough and the VPN tool's own output is needed, and diagnose when the cause may be the installation, a profile's configuration or its saved credentials. Each call asks the privileged helper that starts VPNs which ones are running before it answers. The helper object says whether that helper is installed and current. PassTunnel does not retry a failure of kind auth_rejected, host_scan_required or sso_required, or a host_not_found with credentials_sent true (a name the sign-in was sent on to could not be found; a code sent with it is used up): tell the user instead of connecting again. connect_refusal means this system cannot connect the profile at all. A connected profile can have notices to pass on to the user (Palo Alto GlobalProtect: hip_report_not_sent; Cisco AnyConnect, Palo Alto GlobalProtect with skip_portal, and OpenVPN with one named server and an explicit server identity: connected_through_last_known_address, the server's name could not be resolved and its last known address was used). A failure with last_known_address means the server's name failed and its last known address failed too: both the DNS and that address are involved.",
            input: Schema.object(["profile_id": Schema.profileID(optional: true)]), output: Schema.statusReport, readOnly: true),
        Tool(
            name: "get_logs", title: "Read VPN log",
            description:
                "Returns the last lines of one profile's VPN log, to explain why a connection failed or dropped. source \"raw\" (the default) is the OpenVPN, openfortivpn or openconnect output of the current or last session. source \"activity\" is what PassTunnel did and saw over that profile's recent sessions, also those the app or a terminal started (connecting, waiting for a fresh code, credentials sent, sign-in accepted or rejected, connected, drops, reconnects, stopped by the user), as sentences in lines and as typed events. Call get_status first: its failure may already say why. Use diagnose instead for problems outside one connection, such as the installation, the configuration or missing credentials. It returns at most the requested number of lines (or events), newest last; truncated is true when the log holds more. A profile that has no log yet returns no lines. Anything that looks like a credential is replaced by <redacted>; passwords and one-time codes are never included.",
            input: Schema.object(
                [
                    "profile_id": Schema.profileID(optional: false),
                    "lines": Schema.integer(
                        1, AutomationService.maxLogLines, default: defaultLogLines,
                        "Number of lines (or activity events) from the end of the log."),
                    "source": Schema.choice(
                        Schema.logSources, default: "raw",
                        "raw: the VPN tool's output; activity: PassTunnel's own record of the connection.")
                ],
                required: ["profile_id"]),
            output: Schema.logReport, readOnly: true),
        Tool(
            name: "diagnose", title: "Diagnose PassTunnel",
            description:
                "Checks the PassTunnel installation and every profile without connecting: app version and location, helper installed/enabled/outdated, whether \(MCPWording.theMachine) is online and over what kind of network (from the system's own view, nothing is contacted), and per profile whether the configuration, server and saved credentials are in place (never their values) and the last clock measurement (a FortiGate gateway's time, taken after it rejected a sign-in)\(MCPWording.diagnoseTools). Start here when something does not work; use get_status for whether a profile is connected now and why its last connect failed, and get_logs for the VPN tool's output. A clock off by \(ClockOffset.warnSeconds) s or more can make one-time codes fail.",
            input: Schema.object([
                "check_clock": Schema.boolean(
                    default: false,
                    "Also ask \(MCPWording.timeServer) how far \(MCPWording.thisMachines) clock is off. This contacts that server, so set it only when the user asked to check the clock."
                )
            ]),
            output: Schema.diagnose, readOnly: true)
    ]

    static let connectTools: [Tool] = [
        Tool(
            name: "connect", title: "Connect a VPN profile",
            description:
                "Connects one VPN profile and, by default, waits until it is connected or has failed. Connecting changes \(MCPWording.theMachines) network routes; only connect when the user asked for it. If the profile is already connected, its state is returned; with wait, an attempt already under way is followed. \(MCPWording.connectProtected) \(MCPWording.anyConnectPlatform) Starting a connection for a profile that asks for a user name, password or code on every connect fails with input_required: the user connects it in PassTunnel or in a terminal. With wait, the call fails with timeout when timeout_seconds runs out, and it tries to stop a connect it started. The error of a failed attempt includes a failure object when PassTunnel could tell why; get_logs shows the VPN tool's output. A rejected sign-in is never retried, so do not retry it either. The result's warnings list connected or connecting profiles whose tunnels claim some of the same networks or DNS names (kind overlap): that traffic goes through only one of the two tunnels. The connection goes ahead; tell the user. The result's notices (Palo Alto GlobalProtect: hip_report_not_sent; connected_through_last_known_address) are also for the user.",
            input: Schema.object(
                [
                    "profile_id": Schema.profileID(optional: false),
                    "wait": Schema.boolean(default: true, "Wait until connected or failed; false returns at once with state connecting."),
                    "timeout_seconds": Schema.integer(
                        1, maxTimeout, default: defaultTimeout,
                        MCPWording.timeout)
                ],
                required: ["profile_id"]),
            output: Schema.profileStatus, readOnly: false),
        Tool(
            name: "disconnect", title: "Disconnect a VPN profile",
            description:
                "Disconnects one VPN profile: it asks the privileged helper to stop the profile's VPN process and cancels a connect this server has under way. Only disconnect when the user asked for it. It also marks the profile as stopped by the user, so the app makes no further tries to reach a server of that profile that did not answer. With wait, it then waits up to timeout_seconds for the profile to show as stopped and fails with timeout if it does not. Returns the profile's state.",
            input: Schema.object(
                [
                    "profile_id": Schema.profileID(optional: false),
                    "wait": Schema.boolean(default: true, "Wait until the VPN process has stopped."),
                    "timeout_seconds": Schema.integer(
                        1, maxTimeout, default: defaultTimeout,
                        "How long to wait for it to stop.")
                ],
                required: ["profile_id"]),
            output: Schema.profileStatus, readOnly: false, destructive: true)
    ]

    // MARK: calls

    struct Outcome {
        var object: Any?
        var text: String
        var isError: Bool

        func result(structured: Bool) -> [String: Any] {
            var r: [String: Any] = ["content": [["type": "text", "text": text]], "isError": isError]
            if structured, let object { r["structuredContent"] = object }
            return r
        }
    }

    func call(_ name: String, _ arguments: [String: JSONValue]) async -> Outcome {
        do {
            let value = try await run(name, Arguments(arguments, tool: name))
            let object = try AutomationJSON.object(value)
            let text = String(decoding: try AutomationJSON.encoder().encode(value), as: UTF8.self)
            return Outcome(object: object, text: text, isError: false)
        } catch {
            let envelope = ErrorEnvelope(error)
            log("\(name): \(envelope.error.code)")
            let text =
                (try? AutomationJSON.encoder().encode(envelope)).map { String(decoding: $0, as: UTF8.self) }
                ?? envelope.error.message
            return Outcome(object: nil, text: text, isError: true)
        }
    }

    private func run(_ name: String, _ args: Arguments) async throws -> any Encodable {
        switch name {
        case "list_profiles":
            try args.finish()
            return ProfileList(profiles: await service.summaries(withState: true))
        case "get_status":
            let id = try args.profileID(required: false)
            try args.finish()
            return try await service.statusReport(id: id)
        case "get_logs":
            let id = try args.profileID(required: true)!
            let lines = try args.integer("lines", 1...AutomationService.maxLogLines) ?? Self.defaultLogLines
            let source = try args.choice("source", Schema.logSources) ?? "raw"
            try args.finish()
            return source == "activity" ? try service.activity(id, lines: lines) : try service.logs(id, lines: lines)
        case "diagnose":
            let checkClock = try args.boolean("check_clock") ?? false
            try args.finish()
            return await service.diagnose(checkClock: checkClock)
        case "connect" where allowConnect:
            let id = try args.profileID(required: true)!
            let wait = try args.boolean("wait") ?? true
            let timeout = try args.integer("timeout_seconds", 1...Self.maxTimeout) ?? Self.defaultTimeout
            try args.finish()
            return try await connect(id, wait: wait, timeout: TimeInterval(timeout))
        case "disconnect" where allowConnect:
            let id = try args.profileID(required: true)!
            let wait = try args.boolean("wait") ?? true
            let timeout = try args.integer("timeout_seconds", 1...Self.maxTimeout) ?? Self.defaultTimeout
            try args.finish()
            let p = try store.get(id)
            log("disconnect \(id)")
            try await service.disconnect(id, wait: wait, timeout: TimeInterval(timeout))
            return service.status(p)
        default:
            throw AutomationError(.invalidArgument, "Unknown tool: \(name)")
        }
    }

    /// Like `passtunnel connect`: the other-VPN check, then the confirmation (Touch ID on the Mac for a
    /// protected profile), then the connect. Already connected: returns the state. Already connecting
    /// (the app, the CLI): waits for that attempt; when it ends before it can be followed, this
    /// connects like any other call (with its checks).
    private func connect(_ id: String, wait: Bool, timeout: TimeInterval) async throws -> ProfileStatus {
        let p = try store.get(id)
        try ConnectionManager.checkConnectable(p, macOS: manager.systemVersion)
        await manager.refresh()
        if manager.state(id).isConnected { return service.status(p) }
        if manager.state(id).isConnecting {
            guard wait else { return service.status(p) }
            do {
                try await service.connect(id, timeout: timeout, joining: true)
                return service.status(p)
            } catch is ConnectionManager.NothingToFollow {
                log("connect \(id): the attempt under way ended; starting one")
            }
        }
        guard p.needs.isEmpty else {
            let list = p.needs.map(\.displayName).joined(separator: ", ")
            throw AutomationError(.inputRequired, String(localized: "This profile asks for: \(list). Connect it in PassTunnel or in a terminal."))
        }
        let overlaps = try await manager.checkCanStart(id)
        log("connect \(id)")
        if !overlaps.isEmpty { log("connect \(id): overlaps with \(overlaps.map(\.profileID).joined(separator: ", "))") }
        try await manager.vault.unlock(p, for: .connect)
        if wait {
            try await service.connect(id, timeout: timeout, joining: false)
        } else {
            let service = self.service
            var finished = false
            background.append(
                Task { @MainActor in
                    do { try await service.connect(id, timeout: timeout, joining: false) } catch {}
                    finished = true
                })
            // Until the attempt shows (connecting), so the state returned is not the one before it.
            let deadline = Date().addingTimeInterval(2)
            while !finished && !manager.state(id).isActive && Date() < deadline {
                try? await Task.sleep(nanoseconds: 10_000_000)
            }
        }
        return service.status(p, overlaps: overlaps)
    }

    func drain() async {
        while !background.isEmpty {
            await background.removeFirst().value
        }
    }

    // MARK: argument checks

    /// The arguments of one call; every key must be read, so unknown ones are refused. A `null` value
    /// counts as left out (some clients send every optional argument). Booleans and integers must be
    /// JSON booleans and numbers (`JSONValue` keeps them apart): `1` is not true, `true` is not 1.
    final class Arguments {
        private var values: [String: JSONValue]
        let tool: String

        init(_ values: [String: JSONValue], tool: String) {
            self.values = values.filter { $0.value != .null }
            self.tool = tool
        }

        func profileID(required: Bool) throws -> String? {
            guard let raw = values.removeValue(forKey: "profile_id") else {
                if required { throw AutomationError(.invalidArgument, "Missing argument profile_id.") }
                return nil
            }
            guard let id = raw.stringValue, Slug.isValid(id) else {
                throw AutomationError(.invalidArgument, "profile_id must be a profile id from list_profiles (lowercase letters, digits and dashes).")
            }
            return id
        }

        func boolean(_ key: String) throws -> Bool? {
            guard let raw = values.removeValue(forKey: key) else { return nil }
            guard case .bool(let value) = raw else {
                throw AutomationError(.invalidArgument, "\(key) must be true or false.")
            }
            return value
        }

        /// A whole number in `range` (`5.0` too); a fraction or anything outside is refused.
        func integer(_ key: String, _ range: ClosedRange<Int>) throws -> Int? {
            guard let raw = values.removeValue(forKey: key) else { return nil }
            guard case .integer(let value) = raw, value >= range.lowerBound, value <= range.upperBound else {
                throw AutomationError(.invalidArgument, "\(key) must be an integer from \(range.lowerBound) to \(range.upperBound).")
            }
            return Int(value)
        }

        /// One of `allowed`, as a JSON string.
        func choice(_ key: String, _ allowed: [String]) throws -> String? {
            guard let raw = values.removeValue(forKey: key) else { return nil }
            guard let value = raw.stringValue, allowed.contains(value) else {
                throw AutomationError(.invalidArgument, "\(key) must be one of: \(allowed.joined(separator: ", ")).")
            }
            return value
        }

        func finish() throws {
            if let key = values.keys.sorted().first {
                throw AutomationError(.invalidArgument, "Unknown argument \(key) for \(tool).")
            }
        }
    }
}

/// JSON Schemas (2020-12) of the tools' arguments and results.
enum Schema {
    static func object(_ properties: [String: Any], required: [String] = [], closed: Bool = true) -> [String: Any] {
        var s: [String: Any] = ["type": "object", "properties": properties]
        if !required.isEmpty { s["required"] = required }
        if closed { s["additionalProperties"] = false }
        return s
    }

    /// Result objects stay open: later versions may add fields.
    static func result(_ properties: [String: Any], required: [String]) -> [String: Any] {
        object(properties, required: required, closed: false)
    }

    static func array(_ items: [String: Any]) -> [String: Any] { ["type": "array", "items": items] }
    /// `schema` with a `description`, for result fields whose meaning the name and type do not carry.
    static func described(_ schema: [String: Any], _ text: String) -> [String: Any] {
        var s = schema
        s["description"] = text
        return s
    }
    static let string: [String: Any] = ["type": "string"]
    static let bool: [String: Any] = ["type": "boolean"]
    static let int: [String: Any] = ["type": "integer"]
    static func oneOf(_ values: [String]) -> [String: Any] { ["type": "string", "enum": values] }

    static func profileID(optional: Bool) -> [String: Any] {
        [
            "type": "string", "pattern": "^[a-z0-9]+(-[a-z0-9]+)*$", "maxLength": 64,
            "description": optional ? "A profile id from list_profiles; omit for all profiles." : "A profile id from list_profiles."
        ]
    }

    static func boolean(default value: Bool, _ description: String) -> [String: Any] {
        ["type": "boolean", "default": value, "description": description]
    }

    static func integer(_ min: Int, _ max: Int, default value: Int, _ description: String) -> [String: Any] {
        ["type": "integer", "minimum": min, "maximum": max, "default": value, "description": description]
    }

    static func choice(_ values: [String], default value: String, _ description: String) -> [String: Any] {
        ["type": "string", "enum": values, "default": value, "description": description]
    }

    static let vpnType = oneOf(VPNType.allCases.map(\.rawValue))
    static let state = oneOf(["disconnected", "connecting", "connected"])

    static let profileSummary = result(
        [
            "id": string, "name": string, "type": vpnType, "is_default": bool, "pinned": bool, "username": string,
            "password_mode": oneOf(PasswordMode.allCases.map(\.rawValue)), "otp_mode": oneOf(OTPMode.allCases.map(\.rawValue)),
            "require_auth": oneOf(AuthRequirement.allCases.map(\.rawValue)), "protected": bool, "auto_reconnect": bool,
            "connect_at_login": bool, "state": state, "needs_newer_version": bool, "connect_refusal": connectRefusal,
            "experimental": experimental
        ],
        required: [
            "id", "name", "type", "is_default", "pinned", "username", "password_mode", "otp_mode", "require_auth",
            "protected", "auto_reconnect", "connect_at_login"
        ])

    /// `ClockOffset`: how far the clock is off; positive when it is behind.
    static let clock = result(
        [
            "offset_seconds": int, "source": oneOf(ClockOffset.Source.allCases.map(\.rawValue)), "server": string,
            "checked_at": ["type": "string", "format": "date-time"]
        ], required: ["offset_seconds", "source", "checked_at"])

    /// `ConnectionFailure`: why the last connect failed.
    static let failure = described(
        result(
            [
                "kind": described(
                    oneOf(ConnectionFailure.Kind.allCases.map(\.rawValue)),
                    "auth_rejected: the server refused the sign-in (never retried). host_not_found: the server's name could not be resolved (with last_known_address when its last known address was tried as well and failed too; with credentials_sent when a name the sign-in was sent on to, such as a gateway's, could not be found: not retried). unreachable: the server could not be reached (connection refused or timed out, no route, no TLS answer in time); the sign-in was not sent. configuration: the configuration, a key or the server's certificate was refused, or something the profile needs is missing. setup: setting up the tunnel's network, such as its routes or DNS, failed. timeout: the tunnel did not come up in time. cancelled: stopped before it finished. tool_unsupported: the VPN tool does not run on this macOS version. host_scan_required: a Cisco AnyConnect server requires a host scan, which PassTunnel never runs. sso_required: a Palo Alto GlobalProtect portal or gateway signs in with single sign-on, which PassTunnel does not support. failed: anything else."
                ),
                "at": ["type": "string", "format": "date-time"],
                "reply": described(string, "The server's reply, with credentials redacted."),
                "reason": described(string, "Why, in the VPN tool's or PassTunnel's words, with credentials redacted."),
                "credentials_sent": described(bool, "Whether PassTunnel judges that the sign-in reached the server."),
                "code_sent": described(bool, "Whether a one-time code went with a sign-in judged as sent; that code is then used up."),
                "code_seconds_left": int, "tries": int,
                "clock": described(clock, "After a rejected sign-in: how far \(MCPWording.thisMachines) clock was off, when known."),
                "server_cert": described(
                    string,
                    "For a configuration failure over a certificate that was not trusted: the pin-sha256 of the server's key, when it could be read."
                ),
                "gateways": described(
                    array(string),
                    "For a Palo Alto GlobalProtect configuration failure: the portal's gateways, when the profile's gateway does not pick exactly one of them and their names could be read."
                ),
                "last_known_address": described(
                    result(
                        [
                            "address": string, "confirmed_at": dateTime,
                            "outcome": oneOf(["unreachable", "certificate_refused", "name_not_found"]), "reason": string
                        ], required: ["address", "confirmed_at", "outcome", "reason"]),
                    "For host_not_found: the server's name could not be resolved, so the address that name had at the last connection by it (confirmed_at) was tried too, with nothing sent there, and failed: it could not be reached (unreachable), a server there failed the certificate check (certificate_refused; the address was then forgotten), or a server name was still needed there and not found (name_not_found). Both the DNS and that address are involved; the sign-in was not sent."
                ),
                "dns_left_behind": described(
                    dnsLeftBehind,
                    "For host_not_found: the network service in use, whose DNS still points to a VPN's DNS servers, which only that VPN can reach, so no name resolves (macOS only); the likely reason, also when last_known_address says what was tried instead. Tell the user: a restart sets it back."
                )
            ], required: ["kind", "at", "credentials_sent", "code_sent"]),
        "Why the last connect failed.")

    /// `ConnectWarning`: another connected tunnel takes over some of the same networks or DNS names.
    static let warning = result(
        [
            "kind": oneOf(["overlap"]), "with": string, "name": string, "routes": array(string), "domains": array(string),
            "all_traffic": array(string)
        ], required: ["kind", "with", "name", "routes", "domains"])

    /// `NoticeReport`: something to tell the user about a connection that is up.
    static let notice = result(
        [
            "kind": described(
                oneOf(StatusNotice.allCases.map(\.rawValue)),
                "hip_report_not_sent: the Palo Alto GlobalProtect gateway asked for a host information report, which PassTunnel does not send, so access may be limited. connected_through_last_known_address: (Cisco AnyConnect, Palo Alto GlobalProtect with skip_portal, and OpenVPN with one named server and an explicit server identity) the server's name could not be resolved when connecting, so the address it had at its last successful connection was used; the network's DNS may not be working."
            ), "message": described(string, "The sentence to show the user.")
        ], required: ["kind", "message"])

    /// `connect_refusal`, the same in every result that has it.
    static let connectRefusal = described(
        errorReport, "Present when this system cannot connect the profile at all: the code and message connect would fail with.")
    static let experimental = described(bool, "true for a profile of an experimental type (Palo Alto GlobalProtect).")

    static let profileStatus = result(
        [
            "id": string, "name": string, "type": vpnType, "state": state, "phase": string,
            "ip": described(string, "The tunnel address, while connected."),
            "since": described(dateTime, "When the connection started, as far as PassTunnel can tell."), "duration_seconds": int, "is_default": bool,
            "protected": bool, "auto_reconnect": bool, "health": oneOf(["reachable", "unreachable"]),
            "error": described(string, "Why the last attempt seen by this process failed, in words."), "failure": failure,
            "warning": string,
            "status_unavailable": described(bool, "Connected, but the VPN's management interface did not answer: ip and since may be stale."),
            "warnings": described(
                array(warning),
                "Only in the result of connect: connected or connecting profiles whose tunnels claim some of the same networks or DNS names."),
            "next_try_at": described(dateTime, "While the app tries again to reach a server that did not answer: when the next try is scheduled."),
            "tries": described(int, "While the app tries again to reach a server that did not answer: how many tries found it unreachable."),
            "connect_refusal": connectRefusal, "experimental": experimental,
            "notices": described(array(notice), "While connected: what the user should know about the connection.")
        ], required: ["id", "name", "type", "state", "is_default", "protected", "auto_reconnect"])

    static let helper = result(
        [
            "state": oneOf(["enabled", "requires_approval", "not_installed", "missing_from_bundle"]), "responding": bool,
            "protocol_version": int, "expected_protocol_version": int, "outdated": bool, "error": string,
            "raw_status": int
        ], required: ["state", "responding", "expected_protocol_version"])

    static let statusReport = result(["helper": helper, "profiles": array(profileStatus)], required: ["helper", "profiles"])

    static let dateTime: [String: Any] = ["type": "string", "format": "date-time"]
    /// `get_logs` sources: the VPN tool's output, PassTunnel's activity log.
    static let logSources = ["raw", "activity"]

    /// One `ActivityEvent` (never with code digits); which fields it has depends on `event`.
    static let activityEvent = result(
        [
            "at": dateTime, "event": oneOf(ActivityEvent.names), "host": string, "port": int, "protocol": string,
            "reason": string, "seconds": int, "username": string, "password": bool, "code": bool,
            "seconds_left": int, "format": string, "address": string, "will_reconnect": bool, "attempt": int, "of": int,
            "tries": int, "next_at": dateTime, "reply": string, "failure": oneOf(ConnectionFailure.Kind.allCases.map(\.rawValue)),
            "credentials_sent": bool, "server_address": string, "via_server_address": string, "confirmed_at": dateTime,
            "outcome": oneOf(["unreachable", "certificate_refused", "name_not_found"]), "service": string, "settings": array(string)
        ], required: ["at", "event"])

    static let logReport = result(
        [
            "id": string, "lines": array(string),
            "truncated": described(bool, "The log holds more than was returned."),
            "source": oneOf(logSources), "events": array(activityEvent)
        ],
        required: ["id", "lines", "truncated"])

    static let errorReport = result(["code": string, "message": string], required: ["code", "message"])

    static let profileCheck = result(
        [
            "id": string, "name": string, "type": vpnType, "ok": bool, "server": string, "protected": bool,
            "password_saved": bool, "totp_saved": bool, "asks_for": array(oneOf(["username", "password", "otp"])),
            "problems": array(errorReport), "clock": clock, "experimental": experimental,
            "last_known_address": described(
                result(["host": string, "address": string, "confirmed_at": dateTime], required: ["host", "address", "confirmed_at"]),
                "Cisco AnyConnect, Palo Alto GlobalProtect with skip_portal, and OpenVPN with one named server and an explicit server identity: the address the server's name had at the last connection by that name (confirmed_at), kept for when the name cannot be resolved. Read from this computer only; nothing is contacted."
            )
        ], required: ["id", "name", "type", "ok", "server", "protected", "asks_for", "problems"])

    static let secretStore = result(
        [
            "name": string, "available": bool, "setting": oneOf(SecretStoreChoice.allCases.map(\.rawValue)),
            "chosen_by": oneOf(["environment", "setting", "recorded", "auto"]), "error": string,
            "skipped": array(result(["name": string, "error": string], required: ["name", "error"]))
        ], required: ["name", "available", "setting", "chosen_by"])

    /// `NetworkStatus`: online or not, and over what kind of interface (both absent when unknown).
    static let network = result(
        ["online": bool, "interface": oneOf(NetworkStatus.Interface.allCases.map(\.rawValue))],
        required: [])

    /// `DNSLeftBehind`: a network service and the VPN's DNS servers still set on it.
    static let dnsLeftBehind = result(
        [
            "service": string,
            "servers": described(array(string), "Empty when the VPN sent no server its DNS script could use; it then still left its settings."),
            "search_domains": array(string),
            "in_effect": described(
                bool,
                "The Mac uses it now (the primary service, or the default resolver has those servers); otherwise only once that service is used again."
            )
        ], required: ["service", "servers", "in_effect"])

    /// `ToolCheck`: one VPN tool of the app run with `--version`.
    static let toolCheck = result(
        ["name": string, "ok": bool, "version": string, "problem": string, "note": string], required: ["name", "ok"])

    static let diagnose: [String: Any] = {
        var properties: [String: Any] = [
            "version": string, "build": string, "app_path": string, "in_applications": bool, "helper": helper,
            "profiles": array(profileCheck), "clock": clock, "clock_error": string, "network": network,
            "macos_version": string
        ]
        #if os(Linux)
        properties["secret_store"] = secretStore
        #else
        properties["tools"] = array(toolCheck)
        properties["dns_left_behind"] = described(
            array(dnsLeftBehind),
            "Network services whose DNS still points to a VPN's DNS servers that OpenVPN's DNS script set, with no VPN session running to undo it. While one is in use (in_effect), no name resolves (host_not_found). PassTunnel leaves them as they are, as nothing shows it set them; restarting the Mac sets them back."
        )
        #endif
        return result(properties, required: ["version", "app_path", "in_applications", "helper", "profiles"])
    }()
}
