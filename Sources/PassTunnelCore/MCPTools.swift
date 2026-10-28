import Foundation
import PassTunnelKit

/// The words of the MCP texts that differ between the Mac and Linux (docs/LINUX.md, Commands that
/// differ): the machine, and what a protected profile needs. Linux cannot ask for a confirmation yet,
/// so it refuses protected profiles with `auth_unavailable`. The Mac's texts stay exactly as they are
/// listed in MCP directories.
enum MCPWording {
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
        "; also whether each VPN tool bundled with the app starts on this macOS version (run with --version; nothing is contacted)"
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
                "Lists the VPN profiles configured in PassTunnel with their current state. Use the returned id as profile_id in the other tools. \(MCPWording.listProtected)",
            input: Schema.object([:]), output: Schema.object(["profiles": Schema.array(Schema.profileSummary)], required: ["profiles"]),
            readOnly: true),
        Tool(
            name: "get_status", title: "Get connection status",
            description:
                "Returns the connection state of every profile (or only profile_id): disconnected, connecting or connected, the tunnel IP, since when, the last error and why it happened (failure: auth_rejected, host_not_found, unreachable, configuration, setup, timeout, cancelled, tool_unsupported (the VPN tool does not run on this macOS version) or failed; the server's reply; whether the sign-in and a one-time code were sent; for a rejected sign-in, clock: how far \(MCPWording.thisMachines) clock was off, when known), when the app tries a server that did not answer again (next_try_at, tries), and whether the privileged helper that starts VPNs is installed and current.",
            input: Schema.object(["profile_id": Schema.profileID(optional: true)]), output: Schema.statusReport, readOnly: true),
        Tool(
            name: "get_logs", title: "Read VPN log",
            description:
                "Returns the last lines of a profile's VPN log, for explaining why a connection failed. source \"raw\" (the default): the OpenVPN or openfortivpn output of the current or last session. source \"activity\": what PassTunnel did and saw, also for sessions the app or a terminal started (connecting, waiting for a fresh code, credentials sent, sign-in accepted or rejected, connected, drops, reconnects, stopped by the user), as sentences in lines and as typed events. Anything that looks like a credential is replaced by <redacted>; passwords and one-time codes are never included.",
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
                "Checks the PassTunnel installation and every profile without connecting: app version and location, helper installed/enabled/outdated, whether \(MCPWording.theMachine) is online and over what kind of network (from the system's own view, nothing is contacted), and per profile whether the configuration, server and saved credentials are in place (never their values) and the last clock measurement (a FortiGate gateway's time, taken after it rejected a sign-in)\(MCPWording.diagnoseTools). Start here when something does not work. A clock off by \(ClockOffset.warnSeconds) s or more makes one-time codes fail.",
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
                "Connects a VPN profile and, by default, waits until it is connected or has failed. \(MCPWording.connectProtected) Profiles that ask for a user name, password or code on every connect cannot be connected this way. A failure carries a failure object (why, the server's reply, whether the sign-in was sent); a rejected sign-in is never retried, so do not retry it either. The result's warnings list connected profiles whose tunnels claim some of the same networks or DNS names (kind overlap): that traffic goes through only one of the two tunnels. The connection goes ahead; tell the user. Connecting changes \(MCPWording.theMachines) network routes; only connect when the user asked for it.",
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
                "Disconnects a VPN profile (also stops a connect in progress). Returns the final state; disconnecting a profile that is not connected does nothing.",
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
            "connect_at_login": bool, "state": state
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
    static let failure = result(
        [
            "kind": oneOf(ConnectionFailure.Kind.allCases.map(\.rawValue)), "at": ["type": "string", "format": "date-time"],
            "reply": string, "reason": string, "credentials_sent": bool, "code_sent": bool, "code_seconds_left": int,
            "tries": int, "clock": clock
        ], required: ["kind", "at", "credentials_sent", "code_sent"])

    /// `ConnectWarning`: another connected tunnel takes over some of the same networks or DNS names.
    static let warning = result(
        [
            "kind": oneOf(["overlap"]), "with": string, "name": string, "routes": array(string), "domains": array(string),
            "all_traffic": array(string)
        ], required: ["kind", "with", "name", "routes", "domains"])

    static let profileStatus = result(
        [
            "id": string, "name": string, "type": vpnType, "state": state, "phase": string, "ip": string,
            "since": ["type": "string", "format": "date-time"], "duration_seconds": int, "is_default": bool, "protected": bool,
            "auto_reconnect": bool, "health": oneOf(["reachable", "unreachable"]), "error": string, "failure": failure,
            "warning": string, "status_unavailable": bool, "warnings": array(warning), "next_try_at": dateTime, "tries": int
        ], required: ["id", "name", "type", "state", "is_default", "protected", "auto_reconnect"])

    static let helper = result(
        [
            "state": oneOf(["enabled", "requires_approval", "not_installed", "missing_from_bundle"]), "responding": bool,
            "protocol_version": int, "expected_protocol_version": int, "outdated": bool, "error": string
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
            "credentials_sent": bool
        ], required: ["at", "event"])

    static let logReport = result(
        [
            "id": string, "lines": array(string), "truncated": bool,
            "source": oneOf(logSources), "events": array(activityEvent)
        ],
        required: ["id", "lines", "truncated"])

    static let errorReport = result(["code": string, "message": string], required: ["code", "message"])

    static let profileCheck = result(
        [
            "id": string, "name": string, "type": vpnType, "ok": bool, "server": string, "protected": bool,
            "password_saved": bool, "totp_saved": bool, "asks_for": array(oneOf(["username", "password", "otp"])),
            "problems": array(errorReport), "clock": clock
        ], required: ["id", "name", "type", "ok", "server", "protected", "asks_for", "problems"])

    static let secretStore = result(
        [
            "name": string, "available": bool, "setting": oneOf(SecretStoreChoice.allCases.map(\.rawValue)),
            "chosen_by": oneOf(["environment", "setting", "recorded", "auto"]), "error": string
        ], required: ["name", "available", "setting", "chosen_by"])

    /// `NetworkStatus`: online or not, and over what kind of interface (both absent when unknown).
    static let network = result(
        ["online": bool, "interface": oneOf(NetworkStatus.Interface.allCases.map(\.rawValue))],
        required: [])

    /// `ToolCheck`: one VPN tool of the app run with `--version`.
    static let toolCheck = result(
        ["name": string, "ok": bool, "version": string, "problem": string, "note": string], required: ["name", "ok"])

    static let diagnose: [String: Any] = {
        var properties: [String: Any] = [
            "version": string, "build": string, "app_path": string, "in_applications": bool, "helper": helper,
            "profiles": array(profileCheck), "clock": clock, "clock_error": string, "network": network
        ]
        #if os(Linux)
        properties["secret_store"] = secretStore
        #else
        properties["tools"] = array(toolCheck)
        #endif
        return result(properties, required: ["version", "app_path", "in_applications", "helper", "profiles"])
    }()
}
