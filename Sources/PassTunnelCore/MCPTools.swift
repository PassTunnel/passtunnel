import Foundation
import PassTunnelKit

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
        Tool(name: "list_profiles", title: "List VPN profiles",
             description: "Lists the VPN profiles configured in PassTunnel with their current state. Use the returned id as profile_id in the other tools. protected=true means connecting asks the user for Touch ID on the Mac.",
             input: Schema.object([:]), output: Schema.object(["profiles": Schema.array(Schema.profileSummary)], required: ["profiles"]),
             readOnly: true),
        Tool(name: "get_status", title: "Get connection status",
             description: "Returns the connection state of every profile (or only profile_id): disconnected, connecting or connected, the tunnel IP, since when, the last error, and whether the privileged helper that starts VPNs is installed and current.",
             input: Schema.object(["profile_id": Schema.profileID(optional: true)]), output: Schema.statusReport, readOnly: true),
        Tool(name: "get_logs", title: "Read VPN log",
             description: "Returns the last lines of a profile's VPN log (OpenVPN or openfortivpn output of the current or last session), for explaining why a connection failed. Anything that looks like a credential is replaced by <redacted>.",
             input: Schema.object(["profile_id": Schema.profileID(optional: false),
                                   "lines": Schema.integer(1, AutomationService.maxLogLines, default: defaultLogLines,
                                                           "Number of lines from the end of the log.")],
                                  required: ["profile_id"]),
             output: Schema.logReport, readOnly: true),
        Tool(name: "diagnose", title: "Diagnose PassTunnel",
             description: "Checks the PassTunnel installation and every profile without connecting: app version and location, helper installed/enabled/outdated, and per profile whether the configuration, server and saved credentials are in place (never their values). Start here when something does not work.",
             input: Schema.object([:]), output: Schema.diagnose, readOnly: true),
    ]

    static let connectTools: [Tool] = [
        Tool(name: "connect", title: "Connect a VPN profile",
             description: "Connects a VPN profile and, by default, waits until it is connected or has failed. If the profile is protected, the user must confirm with Touch ID on the Mac: tell them a prompt is waiting. Profiles that ask for a user name, password or code on every connect cannot be connected this way. Connecting changes the Mac's network routes; only connect when the user asked for it.",
             input: Schema.object(["profile_id": Schema.profileID(optional: false),
                                   "wait": Schema.boolean(default: true, "Wait until connected or failed; false returns at once with state connecting."),
                                   "timeout_seconds": Schema.integer(1, maxTimeout, default: defaultTimeout,
                                                                     "How long to wait for the connection (after the Touch ID confirmation).")],
                                  required: ["profile_id"]),
             output: Schema.profileStatus, readOnly: false),
        Tool(name: "disconnect", title: "Disconnect a VPN profile",
             description: "Disconnects a VPN profile (also stops a connect in progress). Returns the final state; disconnecting a profile that is not connected does nothing.",
             input: Schema.object(["profile_id": Schema.profileID(optional: false),
                                   "wait": Schema.boolean(default: true, "Wait until the VPN process has stopped."),
                                   "timeout_seconds": Schema.integer(1, maxTimeout, default: defaultTimeout,
                                                                     "How long to wait for it to stop.")],
                                  required: ["profile_id"]),
             output: Schema.profileStatus, readOnly: false, destructive: true),
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

    func call(_ name: String, _ arguments: [String: Any]) async -> Outcome {
        do {
            let value = try await run(name, Arguments(arguments, tool: name))
            let object = try AutomationJSON.object(value)
            let text = String(decoding: try AutomationJSON.encoder().encode(value), as: UTF8.self)
            return Outcome(object: object, text: text, isError: false)
        } catch {
            let envelope = ErrorEnvelope(error)
            log("\(name): \(envelope.error.code)")
            let text = (try? AutomationJSON.encoder().encode(envelope)).map { String(decoding: $0, as: UTF8.self) }
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
            try args.finish()
            return try service.logs(id, lines: lines)
        case "diagnose":
            try args.finish()
            return await service.diagnose()
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
        try await manager.checkCanStart(id)
        log("connect \(id)")
        try await manager.vault.unlock(p, for: .connect)
        if wait {
            try await service.connect(id, timeout: timeout, joining: false)
        } else {
            let service = self.service
            var finished = false
            background.append(Task { @MainActor in
                do { try await service.connect(id, timeout: timeout, joining: false) } catch {}
                finished = true
            })
            // Until the attempt shows (connecting), so the state returned is not the one before it.
            let deadline = Date().addingTimeInterval(2)
            while !finished && !manager.state(id).isActive && Date() < deadline {
                try? await Task.sleep(nanoseconds: 10_000_000)
            }
        }
        return service.status(p)
    }

    func drain() async {
        while !background.isEmpty {
            await background.removeFirst().value
        }
    }

    // MARK: argument checks

    /// The arguments of one call; every key must be read, so unknown ones are refused. A `null` value
    /// counts as left out (some clients send every optional argument).
    final class Arguments {
        private var values: [String: Any]
        let tool: String

        init(_ values: [String: Any], tool: String) {
            self.values = values.filter { !($0.value is NSNull) }
            self.tool = tool
        }

        func profileID(required: Bool) throws -> String? {
            guard let raw = values.removeValue(forKey: "profile_id") else {
                if required { throw AutomationError(.invalidArgument, "Missing argument profile_id.") }
                return nil
            }
            guard let id = raw as? String, Slug.isValid(id) else {
                throw AutomationError(.invalidArgument, "profile_id must be a profile id from list_profiles (lowercase letters, digits and dashes).")
            }
            return id
        }

        func boolean(_ key: String) throws -> Bool? {
            guard let raw = values.removeValue(forKey: key) else { return nil }
            guard let n = raw as? NSNumber, MCPTools.isBool(n) else {
                throw AutomationError(.invalidArgument, "\(key) must be true or false.")
            }
            return n.boolValue
        }

        func integer(_ key: String, _ range: ClosedRange<Int>) throws -> Int? {
            guard let raw = values.removeValue(forKey: key) else { return nil }
            guard let n = raw as? NSNumber, !MCPTools.isBool(n), n.doubleValue == n.doubleValue.rounded(),
                  n.doubleValue >= Double(range.lowerBound), n.doubleValue <= Double(range.upperBound) else {
                throw AutomationError(.invalidArgument, "\(key) must be an integer from \(range.lowerBound) to \(range.upperBound).")
            }
            return n.intValue
        }

        func finish() throws {
            if let key = values.keys.sorted().first {
                throw AutomationError(.invalidArgument, "Unknown argument \(key) for \(tool).")
            }
        }
    }

    /// JSONSerialization gives booleans as NSNumber too; only a CFBoolean is a JSON true/false.
    nonisolated static func isBool(_ n: NSNumber) -> Bool {
        CFGetTypeID(n) == CFBooleanGetTypeID()
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
        ["type": "string", "pattern": "^[a-z0-9]+(-[a-z0-9]+)*$", "maxLength": 64,
         "description": optional ? "A profile id from list_profiles; omit for all profiles." : "A profile id from list_profiles."]
    }

    static func boolean(default value: Bool, _ description: String) -> [String: Any] {
        ["type": "boolean", "default": value, "description": description]
    }

    static func integer(_ min: Int, _ max: Int, default value: Int, _ description: String) -> [String: Any] {
        ["type": "integer", "minimum": min, "maximum": max, "default": value, "description": description]
    }

    static let vpnType = oneOf(VPNType.allCases.map(\.rawValue))
    static let state = oneOf(["disconnected", "connecting", "connected"])

    static let profileSummary = result([
        "id": string, "name": string, "type": vpnType, "is_default": bool, "pinned": bool, "username": string,
        "password_mode": oneOf(PasswordMode.allCases.map(\.rawValue)), "otp_mode": oneOf(OTPMode.allCases.map(\.rawValue)),
        "require_auth": oneOf(AuthRequirement.allCases.map(\.rawValue)), "protected": bool, "auto_reconnect": bool,
        "state": state,
    ], required: ["id", "name", "type", "is_default", "pinned", "username", "password_mode", "otp_mode", "require_auth",
                  "protected", "auto_reconnect"])

    static let profileStatus = result([
        "id": string, "name": string, "type": vpnType, "state": state, "phase": string, "ip": string,
        "since": ["type": "string", "format": "date-time"], "duration_seconds": int, "is_default": bool, "protected": bool,
        "auto_reconnect": bool, "health": oneOf(["reachable", "unreachable"]), "error": string, "warning": string,
        "status_unavailable": bool,
    ], required: ["id", "name", "type", "state", "is_default", "protected", "auto_reconnect"])

    static let helper = result([
        "state": oneOf(["enabled", "requires_approval", "not_installed", "missing_from_bundle"]), "responding": bool,
        "protocol_version": int, "expected_protocol_version": int, "outdated": bool, "error": string,
    ], required: ["state", "responding", "expected_protocol_version"])

    static let statusReport = result(["helper": helper, "profiles": array(profileStatus)], required: ["helper", "profiles"])

    static let logReport = result(["id": string, "lines": array(string), "truncated": bool], required: ["id", "lines", "truncated"])

    static let errorReport = result(["code": string, "message": string], required: ["code", "message"])

    static let profileCheck = result([
        "id": string, "name": string, "type": vpnType, "ok": bool, "server": string, "protected": bool,
        "password_saved": bool, "totp_saved": bool, "asks_for": array(oneOf(["username", "password", "otp"])),
        "problems": array(errorReport),
    ], required: ["id", "name", "type", "ok", "server", "protected", "asks_for", "problems"])

    static let diagnose = result([
        "version": string, "build": string, "app_path": string, "in_applications": bool, "helper": helper,
        "profiles": array(profileCheck),
    ], required: ["version", "app_path", "in_applications", "helper", "profiles"])
}
