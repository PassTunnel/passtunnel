import Foundation

/// `passtunnel mcp`: a Model Context Protocol server on stdio (newline-delimited JSON-RPC 2.0) that
/// lets an AI assistant read PassTunnel's state and, with `--allow-connect`, connect and disconnect
/// profiles. Dual-era: requests that carry the per-request `_meta` of protocol 2026-07-28 are served
/// statelessly; a client that opens with `initialize` gets the handshake-based protocol it asked for
/// (2025-11-25 and earlier). Tools are in `MCPTools.swift`; their results are the automation objects
/// of `Automation.swift`, the same ones `--json` prints.
@MainActor
public final class MCPServer {
    /// Served with per-request `_meta` (no handshake).
    public static let modernVersions = ["2026-07-28"]
    /// Served after an `initialize` handshake; the first is the one offered when the client asks for
    /// a version not listed.
    public static let legacyVersions = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
    public static var supportedVersions: [String] { modernVersions + legacyVersions }

    static let versionKey = "io.modelcontextprotocol/protocolVersion"
    static let capabilitiesKey = "io.modelcontextprotocol/clientCapabilities"
    static let serverInfoKey = "io.modelcontextprotocol/serverInfo"

    enum ErrorCode {
        static let parse = -32700
        static let invalidRequest = -32600
        static let methodNotFound = -32601
        static let invalidParams = -32602
        static let internalError = -32603
        static let unsupportedVersion = -32022
    }

    let tools: MCPTools
    let serverVersion: String
    private let send: (Data) -> Void
    private let log: (String) -> Void
    /// Set by `initialize`: the handshake-based protocol version requests without `_meta` use.
    private(set) var sessionVersion: String?
    /// Requests running, by id; `serial` tells a request's own entry from a later one's.
    private var inFlight: [String: (serial: Int, task: Task<Void, Never>)] = [:]
    private var nextSerial = 0
    private var cancelled: Set<String> = []

    /// `send` gets each outgoing message (one JSON object, no line break); `log` diagnostics for stderr.
    public init(service: AutomationService, allowConnect: Bool, serverVersion: String = AppInfo.current.version,
                send: @escaping (Data) -> Void, log: @escaping (String) -> Void = { _ in }) {
        tools = MCPTools(service: service, allowConnect: allowConnect, log: log)
        self.serverVersion = serverVersion
        self.send = send
        self.log = log
    }

    // MARK: input

    /// Takes one line from the client. Requests run concurrently (a waiting `connect` does not hold
    /// up `get_status`); this returns at once.
    public func receive(_ line: Data) {
        guard let message = parse(line) else { return }
        switch message {
        case .reply(let data):
            send(data)
        case .notification(let method, let params):
            handleNotification(method, params)
        case let .request(id, method, params):
            let key = Self.key(id)
            // JSON-RPC ids must be unique among the requests in flight: a reuse would make replies
            // and cancels ambiguous.
            guard inFlight[key] == nil else {
                send(errorMessage(id: id, code: ErrorCode.invalidRequest, message: "Invalid Request: id is already in use by a request in progress"))
                return
            }
            nextSerial += 1
            let serial = nextSerial
            let task = Task { @MainActor [weak self] in
                guard let self else { return }
                let response = await self.respond(id: id, method: method, params: params)
                if self.cancelled.remove(key) == nil { self.send(response) }
                if self.inFlight[key]?.serial == serial { self.inFlight[key] = nil }
            }
            inFlight[key] = (serial, task)
        }
    }

    /// A line longer than `maxLineBytes` (dropped unread by the reader): a parse error, as JSON-RPC
    /// has no id to answer.
    public func receiveOversizedLine() {
        send(errorMessage(id: nil, code: ErrorCode.parse, message: "Parse error: message longer than \(Self.maxLineBytes) bytes"))
    }

    /// Longest input line read; anything longer is refused without keeping it in memory.
    public nonisolated static let maxLineBytes = 1 << 20

    /// Handles one line and waits for its response (tests).
    public func handle(_ line: Data) async {
        receive(line)
        await drain()
    }

    /// Waits for every request in flight and every connect started with `wait: false`. At the end of
    /// input the server finishes what it was asked (a client may write its requests and close stdin
    /// at once), then exits.
    public func drain() async {
        while let entry = inFlight.values.first {
            await entry.task.value
        }
        await tools.drain()
    }

    private enum Incoming {
        case reply(Data)
        case notification(String, [String: Any])
        case request(id: Any, method: String, params: [String: Any])
    }

    private func parse(_ line: Data) -> Incoming? {
        guard let json = try? JSONSerialization.jsonObject(with: line, options: [.fragmentsAllowed]) else {
            return .reply(errorMessage(id: nil, code: ErrorCode.parse, message: "Parse error"))
        }
        guard let object = json as? [String: Any] else {
            // Batches are not part of MCP (since 2025-06-18).
            return .reply(errorMessage(id: nil, code: ErrorCode.invalidRequest, message: "Invalid Request: expected one JSON-RPC object"))
        }
        let id = object["id"]
        let validID = id.map(Self.isValidID) ?? false
        guard object["jsonrpc"] as? String == "2.0" else {
            return .reply(errorMessage(id: validID ? id : nil, code: ErrorCode.invalidRequest, message: "Invalid Request: jsonrpc must be \"2.0\""))
        }
        guard let method = object["method"] as? String else {
            // A response from the client: this server sends no requests, so there is nothing to match.
            if object["result"] != nil || object["error"] != nil {
                log("ignoring a response from the client")
                return nil
            }
            return .reply(errorMessage(id: validID ? id : nil, code: ErrorCode.invalidRequest, message: "Invalid Request: missing method"))
        }
        let rawParams = object["params"]
        if rawParams != nil && !(rawParams is [String: Any]) {
            guard id != nil else { return nil }
            return .reply(errorMessage(id: validID ? id : nil, code: ErrorCode.invalidParams, message: "Invalid params: params must be an object"))
        }
        let params = rawParams as? [String: Any] ?? [:]
        guard let id else { return .notification(method, params) }
        guard validID else {
            return .reply(errorMessage(id: nil, code: ErrorCode.invalidRequest, message: "Invalid Request: id must be a string or an integer"))
        }
        return .request(id: id, method: method, params: params)
    }

    /// Strings and integers; never null, never a boolean or fraction.
    public nonisolated static func isValidID(_ id: Any) -> Bool {
        if id is String { return true }
        guard let n = id as? NSNumber, !MCPTools.isBool(n) else { return false }
        return n.doubleValue == n.doubleValue.rounded()
    }

    public nonisolated static func key(_ id: Any) -> String {
        if let s = id as? String { return "s:" + s }
        return "n:\((id as? NSNumber)?.int64Value ?? 0)"
    }

    private func handleNotification(_ method: String, _ params: [String: Any]) {
        switch method {
        case "notifications/initialized":
            break
        case "notifications/cancelled":
            guard let id = params["requestId"], Self.isValidID(id) else { return }
            let key = Self.key(id)
            guard let task = inFlight[key]?.task else { return }
            cancelled.insert(key)
            task.cancel()
        default:
            log("ignoring notification \(method)")
        }
    }

    // MARK: requests

    /// The protocol a request is served with: modern when its `_meta` names one, else the version of
    /// the `initialize` handshake.
    private enum Era {
        case modern(String)
        case legacy(String)

        var version: String {
            switch self {
            case .modern(let v), .legacy(let v): return v
            }
        }
    }

    private func respond(id: Any, method: String, params: [String: Any]) async -> Data {
        if method == "initialize" { return initialize(id: id, params: params) }
        let era: Era
        let meta = params["_meta"] as? [String: Any]
        if let requested = meta?[Self.versionKey] {
            guard let version = requested as? String else {
                return errorMessage(id: id, code: ErrorCode.invalidParams, message: "Invalid params: \(Self.versionKey) must be a string")
            }
            guard Self.supportedVersions.contains(version) else {
                return errorMessage(id: id, code: ErrorCode.unsupportedVersion, message: "Unsupported protocol version",
                                    data: ["supported": Self.supportedVersions, "requested": version])
            }
            if Self.modernVersions.contains(version) && !(meta?[Self.capabilitiesKey] is [String: Any]) {
                return errorMessage(id: id, code: ErrorCode.invalidParams, message: "Invalid params: missing _meta \(Self.capabilitiesKey)")
            }
            era = Self.modernVersions.contains(version) ? .modern(version) : .legacy(version)
        } else if let sessionVersion {
            era = .legacy(sessionVersion)
        } else if method == "ping" {
            era = .legacy(Self.legacyVersions[0])
        } else {
            return errorMessage(id: id, code: ErrorCode.invalidParams,
                                message: "Invalid params: missing _meta \(Self.versionKey) (or send initialize first)")
        }

        switch method {
        case "ping":
            return result(id: id, [:], era: era)
        case "server/discover":
            var r: [String: Any] = ["supportedVersions": Self.supportedVersions, "capabilities": capabilities,
                                    "instructions": instructions]
            r["ttlMs"] = 0
            r["cacheScope"] = "private"
            return result(id: id, r, era: .modern(era.version))
        case "tools/list":
            var r: [String: Any] = ["tools": tools.definitions(version: era.version)]
            if case .modern = era {
                r["ttlMs"] = 0
                r["cacheScope"] = "private"
            }
            return result(id: id, r, era: era)
        case "tools/call":
            guard let name = params["name"] as? String else {
                return errorMessage(id: id, code: ErrorCode.invalidParams, message: "Invalid params: missing tool name")
            }
            let rawArguments = params["arguments"].flatMap { $0 is NSNull ? nil : $0 } ?? [String: Any]()
            guard let arguments = rawArguments as? [String: Any] else {
                return errorMessage(id: id, code: ErrorCode.invalidParams, message: "Invalid params: arguments must be an object")
            }
            guard tools.isAvailable(name) else {
                return errorMessage(id: id, code: ErrorCode.invalidParams, message: "Unknown tool: \(name)")
            }
            let outcome = await tools.call(name, arguments)
            return result(id: id, outcome.result(structured: Self.supportsStructuredContent(era.version)), era: era)
        default:
            return errorMessage(id: id, code: ErrorCode.methodNotFound, message: "Method not found: \(method)")
        }
    }

    /// Handshake of the protocols before 2026-07-28: the version the client asked for when it is one
    /// of `legacyVersions`, else the newest of them (the client disconnects if it cannot use it).
    private func initialize(id: Any, params: [String: Any]) -> Data {
        guard let requested = params["protocolVersion"] as? String else {
            return errorMessage(id: id, code: ErrorCode.invalidParams, message: "Invalid params: missing protocolVersion",
                                data: ["supported": Self.supportedVersions])
        }
        let version = Self.legacyVersions.contains(requested) ? requested : Self.legacyVersions[0]
        sessionVersion = version
        if let client = params["clientInfo"] as? [String: Any], let name = client["name"] as? String {
            log("client \(name) \(client["version"] as? String ?? ""), protocol \(version)")
        }
        let r: [String: Any] = ["protocolVersion": version, "capabilities": capabilities,
                                "serverInfo": serverInfo, "instructions": instructions]
        return result(id: id, r, era: .legacy(version))
    }

    static func supportsStructuredContent(_ version: String) -> Bool { version >= "2025-06-18" }

    private var capabilities: [String: Any] { ["tools": ["listChanged": false]] }

    private var serverInfo: [String: Any] {
        ["name": "passtunnel", "title": "PassTunnel", "version": serverVersion]
    }

    private var instructions: String {
        var text = """
        PassTunnel manages this Mac's VPN connections (OpenVPN and FortiGate SSL VPN). Profiles are \
        identified by their id (from list_profiles). The tools never return passwords, TOTP secrets, \
        one-time codes, keys or configuration files, and they cannot create, change or delete profiles.
        """
        if tools.allowConnect {
            text += " connect and disconnect are enabled. A protected profile shows a Touch ID prompt on the Mac that the user must confirm; tell the user to look for it."
        } else {
            text += " This server is read-only: connecting and disconnecting are disabled (the user can start it with --allow-connect)."
        }
        return text
    }

    // MARK: output

    private func result(id: Any, _ body: [String: Any], era: Era) -> Data {
        var r = body
        if case .modern = era {
            r["resultType"] = "complete"
            var meta = r["_meta"] as? [String: Any] ?? [:]
            meta[Self.serverInfoKey] = serverInfo
            r["_meta"] = meta
        }
        return Self.encode(["jsonrpc": "2.0", "id": id, "result": r])
    }

    private func errorMessage(id: Any?, code: Int, message: String, data: Any? = nil) -> Data {
        var error: [String: Any] = ["code": code, "message": message]
        if let data { error["data"] = data }
        var m: [String: Any] = ["jsonrpc": "2.0", "error": error]
        if let id { m["id"] = id }
        return Self.encode(m)
    }

    /// One line of JSON (JSONSerialization escapes line breaks inside strings).
    static func encode(_ object: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]))
            ?? Data(#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"}}"#.utf8)
    }

    // MARK: stdio

    /// Serves stdin/stdout until stdin ends, then exits 0. Diagnostics go to stderr; stdout carries
    /// protocol messages only.
    public static func runStdio(service: AutomationService, allowConnect: Bool) async -> Int32 {
        signal(SIGPIPE, SIG_IGN)
        let stderr = FileHandle.standardError
        let log: (String) -> Void = { text in try? stderr.write(contentsOf: Data(("passtunnel mcp: " + text + "\n").utf8)) }
        var outputClosed = false
        let server = MCPServer(service: service, allowConnect: allowConnect, send: { data in
            guard !outputClosed else { return }
            do { try FileHandle.standardOutput.write(contentsOf: data + Data([0x0A])) } catch { outputClosed = true }
        }, log: log)
        // Confirmations end on screen lock and sleep, as in the app (this process may run for days).
        let expiry = VaultExpiry(vault: service.manager.vault)
        defer { withExtendedLifetime(expiry) {} }
        log("ready (\(allowConnect ? "connect and disconnect allowed" : "read-only")), protocol \(modernVersions[0]) and \(legacyVersions.joined(separator: ", "))")
        let lines = AsyncStream<LineReader.Line> { continuation in
            Thread.detachNewThread {
                var reader = LineReader(maxBytes: maxLineBytes)
                var buffer = [UInt8](repeating: 0, count: 64 * 1024)
                while true {
                    let n = read(STDIN_FILENO, &buffer, buffer.count)
                    if n < 0 && errno == EINTR { continue }
                    guard n > 0 else { break }
                    for line in reader.feed(buffer[0..<n]) { continuation.yield(line) }
                }
                for line in reader.finish() { continuation.yield(line) }
                continuation.finish()
            }
        }
        for await line in lines {
            switch line {
            case .text(let data):
                if !data.allSatisfy({ $0 == 0x20 || $0 == 0x09 }) { server.receive(data) }
            case .tooLong:
                server.receiveOversizedLine()
            }
            if outputClosed { break }
        }
        await server.drain()
        return 0
    }
}

/// Splits standard input into lines without ever holding more than `maxBytes` of one: the rest of a
/// longer line is skipped up to its newline and reported as `tooLong`. A trailing "\r" is removed
/// (as `readLine` does).
public struct LineReader {
    public enum Line: Equatable, Sendable {
        case text(Data)
        case tooLong
    }

    public let maxBytes: Int
    private var current: [UInt8] = []
    private var skipping = false

    public init(maxBytes: Int) { self.maxBytes = maxBytes }

    public mutating func feed<C: Collection>(_ chunk: C) -> [Line] where C.Element == UInt8 {
        var out: [Line] = []
        var rest = chunk[...]
        while !rest.isEmpty {
            let newline = rest.firstIndex(of: 0x0A)
            let part = rest[..<(newline ?? rest.endIndex)]
            if !skipping {
                if current.count + part.count > maxBytes + 1 {
                    // One byte of slack for the "\r" of a "\r\n" line exactly maxBytes long.
                    current = []
                    skipping = true
                } else {
                    current.append(contentsOf: part)
                }
            }
            guard let newline else { break }
            out.append(endLine())
            rest = rest[rest.index(after: newline)...]
        }
        return out
    }

    /// The last line when the input does not end with a newline.
    public mutating func finish() -> [Line] {
        guard skipping || !current.isEmpty else { return [] }
        return [endLine()]
    }

    private mutating func endLine() -> Line {
        defer { current = []; skipping = false }
        if skipping { return .tooLong }
        if current.last == 0x0D { current.removeLast() }
        return current.count > maxBytes ? .tooLong : .text(Data(current))
    }
}
