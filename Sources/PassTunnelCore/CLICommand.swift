import Foundation
import PassTunnelKit

/// Invalid command line; the CLI prints the message plus usage and exits with 2.
public struct CLIUsageError: Error, Equatable, LocalizedError {
    public var message: String
    public var command: String?
    /// The first word when it names no command (the CLI then adds a hint instead of the full usage).
    public var unknownCommand: String?

    public init(_ message: String, command: String? = nil, unknownCommand: String? = nil) {
        self.message = message
        self.command = command
        self.unknownCommand = unknownCommand
    }

    public var errorDescription: String? { message }
}

/// A parsed `passtunnel` command line. Pure, so it can be unit-tested; execution lives in the app target.
public enum CLICommand: Equatable {
    public enum HelperAction: String, CaseIterable { case status, install, uninstall }
    #if DEBUG
    public enum DebugAction: String, CaseIterable { case drop }
    #endif
    public enum Shell: String, CaseIterable { case zsh, bash, fish }

    // json: print the result (or `{"error": …}`) as JSON on stdout (docs/CLI-JSON.md).
    case status(id: String?, json: Bool)
    // force: even if another VPN takes all traffic. wait / timeout: give up after `timeout` seconds
    // (default `defaultTimeout`); `--timeout` implies `--wait`.
    case connect(id: String?, force: Bool = false, json: Bool = false, wait: Bool = false, timeout: Int? = nil)
    case disconnect(id: String?, all: Bool, json: Bool = false, wait: Bool = false, timeout: Int? = nil)
    case toggle(id: String?, json: Bool = false)
    case code(id: String?, copy: Bool, json: Bool)
    case list(json: Bool, quiet: Bool)  // quiet: ids only (used by shell completion)
    case show(id: String, json: Bool)
    case set(id: String, assignments: [Assignment], json: Bool = false)
    // server: Cisco AnyConnect's address (`--server https://vpn.example.com[:port][/group]`), saved as host, port and usergroup
    case add(name: String, type: VPNType, json: Bool = false, server: AnyConnectServer? = nil)
    case importFile(path: String, name: String?, json: Bool = false)
    case export(id: String, output: String?, json: Bool = false)
    case remove(id: String, yes: Bool, json: Bool = false)
    case secret(id: String, kind: SecretKind, json: Bool = false)
    #if os(Linux)
    case secretStore(choice: SecretStoreChoice?, json: Bool = false)  // nil: show the store in use
    #endif
    case setDefault(id: String?, json: Bool = false)  // nil: print the current default
    case pin(id: String, json: Bool = false)
    case unpin(id: String, json: Bool = false)
    // lines: only the last N; activity: the activity log (`ActivityLog`) instead of the VPN tool's
    case log(id: String, follow: Bool, json: Bool = false, lines: Int? = nil, activity: Bool = false)
    // checkClock: also ask the time server how far the clock is off (it contacts that server)
    case diagnose(checkClock: Bool = false, json: Bool = false)
    case helper(HelperAction, json: Bool = false)  // json: `status` only
    case mcp(allowConnect: Bool)  // MCP server on stdio (`MCPServer`)
    #if DEBUG
    case debug(DebugAction, id: String)  // hidden test hooks, e.g. `debug drop ID` (see `DebugDrop`)
    #endif
    case completion(Shell)
    case help(command: String?)
    case version(json: Bool = false)

    /// Seconds `--wait` waits when no `--timeout` is given.
    public static let defaultTimeout = 60
    static let maxTimeout = 86_400

    public struct Assignment: Equatable {
        public var key: String
        public var value: String
        public init(key: String, value: String) {
            self.key = key
            self.value = value
        }
    }

    /// Every first word that selects CLI mode.
    public static let commandNames: [String] = {
        var names = [
            "status", "connect", "disconnect", "toggle", "code", "list", "show", "set", "add", "import", "export",
            "rm", "secret", "default", "pin", "unpin", "log", "diagnose", "helper", "mcp", "completion", "version",
            "help"
        ]
        #if os(Linux)
        names.insert("secret-store", at: names.firstIndex(of: "secret")! + 1)  // the Mac has the Keychain only
        #endif
        return names
    }()

    /// Commands that select CLI mode but are left out of help and completion (test hooks, debug
    /// builds only).
    #if DEBUG
    public static let hiddenCommandNames = ["debug"]
    #else
    public static let hiddenCommandNames: [String] = []
    #endif

    /// Also accepted as a first argument (`passtunnel --help`, `PassTunnel --version`).
    public static let globalFlags = ["--help", "-h", "--version", "-V"]

    static let aliases = [
        "ls": "list", "remove": "rm", "delete": "rm", "on": "connect", "off": "disconnect",
        "up": "connect", "down": "disconnect", "otp": "code", "logs": "log"
    ]

    /// True when `first` (argv[1]) names a command or a global flag.
    public static func isCommand(_ first: String) -> Bool {
        commandNames.contains(first) || hiddenCommandNames.contains(first) || aliases[first] != nil
            || globalFlags.contains(first) || CLIOptions.flags.contains(first)
    }

    /// True when `arg` (argv[1] after `strippingSystemArguments`) is shaped like a subcommand typed in a
    /// terminal: a lowercase word such as `conect`, not an option, a path, a file name or a document that
    /// exists. Launch Services and Finder never pass such a word, so the app still opens normally.
    public static func looksLikeSubcommand(_ arg: String, fileExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }) -> Bool {
        guard let first = arg.unicodeScalars.first, ("a"..."z").contains(first) else { return false }
        let allowed = arg.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" || $0 == "_" }
        return allowed && !fileExists(arg)
    }

    /// The command closest to a mistyped `name` (at most two edits away), for "did you mean".
    public static func suggestion(for name: String) -> String? {
        let candidates = commandNames + Array(aliases.keys)
        let scored = candidates.map { ($0, editDistance(name, $0)) }.filter { $0.1 <= min(2, max(1, name.count / 3)) }
        guard let best = scored.min(by: { $0.1 < $1.1 }) else { return nil }
        return aliases[best.0] ?? best.0
    }

    private static func editDistance(_ a: String, _ b: String) -> Int {
        let a = Array(a), b = Array(b)
        var previous = Array(0...b.count)
        for i in 1...max(a.count, 1) where !a.isEmpty {
            var row = [i]
            for j in 1...max(b.count, 1) where !b.isEmpty {
                row.append(min(previous[j] + 1, row[j - 1] + 1, previous[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1)))
            }
            previous = row
        }
        return a.isEmpty ? b.count : (b.isEmpty ? a.count : previous[b.count])
    }

    /// Whether the command line asks for JSON output (`--json` before any `--`), also when it does
    /// not parse: a usage error is then reported as JSON too.
    public static func requestsJSON(_ args: [String]) -> Bool {
        args.prefix { $0 != "--" }.contains("--json")
    }

    /// Removes Foundation's argument-domain pairs such as `-AppleLanguages '(tr)'` or `-AppleLocale tr_TR`.
    /// They still take effect through `UserDefaults` (and so pick the CLI language) but are not
    /// commands or options of `passtunnel`.
    public static func strippingSystemArguments(_ args: [String]) -> [String] {
        var out: [String] = []
        var i = args.startIndex
        while i < args.endIndex {
            let arg = args[i]
            let isDefaultsKey =
                (arg.hasPrefix("-Apple") || arg.hasPrefix("-NS")) && arg.count > 3
                && arg.dropFirst().allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" }
            if isDefaultsKey && args.index(after: i) < args.endIndex {
                i = args.index(i, offsetBy: 2)
                continue
            }
            out.append(arg)
            i = args.index(after: i)
        }
        return out
    }

    /// Piped input (e.g. a secret) without its final line breaks: "\n", "\r\n" or "\r". Works on
    /// scalars because Swift treats "\r\n" as one Character that `hasSuffix("\n")` does not match.
    public static func trimmingFinalLineBreaks(_ text: String) -> String {
        var scalars = text.unicodeScalars
        while let last = scalars.last, last == "\n" || last == "\r" { scalars.removeLast() }
        return String(scalars)
    }

    /// Parses the arguments after the program name. No arguments means `status`.
    public static func parse(_ args: [String]) throws -> CLICommand {
        guard let first = args.first else { return .status(id: nil, json: false) }
        if first == "--help" || first == "-h" { return .help(command: args.dropFirst().first) }
        if first == "--version" || first == "-V" { return .version(json: args.dropFirst().contains("--json")) }
        if first == "--json" { return try parse(["status"] + args) }
        let name = aliases[first] ?? first
        guard commandNames.contains(name) || hiddenCommandNames.contains(name) else {
            throw CLIUsageError(String(localized: "unknown command '\(first)'"), unknownCommand: first)
        }
        var a = Args(Array(args.dropFirst()), command: name)
        if a.flag("--help", "-h") { return .help(command: name) }

        switch name {
        case "status":
            let json = a.flag("--json")
            let id = try a.optionalPositional()
            try a.finish()
            return .status(id: id, json: json)
        case "connect", "toggle":
            let json = a.flag("--json")
            guard name == "connect" else {
                let id = try a.optionalPositional()
                try a.finish()
                return .toggle(id: id, json: json)
            }
            let force = a.flag("--force", "-f")
            let (wait, timeout) = try a.waitOptions()
            let id = try a.optionalPositional()
            try a.finish()
            return .connect(id: id, force: force, json: json, wait: wait, timeout: timeout)
        case "disconnect":
            let all = a.flag("--all", "-a")
            let json = a.flag("--json")
            let (wait, timeout) = try a.waitOptions()
            let id = try a.optionalPositional()
            try a.finish()
            if all && id != nil { throw CLIUsageError(String(localized: "Use either a profile or --all, not both."), command: name) }
            return .disconnect(id: id, all: all, json: json, wait: wait, timeout: timeout)
        case "code":
            let copy = a.flag("--copy", "-c")
            let json = a.flag("--json")
            let id = try a.optionalPositional()
            try a.finish()
            return .code(id: id, copy: copy, json: json)
        case "list":
            let json = a.flag("--json")
            let quiet = a.flag("--quiet", "-q")
            try a.finish()
            return .list(json: json, quiet: quiet)
        case "show":
            let json = a.flag("--json")
            let id = try a.positional(String(localized: "profile"))
            try a.finish()
            return .show(id: id, json: json)
        case "set":
            let json = a.flag("--json")
            let id = try a.positional(String(localized: "profile"))
            let rest = a.remaining()
            guard !rest.isEmpty else { throw CLIUsageError(String(localized: "Give at least one key=value."), command: name) }
            let assignments = try rest.map { item -> Assignment in
                guard let eq = item.firstIndex(of: "="), eq != item.startIndex else {
                    throw CLIUsageError(String(localized: "“\(item)” is not in key=value form."), command: name)
                }
                return Assignment(key: String(item[..<eq]), value: String(item[item.index(after: eq)...]))
            }
            return .set(id: id, assignments: assignments, json: json)
        case "add":
            let json = a.flag("--json")
            guard let typeText = try a.option("--type", "-t") else {
                throw CLIUsageError(String(localized: "Missing --type openvpn|forti|anyconnect."), command: name)
            }
            let type: VPNType
            switch typeText.lowercased() {
            case "openvpn": type = .openvpn
            case "forti", "fortigate": type = .forti
            case "anyconnect": type = .anyconnect
            default:
                throw CLIUsageError(
                    String(localized: "Unknown VPN type “\(typeText)” (use openvpn, forti or anyconnect)."), command: name)
            }
            let serverText = try a.option("--server")
            try a.rejectUnknownOptions()
            var server: AnyConnectServer?
            if let serverText {
                guard type == .anyconnect else {
                    throw CLIUsageError(String(localized: "--server is for Cisco AnyConnect profiles (--type anyconnect)."), command: name)
                }
                guard let parsed = AnyConnectServer.parse(serverText) else {
                    // Never echoes the value: it may carry a password (user info) or a token (a query).
                    throw CLIUsageError(
                        String(
                            localized:
                                "--server needs an https:// address like https://vpn.example.com[:port][/group], without user info, a query or a fragment."
                        ), command: name)
                }
                server = parsed
            }
            let words = a.remaining()
            let joined = words.joined(separator: " ").trimmingCharacters(in: .whitespaces)
            guard !joined.isEmpty else { throw CLIUsageError(String(localized: "Missing profile name."), command: name) }
            return .add(name: joined, type: type, json: json, server: server)
        case "import":
            let json = a.flag("--json")
            let newName = try a.option("--name", "-n")
            let path = try a.positional(String(localized: "file"))
            try a.finish()
            return .importFile(path: path, name: newName, json: json)
        case "export":
            let json = a.flag("--json")
            let output = try a.option("--output", "-o")
            let id = try a.positional(String(localized: "profile"))
            try a.finish()
            return .export(id: id, output: output, json: json)
        case "rm":
            let json = a.flag("--json")
            let yes = a.flag("--yes", "-y", "--force", "-f")
            let id = try a.positional(String(localized: "profile"))
            try a.finish()
            return .remove(id: id, yes: yes, json: json)
        case "secret":
            let json = a.flag("--json")
            let id = try a.positional(String(localized: "profile"))
            let kindText = try a.positional("password|totp")
            try a.finish()
            guard let kind = SecretKind(rawValue: kindText.lowercased()) else {
                throw CLIUsageError(String(localized: "Unknown secret “\(kindText)” (use password or totp)."), command: name)
            }
            return .secret(id: id, kind: kind, json: json)
        #if os(Linux)
        case "secret-store":
            let json = a.flag("--json")
            let choiceText = try a.optionalPositional()
            try a.finish()
            guard let choiceText else { return .secretStore(choice: nil, json: json) }
            guard let choice = SecretStoreChoice(rawValue: choiceText.lowercased()) else {
                throw CLIUsageError(
                    String(localized: "Unknown secret store “\(choiceText)” (use auto, secret-service, systemd-creds or file)."), command: name)
            }
            return .secretStore(choice: choice, json: json)
        #endif
        case "default":
            let json = a.flag("--json")
            let id = try a.optionalPositional()
            try a.finish()
            return .setDefault(id: id, json: json)
        case "pin", "unpin":
            let json = a.flag("--json")
            let id = try a.positional(String(localized: "profile"))
            try a.finish()
            return name == "pin" ? .pin(id: id, json: json) : .unpin(id: id, json: json)
        case "log":
            let follow = a.flag("--follow", "-f")
            let json = a.flag("--json")
            let activity = a.flag("--activity")
            let lines = try a.option("--lines", "-n").map { text -> Int in
                guard let n = Int(text), n > 0 else {
                    throw CLIUsageError(String(localized: "--lines needs a positive number."), command: name)
                }
                return n
            }
            let id = try a.positional(String(localized: "profile"))
            try a.finish()
            if follow && json { throw CLIUsageError(String(localized: "--follow cannot be combined with --json."), command: name) }
            if follow && activity { throw CLIUsageError(String(localized: "--follow cannot be combined with --activity."), command: name) }
            return .log(id: id, follow: follow, json: json, lines: lines, activity: activity)
        case "diagnose":
            let json = a.flag("--json")
            let checkClock = a.flag("--check-clock")
            try a.finish()
            return .diagnose(checkClock: checkClock, json: json)
        case "helper":
            let json = a.flag("--json")
            let actionText = try a.optionalPositional() ?? "status"
            try a.finish()
            guard let action = HelperAction(rawValue: actionText) else {
                throw CLIUsageError(String(localized: "Unknown helper action “\(actionText)” (use status, install or uninstall)."), command: name)
            }
            if json && action != .status {
                throw CLIUsageError(String(localized: "--json works with “helper status” only."), command: name)
            }
            return .helper(action, json: json)
        case "mcp":
            let allowConnect = a.flag("--allow-connect")
            try a.finish()
            return .mcp(allowConnect: allowConnect)
        case "version":
            let json = a.flag("--json")
            try a.finish()
            return .version(json: json)
        #if DEBUG
        case "debug":
            let actionText = try a.positional("drop")
            guard let action = DebugAction(rawValue: actionText) else {
                throw CLIUsageError(String(localized: "Unknown debug action “\(actionText)” (use drop)."), command: name)
            }
            let id = try a.positional(String(localized: "profile"))
            try a.finish()
            return .debug(action, id: id)
        #endif
        case "completion":
            let shellText = try a.positional("zsh|bash|fish")
            try a.finish()
            guard let shell = Shell(rawValue: shellText) else {
                throw CLIUsageError(String(localized: "Unknown shell “\(shellText)” (use zsh, bash or fish)."), command: name)
            }
            return .completion(shell)
        case "help":
            let topic = try a.optionalPositional()
            try a.finish()
            return .help(command: topic.map { aliases[$0] ?? $0 })
        default:
            throw CLIUsageError(String(localized: "unknown command '\(first)'"), unknownCommand: first)
        }
    }

    /// Small option scanner: flags anywhere, `--opt value` / `--opt=value`, `--` ends options.
    struct Args {
        private var items: [String]
        private var literal: [String] = []
        let command: String

        init(_ args: [String], command: String) {
            self.command = command
            if let dd = args.firstIndex(of: "--") {
                items = Array(args[..<dd])
                literal = Array(args[args.index(after: dd)...])
            } else {
                items = args
            }
        }

        mutating func flag(_ names: String...) -> Bool {
            var found = false
            items.removeAll { item in
                if names.contains(item) { found = true; return true }
                return false
            }
            return found
        }

        mutating func option(_ names: String...) throws -> String? {
            var result: String?
            var i = 0
            while i < items.count {
                let item = items[i]
                if names.contains(item) {
                    guard i + 1 < items.count else {
                        throw CLIUsageError(String(localized: "\(item) needs a value."), command: command)
                    }
                    result = items[i + 1]
                    items.removeSubrange(i...(i + 1))
                    continue
                }
                if let name = names.first(where: { $0.hasPrefix("--") && item.hasPrefix($0 + "=") }) {
                    result = String(item.dropFirst(name.count + 1))
                    items.remove(at: i)
                    continue
                }
                i += 1
            }
            return result
        }

        private var positionals: [String] {
            items.filter { !$0.hasPrefix("-") || $0 == "-" } + literal
        }

        mutating func optionalPositional() throws -> String? {
            try rejectUnknownOptions()
            if let i = items.firstIndex(where: { !$0.hasPrefix("-") || $0 == "-" }) { return items.remove(at: i) }
            if !literal.isEmpty { return literal.removeFirst() }
            return nil
        }

        /// `--wait` and `--timeout SECONDS` (which implies `--wait`).
        mutating func waitOptions() throws -> (wait: Bool, timeout: Int?) {
            let wait = flag("--wait", "-w")
            guard let text = try option("--timeout", "-t") else { return (wait, nil) }
            guard let seconds = Int(text), (1...CLICommand.maxTimeout).contains(seconds) else {
                throw CLIUsageError(String(localized: "--timeout needs a number of seconds (1–86400)."), command: command)
            }
            return (true, seconds)
        }

        mutating func positional(_ what: String) throws -> String {
            guard let v = try optionalPositional() else {
                throw CLIUsageError(String(localized: "Missing \(what)."), command: command)
            }
            return v
        }

        mutating func remaining() -> [String] {
            let rest = positionals
            items.removeAll()
            literal.removeAll()
            return rest
        }

        func rejectUnknownOptions() throws {
            if let unknown = items.first(where: { $0.hasPrefix("-") && $0 != "-" }) {
                // Without a value after "=": it could be a password or a token typed with the wrong option name.
                let name = unknown.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)[0]
                throw CLIUsageError(String(localized: "Unknown option “\(String(name))”."), command: command)
            }
        }

        func finish() throws {
            try rejectUnknownOptions()
            if let extra = positionals.first {
                throw CLIUsageError(String(localized: "Unexpected argument “\(extra)”."), command: command)
            }
        }
    }
}

/// Options for every command, accepted anywhere before `--`.
public struct CLIOptions: Equatable {
    /// Never read standard input or ask on the terminal; fail with `input_required` instead.
    /// `--no-input`, or `PASSTUNNEL_NO_INPUT=1` in the environment.
    public var noInput = false
    /// Never show the Touch ID / Mac password prompt; fail with `auth_unavailable` instead.
    public var noAuthPrompt = false

    public init(noInput: Bool = false, noAuthPrompt: Bool = false) {
        self.noInput = noInput
        self.noAuthPrompt = noAuthPrompt
    }

    public static let flags = ["--no-input", "--no-auth-prompt"]

    /// `PASSTUNNEL_NO_INPUT` set to 1, true or yes.
    public static func noInputFromEnvironment(_ environment: [String: String]) -> Bool {
        guard let value = environment["PASSTUNNEL_NO_INPUT"]?.trimmingCharacters(in: .whitespaces).lowercased() else { return false }
        return ["1", "true", "yes"].contains(value)
    }
}

/// A command line: the command plus the global options.
public struct CLIInvocation: Equatable {
    public var command: CLICommand
    public var options: CLIOptions

    public init(command: CLICommand, options: CLIOptions = CLIOptions()) {
        self.command = command
        self.options = options
    }

    /// Parses the arguments after the program name: removes the global options, then `CLICommand.parse`.
    public static func parse(_ args: [String], environment: [String: String] = ProcessInfo.processInfo.environment) throws -> CLIInvocation {
        var options = CLIOptions(noInput: CLIOptions.noInputFromEnvironment(environment))
        var rest: [String] = []
        var literal = false
        for arg in args {
            if !literal && arg == "--" { literal = true }
            if !literal && arg == "--no-input" { options.noInput = true; continue }
            if !literal && arg == "--no-auth-prompt" { options.noAuthPrompt = true; continue }
            rest.append(arg)
        }
        return CLIInvocation(command: try CLICommand.parse(rest), options: options)
    }
}
