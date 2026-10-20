import Foundation

/// Invalid command line; the CLI prints the message plus usage and exits with 2.
public struct CLIUsageError: Error, Equatable, LocalizedError {
    public var message: String
    public var command: String?

    public init(_ message: String, command: String? = nil) {
        self.message = message
        self.command = command
    }

    public var errorDescription: String? { message }
}

/// A parsed `passtunnel` command line. Pure, so it can be unit-tested; execution lives in the app target.
public enum CLICommand: Equatable {
    public enum HelperAction: String, CaseIterable { case status, install, uninstall }
    public enum Shell: String, CaseIterable { case zsh, bash, fish }

    case status(id: String?, json: Bool)
    case connect(id: String?)
    case disconnect(id: String?, all: Bool)
    case toggle(id: String?)
    case code(id: String?, copy: Bool, json: Bool)
    case list(json: Bool, quiet: Bool)          // quiet: ids only (used by shell completion)
    case show(id: String, json: Bool)
    case set(id: String, assignments: [Assignment])
    case add(name: String, type: VPNType)
    case importFile(path: String, name: String?)
    case export(id: String, output: String?)
    case remove(id: String, yes: Bool)
    case secret(id: String, kind: SecretKind)
    case setDefault(id: String?)           // nil: print the current default
    case pin(id: String)
    case unpin(id: String)
    case log(id: String, follow: Bool)
    case helper(HelperAction)
    case completion(Shell)
    case help(command: String?)
    case version

    public struct Assignment: Equatable {
        public var key: String
        public var value: String
        public init(key: String, value: String) {
            self.key = key
            self.value = value
        }
    }

    /// Every first word that selects CLI mode.
    public static let commandNames = [
        "status", "connect", "disconnect", "toggle", "code", "list", "show", "set", "add", "import", "export",
        "rm", "secret", "default", "pin", "unpin", "log", "helper", "completion", "help",
    ]

    /// Also accepted as a first argument (`passtunnel --help`, `PassTunnel --version`).
    public static let globalFlags = ["--help", "-h", "--version", "-V"]

    static let aliases = ["ls": "list", "remove": "rm", "delete": "rm", "on": "connect", "off": "disconnect",
                          "up": "connect", "down": "disconnect", "otp": "code", "logs": "log"]

    /// True when `first` (argv[1]) names a command or a global flag.
    public static func isCommand(_ first: String) -> Bool {
        commandNames.contains(first) || aliases[first] != nil || globalFlags.contains(first)
    }

    /// Removes Foundation's argument-domain pairs such as `-AppleLanguages '(tr)'` or `-AppleLocale tr_TR`.
    /// They still take effect through `UserDefaults` (and so pick the CLI language) but are not
    /// commands or options of `passtunnel`.
    public static func strippingSystemArguments(_ args: [String]) -> [String] {
        var out: [String] = []
        var i = args.startIndex
        while i < args.endIndex {
            let arg = args[i]
            let isDefaultsKey = (arg.hasPrefix("-Apple") || arg.hasPrefix("-NS")) && arg.count > 3
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

    /// Parses the arguments after the program name. No arguments means `status`.
    public static func parse(_ args: [String]) throws -> CLICommand {
        guard let first = args.first else { return .status(id: nil, json: false) }
        if first == "--help" || first == "-h" { return .help(command: args.dropFirst().first) }
        if first == "--version" || first == "-V" { return .version }
        if first == "--json" { return try parse(["status"] + args) }
        let name = aliases[first] ?? first
        guard commandNames.contains(name) else {
            throw CLIUsageError(String(localized: "Unknown command “\(first)”."))
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
            let id = try a.optionalPositional()
            try a.finish()
            return name == "connect" ? .connect(id: id) : .toggle(id: id)
        case "disconnect":
            let all = a.flag("--all", "-a")
            let id = try a.optionalPositional()
            try a.finish()
            if all && id != nil { throw CLIUsageError(String(localized: "Use either a profile or --all, not both."), command: name) }
            return .disconnect(id: id, all: all)
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
            let id = try a.positional(String(localized: "profile"))
            let rest = a.remaining()
            guard !rest.isEmpty else { throw CLIUsageError(String(localized: "Give at least one key=value."), command: name) }
            let assignments = try rest.map { item -> Assignment in
                guard let eq = item.firstIndex(of: "="), eq != item.startIndex else {
                    throw CLIUsageError(String(localized: "“\(item)” is not in key=value form."), command: name)
                }
                return Assignment(key: String(item[..<eq]), value: String(item[item.index(after: eq)...]))
            }
            return .set(id: id, assignments: assignments)
        case "add":
            guard let typeText = try a.option("--type", "-t") else {
                throw CLIUsageError(String(localized: "Missing --type openvpn|forti."), command: name)
            }
            guard let type = VPNType(rawValue: typeText.lowercased()) ?? (typeText.lowercased() == "fortigate" ? .forti : nil) else {
                throw CLIUsageError(String(localized: "Unknown VPN type “\(typeText)” (use openvpn or forti)."), command: name)
            }
            try a.rejectUnknownOptions()
            let words = a.remaining()
            let joined = words.joined(separator: " ").trimmingCharacters(in: .whitespaces)
            guard !joined.isEmpty else { throw CLIUsageError(String(localized: "Missing profile name."), command: name) }
            return .add(name: joined, type: type)
        case "import":
            let newName = try a.option("--name", "-n")
            let path = try a.positional(String(localized: "file"))
            try a.finish()
            return .importFile(path: path, name: newName)
        case "export":
            let output = try a.option("--output", "-o")
            let id = try a.positional(String(localized: "profile"))
            try a.finish()
            return .export(id: id, output: output)
        case "rm":
            let yes = a.flag("--yes", "-y", "--force", "-f")
            let id = try a.positional(String(localized: "profile"))
            try a.finish()
            return .remove(id: id, yes: yes)
        case "secret":
            let id = try a.positional(String(localized: "profile"))
            let kindText = try a.positional("password|totp")
            try a.finish()
            guard let kind = SecretKind(rawValue: kindText.lowercased()) else {
                throw CLIUsageError(String(localized: "Unknown secret “\(kindText)” (use password or totp)."), command: name)
            }
            return .secret(id: id, kind: kind)
        case "default":
            let id = try a.optionalPositional()
            try a.finish()
            return .setDefault(id: id)
        case "pin", "unpin":
            let id = try a.positional(String(localized: "profile"))
            try a.finish()
            return name == "pin" ? .pin(id: id) : .unpin(id: id)
        case "log":
            let follow = a.flag("--follow", "-f")
            let id = try a.positional(String(localized: "profile"))
            try a.finish()
            return .log(id: id, follow: follow)
        case "helper":
            let actionText = try a.optionalPositional() ?? "status"
            try a.finish()
            guard let action = HelperAction(rawValue: actionText) else {
                throw CLIUsageError(String(localized: "Unknown helper action “\(actionText)” (use status, install or uninstall)."), command: name)
            }
            return .helper(action)
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
            throw CLIUsageError(String(localized: "Unknown command “\(first)”."))
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
                throw CLIUsageError(String(localized: "Unknown option “\(unknown)”."), command: command)
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
