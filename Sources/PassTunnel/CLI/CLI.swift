import Foundation
import PassTunnelCore

/// `passtunnel` command-line mode of the app binary.
enum PassTunnelCLI {
    enum Exit {
        static let ok: Int32 = 0
        static let error: Int32 = 1
        static let usage: Int32 = 2
        static let notConnected: Int32 = 3
    }

    /// CLI mode when invoked through the `passtunnel` symlink or with a known command as the first argument.
    static func isInvocation(_ args: [String]) -> Bool {
        if let first = args.first, (first as NSString).lastPathComponent == "passtunnel" { return true }
        let args = CLICommand.strippingSystemArguments(args)
        return args.count > 1 && CLICommand.isCommand(args[1])
    }

    /// Runs the command in `args` (argv including the program name) and returns the exit code.
    static func run(_ args: [String]) -> Int32 {
        let command: CLICommand
        do {
            command = try CLICommand.parse(CLICommand.strippingSystemArguments(Array(args.dropFirst())))
        } catch let e as CLIUsageError {
            CLITerminal.fail(e.message)
            CLITerminal.err(CLIHelp.usage(for: e.command))
            return Exit.usage
        } catch {
            CLITerminal.fail(error.localizedDescription)
            return Exit.usage
        }
        return runOnMainRunLoop { await CLIRunner().run(command) }
    }

    /// Drives async main-actor work from synchronous top-level code by spinning the main run loop.
    private static func runOnMainRunLoop(_ body: @escaping @MainActor () async -> Int32) -> Int32 {
        final class Box { var code: Int32 = 0; var done = false }
        let box = Box()
        // Keeps the run loop from returning immediately when it has no other sources.
        let keepAlive = Timer(timeInterval: 3600, repeats: true) { _ in }
        RunLoop.main.add(keepAlive, forMode: .default)
        defer { keepAlive.invalidate() }
        Task { @MainActor in
            box.code = await body()
            box.done = true
        }
        while !box.done {
            _ = RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: 0.1))
        }
        return box.code
    }
}

/// Usage text, per command and overall.
enum CLIHelp {
    static let synopsis: [(String, String)] = [
        ("status", "passtunnel status [ID] [--json]"),
        ("connect", "passtunnel connect [ID] [--force]"),
        ("disconnect", "passtunnel disconnect [ID] | --all"),
        ("toggle", "passtunnel toggle [ID]"),
        ("code", "passtunnel code [ID] [-c|--copy] [--json]"),
        ("list", "passtunnel list [--json] [-q|--quiet]"),
        ("show", "passtunnel show ID [--json]"),
        ("set", "passtunnel set ID key=value…"),
        ("add", "passtunnel add NAME --type openvpn|forti"),
        ("import", "passtunnel import FILE [--name NAME]"),
        ("export", "passtunnel export ID [-o FILE]"),
        ("rm", "passtunnel rm ID [-y|--yes]"),
        ("secret", "passtunnel secret ID password|totp"),
        ("default", "passtunnel default [ID]"),
        ("pin", "passtunnel pin ID"),
        ("unpin", "passtunnel unpin ID"),
        ("log", "passtunnel log ID [-f|--follow]"),
        ("helper", "passtunnel helper status|install|uninstall"),
        ("completion", "passtunnel completion zsh|bash|fish"),
    ]

    static func summary(_ command: String) -> String {
        switch command {
        case "status": return String(localized: "Show the state of all profiles, or of one (exit code 3 when not connected).")
        case "connect": return String(localized: "Connect a profile (default: the default profile). Asks for missing input on a terminal.")
        case "disconnect": return String(localized: "Disconnect a profile, or every profile with --all.")
        case "toggle": return String(localized: "Connect when disconnected, disconnect otherwise.")
        case "code": return String(localized: "Print the current one-time code and the seconds left; -c copies it.")
        case "list": return String(localized: "List profiles.")
        case "show": return String(localized: "Show the settings of a profile.")
        case "set": return String(localized: "Change settings, e.g. username=alice health_host=10.0.0.5 auto_reconnect=true.")
        case "add": return String(localized: "Create an empty profile.")
        case "import": return String(localized: "Import an .ovpn/.conf file or a shared .passtunnel profile.")
        case "export": return String(localized: "Export a profile as a .passtunnel file (no passwords or secrets).")
        case "rm": return String(localized: "Delete a profile and its Keychain items.")
        case "secret": return String(localized: "Save the password or TOTP secret (Base32 or otpauth:// link) in the Keychain. Reads from the terminal without echo, or from standard input.")
        case "default": return String(localized: "Show or set the default profile.")
        case "pin": return String(localized: "Always show the profile in the menu bar.")
        case "unpin": return String(localized: "Show the profile in the menu bar only while it is active.")
        case "log": return String(localized: "Print the VPN log of a profile; -f keeps following it.")
        case "helper": return String(localized: "Show, install or remove the privileged helper.")
        case "completion": return String(localized: "Print a shell completion script.")
        case "debug": return String(localized: "Test hook: make a connected OpenVPN profile drop as if the server ended the session (not a user stop, so auto-reconnect runs).")
        default: return ""
        }
    }

    /// Test hooks: `passtunnel help debug` shows them; the overview does not.
    static let hiddenSynopsis = [("debug", "passtunnel debug drop ID")]

    static func usage(for command: String?) -> String {
        if let command, let line = (synopsis + hiddenSynopsis).first(where: { $0.0 == command }) {
            var text = String(localized: "Usage:") + " " + line.1 + "\n  " + summary(command)
            if command == "set" {
                text += "\n" + String(localized: "Keys:") + " " + ProfileFields.keys.joined(separator: ", ")
            }
            return text
        }
        var lines = [String(localized: "Usage:")]
        let width = synopsis.map(\.1.count).max() ?? 0
        for (name, line) in synopsis {
            lines.append("  " + line.padding(toLength: width + 2, withPad: " ", startingAt: 0) + summary(name))
        }
        lines.append("")
        lines.append(String(localized: "Without arguments, passtunnel prints the status of all profiles."))
        lines.append(String(localized: "Exit codes: 0 ok, 1 error, 2 usage, 3 not connected."))
        return lines.joined(separator: "\n")
    }
}
