import Foundation
import PassTunnelCore
import PassTunnelKit

/// The `passtunnel` command: the CLI mode of the app binary on the Mac, its own executable on Linux.
public enum PassTunnelCLI {
    /// The documented exit codes (`AutomationExit`, docs/CLI-JSON.md).
    enum Exit {
        static let ok = AutomationExit.ok
        static let error = AutomationExit.error
        static let usage = AutomationExit.usage
        static let notConnected = AutomationExit.notFound
    }

    /// CLI mode when invoked through the `passtunnel` symlink, with a known command as the first
    /// argument, or with a first argument that looks like a (mistyped) command.
    public static func isInvocation(_ args: [String]) -> Bool {
        if let first = args.first, (first as NSString).lastPathComponent == "passtunnel" { return true }
        let args = CLICommand.strippingSystemArguments(args)
        return args.count > 1 && (CLICommand.isCommand(args[1]) || CLICommand.looksLikeSubcommand(args[1]))
    }

    /// Reports a first word that is no command: the message, a suggestion when one is close, and a hint.
    static func reportUnknownCommand(_ error: CLIUsageError, name: String) {
        CLITerminal.fail(error.message)
        if let close = CLICommand.suggestion(for: name) {
            CLITerminal.err(String(localized: "Did you mean '\(close)'?"))
        }
        CLITerminal.err(String(localized: "Run 'passtunnel help' for the list of commands."))
    }

    /// Internal first argument of the process `CLIClipboard` leaves behind to clear a copied code.
    static let clearClipboardArgument = "__clear-clipboard"

    /// Runs the command in `args` (argv including the program name) and returns the exit code.
    public static func run(_ args: [String]) -> Int32 {
        if let code = CLIClipboard.runLeftBehind(args) { return code }
        let arguments = CLICommand.strippingSystemArguments(Array(args.dropFirst()))
        let invocation: CLIInvocation
        do {
            invocation = try CLIInvocation.parse(arguments)
        } catch {
            if CLICommand.requestsJSON(arguments) {
                let data = (try? AutomationJSON.encoder().encode(ErrorEnvelope(error))) ?? Data()
                FileHandle.standardOutput.write(data + Data("\n".utf8))
            } else if let e = error as? CLIUsageError, let name = e.unknownCommand {
                reportUnknownCommand(e, name: name)
            } else if let e = error as? CLIUsageError {
                CLITerminal.fail(e.message)
                CLITerminal.err(CLIHelp.usage(for: e.command))
            } else {
                CLITerminal.fail(error.localizedDescription)
            }
            return Exit.usage
        }
        #if os(Linux)
        SecretStores.interaction = secretStoreInteraction(invocation)
        #endif
        return runOnMainRunLoop { await CLIRunner(options: invocation.options).run(invocation.command) }
    }

    #if os(Linux)
    /// On a terminal (not with `--no-input`, never for `mcp`, whose standard input is the protocol) the
    /// secret stores may ask: the file store's passphrase, and time to unlock a locked keyring.
    static func secretStoreInteraction(_ invocation: CLIInvocation) -> SecretStoreInteraction {
        if case .mcp = invocation.command { return .none }
        guard CLITerminal.stdinIsTTY, !invocation.options.noInput else { return .none }
        return SecretStoreInteraction(interactive: true, askPassphrase: CLITerminal.askSecretData)
    }
    #endif

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
    static let synopsis: [(String, String)] = {
        var lines = baseSynopsis
        #if os(Linux)
        let after = lines.firstIndex { $0.0 == "secret" }! + 1
        lines.insert(("secret-store", "passtunnel secret-store [STORE] [--json]"), at: after)
        #endif
        return lines
    }()

    private static let baseSynopsis: [(String, String)] = [
        ("status", "passtunnel status [ID] [--json]"),
        ("connect", "passtunnel connect [ID] [--force] [--wait] [--timeout S] [--json]"),
        ("disconnect", "passtunnel disconnect [ID] | --all [--wait] [--timeout S] [--json]"),
        ("toggle", "passtunnel toggle [ID] [--json]"),
        ("code", "passtunnel code [ID] [-c|--copy] [--json]"),
        ("list", "passtunnel list [--json] [-q|--quiet]"),
        ("show", "passtunnel show ID [--json]"),
        ("set", "passtunnel set ID key=value… [--json]"),
        ("add", "passtunnel add NAME --type openvpn|forti [--json]"),
        ("import", "passtunnel import FILE [--name NAME] [--json]"),
        ("export", "passtunnel export ID [-o FILE] [--json]"),
        ("rm", "passtunnel rm ID [-y|--yes] [--json]"),
        ("secret", "passtunnel secret ID password|totp [--json]"),
        ("default", "passtunnel default [ID] [--json]"),
        ("pin", "passtunnel pin ID [--json]"),
        ("unpin", "passtunnel unpin ID [--json]"),
        ("log", "passtunnel log ID [-f|--follow] [-n N] [--activity] [--json]"),
        ("diagnose", "passtunnel diagnose [--check-clock] [--json]"),
        ("helper", "passtunnel helper status|install|uninstall [--json]"),
        ("mcp", "passtunnel mcp [--allow-connect]"),
        ("completion", "passtunnel completion zsh|bash|fish"),
        ("version", "passtunnel version [--json]"),
    ]

    static func summary(_ command: String) -> String {
        switch command {
        case "status": return String(localized: "Show the state of all profiles, or of one (exit code 3 when not connected).")
        case "connect": return String(localized: "Connect a profile (default: the default profile). Asks for missing input on a terminal. --wait gives up after --timeout seconds (default 60).")
        case "disconnect": return String(localized: "Disconnect a profile, or every profile with --all.")
        case "toggle": return String(localized: "Connect when disconnected, disconnect otherwise.")
        case "code": return String(localized: "Print the current one-time code and the seconds left; -c copies it.")
        case "list": return String(localized: "List profiles.")
        case "show": return String(localized: "Show the settings of a profile.")
        case "set": return String(localized: "Change settings, e.g. username=alice health_host=10.0.0.5 auto_reconnect=true.")
        case "add": return String(localized: "Create an empty profile.")
        case "import": return String(localized: "Import an .ovpn/.conf file or a shared .passtunnel profile.")
        case "export": return String(localized: "Export a profile as a .passtunnel file (no passwords or secrets).")
        #if os(Linux)
        case "rm": return String(localized: "Delete a profile and its saved password and TOTP secret.")
        case "secret": return String(localized: "Save the password or TOTP secret (Base32 or otpauth:// link) in the secret store. Reads from the terminal without echo, or from standard input.")
        case "secret-store": return String(localized: "Show where passwords and TOTP secrets are kept, or choose it: auto, secret-service (the desktop keyring), systemd-creds or file (encrypted with a passphrase).")
        #else
        case "rm": return String(localized: "Delete a profile and its Keychain items.")
        case "secret": return String(localized: "Save the password or TOTP secret (Base32 or otpauth:// link) in the Keychain. Reads from the terminal without echo, or from standard input.")
        #endif
        case "default": return String(localized: "Show or set the default profile.")
        case "pin": return String(localized: "Always show the profile in the menu bar.")
        case "unpin": return String(localized: "Show the profile in the menu bar only while it is active.")
        case "log": return String(localized: "Print the VPN log of a profile; -f keeps following it, -n prints only the last N lines. --activity prints what PassTunnel did instead: connecting, codes, sign-in, drops.")
        #if os(Linux)
        case "diagnose": return String(localized: "Check the installation and every profile without connecting, with the last clock measurement. --check-clock also asks the NTP server this computer is set up with how far the clock is off.")
        #else
        case "diagnose": return String(localized: "Check the installation and every profile without connecting, with the last clock measurement. --check-clock also asks Apple’s time server (time.apple.com) how far the clock is off.")
        #endif
        case "helper": return String(localized: "Show, install or remove the privileged helper.")
        case "mcp": return String(localized: "Run the MCP server for AI assistants on standard input and output. Read-only unless --allow-connect.")
        case "completion": return String(localized: "Print a shell completion script.")
        case "version": return String(localized: "Print the version.")
        #if DEBUG
        case "debug": return String(localized: "Test hook: make a connected OpenVPN profile drop as if the server ended the session (not a user stop, so auto-reconnect runs).")
        #endif
        default: return ""
        }
    }

    /// Test hooks (debug builds only): `passtunnel help debug` shows them; the overview does not.
    #if DEBUG
    static let hiddenSynopsis = [("debug", "passtunnel debug drop ID")]
    #else
    static let hiddenSynopsis: [(String, String)] = []
    #endif

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
        #if os(Linux)
        lines.append(String(localized: "Options for every command: --no-input never asks on the terminal (also PASSTUNNEL_NO_INPUT=1), --no-auth-prompt never asks for a confirmation."))
        #else
        lines.append(String(localized: "Options for every command: --no-input never asks on the terminal (also PASSTUNNEL_NO_INPUT=1), --no-auth-prompt never shows Touch ID."))
        #endif
        lines.append(String(localized: "Exit codes: 0 ok, 1 error, 2 usage, 3 not found or not connected, 4 confirmation cancelled or not possible, 5 helper missing or outdated, 6 connection failed, 7 timeout."))
        return lines.joined(separator: "\n")
    }
}
