import Foundation
import PassTunnelCore
import PassTunnelKit

#if canImport(AppKit)
import AppKit
#endif

/// `passtunnel code --copy`: copies a code like the app does and leaves a process behind that clears
/// it after `Preferences.clearClipboardAfter` unless something else was copied meanwhile; the command
/// itself returns at once.
enum CLIClipboard {
    /// What the process left behind is told, as its arguments after the program name:
    /// `__clear-clipboard SECONDS [COUNT]`. SECONDS is one of `Preferences.clearClipboardChoices`;
    /// COUNT, on the Mac only, is the pasteboard's change count after the copy. Both are plain digits.
    struct ClearOrder: Equatable {
        var seconds: Int
        var changeCount: Int?

        init(seconds: Int, changeCount: Int? = nil) {
            self.seconds = seconds
            self.changeCount = changeCount
        }

        /// Nil for anything else (another number of seconds, a sign, extra arguments).
        init?(arguments: [String]) {
            guard (2...3).contains(arguments.count), arguments[0] == PassTunnelCLI.clearClipboardArgument,
                let seconds = Self.number(arguments[1]), Preferences.clearClipboardChoices.contains(seconds)
            else { return nil }
            self.seconds = seconds
            if arguments.count == 3 {
                guard let count = Self.number(arguments[2]) else { return nil }
                changeCount = count
            }
        }

        var arguments: [String] {
            [PassTunnelCLI.clearClipboardArgument, String(seconds)] + (changeCount.map { [String($0)] } ?? [])
        }

        /// ASCII digits only, at most 18 so the value always fits.
        private static func number(_ text: String) -> Int? {
            guard (1...18).contains(text.utf8.count), text.utf8.allSatisfy({ (0x30...0x39).contains($0) }) else {
                return nil
            }
            return Int(text)
        }
    }

    /// The process left behind (`passtunnel <PassTunnelCLI.clearClipboardArgument> …`): its exit code,
    /// or nil when `args` are not its arguments. Malformed arguments end it with a usage error and
    /// nothing else; they are never read as a command.
    static func runLeftBehind(_ args: [String]) -> Int32? {
        guard args.count > 1, args[1] == PassTunnelCLI.clearClipboardArgument else { return nil }
        guard let order = ClearOrder(arguments: Array(args.dropFirst())) else { return PassTunnelCLI.Exit.usage }
        #if os(macOS)
        guard let count = order.changeCount else { return PassTunnelCLI.Exit.usage }
        return clearLater(ifUnchangedSince: count, after: order.seconds)
        #else
        guard order.changeCount == nil else { return PassTunnelCLI.Exit.usage }
        return serve(for: order.seconds)
        #endif
    }

    #if os(macOS)
    /// As the app does (`Pasteboard.copySecret`: this Mac only, concealed, transient), cleared after
    /// `seconds` (`Preferences.clearClipboardAfter`).
    static func copyConcealed(_ text: String, clearingAfter seconds: Int) throws {
        let count = Pasteboard.copySecret(text)
        scheduleClear(ClearOrder(seconds: seconds, changeCount: count))
    }

    /// Runs `passtunnel <PassTunnelCLI.clearClipboardArgument> SECONDS COUNT` in a new session with no
    /// terminal, so closing the terminal does not end it. It inherits no descriptor (a store lock
    /// would otherwise stay held while it waits): stdin, stdout and stderr are /dev/null. Best effort.
    private static func scheduleClear(_ order: ClearOrder) {
        guard let executable = Bundle.main.executablePath else { return }
        let argv = ["passtunnel"] + order.arguments
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT))
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        for fd in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] {
            posix_spawn_file_actions_addopen(&actions, fd, "/dev/null", fd == STDIN_FILENO ? O_RDONLY : O_WRONLY, 0)
        }
        var cArgs = argv.map { strdup($0) } + [nil]
        defer { cArgs.forEach { free($0) } }
        var pid: pid_t = 0
        _ = posix_spawn(&pid, executable, &actions, &attr, &cArgs, environ)
    }

    /// The detached process: waits, then clears the pasteboard if it still holds the copied code.
    static func clearLater(ifUnchangedSince count: Int, after seconds: Int) -> Int32 {
        Thread.sleep(forTimeInterval: TimeInterval(seconds))
        Pasteboard.clear(ifUnchangedSince: count)
        return PassTunnelCLI.Exit.ok
    }
    #else
    /// With the session's clipboard tool (`tool`), which `passtunnel <clearClipboardArgument> SECONDS`
    /// runs (`serve`): the code goes to it on standard input, never in arguments. Without a tool:
    /// `invalid_argument`.
    static func copyConcealed(_ text: String, clearingAfter seconds: Int) throws {
        guard tool() != nil else {
            throw AutomationError(
                .invalidArgument,
                String(localized: "Copying needs wl-copy (Wayland) or xclip (X11), and neither was found. Run the command without --copy."))
        }
        guard let executable = Bundle.main.executablePath else { return }
        // Foundation starts it in its own process group with no other descriptors; it outlives this one.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = ClearOrder(seconds: seconds).arguments
        let input = Pipe()
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        try? input.fileHandleForWriting.write(contentsOf: Data(text.utf8))
        try? input.fileHandleForWriting.close()
    }

    /// The process left behind: hands its standard input to the clipboard tool and clears it after
    /// `seconds` (see `serve(_:with:lifetime:)`).
    static func serve(for seconds: Int) -> Int32 {
        signal(SIGHUP, SIG_IGN)  // a closed terminal does not end it (or the tool) early
        let text = FileHandle.standardInput.readDataToEndOfFile()
        guard let tool = tool() else { return PassTunnelCLI.Exit.error }
        return serve(text, with: tool, lifetime: TimeInterval(seconds))
    }
    #endif

    // The rest is the Linux clipboard, built everywhere so its tests run on the Mac too.

    /// A command that copies its standard input to the clipboard and serves it in the foreground until
    /// another program takes the clipboard, then exits: the clipboard is PassTunnel's exactly while
    /// it runs, and ending it empties the clipboard.
    struct Tool: Equatable {
        var path: String
        var arguments: [String]
    }

    /// wl-copy in a Wayland session, else xclip with an X display; found in PATH. Nil without one.
    static func tool(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        isExecutable: (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) }
    ) -> Tool? {
        let directories = (environment["PATH"] ?? "").split(separator: ":").filter { $0.hasPrefix("/") }
        func find(_ name: String) -> String? {
            directories.map { "\($0)/\(name)" }.first(where: isExecutable)
        }
        if environment["WAYLAND_DISPLAY"]?.isEmpty == false, let path = find("wl-copy") {
            return Tool(path: path, arguments: ["--foreground"])
        }
        if environment["DISPLAY"]?.isEmpty == false, let path = find("xclip") {
            return Tool(path: path, arguments: ["-quiet", "-selection", "clipboard"])
        }
        return nil
    }

    /// Runs `tool` with `data` on its standard input and waits up to `lifetime`. If it still runs then,
    /// PassTunnel still owns the clipboard and stopping the tool clears it; if it has exited, something
    /// else was copied meanwhile and is left alone.
    static func serve(_ data: Data, with tool: Tool, lifetime: TimeInterval) -> Int32 {
        signal(SIGPIPE, SIG_IGN)  // a tool that exits at once (no display) must not end this process
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool.path)
        process.arguments = tool.arguments
        let input = Pipe()
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return PassTunnelCLI.Exit.error }
        try? input.fileHandleForWriting.write(contentsOf: data)
        try? input.fileHandleForWriting.close()
        let deadline = Date().addingTimeInterval(lifetime)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
        return PassTunnelCLI.Exit.ok
    }
}
