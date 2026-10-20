import Darwin
import Foundation
import PassTunnelCore

/// Terminal I/O for the CLI: output streams, colors, prompts and no-echo input.
enum CLITerminal {
    static var stdinIsTTY: Bool { isatty(STDIN_FILENO) == 1 }
    static var stdoutIsTTY: Bool { isatty(STDOUT_FILENO) == 1 }
    static var stderrIsTTY: Bool { isatty(STDERR_FILENO) == 1 }

    static var useColor: Bool {
        let env = ProcessInfo.processInfo.environment
        return stdoutIsTTY && env["NO_COLOR"] == nil && env["TERM"] != "dumb"
    }

    static func out(_ text: String = "") {
        FileHandle.standardOutput.write(Data((text + "\n").utf8))
    }

    static func err(_ text: String) {
        FileHandle.standardError.write(Data((text + "\n").utf8))
    }

    /// "passtunnel: <message>" on stderr.
    static func fail(_ message: String) {
        err("passtunnel: " + message)
    }

    static func colored(_ text: String, _ color: RGBColor) -> String {
        useColor ? color.ansiForeground + text + "\u{1B}[0m" : text
    }

    static func bold(_ text: String) -> String {
        useColor ? "\u{1B}[1m" + text + "\u{1B}[0m" : text
    }

    static func dim(_ text: String) -> String {
        useColor ? "\u{1B}[2m" + text + "\u{1B}[0m" : text
    }

    // MARK: input

    /// Prompts on stderr and reads one line from the terminal (echo on).
    static func ask(_ prompt: String) -> String? {
        FileHandle.standardError.write(Data(prompt.utf8))
        return readLine(strippingNewline: true)
    }

    /// Prompts on stderr and reads one line with echo off. Ctrl-C restores the terminal first.
    static func askSecret(_ prompt: String) -> String? {
        FileHandle.standardError.write(Data(prompt.utf8))
        var original = termios()
        guard tcgetattr(STDIN_FILENO, &original) == 0 else { return readLine(strippingNewline: true) }
        savedTermios = original
        var silent = original
        silent.c_lflag &= ~tcflag_t(ECHO)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent)
        let previous = signal(SIGINT, restoreAndExit)
        defer {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &original)
            signal(SIGINT, previous)
            savedTermios = nil
            FileHandle.standardError.write(Data("\n".utf8))
        }
        return readLine(strippingNewline: true)
    }

    /// Everything on stdin (for piped secrets), without the final line break.
    static func readAllStdin() -> String {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        return CLICommand.trimmingFinalLineBreaks(String(decoding: data, as: UTF8.self))
    }

    /// y/N question on the terminal.
    static func confirm(_ question: String) -> Bool {
        let choices = String(localized: "[y/N]", comment: "Yes/no choices after a question; the capital letter is the default (no)")
        guard let answer = ask(question + " " + choices + " ") else { return false }
        let a = answer.trimmingCharacters(in: .whitespaces).lowercased()
        let yes = String(localized: "y", comment: "Short form of yes in y/N prompts").lowercased()
        return a == "y" || a == "yes" || a == yes
    }
}

private var savedTermios: termios?

private func restoreAndExit(_ sig: Int32) {
    if var t = savedTermios { tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) }
    _ = write(STDERR_FILENO, "\n", 1)
    _exit(130)
}

/// Human-friendly durations ("1 h 12 m") in the user's language.
enum CLIDurations {
    static func since(_ date: Date, now: Date = Date()) -> String {
        let f = DateComponentsFormatter()
        f.unitsStyle = .abbreviated
        f.maximumUnitCount = 2
        let seconds = max(0, now.timeIntervalSince(date))
        f.allowedUnits = seconds < 60 ? [.second] : seconds < 86_400 ? [.hour, .minute] : [.day, .hour]
        return f.string(from: seconds) ?? ""
    }
}
