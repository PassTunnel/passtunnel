import Foundation

#if canImport(Glibc)
import Glibc
#endif

/// Removes a bearer secret from a line of a tool's output before it is written to the user's log: every
/// literal occurrence of the given secrets, and every cookie-shaped field (`COOKIE=…`, a `webvpn…=` or
/// `openconnect_strapkey=` value, a `Cookie:` or `Set-Cookie:` header to the end of the line, a `cookie …`
/// configuration line). openconnect at its default level prints no cookie, but a server chooses some of what
/// it prints (the CONNECT reply's status line, say) and could reflect the cookie there.
public enum OutputMask {
    public static let mask = "<redacted>"

    private static let patterns: [(NSRegularExpression, String)] = [
        (#"(?i)\b(COOKIE=)\S+"#, "$1" + mask),
        (#"(?i)\b((?:set-)?cookie\s*:\s*).+"#, "$1" + mask),
        (#"(?i)\b(webvpn[a-z_]*=|openconnect_strapkey=)[^;\s]+"#, "$1" + mask),
        // openconnect's configuration option, lowercase: not its "Cookie was rejected by server" message.
        (#"^(\s*cookie)([ \t=]+)\S+"#, "$1$2" + mask)
    ].map { (try! NSRegularExpression(pattern: $0.0), $0.1) }

    /// `line` (one line, without its line break) with `secrets` (literally; values shorter than 3 characters are
    /// ignored) and the cookie-shaped fields masked.
    public static func apply(_ line: String, secrets: [String] = []) -> String {
        var out = line
        for secret in secrets.filter({ $0.count >= 3 }).sorted(by: { $0.count > $1.count }) {
            out = out.replacingOccurrences(of: secret, with: mask)
        }
        for (regex, template) in patterns {
            out = regex.stringByReplacingMatches(in: out, range: NSRange(out.startIndex..., in: out), withTemplate: template)
        }
        return out
    }
}

/// Copies a tool's output from a pipe into its log one whole line at a time, each through `OutputMask`, so a
/// secret is never written in part. A line longer than `maxLineBytes` is cut there and the rest of it, up to
/// the next line break, is dropped (" …" marks the cut): masking always sees the complete text it writes.
/// The tool ignores SIGPIPE (openconnect does), so if this process ends first its output is lost, never
/// the tool.
public final class MaskingCopier: @unchecked Sendable {
    public static let maxLineBytes = 16 * 1024

    private let readFD: Int32
    private let logFD: Int32
    private let secrets: [String]

    /// Takes both descriptors over; `run` closes them.
    public init(readFD: Int32, logFD: Int32, secrets: [String]) {
        self.readFD = readFD
        self.logFD = logFD
        self.secrets = secrets
    }

    public func start(name: String) {
        let thread = Thread { self.run() }
        thread.name = name
        thread.start()
    }

    /// Copies until the end of the output (or a read error), then closes both descriptors.
    public func run() {
        var splitter = Splitter()
        var buffer = [UInt8](repeating: 0, count: 64 << 10)
        while true {
            let n = read(readFD, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { break }
            for line in splitter.feed(buffer[0..<n]) { write(line) }
        }
        if let last = splitter.finish() { write(last) }
        _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
        close(readFD)
        close(logFD)
    }

    private func write(_ line: Splitter.Line) {
        var text = OutputMask.apply(String(decoding: line.bytes, as: UTF8.self), secrets: secrets)
        if line.cut { text += " …" }
        if line.ended { text += "\n" }
        Self.writeAll(logFD, Array(text.utf8))
    }

    /// The log is the user's file: a write that fails (a full disk) loses that output, never the tool.
    static func writeAll(_ fd: Int32, _ bytes: [UInt8]) {
        var offset = 0
        while offset < bytes.count {
            let n = bytes[offset...].withUnsafeBytes { Foundation.write(fd, $0.baseAddress, $0.count) }
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { return }
            offset += n
        }
    }

    /// Splits the output into lines at LF, at most `maxLineBytes` each (pure, for the tests).
    struct Splitter {
        struct Line: Equatable {
            var bytes: [UInt8]
            /// Ended with a line break (the last one may not).
            var ended: Bool
            /// The rest of the line beyond `maxLineBytes` was dropped.
            var cut: Bool
        }

        private var pending: [UInt8] = []
        private var dropping = false

        mutating func feed(_ chunk: ArraySlice<UInt8>) -> [Line] {
            var lines: [Line] = []
            for byte in chunk {
                if byte == 0x0A {
                    lines.append(Line(bytes: pending, ended: true, cut: dropping))
                    pending.removeAll(keepingCapacity: true)
                    dropping = false
                } else if !dropping {
                    if pending.count < MaskingCopier.maxLineBytes {
                        pending.append(byte)
                    } else {
                        dropping = true
                    }
                }
            }
            return lines
        }

        mutating func finish() -> Line? {
            guard !pending.isEmpty || dropping else { return nil }
            defer { pending = [] }
            return Line(bytes: pending, ended: false, cut: dropping)
        }
    }
}
