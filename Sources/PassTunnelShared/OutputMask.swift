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
/// secret is never written in part:
/// - **Whole lines only.** A line longer than `maxLineBytes` is never written, not even in part: it is replaced
///   as a whole by `overlongMarker` (masking a cut-off part could leave the start of a secret that runs over
///   the cut). An unterminated last line (the tool ended mid-line) is dropped too.
/// - **The tool never waits for the log.** One thread drains the pipe into a bounded queue (`maxQueuedLines`,
///   `maxQueuedBytes`), another writes from it; when the queue is full (the log's file system stalls) lines
///   are dropped, and the writer notes how many (`droppedMarker`) before the next line it writes. The tool
///   ignores SIGPIPE (openconnect does), so if this process ends first its output is lost, never the tool.
public final class MaskingCopier: @unchecked Sendable {
    public static let maxLineBytes = 16 * 1024
    public static let maxQueuedLines = 4096
    public static let maxQueuedBytes = 4 << 20
    public static let overlongMarker = "[output line over 16 KiB dropped]"

    public static func droppedMarker(_ count: Int) -> String { count == 1 ? "[1 line dropped]" : "[\(count) lines dropped]" }

    private let readFD: Int32
    private let logFD: Int32
    private let secrets: [String]
    private let condition = NSCondition()
    private var queue: [[UInt8]] = []
    private var queuedBytes = 0
    private var dropped = 0
    private var ended = false
    /// Replaced in tests: writes one line (with its line break) to the log.
    var writeLine: (Int32, [UInt8]) -> Void = { MaskingCopier.writeAll($0, $1) }

    /// Takes both descriptors over; they are closed once the output has ended and been written.
    public init(readFD: Int32, logFD: Int32, secrets: [String]) {
        self.readFD = readFD
        self.logFD = logFD
        self.secrets = secrets
    }

    public func start(name: String) {
        let reader = Thread { self.drain() }
        reader.name = name
        reader.start()
        let writer = Thread { self.writeQueued() }
        writer.name = name + " (log)"
        writer.start()
    }

    /// Both halves on this thread and one more; returns once everything is written (for the tests).
    public func run() {
        let done = DispatchSemaphore(value: 0)
        let writer = Thread {
            self.writeQueued()
            done.signal()
        }
        writer.start()
        drain()
        done.wait()
    }

    /// Reads the pipe to its end, queueing each complete line, never waiting for the writer.
    func drain() {
        var splitter = Splitter()
        var buffer = [UInt8](repeating: 0, count: 64 << 10)
        while true {
            let n = read(readFD, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { break }
            for line in splitter.feed(buffer[0..<n]) { enqueue(line) }
        }
        _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
        close(readFD)
        condition.lock()
        ended = true
        condition.signal()
        condition.unlock()
    }

    private func enqueue(_ line: [UInt8]) {
        condition.lock()
        if queue.count >= Self.maxQueuedLines || queuedBytes + line.count > Self.maxQueuedBytes {
            dropped += 1
        } else {
            queue.append(line)
            queuedBytes += line.count
            condition.signal()
        }
        condition.unlock()
    }

    /// Masks and writes the queued lines until the output has ended and the queue is empty, then closes the log.
    func writeQueued() {
        while true {
            condition.lock()
            while queue.isEmpty && dropped == 0 && !ended { condition.wait() }
            if queue.isEmpty && dropped == 0 && ended {
                condition.unlock()
                break
            }
            let lines = queue
            let lost = dropped
            queue.removeAll()
            queuedBytes = 0
            dropped = 0
            condition.unlock()
            if lost > 0 { writeLine(logFD, Array((Self.droppedMarker(lost) + "\n").utf8)) }
            for line in lines { writeLine(logFD, Array(masked(line).utf8)) }
        }
        close(logFD)
    }

    /// One queued line as it is written: the marker for an overlong one, else the line masked, with its break.
    func masked(_ line: [UInt8]) -> String {
        guard line.count <= Self.maxLineBytes else { return Self.overlongMarker + "\n" }
        return OutputMask.apply(String(decoding: line, as: UTF8.self), secrets: secrets) + "\n"
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

    /// Splits the output into complete lines at LF (pure, for the tests). A line over `maxLineBytes` is not
    /// kept: it comes out as `maxLineBytes + 1` bytes of nothing (`overlong`), which `masked` replaces with
    /// the marker, so no byte of it is ever written. What follows the last LF is never returned.
    struct Splitter {
        static let overlong = [UInt8](repeating: 0, count: MaskingCopier.maxLineBytes + 1)

        private var pending: [UInt8] = []
        private var dropping = false

        mutating func feed(_ chunk: ArraySlice<UInt8>) -> [[UInt8]] {
            var lines: [[UInt8]] = []
            for byte in chunk {
                if byte == 0x0A {
                    lines.append(dropping ? Self.overlong : pending)
                    pending.removeAll(keepingCapacity: true)
                    dropping = false
                } else if !dropping {
                    if pending.count < MaskingCopier.maxLineBytes {
                        pending.append(byte)
                    } else {
                        dropping = true
                        pending.removeAll(keepingCapacity: true)
                    }
                }
            }
            return lines
        }
    }
}
