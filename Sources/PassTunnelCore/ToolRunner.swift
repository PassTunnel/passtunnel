import Foundation
import PassTunnelKit

#if canImport(Glibc)
import Glibc
#endif

// The system tools behind the Linux secret stores (`secret-tool`, `systemd-creds`). Built everywhere,
// so the stores' tests run on the Mac too; only Linux uses them (docs/LINUX.md, Secrets).

/// What a tool returned: its exit status (128 + the signal when a signal ended it) and its output.
struct ToolOutput: Equatable {
    var status: Int32
    var output: Data
    var errorOutput: Data
    /// Standard error went past `SystemToolRunner.maxOutput`, and the rest of it was dropped.
    var errorOutputCut = false

    /// The first line of the error output, without the tool's "name: " prefix, for messages.
    var errorLine: String {
        let text = String(decoding: errorOutput.prefix(1024), as: UTF8.self)
        var line = String(text.split(whereSeparator: \.isNewline).first ?? "").trimmingCharacters(in: .whitespaces)
        if let colon = line.range(of: ": "), !line[..<colon.lowerBound].contains(" ") {
            line = String(line[colon.upperBound...])
        }
        return String(line.prefix(300))
    }

    /// `errorLine`, or the exit status when the tool wrote no message.
    var failure: String {
        let line = errorLine
        return line.isEmpty ? "exit status \(status)" : line
    }

    /// Overwrites the output (it may hold a secret; the error output never does).
    mutating func wipe() {
        output.wipe()
    }
}

/// The tool did not finish within `seconds` and was stopped. `errorOutput`: what it wrote on standard
/// error until then (never its standard output, which may hold a secret).
struct ToolTimeout: Error, Equatable {
    var seconds: Int
    var errorOutput = Data()
}

/// The run was cancelled (`ToolCancellation`) and the tool stopped.
struct ToolCancelled: Error, Equatable {}

/// Stops a `ToolRunning.run` in progress from another thread: the tool is terminated (then killed) and the
/// run throws `ToolCancelled`. Cancelling before the run starts stops it as soon as it has started.
final class ToolCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    init() {}

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

/// Runs a system tool: a fixed path, its arguments and exactly the environment given, with `input` on
/// standard input. Secrets go over standard input and output only, never in arguments or the
/// environment. A tool still running at the deadline is stopped (`ToolTimeout`); with a `cancellation`,
/// also when it is cancelled (`ToolCancelled`). Used for the Linux secret stores' tools and for Cisco
/// AnyConnect's sign-in (`AnyConnectSignIn`).
protocol ToolRunning {
    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data,
        timeout: TimeInterval
    ) throws -> ToolOutput

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data,
        timeout: TimeInterval, cancellation: ToolCancellation?
    ) throws -> ToolOutput
}

extension ToolRunning {
    /// A runner that cannot be cancelled runs to its end or its deadline.
    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data,
        timeout: TimeInterval, cancellation: ToolCancellation?
    ) throws -> ToolOutput {
        try run(path, arguments, environment: environment, input: input, timeout: timeout)
    }
}

/// `ToolRunning` with Foundation's `Process`. Standard input is a socket pair, so a tool that exits
/// without reading it never raises SIGPIPE here; standard output and error are read as they come,
/// so a tool that writes a lot never blocks.
struct SystemToolRunner: ToolRunning {
    /// The most kept of each output stream.
    static let maxOutput = 1 << 20

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data,
        timeout: TimeInterval
    ) throws -> ToolOutput {
        try run(path, arguments, environment: environment, input: input, timeout: timeout, cancellation: nil)
    }

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data,
        timeout: TimeInterval, cancellation: ToolCancellation?
    ) throws -> ToolOutput {
        let deadline = Date().addingTimeInterval(timeout)
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, POSIXSocket.stream, 0, &pair) == 0 else { throw PTError.fileError(path) }
        let inputFD = pair[0]
        defer { POSIXSocket.close(inputFD) }
        POSIXSocket.noSigPipe(inputFD)
        let childInput = FileHandle(fileDescriptor: pair[1], closeOnDealloc: true)
        let output = Pipe()
        let errorOutput = Pipe()

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = environment
        process.standardInput = childInput
        process.standardOutput = output
        process.standardError = errorOutput
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        do {
            try process.run()
        } catch {
            try? childInput.close()
            throw PTError.fileError(path)
        }
        try? childInput.close()

        var streams = Streams(
            input: inputFD, output: output.fileHandleForReading.fileDescriptor,
            errorOutput: errorOutput.fileHandleForReading.fileDescriptor, pending: input)
        defer { streams.wipe() }
        streams.pump(until: deadline, cancellation: cancellation)

        func stop() {
            process.terminate()
            if exited.wait(timeout: .now() + 1) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                _ = exited.wait(timeout: .now() + 1)
            }
        }
        if cancellation?.isCancelled == true {
            stop()
            streams.output.wipe()
            throw ToolCancelled()
        }
        let remaining = deadline.timeIntervalSinceNow
        if remaining <= 0 || exited.wait(timeout: .now() + remaining) == .timedOut {
            stop()
            streams.output.wipe()
            throw ToolTimeout(seconds: Int(timeout.rounded(.up)), errorOutput: streams.errorOutput)
        }
        let status =
            process.terminationReason == .uncaughtSignal
            ? 128 + process.terminationStatus
            : process.terminationStatus
        return ToolOutput(
            status: status, output: streams.output, errorOutput: streams.errorOutput, errorOutputCut: streams.errorOutputCut)
    }

    /// Feeds standard input and collects both outputs with `poll`, until both outputs are closed or
    /// the deadline passes.
    private struct Streams {
        let input: Int32
        let outputFD: Int32
        let errorFD: Int32
        var pending: Data
        var written = 0
        var inputOpen = true
        var outputOpen = true
        var errorOpen = true
        var output = Data()
        var errorOutput = Data()
        /// More came on standard error than `SystemToolRunner.maxOutput`; the rest was dropped.
        var errorOutputCut = false

        init(input: Int32, output: Int32, errorOutput: Int32, pending: Data) {
            self.input = input
            outputFD = output
            errorFD = errorOutput
            self.pending = pending
            for fd in [input, output, errorOutput] { _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) }
            if pending.isEmpty { closeInput() }
        }

        /// `cancellation`: also returns once it is cancelled (checked at least every quarter second).
        mutating func pump(until deadline: Date, cancellation: ToolCancellation? = nil) {
            var buffer = [UInt8](repeating: 0, count: 16 * 1024)
            defer { _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            let slice: TimeInterval = cancellation == nil ? 1 : 0.25
            while outputOpen || errorOpen {
                if cancellation?.isCancelled == true { return }
                let remaining = deadline.timeIntervalSinceNow
                guard remaining > 0 else { return }
                var fds: [pollfd] = []
                if inputOpen { fds.append(pollfd(fd: input, events: Int16(POLLOUT), revents: 0)) }
                if outputOpen { fds.append(pollfd(fd: outputFD, events: Int16(POLLIN), revents: 0)) }
                if errorOpen { fds.append(pollfd(fd: errorFD, events: Int16(POLLIN), revents: 0)) }
                let rc = poll(&fds, nfds_t(fds.count), Int32((min(remaining, slice) * 1000).rounded(.up)))
                if rc < 0 && errno != EINTR { return }
                guard rc > 0 else { continue }
                for entry in fds where entry.revents != 0 {
                    if entry.fd == input {
                        writeInput()
                    } else if entry.fd == outputFD {
                        var cut = false
                        if !read(outputFD, into: &output, buffer: &buffer, cut: &cut) { outputOpen = false }
                    } else if !read(errorFD, into: &errorOutput, buffer: &buffer, cut: &errorOutputCut) {
                        errorOpen = false
                    }
                }
            }
        }

        private mutating func writeInput() {
            let n = pending.withUnsafeBytes { raw in
                POSIXSocket.write(input, raw.baseAddress! + written, raw.count - written)
            }
            if n > 0 {
                written += n
                if written == pending.count { closeInput() }
            } else if n < 0 && errno != EAGAIN && errno != EINTR {
                closeInput()  // the tool closed its input (exited early): the rest is not needed
            }
        }

        /// Ends standard input: the tool reads end of file.
        private mutating func closeInput() {
            inputOpen = false
            #if canImport(Darwin)
            _ = Darwin.shutdown(input, SHUT_WR)
            #else
            _ = Glibc.shutdown(input, Int32(SHUT_WR))
            #endif
        }

        /// Reads what is there; false at end of file or on an error.
        private func read(_ fd: Int32, into data: inout Data, buffer: inout [UInt8], cut: inout Bool) -> Bool {
            let n = buffer.withUnsafeMutableBytes { raw -> Int in
                #if canImport(Darwin)
                Darwin.read(fd, raw.baseAddress, raw.count)
                #else
                Glibc.read(fd, raw.baseAddress, raw.count)
                #endif
            }
            if n > 0 {
                let room = SystemToolRunner.maxOutput - data.count
                if n > room { cut = true }
                if room > 0 { data.append(contentsOf: buffer[0..<min(n, room)]) }
                return true
            }
            return n < 0 && (errno == EAGAIN || errno == EINTR)
        }

        mutating func wipe() {
            pending.wipe()
        }
    }
}

extension Data {
    /// Overwrites the bytes with zeros (best effort: copies made earlier are not reached).
    mutating func wipe() {
        _ = withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
    }
}
