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

/// Standard input that is written in two parts (docs/ARCHITECTURE.md, "The answers, and the second code"): `first`
/// when the run starts, then, while standard input stays open, the second part once the caller's condition holds,
/// read from the run's standard error as it comes (`decide`), and standard input closed after it. `decide` may also
/// close it without the second part. Without a second part standard input is closed once `first` is written.
///
/// The second part's bytes are made only when they are written (`second`, which may compute a code for that
/// moment), handed to the runner once and overwritten here (`SecretBytes`); the runner overwrites its own copy. A
/// run that ends, is cancelled or reaches its deadline before the condition held never gets it.
///
/// `@unchecked Sendable`: its state is behind a lock; the runner calls `next` from one thread.
final class ToolInput: @unchecked Sendable {
    /// What the run's standard error so far (and the time) says about the second part.
    enum Decision: Equatable {
        /// Not yet: keep standard input open and ask again.
        case wait
        /// Write the second part now, then close standard input.
        case write
        /// Close standard input without the second part.
        case close
    }

    /// What the runner does next with standard input, once `first` is written.
    enum Action: Equatable {
        case wait
        case write([UInt8])
        case close
    }

    /// Written when the run starts.
    let first: [UInt8]
    private let second: (() -> [UInt8]?)?
    private let decide: ((Data) -> Decision)?
    private let lock = NSLock()
    private var done = false
    private var _secondWritten = false

    /// `second` makes the second part when it is to be written (nil, or no bytes: none, and standard input is
    /// closed); `decide` reads standard error so far. Without either, standard input is closed after `first`.
    init(_ first: [UInt8], second: (() -> [UInt8]?)? = nil, decide: ((Data) -> Decision)? = nil) {
        self.first = first
        self.second = decide == nil ? nil : second
        self.decide = second == nil ? nil : decide
    }

    /// Whether anything may still follow `first`: the runner keeps standard input open after it only then.
    var hasSecondPart: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !done && second != nil
    }

    /// The second part was handed to the runner to write.
    var secondWritten: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _secondWritten
    }

    /// Called by the runner once `first` is written, with standard error so far, again and again while it
    /// answers `.wait` (when standard error grows, and at least every quarter second, so a condition on the time
    /// is seen in time). `.write` and `.close` are answered once; after them, `.close`.
    func next(errorOutput: Data) -> Action {
        lock.lock()
        defer { lock.unlock() }
        guard !done, let second, let decide else { return .close }
        switch decide(errorOutput) {
        case .wait:
            return .wait
        case .close:
            done = true
            return .close
        case .write:
            done = true
            guard let bytes = second(), !bytes.isEmpty else { return .close }
            let held = SecretBytes(bytes)
            defer { held.wipe() }
            _secondWritten = true
            return .write(held.bytes)
        }
    }
}

/// Runs a system tool: a fixed path, its arguments and exactly the environment given, with `input` on
/// standard input. Secrets go over standard input and output only, never in arguments or the
/// environment. A tool still running at the deadline is stopped (`ToolTimeout`); with a `cancellation`,
/// also when it is cancelled (`ToolCancelled`). Used for the Linux secret stores' tools, for Cisco
/// AnyConnect's sign-in (`AnyConnectSignIn`) and, with standard input in two parts (`ToolInput`), for Palo
/// Alto GlobalProtect's (`GlobalProtectSignIn`).
protocol ToolRunning {
    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data,
        timeout: TimeInterval
    ) throws -> ToolOutput

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data,
        timeout: TimeInterval, cancellation: ToolCancellation?
    ) throws -> ToolOutput

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: ToolInput,
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

    /// A runner that cannot write standard input in parts writes the first one only (the second is never made).
    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: ToolInput,
        timeout: TimeInterval, cancellation: ToolCancellation?
    ) throws -> ToolOutput {
        var first = Data(input.first)
        defer { first.wipe() }
        return try run(path, arguments, environment: environment, input: first, timeout: timeout, cancellation: cancellation)
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
        try run(path, arguments, environment: environment, input: ToolInput(Array(input)), timeout: timeout, cancellation: cancellation)
    }

    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: ToolInput,
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
            errorOutput: errorOutput.fileHandleForReading.fileDescriptor, toolInput: input)
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
        let toolInput: ToolInput
        var pending: Data
        var written = 0
        var inputOpen = true
        /// All that was handed over is written, and standard input stays open for `toolInput`'s second part.
        var awaitingInput = false
        var outputOpen = true
        var errorOpen = true
        var output = Data()
        var errorOutput = Data()
        /// More came on standard error than `SystemToolRunner.maxOutput`; the rest was dropped.
        var errorOutputCut = false

        init(input: Int32, output: Int32, errorOutput: Int32, toolInput: ToolInput) {
            self.input = input
            outputFD = output
            errorFD = errorOutput
            self.toolInput = toolInput
            pending = Data(toolInput.first)
            for fd in [input, output, errorOutput] { _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) }
            if pending.isEmpty { pendingWritten() }
        }

        /// `cancellation`: also returns once it is cancelled (checked at least every quarter second).
        mutating func pump(until deadline: Date, cancellation: ToolCancellation? = nil) {
            var buffer = [UInt8](repeating: 0, count: 16 * 1024)
            defer { _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            while outputOpen || errorOpen {
                if cancellation?.isCancelled == true { return }
                if inputOpen && awaitingInput { askForInput() }
                let remaining = deadline.timeIntervalSinceNow
                guard remaining > 0 else { return }
                // A second part may wait for the time as well as for standard error: asked at least this often.
                let slice: TimeInterval = cancellation == nil && !(inputOpen && awaitingInput) ? 1 : 0.25
                var fds: [pollfd] = []
                if inputOpen && !awaitingInput { fds.append(pollfd(fd: input, events: Int16(POLLOUT), revents: 0)) }
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
            guard written < pending.count else { return pendingWritten() }
            let n = pending.withUnsafeBytes { raw in
                POSIXSocket.write(input, raw.baseAddress! + written, raw.count - written)
            }
            if n > 0 {
                written += n
                if written == pending.count { pendingWritten() }
            } else if n < 0 && errno != EAGAIN && errno != EINTR {
                closeInput()  // the tool closed its input (exited early): the rest is not needed
            }
        }

        /// All that was handed over is written: wait for the second part while there may be one, else close.
        private mutating func pendingWritten() {
            if toolInput.hasSecondPart {
                awaitingInput = true
            } else {
                closeInput()
            }
        }

        /// Asks `toolInput` what follows, from standard error so far.
        private mutating func askForInput() {
            switch toolInput.next(errorOutput: errorOutput) {
            case .wait:
                break
            case .close:
                awaitingInput = false
                closeInput()
            case .write(var bytes):
                pending.append(contentsOf: bytes)
                bytes.wipe()
                awaitingInput = false
            }
        }

        /// Ends standard input: the tool reads end of file.
        private mutating func closeInput() {
            guard inputOpen else { return }
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
