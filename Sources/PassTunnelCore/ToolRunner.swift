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

/// The tool did not finish within `seconds` and was stopped.
struct ToolTimeout: Error, Equatable {
    var seconds: Int
}

/// Runs a system tool for a secret store: a fixed path, its arguments and exactly the environment
/// given, with `input` on standard input. Secrets go over standard input and output only, never in
/// arguments or the environment. A tool still running at the deadline is stopped (`ToolTimeout`).
protocol ToolRunning {
    func run(
        _ path: String, _ arguments: [String], environment: [String: String], input: Data,
        timeout: TimeInterval
    ) throws -> ToolOutput
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
        streams.pump(until: deadline)

        let remaining = deadline.timeIntervalSinceNow
        if remaining <= 0 || exited.wait(timeout: .now() + remaining) == .timedOut {
            process.terminate()
            if exited.wait(timeout: .now() + 1) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                _ = exited.wait(timeout: .now() + 1)
            }
            throw ToolTimeout(seconds: Int(timeout.rounded(.up)))
        }
        let status =
            process.terminationReason == .uncaughtSignal
            ? 128 + process.terminationStatus
            : process.terminationStatus
        return ToolOutput(status: status, output: streams.output, errorOutput: streams.errorOutput)
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

        init(input: Int32, output: Int32, errorOutput: Int32, pending: Data) {
            self.input = input
            outputFD = output
            errorFD = errorOutput
            self.pending = pending
            for fd in [input, output, errorOutput] { _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) }
            if pending.isEmpty { closeInput() }
        }

        mutating func pump(until deadline: Date) {
            var buffer = [UInt8](repeating: 0, count: 16 * 1024)
            defer { _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            while outputOpen || errorOpen {
                let remaining = deadline.timeIntervalSinceNow
                guard remaining > 0 else { return }
                var fds: [pollfd] = []
                if inputOpen { fds.append(pollfd(fd: input, events: Int16(POLLOUT), revents: 0)) }
                if outputOpen { fds.append(pollfd(fd: outputFD, events: Int16(POLLIN), revents: 0)) }
                if errorOpen { fds.append(pollfd(fd: errorFD, events: Int16(POLLIN), revents: 0)) }
                let rc = poll(&fds, nfds_t(fds.count), Int32(min(remaining * 1000, 1000).rounded(.up)))
                if rc < 0 && errno != EINTR { return }
                guard rc > 0 else { continue }
                for entry in fds where entry.revents != 0 {
                    if entry.fd == input {
                        writeInput()
                    } else if entry.fd == outputFD {
                        if !read(outputFD, into: &output, buffer: &buffer) { outputOpen = false }
                    } else if !read(errorFD, into: &errorOutput, buffer: &buffer) {
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
        private func read(_ fd: Int32, into data: inout Data, buffer: inout [UInt8]) -> Bool {
            let n = buffer.withUnsafeMutableBytes { raw -> Int in
                #if canImport(Darwin)
                Darwin.read(fd, raw.baseAddress, raw.count)
                #else
                Glibc.read(fd, raw.baseAddress, raw.count)
                #endif
            }
            if n > 0 {
                if data.count < SystemToolRunner.maxOutput {
                    data.append(contentsOf: buffer[0..<min(n, SystemToolRunner.maxOutput - data.count)])
                }
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
