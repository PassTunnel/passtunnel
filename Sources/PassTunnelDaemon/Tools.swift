import Foundation
import PassTunnelShared

/// Finds and checks a tool before every start; replaced in tests.
public protocol ToolResolving {
    func resolve(_ spec: ToolSpec) throws -> ResolvedTool
    /// The CA bundle openfortivpn verifies the gateway with: its real path, checked like a tool's.
    func caBundle() throws -> String
}

/// The system's tools (`DistributionTools`): the first existing candidate, resolved with `realpath` once,
/// then that real path checked (`TrustedPath`) and the version read by running it with the fixed
/// environment.
public struct SystemTools: ToolResolving {
    public static let caBundles = DistributionTools.caBundles

    public var owner: uid_t
    public var base: String
    public var caBundles: [String]
    /// Runs the tool for its version output; replaced in tests.
    public var versionOutput: (String, [String]) -> String?

    public init(
        owner: uid_t = 0, base: String = "/", caBundles: [String] = SystemTools.caBundles,
        versionOutput: @escaping (String, [String]) -> String? = { path, args in
            ToolRunner.output(of: path, arguments: args)
        }
    ) {
        self.owner = owner
        self.base = base
        self.caBundles = caBundles
        self.versionOutput = versionOutput
    }

    /// The first existing CA bundle, resolved, then checked as a tool is: only root can have changed
    /// what openfortivpn (root) trusts.
    public func caBundle() throws -> String {
        try DistributionTools.caBundle(candidates: caBundles, owner: owner, base: base)
    }

    public func resolve(_ spec: ToolSpec) throws -> ResolvedTool {
        try DistributionTools.resolve(spec, owner: owner, base: base, versionOutput: versionOutput)
    }
}

/// Runs a checked tool briefly and collects what it prints (`openvpn --version`, `resolvectl`).
public enum ToolRunner {
    public static let timeout: TimeInterval = 5
    static let maxOutputBytes = 64 << 10
    /// Standard input given to a tool goes through a pipe, written in full before it starts.
    static let maxInputBytes = 16 << 10

    /// How a run ended: the exit status (128 + the signal for a tool killed by one, as a shell reports
    /// it) and what the tool printed on standard output and error.
    public struct Result: Equatable {
        public let status: Int32
        public let output: String
    }

    /// Standard output and error of `path arguments`, run as the tools are (`Sys.spawn`, the fixed
    /// environment), killed after `timeout`. Nil when it could not be started.
    public static func output(of path: String, arguments: [String], timeout: TimeInterval = timeout) -> String? {
        run(path, arguments: arguments, timeout: timeout)?.output
    }

    /// Runs `path arguments` as `output(of:)` does, with `input` (at most `maxInputBytes`) on standard
    /// input, and waits for it to exit until `timeout`, after which its process group is killed.
    public static func run(
        _ path: String, arguments: [String], input: Data? = nil,
        timeout: TimeInterval = timeout
    ) -> Result? {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { return nil }
        let readEnd = fds[0], writeEnd = fds[1]
        _ = fcntl(readEnd, F_SETFD, FD_CLOEXEC)
        _ = fcntl(writeEnd, F_SETFD, FD_CLOEXEC)
        defer { close(readEnd) }
        var inputFD: Int32?
        if let input {
            guard input.count <= maxInputBytes, let fd = inputPipe(input) else { close(writeEnd); return nil }
            inputFD = fd
        }
        let pid: pid_t
        do {
            pid = try Sys.spawn(
                executable: path, arguments: arguments, environment: HelperCore.fixedEnvironment,
                workingDirectory: "/", outputFD: writeEnd, inputFD: inputFD)
        } catch {
            close(writeEnd)
            inputFD.map { _ = close($0) }
            return nil
        }
        close(writeEnd)
        inputFD.map { _ = close($0) }
        let deadline = Date().addingTimeInterval(timeout)
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while data.count < maxOutputBytes {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { break }
            var p = pollfd(fd: readEnd, events: Int16(POLLIN), revents: 0)
            let r = poll(&p, 1, Int32(min(remaining * 1000 + 1, 60_000)))
            if r < 0, errno == EINTR { continue }
            guard r > 0 else { break }
            let n = read(readEnd, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { break }
            data.append(contentsOf: buffer[0..<n])
        }
        // Until it is reaped the pid (and so its process group) stays taken: waiting without reaping
        // first keeps the kill of what is left in the group from reaching anyone else.
        while deadline.timeIntervalSinceNow > 0 {
            var info = siginfo_t()
            let rc = waitid(P_PID, id_t(pid), &info, WEXITED | WNOHANG | WNOWAIT)
            if rc == 0, info.si_signo == SIGCHLD { break }  // exited (Linux leaves it 0 while running)
            if rc != 0, errno != EINTR { break }
            usleep(10_000)
        }
        kill(-pid, SIGKILL)
        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1, errno == EINTR {}
        let signal = status & 0x7F
        return Result(
            status: signal == 0 ? (status >> 8) & 0xFF : 128 + signal,
            output: String(decoding: data, as: UTF8.self))
    }

    /// The read end of a pipe that already holds all of `input` (far less than a pipe's capacity).
    private static func inputPipe(_ input: Data) -> Int32? {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { return nil }
        _ = fcntl(fds[0], F_SETFD, FD_CLOEXEC)
        _ = fcntl(fds[1], F_SETFD, FD_CLOEXEC)
        defer { close(fds[1]) }
        let bytes = [UInt8](input)
        var offset = 0
        while offset < bytes.count {
            let n = bytes.withUnsafeBytes { write(fds[1], $0.baseAddress! + offset, bytes.count - offset) }
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { close(fds[0]); return nil }
            offset += n
        }
        return fds[0]
    }
}
