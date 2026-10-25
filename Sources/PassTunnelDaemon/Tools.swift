import Foundation
import PassTunnelShared

/// A file root may execute: every component of its real path owned by root and not writable by group
/// or others, none a symbolic link, and the file itself a regular file. Then only root could have
/// replaced it, before or after the check. Used for the VPN tools and for the daemon's own executable.
public enum TrustedPath {
    public enum Failure: Error, Equatable, CustomStringConvertible {
        case missing(String)
        case notAbsolute(String)
        case symlink(String)
        case wrongOwner(String, uid_t)
        case writableByOthers(String)
        case notADirectory(String)
        case notARegularFile(String)

        public var description: String {
            switch self {
            case .missing(let p): return "\(p) does not exist."
            case .notAbsolute(let p): return "\(p) is not an absolute path."
            case .symlink(let p): return "\(p) is a symbolic link."
            case .wrongOwner(let p, let uid): return "\(p) is owned by uid \(uid), not by root."
            case .writableByOthers(let p): return "\(p) is writable by its group or by others."
            case .notADirectory(let p): return "\(p) is not a directory."
            case .notARegularFile(let p): return "\(p) is not a regular file."
            }
        }
    }

    /// Checks `path`, which must already be resolved (`realpath`). `owner` is root except in tests,
    /// which also start at a `base` of their own instead of `/`.
    public static func check(_ path: String, owner: uid_t = 0, base: String = "/") throws {
        guard path.hasPrefix("/"), !path.utf8.contains(0) else { throw Failure.notAbsolute(path) }
        var current = ""
        var components = ["/"]
        for part in path.split(separator: "/", omittingEmptySubsequences: true) {
            current += "/" + part
            components.append(current)
        }
        if base != "/" {
            let root = base.hasSuffix("/") ? String(base.dropLast()) : base
            components = components.filter { $0 == root || $0.hasPrefix(root + "/") }
            guard !components.isEmpty else { throw Failure.notAbsolute(path) }
        }
        for (index, component) in components.enumerated() {
            var st = stat()
            guard lstat(component, &st) == 0 else { throw Failure.missing(component) }
            let type = st.st_mode & S_IFMT
            if type == S_IFLNK { throw Failure.symlink(component) }
            guard st.st_uid == owner else { throw Failure.wrongOwner(component, st.st_uid) }
            guard st.st_mode & (S_IWGRP | S_IWOTH) == 0 else { throw Failure.writableByOthers(component) }
            if index == components.count - 1 {
                guard type == S_IFREG else { throw Failure.notARegularFile(component) }
            } else {
                guard type == S_IFDIR else { throw Failure.notADirectory(component) }
            }
        }
    }
}

/// A tool version, compared numerically (`2.6.10` > `2.6.9`). Pre-release suffixes (`2.7_rc2`) count
/// as the release they lead to.
public struct ToolVersion: Comparable, CustomStringConvertible, Sendable {
    public let major: Int
    public let minor: Int
    public let patch: Int

    public init(_ major: Int, _ minor: Int, _ patch: Int = 0) {
        self.major = major
        self.minor = minor
        self.patch = patch
    }

    /// The leading `major.minor[.patch]` of `text` (`2.6.9`, `2.7_rc2`, `1.21.0-dirty`).
    public init?(parsing text: Substring) {
        var numbers: [Int] = []
        var digits = ""
        for c in text {
            if c.isASCII, c.isNumber {
                digits.append(c)
                guard digits.count <= 6 else { return nil }
            } else if c == ".", !digits.isEmpty, numbers.count < 2 {
                numbers.append(Int(digits)!)
                digits = ""
            } else {
                break
            }
        }
        if !digits.isEmpty { numbers.append(Int(digits)!) }
        guard numbers.count >= 2 else { return nil }
        self.init(numbers[0], numbers[1], numbers.count > 2 ? numbers[2] : 0)
    }

    public static func < (a: ToolVersion, b: ToolVersion) -> Bool {
        (a.major, a.minor, a.patch) < (b.major, b.minor, b.patch)
    }

    public var description: String { "\(major).\(minor).\(patch)" }
}

/// A distribution tool the daemon runs: where it may be, which version it needs and how its version
/// is read. OpenVPN only so far; openfortivpn (1.21, `/usr/bin/openfortivpn`) and pppd
/// (`/usr/sbin/pppd`, checked, run by openfortivpn) follow with FortiGate support.
public struct ToolSpec {
    public let name: String
    /// Fixed paths; the first that exists is used.
    public let candidates: [String]
    public let minimum: ToolVersion
    public let package: String
    public let versionArguments: [String]
    public let parseVersion: (String) -> ToolVersion?

    public static let openvpn = ToolSpec(
        name: "OpenVPN", candidates: ["/usr/sbin/openvpn", "/usr/bin/openvpn"], minimum: ToolVersion(2, 6, 0),
        package: "openvpn", versionArguments: ["--version"], parseVersion: ToolSpec.openVPNVersion)

    /// The version on the first line of `openvpn --version`: "OpenVPN 2.6.9 x86_64-pc-linux-gnu […]".
    public static func openVPNVersion(_ output: String) -> ToolVersion? {
        for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
            let words = line.split(separator: " ", omittingEmptySubsequences: true)
            if words.count >= 2, words[0] == "OpenVPN" { return ToolVersion(parsing: words[1]) }
        }
        return nil
    }
}

/// A checked tool: its real path and version.
public struct ResolvedTool: Equatable, Sendable {
    public let path: String
    public let version: ToolVersion

    public init(path: String, version: ToolVersion) {
        self.path = path
        self.version = version
    }
}

public enum ToolFailure: Error, Equatable, CustomStringConvertible {
    case notInstalled(name: String, candidates: [String], package: String, minimum: ToolVersion)
    case untrusted(name: String, path: String, reason: String)
    case unknownVersion(name: String, path: String)
    case tooOld(name: String, version: ToolVersion, minimum: ToolVersion, package: String)

    public var description: String {
        switch self {
        case .notInstalled(let name, let candidates, let package, let minimum):
            return "\(name) is not installed (none of \(candidates.joined(separator: ", ")) exists). "
                + "Install the distribution's \(package) package, version \(minimum.major).\(minimum.minor) or later."
        case .untrusted(let name, let path, let reason):
            return "Refusing to run \(name) from \(path): \(reason)"
        case .unknownVersion(let name, let path):
            return "Could not tell the version of \(name) at \(path)."
        case .tooOld(let name, let version, let minimum, let package):
            return "\(name) \(version) is too old: PassTunnel needs \(minimum) or later. Update the \(package) package."
        }
    }
}

/// Finds and checks a tool before every start; replaced in tests.
public protocol ToolResolving {
    func resolve(_ spec: ToolSpec) throws -> ResolvedTool
}

/// The system's tools: the first existing candidate, resolved with `realpath` once, then that real
/// path checked (`TrustedPath`) and the version read by running it with the fixed environment.
public struct SystemTools: ToolResolving {
    public var owner: uid_t
    public var base: String
    /// Runs the tool for its version output; replaced in tests.
    public var versionOutput: (String, [String]) -> String?

    public init(owner: uid_t = 0, base: String = "/",
                versionOutput: @escaping (String, [String]) -> String? = { path, args in
                    ToolRunner.output(of: path, arguments: args)
                }) {
        self.owner = owner
        self.base = base
        self.versionOutput = versionOutput
    }

    public func resolve(_ spec: ToolSpec) throws -> ResolvedTool {
        guard let candidate = spec.candidates.first(where: { access($0, F_OK) == 0 }) else {
            throw ToolFailure.notInstalled(name: spec.name, candidates: spec.candidates, package: spec.package,
                                           minimum: spec.minimum)
        }
        guard let real = HelperCore.realPath(candidate) else {
            throw ToolFailure.untrusted(name: spec.name, path: candidate, reason: "its path cannot be resolved.")
        }
        do {
            try TrustedPath.check(real, owner: owner, base: base)
        } catch {
            throw ToolFailure.untrusted(name: spec.name, path: real, reason: String(describing: error))
        }
        guard let output = versionOutput(real, spec.versionArguments), let version = spec.parseVersion(output) else {
            throw ToolFailure.unknownVersion(name: spec.name, path: real)
        }
        guard version >= spec.minimum else {
            throw ToolFailure.tooOld(name: spec.name, version: version, minimum: spec.minimum, package: spec.package)
        }
        return ResolvedTool(path: real, version: version)
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
    public static func run(_ path: String, arguments: [String], input: Data? = nil,
                           timeout: TimeInterval = timeout) -> Result? {
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
            pid = try Sys.spawn(executable: path, arguments: arguments, environment: HelperCore.fixedEnvironment,
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
            if rc == 0, info.si_signo == SIGCHLD { break }      // exited (Linux leaves it 0 while running)
            if rc != 0, errno != EINTR { break }
            usleep(10_000)
        }
        kill(-pid, SIGKILL)
        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1, errno == EINTR {}
        let signal = status & 0x7F
        return Result(status: signal == 0 ? (status >> 8) & 0xFF : 128 + signal,
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
