// macOS only: the suspended, signature-checked launch (and Darwin's posix_spawn extensions).
#if os(macOS)
import Foundation

/// Checks the code of a started process that has not run yet (see `Spawner.spawnVerified`).
public protocol LaunchVerifier {
    /// Throws unless process `pid`, started from `executable`, runs acceptable code.
    func verify(pid: pid_t, executable: String) throws
}

/// A code-signing requirement checked against what the kernel loaded (`CodeSignature.verify(pid:)`),
/// then the cdhash of that code against `cdhashes` (`PinnedTools`).
public struct RequirementVerifier: LaunchVerifier {
    public let requirement: String
    /// The cdhashes the started code must have one of; nil: any code that satisfies `requirement`.
    public let cdhashes: Set<String>?
    /// Checks `requirement` on the process and returns its cdhash (replaced in tests).
    let validate: (_ pid: pid_t, _ path: String, _ requirement: String) throws -> String

    public init(requirement: String, cdhashes: Set<String>? = nil) {
        self.init(requirement: requirement, cdhashes: cdhashes, validate: CodeSignature.verify(pid:path:requirement:))
    }

    init(
        requirement: String, cdhashes: Set<String>?,
        validate: @escaping (_ pid: pid_t, _ path: String, _ requirement: String) throws -> String
    ) {
        self.requirement = requirement
        self.cdhashes = cdhashes
        self.validate = validate
    }

    public func verify(pid: pid_t, executable: String) throws {
        let cdhash = try validate(pid, executable, requirement)
        try PinnedTools.check((executable as NSString).lastPathComponent, cdhash: cdhash, allowed: cdhashes)
    }
}

/// Starts the VPN tools for the helper.
public enum Spawner {
    public struct Failure: Error, Equatable, CustomStringConvertible {
        public let code: Int32
        public var description: String { "Could not launch the VPN tool: \(String(cString: strerror(code)))" }
    }

    /// posix_spawn in a new process group, stdin from /dev/null, stdout+stderr to `outputFD`,
    /// default signal handlers, no inherited descriptors. `suspended`: the process is created stopped
    /// before its first instruction and runs only after SIGCONT.
    public static func spawn(
        executable: String, arguments: [String], environment: [String],
        workingDirectory: String, outputFD: Int32, suspended: Bool = false
    ) throws -> pid_t {
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_adddup2(&actions, outputFD, 1)
        posix_spawn_file_actions_adddup2(&actions, outputFD, 2)
        posix_spawn_file_actions_addchdir_np(&actions, workingDirectory)

        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }
        var flags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT
        if suspended { flags |= POSIX_SPAWN_START_SUSPENDED }
        posix_spawnattr_setflags(&attr, Int16(flags))
        posix_spawnattr_setpgroup(&attr, 0)
        var all = sigset_t(), none = sigset_t()
        sigfillset(&all)
        sigemptyset(&none)
        posix_spawnattr_setsigdefault(&attr, &all)
        posix_spawnattr_setsigmask(&attr, &none)

        let argv = ([executable] + arguments).map { strdup($0) } + [nil]
        let envp = environment.map { strdup($0) } + [nil]
        defer {
            argv.forEach { free($0) }
            envp.forEach { free($0) }
        }
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, executable, &actions, &attr, argv, envp)
        guard rc == 0 else { throw Failure(code: rc) }
        return pid
    }

    /// `spawn`, but the process starts suspended and only runs once `verifier` accepted the code the
    /// kernel actually loaded. Checking the file before the spawn alone is not enough: the path is
    /// opened again by posix_spawn, and whoever can write the app bundle could swap the file in between.
    /// If the check fails, the process is killed and reaped before it ran, and the error is rethrown.
    public static func spawnVerified(
        executable: String, arguments: [String], environment: [String],
        workingDirectory: String, outputFD: Int32,
        verifier: LaunchVerifier
    ) throws -> pid_t {
        let pid = try spawn(
            executable: executable, arguments: arguments, environment: environment,
            workingDirectory: workingDirectory, outputFD: outputFD, suspended: true)
        do {
            try verifier.verify(pid: pid, executable: executable)
        } catch {
            killAndReap(pid)
            throw error
        }
        guard kill(pid, SIGCONT) == 0 else {
            let err = errno
            killAndReap(pid)
            throw Failure(code: err)
        }
        return pid
    }

    /// SIGKILL works on a suspended process; our unreaped child cannot be a recycled pid.
    static func killAndReap(_ pid: pid_t) {
        kill(pid, SIGKILL)
        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1, errno == EINTR {}
    }
}
#endif
