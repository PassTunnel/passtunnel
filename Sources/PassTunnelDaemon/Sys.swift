import Foundation
#if canImport(Glibc)
import Glibc
#endif

/// The system calls whose Swift spelling is Glibc's: socket types, peer credentials, group lists and
/// `posix_spawn` (structs there, not pointers as on Darwin). The rest of the daemon is plain POSIX.
enum Sys {
    /// `SO_PEERPIDFD` (Linux 6.5): not in every C library's headers yet. The same value on x86_64 and
    /// aarch64 (asm-generic).
    static let soPeerPidfd: Int32 = 77

    /// A new unix stream socket, close-on-exec.
    static func unixStreamSocket() -> Int32 {
        socket(AF_UNIX, Int32(SOCK_STREAM.rawValue) | Int32(SOCK_CLOEXEC.rawValue), 0)
    }

    /// `SOCK_STREAM`, for comparing with `SO_TYPE`.
    static var streamType: Int32 { Int32(SOCK_STREAM.rawValue) }

    /// Process, user and group of the peer of a connected unix socket, as they were when it
    /// connected (`SO_PEERCRED`, `struct ucred`: pid, uid, gid).
    static func peerCredentials(_ fd: Int32) -> (pid: pid_t, uid: uid_t, gid: gid_t)? {
        var raw = [Int32](repeating: 0, count: 3)
        var length = socklen_t(MemoryLayout<Int32>.size * 3)
        guard getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &raw, &length) == 0,
              length == socklen_t(MemoryLayout<Int32>.size * 3) else { return nil }
        return (raw[0], uid_t(bitPattern: raw[1]), gid_t(bitPattern: raw[2]))
    }

    /// A pidfd of the peer (`SO_PEERPIDFD`), or nil where the kernel has none.
    static func peerPidfd(_ fd: Int32) -> Int32? {
        var pidfd: Int32 = -1
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, soPeerPidfd, &pidfd, &length) == 0, pidfd >= 0 else { return nil }
        _ = fcntl(pidfd, F_SETFD, FD_CLOEXEC)
        return pidfd
    }

    /// The process a pidfd refers to, from `/proc/self/fdinfo` (nil once it has exited).
    static func pid(ofPidfd pidfd: Int32) -> pid_t? {
        guard let text = try? String(contentsOfFile: "/proc/self/fdinfo/\(pidfd)", encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n") where line.hasPrefix("Pid:") {
            guard let pid = pid_t(line.dropFirst(4).trimmingCharacters(in: .whitespaces)), pid > 0 else { return nil }
            return pid
        }
        return nil
    }

    /// Every group of `user` in the group database, its primary group `primary` included
    /// (`getgrouplist`).
    static func groupList(user: String, primary: gid_t) -> [gid_t]? {
        var capacity: Int32 = 64
        for _ in 0..<8 {
            var groups = [gid_t](repeating: 0, count: Int(capacity))
            var count = capacity
            if getgrouplist(user, primary, &groups, &count) >= 0 {
                return Array(groups.prefix(Int(max(0, count))))
            }
            capacity = max(count, capacity * 2)
        }
        return nil
    }

    /// The group named `name` (`getgrnam_r`).
    static func groupID(named name: String) -> gid_t? {
        var entry = group()
        var result: UnsafeMutablePointer<group>?
        var buffer = [CChar](repeating: 0, count: 65536)
        guard getgrnam_r(name, &entry, &buffer, buffer.count, &result) == 0, result != nil else { return nil }
        return entry.gr_gid
    }

    /// The primary group of `uid` (`getpwuid_r`).
    static func primaryGroup(of uid: uid_t) -> gid_t? {
        var pwd = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 16384)
        guard getpwuid_r(uid, &pwd, &buffer, buffer.count, &result) == 0, result != nil else { return nil }
        return pwd.pw_gid
    }

    static func listen(_ fd: Int32, backlog: Int32) -> Int32 {
        Glibc.listen(fd, backlog)
    }

    static func connect(_ fd: Int32, _ address: UnsafePointer<sockaddr>, _ length: socklen_t) -> Int32 {
        Glibc.connect(fd, address, length)
    }

    /// `send` without SIGPIPE.
    static func send(_ fd: Int32, _ bytes: UnsafeRawPointer, _ count: Int) -> Int {
        Glibc.send(fd, bytes, count, Int32(MSG_NOSIGNAL))
    }

    /// A pipe, both ends close-on-exec (a tool gets its end through `spawn`'s `outputFD`; `spawn` closes
    /// every other descriptor in the child anyway).
    static func makePipe() throws -> (read: Int32, write: Int32) {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { throw SpawnFailure(code: errno) }
        _ = fcntl(fds[0], F_SETFD, FD_CLOEXEC)
        _ = fcntl(fds[1], F_SETFD, FD_CLOEXEC)
        return (fds[0], fds[1])
    }

    struct SpawnFailure: Error, Equatable, CustomStringConvertible {
        let code: Int32
        var description: String { "Could not launch the VPN tool: \(String(cString: strerror(code)))" }
    }

    /// glibc's `posix_spawn_file_actions_addchdir_np` (2.29) and `…_addclosefrom_np` (2.34), looked up by
    /// name: older glibc headers declare them only for `_GNU_SOURCE`, so Swift does not see them on
    /// Ubuntu 22.04 (where the release binaries are built), though its glibc has them. Nil where the C
    /// library lacks them; `spawn` then fails rather than start a tool with descriptors left open.
    private typealias AddChdir = @convention(c) (UnsafeMutablePointer<posix_spawn_file_actions_t>, UnsafePointer<CChar>) -> Int32
    private typealias AddClosefrom = @convention(c) (UnsafeMutablePointer<posix_spawn_file_actions_t>, Int32) -> Int32
    private static let addChdir: AddChdir? = libcFunction("posix_spawn_file_actions_addchdir_np")
    private static let addClosefrom: AddClosefrom? = libcFunction("posix_spawn_file_actions_addclosefrom_np")

    private static func libcFunction<Function>(_ name: String) -> Function? {
        // A null handle is glibc's RTLD_DEFAULT: the libraries the process loaded, the C library among them.
        dlsym(nil, name).map { unsafeBitCast($0, to: Function.self) }
    }

    /// glibc's `pidfd_open` and `pidfd_send_signal` (2.36), looked up by name for the same reason: nil
    /// where the C library lacks them (Ubuntu 22.04, RHEL 9); where the kernel does (before 5.3), their
    /// calls fail with `ENOSYS`.
    private typealias PidfdOpen = @convention(c) (pid_t, UInt32) -> Int32
    private typealias PidfdSendSignal = @convention(c) (Int32, Int32, UnsafeMutableRawPointer?, UInt32) -> Int32
    private static let pidfdOpenFunction: PidfdOpen? = libcFunction("pidfd_open")
    private static let pidfdSendSignalFunction: PidfdSendSignal? = libcFunction("pidfd_send_signal")
    /// `PIDFD_SIGNAL_PROCESS_GROUP` (Linux 6.9; earlier kernels refuse every flag with `EINVAL`).
    static let pidfdSignalProcessGroup: UInt32 = 1 << 2

    /// A pidfd of `pid` (close-on-exec, as every pidfd is), or nil: the process is gone, or the kernel
    /// or the C library has no pidfds.
    static func pidfdOpen(_ pid: pid_t) -> Int32? {
        guard let call = pidfdOpenFunction else { return nil }
        let fd = call(pid, 0)
        return fd >= 0 ? fd : nil
    }

    /// Sends `sig` through `pidfd`, to the process's whole group with `processGroup`; 0, or the error
    /// (`ESRCH` once the process has exited).
    static func pidfdSignal(_ pidfd: Int32, _ sig: Int32, processGroup: Bool) -> Int32 {
        guard let call = pidfdSendSignalFunction else { return ENOSYS }
        return call(pidfd, sig, nil, processGroup ? pidfdSignalProcessGroup : 0) == 0 ? 0 : errno
    }

    /// `posix_spawn` in a new process group: stdin from `inputFD` (else /dev/null), stdout and stderr to
    /// `outputFD`, every other descriptor closed, all signals at their default action, an empty signal mask.
    static func spawn(executable: String, arguments: [String], environment: [String],
                      workingDirectory: String?, outputFD: Int32, inputFD: Int32? = nil) throws -> pid_t {
        var actions = posix_spawn_file_actions_t()
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw SpawnFailure(code: ENOMEM) }
        defer { posix_spawn_file_actions_destroy(&actions) }
        var rc: Int32
        if let inputFD {
            rc = posix_spawn_file_actions_adddup2(&actions, inputFD, 0)
        } else {
            rc = posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        }
        if rc == 0 { rc = posix_spawn_file_actions_adddup2(&actions, outputFD, 1) }
        if rc == 0 { rc = posix_spawn_file_actions_adddup2(&actions, outputFD, 2) }
        if rc == 0, let workingDirectory {
            guard let addChdir = Self.addChdir else { throw SpawnFailure(code: ENOSYS) }
            rc = workingDirectory.withCString { addChdir(&actions, $0) }
        }
        if rc == 0 {
            guard let addClosefrom = Self.addClosefrom else { throw SpawnFailure(code: ENOSYS) }
            rc = addClosefrom(&actions, 3)
        }
        guard rc == 0 else { throw SpawnFailure(code: rc) }

        var attr = posix_spawnattr_t()
        guard posix_spawnattr_init(&attr) == 0 else { throw SpawnFailure(code: ENOMEM) }
        defer { posix_spawnattr_destroy(&attr) }
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK))
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
        rc = posix_spawn(&pid, executable, &actions, &attr, argv, envp)
        guard rc == 0 else { throw SpawnFailure(code: rc) }
        return pid
    }
}
