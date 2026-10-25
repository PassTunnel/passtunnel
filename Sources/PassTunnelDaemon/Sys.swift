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

    struct SpawnFailure: Error, Equatable, CustomStringConvertible {
        let code: Int32
        var description: String { "Could not launch the VPN tool: \(String(cString: strerror(code)))" }
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
        if rc == 0, let workingDirectory { rc = posix_spawn_file_actions_addchdir_np(&actions, workingDirectory) }
        if rc == 0 { rc = posix_spawn_file_actions_addclosefrom_np(&actions, 3) }
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
