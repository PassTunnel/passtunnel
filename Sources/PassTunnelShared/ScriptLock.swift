import Foundation

/// The lock OpenVPN's macOS `dns-updown` serialises its runs with (script lines 29–44: `shlock -f
/// /var/lock/openvpn-dns-updown.lock -p $$`, ten tries 0.2 s apart), taken by the helper the same way around a
/// check of a session's DNS (`OpenVPNDNSKeeper`), so that it never reads and writes in the middle of another
/// session's dns-up or dns-down. `shlock`'s protocol: the holder's pid as text in the lock file, made by linking a
/// file that already holds it; a lock whose pid is no process is stale and may be removed.
///
/// `/var/lock` is world-writable (the script makes it 1777), so anyone can put something there: nothing in it is
/// followed, a lock that is not a regular file of at most a few bytes with a decimal pid is someone's (never
/// removed, waited for), and the wait is bounded: a lock that stays taken is a failed try, never a hang.
public enum ScriptLock {
    public static let scriptPath = "/var/lock/openvpn-dns-updown.lock"

    /// A lock this process holds; `release` (or the end of its life) removes the lock file, only while it is
    /// still the one it made.
    public final class Held {
        let path: String?
        let device: dev_t
        let inode: ino_t
        private var released = false

        init(path: String?, device: dev_t = 0, inode: ino_t = 0) {
            self.path = path
            self.device = device
            self.inode = inode
        }

        public func release() {
            guard !released, let path else { return }
            released = true
            var st = stat()
            if lstat(path, &st) == 0, st.st_dev == device, st.st_ino == inode { unlink(path) }
        }

        deinit { release() }
    }

    /// Takes the lock at `path` for `pid`, trying until `wait` has passed; nil when it stays taken (or the
    /// directory is not a real directory). Without the directory, no run of the script ever took the lock (it
    /// makes the directory first), and none is needed: a held lock with no file.
    public static func acquire(
        path: String = scriptPath, pid: pid_t = getpid(), wait: TimeInterval, now: () -> Date = Date.init,
        pause: (TimeInterval) -> Void = { usleep(useconds_t($0 * 1_000_000)) }
    ) -> Held? {
        let dir = (path as NSString).deletingLastPathComponent
        var st = stat()
        guard lstat(dir, &st) == 0 else { return errno == ENOENT ? Held(path: nil) : nil }
        guard (st.st_mode & S_IFMT) == S_IFDIR else { return nil }
        let deadline = now().addingTimeInterval(wait)
        let temp = dir + "/.passtunnel-shlock.\(pid)"
        defer { unlink(temp) }
        while true {
            if let held = tryOnce(path: path, temp: temp, pid: pid) { return held }
            if now() >= deadline { return nil }
            pause(0.1)
        }
    }

    static func tryOnce(path: String, temp: String, pid: pid_t) -> Held? {
        // A temporary file that holds the pid: anything of that name is removed first (never followed).
        unlink(temp)
        let fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard fd >= 0 else { return nil }
        let text = Array("\(pid)\n".utf8)
        let written = text.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        close(fd)
        guard written == text.count else { return nil }
        if link(temp, path) == 0 {
            var st = stat()
            guard lstat(path, &st) == 0 else { return nil }
            return Held(path: path, device: st.st_dev, inode: st.st_ino)
        }
        guard errno == EEXIST else { return nil }
        // Taken: removed only when it is a sound lock of a process that is gone, and still that file.
        guard let holder = holder(path), holder.pid != pid, kill(holder.pid, 0) != 0, errno == ESRCH else { return nil }
        var st = stat()
        if lstat(path, &st) == 0, st.st_dev == holder.device, st.st_ino == holder.inode { unlink(path) }
        return nil
    }

    /// The pid a lock file names, with the file's identity; nil unless it is a regular file of at most 32 bytes
    /// holding a decimal pid above 0 (and a line break).
    static func holder(_ path: String) -> (pid: pid_t, device: dev_t, inode: ino_t)? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size <= 32 else { return nil }
        var bytes = [UInt8](repeating: 0, count: 33)
        let n = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        guard n > 0, n <= 32 else { return nil }
        let text = String(decoding: bytes[..<n], as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...10).contains(text.count), text.allSatisfy({ $0.isASCII && $0.isNumber }), let pid = pid_t(text), pid > 0 else {
            return nil
        }
        return (pid, st.st_dev, st.st_ino)
    }
}
