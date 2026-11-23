import Foundation

/// The lock OpenVPN's macOS `dns-updown` serialises its runs with (script lines 29–44: `shlock -f
/// /var/lock/openvpn-dns-updown.lock -p $$`, ten tries 0.2 s apart), taken by the helper the same way around a
/// check of a session's DNS (`OpenVPNDNSKeeper`), so that it never reads and writes in the middle of another
/// session's dns-up or dns-down.
///
/// `shlock`'s rules, as `/usr/bin/shlock` on macOS keeps them (run on files of a scratch directory: a lock it made
/// holds its pid as text; an existing lock is valid while it names a process; one whose content is no pid above 0
/// (words, nothing, `0`, `-5`) or names a process that is gone is invalid, and is removed and taken, unless its
/// status changed (ctime) in the very second `shlock` looks at it, when it may still be being written: then it is
/// left and the try fails; a second later it is removed). The helper keeps the same rules, so a lock someone
/// writes junk into blocks it no longer than it blocks the script.
///
/// `/var/lock` is world-writable (the script makes it 1777), so anyone can put something there: nothing in it is
/// followed (a link or a fifo where the lock goes is invalid content, and only its name is removed; `shlock` itself
/// removes a link that way but waits on a fifo, as it opens without `O_NONBLOCK`: the script's own exposure), a
/// directory there is never removed, and the wait is bounded.
///
/// Limit of the protocol: a stale lock is removed by name. The helper checks that the entry is still the one it
/// read; `shlock` does not, so a `shlock` that read a stale lock just before the helper replaced it removes the
/// helper's fresh lock and links its own, and both hold it. A stale lock exists only when the script was killed
/// while it held it; the helper's write is then guarded only by reading the key again right before it and back
/// after it (`OpenVPNDNS.restore`).
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
            if let held = tryOnce(path: path, temp: temp, pid: pid, now: now()) { return held }
            if now() >= deadline { return nil }
            pause(0.1)
        }
    }

    static func tryOnce(path: String, temp: String, pid: pid_t, now: Date) -> Held? {
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
        // Taken. Valid while it names a running process; otherwise removed as `shlock` removes it, once its status
        // did not change in this second, and only while it is still that entry. The next try takes it.
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) != S_IFDIR else { return nil }
        if let holder = holder(path), holder == pid || kill(holder, 0) == 0 || errno == EPERM { return nil }
        guard changeSeconds(st) < Int(now.timeIntervalSince1970.rounded(.down)) else { return nil }
        var again = stat()
        if lstat(path, &again) == 0, again.st_dev == st.st_dev, again.st_ino == st.st_ino { unlink(path) }
        return nil
    }

    /// When the entry's status last changed, in whole seconds.
    static func changeSeconds(_ st: stat) -> Int {
        #if os(Linux)
        return Int(st.st_ctim.tv_sec)
        #else
        return Int(st.st_ctimespec.tv_sec)
        #endif
    }

    /// The pid a lock file names: nil unless it is a regular file (not followed) whose first 32 bytes are a
    /// decimal pid above 0, with white space around it at most.
    static func holder(_ path: String) -> pid_t? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return nil }
        var bytes = [UInt8](repeating: 0, count: 32)
        let n = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        guard n > 0 else { return nil }
        let text = String(decoding: bytes[..<n], as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...10).contains(text.count), text.allSatisfy({ $0.isASCII && $0.isNumber }), let pid = pid_t(text), pid > 0 else {
            return nil
        }
        return pid
    }
}
