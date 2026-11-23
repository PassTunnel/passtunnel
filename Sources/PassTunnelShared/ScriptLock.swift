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
    /// still the one it made: the same device and inode, and still a regular file that names this process. An inode
    /// number alone is no proof: a file system may give a new file the number of one just removed (Linux file
    /// systems do; on the Mac's APFS new files got new numbers whenever we looked, but nothing promises it).
    public final class Held {
        let path: String?
        let device: dev_t
        let inode: ino_t
        let pid: pid_t
        private var released = false

        init(path: String?, device: dev_t = 0, inode: ino_t = 0, pid: pid_t = 0) {
            self.path = path
            self.device = device
            self.inode = inode
            self.pid = pid
        }

        public func release() {
            guard !released, let path else { return }
            released = true
            guard let entry = Entry.at(path), entry.kind == S_IFREG, entry.device == device, entry.inode == inode,
                entry.pid == pid
            else { return }
            unlink(path)
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

    /// `beforeRemoving`: the tests' way in between the reading of a stale lock and its removal.
    static func tryOnce(path: String, temp: String, pid: pid_t, now: Date, beforeRemoving: () -> Void = {}) -> Held? {
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
            return Held(path: path, device: st.st_dev, inode: st.st_ino, pid: pid)
        }
        guard errno == EEXIST else { return nil }
        // Taken. Valid while it names a running process; otherwise removed as `shlock` removes it, once its status
        // did not change in this second, and only while it is still the entry that was read: the same device, inode,
        // change time (to the nanosecond), kind and first bytes, read again right before the removal. The next try
        // takes it. Removal is by name, so a window stays between that read and the unlink (docs/ARCHITECTURE.md).
        guard let first = Entry.at(path), first.kind != S_IFDIR else { return nil }
        if let holder = first.pid, holder == pid || kill(holder, 0) == 0 || errno == EPERM { return nil }
        guard first.changeSeconds < Int(now.timeIntervalSince1970.rounded(.down)) else { return nil }
        beforeRemoving()
        if Entry.at(path) == first { unlink(path) }
        return nil
    }

    /// What is at the lock path, read without following: its identity, its change time, its kind and, for a
    /// regular file, its first 32 bytes. Two reads that give equal entries saw the same, unchanged lock; equal inode
    /// numbers alone do not show that.
    struct Entry: Equatable {
        var device: dev_t
        var inode: ino_t
        var changeSeconds: Int
        var changeNanoseconds: Int
        var kind: mode_t
        var bytes: [UInt8]?

        static func at(_ path: String) -> Entry? {
            var st = stat()
            guard lstat(path, &st) == 0 else { return nil }
            let kind = st.st_mode & S_IFMT
            var bytes: [UInt8]?
            if kind == S_IFREG {
                let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard fd >= 0 else { return nil }
                defer { close(fd) }
                var opened = stat()
                guard fstat(fd, &opened) == 0, (opened.st_mode & S_IFMT) == S_IFREG, opened.st_dev == st.st_dev,
                    opened.st_ino == st.st_ino
                else { return nil }
                var buffer = [UInt8](repeating: 0, count: 32)
                let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
                guard n >= 0 else { return nil }
                bytes = Array(buffer[..<n])
            }
            return Entry(
                device: st.st_dev, inode: st.st_ino, changeSeconds: ScriptLock.changeSeconds(st),
                changeNanoseconds: ScriptLock.changeNanoseconds(st), kind: kind, bytes: bytes)
        }

        /// The pid it names: a regular file whose first 32 bytes are a decimal pid above 0, with white space around it
        /// at most; nil for anything else.
        var pid: pid_t? {
            guard let bytes, !bytes.isEmpty else { return nil }
            let text = String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            guard (1...10).contains(text.count), text.allSatisfy({ $0.isASCII && $0.isNumber }), let pid = pid_t(text), pid > 0 else {
                return nil
            }
            return pid
        }
    }

    static func changeNanoseconds(_ st: stat) -> Int {
        #if os(Linux)
        return Int(st.st_ctim.tv_nsec)
        #else
        return Int(st.st_ctimespec.tv_nsec)
        #endif
    }

    /// When the entry's status last changed, in whole seconds.
    static func changeSeconds(_ st: stat) -> Int {
        #if os(Linux)
        return Int(st.st_ctim.tv_sec)
        #else
        return Int(st.st_ctimespec.tv_sec)
        #endif
    }
}
