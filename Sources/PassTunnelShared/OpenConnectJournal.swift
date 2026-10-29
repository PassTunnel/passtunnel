import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// The session's record on disk (`network`, 0600, root): `OpenConnectRecord` kept in memory and written one
/// entry at a time, each entry one `write` of one line appended to the file, so a hook killed at any point
/// leaves a record that reads back (docs/ARCHITECTURE.md, "The hook", step 4). Nothing is ever written that
/// `OpenConnectRecord.append` refused.
public final class OpenConnectJournal {
    public private(set) var record: OpenConnectRecord
    public let path: String
    private var fd: Int32
    private var size: Int

    /// A record larger than this is compacted when it is opened (a long session whose routes followed the
    /// gateway many times).
    static let compactAbove = 1 << 20

    private init(record: OpenConnectRecord, path: String, fd: Int32, size: Int) {
        self.record = record
        self.path = path
        self.fd = fd
        self.size = size
    }

    deinit { close(fd) }

    public static func path(runDir: String) -> String { runDir + "/" + OpenConnectRecord.fileName }

    /// Whether the session directory holds a record (whatever its state).
    public static func exists(runDir: String) -> Bool {
        var st = stat()
        return lstat(path(runDir: runDir), &st) == 0
    }

    /// A new, empty record for `interface`; throws if one exists already.
    public static func create(runDir: String, interface: String) throws -> OpenConnectJournal {
        guard let record = OpenConnectRecord(interface: interface) else { throw OpenConnectRecord.Failure.outOfOrder("interface " + interface) }
        let path = path(runDir: runDir)
        let text = try record.text()
        try HelperCore.writeNewFile(path, Data(text.utf8), mode: 0o600)
        return try OpenConnectJournal(record: record, path: path, fd: openForAppend(path), size: text.utf8.count)
    }

    /// The record in `runDir`: nil when there is none; throws when it cannot be read or is not a record
    /// `OpenConnectRecord.parse` takes. A large one is compacted first (written next to it, then renamed).
    public static func open(runDir: String) throws -> OpenConnectJournal? {
        let path = path(runDir: runDir)
        guard let record = try read(path) else { return nil }
        var text = try record.text()
        var current = record
        if text.utf8.count > compactAbove {
            current = try record.compacted()
            text = try current.text()
            try replace(path, with: text)
        }
        return try OpenConnectJournal(record: current, path: path, fd: openForAppend(path), size: text.utf8.count)
    }

    /// The record at `path`, read only: nil when there is none.
    public static func read(_ path: String) throws -> OpenConnectRecord? {
        var st = stat()
        guard lstat(path, &st) == 0 else {
            if errno == ENOENT { return nil }
            throw HelperCore.Failure.system("stat \(path)", errno)
        }
        let data = try HelperCore.readOwnFile(path, maxBytes: OpenConnectRecord.maxBytes)
        guard let text = String(data: data, encoding: .utf8), let record = OpenConnectRecord.parse(text) else {
            throw HelperCore.Failure.unsafeFile(OpenConnectRecord.fileName)
        }
        return record
    }

    /// The latest status of the record in `runDir`; nil when there is none or it cannot be read.
    public static func status(runDir: String) -> OpenConnectRecord.Status? {
        (try? read(path(runDir: runDir)))??.status
    }

    /// Adds `entry` to the record and to the file. The entry must be one `OpenConnectRecord.append` takes;
    /// the file is compacted when it would grow past `OpenConnectRecord.maxBytes`.
    public func append(_ entry: OpenConnectRecord.Entry) throws {
        var next = record
        try next.append(entry)
        let line = entry.text + "\n"
        try HelperCore.checkLines(line, count: 1, file: OpenConnectRecord.fileName)
        if size + line.utf8.count > OpenConnectRecord.maxBytes {
            let compact = try next.compacted()
            let text = try compact.text()
            try Self.replace(path, with: text)
            let newFD = try Self.openForAppend(path)
            close(fd)
            fd = newFD
            size = text.utf8.count
            record = compact
            return
        }
        try Self.write(fd, line, path: path)
        size += line.utf8.count
        record = next
    }

    /// `OpenConnectRecord.beginRevert(sparing:)`, with every entry it adds written.
    public func beginRevert(sparing others: [OpenConnectRecord]) throws -> [OpenConnectPlan.Change] {
        var copy = record
        let before = copy.entries.count
        let undo = try copy.beginRevert(sparing: others)
        for entry in copy.entries[before...] { try append(entry) }
        return undo
    }

    // MARK: Files

    static func openForAppend(_ path: String) throws -> Int32 {
        let fd = posixOpen(path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw HelperCore.Failure.system("open \(path)", errno) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == geteuid(), st.st_nlink == 1 else {
            close(fd)
            throw HelperCore.Failure.unsafeFile(OpenConnectRecord.fileName)
        }
        return fd
    }

    static func write(_ fd: Int32, _ text: String, path: String) throws {
        let bytes = Array(text.utf8)
        var off = 0
        while off < bytes.count {
            let n = bytes.withUnsafeBytes { posixWrite(fd, $0.baseAddress! + off, $0.count - off) }
            if n < 0 {
                if errno == EINTR { continue }
                throw HelperCore.Failure.system("write \(path)", errno)
            }
            off += n
        }
    }

    /// Replaces the file at `path` by one with `text`: written next to it, then renamed over it.
    static func replace(_ path: String, with text: String) throws {
        let temporary = path + ".new"
        HelperCore.removeEntry(temporary)
        do {
            try HelperCore.writeNewFile(temporary, Data(text.utf8), mode: 0o600)
            guard rename(temporary, path) == 0 else { throw HelperCore.Failure.system("rename \(temporary)", errno) }
        } catch {
            HelperCore.removeEntry(temporary)
            throw error
        }
    }
}

/// The lock every hook run and every revert of the helper hold while they read or change the network of any
/// openconnect session (`<run root>/network.lock`, 0600, root): changes are made one session at a time, and a
/// revert reads the other sessions' records while none of them changes.
public final class OpenConnectLock {
    public static let fileName = "network.lock"
    private let fd: Int32

    private init(fd: Int32) { self.fd = fd }

    deinit {
        _ = flock(fd, LOCK_UN)
        close(fd)
    }

    /// Takes the lock, waiting at most until `deadline`; nil when it was not free by then or the file is
    /// not a regular, single-link file of ours.
    public static func acquire(runRoot: String, until deadline: Date, now: () -> Date = Date.init) -> OpenConnectLock? {
        let path = runRoot + "/" + fileName
        let fd = posixOpen(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return nil }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == geteuid(), st.st_nlink == 1 else {
            close(fd)
            return nil
        }
        while flock(fd, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EWOULDBLOCK || errno == EINTR, now() < deadline else {
                close(fd)
                return nil
            }
            usleep(20_000)
        }
        return OpenConnectLock(fd: fd)
    }
}

/// The two marks in a session directory around the hook (docs/ARCHITECTURE.md, "The hook", steps 5 and 7):
/// `hook`, the running hook's pid and start time, written under the lock when it starts and removed when it
/// ends; and `stopping`, set by the helper when the session stops: from then on no hook applies a change.
public enum OpenConnectMarks {
    public static let hook = "hook"
    public static let stopping = "stopping"

    /// Records the running hook: `<pid>\n<start time>\n`, replaced atomically.
    public static func setHook(runDir: String, pid: pid_t, start: ProcessStart?) throws {
        let path = runDir + "/" + hook
        try OpenConnectJournal.replace(path, with: "\(pid)\n\(start?.text ?? "")\n")
    }

    public static func clearHook(runDir: String) {
        unlink(runDir + "/" + hook)
    }

    /// The running hook's pid and start time, nil when none is recorded (or the record is not ours).
    public static func runningHook(runDir: String) -> (pid: pid_t, start: ProcessStart)? {
        guard let data = try? HelperCore.readOwnFile(runDir + "/" + hook, maxBytes: 256), let text = String(data: data, encoding: .utf8)
        else { return nil }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count == 3, lines[2].isEmpty, let pid = pid_t(lines[0]), pid > 1, let start = ProcessStart.parse(String(lines[1])) else {
            return nil
        }
        return (pid, start)
    }

    /// Marks the session as stopping (once; an existing mark stays).
    public static func setStopping(runDir: String) {
        let fd = posixOpen(runDir + "/" + stopping, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if fd >= 0 { close(fd) }
    }

    public static func isStopping(runDir: String) -> Bool {
        var st = stat()
        return lstat(runDir + "/" + stopping, &st) == 0
    }
}

// `open` and `write` are shadowed by members above; these reach the C functions.
private func posixOpen(_ path: String, _ flags: Int32, _ mode: mode_t = 0) -> Int32 {
    open(path, flags, mode)
}

private func posixWrite(_ fd: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
    write(fd, buffer, count)
}
