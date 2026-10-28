import Foundation

/// What the helper records in a session directory (`state`, 0600, root) about the tool it started: one
/// field per line, the pid, the owner's uid, the tool's executable (as `proc_pidpath` reports it), the
/// profile directory and the OpenVPN management socket (empty for other tools). A restarted helper adopts
/// a tool from it (`Supervisor.adoptOrphans`), and openconnect's hook proves its session with it
/// (`VPNHook.session`). The helper writes it before the tool runs its first instruction
/// (`Spawner.spawnVerified`'s `beforeResume`), so the tool's hook always finds it.
public struct SessionState: Equatable {
    public let pid: pid_t
    public let uid: uid_t
    public let executable: String
    public let profileDir: String
    public let mgmtSocket: String?

    public static let fileName = "state"
    /// Larger files are not read (five short lines).
    static let maxBytes = 16 << 10

    public init(pid: pid_t, uid: uid_t, executable: String, profileDir: String, mgmtSocket: String?) {
        self.pid = pid
        self.uid = uid
        self.executable = executable
        self.profileDir = profileDir
        self.mgmtSocket = mgmtSocket
    }

    /// The file's text; throws `HelperCore.Failure.unsafeFile` unless it is exactly five lines (a field
    /// with a line break would shift the others).
    public func text() throws -> String {
        let text = "\(pid)\n\(uid)\n\(executable)\n\(profileDir)\n\(mgmtSocket ?? "")\n"
        try HelperCore.checkLines(text, count: 5, file: Self.fileName)
        return text
    }

    /// Reads back `text()`. Lenient about what comes after the executable: a protocol-2 helper wrote only
    /// pid, uid and executable.
    public static func parse(_ text: String) -> SessionState? {
        let parts = text.components(separatedBy: "\n")
        guard parts.count >= 3, let pid = pid_t(parts[0]), let uid = uid_t(parts[1]), pid > 1, !parts[2].isEmpty else {
            return nil
        }
        let profileDir = parts.count >= 4 ? parts[3] : ""
        let socket = parts.count >= 5 && !parts[4].isEmpty ? parts[4] : nil
        return SessionState(pid: pid, uid: uid, executable: parts[2], profileDir: profileDir, mgmtSocket: socket)
    }

    /// The state at `path`: a regular, single-link file owned by us (root in the helper), opened without
    /// following a link; nil for anything else.
    public static func read(_ path: String) -> SessionState? {
        guard let data = try? HelperCore.readOwnFile(path, maxBytes: maxBytes) else { return nil }
        return String(data: data, encoding: .utf8).flatMap(parse)
    }
}

/// What openconnect's hook may do for a session (`policy`, 0600, root), written by the helper from the
/// checked start request before the tool starts (docs/ARCHITECTURE.md, "The hook", step 2). The hook reads
/// nothing else to decide it: not the user's profile, and nothing openconnect or the server passes.
public struct OpenConnectPolicy: Equatable {
    public let uid: uid_t
    public let profileID: String
    public let setRoutes: Bool
    public let setDNS: Bool

    public static let fileName = "policy"
    static let keys = ["uid", "profile", "set_routes", "set_dns"]

    public init(uid: uid_t, profileID: String, setRoutes: Bool, setDNS: Bool) {
        self.uid = uid
        self.profileID = profileID
        self.setRoutes = setRoutes
        self.setDNS = setDNS
    }

    /// `uid=<n>`, `profile=<id>`, `set_routes=0|1`, `set_dns=0|1`, one per line. Throws for a profile ID
    /// the helper would not accept.
    public func text() throws -> String {
        guard HelperCore.isValidProfileID(profileID) else { throw HelperCore.Failure.invalidProfileID(profileID) }
        let text = "uid=\(uid)\nprofile=\(profileID)\nset_routes=\(setRoutes ? 1 : 0)\nset_dns=\(setDNS ? 1 : 0)\n"
        try HelperCore.checkLines(text, count: Self.keys.count, file: Self.fileName)
        return text
    }

    /// Exactly `text()`'s form: the four keys in order, a canonical uid, a valid profile ID, `0` or `1`.
    public static func parse(_ text: String) -> OpenConnectPolicy? {
        var lines = text.components(separatedBy: "\n")
        guard lines.last == "" else { return nil }
        lines.removeLast()
        guard lines.count == keys.count else { return nil }
        var values: [String] = []
        for (line, key) in zip(lines, keys) {
            guard line.hasPrefix(key + "=") else { return nil }
            values.append(String(line.dropFirst(key.count + 1)))
        }
        guard let uid = uid_t(values[0]), String(uid) == values[0], HelperCore.isValidProfileID(values[1]),
            let setRoutes = flag(values[2]), let setDNS = flag(values[3])
        else { return nil }
        return OpenConnectPolicy(uid: uid, profileID: values[1], setRoutes: setRoutes, setDNS: setDNS)
    }

    static func flag(_ s: String) -> Bool? {
        switch s {
        case "0": return false
        case "1": return true
        default: return nil
        }
    }
}

extension HelperCore {
    /// Reads a regular, single-link file owned by us of at most `maxBytes`, without following a link.
    static func readOwnFile(_ path: String, maxBytes: Int) throws -> Data {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ELOOP { throw Failure.symlinkNotAllowed(path) }
            throw Failure.system("open \(path)", errno)
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else { throw Failure.system("stat \(path)", errno) }
        guard (st.st_mode & S_IFMT) == S_IFREG else { throw Failure.notARegularFile(path) }
        guard st.st_uid == geteuid() else { throw Failure.wrongOwner(path: path, expected: geteuid(), actual: st.st_uid) }
        guard st.st_nlink == 1 else { throw Failure.multipleLinks(path) }
        guard st.st_size <= maxBytes else { throw Failure.fileTooLarge(path) }
        var bytes = [UInt8](repeating: 0, count: maxBytes + 1)
        var count = 0
        while count < bytes.count {
            let n = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress! + count, $0.count - count) }
            if n < 0 {
                if errno == EINTR { continue }
                throw Failure.system("read \(path)", errno)
            }
            if n == 0 { break }
            count += n
        }
        guard count <= maxBytes else { throw Failure.fileTooLarge(path) }
        return Data(bytes[..<count])
    }
}
