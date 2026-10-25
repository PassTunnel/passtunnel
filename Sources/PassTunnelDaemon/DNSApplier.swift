import Foundation
#if canImport(Glibc)
import Glibc
#endif
import PassTunnelShared

/// Where DNS is changed (docs/LINUX.md, "DNS"), in this order of preference.
public enum DNSBackend: String, Equatable, Sendable {
    /// systemd-resolved manages /etc/resolv.conf: per link, through `resolvectl`.
    case resolved
    /// `resolvconf` (Debian's or openresolv) is installed: a record of its own for the tunnel.
    case resolvconf
    /// Neither: a marked block in /etc/resolv.conf itself.
    case file

    var name: String {
        switch self {
        case .resolved: return "systemd-resolved"
        case .resolvconf: return "resolvconf"
        case .file: return "/etc/resolv.conf"
        }
    }
}

/// What the DNS code touches: fixed paths, tools at fixed places (each checked with `TrustedPath` before
/// it runs) and how they are run. The defaults are the system's; tests use a fake root of their own.
public struct DNSSystem {
    public var resolvConf = "/etc/resolv.conf"
    /// Where /etc/resolv.conf points when systemd-resolved manages it: inside its run directory (a path
    /// ending in "/"), or its static file.
    public var resolvedTargets = ["/run/systemd/resolve/", "/usr/lib/systemd/resolv.conf", "/lib/systemd/resolv.conf"]
    public var resolvectl = ["/usr/bin/resolvectl", "/bin/resolvectl"]
    public var resolvconf = ["/usr/sbin/resolvconf", "/sbin/resolvconf"]
    /// openresolv's configuration, read for `resolv_conf_mv` only.
    public var resolvconfConf = "/etc/resolvconf.conf"
    /// Who must own the tools, the paths above them and /etc/resolv.conf (root, but in tests), and where
    /// the `TrustedPath` checks start.
    public var owner: uid_t = 0
    public var base = "/"
    public var interfaceIndex: (String) -> UInt32? = { name in
        let index = if_nametoindex(name)
        return index == 0 ? nil : index
    }
    public var run: (String, [String], Data?) -> ToolRunner.Result? = { path, arguments, input in
        ToolRunner.run(path, arguments: arguments, input: input, timeout: DNSSystem.toolTimeout)
    }
    /// `rename(2)`, returning 0 or the error; tests make it fail as it does on a mount point.
    public var renameFile: (String, String) -> Int32 = { rename($0, $1) == 0 ? 0 : errno }
    /// A directory on a read-only mount (`EROFS`), as /etc is inside passtunnel.service; tests say so
    /// of their fake /etc.
    public var isReadOnly: (String) -> Bool = { access($0, W_OK) != 0 && errno == EROFS }

    static let toolTimeout: TimeInterval = 10

    public init() {}
}

/// Sets and reverts the DNS of one session's tunnel, recording what it changes in the session's
/// root-owned directory (`DNSRecord`) before it changes it, so that whoever ends the session (the hook
/// when OpenVPN takes the tunnel down, the daemon when it reaps the tool, a starting daemon after a
/// crash) can revert exactly that. One change at a time on the machine: the run root is locked, by the
/// hook (a process of its own) and the daemon alike. On the file backend the session records are also
/// the registry of the tunnels whose DNS /etc/resolv.conf carries: every change makes the file again
/// from them and the baseline kept in the run root (`ResolvConfBaseline`), so sessions that overlap
/// never restore each other's snapshots.
/// Used by OpenVPN's DNS hook (`DNSHook`) and, for FortiGate's ppp interface, by the daemon:
/// `supervisor.dns.apply(DNSSettings(servers:searchDomains:fullTunnel:), interface: "ppp0",
/// in: job.sessionDir)` once the tunnel is up; `Supervisor` reverts it when it reaps the tool, and a
/// starting daemon when one did not (`revert(in:)`, then `restoreUnclaimed()`).
public struct DNSApplier {
    public var system: DNSSystem
    /// The run root, locked (`flock`) while DNS changes.
    public var runRoot: String
    public var lockTimeout: TimeInterval = 10

    /// The resolv.conf files PassTunnel reads, and leaves alone when larger.
    static let maxResolvConfBytes = 64 << 10
    /// glibc reads at most 3 nameservers; resolvconf passes them on.
    static let maxNameservers = 3

    /// resolvconf's record for a tunnel: one per link (name and index), so that a session never removes
    /// the record of a later link that got the same name.
    static func resolvconfRecord(_ record: DNSRecord) -> String { "\(record.interface).passtunnel-\(record.index)" }

    public init(system: DNSSystem = DNSSystem(), runRoot: String = PT.helperRunRoot) {
        self.system = system
        self.runRoot = runRoot
    }

    // MARK: - Applying

    /// Applies `settings` for `interface`, which must exist. What an earlier call recorded for the
    /// session is reverted first (on the file backend it is replaced, without the file's own servers
    /// coming back in between). On failure everything already changed is reverted and nothing stays
    /// recorded. Returns the backend used.
    @discardableResult
    public func apply(_ settings: DNSSettings, interface: String, in session: SessionDirectory) throws -> DNSBackend {
        let name = try DNSSettings.interface(interface)
        guard let index = system.interfaceIndex(name) else { throw DNSFailure.noInterface(name) }
        return try withLock { root in
            let (backend, tool) = try chooseBackend()
            var record = DNSRecord(backend: backend, interface: name, index: index)
            if backend == .file {
                let serial = (fileSessions(excluding: session.path).map(\.serial).max() ?? 0) + 1
                record = DNSRecord(backend: .file, interface: name, index: index, serial: serial,
                                   settings: try DNSSettings(servers: settings.servers, searchDomains: settings.searchDomains,
                                                             fullTunnel: true))
            }
            if let earlier = try? DNSRecord.load(in: session) {
                if earlier.backend != .file || backend != .file { _ = undo(earlier, in: session, root: root) }
                DNSRecord.remove(in: session)
            }
            do {
                try record.write(in: session)
                try commit(record, settings: settings, tool: tool, root: root)
            } catch {
                _ = undo(record, in: session, root: root)
                DNSRecord.remove(in: session)
                throw error
            }
            return backend
        }
    }

    /// Changes the DNS as `record` (written already) says. systemd-resolved is given the link's index,
    /// never its name, each time after `checkLink`.
    func commit(_ record: DNSRecord, settings: DNSSettings, tool: String?, root: Int32) throws {
        switch record.backend {
        case .resolved:
            let tool = tool!, link = String(record.index)
            var domains = settings.searchDomains + settings.routingDomains.map { "~" + $0 }
            if settings.fullTunnel { domains.append("~.") }
            for arguments in [["dns", link] + settings.servers, ["domain", link] + domains,
                              ["default-route", link, settings.fullTunnel ? "true" : "false"]] {
                try checkLink(record)
                try run(tool, "resolvectl", arguments)
            }
        case .resolvconf:
            var text = settings.servers.prefix(Self.maxNameservers).map { "nameserver \($0)\n" }.joined()
            if !settings.searchDomains.isEmpty { text += "search " + settings.searchDomains.joined(separator: " ") + "\n" }
            try run(tool!, "resolvconf", ["-a", Self.resolvconfRecord(record)], input: Data(text.utf8))
        case .file:
            try updateResolvConf(root: root, sessions: fileSessions())
        }
    }

    /// The recorded index still names the recorded interface, and no interface is named like the index:
    /// `resolvectl` reads a number as an interface index, systemd 256 and later only once no interface
    /// has it as its name or alternative name (both of which `if_nametoindex` finds). Interface indexes
    /// are not reused soon (the kernel counts up), so a link that passes is the session's own.
    func checkLink(_ record: DNSRecord) throws {
        guard system.interfaceIndex(record.interface) == record.index,
              system.interfaceIndex(String(record.index)).map({ $0 == record.index }) ?? true else {
            throw DNSFailure.interfaceChanged(record.interface, record.index)
        }
    }

    private func run(_ tool: String, _ name: String, _ arguments: [String], input: Data? = nil) throws {
        guard let result = system.run(tool, arguments, input) else {
            throw DNSFailure.toolFailed("\(name) \(arguments.first ?? "")", -1, "could not be started")
        }
        guard result.status == 0 else {
            throw DNSFailure.toolFailed("\(name) \(arguments.first ?? "")", result.status, result.output)
        }
    }

    // MARK: - Reverting

    /// Reverts what `session` records, then removes the record. Nil when nothing was recorded, else a
    /// line for the log. Never throws: a revert does what it can.
    @discardableResult
    public func revert(in session: SessionDirectory) -> String? {
        let locked = try? lock()
        let root = locked ?? open(runRoot, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        defer { if root >= 0 { close(root) } }
        let record: DNSRecord
        do {
            guard let loaded = try DNSRecord.load(in: session) else { return nil }
            record = loaded
        } catch {
            DNSRecord.remove(in: session)
            return "removed an unreadable DNS record: \(error)"
        }
        let problems = undo(record, in: session, root: root)
        DNSRecord.remove(in: session)
        let what = "the DNS of \(record.interface) (\(record.backend.name))"
        let busy = locked == nil ? " (without the lock: \(DNSFailure.busy))" : ""
        guard problems.isEmpty else {
            return "could not fully restore \(what)\(busy): " + problems.joined(separator: "; ")
        }
        return "restored \(what)\(busy)"
    }

    /// Undoes `record` of `session`; the problems met, if any.
    func undo(_ record: DNSRecord, in session: SessionDirectory, root: Int32) -> [String] {
        do {
            switch record.backend {
            case .resolved:
                // Its link gone, systemd-resolved has dropped the settings; a link of that name with
                // another index belongs to someone else.
                guard system.interfaceIndex(record.interface) == record.index else { return [] }
                guard let tool = try trustedTool(system.resolvectl) else {
                    throw DNSFailure.missingTool("resolvectl", "the link was set up through systemd-resolved")
                }
                try checkLink(record)
                try run(tool, "resolvectl", ["revert", String(record.index)])
            case .resolvconf:
                guard let tool = try trustedResolvconf() else {
                    throw DNSFailure.missingTool("resolvconf", "the record was made with resolvconf")
                }
                try run(tool, "resolvconf", ["-d", Self.resolvconfRecord(record)])
            case .file:
                do {
                    try updateResolvConf(root: root, sessions: fileSessions(excluding: session.path))
                } catch DNSFailure.unexpectedLink {
                    // Replaced by a link since: someone else's now, left alone.
                }
            }
            return []
        } catch {
            return [String(describing: error)]
        }
    }

    /// The file backend's baseline when no session claims it any more (a revert that failed, or a crash
    /// between its steps): /etc/resolv.conf loses PassTunnel's lines, the baseline goes. Run by a
    /// starting daemon once it reverted what the sessions of an earlier one recorded. Nil when there was
    /// nothing to do, else a line for the log.
    public func restoreUnclaimed() -> String? {
        guard let root = try? lock() else { return nil }
        defer { close(root) }
        var st = stat()
        guard fstatat(root, ResolvConfBaseline.fileName, &st, AT_SYMLINK_NOFOLLOW) == 0, fileSessions().isEmpty else { return nil }
        do {
            try updateResolvConf(root: root, sessions: [])
            return "restored \(system.resolvConf), which no session uses any more"
        } catch DNSFailure.unexpectedLink {
            ResolvConfBaseline.remove(in: root)
            return nil
        } catch {
            return "could not restore \(system.resolvConf), which no session uses any more: \(error)"
        }
    }

    // MARK: - The file backend

    /// The registry of the file backend: the records of every session in the run root (but the one at
    /// `excluding`) whose DNS is in /etc/resolv.conf, newest first. The hook and the daemon read it under
    /// the run root's lock; a session leaves it when its record goes (`revert(in:)`, by its hook, the
    /// daemon's reap or a starting daemon).
    func fileSessions(excluding: String? = nil) -> [DNSRecord] {
        let core = HelperCore(runRoot: runRoot)
        var found: [DNSRecord] = []
        for entry in PreviousInstance.entries(runRoot) {
            guard let uid = uid_t(entry), String(uid) == entry, PreviousInstance.isRealDirectory(runRoot + "/" + entry) else {
                continue
            }
            for id in PreviousInstance.entries(runRoot + "/" + entry) where HelperCore.isValidProfileID(id) {
                guard let session = try? core.openRunDir(profileID: id, uid: uid), session.path != excluding,
                      let record = try? DNSRecord.load(in: session), record.backend == .file else { continue }
                found.append(record)
            }
        }
        return found.sorted { ($0.serial, $0.interface) > ($1.serial, $1.interface) }
    }

    /// /etc/resolv.conf made again from the baseline and the newest of `sessions`: its block at the
    /// top, the baseline's resolver lines disabled (a resolv.conf cannot route names, so the newest
    /// tunnel's DNS is in effect, and an older one's comes back when it ends). With no session the
    /// baseline comes back. The baseline is the recorded one while the file is still what PassTunnel
    /// wrote; changed by someone else since, it is the file without PassTunnel's lines (their changes
    /// stay); a file without any of them that no session needs any more is left alone.
    func updateResolvConf(root: Int32, sessions: [DNSRecord]) throws {
        let current = try readResolvConf()
        let currentBytes = current.map { [UInt8]($0.data) }
        let saved = ResolvConfBaseline.load(in: root, path: runRoot)
        let unchanged = current.map { saved?.written == HelperCore.sha256Hex($0.data) } ?? false
        let baseline: [UInt8]?
        if unchanged, let saved {
            baseline = saved.content
        } else if let currentBytes {
            baseline = ResolvConf.stripAll(currentBytes) ?? currentBytes
        } else {
            baseline = nil
        }
        guard let newest = sessions.first(where: { $0.settings != nil }), let settings = newest.settings else {
            if unchanged || currentBytes.map({ ResolvConf.stripAll($0) != nil }) == true, let current {
                if let baseline {
                    try writeResolvConf(Data(baseline), mode: current.mode, group: current.group)
                } else if unlink(system.resolvConf) != 0, errno != ENOENT {
                    throw DNSFailure.system("remove \(system.resolvConf)", errno)
                }
            }
            ResolvConfBaseline.remove(in: root)
            return
        }
        let content = ResolvConf.apply(settings, interface: newest.interface, to: baseline ?? [])
        if unchanged, currentBytes == content { return }
        try ResolvConfBaseline(written: HelperCore.sha256Hex(Data(content)), content: baseline).write(in: root, path: runRoot)
        try writeResolvConf(Data(content), mode: current?.mode ?? 0o644, group: current?.group ?? 0)
    }

    // MARK: - Choosing

    /// systemd-resolved when /etc/resolv.conf links into it, else resolvconf when installed, else the
    /// file itself. A link anywhere else is never followed.
    func chooseBackend() throws -> (DNSBackend, String?) {
        let path = system.resolvConf
        var st = stat()
        if lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFLNK {
            let target = Self.readLink(path) ?? ""
            let resolved = Self.lexicalTarget(of: path, target: target)
            if system.resolvedTargets.contains(where: { $0.hasSuffix("/") ? resolved.hasPrefix($0) : resolved == $0 }) {
                guard let tool = try trustedTool(system.resolvectl) else {
                    throw DNSFailure.missingTool("resolvectl", "systemd-resolved manages \(path)")
                }
                return (.resolved, tool)
            }
            if let tool = try trustedResolvconf() { return (.resolvconf, try checkedResolvconf(tool)) }
            throw DNSFailure.unexpectedLink(path, target)
        }
        if let tool = try trustedResolvconf() { return (.resolvconf, try checkedResolvconf(tool)) }
        return (.file, nil)
    }

    /// openresolv writes /etc/resolv.conf in place, unless `resolv_conf_mv` asks it to rename a new
    /// file over it, which cannot work where /etc is read-only (inside passtunnel.service): refused
    /// there, rather than left to fail without a word.
    func checkedResolvconf(_ tool: String) throws -> String {
        let directory = (system.resolvConf as NSString).deletingLastPathComponent
        guard Self.replacesResolvConf(system.resolvconfConf), system.isReadOnly(directory) else { return tool }
        throw DNSFailure.resolvconfReplaces(system.resolvconfConf, directory)
    }

    /// Whether openresolv's configuration sets `resolv_conf_mv` to a true value (the last assignment
    /// counts, as in the shell that reads it).
    static func replacesResolvConf(_ path: String) -> Bool {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size <= 64 << 10,
              let text = try? String(contentsOfFile: path, encoding: .utf8) else { return false }
        var replaces = false
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.drop { $0 == " " || $0 == "\t" }
            guard line.hasPrefix("resolv_conf_mv=") else { continue }
            let value = line.dropFirst("resolv_conf_mv=".count)
                .prefix { !" \t;#".contains($0) }
                .filter { $0 != "\"" && $0 != "'" }
                .lowercased()
            replaces = ["yes", "true", "on", "1"].contains(value)
        }
        return replaces
    }

    /// The real path of the first candidate that exists, once it passed `TrustedPath`; nil when none
    /// exists.
    func trustedTool(_ candidates: [String]) throws -> String? {
        guard let candidate = candidates.first(where: { access($0, F_OK) == 0 }) else { return nil }
        guard let real = HelperCore.realPath(candidate) else {
            throw DNSFailure.untrustedTool(candidate, "its path cannot be resolved.")
        }
        do {
            try TrustedPath.check(real, owner: system.owner, base: system.base)
        } catch {
            throw DNSFailure.untrustedTool(real, String(describing: error))
        }
        return real
    }

    /// resolvconf, unless it is systemd's stand-in for it (a link to resolvectl, which only works with
    /// systemd-resolved, and then that is used).
    func trustedResolvconf() throws -> String? {
        guard let tool = try trustedTool(system.resolvconf), (tool as NSString).lastPathComponent == "resolvconf" else {
            return nil
        }
        return tool
    }

    static func readLink(_ path: String) -> String? {
        var buffer = [CChar](repeating: 0, count: 4097)
        let n = readlink(path, &buffer, buffer.count - 1)
        guard n > 0 else { return nil }
        buffer[n] = 0
        return String(cString: buffer)
    }

    /// Where a link points, worked out from its text alone (`..` and `.` removed), never following the
    /// target any further.
    static func lexicalTarget(of link: String, target: String) -> String {
        let joined = target.hasPrefix("/") ? target : (link as NSString).deletingLastPathComponent + "/" + target
        var parts: [Substring] = []
        for part in joined.split(separator: "/") where part != "." {
            if part == ".." { _ = parts.popLast() } else { parts.append(part) }
        }
        return "/" + parts.joined(separator: "/")
    }

    // MARK: - /etc/resolv.conf

    struct ResolvConfFile {
        let data: Data
        let mode: mode_t
        let group: gid_t
    }

    /// The current file: nil when there is none; a link, anything but a regular file of `owner` or
    /// more than `maxResolvConfBytes` is refused.
    func readResolvConf() throws -> ResolvConfFile? {
        let path = system.resolvConf
        var st = stat()
        guard lstat(path, &st) == 0 else {
            if errno == ENOENT { return nil }
            throw DNSFailure.system("stat \(path)", errno)
        }
        if (st.st_mode & S_IFMT) == S_IFLNK { throw DNSFailure.unexpectedLink(path, Self.readLink(path) ?? "") }
        guard (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == system.owner else { throw DNSFailure.notARegularFile(path) }
        guard st.st_size <= Self.maxResolvConfBytes else { throw DNSFailure.tooLarge(path) }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw DNSFailure.system("open \(path)", errno) }
        defer { close(fd) }
        var opened = stat()
        guard fstat(fd, &opened) == 0, opened.st_ino == st.st_ino, opened.st_dev == st.st_dev else {
            throw DNSFailure.notARegularFile(path)
        }
        // Inside passtunnel.service the file is systemd's bind mount of the one there was when the unit
        // started; one renamed over it since (by a network manager) leaves this one with no name.
        guard opened.st_nlink > 0 else { throw DNSFailure.detached(path) }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n >= 0 else { throw DNSFailure.system("read \(path)", errno) }
            if n == 0 { break }
            data.append(contentsOf: buffer[0..<n])
            guard data.count <= Self.maxResolvConfBytes else { throw DNSFailure.tooLarge(path) }
        }
        return ResolvConfFile(data: data, mode: st.st_mode & 0o7777, group: st.st_gid)
    }

    /// Written next to /etc/resolv.conf, then renamed over it.
    var temporaryPath: String { system.resolvConf + ".passtunnel" }

    /// Replaces /etc/resolv.conf atomically where it can: a new file in the same directory, synced,
    /// renamed over it. Where it cannot, the file is rewritten in place: inside passtunnel.service,
    /// where /etc is read-only and the file a bind mount of its own (`ReadWritePaths`), and where a
    /// container runtime bind-mounts it (rename fails with `EBUSY`).
    func writeResolvConf(_ data: Data, mode: mode_t, group: gid_t) throws {
        let path = system.resolvConf, temp = temporaryPath
        guard !system.isReadOnly((path as NSString).deletingLastPathComponent) else { return try rewriteInPlace(data) }
        if unlink(temp) != 0, errno != ENOENT {
            if errno == EROFS { return try rewriteInPlace(data) }
            throw DNSFailure.system("remove \(temp)", errno)
        }
        let fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else {
            if errno == EROFS { return try rewriteInPlace(data) }
            throw DNSFailure.system("create \(temp)", errno)
        }
        do {
            if geteuid() == 0, fchown(fd, system.owner, group) != 0 { throw DNSFailure.system("chown \(temp)", errno) }
            guard fchmod(fd, mode) == 0 else { throw DNSFailure.system("chmod \(temp)", errno) }
            try Self.writeAll(fd, data, at: nil, path: temp)
            guard fsync(fd) == 0 else { throw DNSFailure.system("sync \(temp)", errno) }
            close(fd)
        } catch {
            close(fd)
            unlink(temp)
            throw error
        }
        let err = system.renameFile(temp, path)
        if err != 0 {
            unlink(temp)
            guard err == EBUSY else { throw DNSFailure.system("replace \(path)", err) }
            try rewriteInPlace(data)
            return
        }
        let dir = open((path as NSString).deletingLastPathComponent, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        if dir >= 0 {
            _ = fsync(dir)
            close(dir)
        }
    }

    /// The whole content written at once from the start, the file cut to its length, synced. The
    /// baseline it is made from is in the run root already (`ResolvConfBaseline`).
    private func rewriteInPlace(_ data: Data) throws {
        let path = system.resolvConf
        let fd = open(path, O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw DNSFailure.system("open \(path)", errno) }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == system.owner else {
            throw DNSFailure.notARegularFile(path)
        }
        guard st.st_nlink > 0 else { throw DNSFailure.detached(path) }
        try Self.writeAll(fd, data, at: 0, path: path)
        guard ftruncate(fd, off_t(data.count)) == 0 else { throw DNSFailure.system("truncate \(path)", errno) }
        guard fsync(fd) == 0 else { throw DNSFailure.system("sync \(path)", errno) }
    }

    /// All of `data`, appended (`offset` nil) or from `offset` on.
    static func writeAll(_ fd: Int32, _ data: Data, at offset: off_t?, path: String) throws {
        let bytes = [UInt8](data)
        var done = 0
        while done < bytes.count {
            let n = bytes.withUnsafeBytes { raw -> Int in
                let start = raw.baseAddress! + done
                if let offset { return pwrite(fd, start, bytes.count - done, offset + off_t(done)) }
                return write(fd, start, bytes.count - done)
            }
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { throw DNSFailure.system("write \(path)", errno) }
            done += n
        }
    }

    // MARK: - Lock

    /// The run root's directory, locked; the caller closes the descriptor to unlock it.
    func lock() throws -> Int32 {
        let fd = open(runRoot, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw DNSFailure.system("open \(runRoot)", errno) }
        let deadline = Date().addingTimeInterval(lockTimeout)
        while flock(fd, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EWOULDBLOCK || errno == EINTR, Date() < deadline else {
                close(fd)
                throw DNSFailure.busy
            }
            usleep(20_000)
        }
        return fd
    }

    /// `body` with the run root locked, given its descriptor.
    private func withLock<T>(_ body: (Int32) throws -> T) throws -> T {
        let fd = try lock()
        defer { close(fd) }
        return try body(fd)
    }
}

/// What `DNSApplier` changed for a session, in its directory (`dns`, root's, 0600), written before the
/// change: the backend and the interface (name and index); for the file backend also when it was
/// applied (`serial`, higher is newer) and the servers and search domains of its block, from which the
/// file is made again whenever a session comes or goes.
public struct DNSRecord: Equatable {
    public static let fileName = "dns"
    static let header = "passtunnel-dns 2"
    static let maxBytes = 8192

    public let backend: DNSBackend
    public let interface: String
    public let index: UInt32
    /// File backend only (0 and nil otherwise).
    public let serial: UInt64
    public let settings: DNSSettings?

    init(backend: DNSBackend, interface: String, index: UInt32, serial: UInt64 = 0, settings: DNSSettings? = nil) {
        self.backend = backend
        self.interface = interface
        self.index = index
        self.serial = serial
        self.settings = settings
    }

    var text: String {
        func list(_ values: [String]) -> String { values.isEmpty ? "-" : values.joined(separator: " ") }
        let file = settings.map { "\(serial)\n\(list($0.servers))\n\(list($0.searchDomains))" } ?? "-\n-\n-"
        return "\(Self.header)\n\(backend.rawValue)\n\(interface)\n\(index)\n\(file)\n"
    }

    /// Parses the record strictly (it is root's own, but it decides what a root process changes): every
    /// value is checked again as `DNSSettings` checks the server's.
    init?(text: String) {
        let lines = text.components(separatedBy: "\n")
        guard lines.count == 8, lines[7].isEmpty, lines[0] == Self.header, let backend = DNSBackend(rawValue: lines[1]),
              (try? DNSSettings.interface(lines[2])) != nil, let index = UInt32(lines[3]), String(index) == lines[3],
              index > 0 else { return nil }
        guard backend == .file else {
            guard lines[4...6].allSatisfy({ $0 == "-" }) else { return nil }
            self.init(backend: backend, interface: lines[2], index: index)
            return
        }
        guard let serial = UInt64(lines[4]), String(serial) == lines[4], serial > 0,
              let servers = Self.list(lines[5], DNSSettings.address), let search = Self.list(lines[6], DNSSettings.domain),
              let settings = try? DNSSettings(servers: servers, searchDomains: search, fullTunnel: true) else { return nil }
        self.init(backend: .file, interface: lines[2], index: index, serial: serial, settings: settings)
    }

    /// "-" for none, else values separated by single spaces, each in the form `check` gives it.
    private static func list(_ line: String, _ check: (String) throws -> String) -> [String]? {
        if line == "-" { return [] }
        let values = line.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard values.allSatisfy({ (try? check($0)) == $0 }) else { return nil }
        return values
    }

    /// The record of `session`: nil when there is none, an error when it is not one.
    static func load(in session: SessionDirectory) throws -> DNSRecord? {
        guard let data = try RootFile.load(fileName, at: session.fd, path: session.path, maxBytes: maxBytes) else { return nil }
        guard let text = String(data: data, encoding: .utf8), let record = DNSRecord(text: text) else {
            throw DNSFailure.invalid("DNS record", session.path + "/" + fileName)
        }
        return record
    }

    /// Writes the record atomically.
    func write(in session: SessionDirectory) throws {
        try HelperCore.checkLines(text, count: 7, file: Self.fileName)
        try RootFile.store(Self.fileName, Data(text.utf8), at: session.fd, path: session.path)
    }

    static func remove(in session: SessionDirectory) {
        _ = unlinkat(session.fd, fileName, 0)
    }
}

/// The file backend's baseline, in the run root (`resolv.conf.base`, root's, 0600) while a session's
/// DNS is in /etc/resolv.conf: the file as it is without PassTunnel (nil: there was none), and a digest
/// of what PassTunnel wrote last, which tells whether anyone changed the file since.
struct ResolvConfBaseline: Equatable {
    static let fileName = "resolv.conf.base"
    static let header = "passtunnel-resolv-base 1"

    let written: String
    let content: [UInt8]?

    var bytes: [UInt8] {
        Array("\(Self.header)\n\(written)\n\(content == nil ? "none" : "file")\n".utf8) + (content ?? [])
    }

    init(written: String, content: [UInt8]?) {
        self.written = written
        self.content = content
    }

    /// Three lines (header, digest, "file" or "none"), then the content as it was, byte for byte.
    init?(bytes: [UInt8]) {
        var lines: [[UInt8]] = []
        var start = 0
        while lines.count < 3, let end = bytes[start...].firstIndex(of: 0x0A) {
            lines.append(Array(bytes[start..<end]))
            start = end + 1
        }
        guard lines.count == 3, lines[0] == Array(Self.header.utf8), lines[1].count == 64,
              lines[1].allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else { return nil }
        let rest = Array(bytes[start...])
        switch String(decoding: lines[2], as: UTF8.self) {
        case "file": self.init(written: String(decoding: lines[1], as: UTF8.self), content: rest)
        case "none" where rest.isEmpty: self.init(written: String(decoding: lines[1], as: UTF8.self), content: nil)
        default: return nil
        }
    }

    /// Nil when there is none, or it cannot be read (the file is then taken as someone else's).
    static func load(in root: Int32, path: String) -> ResolvConfBaseline? {
        guard let data = try? RootFile.load(fileName, at: root, path: path, maxBytes: DNSApplier.maxResolvConfBytes + 256) else {
            return nil
        }
        return ResolvConfBaseline(bytes: [UInt8](data))
    }

    func write(in root: Int32, path: String) throws {
        try RootFile.store(Self.fileName, Data(bytes), at: root, path: path)
    }

    static func remove(in root: Int32) {
        _ = unlinkat(root, fileName, 0)
    }
}

/// Root's own small files in a root-owned directory, by descriptor: never through a link, written
/// atomically (a new file, synced, renamed over the old one).
enum RootFile {
    static func load(_ name: String, at dir: Int32, path: String, maxBytes: Int) throws -> Data? {
        let fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            throw DNSFailure.system("open \(path)/\(name)", errno)
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == geteuid(), st.st_size <= maxBytes else {
            throw DNSFailure.notARegularFile(path + "/" + name)
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while data.count <= maxBytes {
            let n = read(fd, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n >= 0 else { throw DNSFailure.system("read \(path)/\(name)", errno) }
            if n == 0 { return data }
            data.append(contentsOf: buffer[0..<n])
        }
        throw DNSFailure.tooLarge(path + "/" + name)
    }

    static func store(_ name: String, _ data: Data, at dir: Int32, path: String) throws {
        let temp = "." + name + ".new"
        if unlinkat(dir, temp, 0) != 0, errno != ENOENT { throw DNSFailure.system("remove \(path)/\(temp)", errno) }
        let fd = openat(dir, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw DNSFailure.system("create \(path)/\(temp)", errno) }
        do {
            try DNSApplier.writeAll(fd, data, at: nil, path: path + "/" + temp)
            guard fsync(fd) == 0 else { throw DNSFailure.system("sync \(path)/\(temp)", errno) }
            close(fd)
        } catch {
            close(fd)
            unlinkat(dir, temp, 0)
            throw error
        }
        guard renameat(dir, temp, dir, name) == 0 else {
            let err = errno
            unlinkat(dir, temp, 0)
            throw DNSFailure.system("rename \(path)/\(temp)", err)
        }
    }
}
