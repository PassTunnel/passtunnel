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

    static let toolTimeout: TimeInterval = 10

    public init() {}
}

/// Sets and reverts the DNS of one session's tunnel, recording what it changes in the session's
/// root-owned directory (`DNSRecord`) before it changes it, so that whoever ends the session (the hook
/// when OpenVPN takes the tunnel down, the daemon when it reaps the tool, a starting daemon after a
/// crash) can revert exactly that. One change at a time on the machine: the run root is locked.
/// Used by OpenVPN's DNS hook (`DNSHook`) and, for FortiGate's ppp interface, by the daemon:
/// `supervisor.dns.apply(DNSSettings(servers:searchDomains:fullTunnel:), interface: "ppp0",
/// in: job.sessionDir)` once the tunnel is up; `Supervisor` reverts it when it reaps the tool, and a
/// starting daemon when one did not. `apply` and `revert(in:)` are the whole interface.
public struct DNSApplier {
    public var system: DNSSystem
    /// The run root, locked (`flock`) while DNS changes.
    public var runRoot: String
    public var lockTimeout: TimeInterval = 10

    /// The resolv.conf files PassTunnel reads, and leaves alone when larger.
    static let maxResolvConfBytes = 64 << 10
    /// glibc reads at most 3 nameservers; resolvconf passes them on.
    static let maxNameservers = 3
    static let resolvconfSuffix = ".passtunnel"

    public init(system: DNSSystem = DNSSystem(), runRoot: String = PT.helperRunRoot) {
        self.system = system
        self.runRoot = runRoot
    }

    // MARK: - Applying

    /// Applies `settings` for `interface`, which must exist. What an earlier call recorded for the
    /// session is reverted first. On failure everything already changed is reverted and nothing stays
    /// recorded. Returns the backend used.
    @discardableResult
    public func apply(_ settings: DNSSettings, interface: String, in session: SessionDirectory) throws -> DNSBackend {
        let name = try DNSSettings.interface(interface)
        guard let index = system.interfaceIndex(name) else { throw DNSFailure.noInterface(name) }
        return try withLock {
            if let earlier = try? DNSRecord.load(in: session) {
                _ = undo(earlier, in: session)
                DNSRecord.remove(in: session)
            }
            let plan = try prepare(settings, interface: name, index: index)
            do {
                try plan.record.write(in: session, previous: plan.previous)
            } catch {
                DNSRecord.remove(in: session)
                throw error
            }
            do {
                try commit(plan)
            } catch {
                _ = undo(plan.record, in: session)
                DNSRecord.remove(in: session)
                throw error
            }
            return plan.record.backend
        }
    }

    /// What `apply` will do, worked out before anything changes.
    struct Plan {
        let record: DNSRecord
        let settings: DNSSettings
        let tool: String?
        /// File backend: the resolv.conf it replaces (nil: there was none) and what replaces it.
        let previous: Data?
        let content: Data?
        let mode: mode_t
        let group: gid_t
    }

    func prepare(_ settings: DNSSettings, interface: String, index: UInt32) throws -> Plan {
        let (backend, tool) = try chooseBackend()
        guard backend == .file else {
            return Plan(record: DNSRecord(backend: backend, interface: interface, index: index),
                        settings: settings, tool: tool, previous: nil, content: nil, mode: 0, group: 0)
        }
        let current = try readResolvConf()
        var previous = current.map { [UInt8]($0.data) }
        // A block of this interface whose record went missing (a crash) is not carried on.
        if let p = previous, let stripped = ResolvConf.strip(p, interface: interface) { previous = stripped }
        let content = Data(ResolvConf.apply(settings, interface: interface, to: previous ?? []))
        let record = DNSRecord(backend: .file, interface: interface, index: index,
                               written: HelperCore.sha256Hex(content), hadPrevious: current != nil)
        return Plan(record: record, settings: settings, tool: nil, previous: previous.map { Data($0) }, content: content,
                    mode: current.map { $0.mode } ?? 0o644, group: current.map { $0.group } ?? 0)
    }

    func commit(_ plan: Plan) throws {
        let settings = plan.settings, interface = plan.record.interface
        switch plan.record.backend {
        case .resolved:
            let tool = plan.tool!
            var domains = settings.searchDomains + settings.routingDomains.map { "~" + $0 }
            if settings.fullTunnel { domains.append("~.") }
            try run(tool, "resolvectl", ["dns", interface] + settings.servers)
            try run(tool, "resolvectl", ["domain", interface] + domains)
            try run(tool, "resolvectl", ["default-route", interface, settings.fullTunnel ? "true" : "false"])
        case .resolvconf:
            var text = settings.servers.prefix(Self.maxNameservers).map { "nameserver \($0)\n" }.joined()
            if !settings.searchDomains.isEmpty { text += "search " + settings.searchDomains.joined(separator: " ") + "\n" }
            try run(plan.tool!, "resolvconf", ["-a", interface + Self.resolvconfSuffix], input: Data(text.utf8))
        case .file:
            try writeResolvConf(plan.content!, mode: plan.mode, group: plan.group)
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
        defer { locked.map { _ = close($0) } }
        let record: DNSRecord
        do {
            guard let loaded = try DNSRecord.load(in: session) else { return nil }
            record = loaded
        } catch {
            DNSRecord.remove(in: session)
            return "removed an unreadable DNS record: \(error)"
        }
        let problems = undo(record, in: session)
        DNSRecord.remove(in: session)
        let what = "the DNS of \(record.interface) (\(record.backend.name))"
        let busy = locked == nil ? " (without the lock: \(DNSFailure.busy))" : ""
        guard problems.isEmpty else {
            return "could not fully restore \(what)\(busy): " + problems.joined(separator: "; ")
        }
        return "restored \(what)\(busy)"
    }

    /// Undoes `record`; the problems met, if any.
    func undo(_ record: DNSRecord, in session: SessionDirectory) -> [String] {
        do {
            switch record.backend {
            case .resolved:
                // Its link gone, systemd-resolved has dropped the settings; a link of that name with
                // another index belongs to someone else.
                guard system.interfaceIndex(record.interface) == record.index else { return [] }
                guard let tool = try trustedTool(system.resolvectl) else {
                    throw DNSFailure.missingTool("resolvectl", "the link was set up through systemd-resolved")
                }
                try run(tool, "resolvectl", ["revert", record.interface])
            case .resolvconf:
                guard let tool = try trustedResolvconf() else {
                    throw DNSFailure.missingTool("resolvconf", "the record was made with resolvconf")
                }
                try run(tool, "resolvconf", ["-d", record.interface + Self.resolvconfSuffix])
            case .file:
                try restoreResolvConf(record, in: session)
            }
            return []
        } catch {
            return [String(describing: error)]
        }
    }

    /// The resolv.conf written is replaced by the one it replaced; one changed since keeps its own
    /// changes and loses only this interface's block and the marks on the lines it disabled; one
    /// replaced by something else entirely (or by a link) is left alone.
    private func restoreResolvConf(_ record: DNSRecord, in session: SessionDirectory) throws {
        defer { _ = unlink(temporaryPath) }
        let current: ResolvConfFile?
        do {
            current = try readResolvConf()
        } catch DNSFailure.unexpectedLink {
            return
        }
        guard let current else { return }
        if HelperCore.sha256Hex(current.data) == record.written {
            if !record.hadPrevious {
                guard unlink(system.resolvConf) == 0 || errno == ENOENT else {
                    throw DNSFailure.system("remove \(system.resolvConf)", errno)
                }
                return
            }
            if let previous = DNSRecord.loadPrevious(in: session) {
                try writeResolvConf(previous, mode: current.mode, group: current.group)
                return
            }
        }
        if let stripped = ResolvConf.strip([UInt8](current.data), interface: record.interface) {
            try writeResolvConf(Data(stripped), mode: current.mode, group: current.group)
        }
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
            if let tool = try trustedResolvconf() { return (.resolvconf, tool) }
            throw DNSFailure.unexpectedLink(path, target)
        }
        if let tool = try trustedResolvconf() { return (.resolvconf, tool) }
        return (.file, nil)
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

    /// Replaces /etc/resolv.conf atomically: a new file in the same directory, synced, renamed over it.
    /// A file that cannot be replaced because it is a mount point (as containers bind-mount it) is
    /// rewritten in place instead.
    func writeResolvConf(_ data: Data, mode: mode_t, group: gid_t) throws {
        let path = system.resolvConf, temp = temporaryPath
        if unlink(temp) != 0, errno != ENOENT { throw DNSFailure.system("remove \(temp)", errno) }
        let fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw DNSFailure.system("create \(temp)", errno) }
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

    private func rewriteInPlace(_ data: Data) throws {
        let path = system.resolvConf
        let fd = open(path, O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw DNSFailure.system("open \(path)", errno) }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == system.owner else {
            throw DNSFailure.notARegularFile(path)
        }
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

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        let fd = try lock()
        defer { close(fd) }
        return try body()
    }
}

/// What `DNSApplier` changed for a session, in its directory (`dns`, root's, 0600), written before the
/// change: the backend, the interface (name and index) and, for the file backend, a digest of the
/// resolv.conf written and whether there was one before, whose content is kept in `dns.resolv.conf`.
public struct DNSRecord: Equatable {
    public static let fileName = "dns"
    static let previousFileName = "dns.resolv.conf"
    static let header = "passtunnel-dns 1"

    public let backend: DNSBackend
    public let interface: String
    public let index: UInt32
    public let written: String?
    public let hadPrevious: Bool

    init(backend: DNSBackend, interface: String, index: UInt32, written: String? = nil, hadPrevious: Bool = false) {
        self.backend = backend
        self.interface = interface
        self.index = index
        self.written = written
        self.hadPrevious = hadPrevious
    }

    var text: String {
        "\(Self.header)\n\(backend.rawValue)\n\(interface)\n\(index)\n\(written ?? "-")\n\(hadPrevious ? "previous" : "none")\n"
    }

    /// Parses the record strictly (it is root's own, but it decides what a root process changes).
    init?(text: String) {
        let lines = text.components(separatedBy: "\n")
        guard lines.count == 7, lines[6].isEmpty, lines[0] == Self.header, let backend = DNSBackend(rawValue: lines[1]),
              (try? DNSSettings.interface(lines[2])) != nil, let index = UInt32(lines[3]), String(index) == lines[3],
              ["previous", "none"].contains(lines[5]) else { return nil }
        let written: String? = lines[4] == "-" ? nil : lines[4]
        if let written {
            guard backend == .file, written.utf8.count == 64,
                  written.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else { return nil }
        } else if backend == .file {
            return nil
        }
        self.init(backend: backend, interface: lines[2], index: index, written: written, hadPrevious: lines[5] == "previous")
    }

    /// The record of `session`: nil when there is none, an error when it is not one.
    static func load(in session: SessionDirectory) throws -> DNSRecord? {
        guard let data = try readFile(fileName, in: session, maxBytes: 4096) else { return nil }
        guard let text = String(data: data, encoding: .utf8), let record = DNSRecord(text: text) else {
            throw DNSFailure.invalid("DNS record", session.path + "/" + fileName)
        }
        return record
    }

    static func loadPrevious(in session: SessionDirectory) -> Data? {
        (try? readFile(previousFileName, in: session, maxBytes: DNSApplier.maxResolvConfBytes)) ?? nil
    }

    /// Writes the record, and first what resolv.conf held (`previous`), each atomically.
    func write(in session: SessionDirectory, previous: Data?) throws {
        if let previous { try Self.writeFile(Self.previousFileName, previous, in: session) }
        try HelperCore.checkLines(text, count: 6, file: Self.fileName)
        try Self.writeFile(Self.fileName, Data(text.utf8), in: session)
    }

    static func remove(in session: SessionDirectory) {
        _ = unlinkat(session.fd, fileName, 0)
        _ = unlinkat(session.fd, previousFileName, 0)
    }

    private static func readFile(_ name: String, in session: SessionDirectory, maxBytes: Int) throws -> Data? {
        let fd = openat(session.fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            throw DNSFailure.system("open \(session.path)/\(name)", errno)
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == geteuid(), st.st_size <= maxBytes else {
            throw DNSFailure.notARegularFile(session.path + "/" + name)
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while data.count <= maxBytes {
            let n = read(fd, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n >= 0 else { throw DNSFailure.system("read \(session.path)/\(name)", errno) }
            if n == 0 { return data }
            data.append(contentsOf: buffer[0..<n])
        }
        throw DNSFailure.tooLarge(session.path + "/" + name)
    }

    private static func writeFile(_ name: String, _ data: Data, in session: SessionDirectory) throws {
        let temp = "." + name + ".new"
        if unlinkat(session.fd, temp, 0) != 0, errno != ENOENT { throw DNSFailure.system("remove \(session.path)/\(temp)", errno) }
        let fd = openat(session.fd, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw DNSFailure.system("create \(session.path)/\(temp)", errno) }
        do {
            try DNSApplier.writeAll(fd, data, at: nil, path: session.path + "/" + temp)
            guard fsync(fd) == 0 else { throw DNSFailure.system("sync \(session.path)/\(temp)", errno) }
            close(fd)
        } catch {
            close(fd)
            unlinkat(session.fd, temp, 0)
            throw error
        }
        guard renameat(session.fd, temp, session.fd, name) == 0 else {
            let err = errno
            unlinkat(session.fd, temp, 0)
            throw DNSFailure.system("rename \(session.path)/\(temp)", err)
        }
    }
}
