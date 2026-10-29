import Foundation
import PassTunnelShared

#if canImport(Glibc)
import Glibc
#endif

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
    /// `ftruncate(2)`; tests make it fail, leaving a rewrite in place as a writer that died leaves it.
    public var truncateFile: (Int32, off_t) -> Int32 = { ftruncate($0, $1) }
    /// Called right before PassTunnel checks that /etc/resolv.conf is still what it read, and replaces
    /// it; tests change the file here, as another writer could.
    public var willReplace: (String) -> Void = { _ in }
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
/// starting daemon when one did not (`revert(in:)`, then `recover()`).
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
    /// recorded, unless a link's revert failed too: then the record stays, for `revert(in:)` to try again.
    /// Returns the backend used.
    @discardableResult
    public func apply(_ settings: DNSSettings, interface: String, in session: SessionDirectory) throws -> DNSBackend {
        let name = try DNSSettings.interface(interface)
        guard let index = system.interfaceIndex(name) else { throw DNSFailure.noInterface(name) }
        return try withLock { root in
            let (backend, tool) = try chooseBackend()
            var record = DNSRecord(backend: backend, interface: name, index: index)
            if backend == .file {
                let serial = (fileSessions(excluding: session.path).map(\.serial).max() ?? 0) + 1
                record = DNSRecord(
                    backend: .file, interface: name, index: index, serial: serial,
                    settings: try DNSSettings(
                        servers: settings.servers, searchDomains: settings.searchDomains,
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
                // Not undone, a link's settings keep their record, for the end of the session to try
                // again; on the file backend the run root's state has what is left to finish (`recover`).
                if undo(record, in: session, root: root).isEmpty || record.backend == .file { DNSRecord.remove(in: session) }
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
            for arguments in [
                ["dns", link] + settings.servers, ["domain", link] + domains,
                ["default-route", link, settings.fullTunnel ? "true" : "false"]
            ] {
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
            system.interfaceIndex(String(record.index)).map({ $0 == record.index }) ?? true
        else {
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

    // MARK: - Checking

    /// Whether the DNS `session` records is still in effect as `settings` set it up (openconnect's
    /// reconnect check, docs/LINUX.md): nil when it is, else why not. Read back from where it took effect,
    /// never only from the record:
    /// - systemd-resolved: the link's servers, domains and default route as `resolvectl dns`, `domain` and
    ///   `default-route` report them for the recorded index (after `checkLink`), compared as sets;
    /// - resolvconf: the resolv.conf the system reads (`system.resolvConf`, a link followed) names each of
    ///   the servers it was given as a `nameserver`;
    /// - the file: the record holds these servers and search domains, and `/etc/resolv.conf` is still
    ///   exactly what PassTunnel wrote last (the run root's state), with no change under way.
    /// What cannot be established (a tool that fails or answers in another form, a file that cannot be read)
    /// counts as not in effect.
    public func verify(_ settings: DNSSettings, in session: SessionDirectory) -> String? {
        let record: DNSRecord
        do {
            guard let loaded = try DNSRecord.load(in: session) else { return "nothing is recorded" }
            record = loaded
        } catch {
            return "the record cannot be read"
        }
        do {
            switch record.backend {
            case .resolved:
                guard let tool = try trustedTool(system.resolvectl) else { return "resolvectl is not installed" }
                try checkLink(record)
                let link = String(record.index)
                var domains = settings.searchDomains + settings.routingDomains.map { "~" + $0 }
                if settings.fullTunnel { domains.append("~.") }
                let servers = Set(settings.servers)
                guard let shown = try linkValue(tool, "dns", link, record), Set(shown.compactMap(Self.serverAddress)) == servers,
                    shown.count == servers.count
                else { return "systemd-resolved no longer has the link's DNS servers" }
                guard let shownDomains = try linkValue(tool, "domain", link, record), Set(shownDomains) == Set(domains) else {
                    return "systemd-resolved no longer has the link's DNS domains"
                }
                guard let route = try linkValue(tool, "default-route", link, record),
                    route == [settings.fullTunnel ? "yes" : "no"]
                else { return "systemd-resolved no longer has the link's DNS default route" }
                return nil
            case .resolvconf:
                guard let text = Self.readEffective(system.resolvConf, owner: system.owner) else {
                    return "\(system.resolvConf) cannot be read"
                }
                let named = Set(Self.nameservers(text))
                guard settings.servers.prefix(Self.maxNameservers).allSatisfy(named.contains) else {
                    return "\(system.resolvConf) no longer names the VPN's DNS servers"
                }
                return nil
            case .file:
                // The block of the session is made from its record: it must be what was asked for.
                guard record.settings?.servers == settings.servers, record.settings?.searchDomains == settings.searchDomains else {
                    return "the recorded DNS settings are not these"
                }
                let root = try lock()
                defer { close(root) }
                guard let current = try readResolvConf(), let state = ResolvConfBaseline.load(in: root, path: runRoot),
                    state.pending == nil, state.written == HelperCore.sha256Hex(current.data)
                else { return "\(system.resolvConf) was changed by something else" }
                return nil
            }
        } catch {
            return String(describing: error)
        }
    }

    /// The words `resolvectl <command> <index>` prints for the link: its line `Link <index> (<name>): …`;
    /// nil when it answers in another form or fails.
    private func linkValue(_ tool: String, _ command: String, _ link: String, _ record: DNSRecord) throws -> [String]? {
        guard let result = system.run(tool, [command, link], nil), result.status == 0 else { return nil }
        return Self.linkLine(result.output, index: record.index, interface: record.interface)
    }

    /// The words after `Link <index> (<interface>):` in `resolvectl`'s output; nil without that line.
    static func linkLine(_ output: String, index: UInt32, interface: String) -> [String]? {
        let prefix = "Link \(index) (\(interface)):"
        for line in output.split(whereSeparator: \.isNewline) where line.hasPrefix(prefix) {
            return line.dropFirst(prefix.count).split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        }
        return nil
    }

    /// A server as `resolvectl dns` shows it, in `DNSSettings.address`'s form: a plain address, or one with a
    /// port, interface or name (`[2001:db8::53]:53`, `192.0.2.53:53#dns.example.com`) only when the port is
    /// 53 and no interface is given; nil otherwise.
    static func serverAddress(_ word: String) -> String? {
        var text = Substring(word)
        if let hash = text.firstIndex(of: "#") { text = text[..<hash] }
        guard !text.contains("%") else { return nil }
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]") else { return nil }
            let rest = text[text.index(after: close)...]
            guard rest.isEmpty || rest == ":53" else { return nil }
            text = text[text.index(after: text.startIndex)..<close]
        } else if text.filter({ $0 == ":" }).count == 1 {
            guard text.hasSuffix(":53") else { return nil }
            text = text.dropLast(3)
        }
        return try? DNSSettings.address(String(text))
    }

    /// The `nameserver` addresses of a resolv.conf, in `DNSSettings.address`'s form.
    static func nameservers(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).compactMap { line in
            let words = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard words.count >= 2, words[0] == "nameserver" else { return nil }
            return try? DNSSettings.address(String(words[1]))
        }
    }

    /// The resolv.conf the system reads, a link followed (resolvconf's own file): a regular file of `owner`
    /// of at most `maxResolvConfBytes`; nil otherwise.
    static func readEffective(_ path: String, owner: uid_t) -> String? {
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == owner, st.st_size <= maxResolvConfBytes else {
            return nil
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while data.count <= maxResolvConfBytes {
            let n = read(fd, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { break }
            data.append(contentsOf: buffer[0..<n])
        }
        return data.count <= maxResolvConfBytes ? String(decoding: data, as: UTF8.self) : nil
    }

    // MARK: - Reverting

    /// Reverts what `session` records, then removes the record. Nil when nothing was recorded, else a
    /// line for the log. Never throws, and never changes anything without the run root's lock: when it
    /// cannot take the lock, or the revert fails, the record stays (and with it the session in the
    /// registry), for whoever ends the session to try again (`DNSRecord.isRecorded`); the caller keeps
    /// the session directory meanwhile.
    @discardableResult
    public func revert(in session: SessionDirectory) -> String? {
        guard DNSRecord.isRecorded(in: session) else { return nil }
        let root: Int32
        do {
            root = try lock()
        } catch {
            return "could not restore DNS yet (\(error)); kept, to be restored later"
        }
        defer { close(root) }
        let record: DNSRecord
        do {
            guard let loaded = try DNSRecord.load(in: session) else { return nil }
            record = loaded
        } catch {
            DNSRecord.remove(in: session)
            return "removed an unreadable DNS record: \(error)"
        }
        let what = "the DNS of \(record.interface) (\(record.backend.name))"
        let problems = undo(record, in: session, root: root)
        guard problems.isEmpty else {
            return "could not restore \(what) yet: " + problems.joined(separator: "; ") + "; kept, to be restored later"
        }
        DNSRecord.remove(in: session)
        return "restored \(what)"
    }

    /// Undoes `record` of `session` (the run root locked: `root`); the problems met, if any.
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

    /// What the file backend's state in the run root says is left to do, done: a change of
    /// /etc/resolv.conf that did not finish (its writer died) is finished, and with no session left
    /// the baseline comes back. Run by a starting daemon once it reverted what the sessions of an
    /// earlier one recorded, and again from time to time while something is left. Nil when there was
    /// nothing to do (or the lock was taken), else a line for the log.
    public func recover() -> String? {
        var st = stat()
        guard lstat(runRoot + "/" + ResolvConfBaseline.fileName, &st) == 0, let root = try? lock() else { return nil }
        defer { close(root) }
        guard fstatat(root, ResolvConfBaseline.fileName, &st, AT_SYMLINK_NOFOLLOW) == 0 else { return nil }
        let sessions = fileSessions()
        let interrupted = ResolvConfBaseline.load(in: root, path: runRoot)?.pending != nil
        guard sessions.isEmpty || interrupted else { return nil }
        let what =
            sessions.isEmpty
            ? "\(system.resolvConf), which no session uses any more"
            : "an interrupted change of \(system.resolvConf)"
        do {
            try updateResolvConf(root: root, sessions: sessions)
            return sessions.isEmpty ? "restored \(what)" : "finished \(what)"
        } catch DNSFailure.unexpectedLink {
            if sessions.isEmpty { ResolvConfBaseline.remove(in: root) }
            return nil
        } catch {
            return "could not restore \(what) yet: \(error)"
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
                    let record = try? DNSRecord.load(in: session), record.backend == .file
                else { continue }
                found.append(record)
            }
        }
        return found.sorted { ($0.serial, $0.interface) > ($1.serial, $1.interface) }
    }

    /// How often a change is tried again when the file changed between reading and writing it.
    static let writeAttempts = 3

    /// /etc/resolv.conf made again from the baseline and the newest of `sessions` (`root`: the run root,
    /// locked). Should someone else change the file between PassTunnel reading and replacing it, it is
    /// read again and the change worked out anew, `writeAttempts` times in all; then it fails
    /// (`changedMeanwhile`), the file left as the other writer made it.
    func updateResolvConf(root: Int32, sessions: [DNSRecord]) throws {
        var attempt = 1
        while true {
            do {
                return try updateResolvConfOnce(root: root, sessions: sessions)
            } catch DNSFailure.changedMeanwhile where attempt < Self.writeAttempts {
                attempt += 1
            }
        }
    }

    /// The file with the newest session's block at the top, the baseline's resolver lines disabled (a
    /// resolv.conf cannot route names, so the newest tunnel's DNS is in effect, and an older one's
    /// comes back when it ends). With no session the baseline comes back. The baseline is the recorded
    /// one while the file is still what PassTunnel wrote; changed by someone else since, it is the file
    /// without PassTunnel's lines (their changes stay); a file without any of them that no session needs
    /// any more is left alone. First, a change that did not finish is finished (`ResolvConfBaseline`).
    private func updateResolvConfOnce(root: Int32, sessions: [DNSRecord]) throws {
        var current = try readResolvConf()
        var saved = ResolvConfBaseline.load(in: root, path: runRoot)
        if let state = saved, let pending = state.pending {
            if ResolvConfBaseline.isInterrupted(
                current.map { [UInt8]($0.data) }, previous: pending.previous,
                intended: pending.intended)
            {
                try replaceResolvConf(with: pending.intended, expected: current)
                current = try readResolvConf()
            }
            // Else changed by someone else since: theirs, as any other change.
            saved = ResolvConfBaseline(written: state.written, content: state.content)
            try saved?.write(in: root, path: runRoot)
        }
        let currentBytes = current.map { [UInt8]($0.data) }
        let unchanged = current.map { saved != nil && saved?.written == HelperCore.sha256Hex($0.data) } ?? false
        let baseline: [UInt8]?
        if unchanged, let saved {
            baseline = saved.content
        } else if let currentBytes {
            baseline = ResolvConf.stripAll(currentBytes) ?? currentBytes
        } else {
            baseline = nil
        }
        guard let newest = sessions.first(where: { $0.settings != nil }), let settings = newest.settings else {
            if unchanged || currentBytes.map({ ResolvConf.stripAll($0) != nil }) == true {
                try transact(baseline, over: current, baseline: baseline, root: root)
            }
            ResolvConfBaseline.remove(in: root)
            return
        }
        let content = ResolvConf.apply(settings, interface: newest.interface, to: baseline ?? [])
        // What is written must be what PassTunnel can read back, to restore it.
        guard content.count <= Self.maxResolvConfBytes else { throw DNSFailure.wouldBeTooLarge(system.resolvConf) }
        if unchanged, currentBytes == content { return }
        try transact(content, over: current, baseline: baseline, root: root)
    }

    /// Writes `content` over `current` (nil: removes the file), journalled: the run root's state says
    /// first what is about to change (the file before and after, and the baseline), so that a writer
    /// dying in the middle of a rewrite in place leaves a change the next one finishes, never a file
    /// taken for someone else's.
    private func transact(_ content: [UInt8]?, over current: ResolvConfFile?, baseline: [UInt8]?, root: Int32) throws {
        var state = ResolvConfBaseline(
            written: content.map { HelperCore.sha256Hex(Data($0)) }, content: baseline,
            pending: .init(previous: current.map { [UInt8]($0.data) }, intended: content))
        try state.write(in: root, path: runRoot)
        try replaceResolvConf(with: content, expected: current)
        state.pending = nil
        try state.write(in: root, path: runRoot)
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
            let text = try? String(contentsOfFile: path, encoding: .utf8)
        else { return false }
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

    struct ResolvConfFile: Equatable {
        let data: Data
        let mode: mode_t
        let group: gid_t
        /// Which file it is, to tell it from one put in its place later.
        let device: UInt64
        let inode: UInt64
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
        return ResolvConfFile(
            data: data, mode: st.st_mode & 0o7777, group: st.st_gid,
            device: UInt64(opened.st_dev), inode: UInt64(opened.st_ino))
    }

    /// `content` in place of the file that was `expected` when PassTunnel read it (nil: there was none;
    /// `content` nil: removed), unless someone else replaced or changed it since (`changedMeanwhile`):
    /// checked right before, and the rewrite in place checks that it opened that same file. Only a
    /// writer that changes the file in the instant between the check and the write is not seen; the
    /// run root's lock cannot hold back writers outside PassTunnel.
    func replaceResolvConf(with content: [UInt8]?, expected: ResolvConfFile?) throws {
        let path = system.resolvConf
        system.willReplace(path)
        let now: ResolvConfFile?
        do {
            now = try readResolvConf()
        } catch DNSFailure.unexpectedLink {
            throw DNSFailure.changedMeanwhile(path)
        }
        guard now == expected else { throw DNSFailure.changedMeanwhile(path) }
        guard let content else {
            if expected != nil, unlink(path) != 0, errno != ENOENT { throw DNSFailure.system("remove \(path)", errno) }
            return
        }
        if let expected, expected.data == Data(content) { return }
        try writeResolvConf(Data(content), mode: expected?.mode ?? 0o644, group: expected?.group ?? 0, expected: expected)
    }

    /// Written next to /etc/resolv.conf, then renamed over it; a name of each process's own.
    var temporaryPath: String { system.resolvConf + ".passtunnel.\(getpid())" }

    /// Replaces /etc/resolv.conf atomically where it can: a new file in the same directory, synced,
    /// renamed over it. Where it cannot, the file is rewritten in place: inside passtunnel.service,
    /// where /etc is read-only and the file a bind mount of its own (`ReadWritePaths`), and where a
    /// container runtime bind-mounts it (rename fails with `EBUSY`).
    func writeResolvConf(_ data: Data, mode: mode_t, group: gid_t, expected: ResolvConfFile?) throws {
        let path = system.resolvConf, temp = temporaryPath
        guard !system.isReadOnly((path as NSString).deletingLastPathComponent) else {
            return try rewriteInPlace(data, expected: expected)
        }
        if unlink(temp) != 0, errno != ENOENT {
            if errno == EROFS { return try rewriteInPlace(data, expected: expected) }
            throw DNSFailure.system("remove \(temp)", errno)
        }
        let fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else {
            if errno == EROFS { return try rewriteInPlace(data, expected: expected) }
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
            try rewriteInPlace(data, expected: expected)
            return
        }
        let dir = open((path as NSString).deletingLastPathComponent, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        if dir >= 0 {
            _ = fsync(dir)
            close(dir)
        }
    }

    /// The whole content written at once from the start, the file cut to its length, synced; only into
    /// the file `expected` was. What it replaces is journalled in the run root first (`transact`).
    private func rewriteInPlace(_ data: Data, expected: ResolvConfFile?) throws {
        let path = system.resolvConf
        let fd = open(path, O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw DNSFailure.system("open \(path)", errno) }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == system.owner else {
            throw DNSFailure.notARegularFile(path)
        }
        guard let expected, UInt64(st.st_dev) == expected.device, UInt64(st.st_ino) == expected.inode else {
            throw DNSFailure.changedMeanwhile(path)
        }
        guard st.st_nlink > 0 else { throw DNSFailure.detached(path) }
        try Self.writeAll(fd, data, at: 0, path: path)
        guard system.truncateFile(fd, off_t(data.count)) == 0 else { throw DNSFailure.system("truncate \(path)", errno) }
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
            index > 0
        else { return nil }
        guard backend == .file else {
            guard lines[4...6].allSatisfy({ $0 == "-" }) else { return nil }
            self.init(backend: backend, interface: lines[2], index: index)
            return
        }
        guard let serial = UInt64(lines[4]), String(serial) == lines[4], serial > 0,
            let servers = Self.list(lines[5], DNSSettings.address), let search = Self.list(lines[6], DNSSettings.domain),
            let settings = try? DNSSettings(servers: servers, searchDomains: search, fullTunnel: true)
        else { return nil }
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

    /// Whether `session` still has a record: its DNS is not restored yet.
    static func isRecorded(in session: SessionDirectory) -> Bool {
        var st = stat()
        return fstatat(session.fd, fileName, &st, AT_SYMLINK_NOFOLLOW) == 0
    }
}

/// The file backend's state, in the run root (`resolv.conf.base`, root's, 0600) while a session's DNS
/// is in /etc/resolv.conf or something is left to restore: the baseline (the file as it is without
/// PassTunnel; nil: there was none), a digest of what PassTunnel wrote last (nil: it removed the
/// file), which tells whether anyone changed the file since, and, while a change is under way, the
/// file before and after it (`pending`), written before the file is touched. A starting daemon keeps
/// it while it is needed.
struct ResolvConfBaseline: Equatable {
    static let fileName = "resolv.conf.base"
    static let header = "passtunnel-resolv-base 2"
    /// The baseline and both files of a change, each at most what `readResolvConf` reads.
    static let maxBytes = 3 * DNSApplier.maxResolvConfBytes + 512

    /// A change under way: the file before it (nil: none) and after it (nil: removed).
    struct Pending: Equatable {
        let previous: [UInt8]?
        let intended: [UInt8]?
    }

    let written: String?
    let content: [UInt8]?
    var pending: Pending?

    init(written: String?, content: [UInt8]?, pending: Pending? = nil) {
        self.written = written
        self.content = content
        self.pending = pending
    }

    /// Four lines (header; digest or "-"; the baseline's length or "-"; "-", or the lengths of the
    /// file before and after the change, each a number or "-"), then the bytes of the baseline and of
    /// the two files, as they are.
    var bytes: [UInt8] {
        func length(_ bytes: [UInt8]?) -> String { bytes.map { String($0.count) } ?? "-" }
        let change = pending.map { length($0.previous) + " " + length($0.intended) } ?? "-"
        let head = "\(Self.header)\n\(written ?? "-")\n\(length(content))\n\(change)\n"
        return Array(head.utf8) + (content ?? []) + (pending?.previous ?? []) + (pending?.intended ?? [])
    }

    init?(bytes: [UInt8]) {
        var lines: [String] = []
        var start = 0
        while lines.count < 4, let end = bytes[start...].firstIndex(of: 0x0A) {
            lines.append(String(decoding: bytes[start..<end], as: UTF8.self))
            start = end + 1
        }
        guard lines.count == 4, lines[0] == Self.header else { return nil }
        let written: String?
        if lines[1] == "-" {
            written = nil
        } else {
            guard lines[1].utf8.count == 64,
                lines[1].utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) })
            else { return nil }
            written = lines[1]
        }
        var rest = bytes[start...]
        func take(_ field: Substring) -> [UInt8]?? {
            if field == "-" { return .some(nil) }
            guard let n = Int(field), String(n) == field, n >= 0, n <= DNSApplier.maxResolvConfBytes, n <= rest.count else { return nil }
            defer { rest = rest.dropFirst(n) }
            return .some(Array(rest.prefix(n)))
        }
        guard let content = take(Substring(lines[2])) else { return nil }
        var pending: Pending?
        if lines[3] != "-" {
            let fields = lines[3].split(separator: " ", omittingEmptySubsequences: false)
            guard fields.count == 2, let previous = take(fields[0]), let intended = take(fields[1]),
                written == intended.map({ HelperCore.sha256Hex(Data($0)) })
            else { return nil }
            pending = Pending(previous: previous, intended: intended)
        }
        guard rest.isEmpty else { return nil }
        self.init(written: written, content: content, pending: pending)
    }

    /// Nil when there is none, or it cannot be read (the file is then taken as someone else's).
    static func load(in root: Int32, path: String) -> ResolvConfBaseline? {
        guard let data = try? RootFile.load(fileName, at: root, path: path, maxBytes: maxBytes) else { return nil }
        return ResolvConfBaseline(bytes: [UInt8](data))
    }

    func write(in root: Int32, path: String) throws {
        try RootFile.store(Self.fileName, Data(bytes), at: root, path: path)
    }

    static func remove(in root: Int32) {
        _ = unlinkat(root, fileName, 0)
    }

    /// Whether `current` is what a change of `previous` into `intended` can leave when its writer died:
    /// either of them (a rename and a removal are atomic), or, rewritten in place, the start of
    /// `intended` over the rest of `previous` (cut to its length or not yet), or the start of
    /// `intended` alone where it grew past `previous`. Anything else is someone else's change.
    static func isInterrupted(_ current: [UInt8]?, previous: [UInt8]?, intended: [UInt8]?) -> Bool {
        if current == previous || current == intended { return true }
        guard let current, let previous, let intended else { return false }
        if current.count > previous.count { return intended.starts(with: current) }
        guard current.count == previous.count else { return false }
        let written = zip(current, intended).prefix { $0 == $1 }.count  // at most this much of `intended`
        var kept = current.count  // `previous` from here on
        while kept > 0, current[kept - 1] == previous[kept - 1] { kept -= 1 }
        return kept <= written
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
        let temp = "." + name + ".\(getpid()).new"  // a name of each process's own
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
