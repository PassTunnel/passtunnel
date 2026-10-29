import Foundation
import PassTunnelShared

/// What an earlier daemon left in the run root: sessions it recorded (`<uid>/<id>/state`) whose tool
/// may still run, the DNS they set up (`<uid>/<id>/dns`), and anything else. A starting daemon stops
/// those tools (SIGTERM, SIGKILL after the grace period), reverts that DNS and removes every session
/// directory whose DNS is restored; it does not adopt them. Under systemd, `KillMode=control-group`
/// has already stopped them.
///
/// A recorded pid is signalled only while it is provably the recorded process: the same boot, the same
/// start time and the same executable, checked after a pidfd of it was opened and before every signal,
/// which goes through that pidfd, so it cannot reach a process that took the pid over in between.
/// Nothing is ever signalled by number: without pidfds (Linux before 5.3) a tool is left running and
/// logged, and so is one whose state has no boot ID and start time (written by an earlier build). Its
/// process group is signalled through the pidfd where the kernel can (6.9); before that only the
/// tool itself is.
///
/// A session whose DNS or openconnect network cannot be restored yet (a lock is held, the file cannot be
/// written, a route cannot be deleted) keeps its directory and records, and the run root its file-backend
/// state (`ResolvConfBaseline`): the daemon tries again later (`Supervisor`).
enum PreviousInstance {
    struct State: Equatable {
        let pid: pid_t
        let uid: uid_t
        let executable: String
        /// `/proc/sys/kernel/random/boot_id` and field 22 of `/proc/<pid>/stat` (clock ticks after boot)
        /// when the tool started; nil in a state an earlier build wrote.
        var bootID: String? = nil
        var startTime: UInt64? = nil
    }

    /// What the process a state records is now.
    enum Identity: Equatable {
        /// It still runs: same boot, start time and executable.
        case same
        /// It is gone, or its pid belongs to another process.
        case gone
        /// Something runs the recorded executable under that pid, but the state has no boot ID and
        /// start time to tell whether it is the recorded process.
        case unverifiable
    }

    /// How processes are signalled: through pidfds only (`Sys`); replaced in tests.
    struct Pidfds {
        var open: (pid_t) -> Int32? = Sys.pidfdOpen
        var signal: (Int32, Int32, Bool) -> Int32 = { Sys.pidfdSignal($0, $1, processGroup: $2) }
    }

    struct Outcome: Equatable {
        /// The pids it signalled.
        var signalled: [pid_t] = []
        /// The sessions whose DNS or network is not restored yet, left in place for the daemon to try again.
        var pending: [SessionPolicy.Key] = []
    }

    /// Stops the recorded tools that still run, restores what every session recorded (with `restore`: an
    /// openconnect session's network, then the DNS) and removes everything in `runRoot` but the entries in
    /// `keep` (the daemon's socket and locks), the sessions not restored yet, and the file backend's state
    /// while it is needed.
    @discardableResult
    static func cleanUp(
        runRoot: String, keep: Set<String>, grace: TimeInterval = 5, restore: SessionRestore? = nil,
        pidfds: Pidfds = Pidfds()
    ) -> Outcome {
        var running: [State] = []
        for entry in entries(runRoot) where !keep.contains(entry) {
            let path = runRoot + "/" + entry
            guard let uid = uid_t(entry), String(uid) == entry, isRealDirectory(path) else { continue }
            for id in entries(path) {
                guard HelperCore.isValidProfileID(id), let state = readState(path + "/" + id + "/" + Supervisor.stateFileName),
                    state.uid == uid
                else { continue }
                switch identify(state) {
                case .same:
                    running.append(state)
                case .unverifiable:
                    DaemonLog.info(
                        "pid \(state.pid) of uid \(state.uid) runs \(state.executable), recorded by an earlier "
                            + "instance without its start time: not stopped, as it may be another process")
                case .gone:
                    continue
                }
            }
        }
        var outcome = Outcome()
        var signalled: [State] = []
        for state in running {
            DaemonLog.info("stopping pid \(state.pid) of uid \(state.uid), left running by an earlier instance")
            if deliver(SIGTERM, to: state, pidfds: pidfds) { signalled.append(state) }
        }
        let deadline = Date().addingTimeInterval(grace)
        while signalled.contains(where: isAlive), Date() < deadline { usleep(100_000) }
        for state in signalled where isAlive(state) {
            DaemonLog.info("pid \(state.pid) ignored SIGTERM, killing it")
            deliver(SIGKILL, to: state, pidfds: pidfds)
        }
        outcome.signalled = signalled.map(\.pid)
        if let restore {
            outcome.pending = restoreSessions(runRoot: runRoot, keep: keep, restore: restore)
            if let message = restore.dns.recover() { DaemonLog.info(message) }
        }
        let pending = Set(outcome.pending)
        for entry in entries(runRoot) where !keep.contains(entry) && entry != ResolvConfBaseline.fileName {
            let path = runRoot + "/" + entry
            guard let uid = uid_t(entry), String(uid) == entry, isRealDirectory(path) else {
                HelperCore.removeEntry(path)
                continue
            }
            for id in entries(path) {
                if pending.contains(SessionPolicy.Key(uid: uid, profileID: id)) {
                    keepOnlyRecords(in: path + "/" + id)
                } else {
                    HelperCore.removeEntry(path + "/" + id)
                }
            }
            _ = rmdir(path)  // unless a session is left in it
        }
        return outcome
    }

    /// What each session directory records, restored (its tool, stopped by now, did not). Returns the
    /// sessions with something still recorded: not restored yet.
    static func restoreSessions(runRoot: String, keep: Set<String>, restore: SessionRestore) -> [SessionPolicy.Key] {
        let core = HelperCore(runRoot: runRoot)
        var pending: [SessionPolicy.Key] = []
        for entry in entries(runRoot) where !keep.contains(entry) {
            guard let uid = uid_t(entry), String(uid) == entry, isRealDirectory(runRoot + "/" + entry) else { continue }
            for id in entries(runRoot + "/" + entry) {
                guard HelperCore.isValidProfileID(id), let session = try? core.openRunDir(profileID: id, uid: uid) else { continue }
                let key = SessionPolicy.Key(uid: uid, profileID: id)
                if !restore.restore(session, key: key, context: "left by an earlier instance") { pending.append(key) }
            }
        }
        return pending
    }

    /// Sends `sig` through a pidfd of the recorded process, opened before `identify` says it still is
    /// that process; to its whole process group when it leads one (as every tool the daemon starts
    /// does) and the kernel can (Linux 6.9), else to the process alone. Never by number: without a
    /// pidfd nothing is sent. False when nothing was sent.
    @discardableResult
    static func deliver(_ sig: Int32, to state: State, pidfds: Pidfds = Pidfds()) -> Bool {
        guard let pidfd = pidfds.open(state.pid) else {
            if identify(state) == .same {
                DaemonLog.info(
                    "pid \(state.pid) of uid \(state.uid) is not signalled: this kernel has no pidfds, "
                        + "and a signal by number could reach another process")
            }
            return false
        }
        defer { close(pidfd) }
        guard identify(state) == .same else { return false }
        if getpgid(state.pid) == state.pid, pidfds.signal(pidfd, sig, true) == 0 { return true }
        return pidfds.signal(pidfd, sig, false) == 0
    }

    static func readState(_ path: String) -> State? {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == geteuid(), st.st_size < 8192,
            let text = try? String(contentsOfFile: path, encoding: .utf8)
        else { return nil }
        let parts = text.components(separatedBy: "\n")
        guard parts.count >= 3, let pid = pid_t(parts[0]), let uid = uid_t(parts[1]), pid > 1,
            parts[2].hasPrefix("/")
        else { return nil }
        var state = State(pid: pid, uid: uid, executable: parts[2])
        // Boot ID and start time follow profile directory and management socket; both or none.
        if parts.count >= 7, !parts[5].isEmpty || !parts[6].isEmpty {
            guard isBootID(parts[5]), let start = UInt64(parts[6]), String(start) == parts[6] else { return nil }
            state.bootID = parts[5]
            state.startTime = start
        }
        return state
    }

    /// The text recorded for the process `pid` (just started, not reaped): its boot ID and start time
    /// lines, empty where they cannot be read.
    static func identityLines(of pid: pid_t) -> String {
        guard let boot = bootID(), let start = startTime(of: pid) else { return "\n\n" }
        return "\(boot)\n\(start)\n"
    }

    /// The recorded process still runs what it ran (not a recycled pid): `identify` is `.same`.
    static func isAlive(_ s: State) -> Bool { identify(s) == .same }

    static func identify(_ s: State) -> Identity {
        guard isRunning(s), let exe = executable(of: s.pid), exe == s.executable || exe == s.executable + " (deleted)" else {
            return .gone
        }
        guard let boot = s.bootID, let start = s.startTime else { return .unverifiable }
        // A replaced executable (a package update) shows as "<path> (deleted)"; the start time is read
        // after the executable, so a process that took the pid over in between shows a later one.
        return boot == bootID() && start == startTime(of: s.pid) ? .same : .gone
    }

    /// Exists and is not a zombie (which nothing may reap where the daemon is not its parent).
    static func isRunning(_ s: State) -> Bool {
        guard kill(s.pid, 0) == 0 || errno == EPERM else { return false }
        return processState(s.pid).map { $0 != "Z" && $0 != "X" } ?? false
    }

    /// The fields of `/proc/<pid>/stat` after the command name (which may contain anything), from the
    /// third (the state letter) on.
    static func statFields(_ pid: pid_t) -> [Substring]? {
        guard let text = try? String(contentsOfFile: "/proc/\(pid)/stat", encoding: .utf8),
            let end = text.lastIndex(of: ")")
        else { return nil }
        return text[text.index(after: end)...].split(separator: " ")
    }

    /// The state letter of `/proc/<pid>/stat`.
    static func processState(_ pid: pid_t) -> Character? {
        statFields(pid)?.first?.first
    }

    /// Field 22 of `/proc/<pid>/stat`: when the process started, in clock ticks after boot.
    static func startTime(of pid: pid_t) -> UInt64? {
        guard let fields = statFields(pid), fields.count > 19 else { return nil }
        return UInt64(fields[19])
    }

    /// This boot's random ID, which a new boot changes.
    static func bootID(path: String = "/proc/sys/kernel/random/boot_id") -> String? {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        let id = text.trimmingCharacters(in: .newlines)
        return isBootID(id) ? id : nil
    }

    /// A UUID as the kernel writes it: 36 lowercase hex digits and dashes.
    static func isBootID(_ text: String) -> Bool {
        let bytes = Array(text.utf8)
        return bytes.count == 36
            && bytes.enumerated().allSatisfy { i, c in
                [8, 13, 18, 23].contains(i) ? c == 0x2D : (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66)
            }
    }

    static func executable(of pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 4097)
        let n = readlink("/proc/\(pid)/exe", &buf, buf.count - 1)
        guard n > 0 else { return nil }
        buf[n] = 0
        return String(cString: buf)
    }

    /// A session directory not restored yet loses everything but its records (`dns`, and openconnect's
    /// `network`): the tool's config and auth file hold secrets (openconnect's its cookie), and nothing else
    /// is needed to restore it.
    static func keepOnlyRecords(in dir: String) {
        for name in entries(dir) where name != DNSRecord.fileName && name != OpenConnectRecord.fileName {
            HelperCore.removeEntry(dir + "/" + name)
        }
    }

    static func entries(_ dir: String) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
    }

    static func isRealDirectory(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR && st.st_uid == geteuid()
    }
}

/// Restores what an ended session left (docs/LINUX.md, "Cisco AnyConnect" and "DNS"): an openconnect
/// session's network from its record (`OpenConnectHook.restoreAfterExit`, as the Mac's helper does: the
/// session marked as stopping, a hook still running waited for and, past its limit, killed, then everything
/// the record holds reverted but what another session holds), then whatever `DNSApplier` still records. Used
/// by the daemon when a tool exits, when it stops, for its retries, and by a starting daemon.
struct SessionRestore {
    let runRoot: String
    let dns: DNSApplier
    /// The system an openconnect session's network is restored with (`LinuxOpenConnectSystem`; a fake in tests).
    let openConnect: (SessionDirectory) -> OpenConnectSystem
    /// The daemon's own executable: what a running hook of a session runs (`LinuxVPNHook.killHook`).
    let hookExecutable: String?

    /// Restores `session`; true when nothing is left recorded. `context` goes into the daemon's log lines.
    func restore(_ session: SessionDirectory, key: SessionPolicy.Key, context: String? = nil) -> Bool {
        let name = "\(key.profileID) of uid \(key.uid)" + (context.map { ", \($0)" } ?? "")
        if OpenConnectJournal.exists(runDir: session.path) {
            let runDir = session.path, executable = hookExecutable
            let result = OpenConnectHook.restoreAfterExit(
                runRoot: runRoot, runDir: runDir, system: openConnect(session),
                killHook: { LinuxVPNHook.killHook(runDir: runDir, executable: executable) })
            switch result {
            case .done:
                _ = unlinkat(session.fd, OpenConnectRecord.fileName, 0)
            case .unreadable:
                DaemonLog.info("\(name): the network record cannot be read; nothing restored from it")
                _ = unlinkat(session.fd, OpenConnectRecord.fileName, 0)
            case .failed(let reason):
                DaemonLog.info("\(name): could not restore the network yet: \(reason); kept, to be restored later")
            }
        }
        if let message = dns.revert(in: session) { DaemonLog.info("\(name): \(message)") }
        return !OpenConnectJournal.exists(runDir: session.path) && !DNSRecord.isRecorded(in: session)
    }
}
