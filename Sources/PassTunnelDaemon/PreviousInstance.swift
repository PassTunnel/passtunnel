import Foundation
import PassTunnelShared

/// What an earlier daemon left in the run root: sessions it recorded (`<uid>/<id>/state`) whose tool
/// may still run, the DNS they set up (`<uid>/<id>/dns`), and anything else. A starting daemon stops
/// those tools (SIGTERM to their process groups, SIGKILL after the grace period), reverts that DNS and
/// removes every session directory; it does not adopt them. Under systemd, `KillMode=control-group`
/// has already stopped them.
///
/// A recorded pid is signalled only while it is provably the recorded process: the same boot, the same
/// start time and the same executable, checked again before every signal, through a pidfd where the
/// kernel and the C library have one (then the signal cannot reach a process that took the pid over
/// in between). A state without boot ID and start time (written by an earlier build) cannot prove
/// that, and its pid is never signalled: a stray tool is left running and logged, rather than risking
/// a signal to an unrelated process that got its pid.
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

    /// Stops the recorded tools that still run, reverts the DNS of every session (with `dns`) and
    /// removes everything in `runRoot` but the entries in `keep` (the daemon's socket and lock).
    /// Returns the pids it signalled.
    @discardableResult
    static func cleanUp(runRoot: String, keep: Set<String>, grace: TimeInterval = 5, dns: DNSApplier? = nil) -> [pid_t] {
        var running: [State] = []
        for entry in entries(runRoot) where !keep.contains(entry) {
            let path = runRoot + "/" + entry
            guard let uid = uid_t(entry), String(uid) == entry, isRealDirectory(path) else { continue }
            for id in entries(path) {
                guard HelperCore.isValidProfileID(id), let state = readState(path + "/" + id + "/" + Supervisor.stateFileName),
                      state.uid == uid else { continue }
                switch identify(state) {
                case .same:
                    running.append(state)
                case .unverifiable:
                    DaemonLog.info("pid \(state.pid) of uid \(state.uid) runs \(state.executable), recorded by an earlier "
                                   + "instance without its start time: not stopped, as it may be another process")
                case .gone:
                    continue
                }
            }
        }
        var signalled: [State] = []
        for state in running {
            DaemonLog.info("stopping pid \(state.pid) of uid \(state.uid), left running by an earlier instance")
            if deliver(SIGTERM, to: state) { signalled.append(state) }
        }
        let deadline = Date().addingTimeInterval(grace)
        while signalled.contains(where: isAlive), Date() < deadline { usleep(100_000) }
        for state in signalled where isAlive(state) {
            DaemonLog.info("pid \(state.pid) ignored SIGTERM, killing it")
            deliver(SIGKILL, to: state)
        }
        if let dns {
            revertDNS(runRoot: runRoot, keep: keep, dns: dns)
            if let message = dns.restoreUnclaimed() { DaemonLog.info(message) }
        }
        for entry in entries(runRoot) where !keep.contains(entry) {
            HelperCore.removeEntry(runRoot + "/" + entry)
        }
        return signalled.map(\.pid)
    }

    /// The DNS each session directory records, reverted (its tool, stopped by now, did not).
    static func revertDNS(runRoot: String, keep: Set<String>, dns: DNSApplier) {
        let core = HelperCore(runRoot: runRoot)
        for entry in entries(runRoot) where !keep.contains(entry) {
            guard let uid = uid_t(entry), String(uid) == entry, isRealDirectory(runRoot + "/" + entry) else { continue }
            for id in entries(runRoot + "/" + entry) {
                guard HelperCore.isValidProfileID(id), let session = try? core.openRunDir(profileID: id, uid: uid),
                      let message = dns.revert(in: session) else { continue }
                DaemonLog.info("\(id) of uid \(uid), left by an earlier instance: \(message)")
            }
        }
    }

    /// Sends `sig` to the recorded process, and to its whole process group when it leads one (as every
    /// tool the daemon starts does), once `identify` says it is still the recorded one. With a pidfd
    /// (opened before the check, so it refers to the checked process) the process itself, and on Linux
    /// 6.9 its group too, is signalled through it; the group is otherwise signalled by number right after
    /// the check, while its leader is known to run (a group's number is not reused while it has members).
    /// False when nothing was sent.
    @discardableResult
    static func deliver(_ sig: Int32, to state: State) -> Bool {
        let pidfd = Sys.pidfdOpen(state.pid)
        defer { pidfd.map { _ = close($0) } }
        guard identify(state) == .same else { return false }
        let leadsGroup = getpgid(state.pid) == state.pid
        guard let pidfd else {
            if leadsGroup { kill(-state.pid, sig) }
            return kill(state.pid, sig) == 0
        }
        if leadsGroup {
            switch Sys.pidfdSignal(pidfd, sig, processGroup: true) {
            case 0: return true
            case EINVAL: kill(-state.pid, sig)          // before Linux 6.9
            default: break
            }
        }
        return Sys.pidfdSignal(pidfd, sig, processGroup: false) == 0
    }

    static func readState(_ path: String) -> State? {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == geteuid(), st.st_size < 8192,
              let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        let parts = text.components(separatedBy: "\n")
        guard parts.count >= 3, let pid = pid_t(parts[0]), let uid = uid_t(parts[1]), pid > 1,
              parts[2].hasPrefix("/") else { return nil }
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
              let end = text.lastIndex(of: ")") else { return nil }
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
        return bytes.count == 36 && bytes.enumerated().allSatisfy { i, c in
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

    static func entries(_ dir: String) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
    }

    static func isRealDirectory(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR && st.st_uid == geteuid()
    }
}
