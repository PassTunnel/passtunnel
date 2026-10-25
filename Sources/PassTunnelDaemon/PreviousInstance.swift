import Foundation
import PassTunnelShared

/// What an earlier daemon left in the run root: sessions it recorded (`<uid>/<id>/state`) whose tool
/// may still run, the DNS they set up (`<uid>/<id>/dns`), and anything else. A starting daemon stops
/// those tools (SIGTERM to their process groups, SIGKILL after the grace period), reverts that DNS and
/// removes every session directory; it does not adopt them. Under systemd, `KillMode=control-group`
/// has already stopped them.
enum PreviousInstance {
    struct State: Equatable {
        let pid: pid_t
        let uid: uid_t
        let executable: String
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
                      state.uid == uid, isAlive(state) else { continue }
                running.append(state)
            }
        }
        for state in running {
            DaemonLog.info("stopping pid \(state.pid) of uid \(state.uid), left running by an earlier instance")
            deliver(SIGTERM, to: state)
        }
        let deadline = Date().addingTimeInterval(grace)
        while running.contains(where: isRunning), Date() < deadline { usleep(100_000) }
        for state in running where isRunning(state) {
            DaemonLog.info("pid \(state.pid) ignored SIGTERM, killing it")
            deliver(SIGKILL, to: state)
        }
        if let dns { revertDNS(runRoot: runRoot, keep: keep, dns: dns) }
        for entry in entries(runRoot) where !keep.contains(entry) {
            HelperCore.removeEntry(runRoot + "/" + entry)
        }
        return running.map(\.pid)
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

    /// Its whole process group when it leads one (as every tool the daemon starts does).
    static func deliver(_ sig: Int32, to state: State) {
        if getpgid(state.pid) == state.pid { kill(-state.pid, sig) }
        kill(state.pid, sig)
    }

    static func readState(_ path: String) -> State? {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == geteuid(), st.st_size < 8192,
              let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        let parts = text.components(separatedBy: "\n")
        guard parts.count >= 3, let pid = pid_t(parts[0]), let uid = uid_t(parts[1]), pid > 1,
              parts[2].hasPrefix("/") else { return nil }
        return State(pid: pid, uid: uid, executable: parts[2])
    }

    /// The recorded process still runs the recorded executable (not a recycled pid). A replaced
    /// executable (a package update) shows as "<path> (deleted)".
    static func isAlive(_ s: State) -> Bool {
        guard isRunning(s), let exe = executable(of: s.pid) else { return false }
        return exe == s.executable || exe == s.executable + " (deleted)"
    }

    /// Exists and is not a zombie (which nothing may reap where the daemon is not its parent).
    static func isRunning(_ s: State) -> Bool {
        guard kill(s.pid, 0) == 0 || errno == EPERM else { return false }
        return processState(s.pid).map { $0 != "Z" && $0 != "X" } ?? false
    }

    /// The state letter of `/proc/<pid>/stat` (after the command name, which may contain anything).
    static func processState(_ pid: pid_t) -> Character? {
        guard let text = try? String(contentsOfFile: "/proc/\(pid)/stat", encoding: .utf8),
              let end = text.lastIndex(of: ")") else { return nil }
        return text[text.index(after: end)...].first { $0 != " " }
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
