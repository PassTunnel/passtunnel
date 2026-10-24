import Foundation
import PassTunnelShared

/// Starts, tracks and stops the VPN tools, as the Mac's helper does; all state is confined to `queue`.
/// Sessions are keyed by (owner uid, profile ID) (`SessionPolicy`). Each child has a thread of its own
/// that waits for it to exit. There is no adoption: tools recorded by an earlier instance are stopped
/// when the daemon starts (`stopPreviousInstance`).
final class Supervisor {
    typealias Key = SessionPolicy.Key

    struct Job {
        let profileID: String
        let ownerUID: uid_t
        let pid: pid_t
        let executable: String
        let sessionDir: SessionDirectory
        let mgmtSocket: String?
        /// Our copy of the tool's log descriptor, for `HelperCore.capLog`.
        let logFD: Int32
        var waiters: [() -> Void] = []

        var key: Key { Key(uid: ownerUID, profileID: profileID) }
    }

    static let logCheckInterval: TimeInterval = 60
    static let stateFileName = "state"

    let queue = DispatchQueue(label: "passtunneld.supervisor")
    private let core: HelperCore
    private let tools: ToolResolving
    private let stopGrace: TimeInterval
    private var jobs: [Key: Job] = [:]
    private var logTimer: DispatchSourceTimer?

    private var sessions: [SessionPolicy.Session] {
        jobs.values.map {
            SessionPolicy.Session(profileID: $0.profileID, ownerUID: $0.ownerUID, pid: $0.pid, mgmtSocket: $0.mgmtSocket)
        }
    }

    init(core: HelperCore, tools: ToolResolving, stopGrace: TimeInterval = 5) {
        self.core = core
        self.tools = tools
        self.stopGrace = stopGrace
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + Self.logCheckInterval, repeating: Self.logCheckInterval)
        timer.setEventHandler { [weak self] in self?.capLogs() }
        timer.resume()
        logTimer = timer
    }

    deinit { logTimer?.cancel() }

    /// A long session must not fill the disk: logs above `HelperCore.maxLogBytes` keep only their ends.
    private func capLogs() {
        for job in jobs.values where HelperCore.capLog(fd: job.logFD) {
            DaemonLog.info("trimmed the log of \(job.profileID) (uid \(job.ownerUID))")
        }
    }

    // MARK: - Requests

    func handle(_ request: HelperRequest, uid: uid_t, reply: @escaping (HelperResponse) -> Void) {
        queue.async {
            switch request {
            case .startOpenVPN(let s):
                reply(self.startOpenVPN(s, uid: uid))
            case .startForti:
                reply(.failure("FortiGate profiles cannot be connected on Linux yet: the daemon runs OpenVPN only for now."))
            case .stop(let id):
                self.stop(profileID: id, uid: uid, reply: reply)
            case .status:
                reply(.success(running: SessionPolicy.visible(to: uid, sessions: self.sessions),
                               mgmtSockets: SessionPolicy.sockets(visibleTo: uid, sessions: self.sessions)))
            }
        }
    }

    private func startOpenVPN(_ s: OpenVPNStart, uid: uid_t) -> HelperResponse {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            try SessionPolicy.checkStart(profileID: s.profileID, uid: uid, sessions: sessions)
        } catch {
            return .failure(String(describing: error))
        }
        let tool: ResolvedTool
        let plan: HelperCore.LaunchPlan
        do {
            tool = try tools.resolve(.openvpn)
            var core = self.core
            // DNS is left alone for now: `--dns-updown disable` where OpenVPN knows it (2.7), nothing on 2.6.
            core.openVPNHasDNSUpdown = tool.version >= ToolVersion(2, 7, 0)
            plan = try core.prepareOpenVPN(s, uid: uid)
        } catch {
            DaemonLog.info("start of \(s.profileID) for uid \(uid) refused: \(error)")
            return .failure(error)
        }
        defer { close(plan.logFD) }
        do {
            let pid = try Sys.spawn(executable: tool.path, arguments: plan.arguments,
                                    environment: HelperCore.fixedEnvironment,
                                    workingDirectory: plan.runDir, outputFD: plan.logFD)
            writeState(plan: plan, pid: pid, executable: tool.path)
            let logCopy = fcntl(plan.logFD, F_DUPFD_CLOEXEC, 0)
            let job = Job(profileID: plan.profileID, ownerUID: plan.ownerUID, pid: pid, executable: tool.path,
                          sessionDir: plan.sessionDir, mgmtSocket: plan.mgmtSocket, logFD: logCopy)
            jobs[job.key] = job
            watch(job.key, pid: pid)
            if plan.mgmtSocket != nil { restrictSocketWhenReady(job.key, pid: pid, attempt: 0) }
            DaemonLog.info("started OpenVPN \(tool.version) for \(s.profileID), uid \(uid), pid \(pid)")
            return .success(pid: pid, mgmtSocket: plan.mgmtSocket)
        } catch {
            core.removeRunDir(profileID: s.profileID, uid: uid)
            let line = "PassTunnel: \(error)\n"
            _ = line.withCString { write(plan.logFD, $0, strlen($0)) }
            DaemonLog.info("start of \(s.profileID) for uid \(uid) failed: \(error)")
            return .failure(String(describing: error))
        }
    }

    /// OpenVPN binds its management socket with umask 0 and relies on --management-client-user; once
    /// the socket exists it goes to the user with mode 0600 as a second barrier. The session directory
    /// is root-owned, so nobody else can swap the entry in between.
    private func restrictSocketWhenReady(_ key: Key, pid: pid_t, attempt: Int) {
        guard let job = jobs[key], job.pid == pid, attempt < 100 else { return }
        if job.sessionDir.restrictSocket(PT.mgmtSocketName) { return }
        queue.asyncAfter(deadline: .now() + 0.1) { [weak self] in
            self?.restrictSocketWhenReady(key, pid: pid, attempt: attempt + 1)
        }
    }

    private func stop(profileID: String, uid: uid_t, reply: @escaping (HelperResponse) -> Void) {
        dispatchPrecondition(condition: .onQueue(queue))
        let key = Key(uid: uid, profileID: profileID)
        guard case .terminate = SessionPolicy.stopDecision(profileID: profileID, uid: uid, sessions: sessions),
              let job = jobs[key] else { return reply(.success()) }
        jobs[key]?.waiters.append { reply(.success(pid: job.pid)) }
        terminate(job)
    }

    /// SIGTERM now, SIGKILL to the whole process group after the grace period. The child is reaped
    /// only on the queue (`exited`), so its pid cannot be reused while the job is listed.
    private func terminate(_ job: Job) {
        kill(job.pid, SIGTERM)
        queue.asyncAfter(deadline: .now() + stopGrace) { [weak self] in
            guard let self, let current = self.jobs[job.key], current.pid == job.pid else { return }
            DaemonLog.info("pid \(job.pid) ignored SIGTERM, killing it")
            kill(-job.pid, SIGKILL)
            kill(job.pid, SIGKILL)
        }
    }

    /// Stops everything (daemon shutdown). Blocks up to the grace period plus a little.
    func stopAll() {
        let group = DispatchGroup()
        queue.sync {
            for job in jobs.values {
                group.enter()
                jobs[job.key]?.waiters.append { group.leave() }
                terminate(job)
            }
        }
        _ = group.wait(timeout: .now() + stopGrace + 1.5)
        queue.sync {
            for job in jobs.values {
                kill(-job.pid, SIGKILL)
                core.removeRunDir(profileID: job.profileID, uid: job.ownerUID)
            }
        }
    }

    // MARK: - Exit

    /// One thread per child waits for it to exit without reaping it (`WNOWAIT`): until `exited` reaps
    /// it on the queue, the pid stays taken, so signals to it or its process group cannot reach
    /// another process.
    private func watch(_ key: Key, pid: pid_t) {
        let thread = Thread { [weak self] in
            var info = siginfo_t()
            while waitid(P_PID, id_t(pid), &info, WEXITED | WNOWAIT) != 0, errno == EINTR {}
            self?.queue.async { self?.exited(key, pid: pid) }
        }
        thread.name = "passtunneld.wait.\(pid)"
        thread.start()
    }

    private func exited(_ key: Key, pid: pid_t) {
        guard let job = jobs[key], job.pid == pid else { return }
        kill(-pid, SIGTERM)          // anything left in its process group
        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1, errno == EINTR {}
        close(job.logFD)
        jobs[key] = nil
        core.removeRunDir(profileID: job.profileID, uid: job.ownerUID)   // config, auth file, socket, state
        DaemonLog.info("\(job.profileID) of uid \(job.ownerUID) exited (pid \(pid), status \(status))")
        job.waiters.forEach { $0() }
    }

    // MARK: - State of the previous instance

    /// Records pid, owner, executable, profile directory and management socket, so that the next
    /// instance can stop a tool this one leaves behind.
    private func writeState(plan: HelperCore.LaunchPlan, pid: pid_t, executable: String) {
        let text = "\(pid)\n\(plan.ownerUID)\n\(executable)\n\(plan.profileDir.path)\n\(plan.mgmtSocket ?? "")\n"
        do {
            try HelperCore.checkLines(text, count: 5, file: Self.stateFileName)
            try HelperCore.writeNewFile(plan.runDir + "/" + Self.stateFileName, Data(text.utf8), mode: 0o600)
        } catch {
            DaemonLog.info("not recording the state of \(plan.profileID): \(error)")
        }
    }
}
