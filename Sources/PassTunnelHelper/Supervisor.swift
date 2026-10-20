import Foundation
import os
import PassTunnelShared

/// Starts, tracks and stops the VPN tool processes. All state is confined to `queue`.
/// Jobs are keyed by (owner uid, profile ID); see `SessionPolicy`.
final class Supervisor {
    typealias Key = SessionPolicy.Key

    struct Job {
        let profileID: String
        let ownerUID: uid_t
        let pid: pid_t
        let executable: String
        let runDir: String
        let isChild: Bool
        /// Open root-owned session directory (holds the management socket).
        let sessionDir: SessionDirectory?
        let mgmtSocket: String?
        var source: DispatchSourceProcess?
        var waiters: [() -> Void] = []

        var key: Key { Key(uid: ownerUID, profileID: profileID) }
    }

    static let stopGrace: TimeInterval = 5

    let queue = DispatchQueue(label: "com.furkanprlk.passtunnel.helper.supervisor")
    private let core: HelperCore
    private let log = Logger(subsystem: PT.helperLabel, category: "supervisor")
    private var jobs: [Key: Job] = [:]

    private var sessions: [SessionPolicy.Session] {
        jobs.values.map {
            SessionPolicy.Session(profileID: $0.profileID, ownerUID: $0.ownerUID, pid: $0.pid, mgmtSocket: $0.mgmtSocket)
        }
    }

    init(core: HelperCore) {
        self.core = core
    }

    // MARK: - Requests

    func handle(_ request: HelperRequest, uid: uid_t, reply: @escaping (HelperResponse) -> Void) {
        queue.async {
            switch request {
            case .startOpenVPN(let s):
                reply(self.start(profileID: s.profileID, uid: uid) { try self.core.prepareOpenVPN(s, uid: uid) })
            case .startForti(let s):
                reply(self.start(profileID: s.profileID, uid: uid) { try self.core.prepareForti(s, uid: uid) })
            case .stop(let id):
                self.stop(profileID: id, uid: uid, reply: reply)
            case .status:
                reply(.success(running: SessionPolicy.visible(to: uid, sessions: self.sessions),
                               mgmtSockets: SessionPolicy.sockets(visibleTo: uid, sessions: self.sessions)))
            }
        }
    }

    private func start(profileID: String, uid: uid_t, prepare: () throws -> HelperCore.LaunchPlan) -> HelperResponse {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            try SessionPolicy.checkStart(profileID: profileID, uid: uid, sessions: sessions)
        } catch {
            return .failure(String(describing: error))
        }
        let plan: HelperCore.LaunchPlan
        do {
            plan = try prepare()
        } catch {
            log.error("start \(profileID, privacy: .public) rejected: \(String(describing: error), privacy: .public)")
            return .failure(String(describing: error))
        }
        defer { close(plan.logFD) }
        let executable = HelperBundle.toolPath(plan.tool)
        do {
            try CodeSignature.verify(path: executable, requirement: PT.toolRequirement(identifier: plan.tool.signingIdentifier))
            if let dns = plan.dnsUpdownPath {
                try CodeSignature.verify(path: dns, requirement: PT.toolRequirement(identifier: PT.dnsUpdownIdentifier))
            }
            let pid = try Spawner.spawn(executable: executable, arguments: plan.arguments,
                                        environment: HelperCore.fixedEnvironment,
                                        workingDirectory: plan.runDir, outputFD: plan.logFD)
            writeState(plan: plan, pid: pid, executable: executable)
            let job = Job(profileID: plan.profileID, ownerUID: plan.ownerUID, pid: pid, executable: executable,
                          runDir: plan.runDir, isChild: true, sessionDir: plan.sessionDir, mgmtSocket: plan.mgmtSocket)
            track(job)
            if plan.mgmtSocket != nil { restrictSocketWhenReady(job.key, pid: pid, attempt: 0) }
            log.info("started \(plan.tool.rawValue, privacy: .public) for \(profileID, privacy: .public), uid \(uid), pid \(pid)")
            return .success(pid: pid, mgmtSocket: plan.mgmtSocket)
        } catch {
            core.removeRunDir(profileID: profileID, uid: uid)
            let line = "PassTunnel: \(error)\n"
            _ = line.withCString { write(plan.logFD, $0, strlen($0)) }
            log.error("start \(profileID, privacy: .public) failed: \(String(describing: error), privacy: .public)")
            return .failure(String(describing: error))
        }
    }

    /// OpenVPN binds the socket with umask 0 (it relies on --management-client-user); once it exists,
    /// hand it to the user with mode 0600 as a second barrier. The session directory is root-owned,
    /// so nobody else can swap the entry between the check and the chown.
    private func restrictSocketWhenReady(_ key: Key, pid: pid_t, attempt: Int) {
        guard let job = jobs[key], job.pid == pid, let dir = job.sessionDir, attempt < 100 else { return }
        if dir.restrictSocket(PT.mgmtSocketName) { return }
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

    /// SIGTERM now, SIGKILL to the whole process group after the grace period.
    private func terminate(_ job: Job) {
        kill(job.pid, SIGTERM)
        queue.asyncAfter(deadline: .now() + Self.stopGrace) { [weak self] in
            guard let self, let current = self.jobs[job.key], current.pid == job.pid else { return }
            self.log.notice("pid \(job.pid) ignored SIGTERM, killing")
            kill(-job.pid, SIGKILL)
            kill(job.pid, SIGKILL)
            // Adopted processes are not our children, so no exit event may follow quickly; check again.
            self.queue.asyncAfter(deadline: .now() + 1) { self.reapIfGone(job.key, pid: job.pid) }
        }
    }

    /// Stops everything (helper shutdown). Blocks up to the grace period plus one second.
    func stopAll() {
        let group = DispatchGroup()
        queue.sync {
            for job in jobs.values {
                group.enter()
                jobs[job.key]?.waiters.append { group.leave() }
                terminate(job)
            }
        }
        _ = group.wait(timeout: .now() + Self.stopGrace + 1.5)
        queue.sync {
            for job in jobs.values {
                kill(-job.pid, SIGKILL)
                core.removeRunDir(profileID: job.profileID, uid: job.ownerUID)
            }
        }
    }

    // MARK: - Tracking

    private func track(_ job: Job) {
        var job = job
        let key = job.key
        let source = DispatchSource.makeProcessSource(identifier: job.pid, eventMask: .exit, queue: queue)
        source.setEventHandler { [weak self] in self?.exited(key, pid: job.pid) }
        job.source = source
        jobs[key] = job
        source.resume()
        // The process may have exited before the source was armed.
        queue.async { [weak self] in self?.reapIfGone(key, pid: job.pid) }
    }

    private func reapIfGone(_ key: Key, pid: pid_t) {
        guard let job = jobs[key], job.pid == pid else { return }
        if job.isChild {
            var status: Int32 = 0
            if waitpid(pid, &status, WNOHANG) == pid { finish(job, status: status) }
        } else if kill(pid, 0) != 0, errno == ESRCH {
            finish(job, status: 0)
        }
    }

    private func exited(_ key: Key, pid: pid_t) {
        guard let job = jobs[key], job.pid == pid else { return }
        var status: Int32 = 0
        if job.isChild { _ = waitpid(pid, &status, 0) }
        finish(job, status: status)
    }

    private func finish(_ job: Job, status: Int32) {
        job.source?.cancel()
        jobs[job.key] = nil
        kill(-job.pid, SIGTERM)          // leftovers in the group (pppd)
        core.removeRunDir(profileID: job.profileID, uid: job.ownerUID)   // config, auth file and socket
        log.info("\(job.profileID, privacy: .public) of uid \(job.ownerUID) exited (pid \(job.pid), status \(status))")
        job.waiters.forEach { $0() }
    }

    // MARK: - Crash recovery

    /// Records pid, owner, executable, profile directory and management socket so a restarted
    /// helper can adopt still-running tools.
    private func writeState(plan: HelperCore.LaunchPlan, pid: pid_t, executable: String) {
        let text = "\(pid)\n\(plan.ownerUID)\n\(executable)\n\(plan.profileDir.path)\n\(plan.mgmtSocket ?? "")\n"
        try? HelperCore.writeNewFile(plan.runDir + "/state", Data(text.utf8), mode: 0o600)
    }

    /// Adopts tools left running by a previous helper instance (`<root>/<uid>/<id>/state`) and removes
    /// stale run directories. Tools started by a protocol-2 helper (`<root>/<id>/state`) are stopped:
    /// their management socket is in the profile directory, where this version never looks.
    func adoptOrphans() {
        queue.sync {
            let root = core.runRoot
            var st = stat()
            guard lstat(root, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == geteuid() else { return }
            for entry in Self.entries(root) {
                let path = root + "/" + entry
                if let legacy = Self.readState(path + "/state") {
                    if Self.isAlive(legacy) {
                        log.notice("stopping \(entry, privacy: .public) (pid \(legacy.pid)) left by an older helper")
                        kill(legacy.pid, SIGTERM)
                    }
                    HelperCore.removeEntry(path)
                    continue
                }
                guard let uid = uid_t(entry), String(uid) == entry, Self.isRealDirectory(path) else {
                    HelperCore.removeEntry(path); continue
                }
                for id in Self.entries(path) {
                    guard HelperCore.isValidProfileID(id), let state = Self.readState(path + "/" + id + "/state"),
                          state.uid == uid, Self.isAlive(state),
                          let dir = try? core.openRunDir(profileID: id, uid: uid) else {
                        HelperCore.removeEntry(path + "/" + id); continue
                    }
                    log.notice("adopting \(id, privacy: .public) of uid \(uid) (pid \(state.pid))")
                    let socket = state.mgmtSocket == PT.mgmtSocketPath(uid: uid, profileID: id, runRoot: root)
                        ? state.mgmtSocket : nil
                    track(Job(profileID: id, ownerUID: uid, pid: state.pid, executable: state.executable,
                              runDir: dir.path, isChild: false, sessionDir: dir, mgmtSocket: socket))
                }
            }
        }
    }

    struct State {
        let pid: pid_t
        let uid: uid_t
        let executable: String
        let mgmtSocket: String?
    }

    static func readState(_ path: String) -> State? {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        let parts = text.components(separatedBy: "\n")
        guard parts.count >= 3, let pid = pid_t(parts[0]), let uid = uid_t(parts[1]), pid > 1 else { return nil }
        let socket = parts.count >= 5 && !parts[4].isEmpty ? parts[4] : nil
        return State(pid: pid, uid: uid, executable: parts[2], mgmtSocket: socket)
    }

    /// The recorded process still runs the recorded executable (not a recycled pid).
    static func isAlive(_ s: State) -> Bool {
        kill(s.pid, 0) == 0 && executablePath(of: s.pid) == s.executable
    }

    static func entries(_ dir: String) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
    }

    static func isRealDirectory(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR && st.st_uid == geteuid()
    }

    static func executablePath(of pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : nil
    }
}

enum Spawner {
    struct Failure: Error, CustomStringConvertible {
        let code: Int32
        var description: String { "Could not launch the VPN tool: \(String(cString: strerror(code)))" }
    }

    /// posix_spawn in a new process group, stdin from /dev/null, stdout+stderr to `outputFD`,
    /// default signal handlers, no inherited descriptors.
    static func spawn(executable: String, arguments: [String], environment: [String],
                      workingDirectory: String, outputFD: Int32) throws -> pid_t {
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_adddup2(&actions, outputFD, 1)
        posix_spawn_file_actions_adddup2(&actions, outputFD, 2)
        posix_spawn_file_actions_addchdir_np(&actions, workingDirectory)

        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF
                                                | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT))
        posix_spawnattr_setpgroup(&attr, 0)
        var all = sigset_t(), none = sigset_t()
        sigfillset(&all)
        sigemptyset(&none)
        posix_spawnattr_setsigdefault(&attr, &all)
        posix_spawnattr_setsigmask(&attr, &none)

        let argv = ([executable] + arguments).map { strdup($0) } + [nil]
        let envp = environment.map { strdup($0) } + [nil]
        defer {
            argv.forEach { free($0) }
            envp.forEach { free($0) }
        }
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, executable, &actions, &attr, argv, envp)
        guard rc == 0 else { throw Failure(code: rc) }
        return pid
    }
}
