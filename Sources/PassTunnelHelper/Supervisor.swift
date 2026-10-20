import Foundation
import os
import PassTunnelShared

/// Starts, tracks and stops the VPN tool processes. All state is confined to `queue`.
final class Supervisor {
    struct Job {
        let profileID: String
        let ownerUID: uid_t
        let pid: pid_t
        let executable: String
        let runDir: String
        let isChild: Bool
        /// Open profile directory; used to remove the management socket when the tool exits.
        let profileDir: ProfileDirectory?
        var source: DispatchSourceProcess?
        var waiters: [() -> Void] = []
    }

    static let stopGrace: TimeInterval = 5

    let queue = DispatchQueue(label: "com.furkanprlk.passtunnel.helper.supervisor")
    private let core: HelperCore
    private let log = Logger(subsystem: PT.helperLabel, category: "supervisor")
    private var jobs: [String: Job] = [:]

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
                let mine = self.jobs.values.filter { uid == 0 || $0.ownerUID == uid }
                reply(.success(running: Dictionary(uniqueKeysWithValues: mine.map { ($0.profileID, $0.pid) })))
            }
        }
    }

    private func start(profileID: String, uid: uid_t, prepare: () throws -> HelperCore.LaunchPlan) -> HelperResponse {
        dispatchPrecondition(condition: .onQueue(queue))
        if let job = jobs[profileID] {
            return .failure(job.ownerUID == uid ? "Profile \(profileID) is already running (pid \(job.pid))."
                                                : "Profile \(profileID) is in use by another user.")
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
            track(Job(profileID: plan.profileID, ownerUID: plan.ownerUID, pid: pid, executable: executable,
                      runDir: plan.runDir, isChild: true, profileDir: plan.profileDir))
            if plan.mgmtSocket != nil { restrictSocketWhenReady(profileID: plan.profileID, pid: pid, attempt: 0) }
            log.info("started \(plan.tool.rawValue, privacy: .public) for \(profileID, privacy: .public), pid \(pid)")
            return .success(pid: pid, mgmtSocket: plan.mgmtSocket)
        } catch {
            core.removeRunDir(profileID: profileID)
            let line = "PassTunnel: \(error)\n"
            _ = line.withCString { write(plan.logFD, $0, strlen($0)) }
            log.error("start \(profileID, privacy: .public) failed: \(String(describing: error), privacy: .public)")
            return .failure(String(describing: error))
        }
    }

    /// OpenVPN creates the socket world-connectable (it relies on --management-client-user); once it
    /// exists, hand it to the user with mode 0600 as a second barrier.
    private func restrictSocketWhenReady(profileID: String, pid: pid_t, attempt: Int) {
        guard let job = jobs[profileID], job.pid == pid, let dir = job.profileDir, attempt < 100 else { return }
        if dir.restrictSocket(PT.mgmtSocketName) { return }
        queue.asyncAfter(deadline: .now() + 0.1) { [weak self] in
            self?.restrictSocketWhenReady(profileID: profileID, pid: pid, attempt: attempt + 1)
        }
    }

    private func stop(profileID: String, uid: uid_t, reply: @escaping (HelperResponse) -> Void) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard let job = jobs[profileID] else { return reply(.success()) }
        guard uid == 0 || job.ownerUID == uid else { return reply(.failure("Profile \(profileID) belongs to another user.")) }
        jobs[profileID]?.waiters.append { reply(.success(pid: job.pid)) }
        terminate(job)
    }

    /// SIGTERM now, SIGKILL to the whole process group after the grace period.
    private func terminate(_ job: Job) {
        kill(job.pid, SIGTERM)
        queue.asyncAfter(deadline: .now() + Self.stopGrace) { [weak self] in
            guard let self, let current = self.jobs[job.profileID], current.pid == job.pid else { return }
            self.log.notice("pid \(job.pid) ignored SIGTERM, killing")
            kill(-job.pid, SIGKILL)
            kill(job.pid, SIGKILL)
            // Adopted processes are not our children, so no exit event may follow quickly; check again.
            self.queue.asyncAfter(deadline: .now() + 1) { self.reapIfGone(job.profileID, pid: job.pid) }
        }
    }

    /// Stops everything (helper shutdown). Blocks up to the grace period plus one second.
    func stopAll() {
        let group = DispatchGroup()
        queue.sync {
            for job in jobs.values {
                group.enter()
                jobs[job.profileID]?.waiters.append { group.leave() }
                terminate(job)
            }
        }
        _ = group.wait(timeout: .now() + Self.stopGrace + 1.5)
        queue.sync {
            for job in jobs.values {
                kill(-job.pid, SIGKILL)
                core.removeRunDir(profileID: job.profileID)
                try? job.profileDir?.removeSocket(PT.mgmtSocketName)
            }
        }
    }

    // MARK: - Tracking

    private func track(_ job: Job) {
        var job = job
        let source = DispatchSource.makeProcessSource(identifier: job.pid, eventMask: .exit, queue: queue)
        source.setEventHandler { [weak self] in self?.exited(job.profileID, pid: job.pid) }
        job.source = source
        jobs[job.profileID] = job
        source.resume()
        // The process may have exited before the source was armed.
        queue.async { [weak self] in self?.reapIfGone(job.profileID, pid: job.pid) }
    }

    private func reapIfGone(_ profileID: String, pid: pid_t) {
        guard let job = jobs[profileID], job.pid == pid else { return }
        if job.isChild {
            var status: Int32 = 0
            if waitpid(pid, &status, WNOHANG) == pid { finish(job, status: status) }
        } else if kill(pid, 0) != 0, errno == ESRCH {
            finish(job, status: 0)
        }
    }

    private func exited(_ profileID: String, pid: pid_t) {
        guard let job = jobs[profileID], job.pid == pid else { return }
        var status: Int32 = 0
        if job.isChild { _ = waitpid(pid, &status, 0) }
        finish(job, status: status)
    }

    private func finish(_ job: Job, status: Int32) {
        job.source?.cancel()
        jobs[job.profileID] = nil
        kill(-job.pid, SIGTERM)          // leftovers in the group (pppd)
        core.removeRunDir(profileID: job.profileID)
        try? job.profileDir?.removeSocket(PT.mgmtSocketName)
        log.info("\(job.profileID, privacy: .public) exited (pid \(job.pid), status \(status))")
        job.waiters.forEach { $0() }
    }

    // MARK: - Crash recovery

    /// Records pid, owner, executable and profile directory so a restarted helper can adopt
    /// still-running tools.
    private func writeState(plan: HelperCore.LaunchPlan, pid: pid_t, executable: String) {
        let text = "\(pid)\n\(plan.ownerUID)\n\(executable)\n\(plan.profileDir.path)\n"
        try? HelperCore.writeNewFile(plan.runDir + "/state", Data(text.utf8), mode: 0o600)
    }

    /// Adopts tools left running by a previous helper instance and removes stale run directories.
    func adoptOrphans() {
        queue.sync {
            let root = core.runRoot
            var st = stat()
            guard lstat(root, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == geteuid() else { return }
            let entries = (try? FileManager.default.contentsOfDirectory(atPath: root)) ?? []
            for id in entries where HelperCore.isValidProfileID(id) {
                let dir = root + "/" + id
                guard let text = try? String(contentsOfFile: dir + "/state", encoding: .utf8) else {
                    core.removeRunDir(profileID: id); continue
                }
                let parts = text.split(separator: "\n").map(String.init)
                guard parts.count >= 3, let pid = pid_t(parts[0]), let uid = uid_t(parts[1]), pid > 1,
                      kill(pid, 0) == 0, Self.executablePath(of: pid) == parts[2] else {
                    core.removeRunDir(profileID: id); continue
                }
                log.notice("adopting \(id, privacy: .public) (pid \(pid))")
                let profileDir = parts.count >= 4 ? try? core.openProfileDir(parts[3], profileID: id, uid: uid) : nil
                track(Job(profileID: id, ownerUID: uid, pid: pid, executable: parts[2], runDir: dir, isChild: false,
                          profileDir: profileDir))
            }
        }
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
