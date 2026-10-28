import Foundation
import PassTunnelShared
import os

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
        /// Our copy of the tool's log descriptor, for `HelperCore.capLog` (nil for adopted tools).
        let logFD: Int32?
        var source: DispatchSourceProcess?
        var waiters: [() -> Void] = []

        var key: Key { Key(uid: ownerUID, profileID: profileID) }
    }

    static let stopGrace: TimeInterval = 5
    static let dnsRestoreTimeout: TimeInterval = 10
    static let logCheckInterval: TimeInterval = 60
    /// How often the helper looks at each openconnect session's record (`superviseOpenConnect`).
    static let openConnectCheckInterval: TimeInterval = 5
    /// How often a revert of an openconnect session's network that failed is tried again.
    static let restoreRetryInterval: TimeInterval = 15

    let queue = DispatchQueue(label: "com.furkanprlk.passtunnel.helper.supervisor")
    private let core: HelperCore
    private let stager: ToolStager
    private let log = Logger(subsystem: PT.helperLabel, category: "supervisor")
    private var jobs: [Key: Job] = [:]
    private var logTimer: DispatchSourceTimer?
    private var restoreTimer: DispatchSourceTimer?
    /// Sessions whose tool ended but whose network could not be restored yet: only their record is left, the
    /// profile cannot start over it, and `retryRestores` tries again.
    private var pendingRestores: Set<Key> = []

    private var sessions: [SessionPolicy.Session] {
        jobs.values.map {
            SessionPolicy.Session(profileID: $0.profileID, ownerUID: $0.ownerUID, pid: $0.pid, mgmtSocket: $0.mgmtSocket)
        }
    }

    init(core: HelperCore, stager: ToolStager) {
        self.core = core
        self.stager = stager
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + Self.logCheckInterval, repeating: Self.logCheckInterval)
        timer.setEventHandler { [weak self] in self?.capLogs() }
        timer.resume()
        logTimer = timer
        let retry = DispatchSource.makeTimerSource(queue: queue)
        retry.schedule(deadline: .now() + Self.restoreRetryInterval, repeating: Self.restoreRetryInterval)
        retry.setEventHandler { [weak self] in self?.retryRestores() }
        retry.resume()
        restoreTimer = retry
    }

    /// A long session must not fill the disk: logs above `HelperCore.maxLogBytes` keep only their end.
    private func capLogs() {
        for job in jobs.values {
            if let fd = job.logFD, HelperCore.capLog(fd: fd) {
                log.notice("trimmed the log of \(job.profileID, privacy: .public) (uid \(job.ownerUID))")
            }
        }
    }

    // MARK: - Requests

    func handle(_ request: HelperRequest, uid: uid_t, reply: @escaping (HelperResponse) -> Void) {
        queue.async {
            switch request {
            case .startOpenVPN(let s):
                reply(self.start(profileID: s.profileID, uid: uid) { _ in try self.core.prepareOpenVPN(s, uid: uid) })
            case .startForti(let s):
                reply(self.start(profileID: s.profileID, uid: uid) { _ in try self.core.prepareForti(s, uid: uid) })
            case .startOpenConnect(let s):
                // The config names the staged hook, so the tools are staged while it is prepared. Only
                // this start stages the hook: a failure there never affects the other tools.
                reply(
                    self.start(profileID: s.profileID, uid: uid) { stage in
                        try self.core.prepareOpenConnect(s, uid: uid) { try self.stager.stageHook(in: try stage()) }
                    })
            case .stop(let id):
                self.stop(profileID: id, uid: uid, reply: reply)
            case .status:
                reply(
                    .success(
                        running: SessionPolicy.visible(to: uid, sessions: self.sessions),
                        mgmtSockets: SessionPolicy.sockets(visibleTo: uid, sessions: self.sessions)))
            }
        }
    }

    /// `prepare` checks the request and writes the session's files; it is given `stage`, which stages the
    /// tools once per start (openconnect's config names the staged hook), and they are staged after it
    /// otherwise.
    private func start(
        profileID: String, uid: uid_t, prepare: (_ stage: () throws -> ToolStager.Staged) throws -> HelperCore.LaunchPlan
    ) -> HelperResponse {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            try SessionPolicy.checkStart(profileID: profileID, uid: uid, sessions: sessions)
        } catch {
            return .failure(String(describing: error))
        }
        // The session directory still holds the record of a network that could not be restored: a new start
        // would remove it. Tried once more now.
        let key = Key(uid: uid, profileID: profileID)
        if pendingRestores.contains(key) {
            let dir = PT.sessionDir(uid: uid, profileID: profileID, runRoot: core.runRoot)
            guard restoreNetwork(key, runDir: dir, outputFD: nil) else {
                return .failure("The network settings of this profile's last Cisco AnyConnect session are still being restored. Try again shortly.")
            }
            core.removeRunDir(profileID: profileID, uid: uid)
        }
        // The root-owned copy of the tools and their libraries, each file checked (requirement and pins)
        // as copied; tools still running from another build's copy keep theirs.
        var staged: ToolStager.Staged?
        let stage: () throws -> ToolStager.Staged = {
            if let staged { return staged }
            let inUse = Set(self.jobs.values.compactMap { self.stager.buildDirectory(ofExecutable: $0.executable) })
            let copy = try self.stager.stage(inUse: inUse)
            staged = copy
            return copy
        }
        let plan: HelperCore.LaunchPlan
        do {
            plan = try prepare(stage)
        } catch {
            log.error("start \(profileID, privacy: .public) rejected: \(String(describing: error), privacy: .public)")
            return .failure(error)
        }
        defer { close(plan.logFD) }
        let requirement = PT.toolRequirement(identifier: plan.tool.signingIdentifier)
        do {
            let executable = try stage().executable(plan.tool)
            if let dns = plan.dnsUpdownPath {
                // The root-owned copy openvpn runs; the release's own build only (`PinnedTools`).
                try Self.checkDNSScript(dns)
            }
            // Requirement, then the cdhashes this helper was built with, both on the started process
            // (the staged file is root-owned; this also covers whatever posix_spawn actually opened).
            let verifier = RequirementVerifier(requirement: requirement, cdhashes: PinnedTools.allowed(plan.tool.rawValue))
            // `state` is written before the tool runs, so openconnect's hook always finds it (`VPNHook.session`).
            let pid = try Spawner.spawnVerified(
                executable: executable, arguments: plan.arguments,
                environment: HelperCore.environment(for: plan.tool),
                workingDirectory: plan.runDir, outputFD: plan.logFD,
                verifier: verifier,
                beforeResume: { pid in try self.writeState(plan: plan, pid: pid, executable: executable, launching: true) })
            // Resumed: the state no longer says `launching`, so a restarted helper adopts the tool.
            try? writeState(plan: plan, pid: pid, executable: executable, launching: false)
            let logCopy = fcntl(plan.logFD, F_DUPFD_CLOEXEC, 0)
            let job = Job(
                profileID: plan.profileID, ownerUID: plan.ownerUID, pid: pid, executable: executable,
                runDir: plan.runDir, isChild: true, sessionDir: plan.sessionDir, mgmtSocket: plan.mgmtSocket,
                logFD: logCopy >= 0 ? logCopy : nil)
            track(job)
            if plan.mgmtSocket != nil { restrictSocketWhenReady(job.key, pid: pid, attempt: 0) }
            if plan.tool == .openconnect { superviseOpenConnect(job.key, pid: pid, since: Date()) }
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

    /// openconnect ignores its hook's result and keeps a tunnel nothing set up, so every
    /// `openConnectCheckInterval` the helper reads the session's record and stops a session whose set-up
    /// failed, that was not reported up within `VPNHook.setupDeadline` of its start (or adoption), or that
    /// stayed `reconnecting` for `VPNHook.reconnectDeadline`, whether or not a client is still waiting for it
    /// (docs/ARCHITECTURE.md, "Report and enforcement"). A record that cannot be read right now (the hook is
    /// writing it) is looked at again next time.
    private func superviseOpenConnect(_ key: Key, pid: pid_t, since started: Date, reconnectingSince: Date? = nil) {
        queue.asyncAfter(deadline: .now() + Self.openConnectCheckInterval) { [weak self] in
            guard let self, let job = self.jobs[key], job.pid == pid else { return }
            let now = Date()
            var since = reconnectingSince
            var reason: (log: String, line: String)?
            let record: Result<OpenConnectRecord?, Error> = Result { try OpenConnectJournal.read(OpenConnectJournal.path(runDir: job.runDir)) }
            switch record {
            case .failure:
                break
            case .success(let record):
                switch record?.status {
                case .failed?:
                    reason = ("its network set-up failed", "the network set-up failed; stopping")
                case .up?:
                    since = nil
                case .reconnecting?:
                    let first = since ?? now
                    since = first
                    if now.timeIntervalSince(first) >= VPNHook.reconnectDeadline {
                        reason = (
                            "it did not reconnect", "the connection did not come back within \(Int(VPNHook.reconnectDeadline)) seconds; stopping"
                        )
                    }
                case nil:
                    if now.timeIntervalSince(started) >= VPNHook.setupDeadline {
                        reason = (
                            "its network was not set up", "the network was not set up within \(Int(VPNHook.setupDeadline)) seconds; stopping"
                        )
                    }
                }
            }
            guard let reason else {
                return self.superviseOpenConnect(key, pid: pid, since: started, reconnectingSince: since)
            }
            self.log.notice("stopping \(job.profileID, privacy: .public) of uid \(job.ownerUID) (pid \(pid)): \(reason.log, privacy: .public)")
            if let fd = job.logFD {
                // Not "PassTunnel: ", which `VPNLog.isFatal` reads as a failed start.
                let line = "PassTunnel helper: \(reason.line)\n"
                _ = line.withCString { write(fd, $0, strlen($0)) }
            }
            self.terminate(job)
        }
    }

    private func stop(profileID: String, uid: uid_t, reply: @escaping (HelperResponse) -> Void) {
        dispatchPrecondition(condition: .onQueue(queue))
        let key = Key(uid: uid, profileID: profileID)
        guard case .terminate = SessionPolicy.stopDecision(profileID: profileID, uid: uid, sessions: sessions),
            let job = jobs[key]
        else { return reply(.success()) }
        jobs[key]?.waiters.append { reply(.success(pid: job.pid)) }
        terminate(job)
    }

    /// SIGTERM now, SIGKILL to the whole process group after the grace period. An openconnect session is
    /// marked as stopping first: a hook running now applies no further change (`OpenConnectMarks`).
    private func terminate(_ job: Job) {
        if Self.isOpenConnect(job.executable) { OpenConnectMarks.setStopping(runDir: job.runDir) }
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
                restoreDNS(runDir: job.runDir, profileID: job.profileID, uid: job.ownerUID, outputFD: job.logFD)
                // Left for the next helper when it fails (`adoptOrphans`).
                if restoreNetwork(job.key, runDir: job.runDir, outputFD: job.logFD) {
                    core.removeRunDir(profileID: job.profileID, uid: job.ownerUID)
                }
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
        kill(-job.pid, SIGTERM)  // leftovers in the group (pppd)
        restoreDNS(runDir: job.runDir, profileID: job.profileID, uid: job.ownerUID, outputFD: job.logFD)
        let restored = restoreNetwork(job.key, runDir: job.runDir, outputFD: job.logFD)
        if let fd = job.logFD { close(fd) }
        if restored { core.removeRunDir(profileID: job.profileID, uid: job.ownerUID) }  // config, auth file and socket
        log.info("\(job.profileID, privacy: .public) of uid \(job.ownerUID) exited (pid \(job.pid), status \(status))")
        job.waiters.forEach { $0() }
    }

    // MARK: - DNS

    /// The session's copy of OpenVPN's DNS script: our signing requirement and, in a pinned build, the
    /// release's own cdhash (`PinnedTools`).
    private static func checkDNSScript(_ path: String) throws {
        let cdhash = try CodeSignature.verify(path: path, requirement: PT.toolRequirement(identifier: PT.dnsUpdownIdentifier))
        try PinnedTools.check("dns-updown", cdhash: cdhash, allowed: PinnedTools.allowed("dns-updown"))
    }

    /// Runs the dns-down OpenVPN still owes the session in `runDir` (`HelperCore.pendingDNSDown`). OpenVPN
    /// runs it when it closes the tunnel, but not when it is killed, and not after a PUSH_UPDATE that
    /// replaced or removed the `dns` options (2.7 then forgets its `--dns-updown`; docs/ARCHITECTURE.md,
    /// "DNS script (macOS)"). The same script, checked again, with the recorded variables; output to the
    /// session's log; at most `dnsRestoreTimeout`, before the run directory is removed.
    private func restoreDNS(runDir: String, profileID: String, uid: uid_t, outputFD: Int32?) {
        let environment: [String]
        do {
            guard let pending = try HelperCore.pendingDNSDown(runDir: runDir) else { return }
            environment = pending
        } catch {
            log.error("not restoring DNS for \(profileID, privacy: .public) of uid \(uid): \(String(describing: error), privacy: .public)")
            return
        }
        let script = runDir + "/dns-updown"
        let devNull = outputFD == nil ? open("/dev/null", O_WRONLY | O_CLOEXEC) : -1
        defer { if devNull >= 0 { close(devNull) } }
        let output = outputFD ?? devNull
        do {
            try Self.checkDNSScript(script)
            // Not "PassTunnel: ", which `VPNLog.isFatal` reads as a failed start.
            let line = "PassTunnel helper: OpenVPN did not undo its DNS settings; running dns-down\n"
            _ = line.withCString { write(output, $0, strlen($0)) }
            let pid = try Spawner.spawn(
                executable: "/bin/bash", arguments: [script], environment: environment,
                workingDirectory: runDir, outputFD: output)
            let status = Self.wait(pid, timeout: Self.dnsRestoreTimeout)
            log.notice(
                "ran dns-down for \(profileID, privacy: .public) of uid \(uid): \(status.map { "status \($0)" } ?? "timed out", privacy: .public)")
        } catch {
            log.error("restoring DNS for \(profileID, privacy: .public) of uid \(uid) failed: \(String(describing: error), privacy: .public)")
        }
    }

    /// Waits for child `pid` at most `timeout`, then kills its process group. The exit status (128 + the
    /// signal that ended it, -1 if it cannot be waited for), nil after a timeout.
    private static func wait(_ pid: pid_t, timeout: TimeInterval) -> Int32? {
        let deadline = Date().addingTimeInterval(timeout)
        var status: Int32 = 0
        repeat {
            let r = waitpid(pid, &status, WNOHANG)
            if r == pid { return status & 0x7f == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f) }
            if r < 0, errno != EINTR { return -1 }
            usleep(20_000)
        } while Date() < deadline
        kill(-pid, SIGKILL)
        kill(pid, SIGKILL)
        _ = waitpid(pid, &status, 0)
        return nil
    }

    // MARK: - openconnect's network

    static func isOpenConnect(_ executable: String) -> Bool {
        (executable as NSString).lastPathComponent == HelperCore.Tool.openconnect.rawValue
    }

    /// Reverts what an openconnect session's hook left, from its record, once the tool has ended (also killed,
    /// or when the helper stops or restarts): `OpenConnectHook.restoreAfterExit`, sparing what another live
    /// session holds. True when nothing is left to undo and the session directory can go; false when a change
    /// could not be undone: then everything but the record is removed (the configuration with the cookie
    /// first), the profile cannot start over it, and `retryRestores` tries again.
    private func restoreNetwork(_ key: Key, runDir: String, outputFD: Int32?) -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        guard OpenConnectJournal.exists(runDir: runDir) else {
            pendingRestores.remove(key)
            return true
        }
        let runRoot = core.runRoot
        let result = OpenConnectHook.restoreAfterExit(
            runRoot: runRoot, runDir: runDir, system: MacOpenConnectSystem(),
            killHook: { Self.killHook(runDir: runDir, runRoot: runRoot) })
        switch result {
        case .done:
            pendingRestores.remove(key)
            return true
        case .unreadable:
            log.error("the network record of \(key.profileID, privacy: .public) of uid \(key.uid) cannot be read; nothing restored")
            pendingRestores.remove(key)
            return true
        case .failed(let reason):
            log.error(
                "restoring the network of \(key.profileID, privacy: .public) of uid \(key.uid) failed: \(reason, privacy: .public); trying again")
            if let fd = outputFD {
                let line = "PassTunnel helper: restoring the network failed (\(VPNHook.oneLine(reason))); trying again\n"
                _ = line.withCString { write(fd, $0, strlen($0)) }
            }
            OpenConnectHook.keepOnlyRecord(runDir: runDir)
            pendingRestores.insert(key)
            return false
        }
    }

    /// Tries the reverts that failed again (every `restoreRetryInterval`).
    private func retryRestores() {
        for key in pendingRestores where jobs[key] == nil {
            let dir = PT.sessionDir(uid: key.uid, profileID: key.profileID, runRoot: core.runRoot)
            if restoreNetwork(key, runDir: dir, outputFD: nil) {
                core.removeRunDir(profileID: key.profileID, uid: key.uid)
                log.notice("restored the network of \(key.profileID, privacy: .public) of uid \(key.uid)")
            }
        }
    }

    /// Kills a hook of the session that is still running past its limit: the process its `hook` mark names,
    /// only if it is still that process (pid, start time) and a root process of a staged `vpn-hook`.
    static func killHook(runDir: String, runRoot: String) {
        guard let mark = OpenConnectMarks.runningHook(runDir: runDir), let realRoot = HelperCore.realPath(runRoot),
            let facts = SessionRecovery.facts(of: mark.pid), facts.start == mark.start
        else { return }
        let tools = realRoot + "/" + ToolStager.toolsDirName + "/"
        func isHook(_ p: SessionRecovery.ProcessFacts) -> Bool {
            p.uid == 0 && (p.path?.hasPrefix(tools) ?? false) && (p.path.map { ($0 as NSString).lastPathComponent } == VPNHook.name)
        }
        guard isHook(facts) else { return }
        SessionRecovery.signal(facts, SIGKILL, still: isHook, read: SessionRecovery.facts(of:), send: kill)
    }

    // MARK: - Crash recovery

    /// Records pid, owner, executable, profile directory and management socket (`SessionState`) so a
    /// restarted helper can adopt still-running tools: before the tool runs (`Spawner.spawnVerified`) as
    /// `launching`, then again once it was resumed. Read back as root: one field per line, or not written at
    /// all. openconnect never runs without it (its hook proves its session with it), so a failure stops its
    /// launch; for the other tools a failure is only logged. A record left `launching` makes a restarted
    /// helper stop the tool rather than adopt it (`SessionRecovery`). The tool's start time makes the record
    /// name this process and no later one with the same pid.
    private func writeState(plan: HelperCore.LaunchPlan, pid: pid_t, executable: String, launching: Bool) throws {
        let state = SessionState(
            pid: pid, uid: plan.ownerUID, executable: executable, profileDir: plan.profileDir.path, mgmtSocket: plan.mgmtSocket,
            startTime: SessionRecovery.facts(of: pid)?.start, launching: launching)
        do {
            try state.write(runDir: plan.runDir)
        } catch {
            log.error("not recording state for \(plan.profileID, privacy: .public): \(String(describing: error), privacy: .public)")
            if plan.tool == .openconnect { throw error }
        }
    }

    /// Adopts tools left running by a previous helper instance (`<root>/<uid>/<id>/state`) and removes
    /// stale run directories. Tools started by a protocol-2 helper (`<root>/<id>/state`) are stopped:
    /// their management socket is in the profile directory, where this version never looks.
    /// A tool that was killed rather than stopped cleanly (also when launchd stops an unregistered
    /// helper) may leave the host route to its server via the default gateway behind. Nothing to clean
    /// up: the next connect's "File exists" for that route is harmless (`VPNLog.setupProblem` ignores it).
    /// openconnect's hook keeps a record of what it changed: a session that is not adopted is restored from
    /// it first (`restoreNetwork`), and one whose revert fails keeps only its record.
    func adoptOrphans() {
        queue.sync {
            let root = core.runRoot
            var st = stat()
            guard lstat(root, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == geteuid() else { return }
            var recorded = Set<pid_t>()
            defer { stopStrandedLaunches(recorded: recorded) }
            for entry in Self.entries(root) {
                let path = root + "/" + entry
                if entry == ToolStager.toolsDirName { continue }  // staged tools (`ToolStager`)
                if entry == OpenConnectLock.fileName { continue }  // openconnect's network lock
                if let legacy = Self.readState(path + "/state") {
                    recorded.insert(legacy.pid)
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
                    let state = HelperCore.isValidProfileID(id) ? Self.readState(path + "/" + id + "/state") : nil
                    if let state { recorded.insert(state.pid) }
                    let current = state.flatMap { SessionRecovery.facts(of: $0.pid) }
                    let decision = state.map { SessionRecovery.decide($0, current: current) }
                    if decision == .stopInterruptedLaunch, let current {
                        // Its launch was interrupted: it may never have run. Killed (that process alone, checked
                        // again just before), then cleaned up like a tool that ended (a resumed OpenVPN may have
                        // set DNS already).
                        log.notice("stopping \(id, privacy: .public) of uid \(uid) (pid \(current.pid)): its launch was not finished")
                        SessionRecovery.signal(current, SIGKILL, read: SessionRecovery.facts(of:), send: kill)
                    }
                    if decision == .stopUnidentified, let state {
                        // Its hooks cannot prove their generation: it would run on with nothing to set up or
                        // revert its network. Killed while it is still the recorded process (pid and executable;
                        // there is no start time to compare), then its network is reverted below.
                        log.notice("stopping \(id, privacy: .public) of uid \(uid) (pid \(state.pid)): recorded without its start time")
                        if SessionRecovery.matches(state, SessionRecovery.facts(of: state.pid)) { kill(state.pid, SIGKILL) }
                    }
                    guard let state, state.uid == uid, decision == .adopt,
                        let dir = try? core.openRunDir(profileID: id, uid: uid)
                    else {
                        // A tool that ended while no helper ran: undo what its DNS hook left first.
                        if let decision, decision != .adopt, let dir = try? core.openRunDir(profileID: id, uid: uid) {
                            restoreDNS(runDir: dir.path, profileID: id, uid: uid, outputFD: nil)
                        }
                        // openconnect's network, also of a session a previous helper could not restore.
                        if HelperCore.isValidProfileID(id), Self.isRealDirectory(path + "/" + id),
                            !restoreNetwork(Key(uid: uid, profileID: id), runDir: path + "/" + id, outputFD: nil)
                        {
                            continue
                        }
                        HelperCore.removeEntry(path + "/" + id); continue
                    }
                    log.notice("adopting \(id, privacy: .public) of uid \(uid) (pid \(state.pid))")
                    let socket =
                        state.mgmtSocket == PT.mgmtSocketPath(uid: uid, profileID: id, runRoot: root)
                        ? state.mgmtSocket : nil
                    track(
                        Job(
                            profileID: id, ownerUID: uid, pid: state.pid, executable: state.executable,
                            runDir: dir.path, isChild: false, sessionDir: dir, mgmtSocket: socket, logFD: nil))
                    if Self.isOpenConnect(state.executable) {
                        superviseOpenConnect(Key(uid: uid, profileID: id), pid: state.pid, since: Date())
                    }
                }
            }
        }
    }

    /// Stopped root orphans of the staged tools that no state records (a helper died between starting one
    /// and recording it): they would never run. Each is killed alone, and only if it is still the same
    /// stopped root orphan right before the signal (`SessionRecovery`).
    private func stopStrandedLaunches(recorded: Set<pid_t>) {
        guard let realRoot = HelperCore.realPath(core.runRoot) else { return }
        let toolsRoot = realRoot + "/" + ToolStager.toolsDirName
        for stray in SessionRecovery.strandedLaunches(processes: SessionRecovery.systemProcesses(), toolsRoot: toolsRoot, recorded: recorded) {
            let sent = SessionRecovery.signal(
                stray, SIGKILL, still: { SessionRecovery.isStranded($0, toolsRoot: toolsRoot) }, read: SessionRecovery.facts(of:), send: kill)
            if sent { log.notice("stopped pid \(stray.pid): a tool whose launch was not finished") }
        }
    }

    static func readState(_ path: String) -> SessionState? { SessionState.read(path) }

    static func isAlive(_ s: SessionState) -> Bool { SessionRecovery.isAlive(s) }

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
