import Foundation
import PassTunnelShared
import PassTunnelVPNConfig

/// Starts, tracks and stops the VPN tools, as the Mac's helper does; all state is confined to `queue`.
/// Sessions are keyed by (owner uid, profile ID) (`SessionPolicy`). Each child has a thread of its own
/// that waits for it to exit; then what its session recorded is restored (`SessionRestore`: an openconnect
/// session's network, the DNS; normally its hook has done that already) and the session directory removed.
/// There is no adoption: tools recorded by an earlier instance are stopped when the daemon starts
/// (`PreviousInstance`). FortiGate sessions print into a pipe the daemon reads (`OutputCopier`): it copies
/// their output into the log and, for a profile with `set_dns`, sets the DNS openfortivpn reports there for
/// the session's ppp interface (`FortiDNSWatch`, `SessionInterface`, `DNSApplier`), off the queue, on
/// `dnsQueue`. Cisco AnyConnect sessions print through `MaskingCopier` (the cookie never reaches the log);
/// their hook (`LinuxVPNHook`) records the network it sets up, which the daemon follows
/// (`superviseOpenConnect`) and reports (`tunnels`).
final class Supervisor {
    typealias Key = SessionPolicy.Key

    struct Job {
        let profileID: String
        let ownerUID: uid_t
        let pid: pid_t
        let executable: String
        let tool: HelperCore.Tool
        let sessionDir: SessionDirectory
        let mgmtSocket: String?
        /// Our copy of the tool's log descriptor, for `HelperCore.capLog`.
        let logFD: Int32
        var waiters: [() -> Void] = []
        /// FortiGate: copies the tool's output into the log.
        var output: OutputCopier?
        /// FortiGate with `set_dns`: what the output said about DNS so far.
        var fortiDNS: FortiDNSWatch?
        /// The highest interface index when the tool started: its ppp interface comes later.
        var indexAtStart: UInt32 = 0
        /// The DNS set-up handed to `dnsQueue`, if any.
        var dnsTask: DNSTask?

        var key: Key { Key(uid: ownerUID, profileID: profileID) }
    }

    static let logCheckInterval: TimeInterval = 60
    static let stateFileName = SessionState.fileName
    static let noServers = "the gateway named no DNS servers; DNS is left as it is"

    let queue = DispatchQueue(label: "passtunneld.supervisor")
    /// FortiGate DNS set-ups: they run tools and wait for the run root's lock, so not on `queue`.
    let dnsQueue = DispatchQueue(label: "passtunneld.dns")
    private let core: HelperCore
    private let tools: ToolResolving
    /// Reverts what a session's DNS hook left, and sets FortiGate's (`DNSApplier`).
    let dns: DNSApplier
    /// Restores what an ended session left: an openconnect session's network, then its DNS.
    let restorer: SessionRestore
    /// How often each openconnect session's record is looked at, and the set-up and reconnect deadlines
    /// (`superviseOpenConnect`).
    let openConnectTiming: OpenConnectTiming
    private let interfaces: InterfaceSystem
    /// How long the DNS set-up waits, once openfortivpn says the tunnel is up, for what it did not
    /// report yet.
    private let reportWait: TimeInterval
    private let stopGrace: TimeInterval
    private var jobs: [Key: Job] = [:]
    /// Ended sessions not restored yet (an openconnect network or DNS whose revert failed kept its record):
    /// their directories stay, with the records only, and are tried again every `retryInterval`.
    private var pending: [Key: SessionDirectory] = [:]
    private var logTimer: DispatchSourceTimer?
    private var retryTimer: DispatchSourceTimer?

    private var sessions: [SessionPolicy.Session] {
        jobs.values.map {
            SessionPolicy.Session(profileID: $0.profileID, ownerUID: $0.ownerUID, pid: $0.pid, mgmtSocket: $0.mgmtSocket)
        }
    }

    /// `pending`: sessions of an earlier instance it could not restore yet (`PreviousInstance`).
    init(
        core: HelperCore, tools: ToolResolving, dns: DNSApplier, restorer: SessionRestore? = nil,
        interfaces: InterfaceSystem = InterfaceSystem(), reportWait: TimeInterval = 10, stopGrace: TimeInterval = 5,
        pending: [Key] = [], retryInterval: TimeInterval = 15, openConnectTiming: OpenConnectTiming = OpenConnectTiming()
    ) {
        self.core = core
        self.tools = tools
        self.dns = dns
        let runRoot = core.runRoot
        self.restorer =
            restorer
            ?? SessionRestore(
                runRoot: runRoot, dns: dns, openConnect: { LinuxOpenConnectSystem(session: $0, dns: dns) }, hookExecutable: core.dnsHook)
        self.openConnectTiming = openConnectTiming
        self.interfaces = interfaces
        self.reportWait = reportWait
        self.stopGrace = stopGrace
        for key in pending {
            if let session = try? core.openRunDir(profileID: key.profileID, uid: key.uid) { self.pending[key] = session }
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + Self.logCheckInterval, repeating: Self.logCheckInterval)
        timer.setEventHandler { [weak self] in self?.capLogs() }
        timer.resume()
        logTimer = timer
        let retry = DispatchSource.makeTimerSource(queue: queue)
        retry.schedule(deadline: .now() + retryInterval, repeating: retryInterval)
        retry.setEventHandler { [weak self] in self?.retryRestores() }
        retry.resume()
        retryTimer = retry
    }

    deinit {
        logTimer?.cancel()
        retryTimer?.cancel()
    }

    // MARK: - Not restored yet

    /// Removes the directory of an ended session once what it recorded is restored (`SessionRestore`);
    /// otherwise only its records stay (the tool's config, auth file, cookie and socket go), and it is tried
    /// again (`retryRestores`).
    private func release(_ key: Key, _ session: SessionDirectory) {
        guard OpenConnectJournal.exists(runDir: session.path) || DNSRecord.isRecorded(in: session) else {
            return core.removeRunDir(profileID: key.profileID, uid: key.uid)
        }
        PreviousInstance.keepOnlyRecords(in: session.path)
        pending[key] = session
        DaemonLog.info("\(key.profileID) of uid \(key.uid): not restored yet, kept to try again")
    }

    /// Tries again to restore `key`'s ended session; true once nothing is left of it.
    @discardableResult
    private func retryRestore(_ key: Key) -> Bool {
        guard let session = pending[key] else { return true }
        guard restorer.restore(session, key: key) else { return false }
        pending[key] = nil
        core.removeRunDir(profileID: key.profileID, uid: key.uid)
        return true
    }

    /// Every ended session not restored yet, and what the file backend's state says is left to do
    /// (`DNSApplier.recover`).
    private func retryRestores() {
        for key in pending.keys where jobs[key] == nil { retryRestore(key) }
        if let message = dns.recover() { DaemonLog.info(message) }
    }

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
                reply(
                    self.start(profileID: s.profileID, uid: uid, tool: .openvpn) { tool, core in
                        // The DNS hook as `--dns-updown` where OpenVPN knows it (2.7), else as `--route-up` and `--down`.
                        core.openVPNHasDNSUpdown = tool.version >= ToolVersion(2, 7, 0)
                        return try core.prepareOpenVPN(s, uid: uid)
                    })
            case .startForti(let s):
                reply(
                    self.start(profileID: s.profileID, uid: uid, tool: .openfortivpn, output: .copied(setDNS: s.setDNS)) { _, core in
                        // openfortivpn runs pppd from the path compiled into it: checked as a tool is.
                        _ = try self.tools.resolve(.pppd)
                        core.caFile = try self.tools.caBundle()
                        // openfortivpn and pppd never touch resolv.conf; the daemon applies DNS (docs/LINUX.md).
                        core.fortiHandlesDNS = false
                        return try core.prepareForti(s, uid: uid)
                    })
            case .startOpenConnect(let s):
                // Cisco AnyConnect or Palo Alto GlobalProtect (docs/LINUX.md): the tool checked for the type's minimum
                // (9.01; GlobalProtect 9.11), the request as the Mac's helper checks it, the root configuration
                // rendered with `script` the session's `vpn-hook` link (made with the policy), its output masked.
                reply(
                    self.start(profileID: s.profileID, uid: uid, tool: .openconnect(for: s.protocol)) { tool, core in
                        // GlobalProtect before 9.20 reads the gateway's IPv6 routes as excludes: `disable-ipv6`, decided
                        // from the version just checked, never from the request.
                        core.openConnectDisableIPv6 = ToolSpec.openConnectDisablesIPv6(s.protocol, version: tool.version)
                        return try core.prepareOpenConnect(s, uid: uid) { try core.vpnHookPath(profileID: s.profileID, uid: uid) }
                    })
            case .stop(let id):
                self.stop(profileID: id, uid: uid, reply: reply)
            case .status:
                reply(
                    .success(
                        running: SessionPolicy.visible(to: uid, sessions: self.sessions),
                        mgmtSockets: SessionPolicy.sockets(visibleTo: uid, sessions: self.sessions),
                        tunnels: self.tunnels(visibleTo: uid)))
            }
        }
    }

    /// The network of each of `uid`'s openconnect sessions, from its root-owned record
    /// (`HelperCore.tunnelStatus`), for the `status` reply; nil when there are none.
    private func tunnels(visibleTo uid: uid_t) -> [String: TunnelStatus]? {
        dispatchPrecondition(condition: .onQueue(queue))
        var out: [String: TunnelStatus] = [:]
        for job in jobs.values where job.ownerUID == uid && job.tool == .openconnect {
            out[job.profileID] = HelperCore.tunnelStatus(runDir: job.sessionDir.path)
        }
        return out.isEmpty ? nil : out
    }

    /// Where a tool's output goes: straight into the log (OpenVPN), or through `OutputCopier`
    /// (openfortivpn), followed for DNS when the profile has `set_dns`. A plan with secrets to mask
    /// (openconnect's cookie, `LaunchPlan.maskedSecrets`) goes through `MaskingCopier` instead.
    enum Output {
        case log
        case copied(setDNS: Bool)
    }

    /// Checks the session limits and the tool, has `prepare` write the session's files (given the
    /// checked tool and a copy of the core to adjust), then spawns the tool and supervises it.
    private func start(
        profileID: String, uid: uid_t, tool spec: ToolSpec, output: Output = .log,
        prepare: (ResolvedTool, inout HelperCore) throws -> HelperCore.LaunchPlan
    ) -> HelperResponse {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            try SessionPolicy.checkStart(profileID: profileID, uid: uid, sessions: sessions)
        } catch {
            return .failure(String(describing: error))
        }
        // A new session would replace the directory that still holds the last one's records.
        guard retryRestore(Key(uid: uid, profileID: profileID)) else {
            DaemonLog.info("start of \(profileID) for uid \(uid) refused: the last session is not restored yet")
            return .failure("The network settings of the last \(profileID) session are not restored yet. Try again shortly.")
        }
        let tool: ResolvedTool
        let plan: HelperCore.LaunchPlan
        do {
            tool = try tools.resolve(spec)
            var core = self.core
            plan = try prepare(tool, &core)
        } catch {
            DaemonLog.info("start of \(profileID) for uid \(uid) refused: \(error)")
            return .failure(error)
        }
        defer { close(plan.logFD) }
        var pipeFDs: (read: Int32, write: Int32)?
        do {
            let masked = plan.maskedSecrets != nil
            if masked { pipeFDs = try Sys.makePipe() } else if case .copied = output { pipeFDs = try Sys.makePipe() }
            defer { pipeFDs.map { _ = close($0.write) } }  // the tool has its own copy
            let indexAtStart = pipeFDs == nil ? 0 : interfaces.highestIndex()
            let pid = try Sys.spawn(
                executable: tool.path, arguments: plan.arguments,
                environment: HelperCore.environment(for: plan.tool),
                workingDirectory: plan.runDir, outputFD: pipeFDs?.write ?? plan.logFD)
            do {
                try writeState(plan: plan, pid: pid, executable: tool.path)
            } catch  where plan.tool == .openconnect {
                // Its hook proves its session by `state`: without it, nothing would set up or revert its network.
                kill(pid, SIGKILL)
                var status: Int32 = 0
                while waitpid(pid, &status, 0) == -1, errno == EINTR {}
                throw error
            } catch {
                DaemonLog.info("not recording the state of \(plan.profileID): \(error)")
            }
            let logCopy = fcntl(plan.logFD, F_DUPFD_CLOEXEC, 0)
            var job = Job(
                profileID: plan.profileID, ownerUID: plan.ownerUID, pid: pid, executable: tool.path, tool: plan.tool,
                sessionDir: plan.sessionDir, mgmtSocket: plan.mgmtSocket, logFD: logCopy)
            if let fds = pipeFDs, let secrets = plan.maskedSecrets {
                // The copier takes both descriptors over; the tool's output is lost, never the tool, without a log.
                let logFD = fcntl(plan.logFD, F_DUPFD_CLOEXEC, 0)
                if logFD >= 0 {
                    MaskingCopier(readFD: fds.read, logFD: logFD, secrets: secrets).start(name: "passtunneld.output.\(pid)")
                } else {
                    close(fds.read)
                }
                pipeFDs = (-1, fds.write)
            } else if let fds = pipeFDs, case .copied(let setDNS) = output {
                let key = job.key
                let copier = OutputCopier(readFD: fds.read, logFD: fcntl(plan.logFD, F_DUPFD_CLOEXEC, 0)) { [weak self] line in
                    guard let self else { return }
                    self.queue.async { [weak self] in self?.received(line, key: key, pid: pid) }
                }
                pipeFDs = (-1, fds.write)  // the copier closes the read end
                job.output = copier
                job.fortiDNS = setDNS ? FortiDNSWatch() : nil
                job.indexAtStart = indexAtStart
                copier.start(name: "passtunneld.output.\(pid)")
            }
            jobs[job.key] = job
            watch(job.key, pid: pid)
            if plan.mgmtSocket != nil { restrictSocketWhenReady(job.key, pid: pid, attempt: 0) }
            if plan.tool == .openconnect { superviseOpenConnect(job.key, pid: pid, since: Date()) }
            DaemonLog.info("started \(spec.name) \(tool.version) for \(profileID), uid \(uid), pid \(pid)")
            return .success(pid: pid, mgmtSocket: plan.mgmtSocket)
        } catch {
            if let fds = pipeFDs, fds.read >= 0 { close(fds.read) }
            core.removeRunDir(profileID: profileID, uid: uid)
            let line = "PassTunnel: \(error)\n"
            _ = line.withCString { write(plan.logFD, $0, strlen($0)) }
            DaemonLog.info("start of \(profileID) for uid \(uid) failed: \(error)")
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
            let job = jobs[key]
        else { return reply(.success()) }
        jobs[key]?.waiters.append { reply(.success(pid: job.pid)) }
        terminate(job)
    }

    /// SIGTERM now, SIGKILL to the whole process group after the grace period. The child is reaped
    /// only on the queue (`exited`), so its pid cannot be reused while the job is listed. An openconnect
    /// session is marked as stopping first: a hook running now applies no further change
    /// (`OpenConnectMarks`).
    private func terminate(_ job: Job) {
        if job.tool == .openconnect { OpenConnectMarks.setStopping(runDir: job.sessionDir.path) }
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
                endDNSTask(job)
                restore(job)
                release(job.key, job.sessionDir)  // one not restored yet is left to the next instance
            }
        }
    }

    /// What the session's hook (or, for FortiGate, the daemon) recorded and did not revert itself (the
    /// tool was killed, or died; FortiGate's DNS is always reverted here): an openconnect session's network,
    /// then the DNS. A revert that fails says so in the session's log.
    private func restore(_ job: Job) {
        guard !restorer.restore(job.sessionDir, key: job.key), job.tool == .openconnect else { return }
        note(job, "restoring the network failed; trying again")
    }

    /// One line of the daemon's own in the session's log (`passtunneld: …`), one `write`.
    private func note(_ job: Job, _ text: String) {
        let line = OutputCopier.notePrefix + DaemonLog.oneLine(text) + "\n"
        _ = line.withCString { write(job.logFD, $0, strlen($0)) }
    }

    // MARK: - Exit

    /// One thread per child waits for it to exit without reaping it (`WNOWAIT`): until `exited` reaps
    /// it on the queue, the pid stays taken, so signals to it or its process group cannot reach
    /// another process.
    private func watch(_ key: Key, pid: pid_t) {
        let thread = Thread { [weak self] in
            var info = siginfo_t()
            while waitid(P_PID, id_t(pid), &info, WEXITED | WNOWAIT) != 0, errno == EINTR {}
            guard let self else { return }
            self.queue.async { [weak self] in self?.exited(key, pid: pid) }
        }
        thread.name = "passtunneld.wait.\(pid)"
        thread.start()
    }

    private func exited(_ key: Key, pid: pid_t) {
        guard let job = jobs[key], job.pid == pid else { return }
        kill(-pid, SIGTERM)  // anything left in its process group
        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1, errno == EINTR {}
        jobs[key] = nil
        endDNSTask(job)
        restore(job)
        close(job.logFD)
        release(key, job.sessionDir)  // config, auth file, socket, state
        DaemonLog.info("\(job.profileID) of uid \(job.ownerUID) exited (pid \(pid), status \(status))")
        job.waiters.forEach { $0() }
    }

    // MARK: - FortiGate DNS

    /// A line of a FortiGate session's own output (never the log file's).
    private func received(_ line: String, key: Key, pid: pid_t) {
        guard let job = jobs[key], job.pid == pid, var watch = job.fortiDNS else { return }
        let event = watch.feed(line)
        jobs[key]?.fortiDNS = watch
        switch event {
        case .none:
            break
        case .waiting:
            queue.asyncAfter(deadline: .now() + reportWait) { [weak self] in self?.stillWaiting(key, pid: pid) }
        case .failed(let reason):
            dnsFailed(job, reason)
        case .ready(let addresses, let interface):
            setDNS(job, addresses: addresses, interface: interface)
        }
    }

    /// The tunnel came up, and openfortivpn still has not said everything DNS needs.
    private func stillWaiting(_ key: Key, pid: pid_t) {
        guard let job = jobs[key], job.pid == pid, var watch = job.fortiDNS, !watch.done else { return }
        let missing = watch.missing
        watch.giveUp()
        jobs[key]?.fortiDNS = watch
        dnsFailed(job, String(describing: DNSFailure.notReported(missing)))
    }

    /// Checks the values, then (on `dnsQueue`) the interface, and applies them. Every name goes through
    /// the tunnel, as with openfortivpn's own `set-dns` on the Mac.
    private func setDNS(_ job: Job, addresses: FortiOutput.Addresses, interface: String) {
        guard !addresses.servers.isEmpty else {
            job.output?.note(Self.noServers)
            DaemonLog.info("\(job.profileID) of uid \(job.ownerUID): \(Self.noServers)")
            return
        }
        let settings: DNSSettings
        do {
            settings = try DNSSettings(servers: addresses.servers, searchDomains: addresses.domains, fullTunnel: true)
        } catch {
            return dnsFailed(job, String(describing: error))
        }
        let task = DNSTask()
        jobs[job.key]?.dnsTask = task
        let dns = self.dns, interfaces = self.interfaces, session = job.sessionDir
        let key = job.key, pid = job.pid, indexAtStart = job.indexAtStart
        dnsQueue.async { [weak self] in
            guard !task.isCancelled else { return }
            let result = Result { () throws -> String in
                let name = try SessionInterface.check(
                    interface, address: addresses.local, createdAfter: indexAtStart,
                    system: interfaces)
                let backend = try dns.apply(settings, interface: name, in: session)
                return DNSHook.describe(settings, interface: name, backend: backend)
            }
            guard let self else { return }
            self.queue.async { [weak self] in self?.dnsDone(key, pid: pid, result) }
        }
    }

    private func dnsDone(_ key: Key, pid: pid_t, _ result: Result<String, Error>) {
        guard let job = jobs[key], job.pid == pid else { return }  // ended meanwhile: reverted on exit
        switch result {
        case .success(let message):
            job.output?.note(message)
            DaemonLog.info("\(job.profileID) of uid \(job.ownerUID): \(message)")
        case .failure(let error):
            dnsFailed(job, String(describing: error))
        }
    }

    /// The session ends, as one whose DNS hook failed on the Mac: the client finds "setting DNS failed"
    /// in the log (`PTError.setupFailed`). `DNSApplier.apply` has undone what it did.
    private func dnsFailed(_ job: Job, _ reason: String) {
        job.output?.note("setting DNS failed: " + reason)
        DaemonLog.info("\(job.profileID) of uid \(job.ownerUID): setting DNS failed: \(reason)")
        terminate(job)
    }

    /// No DNS set-up of `job` starts any more, and one that runs is waited for (it is reverted next).
    private func endDNSTask(_ job: Job) {
        guard let task = job.dnsTask else { return }
        task.cancel()
        dnsQueue.sync {}
    }

    // MARK: - openconnect

    /// openconnect ignores its hook's result and keeps a tunnel nothing set up, so every `checkInterval` the
    /// daemon reads the session's record and stops a session whose set-up failed, that was not reported up
    /// within the set-up deadline of its start, or that stayed `reconnecting` for the reconnect deadline,
    /// whether or not a client is still waiting for it (docs/ARCHITECTURE.md, "Report and enforcement"). A
    /// record that cannot be read right now (the hook is writing it) is looked at again next time.
    private func superviseOpenConnect(_ key: Key, pid: pid_t, since started: Date, reconnectingSince: Date? = nil) {
        let timing = openConnectTiming
        queue.asyncAfter(deadline: .now() + timing.checkInterval) { [weak self] in
            guard let self, let job = self.jobs[key], job.pid == pid else { return }
            let now = Date()
            var since = reconnectingSince
            var reason: String?
            switch Result(catching: { try OpenConnectJournal.read(OpenConnectJournal.path(runDir: job.sessionDir.path)) }) {
            case .failure:
                break
            case .success(let record):
                switch record?.status {
                case .failed?:
                    reason = "the network set-up failed; stopping"
                case .up?:
                    since = nil
                case .reconnecting?:
                    let first = since ?? now
                    since = first
                    if now.timeIntervalSince(first) >= timing.reconnectDeadline {
                        reason = "the connection did not come back within \(Int(timing.reconnectDeadline)) seconds; stopping"
                    }
                case nil:
                    if now.timeIntervalSince(started) >= timing.setupDeadline {
                        reason = "the network was not set up within \(Int(timing.setupDeadline)) seconds; stopping"
                    }
                }
            }
            guard let reason else {
                return self.superviseOpenConnect(key, pid: pid, since: started, reconnectingSince: since)
            }
            DaemonLog.info("stopping \(job.profileID) of uid \(job.ownerUID) (pid \(pid)): \(reason)")
            self.note(job, reason)
            self.terminate(job)
        }
    }

    // MARK: - State of the previous instance

    /// Records pid, owner, executable, profile directory, management socket, boot ID and start time, so
    /// that the next instance can stop a tool this one leaves behind, and only that process
    /// (`PreviousInstance`), and openconnect's hook can prove its session (`LinuxVPNHook`). The child is not
    /// reaped yet: its pid, and so its start time, is its own. Written next to its place, then renamed over
    /// it, so a hook never reads half of it.
    private func writeState(plan: HelperCore.LaunchPlan, pid: pid_t, executable: String) throws {
        let text =
            "\(pid)\n\(plan.ownerUID)\n\(executable)\n\(plan.profileDir.path)\n\(plan.mgmtSocket ?? "")\n"
            + PreviousInstance.identityLines(of: pid)
        try HelperCore.checkLines(text, count: 7, file: Self.stateFileName)
        let path = plan.runDir + "/" + Self.stateFileName
        let temporary = path + ".new"
        try HelperCore.writeNewFile(temporary, Data(text.utf8), mode: 0o600)
        guard rename(temporary, path) == 0 else {
            let error = errno
            HelperCore.removeEntry(temporary)
            throw HelperCore.Failure.system("rename \(temporary)", error)
        }
    }
}

/// How the daemon follows its openconnect sessions (`Supervisor.superviseOpenConnect`): the Mac's
/// intervals and deadlines (`VPNHook.setupDeadline`, `VPNHook.reconnectDeadline`); shorter in tests.
struct OpenConnectTiming {
    var checkInterval: TimeInterval = 5
    var setupDeadline: TimeInterval = VPNHook.setupDeadline
    var reconnectDeadline: TimeInterval = VPNHook.reconnectDeadline
}
