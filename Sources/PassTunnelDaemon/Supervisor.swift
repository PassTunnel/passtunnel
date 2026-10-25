import Foundation
import PassTunnelShared

/// Starts, tracks and stops the VPN tools, as the Mac's helper does; all state is confined to `queue`.
/// Sessions are keyed by (owner uid, profile ID) (`SessionPolicy`). Each child has a thread of its own
/// that waits for it to exit; then the DNS its session recorded is reverted (normally its hook has done
/// that already) and the session directory removed. There is no adoption: tools recorded by an earlier
/// instance are stopped when the daemon starts (`PreviousInstance`). FortiGate sessions print into a
/// pipe the daemon reads (`OutputCopier`): it copies their output into the log and, for a profile with
/// `set_dns`, sets the DNS openfortivpn reports there for the session's ppp interface (`FortiDNSWatch`,
/// `SessionInterface`, `DNSApplier`), off the queue, on `dnsQueue`.
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
    static let stateFileName = "state"
    static let noServers = "the gateway named no DNS servers; DNS is left as it is"

    let queue = DispatchQueue(label: "passtunneld.supervisor")
    /// FortiGate DNS set-ups: they run tools and wait for the run root's lock, so not on `queue`.
    let dnsQueue = DispatchQueue(label: "passtunneld.dns")
    private let core: HelperCore
    private let tools: ToolResolving
    /// Reverts what a session's DNS hook left, and sets FortiGate's (`DNSApplier`).
    let dns: DNSApplier
    private let interfaces: InterfaceSystem
    /// How long the DNS set-up waits, once openfortivpn says the tunnel is up, for what it did not
    /// report yet.
    private let reportWait: TimeInterval
    private let stopGrace: TimeInterval
    private var jobs: [Key: Job] = [:]
    private var logTimer: DispatchSourceTimer?

    private var sessions: [SessionPolicy.Session] {
        jobs.values.map {
            SessionPolicy.Session(profileID: $0.profileID, ownerUID: $0.ownerUID, pid: $0.pid, mgmtSocket: $0.mgmtSocket)
        }
    }

    init(core: HelperCore, tools: ToolResolving, dns: DNSApplier, interfaces: InterfaceSystem = InterfaceSystem(),
         reportWait: TimeInterval = 10, stopGrace: TimeInterval = 5) {
        self.core = core
        self.tools = tools
        self.dns = dns
        self.interfaces = interfaces
        self.reportWait = reportWait
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
                reply(self.start(profileID: s.profileID, uid: uid, tool: .openvpn) { tool, core in
                    // The DNS hook as `--dns-updown` where OpenVPN knows it (2.7), else as `--route-up` and `--down`.
                    core.openVPNHasDNSUpdown = tool.version >= ToolVersion(2, 7, 0)
                    return try core.prepareOpenVPN(s, uid: uid)
                })
            case .startForti(let s):
                reply(self.start(profileID: s.profileID, uid: uid, tool: .openfortivpn, output: .copied(setDNS: s.setDNS)) { _, core in
                    // openfortivpn runs pppd from the path compiled into it: checked as a tool is.
                    _ = try self.tools.resolve(.pppd)
                    core.caFile = try self.tools.caBundle()
                    // openfortivpn and pppd never touch resolv.conf; the daemon applies DNS (docs/LINUX.md).
                    core.fortiHandlesDNS = false
                    return try core.prepareForti(s, uid: uid)
                })
            case .stop(let id):
                self.stop(profileID: id, uid: uid, reply: reply)
            case .status:
                reply(.success(running: SessionPolicy.visible(to: uid, sessions: self.sessions),
                               mgmtSockets: SessionPolicy.sockets(visibleTo: uid, sessions: self.sessions)))
            }
        }
    }

    /// Where a tool's output goes: straight into the log (OpenVPN), or through `OutputCopier`
    /// (openfortivpn), followed for DNS when the profile has `set_dns`.
    enum Output {
        case log
        case copied(setDNS: Bool)
    }

    /// Checks the session limits and the tool, has `prepare` write the session's files (given the
    /// checked tool and a copy of the core to adjust), then spawns the tool and supervises it.
    private func start(profileID: String, uid: uid_t, tool spec: ToolSpec, output: Output = .log,
                       prepare: (ResolvedTool, inout HelperCore) throws -> HelperCore.LaunchPlan) -> HelperResponse {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            try SessionPolicy.checkStart(profileID: profileID, uid: uid, sessions: sessions)
        } catch {
            return .failure(String(describing: error))
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
            if case .copied = output { pipeFDs = try Sys.makePipe() }
            defer { pipeFDs.map { _ = close($0.write) } }      // the tool has its own copy
            let indexAtStart = pipeFDs == nil ? 0 : interfaces.highestIndex()
            let pid = try Sys.spawn(executable: tool.path, arguments: plan.arguments,
                                    environment: HelperCore.fixedEnvironment,
                                    workingDirectory: plan.runDir, outputFD: pipeFDs?.write ?? plan.logFD)
            writeState(plan: plan, pid: pid, executable: tool.path)
            let logCopy = fcntl(plan.logFD, F_DUPFD_CLOEXEC, 0)
            var job = Job(profileID: plan.profileID, ownerUID: plan.ownerUID, pid: pid, executable: tool.path,
                          sessionDir: plan.sessionDir, mgmtSocket: plan.mgmtSocket, logFD: logCopy)
            if let fds = pipeFDs, case .copied(let setDNS) = output {
                let key = job.key
                let copier = OutputCopier(readFD: fds.read, logFD: fcntl(plan.logFD, F_DUPFD_CLOEXEC, 0)) { [weak self] line in
                    self?.queue.async { self?.received(line, key: key, pid: pid) }
                }
                pipeFDs = (-1, fds.write)                        // the copier closes the read end
                job.output = copier
                job.fortiDNS = setDNS ? FortiDNSWatch() : nil
                job.indexAtStart = indexAtStart
                copier.start(name: "passtunneld.output.\(pid)")
            }
            jobs[job.key] = job
            watch(job.key, pid: pid)
            if plan.mgmtSocket != nil { restrictSocketWhenReady(job.key, pid: pid, attempt: 0) }
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
                endDNSTask(job)
                revertDNS(job)
                core.removeRunDir(profileID: job.profileID, uid: job.ownerUID)
            }
        }
    }

    /// What the session's DNS hook (or, for FortiGate, the daemon) recorded and did not revert itself
    /// (the tool was killed, or died; FortiGate's is always reverted here).
    private func revertDNS(_ job: Job) {
        if let message = dns.revert(in: job.sessionDir) {
            DaemonLog.info("\(job.profileID) of uid \(job.ownerUID): \(message)")
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
        endDNSTask(job)
        revertDNS(job)
        core.removeRunDir(profileID: job.profileID, uid: job.ownerUID)   // config, auth file, socket, state
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
                let name = try SessionInterface.check(interface, address: addresses.local, createdAfter: indexAtStart,
                                                      system: interfaces)
                let backend = try dns.apply(settings, interface: name, in: session)
                return DNSHook.describe(settings, interface: name, backend: backend)
            }
            self?.queue.async { self?.dnsDone(key, pid: pid, result) }
        }
    }

    private func dnsDone(_ key: Key, pid: pid_t, _ result: Result<String, Error>) {
        guard let job = jobs[key], job.pid == pid else { return }      // ended meanwhile: reverted on exit
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
