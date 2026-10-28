import Foundation

/// What a restarted helper does with the sessions a previous helper left (`Supervisor.adoptOrphans`).
///
/// The helper starts every tool suspended and resumes it only after the signature check and after
/// recording it as `launching` (`Spawner.spawnVerified`, `SessionState`); once resumed, it records it again
/// without the mark. A helper that died in between leaves a tool that may never run: adopting it would hold
/// the session's slot and show it as running for good. So a recorded tool whose state still says
/// `launching` is stopped and its session cleaned up instead of adopted. Only that mark means an
/// interrupted launch: a recorded tool without it is adopted as before, even if it is stopped (a debugger,
/// say). A tool stopped right after it was resumed, before the second write, ends the same way as one
/// never resumed: nothing can tell whether it ran, and stopping it is the safe side.
///
/// Every decision and every signal goes by the process's identity: pid, start time and executable
/// (`ProcessFacts`), checked again right before the signal (`signal`), so a recycled pid is never hit. A
/// record without a start time (from a helper before #182) cannot be verified that way: it is adopted or
/// cleaned up by the old rule (pid and executable), never killed on the `launching` path.
///
/// Strays (`strandedLaunches`): a stopped root process of the staged tools that launchd inherited and that
/// no record names was left by a helper that died before it recorded the launch at all; it would stay
/// suspended forever. It is killed, alone (never a process group), and only if it is still the same
/// stopped root orphan when the signal is sent. A user cannot make one: running the staged tool gives a
/// process of their own, which is never touched.
public enum SessionRecovery {
    public enum Decision: Equatable {
        /// The tool runs as recorded: track it again.
        case adopt
        /// The launch did not finish: kill the tool (`signal`), then clean up as for a tool that ended.
        case stopInterruptedLaunch
        /// The recorded tool is gone (or its pid now belongs to another process): clean up (undo its DNS,
        /// remove the session directory).
        case cleanUp
    }

    /// What the kernel says about a process.
    public struct ProcessFacts: Equatable {
        public let pid: pid_t
        public let parent: pid_t
        public let path: String?
        public let stopped: Bool
        public let start: ProcessStart?
        /// Effective and real user.
        public let uid: uid_t
        public let ruid: uid_t

        public init(
            pid: pid_t, parent: pid_t, path: String?, stopped: Bool, start: ProcessStart?, uid: uid_t, ruid: uid_t
        ) {
            self.pid = pid
            self.parent = parent
            self.path = path
            self.stopped = stopped
            self.start = start
            self.uid = uid
            self.ruid = ruid
        }
    }

    /// Whether `current` (nil: no such process) is the process `state` records: the same executable and,
    /// when the record has one, the same start time.
    public static func matches(_ state: SessionState, _ current: ProcessFacts?) -> Bool {
        guard let current, current.pid == state.pid, current.path == state.executable else { return false }
        guard let recorded = state.startTime else { return true }
        return current.start == recorded
    }

    public static func decide(_ state: SessionState, current: ProcessFacts?) -> Decision {
        guard matches(state, current) else { return .cleanUp }
        // Only a record with a start time identifies the process well enough to kill it.
        return state.launching && state.startTime != nil ? .stopInterruptedLaunch : .adopt
    }

    /// Stopped root orphans of the staged tools (`<toolsRoot>/…`, run root resolved) that no record names.
    public static func strandedLaunches(processes: [ProcessFacts], toolsRoot: String, recorded: Set<pid_t>) -> [ProcessFacts] {
        processes.filter { isStranded($0, toolsRoot: toolsRoot) && !recorded.contains($0.pid) }
    }

    public static func isStranded(_ p: ProcessFacts, toolsRoot: String) -> Bool {
        p.stopped && p.parent == 1 && p.pid > 1 && p.uid == 0 && p.ruid == 0 && p.start != nil
            && (p.path?.hasPrefix(toolsRoot + "/") ?? false)
    }

    /// Sends `sig` to `expected.pid` alone, and only if the process there is still `expected` (pid, start
    /// time, executable; a process without a known start time is never signalled) and `still` holds for
    /// what the kernel says now. Returns whether it was sent.
    @discardableResult
    public static func signal(
        _ expected: ProcessFacts, _ sig: Int32, still: (ProcessFacts) -> Bool = { _ in true },
        read: (pid_t) -> ProcessFacts?, send: (pid_t, Int32) -> Int32
    ) -> Bool {
        guard expected.pid > 1, let start = expected.start, let path = expected.path, let now = read(expected.pid),
            now.pid == expected.pid, now.start == start, now.path == path, still(now)
        else { return false }
        return send(expected.pid, sig) == 0
    }

    #if os(macOS)
    /// The kernel's facts about `pid` (`proc_pidinfo`, `proc_pidpath`); nil when there is no such process.
    public static func facts(of pid: pid_t) -> ProcessFacts? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard pid > 0, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return ProcessFacts(
            pid: pid, parent: pid_t(info.pbi_ppid), path: VPNHook.executablePath(of: pid), stopped: info.pbi_status == UInt32(SSTOP),
            start: ProcessStart(seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec), uid: info.pbi_uid,
            ruid: info.pbi_ruid)
    }

    /// The recorded process still runs (`matches`).
    public static func isAlive(_ s: SessionState) -> Bool { matches(s, facts(of: s.pid)) }

    /// Every process on the Mac.
    public static func systemProcesses() -> [ProcessFacts] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let n = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        guard n > 0 else { return [] }
        return pids.prefix(Int(n)).compactMap { $0 > 0 ? facts(of: $0) : nil }
    }
    #endif
}
