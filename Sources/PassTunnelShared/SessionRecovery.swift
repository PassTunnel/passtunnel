import Foundation

/// What a restarted helper does with the sessions a previous helper left (`Supervisor.adoptOrphans`).
///
/// The helper starts every tool suspended and resumes it only after the signature check and after
/// recording it (`Spawner.spawnVerified`, `SessionState`). A helper that died in between leaves a tool
/// that never runs: adopting it would hold the session's slot and show it as running for good. So a tool
/// whose state still says `launching`, or that the kernel shows stopped, is stopped and its session cleaned
/// up instead; and a stopped tool of the staged copy that no state records at all (the helper died before
/// the state was written) is stopped too (`strandedLaunches`). A tool stopped right after it was resumed,
/// before its state was rewritten, ends the same way: the safe side, since nothing can tell whether it ran.
public enum SessionRecovery {
    public enum Decision: Equatable {
        /// The tool runs as recorded: track it again.
        case adopt
        /// The launch did not finish: kill the tool, then clean up as for a tool that ended.
        case stopInterruptedLaunch
        /// The tool is gone: clean up (undo its DNS, remove the session directory).
        case cleanUp
    }

    /// `alive`: the recorded pid runs the recorded executable (`isAlive`); `stopped`: the kernel shows it
    /// stopped (`isStopped`).
    public static func decide(_ state: SessionState, alive: Bool, stopped: Bool) -> Decision {
        guard alive else { return .cleanUp }
        return state.launching || stopped ? .stopInterruptedLaunch : .adopt
    }

    /// A process as `strandedLaunches` needs it.
    public struct Process: Equatable {
        public let pid: pid_t
        public let parent: pid_t
        public let path: String?
        public let stopped: Bool

        public init(pid: pid_t, parent: pid_t, path: String?, stopped: Bool) {
            self.pid = pid
            self.parent = parent
            self.path = path
            self.stopped = stopped
        }
    }

    /// Stopped tools of the staged copy (`<toolsRoot>/…`, run root resolved) that launchd inherited from a
    /// helper that died, and that no session state records: launches interrupted before their state was
    /// written. The helper never stops a tool it resumed, so nothing else is stopped there.
    public static func strandedLaunches(processes: [Process], toolsRoot: String, recorded: Set<pid_t>) -> [pid_t] {
        processes.filter { p in
            p.stopped && p.parent == 1 && p.pid > 1 && !recorded.contains(p.pid) && (p.path?.hasPrefix(toolsRoot + "/") ?? false)
        }.map(\.pid)
    }

    #if os(macOS)
    /// The recorded process still runs the recorded executable (not a recycled pid).
    public static func isAlive(_ s: SessionState) -> Bool {
        kill(s.pid, 0) == 0 && VPNHook.executablePath(of: s.pid) == s.executable
    }

    /// The kernel shows `pid` stopped (`SSTOP`): a tool started suspended and never resumed.
    public static func isStopped(_ pid: pid_t) -> Bool {
        bsdInfo(pid).map { $0.pbi_status == UInt32(SSTOP) } ?? false
    }

    static func bsdInfo(_ pid: pid_t) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size ? info : nil
    }

    /// Every process on the Mac, with its parent, executable and whether it is stopped.
    public static func systemProcesses() -> [Process] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let n = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        guard n > 0 else { return [] }
        return pids.prefix(Int(n)).compactMap { pid in
            guard pid > 0, let info = bsdInfo(pid) else { return nil }
            return Process(
                pid: pid, parent: pid_t(info.pbi_ppid), path: VPNHook.executablePath(of: pid), stopped: info.pbi_status == UInt32(SSTOP))
        }
    }
    #endif
}
