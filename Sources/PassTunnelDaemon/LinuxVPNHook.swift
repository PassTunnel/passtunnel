import Foundation
import PassTunnelShared

#if canImport(Glibc)
import Glibc
#endif

/// `vpn-hook` mode of passtunneld: openconnect's `script` (docs/LINUX.md, "Cisco AnyConnect"), the daemon's
/// own executable run by openconnect as root through the session directory's `vpn-hook` link, with
/// `/bin/sh -c`, and server-controlled values in its environment. The Linux side of the Mac's `VPNHook.run`:
/// the same steps, the shared validation, plan, record and run (`OpenConnectNetwork`, `OpenConnectPlan`,
/// `OpenConnectHook`) through `LinuxOpenConnectSystem`.
///
/// 1. **Session proof**, from the kernel's view of the process tree and the daemon's root-owned files, never from
///    the environment: euid 0; its own executable passes `TrustedPath` (as the daemon checks itself); its parent
///    is openconnect, or the shell `/bin/sh` resolves to (checked by its executable) whose parent is; that
///    openconnect's working directory is a session directory `<run root>/<uid>/<profile ID>` (root's), whose
///    `state` names that pid, that uid and that executable (an `openconnect`), with the boot and the start time
///    the kernel reports for it (`PreviousInstance.identify`). The daemon writes `state` right after
///    `posix_spawn` (there is no suspended start), so the hook waits up to `stateWait` for it.
/// 2. **Generation:** the start time in `state` and the kernel's for that pid; once the hook holds the run root's
///    network lock it proves the session again and compares them (`OpenConnectHook.stillOurs`).
/// 3. The environment checked for Linux (`OpenConnectNetwork.parse(platform: .linux)`: `tun0`–`tun99999`), the
///    session's `policy`, and the run (`OpenConnectHook`), limited to `OpenConnectHook.runLimit` with `SIGALRM`
///    one second later.
/// 4. Its lines go to its standard error, which openconnect shares with the session log (through the daemon's
///    `MaskingCopier`). After a failure it sends its openconnect SIGTERM through a pidfd, once the session check
///    holds again; the daemon stops every session whose record says failed anyway.
public enum LinuxVPNHook {
    /// The executable started under the hook's name (`argv[0]`'s last component, as the shell gives the link's
    /// path): `vpn-hook`. Its arguments are none of its business.
    public static func isInvocation(_ arguments: [String]) -> Bool {
        arguments.first.map { ($0 as NSString).lastPathComponent } == VPNHook.name
    }

    /// How long the hook waits for the daemon's `state` to name its openconnect.
    static let stateWait: TimeInterval = 5

    struct Options {
        var runRoot = PT.helperRunRoot
        /// Checked with `TrustedPath`, as the daemon checks itself when it starts. Nil only in tests.
        var ownExecutable: String? = "/proc/self/exe"
        var effectiveUID: () -> uid_t = { geteuid() }
        var parent: () -> pid_t = { getppid() }
        var processes = VPNHook.Processes.linux
        /// The shell openconnect runs the hook with (`/bin/sh`, resolved: dash or bash).
        var shell: () -> String? = { HelperCore.realPath("/bin/sh") }
        /// The recorded tool is still the process the daemon started (the same boot, start time and executable).
        var isRecordedTool: (PreviousInstance.State) -> Bool = PreviousInstance.isAlive
        var stateWait: TimeInterval = LinuxVPNHook.stateWait
        var now: () -> Date = Date.init
        var system: (SessionDirectory, String) -> OpenConnectSystem = { session, runRoot in
            LinuxOpenConnectSystem(session: session, dns: DNSApplier(runRoot: runRoot))
        }
        var environment: () -> [[UInt8]] = VPNHook.rawEnvironment
        var output: (String) -> Void = VPNHook.writeLine
        /// Sends SIGTERM to the session's openconnect when `still` holds right before (through a pidfd opened
        /// before that check, so it cannot reach a process that took the pid over).
        var stopTool: (pid_t, () -> Bool) -> Void = LinuxVPNHook.signalTool
        /// The hook's own start time, for the `hook` mark.
        var ownStart: () -> ProcessStart? = { LinuxProcess.start(of: getpid()) }
    }

    /// A proven session, and the generation of its openconnect (`state`'s boot ID and start time).
    struct Proof: Equatable {
        let session: VPNHook.Session
        let bootID: String
        let startTime: UInt64
    }

    /// Runs the hook; returns its exit status, which openconnect ignores.
    public static func main() -> Int32 {
        // The backstop: whatever hangs, SIGALRM ends the run a second after its limit. An ignored or blocked
        // signal stays so across exec: both are undone.
        signal(SIGALRM, SIG_DFL)
        var alarmSet = sigset_t()
        sigemptyset(&alarmSet)
        sigaddset(&alarmSet, SIGALRM)
        sigprocmask(SIG_UNBLOCK, &alarmSet, nil)
        alarm(UInt32(OpenConnectHook.runLimit) + 1)
        return run(options: Options())
    }

    static func run(options: Options) -> Int32 {
        let started = options.now()
        let notOurs = VPNHook.failureLine("this run is not one of a PassTunnel session")
        guard let runRoot = HelperCore.realPath(options.runRoot), let proof = prove(options, runRoot: runRoot) else {
            options.output(notOurs)
            return 1
        }
        func stillOurs() -> Bool {
            guard let again = session(options, runRoot: runRoot, wait: false) else { return false }
            return again == proof
        }
        let directory: SessionDirectory
        do {
            directory = try HelperCore(runRoot: runRoot).openRunDir(profileID: proof.session.profileID, uid: proof.session.ownerUID)
        } catch {
            options.output(notOurs)
            return 1
        }
        let environment = OpenConnectNetwork.Environment(entries: options.environment())
        var hook = OpenConnectHook(
            runRoot: runRoot, runDir: proof.session.runDir, system: options.system(directory, runRoot),
            deadline: started.addingTimeInterval(OpenConnectHook.runLimit), identity: (getpid(), options.ownStart()))
        hook.now = options.now
        hook.stillOurs = stillOurs
        let outcome = hook.run(
            event: { try OpenConnectNetwork.parse(environment, platform: .linux) },
            policy: { try VPNHook.policy(of: proof.session) })
        outcome.lines.forEach(options.output)
        // Still that openconnect of that session: it ends the session, runs the hook once more for `disconnect`,
        // and the daemon cleans up when it exits.
        if outcome.stopTool { options.stopTool(proof.session.toolPID, stillOurs) }
        return outcome.stopTool || outcome.lines.contains(where: { $0.hasPrefix(VPNHook.revertFailurePrefix) }) ? 1 : 0
    }

    /// The session, proven (step 1), with its generation; nil unless every step holds.
    static func prove(_ options: Options, runRoot: String) -> Proof? {
        guard options.effectiveUID() == 0 else { return nil }
        if let own = options.ownExecutable {
            guard let real = HelperCore.realPath(own), (try? TrustedPath.check(real)) != nil else { return nil }
        }
        return session(options, runRoot: runRoot, wait: true)
    }

    /// Steps 1 (but the euid and executable) and 2: the session whose openconnect is the hook's parent (or the
    /// shell's parent), and its generation. With `wait`, a `state` that does not name the tool yet is read again
    /// until `stateWait` has passed.
    static func session(_ options: Options, runRoot: String, wait: Bool) -> Proof? {
        let processes = options.processes
        let parent = options.parent()
        // A package update replaces a running program's file: the kernel then shows "<path> (deleted)".
        guard parent > 1, let parentExecutable = processes.executable(parent).map(installedPath) else { return nil }
        var toolPID = parent
        var toolExecutable = parentExecutable
        if !isOpenConnect(parentExecutable) {
            guard let shell = options.shell(), parentExecutable == shell, let grandparent = processes.parent(parent), grandparent > 1,
                let executable = processes.executable(grandparent).map(installedPath), isOpenConnect(executable)
            else { return nil }
            toolPID = grandparent
            toolExecutable = executable
        }
        guard let cwd = processes.workingDirectory(toolPID), cwd.hasPrefix(runRoot + "/") else { return nil }
        let parts = cwd.dropFirst(runRoot.count + 1).split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2, let uid = uid_t(parts[0]), String(uid) == parts[0], HelperCore.isValidProfileID(parts[1]) else {
            return nil
        }
        guard (try? HelperCore(runRoot: runRoot).openRunDir(profileID: parts[1], uid: uid)) != nil else { return nil }
        let deadline = options.now().addingTimeInterval(wait ? options.stateWait : 0)
        while true {
            if let state = PreviousInstance.readState(cwd + "/" + SessionState.fileName), state.pid == toolPID, state.uid == uid,
                state.executable == toolExecutable, let bootID = state.bootID, let start = state.startTime, options.isRecordedTool(state)
            {
                return Proof(
                    session: VPNHook.Session(toolPID: toolPID, runDir: cwd, ownerUID: uid, profileID: parts[1]), bootID: bootID,
                    startTime: start)
            }
            guard options.now() < deadline else { return nil }
            usleep(50_000)
        }
    }

    /// The path a running program was started from, without the " (deleted)" the kernel adds once a package
    /// update replaced its file.
    static func installedPath(_ path: String) -> String {
        path.hasSuffix(" (deleted)") ? String(path.dropLast(" (deleted)".count)) : path
    }

    /// An `openconnect` executable (the daemon recorded which one in `state`, and it must be that one).
    static func isOpenConnect(_ path: String) -> Bool {
        (path as NSString).lastPathComponent == ToolSpec.openconnect.name
    }

    /// SIGTERM to `pid` through a pidfd opened before `still` is checked; nothing without pidfds.
    static func signalTool(_ pid: pid_t, still: () -> Bool) {
        guard let pidfd = Sys.pidfdOpen(pid) else { return }
        defer { close(pidfd) }
        guard still() else { return }
        _ = Sys.pidfdSignal(pidfd, SIGTERM, processGroup: false)
    }

    // MARK: - The daemon's side

    /// Kills a hook of the session in `runDir` that is still running past its limit: the process its `hook` mark
    /// names, only if it is still that process (pid and start time) and runs `executable` (the daemon's own),
    /// through a pidfd opened before that check.
    static func killHook(runDir: String, executable: String?) {
        guard let executable, let mark = OpenConnectMarks.runningHook(runDir: runDir), let pidfd = Sys.pidfdOpen(mark.pid) else { return }
        defer { close(pidfd) }
        guard let running = PreviousInstance.executable(of: mark.pid), running == executable || running == executable + " (deleted)",
            LinuxProcess.start(of: mark.pid) == mark.start
        else { return }
        _ = Sys.pidfdSignal(pidfd, SIGKILL, processGroup: false)
    }
}

/// What `/proc` says about processes.
enum LinuxProcess {
    /// When `pid` started, as a time after boot (field 22 of `/proc/<pid>/stat`, clock ticks, converted), in the
    /// form the `hook` mark records (`ProcessStart`).
    static func start(of pid: pid_t) -> ProcessStart? {
        guard let ticks = PreviousInstance.startTime(of: pid) else { return nil }
        return start(ticks: ticks, hz: UInt64(max(1, sysconf(Int32(_SC_CLK_TCK)))))
    }

    static func start(ticks: UInt64, hz: UInt64) -> ProcessStart {
        ProcessStart(seconds: ticks / hz, microseconds: (ticks % hz) * 1_000_000 / hz)
    }

    /// Field 4 of `/proc/<pid>/stat`: the parent.
    static func parent(of pid: pid_t) -> pid_t? {
        guard let fields = PreviousInstance.statFields(pid), fields.count > 1, let parent = pid_t(fields[1]) else { return nil }
        return parent
    }

    /// `/proc/<pid>/cwd`, resolved by the kernel.
    static func workingDirectory(of pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 4097)
        let n = readlink("/proc/\(pid)/cwd", &buf, buf.count - 1)
        guard n > 0 else { return nil }
        buf[n] = 0
        return String(cString: buf)
    }
}

extension VPNHook.Processes {
    /// The kernel's answers on Linux: `/proc/<pid>/exe`, `/proc/<pid>/stat`, `/proc/<pid>/cwd`.
    static let linux = VPNHook.Processes(
        executable: PreviousInstance.executable(of:), parent: LinuxProcess.parent(of:), workingDirectory: LinuxProcess.workingDirectory(of:))
}
