import Foundation

/// openconnect's `script` on the Mac: a root-owned copy of the helper's own executable, staged as
/// `<tools>/<build>/Resources/bin/vpn-hook` next to the openconnect it serves (`ToolStager`), and run by
/// openconnect as root through `/bin/sh -c` with server-controlled values in its environment
/// (docs/ARCHITECTURE.md, "The hook: vpn-hook").
///
/// `run` proves which PassTunnel session's openconnect ran it (`session`), checks the environment
/// (`OpenConnectNetwork`), reads the session's `policy` and sets up or reverts the network
/// (`OpenConnectHook`, through `MacOpenConnectSystem`). It writes one line to its standard error, which
/// openconnect shares with the session's log: the success line (`Report.line`) or the failure line
/// (`failureLine`). openconnect ignores a script's exit status and would keep a tunnel nothing set up, so after
/// a failure the hook sends that openconnect SIGTERM, and the helper stops every openconnect session whose
/// record says failed, that was not reported up within `setupDeadline`, or that did not come back within
/// `reconnectDeadline` (`Supervisor`).
public enum VPNHook {
    /// The hook's file name, also the last component of its `argv[0]` (openconnect runs the path as a
    /// `/bin/sh -c` command, so the shell gives the path as `argv[0]`).
    public static let name = "vpn-hook"

    // MARK: - Report lines

    /// What starts every line the hook writes to the session's log.
    public static let linePrefix = "passtunnel vpn-hook: "
    /// What starts the line of a failed set-up: `PTError.setupFailed` for the client (#184).
    public static let failurePrefix = linePrefix + "setting up the network failed: "
    /// The longest reason a failure line carries.
    public static let maxReasonBytes = 300

    /// `text` as one line of printable ASCII: every byte outside 0x20–0x7E (line breaks, other control
    /// bytes, UTF-8) becomes `?`, blanks at either end go, at most `maxBytes` bytes are kept; `?` when
    /// nothing is left. So no text, whatever it holds, can end the line or start another one.
    public static func oneLine(_ text: String, maxBytes: Int = maxReasonBytes) -> String {
        let bytes = text.utf8.prefix(maxBytes).map { $0 >= 0x20 && $0 < 0x7F ? $0 : UInt8(ascii: "?") }
        let line = String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: CharacterSet(charactersIn: " "))
        return line.isEmpty ? "?" : line
    }

    /// `passtunnel vpn-hook: setting up the network failed: <reason>` and a line break. The reason passes
    /// through `oneLine`; the hook's own reasons name variables and rules, never values (`OpenConnectNetwork.Failure`).
    public static func failureLine(_ reason: String) -> String { failurePrefix + oneLine(reason) + "\n" }

    /// What starts the line of a revert that did not finish (the helper tries again once openconnect ended).
    public static let revertFailurePrefix = linePrefix + "restoring the network failed: "

    /// The line of a run whose session ended while it waited: it changed nothing, and stops nothing.
    public static let endedLine = linePrefix + "the session this run was started for has ended; nothing was changed\n"

    /// `passtunnel vpn-hook: restoring the network failed: <reason>` and a line break.
    public static func revertFailureLine(_ reason: String) -> String { revertFailurePrefix + oneLine(reason) + "\n" }

    /// What the line of a set-up that succeeded says, the "connected" marker for the client (#184), whose
    /// `NetworkClaims` read the DNS from it:
    ///
    ///     passtunnel vpn-hook: utun5 up: 10.0.0.2, 2001:db8::5, 2 routes, full tunnel, IPv6 blocked, DNS 10.0.0.53 10.0.0.54, search example.com, split DNS corp.example.com
    ///
    /// The interface, then its addresses, the number of routes into the tunnel, how many routes the server
    /// asked for stay local instead (`2 routes kept local`, only when there are any), `full tunnel` when every
    /// family with an address sends everything into it, `IPv4 blocked`/`IPv6 blocked` for a family refused
    /// meanwhile (`OpenConnectPlan.blocked`), and with DNS its servers, search domains and split DNS
    /// domains. Every item is a checked value or fixed text, none holds `,` or a line break, so `parse` reads
    /// back exactly what was written.
    public struct Report: Equatable, Sendable {
        public var interface: String
        public var addresses: [IPAddress]
        public var routes: Int
        /// Routes the server asked for that stay local (`OpenConnectPlan.keptLocal`).
        public var keptLocal: Int
        public var fullTunnel: Bool
        public var blocked: [IPAddress.Family]
        public var dnsServers: [IPAddress]
        public var searchDomains: [String]
        public var splitDNSDomains: [String]

        public init(
            interface: String, addresses: [IPAddress], routes: Int, keptLocal: Int = 0, fullTunnel: Bool, blocked: [IPAddress.Family] = [],
            dnsServers: [IPAddress] = [], searchDomains: [String] = [], splitDNSDomains: [String] = []
        ) {
            self.interface = interface
            self.addresses = addresses
            self.routes = routes
            self.keptLocal = keptLocal
            self.fullTunnel = fullTunnel
            self.blocked = blocked
            self.dnsServers = dnsServers
            self.searchDomains = searchDomains
            self.splitDNSDomains = splitDNSDomains
        }

        /// What `plan` sets up.
        public init(_ plan: OpenConnectPlan) {
            let dns = plan.dns
            self.init(
                interface: plan.interface, addresses: plan.addresses, routes: plan.tunnelRoutes.count, keptLocal: plan.keptLocal,
                fullTunnel: plan.fullTunnel,
                blocked: plan.blocked, dnsServers: dns?.servers ?? [], searchDomains: dns?.searchDomains ?? [],
                splitDNSDomains: dns?.matchDomains ?? [])
        }

        /// The line, with its line break.
        public var line: String {
            var items = addresses.map(\.description)
            items.append(routes == 1 ? "1 route" : "\(routes) routes")
            if keptLocal > 0 { items.append(keptLocal == 1 ? "1 route kept local" : "\(keptLocal) routes kept local") }
            if fullTunnel { items.append("full tunnel") }
            for family in blocked { items.append(family == .ipv4 ? "IPv4 blocked" : "IPv6 blocked") }
            if !dnsServers.isEmpty { items.append("DNS " + dnsServers.map(\.description).joined(separator: " ")) }
            if !searchDomains.isEmpty { items.append("search " + searchDomains.joined(separator: " ")) }
            if !splitDNSDomains.isEmpty { items.append("split DNS " + splitDNSDomains.joined(separator: " ")) }
            return VPNHook.linePrefix + interface + " up: " + items.joined(separator: ", ") + "\n"
        }

        /// The report a success line (with or without its line break) gives, exactly `line`'s form; nil for any
        /// other line.
        public static func parse(_ line: Substring) -> Report? {
            var text = line
            if text.hasSuffix("\n") { text = text.dropLast() }
            guard text.utf8.count <= 16 << 10, text.hasPrefix(VPNHook.linePrefix) else { return nil }
            text = text.dropFirst(VPNHook.linePrefix.count)
            guard let up = text.range(of: " up: ") else { return nil }
            let interface = String(text[..<up.lowerBound])
            guard OpenConnectRecord.isInterface(interface) else { return nil }
            var report = Report(interface: interface, addresses: [], routes: -1, fullTunnel: false)
            for item in text[up.upperBound...].components(separatedBy: ", ") {
                let words = item.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
                if report.routes < 0 {
                    if let address = IPAddress(item) {
                        report.addresses.append(address)
                    } else if words.count == 2, words[1] == "route" || words[1] == "routes",
                        let n = OpenConnectNetwork.decimal(words[0], max: 1 << 20)
                    {
                        report.routes = n
                    } else {
                        return nil
                    }
                } else if words.count == 4, words[2] == "kept", words[3] == "local", words[1] == "route" || words[1] == "routes",
                    report.keptLocal == 0, let n = OpenConnectNetwork.decimal(words[0], max: 1 << 20), n > 0
                {
                    report.keptLocal = n
                } else if item == "full tunnel" {
                    report.fullTunnel = true
                } else if item == "IPv4 blocked" || item == "IPv6 blocked" {
                    report.blocked.append(item == "IPv4 blocked" ? .ipv4 : .ipv6)
                } else if words.count > 1, words[0] == "DNS" {
                    let servers = words.dropFirst().compactMap(IPAddress.init)
                    guard servers.count == words.count - 1 else { return nil }
                    report.dnsServers = servers
                } else if words.count > 1, words[0] == "search" {
                    report.searchDomains = Array(words.dropFirst())
                } else if words.count > 2, words[0] == "split", words[1] == "DNS" {
                    report.splitDNSDomains = Array(words.dropFirst(2))
                } else {
                    return nil
                }
            }
            guard report.routes >= 0,
                (report.searchDomains + report.splitDNSDomains).allSatisfy({ DomainName.normalize($0) == $0 }),
                report.line == VPNHook.linePrefix + text + "\n"
            else { return nil }
            return report
        }
    }

    /// How long an openconnect session may run without its hook reporting the network up before the
    /// helper stops it (docs/ARCHITECTURE.md, "Report and enforcement").
    public static let setupDeadline: TimeInterval = 60

    /// How long a session may stay `reconnecting` (openconnect re-establishing a dropped connection) before
    /// the helper stops it, and a new sign-in takes over.
    public static let reconnectDeadline: TimeInterval = 120

    /// Whether the hook reported the session's network up: the record's latest status is `up`, or
    /// `reconnecting` (which only follows `up`).
    public static func reportedUp(runDir: String) -> Bool {
        switch OpenConnectJournal.status(runDir: runDir) {
        case .up, .reconnecting: return true
        case .failed, nil: return false
        }
    }

    // MARK: - Mode

    /// What the helper's executable runs as.
    public enum Mode: Equatable {
        /// The privileged helper (launchd, XPC).
        case helper
        /// openconnect's hook.
        case hook
        /// Neither: the staged copy started under another name, or the helper started as `vpn-hook`.
        case refused
    }

    /// The mode of a process whose executable the kernel reports at `executablePath` (`proc_pidpath`,
    /// links resolved: not chosen by whoever starts it) and that was given `argv0`. The hook mode needs
    /// both to be named `vpn-hook`: the installed helper (`Contents/MacOS/PassTunnelHelper`, which launchd
    /// starts and which serves XPC) never runs as the hook whatever its `argv[0]`, and the staged copy
    /// never runs as the helper. A mismatch in either direction is refused.
    public static func mode(executablePath: String?, argv0: String?) -> Mode {
        let executableIsHook = executablePath.map { ($0 as NSString).lastPathComponent == name } ?? false
        let argumentIsHook = argv0.map { ($0 as NSString).lastPathComponent == name } ?? false
        switch (executableIsHook, argumentIsHook) {
        case (true, true): return .hook
        case (false, false): return .helper
        default: return .refused
        }
    }

    // MARK: - Session check

    /// What the kernel says about a process; replaced in tests.
    public struct Processes {
        public var executable: (pid_t) -> String?
        public var parent: (pid_t) -> pid_t?
        public var workingDirectory: (pid_t) -> String?

        public init(
            executable: @escaping (pid_t) -> String?, parent: @escaping (pid_t) -> pid_t?,
            workingDirectory: @escaping (pid_t) -> String?
        ) {
            self.executable = executable
            self.parent = parent
            self.workingDirectory = workingDirectory
        }
    }

    /// Shells `/bin/sh` may be or become (macOS's `/bin/sh` starts the shell `/private/var/select/sh`
    /// names, in the same process): openconnect runs the hook through `/bin/sh -c`, which may or may not
    /// replace itself with the hook.
    public static let shells: Set<String> = ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh"]

    /// A proven session: the pid of the openconnect that ran the hook and its session directory.
    public struct Session: Equatable {
        public let toolPID: pid_t
        public let runDir: String
        public let ownerUID: uid_t
        public let profileID: String

        public init(toolPID: pid_t, runDir: String, ownerUID: uid_t, profileID: String) {
            self.toolPID = toolPID
            self.runDir = runDir
            self.ownerUID = ownerUID
            self.profileID = profileID
        }
    }

    /// The PassTunnel session whose openconnect ran the hook, proven from the kernel's view of the process
    /// tree and the helper's root-owned files, never from the environment; nil unless every step holds:
    /// 1. the hook's own executable is `<runRoot>/tools/<build>/Resources/bin/vpn-hook` (`runRoot` with links
    ///    resolved), so the openconnect it serves is `openconnect` next to it;
    /// 2. its parent runs that openconnect, or one of `shells` whose own parent does;
    /// 3. that openconnect's working directory is a session directory `<runRoot>/<uid>/<profile ID>` (the
    ///    helper starts every tool there);
    /// 4. that directory's `state` (`readState`) names that pid, that uid and that executable.
    public static func session(
        hookExecutable: String, parent: pid_t, runRoot: String, processes: Processes,
        readState: (String) -> SessionState? = SessionState.read
    ) -> Session? {
        guard (hookExecutable as NSString).lastPathComponent == name else { return nil }
        let bin = (hookExecutable as NSString).deletingLastPathComponent
        let toolsPrefix = runRoot + "/tools/"
        let binSuffix = "/Resources/bin"
        guard bin.hasPrefix(toolsPrefix), bin.hasSuffix(binSuffix) else { return nil }
        let build = bin.dropFirst(toolsPrefix.count).dropLast(binSuffix.count)
        guard isBuildID(build) else { return nil }
        let tool = bin + "/openconnect"

        var toolPID = parent
        if processes.executable(parent) != tool {
            guard let shell = processes.executable(parent), shells.contains(shell), let grandparent = processes.parent(parent),
                processes.executable(grandparent) == tool
            else { return nil }
            toolPID = grandparent
        }
        guard toolPID > 1, let cwd = processes.workingDirectory(toolPID), cwd.hasPrefix(runRoot + "/") else { return nil }
        let parts = cwd.dropFirst(runRoot.count + 1).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let uid = uid_t(parts[0]), String(uid) == parts[0], HelperCore.isValidProfileID(String(parts[1]))
        else { return nil }
        guard let state = readState(cwd + "/" + SessionState.fileName), state.pid == toolPID, state.uid == uid,
            state.executable == tool
        else { return nil }
        return Session(toolPID: toolPID, runDir: cwd, ownerUID: uid, profileID: String(parts[1]))
    }

    /// A staged build directory's name (`ToolStager`): 16–64 lowercase hex digits.
    static func isBuildID(_ s: Substring) -> Bool {
        (16...64).contains(s.utf8.count) && s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    // MARK: - The hook

    /// The session's `policy` (0600, the helper's), which must name the session's user and profile.
    public static func policy(of session: Session) throws -> OpenConnectPolicy {
        guard let data = try? HelperCore.readOwnFile(session.runDir + "/" + OpenConnectPolicy.fileName, maxBytes: 4096),
            let text = String(data: data, encoding: .utf8), let policy = OpenConnectPolicy.parse(text),
            policy.uid == session.ownerUID, policy.profileID == session.profileID
        else { throw OpenConnectHook.Failure.policy }
        return policy
    }

    /// The process's environment as openconnect left it: raw `NAME=VALUE` bytes, decoded by nobody but
    /// `OpenConnectNetwork.Environment`.
    public static func rawEnvironment() -> [[UInt8]] {
        var out: [[UInt8]] = []
        var cursor: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?> = environ
        while let entry = cursor.pointee {
            out.append(Array(UnsafeRawBufferPointer(start: entry, count: strlen(entry))))
            cursor += 1
        }
        return out
    }

    public static func writeLine(_ line: String) {
        _ = line.withCString { write(STDERR_FILENO, $0, strlen($0)) }
    }

    #if os(macOS)
    /// The hook's whole run (`PassTunnelHelper`'s `main` in hook mode); returns the exit status, which
    /// openconnect ignores. Nothing is read from the environment before the session is proven, and nothing
    /// but the variables `OpenConnectNetwork` reads after.
    public static func run() -> Int32 {
        let started = Date()
        guard geteuid() == 0, let executable = Self.executablePath(of: getpid()),
            let runRoot = HelperCore.realPath(PT.helperRunRoot),
            let session = session(hookExecutable: executable, parent: getppid(), runRoot: runRoot, processes: .system)
        else {
            writeLine(failureLine("this run is not one of a PassTunnel session"))
            return 1
        }
        // The backstop: whatever hangs (a tool past its limit is killed by the hook itself), SIGALRM ends the
        // run a second after its limit. An ignored or blocked signal stays so across exec: both are undone.
        signal(SIGALRM, SIG_DFL)
        var alarmSet = sigset_t()
        sigemptyset(&alarmSet)
        sigaddset(&alarmSet, SIGALRM)
        sigprocmask(SIG_UNBLOCK, &alarmSet, nil)
        alarm(UInt32(OpenConnectHook.runLimit) + 1)
        // The session's generation: its openconnect's start time, which the helper recorded in `state` and the
        // kernel reports for that pid. A later session in the same directory has another one.
        let generation = SessionState.read(session.runDir + "/" + SessionState.fileName)?.startTime
        func stillOurs() -> Bool {
            guard let generation,
                let again = Self.session(hookExecutable: executable, parent: getppid(), runRoot: runRoot, processes: .system),
                again == session, SessionState.read(session.runDir + "/" + SessionState.fileName)?.startTime == generation,
                SessionRecovery.facts(of: session.toolPID)?.start == generation
            else { return false }
            return true
        }
        guard stillOurs() else {
            writeLine(failureLine("this run is not one of a PassTunnel session"))
            return 1
        }
        let environment = OpenConnectNetwork.Environment(entries: rawEnvironment())
        var hook = OpenConnectHook(
            runRoot: runRoot, runDir: session.runDir, system: MacOpenConnectSystem(),
            deadline: started.addingTimeInterval(OpenConnectHook.runLimit), identity: (getpid(), SessionRecovery.facts(of: getpid())?.start))
        hook.stillOurs = stillOurs
        let outcome = hook.run(
            event: { try OpenConnectNetwork.parse(environment, platform: .macOS) }, policy: { try policy(of: session) })
        outcome.lines.forEach(writeLine)
        // Still that openconnect of that session (it may have ended meanwhile, and its pid been reused): it ends
        // the session, runs the hook once more for `disconnect`, and the helper cleans up when it exits.
        if outcome.stopTool, stillOurs() {
            kill(session.toolPID, SIGTERM)
        }
        return outcome.stopTool || outcome.lines.contains(where: { $0.hasPrefix(revertFailurePrefix) }) ? 1 : 0
    }

    /// The executable of `pid` as the kernel reports it (links resolved), nil when it cannot be read.
    public static func executablePath(of pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : nil
    }
    #endif
}

#if os(macOS)
extension VPNHook.Processes {
    /// The kernel's answers: `proc_pidpath`, `proc_pidinfo`.
    public static let system = VPNHook.Processes(
        executable: VPNHook.executablePath(of:),
        parent: { pid in
            var info = proc_bsdinfo()
            let size = Int32(MemoryLayout<proc_bsdinfo>.size)
            guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
            return pid_t(info.pbi_ppid)
        },
        workingDirectory: { pid in
            var info = proc_vnodepathinfo()
            let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
            guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, size) == size else { return nil }
            return withUnsafeBytes(of: info.pvi_cdir.vip_path) { raw in
                String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
            }
        })
}
#endif
