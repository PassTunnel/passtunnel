import Foundation
import PassTunnelShared

#if canImport(Darwin)
import Darwin
#endif

/// Decides when the app replaces an outdated helper on its own, e.g. right after the app itself was
/// updated (the helper still runs the build it was started from). Only an older helper is replaced,
/// and only by a copy in /Applications: re-registering points the root helper at this copy, so a copy
/// elsewhere (user-writable) or an older build (a downgrade) needs the user's explicit confirmation.
/// Updating unregisters the helper, which stops every tunnel it runs, so it only happens while no
/// PassTunnel session is active; otherwise the app keeps showing "Needs an update" and updates as soon
/// as the last session ends.
///
/// Feed it the current situation every time something may have changed; it remembers whether it
/// already notified and whether it already tried (one automatic attempt per outdated helper, so a
/// failing update is left to the Update Helper button instead of looping).
public struct HelperAutoUpdate: Equatable, Sendable {
    public enum Action: Equatable, Sendable {
        case none
        /// Run `HelperInstaller.update` now.
        case update
        /// Sessions are active: wait. `notify` is true the first time only.
        case wait(notify: Bool)
    }

    public struct Situation: Equatable, Sendable {
        public var status: HelperStatus
        /// nil while unknown (the helper has not answered yet).
        public var outdated: Bool?
        /// The helper is an earlier build than this copy's (`HelperBuild.Relation.older`).
        public var helperIsOlder: Bool
        /// Active PassTunnel sessions on this Mac, from any user or process (see `HelperSessions`).
        public var activeSessions: Int
        /// An update (automatic or from Settings → Helper) is running.
        public var updating: Bool
        /// The app runs from /Applications. A copy elsewhere (a test build, a mounted disk image,
        /// ~/Applications) never takes over the helper on its own.
        public var inApplicationsFolder: Bool

        public init(
            status: HelperStatus, outdated: Bool?, helperIsOlder: Bool, activeSessions: Int, updating: Bool,
            inApplicationsFolder: Bool
        ) {
            self.status = status
            self.outdated = outdated
            self.helperIsOlder = helperIsOlder
            self.activeSessions = activeSessions
            self.updating = updating
            self.inApplicationsFolder = inApplicationsFolder
        }
    }

    /// Sessions are active and the update waits for them to end.
    public private(set) var waiting = false
    public private(set) var notified = false
    public private(set) var attempted = false

    public init() {}

    public mutating func next(_ s: Situation) -> Action {
        guard s.status == .enabled, s.outdated == true else {
            // Current again (or gone): a later mismatch starts over.
            if s.outdated == false || s.status != .enabled {
                waiting = false
                notified = false
                attempted = false
            }
            return .none
        }
        // A newer (or not comparable) helper stays until the user replaces it in Settings → Helper.
        guard s.helperIsOlder, s.inApplicationsFolder, !s.updating, !attempted else {
            waiting = false
            return .none
        }
        if s.activeSessions > 0 {
            waiting = true
            let notify = !notified
            notified = true
            return .wait(notify: notify)
        }
        waiting = false
        attempted = true
        return .update
    }
}

/// Finds running PassTunnel sessions from the process list, so sessions of other users (the helper
/// is shared by everyone on the Mac) and sessions an older helper started are counted too.
public enum HelperSessions {
    public struct RunningProcess: Equatable, Sendable {
        public var pid: Int32
        public var parent: Int32
        /// Short name (`p_comm`, at most 16 bytes).
        public var name: String
        /// Executable path, nil when it cannot be read.
        public var path: String?

        public init(pid: Int32, parent: Int32, name: String, path: String?) {
            self.pid = pid
            self.parent = parent
            self.name = name
            self.path = path
        }
    }

    static let toolNames: Set<String> = Set(HelperCore.Tool.allCases.map(\.rawValue))

    /// The helper's staged tools (`ToolStager`: `<run root>/tools/<build>/Resources/bin/<tool>`), under the
    /// run root as written and with its links resolved (`proc_pidpath` reports `/private/var/run/…`).
    public static let stagedToolsRoots: [String] = {
        let root = PT.helperRunRoot
        let resolved = HelperCore.realPath(root) ?? (root.hasPrefix("/var/") ? "/private" + root : root)
        return Array(Set([root, resolved])).sorted().map { $0 + "/tools" }  // ToolStager.toolsDirName (macOS only)
    }()

    /// PIDs of VPN tools run for PassTunnel, of any user: children of a PassTunnel helper; the tools the
    /// helper runs from its staged copy (`stagedToolsRoots`), which only root can write; and the tools inside
    /// an app bundle (`<app>/Contents/Resources/bin/openvpn|openfortivpn|openconnect`) whose bundle identifier
    /// is PassTunnel's or that is gone from disk (replaced by an update). A restarted helper adopts tools that
    /// are no longer its children (their parent is launchd), hence the path checks: replacing the helper
    /// stops every tunnel it runs, so each of them must count.
    public static func toolPIDs(
        in processes: [RunningProcess],
        bundleIdentifier: (String) -> String? = Self.bundleIdentifier(ofApp:),
        exists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) },
        stagedToolsRoots: [String] = Self.stagedToolsRoots
    ) -> [Int32] {
        let helpers = Set(processes.filter(isHelper).map(\.pid))
        return processes.filter { p in
            if helpers.contains(p.parent), !isHelper(p) { return true }
            guard let path = p.path else { return false }
            if isStagedTool(path, roots: stagedToolsRoots) { return true }
            guard let app = appPath(ofTool: path) else { return false }
            guard let id = bundleIdentifier(app) else { return !exists(app) }
            return id == PT.bundleID
        }
        .map(\.pid)
    }

    /// `<root>/<build>/Resources/bin/<tool>` for one of `roots`: a build directory name as `ToolStager`
    /// makes it (16–64 lowercase hex digits) and one of the tools (not openconnect's hook).
    static func isStagedTool(_ path: String, roots: [String]) -> Bool {
        for root in roots where path.hasPrefix(root + "/") {
            let parts = path.dropFirst(root.count + 1).split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 4, parts[1] == "Resources", parts[2] == "bin", toolNames.contains(String(parts[3])),
                (16...64).contains(parts[0].utf8.count),
                parts[0].utf8.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) })
            else { continue }
            return true
        }
        return false
    }

    static func isHelper(_ p: RunningProcess) -> Bool {
        p.name == HelperBuild.executableName || p.path?.hasSuffix("/Contents/MacOS/\(HelperBuild.executableName)") == true
    }

    /// `/X.app` for `/X.app/Contents/Resources/bin/openvpn`, else nil.
    static func appPath(ofTool path: String) -> String? {
        let url = URL(fileURLWithPath: path)
        guard toolNames.contains(url.lastPathComponent) else { return nil }
        let bin = url.deletingLastPathComponent()
        let resources = bin.deletingLastPathComponent()
        let contents = resources.deletingLastPathComponent()
        let app = contents.deletingLastPathComponent()
        guard bin.lastPathComponent == "bin", resources.lastPathComponent == "Resources",
            contents.lastPathComponent == "Contents", app.pathExtension == "app"
        else { return nil }
        return app.path
    }

    public static func bundleIdentifier(ofApp path: String) -> String? {
        let plist = URL(fileURLWithPath: path).appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: plist),
            let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else { return nil }
        return dict["CFBundleIdentifier"] as? String
    }

    #if os(macOS)
    /// Number of PassTunnel VPN tools running on this Mac right now.
    public static func runningToolCount() -> Int {
        toolPIDs(in: currentProcesses()).count
    }

    /// Every process on the Mac (`sysctl KERN_PROC_ALL`, paths from `proc_pidpath`). macOS only, like
    /// the helper updates it serves (the Linux daemon comes with its package).
    public static func currentProcesses() -> [RunningProcess] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        size += size / 4  // processes started in between
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: size / MemoryLayout<kinfo_proc>.stride)
        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return [] }
        let count = size / MemoryLayout<kinfo_proc>.stride
        return procs.prefix(count).map { kp in
            let pid = kp.kp_proc.p_pid
            let name = withUnsafeBytes(of: kp.kp_proc.p_comm) { raw in
                String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
            }
            var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            let n = proc_pidpath(pid, &buf, UInt32(buf.count))
            return RunningProcess(pid: pid, parent: kp.kp_eproc.e_ppid, name: name, path: n > 0 ? String(cString: buf) : nil)
        }
    }
    #endif

    /// True when `appPath` (symlinks resolved) is inside `/Applications`. Not `~/Applications`: any
    /// process of the user can put a copy there.
    public static func isInApplicationsFolder(_ appPath: String) -> Bool {
        URL(fileURLWithPath: appPath).resolvingSymlinksInPath().standardizedFileURL.path.hasPrefix("/Applications/")
    }
}
