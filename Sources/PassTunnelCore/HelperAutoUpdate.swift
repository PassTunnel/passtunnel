import Darwin
import Foundation
import PassTunnelShared

/// Decides when the app replaces an outdated helper on its own, e.g. right after the app itself was
/// updated (the helper still runs the build it was started from). Updating unregisters the helper,
/// which stops every tunnel it runs, so it only happens while no PassTunnel session is active;
/// otherwise the app keeps showing "Needs an update" and updates as soon as the last session ends.
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
        /// Active PassTunnel sessions on this Mac, from any user or process (see `HelperSessions`).
        public var activeSessions: Int
        /// An update (automatic or from Settings → Helper) is running.
        public var updating: Bool
        /// The app runs from an Applications folder. A copy elsewhere (a test build, a mounted disk
        /// image) never takes over the helper on its own.
        public var inApplicationsFolder: Bool

        public init(status: HelperStatus, outdated: Bool?, activeSessions: Int, updating: Bool,
                    inApplicationsFolder: Bool) {
            self.status = status
            self.outdated = outdated
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
        guard s.inApplicationsFolder, !s.updating, !attempted else { return .none }
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

    static let toolNames: Set<String> = ["openvpn", "openfortivpn"]

    /// PIDs of VPN tools run for PassTunnel: children of a PassTunnel helper, and the tools inside an
    /// app bundle (`<app>/Contents/Resources/bin/openvpn|openfortivpn`) whose bundle identifier is
    /// PassTunnel's or that is gone from disk (replaced by an update). A restarted helper adopts
    /// tools that are no longer its children, hence the path check.
    public static func toolPIDs(in processes: [RunningProcess],
                                bundleIdentifier: (String) -> String? = Self.bundleIdentifier(ofApp:),
                                exists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }) -> [Int32] {
        let helpers = Set(processes.filter(isHelper).map(\.pid))
        return processes.filter { p in
            if helpers.contains(p.parent), !isHelper(p) { return true }
            guard let path = p.path, let app = appPath(ofTool: path) else { return false }
            guard let id = bundleIdentifier(app) else { return !exists(app) }
            return id == PT.bundleID
        }
        .map(\.pid)
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
              contents.lastPathComponent == "Contents", app.pathExtension == "app" else { return nil }
        return app.path
    }

    public static func bundleIdentifier(ofApp path: String) -> String? {
        let plist = URL(fileURLWithPath: path).appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: plist),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else { return nil }
        return dict["CFBundleIdentifier"] as? String
    }

    /// Number of PassTunnel VPN tools running on this Mac right now.
    public static func runningToolCount() -> Int {
        toolPIDs(in: currentProcesses()).count
    }

    /// Every process on the Mac (`sysctl KERN_PROC_ALL`, paths from `proc_pidpath`).
    public static func currentProcesses() -> [RunningProcess] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        size += size / 4   // processes started in between
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

    /// True when `appPath` is inside `/Applications` or `~/Applications`.
    public static func isInApplicationsFolder(_ appPath: String, home: String = NSHomeDirectory()) -> Bool {
        let path = URL(fileURLWithPath: appPath).standardizedFileURL.path
        return ["/Applications/", home + "/Applications/"].contains { path.hasPrefix($0) }
    }
}
