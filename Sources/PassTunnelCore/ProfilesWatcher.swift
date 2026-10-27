import Foundation

#if os(macOS)
import CoreServices
#endif

#if os(macOS)
/// Watches the support directory (profiles and `config.json`) with FSEvents and calls `onChange`
/// on the main queue, debounced, when something another process (the CLI) or this one wrote may
/// have changed what is stored. Noise the VPN tools produce while connected (`vpn.log`, the
/// management socket, markers, the last-used code window, the activity log, the network claims, the retries of an
/// unreachable server, temp files of atomic writes) is ignored. The app's own writes also
/// trigger a call; a reload that finds nothing new must therefore be cheap and harmless.
public final class ProfilesWatcher {
    public let paths: AppPaths
    private let latency: TimeInterval
    private let debounce: TimeInterval
    private let onChange: () -> Void
    private var stream: FSEventStreamRef?
    private let queue = DispatchQueue(label: "com.furkanprlk.passtunnel.profiles-watcher")
    private var pending: DispatchWorkItem?  // main queue only

    public init(
        paths: AppPaths = .default, latency: TimeInterval = 0.3, debounce: TimeInterval = 0.25,
        onChange: @escaping () -> Void
    ) {
        self.paths = paths
        self.latency = latency
        self.debounce = debounce
        self.onChange = onChange
    }

    deinit { stop() }

    public var isRunning: Bool { stream != nil }

    /// Starts watching (creating the support directories if needed). Returns false if FSEvents
    /// could not be started; callers keep their other refresh triggers either way.
    @discardableResult
    public func start() -> Bool {
        guard stream == nil else { return true }
        try? paths.ensureDirectories()
        let sink = EventSink { [weak self] events in self?.received(events) }
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(sink).toOpaque(),
            retain: { info in
                guard let info else { return nil }
                _ = Unmanaged<EventSink>.fromOpaque(info).retain()
                return UnsafeRawPointer(info)
            },
            release: { info in
                guard let info else { return }
                Unmanaged<EventSink>.fromOpaque(info).release()
            },
            copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, rawPaths, rawFlags, _ in
            guard let info else { return }
            let sink = Unmanaged<EventSink>.fromOpaque(info).takeUnretainedValue()
            let list = unsafeBitCast(rawPaths, to: NSArray.self)
            var events: [(String, FSEventStreamEventFlags)] = []
            for i in 0..<count {
                events.append(((list[i] as? String) ?? "", rawFlags[i]))
            }
            sink.handler(events)
        }
        let flags = FSEventStreamCreateFlags(
            kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes
                | kFSEventStreamCreateFlagWatchRoot)
        guard
            let s = FSEventStreamCreate(
                kCFAllocatorDefault, callback, &context,
                [paths.root.path] as CFArray,
                FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
                latency, flags)
        else { return false }
        FSEventStreamSetDispatchQueue(s, queue)
        guard FSEventStreamStart(s) else {
            FSEventStreamInvalidate(s)
            FSEventStreamRelease(s)
            return false
        }
        stream = s
        return true
    }

    public func stop() {
        guard let s = stream else { return }
        stream = nil
        FSEventStreamStop(s)
        FSEventStreamInvalidate(s)
        FSEventStreamRelease(s)
        pending?.cancel()
        pending = nil
    }

    private func received(_ events: [(String, FSEventStreamEventFlags)]) {
        guard events.contains(where: { Self.isRelevant(path: $0.0, flags: $0.1) }) else { return }
        DispatchQueue.main.async { [weak self] in self?.schedule() }
    }

    private func schedule() {
        guard stream != nil else { return }
        pending?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.stream != nil else { return }
            self.pending = nil
            self.onChange()
        }
        pending = work
        DispatchQueue.main.asyncAfter(deadline: .now() + debounce, execute: work)
    }

    /// Files that change while a VPN runs or that only exist mid-write; they never change a profile.
    static let ignoredNames: Set<String> = [
        "vpn.log", "mgmt.sock", ".lock", ".DS_Store", ".user-stopped", ".last-otp",
        ".mgmt-state", "activity.jsonl", ".activity.lock", "clock.json", ProfileNetwork.fileName,
        ".retry"
    ]

    /// Whether an event can mean a changed profile, config or preference.
    public static func isRelevant(path: String, flags: FSEventStreamEventFlags = 0) -> Bool {
        let rescan = FSEventStreamEventFlags(
            kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagRootChanged
                | kFSEventStreamEventFlagUserDropped | kFSEventStreamEventFlagKernelDropped)
        if flags & rescan != 0 { return true }
        let name = (path as NSString).lastPathComponent
        if ignoredNames.contains(name) { return false }
        // Temp files of atomic writes: ".profile.json.<uuid>.tmp" (the rename reports the real name too).
        if name.hasPrefix(".") && name.hasSuffix(".tmp") { return false }
        return true
    }
}

private final class EventSink {
    let handler: ([(String, FSEventStreamEventFlags)]) -> Void
    init(_ handler: @escaping ([(String, FSEventStreamEventFlags)]) -> Void) { self.handler = handler }
}
#endif

/// Tells a running app that the CLI changed something the file watcher cannot see (Keychain items),
/// or simply that it changed profiles, so the app reloads right away. Any process in the session
/// can post it; receivers only re-read their own storage, so it carries no data. Nothing to tell on
/// Linux, which has no app yet.
public enum ProfileChangeSignal {
    public static let name = Notification.Name("com.furkanprlk.passtunnel.profilesChanged")

    public static func post() {
        #if os(macOS)
        DistributedNotificationCenter.default().postNotificationName(
            name, object: nil, userInfo: nil,
            deliverImmediately: true)
        #endif
    }
}
