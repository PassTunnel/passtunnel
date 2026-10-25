import Foundation
#if canImport(Network)
import Network
#endif

/// Whether this computer is online and over what kind of interface, as the system sees its own network
/// path. Nothing is contacted to find out: no probe, no lookup (the privacy page promises it). On Apple
/// platforms from `NWPathMonitor`; on Linux from the routes and the links' state (`NetworkPath.linuxStatus`).
public struct NetworkStatus: Codable, Equatable, Sendable {
    public enum Interface: String, Codable, CaseIterable, Sendable {
        case wifi, ethernet, cellular, other
    }

    /// nil: not known (not read yet, or the system does not say).
    public var online: Bool?
    /// The kind of interface the path goes through; nil when offline or not known.
    public var interface: Interface?

    public init(online: Bool?, interface: Interface? = nil) {
        self.online = online
        self.interface = online == true ? interface : nil
    }

    public static let unknown = NetworkStatus(online: nil)

    /// "Online · Wi-Fi", "Offline", "Unknown".
    public var summary: String {
        switch online {
        case true?:
            guard let interface else { return String(localized: "Online") }
            return String(localized: "Online") + " · " + interface.name
        case false?: return String(localized: "Offline")
        case nil: return String(localized: "Unknown")
        }
    }
}

extension NetworkStatus.Interface {
    public var name: String {
        switch self {
        case .wifi: return String(localized: "Wi-Fi")
        case .ethernet: return String(localized: "Ethernet")
        case .cellular: return String(localized: "Cellular")
        case .other: return String(localized: "Other network")
        }
    }
}

/// Watches the network path; `NetworkPath` in the app, a fake in tests.
@MainActor
public protocol NetworkPathWatching: AnyObject {
    /// The last status seen; `.unknown` before the first one.
    var status: NetworkStatus { get }
    /// Starts watching: `onChange` gets every status that differs from the one before.
    func start(_ onChange: @escaping @MainActor (NetworkStatus) -> Void)
    func stop()
}

/// The system's view of the network path: `NWPathMonitor` where the Network framework exists, else (Linux)
/// the links and routes, read again every `pollInterval`.
@MainActor
public final class NetworkPath: NetworkPathWatching {
    public private(set) var status = NetworkStatus.unknown
    private var onChange: (@MainActor (NetworkStatus) -> Void)?
    #if canImport(Network)
    private var monitor: NWPathMonitor?
    #else
    private var poll: Task<Void, Never>?
    nonisolated static let pollInterval: TimeInterval = 5
    #endif

    public init() {}

    public func start(_ onChange: @escaping @MainActor (NetworkStatus) -> Void) {
        stop()
        self.onChange = onChange
        #if canImport(Network)
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            let status = Self.status(of: path)
            MainActor.assumeIsolated { self?.update(status) }
        }
        monitor.start(queue: .main)
        self.monitor = monitor
        #else
        poll = Task { [weak self] in
            while !Task.isCancelled {
                let status = await Self.read()
                self?.update(status)
                try? await Task.sleep(nanoseconds: UInt64(Self.pollInterval * 1_000_000_000))
            }
        }
        #endif
    }

    public func stop() {
        onChange = nil
        #if canImport(Network)
        monitor?.cancel()
        monitor = nil
        #else
        poll?.cancel()
        poll = nil
        #endif
    }

    private func update(_ new: NetworkStatus) {
        guard new != status else { return }
        status = new
        onChange?(new)
    }

    /// The status now, for a process that does not watch (`diagnose`): the first answer of a monitor, or
    /// `.unknown` when none comes within `timeout` seconds.
    public static func current(timeout: TimeInterval = 1) async -> NetworkStatus {
        #if canImport(Network)
        let monitor = NWPathMonitor()
        defer { monitor.cancel() }
        let queue = DispatchQueue(label: "com.furkanprlk.passtunnel.network-path")
        return await withCheckedContinuation { (cont: CheckedContinuation<NetworkStatus, Never>) in
            let once = Once(cont)
            monitor.pathUpdateHandler = { path in once.resume(Self.status(of: path)) }
            monitor.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { once.resume(.unknown) }
        }
        #else
        return await read()
        #endif
    }

    #if canImport(Network)
    /// Resumes a continuation once; later calls do nothing.
    private final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var cont: CheckedContinuation<NetworkStatus, Never>?

        init(_ cont: CheckedContinuation<NetworkStatus, Never>) { self.cont = cont }

        func resume(_ status: NetworkStatus) {
            lock.lock()
            let c = cont
            cont = nil
            lock.unlock()
            c?.resume(returning: status)
        }
    }

    nonisolated static func status(of path: NWPath) -> NetworkStatus {
        status(satisfied: path.status == .satisfied) { interface in
            switch interface {
            case .wifi: return path.usesInterfaceType(.wifi)
            case .ethernet: return path.usesInterfaceType(.wiredEthernet)
            case .cellular: return path.usesInterfaceType(.cellular)
            case .other: return path.usesInterfaceType(.other)
            }
        }
    }
    #endif

    /// A satisfied path is online; its interface is the first kind it uses, in the order of
    /// `NetworkStatus.Interface` (a VPN's tunnel is `other`, so Wi-Fi under a VPN still reads Wi-Fi).
    nonisolated static func status(satisfied: Bool, uses: (NetworkStatus.Interface) -> Bool) -> NetworkStatus {
        guard satisfied else { return NetworkStatus(online: false) }
        return NetworkStatus(online: true, interface: NetworkStatus.Interface.allCases.first(where: uses) ?? .other)
    }

    // MARK: Linux

    /// Linux: online when a route that carries all traffic (`RoutingTable.trafficRoutes`, rtnetlink) goes
    /// through a link that is up (`operstate` "up", or "unknown", which tun devices and some drivers
    /// report). The interface is that of the first such link that is not a tunnel: Wi-Fi when it is
    /// wireless, Ethernet for ARPHRD_ETHER (1), else other.
    nonisolated static func linuxStatus(routes: [RoutingTable.Route], operstate: (String) -> String?,
                                        isWireless: (String) -> Bool, linkType: (String) -> Int?) -> NetworkStatus {
        var seen = Set<String>()
        let up = routes.filter { $0.capturesAllTraffic && !$0.scoped && $0.interface != "lo" && !$0.interface.isEmpty }
            .filter { seen.insert($0.interface).inserted }
            .filter { ["up", "unknown"].contains(operstate($0.interface) ?? "") }
        guard !up.isEmpty else { return NetworkStatus(online: false) }
        guard let link = up.first(where: { !$0.tunnelDevice && !FullTunnelCheck.isVPNInterface($0.interface) }) else {
            return NetworkStatus(online: true, interface: .other)
        }
        if isWireless(link.interface) { return NetworkStatus(online: true, interface: .wifi) }
        return NetworkStatus(online: true, interface: linkType(link.interface) == 1 ? .ethernet : .other)
    }

    #if !canImport(Network)
    /// The routes over rtnetlink, the links' state from /sys/class/net; off the main actor.
    nonisolated static func read() async -> NetworkStatus {
        await Task.detached {
            #if os(Linux)
            let sys = "/sys/class/net/"
            func text(_ path: String) -> String? {
                (try? String(contentsOfFile: path, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            // A name from the kernel's own link list, never a path component someone else chose.
            func safe(_ name: String) -> Bool { !name.isEmpty && !name.contains("/") && name != "." && name != ".." }
            let files = FileManager.default
            return NetworkPath.linuxStatus(
                routes: RoutingTable.trafficRoutes(),
                operstate: { link in safe(link) ? text(sys + link + "/operstate") : nil },
                isWireless: { link in
                    safe(link) && (files.fileExists(atPath: sys + link + "/wireless") || files.fileExists(atPath: sys + link + "/phy80211"))
                },
                linkType: { link in safe(link) ? text(sys + link + "/type").flatMap { Int($0) } : nil })
            #else
            return NetworkStatus.unknown
            #endif
        }.value
    }
    #endif
}
