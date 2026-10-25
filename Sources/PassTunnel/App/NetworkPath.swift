import Foundation
import Network

/// Whether this Mac is online, from `NWPathMonitor`: the system's own view of its network path. Nothing is
/// contacted to find out.
@MainActor
final class NetworkPath {
    private let monitor = NWPathMonitor()
    private(set) var isSatisfied = false

    func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            MainActor.assumeIsolated { self?.isSatisfied = path.status == .satisfied }
        }
        monitor.start(queue: .main)
    }

    func stop() {
        monitor.cancel()
    }
}
