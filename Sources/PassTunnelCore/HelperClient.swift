import Foundation
import ServiceManagement
import PassTunnelShared

public enum HelperClientError: Error, Equatable, LocalizedError {
    case notInstalled
    case requiresApproval
    case notFound
    case unavailable(String)
    case timeout(TimeInterval)
    case versionMismatch(helper: Int, app: Int)
    case buildMismatch
    case badResponse

    /// The running helper is from another protocol version or build and must be updated.
    public var meansOutdatedHelper: Bool {
        switch self {
        case .versionMismatch, .buildMismatch: return true
        default: return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .notInstalled:
            return String(localized: "The PassTunnel helper is not installed. Install it from the app’s setup screen.")
        case .requiresApproval:
            return String(localized: "The PassTunnel helper needs your approval in System Settings → General → Login Items.")
        case .notFound:
            return String(localized: "The PassTunnel helper is missing from the app bundle. Reinstall PassTunnel.")
        case .unavailable(let reason):
            return String(localized: "Could not reach the PassTunnel helper: \(reason)")
        case .timeout(let s):
            return String(localized: "The PassTunnel helper did not answer within \(Int(s)) seconds.")
        case .versionMismatch(let helper, let app):
            return String(localized: "The PassTunnel helper belongs to another version of PassTunnel (version \(helper), expected \(app)). Update it in Settings → Helper.")
        case .buildMismatch:
            return String(localized: "The PassTunnel helper is from another build of PassTunnel. Update it in Settings → Helper.")
        case .badResponse:
            return String(localized: "The PassTunnel helper sent an invalid response.")
        }
    }
}

/// Async wrapper around the privileged helper's XPC service.
public final class HelperClient: @unchecked Sendable {
    public static let shared = HelperClient()

    public let machServiceName: String
    public let timeout: TimeInterval
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    public init(machServiceName: String = PT.helperLabel, timeout: TimeInterval = 15) {
        self.machServiceName = machServiceName
        self.timeout = timeout
    }

    deinit { connection?.invalidate() }

    /// Protocol version reported by the running helper.
    public func version() async throws -> Int {
        try await call(timeout: timeout) { proxy, done in
            proxy.version { done(.success($0)) }
        }
    }

    /// Build identity of the running helper (`HelperBuild`); protocol 3 and later.
    public func build() async throws -> String {
        try await call(timeout: timeout) { proxy, done in
            proxy.build { done(.success($0)) }
        }
    }

    /// Throws `.versionMismatch` unless the helper speaks `PT.helperProtocolVersion`, and
    /// `.buildMismatch` unless it is the helper shipped with this app (`HelperBuild.bundled`).
    public func ensureCompatible() async throws {
        let v = try await version()
        guard v == PT.helperProtocolVersion else { throw HelperClientError.versionMismatch(helper: v, app: PT.helperProtocolVersion) }
        guard let expected = HelperBuild.bundled else { return }
        guard HelperBuild.matches(helper: try await build(), expected: expected) else { throw HelperClientError.buildMismatch }
    }

    /// True when the running helper must be replaced (other protocol or other build).
    public func isOutdated() async throws -> Bool {
        do {
            try await ensureCompatible()
            return false
        } catch let e as HelperClientError where e.meansOutdatedHelper {
            return true
        }
    }

    /// Sends a request. A response with `ok == false` is returned, not thrown; transport problems throw.
    /// `stop` can take up to ~6 s while the tool shuts down.
    public func perform(_ request: HelperRequest, timeout: TimeInterval? = nil) async throws -> HelperResponse {
        let payload = try request.jsonData()
        let data: Data = try await call(timeout: timeout ?? self.timeout) { proxy, done in
            proxy.perform(payload) { done(.success($0)) }
        }
        guard let response = try? HelperResponse(jsonData: data) else { throw HelperClientError.badResponse }
        return response
    }

    public func invalidate() {
        lock.lock()
        let c = connection
        connection = nil
        lock.unlock()
        c?.invalidate()
    }

    // MARK: - Internals

    private func currentConnection() -> NSXPCConnection {
        lock.lock()
        defer { lock.unlock() }
        if let connection { return connection }
        let c = NSXPCConnection(machServiceName: machServiceName, options: .privileged)
        c.remoteObjectInterface = NSXPCInterface(with: PassTunnelHelperProtocol.self)
        c.invalidationHandler = { [weak self, weak c] in
            guard let self else { return }
            self.lock.lock()
            if self.connection === c { self.connection = nil }
            self.lock.unlock()
        }
        c.resume()
        connection = c
        return c
    }

    private func call<T>(timeout: TimeInterval,
                         _ body: @escaping (PassTunnelHelperProtocol, @escaping (Result<T, Error>) -> Void) -> Void)
        async throws -> T {
        let conn = currentConnection()
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, Error>) in
            let once = ResumeOnce(cont)
            let proxy = conn.remoteObjectProxyWithErrorHandler { [weak self] error in
                once.resume(.failure(self?.translate(error) ?? error))
            }
            guard let helper = proxy as? PassTunnelHelperProtocol else {
                once.resume(.failure(HelperClientError.badResponse))
                return
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                once.resume(.failure(HelperClientError.timeout(timeout)))
            }
            body(helper) { once.resume($0) }
        }
    }

    /// XPC only says "connection invalid"; ask ServiceManagement why.
    private func translate(_ error: Error) -> Error {
        let ns = error as NSError
        guard ns.domain == NSCocoaErrorDomain,
              ns.code == NSXPCConnectionInvalid || ns.code == NSXPCConnectionInterrupted else {
            return HelperClientError.unavailable(ns.localizedDescription)
        }
        if ns.code == NSXPCConnectionInvalid { invalidate() }
        switch HelperInstaller.status {
        case .notRegistered: return HelperClientError.notInstalled
        case .requiresApproval: return HelperClientError.requiresApproval
        case .notFound: return HelperClientError.notFound
        case .enabled:
            return HelperClientError.unavailable(ns.code == NSXPCConnectionInterrupted
                ? String(localized: "the connection was interrupted")
                : String(localized: "the connection was refused (is this a properly signed build?)"))
        }
    }
}

private final class ResumeOnce<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var cont: CheckedContinuation<T, Error>?

    init(_ cont: CheckedContinuation<T, Error>) { self.cont = cont }

    func resume(_ result: Result<T, Error>) {
        lock.lock()
        let c = cont
        cont = nil
        lock.unlock()
        c?.resume(with: result)
    }
}

// MARK: - Installation

public enum HelperStatus: String, Sendable {
    case notRegistered, enabled, requiresApproval, notFound
}

/// Registers the helper daemon with launchd via SMAppService. The user approves it once in
/// System Settings → General → Login Items.
public enum HelperInstaller {
    public static var service: SMAppService { SMAppService.daemon(plistName: PT.helperPlistName) }

    public static var status: HelperStatus {
        switch service.status {
        case .notRegistered: return .notRegistered
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .notFound
        @unknown default: return .notFound
        }
    }

    /// Registers the daemon. Afterwards the status is usually `.requiresApproval`.
    public static func register() throws {
        do {
            try service.register()
        } catch let error as NSError where error.code == kSMErrorAlreadyRegistered {
            return
        }
    }

    public static func unregister() async throws {
        try await service.unregister()
        HelperClient.shared.invalidate()
    }

    public static func openSystemSettingsLoginItems() {
        SMAppService.openSystemSettingsLoginItems()
    }
}

/// Helper install / removal requested by the CLI but carried out by the app: SMAppService refuses
/// (or misattributes) registrations from a process started in Terminal, so `passtunnel helper
/// install|uninstall` opens the app with `argument`, or, when it already runs, posts `notification`
/// with the raw value as the object. The app then shows Settings → Helper and starts the action
/// there (removal still asks for confirmation).
public enum HelperHandoff: String, CaseIterable, Sendable {
    case install, uninstall

    public static let notification = Notification.Name("com.furkanprlk.passtunnel.helperHandoff")

    /// Launch argument, e.g. `--install-helper` (not a CLI command, so the binary starts as the app).
    public var argument: String { "--\(rawValue)-helper" }

    public static func from(arguments: [String]) -> HelperHandoff? {
        allCases.first { arguments.dropFirst().contains($0.argument) }
    }
}
