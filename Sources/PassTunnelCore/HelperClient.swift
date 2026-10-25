import Foundation
#if os(macOS)
import ServiceManagement
#endif
import PassTunnelKit
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
            #if os(macOS)
            return String(localized: "The PassTunnel helper is not installed. Install it from the app’s setup screen.")
            #else
            return String(localized: "The PassTunnel daemon (passtunneld) is not installed. Connecting needs it.")
            #endif
        case .requiresApproval:
            return String(localized: "The PassTunnel helper needs your approval in System Settings → General → Login Items.")
        case .notFound:
            return String(localized: "The PassTunnel helper is missing from the app bundle. Reinstall PassTunnel.")
        case .unavailable(let reason):
            #if os(macOS)
            return String(localized: "Could not reach the PassTunnel helper: \(reason)")
            #else
            return String(localized: "Could not reach the PassTunnel daemon (passtunneld): \(reason)")
            #endif
        case .timeout(let s):
            return String(localized: "The PassTunnel helper did not answer within \(Int(s)) seconds.")
        case .versionMismatch(let helper, let app):
            #if os(macOS)
            return String(localized: "The PassTunnel helper belongs to another version of PassTunnel (version \(helper), expected \(app)). Update it in Settings → Helper.")
            #else
            return String(localized: "The PassTunnel daemon (passtunneld) belongs to another version of PassTunnel (version \(helper), expected \(app)). Install the same version of both, then restart the daemon (systemctl restart passtunnel).")
            #endif
        case .buildMismatch:
            #if os(macOS)
            return String(localized: "The PassTunnel helper is from another build of PassTunnel. Update it in Settings → Helper.")
            #else
            return String(localized: "The running PassTunnel daemon (passtunneld) is not the one installed with this passtunnel. Restart it (systemctl restart passtunnel).")
            #endif
        case .badResponse:
            return String(localized: "The PassTunnel helper sent an invalid response.")
        }
    }
}

#if os(Linux)
/// The client of passtunneld, the Linux daemon (docs/LINUX.md, "The daemon protocol"): one
/// connection to its unix socket per call, one JSON line each way.
public final class UnixSocketHelperClient: HelperClienting, @unchecked Sendable {
    public static let shared = UnixSocketHelperClient()

    public let socketPath: String
    public let timeout: TimeInterval
    private let expected: () -> String?

    /// Replies are a few hundred bytes; anything this long is not one.
    static let maxReplyBytes = 1 << 20

    /// `expectedBuild` is only worked out when a build is compared (it hashes the installed daemon).
    public init(socketPath: String = PT.daemonSocketPath(), timeout: TimeInterval = 15,
                expectedBuild: @autoclosure @escaping () -> String? = HelperBuild.installedDaemon) {
        self.socketPath = socketPath
        self.timeout = timeout
        self.expected = expectedBuild
    }

    /// The build the daemon must report (`HelperBuild.installedDaemon`); nil: builds are not compared.
    public var expectedBuild: String? { expected() }

    /// The daemon's socket exists (systemd's, or the daemon's own): it is installed.
    public var isInstalled: Bool {
        var st = stat()
        return lstat(socketPath, &st) == 0 && (st.st_mode & S_IFMT) == S_IFSOCK
    }

    /// The daemon's protocol and build.
    public func hello(timeout: TimeInterval? = nil) async throws -> DaemonHello {
        let data = try await exchange(DaemonProtocol.helloLine, timeout: timeout ?? self.timeout)
        guard let hello = try? DaemonHello(jsonData: data) else { throw HelperClientError.badResponse }
        return hello
    }

    /// Throws `.versionMismatch` unless the daemon speaks `PT.helperProtocolVersion`, and
    /// `.buildMismatch` unless it runs the binary installed with this `passtunnel` (`expectedBuild`).
    public func ensureCompatible() async throws {
        let hello = try await hello()
        guard hello.protocolVersion == PT.helperProtocolVersion else {
            throw HelperClientError.versionMismatch(helper: hello.protocolVersion, app: PT.helperProtocolVersion)
        }
        guard HelperBuild.matches(helper: hello.build, expected: expectedBuild) else { throw HelperClientError.buildMismatch }
    }

    /// True when the running daemon is another protocol or build than the installed one.
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
        let data = try await exchange(try DaemonProtocol.performLine(request), timeout: timeout ?? self.timeout)
        guard let response = try? HelperResponse(jsonData: data) else { throw HelperClientError.badResponse }
        return response
    }

    private func exchange(_ line: Data, timeout: TimeInterval) async throws -> Data {
        let path = socketPath
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            DispatchQueue.global(qos: .userInitiated).async {
                cont.resume(with: Result { try Self.exchange(path: path, line: line, timeout: timeout) })
            }
        }
    }

    /// Connects, sends `line` and reads the reply line (without its newline), all within `timeout`.
    static func exchange(path: String, line: Data, timeout: TimeInterval) throws -> Data {
        guard var address = POSIXSocket.unixAddress(path) else {
            throw HelperClientError.unavailable(String(cString: strerror(ENAMETOOLONG)))
        }
        let deadline = Date().addingTimeInterval(timeout)
        let fd = socket(AF_UNIX, POSIXSocket.stream, 0)
        guard fd >= 0 else { throw HelperClientError.unavailable(String(cString: strerror(errno))) }
        defer { POSIXSocket.close(fd) }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        POSIXSocket.noSigPipe(fd)
        setTimeout(fd, until: deadline)
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                POSIXSocket.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if connected != 0 {
            let e = errno
            switch e {
            case ENOENT: throw HelperClientError.notInstalled
            case EAGAIN, EWOULDBLOCK, ETIMEDOUT, EINPROGRESS: throw HelperClientError.timeout(timeout)
            default: throw HelperClientError.unavailable(String(cString: strerror(e)))
            }
        }
        var offset = 0
        try line.withUnsafeBytes { bytes in
            while offset < bytes.count {
                setTimeout(fd, until: deadline)
                let n = POSIXSocket.write(fd, bytes.baseAddress! + offset, bytes.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK { throw HelperClientError.timeout(timeout) }
                    throw HelperClientError.unavailable(String(cString: strerror(errno)))
                }
                offset += n
            }
        }
        var reply = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            guard deadline.timeIntervalSinceNow > 0 else { throw HelperClientError.timeout(timeout) }
            setTimeout(fd, until: deadline)
            let n = read(fd, &buffer, buffer.count)
            if n < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { throw HelperClientError.timeout(timeout) }
                throw HelperClientError.unavailable(String(cString: strerror(errno)))
            }
            if n == 0 { break }
            if let newline = buffer[0..<n].firstIndex(of: 0x0A) {
                reply.append(contentsOf: buffer[0..<newline])
                return reply
            }
            reply.append(contentsOf: buffer[0..<n])
            guard reply.count <= maxReplyBytes else { throw HelperClientError.badResponse }
        }
        guard !reply.isEmpty else { throw HelperClientError.unavailable(String(cString: strerror(ECONNRESET))) }
        return reply
    }

    /// Send and receive time out at `deadline` (at least a millisecond from now).
    private static func setTimeout(_ fd: Int32, until deadline: Date) {
        let remaining = max(0.001, deadline.timeIntervalSinceNow)
        var tv = timeval(tv_sec: time_t(remaining), tv_usec: suseconds_t((remaining - Double(Int(remaining))) * 1_000_000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }
}
#endif

#if os(macOS)
/// Async wrapper around the privileged helper's XPC service.
public final class HelperClient: @unchecked Sendable {
    public static let shared = HelperClient()

    /// `PT.helperLabel`. Debug builds take `$PASSTUNNEL_HELPER_SERVICE` instead when set, so a test run
    /// of the CLI or the MCP server can be pointed away from the installed helper.
    public static var defaultMachServiceName: String {
        #if DEBUG
        if let name = Env.string("PASSTUNNEL_HELPER_SERVICE") { return name }
        #endif
        return PT.helperLabel
    }

    public let machServiceName: String
    public let timeout: TimeInterval
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    public init(machServiceName: String = HelperClient.defaultMachServiceName, timeout: TimeInterval = 15) {
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

    /// How the running helper relates to the one shipped with this app (`HelperBuild.relation`): whether
    /// replacing it would be an upgrade or a downgrade. A helper that does not report its build number
    /// (`HelperResponse.helperBuild`) predates it and counts as older.
    public func relation() async throws -> HelperBuild.Relation {
        let v = try await version()
        guard v == PT.helperProtocolVersion, let expected = HelperBuild.bundled else {
            return HelperBuild.relation(helperProtocol: v, helperDigest: nil, helperNumber: nil,
                                        appDigest: HelperBuild.bundled, appNumber: HelperBuild.bundledNumber)
        }
        let digest = try await build()
        if HelperBuild.matches(helper: digest, expected: expected) { return .current }
        let number = try await perform(.status).helperBuild
        return HelperBuild.relation(helperProtocol: v, helperDigest: digest, helperNumber: number,
                                    appDigest: expected, appNumber: HelperBuild.bundledNumber)
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
#endif
