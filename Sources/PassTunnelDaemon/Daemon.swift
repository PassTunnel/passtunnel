import Foundation
import PassTunnelShared

/// passtunneld, the Linux root daemon (docs/LINUX.md): the Mac's helper behind a unix socket. It
/// listens on `<runRoot>/daemon.sock` (systemd's socket, or one of its own), serves one request per
/// connection on a thread of its own, and runs the VPN tools through `Supervisor`.
public final class Daemon {
    public struct Options {
        public var runRoot = PT.helperRunRoot
        public var users = UserDatabase.system
        public var tools: ToolResolving = SystemTools()
        /// The daemon's own executable, which must be a `TrustedPath` (part of trusting the DNS hook it
        /// will serve as). Nil only in tests.
        public var ownExecutable: String? = "/proc/self/exe"
        /// What OpenVPN runs as its DNS hook, and openconnect as its `vpn-hook`: the real path of
        /// `ownExecutable` unless set (tests); none without either (and no Cisco AnyConnect).
        public var dnsHook: String?
        /// Where DNS is changed and reverted (`DNSApplier`); a fake root in tests.
        public var dns = DNSSystem()
        /// The network interfaces, as the checks of a FortiGate session's ppp interface and of an OpenVPN
        /// profile's device name see them.
        public var interfaces = InterfaceSystem()
        /// How long a FortiGate DNS set-up waits, once the tunnel is up, for what openfortivpn did not
        /// report yet.
        public var reportWait: TimeInterval = 10
        /// `hello`'s `build`: hex SHA-256 of the executable (`HelperBuild.digest`).
        public var build = "unknown"
        /// `hello`'s `build_number` and every reply's `helper_build`; none in development builds.
        public var buildNumber: Int?
        /// How long a client has to send its line, and to take the reply.
        public var readTimeout: TimeInterval = 5
        public var writeTimeout: TimeInterval = 5
        /// Connections served at once, in all and per user; more are turned away at once.
        public var maxConnections = 64
        public var maxConnectionsPerUser = 8
        public var stopGrace: TimeInterval = 5
        /// How long a DNS change waits for the run root's lock, and how often DNS (or an openconnect
        /// session's network) that could not be restored yet is tried again.
        public var dnsLockTimeout: TimeInterval = 10
        public var dnsRetryInterval: TimeInterval = 15
        /// What an openconnect session's network is set up and restored with: `LinuxOpenConnectSystem` for the
        /// session's directory; a fake in tests.
        public var openConnectSystem: ((SessionDirectory, DNSApplier) -> OpenConnectSystem)?
        /// How openconnect sessions are followed (the record's interval, the set-up and reconnect deadlines).
        var openConnectTiming = OpenConnectTiming()
        /// Who is on the other end of an accepted connection (`SO_PEERCRED`); replaced in tests.
        public var peer: (Int32) -> Caller? = Caller.of(socket:)

        public init() {}
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case untrustedExecutable(String, String)
        case alreadyRunning(String)
        case socket(String, Int32)
        case notASocket(String)

        public var description: String {
            switch self {
            case .untrustedExecutable(let path, let reason):
                return "Refusing to run from \(path): \(reason) The daemon must be installed where only root can change it."
            case .alreadyRunning(let lock): return "Another passtunneld is running (\(lock) is locked)."
            case .socket(let what, let err): return "\(what): \(String(cString: strerror(err)))"
            case .notASocket(let path): return "Refusing to replace \(path): it is not a socket."
            }
        }
    }

    static let lockName = "daemon.lock"

    public let options: Options
    let supervisor: Supervisor
    private let lockFD: Int32
    private let lock = NSLock()
    private var connections: [uid_t: Int] = [:]
    private var listener: Int32 = -1
    private var ownsSocket = false
    private var wakeFDs: [Int32] = [-1, -1]
    private var stopped = false

    public var socketPath: String { PT.daemonSocketPath(runRoot: options.runRoot) }

    /// Checks the executable, takes the run root (root-owned, 0711) and its lock, and stops whatever
    /// an earlier instance left running, reverting the DNS it set up.
    public init(options: Options) throws {
        var hook = options.dnsHook
        if let own = options.ownExecutable {
            guard let real = HelperCore.realPath(own) else {
                throw Failure.untrustedExecutable(own, "its path cannot be resolved.")
            }
            do { try TrustedPath.check(real) } catch { throw Failure.untrustedExecutable(real, String(describing: error)) }
            hook = hook ?? real
        }
        try HelperCore.ensureRootOwnedDir(options.runRoot)
        let lockPath = options.runRoot + "/" + Self.lockName
        let fd = open(lockPath, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure.socket("open \(lockPath)", errno) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            throw Failure.alreadyRunning(lockPath)
        }
        lockFD = fd
        self.options = options
        var dns = DNSApplier(system: options.dns, runRoot: options.runRoot)
        dns.lockTimeout = options.dnsLockTimeout
        let applier = dns
        let makeSystem = options.openConnectSystem ?? { session, dns in LinuxOpenConnectSystem(session: session, dns: dns) }
        let restorer = SessionRestore(
            runRoot: options.runRoot, dns: dns, openConnect: { makeSystem($0, applier) }, hookExecutable: hook)
        // The network lock stays: a hook of an earlier instance's openconnect may still hold it.
        let previous = PreviousInstance.cleanUp(
            runRoot: options.runRoot, keep: [PT.daemonSocketName, Self.lockName, OpenConnectLock.fileName],
            grace: options.stopGrace, restore: restorer)
        var core = HelperCore(
            runRoot: options.runRoot, dnsUpdownSource: nil,
            homeDirectory: options.users.home, userName: options.users.name)
        core.dnsHook = hook
        core.interfaceExists = options.interfaces.exists
        supervisor = Supervisor(
            core: core, tools: options.tools, dns: dns, restorer: restorer, interfaces: options.interfaces,
            reportWait: options.reportWait, stopGrace: options.stopGrace,
            pending: previous.pending, retryInterval: options.dnsRetryInterval, openConnectTiming: options.openConnectTiming)
    }

    deinit {
        if listener >= 0 { close(listener) }
        wakeFDs.filter { $0 >= 0 }.forEach { close($0) }
        close(lockFD)
    }

    // MARK: - Listening

    /// The socket systemd passed (`LISTEN_PID` is this process, `LISTEN_FDS` ≥ 1: descriptor 3), else
    /// a new one at `socketPath` (mode 0666; who may do what is decided per request).
    public func listen(environment: [String: String] = ProcessInfo.processInfo.environment) throws {
        if let fd = Self.activationSocket(environment: environment) {
            listener = fd
            ownsSocket = false
            unsetenv("LISTEN_PID")
            unsetenv("LISTEN_FDS")
            unsetenv("LISTEN_FDNAMES")
            return
        }
        listener = try Self.makeSocket(at: socketPath)
        ownsSocket = true
    }

    static func activationSocket(environment: [String: String]) -> Int32? {
        guard let pid = environment["LISTEN_PID"].flatMap({ pid_t($0) }), pid == getpid(),
            let count = environment["LISTEN_FDS"].flatMap({ Int($0) }), count >= 1
        else { return nil }
        let fd: Int32 = 3
        guard isListeningUnixStream(fd) else {
            DaemonLog.info("ignoring descriptor 3 from systemd: not a listening unix stream socket")
            return nil
        }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        if count > 1 { DaemonLog.info("ignoring \(count - 1) more descriptors from systemd") }
        return fd
    }

    static func isListeningUnixStream(_ fd: Int32) -> Bool {
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFSOCK else { return false }
        var type: Int32 = 0, listening: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0, type == Sys.streamType else { return false }
        length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &length) == 0, listening != 0 else { return false }
        var address = sockaddr_storage()
        length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let rc = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        return rc == 0 && Int32(address.ss_family) == AF_UNIX
    }

    /// Binds a new socket at `path`, replacing a stale socket there (nothing else).
    static func makeSocket(at path: String) throws -> Int32 {
        var st = stat()
        if lstat(path, &st) == 0 {
            guard (st.st_mode & S_IFMT) == S_IFSOCK else { throw Failure.notASocket(path) }
            guard unlink(path) == 0 else { throw Failure.socket("remove \(path)", errno) }
        }
        var address = sockaddr_un()
        guard path.utf8.count < MemoryLayout.size(ofValue: address.sun_path) else {
            throw Failure.socket("socket path \(path)", ENAMETOOLONG)
        }
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: path.utf8)
            raw[path.utf8.count] = 0
        }
        let fd = Sys.unixStreamSocket()
        guard fd >= 0 else { throw Failure.socket("socket", errno) }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0 else { let e = errno; close(fd); throw Failure.socket("bind \(path)", e) }
        guard chmod(path, 0o666) == 0 else { let e = errno; close(fd); throw Failure.socket("chmod \(path)", e) }
        guard Sys.listen(fd, backlog: 128) == 0 else { let e = errno; close(fd); throw Failure.socket("listen \(path)", e) }
        return fd
    }

    // MARK: - Serving

    /// Accepts connections on a thread of its own until `shutdown`.
    public func serve() {
        precondition(listener >= 0, "listen() first")
        _ = pipe(&wakeFDs)
        wakeFDs.forEach { _ = fcntl($0, F_SETFD, FD_CLOEXEC) }
        let thread = Thread { [self] in acceptLoop() }
        thread.name = "passtunneld.accept"
        thread.start()
    }

    private func acceptLoop() {
        while true {
            var fds = [
                pollfd(fd: listener, events: Int16(POLLIN), revents: 0),
                pollfd(fd: wakeFDs[0], events: Int16(POLLIN), revents: 0)
            ]
            let r = poll(&fds, 2, -1)
            if isStopped { return }
            if r < 0 {
                if errno != EINTR { usleep(100_000) }
                continue
            }
            guard fds[0].revents != 0 else { continue }
            let fd = accept(listener, nil, nil)
            guard fd >= 0 else {
                if errno == EMFILE || errno == ENFILE { usleep(100_000) }
                continue
            }
            _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
            admit(fd)
        }
    }

    /// Hands the connection to a thread of its own, unless too many are being served already.
    private func admit(_ fd: Int32) {
        guard let caller = options.peer(fd) else { close(fd); return }
        lock.lock()
        let total = connections.values.reduce(0, +)
        let mine = connections[caller.uid, default: 0]
        let admitted = total < options.maxConnections && mine < options.maxConnectionsPerUser
        if admitted { connections[caller.uid] = mine + 1 }
        lock.unlock()
        guard admitted else {
            let reply = (try? HelperResponse.failure("The daemon is busy. Try again.").jsonData()) ?? Data()
            LineIO.write(fd, reply + Data([0x0A]), deadline: Date().addingTimeInterval(0.1))
            close(fd)
            return
        }
        let thread = Thread { [self] in
            serve(fd, caller: caller)
            close(fd)
            lock.lock()
            connections[caller.uid, default: 1] -= 1
            if connections[caller.uid] == 0 { connections[caller.uid] = nil }
            lock.unlock()
        }
        thread.name = "passtunneld.connection"
        thread.start()
    }

    private var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    /// One request: read the line, answer it, done.
    func serve(_ fd: Int32, caller: Caller) {
        let reply: Data
        switch LineIO.readLine(fd, limit: DaemonProtocol.maxLineBytes, deadline: Date().addingTimeInterval(options.readTimeout)) {
        case .line(let line):
            reply = answer(line, caller: caller)
        case .tooLarge:
            reply = encode(.failure(String(describing: HelperCore.RequestError.tooLarge(DaemonProtocol.maxLineBytes + 1))))
        case .timedOut, .closed, .failed:
            return
        }
        LineIO.write(fd, reply + Data([0x0A]), deadline: Date().addingTimeInterval(options.writeTimeout))
    }

    func answer(_ line: Data, caller: Caller) -> Data {
        let call: DaemonCall
        do {
            call = try DaemonCall.parse(line)
        } catch {
            return encode(.failure(String(describing: error)))
        }
        switch call {
        case .hello:
            let hello = DaemonHello(build: options.build, buildNumber: options.buildNumber)
            return (try? hello.jsonData()) ?? encode(.failure("encoding failed"))
        case .perform(let data):
            return encode(perform(data, caller: caller))
        }
    }

    func perform(_ data: Data, caller: Caller) -> HelperResponse {
        let request: HelperRequest
        do {
            request = try HelperCore.decodeRequest(data)
        } catch {
            return .failure(String(describing: error))
        }
        if case .refused(let reason) = Access.decide(request, uid: caller.uid, users: options.users) {
            DaemonLog.info("refused a start for uid \(caller.uid) (pid \(caller.pid)): not root or in the group \(Access.groupName)")
            return .failure(reason)
        }
        let done = DispatchSemaphore(value: 0)
        let box = ResponseBox()
        supervisor.handle(request, uid: caller.uid) { response in
            box.set(response)
            done.signal()
        }
        guard done.wait(timeout: .now() + options.stopGrace + 10) == .success, let response = box.get() else {
            return .failure("The daemon did not finish the request in time.")
        }
        return response
    }

    private func encode(_ response: HelperResponse) -> Data {
        var response = response
        response.helperBuild = options.buildNumber
        return (try? response.jsonData()) ?? Data(#"{"ok":false,"error":"encoding failed"}"#.utf8)
    }

    // MARK: - Shutdown

    /// Stops accepting, stops every tool and removes the socket the daemon made itself (systemd's
    /// stays). Blocks up to the stop grace period.
    public func shutdown() {
        lock.lock()
        let already = stopped
        stopped = true
        lock.unlock()
        guard !already else { return }
        if wakeFDs[1] >= 0 { _ = write(wakeFDs[1], "x", 1) }
        if ownsSocket { unlink(socketPath) }
        supervisor.stopAll()
    }
}

private final class ResponseBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: HelperResponse?

    func set(_ response: HelperResponse) {
        lock.lock()
        value = response
        lock.unlock()
    }

    func get() -> HelperResponse? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

/// The daemon's log: standard error, which systemd sends to the journal. Never request contents.
/// Messages can quote what a client sent (a profile ID, a path), so control characters become "?"
/// and a message is always one line.
public enum DaemonLog {
    public static func info(_ message: String) {
        let line = "passtunneld: " + oneLine(message) + "\n"
        _ = line.withCString { write(2, $0, strlen($0)) }
    }

    static func oneLine(_ message: String) -> String {
        String(String.UnicodeScalarView(message.unicodeScalars.map { $0.value < 0x20 || $0.value == 0x7F ? "?" : $0 }))
    }
}
