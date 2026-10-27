import Foundation

/// Keeps one management connection per OpenVPN socket open and follows the state through real-time
/// `>STATE:` notifications (`state on`), so polling does not open a new connection every few seconds
/// (OpenVPN logs every client connect, command and disconnect). A dropped connection is reopened on
/// the next query. Used by the app; the CLI's one-shot queries meanwhile find the interface busy and
/// read the state the app shares (`ConnectionManager`'s snapshot file).
public final class PersistentManagementQuerier: ManagementQuerying, @unchecked Sendable {
    private let lock = NSLock()
    private var sessions: [String: Session] = [:]  // by socket path
    private var opening: [String: Task<Session, Error>] = [:]  // one open at a time per socket
    /// Wait for the banner when opening (OpenVPN sends it at once unless another client is served).
    var bannerTimeout: TimeInterval = 1

    public init() {}

    public var sharesState: Bool { true }

    public func state(socketPath: String, timeout: TimeInterval) async throws -> ManagementState {
        if let s = liveSession(socketPath), let state = s.latest { return state }
        guard FileManager.default.fileExists(atPath: socketPath) else {
            throw ManagementError.connectFailed(socketPath, ENOENT)
        }
        let session = try await openSession(socketPath, timeout: timeout).value
        guard let state = session.latest else { throw ManagementError.closed }
        return state
    }

    /// The open in progress for `path`, or a new one (a second one would only wait in OpenVPN's backlog).
    private func openSession(_ path: String, timeout: TimeInterval) -> Task<Session, Error> {
        lock.withLock {
            if let pending = opening[path] { return pending }
            let bannerTimeout = self.bannerTimeout
            let task = Task<Session, Error> { [weak self] in
                defer { self?.lock.withLock { self?.opening[path] = nil } }
                let session = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Session, Error>) in
                    DispatchQueue.global(qos: .userInitiated).async {
                        cont.resume(with: Result { try Session.open(path, bannerTimeout: bannerTimeout, timeout: timeout) })
                    }
                }
                let replaced = self?.lock.withLock { () -> Session? in
                    let old = self?.sessions[path]
                    self?.sessions[path] = session
                    return old
                }
                replaced?.close()
                return session
            }
            opening[path] = task
            return task
        }
    }

    /// Over the held connection when there is one (the reply is read, and ignored, by its reader
    /// thread), else on a one-shot connection.
    public func send(_ command: String, socketPath: String, timeout: TimeInterval) async throws -> String {
        guard !command.contains("\n"), !command.contains("\r") else { throw ManagementError.unexpectedReply(command) }
        if let s = liveSession(socketPath) {
            try s.write(command + "\n", timeout: timeout)
            return ""
        }
        return try await ManagementSocket.sendOneShot(command, socketPath: socketPath, timeout: timeout)
    }

    /// Closes the connection to `socketPath` (e.g. the profile went away).
    public func release(socketPath: String) {
        lock.withLock { sessions.removeValue(forKey: socketPath) }?.close()
    }

    public func releaseAll() {
        let all = lock.withLock { () -> [Session] in
            defer { sessions.removeAll() }
            return Array(sessions.values)
        }
        all.forEach { $0.close() }
    }

    /// Number of open connections (tests).
    var openConnections: Int { lock.withLock { sessions.values.filter(\.isAlive).count } }

    private func liveSession(_ path: String) -> Session? {
        lock.withLock {
            guard let s = sessions[path] else { return nil }
            if s.isAlive { return s }
            sessions[path] = nil
            return nil
        }
    }

    /// One held connection; a background thread reads replies and notifications until it closes.
    final class Session: @unchecked Sendable {
        private let conn: ManagementSocket.Connection
        private let lock = NSLock()
        private var _latest: ManagementState?
        private var _alive = true
        private var descriptorClosed = false  // by the reader thread; never shut down after that

        private init(_ conn: ManagementSocket.Connection) { self.conn = conn }

        var latest: ManagementState? { lock.withLock { _latest } }
        var isAlive: Bool { lock.withLock { _alive } }

        /// Connects, turns real-time state on, asks for the current state and waits for it.
        static func open(_ path: String, bannerTimeout: TimeInterval, timeout: TimeInterval) throws -> Session {
            let conn = try ManagementSocket.Connection(path: path)
            let deadline = Date().addingTimeInterval(timeout)
            do {
                guard let banner = try conn.readLine(until: min(deadline, Date().addingTimeInterval(bannerTimeout))),
                    banner.hasPrefix(">INFO:")
                else { throw ManagementError.busy }
            } catch ManagementError.timeout {
                conn.close()
                throw ManagementError.busy
            } catch {
                conn.close()
                throw error is ManagementError ? error : ManagementError.busy
            }
            let session = Session(conn)
            do {
                try conn.write("state on\nstate\n", until: deadline)
                // Read until the reply to `state` arrives, then hand reading over to the thread.
                while session.latest == nil {
                    guard let line = try conn.readLine(until: deadline) else { throw ManagementError.closed }
                    session.handle(line)
                }
            } catch {
                conn.close()
                throw error
            }
            Thread.detachNewThread { session.readLoop() }
            return session
        }

        func handle(_ line: String) {
            var text = Substring(line)
            if text.hasPrefix(">STATE:") {
                text = text.dropFirst(7)
            } else if text.hasPrefix(">") || text.hasPrefix("SUCCESS:") || text.hasPrefix("ERROR:") || text == "END" {
                return
            }
            guard let state = try? ManagementSocket.parseState(String(text)) else { return }
            lock.withLock { _latest = state }
        }

        private func readLoop() {
            while true {
                do {
                    guard let line = try conn.readLine(until: Date().addingTimeInterval(3600)) else { break }
                    handle(line)
                } catch ManagementError.timeout {
                    continue
                } catch {
                    break
                }
            }
            lock.withLock {
                _alive = false
                descriptorClosed = true
                conn.close()
            }
        }

        func write(_ text: String, timeout: TimeInterval) throws {
            let open = lock.withLock { _alive && !descriptorClosed }
            guard open else { throw ManagementError.closed }
            try conn.write(text, until: Date().addingTimeInterval(timeout))
        }

        /// Ends the connection; the reader thread finishes and closes the descriptor.
        func close() {
            lock.withLock {
                _alive = false
                if !descriptorClosed { conn.shutdown() }
            }
        }
    }
}
