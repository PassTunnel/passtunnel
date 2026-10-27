import Foundation

/// Who may start, stop and see which running tool. Pure, so it can be unit-tested; the helper's
/// `Supervisor` applies it to its job table. Sessions are keyed by (owner uid, profile ID): two
/// users may run profiles with the same ID, and every request only ever sees the caller's own
/// sessions (another user's session is invisible, so `stop` of it is the same no-op as an unknown ID).
public enum SessionPolicy {
    public struct Key: Hashable {
        public let uid: uid_t
        public let profileID: String

        public init(uid: uid_t, profileID: String) {
            self.uid = uid
            self.profileID = profileID
        }
    }

    public struct Session: Equatable {
        public let profileID: String
        public let ownerUID: uid_t
        public let pid: Int32
        /// OpenVPN management socket (nil for other tools).
        public let mgmtSocket: String?

        public init(profileID: String, ownerUID: uid_t, pid: Int32, mgmtSocket: String? = nil) {
            self.profileID = profileID
            self.ownerUID = ownerUID
            self.pid = pid
            self.mgmtSocket = mgmtSocket
        }

        public var key: Key { Key(uid: ownerUID, profileID: profileID) }
    }

    /// Concurrent tunnels one user may run.
    public static let maxSessionsPerUser = 8

    public enum Denial: Error, Equatable, LocalizedError, CustomStringConvertible {
        case alreadyRunning(String, pid: Int32)
        case tooManySessions(limit: Int)

        public var description: String {
            switch self {
            case .alreadyRunning(let id, let pid): return "Profile \(id) is already running (pid \(pid))."
            case .tooManySessions(let n): return "Too many active connections (limit \(n)). Disconnect one first."
            }
        }
        public var errorDescription: String? { description }
    }

    public enum StopDecision: Equatable {
        /// Nothing of the caller's to stop: reported as success so `stop` is idempotent.
        case notRunning
        case terminate(pid: Int32)
    }

    static func mine(_ uid: uid_t, _ sessions: [Session]) -> [Session] {
        sessions.filter { $0.ownerUID == uid }
    }

    public static func checkStart(
        profileID: String, uid: uid_t, sessions: [Session],
        limit: Int = maxSessionsPerUser
    ) throws {
        let own = mine(uid, sessions)
        if let s = own.first(where: { $0.profileID == profileID }) {
            throw Denial.alreadyRunning(profileID, pid: s.pid)
        }
        if own.count >= limit { throw Denial.tooManySessions(limit: limit) }
    }

    public static func stopDecision(profileID: String, uid: uid_t, sessions: [Session]) -> StopDecision {
        guard let s = mine(uid, sessions).first(where: { $0.profileID == profileID }) else { return .notRunning }
        return .terminate(pid: s.pid)
    }

    /// `status` reply: profile ID → pid of the caller's own sessions.
    public static func visible(to uid: uid_t, sessions: [Session]) -> [String: Int32] {
        Dictionary(mine(uid, sessions).map { ($0.profileID, $0.pid) }, uniquingKeysWith: { a, _ in a })
    }

    /// `status` reply: profile ID → management socket of the caller's own OpenVPN sessions.
    public static func sockets(visibleTo uid: uid_t, sessions: [Session]) -> [String: String] {
        Dictionary(
            mine(uid, sessions).compactMap { s in s.mgmtSocket.map { (s.profileID, $0) } },
            uniquingKeysWith: { a, _ in a })
    }
}
