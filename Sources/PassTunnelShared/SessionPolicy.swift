import Foundation

/// Who may start, stop and see which running tool. Pure, so it can be unit-tested; the helper's
/// `Supervisor` applies it to its job table. Root (uid 0) sees and may stop every session.
public enum SessionPolicy {
    public struct Session: Equatable {
        public let profileID: String
        public let ownerUID: uid_t
        public let pid: Int32

        public init(profileID: String, ownerUID: uid_t, pid: Int32) {
            self.profileID = profileID
            self.ownerUID = ownerUID
            self.pid = pid
        }
    }

    /// Concurrent tunnels one user may run.
    public static let maxSessionsPerUser = 8

    public enum Denial: Error, Equatable, LocalizedError, CustomStringConvertible {
        case alreadyRunning(String, pid: Int32)
        case inUseByAnotherUser(String)
        case tooManySessions(limit: Int)
        case belongsToAnotherUser(String)

        public var description: String {
            switch self {
            case .alreadyRunning(let id, let pid): return "Profile \(id) is already running (pid \(pid))."
            case .inUseByAnotherUser(let id): return "Profile \(id) is in use by another user."
            case .tooManySessions(let n): return "Too many active connections (limit \(n)). Disconnect one first."
            case .belongsToAnotherUser(let id): return "Profile \(id) belongs to another user."
            }
        }
        public var errorDescription: String? { description }
    }

    public enum StopDecision: Equatable {
        /// Nothing to stop: reported as success so `stop` is idempotent.
        case notRunning
        case terminate(pid: Int32)
    }

    public static func checkStart(profileID: String, uid: uid_t, sessions: [Session],
                                  limit: Int = maxSessionsPerUser) throws {
        if let s = sessions.first(where: { $0.profileID == profileID }) {
            throw s.ownerUID == uid ? Denial.alreadyRunning(profileID, pid: s.pid) : Denial.inUseByAnotherUser(profileID)
        }
        if sessions.filter({ $0.ownerUID == uid }).count >= limit { throw Denial.tooManySessions(limit: limit) }
    }

    public static func stopDecision(profileID: String, uid: uid_t, sessions: [Session]) throws -> StopDecision {
        guard let s = sessions.first(where: { $0.profileID == profileID }) else { return .notRunning }
        guard uid == 0 || s.ownerUID == uid else { throw Denial.belongsToAnotherUser(profileID) }
        return .terminate(pid: s.pid)
    }

    /// `status` reply: the caller's own sessions (all of them for root).
    public static func visible(to uid: uid_t, sessions: [Session]) -> [String: Int32] {
        Dictionary(sessions.filter { uid == 0 || $0.ownerUID == uid }.map { ($0.profileID, $0.pid) },
                   uniquingKeysWith: { a, _ in a })
    }
}
