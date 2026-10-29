import Foundation
import PassTunnelShared

/// The process on the other end of a connection, from the kernel (`SO_PEERCRED`) as it was when it
/// connected. Every request acts for `uid` only.
public struct Caller: Equatable {
    public let uid: uid_t
    public let gid: gid_t
    public let pid: pid_t

    public init(uid: uid_t, gid: gid_t, pid: pid_t) {
        self.uid = uid
        self.gid = gid
        self.pid = pid
    }

    /// The peer of the connected unix socket `fd`. Where the kernel has `SO_PEERPIDFD`, the pid is
    /// taken from the pidfd instead (it cannot refer to a recycled pid); that is extra information,
    /// nothing is decided by it.
    public static func of(socket fd: Int32) -> Caller? {
        guard let cred = Sys.peerCredentials(fd) else { return nil }
        var pid = cred.pid
        if let pidfd = Sys.peerPidfd(fd) {
            if let current = Sys.pid(ofPidfd: pidfd) { pid = current }
            close(pidfd)
        }
        return Caller(uid: cred.uid, gid: cred.gid, pid: pid)
    }
}

/// The user and group database, replaced in tests.
public struct UserDatabase {
    public var name: (uid_t) -> String?
    public var home: (uid_t) -> String?
    /// Every group of the user in the group database, the primary one included (`getgrouplist`).
    /// Not the caller's current groups: adding a user to the group works without a new login, and
    /// removing one takes effect at once.
    public var groups: (uid_t) -> [gid_t]?
    public var groupID: (String) -> gid_t?

    public init(
        name: @escaping (uid_t) -> String?, home: @escaping (uid_t) -> String?,
        groups: @escaping (uid_t) -> [gid_t]?, groupID: @escaping (String) -> gid_t?
    ) {
        self.name = name
        self.home = home
        self.groups = groups
        self.groupID = groupID
    }

    public static let system = UserDatabase(
        name: HelperCore.passwdName,
        home: HelperCore.passwdHome,
        groups: { uid in
            guard let name = HelperCore.passwdName(uid), let primary = Sys.primaryGroup(of: uid) else { return nil }
            return Sys.groupList(user: name, primary: primary)
        },
        groupID: Sys.groupID(named:))
}

/// Who may do what (docs/LINUX.md, "Daemon security rules"). Anyone who can reach the socket may ask
/// for `hello`, `status` and `stop`, which only ever see the caller's own sessions (`SessionPolicy`);
/// starting a session needs root or membership in the group `passtunnel`.
public enum Access {
    public static let groupName = "passtunnel"

    public enum Decision: Equatable {
        case allowed
        case refused(String)
    }

    public static func decide(_ request: HelperRequest, uid: uid_t, users: UserDatabase) -> Decision {
        switch request {
        case .status, .stop:
            return .allowed
        case .startOpenVPN, .startForti, .startOpenConnect:
            return mayStart(uid: uid, users: users) ? .allowed : .refused(refusal(uid: uid, users: users))
        }
    }

    /// Root, or a user whose groups in the group database include `passtunnel`.
    public static func mayStart(uid: uid_t, users: UserDatabase) -> Bool {
        if uid == 0 { return true }
        guard let gid = users.groupID(groupName), let groups = users.groups(uid) else { return false }
        return groups.contains(gid)
    }

    static func refusal(uid: uid_t, users: UserDatabase) -> String {
        let user = users.name(uid) ?? "uid \(uid)"
        guard users.groupID(groupName) != nil else {
            return "Only root may start VPN connections here: the group “\(groupName)” does not exist. "
                + "Reinstall PassTunnel, or create the group and add \(user) to it."
        }
        return "Only root and members of the group “\(groupName)” may start VPN connections, and \(user) is not one. "
            + "Add the user to the group (as root: usermod -aG \(groupName) \(user)), then connect again."
    }
}
