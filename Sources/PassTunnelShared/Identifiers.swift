import Foundation

/// Identifiers shared by the app, the CLI and the privileged helper.
public enum PT {
    public static let bundleID = "com.furkanprlk.passtunnel"
    public static let helperLabel = "com.furkanprlk.passtunnel.helper"   // launchd label == mach service name
    public static let helperPlistName = "com.furkanprlk.passtunnel.helper.plist"
    public static let teamID = "YH4NUPFH74"
    public static let keychainService = "PassTunnel"
    /// 2: OpenVPN management moved from TCP 127.0.0.1:mgmtPort to a per-profile unix socket.
    /// 3: sessions keyed by (uid, profile ID); the socket moved to the root-owned session directory
    ///    (`mgmtSocketPath`), `status` also returns socket paths, requests must carry the version.
    public static let helperProtocolVersion = 3

    /// Code-signing requirement the helper enforces on its XPC clients.
    public static let clientRequirement =
        "identifier \"\(bundleID)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""

    /// Any code signed with our Developer ID.
    public static let teamRequirement = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""

    /// Requirement for one bundled tool (openvpn, openfortivpn, dns-updown).
    public static func toolRequirement(identifier: String) -> String {
        "identifier \"\(identifier)\" and \(teamRequirement)"
    }

    /// Code-signing identifiers of the bundled tools (set by scripts/build-app.sh).
    public static let openvpnIdentifier = "com.furkanprlk.passtunnel.openvpn"
    public static let openfortivpnIdentifier = "com.furkanprlk.passtunnel.openfortivpn"
    public static let dnsUpdownIdentifier = "com.furkanprlk.passtunnel.dns-updown"

    /// Root-owned directory where the helper keeps per-session runtime files:
    /// `<root>/<uid>/<profileID>/` (all 0711, so users can reach their socket but list nothing), and
    /// the staged tools in `<root>/tools/<build>/` (`ToolStager`). On Linux the daemon's (docs/LINUX.md).
    #if os(Linux)
    public static let helperRunRoot = "/run/passtunnel"
    #else
    public static let helperRunRoot = "/var/run/passtunnel"
    #endif

    /// OpenVPN management socket inside the session directory (owned by the user, 0600).
    public static let mgmtSocketName = "mgmt.sock"

    /// Session directory of `profileID` for user `uid`.
    public static func sessionDir(uid: uid_t, profileID: String, runRoot: String = helperRunRoot) -> String {
        "\(runRoot)/\(uid)/\(profileID)"
    }

    /// Where the helper puts the OpenVPN management socket of `profileID` for user `uid`.
    public static func mgmtSocketPath(uid: uid_t, profileID: String, runRoot: String = helperRunRoot) -> String {
        sessionDir(uid: uid, profileID: profileID, runRoot: runRoot) + "/" + mgmtSocketName
    }

    /// Location of profile directories relative to the user's home. Fixed on Linux too (no
    /// `XDG_DATA_HOME`): the daemon checks that a profile directory is under the caller's home at this path.
    #if os(Linux)
    public static let profilesSubpath = ".local/share/passtunnel/profiles"
    #else
    public static let profilesSubpath = "Library/Application Support/PassTunnel/profiles"
    #endif
}
