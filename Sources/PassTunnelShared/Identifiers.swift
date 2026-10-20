import Foundation

/// Identifiers shared by the app, the CLI and the privileged helper.
public enum PT {
    public static let bundleID = "com.furkanprlk.passtunnel"
    public static let helperLabel = "com.furkanprlk.passtunnel.helper"   // launchd label == mach service name
    public static let helperPlistName = "com.furkanprlk.passtunnel.helper.plist"
    public static let teamID = "YH4NUPFH74"
    public static let keychainService = "PassTunnel"
    /// 2: OpenVPN management moved from TCP 127.0.0.1:mgmtPort to a per-profile unix socket.
    public static let helperProtocolVersion = 2

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

    /// Root-only directory where the helper keeps per-profile runtime files.
    public static let helperRunRoot = "/var/run/passtunnel"

    /// OpenVPN management socket inside the profile directory (only the calling user may connect).
    public static let mgmtSocketName = "mgmt.sock"

    /// Location of profile directories relative to the user's home.
    public static let profilesSubpath = "Library/Application Support/PassTunnel/profiles"
}
