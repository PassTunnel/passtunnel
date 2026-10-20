import Foundation

/// Identifiers shared by the app, the CLI and the privileged helper.
public enum PT {
    public static let bundleID = "com.furkanprlk.passtunnel"
    public static let helperLabel = "com.furkanprlk.passtunnel.helper"   // launchd label == mach service name
    public static let helperPlistName = "com.furkanprlk.passtunnel.helper.plist"
    public static let teamID = "YH4NUPFH74"
    public static let keychainService = "PassTunnel"
    public static let helperProtocolVersion = 1

    /// Code-signing requirement the helper enforces on its XPC clients.
    public static let clientRequirement =
        "identifier \"\(bundleID)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
}
