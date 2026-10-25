import Foundation
import PassTunnelKit

/// Where the app takes a code read from a QR image dropped on the main window or chosen with File → Add Code from QR…
/// (`ImportActions.addCode`). The add view's "Use a QR image" always starts a new profile.
public enum ScannedCodeTarget: Equatable {
    /// The editor of this profile, with the code filled in.
    case profile(String)
    /// Ask which of these profiles it is for: the ones that sign in with a password.
    case choose([Profile])
    /// A new profile that starts with the code (the redesigned window).
    case newProfile
    /// No profile can take it, so the user is told to add a VPN first (the current window).
    case addVPNFirst

    /// `requested`: the profile the code was asked for (the selected one), taken while it exists. `startsProfiles`:
    /// the redesigned window, which starts a new profile where the current one sends the user to add a VPN first.
    public static func route(requested: String?, profiles: [Profile], startsProfiles: Bool) -> ScannedCodeTarget {
        if let requested, profiles.contains(where: { $0.id == requested }) { return .profile(requested) }
        let targets = profiles.filter { $0.passwordMode != .none }
        if !targets.isEmpty { return .choose(targets) }
        return startsProfiles ? .newProfile : .addVPNFirst
    }
}
