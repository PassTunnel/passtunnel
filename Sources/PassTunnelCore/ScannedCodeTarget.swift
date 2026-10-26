import Foundation
import PassTunnelKit

/// Where the app takes a code read from a QR image dropped on the main window or chosen with File → Add Code from QR…
/// (`ImportActions.addCode`). The add view's "Use a QR image" always starts a new profile.
public enum ScannedCodeTarget: Equatable {
    /// The editor of this profile, with the code filled in.
    case profile(String)
    /// Ask which of these profiles it is for: the ones that sign in with a password.
    case choose([Profile])
    /// No profile can take it: a new profile that starts with the code.
    case newProfile

    /// `requested`: the profile the code was asked for (the selected one), taken while it exists.
    public static func route(requested: String?, profiles: [Profile]) -> ScannedCodeTarget {
        if let requested, profiles.contains(where: { $0.id == requested }) { return .profile(requested) }
        let targets = profiles.filter { $0.passwordMode != .none }
        return targets.isEmpty ? .newProfile : .choose(targets)
    }
}
