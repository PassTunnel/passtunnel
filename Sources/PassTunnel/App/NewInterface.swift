import Foundation

/// The redesigned main window and menu bar (decision D-23) stay behind this hidden switch until the last
/// screen lands: `defaults write com.furkanprlk.passtunnel PTNewInterface -bool YES`, then relaunch. Read once.
enum NewInterface {
    static let isEnabled = UserDefaults.standard.bool(forKey: "PTNewInterface")
}
