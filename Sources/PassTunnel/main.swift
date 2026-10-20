import AppKit
import Foundation
import PassTunnelCore
import PassTunnelShared

// Started through a symlink (the installed `passtunnel` command), Bundle.main is not the app bundle:
// no translations, Info.plist or helper plist. Run the real executable inside the app instead,
// keeping argv[0] so the CLI mode is still recognized.
if Bundle.main.bundleURL.pathExtension != "app", let current = Bundle.main.executablePath,
   let resolved = realpath(current, nil) {
    let real = String(cString: resolved)
    free(resolved)
    if real != current, real.contains(".app/Contents/MacOS/") {
        var cArgs = CommandLine.arguments.map { strdup($0) } + [nil]
        execv(real, &cArgs)
    }
}

if PassTunnelCLI.isInvocation(CommandLine.arguments) {
    exit(PassTunnelCLI.run(CommandLine.arguments))
}

// Debug/screenshot path: renders key views to PNGs offscreen and exits. Never shows a window.
if let dir = ProcessInfo.processInfo.environment["PASSTUNNEL_RENDER"], !dir.isEmpty {
    // PASSTUNNEL_RENDER_LANG=tr renders in that language: restart with `-AppleLanguages (tr)` so the
    // bundle picks the localization before any string is looked up (nothing is written to defaults).
    if let lang = ProcessInfo.processInfo.environment["PASSTUNNEL_RENDER_LANG"], !lang.isEmpty,
       !CommandLine.arguments.contains("-AppleLanguages"), let executable = Bundle.main.executablePath {
        let argv = [executable] + CommandLine.arguments.dropFirst() + ["-AppleLanguages", "(\(lang))"]
        var cArgs = argv.map { strdup($0) } + [nil]
        execv(executable, &cArgs)
        FileHandle.standardError.write(Data("render: could not restart with language \(lang)\n".utf8))
        exit(1)
    }
    exit(MainActor.assumeIsolated { RenderSnapshots.run(outputDirectory: dir) })
}

// Single instance: hand over to an already running copy.
if let bundleID = Bundle.main.bundleIdentifier {
    let me = ProcessInfo.processInfo.processIdentifier
    if let other = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
        .first(where: { $0.processIdentifier != me && !$0.isTerminated }) {
        // A background start (login item) never pulls the running copy forward.
        if CommandLine.arguments.dropFirst().contains(LoginItem.backgroundArgument) { exit(0) }
        other.activate(options: [.activateAllWindows])
        DistributedNotificationCenter.default().postNotificationName(
            AppDelegate.showMainWindowNotification, object: nil, userInfo: nil, deliverImmediately: true)
        exit(0)
    }
}

PassTunnelApp.main()
