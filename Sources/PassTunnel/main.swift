import AppKit
import Foundation
import PassTunnelCore
import PassTunnelShared

if PassTunnelCLI.isInvocation(CommandLine.arguments) {
    exit(PassTunnelCLI.run(CommandLine.arguments))
}

// Debug/screenshot path: renders key views to PNGs offscreen and exits. Never shows a window.
if let dir = ProcessInfo.processInfo.environment["PASSTUNNEL_RENDER"], !dir.isEmpty {
    exit(MainActor.assumeIsolated { RenderSnapshots.run(outputDirectory: dir) })
}

// Single instance: hand over to an already running copy.
if let bundleID = Bundle.main.bundleIdentifier {
    let me = ProcessInfo.processInfo.processIdentifier
    if let other = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
        .first(where: { $0.processIdentifier != me && !$0.isTerminated }) {
        other.activate(options: [.activateAllWindows])
        DistributedNotificationCenter.default().postNotificationName(
            AppDelegate.showMainWindowNotification, object: nil, userInfo: nil, deliverImmediately: true)
        exit(0)
    }
}

PassTunnelApp.main()
