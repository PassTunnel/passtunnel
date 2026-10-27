import Foundation
import PassTunnelShared
import os

// Privileged helper: launched on demand by launchd (SMAppService daemon) as root.

let log = Logger(subsystem: PT.helperLabel, category: "main")
if geteuid() != 0 {
    log.error("PassTunnelHelper must run as root (launched by launchd)")
}
umask(0o077)

// Hashed now: after an app update replaces the binary on disk, this process still reports its own build.
let buildID = HelperBuild.digest(ofFile: HelperBundle.executablePath) ?? "unknown"
// Read now for the same reason; the app only replaces a helper with a lower number on its own.
let buildNumber = HelperBuild.buildNumber(ofBundleContaining: HelperBundle.executablePath)

let core = HelperCore(runRoot: PT.helperRunRoot, dnsUpdownSource: HelperBundle.dnsUpdownPath)
let stager = ToolStager(bundleContents: HelperBundle.contentsDir, runRoot: PT.helperRunRoot, buildID: buildID)
let supervisor = Supervisor(core: core, stager: stager)
supervisor.adoptOrphans()

// Stop all tools and clean up when launchd stops the helper.
var signalSources: [DispatchSourceSignal] = []
for sig in [SIGTERM, SIGINT, SIGHUP] {
    signal(sig, SIG_IGN)
    let src = DispatchSource.makeSignalSource(signal: sig, queue: .global())
    src.setEventHandler {
        log.notice("signal \(sig), stopping all tunnels")
        supervisor.stopAll()
        exit(0)
    }
    src.resume()
    signalSources.append(src)
}
signal(SIGPIPE, SIG_IGN)

let delegate = ListenerDelegate(supervisor: supervisor, buildID: buildID, buildNumber: buildNumber)
let listener = NSXPCListener(machServiceName: PT.helperLabel)
listener.delegate = delegate
listener.resume()
log.info(
    "listening on \(PT.helperLabel, privacy: .public), version \(PT.helperProtocolVersion), build \(buildID, privacy: .public) (\(buildNumber ?? 0))")
dispatchMain()
