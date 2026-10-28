import Foundation
import PassTunnelShared
import os

// Privileged helper: launched on demand by launchd (SMAppService daemon) as root. Its staged copy is also
// openconnect's hook (`VPNHook`), decided here before anything else runs: no XPC, no state, no logging.
switch VPNHook.mode(executablePath: VPNHook.executablePath(of: getpid()), argv0: CommandLine.arguments.first) {
case .helper:
    break
case .hook:
    exit(VPNHook.runStub())
case .refused:
    _ = "PassTunnelHelper: refusing to run under this name\n".withCString { write(STDERR_FILENO, $0, strlen($0)) }
    exit(2)
}

let log = Logger(subsystem: PT.helperLabel, category: "main")
if geteuid() != 0 {
    log.error("PassTunnelHelper must run as root (launched by launchd)")
}
umask(0o077)

// Opened, verified as the running image and hashed now (`HelperImage`): after an app update replaces the
// binary on disk, this process still reports its own build, and still stages its own bytes as openconnect's
// hook (`ToolStager.stageHook`). Without a verified image (the file at the path is not the one running:
// replaced between the exec and the open) the tools still stage and run, under a build ID from the
// kernel's cdhash of this process, and openconnect is refused. That ID never equals the app's digest of its
// bundled helper, and no build number is reported (nothing read from the bundle is trusted then), so the
// app sees an older helper: it replaces it on its own once, as after an app update, and asks to update it
// in Settings → Helper until then.
let image: HelperImage?
do {
    image = try HelperImage.open(HelperBundle.executablePath, imageAddress: #dsohandle)
} catch {
    image = nil
    log.error("own executable not verified (\(String(describing: error), privacy: .public)); Cisco AnyConnect is unavailable")
}
let buildID = image?.digest ?? HelperImage.fallbackBuildID() ?? "unknown"
// Read now for the same reason; the app only replaces a helper with a lower number on its own.
let buildNumber = image == nil ? nil : HelperBuild.buildNumber(ofBundleContaining: HelperBundle.executablePath)

let core = HelperCore(runRoot: PT.helperRunRoot, dnsUpdownSource: HelperBundle.dnsUpdownPath)
let stager = ToolStager(
    bundleContents: HelperBundle.contentsDir, runRoot: PT.helperRunRoot, buildID: buildID,
    hookSource: image?.descriptor)
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
