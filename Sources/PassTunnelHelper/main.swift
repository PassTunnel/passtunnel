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

// Opened and hashed now: after an app update replaces the binary on disk, this process still reports its
// own build, and still stages its own bytes as openconnect's hook (`ToolStager`).
let ownExecutable = open(HelperBundle.executablePath, O_RDONLY | O_CLOEXEC)
let buildID = (ownExecutable >= 0 ? HelperBuild.digest(ofDescriptor: ownExecutable) : nil) ?? "unknown"
// Read now for the same reason; the app only replaces a helper with a lower number on its own.
let buildNumber = HelperBuild.buildNumber(ofBundleContaining: HelperBundle.executablePath)

let core = HelperCore(runRoot: PT.helperRunRoot, dnsUpdownSource: HelperBundle.dnsUpdownPath)
let stager = ToolStager(
    bundleContents: HelperBundle.contentsDir, runRoot: PT.helperRunRoot, buildID: buildID,
    hookSource: ownExecutable >= 0 ? ownExecutable : nil)
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
