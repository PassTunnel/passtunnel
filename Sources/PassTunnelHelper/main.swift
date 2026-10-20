import Foundation
import os
import PassTunnelShared

// Privileged helper: launched on demand by launchd (SMAppService daemon) as root.

let log = Logger(subsystem: PT.helperLabel, category: "main")
if geteuid() != 0 {
    log.error("PassTunnelHelper must run as root (launched by launchd)")
}
umask(0o077)

let core = HelperCore(runRoot: PT.helperRunRoot, dnsUpdownSource: HelperBundle.dnsUpdownPath)
let supervisor = Supervisor(core: core)
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

let delegate = ListenerDelegate(supervisor: supervisor)
let listener = NSXPCListener(machServiceName: PT.helperLabel)
listener.delegate = delegate
listener.resume()
log.info("listening on \(PT.helperLabel, privacy: .public), version \(PT.helperProtocolVersion)")
dispatchMain()
