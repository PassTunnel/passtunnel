import Foundation
import PassTunnelDaemon
import PassTunnelShared

// passtunneld, the root daemon of PassTunnel on Linux (docs/LINUX.md), started by systemd through
// passtunnel.socket, or by hand (containers, development) with a socket of its own.

// Before any other thread exists, so that every thread inherits it: the stop signals are taken
// only by `sigwait` below. The tools get an empty mask and default actions (`Sys.spawn`).
var stopSignals = sigset_t()
sigemptyset(&stopSignals)
for sig in [SIGTERM, SIGINT, SIGHUP] { sigaddset(&stopSignals, sig) }
pthread_sigmask(SIG_BLOCK, &stopSignals, nil)
signal(SIGPIPE, SIG_IGN)
umask(0o077)

func fail(_ message: String, code: Int32 = 1) -> Never {
    DaemonLog.info(message)
    exit(code)
}

if CommandLine.arguments.count > 1 {
    fail("passtunneld takes no arguments; systemd starts it through passtunnel.socket.", code: 2)
}
if geteuid() != 0 { fail("passtunneld must run as root.") }

// Hashed now: after a package update replaces the file, this process still reports its own build.
var options = Daemon.Options()
options.build = HelperBuild.digest(ofFile: "/proc/self/exe") ?? "unknown"

let daemon: Daemon = {
    do {
        let daemon = try Daemon(options: options)
        try daemon.listen()
        return daemon
    } catch {
        fail(String(describing: error))
    }
}()
daemon.serve()
DaemonLog.info("listening on \(daemon.socketPath), protocol \(PT.helperProtocolVersion), build \(options.build)")

let signals = Thread {
    var waitSet = stopSignals
    var sig: Int32 = 0
    sigwait(&waitSet, &sig)
    DaemonLog.info("signal \(sig), stopping all tunnels")
    daemon.shutdown()
    exit(0)
}
signals.name = "passtunneld.signals"
signals.start()
dispatchMain()
