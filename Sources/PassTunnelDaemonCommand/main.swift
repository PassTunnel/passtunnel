import Foundation
import PassTunnelDaemon
import PassTunnelShared

// passtunneld, the root daemon of PassTunnel on Linux (docs/LINUX.md), started by systemd through
// passtunnel.socket, or by hand (containers, development) with a socket of its own.

// Also OpenVPN's DNS hook (`passtunneld dns-hook`, run through the session directory's `dns-hook`
// link): that mode only sets up or reverts one session's DNS and exits, before anything of the daemon.
if DNSHook.isInvocation(CommandLine.arguments) {
    umask(0o077)
    exit(DNSHook.main(environment: ProcessInfo.processInfo.environment))
}

// Before any other thread exists, so that every thread inherits it: the stop signals are taken
// only by `sigwait` at the end. The tools get an empty mask and default actions (`Sys.spawn`).
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
    fail("passtunneld takes no arguments (but dns-hook, which OpenVPN runs); systemd starts it through passtunnel.socket.",
         code: 2)
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

// The main thread waits for a stop signal itself. Not dispatchMain(): on Linux it parks the main
// thread in sigsuspend with an empty mask, where SIGTERM would end the process without the cleanup.
var sig: Int32 = 0
while sigwait(&stopSignals, &sig) != 0 {}
DaemonLog.info("signal \(sig), stopping all tunnels")
daemon.shutdown()
exit(0)
