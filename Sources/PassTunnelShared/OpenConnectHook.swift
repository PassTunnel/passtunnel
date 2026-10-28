import Foundation

/// What openconnect's hook does in one run, and the revert the helper runs once a session's tool has ended
/// (docs/ARCHITECTURE.md, "The hook", steps 4–7). Every change goes through `system`, one at a time, under
/// the run root's lock (`OpenConnectLock`), journaled in the session's record (`OpenConnectJournal`) before it
/// is made and with its outcome after; every program has `toolLimit` and the whole run `runLimit`.
///
/// - `pre-init`: nothing.
/// - `connect`: the plan (`OpenConnectPlan.connect`) from the checked network, the policy and the underlay
///   (the routing table's default gateways and the interfaces' networks), applied in order.
/// - `attempt-reconnect`: the routes around the tunnel follow the default gateway (`OpenConnectPlan.refresh`).
/// - `reconnect`: the network must be what the record holds (`OpenConnectPlan.matches`).
/// - `disconnect`: everything the record holds is reverted, but what another session holds.
///
/// Every change is looked for before anything is journaled for it. A route already there with exactly the
/// planned next hop is shared (`&`) when another session holds it, and the last of them to end removes
/// it, or not PassTunnel's (`~`) and never removed; any other route of that destination fails the set-up
/// (`finding`): the hook replaces nobody's route.
///
/// Any failure reverts what the record holds, records `status failed <reason>`, gives the failure line and
/// asks for openconnect to be stopped (`Outcome.stopTool`): openconnect ignores the hook's exit status.
public struct OpenConnectHook {
    public typealias Change = OpenConnectPlan.Change

    /// The whole run, the wait for the lock included (the hook is also stopped by `SIGALRM` a second later).
    public static let runLimit: TimeInterval = 30
    /// Each program the hook runs.
    public static let toolLimit: TimeInterval = 10

    /// What a run ends with.
    public struct Outcome: Equatable {
        /// Lines for the session's log, each with its line break.
        public var lines: [String] = []
        /// The set-up failed: openconnect is to be stopped.
        public var stopTool = false

        public init(lines: [String] = [], stopTool: Bool = false) {
            self.lines = lines
            self.stopTool = stopTool
        }
    }

    /// Why a run could not use its inputs.
    public enum Failure: Error, CustomStringConvertible {
        case policy

        public var description: String {
            switch self {
            case .policy: return "the session's policy cannot be read"
            }
        }
    }

    public let runRoot: String
    public let runDir: String
    public let system: OpenConnectSystem
    public let deadline: Date
    /// The pid and start time the `hook` mark records.
    public let identity: (pid: pid_t, start: ProcessStart?)
    public var now: () -> Date = Date.init
    /// Whether the run still serves the session it proved, checked once the lock is held, before the record is
    /// read or anything is changed: the hook may have waited for the lock while its openconnect ended, the
    /// helper cleaned up and the profile started again in the same session directory (`VPNHook.run` proves the
    /// session again and compares its generation, the tool's start time in `state`).
    public var stillOurs: () -> Bool = { true }

    public init(
        runRoot: String, runDir: String, system: OpenConnectSystem, deadline: Date,
        identity: (pid: pid_t, start: ProcessStart?) = (getpid(), nil)
    ) {
        self.runRoot = runRoot
        self.runDir = runDir
        self.system = system
        self.deadline = deadline
        self.identity = identity
    }

    // MARK: - A run of the hook

    /// One run of the hook for a proven session (`VPNHook.session`): `event` is openconnect's environment
    /// checked (`OpenConnectNetwork.parse`), `policy` the session's `policy`; either may throw, which fails the
    /// run like any other failure.
    public func run(event parse: () throws -> OpenConnectNetwork.Event, policy readPolicy: () throws -> OpenConnectPolicy) -> Outcome {
        let event: OpenConnectNetwork.Event
        do {
            event = try parse()
        } catch {
            return locked(reverting: false) { fail(String(describing: error), interface: nil) }
        }
        if case .preInit = event { return Outcome() }
        let policy: OpenConnectPolicy
        do {
            policy = try readPolicy()
        } catch {
            return locked(reverting: event == .disconnect) {
                event == .disconnect ? disconnect() : fail(String(describing: error), interface: event.network?.interface)
            }
        }
        return locked(reverting: event == .disconnect) {
            switch event {
            case .preInit: return Outcome()
            case .disconnect: return disconnect()
            case .connect(let n): return connect(n, policy: policy)
            case .attemptReconnect(let n): return attemptReconnect(n, policy: policy)
            case .reconnect(let n): return reconnect(n, policy: policy)
            }
        }
    }

    /// `body` under the run root's lock, with the `hook` mark set while it runs; nothing at all when the session
    /// the run proved has ended meanwhile (`stillOurs`).
    func locked(reverting: Bool, _ body: () -> Outcome) -> Outcome {
        guard let lock = OpenConnectLock.acquire(runRoot: runRoot, until: deadline, now: now) else {
            let reason = "the network lock was not free within \(Int(Self.runLimit)) seconds"
            return reverting ? Outcome(lines: [VPNHook.revertFailureLine(reason)]) : Outcome(lines: [VPNHook.failureLine(reason)], stopTool: true)
        }
        guard stillOurs() else {
            withExtendedLifetime(lock) {}
            return Outcome(lines: [VPNHook.endedLine])
        }
        try? OpenConnectMarks.setHook(runDir: runDir, pid: identity.pid, start: identity.start)
        defer {
            OpenConnectMarks.clearHook(runDir: runDir)
            withExtendedLifetime(lock) {}
        }
        return body()
    }

    /// `connect`: the plan, applied change by change.
    func connect(_ n: OpenConnectNetwork, policy: OpenConnectPolicy) -> Outcome {
        if let stop = interruption() { return fail(stop, interface: n.interface) }
        guard !OpenConnectJournal.exists(runDir: runDir) else { return fail("the network was set up already", interface: n.interface) }
        guard let index = system.interfaceIndex(n.interface) else { return fail("TUNDEV is not an existing interface", interface: n.interface) }
        let tunnel = Tunnel.index(index)
        guard var table = system.routes() else { return fail("the routing table cannot be read", interface: n.interface, tunnel: tunnel) }
        let underlay = OpenConnectPlan.Underlay(routes: table, attached: system.attachedNetworks(), tunnel: n.interface)
        let plan: OpenConnectPlan
        do {
            plan = try OpenConnectPlan.connect(n, policy: policy, underlay: underlay)
        } catch {
            return fail(String(describing: error), interface: n.interface, tunnel: tunnel)
        }
        let journal: OpenConnectJournal
        do {
            journal = try OpenConnectJournal.create(runDir: runDir, interface: n.interface)
        } catch {
            return fail("the network record cannot be written (\(error))", tunnel: tunnel)
        }
        let context = context(index: index, addresses: plan.addresses)
        if let failure = add(plan.changes, context: context, table: &table, journal: journal) {
            return fail(failure, journal: journal, tunnel: tunnel)
        }
        do {
            try journal.append(.status(.up))
        } catch {
            return fail("the network record cannot be written (\(error))", journal: journal, tunnel: tunnel)
        }
        return Outcome(lines: [VPNHook.Report(plan).line])
    }

    /// `attempt-reconnect`: the routes around the tunnel follow the default gateway as it is now.
    func attemptReconnect(_ n: OpenConnectNetwork, policy: OpenConnectPolicy) -> Outcome {
        if let stop = interruption() { return fail(stop, interface: n.interface) }
        let journal: OpenConnectJournal
        switch session(n) {
        case .failure(let reason): return fail(reason.text, interface: n.interface)
        case .success(let j): journal = j
        }
        guard let index = system.interfaceIndex(n.interface) else { return fail("TUNDEV is not an existing interface", journal: journal) }
        let tunnel = Tunnel.index(index)
        do {
            try journal.append(.status(.reconnecting))
        } catch {
            return fail("the network record cannot be written (\(error))", journal: journal, tunnel: tunnel)
        }
        var table = system.routes()
        guard let current = table else { return fail("the routing table cannot be read", journal: journal, tunnel: tunnel) }
        let underlay = OpenConnectPlan.Underlay(routes: current, attached: system.attachedNetworks(), tunnel: n.interface)
        let (remove, add) = OpenConnectPlan.refresh(n, policy: policy, underlay: underlay, record: journal.record)
        let claimed = OpenConnectRecord.claimed(by: sparing(journal.record))
        for change in remove {
            if let stop = interruption() { return fail(stop, journal: journal, tunnel: tunnel) }
            do {
                // Another live session uses it (the route to a server both connect to): it stays.
                if claimed.contains(change) {
                    try journal.append(.spared(change))
                    continue
                }
                if let failure = undo(change, index: index, table: &table) { return fail(failure, journal: journal, tunnel: tunnel) }
                try journal.append(.reverted(change))
            } catch {
                return fail("the network record cannot be written (\(error))", journal: journal, tunnel: tunnel)
            }
        }
        var rows = table ?? current
        let context = context(index: index, addresses: journal.record.applied.compactMap(Self.address))
        if let failure = self.add(add, context: context, table: &rows, journal: journal) {
            return fail(failure, journal: journal, tunnel: tunnel)
        }
        return Outcome()
    }

    /// `reconnect`: the network must be what the record holds, and the system must still have it (`verify`); it
    /// is checked, never repaired: any difference stops the session, and a new connection sets up afresh.
    func reconnect(_ n: OpenConnectNetwork, policy: OpenConnectPolicy) -> Outcome {
        if let stop = interruption() { return fail(stop, interface: n.interface) }
        let journal: OpenConnectJournal
        switch session(n) {
        case .failure(let reason): return fail(reason.text, interface: n.interface)
        case .success(let j): journal = j
        }
        guard let index = system.interfaceIndex(n.interface) else { return fail("TUNDEV is not an existing interface", journal: journal) }
        let tunnel = Tunnel.index(index)
        guard let table = system.routes() else { return fail("the routing table cannot be read", journal: journal, tunnel: tunnel) }
        let underlay = OpenConnectPlan.Underlay(routes: table, attached: system.attachedNetworks(), tunnel: n.interface)
        guard OpenConnectPlan.matches(n, policy: policy, underlay: underlay, record: journal.record) else {
            return fail("the server changed the network settings", journal: journal, tunnel: tunnel)
        }
        if let mismatch = verify(journal.record, index: index, table: table) {
            return fail("the network changed while the connection was re-established: " + mismatch, journal: journal, tunnel: tunnel)
        }
        do {
            try journal.append(.status(.up))
        } catch {
            return fail("the network record cannot be written (\(error))", journal: journal, tunnel: tunnel)
        }
        return Outcome(lines: [VPNHook.Report(OpenConnectPlan.build(n, policy: policy, underlay: underlay).plan).line])
    }

    /// `disconnect`: everything the record holds is reverted, but what another session holds.
    func disconnect() -> Outcome {
        let journal: OpenConnectJournal
        do {
            guard let j = try OpenConnectJournal.open(runDir: runDir) else { return Outcome() }
            journal = j
        } catch {
            return Outcome(lines: [VPNHook.revertFailureLine("the network record cannot be read")])
        }
        let failures = revert(journal, tunnel: .lookUp)
        return failures.isEmpty ? Outcome() : Outcome(lines: [VPNHook.revertFailureLine(failures[0])])
    }

    /// The session's record for a later run: there, for `n`'s interface, and set up.
    func session(_ n: OpenConnectNetwork) -> Result<OpenConnectJournal, ReasonText> {
        let journal: OpenConnectJournal?
        do {
            journal = try OpenConnectJournal.open(runDir: runDir)
        } catch {
            return .failure(ReasonText("the network record cannot be read"))
        }
        guard let journal, journal.record.interface == n.interface, journal.record.status == .up || journal.record.status == .reconnecting
        else { return .failure(ReasonText("the network was not set up")) }
        return .success(journal)
    }

    /// A failure's reason, as an `Error` for `Result`.
    struct ReasonText: Error, ExpressibleByStringLiteral {
        let text: String
        init(_ text: String) { self.text = text }
        init(stringLiteral value: String) { text = value }
    }

    /// Stops the set-up: reverts what the record holds (the one in `journal`, the one on disk, or none: a new
    /// one is made for `interface`, a checked name, so the helper finds the failure), with the tunnel interface
    /// as `tunnel` knows it, records the failure and gives its line.
    func fail(_ reason: String, interface: String? = nil, journal: OpenConnectJournal? = nil, tunnel: Tunnel = .lookUp) -> Outcome {
        var record = journal
        if record == nil { record = (try? OpenConnectJournal.open(runDir: runDir)) ?? nil }
        if record == nil, let interface, OpenConnectRecord.isInterface(interface) {
            record = try? OpenConnectJournal.create(runDir: runDir, interface: interface)
        }
        var lines: [String] = []
        if let record {
            let failures = revert(record, tunnel: tunnel)
            if let first = failures.first { lines.append(VPNHook.revertFailureLine(first)) }
            try? record.append(.status(.failed(VPNHook.oneLine(reason, maxBytes: OpenConnectRecord.maxReasonBytes))))
        }
        lines.append(VPNHook.failureLine(reason))
        return Outcome(lines: lines, stopTool: true)
    }

    /// Why no further change may be made: the helper is stopping the session, or the run's time is up.
    func interruption() -> String? {
        if OpenConnectMarks.isStopping(runDir: runDir) { return "the session is being stopped" }
        if now() >= deadline { return "the network set-up did not finish within \(Int(Self.runLimit)) seconds" }
        return nil
    }

    // MARK: - Applying

    /// What one run's changes are made with: the tunnel interface's index noted when it started, the tunnel's
    /// addresses (for DNS), the changes another session holds, the Mac's attached networks.
    struct Context {
        var index: UInt32
        var addresses: [IPAddress]
        var claimed: Set<Change>
        var attached: [OpenConnectPlan.Attached]
    }

    /// The context of a run on the tunnel interface with `index`. The changes other sessions hold come from
    /// the records that can be read: a change found there that only an unreadable record could hold counts as
    /// not PassTunnel's (`~`), which no session ever removes.
    func context(index: UInt32, addresses: [IPAddress]) -> Context {
        Context(
            index: index, addresses: addresses, claimed: OpenConnectRecord.claimed(by: otherRecords().records),
            attached: system.attachedNetworks())
    }

    /// What the system has of a change before it is made.
    enum Finding: Equatable {
        /// Not there: the hook makes it.
        case absent
        /// There as planned (an address, a route with exactly the planned next hop): `shared` when another live
        /// session holds it, otherwise it is not PassTunnel's.
        case there(shared: Bool)
        /// Something else is in the way: the set-up fails, and nothing of someone else's is replaced.
        case conflict(String)
    }

    /// How making a change went.
    enum Made: Equatable {
        case made
        /// Someone else made it meanwhile.
        case there(shared: Bool)
        case failed(String)
    }

    /// Applies `changes` in order: each is looked for first, under the lock. One there already is journaled as
    /// shared (`&`) or not PassTunnel's (`~`) and not made; one in the way of something else fails the set-up
    /// unjournaled; any other is journaled (`+`), made and journaled with its outcome. A crash leaves at most the
    /// change being made pending, never one the system had before. The reason of the first failure, nil when all
    /// were applied.
    func add(_ changes: [Change], context: Context, table: inout [KernelRoute], journal: OpenConnectJournal) -> String? {
        for change in changes {
            if let stop = interruption() { return stop }
            do {
                switch inspect(change, context: context, table: table) {
                case .conflict(let reason):
                    return reason
                case .there(let shared):
                    try journal.append(shared ? .shared(change) : .existed(change))
                    continue
                case .absent:
                    break
                }
                try journal.append(.begin(change))
                switch make(change, context: context, table: &table) {
                case .made: try journal.append(.owned(change))
                case .there(let shared): try journal.append(shared ? .shared(change) : .existed(change))
                case .failed(let reason):
                    try journal.append(.failed(change))
                    return reason
                }
            } catch {
                return "the network record cannot be written (\(error))"
            }
        }
        return nil
    }

    /// Looks for `change` on the system. `table` is the routing table as the run last read it, kept up to date
    /// with the routes added.
    func inspect(_ change: Change, context: Context, table: [KernelRoute]) -> Finding {
        switch change {
        case .link(let interface, _):
            return system.interfaceIndex(interface) == context.index ? .absent : .conflict(Self.interfaceGone)
        case .address(let interface, let address):
            guard system.interfaceIndex(interface) == context.index else { return .conflict(Self.interfaceGone) }
            return system.interfaceAddresses(interface).contains(address) ? .there(shared: false) : .absent
        case .route(let route):
            if case .interface(let interface) = route.via, system.interfaceIndex(interface) != context.index {
                return .conflict(Self.interfaceGone)
            }
            return Self.finding(route, in: table, claimed: context.claimed, attached: context.attached)
        case .dns:
            return .absent
        }
    }

    /// Makes `change`, which was not there.
    func make(_ change: Change, context: Context, table: inout [KernelRoute]) -> Made {
        switch change {
        case .link(let interface, let mtu):
            return run(.link(interface: interface, mtu: mtu)).map(Made.failed) ?? .made
        case .address(let interface, let address):
            guard let failure = run(.addAddress(interface: interface, address)) else { return .made }
            return system.interfaceAddresses(interface).contains(address) ? .there(shared: false) : .failed(failure)
        case .route(let route):
            if let failure = run(.addRoute(route)) {
                // Someone else may have made exactly this route meanwhile; anything else is a failure.
                if let fresh = system.routes() {
                    table = fresh
                    if fresh.contains(where: { $0.is(route) }) { return .there(shared: context.claimed.contains(change)) }
                }
                return .failed(failure)
            }
            table.append(KernelRoute(route))
            return .made
        case .dns(let dns):
            return system.setDNS(OpenConnectDNSSettings(dns, addresses: context.addresses))
                ? .made : .failed(system.dnsFailure ?? "the DNS settings could not be written")
        }
    }

    static let interfaceGone = "the tunnel interface went away"

    /// What `reconnect` checks: every change the session holds (its own and shared ones; not those it found
    /// there, which were never its) is still on the system exactly as made: the tunnel interface (the index noted
    /// when the run started, up, with its MTU) with its addresses, every route with its planned next hop, the DNS keys with their
    /// contents. The first difference, nil when there is none.
    func verify(_ record: OpenConnectRecord, index: UInt32, table: [KernelRoute]) -> String? {
        let addresses = record.applied.compactMap(Self.address)
        for change in record.held {
            switch change {
            case .link(let interface, let mtu):
                if system.interfaceIndex(interface) != index { return Self.interfaceGone }
                guard let link = system.interfaceLink(interface), link.mtu == mtu, link.up else {
                    return "\(interface) is no longer up with MTU \(mtu)"
                }
            case .address(let interface, let address):
                guard system.interfaceIndex(interface) == index, system.interfaceAddresses(interface).contains(address) else {
                    return "the address \(address) is no longer on \(interface)"
                }
            case .route(let route):
                if !table.contains(where: { $0.is(route) }) { return "the route for \(route.network) is no longer as it was set up" }
            case .dns(let dns):
                if !system.hasDNS(OpenConnectDNSSettings(dns, addresses: addresses)) {
                    return "the DNS settings are no longer as they were set up"
                }
            }
        }
        return nil
    }

    /// What the routes in `table` mean for `route`: absent when no route holds its destination; there when one
    /// has exactly the planned next hop (the same interface, the same gateway on its interface, a reject route),
    /// shared when another session holds it (`claimed`); there as well for a route around the tunnel (an
    /// exclude) whose destination is a network the Mac is attached to, held by that network's own on-link route
    /// (that traffic leaves outside every tunnel already). Any other route in the way is a conflict: traffic the
    /// set-up would claim goes elsewhere (another VPN, another gateway), and the hook replaces nobody's route.
    static func finding(
        _ route: OpenConnectPlan.Route, in table: [KernelRoute], claimed: Set<Change>, attached: [OpenConnectPlan.Attached]
    ) -> Finding {
        let held = table.filter { $0.network == route.network && $0.holdsDestination }
        guard let first = held.first else { return .absent }
        if held.contains(where: { $0.is(route) }) { return .there(shared: claimed.contains(.route(route))) }
        if case .gateway = route.via,
            held.allSatisfy({ entry in
                entry.gateway == nil && !entry.reject && attached.contains(OpenConnectPlan.Attached(route.network, interface: entry.interface))
            })
        {
            return .there(shared: false)
        }
        let through = first.reject ? "a reject route" : first.gateway.map { "through \($0) \(first.interface)" } ?? "through \(first.interface)"
        return .conflict("another route for \(route.network) exists already, \(through)")
    }

    static func address(_ change: Change) -> IPAddress? {
        if case .address(_, let address) = change { return address }
        return nil
    }

    /// Runs the command that makes `effect` on this system (`OpenConnectCommand.Tools`) for at most `toolLimit`
    /// and what is left of the run; the reason it failed, nil when it succeeded.
    func run(_ effect: OpenConnectCommand.Effect) -> String? {
        let command = OpenConnectCommand(effect, tools: system.tools)
        let left = deadline.timeIntervalSince(now())
        guard left > 0 else { return "no time was left for \(command.line)" }
        let result = system.run(command, timeout: min(Self.toolLimit, left))
        return result.succeeded ? nil : "\(command.line) failed (\(result.summary))"
    }

    // MARK: - Reverting

    /// What a revert knows of the tunnel interface, which its link, its addresses and the routes through it
    /// belong to.
    enum Tunnel: Equatable {
        /// Its index, noted when the run started: only an interface of that name with that index is the
        /// session's.
        case index(UInt32)
        /// Looked up now: openconnect still holds it while it runs the hook for `disconnect`.
        case lookUp
        /// Gone with the tool (the helper, after the tool ended): nothing is done to an interface of that name,
        /// which may be another session's by now.
        case gone
    }

    /// Reverts what `journal` holds (`OpenConnectRecord.beginRevert(sparing:)` with the other sessions'
    /// records), newest first, each journaled once undone; the reasons of the changes that could not be undone.
    /// What belongs to the tunnel interface is undone only on the interface `tunnel` names; once that has gone,
    /// so have its link, its addresses and the routes through it.
    func revert(_ journal: OpenConnectJournal, tunnel: Tunnel) -> [String] {
        let index: UInt32?
        switch tunnel {
        case .index(let noted): index = noted
        case .lookUp: index = system.interfaceIndex(journal.record.interface)
        case .gone: index = nil
        }
        let undo: [Change]
        do {
            undo = try journal.beginRevert(sparing: sparing(journal.record))
        } catch {
            return ["the network record cannot be written (\(error))"]
        }
        guard !undo.isEmpty else { return [] }
        var table = system.routes()
        var failures: [String] = []
        for change in undo {
            guard now() < deadline else {
                failures.append("restoring the network did not finish within \(Int(Self.runLimit)) seconds")
                break
            }
            if let failure = self.undo(change, index: index, table: &table) {
                failures.append(failure)
                continue
            }
            // Fails only while a change before it in the revert could not be undone (it stays pending);
            // undoing again later finds this one gone.
            try? journal.append(.reverted(change))
        }
        return failures
    }

    /// Undoes one change: nil when it is gone (also when it already was, or is no longer what the session made:
    /// a route of that destination through another next hop, an interface of that name other than the one with
    /// `index`; nil `index`: the tunnel interface has gone).
    func undo(_ change: Change, index: UInt32?, table: inout [KernelRoute]?) -> String? {
        func isTunnel(_ name: String) -> Bool { index != nil && system.interfaceIndex(name) == index }
        switch change {
        case .link(let interface, _):
            guard isTunnel(interface) else { return nil }
            return run(.linkDown(interface: interface))
        case .address(let interface, let address):
            guard isTunnel(interface), system.interfaceAddresses(interface).contains(address) else { return nil }
            guard let failure = run(.deleteAddress(interface: interface, address)) else { return nil }
            return system.interfaceAddresses(interface).contains(address) ? failure : nil
        case .route(let route):
            if case .interface(let interface) = route.via, !isTunnel(interface) { return nil }
            if table == nil { table = system.routes() }
            guard let current = table else { return "the routing table cannot be read" }
            guard current.contains(where: { $0.is(route) }) else { return nil }
            if let failure = run(.deleteRoute(route)) {
                table = system.routes()
                if let fresh = table, !fresh.contains(where: { $0.is(route) }) { return nil }
                return failure
            }
            table = current.filter { !$0.is(route) }
            return nil
        case .dns(let dns):
            return system.removeDNS(service: dns.service) ? nil : "the DNS settings could not be removed"
        }
    }

    /// The records of the other sessions of the run root, read under the lock, and whether one of them could
    /// not be read. Not only those whose tool still runs: a session that ended holds what its record holds until
    /// its revert has run (the helper's, after the tool exited), so a session that connects meanwhile shares a
    /// route it finds there (`&`) rather than taking it for nobody's, and that revert spares it.
    func otherRecords() -> (records: [OpenConnectRecord], unreadable: Bool) {
        var out: [OpenConnectRecord] = []
        var unreadable = false
        for uid in Self.entries(runRoot) where UInt32(uid).map({ String($0) == uid }) ?? false {
            for id in Self.entries(runRoot + "/" + uid) where HelperCore.isValidProfileID(id) {
                let dir = runRoot + "/" + uid + "/" + id
                guard dir != runDir else { continue }
                do {
                    if let record = try OpenConnectJournal.read(OpenConnectJournal.path(runDir: dir)) { out.append(record) }
                } catch {
                    unreadable = true
                }
            }
        }
        return (out, unreadable)
    }

    /// The records a revert of `own` spares: the other sessions', and when one of them cannot be read, a
    /// record that holds every change of `own` two sessions can share (routes around the tunnel, reject
    /// routes): nothing is taken from under a running session.
    func sparing(_ own: OpenConnectRecord) -> [OpenConnectRecord] {
        let others = otherRecords()
        guard others.unreadable, let claim = Self.claimingShared(own) else { return others.records }
        return others.records + [claim]
    }

    /// A record that holds every change of `own` another session could hold too.
    static func claimingShared(_ own: OpenConnectRecord) -> OpenConnectRecord? {
        guard var claim = OpenConnectRecord(interface: own.interface) else { return nil }
        for change in own.states.keys where isShareable(change) { try? claim.append(.shared(change)) }
        return claim
    }

    /// A change two sessions can both need: a route around the tunnel, a reject route.
    static func isShareable(_ change: Change) -> Bool {
        guard case .route(let route) = change else { return false }
        if case .interface = route.via { return false }
        return true
    }

    static func entries(_ dir: String) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
    }

    // MARK: - The helper's revert

    /// How the helper's revert of an ended session went.
    public enum Restore: Equatable {
        /// Nothing is left to undo (or there was no record): the session directory can go.
        case done
        /// Some change could not be undone: the record stays, and the helper tries again.
        case failed(String)
        /// The record cannot be read: nothing can be undone from it.
        case unreadable
    }

    /// The helper's revert once a session's tool has ended (docs/ARCHITECTURE.md, "The hook", step 7): marks
    /// the session as stopping, waits for a hook still running to end (the lock; `killHook` after `runLimit`
    /// and a second), then, under the lock, reverts what the record holds but what another session holds.
    /// The tunnel interface has gone with the tool, and with it its link, its addresses and the routes through
    /// it; the routes around the tunnel, the reject routes and the DNS keys have not.
    public static func restoreAfterExit(
        runRoot: String, runDir: String, system: OpenConnectSystem, killHook: () -> Void,
        now: @escaping () -> Date = Date.init
    ) -> Restore {
        guard OpenConnectJournal.exists(runDir: runDir) else { return .done }
        OpenConnectMarks.setStopping(runDir: runDir)
        var lock = OpenConnectLock.acquire(runRoot: runRoot, until: now().addingTimeInterval(runLimit + 2), now: now)
        if lock == nil {
            killHook()
            lock = OpenConnectLock.acquire(runRoot: runRoot, until: now().addingTimeInterval(2), now: now)
        }
        guard let lock else { return .failed("the network lock was not free") }
        defer { withExtendedLifetime(lock) {} }
        var hook = OpenConnectHook(runRoot: runRoot, runDir: runDir, system: system, deadline: now().addingTimeInterval(runLimit))
        hook.now = now
        let journal: OpenConnectJournal
        do {
            guard let j = try OpenConnectJournal.open(runDir: runDir) else { return .done }
            journal = j
        } catch {
            return .unreadable
        }
        let failures = hook.revert(journal, tunnel: .gone)
        return failures.first.map(Restore.failed) ?? .done
    }

    /// Removes everything in a session directory but its record: what a revert that failed leaves for the
    /// next try (the configuration with its cookie, the policy, the state and the marks go now).
    public static func keepOnlyRecord(runDir: String) {
        for entry in entries(runDir) where entry != OpenConnectRecord.fileName {
            HelperCore.removeEntry(runDir + "/" + entry)
        }
    }
}
