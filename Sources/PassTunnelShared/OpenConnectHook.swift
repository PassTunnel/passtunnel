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
/// - `disconnect`: everything the record holds is reverted, but what another live session holds.
///
/// A route that is there already is the session's only if it added it: the same route (or any route of that
/// destination, for a route around the tunnel or one of the server's routes into it) is recorded as there
/// already (`~`) and never removed; but a full tunnel's half (`0/1`, `128/1`, `::/1`, `8000::/1`) or a reject
/// route that finds another route of its destination fails the set-up: another tunnel holds that traffic.
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
    /// Whether a session directory holds a tool that still runs (its `state` names a live process).
    public let isLive: (String) -> Bool
    /// The pid and start time the `hook` mark records.
    public let identity: (pid: pid_t, start: ProcessStart?)
    public var now: () -> Date = Date.init

    public init(
        runRoot: String, runDir: String, system: OpenConnectSystem, deadline: Date, isLive: @escaping (String) -> Bool,
        identity: (pid: pid_t, start: ProcessStart?) = (getpid(), nil)
    ) {
        self.runRoot = runRoot
        self.runDir = runDir
        self.system = system
        self.deadline = deadline
        self.isLive = isLive
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

    /// `body` under the run root's lock, with the `hook` mark set while it runs.
    func locked(reverting: Bool, _ body: () -> Outcome) -> Outcome {
        guard let lock = OpenConnectLock.acquire(runRoot: runRoot, until: deadline, now: now) else {
            let reason = "the network lock was not free within \(Int(Self.runLimit)) seconds"
            return reverting ? Outcome(lines: [VPNHook.revertFailureLine(reason)]) : Outcome(lines: [VPNHook.failureLine(reason)], stopTool: true)
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
        guard let index = system.interfaceIndex(n.interface) else { return fail("TUNDEV is not an interface of this Mac", interface: n.interface) }
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
        if let failure = add(plan.changes, addresses: plan.addresses, index: index, table: &table, journal: journal) {
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
        guard let index = system.interfaceIndex(n.interface) else { return fail("TUNDEV is not an interface of this Mac", journal: journal) }
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
        let claimed = Self.claimed(by: otherRecords(own: journal.record))
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
        if let failure = self.add(add, addresses: journal.record.applied.compactMap(Self.address), index: index, table: &rows, journal: journal) {
            return fail(failure, journal: journal, tunnel: tunnel)
        }
        return Outcome()
    }

    /// `reconnect`: nothing changes, but the network must be what the record holds.
    func reconnect(_ n: OpenConnectNetwork, policy: OpenConnectPolicy) -> Outcome {
        if let stop = interruption() { return fail(stop, interface: n.interface) }
        let journal: OpenConnectJournal
        switch session(n) {
        case .failure(let reason): return fail(reason.text, interface: n.interface)
        case .success(let j): journal = j
        }
        guard let index = system.interfaceIndex(n.interface) else { return fail("TUNDEV is not an interface of this Mac", journal: journal) }
        let tunnel = Tunnel.index(index)
        guard let table = system.routes() else { return fail("the routing table cannot be read", journal: journal, tunnel: tunnel) }
        let underlay = OpenConnectPlan.Underlay(routes: table, attached: system.attachedNetworks(), tunnel: n.interface)
        guard OpenConnectPlan.matches(n, policy: policy, underlay: underlay, record: journal.record) else {
            return fail("the server changed the network settings", journal: journal, tunnel: tunnel)
        }
        do {
            try journal.append(.status(.up))
        } catch {
            return fail("the network record cannot be written (\(error))", journal: journal, tunnel: tunnel)
        }
        return Outcome(lines: [VPNHook.Report(OpenConnectPlan.build(n, policy: policy, underlay: underlay).plan).line])
    }

    /// `disconnect`: everything the record holds is reverted, but what another live session holds.
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

    enum Applied: Equatable {
        case owned, existed
        case failed(String)
    }

    /// Applies `changes` in order, each journaled first and with its outcome after; the reason of the first
    /// failure, nil when all were applied.
    func add(_ changes: [Change], addresses: [IPAddress], index: UInt32, table: inout [KernelRoute], journal: OpenConnectJournal) -> String? {
        for change in changes {
            if let stop = interruption() { return stop }
            do {
                try journal.append(.begin(change))
                switch apply(change, addresses: addresses, index: index, table: &table) {
                case .owned: try journal.append(.owned(change))
                case .existed: try journal.append(.existed(change))
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

    /// Makes one change. `table` is the routing table as the run last read it, kept up to date with the
    /// routes added.
    func apply(_ change: Change, addresses: [IPAddress], index: UInt32, table: inout [KernelRoute]) -> Applied {
        switch change {
        case .link(let interface, let mtu):
            guard system.interfaceIndex(interface) == index else { return .failed(Self.interfaceGone) }
            return run(.link(interface, mtu: mtu)).map(Applied.failed) ?? .owned
        case .address(let interface, let address):
            guard system.interfaceIndex(interface) == index else { return .failed(Self.interfaceGone) }
            if system.interfaceAddresses(interface).contains(address) { return .existed }
            return run(.addAddress(interface, address)).map(Applied.failed) ?? .owned
        case .route(let route):
            if case .interface(let interface) = route.via, system.interfaceIndex(interface) != index { return .failed(Self.interfaceGone) }
            if let found = Self.existing(route, in: table) { return found }
            if let failure = run(.addRoute(route)) {
                // Someone else's route may have come in between: then it counts as there already.
                if let fresh = system.routes() {
                    table = fresh
                    if let found = Self.existing(route, in: fresh) { return found }
                }
                return .failed(failure)
            }
            table.append(KernelRoute(route))
            return .owned
        case .dns(let dns):
            return system.setDNS(OpenConnectDNSSettings(dns, addresses: addresses)) ? .owned : .failed("the DNS settings could not be written")
        }
    }

    static let interfaceGone = "the tunnel interface went away"

    /// What a route already in `table` means for adding `route`: nil when no route holds its destination;
    /// `existed` for the same route, or another one where the session can do without its own (a route around
    /// the tunnel, a route of the server's into it); a failure for a full tunnel's half or a reject route, which
    /// the set-up needs as it planned them.
    static func existing(_ route: OpenConnectPlan.Route, in table: [KernelRoute]) -> Applied? {
        let held = table.filter { $0.network == route.network && $0.holdsDestination }
        guard !held.isEmpty else { return nil }
        if held.contains(where: { $0.is(route) }) { return .existed }
        if isRequired(route) { return .failed("another route for \(route.network) exists already (another VPN?)") }
        return .existed
    }

    /// A route the set-up needs as planned: a full tunnel's half, or a reject route.
    static func isRequired(_ route: OpenConnectPlan.Route) -> Bool {
        switch route.via {
        case .reject: return true
        case .interface: return IPNetwork.halves(route.network.family).contains(route.network)
        case .gateway: return false
        }
    }

    static func address(_ change: Change) -> IPAddress? {
        if case .address(_, let address) = change { return address }
        return nil
    }

    /// Runs `command` for at most `toolLimit` and what is left of the run; the reason it failed, nil when it
    /// succeeded.
    func run(_ command: OpenConnectCommand) -> String? {
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

    /// Reverts what `journal` holds (`OpenConnectRecord.beginRevert(sparing:)` with the other live sessions'
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
            undo = try journal.beginRevert(sparing: otherRecords(own: journal.record))
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
            return run(.linkDown(interface))
        case .address(let interface, let address):
            guard isTunnel(interface), system.interfaceAddresses(interface).contains(address) else { return nil }
            guard let failure = run(.deleteAddress(interface, address)) else { return nil }
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

    /// The records of the other sessions of the run root whose tool still runs, read under the lock. One that
    /// cannot be read counts as holding every change of `own` two sessions can share (routes around the
    /// tunnel, reject routes): nothing is taken from under a running session.
    func otherRecords(own: OpenConnectRecord) -> [OpenConnectRecord] {
        var out: [OpenConnectRecord] = []
        for uid in Self.entries(runRoot) where UInt32(uid).map({ String($0) == uid }) ?? false {
            for id in Self.entries(runRoot + "/" + uid) where HelperCore.isValidProfileID(id) {
                let dir = runRoot + "/" + uid + "/" + id
                guard dir != runDir, isLive(dir) else { continue }
                do {
                    if let record = try OpenConnectJournal.read(OpenConnectJournal.path(runDir: dir)) { out.append(record) }
                } catch {
                    if let claim = Self.claimingShared(own) { out.append(claim) }
                }
            }
        }
        return out
    }

    /// A record that holds every change of `own` another session could hold too.
    static func claimingShared(_ own: OpenConnectRecord) -> OpenConnectRecord? {
        guard var claim = OpenConnectRecord(interface: own.interface) else { return nil }
        for change in own.states.keys where isShareable(change) {
            try? claim.append(.begin(change))
            try? claim.append(.existed(change))
        }
        return claim
    }

    /// A change two sessions can both need: a route around the tunnel, a reject route.
    static func isShareable(_ change: Change) -> Bool {
        guard case .route(let route) = change else { return false }
        if case .interface = route.via { return false }
        return true
    }

    /// Every change another session holds: its own, pending or there already.
    static func claimed(by others: [OpenConnectRecord]) -> Set<Change> {
        var out = Set<Change>()
        for other in others {
            for (change, state) in other.states where state == .owned || state == .pending || state == .existed { out.insert(change) }
        }
        return out
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
    /// and a second), then, under the lock, reverts what the record holds but what another live session holds.
    /// The tunnel interface has gone with the tool, and with it its link, its addresses and the routes through
    /// it; the routes around the tunnel, the reject routes and the DNS keys have not.
    public static func restoreAfterExit(
        runRoot: String, runDir: String, system: OpenConnectSystem, isLive: @escaping (String) -> Bool, killHook: () -> Void,
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
        var hook = OpenConnectHook(runRoot: runRoot, runDir: runDir, system: system, deadline: now().addingTimeInterval(runLimit), isLive: isLive)
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
