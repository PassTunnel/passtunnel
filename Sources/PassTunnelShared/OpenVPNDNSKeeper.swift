import Foundation

/// The helper's account of OpenVPN sessions' DNS once their tool has ended (docs/ARCHITECTURE.md, "DNS script
/// (macOS)"): settling a session (`settle`, under OpenVPN's script lock), what is still to settle and why
/// (`pending`), the retries, what a start of a profile waits for (`beforeStart`), and where every note goes:
/// into the log of the session it is about, and nowhere else. The helper's `Supervisor` holds one and calls it on
/// its queue; the tests run it against a fake system, a fake lock and fake logs.
public final class OpenVPNDNSKeeper {
    public typealias Key = SessionPolicy.Key

    public enum Pending: Equatable, Sendable {
        /// The check ran and could not finish: tried again, and a start of the profile waits.
        case failed
        /// Something waits for a tunnel that is there (`OpenVPNDNS.Settlement.Outcome.parked`): tried again; a start
        /// of the profile goes ahead and carries the record into its session directory.
        case parked
        /// OpenVPN's script lock could not be had, so the check did not run: tried again, and like `parked` it never
        /// holds a start up (anyone can hold or fill the lock file).
        case lockBusy
    }

    public enum Start: Equatable, Sendable {
        case proceed
        case refuse(String)
    }

    public let runRoot: String
    let system: OpenVPNDNSSystem
    /// OpenVPN's script lock (`ScriptLock`), waited for a short, bounded time; nil when it could not be had. Taken
    /// at most once per event (a session's end, a start, a retry), for every session that event checks together.
    let lock: () -> ScriptLock.Held?
    /// Appends a line to the log a session directory's owner file names (the helper: `HelperCore.appendToLog`).
    let appendToLog: (_ key: Key, _ owner: HelperCore.DNSOwner, _ line: String) -> Void
    /// The helper's own log.
    let report: (String) -> Void
    public private(set) var pending: [Key: Pending] = [:]
    /// Records carried over a start of their profile (`beforeStart`) until `carry(into:)` writes them.
    private var carrying: [Key: (record: String, result: String?)] = [:]

    public init(
        runRoot: String, system: OpenVPNDNSSystem, lock: @escaping () -> ScriptLock.Held?,
        appendToLog: @escaping (Key, HelperCore.DNSOwner, String) -> Void, report: @escaping (String) -> Void
    ) {
        self.runRoot = runRoot
        self.system = system
        self.lock = lock
        self.appendToLog = appendToLog
        self.report = report
    }

    public func runDir(_ key: Key) -> String { PT.sessionDir(uid: key.uid, profileID: key.profileID, runRoot: runRoot) }

    /// Why a start of a profile is refused while its last session's DNS check ran and could not finish.
    public static let stillRestoringMessage =
        "The DNS settings of this profile's last OpenVPN session are still being restored, so it cannot connect yet. Try again shortly; if this keeps happening, restarting the Mac clears it."

    /// One event's use of the lock: asked for once, the first time a check needs it, and given back at the end.
    final class LockRound {
        private let take: () -> ScriptLock.Held?
        private var asked = false
        private var held: ScriptLock.Held?

        init(_ take: @escaping () -> ScriptLock.Held?) { self.take = take }

        var lock: ScriptLock.Held? {
            if !asked {
                asked = true
                held = take()
            }
            return held
        }

        func end() {
            held?.release()
            held = nil
        }
    }

    // MARK: Settling

    /// Settles the session of `key`, whose directory is `runDir`, once its tool has ended: each of its records (its
    /// own, and one carried over its start), under the script's lock. `live`: the directories of the sessions still
    /// running. `sink`: where its notes go while the helper holds the session's log open; nil, appended to the log
    /// its owner file names. True when nothing is left to do (also without a record, or with one that cannot be
    /// read: nothing then shows what it set); false while something is (`pending`), and the records stay.
    @discardableResult
    public func settle(_ key: Key, runDir: String, live: [String], sink: ((OpenVPNDNS.Note) -> Void)? = nil) -> Bool {
        let round = LockRound(lock)
        defer { round.end() }
        return settle(key, runDir: runDir, live: live, sink: sink, round: round)
    }

    func settle(_ key: Key, runDir: String, live: [String], sink: ((OpenVPNDNS.Note) -> Void)?, round: LockRound) -> Bool {
        func say(_ note: OpenVPNDNS.Note) {
            if let sink {
                sink(note)
            } else if let owner = HelperCore.dnsOwner(runDir: runDir) {
                appendToLog(key, owner, note.line + "\n")
            }
        }
        var records: [(HelperCore.DNSSlot, OpenVPNDNSRecord)] = []
        for slot in HelperCore.DNSSlot.allCases {
            do {
                if let record = try HelperCore.dnsRecord(runDir: runDir, slot: slot) { records.append((slot, record)) }
            } catch {
                report("not checking the DNS of \(key.profileID) of uid \(key.uid): \(error)")
                HelperCore.removeDNSSlot(runDir: runDir, slot)
            }
        }
        guard !records.isEmpty else {
            pending[key] = nil
            return true
        }
        guard round.lock != nil else {
            report("checking the DNS of \(key.profileID) of uid \(key.uid): OpenVPN's DNS script lock is held; trying again")
            pending[key] = .lockBusy
            return false
        }
        let running = live.compactMap { dir -> OpenVPNDNSRecord? in
            HelperCore.dnsDownRan(runDir: dir) ? nil : (try? HelperCore.dnsRecord(runDir: dir)).flatMap { $0 }
        }
        var state: Pending?
        for (slot, record) in records {
            let s = OpenVPNDNS.settle(record, live: running, system: system)
            for r in s.restored {
                report("gave \(r.service) its DNS back after \(key.profileID) of uid \(key.uid): it still used \(r.settings.joined(separator: " "))")
                say(OpenVPNDNS.Note(.restored, service: r.service, settings: r.settings))
            }
            for line in s.reports { report("\(key.profileID) of uid \(key.uid): \(line)") }
            switch s.outcome {
            case .done:
                // Whichever slot: a record that is done is never looked at again.
                HelperCore.removeDNSSlot(runDir: runDir, slot)
            case .parked:
                state = state ?? .parked
            case .failed(let reason):
                report("checking the DNS of \(key.profileID) of uid \(key.uid) failed: \(reason); trying again")
                for r in s.left { say(OpenVPNDNS.Note(.notRestored, service: r.service, settings: r.settings, reason: reason)) }
                state = .failed
            }
        }
        pending[key] = state
        return state == nil
    }

    /// After a session's tool ended and `settle` answered: the directory goes when its network (`networkRestored`)
    /// and its DNS (`settled`) are back; while only the DNS is not, only its records, marks and owner stay
    /// (`HelperCore.keepOnlyDNSRecord`: the configuration and the auth file go now). While the network is not
    /// back, its own revert has kept what it needs already.
    public static func cleanUp(runDir: String, settled: Bool, networkRestored: Bool) {
        guard networkRestored else { return }
        if settled { HelperCore.removeEntry(runDir) } else { HelperCore.keepOnlyDNSRecord(runDir: runDir) }
    }

    /// Settles again every session in `pending` whose profile is not running (`isRunning`): every 15 s, and before
    /// every start, all under one use of the lock (one bounded wait for the whole event, never one per session).
    /// The notes of `holding` (the profile being started, whose log is about to be made anew) go to `collect`;
    /// every other session's go to its own log.
    public func retry(
        live: [String], isRunning: (Key) -> Bool, holding: Key? = nil, collect: @escaping (OpenVPNDNS.Note) -> Void = { _ in }
    ) {
        let round = LockRound(lock)
        defer { round.end() }
        for key in pending.keys.sorted(by: { ($0.uid, $0.profileID) < ($1.uid, $1.profileID) }) where !isRunning(key) {
            let dir = runDir(key)
            if settle(key, runDir: dir, live: live, sink: key == holding ? collect : nil, round: round) {
                HelperCore.removeEntry(dir)
                report("settled the DNS of \(key.profileID) of uid \(key.uid)")
            }
        }
    }

    /// Before a start of `key`'s profile: every pending session is tried again first (a dns-up of the new session
    /// would back up whatever the primary service has). Refused only when the check of its last session ran and
    /// failed. `parked`, or the lock not had (`lockBusy`): the start goes ahead, and the record is carried into the
    /// new session directory (`carry(into:)`), so what it set stays attributable. The notes of `key`'s own last
    /// session come back to be written into the new log.
    public func beforeStart(_ key: Key, live: [String], isRunning: (Key) -> Bool) -> (start: Start, notes: [OpenVPNDNS.Note]) {
        var notes: [OpenVPNDNS.Note] = []
        retry(live: live, isRunning: isRunning, holding: key) { notes.append($0) }
        switch pending[key] {
        case .failed?:
            return (.refuse(Self.stillRestoringMessage), notes)
        case .parked?, .lockBusy?:
            let dir = runDir(key)
            let own = (try? HelperCore.dnsRecordTexts(runDir: dir, slot: .current)) ?? nil
            let older = (try? HelperCore.dnsRecordTexts(runDir: dir, slot: .carried)) ?? nil
            if let texts = own ?? older { carrying[key] = texts }
            if own != nil && older != nil {
                report("starting \(key.profileID) of uid \(key.uid): of two pending records only the newer one is carried")
            }
            pending[key] = nil
            return (.proceed, notes)
        case nil:
            return (.proceed, notes)
        }
    }

    /// Writes what `beforeStart` carried for `key` into its new session directory, and keeps it pending, so that the
    /// next check (at the session's end, or a retry) settles it.
    public func carry(into runDir: String, key: Key) {
        guard let texts = carrying.removeValue(forKey: key) else { return }
        do {
            try HelperCore.writeCarriedDNSRecord(runDir: runDir, record: texts.record, result: texts.result)
        } catch {
            report("could not carry the DNS record of \(key.profileID) of uid \(key.uid): \(error)")
        }
    }

    /// A start of `key` that `beforeStart` let go ahead failed. A record it carried stays pending: still in the old
    /// directory when the start failed before making a new one, else written back into a directory of its own (the
    /// failed start removed the one it made); a record `carry(into:)` wrote into `runDir` stays there with only what
    /// `keepOnlyDNSRecord` keeps. True when the directory is to be removed as before (nothing of the DNS in it).
    public func startFailed(_ key: Key, runDir: String) -> Bool {
        if let texts = carrying.removeValue(forKey: key) {
            let hasRecord = HelperCore.DNSSlot.allCases.contains { (try? HelperCore.dnsRecordTexts(runDir: runDir, slot: $0)) != nil }
            if !hasRecord {
                do {
                    try HelperCore.ensureRootOwnedDir(runRoot)
                    try HelperCore.ensureRootOwnedDir(runRoot + "/\(key.uid)")
                    if mkdir(runDir, 0o700) != 0, errno != EEXIST { throw HelperCore.Failure.system("mkdir \(runDir)", errno) }
                    _ = chmod(runDir, HelperCore.runDirMode)
                    try HelperCore.writeCarriedDNSRecord(runDir: runDir, record: texts.record, result: texts.result)
                } catch {
                    report("could not keep the DNS record of \(key.profileID) of uid \(key.uid): \(error)")
                    return true
                }
            }
            pending[key] = .parked
            HelperCore.keepOnlyDNSRecord(runDir: runDir)
            return false
        }
        guard (try? HelperCore.dnsRecordTexts(runDir: runDir, slot: .carried)) != nil else { return true }
        pending[key] = .parked
        HelperCore.keepOnlyDNSRecord(runDir: runDir)
        return false
    }

    /// Session directories with a record whose tool is gone, found when the helper starts (`adoptOrphans`), settled
    /// once every running session is adopted (`live`), so that what one of those set is never taken for theirs.
    public func settleOrphans(_ dirs: [(key: Key, path: String)], live: [String]) {
        let round = LockRound(lock)
        defer { round.end() }
        for (key, dir) in dirs {
            Self.cleanUp(runDir: dir, settled: settle(key, runDir: dir, live: live, sink: nil, round: round), networkRestored: true)
        }
    }

    // MARK: Left behind

    /// Before an OpenVPN start: a VPN's DNS the script set with no session to undo it (`OpenVPNDNS.leftBehind`),
    /// but on a service a pending session's record names (that one is still being settled), reported in the helper's
    /// log and returned as notes for the new session's log. Never changed.
    public func leftBehindNotes(before key: Key) -> [OpenVPNDNS.Note] {
        guard let found = OpenVPNDNS.leftBehind(system: system), !found.isEmpty else { return [] }
        let claimed = Set(
            pending.keys.flatMap { pendingKey -> [String] in
                HelperCore.DNSSlot.allCases.compactMap { (try? HelperCore.dnsRecord(runDir: runDir(pendingKey), slot: $0))??.service }
            })
        return found.filter { !claimed.contains($0.serviceID) }.map { item in
            report(
                "before \(key.profileID) of uid \(key.uid): \(item.service) still uses \(item.settings.joined(separator: " ")), set by OpenVPN's DNS script with no session to undo it; left as it is"
            )
            return OpenVPNDNS.Note(.leftBehind, service: item.service, settings: item.settings)
        }
    }
}
