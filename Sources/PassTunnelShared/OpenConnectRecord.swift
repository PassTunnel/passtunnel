import Foundation

/// The hook's record of what it changed for a session (`network` in the session directory, 0600, root),
/// docs/ARCHITECTURE.md, "The hook", steps 4–7. A journal, one entry per line: every change is written
/// before it is made (`+`) and its outcome after (`=` the session's own, `!` it failed and nothing was
/// changed), a revert after it succeeded (`-`), and the set-up's outcome (`status`). A change the hook finds
/// there already is journaled without a `+`, since nothing is made: `&` when another session of the run
/// root holds it as its own or shared (the two share it, and the last one of them to end removes it), `~`
/// when no session does (it is not PassTunnel's and is never removed); either can also be the outcome of a
/// change begun when someone else made it meanwhile. A change that was begun and has no outcome (the hook was killed during it)
/// may have been made, so it is reverted like one of the session's own, unless another session's record
/// lists the same change (`toRevert(sparing:)`). Reverting is idempotent: a change already gone counts as
/// reverted.
///
///     passtunnel-network 1
///     interface utun5
///     + link utun5 mtu 1400
///     = link utun5 mtu 1400
///     + route 0.0.0.0/1 interface utun5
///     = route 0.0.0.0/1 interface utun5
///     status up
///
/// Strict, like `policy`: the header, then `interface`, then entries whose changes parse again
/// (`OpenConnectPlan.Change(text:)`) in the order the journal allows (`append`); anything else is refused
/// as a whole.
public struct OpenConnectRecord: Equatable, Sendable {
    public typealias Change = OpenConnectPlan.Change

    public static let fileName = "network"
    public static let header = "passtunnel-network 1"
    /// Larger files are not read (with every list at its limit a set-up is about 0.5 MiB; `compacted`
    /// keeps a long session's record small).
    public static let maxBytes = 4 << 20
    /// The longest reason of a failure kept.
    public static let maxReasonBytes = 300

    /// The set-up's outcome, latest last.
    public enum Status: Equatable, Sendable {
        case up
        /// Why, as one line of printable ASCII (`VPNHook.oneLine`).
        case failed(String)
        /// openconnect is re-establishing the connection (`attempt-reconnect`); `up` again after `reconnect`.
        case reconnecting
    }

    public enum Entry: Equatable, Sendable {
        case begin(Change)
        case owned(Change)
        /// There already, held by another session: shared with it.
        case shared(Change)
        /// There already, held by no session: never removed.
        case existed(Change)
        case failed(Change)
        case reverted(Change)
        /// Left in place at the revert: another session holds it (`beginRevert(sparing:)`).
        case spared(Change)
        case status(Status)

        var text: String {
            switch self {
            case .begin(let c): return "+ " + c.text
            case .owned(let c): return "= " + c.text
            case .shared(let c): return "& " + c.text
            case .existed(let c): return "~ " + c.text
            case .failed(let c): return "! " + c.text
            case .reverted(let c): return "- " + c.text
            case .spared(let c): return "? " + c.text
            case .status(.up): return "status up"
            case .status(.reconnecting): return "status reconnecting"
            case .status(.failed(let reason)): return "status failed " + reason
            }
        }

        init?(text: String) {
            if text.hasPrefix("status ") {
                let rest = text.dropFirst("status ".count)
                switch rest {
                case "up": self = .status(.up)
                case "reconnecting": self = .status(.reconnecting)
                default:
                    guard rest.hasPrefix("failed ") else { return nil }
                    let reason = String(rest.dropFirst("failed ".count))
                    guard OpenConnectRecord.isReason(reason) else { return nil }
                    self = .status(.failed(reason))
                }
                return
            }
            guard text.utf8.count > 2, text.dropFirst().hasPrefix(" "), let change = Change(text: String(text.dropFirst(2))) else {
                return nil
            }
            switch text.first {
            case "+": self = .begin(change)
            case "=": self = .owned(change)
            case "&": self = .shared(change)
            case "~": self = .existed(change)
            case "!": self = .failed(change)
            case "-": self = .reverted(change)
            case "?": self = .spared(change)
            default: return nil
            }
        }
    }

    /// Where a change stands.
    public enum State: Equatable, Sendable {
        /// Begun, no outcome: it may have been made.
        case pending
        case owned
        /// Found there, held by another session too: reverted by whichever of them ends last.
        case shared
        case existed
        case failed
        case reverted
        /// The session's or pending, left to another session at the revert: no longer this one's.
        case spared
    }

    /// Why an entry cannot follow the record.
    public enum Failure: Error, Equatable, Sendable, CustomStringConvertible {
        case outOfOrder(String)
        case invalidReason
        case tooLarge

        public var description: String {
            switch self {
            case .outOfOrder(let entry): return "the network record cannot take “\(HelperCore.printable(entry))” now"
            case .invalidReason: return "the reason is not one line of printable ASCII"
            case .tooLarge: return "the network record is larger than \(OpenConnectRecord.maxBytes >> 20) MiB"
            }
        }
    }

    /// The session's tunnel interface.
    public let interface: String
    public private(set) var entries: [Entry] = []
    /// Each change's state.
    public private(set) var states: [Change: State] = [:]
    /// When each change was last begun (the number of its entry), for the order of a revert.
    private var begun: [Change: Int] = [:]
    /// The change being made, if any: at most one is, the hook makes them one at a time.
    public private(set) var pending: Change?

    /// An empty record for `interface` (`utunN` or `tunN`); nil for another name.
    public init?(interface: String) {
        guard Self.isInterface(interface) else { return nil }
        self.interface = interface
    }

    /// `utun0`–`utun999` or `tun0`–`tun99999`: the record does not say which platform wrote it.
    static func isInterface(_ name: String) -> Bool {
        OpenConnectNetwork.isTunnelInterface(name, platform: .macOS) || OpenConnectNetwork.isTunnelInterface(name, platform: .linux)
    }

    static func isReason(_ s: String) -> Bool {
        (1...maxReasonBytes).contains(s.utf8.count) && s.utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7F } && s.first != " " && s.last != " "
    }

    /// Adds `entry`, in the order the journal allows:
    /// - `begin`: no change is pending, and this one is neither pending nor the session's (own or shared);
    /// - `owned`, `failed`: the outcome of the pending change;
    /// - `shared`, `existed`: the outcome of the pending change, or, while none is pending, a change found
    ///   there that is not the session's yet;
    /// - `reverted`: a change that is the session's (own or shared) or pending, while no other change is pending;
    /// - `spared`: a change that is the session's (own or shared) or pending (it settles a pending one);
    /// - `status`: no change is pending; a failure's reason is one line of printable ASCII.
    public mutating func append(_ entry: Entry) throws {
        let pending = self.pending
        switch entry {
        case .begin(let c):
            guard pending == nil, !Self.held(states[c]) else { throw Failure.outOfOrder(entry.text) }
            states[c] = .pending
            begun[c] = entries.count
            self.pending = c
        case .owned(let c), .failed(let c):
            guard pending == c else { throw Failure.outOfOrder(entry.text) }
            states[c] = entry == .owned(c) ? .owned : .failed
            self.pending = nil
        case .shared(let c), .existed(let c):
            if pending != c {
                guard pending == nil, !Self.held(states[c]) else { throw Failure.outOfOrder(entry.text) }
                begun[c] = entries.count
            }
            states[c] = entry == .shared(c) ? .shared : .existed
            self.pending = nil
        case .reverted(let c):
            guard pending == nil || pending == c, Self.held(states[c]) || states[c] == .pending else {
                throw Failure.outOfOrder(entry.text)
            }
            states[c] = .reverted
            self.pending = nil
        case .spared(let c):
            guard Self.held(states[c]) || states[c] == .pending else { throw Failure.outOfOrder(entry.text) }
            states[c] = .spared
            if pending == c { self.pending = nil }
        case .status(let status):
            guard pending == nil else { throw Failure.outOfOrder(entry.text) }
            if case .failed(let reason) = status, !Self.isReason(reason) { throw Failure.invalidReason }
        }
        entries.append(entry)
    }

    /// The session's: its own, or shared with another session.
    static func held(_ state: State?) -> Bool { state == .owned || state == .shared }

    /// The changes to undo, newest first: the session's own and shared ones and those begun without an outcome
    /// (they may have been made), but none that another session's record (`others`, every other session of
    /// the run root whose record is there, read under its lock: one that ended holds what it holds until its
    /// revert has run) holds as its own, shared or begun. Some changes
    /// can be the same in two sessions: a reject route, the host route to a VPN server two sessions share, an
    /// exclude through the same gateway; the session that set one up first owns it, the other shares it (`&`),
    /// and the last of them to end removes it, so it neither goes from under a running session nor stays after
    /// all of them. One a session found there with no session holding it (`existed`) claims nothing: it is not
    /// PassTunnel's, and no session removes it. Others are unique to a session and never spared in practice:
    /// its interface's link and addresses, its routes through that interface, its DNS service key.
    public func toRevert(sparing others: [OpenConnectRecord]) -> [Change] {
        let claimed = Self.claimed(by: others)
        return ordered.reversed().filter { (Self.held(states[$0]) || states[$0] == .pending) && !claimed.contains($0) }
    }

    /// Every change one of `others` holds: its own, shared or begun.
    public static func claimed(by others: [OpenConnectRecord]) -> Set<Change> {
        var claimed = Set<Change>()
        for other in others {
            for (change, state) in other.states where held(state) || state == .pending { claimed.insert(change) }
        }
        return claimed
    }

    /// Starts the revert: journals every change `toRevert(sparing:)` leaves to another session as `spared`
    /// (`?`; a pending one is settled by it), then returns the changes to undo, newest first, each of which can
    /// then be journaled as `reverted` once undone. Call it under the run root's lock with the other live
    /// sessions' records; the record must then be written before anything is undone.
    public mutating func beginRevert(sparing others: [OpenConnectRecord]) throws -> [Change] {
        let undo = toRevert(sparing: others)
        let kept = Set(undo)
        for change in ordered.reversed() where (Self.held(states[change]) || states[change] == .pending) && !kept.contains(change) {
            try append(.spared(change))
        }
        return undo
    }

    /// Every change, in the order it was last begun.
    var ordered: [Change] { begun.sorted { $0.value < $1.value }.map(\.key) }

    /// The session's own changes, oldest first.
    public var owned: [Change] { ordered.filter { states[$0] == .owned } }

    /// The session's own and shared changes, oldest first: what it removes when it ends (unless another live
    /// session still holds it).
    public var held: [Change] { ordered.filter { Self.held(states[$0]) } }

    /// What the system has as the set-up asked: the session's own and shared changes and those that were there
    /// already, oldest first.
    public var applied: [Change] { ordered.filter { Self.held(states[$0]) || states[$0] == .existed } }

    /// The latest status.
    public var status: Status? {
        for entry in entries.reversed() { if case .status(let s) = entry { return s } }
        return nil
    }

    /// The same state in as few entries as possible: each applied change begun with its outcome, the latest
    /// status, then a pending change begun (a status cannot follow it). For a long session whose routes followed
    /// the gateway many times. Throws only if the record's own state does not allow it, which `append` prevents.
    public func compacted() throws -> OpenConnectRecord {
        guard var out = OpenConnectRecord(interface: interface) else { throw Failure.outOfOrder("interface " + interface) }
        for change in ordered {
            switch states[change] {
            case .owned:
                try out.append(.begin(change))
                try out.append(.owned(change))
            case .shared:
                try out.append(.shared(change))
            case .existed:
                try out.append(.existed(change))
            default: break
            }
        }
        if let status { try out.append(.status(status)) }
        if let pending { try out.append(.begin(pending)) }
        return out
    }

    // MARK: Text

    /// The file's text: the header, `interface <name>`, one line per entry. Throws `Failure.tooLarge` above
    /// `maxBytes`, and `HelperCore.Failure.unsafeFile` unless every line is one line.
    public func text() throws -> String {
        var lines = [Self.header, "interface " + interface]
        lines += entries.map(\.text)
        let text = lines.joined(separator: "\n") + "\n"
        guard text.utf8.count <= Self.maxBytes else { throw Failure.tooLarge }
        try HelperCore.checkLines(text, count: lines.count, file: Self.fileName)
        return text
    }

    /// Exactly `text()`'s form, every entry checked and in an order `append` allows; nil for anything else.
    public static func parse(_ text: String) -> OpenConnectRecord? {
        guard text.utf8.count <= maxBytes, text.hasSuffix("\n"), !text.utf8.contains(0), !text.utf8.contains(0x0D) else { return nil }
        let lines = text.dropLast().split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count >= 2, lines[0] == header, lines[1].hasPrefix("interface "),
            var record = OpenConnectRecord(interface: String(lines[1].dropFirst("interface ".count)))
        else { return nil }
        for line in lines.dropFirst(2) {
            guard let entry = Entry(text: String(line)), (try? record.append(entry)) != nil else { return nil }
        }
        return record
    }
}
