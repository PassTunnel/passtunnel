import Foundation

/// The hook's record of what it changed for a session (`network` in the session directory, 0600, root),
/// docs/ARCHITECTURE.md, "The hook", steps 4–7. A journal, one entry per line: every change is written
/// before it is made (`+`) and its outcome after (`=` the session's own, `~` it was there already and is
/// not the session's, `!` it failed and nothing was changed), a revert after it succeeded (`-`), and the
/// set-up's outcome (`status`). A change that was begun and has no outcome (the hook was killed during it)
/// may have been made, so it is reverted like one of the session's own (`toRevert`). Reverting is
/// idempotent: a change already gone counts as reverted.
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
        case existed(Change)
        case failed(Change)
        case reverted(Change)
        case status(Status)

        var text: String {
            switch self {
            case .begin(let c): return "+ " + c.text
            case .owned(let c): return "= " + c.text
            case .existed(let c): return "~ " + c.text
            case .failed(let c): return "! " + c.text
            case .reverted(let c): return "- " + c.text
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
            case "~": self = .existed(change)
            case "!": self = .failed(change)
            case "-": self = .reverted(change)
            default: return nil
            }
        }
    }

    /// Where a change stands.
    public enum State: Equatable, Sendable {
        /// Begun, no outcome: it may have been made.
        case pending
        case owned
        case existed
        case failed
        case reverted
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
    /// - `begin`: no change is pending, and this one is neither pending nor the session's;
    /// - `owned`, `existed`, `failed`: the outcome of the pending change;
    /// - `reverted`: a change that is the session's or pending, while no other change is pending;
    /// - `status`: no change is pending; a failure's reason is one line of printable ASCII.
    public mutating func append(_ entry: Entry) throws {
        let pending = self.pending
        switch entry {
        case .begin(let c):
            guard pending == nil, states[c] != .owned else { throw Failure.outOfOrder(entry.text) }
            states[c] = .pending
            begun[c] = entries.count
            self.pending = c
        case .owned(let c), .existed(let c), .failed(let c):
            guard pending == c else { throw Failure.outOfOrder(entry.text) }
            switch entry {
            case .owned: states[c] = .owned
            case .existed: states[c] = .existed
            default: states[c] = .failed
            }
            self.pending = nil
        case .reverted(let c):
            guard pending == nil || pending == c, states[c] == .owned || states[c] == .pending else {
                throw Failure.outOfOrder(entry.text)
            }
            states[c] = .reverted
            self.pending = nil
        case .status(let status):
            guard pending == nil else { throw Failure.outOfOrder(entry.text) }
            if case .failed(let reason) = status, !Self.isReason(reason) { throw Failure.invalidReason }
        }
        entries.append(entry)
    }

    /// The changes to undo, newest first: the session's own and those begun without an outcome.
    public var toRevert: [Change] {
        ordered.reversed().filter { states[$0] == .owned || states[$0] == .pending }
    }

    /// Every change, in the order it was last begun.
    var ordered: [Change] { begun.sorted { $0.value < $1.value }.map(\.key) }

    /// The session's own changes, oldest first.
    public var owned: [Change] { ordered.filter { states[$0] == .owned } }

    /// What the system has as the set-up asked: the session's own changes and those that were there already,
    /// oldest first.
    public var applied: [Change] { ordered.filter { states[$0] == .owned || states[$0] == .existed } }

    /// The latest status.
    public var status: Status? {
        for entry in entries.reversed() { if case .status(let s) = entry { return s } }
        return nil
    }

    /// The same state in as few entries as possible: each applied change begun with its outcome, a pending one
    /// begun, then the latest status. For a long session whose routes followed the gateway many times.
    public func compacted() -> OpenConnectRecord {
        var out = OpenConnectRecord(interface: interface)!
        for change in ordered {
            switch states[change] {
            case .owned: out.unchecked(.begin(change), .owned(change))
            case .existed: out.unchecked(.begin(change), .existed(change))
            default: break
            }
        }
        if let pending { out.unchecked(.begin(pending)) }
        if let status { out.unchecked(.status(status)) }
        return out
    }

    /// Appends entries that the record allows by construction.
    private mutating func unchecked(_ entries: Entry...) {
        for entry in entries { try! append(entry) }
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
