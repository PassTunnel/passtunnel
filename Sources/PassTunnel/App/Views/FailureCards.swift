import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

// The error states of the redesigned window's detail (docs/APP.md, Redesigned window): under the status line, a card
// that says what happened and what is worth checking, instead of the code cards. Core reports why the connect failed
// (`ConnectionFailure`), the tries of an unreachable server (`UnreachableRetry`) and the network path
// (`NetworkStatus`); the cards word them. A clock that is off has its own banner (ClockBanner.swift).

/// Render overrides for the error states, used while the model shows preview states (`AppModel.previewStates`).
struct FailurePreview {
    var failures: [String: ConnectionFailure] = [:]
    var retries: [String: UnreachableRetry] = [:]
    var network = NetworkStatus.unknown
    /// The clock measurements the banner chooses from.
    var clocks: [ClockOffset] = []
}

extension AppModel {
    /// Why the last connect of `id` failed, typed.
    func failure(_ id: String) -> ConnectionFailure? {
        previewStates != nil ? previewFailures.failures[id] : connections.failures[id]
    }

    /// The tries of `id`'s server that did not answer, while there are any.
    func unreachableRetry(_ id: String) -> UnreachableRetry? {
        previewStates != nil ? previewFailures.retries[id] : connections.unreachableRetries[id]
    }

    /// Whether this Mac is online, as the system sees it.
    var networkStatus: NetworkStatus {
        previewStates != nil ? previewFailures.network : connections.networkStatus
    }

    /// The last clock measurement of any profile or the time server, when it is recent and off.
    var clockWarning: ClockOffset? {
        let measurements = previewStates != nil
            ? previewFailures.clocks
            : Array(connections.clockOffsets.values) + [connections.timeServerClock].compactMap { $0 }
        return ClockOffset.recentWarning(in: measurements, now: now)
    }

    /// Whether the detail shows a card for the failure, in place of the code cards.
    func showsFailureCard(_ p: Profile, _ status: DisplayStatus) -> Bool {
        guard case .failed(let reason) = status else { return false }
        switch reason {
        case .signInRejected: return failure(p.id) != nil
        case .unreachable, .hostNotFound: return true
        case .message:
            return failure(p.id).map { !MessageCard.lines($0, shown: status.line(at: now)).isEmpty } ?? false
        }
    }

    /// "Copy details": the summary for the user's IT team, on the pasteboard as ordinary text. False when there is
    /// no failure to describe.
    @discardableResult
    func copyFailureDetails(_ p: Profile) -> Bool {
        guard let text = connections.failureDetails(p.id)?.text() else { return false }
        NSPasteboard.general.clearContents()
        return NSPasteboard.general.setString(text, forType: .string)
    }
}

// MARK: - Dispatch

/// The card for the profile's failure: the sign-in the server rejected, the server that does not answer, a name that
/// was not found, or another failure's reason. `server`: where the connect goes ("203.0.113.10:443"; "" when unknown).
struct FailureCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let status: DisplayStatus
    var server = ""

    var body: some View {
        let failure = model.failure(profile.id)
        switch status {
        case .failed(.signInRejected):
            if let failure { RejectedCard(profile: profile, failure: failure) }
        case .failed(.unreachable(let retry)):
            UnreachableCard(profile: profile, failure: failure, retry: retry, server: server)
        case .failed(.hostNotFound):
            MessageCard(profile: profile, failure: failure, shown: status.line(at: model.now), editsAddress: true)
        case .failed(.message):
            MessageCard(profile: profile, failure: failure, shown: status.line(at: model.now))
        default:
            EmptyView()
        }
    }
}

// MARK: - Rows

/// A fact in a card: a 16 pt glyph (✓ green, ⚠ amber, ✗ red, ⓘ gray) and a line, with a smaller one under it or a link.
/// The glyph is never the only carrier of the meaning: the words say it too.
struct DiagnosisRow: View {
    let symbol: StatusSymbol
    let title: Text
    var detail: Text?
    var link: (title: String, action: () -> Void)?

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            StatusIcon(symbol, size: 16)
                .frame(width: 18)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 1) {
                title
                    .typography(.body)
                    .foregroundStyle(Palette.fg)
                    .fixedSize(horizontal: false, vertical: true)
                if let detail {
                    detail
                        .typography(.hint)
                        .foregroundStyle(Palette.fg2)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let link {
                    Button(action: link.action) {
                        Text(link.title).underline()
                    }
                    .buttonStyle(.plain)
                    .typography(.hint)
                    .foregroundStyle(Palette.fg)
                }
            }
            // A link stays a control of its own for VoiceOver.
            .accessibilityElement(children: link == nil ? .combine : .contain)
            Spacer(minLength: 0)
        }
    }
}

extension Text {
    /// `sentence` with `part` (an address, the server's reply) set in SF Mono.
    static func mono(_ sentence: String, part: String) -> Text {
        var text = AttributedString(sentence)
        if !part.isEmpty, let range = text.range(of: part) {
            text[range].font = .system(size: 12.5, design: .monospaced)
        }
        return Text(text)
    }
}

/// A card's first paragraph.
private struct Lead: View {
    let text: Text

    var body: some View {
        text
            .typography(.body)
            .foregroundStyle(Palette.fg)
            .lineSpacing(2)
            .fixedSize(horizontal: false, vertical: true)
    }
}

// MARK: - Sign-in rejected

/// "The server answered AUTH_FAILED. PassTunnel stopped instead of retrying, so your account won't get locked." and what
/// is worth checking: whether the code was fresh (from the sign-in that was sent), whether the clock is off (the gateway's
/// time after the rejection, or the time server's when asked with the button), and a changed password.
struct RejectedCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let failure: ConnectionFailure
    @StateObject private var check = ClockCheck()

    var body: some View {
        Card(style: .compact) {
            Lead(text: lead)
            codeRow
            clockRow
            if profile.passwordMode == .keychain {
                DiagnosisRow(symbol: .info, title: Text(String(localized: "Changed your password at work?")),
                             link: (String(localized: "Update it in PassTunnel"), { model.edit(profile) }))
                    .accessibilityIdentifier("profile.\(profile.id).failure.password")
            }
            ClockCheckButton(check: check)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("profile.\(profile.id).failure")
    }

    private var lead: Text {
        let stopped = String(localized: "PassTunnel stopped instead of retrying, so your account won’t get locked.")
        guard let reply = failure.reply?.trimmingCharacters(in: .whitespacesAndNewlines), !reply.isEmpty else {
            return Text(String(localized: "The server didn’t accept the sign-in.") + " " + stopped)
        }
        let shown = reply.count > 120 ? String(reply.prefix(120)) + "…" : reply
        return Text.mono(String(localized: "The server answered \(shown).") + " " + stopped, part: shown)
    }

    @ViewBuilder private var codeRow: some View {
        if failure.codeSent, let left = failure.codeSecondsLeft {
            if left > Preferences.freshCodeSeconds {
                DiagnosisRow(symbol: .check, title: Text(String(localized: "The code was fresh")),
                             detail: Text(String(localized: "Sent with \(left) s left")))
            } else {
                DiagnosisRow(symbol: .warning, title: Text(String(localized: "The code was about to expire")),
                             detail: Text(String(localized: "Sent with \(left) s left, so it may have run out on the way.")))
            }
        }
    }

    @ViewBuilder private var clockRow: some View {
        if let clock = failure.clock {
            if clock.isWrong {
                DiagnosisRow(symbol: .warning, title: Text(String(localized: "The clock is off by \(clock.offBy)")),
                             detail: Text(String(localized: "Most likely cause. Fix the clock, then try again.")))
            } else {
                DiagnosisRow(symbol: .check, title: Text(String(localized: "The clock is right")),
                             detail: Text(Self.checked(clock)))
            }
        }
    }

    /// "Within 2 s of time.apple.com".
    private static func checked(_ clock: ClockOffset) -> String {
        let seconds = Int(min(clock.offsetSeconds.magnitude, 1_000_000))
        guard let server = clock.server, !server.isEmpty else { return String(localized: "Within \(seconds) s") }
        return String(localized: "Within \(seconds) s of \(server)")
    }
}

// MARK: - Server unreachable

/// "No answer after 3 tries. Your password and code were not sent." with the network (never whether other sites answer: the
/// app only reads the system's own view), the server that did not answer, and a word about networks that block VPN traffic.
/// "Try now" runs the next try at once; "Copy details" puts the summary for the IT team on the pasteboard.
struct UnreachableCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let failure: ConnectionFailure?
    let retry: UnreachableRetry?
    let server: String
    @State private var copied = false

    var body: some View {
        let network = model.networkStatus
        Card(style: .compact) {
            Lead(text: Text(lead))
            networkRow(network)
            DiagnosisRow(symbol: .rejected, title: Self.title(server), detail: failure?.reason.flatMap { $0.isEmpty ? nil : Text($0) })
            DiagnosisRow(symbol: .info, title: Text(String(localized: "On a guest or hotel network?")),
                         detail: Text(String(localized: "Some networks block VPN traffic. Try another network or ask your IT team.")))
            HStack(spacing: Spacing.xs) {
                if let retry {
                    Button { model.connections.retryNow(profile.id) } label: { Text(String(localized: "Try now")) }
                        .buttonStyle(.primaryCapsule(.compact))
                        .disabled(retry.nextTryAt == nil && !retry.waitingForNetwork)
                        .accessibilityIdentifier("profile.\(profile.id).failure.tryNow")
                }
                Button(action: copyDetails) {
                    Text(copied ? String(localized: "Copied ✓") : String(localized: "Copy details"))
                }
                .buttonStyle(.secondaryCapsule(.compact, minWidth: 112))
                .accessibilityIdentifier("profile.\(profile.id).failure.copyDetails")
            }
            .padding(.top, 2)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("profile.\(profile.id).failure")
    }

    /// "No answer after 3 tries. Your password and code were not sent."
    private var lead: String {
        let tries = retry?.tries ?? failure?.tries ?? 1
        let answer = tries > 1 ? String(localized: "No answer after \(tries) tries.") : String(localized: "No answer.")
        guard failure?.credentialsSent != true else { return answer }
        return answer + " " + String(localized: "Your password and code were not sent.")
    }

    /// "This Mac is online · Wi-Fi", or offline; nothing while the system has not said.
    @ViewBuilder private func networkRow(_ network: NetworkStatus) -> some View {
        switch network.online {
        case true?:
            let interface = network.interface.map { " · " + $0.name } ?? ""
            DiagnosisRow(symbol: .check, title: Text(String(localized: "This Mac is online") + interface))
        case false?:
            DiagnosisRow(symbol: .rejected, title: Text(String(localized: "This Mac is offline")),
                         detail: retry?.waitingForNetwork == true
                             ? Text(String(localized: "The next try starts when the network is back.")) : nil)
        case nil:
            EmptyView()
        }
    }

    /// "203.0.113.10:443 didn’t answer".
    static func title(_ server: String) -> Text {
        server.isEmpty ? Text(String(localized: "The server didn’t answer"))
                       : Text.mono(String(localized: "\(server) didn’t answer"), part: server)
    }

    private func copyDetails() {
        guard model.copyFailureDetails(profile) else { return }
        copied = true
        Task {
            try? await Task.sleep(nanoseconds: UInt64(Motion.copiedDuration * 1_000_000_000))
            copied = false
        }
    }
}

// MARK: - Other failures

/// A short card for the other failures: the tool's reason, and that the sign-in was not sent when it was not. A name that
/// was not found also offers the profile, where the address is.
struct MessageCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let failure: ConnectionFailure?
    /// What the status line already says.
    let shown: String
    var editsAddress = false

    var body: some View {
        let lines = failure.map { Self.lines($0, shown: shown) } ?? []
        if !lines.isEmpty || editsAddress {
            Card(style: .compact) {
                ForEach(lines, id: \.self) { Lead(text: Text(verbatim: $0)) }
                if editsAddress {
                    DiagnosisRow(symbol: .info, title: Text(String(localized: "Is the server’s address right?")),
                                 link: (String(localized: "Check it in PassTunnel"), { model.edit(profile) }))
                }
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("profile.\(profile.id).failure")
        }
    }

    /// The tool's reason, unless the status line says it already, and that nothing was sent.
    static func lines(_ failure: ConnectionFailure, shown: String) -> [String] {
        var lines: [String] = []
        if let reason = failure.reason?.trimmingCharacters(in: .whitespacesAndNewlines), !reason.isEmpty, reason != shown {
            lines.append(reason)
        }
        if !failure.credentialsSent { lines.append(String(localized: "Your password and code were not sent.")) }
        return lines
    }
}
