import PassTunnelCore
import PassTunnelKit
import SwiftUI

// The profile's status in the app's views: `DisplayStatus` (Core) gives the state and its words, this file
// the icon, the color and the views that show them. The status item's badges still use `StatusKind`.

extension AppModel {
    /// The one status `p` shows in the app's views; from the render overrides while they are set.
    func displayStatus(_ p: Profile) -> DisplayStatus {
        let id = p.id
        let dropped = droppedUnseen.contains(id)
        guard previewStates != nil else {
            return DisplayStatus(DisplayStatus.Facts(p, in: connections, droppedUnseen: dropped))
        }
        return DisplayStatus(
            DisplayStatus.Facts(
                p, state: state(id), reconnect: reconnectInfo(id), codeWaitUntil: previewCodeWaits[id], lastError: error(id),
                notResponding: isUnreachable(id), droppedUnseen: dropped, failure: failure(id), retry: unreachableRetry(id),
                refusal: connectRefusal(p.type)))
    }
}

extension DisplayStatus {
    /// The glyph in the status line; rows show the same symbol's dot.
    var symbol: StatusSymbol {
        switch self {
        case .off, .protected: return .off
        case .connecting: return .connecting
        case .waitingForCode: return .waiting
        case .connected, .statusUnavailable: return .connected
        case .setupIncomplete, .notResponding, .dropped: return .warning
        case .failed(.signInRejected): return .rejected
        case .failed(.unreachable): return .unreachable
        case .failed(.hostNotFound), .failed(.message), .failed(.hostScanRequired): return .warning
        case .failed(.serverNotTrusted): return .rejected
        case .reconnecting: return .dropped
        case .unavailable: return .warning
        }
    }

    /// The words' color: fg2 at rest, fg on the way, green connected, amber waiting or with a problem, red once
    /// it dropped or failed.
    var textColor: Color {
        switch self {
        case .off, .protected: return Palette.fg2
        case .connecting: return Palette.fg
        case .waitingForCode, .setupIncomplete, .notResponding, .unavailable: return Palette.amber
        case .connected, .statusUnavailable: return Palette.green
        case .reconnecting, .dropped, .failed: return Palette.red
        }
    }

    /// A drop or a failure: the warning glyph and its dot are red instead of amber.
    var isError: Bool {
        switch self {
        case .dropped, .failed: return true
        default: return false
        }
    }

    /// More than the line says, for its tooltip: the setup problem.
    var help: String? {
        if case .setupIncomplete(_, let warning) = self { return warning }
        return nil
    }

    /// How often the words change with the time: countdowns several times a second, the uptime every second;
    /// nil when they do not.
    var refreshInterval: TimeInterval? {
        switch self {
        case .waitingForCode, .reconnecting: return 0.25
        case .failed(.unreachable(let retry)): return retry?.nextTryAt == nil ? nil : 0.25
        case .connected(let c), .setupIncomplete(let c, _), .notResponding(let c), .statusUnavailable(let c):
            return c.since == nil ? nil : 1
        case .off, .protected, .connecting, .dropped, .failed, .unavailable: return nil
        }
    }
}

/// The detail's status line: a 20 pt status icon and the long words (15 semibold) in the state's color. It wraps
/// and never truncates. `server` names where a connect goes ("vpn.example.com:1194"); `now` pins the time (renders).
struct ProfileStatusLine: View {
    let status: DisplayStatus
    var server = ""
    var now: Date?

    var body: some View {
        StatusClock(interval: status.refreshInterval, now: now) { date in
            HStack(alignment: .firstTextBaseline, spacing: Spacing.xs) {
                StatusIcon(status.symbol, tint: status.isError ? Palette.red : nil)
                    .alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 5 }
                Text(verbatim: status.line(at: date, server: server))
                    .typography(.statusLine)
                    .foregroundStyle(status.textColor)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            .help(status.help ?? "")
        }
    }
}

/// A row's status (sidebar, menu bar panel): the dot and the short words (11.5 medium) in the state's color,
/// wrapping to a second line rather than truncating. On the accent color of a selected row the words follow the
/// row's text (macOS 14 and later); the dot keeps its color.
struct ProfileStatusRow: View {
    let status: DisplayStatus
    var now: Date?

    var body: some View {
        StatusClock(interval: status.refreshInterval, now: now) { date in
            HStack(alignment: .firstTextBaseline, spacing: 5) {
                ProfileStatusDot(status: status)
                    .alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 4 }
                Text(verbatim: status.summary(at: date))
                    .typography(.rowStatus)
                    .rowForeground(status.textColor)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
        }
    }
}

/// The 7 pt dot of a row: filled in the state's color, an empty circle when off. Hidden from VoiceOver.
struct ProfileStatusDot: View {
    let status: DisplayStatus
    var size: CGFloat = 7

    var body: some View {
        StatusDot(status.symbol, size: size, tint: status.isError ? Palette.redDot : nil)
    }
}

extension View {
    /// `style`, except on the accent color of a selected row in a focused list, where text takes `emphasized`, a
    /// style that follows the row (white). The list tells only from macOS 14 on; before, `style` stays.
    func rowForeground<S: ShapeStyle>(_ style: S, emphasized: HierarchicalShapeStyle = .secondary) -> some View {
        modifier(RowForeground(style: AnyShapeStyle(style), emphasized: AnyShapeStyle(emphasized)))
    }
}

private struct RowForeground: ViewModifier {
    let style: AnyShapeStyle
    let emphasized: AnyShapeStyle

    func body(content: Content) -> some View {
        if #available(macOS 14, *) {
            content.modifier(Prominence(style: style, emphasized: emphasized))
        } else {
            content.foregroundStyle(style)
        }
    }

    @available(macOS 14, *)
    private struct Prominence: ViewModifier {
        let style: AnyShapeStyle
        let emphasized: AnyShapeStyle
        @Environment(\.backgroundProminence) private var prominence

        func body(content: Content) -> some View {
            content.foregroundStyle(prominence == .increased ? emphasized : style)
        }
    }
}

/// Redraws `content` every `interval` seconds while the words depend on the time; `now` pins the time.
private struct StatusClock<Content: View>: View {
    let interval: TimeInterval?
    let now: Date?
    @ViewBuilder let content: (Date) -> Content

    var body: some View {
        if let now {
            content(now)
        } else if let interval {
            TimelineView(.periodic(from: .now, by: interval)) { content($0.date) }
        } else {
            content(Date())
        }
    }
}

// MARK: - render

/// Every profile status, for the `profile-status` render (RenderSnapshots): the row form at a sidebar row's width
/// and the detail's status line. The statuses' words are the app's; the sample names and labels are not localized.
struct ProfileStatusGallery: View {
    let now: Date

    private var samples: [(name: String, status: DisplayStatus)] {
        let up = DisplayStatus.Connection(since: now.addingTimeInterval(-(72 * 60 + 14)), address: "10.8.0.6")
        let fresh = DisplayStatus.Connection(since: now.addingTimeInterval(-20), address: "10.9.0.14")
        return [
            ("off", .off),
            ("protected", .protected),
            ("connecting", .connecting(phase: ConnectionManager.Phase.signingIn)),
            ("waitingForCode", .waitingForCode(until: now.addingTimeInterval(3.6))),
            ("connected", .connected(up)),
            ("connected, just now", .connected(fresh)),
            ("setupIncomplete", .setupIncomplete(up, warning: "")),
            ("notResponding", .notResponding(up)),
            ("statusUnavailable", .statusUnavailable(up)),
            (
                "reconnecting",
                .reconnecting(
                    ReconnectInfo(attempt: 1, maxAttempts: 3, at: now.addingTimeInterval(4)),
                    freshCode: true)
            ),
            (
                "reconnecting, no code",
                .reconnecting(
                    ReconnectInfo(attempt: 1, maxAttempts: 3, at: now),
                    freshCode: false)
            ),
            (
                "reconnecting, 2nd try",
                .reconnecting(
                    ReconnectInfo(
                        attempt: 2, maxAttempts: 3,
                        at: now.addingTimeInterval(11.5)), freshCode: true)
            ),
            ("dropped", .dropped),
            ("failed", .failed(.message(PTError.authFailed("").localizedDescription))),
            ("sign-in rejected", .failed(.signInRejected)),
            ("server not found", .failed(.hostNotFound)),
            (
                "unreachable, next try",
                .failed(
                    .unreachable(
                        retry: UnreachableRetry(
                            tries: 3, maxTries: 5, nextTryAt: now.addingTimeInterval(17.2), firstFailedAt: now, lastFailedAt: now)))
            ),
            (
                "unreachable, trying",
                .failed(
                    .unreachable(
                        retry: UnreachableRetry(
                            tries: 3, maxTries: 5, firstFailedAt: now, lastFailedAt: now)))
            ),
            (
                "unreachable, offline",
                .failed(
                    .unreachable(
                        retry: UnreachableRetry(
                            tries: 3, maxTries: 5, waitingForNetwork: true, firstFailedAt: now, lastFailedAt: now)))
            ),
            ("unreachable, gave up", .failed(.unreachable(retry: nil))),
            ("server not trusted", .failed(.serverNotTrusted)),
            ("host scan required", .failed(.hostScanRequired)),
            (
                "requires a later macOS",
                .unavailable(
                    note: PTError.anyConnectRequiresMacOS("15.4").unavailableNote ?? "",
                    reason: PTError.anyConnectRequiresMacOS("15.4").localizedDescription)
            )
        ]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text(verbatim: "Profile status").typography(.detailTitle).foregroundStyle(Palette.fg)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: Spacing.l, verticalSpacing: Spacing.m) {
                GridRow {
                    caption("state")
                    caption("row · menu bar panel")
                    caption("detail (server vpn.example.com:1194)")
                }
                ForEach(samples, id: \.name) { sample in
                    GridRow {
                        Text(verbatim: sample.name).typography(.rowCode).foregroundStyle(Palette.fg2)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(verbatim: "Work").typography(.bodyEmphasized).foregroundStyle(Palette.fg)
                            ProfileStatusRow(status: sample.status, now: now)
                        }
                        .frame(width: 180, alignment: .leading)
                        ProfileStatusLine(status: sample.status, server: "vpn.example.com:1194", now: now)
                            .frame(width: 440, alignment: .leading)
                    }
                }
            }
        }
        .padding(Spacing.xl)
        .fixedSize()
        .background(Palette.background)
    }

    private func caption(_ text: String) -> some View {
        Text(verbatim: text).typography(.hint).foregroundStyle(Palette.fg3)
    }
}
