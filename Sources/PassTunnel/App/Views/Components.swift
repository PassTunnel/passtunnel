import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// Visual state of a profile, derived from the connection state plus errors and health.
enum StatusKind: Equatable {
    case disconnected, connecting, connected, degraded, error, dropped

    var tint: Color {
        switch self {
        case .connected: return .green
        case .connecting, .degraded: return .orange
        case .error, .dropped: return .red
        case .disconnected: return .secondary
        }
    }
}

extension AppModel {
    func statusKind(_ p: Profile) -> StatusKind {
        switch state(p.id) {
        case .connected: return isUnreachable(p.id) || warning(p.id) != nil ? .degraded : .connected
        case .connecting: return .connecting
        case .disconnected:
            if reconnectInfo(p.id) != nil { return .connecting }
            if error(p.id) != nil { return .error }
            if droppedUnseen.contains(p.id) { return .dropped }
            return .disconnected
        }
    }
}

extension VPNType {
    var displayName: String {
        switch self {
        case .openvpn: return "OpenVPN"  // product names stay untranslated
        case .forti: return "FortiGate"
        }
    }
}

enum CodeFormat {
    /// "482913" → "482 913", "48291352" → "4829 1352".
    static func grouped(_ code: String) -> String {
        guard code.count >= 6 else { return code }
        let split = code.count / 2
        let i = code.index(code.startIndex, offsetBy: split)
        return "\(code[..<i]) \(code[i...])"
    }

    static func hidden(_ digits: Int) -> String {
        let half = digits / 2
        return String(repeating: "•", count: half) + " " + String(repeating: "•", count: digits - half)
    }
}

/// Rounded-square avatar: SF Symbol or badge letter on a tinted background.
struct ProfileAvatar: View {
    let profile: Profile
    let kind: StatusKind
    var size: CGFloat = 34

    private var tint: Color {
        kind == .disconnected ? Color.accentColor : kind.tint
    }

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                .fill(tint.gradient.opacity(kind == .disconnected ? 0.16 : 0.22))
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                .strokeBorder(tint.opacity(0.25), lineWidth: 0.5)
            content
                .foregroundStyle(tint)
        }
        .frame(width: size, height: size)
        .overlay(alignment: .bottomTrailing) {
            if kind != .disconnected {
                Circle()
                    .fill(kind.tint)
                    .frame(width: size * 0.3, height: size * 0.3)
                    .overlay(Circle().strokeBorder(Color(nsColor: .windowBackgroundColor), lineWidth: 2))
                    .offset(x: 3, y: 3)
            }
        }
        .accessibilityHidden(true)
    }

    @ViewBuilder private var content: some View {
        let showIcon = profile.badgeStyle != .letter && !profile.icon.isEmpty
        if showIcon {
            Image(systemName: profile.icon)
                .font(.system(size: size * 0.44, weight: .semibold))
        } else {
            Text(profile.displayBadge.prefix(2))
                .font(.system(size: size * (profile.displayBadge.count > 1 ? 0.36 : 0.46), weight: .bold, design: .rounded))
        }
    }
}

/// Circular countdown for the current TOTP window.
struct CountdownRing: View {
    let remaining: Double
    let period: Double
    var size: CGFloat = 20
    var lineWidth: CGFloat = 2.5

    private var fraction: Double { max(0, min(1, remaining / period)) }
    private var color: Color { remaining <= 5 ? .red : remaining <= 10 ? .orange : .accentColor }

    var body: some View {
        ZStack {
            Circle().stroke(Color.secondary.opacity(0.2), lineWidth: lineWidth)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(color, style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text(verbatim: "\(Int(remaining.rounded(.up)))")
                .font(.system(size: size * 0.42, weight: .semibold, design: .rounded).monospacedDigit())
                .foregroundStyle(remaining <= 5 ? Color.red : Color.secondary)
        }
        .frame(width: size, height: size)
    }
}

// MARK: - design system (App/Design)

/// Countdown ring of the redesign: `fg` on the `track`, turning amber over 200 ms when 5 s are left (or at once
/// while waiting for a fresh code). It empties with the time and refills from empty in 240 ms when a new code
/// starts. Under Reduce Motion it moves in 1 s steps and does not refill; the color still changes.
struct CodeRing: View {
    let remaining: Double
    let period: Double
    var waiting = false
    var size: CGFloat = 26
    /// Stroke width in the design's 30-unit box (3.2 in the detail, 2.6 for large rings, 4 for small ones).
    var weight: CGFloat = 3.2

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let fraction = Self.fraction(remaining: remaining, period: period, stepped: reduceMotion)
        let amber = waiting ? 1 : Self.amberProgress(remaining: remaining, stepped: reduceMotion)
        let lineWidth = weight * size / 30
        // Radius 12 of 30: the stroke's center runs at 4/5 of the box.
        ZStack {
            Circle().stroke(Palette.track, lineWidth: lineWidth)
            arc(fraction, lineWidth).foregroundStyle(Palette.fg).opacity(1 - amber)
            arc(fraction, lineWidth).foregroundStyle(Palette.amberRing).opacity(amber)
        }
        .frame(width: size * 0.8, height: size * 0.8)
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    private func arc(_ fraction: Double, _ lineWidth: CGFloat) -> some View {
        Circle()
            .trim(from: 0, to: fraction)
            .stroke(style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
            .rotationEffect(.degrees(-90))
    }

    /// The filled part of the ring for `remaining` of `period` seconds.
    static func fraction(remaining: Double, period: Double, stepped: Bool) -> Double {
        guard period > 0 else { return 0 }
        let left = min(max(remaining, 0), period)
        if stepped { return left.rounded(.up) / period }
        let level = left / period
        let elapsed = period - left
        guard elapsed < Motion.refillDuration else { return level }
        let t = elapsed / Motion.refillDuration
        return level * (1 - pow(1 - t, 3))  // ease-out from empty
    }

    /// 0 before the last 5 s, then up to 1 over 200 ms (ease-out); at once when stepped.
    static func amberProgress(remaining: Double, stepped: Bool) -> Double {
        guard remaining <= Motion.lastSeconds else { return 0 }
        if stepped { return 1 }
        let t = min(max((Motion.lastSeconds - remaining) / Motion.colorChangeDuration, 0), 1)
        return 1 - pow(1 - t, 2)
    }
}

/// The ring with the seconds written next to it, so the ring is never the only cue. The seconds turn amber in
/// the last 5 s. VoiceOver reads "18 seconds left".
struct CodeCountdown: View {
    let remaining: Double
    let period: Double
    var waiting = false

    var body: some View {
        let seconds = Int(max(0, remaining).rounded(.up))
        let last = remaining <= Motion.lastSeconds
        HStack(spacing: Spacing.s) {
            CodeRing(remaining: remaining, period: period, waiting: waiting)
            Text(verbatim: "\(seconds)")
                .typography(.seconds)
                .foregroundStyle(last ? Palette.amber : Palette.fg2)
                .fixedSize()
                .frame(minWidth: 16, alignment: .leading)
                .animation(Motion.colorChange, value: last)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(String(localized: "\(seconds) seconds left"))
    }
}

/// A code in two digit groups with a real space between them ("482 913"), in SF Mono. A new code rolls in;
/// under Reduce Motion it crossfades. VoiceOver reads the digits one by one with a pause between the groups
/// ("4 8 2, 9 1 3"). The caller colors it: `fg`, or `fg3` when hidden.
struct GroupedCodeText: View {
    let code: String
    var hidden = false
    var style: Typography = .heroCode

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Text(verbatim: hidden ? CodeFormat.hidden(max(6, code.count)) : CodeFormat.grouped(code))
            .typography(style)
            .lineLimit(1)
            .fixedSize()
            .contentTransition(reduceMotion ? .opacity : .numericText())
            .animation(reduceMotion ? Motion.reducedCodeChange : Motion.codeChange, value: code)
            .accessibilityLabel(hidden ? String(localized: "Code hidden") : Self.spoken(code))
    }

    /// "482913" → "4 8 2, 9 1 3".
    static func spoken(_ code: String) -> String {
        CodeFormat.grouped(code).split(separator: " ")
            .map { $0.map(String.init).joined(separator: " ") }
            .joined(separator: ", ")
    }
}

/// Redraws a countdown: every frame (at most 30 a second), or once a second, on the second, under Reduce
/// Motion. `now` pins the time, for renders.
struct CountdownTimeline<Content: View>: View {
    var now: Date?
    @ViewBuilder let content: (Date) -> Content

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        if let now {
            content(now)
        } else if reduceMotion {
            TimelineView(.periodic(from: Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down)), by: 1)) {
                content($0.date)
            }
        } else {
            TimelineView(.animation(minimumInterval: 1.0 / 30)) { content($0.date) }
        }
    }
}
