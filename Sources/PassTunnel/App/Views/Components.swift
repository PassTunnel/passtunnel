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
        case .openvpn: return "OpenVPN"   // product names stay untranslated
        case .forti: return "FortiGate"
        }
    }

    var defaultSymbol: String {
        switch self {
        case .openvpn: return "network.badge.shield.half.filled"
        case .forti: return "building.2"
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

enum DurationFormat {
    static func since(_ date: Date, now: Date = Date()) -> String {
        let f = DateComponentsFormatter()
        f.unitsStyle = .abbreviated
        let secs = max(0, now.timeIntervalSince(date))
        f.allowedUnits = secs < 60 ? [.second] : secs < 3600 ? [.minute] : secs < 86_400 ? [.hour, .minute] : [.day, .hour]
        f.maximumUnitCount = 2
        return f.string(from: secs) ?? ""
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

/// Large live code with countdown; click copies. A locked code (stored encrypted, "Confirm with Touch ID")
/// is masked with a lock; click asks for Touch ID or the Mac password and shows it.
struct LiveCodeView: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    var fontSize: CGFloat = 22

    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.25)) { context in
            let date = model.previewNow ?? context.date
            if model.isCodeLocked(profile) {
                Button {
                    model.revealCode(profile)
                } label: {
                    HStack(spacing: 8) {
                        CodeText(code: String(repeating: "0", count: max(6, profile.totp.digits)), hidden: true, fontSize: fontSize)
                            .foregroundStyle(Color.secondary)
                        Image(systemName: "lock.fill")
                            .font(.system(size: fontSize * 0.6, weight: .medium))
                            .foregroundStyle(.secondary)
                            .frame(width: fontSize * 0.95, height: fontSize * 0.95)
                    }
                    .fixedSize()
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .contentShape(Rectangle())
                }
                .buttonStyle(CodeButtonStyle())
                .help(String(localized: "Click to show the code"))
                .accessibilityLabel(String(localized: "One-time code, hidden. Click to show it."))
                .accessibilityIdentifier("profile.\(profile.id).code")
            } else if let c = model.code(for: profile, at: date) {
                let period = Double(max(1, profile.totp.period))
                let remaining = period - date.timeIntervalSince1970.truncatingRemainder(dividingBy: period)
                Button {
                    model.copyCode(profile)
                } label: {
                    HStack(spacing: 8) {
                        CodeText(code: c.code, hidden: model.prefs.hideCodes, fontSize: fontSize)
                            .foregroundStyle(model.prefs.hideCodes ? Color.secondary : remaining <= 5 ? Color.red : Color.primary)
                        CountdownRing(remaining: remaining, period: period, size: fontSize * 0.95)
                    }
                    .fixedSize()
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .contentShape(Rectangle())
                }
                .buttonStyle(CodeButtonStyle())
                .help(String(localized: "Click to copy the code"))
                .accessibilityLabel(model.prefs.hideCodes
                    ? String(localized: "One-time code, hidden. Click to copy.")
                    : String(localized: "One-time code \(c.code.map(String.init).joined(separator: " ")), \(Int(remaining)) seconds left. Click to copy."))
                .accessibilityIdentifier("profile.\(profile.id).code")
            }
        }
    }
}

/// Code digits in two groups with a narrow gap (a monospaced space is too wide).
struct CodeText: View {
    let code: String
    var hidden = false
    var fontSize: CGFloat = 22

    var body: some View {
        let half = code.count / 2
        let first = hidden ? String(repeating: "•", count: half) : String(code.prefix(half))
        let second = hidden ? String(repeating: "•", count: code.count - half) : String(code.suffix(code.count - half))
        HStack(spacing: fontSize * 0.28) {
            Text(verbatim: first)
            Text(verbatim: second)
        }
        .font(.system(size: fontSize, weight: .medium, design: .monospaced))
        .contentTransition(.numericText())
        .lineLimit(1)
    }
}

struct CodeButtonStyle: ButtonStyle {
    @State private var hover = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(Color.primary.opacity(configuration.isPressed ? 0.12 : hover ? 0.06 : 0))
            )
            .onHover { hover = $0 }
    }
}

struct ToastView: View {
    let toast: ToastMessage

    var body: some View {
        Label(toast.text, systemImage: toast.symbol)
            .font(.callout.weight(.medium))
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(.regularMaterial, in: Capsule())
            .overlay(Capsule().strokeBorder(Color.primary.opacity(0.08)))
            .shadow(color: .black.opacity(0.15), radius: 8, y: 3)
            .accessibilityAddTraits(.isStaticText)
    }
}
