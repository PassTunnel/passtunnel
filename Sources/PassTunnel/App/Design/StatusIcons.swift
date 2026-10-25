import SwiftUI

/// The status glyphs of the redesign: SF Symbols, plus two drawn ones that turn (connecting, dropped). Status is
/// never shown by color alone, so a glyph always comes with words and is hidden from VoiceOver.
enum StatusSymbol: CaseIterable {
    // Connection states, in the status line (20 pt) and as row dots
    case off, connecting, waiting, connected, dropped, rejected, unreachable
    // Diagnosis rows and banners (16–18 pt)
    case check, warning, info

    /// The glyph's color; text next to it uses the matching text color.
    var tint: Color {
        switch self {
        case .off, .info: return Palette.fg2
        case .connecting: return Palette.fg
        case .waiting, .warning: return Palette.amber
        case .connected, .check: return Palette.green
        case .dropped: return Palette.redDot
        case .rejected, .unreachable: return Palette.red
        }
    }

    /// The dot's color in rows; nil draws an empty circle.
    var dot: Color? {
        switch self {
        case .off: return nil
        case .connecting: return Palette.fg
        case .waiting, .warning: return Palette.amberRing
        case .connected, .check: return Palette.green
        case .dropped, .rejected, .unreachable: return Palette.redDot
        case .info: return Palette.fg3
        }
    }

    var systemName: String? {
        switch self {
        case .off: return "circle"
        case .waiting: return "clock"
        case .connected: return "checkmark.circle"
        case .rejected: return "xmark.circle"
        case .unreachable: return "nosign"
        case .check: return "checkmark"
        case .warning: return "exclamationmark.triangle"
        case .info: return "info.circle"
        case .connecting, .dropped: return nil
        }
    }
}

struct StatusIcon: View {
    let symbol: StatusSymbol
    var size: CGFloat = 20
    /// Overrides the symbol's color (a warning that is an error, say).
    var tint: Color?

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(_ symbol: StatusSymbol, size: CGFloat = 20, tint: Color? = nil) {
        self.symbol = symbol
        self.size = size
        self.tint = tint
    }

    var body: some View {
        glyph
            .foregroundStyle(tint ?? symbol.tint)
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }

    @ViewBuilder private var glyph: some View {
        if let name = symbol.systemName {
            Image(systemName: name)
                // "Off" is a smaller, lighter circle than the other glyphs.
                .font(.system(size: size * (symbol == .off ? 0.62 : 0.86), weight: symbol == .off ? .regular : .medium))
        } else if reduceMotion {
            drawn(angle: .zero)
        } else {
            TimelineView(.animation(minimumInterval: 1.0 / 30)) { context in
                let turn = context.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: Motion.spinPeriod)
                drawn(angle: .degrees(360 * turn / Motion.spinPeriod))
            }
        }
    }

    /// The design's 24-unit glyphs: a three-quarter arc while connecting; a dot inside a dashed ring once dropped.
    @ViewBuilder private func drawn(angle: Angle) -> some View {
        let unit = size / 24
        if symbol == .connecting {
            Circle()
                .trim(from: 0, to: 0.75)
                .stroke(style: StrokeStyle(lineWidth: 2.1 * unit, lineCap: .round))
                .frame(width: 17 * unit, height: 17 * unit)
                .rotationEffect(.degrees(-90) + angle)
        } else {
            ZStack {
                Circle().frame(width: 10 * unit, height: 10 * unit)
                Circle()
                    .stroke(style: StrokeStyle(lineWidth: 1.6 * unit, dash: [3 * unit, 3 * unit]))
                    .frame(width: 18 * unit, height: 18 * unit)
                    .rotationEffect(angle)
            }
        }
    }
}

/// The small dot before a row's status: filled in the state's color, an empty `fg3` circle when off.
struct StatusDot: View {
    let symbol: StatusSymbol
    var size: CGFloat = 7
    /// Overrides the symbol's dot color (a warning that is an error, say).
    var tint: Color?

    init(_ symbol: StatusSymbol, size: CGFloat = 7, tint: Color? = nil) {
        self.symbol = symbol
        self.size = size
        self.tint = tint
    }

    var body: some View {
        Group {
            if let color = tint ?? symbol.dot {
                Circle().fill(color)
            } else {
                Circle().strokeBorder(Palette.fg3, lineWidth: 1.4)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
