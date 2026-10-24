import SwiftUI

/// Capsule buttons of the redesign. Primary is monochrome, fg on bg inverted (decision D-2), and ignores the
/// accent color; secondary sits on `fill2`. Pressed buttons shrink to 97 %; disabled ones fade to 38 %, and the
/// view says why next to them. Keyboard focus keeps the system focus ring, shaped to the capsule. Labels never
/// truncate: the button grows instead.
struct CapsuleButtonStyle: ButtonStyle {
    enum Kind { case primary, secondary }

    enum Size {
        /// 28 pt, 12 pt label ("Show all").
        case small
        /// 32 pt, for sheets and inline actions.
        case compact
        /// 36 pt, the default.
        case regular
        /// 40 pt and at least 120 pt wide, 14 pt label: the detail's primary action.
        case large

        var height: CGFloat {
            switch self {
            case .small: return 28
            case .compact: return 32
            case .regular: return 36
            case .large: return 40
            }
        }

        var padding: CGFloat {
            switch self {
            case .small: return 12
            case .compact: return 14
            case .regular: return 16
            case .large: return 22
            }
        }

        var minWidth: CGFloat? { self == .large ? 120 : nil }

        var typography: Typography {
            switch self {
            case .small: return .buttonSmall
            case .compact, .regular: return .bodyEmphasized
            case .large: return .buttonLarge
            }
        }
    }

    var kind: Kind
    var size: Size = .regular
    /// Keeps buttons that swap labels ("Copy code" → "Copied ✓") from changing width.
    var minWidth: CGFloat?

    func makeBody(configuration: Configuration) -> some View {
        CapsuleButton(configuration: configuration, kind: kind, size: size, minWidth: minWidth ?? size.minWidth)
    }
}

extension ButtonStyle where Self == CapsuleButtonStyle {
    static var primaryCapsule: CapsuleButtonStyle { CapsuleButtonStyle(kind: .primary) }
    static var secondaryCapsule: CapsuleButtonStyle { CapsuleButtonStyle(kind: .secondary) }
    /// A small secondary capsule, for actions in a card's header ("Show all").
    static var smallCapsule: CapsuleButtonStyle { CapsuleButtonStyle(kind: .secondary, size: .small) }

    static func primaryCapsule(_ size: CapsuleButtonStyle.Size, minWidth: CGFloat? = nil) -> CapsuleButtonStyle {
        CapsuleButtonStyle(kind: .primary, size: size, minWidth: minWidth)
    }

    static func secondaryCapsule(_ size: CapsuleButtonStyle.Size, minWidth: CGFloat? = nil) -> CapsuleButtonStyle {
        CapsuleButtonStyle(kind: .secondary, size: size, minWidth: minWidth)
    }
}

private struct CapsuleButton: View {
    let configuration: ButtonStyleConfiguration
    let kind: CapsuleButtonStyle.Kind
    let size: CapsuleButtonStyle.Size
    let minWidth: CGFloat?
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        configuration.label
            .typography(size.typography)
            .lineLimit(1)
            .fixedSize()
            .padding(.horizontal, size.padding)
            .frame(minWidth: minWidth, minHeight: size.height)
            .foregroundStyle(kind == .primary ? Palette.onPrimary : Palette.fg)
            .background(kind == .primary ? Palette.primary : Palette.fill2, in: Capsule())
            // Clear unless Increase Contrast is on: then secondary buttons get an edge, like the system's controls.
            .edge(Capsule(), kind == .secondary ? Palette.controlEdge : .clear)
            .contentShape(Capsule())
            .contentShape(.focusEffect, Capsule())
            .scaleEffect(configuration.isPressed ? Motion.pressedScale : 1)
            .opacity(isEnabled ? 1 : 0.38)
    }
}
