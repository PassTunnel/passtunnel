import SwiftUI

/// A hairline card: the `card` color, a 1 pt `line` border and no shadow. Its content is stacked from the
/// leading edge, and the card takes the full width it is offered.
struct Card<Content: View>: View {
    enum Style {
        /// Main window: radius 18, padding 16 × 18.
        case regular
        /// Sheets, first run and error screens: radius 14, padding 14 × 16.
        case compact

        var radius: CGFloat { self == .regular ? Radius.card : Radius.compactCard }
        var insets: EdgeInsets {
            self == .regular
                ? EdgeInsets(top: 16, leading: 18, bottom: 16, trailing: 18)
                : EdgeInsets(top: 14, leading: 16, bottom: 14, trailing: 16)
        }
        var spacing: CGFloat { self == .regular ? 8 : 10 }
    }

    var style: Style = .regular
    @ViewBuilder var content: Content

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: style.radius, style: .continuous)
        VStack(alignment: .leading, spacing: style.spacing) { content }
            .padding(style.insets)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Palette.card, in: shape)
            .edge(shape, Palette.line)
    }
}

/// The small uppercase label at the top of a card ("CURRENT CODE", "LOG"): 11 pt semibold, +0.05 em, `fg2`.
/// Pass a localized string; VoiceOver treats it as a heading.
struct SectionLabel: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .typography(.sectionLabel)
            .textCase(.uppercase)
            .foregroundStyle(Palette.fg2)
            .accessibilityAddTraits(.isHeader)
    }
}

extension View {
    /// Glass for chrome only (toolbar capsule, menu bar panel, sheets): Liquid Glass on macOS 26, and before
    /// that `materialGlass` (decision D-20). The system makes both opaque with Reduce Transparency.
    @ViewBuilder
    func glass<S: InsettableShape>(in shape: S, shadow: Elevation.Shadow = Elevation.glass) -> some View {
        if #available(macOS 26, *) {
            glassEffect(.regular, in: shape)
        } else {
            materialGlass(in: shape, shadow: shadow)
        }
    }

    /// The glass of macOS 13–15: the system's regular material with the design's edge and shadow.
    func materialGlass<S: InsettableShape>(in shape: S, shadow: Elevation.Shadow = Elevation.glass) -> some View {
        background(.regularMaterial, in: shape)
            .edge(shape, Palette.glassEdge, width: Elevation.glassEdge)
            .shadow(color: Palette.glassShadow, radius: shadow.radius, y: shadow.y)
    }

    /// A hairline just inside `shape`'s outline.
    func edge<S: InsettableShape>(_ shape: S, _ color: Color, width: CGFloat = Elevation.hairline) -> some View {
        overlay(InnerEdge(shape: shape, width: width).fill(color, style: FillStyle(eoFill: true)))
    }
}

/// The band between a shape and its inset, filled rather than stroked: SwiftUI strokes a fully rounded shape (a
/// capsule) with flat, protruding ends.
private struct InnerEdge<S: InsettableShape>: Shape {
    var shape: S
    var width: CGFloat

    func path(in rect: CGRect) -> Path {
        var path = shape.path(in: rect)
        path.addPath(shape.inset(by: width).path(in: rect))
        return path
    }
}
