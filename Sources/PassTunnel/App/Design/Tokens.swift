import AppKit
import SwiftUI

// Design tokens of the redesigned interface (docs/APP.md, Design system). Mostly monochrome: color appears only
// when it means something, and always together with an icon and words.

/// Colors. Each token has a light, a dark and an Increase Contrast value and resolves per `NSAppearance`, so
/// views, offscreen renders and AppKit drawing follow the window's appearance. Window and sidebar backgrounds
/// are the system's (decision D-1), so fills, hairlines, the selection and the ring track are translucent: on
/// white and black they give the design's values, and on the system backgrounds they keep the same contrast.
enum Palette {
    // Surfaces
    static let background = Color(nsColor: .windowBackgroundColor)
    static let card = Color(nsColor: Raw.card)
    static let fill = Color(nsColor: Raw.fill)
    static let fill2 = Color(nsColor: Raw.fill2)
    static let line = Color(nsColor: Raw.line)
    static let selection = Color(nsColor: Raw.selection)
    static let track = Color(nsColor: Raw.track)

    // Text, and the primary button (fg on bg, inverted). Each tier keeps 4.5:1 on the window and on cards;
    // text on a `fill` uses fg or fg2 (fg3 drops below 4.5:1 there in dark mode).
    static let fg = Color(nsColor: Raw.fg)
    static let fg2 = Color(nsColor: Raw.fg2)
    static let fg3 = Color(nsColor: Raw.fg3)
    static let primary = Color(nsColor: Raw.primary)
    static let onPrimary = Color(nsColor: Raw.onPrimary)

    // State: text colors, and the stronger ones for dots, the ring and glyphs
    static let green = Color(nsColor: Raw.green)
    static let amber = Color(nsColor: Raw.amber)
    static let amberRing = Color(nsColor: Raw.amberRing)
    static let red = Color(nsColor: Raw.red)
    static let redDot = Color(nsColor: Raw.redDot)

    // Edges: secondary controls get one only with Increase Contrast; glass edge and shadow (the material
    // itself is the system's)
    static let controlEdge = Color(nsColor: Raw.controlEdge)
    static let glassEdge = Color(nsColor: Raw.glassEdge)
    static let glassShadow = Color(nsColor: Raw.glassShadow)

    /// Renders the Increase Contrast values whatever the setting (`PASSTUNNEL_RENDER` only: an offscreen
    /// window cannot be given the high-contrast appearance).
    static var previewIncreasedContrast = false

    /// The tokens as `NSColor`s, for AppKit drawing and the component render.
    enum Raw {
        static let card = dynamic("card", light: .hex(0xFFFFFF), dark: .white(0.043))
        static let fill = dynamic("fill", light: .black(0.043), dark: .white(0.08),
                                  contrast: (.black(0.06), .white(0.11)))
        static let fill2 = dynamic("fill2", light: .black(0.078), dark: .white(0.115),
                                   contrast: (.black(0.11), .white(0.17)))
        static let line = dynamic("line", light: .black(0.105), dark: .white(0.15),
                                  contrast: (.black(0.21), .white(0.23)))
        static let selection = dynamic("selection", light: .black(0.07), dark: .white(0.10),
                                       contrast: (.black(0.12), .white(0.16)))
        static let track = dynamic("track", light: .black(0.094), dark: .white(0.173),
                                   contrast: (.black(0.16), .white(0.26)))

        static let fg = dynamic("fg", light: .hex(0x0B0B0C), dark: .hex(0xF5F5F7),
                                contrast: (.hex(0x000000), .hex(0xFFFFFF)))
        static let fg2 = dynamic("fg2", light: .hex(0x5C5C62), dark: .hex(0xA1A1A8),
                                 contrast: (.hex(0x404045), .hex(0xC7C7CC)))
        static let fg3 = dynamic("fg3", light: .hex(0x6B6B70), dark: .hex(0x8E8E95),
                                 contrast: (.hex(0x4E4E53), .hex(0xB4B4BB)))
        static let primary = dynamic("primary", light: .hex(0x0B0B0C), dark: .hex(0xF5F5F7),
                                     contrast: (.hex(0x000000), .hex(0xFFFFFF)))
        static let onPrimary = dynamic("onPrimary", light: .hex(0xFFFFFF), dark: .hex(0x000000))

        static let green = dynamic("green", light: .hex(0x1C7C3A), dark: .hex(0x42C66A),
                                   contrast: (.hex(0x136030), .hex(0x5ED27F)))
        static let amber = dynamic("amber", light: .hex(0x965A00), dark: .hex(0xFFB43A),
                                   contrast: (.hex(0x754600), .hex(0xFFC766)))
        static let amberRing = dynamic("amberRing", light: .hex(0xE59A00), dark: .hex(0xFFB43A),
                                       contrast: (.hex(0xB57800), .hex(0xFFC766)))
        static let red = dynamic("red", light: .hex(0xC4291C), dark: .hex(0xFF6A5C),
                                 contrast: (.hex(0x9E1F14), .hex(0xFF9A91)))
        static let redDot = dynamic("redDot", light: .hex(0xE5483A), dark: .hex(0xFF5A4C),
                                    contrast: (.hex(0xC4291C), .hex(0xFF7A6E)))

        static let controlEdge = dynamic("controlEdge", light: .black(0), dark: .white(0),
                                         contrast: (.black(0.21), .white(0.23)))
        static let glassEdge = dynamic("glassEdge", light: .black(0.10), dark: .white(0.12))
        static let glassShadow = dynamic("glassShadow", light: .black(0.08), dark: .black(0.5))

        /// Every token, in the order the component render shows them.
        static let all: [(name: String, color: NSColor)] = [
            ("card", card), ("fill", fill), ("fill2", fill2), ("line", line), ("selection", selection),
            ("track", track), ("fg", fg), ("fg2", fg2), ("fg3", fg3), ("primary", primary),
            ("onPrimary", onPrimary), ("green", green), ("amber", amber), ("amberRing", amberRing), ("red", red),
            ("redDot", redDot), ("controlEdge", controlEdge), ("glassEdge", glassEdge), ("glassShadow", glassShadow),
        ]

        /// A color that resolves per appearance; Increase Contrast uses `contrast` (light, dark) when given.
        private static func dynamic(_ name: String, light: NSColor, dark: NSColor,
                                    contrast: (light: NSColor, dark: NSColor)? = nil) -> NSColor {
            NSColor(name: "PassTunnel.\(name)") { appearance in
                let match = appearance.bestMatch(from: [.aqua, .darkAqua, .accessibilityHighContrastAqua,
                                                        .accessibilityHighContrastDarkAqua])
                let isDark = match == .darkAqua || match == .accessibilityHighContrastDarkAqua
                let increased = previewIncreasedContrast || match == .accessibilityHighContrastAqua
                    || match == .accessibilityHighContrastDarkAqua
                guard increased, let contrast else { return isDark ? dark : light }
                return isDark ? contrast.dark : contrast.light
            }
        }
    }
}

private extension NSColor {
    static func hex(_ value: UInt32) -> NSColor {
        NSColor(srgbRed: CGFloat((value >> 16) & 0xFF) / 255, green: CGFloat((value >> 8) & 0xFF) / 255,
                blue: CGFloat(value & 0xFF) / 255, alpha: 1)
    }

    static func black(_ alpha: CGFloat) -> NSColor { NSColor(srgbRed: 0, green: 0, blue: 0, alpha: alpha) }
    static func white(_ alpha: CGFloat) -> NSColor { NSColor(srgbRed: 1, green: 1, blue: 1, alpha: alpha) }
}

/// Text roles on macOS (13 pt base): a system text style where the size matches one, SF Mono for codes and logs,
/// and the design's tracking (em × size).
struct Typography {
    var font: Font
    var tracking: CGFloat = 0
    var lineSpacing: CGFloat = 0

    /// Profile name above the detail (28 bold, −0.02 em).
    static let detailTitle = Typography(font: .system(size: 28, weight: .bold), tracking: -0.56)
    /// First-run and error screens (26 bold, −0.02 em).
    static let screenTitle = Typography(font: .largeTitle.bold(), tracking: -0.52)
    /// Import review (22 bold).
    static let reviewTitle = Typography(font: .title.bold())
    /// Dialogs (17 bold, −0.01 em).
    static let dialogTitle = Typography(font: .title2.bold(), tracking: -0.17)
    /// Sheets (15 bold).
    static let sheetTitle = Typography(font: .title3.bold())
    /// The detail's status line, next to a 20 pt status icon (15 semibold).
    static let statusLine = Typography(font: .title3.weight(.semibold))
    /// Body text, rows and fields (13).
    static let body = Typography(font: .body)
    /// Profile names in rows, and buttons (13 semibold).
    static let bodyEmphasized = Typography(font: .body.weight(.semibold))
    /// The detail's primary button (14 semibold).
    static let buttonLarge = Typography(font: .system(size: 14, weight: .semibold))
    /// Small buttons ("Show all") and the menu bar panel header (12 semibold).
    static let buttonSmall = Typography(font: .callout.weight(.semibold))
    /// Card hints, footers and "Next 771 204" (12).
    static let hint = Typography(font: .callout)
    /// The status under a profile name in a row (11.5 medium, in the state's color).
    static let rowStatus = Typography(font: .system(size: 11.5, weight: .medium))
    /// Section labels above card content, uppercased (11 semibold, +0.05 em).
    static let sectionLabel = Typography(font: .system(size: 11, weight: .semibold), tracking: 0.55)
    /// The current code in the detail (44 medium mono, −0.03 em).
    static let heroCode = Typography(font: .system(size: 44, weight: .medium, design: .monospaced), tracking: -1.32)
    /// The code in the profile editor (18 medium mono).
    static let editorCode = Typography(font: .system(size: 18, weight: .medium, design: .monospaced))
    /// Codes in rows and the menu bar panel (13 mono).
    static let rowCode = Typography(font: .system(size: 13, design: .monospaced))
    /// Seconds next to the countdown ring (13 semibold mono).
    static let seconds = Typography(font: .system(size: 13, weight: .semibold, design: .monospaced))
    /// Log lines (11.5 mono, line height 1.65).
    static let log = Typography(font: .system(size: 11.5, design: .monospaced), lineSpacing: 5)
}

extension View {
    func typography(_ style: Typography) -> some View {
        font(style.font).tracking(style.tracking).lineSpacing(style.lineSpacing)
    }
}

/// The spacing scale (pt). Paddings of cards and buttons are part of those components.
enum Spacing {
    static let xxs: CGFloat = 4
    static let xs: CGFloat = 8
    static let s: CGFloat = 12
    static let m: CGFloat = 16
    static let l: CGFloat = 24
    static let xl: CGFloat = 32
    static let xxl: CGFloat = 48
}

/// Corner radii (pt), drawn continuous as everywhere on macOS. Windows, sheets and notifications keep the
/// system's; buttons are capsules.
enum Radius {
    /// Cards in the main window.
    static let card: CGFloat = 18
    /// Cards in sheets, the first run and error screens; the drop zone and tiles.
    static let compactCard: CGFloat = 14
    /// The sidebar and the menu bar panel.
    static let panel: CGFloat = 16
    /// Rows in the sidebar.
    static let row: CGFloat = 12
    /// Fields, popups, menu items and inset tables.
    static let field: CGFloat = 8
}

/// Depth. Cards are flat: a 1 pt hairline and no shadow. Glass (toolbar capsule, menu bar panel, sheets) is
/// the system's material with an edge and a soft shadow, and is never under codes or rows.
enum Elevation {
    struct Shadow {
        var radius: CGFloat
        var y: CGFloat
    }

    static let hairline: CGFloat = 1
    static let glassEdge: CGFloat = 0.5
    /// Toolbar capsule and sidebar.
    static let glass = Shadow(radius: 10, y: 6)
    /// Menu bar panel, sheets and notifications.
    static let floating = Shadow(radius: 20, y: 14)
}

/// Motion: time moves linearly and never bounces; nothing pulses or scales for attention.
enum Motion {
    /// Seconds left at which the ring and the seconds turn amber.
    static let lastSeconds: Double = 5
    /// Color changes (ring and seconds turning amber, a status turning green).
    static let colorChange = Animation.easeOut(duration: 0.2)
    static let colorChangeDuration: Double = 0.2
    /// A new code rolls in (numeric text transition), smooth and without bounce.
    static let codeChange = Animation.spring(response: 0.3, dampingFraction: 1)
    /// Under Reduce Motion a new code crossfades, with no movement.
    static let reducedCodeChange = Animation.easeInOut(duration: 0.15)
    /// The ring refills from empty when a new code starts; it never runs backwards.
    static let refillDuration: Double = 0.24
    /// One turn of the connecting and reconnecting glyphs (they stand still under Reduce Motion).
    static let spinPeriod: Double = 1.2
    /// How long "Copied ✓" stays (it clears early when the code changes).
    static let copiedDuration: Double = 1.6
    /// Pressed buttons.
    static let pressedScale: CGFloat = 0.97
}
