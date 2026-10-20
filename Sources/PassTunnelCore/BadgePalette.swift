import Foundation

/// An sRGB color as 8-bit components, shared by the app (SwiftUI/AppKit) and the CLI (ANSI).
public struct RGBColor: Equatable, Hashable, Sendable {
    public let red: UInt8
    public let green: UInt8
    public let blue: UInt8

    public init(_ red: UInt8, _ green: UInt8, _ blue: UInt8) {
        self.red = red
        self.green = green
        self.blue = blue
    }

    /// Components in 0...1, e.g. for `Color(red:green:blue:)`.
    public var components: (red: Double, green: Double, blue: Double) {
        (Double(red) / 255, Double(green) / 255, Double(blue) / 255)
    }

    /// "#RRGGBB".
    public var hex: String { String(format: "#%02X%02X%02X", red, green, blue) }

    /// 24-bit ANSI foreground escape sequence.
    public var ansiForeground: String { "\u{1B}[38;2;\(red);\(green);\(blue)m" }
}

/// What a badge color stands for. `connecting` is also used for "connected but unreachable".
public enum BadgeTone: String, CaseIterable, Sendable { case connected, connecting, disconnected }

/// Menu-bar badge color sets (Settings → General → Badge palette).
public enum BadgePalette: String, Codable, CaseIterable, Sendable {
    case pastel, vivid, soft, candy, earth

    public var connected: RGBColor {
        switch self {
        case .pastel: return RGBColor(120, 204, 140)
        case .vivid: return RGBColor(52, 199, 89)
        case .soft: return RGBColor(140, 184, 152)
        case .candy: return RGBColor(102, 230, 178)
        case .earth: return RGBColor(120, 153, 84)
        }
    }

    public var connecting: RGBColor {
        switch self {
        case .pastel: return RGBColor(245, 199, 107)
        case .vivid: return RGBColor(255, 159, 10)
        case .soft: return RGBColor(217, 184, 128)
        case .candy: return RGBColor(255, 153, 204)
        case .earth: return RGBColor(204, 148, 64)
        }
    }

    public var disconnected: RGBColor {
        switch self {
        case .pastel: return RGBColor(178, 184, 194)
        case .vivid: return RGBColor(142, 142, 147)
        case .soft: return RGBColor(158, 163, 168)
        case .candy: return RGBColor(191, 178, 217)
        case .earth: return RGBColor(153, 140, 128)
        }
    }

    public func color(_ tone: BadgeTone) -> RGBColor {
        switch tone {
        case .connected: return connected
        case .connecting: return connecting
        case .disconnected: return disconnected
        }
    }

    /// Localized name for pickers.
    public var displayName: String {
        switch self {
        case .pastel: return String(localized: "Pastel")
        case .vivid: return String(localized: "Vivid")
        case .soft: return String(localized: "Soft")
        case .candy: return String(localized: "Candy")
        case .earth: return String(localized: "Earth")
        }
    }
}
