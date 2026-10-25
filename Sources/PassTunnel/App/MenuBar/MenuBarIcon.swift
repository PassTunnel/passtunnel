import AppKit
import PassTunnelCore

/// Draws the status item title: optional lock symbol followed by one colored badge per visible profile.
enum MenuBarIcon {
    struct Badge: Equatable {
        var text: String
        var symbol: String?
        var tone: BadgeTone
        var dropped = false
    }

    static let height: CGFloat = 18
    static let badgeHeight: CGFloat = 15
    static let spacing: CGFloat = 3

    @MainActor static func badges(for model: AppModel) -> [Badge] {
        model.menuBarProfiles.map { p in
            let tone: BadgeTone
            switch model.statusKind(p) {
            case .connected: tone = .connected
            case .connecting, .degraded: tone = .connecting
            case .disconnected, .error, .dropped: tone = .disconnected
            }
            let symbol = p.badgeStyle == .letter || p.icon.isEmpty ? nil : p.icon
            let text = p.badgeStyle == .icon && symbol != nil ? "" : String(p.displayBadge.prefix(3))
            return Badge(text: text, symbol: symbol, tone: tone, dropped: model.droppedUnseen.contains(p.id))
        }
    }

    @MainActor static func image(for model: AppModel) -> NSImage {
        let badges = badges(for: model)
        let anyConnected = badges.contains { $0.tone == .connected }
        return image(badges: badges, palette: model.prefs.badgePalette,
                     showLock: model.prefs.showLock || badges.isEmpty, locked: anyConnected)
    }

    static func image(badges: [Badge], palette: BadgePalette, showLock: Bool, locked: Bool) -> NSImage {
        let lock = showLock ? lockImage(locked: locked) : nil
        var width: CGFloat = 0
        if let lock { width += lock.size.width }
        let widths = badges.map(badgeWidth)
        if !badges.isEmpty {
            if lock != nil { width += 4 }
            width += widths.reduce(0, +) + spacing * CGFloat(badges.count - 1)
        }
        let size = NSSize(width: max(ceil(width), 1), height: height)
        let image = NSImage(size: size, flipped: false) { _ in
            var x: CGFloat = 0
            if let lock {
                let tinted = tint(lock, NSColor.labelColor)
                tinted.draw(in: NSRect(x: 0, y: (height - lock.size.height) / 2, width: lock.size.width, height: lock.size.height))
                x += lock.size.width + 4
            }
            for (badge, w) in zip(badges, widths) {
                draw(badge, in: NSRect(x: x, y: (height - badgeHeight) / 2, width: w, height: badgeHeight), palette: palette)
                x += w + spacing
            }
            return true
        }
        image.isTemplate = false
        image.accessibilityDescription = "PassTunnel"
        return image
    }

    // MARK: drawing

    private static let font = NSFont.systemFont(ofSize: 10.5, weight: .bold)

    private static func badgeWidth(_ b: Badge) -> CGFloat {
        var w: CGFloat = 0
        if b.symbol != nil { w += 11 }
        if !b.text.isEmpty {
            if b.symbol != nil { w += 2 }
            w += ceil((b.text as NSString).size(withAttributes: [.font: font]).width)
        }
        return max(badgeHeight, w + 8)
    }

    private static func draw(_ b: Badge, in rect: NSRect, palette: BadgePalette) {
        let c = palette.color(b.tone).components
        let fill = NSColor(srgbRed: c.red, green: c.green, blue: c.blue, alpha: 1)
        let path = NSBezierPath(roundedRect: rect, xRadius: 4, yRadius: 4)
        fill.setFill()
        path.fill()

        let luminance = 0.2126 * c.red + 0.7152 * c.green + 0.0722 * c.blue
        let ink = luminance > 0.6 ? NSColor.black.withAlphaComponent(0.82) : NSColor.white
        var x = rect.minX + 4
        if let symbol = b.symbol, let img = symbolImage(symbol, pointSize: 9) {
            let s = img.size
            let scale = min(11 / s.width, 11 / s.height, 1)
            let r = NSRect(x: x + (11 - s.width * scale) / 2, y: rect.midY - s.height * scale / 2,
                           width: s.width * scale, height: s.height * scale)
            tint(img, ink).draw(in: r)
            x += 11 + 2
        }
        if !b.text.isEmpty {
            let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: ink]
            let ts = (b.text as NSString).size(withAttributes: attrs)
            let tx = b.symbol == nil ? rect.midX - ts.width / 2 : x
            (b.text as NSString).draw(at: NSPoint(x: tx, y: rect.midY - ts.height / 2 + 0.5), withAttributes: attrs)
        }
        if b.dropped {
            // Small red marker: dropped and not seen yet.
            let d: CGFloat = 6
            let dot = NSRect(x: rect.maxX - d + 1.5, y: rect.maxY - d + 1.5, width: d, height: d)
            NSColor.systemRed.setFill()
            NSBezierPath(ovalIn: dot).fill()
        }
    }

    // MARK: new interface

    /// The status item of the new interface (`NewInterface`): a monochrome shield with the lock body cut out, 16 pt,
    /// as a template image that the menu bar tints. While a drop has not been seen, a small dot sits at its top
    /// right, cut free of the shield (no color: the menu bar draws template images in one).
    static func shield(dropped: Bool) -> NSImage {
        dropped ? droppedShield : plainShield
    }

    private static let plainShield = makeShield(dropped: false)
    private static let droppedShield = makeShield(dropped: true)

    private static func makeShield(dropped: Bool) -> NSImage {
        let side: CGFloat = 16
        let image = NSImage(size: NSSize(width: side, height: side), flipped: false) { _ in
            // 20 grid units across the image, centered on the glyph: as tall as the system's status symbols.
            let unit = side / 20
            let transform = AffineTransform(m11: unit, m12: 0, m21: 0, m22: -unit,
                                            tX: side / 2 - 12 * unit, tY: side / 2 + 11.3 * unit)
            func fill(_ path: NSBezierPath) {
                path.transform(using: transform)
                path.fill()
            }
            NSColor.black.setFill()
            fill(shieldOutline())
            if dropped {
                NSGraphicsContext.current?.compositingOperation = .clear
                fill(NSBezierPath(ovalIn: NSRect(x: 14.7, y: 0.5, width: 7.4, height: 7.4)))
                NSGraphicsContext.current?.compositingOperation = .sourceOver
                fill(NSBezierPath(ovalIn: NSRect(x: 15.9, y: 1.7, width: 5, height: 5)))
            }
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "PassTunnel"
        return image
    }

    /// The shield and its cut-out lock body on the glyph's 24-unit grid, y down.
    private static func shieldOutline() -> NSBezierPath {
        let path = NSBezierPath()
        path.move(to: NSPoint(x: 6.6, y: 4.2))
        path.curve(to: NSPoint(x: 12, y: 2.8), controlPoint1: NSPoint(x: 9, y: 4.2), controlPoint2: NSPoint(x: 10.7, y: 3.6))
        path.curve(to: NSPoint(x: 17.4, y: 4.2), controlPoint1: NSPoint(x: 13.3, y: 3.6), controlPoint2: NSPoint(x: 15, y: 4.2))
        path.curve(to: NSPoint(x: 18.4, y: 5.2), controlPoint1: NSPoint(x: 18.2, y: 4.2), controlPoint2: NSPoint(x: 18.4, y: 4.6))
        path.line(to: NSPoint(x: 18.4, y: 11))
        path.curve(to: NSPoint(x: 12, y: 19.8), controlPoint1: NSPoint(x: 18.4, y: 15.4), controlPoint2: NSPoint(x: 15.8, y: 18.2))
        path.curve(to: NSPoint(x: 5.6, y: 11), controlPoint1: NSPoint(x: 8.2, y: 18.2), controlPoint2: NSPoint(x: 5.6, y: 15.4))
        path.line(to: NSPoint(x: 5.6, y: 5.2))
        path.curve(to: NSPoint(x: 6.6, y: 4.2), controlPoint1: NSPoint(x: 5.6, y: 4.6), controlPoint2: NSPoint(x: 5.8, y: 4.2))
        path.close()
        path.append(NSBezierPath(roundedRect: NSRect(x: 9.3, y: 9.8, width: 5.4, height: 4.2), xRadius: 1, yRadius: 1))
        path.windingRule = .evenOdd
        return path
    }

    private static func lockImage(locked: Bool) -> NSImage? {
        symbolImage(locked ? "lock.fill" : "lock.open.fill", pointSize: 13)
    }

    private static func symbolImage(_ name: String, pointSize: CGFloat) -> NSImage? {
        NSImage(systemSymbolName: name, accessibilityDescription: nil)?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: pointSize, weight: .semibold))
    }

    private static func tint(_ image: NSImage, _ color: NSColor) -> NSImage {
        let out = NSImage(size: image.size, flipped: false) { rect in
            image.draw(in: rect)
            color.set()
            rect.fill(using: .sourceAtop)
            return true
        }
        return out
    }
}
