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
