#!/usr/bin/env swift
// Renders the PassTunnel app icon with AppKit and builds Resources/AppIcon.icns.
//
//   swift scripts/make-icon.swift                      # writes Resources/AppIcon.icns
//   swift scripts/make-icon.swift --iconset DIR        # also keeps the .iconset PNGs in DIR
//   swift scripts/make-icon.swift --icns PATH          # different output file
//
// Artwork: a macOS-style squircle with a deep teal → blue gradient, a white shield-and-lock
// (the tunnel) and a code badge cut out of it (the one-time code). Small sizes get a simplified
// badge (dots instead of digits) so the icon stays legible at 16 px.
import AppKit

let canvas: CGFloat = 1024

struct Palette {
    static let top = NSColor(srgbRed: 0.06, green: 0.62, blue: 0.62, alpha: 1)      // deep teal
    static let bottom = NSColor(srgbRed: 0.11, green: 0.29, blue: 0.80, alpha: 1)   // blue
    static let glyphShadow = NSColor(srgbRed: 0.02, green: 0.12, blue: 0.35, alpha: 0.35)
}

/// Rounded rectangle with continuous ("squircle") corners, close to the macOS app icon shape.
func squircle(in rect: CGRect, radius: CGFloat) -> CGPath {
    let r = min(radius, min(rect.width, rect.height) / 2 / 1.52866483)
    // One corner (top right, y up), as offsets from the corner point: three cubic segments.
    let segments: [(CGPoint, CGPoint, CGPoint)] = [
        (CGPoint(x: -1.08849323, y: 0), CGPoint(x: -0.86840689, y: 0), CGPoint(x: -0.63149399, y: -0.07491139)),
        (CGPoint(x: -0.37282392, y: -0.16906013), CGPoint(x: -0.16906013, y: -0.37282392), CGPoint(x: -0.07491139, y: -0.63149399)),
        (CGPoint(x: 0, y: -0.86840689), CGPoint(x: 0, y: -1.08849323), CGPoint(x: 0, y: -1.52866483)),
    ]
    // Clockwise: top right, bottom right, bottom left, top left; each turn rotates offsets by -90°.
    let corners = [CGPoint(x: rect.maxX, y: rect.maxY), CGPoint(x: rect.maxX, y: rect.minY),
                   CGPoint(x: rect.minX, y: rect.minY), CGPoint(x: rect.minX, y: rect.maxY)]
    func rotate(_ p: CGPoint, _ turns: Int) -> CGPoint {
        var q = p
        for _ in 0..<turns { q = CGPoint(x: q.y, y: -q.x) }
        return q
    }
    let path = CGMutablePath()
    for (i, corner) in corners.enumerated() {
        func pt(_ o: CGPoint) -> CGPoint {
            let v = rotate(o, i)
            return CGPoint(x: corner.x + v.x * r, y: corner.y + v.y * r)
        }
        let start = pt(CGPoint(x: -1.52866483, y: 0))
        if i == 0 { path.move(to: start) } else { path.addLine(to: start) }
        for (c1, c2, end) in segments { path.addCurve(to: pt(end), control1: pt(c1), control2: pt(c2)) }
    }
    path.closeSubpath()
    return path
}

/// A white SF Symbol (monochrome, so cut-outs such as the lock in "lock.shield.fill" stay transparent).
func symbol(_ name: String, pointSize: CGFloat, weight: NSFont.Weight) -> NSImage {
    let config = NSImage.SymbolConfiguration(pointSize: pointSize, weight: weight)
    guard let template = NSImage(systemSymbolName: name, accessibilityDescription: nil)?
        .withSymbolConfiguration(config) else {
        fatalError("SF Symbol \(name) is not available on this system")
    }
    return NSImage(size: template.size, flipped: false) { rect in
        template.draw(in: rect)
        NSColor.white.set()
        rect.fill(using: .sourceAtop)
        return true
    }
}

/// Draws the icon into the current context, in a 1024 × 1024 coordinate space.
/// `pixels` is the final pixel size (used to scale shadows and pick the small-size badge).
func drawIcon(in ctx: CGContext, pixels: Int) {
    let s = CGFloat(pixels) / canvas
    let small = pixels <= 64
    // Small sizes use more of the canvas, as Apple's own small icons do.
    let inset: CGFloat = small ? 64 : 100
    let body = CGRect(x: inset, y: inset, width: canvas - 2 * inset, height: canvas - 2 * inset)
    let shape = squircle(in: body, radius: body.width * 0.225)

    // Drop shadow under the tile.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -10 * s), blur: 26 * s,
                  color: NSColor(white: 0, alpha: small ? 0.22 : 0.32).cgColor)
    ctx.addPath(shape)
    ctx.setFillColor(Palette.bottom.cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    // Gradient body.
    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    let gradient = CGGradient(colorsSpace: space, colors: [Palette.top.cgColor, Palette.bottom.cgColor] as CFArray,
                              locations: [0, 1])!
    ctx.drawLinearGradient(gradient, start: CGPoint(x: 0, y: body.maxY), end: CGPoint(x: 0, y: body.minY), options: [])

    // Soft highlight across the top.
    let highlight = CGGradient(colorsSpace: space,
                               colors: [NSColor(white: 1, alpha: 0.26).cgColor, NSColor(white: 1, alpha: 0).cgColor] as CFArray,
                               locations: [0, 1])!
    ctx.drawRadialGradient(highlight,
                           startCenter: CGPoint(x: body.midX, y: body.maxY + body.height * 0.15), startRadius: 0,
                           endCenter: CGPoint(x: body.midX, y: body.maxY + body.height * 0.15), endRadius: body.height * 0.85,
                           options: [])
    // Slight darkening at the bottom for depth.
    let shade = CGGradient(colorsSpace: space,
                           colors: [NSColor(white: 0, alpha: 0).cgColor, NSColor(white: 0, alpha: 0.12).cgColor] as CFArray,
                           locations: [0, 1])!
    ctx.drawLinearGradient(shade, start: CGPoint(x: 0, y: body.midY), end: CGPoint(x: 0, y: body.minY), options: [])
    ctx.restoreGState()

    // Hairline edge: lighter at the top.
    if !small {
        ctx.saveGState()
        ctx.addPath(shape)
        ctx.setLineWidth(3)
        ctx.replacePathWithStrokedPath()
        ctx.clip()
        let edge = CGGradient(colorsSpace: space,
                              colors: [NSColor(white: 1, alpha: 0.35).cgColor, NSColor(white: 1, alpha: 0.04).cgColor] as CFArray,
                              locations: [0, 1])!
        ctx.drawLinearGradient(edge, start: CGPoint(x: 0, y: body.maxY), end: CGPoint(x: 0, y: body.midY), options: [])
        ctx.restoreGState()
    }

    // Glyph group: shield + badge, with the badge outline and digits knocked out.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -8 * s), blur: 18 * s, color: Palette.glyphShadow.cgColor)
    ctx.beginTransparencyLayer(auxiliaryInfo: nil)

    // Target height of the symbol image (it carries some padding around the visible shield).
    let shieldHeight: CGFloat = small ? 760 : 600
    // At 16 px the lock is only noise; a plain shield reads better.
    let shield = symbol(pixels <= 16 ? "shield.fill" : "lock.shield.fill", pointSize: shieldHeight, weight: .regular)
    let fit = shield.size
    let scale = shieldHeight / fit.height
    let shieldRect = CGRect(x: 0, y: 0, width: fit.width * scale, height: fit.height * scale)
    let center = small ? CGPoint(x: 440, y: 590) : CGPoint(x: 458, y: 570)
    let placed = shieldRect.offsetBy(dx: center.x - shieldRect.width / 2, dy: center.y - shieldRect.height / 2)
    NSGraphicsContext.current = NSGraphicsContext(cgContext: ctx, flipped: false)
    shield.draw(in: placed, from: .zero, operation: .sourceOver, fraction: 1)

    // Code badge, bottom right, overlapping the shield.
    let badgeSize = small ? CGSize(width: 500, height: 270) : CGSize(width: 390, height: 200)
    let badgeCenter = small ? CGPoint(x: 664, y: 290) : CGPoint(x: 666, y: 300)
    let badge = CGRect(x: badgeCenter.x - badgeSize.width / 2, y: badgeCenter.y - badgeSize.height / 2,
                       width: badgeSize.width, height: badgeSize.height)
    let gap: CGFloat = small ? 44 : 26
    let ring = badge.insetBy(dx: -gap, dy: -gap)
    ctx.setBlendMode(.clear)
    ctx.addPath(CGPath(roundedRect: ring, cornerWidth: ring.height / 2, cornerHeight: ring.height / 2, transform: nil))
    ctx.fillPath()
    ctx.setBlendMode(.normal)
    ctx.setFillColor(NSColor.white.cgColor)
    ctx.addPath(CGPath(roundedRect: badge, cornerWidth: badge.height / 2, cornerHeight: badge.height / 2, transform: nil))
    ctx.fillPath()

    ctx.setBlendMode(.clear)
    if small {
        // Three dots read better than digits at 16–32 px.
        let r: CGFloat = 50
        let spacing: CGFloat = 136
        for i in -1...1 {
            let c = CGPoint(x: badge.midX + CGFloat(i) * spacing, y: badge.midY)
            ctx.fillEllipse(in: CGRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r))
        }
    } else {
        let base = NSFont.systemFont(ofSize: 150, weight: .heavy)
        let font = base.fontDescriptor.withDesign(.rounded).flatMap { NSFont(descriptor: $0, size: 150) } ?? base
        let text = NSAttributedString(string: "123", attributes: [
            .font: font, .foregroundColor: NSColor.black, .kern: 4,
        ])
        let bounds = text.boundingRect(with: .zero, options: [.usesLineFragmentOrigin, .usesFontLeading])
        let glyphBox = CTLineGetImageBounds(CTLineCreateWithAttributedString(text), ctx)
        let origin = CGPoint(x: badge.midX - bounds.width / 2,
                             y: badge.midY - glyphBox.midY)
        let line = CTLineCreateWithAttributedString(text)
        ctx.textPosition = origin
        CTLineDraw(line, ctx)
    }
    ctx.setBlendMode(.normal)

    ctx.endTransparencyLayer()
    ctx.restoreGState()
}

func renderPNG(pixels: Int) -> Data {
    guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
                                     bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                     colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
          let gc = NSGraphicsContext(bitmapImageRep: rep) else { fatalError("cannot create bitmap") }
    rep.size = NSSize(width: pixels, height: pixels)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = gc
    let ctx = gc.cgContext
    ctx.clear(CGRect(x: 0, y: 0, width: pixels, height: pixels))
    ctx.interpolationQuality = .high
    ctx.setShouldAntialias(true)
    ctx.scaleBy(x: CGFloat(pixels) / canvas, y: CGFloat(pixels) / canvas)
    drawIcon(in: ctx, pixels: pixels)
    NSGraphicsContext.restoreGraphicsState()
    guard let data = rep.representation(using: .png, properties: [:]) else { fatalError("PNG encoding failed") }
    return data
}

// MARK: main

let repoRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
var icnsURL = repoRoot.appendingPathComponent("Resources/AppIcon.icns")
var keepIconset: URL?
var args = CommandLine.arguments.dropFirst()
while let arg = args.popFirst() {
    switch arg {
    case "--iconset": keepIconset = args.popFirst().map { URL(fileURLWithPath: $0) }
    case "--icns": if let p = args.popFirst() { icnsURL = URL(fileURLWithPath: p) }
    case "-h", "--help":
        print("usage: swift scripts/make-icon.swift [--iconset DIR] [--icns PATH]")
        exit(0)
    default:
        FileHandle.standardError.write(Data("unknown argument: \(arg)\n".utf8))
        exit(2)
    }
}

let fm = FileManager.default
let iconset = keepIconset ?? fm.temporaryDirectory.appendingPathComponent("PassTunnel-\(UUID().uuidString).iconset")
let iconsetDir = iconset.pathExtension == "iconset" ? iconset : iconset.appendingPathComponent("AppIcon.iconset")
try? fm.removeItem(at: iconsetDir)
try fm.createDirectory(at: iconsetDir, withIntermediateDirectories: true)

var cache: [Int: Data] = [:]
for base in [16, 32, 128, 256, 512] {
    for factor in [1, 2] {
        let pixels = base * factor
        let data = cache[pixels] ?? renderPNG(pixels: pixels)
        cache[pixels] = data
        let name = factor == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
        try data.write(to: iconsetDir.appendingPathComponent(name))
    }
}

try fm.createDirectory(at: icnsURL.deletingLastPathComponent(), withIntermediateDirectories: true)
let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", "-o", icnsURL.path, iconsetDir.path]
try iconutil.run()
iconutil.waitUntilExit()
if keepIconset == nil { try? fm.removeItem(at: iconsetDir) }
guard iconutil.terminationStatus == 0 else {
    FileHandle.standardError.write(Data("iconutil failed\n".utf8))
    exit(1)
}
print(icnsURL.path)
if keepIconset != nil { print(iconsetDir.path) }
