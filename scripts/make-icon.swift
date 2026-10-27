#!/usr/bin/env swift  // Renders the PassTunnel app icon with AppKit and builds Resources/AppIcon.icns.
//
//   swift scripts/make-icon.swift                      # writes Resources/AppIcon.icns
//   swift scripts/make-icon.swift --iconset DIR        # also keeps the .iconset PNGs in DIR
//   swift scripts/make-icon.swift --icns PATH          # different output file
//   swift scripts/make-icon.swift --preview DIR        # only writes PNG previews (16…1024 px) to DIR
//
// Artwork: flat, solid fills only (no gradients, highlights or shadows). A blue squircle with a white
// shield, a lock knocked out of it, and an amber one-time-code pill across its base. Small sizes are
// simplified so the icon stays legible: dots instead of digits at 32–64 px, and at 16 px the plain
// shield with an amber code bar.
import AppKit

let canvas: CGFloat = 1024

func rgb(_ hex: UInt32) -> CGColor {
    CGColor(
        srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
        blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
}

enum Palette {
    static let tile = rgb(0x2563EB)  // blue
    static let shield = rgb(0xFFFFFF)
    static let code = rgb(0xFFB224)  // amber
    static let digits = rgb(0x0B1636)  // ink
}

/// Rounded rectangle with continuous ("squircle") corners, close to the macOS app icon shape.
func squircle(in rect: CGRect, radius: CGFloat) -> CGPath {
    let r = min(radius, min(rect.width, rect.height) / 2 / 1.52866483)
    // One corner (top right, y up), as offsets from the corner point: three cubic segments.
    let segments: [(CGPoint, CGPoint, CGPoint)] = [
        (CGPoint(x: -1.08849323, y: 0), CGPoint(x: -0.86840689, y: 0), CGPoint(x: -0.63149399, y: -0.07491139)),
        (CGPoint(x: -0.37282392, y: -0.16906013), CGPoint(x: -0.16906013, y: -0.37282392), CGPoint(x: -0.07491139, y: -0.63149399)),
        (CGPoint(x: 0, y: -0.86840689), CGPoint(x: 0, y: -1.08849323), CGPoint(x: 0, y: -1.52866483))
    ]
    // Clockwise: top right, bottom right, bottom left, top left; each turn rotates offsets by -90°.
    let corners = [
        CGPoint(x: rect.maxX, y: rect.maxY), CGPoint(x: rect.maxX, y: rect.minY),
        CGPoint(x: rect.minX, y: rect.minY), CGPoint(x: rect.minX, y: rect.maxY)
    ]
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

/// Shield centred on x = 0: gently domed top, straight sides, curving to a point at `bottom`.
func shieldPath(width w: CGFloat, top: CGFloat, bottom: CGFloat) -> CGPath {
    let h = top - bottom
    let r = w / 2
    let p = CGMutablePath()
    p.move(to: CGPoint(x: 0, y: top))
    p.addCurve(
        to: CGPoint(x: r, y: top - h * 0.10),
        control1: CGPoint(x: r * 0.45, y: top), control2: CGPoint(x: r * 0.80, y: top - h * 0.04))
    p.addLine(to: CGPoint(x: r, y: top - h * 0.40))
    p.addCurve(
        to: CGPoint(x: 0, y: bottom),
        control1: CGPoint(x: r, y: top - h * 0.78), control2: CGPoint(x: r * 0.42, y: bottom + h * 0.06))
    p.addCurve(
        to: CGPoint(x: -r, y: top - h * 0.40),
        control1: CGPoint(x: -r * 0.42, y: bottom + h * 0.06), control2: CGPoint(x: -r, y: top - h * 0.78))
    p.addLine(to: CGPoint(x: -r, y: top - h * 0.10))
    p.addCurve(
        to: CGPoint(x: 0, y: top),
        control1: CGPoint(x: -r * 0.80, y: top - h * 0.04), control2: CGPoint(x: -r * 0.45, y: top))
    p.closeSubpath()
    return p
}

func fill(_ ctx: CGContext, _ path: CGPath, _ color: CGColor) {
    ctx.addPath(path)
    ctx.setFillColor(color)
    ctx.fillPath()
}

func capsule(_ rect: CGRect) -> CGPath {
    let r = min(rect.width, rect.height) / 2
    return CGPath(roundedRect: rect, cornerWidth: r, cornerHeight: r, transform: nil)
}

func drawDigits(_ string: String, in ctx: CGContext, center: CGPoint, size: CGFloat, color: CGColor) {
    let base = NSFont.systemFont(ofSize: size, weight: .heavy)
    let font = base.fontDescriptor.withDesign(.rounded).flatMap { NSFont(descriptor: $0, size: size) } ?? base
    let text = NSAttributedString(
        string: string,
        attributes: [
            .font: font, .foregroundColor: NSColor(cgColor: color) ?? .black, .kern: size * 0.06
        ])
    let line = CTLineCreateWithAttributedString(text)
    ctx.textPosition = .zero
    let box = CTLineGetImageBounds(line, ctx)
    ctx.textPosition = CGPoint(x: center.x - box.midX, y: center.y - box.midY)
    CTLineDraw(line, ctx)
}

/// Draws the icon into the current context, in a 1024 × 1024 coordinate space.
/// `pixels` is the final pixel size, used to pick the small-size simplifications.
func drawIcon(in ctx: CGContext, pixels: Int) {
    let small = pixels <= 64
    let tiny = pixels <= 16

    // Tile: the standard 824 px body; small sizes use more of the canvas, as Apple's own small icons do.
    let inset: CGFloat = small ? 64 : 100
    let body = CGRect(x: inset, y: inset, width: canvas - 2 * inset, height: canvas - 2 * inset)
    let tile = squircle(in: body, radius: body.width * 0.225)
    fill(ctx, tile, Palette.tile)
    ctx.addPath(tile)
    ctx.clip()

    // Glyph space: origin at the tile centre, the tile spans -412…412; small sizes enlarge the glyph a bit.
    ctx.translateBy(x: canvas / 2, y: canvas / 2)
    let scale = body.width / 824 * (small ? 1.1 : 1)
    ctx.scaleBy(x: scale, y: scale)

    if tiny {
        // 16 px: the whole shield silhouette with an amber code bar inside; lock and digits would blur.
        fill(ctx, shieldPath(width: 560, top: 350, bottom: -370), Palette.shield)
        fill(ctx, capsule(CGRect(x: -190, y: -20, width: 380, height: 150)), Palette.code)
        return
    }

    // Shield with the lock (shackle + body) knocked out.
    ctx.beginTransparencyLayer(auxiliaryInfo: nil)
    fill(ctx, shieldPath(width: 520, top: 330, bottom: -290), Palette.shield)
    ctx.setBlendMode(.clear)
    let shackle = CGMutablePath()
    shackle.move(to: CGPoint(x: -78, y: 110))
    shackle.addLine(to: CGPoint(x: -78, y: 160))
    shackle.addArc(center: CGPoint(x: 0, y: 160), radius: 78, startAngle: .pi, endAngle: 0, clockwise: true)
    shackle.addLine(to: CGPoint(x: 78, y: 110))
    ctx.addPath(shackle.copy(strokingWithWidth: small ? 58 : 50, lineCap: .butt, lineJoin: .round, miterLimit: 10))
    ctx.fillPath()
    ctx.addPath(
        CGPath(
            roundedRect: CGRect(x: -132, y: -40, width: 264, height: 170),
            cornerWidth: 36, cornerHeight: 36, transform: nil))
    ctx.fillPath()
    ctx.setBlendMode(.normal)
    ctx.endTransparencyLayer()

    // Code pill across the shield's base, separated from it by a gap in the tile colour.
    let pill =
        small
        ? CGRect(x: -290, y: -330, width: 580, height: 190)
        : CGRect(x: -250, y: -300, width: 500, height: 160)
    let gap: CGFloat = small ? 36 : 26
    fill(ctx, capsule(pill.insetBy(dx: -gap, dy: -gap)), Palette.tile)
    fill(ctx, capsule(pill), Palette.code)
    let mid = CGPoint(x: pill.midX, y: pill.midY)
    if small {
        // Three dots read better than digits at 32–64 px.
        let r: CGFloat = 34
        let dots = CGMutablePath()
        for i in -1...1 {
            dots.addEllipse(in: CGRect(x: mid.x + CGFloat(i) * 130 - r, y: mid.y - r, width: 2 * r, height: 2 * r))
        }
        fill(ctx, dots, Palette.digits)
    } else {
        drawDigits("123", in: ctx, center: mid, size: 132, color: Palette.digits)
    }
}

func renderPNG(pixels: Int) -> Data {
    guard
        let rep = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
        let gc = NSGraphicsContext(bitmapImageRep: rep)
    else { fatalError("cannot create bitmap") }
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
var previewDir: URL?
let usage = "usage: swift scripts/make-icon.swift [--iconset DIR] [--icns PATH] [--preview DIR]"
var args = CommandLine.arguments.dropFirst()
while let arg = args.popFirst() {
    switch arg {
    case "--iconset": keepIconset = args.popFirst().map { URL(fileURLWithPath: $0) }
    case "--icns": if let p = args.popFirst() { icnsURL = URL(fileURLWithPath: p) }
    case "--preview": previewDir = args.popFirst().map { URL(fileURLWithPath: $0) }
    case "-h", "--help":
        print(usage)
        exit(0)
    default:
        FileHandle.standardError.write(Data("unknown argument: \(arg)\n\(usage)\n".utf8))
        exit(2)
    }
}

let fm = FileManager.default

if let dir = previewDir {
    try fm.createDirectory(at: dir, withIntermediateDirectories: true)
    for pixels in [16, 32, 64, 128, 256, 512, 1024] {
        let url = dir.appendingPathComponent("icon-\(pixels).png")
        try renderPNG(pixels: pixels).write(to: url)
        print(url.path)
    }
    exit(0)
}

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
