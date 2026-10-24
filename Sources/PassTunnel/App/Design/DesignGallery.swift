import AppKit
import SwiftUI

/// Every design token and base component on one page, for the `components` render (RenderSnapshots). Sample
/// copy is the design's and is not localized: the page is a design check, not part of the app.
struct DesignGallery: View {
    /// The appearance the page is rendered in; the tokens' values are printed as they resolve in it.
    let isDark: Bool
    /// Whether `Palette.previewIncreasedContrast` is on, for the title.
    let isContrast: Bool

    private var appearance: NSAppearance { NSAppearance(named: isDark ? .darkAqua : .aqua)! }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: "Design system").typography(.detailTitle).foregroundStyle(Palette.fg)
                Text(verbatim: "\(isDark ? "Dark" : "Light")\(isContrast ? " · Increase Contrast" : "") · system window background (D-1)")
                    .typography(.body).foregroundStyle(Palette.fg2)
            }
            HStack(alignment: .top, spacing: Spacing.xl) {
                VStack(alignment: .leading, spacing: Spacing.l) {
                    colors
                    typography
                    spacingAndRadii
                }
                .frame(width: 470, alignment: .leading)
                VStack(alignment: .leading, spacing: Spacing.l) {
                    buttons
                    cards
                    statuses
                    countdown
                    codes
                    surfaces
                }
                .frame(width: 470, alignment: .leading)
            }
        }
        .padding(Spacing.xl)
        .fixedSize()
        .background(Palette.background)
    }

    // MARK: tokens

    private var colors: some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            SectionLabel("Color")
            LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading)],
                      alignment: .leading, spacing: Spacing.xs) {
                swatch("background", NSColor.windowBackgroundColor)
                ForEach(Palette.Raw.all, id: \.name) { token in swatch(token.name, token.color) }
            }
            caption("Translucent tokens show their value on the window background after the arrow.")
        }
    }

    private func swatch(_ name: String, _ color: NSColor) -> some View {
        HStack(spacing: 10) {
            RoundedRectangle(cornerRadius: Radius.field, style: .continuous)
                .fill(Color(nsColor: color))
                .overlay(RoundedRectangle(cornerRadius: Radius.field, style: .continuous)
                    .strokeBorder(Palette.line, lineWidth: Elevation.hairline))
                .frame(width: 30, height: 30)
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: name).typography(.bodyEmphasized).foregroundStyle(Palette.fg)
                Text(verbatim: describe(color)).typography(.rowCode).foregroundStyle(Palette.fg2)
            }
        }
    }

    /// "#0B0B0C", or "black 10.5 % → #E4E4E4" for a translucent token over the window background.
    private func describe(_ color: NSColor) -> String {
        func rgba(_ c: NSColor) -> (r: Double, g: Double, b: Double, a: Double) {
            var out = (r: 0.0, g: 0.0, b: 0.0, a: 0.0)
            appearance.performAsCurrentDrawingAppearance {
                if let s = c.usingColorSpace(.sRGB) {
                    out = (Double(s.redComponent), Double(s.greenComponent), Double(s.blueComponent), Double(s.alphaComponent))
                }
            }
            return out
        }
        func hex(_ r: Double, _ g: Double, _ b: Double) -> String {
            String(format: "#%02X%02X%02X", Int((r * 255).rounded()), Int((g * 255).rounded()), Int((b * 255).rounded()))
        }
        let c = rgba(color)
        guard c.a < 0.999 else { return hex(c.r, c.g, c.b) }
        let bg = rgba(.windowBackgroundColor)
        let base = c.r > 0.5 ? "white" : c.r < 0.01 && c.g < 0.01 && c.b < 0.01 ? "black" : hex(c.r, c.g, c.b)
        let percent = String(format: "%.1f %%", c.a * 100)
        func mix(_ f: Double, _ b: Double) -> Double { f * c.a + b * (1 - c.a) }
        return "\(base) \(percent) → \(hex(mix(c.r, bg.r), mix(c.g, bg.g), mix(c.b, bg.b)))"
    }

    private var typography: some View {
        let rows: [(String, Typography, String, Color)] = [
            ("detailTitle · 28 bold, −0.02 em", .detailTitle, "Work", Palette.fg),
            ("screenTitle · 26 bold, −0.02 em", .screenTitle, "Add your first VPN", Palette.fg),
            ("reviewTitle · 22 bold", .reviewTitle, "Review work.ovpn", Palette.fg),
            ("dialogTitle · 17 bold, −0.01 em", .dialogTitle, "Lab overlaps with Work", Palette.fg),
            ("sheetTitle · 15 bold", .sheetTitle, "Edit “Work”", Palette.fg),
            ("statusLine · 15 semibold", .statusLine, "Connected · 1h 12m · 10.8.0.6", Palette.green),
            ("body · 13", .body, "vpn.example.com:1194 · OpenVPN · UDP", Palette.fg2),
            ("bodyEmphasized · 13 semibold", .bodyEmphasized, "Data Center", Palette.fg),
            ("buttonLarge · 14 semibold", .buttonLarge, "Disconnect", Palette.fg),
            ("buttonSmall · 12 semibold", .buttonSmall, "Show all", Palette.fg),
            ("hint · 12", .hint, "Format: Append · sent at 09:41:02", Palette.fg2),
            ("rowStatus · 11.5 medium", .rowStatus, "Waiting for a fresh code · 4 s", Palette.amber),
            ("heroCode · 44 medium mono, −0.03 em", .heroCode, "482 913", Palette.fg),
            ("editorCode · 18 medium mono", .editorCode, "482 913", Palette.fg),
            ("rowCode · 13 mono", .rowCode, "482 913", Palette.fg),
            ("seconds · 13 semibold mono", .seconds, "18", Palette.fg2),
            ("log · 11.5 mono, line height 1.65", .log, "09:41:02  Sending alice / ••••••••+482 •••\n09:41:03  Connected, 10.8.0.6", Palette.fg),
        ]
        return VStack(alignment: .leading, spacing: Spacing.s) {
            SectionLabel("Typography")
            VStack(alignment: .leading, spacing: 2) {
                SectionLabel("Current code")
                caption("sectionLabel · 11 semibold, +0.05 em, uppercase")
            }
            ForEach(rows, id: \.0) { row in
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: row.2).typography(row.1).foregroundStyle(row.3)
                    caption(row.0)
                }
            }
        }
    }

    private var spacingAndRadii: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionLabel("Spacing and radii")
            HStack(alignment: .bottom, spacing: 6) {
                ForEach([Spacing.xxs, Spacing.xs, Spacing.s, Spacing.m, Spacing.l, Spacing.xl, Spacing.xxl], id: \.self) {
                    Rectangle().fill(Palette.fg).frame(width: $0, height: $0)
                }
                caption("4 · 8 · 12 · 16 · 24 · 32 · 48").padding(.leading, 6)
            }
            HStack(spacing: Spacing.s) {
                ForEach([("card 18", Radius.card), ("compact 14", Radius.compactCard), ("panel 16", Radius.panel),
                         ("row 12", Radius.row), ("field 8", Radius.field)], id: \.0) { item in
                    VStack(spacing: 4) {
                        RoundedRectangle(cornerRadius: item.1, style: .continuous)
                            .strokeBorder(Palette.fg2, lineWidth: 1)
                            .frame(width: 64, height: 44)
                        caption(item.0)
                    }
                }
            }
        }
    }

    // MARK: components

    private var buttons: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionLabel("Buttons")
            HStack(spacing: Spacing.xs) {
                sample("Connect", .primaryCapsule(.large))
                sample("Cancel", .secondaryCapsule(.large))
                sample("Stop", .secondaryCapsule(.large))
            }
            HStack(spacing: Spacing.xs) {
                sample("Copy code", .secondaryCapsule(.regular, minWidth: 104))
                sample("Copy password + code", .secondaryCapsule(.regular, minWidth: 176))
                sample("Try now", .primaryCapsule)
            }
            HStack(spacing: Spacing.xs) {
                sample("Cancel", .secondaryCapsule(.compact))
                sample("Save", .primaryCapsule(.compact))
                sample("Show all", .smallCapsule)
                sample("Add profile", .primaryCapsule).disabled(true)
                caption("Add the code secret to finish.")
            }
            caption("large 40 · regular 36 · compact 32 · small 28; disabled at 38 %, with the reason beside it")
        }
    }

    private func sample(_ title: String, _ style: CapsuleButtonStyle) -> some View {
        Button {} label: { Text(verbatim: title) }.buttonStyle(style)
    }

    private var cards: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionLabel("Cards")
            codeCard(remaining: 18, last: false)
            codeCard(remaining: 4, last: true)
            Card(style: .compact) {
                SectionLabel("Found in the file")
                checkRow("Server", "vpn.example.com:1194 · UDP")
                checkRow("Certificates", "CA, client certificate and key, inside the file")
            }
            caption("regular: radius 18, padding 16 × 18 · compact: radius 14, padding 14 × 16 · 1 pt hairline, no shadow")
        }
    }

    private func codeCard(remaining: Double, last: Bool) -> some View {
        Card {
            SectionLabel("Current code")
            HStack(spacing: Spacing.s) {
                GroupedCodeText(code: "482913").foregroundStyle(Palette.fg)
                CodeCountdown(remaining: remaining, period: 30)
            }
            HStack(spacing: 4) {
                Text(verbatim: "Next")
                Text(verbatim: "771 204").font(.system(size: 12, design: .monospaced))
            }
            .typography(.hint)
            .foregroundStyle(Palette.fg3)
            HStack(spacing: Spacing.xs) {
                Button {} label: { Text(verbatim: last ? "Copied ✓" : "Copy code") }
                    .buttonStyle(.secondaryCapsule(.regular, minWidth: 104))
                Button {} label: { Text(verbatim: "Copy password + code") }
                    .buttonStyle(.secondaryCapsule(.regular, minWidth: 176))
            }
            .padding(.top, 4)
        }
    }

    private func checkRow(_ title: String, _ detail: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            StatusIcon(.check, size: 16).alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 4 }
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: title).typography(.body).foregroundStyle(Palette.fg)
                Text(verbatim: detail).typography(.hint).foregroundStyle(Palette.fg2)
            }
        }
    }

    private var statuses: some View {
        let lines: [(StatusSymbol, String, Color)] = [
            (.off, "Disconnected", Palette.fg2),
            (.connecting, "Connecting to vpn.example.com:1194…", Palette.fg),
            (.waiting, "Waiting for a fresh code · sends in 4 s", Palette.amber),
            (.connected, "Connected · 1h 12m · 10.8.0.6", Palette.green),
            (.dropped, "Dropped, reconnecting with a fresh code…", Palette.red),
            (.rejected, "Sign-in rejected by the server", Palette.red),
            (.unreachable, "Can’t reach the server · next try in 18 s", Palette.red),
        ]
        return VStack(alignment: .leading, spacing: Spacing.s) {
            SectionLabel("Status")
            VStack(alignment: .leading, spacing: 6) {
                ForEach(lines, id: \.1) { line in
                    HStack(spacing: Spacing.xs) {
                        StatusIcon(line.0)
                        Text(verbatim: line.1).typography(.statusLine).foregroundStyle(line.2)
                    }
                }
            }
            HStack(spacing: Spacing.m) {
                ForEach([(StatusSymbol.check, "check"), (.warning, "warning"), (.info, "info"),
                         (.warning, "warning, red")], id: \.1) { item in
                    HStack(spacing: 6) {
                        StatusIcon(item.0, size: 16, tint: item.1 == "warning, red" ? Palette.red : nil)
                        caption(item.1)
                    }
                }
            }
            HStack(spacing: Spacing.m) {
                ForEach([(StatusSymbol.off, "Disconnected", Palette.fg2), (.connected, "Connected · 1h 12m", Palette.green),
                         (.waiting, "Waiting · 4 s", Palette.amber), (.dropped, "Dropped", Palette.red)], id: \.1) { item in
                    HStack(spacing: 5) {
                        StatusDot(item.0)
                        Text(verbatim: item.1).typography(.rowStatus).foregroundStyle(item.2)
                    }
                }
            }
            caption("20 pt glyphs in the status line, 16 pt in diagnosis rows, 7 pt dots in rows")
        }
    }

    private var countdown: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionLabel("Countdown ring")
            HStack(alignment: .bottom, spacing: Spacing.l) {
                ringSample("18 s", CodeRing(remaining: 18, period: 30, size: 56, weight: 2.6))
                ringSample("last 5 s", CodeRing(remaining: 4, period: 30, size: 56, weight: 2.6))
                ringSample("waiting", CodeRing(remaining: 18, period: 30, waiting: true, size: 56, weight: 2.6))
                ringSample("refilling", CodeRing(remaining: 29.9, period: 30, size: 56, weight: 2.6))
                ringSample("26 · 30 · 20", HStack(spacing: Spacing.xs) {
                    CodeRing(remaining: 18, period: 30)
                    CodeRing(remaining: 18, period: 30, size: 30)
                    CodeRing(remaining: 18, period: 30, size: 20, weight: 4)
                })
            }
            caption("Reduce Motion: 1 s steps, no refill; the color still changes")
        }
    }

    private func ringSample<V: View>(_ title: String, _ ring: V) -> some View {
        VStack(spacing: 6) {
            ring
            caption(title)
        }
    }

    private var codes: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionLabel("Code text")
            HStack(alignment: .firstTextBaseline, spacing: Spacing.l) {
                GroupedCodeText(code: "482913").foregroundStyle(Palette.fg)
                GroupedCodeText(code: "482913", hidden: true).foregroundStyle(Palette.fg3)
            }
            HStack(alignment: .firstTextBaseline, spacing: Spacing.l) {
                GroupedCodeText(code: "482913", style: .editorCode).foregroundStyle(Palette.fg)
                GroupedCodeText(code: "482913", style: .rowCode).foregroundStyle(Palette.fg)
                GroupedCodeText(code: "48291352", style: .rowCode).foregroundStyle(Palette.fg)
                GroupedCodeText(code: "", hidden: true, style: .rowCode).foregroundStyle(Palette.fg3)
            }
            caption("A real space between the groups. VoiceOver: “\(GroupedCodeText.spoken("482913"))”")
        }
    }

    private var surfaces: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionLabel("Surfaces")
            HStack(spacing: Spacing.s) {
                surface("system window", Palette.background)
                surface("design bg", Color(nsColor: isDark ? .black : .white))
            }
            ZStack {
                LinearGradient(colors: [Palette.green.opacity(0.5), Palette.amberRing.opacity(0.5), Palette.redDot.opacity(0.5)],
                               startPoint: .leading, endPoint: .trailing)
                HStack(spacing: 0) {
                    Text(verbatim: "Edit").typography(.body).foregroundStyle(Palette.fg).padding(.horizontal, 12)
                    Image(systemName: "ellipsis").foregroundStyle(Palette.fg).frame(width: 36)
                }
                .frame(height: 36)
                .padding(2)
                .materialGlass(in: Capsule())
            }
            .frame(height: 64)
            .clipShape(RoundedRectangle(cornerRadius: Radius.compactCard, style: .continuous))
            caption("Glass, for chrome only: the material of macOS 13–15 (D-20). Liquid Glass on macOS 26 is drawn "
                    + "by the window server and does not show in offscreen renders.")
        }
    }

    private func surface(_ title: String, _ background: Color) -> some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            caption(title)
            Card(style: .compact) {
                Text(verbatim: "fg · Work").foregroundStyle(Palette.fg)
                Text(verbatim: "fg2 · vpn.example.com").foregroundStyle(Palette.fg2)
                Text(verbatim: "fg3 · 09:41:02").foregroundStyle(Palette.fg3)
                Text(verbatim: "fill · alice")
                    .typography(.rowCode).foregroundStyle(Palette.fg2)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Palette.fill, in: RoundedRectangle(cornerRadius: Radius.field, style: .continuous))
            }
        }
        .padding(Spacing.s)
        .background(background, in: RoundedRectangle(cornerRadius: Radius.compactCard, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.compactCard, style: .continuous)
            .strokeBorder(Palette.line, lineWidth: Elevation.hairline))
    }

    private func caption(_ text: String) -> some View {
        Text(verbatim: text).typography(.hint).foregroundStyle(Palette.fg3).fixedSize(horizontal: false, vertical: true)
    }
}
