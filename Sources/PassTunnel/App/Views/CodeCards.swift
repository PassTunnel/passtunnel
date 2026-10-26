import PassTunnelCore
import PassTunnelKit
import SwiftUI

// The cards under the status line of the redesigned window's detail (docs/APP.md, Redesigned window): the current
// code, and what the server receives (ServerReceivesCard.swift). When codes show, "Copied ✓" and the next window are
// `CodeCard` in Core.

/// The current code card and the card about what the server receives; a profile without a TOTP secret gets only the
/// second. Both follow one clock, so their codes change together. `sentAt`: when the sign-in of the connection that is
/// up was sent (the activity log), which the second card says.
struct DetailCodeCards: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    var sentAt: Date?

    var body: some View {
        CountdownTimeline(now: model.previewNow) { date in
            let codes = CardCodes(model, profile, at: date)
            CardColumns {
                if codes.hasSecret {
                    CurrentCodeCard(profile: profile, codes: codes, date: date)
                }
                ServerReceivesCard(profile: profile,
                                   receives: ServerReceives(profile, codes: codes.receives, waitingForCode: codes.waiting,
                                                            sentAt: sentAt))
            }
        }
    }
}

/// What both cards show of a profile's code at one moment.
struct CardCodes {
    /// The profile has a TOTP secret (shown, or locked behind a confirmation).
    var hasSecret: Bool
    /// The code of this window and of the next; nil while masked, so the views never hold them.
    var current: String?
    var next: String?
    /// Bullets instead of the codes (`AppModel.codesMasked`).
    var masked: Bool
    /// A connect waits for a fresh code: the ring is amber, and the next code is the one it sends.
    var waiting: Bool
    var remaining: Double
    var period: Double
    /// The TOTP window at that moment.
    var window: UInt64

    @MainActor
    init(_ model: AppModel, _ p: Profile, at date: Date) {
        period = Double(max(1, p.totp.period))
        remaining = period - date.timeIntervalSince1970.truncatingRemainder(dividingBy: period)
        window = TOTP.counter(params: p.totp, at: date)
        hasSecret = model.hasCode(p)
        masked = model.codesMasked(p, at: date)
        waiting = model.codeWaitUntil(p) != nil
        guard !masked else { return }
        current = model.code(for: p, at: date)?.code
        next = model.code(for: p, at: CodeCard.nextWindow(p.totp, after: date))?.code
    }

    var receives: ServerReceives.Codes {
        guard hasSecret else { return .noSecret }
        guard !masked, let current, let next else { return .masked }
        return .shown(current: current, next: next)
    }
}

extension AppModel {
    /// A connect of `p` waits for a fresh code until then (`ConnectionManager.codeWaitUntil`); from the render
    /// overrides while they are set.
    func codeWaitUntil(_ p: Profile) -> Date? {
        previewStates == nil ? connections.codeWaitUntil[p.id] : previewCodeWaits[p.id]
    }
}

// MARK: - Current code

/// "CURRENT CODE": the code in 44 pt SF Mono with the countdown beside it (amber in the last 5 s and while a connect
/// waits for a fresh code), the next code under it, then Copy code and, with a password in the Keychain, Copy
/// password + code; each says "Copied ✓" for 1.6 s, less when the code changes. A click on the code copies it; a
/// masked code (hidden, or protected by "Confirm with Touch ID") is shown for 20 s instead, after the confirmation
/// when it is locked. Copying never shows a masked code. VoiceOver reads the code, the seconds and the next code as
/// one element.
struct CurrentCodeCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let codes: CardCodes
    let date: Date

    /// "Next 771 204" (12 pt SF Mono).
    private static let nextCode = Typography(font: .callout.monospaced())

    var body: some View {
        let p = profile
        // Masked codes are not given to the views: bullets for as many digits.
        let placeholder = String(repeating: "0", count: max(6, p.totp.digits))
        Card {
            VStack(alignment: .leading, spacing: Spacing.xs) {
                SectionLabel(String(localized: "Current code"))
                HStack(spacing: Spacing.s) {
                    Button(action: click) {
                        GroupedCodeText(code: codes.current ?? placeholder, hidden: codes.masked)
                            .foregroundStyle(codes.masked ? Palette.fg3 : Palette.fg)
                    }
                    .buttonStyle(HeroCodeButtonStyle())
                    .help(hint)
                    CodeCountdown(remaining: codes.remaining, period: codes.period, waiting: codes.waiting)
                }
                HStack(spacing: Spacing.xxs) {
                    Text(String(localized: "Next"))
                        .typography(.hint)
                    GroupedCodeText(code: codes.next ?? placeholder, hidden: codes.masked, style: Self.nextCode)
                }
                .foregroundStyle(Palette.fg3)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(String(localized: "Current code"))
            .accessibilityValue(spoken)
            .accessibilityHint(hint)
            .accessibilityAddTraits(.isButton)
            .accessibilityAction { click() }
            .accessibilityIdentifier("profile.\(p.id).code")
            HStack(spacing: Spacing.xs) {
                CopyButton(title: String(localized: "Copy code"), copied: copied(.code), minWidth: 104,
                           identifier: "profile.\(p.id).copyCode") { model.copyCode(p) }
                if p.passwordMode == .keychain {
                    CopyButton(title: String(localized: "Copy password + code"), copied: copied(.passwordAndCode),
                               minWidth: 176, identifier: "profile.\(p.id).copyPasswordCode") {
                        model.copyPasswordAndCode(p)
                    }
                }
            }
            .padding(.top, Spacing.xxs)
            Spacer(minLength: 0)
        }
    }

    private func click() {
        if codes.masked { model.revealCodes(profile) } else { model.copyCode(profile) }
    }

    private var hint: String {
        codes.masked ? String(localized: "Click to show the code") : String(localized: "Click to copy the code")
    }

    private func copied(_ kind: CodeCard.Copy.Kind) -> Bool {
        model.lastCopy?.shows(kind, for: profile.id, window: codes.window, at: date) == true
    }

    /// "4 8 2, 9 1 3, 12 seconds left, next code 7 7 1, 2 0 4"; "Code hidden, 12 seconds left".
    private var spoken: String {
        let seconds = Int(max(0, codes.remaining).rounded(.up))
        guard !codes.masked, let current = codes.current else {
            let hidden = String(localized: "Code hidden")
            return String(localized: "\(hidden), \(seconds) seconds left")
        }
        let words = GroupedCodeText.spoken(current)
        var value = String(localized: "\(words), \(seconds) seconds left")
        if let next = codes.next {
            let nextWords = GroupedCodeText.spoken(next)
            value += ", " + String(localized: "next code \(nextWords)")
        }
        return value
    }
}

/// The big code as a button: no chrome, a faint fill under the pointer and while pressed.
private struct HeroCodeButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        HeroCodeButton(configuration: configuration)
    }
}

private struct HeroCodeButton: View {
    let configuration: ButtonStyleConfiguration
    @State private var hover = false

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: Radius.field, style: .continuous)
        configuration.label
            .padding(.horizontal, 6)
            .background(configuration.isPressed ? Palette.fill2 : hover ? Palette.fill : .clear, in: shape)
            .padding(.horizontal, -6)   // the code stays in line with the card's label
            .contentShape(shape)
            .onHover { hover = $0 }
    }
}

/// A secondary capsule that says "Copied ✓" for a moment; as wide as the wider of its two labels, so it keeps its
/// size in any language.
private struct CopyButton: View {
    let title: String
    let copied: Bool
    let minWidth: CGFloat
    let identifier: String
    let action: () -> Void

    var body: some View {
        let done = String(localized: "Copied ✓")
        Button(action: action) {
            ZStack {
                Group {
                    Text(verbatim: title)
                    Text(verbatim: done)
                }
                .hidden()
                .accessibilityHidden(true)
                Text(verbatim: copied ? done : title)
            }
        }
        .buttonStyle(.secondaryCapsule(.regular, minWidth: minWidth))
        // On the button itself, and always the action: VoiceOver hears "Code copied" when it is done.
        .accessibilityLabel(Text(verbatim: title))
        .accessibilityIdentifier(identifier)
    }
}

// MARK: - Layout

/// Cards in equal columns of the same height, as the design's grid; a single card takes the first column. Stacked at
/// full width when a column is narrower than a card needs (a narrow window, a longer language).
struct CardColumns: Layout {
    var spacing: CGFloat = Spacing.m

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? idealWidth(subviews)
        let frames = arrange(subviews, width: width)
        return CGSize(width: width, height: frames.map(\.maxY).max() ?? 0)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        for (subview, frame) in zip(subviews, arrange(subviews, width: bounds.width)) {
            subview.place(at: CGPoint(x: bounds.minX + frame.minX, y: bounds.minY + frame.minY),
                          proposal: ProposedViewSize(frame.size))
        }
    }

    private func arrange(_ subviews: Subviews, width: CGFloat) -> [CGRect] {
        let column = max(0, (width - spacing) / 2)
        // The narrowest each card can be: its buttons and code do not wrap, its text does.
        let needed = subviews.map { $0.sizeThatFits(ProposedViewSize(width: 0, height: nil)).width }
        if needed.allSatisfy({ $0 <= column }) {
            let height = subviews.map { $0.sizeThatFits(ProposedViewSize(width: column, height: nil)).height }.max() ?? 0
            return subviews.indices.map { CGRect(x: CGFloat($0) * (column + spacing), y: 0, width: column, height: height) }
        }
        var y: CGFloat = 0
        return subviews.map { subview in
            let height = subview.sizeThatFits(ProposedViewSize(width: width, height: nil)).height
            defer { y += height + spacing }
            return CGRect(x: 0, y: y, width: width, height: height)
        }
    }

    private func idealWidth(_ subviews: Subviews) -> CGFloat {
        let widths = subviews.map { $0.sizeThatFits(.unspecified).width }
        return widths.reduce(0, +) + spacing * CGFloat(max(0, widths.count - 1))
    }
}
