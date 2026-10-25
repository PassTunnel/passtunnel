import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// "WHAT THE SERVER RECEIVES": what the sign-in sends (`ServerReceives`), one row per field in SF Mono with the labels
/// in a column: the user name; the password as eight bullets, with the code where the format puts it, or the code on a
/// row of its own when it is sent separately. Then the format and which code the preview holds. Built with a
/// placeholder password, never the real one. VoiceOver reads the card as one element.
struct ServerReceivesCard: View {
    let profile: Profile
    let receives: ServerReceives

    var body: some View {
        Card {
            SectionLabel(String(localized: "What the server receives"))
            if !receives.rows.isEmpty {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: Spacing.s, verticalSpacing: Spacing.xxs) {
                    ForEach(Array(receives.rows.enumerated()), id: \.offset) { _, row in
                        GridRow {
                            // The labels keep their width; the values take the rest and wrap.
                            Text(verbatim: row.field.label)
                                .foregroundStyle(Palette.fg3)
                                .fixedSize()
                            Text(Self.line(row.segments))
                                .foregroundStyle(Palette.fg)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .typography(.rowCode)
                // The footer sits at the bottom when the code card next to it is taller.
                Spacer(minLength: 0)
            }
            Text(verbatim: receives.footer)
                .typography(.hint)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, receives.rows.isEmpty ? 0 : Spacing.xxs)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(String(localized: "What the server receives"))
        .accessibilityValue(spoken)
        .accessibilityIdentifier("profile.\(profile.id).serverReceives")
    }

    /// The row's value; bullets, example digits and words that stand for a value are dimmed.
    private static func line(_ segments: [ServerReceives.Segment]) -> AttributedString {
        segments.reduce(into: AttributedString()) { line, segment in
            var part = AttributedString(segment.text)
            if segment.isDimmed { part.foregroundColor = Palette.fg3 }
            line += part
        }
    }

    /// "user name alice, password hidden password 4 8 2, 9 1 3, Format: Append · preview with the current code".
    private var spoken: String {
        let rows = receives.rows.map { row in
            ([row.field.label] + row.segments.map(Self.spoken)).joined(separator: " ")
        }
        return (rows + [receives.footer]).joined(separator: ", ")
    }

    private static func spoken(_ segment: ServerReceives.Segment) -> String {
        switch segment {
        case .text, .askedUsername: return segment.text
        case .password: return String(localized: "hidden password")
        case .code(let digits): return GroupedCodeText.spoken(digits)
        case .hiddenCode: return String(localized: "Code hidden")
        case .exampleCode: return String(localized: "example code")
        }
    }
}
