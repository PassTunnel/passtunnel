import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// Curated SF Symbols that exist on macOS 13.
enum EditorIcons {
    static let all: [String] = [
        "lock.shield", "lock", "key", "shield",
        "network", "globe", "server.rack", "cloud",
        "building.2", "house", "briefcase", "desktopcomputer",
        "laptopcomputer", "terminal", "antenna.radiowaves.left.and.right", "wifi",
        "airplane", "graduationcap", "cross.case", "cart",
        "wrench.and.screwdriver", "leaf", "flame", "star"
    ]

    /// Readable name for VoiceOver: "server.rack" → "server rack".
    static func spokenName(_ symbol: String) -> String {
        symbol.replacingOccurrences(of: ".", with: " ")
    }
}

/// Red caption shown under the field it belongs to.
struct EditorInlineError: View {
    let message: String?

    var body: some View {
        if let message {
            Label {
                Text(verbatim: message).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.circle.fill")
            }
            .typography(.hint)
            .foregroundStyle(Palette.red)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("Error: \(message)"))
        }
    }
}

/// Secondary explanation under a row (12 pt, `fg2`).
struct EditorHint: View {
    let text: Text
    init(_ key: LocalizedStringKey) { text = Text(key) }
    init(verbatim: String) { text = Text(verbatim: verbatim) }

    var body: some View {
        text.typography(.hint).foregroundStyle(Palette.fg2).fixedSize(horizontal: false, vertical: true)
    }
}

// MARK: - cards and rows

/// A card of the editor sheet: `Card`'s hairline look with the sheet's tighter padding (12 × 16), or none for
/// switch rows, which bring their own.
struct EditorCard<Content: View>: View {
    var spacing: CGFloat = 4
    var insets = EdgeInsets(top: 12, leading: 16, bottom: 12, trailing: 16)
    @ViewBuilder var content: Content

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: Radius.compactCard, style: .continuous)
        VStack(alignment: .leading, spacing: spacing) { content }
            .padding(insets)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Palette.card, in: shape)
            .edge(shape, Palette.line)
    }
}

/// A row of the editor's cards: the label right-aligned in a 150 pt column (it wraps, never truncates), the
/// control after it, hints and errors under the control. The label is for sight only: every control carries its
/// own accessibility label.
struct EditorRow<Content: View>: View {
    static var labelWidth: CGFloat { 150 }

    let label: Text?
    /// The label in `fg2` ("Server receives": a preview, not a setting).
    var secondary = false
    @ViewBuilder var content: Content

    init(_ label: Text?, secondary: Bool = false, @ViewBuilder content: () -> Content) {
        self.label = label
        self.secondary = secondary
        self.content = content()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.s) {
            (label ?? Text(verbatim: ""))
                .typography(.body)
                .foregroundStyle(secondary ? Palette.fg2 : Palette.fg)
                .multilineTextAlignment(.trailing)
                .fixedSize(horizontal: false, vertical: true)
                .frame(width: Self.labelWidth, alignment: .trailing)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Spacing.xxs) { content }
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minHeight: 36)
    }
}

/// A row of the switch card: the words, the switch at the trailing edge, and a footnote under the words.
struct EditorSwitchRow: View {
    let title: String
    @Binding var isOn: Bool
    var footnote: String?
    /// `accessibilityIdentifier` of the switch.
    var identifier = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xxs) {
            Toggle(isOn: $isOn) { Text(verbatim: title).typography(.body).foregroundStyle(Palette.fg) }
                .toggleStyle(EditorSwitchStyle())
                .accessibilityIdentifier(identifier)
            if let footnote {
                EditorHint(verbatim: footnote).padding(.trailing, 50)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(minHeight: 44)
    }
}

extension View {
    /// The editor's text fields: 30 pt high on the text background, a hairline, radius 8, and the system's focus
    /// ring while the field has focus (a plain field draws none of its own).
    func editorField(focused: Bool) -> some View {
        modifier(EditorFieldChrome(focused: focused))
    }
}

private struct EditorFieldChrome: ViewModifier {
    let focused: Bool

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: Radius.field, style: .continuous)
        content
            .textFieldStyle(.plain)
            .typography(.body)
            .padding(.horizontal, 10)
            .frame(minHeight: 30)
            .background(Color(nsColor: .textBackgroundColor), in: shape)
            .edge(shape, Palette.line)
            .overlay {
                if focused {
                    RoundedRectangle(cornerRadius: Radius.field + 3, style: .continuous)
                        .strokeBorder(Color(nsColor: .keyboardFocusIndicatorColor), lineWidth: 3)
                        .padding(-3)
                        .allowsHitTesting(false)
                }
            }
    }
}

/// The design's switch, 38 × 22 with an 18 pt knob, `primary` when on: monochrome, where the system switch takes
/// the accent color (and keeps its white knob on the white `primary` of dark mode). It is a focusable button, and
/// VoiceOver reads it as a standard switch.
struct EditorSwitchStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        EditorSwitch(configuration: configuration)
    }
}

private struct EditorSwitch: View {
    let configuration: ToggleStyleConfiguration
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: Spacing.s) {
            configuration.label
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                configuration.isOn.toggle()
            } label: {
                track
            }
            .buttonStyle(.plain)
            .contentShape(Capsule())
            .contentShape(.focusEffect, Capsule())
        }
        .opacity(isEnabled ? 1 : 0.38)
        .accessibilityRepresentation {
            Toggle(isOn: configuration.$isOn) { configuration.label }
        }
    }

    private var track: some View {
        let on = configuration.isOn
        return ZStack(alignment: on ? .trailing : .leading) {
            Capsule().fill(on ? Palette.primary : Palette.fill2)
            Circle()
                .fill(on ? Palette.onPrimary : Color.white)
                .shadow(color: .black.opacity(on ? 0 : 0.25), radius: 1.5, y: 1)
                .frame(width: 18, height: 18)
                .padding(2)
        }
        .frame(width: 38, height: 22)
        .overlay { if !on { Capsule().strokeBorder(Palette.line, lineWidth: Elevation.hairline) } }
        .animation(reduceMotion ? nil : .easeOut(duration: 0.15), value: on)
    }
}

/// "Delete Profile…": red words without a fill, as tall as the sheet's capsules.
struct EditorDestructiveButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .typography(.bodyEmphasized)
            .foregroundStyle(Palette.red)
            .lineLimit(1)
            .fixedSize()
            .padding(.horizontal, 6)
            .frame(minHeight: 32)
            .contentShape(Capsule())
            .contentShape(.focusEffect, Capsule())
            .opacity(configuration.isPressed ? 0.6 : 1)
    }
}

extension View {
    /// Asks before a profile is deleted, with the same dialog wherever it starts (the main window's row menu, the
    /// editor's "Delete Profile…").
    func profileDeleteConfirmation(_ profile: Binding<Profile?>, delete: @escaping (Profile) -> Void) -> some View {
        confirmationDialog(
            String(localized: "Delete “\(profile.wrappedValue?.name ?? "")”?"),
            isPresented: Binding(
                get: { profile.wrappedValue != nil },
                set: { if !$0 { profile.wrappedValue = nil } }),
            titleVisibility: .visible, presenting: profile.wrappedValue
        ) { p in
            Button(String(localized: "Delete"), role: .destructive) { delete(p) }
            Button(String(localized: "Cancel"), role: .cancel) {}
        } message: { _ in
            Text(String(localized: "The profile, its configuration and its Keychain items are removed. This cannot be undone."))
        }
    }
}

// MARK: - icon picker

struct EditorIconPicker: View {
    @Binding var icon: String
    @State private var showing = false

    var body: some View {
        Button {
            showing.toggle()
        } label: {
            HStack(spacing: 6) {
                if icon.isEmpty {
                    Text("None").foregroundStyle(Palette.fg2)
                } else {
                    Image(systemName: icon).frame(width: 18)
                }
                Image(systemName: "chevron.down").font(.caption2).foregroundStyle(Palette.fg2)
            }
        }
        .accessibilityLabel(Text("Icon"))
        .accessibilityValue(icon.isEmpty ? Text("None") : Text(verbatim: EditorIcons.spokenName(icon)))
        .popover(isPresented: $showing, arrowEdge: .bottom) {
            EditorIconGrid(icon: $icon) { showing = false }
                .padding(12)
        }
    }
}

struct EditorIconGrid: View {
    @Binding var icon: String
    var onPick: () -> Void = {}

    private let columns = Array(repeating: GridItem(.fixed(34), spacing: 6), count: 6)

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            LazyVGrid(columns: columns, spacing: 6) {
                ForEach(EditorIcons.all, id: \.self) { name in
                    cell(name)
                }
            }
            Button("No Icon") {
                icon = ""
                onPick()
            }
            .buttonStyle(.link)
            .disabled(icon.isEmpty)
        }
    }

    private func cell(_ name: String) -> some View {
        let selected = name == icon
        let shape = RoundedRectangle(cornerRadius: 6, style: .continuous)
        return Button {
            icon = name
            onPick()
        } label: {
            Image(systemName: name)
                .font(.system(size: 15))
                .foregroundStyle(Palette.fg)
                .frame(width: 34, height: 30)
                .background(selected ? Palette.selection : Color.clear, in: shape)
                .overlay(shape.strokeBorder(selected ? Palette.fg : Palette.line))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(Text(verbatim: EditorIcons.spokenName(name)))
        .accessibilityLabel(Text(verbatim: EditorIcons.spokenName(name)))
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

// MARK: - menu-bar preview

/// One menu-bar badge as the status item draws it.
struct EditorBadgePreview: View {
    let profile: Profile
    let color: Color

    var body: some View {
        let style = (profile.badgeStyle != .letter && profile.icon.isEmpty) ? .letter : profile.badgeStyle
        HStack(spacing: 3) {
            if style != .letter {
                Image(systemName: profile.icon).font(.system(size: 11, weight: .semibold))
            }
            if style != .icon {
                Text(verbatim: profile.displayBadge).font(.system(size: 11, weight: .bold, design: .rounded))
            }
        }
        .foregroundStyle(.black.opacity(0.8))
        .padding(.horizontal, 5)
        .frame(minWidth: 18, minHeight: 16)
        .background(RoundedRectangle(cornerRadius: 4).fill(color))
    }
}

/// A slice of a menu bar showing the badge in its three states.
struct EditorMenuBarPreview: View {
    let profile: Profile
    let palette: BadgePalette

    private func color(_ tone: BadgeTone) -> Color {
        let c = palette.color(tone).components
        return Color(red: c.red, green: c.green, blue: c.blue)
    }

    var body: some View {
        HStack(spacing: 14) {
            ForEach([BadgeTone.connected, .connecting, .disconnected], id: \.self) { tone in
                VStack(spacing: 4) {
                    EditorBadgePreview(profile: profile, color: color(tone))
                    Text(label(tone)).font(.caption2).foregroundStyle(Palette.fg2)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(Palette.fill, in: RoundedRectangle(cornerRadius: Radius.field, style: .continuous))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Menu bar preview"))
        .accessibilityValue(Text(verbatim: profile.displayBadge))
    }

    private func label(_ tone: BadgeTone) -> LocalizedStringKey {
        switch tone {
        case .connected: return "Connected"
        case .connecting: return "Connecting"
        case .disconnected: return "Off"
        }
    }
}

// MARK: - live code

/// The code of the secret entered or saved in the sheet (18 pt mono, 3+3) with a small countdown ring, so it can
/// be compared with the authenticator app. VoiceOver reads the digits and the seconds left.
struct EditorLiveCode: View {
    let secret: Data
    let params: TOTPParams
    /// Pins the time, for renders.
    var now: Date?

    var body: some View {
        CountdownTimeline(now: now) { date in
            let code = TOTP.code(secret: secret, params: params, at: date)
            let left = Self.remaining(params: params, at: date)
            HStack(spacing: Spacing.xs) {
                GroupedCodeText(code: code, style: .editorCode).foregroundStyle(Palette.fg)
                CodeRing(remaining: left, period: Double(max(1, params.period)), size: 18, weight: 4)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("Current code"))
            .accessibilityValue(
                Text(
                    verbatim: "\(GroupedCodeText.spoken(code)), "
                        + String(localized: "\(Int(left.rounded(.up))) seconds left")))
        }
    }

    /// Seconds left in the current window, with the fraction for a smooth ring.
    static func remaining(params: TOTPParams, at date: Date) -> Double {
        let period = Double(max(1, params.period))
        return period - date.timeIntervalSince1970.truncatingRemainder(dividingBy: period)
    }
}

/// The saved, encrypted TOTP secret's code: hidden until the user confirms (which decrypts it), then
/// live for the reuse window.
struct EditorLockedCode: View {
    let profile: Profile
    let params: TOTPParams
    @ObservedObject var vault: SecretVault
    var now: Date?
    /// A failure (not a cancel), for display.
    var onError: (String) -> Void = { _ in }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            if vault.isUnlocked(profile.id, .totp),
                let secret = vault.available(profile.id, .totp).flatMap({ try? TOTP.decodeSecret($0) })
            {
                EditorLiveCode(secret: secret, params: params, now: now)
            } else {
                HStack(spacing: Spacing.xs) {
                    GroupedCodeText(
                        code: String(repeating: "0", count: max(6, params.digits)), hidden: true,
                        style: .editorCode
                    )
                    .foregroundStyle(Palette.fg3)
                    Button("Show") { reveal() }
                        .buttonStyle(.smallCapsule)
                        .accessibilityIdentifier("editor.revealCode")
                }
            }
        }
    }

    private func reveal() {
        Task { @MainActor in
            do { try await vault.unlock(profile, [.totp], for: .code) } catch {
                if (error as? PTError) != .userConfirmationCancelled { onError(error.localizedDescription) }
            }
        }
    }
}

// MARK: - server receives

/// "Server receives": what the sign-in sends, from the profile's real user name, code format and delivery. The
/// password is always bullets (the view is never given it); the code is the live one, or example digits in `fg3`
/// when there is none to show (asked when connecting, or locked).
struct EditorServerPreview: View {
    let username: String
    let parts: [OTPComposer.Part]
    /// The code goes in a field of its own: shown on a second line.
    let separateCode: Bool
    let digits: Int
    /// The current code, or nil.
    let code: (Date) -> String?
    /// Pins the time, for renders.
    var now: Date?

    static let maskedPassword = String(repeating: "•", count: 8)

    var body: some View {
        if let now {
            content(now)
        } else {
            TimelineView(.periodic(from: .now, by: 1)) { content($0.date) }
        }
    }

    private func content(_ date: Date) -> some View {
        let live = code(date)
        let shown = live ?? String("123456789".prefix(max(1, digits)))
        return VStack(alignment: .leading, spacing: 2) {
            Text(firstLine(code: shown, live: live != nil))
            if separateCode { Text(segment(shown, dim: live == nil)) }
        }
        .typography(.rowCode)
        .foregroundStyle(Palette.fg)
        .fixedSize(horizontal: false, vertical: true)
        .padding(.vertical, Spacing.xs)
        .padding(.horizontal, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.fill, in: RoundedRectangle(cornerRadius: Radius.field, style: .continuous))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Server receives"))
        .accessibilityValue(Text(verbatim: spoken(code: shown)))
    }

    private func firstLine(code: String, live: Bool) -> AttributedString {
        var line = username.isEmpty ? segment(String(localized: "user name"), dim: true) : segment(username)
        line += segment(" · ")
        for part in parts {
            switch part {
            case .password: line += segment(Self.maskedPassword, dim: true)
            case .code: line += segment(code, dim: !live)
            case .text(let text): line += segment(text)
            }
        }
        return line
    }

    private func segment(_ text: String, dim: Bool = false) -> AttributedString {
        var s = AttributedString(text)
        if dim { s.foregroundColor = Palette.fg3 }
        return s
    }

    /// "alice, hidden password, 4 8 2, 9 1 3".
    private func spoken(code: String) -> String {
        var words = [username.isEmpty ? String(localized: "user name") : username]
        for part in parts {
            switch part {
            case .password: words.append(String(localized: "hidden password"))
            case .code: words.append(GroupedCodeText.spoken(code))
            case .text(let text): words.append(text)
            }
        }
        if separateCode { words.append(GroupedCodeText.spoken(code)) }
        return words.joined(separator: ", ")
    }
}
