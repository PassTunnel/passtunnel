import AppKit
import PassTunnelCore
import SwiftUI

/// Curated SF Symbols that exist on macOS 13.
enum EditorIcons {
    static let all: [String] = [
        "lock.shield", "lock", "key", "shield",
        "network", "globe", "server.rack", "cloud",
        "building.2", "house", "briefcase", "desktopcomputer",
        "laptopcomputer", "terminal", "antenna.radiowaves.left.and.right", "wifi",
        "airplane", "graduationcap", "cross.case", "cart",
        "wrench.and.screwdriver", "leaf", "flame", "star",
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
            .font(.callout)
            .foregroundStyle(.red)
            .accessibilityLabel(Text("Error: \(message)"))
        }
    }
}

/// Secondary one-line explanation under a row.
struct EditorHint: View {
    let text: Text
    init(_ key: LocalizedStringKey) { text = Text(key) }
    init(verbatim: String) { text = Text(verbatim: verbatim) }

    var body: some View {
        text.font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}

/// "Saved in Keychain ✓"
struct EditorKeychainBadge: View {
    var body: some View {
        Label("Saved in Keychain", systemImage: "checkmark.circle.fill")
            .font(.callout)
            .foregroundStyle(.green)
            .accessibilityLabel(Text("Saved in Keychain"))
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
                    Text("None").foregroundStyle(.secondary)
                } else {
                    Image(systemName: icon).frame(width: 18)
                }
                Image(systemName: "chevron.down").font(.caption2).foregroundStyle(.secondary)
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
        return Button {
            icon = name
            onPick()
        } label: {
            Image(systemName: name)
                .font(.system(size: 15))
                .frame(width: 34, height: 30)
                .background(RoundedRectangle(cornerRadius: 6)
                    .fill(selected ? Color.accentColor.opacity(0.25) : Color.clear))
                .overlay(RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(selected ? Color.accentColor : Color.secondary.opacity(0.2)))
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
                    Text(label(tone)).font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 7).fill(.quaternary))
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

/// Large live code with a countdown ring; updates every second.
struct EditorLiveCode: View {
    let secret: Data
    let params: TOTPParams

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = TOTP.code(secret: secret, params: params, at: context.date)
            let left = TOTP.remaining(params: params, at: context.date)
            HStack(spacing: 12) {
                Text(verbatim: Self.grouped(code))
                    .font(.system(size: 26, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.primary)
                    .textSelection(.enabled)
                EditorCountdownRing(remaining: left, period: max(1, params.period))
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("Current code"))
            .accessibilityValue(Text("\(code), \(left) seconds left"))
        }
    }

    /// "482913" → "482 913"; 7 and 8 digits split 4+3 / 4+4.
    static func grouped(_ code: String) -> String {
        guard code.count > 4 else { return code }
        let split = code.count == 6 ? 3 : 4
        let i = code.index(code.startIndex, offsetBy: split)
        return "\(code[..<i]) \(code[i...])"
    }
}

struct EditorCountdownRing: View {
    let remaining: Int
    let period: Int

    var body: some View {
        let fraction = Double(remaining) / Double(period)
        ZStack {
            Circle().stroke(Color.secondary.opacity(0.25), lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(remaining <= 5 ? Color.orange : Color.accentColor,
                        style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text(verbatim: "\(remaining)")
                .font(.system(size: 10, weight: .medium, design: .rounded))
                .monospacedDigit()
        }
        .frame(width: 28, height: 28)
    }
}

// MARK: - QR drop zone

struct EditorQRDropZone: View {
    let isTargeted: Bool
    let chooseImage: () -> Void
    let pasteImage: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 26))
                .foregroundStyle(isTargeted ? Color.accentColor : .secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text("Scan the QR code your VPN provider gave you")
                    .font(.body.weight(.medium))
                Text("Drop a screenshot here, or:")
                    .font(.callout).foregroundStyle(.secondary)
                HStack {
                    Button("Choose Image…", action: chooseImage)
                    Button("Paste from Clipboard", action: pasteImage)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(isTargeted ? Color.accentColor : Color.secondary.opacity(0.35),
                              style: StrokeStyle(lineWidth: isTargeted ? 2 : 1, dash: [5, 4]))
        )
    }
}
