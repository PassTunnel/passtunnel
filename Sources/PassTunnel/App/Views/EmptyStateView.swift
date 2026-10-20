import PassTunnelCore
import SwiftUI

struct EmptyStateView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(spacing: 22) {
                ZStack {
                    Circle()
                        .fill(Color.accentColor.gradient.opacity(0.14))
                        .frame(width: 96, height: 96)
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 44, weight: .regular))
                        .foregroundStyle(Color.accentColor.gradient)
                }
                .accessibilityHidden(true)
                VStack(spacing: 8) {
                    Text(String(localized: "Add your first VPN"))
                        .font(.system(size: 22, weight: .bold))
                    Text(String(localized: "Import a configuration and PassTunnel fills in your password and one-time code every time you connect."))
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 380)
                }
                ImportOptionsView()
                    .frame(maxWidth: 400)
                HStack(spacing: 6) {
                    Text(String(localized: "Or start from scratch:"))
                        .foregroundStyle(.secondary)
                    Button(String(localized: "OpenVPN")) { model.newProfile(.openvpn) }
                        .buttonStyle(.link)
                    Text(verbatim: "·").foregroundStyle(.tertiary)
                    Button(String(localized: "FortiGate")) { model.newProfile(.forti) }
                        .buttonStyle(.link)
                }
                .font(.callout)
                Label(String(localized: "You can also drop .ovpn, .passtunnel or QR code images here."), systemImage: "arrow.down.doc")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(32)
            .frame(maxWidth: .infinity)
        }
    }
}

/// The three ways in: shown on the empty state and in onboarding.
struct ImportOptionsView: View {
    var body: some View {
        VStack(spacing: 8) {
            ImportOptionButton(symbol: "doc.badge.plus", tint: .blue,
                               title: String(localized: "Import .ovpn…"),
                               subtitle: String(localized: "An OpenVPN configuration file from your IT team")) {
                ImportActions.importOVPN()
            }
            ImportOptionButton(symbol: "square.and.arrow.down", tint: .purple,
                               title: String(localized: "Import shared profile…"),
                               subtitle: String(localized: "A .passtunnel file exported by a colleague")) {
                ImportActions.importShared()
            }
            ImportOptionButton(symbol: "qrcode.viewfinder", tint: .orange,
                               title: String(localized: "Add code from QR…"),
                               subtitle: String(localized: "Scan the authenticator QR code of your VPN")) {
                ImportActions.addCodeFromQR(profileID: nil)
            }
        }
    }
}

struct ImportOptionButton: View {
    let symbol: String
    let tint: Color
    let title: String
    let subtitle: String
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: symbol)
                    .font(.system(size: 17, weight: .medium))
                    .foregroundStyle(.white)
                    .frame(width: 34, height: 34)
                    .background(tint.gradient, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.system(size: 13, weight: .semibold))
                    Text(subtitle).font(.system(size: 11.5)).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.primary.opacity(hover ? 0.07 : 0.04))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.primary.opacity(0.08))
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .accessibilityLabel(title)
        .accessibilityHint(subtitle)
    }
}
