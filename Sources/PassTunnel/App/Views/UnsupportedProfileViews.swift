import PassTunnelCore
import PassTunnelKit
import SwiftUI

// A profile of a VPN type this version does not know (written by a newer PassTunnel; `UnsupportedProfile`): a row
// under the others and a detail that says so. Nothing but deleting it is offered.

/// The sidebar row: the name and "Needs a newer PassTunnel" in amber.
struct UnsupportedSidebarRow: View {
    let profile: UnsupportedProfile

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(verbatim: profile.name)
                .typography(.bodyEmphasized)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .firstTextBaseline, spacing: 5) {
                StatusDot(.warning, size: 7)
                    .alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 4 }
                Text(verbatim: UnsupportedProfile.statusText)
                    .typography(.rowStatus)
                    .rowForeground(Palette.amber)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 5)
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: profile.name))
        .accessibilityValue(Text(verbatim: UnsupportedProfile.statusText))
        .accessibilityIdentifier("profile.\(profile.id)")
    }
}

/// The detail: name, the stored type, why nothing can be done, and Delete.
struct UnsupportedProfileDetail: View {
    @EnvironmentObject private var model: AppModel
    let profile: UnsupportedProfile

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: profile.name)
                    .typography(.detailTitle)
                    .foregroundStyle(Palette.fg)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                Text(verbatim: profile.type)
                    .typography(.body)
                    .foregroundStyle(Palette.fg2)
                    .textSelection(.enabled)
            }
            HStack(alignment: .firstTextBaseline, spacing: Spacing.xs) {
                StatusIcon(.warning)
                    .alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 5 }
                Text(verbatim: UnsupportedProfile.statusText)
                    .typography(.statusLine)
                    .foregroundStyle(Palette.amber)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            Text(
                String(
                    localized:
                        "This profile uses a VPN type this version of PassTunnel does not know. It is kept as it is. Update PassTunnel to connect, edit or share it."
                )
            )
            .typography(.body)
            .foregroundStyle(Palette.fg2)
            .fixedSize(horizontal: false, vertical: true)
            Button(String(localized: "Delete…"), role: .destructive) { model.pendingDeleteUnsupported = profile }
                .buttonStyle(CapsuleButtonStyle(kind: .secondary, size: .large))
                .accessibilityIdentifier("profile.\(profile.id).delete")
        }
        .padding(.horizontal, Spacing.xl)
        .padding(.top, Spacing.s)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

extension View {
    /// Asks before the profile is deleted (same words as `profileDeleteConfirmation`).
    func unsupportedDeleteConfirmation(_ profile: Binding<UnsupportedProfile?>, delete: @escaping (UnsupportedProfile) -> Void) -> some View {
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
