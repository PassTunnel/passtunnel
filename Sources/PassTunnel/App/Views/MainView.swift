import PassTunnelCore
import SwiftUI
import UniformTypeIdentifiers

struct MainView: View {
    @EnvironmentObject private var model: AppModel
    @State private var dropTargeted = false

    var body: some View {
        ZStack {
            if model.profiles.isEmpty {
                EmptyStateView()
            } else {
                ProfileList()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
        .navigationTitle(Text(verbatim: "PassTunnel"))
        .navigationSubtitle(subtitle)
        .toolbar {
            ToolbarItem(placement: .primaryAction) { AddMenu() }
        }
        .modifier(SearchWhenLong(enabled: model.profiles.count > 6, text: $model.searchText))
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                ToastView(toast: toast)
                    .padding(.bottom, 18)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .id(toast.id)
            }
        }
        .overlay { if dropTargeted { DropHighlight() } }
        .onDrop(of: [.fileURL, .image], isTargeted: $dropTargeted) { ImportActions.handleDrop($0) }
        .background {
            Color.clear.sheet(item: $model.editor) { request in
                ProfileEditorView(profileID: request.profileID, newType: request.newType) {
                    model.editor = nil
                    if let id = request.profileID { model.forgetSecrets(id) }
                    model.reload()
                }
                .environmentObject(model)
            }
        }
        .background {
            Color.clear.sheet(item: $model.credentialRequest) { request in
                CredentialSheet(request: request).environmentObject(model)
            }
        }
        .background {
            Color.clear.sheet(isPresented: $model.showOnboarding) {
                OnboardingView().environmentObject(model)
            }
        }
        .alert(item: $model.alert) { alert in
            if alert.opensHelperSettings {
                return Alert(title: Text(alert.title), message: Text(alert.message),
                             primaryButton: .default(Text(String(localized: "Open Helper Settings"))) {
                                 model.settingsTab = .helper
                                 AppDelegate.shared?.showSettings()
                             },
                             secondaryButton: .cancel())
            }
            return Alert(title: Text(alert.title), message: Text(alert.message))
        }
        .confirmationDialog(deleteTitle, isPresented: deleteBinding, titleVisibility: .visible, presenting: model.pendingDelete) { p in
            Button(String(localized: "Delete"), role: .destructive) { model.delete(p) }
            Button(String(localized: "Cancel"), role: .cancel) {}
        } message: { _ in
            Text(String(localized: "The profile, its configuration and its Keychain items are removed. This cannot be undone."))
        }
        .onAppear { model.markDropsSeen() }
    }

    private var subtitle: String {
        let active = model.profiles.filter { model.statusKind($0) == .connected || model.statusKind($0) == .degraded }.count
        return active == 0 ? "" : String(localized: "\(active) connected")
    }

    private var deleteTitle: String {
        String(localized: "Delete “\(model.pendingDelete?.name ?? "")”?")
    }

    private var deleteBinding: Binding<Bool> {
        Binding(get: { model.pendingDelete != nil }, set: { if !$0 { model.pendingDelete = nil } })
    }
}

private struct SearchWhenLong: ViewModifier {
    let enabled: Bool
    @Binding var text: String

    func body(content: Content) -> some View {
        if enabled {
            content.searchable(text: $text, placement: .toolbar, prompt: Text(String(localized: "Search profiles")))
        } else {
            content
        }
    }
}

private struct DropHighlight: View {
    var body: some View {
        RoundedRectangle(cornerRadius: 12, style: .continuous)
            .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 3, dash: [8, 5]))
            .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay {
                Label(String(localized: "Drop to import"), systemImage: "square.and.arrow.down")
                    .font(.title3.weight(.semibold))
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(.regularMaterial, in: Capsule())
            }
            .padding(8)
            .allowsHitTesting(false)
    }
}

struct AddMenu: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Menu {
            Button { model.newProfile(.openvpn) } label: {
                Label(String(localized: "New OpenVPN…"), systemImage: VPNType.openvpn.defaultSymbol)
            }
            Button { model.newProfile(.forti) } label: {
                Label(String(localized: "New FortiGate…"), systemImage: VPNType.forti.defaultSymbol)
            }
            Divider()
            Button { ImportActions.importOVPN() } label: {
                Label(String(localized: "Import .ovpn…"), systemImage: "doc.badge.plus")
            }
            Button { ImportActions.importShared() } label: {
                Label(String(localized: "Import Shared Profile…"), systemImage: "square.and.arrow.down")
            }
            Button { ImportActions.addCodeFromQR(profileID: model.selection) } label: {
                Label(String(localized: "Add Code from QR…"), systemImage: "qrcode.viewfinder")
            }
        } label: {
            Label(String(localized: "Add"), systemImage: "plus")
        }
        .help(String(localized: "Add or import a VPN profile"))
    }
}

// MARK: - List

struct ProfileList: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        let items = model.filteredProfiles
        List(selection: $model.selection) {
            ForEach(items) { p in
                ProfileRow(profile: p)
                    .tag(p.id)
                    .listRowSeparator(.visible)
            }
            .onMove(perform: model.searchText.isEmpty ? { model.move(fromOffsets: $0, toOffset: $1) } : nil)
            if items.isEmpty {
                Text(String(localized: "No profiles match “\(model.searchText)”."))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, 24)
                    .disableSelection()
            }
        }
        .listStyle(.inset(alternatesRowBackgrounds: false))
        .scrollContentBackground(.hidden)
        .contextMenu(forSelectionType: String.self) { ids in
            if let id = ids.first, let p = model.profile(id) {
                ProfileMenuItems(profile: p)
            }
        } primaryAction: { ids in
            // Return or double click.
            if let id = ids.first, let p = model.profile(id) { model.primaryAction(p) }
        }
        .onCopyCommand {
            guard let id = model.selection, let p = model.profile(id), let c = model.code(for: p) else { return [] }
            model.showToast(String(localized: "Code copied"))
            return [NSItemProvider(object: c.code as NSString)]
        }
    }
}

private extension View {
    @ViewBuilder func disableSelection() -> some View {
        if #available(macOS 14, *) { self.selectionDisabled(true) } else { self }
    }
}

/// Shared by the row's ⋯ button and the list's context menu.
struct ProfileMenuItems: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile

    var body: some View {
        let p = profile
        Button(String(localized: "Edit…")) { model.edit(p) }
        Divider()
        Button(String(localized: "Copy Code")) { model.copyCode(p) }
            .disabled(model.code(for: p) == nil)
        Button(String(localized: "Copy Password + Code")) { model.copyPasswordAndCode(p) }
            .disabled(p.passwordMode != .keychain)
        Divider()
        Button(String(localized: "Share…")) { model.share(p) }
        Button(String(localized: "Show Log")) { model.showLog(p) }
        Divider()
        Toggle(String(localized: "Pin to Menu Bar"), isOn: Binding(get: { p.pinned }, set: { _ in model.togglePin(p) }))
        Toggle(String(localized: "Default Profile"), isOn: Binding(get: { model.isDefault(p) }, set: { _ in model.makeDefault(p) }))
        Divider()
        Button(String(localized: "Delete…"), role: .destructive) { model.pendingDelete = p }
    }
}

// MARK: - Row

struct ProfileRow: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile

    var body: some View {
        let kind = model.statusKind(profile)
        HStack(spacing: 12) {
            ProfileAvatar(profile: profile, kind: kind, size: 36)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 5) {
                    Text(profile.name)
                        .font(.system(size: 14, weight: .semibold))
                        .lineLimit(1)
                    if model.isDefault(profile) {
                        Image(systemName: "star.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(.yellow)
                            .help(String(localized: "Default profile"))
                            .accessibilityLabel(String(localized: "Default profile"))
                    }
                    if profile.pinned {
                        Image(systemName: "pin.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(.secondary)
                            .help(String(localized: "Pinned to the menu bar"))
                            .accessibilityLabel(String(localized: "Pinned to the menu bar"))
                    }
                }
                StatusLine(profile: profile, kind: kind)
            }
            .layoutPriority(1)
            Spacer(minLength: 8)
            if model.hasCode(profile) {
                LiveCodeView(profile: profile)
                    .layoutPriority(2)
            }
            PrimaryButton(profile: profile, kind: kind)
                .layoutPriority(2)
            Menu {
                ProfileMenuItems(profile: profile)
            } label: {
                Image(systemName: "ellipsis.circle")
                    .font(.system(size: 15))
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .foregroundStyle(.secondary)
            .help(String(localized: "More actions"))
            .accessibilityLabel(String(localized: "More actions for \(profile.name)"))
        }
        .padding(.vertical, 7)
        .padding(.horizontal, 4)
        .contentShape(Rectangle())
        .accessibilityElement(children: .contain)
        .accessibilityLabel(profile.name)
    }
}

struct PrimaryButton: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let kind: StatusKind

    var body: some View {
        Group {
            switch model.state(profile.id) {
            case .disconnected:
                Button { model.connect(profile) } label: {
                    uniformWidth(Text(String(localized: "Connect")))
                }
                .buttonStyle(.borderedProminent)
            case .connecting:
                Button { model.disconnect(profile) } label: {
                    uniformWidth(cancelLabel)
                }
                .buttonStyle(.bordered)
            case .connected:
                Button { model.disconnect(profile) } label: {
                    uniformWidth(Text(String(localized: "Disconnect")))
                }
                .buttonStyle(.bordered)
            }
        }
        .controlSize(.regular)
        .accessibilityHint(Text(profile.name))
    }

    private var cancelLabel: some View {
        HStack(spacing: 6) {
            ProgressView().controlSize(.small).scaleEffect(0.7).frame(width: 12, height: 12)
            Text(String(localized: "Cancel"))
        }
    }

    /// Every state's label takes the width of the widest one, so codes line up across rows in
    /// any language ("Bağlantıyı Kes" is much wider than "Bağlan").
    private func uniformWidth<Label: View>(_ label: Label) -> some View {
        ZStack {
            Text(String(localized: "Connect")).hidden()
            Text(String(localized: "Disconnect")).hidden()
            cancelLabel.hidden()
            label
        }
        .frame(minWidth: 78)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: labelText))
    }

    private var labelText: String {
        switch model.state(profile.id) {
        case .disconnected: return String(localized: "Connect")
        case .connecting: return String(localized: "Cancel")
        case .connected: return String(localized: "Disconnect")
        }
    }
}

struct StatusLine: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let kind: StatusKind

    var body: some View {
        HStack(spacing: 4) {
            Text(prefix)
                .foregroundStyle(.secondary)
            if kind != .disconnected {
                Text(verbatim: "·").foregroundStyle(.tertiary)
                statusText
            }
            if kind == .error || kind == .dropped || model.warning(profile.id) != nil {
                Button(String(localized: "Show log")) { model.showLog(profile) }
                    .buttonStyle(.link)
                    .controlSize(.small)
            }
        }
        .font(.system(size: 11.5))
        .lineLimit(1)
        .truncationMode(.tail)
        .help(helpText)
    }

    private var prefix: String {
        var parts = [profile.type.displayName]
        let user = profile.username.isEmpty ? profile.lastUsername : profile.username
        if !user.isEmpty { parts.append(user) }
        if kind == .disconnected { parts.append(String(localized: "Not connected")) }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder private var statusText: some View {
        switch model.state(profile.id) {
        case .connected(let ip, let since):
            let duration = since.map { DurationFormat.since($0, now: model.now) }
            let base = duration.map { String(localized: "Connected \($0)") } ?? String(localized: "Connected")
            let degraded = model.isUnreachable(profile.id) ? String(localized: "Not responding")
                                                           : String(localized: "Setup incomplete")
            let line = [kind == .degraded ? degraded : base, ip].filter { !$0.isEmpty }
            Text(line.joined(separator: " · ")).foregroundStyle(kind.tint)
        case .connecting(let detail):
            Text(detail.isEmpty ? String(localized: "Connecting…") : detail).foregroundStyle(kind.tint)
        case .disconnected:
            if let info = model.reconnectInfo(profile.id) {
                Text(reconnectText(info)).foregroundStyle(StatusKind.connecting.tint)
            } else if let err = model.error(profile.id) {
                Text(err).foregroundStyle(kind.tint)
            } else if kind == .dropped {
                Text(String(localized: "Connection dropped")).foregroundStyle(kind.tint)
            }
        }
    }

    private func reconnectText(_ info: ReconnectInfo) -> String {
        let secs = max(0, Int(info.at.timeIntervalSince(model.now).rounded(.up)))
        let attempt = String(localized: "attempt \(info.attempt) of \(info.maxAttempts)")
        return secs > 0 ? String(localized: "Reconnecting in \(secs) s (\(attempt))")
                        : String(localized: "Reconnecting… (\(attempt))")
    }

    private var helpText: String {
        if let err = model.error(profile.id) {
            if let tail = model.errorLog(profile.id) { return "\(err)\n\n\(tail)" }
            return err
        }
        if let warning = model.warning(profile.id) { return warning }
        if kind == .degraded {
            return String(localized: "Connected, but the health check host \(profile.healthHost) is not responding.")
        }
        return ""
    }
}
