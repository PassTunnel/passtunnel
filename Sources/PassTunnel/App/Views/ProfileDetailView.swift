import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// The selected profile in the main window: its name, where it connects, the main button and the status
/// line, then the current code and what the server receives (CodeCards.swift) and the activity (ActivityViews.swift).
/// After a failure a card says what happened instead of the code cards (FailureCards.swift), and a clock that is off has
/// a banner above it all (ClockBanner.swift). Edit and ⋯ are in the toolbar.
struct ProfileDetailView: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile

    var body: some View {
        // Keyed by the profile: another one reads its own activity from the start.
        DetailPage(model: model, profile: profile)
            .id(profile.id)
            .toolbar {
                // Trailing (`primaryAction` is the leading edge on macOS).
                ToolbarItemGroup(placement: .automatic) {
                    Button(String(localized: "Edit")) { model.edit(profile) }
                        .disabled(model.editRefusal(profile) != nil)
                        .help(model.editRefusal(profile)?.unavailableNote ?? "")
                        .accessibilityIdentifier("profile.\(profile.id).edit")
                    DetailMoreMenu(profile: profile)
                }
            }
    }
}

private struct DetailPage: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    @StateObject private var activity: ActivityFeed

    init(model: AppModel, profile: Profile) {
        self.profile = profile
        _activity = StateObject(wrappedValue: ActivityFeed(model, profile.id))
    }

    var body: some View {
        let status = model.displayStatus(profile)
        let server = model.serverSummary(profile)
        // When the sign-in of the connection that is up was sent.
        let sentAt = status.connectedSince.flatMap { ActivityEvent.sentAt(connectedSince: $0, in: activity.events) }
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.m) {
                // Above the detail of any profile.
                if let clock = model.clockWarning { ClockBanner(clock: clock) }
                HStack(alignment: .bottom, spacing: Spacing.m) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: profile.name)
                            .typography(.detailTitle)
                            .foregroundStyle(Palette.fg)
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityAddTraits(.isHeader)
                        Text(verbatim: server.subtitle)
                            .typography(.body)
                            .foregroundStyle(Palette.fg2)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    DetailActionButton(profile: profile, action: status.action)
                }
                ProfileStatusLine(status: status, server: server.address, now: model.previewNow)
                if case .unavailable = status {
                    UnavailableCard(profile: profile)
                } else if model.showsFailureCard(profile, status) {
                    FailureCard(profile: profile, status: status, server: server.address)
                } else {
                    DetailCodeCards(profile: profile, sentAt: sentAt)
                }
                ActivityCard(profile: profile, feed: activity)
            }
            .padding(.horizontal, Spacing.xl)
            .padding(.top, Spacing.s)
            .padding(.bottom, Spacing.l)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .onReceive(model.connections.activity) { record in
            if record.profileID == profile.id { activity.refresh(force: true) }
        }
        .task { await activity.follow() }
    }
}

/// Connect, Cancel, Disconnect, Stop or Try again (`DisplayStatus.action`): a 40 pt capsule as wide as the widest of
/// them, so it keeps its size when the state changes, in any language.
struct DetailActionButton: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let action: DisplayStatus.Action

    var body: some View {
        Button {
            model.runAction(profile)
        } label: {
            ZStack {
                ForEach(DisplayStatus.Action.allCases, id: \.self) { Text($0.title).hidden() }
                    .accessibilityHidden(true)
                Text(action.title)
            }
        }
        .buttonStyle(CapsuleButtonStyle(kind: action.isProminent ? .primary : .secondary, size: .large))
        // Connect stays in its place, disabled, for a type this Mac cannot connect (`DisplayStatus.unavailable`).
        .disabled(!model.displayStatus(profile).allowsAction)
        // On the button itself: a label set inside the button's label can leave the button without a name.
        .accessibilityLabel(Text(verbatim: action.title))
        .accessibilityHint(Text(verbatim: profile.name))
        .accessibilityIdentifier("profile.\(profile.id).primary")
    }
}

/// A profile of a type this Mac cannot connect (`DisplayStatus.unavailable`: Cisco AnyConnect below macOS 15.4), in
/// place of the code cards: why, and what still works. Connect and Edit are disabled; sharing and deleting are not.
private struct UnavailableCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile

    var body: some View {
        Card(style: .compact) {
            Text(text)
                .typography(.body)
                .foregroundStyle(Palette.fg)
                .lineSpacing(2)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("profile.\(profile.id).unavailable")
    }

    private var text: String {
        guard case .anyConnectRequiresMacOS(let version)? = model.connectRefusal(profile.type) else {
            return model.connectRefusal(profile.type)?.localizedDescription ?? ""
        }
        return String(
            localized:
                "PassTunnel connects Cisco AnyConnect with openconnect, which runs on macOS \(version) or later. Update macOS to connect or edit this profile. You can still share or delete it."
        )
    }
}

/// ⋯ in the toolbar: what the sidebar's context menu has besides Edit.
private struct DetailMoreMenu: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile

    var body: some View {
        let p = profile
        Menu {
            Button(String(localized: "Copy Code")) { model.copyCode(p) }
                .disabled(model.code(for: p) == nil && !model.isCodeLocked(p))
            Button(String(localized: "Copy Password + Code")) { model.copyPasswordAndCode(p) }
                .disabled(!model.canCopyPassword(p))
            Divider()
            Button(String(localized: "Share…")) { model.share(p) }
            Button(String(localized: "Show Log")) { model.showLog(p) }
            Divider()
            Button(p.pinned ? String(localized: "Unpin from Menu Bar") : String(localized: "Pin to Menu Bar")) {
                model.togglePin(p)
            }
            Toggle(String(localized: "Default Profile"), isOn: Binding(get: { model.isDefault(p) }, set: { _ in model.makeDefault(p) }))
            Divider()
            Button(String(localized: "Delete…"), role: .destructive) { model.pendingDelete = p }
        } label: {
            Label(String(localized: "More actions"), systemImage: Self.symbol)
        }
        .menuIndicator(.hidden)
        .help(String(localized: "More actions"))
        .accessibilityLabel(String(localized: "More actions for \(p.name)"))
        .accessibilityIdentifier("profile.\(p.id).more")
    }

    /// Toolbar items sit in glass capsules on macOS 26; before, the circle draws the button.
    private static var symbol: String {
        if #available(macOS 26, *) { return "ellipsis" }
        return "ellipsis.circle"
    }
}

extension DisplayStatus.Action {
    /// Connect, Disconnect and Try again are primary (fg on bg); Cancel and Stop secondary.
    var isProminent: Bool {
        switch self {
        case .connect, .disconnect, .tryAgain: return true
        case .cancel, .stop: return false
        }
    }
}

extension AppModel {
    /// The detail's main button, which Return, a double click and ⌘↩ run too: connects or ends the connection, the
    /// attempt or the automatic reconnect.
    func runAction(_ p: Profile) {
        if displayStatus(p).action.connects { connect(p) } else { disconnect(p) }
    }

    /// The line under the profile's name ("vpn.example.com:1194 · OpenVPN · UDP", "gw.example.net:443 · FortiGate";
    /// the VPN type alone when the server is unknown) and the server alone ("" when unknown).
    func serverSummary(_ p: Profile) -> (address: String, subtitle: String) {
        switch p.type {
        case .openvpn:
            guard let e = ConfigEndpoints.endpoint(store.ovpnURL(p.id)) else { return ("", p.type.displayName) }
            // Protocol names stay untranslated.
            return (e.address, [e.server, p.type.displayName, e.tcp ? "TCP" : "UDP"].joined(separator: " · "))
        case .forti, .anyconnect:
            let host = p.host.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty else { return ("", p.type.displayName) }
            let address = OVPNAnalyzer.Endpoint.address(host: host, port: String(p.port))
            // Cisco AnyConnect: the user group the address leads to ("vpn.example.com:443/engineering").
            let shown = p.type == .anyconnect && !p.usergroup.isEmpty ? address + "/" + p.usergroup : address
            return (address, [shown, p.type.displayName].joined(separator: " · "))
        }
    }
}

/// The first server of each config.ovpn, read again only when the file changes (the editor, the CLI or a hand
/// edit).
@MainActor
private enum ConfigEndpoints {
    private struct Stamp: Equatable {
        var modified: Date?
        var size: Int?
    }

    private static var cache: [URL: (stamp: Stamp, endpoint: OVPNAnalyzer.Endpoint?)] = [:]

    static func endpoint(_ url: URL) -> OVPNAnalyzer.Endpoint? {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path) else {
            cache[url] = nil
            return nil
        }
        let stamp = Stamp(
            modified: attributes[.modificationDate] as? Date,
            size: (attributes[.size] as? NSNumber)?.intValue)
        if let entry = cache[url], entry.stamp == stamp { return entry.endpoint }
        let endpoint = (try? String(contentsOf: url, encoding: .utf8)).flatMap(OVPNAnalyzer.endpoint)
        cache[url] = (stamp, endpoint)
        return endpoint
    }
}
