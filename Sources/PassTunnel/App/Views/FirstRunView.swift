import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

// Adding a VPN in the main window: the first run, while there are no profiles, and what the sidebar's + opens ("Add a
// VPN"). A drop zone with Choose File…, a tile for each other way in, and the helper card while the helper is not
// installed. There is no onboarding sheet (decision D-18): once the first profile is there, the detail asks whether
// PassTunnel should open at login.

struct FirstRunView: View {
    @EnvironmentObject private var model: AppModel
    /// No profiles yet: the app icon, "Add your first VPN" and what PassTunnel does; else only "Add a VPN".
    let isFirstRun: Bool
    /// The helper was not installed when the view appeared: its card stays, saying when it is.
    @State private var showsHelper = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                FileDropZone()
                AddTiles()
                if showsHelper || model.helperStatus != .enabled {
                    HelperCard()
                }
            }
            .frame(maxWidth: 680, alignment: .leading)
            .padding(.horizontal, Spacing.xl)
            .padding(.top, Spacing.s)
            .padding(.bottom, Spacing.l)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .onAppear { showsHelper = model.helperStatus != .enabled }
        .onExitCommand(perform: isFirstRun ? nil : { model.addingProfile = false })
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            if isFirstRun {
                Image(nsImage: AppInfo.appIcon)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 52, height: 52)
                    .accessibilityHidden(true)
            }
            Text(isFirstRun ? String(localized: "Add your first VPN") : String(localized: "Add a VPN"))
                .typography(.screenTitle)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            if isFirstRun {
                // Not "nothing leaves this Mac": the VPN and update checks do (decision D-13).
                Text(String(localized: "PassTunnel works out the one-time code and sends it with your password when you connect. No account. Your passwords and secrets stay on this Mac."))
                    .typography(.intro)
                    .foregroundStyle(Palette.fg2)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 520, alignment: .leading)
            }
        }
        .padding(.top, isFirstRun ? 10 : 0)
    }
}

extension AppModel {
    /// The sidebar's +: the add view in the detail, with no profile selected. Selecting a profile closes it.
    func showAddView() {
        selection = nil
        addingProfile = true
    }
}

// MARK: - Drop zone

/// A dashed area for a .passtunnel or .ovpn file, with Choose File…. A drop on it is the window's drop
/// (`ImportActions.handleDrop`, a QR code image included); the area is outlined instead of the whole window.
private struct FileDropZone: View {
    @State private var targeted = false

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: Radius.compactCard, style: .continuous)
        VStack(spacing: 6) {
            Image(systemName: "doc")
                .font(.system(size: 24, weight: .light))
                .foregroundStyle(Palette.fg2)
                .accessibilityHidden(true)
            Text(String(localized: "Drop a .passtunnel or .ovpn file here"))
                .typography(.dropTitle)
                .foregroundStyle(Palette.fg)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Button(String(localized: "Choose File…")) { ImportActions.importFile() }
                .buttonStyle(.secondaryCapsule(.compact))
                .padding(.top, Spacing.xxs)
                .accessibilityIdentifier("firstRun.chooseFile")
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .background(targeted ? Palette.fill2 : Palette.fill, in: shape)
        .overlay(shape.strokeBorder(targeted ? Palette.fg : Palette.fg3, style: StrokeStyle(lineWidth: 1.5, dash: [5, 4])))
        .onDrop(of: [.fileURL, .image], isTargeted: $targeted) { ImportActions.handleDrop($0) }
    }
}

// MARK: - Tiles

/// The ways in besides a file, one tile each, in this order. Scanning a QR code on screen is the first one, on macOS 14
/// and later only (decision D-20: the system's content picker came with macOS 14).
enum AddOption: CaseIterable {
    case scanScreen, qrImage, byHand

    /// The tiles this Mac shows.
    static var shown: [AddOption] {
        if #available(macOS 14, *) { return allCases }
        return allCases.filter { $0 != .scanScreen }
    }

    var symbol: String {
        switch self {
        case .scanScreen: return "qrcode.viewfinder"
        case .qrImage: return "photo"
        case .byHand: return "keyboard"
        }
    }

    var title: String {
        switch self {
        case .scanScreen: return String(localized: "Scan a QR code on screen")
        case .qrImage: return String(localized: "Use a QR image")
        case .byHand: return String(localized: "Enter details by hand")
        }
    }

    var detail: String {
        switch self {
        case .scanScreen: return String(localized: "Select the authenticator QR open in your browser.")
        case .qrImage: return String(localized: "A screenshot or a photo of the QR.")
        case .byHand: return String(localized: "Server, user name, password and code secret.")
        }
    }

    var identifier: String {
        switch self {
        case .scanScreen: return "firstRun.scanScreen"
        case .qrImage: return "firstRun.qrImage"
        case .byHand: return "firstRun.byHand"
        }
    }

    /// Each asks OpenVPN or FortiGate, then opens a new profile's editor: with the code filled in for a scanned QR.
    @MainActor func run() {
        switch self {
        case .scanScreen: ImportActions.newProfileFromScreen()
        case .qrImage: ImportActions.newProfileFromQR()
        case .byHand: ImportActions.newProfileByHand()
        }
    }
}

/// The tiles side by side, as wide and as tall as each other.
private struct AddTiles: View {
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            ForEach(AddOption.shown, id: \.self) { AddTile(option: $0) }
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}

private struct AddTile: View {
    let option: AddOption
    @State private var hover = false

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: Radius.compactCard, style: .continuous)
        Button { option.run() } label: {
            VStack(alignment: .leading, spacing: 6) {
                Image(systemName: option.symbol)
                    .font(.system(size: 17))
                    .frame(height: 20)
                    .foregroundStyle(Palette.fg)
                    .accessibilityHidden(true)
                Text(option.title)
                    .typography(.bodyEmphasized)
                    .foregroundStyle(Palette.fg)
                    .fixedSize(horizontal: false, vertical: true)
                Text(option.detail)
                    .typography(.hint)
                    .foregroundStyle(Palette.fg2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(hover ? Palette.fill : Palette.card, in: shape)
            .edge(shape, Palette.line)
            .contentShape(shape)
            .contentShape(.focusEffect, shape)
        }
        .buttonStyle(TileButtonStyle())
        .onHover { hover = $0 }
        // On the button itself: a label set inside the button's label can leave the button without a name.
        .accessibilityLabel(Text(verbatim: option.title))
        .accessibilityHint(Text(verbatim: option.detail))
        .accessibilityIdentifier(option.identifier)
    }
}

/// Pressed tiles shrink like the capsule buttons; keyboard focus keeps the system focus ring.
private struct TileButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? Motion.pressedScale : 1)
    }
}

// MARK: - Helper

/// What the helper is for and its Install button (decision D-18). After Install,
/// macOS may ask for an approval in Login Items: the card opens them and follows the status. Once the helper runs, the
/// card says so until the view goes.
private struct HelperCard: View {
    @EnvironmentObject private var model: AppModel
    @State private var busy = false
    @State private var errorText: String?
    private let timer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        let installed = model.helperStatus == .enabled
        Card(style: .compact) {
            HStack(alignment: .top, spacing: Spacing.s) {
                Image(systemName: installed ? "checkmark.shield" : "lock.shield")
                    .font(.system(size: 20))
                    .foregroundStyle(installed ? Palette.green : Palette.fg)
                    .frame(width: 24)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 6) {
                    Text(String(localized: "Install the helper"))
                        .typography(.bodyEmphasized)
                        .foregroundStyle(Palette.fg)
                        .accessibilityAddTraits(.isHeader)
                    Text(String(localized: "Creating a VPN tunnel needs administrator rights. A small helper does that part, and it only runs the signed VPN tools that ship inside PassTunnel."))
                        .typography(.hint)
                        .foregroundStyle(Palette.fg2)
                        .fixedSize(horizontal: false, vertical: true)
                    status
                    if let errorText {
                        Text(errorText)
                            .typography(.hint)
                            .foregroundStyle(Palette.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .onReceive(timer) { _ in if !installed { model.refreshHelperStatus() } }
    }

    @ViewBuilder private var status: some View {
        switch model.helperStatus {
        case .notRegistered:
            HStack(spacing: Spacing.xs) {
                Button(String(localized: "Install Helper")) { install() }
                    .buttonStyle(.primaryCapsule(.compact))
                    .disabled(busy)
                    .accessibilityIdentifier("firstRun.installHelper")
                if busy {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityLabel(String(localized: "Working…"))
                }
            }
            .padding(.top, Spacing.xxs)
        case .requiresApproval:
            Text(String(localized: "Almost done: turn on PassTunnel in System Settings → General → Login Items."))
                .typography(.hint)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
            Button(String(localized: "Open Login Items…")) { HelperInstaller.openSystemSettingsLoginItems() }
                .buttonStyle(.primaryCapsule(.compact))
                .padding(.top, Spacing.xxs)
                .accessibilityIdentifier("firstRun.loginItems")
        case .notFound:
            Text(String(localized: "Move PassTunnel to the Applications folder and open it from there to install the helper."))
                .typography(.hint)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
        case .enabled:
            Text(String(localized: "The helper is installed and running."))
                .typography(.hint)
                .foregroundStyle(Palette.green)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// As Settings → Helper installs it.
    private func install() {
        guard !busy else { return }
        busy = true
        errorText = nil
        Task {
            do {
                try await HelperInstaller.registerRetrying()
            } catch {
                errorText = error.localizedDescription
            }
            busy = false
            model.refreshHelperStatus()
            if model.helperStatus == .requiresApproval { HelperInstaller.openSystemSettingsLoginItems() }
        }
    }
}

// MARK: - Open at login

/// "Open PassTunnel at login?" under the detail once the first profile is there, until it is answered (decision D-18):
/// the login item is registered only when the user says so. Not asked when PassTunnel already opens at login or cannot
/// (not run as an app).
struct OpenAtLoginQuestion: View {
    @EnvironmentObject private var model: AppModel
    @AppStorage(AppModel.onboardingKey) private var answered = false
    /// Renders: shown or not, whatever the defaults and the login item say.
    var preview: Bool?

    var body: some View {
        if preview ?? LoginItem.asksAfterFirstProfile(answered: answered, hasProfiles: !model.profiles.isEmpty,
                                                      status: LoginItem.status) {
            Card(style: .compact) {
                // The buttons go under the words when both do not fit on one line. No fixed size for the words:
                // outside a scroll view it would raise the window's minimum height.
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: Spacing.s) {
                        question
                        Spacer(minLength: 0)
                        buttons
                    }
                    VStack(alignment: .leading, spacing: Spacing.s) {
                        question
                        buttons
                    }
                }
            }
            .padding(.horizontal, Spacing.xl)
            .padding(.vertical, Spacing.s)
        }
    }

    private var question: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(String(localized: "Open PassTunnel at login?"))
                .typography(.bodyEmphasized)
                .foregroundStyle(Palette.fg)
            Text(String(localized: "Starts quietly in the menu bar, without opening the window."))
                .typography(.hint)
                .foregroundStyle(Palette.fg2)
        }
        .accessibilityElement(children: .combine)
    }

    private var buttons: some View {
        HStack(spacing: Spacing.s) {
            Button(String(localized: "Not Now")) { answer(false) }
                .buttonStyle(.secondaryCapsule(.compact))
                .accessibilityIdentifier("firstRun.notNow")
            Button(String(localized: "Open at Login")) { answer(true) }
                .buttonStyle(.primaryCapsule(.compact))
                .accessibilityIdentifier("firstRun.openAtLogin")
        }
    }

    private func answer(_ open: Bool) {
        model.answerOpenAtLogin(open)
        answered = true
    }
}
