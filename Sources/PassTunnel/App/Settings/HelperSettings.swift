import AppKit
import PassTunnelCore
import SwiftUI

/// Bundled third-party tools, read from `Resources/licenses/THIRD_PARTY_NOTICES.txt`
/// (written by scripts/bundle-tools.sh). The tools themselves are never executed for this.
struct BundledTool: Identifiable, Equatable {
    var id: String { name }
    let name: String
    let version: String
    let license: String
    let url: String
}

enum BundledTools {
    static var licensesDirectory: URL? {
        Bundle.main.resourceURL?.appendingPathComponent("licenses", isDirectory: true)
    }

    static func load(from dir: URL? = licensesDirectory) -> [BundledTool] {
        guard let dir, let text = try? String(contentsOf: dir.appendingPathComponent("THIRD_PARTY_NOTICES.txt"), encoding: .utf8)
        else { return [] }
        return parse(text)
    }

    /// Lines look like "openvpn          2.7.7      GPL-2.0 (…)" followed by an indented URL line.
    static func parse(_ text: String) -> [BundledTool] {
        let lines = text.components(separatedBy: .newlines)
        var out: [BundledTool] = []
        for (i, line) in lines.enumerated() {
            guard let first = line.first, !first.isWhitespace else { continue }
            let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard parts.count == 3, parts[1].first?.isNumber == true else { continue }
            let next = i + 1 < lines.count ? lines[i + 1].trimmingCharacters(in: .whitespaces) : ""
            // Homebrew revisions ("1.24.1_1") are packaging details, not upstream versions.
            let version = parts[1].split(separator: "_").first.map(String.init) ?? String(parts[1])
            out.append(
                BundledTool(
                    name: String(parts[0]), version: version,
                    license: parts[2].trimmingCharacters(in: .whitespaces),
                    url: next.hasPrefix("http") ? next : ""))
        }
        return out
    }

    static func licenseFiles(in dir: URL? = licensesDirectory) -> [URL] {
        guard let dir, let items = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
        else { return [] }
        return items.filter { !$0.lastPathComponent.hasPrefix(".") }
            .sorted { a, b in
                // The overview first, then alphabetical.
                if a.lastPathComponent == "THIRD_PARTY_NOTICES.txt" { return true }
                if b.lastPathComponent == "THIRD_PARTY_NOTICES.txt" { return false }
                return a.lastPathComponent.localizedStandardCompare(b.lastPathComponent) == .orderedAscending
            }
    }
}

struct HelperSettings: View {
    @EnvironmentObject private var model: AppModel
    @State private var busy = false
    @State private var errorText: String?
    @State private var confirmRemove = false
    /// Replacing the helper on request from outside the app (CLI, launch argument) asks first.
    @State private var confirmReplace = false
    /// Replacing a newer helper with this copy's older one always asks.
    @State private var confirmDowngrade = false
    /// The open replace or downgrade confirmation came from Repair Helper.
    @State private var confirmationRepairs = false
    /// The CLI request the open confirmation answers; it is told when the user cancels.
    @State private var replyTo: HelperHandoff?
    @State private var showLicenses = false
    var tools: [BundledTool] = BundledTools.load()
    private let timer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        Form {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: statusSymbol)
                        .font(.system(size: 26))
                        .foregroundStyle(statusColor)
                        .frame(width: 34)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(statusTitle).font(.headline)
                        Text(statusDetail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    if isBusy {
                        ProgressView().controlSize(.small)
                            .accessibilityLabel(updating ? String(localized: "Updating…") : String(localized: "Working…"))
                    }
                }
                .padding(.vertical, 4)
                if let error = errorText ?? model.helperInstallError ?? model.helperUpdateError {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
                HStack {
                    switch model.helperStatus {
                    case .notRegistered, .notFound:
                        Button(String(localized: "Install Helper")) { install() }
                            .buttonStyle(.borderedProminent)
                            .disabled(isBusy || !mayInstall)
                            .accessibilityLabel(String(localized: "Install Helper"))
                            .accessibilityIdentifier("helper.install")
                    case .requiresApproval:
                        Button(String(localized: "Open Login Items…")) { model.openLoginItemsForHelper() }
                            .buttonStyle(.borderedProminent)
                            .accessibilityLabel(String(localized: "Open Login Items…"))
                            .accessibilityIdentifier("helper.loginItems")
                        if model.pendingConnect.isWaiting {
                            Button(String(localized: "Cancel Connecting")) { model.cancelPendingConnect() }
                                .accessibilityLabel(String(localized: "Cancel Connecting"))
                                .accessibilityIdentifier("helper.cancelConnect")
                        }
                        Button(String(localized: "Remove"), role: .destructive) { confirmRemove = true }
                            .accessibilityLabel(String(localized: "Remove Helper…"))
                            .accessibilityIdentifier("helper.remove")
                    case .enabled:
                        // As the title: a helper that does not answer is repaired, even when it was last seen outdated.
                        if notAnswering {
                            Button(String(localized: "Repair Helper")) { repair() }
                                .buttonStyle(.borderedProminent)
                                .disabled(isBusy)
                                .accessibilityLabel(String(localized: "Repair Helper"))
                                .accessibilityIdentifier("helper.repair")
                        } else if model.helperOutdated {
                            Button(String(localized: "Update Helper")) { update() }
                                .buttonStyle(.borderedProminent)
                                .disabled(isBusy)
                                .accessibilityLabel(String(localized: "Update Helper"))
                                .accessibilityIdentifier("helper.update")
                        }
                        Button(String(localized: "Open Login Items…")) { model.openLoginItemsForHelper() }
                            .accessibilityLabel(String(localized: "Open Login Items…"))
                            .accessibilityIdentifier("helper.loginItems")
                        Button(String(localized: "Remove Helper…"), role: .destructive) { confirmRemove = true }
                            .disabled(isBusy)
                            .accessibilityLabel(String(localized: "Remove Helper…"))
                            .accessibilityIdentifier("helper.remove")
                    }
                    Spacer()
                }
                VStack(alignment: .leading, spacing: 2) {
                    Toggle(
                        String(localized: "Install and repair the helper automatically"),
                        isOn: Binding(get: { model.prefs.autoInstallHelper }, set: { model.setAutoInstallHelper($0) })
                    )
                    .accessibilityIdentifier("helper.autoInstall")
                    Text(
                        String(
                            localized:
                                "PassTunnel installs a missing helper on the first run or when you connect. If the helper does not answer when PassTunnel opens or when you connect, it installs it again once, while no VPN is connected and unless the helper is from a newer or different build. macOS still asks you to approve it in Login Items. Only a copy in the Applications folder does this."
                        )
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }
            } header: {
                Text(String(localized: "Privileged helper"))
            } footer: {
                Text(
                    String(
                        localized:
                            "VPN tools need administrator rights to create the tunnel. The helper only runs the signed copies of OpenVPN and openfortivpn inside PassTunnel, never anything else."
                    )
                )
                .settingsFooter()
            }

            Section {
                if tools.isEmpty {
                    Text(String(localized: "Tool information is not available in this build."))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(tools) { tool in
                        LabeledContent {
                            Text(tool.version).monospacedDigit().foregroundStyle(.secondary).textSelection(.enabled)
                        } label: {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(tool.name)
                                Text(tool.license).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                Button(String(localized: "Show Licenses…")) { showLicenses = true }
                    .disabled(BundledTools.licenseFiles().isEmpty)
                    .accessibilityLabel(String(localized: "Show Licenses…"))
                    .accessibilityIdentifier("helper.licenses")
            } header: {
                Text(String(localized: "Bundled tools"))
            }
        }
        .formStyle(.grouped)
        .frame(minHeight: 480)
        .onReceive(timer) { _ in model.refreshHelperStatus() }
        .onAppear {
            model.refreshHelperStatus()
            model.askHelperNow()
            runPendingAction()
        }
        .onDisappear { declined() }
        .onChange(of: model.pendingHelperAction) { _ in runPendingAction() }
        .confirmationDialog(String(localized: "Remove the PassTunnel helper?"), isPresented: $confirmRemove) {
            Button(String(localized: "Remove"), role: .destructive) {
                replyTo = nil; remove()
            }
            Button(String(localized: "Cancel"), role: .cancel) { declined() }
        } message: {
            Text(String(localized: "Active connections stop. You can install the helper again at any time."))
        }
        .confirmationDialog(String(localized: "Replace the PassTunnel helper?"), isPresented: $confirmReplace) {
            Button(String(localized: "Replace Helper")) {
                replyTo = nil; performUpdate(repair: confirmationRepairs)
            }
            Button(String(localized: "Cancel"), role: .cancel) { declined() }
        } message: {
            Text(
                String(
                    localized:
                        "The helper is replaced with the one inside this copy of PassTunnel (\(Bundle.main.bundlePath)). Active connections stop."))
        }
        .confirmationDialog(String(localized: "Replace the helper with an older version?"), isPresented: $confirmDowngrade) {
            Button(String(localized: "Install Older Helper"), role: .destructive) {
                replyTo = nil; performUpdate(repair: confirmationRepairs)
            }
            Button(String(localized: "Cancel"), role: .cancel) { declined() }
        } message: {
            Text(
                String(
                    localized:
                        "The installed helper is from a newer version of PassTunnel than this copy. Replacing it installs an older helper. Active connections stop."
                ))
        }
        .sheet(isPresented: $showLicenses) { LicensesView() }
    }

    /// Answering (or last seen) as another build; a helper that does not answer shows as such instead.
    private var outdated: Bool { model.helperStatus == .enabled && model.helperOutdated && !model.helperNotAnswering }
    private var updating: Bool { model.helperUpdating }
    private var isBusy: Bool { busy || updating || model.helperInstalling }
    /// Enabled, but the helper does not answer (`HelperAnswerWatch`): Repair Helper.
    private var notAnswering: Bool { model.helperStatus == .enabled && model.helperNotAnswering }
    /// Enabled, and the helper has not answered yet.
    private var checking: Bool { model.helperStatus == .enabled && !model.helperAnswered && !notAnswering }
    /// The profile whose connect waits for the approval.
    private var waitingProfile: String? {
        guard model.helperStatus == .requiresApproval, let id = model.pendingConnect.profileID else { return nil }
        return model.profile(id)?.name ?? id
    }
    /// Install Helper is possible: not registered, or not found by a bundled copy in /Applications
    /// (macOS 27.0.1 reported a helper that was never registered that way; register() decides).
    private var mayInstall: Bool { HelperInstaller.canAttemptInstall(status: model.helperStatus) }

    private var statusTitle: String {
        if model.helperRepairing { return String(localized: "Repairing…") }
        if updating { return String(localized: "Updating…") }
        if model.helperInstalling { return String(localized: "Installing…") }
        if outdated { return String(localized: "Needs an update") }
        if notAnswering { return String(localized: "Not responding") }
        if checking { return String(localized: "Installed") }
        switch model.helperStatus {
        case .enabled: return String(localized: "Installed and running")
        case .requiresApproval: return String(localized: "Waiting for your approval")
        case .notRegistered: return String(localized: "Not installed")
        case .notFound:
            return mayInstall
                ? String(localized: "Not reported by macOS yet") : String(localized: "Missing from this copy of PassTunnel")
        }
    }

    private var statusDetail: String {
        if model.helperRepairing {
            return String(localized: "Installing the helper again from this copy of PassTunnel. Active connections stop.")
        }
        if model.helperInstalling {
            return String(localized: "Registering the helper with macOS. macOS asks you to approve it once.")
        }
        if updating {
            return String(localized: "Replacing the helper with the one from this copy of PassTunnel. Active connections stop.")
        }
        if outdated && model.helperRelation == .newer {
            return String(
                localized:
                    "This helper belongs to a newer version of PassTunnel. Update PassTunnel to connect, or replace the helper with the older one from this copy."
            )
        }
        if outdated && model.helperUpdateWaiting {
            return String(
                localized: "This helper belongs to another version of PassTunnel. It updates itself when all VPN connections are disconnected.")
        }
        if outdated {
            return String(localized: "This helper belongs to another version of PassTunnel. Update it to connect; active connections stop.")
        }
        if notAnswering {
            return String(
                localized: "macOS lists the helper as turned on, but it does not answer. Repair it to connect; active connections stop.")
        }
        if checking { return String(localized: "Checking that the helper answers…") }
        if let waitingProfile {
            return String(
                localized:
                    "Turn on PassTunnel in System Settings → General → Login Items. \(waitingProfile) connects if you do within \(Int(HelperPendingConnect.timeout / 60)) minutes."
            )
        }
        switch model.helperStatus {
        case .enabled: return String(localized: "PassTunnel can start and stop VPN connections.")
        case .requiresApproval: return String(localized: "Turn on PassTunnel in System Settings → General → Login Items.")
        case .notRegistered: return String(localized: "Install the helper to connect VPNs. macOS asks you to approve it once.")
        case .notFound:
            return mayInstall
                ? String(localized: "macOS does not list the helper yet. Try installing it; macOS asks you to approve it once.")
                : String(localized: "Move PassTunnel to the Applications folder and open it from there.")
        }
    }

    private var statusSymbol: String {
        if outdated || updating || model.helperInstalling { return "arrow.triangle.2.circlepath" }
        if notAnswering { return "exclamationmark.shield.fill" }
        if checking { return "shield" }
        switch model.helperStatus {
        case .enabled: return "checkmark.shield.fill"
        case .requiresApproval: return "exclamationmark.shield.fill"
        case .notRegistered: return "shield.slash"
        case .notFound: return mayInstall ? "shield.slash" : "xmark.shield.fill"
        }
    }

    private var statusColor: Color {
        if outdated || updating || model.helperInstalling || notAnswering { return .orange }
        if checking { return .secondary }
        switch model.helperStatus {
        case .enabled: return .green
        case .requiresApproval: return .orange
        case .notRegistered: return .secondary
        case .notFound: return mayInstall ? .secondary : .red
        }
    }

    /// Carries out what `passtunnel helper install|update|uninstall` asked for (launch argument or
    /// notification). Any local process can make the request, and registering points the root helper
    /// at this copy, so: installing or updating only from /Applications, and replacing a running
    /// helper or removing it only after the user confirms here (a newer helper with a warning).
    /// The waiting CLI is told when the app asks, refuses, or the user cancels (`HelperHandoff.Outcome`).
    private func runPendingAction() {
        guard let action = model.pendingHelperAction else { return }
        model.pendingHelperAction = nil
        model.refreshHelperStatus()
        if action != .uninstall, model.helperStatus != .requiresApproval,
            !HelperSessions.isInApplicationsFolder(Bundle.main.bundlePath)
        {
            errorText = String(localized: "Open PassTunnel from the Applications folder to install or update the helper from the command line.")
            action.postReply(.refused)
            return
        }
        switch (action, model.helperStatus) {
        case (.install, .notRegistered), (.update, .notRegistered): install()
        case (.install, .notFound) where mayInstall, (.update, .notFound) where mayInstall: install()
        case (.install, .requiresApproval), (.update, .requiresApproval): model.openLoginItemsForHelper()
        case (.install, .enabled): confirmUpdateIfOutdated(force: false, for: action)
        case (.update, .enabled): confirmUpdateIfOutdated(force: true, for: action)
        case (.install, _), (.update, _): break
        case (.uninstall, .enabled), (.uninstall, .requiresApproval): ask(for: action) { confirmRemove = true }
        case (.uninstall, _): break
        }
    }

    /// Asks the running helper how it relates to this copy (the cached `helperRelation` may not be
    /// known yet right after launch) and asks before replacing it. `force`: also offer to replace a
    /// helper that does not answer.
    private func confirmUpdateIfOutdated(force: Bool, for action: HelperHandoff) {
        guard !isBusy else { return }
        Task {
            confirmationRepairs = false
            switch try? await HelperClient.shared.relation() {
            case .current?: break
            case .newer?: ask(for: action) { confirmDowngrade = true }
            case .older?, .different?: ask(for: action) { confirmReplace = true }
            case nil:
                // Not answering now: the last answer decides between the downgrade warning and the plain one.
                guard force else { break }
                if model.helperRelation == .newer {
                    ask(for: action) { confirmDowngrade = true }
                } else {
                    ask(for: action) { confirmReplace = true }
                }
            }
        }
    }

    /// Shows a confirmation for a CLI request and tells the CLI it now waits for the user.
    private func ask(for action: HelperHandoff, _ show: () -> Void) {
        if replyTo != action { declined() }  // a confirmation still open for another request
        replyTo = action
        show()
        action.postReply(.asking)
    }

    private func declined() {
        replyTo?.postReply(.declined)
        replyTo = nil
    }

    /// Install Helper, and an install hand-off: `AppModel.installHelper` (the error shows from the model).
    private func install() {
        guard !isBusy else { return }
        errorText = nil
        Task { await model.installHelper(.button) }
    }

    /// Repair Helper: replaces a helper that does not answer with this copy's (active connections stop). The
    /// click is the confirmation for one never seen or last seen as this build or an older one; one last seen
    /// as newer gets the downgrade warning, one last seen as not comparable "Replace the PassTunnel helper?"
    /// (it cannot be asked now: it does not answer).
    private func repair() {
        guard !isBusy else { return }
        switch model.helperRelation {
        case .newer?:
            confirmationRepairs = true
            confirmDowngrade = true
        case .different?:
            confirmationRepairs = true
            confirmReplace = true
        case nil, .current?, .older?:
            performUpdate(repair: true)
        }
    }

    /// Update Helper button: the click is the confirmation, except for replacing a newer helper (asked
    /// fresh: the cached relation may not be known yet; when the helper does not answer, the cached one).
    private func update() {
        guard !isBusy else { return }
        Task {
            if ((try? await HelperClient.shared.relation()) ?? model.helperRelation) == .newer {
                confirmationRepairs = false
                confirmDowngrade = true
            } else {
                performUpdate()
            }
        }
    }

    /// Replaces a helper left running from another app version, or one that does not answer (`repair`; see
    /// `AppModel.updateHelper`).
    private func performUpdate(repair: Bool = false) {
        guard !isBusy else { return }
        errorText = nil
        Task {
            await model.updateHelper(repair: repair)
            if model.helperStatus == .requiresApproval { model.openLoginItemsForHelper() }
        }
    }

    private func remove() {
        busy = true
        errorText = nil
        Task {
            do {
                try await model.removeHelper()
            } catch {
                errorText = error.localizedDescription
            }
            busy = false
            model.refreshHelperStatus()
        }
    }
}

struct LicensesView: View {
    @Environment(\.dismiss) private var dismiss
    private let files = BundledTools.licenseFiles()
    @State private var selection: URL?

    var body: some View {
        VStack(spacing: 0) {
            HSplitView {
                List(files, id: \.self, selection: $selection) { url in
                    Text(url.lastPathComponent).lineLimit(1)
                }
                .frame(minWidth: 190, maxWidth: 240)
                ScrollView {
                    Text(selection.flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? "")
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                }
                .frame(minWidth: 380)
            }
            Divider()
            HStack {
                if let dir = BundledTools.licensesDirectory {
                    Button(String(localized: "Show in Finder")) { NSWorkspace.shared.activateFileViewerSelecting([dir]) }
                }
                Spacer()
                Button(String(localized: "Done")) { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(12)
        }
        .frame(width: 680, height: 460)
        .onAppear { selection = files.first }
    }
}
