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
            out.append(BundledTool(name: String(parts[0]), version: version,
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
                    if busy { ProgressView().controlSize(.small) }
                }
                .padding(.vertical, 4)
                if let errorText {
                    Text(errorText).font(.caption).foregroundStyle(.red)
                }
                HStack {
                    switch model.helperStatus {
                    case .notRegistered, .notFound:
                        Button(String(localized: "Install Helper")) { install() }
                            .buttonStyle(.borderedProminent)
                            .disabled(busy || model.helperStatus == .notFound)
                    case .requiresApproval:
                        Button(String(localized: "Open Login Items…")) { HelperInstaller.openSystemSettingsLoginItems() }
                            .buttonStyle(.borderedProminent)
                        Button(String(localized: "Remove"), role: .destructive) { confirmRemove = true }
                    case .enabled:
                        if model.helperOutdated {
                            Button(String(localized: "Update Helper")) { update() }
                                .buttonStyle(.borderedProminent)
                                .disabled(busy)
                        }
                        Button(String(localized: "Open Login Items…")) { HelperInstaller.openSystemSettingsLoginItems() }
                        Button(String(localized: "Remove Helper…"), role: .destructive) { confirmRemove = true }
                            .disabled(busy)
                    }
                    Spacer()
                }
            } header: {
                Text(String(localized: "Privileged helper"))
            } footer: {
                Text(String(localized: "VPN tools need administrator rights to create the tunnel. The helper only runs the signed copies of OpenVPN and openfortivpn inside PassTunnel, never anything else."))
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
            } header: {
                Text(String(localized: "Bundled tools"))
            }
        }
        .formStyle(.grouped)
        .frame(minHeight: 480)
        .onReceive(timer) { _ in model.refreshHelperStatus() }
        .onAppear {
            model.refreshHelperStatus()
            runPendingAction()
        }
        .onChange(of: model.pendingHelperAction) { _ in runPendingAction() }
        .confirmationDialog(String(localized: "Remove the PassTunnel helper?"), isPresented: $confirmRemove) {
            Button(String(localized: "Remove"), role: .destructive) { remove() }
        } message: {
            Text(String(localized: "Active connections stop. You can install the helper again at any time."))
        }
        .sheet(isPresented: $showLicenses) { LicensesView() }
    }

    private var outdated: Bool { model.helperStatus == .enabled && model.helperOutdated }

    private var statusTitle: String {
        if outdated { return String(localized: "Needs an update") }
        switch model.helperStatus {
        case .enabled: return String(localized: "Installed and running")
        case .requiresApproval: return String(localized: "Waiting for your approval")
        case .notRegistered: return String(localized: "Not installed")
        case .notFound: return String(localized: "Missing from this copy of PassTunnel")
        }
    }

    private var statusDetail: String {
        if outdated {
            return String(localized: "This helper belongs to another version of PassTunnel. Update it to connect; active connections stop.")
        }
        switch model.helperStatus {
        case .enabled: return String(localized: "PassTunnel can start and stop VPN connections.")
        case .requiresApproval: return String(localized: "Turn on PassTunnel in System Settings → General → Login Items.")
        case .notRegistered: return String(localized: "Install the helper to connect VPNs. macOS asks you to approve it once.")
        case .notFound: return String(localized: "Move PassTunnel to the Applications folder and open it from there.")
        }
    }

    private var statusSymbol: String {
        if outdated { return "arrow.triangle.2.circlepath" }
        switch model.helperStatus {
        case .enabled: return "checkmark.shield.fill"
        case .requiresApproval: return "exclamationmark.shield.fill"
        case .notRegistered: return "shield.slash"
        case .notFound: return "xmark.shield.fill"
        }
    }

    private var statusColor: Color {
        if outdated { return .orange }
        switch model.helperStatus {
        case .enabled: return .green
        case .requiresApproval: return .orange
        case .notRegistered: return .secondary
        case .notFound: return .red
        }
    }

    /// Carries out what `passtunnel helper install|uninstall` asked for. Removal is never silent:
    /// any local process can post the request, so the user confirms it here.
    private func runPendingAction() {
        guard let action = model.pendingHelperAction else { return }
        model.pendingHelperAction = nil
        model.refreshHelperStatus()
        switch (action, model.helperStatus) {
        case (.install, .notRegistered): install()
        case (.install, .requiresApproval): HelperInstaller.openSystemSettingsLoginItems()
        case (.install, _): break
        case (.uninstall, .enabled), (.uninstall, .requiresApproval): confirmRemove = true
        case (.uninstall, _): break
        }
    }

    private func install() {
        errorText = nil
        do {
            try HelperInstaller.register()
        } catch {
            errorText = error.localizedDescription
        }
        model.refreshHelperStatus()
        if model.helperStatus == .requiresApproval { HelperInstaller.openSystemSettingsLoginItems() }
    }

    /// Replaces a helper left running from another app version: unregistering stops it (launchd
    /// sends SIGTERM, which stops its tunnels), registering again points launchd at this copy.
    private func update() {
        busy = true
        errorText = nil
        Task {
            do {
                try await HelperInstaller.unregister()
                try HelperInstaller.register()
            } catch {
                errorText = error.localizedDescription
            }
            busy = false
            model.refreshHelperStatus()
            model.checkHelperVersion()
            if model.helperStatus == .requiresApproval { HelperInstaller.openSystemSettingsLoginItems() }
        }
    }

    private func remove() {
        busy = true
        errorText = nil
        Task {
            do { try await HelperInstaller.unregister() } catch { errorText = error.localizedDescription }
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
