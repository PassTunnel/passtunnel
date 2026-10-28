import PassTunnelCore
import PassTunnelKit
import SwiftUI

// "Lab overlaps with Work": the sheet connecting a profile asks for when its routes or DNS names overlap with a tunnel that is
// connected (`ConnectionManager.overlaps(for:)`, docs/APP.md, Main window). Only the main window asks; the CLI
// and the MCP server warn and go on. The wording says that the traffic can go through just one of the two tunnels, not
// which one: that depends on the system and has not been verified on a Mac (decision D-22).

/// A connect that waits for the answer: the profile and the connected ones its tunnel overlaps with.
struct OverlapRequest: Identifiable {
    let id = UUID()
    let profile: Profile
    let overlaps: [ProfileOverlap]

    /// "Work", "Work and Data Center", "Work, Data Center and Home".
    var otherNames: String {
        ListFormatter.localizedString(byJoining: overlaps.map(\.name))
    }
}

extension AppModel {
    /// Connects `p` at once when no connected tunnel overlaps with it; else asks (`overlapRequest`).
    func connectUnlessOverlapping(_ p: Profile) {
        // Not even the helper is asked about a profile this version does not connect.
        if let stored = storedProfile(p) {
            do { try ConnectionManager.checkConnectable(stored) } catch { return showError(error) }
        }
        Task {
            let overlaps = await connections.overlaps(for: p.id)
            if overlaps.isEmpty {
                startConnect(p)
            } else {
                overlapRequest = OverlapRequest(profile: p, overlaps: overlaps)
                // The sheet lives in the main window (asked from the menu bar, a shortcut or a notification).
                if !mainWindowVisible { AppDelegate.shared?.showMainWindow() }
            }
        }
    }

    /// "Switch to Lab": disconnects the tunnels it overlaps with, then connects.
    func switchToOverlapping(_ request: OverlapRequest) {
        overlapRequest = nil
        Task {
            for overlap in request.overlaps {
                do { try await connections.disconnect(overlap.profileID) } catch { return showError(error) }
            }
            startConnect(request.profile)
        }
    }

    /// "Connect both".
    func connectBoth(_ request: OverlapRequest) {
        overlapRequest = nil
        startConnect(request.profile)
    }
}

/// The sheet: what overlaps in a table per connected profile, then Cancel, Connect both and Switch to (primary).
struct OverlapSheet: View {
    @EnvironmentObject private var model: AppModel
    let request: OverlapRequest

    var body: some View {
        let mine = request.profile.name
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text(String(localized: "\(mine) overlaps with \(request.otherNames)"))
                .typography(.dialogTitle)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            Text(explanation)
                .typography(.body)
                .lineSpacing(3)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(request.overlaps, id: \.profileID) { overlap in
                OverlapTable(overlap: overlap, mine: mine, captioned: request.overlaps.count > 1)
            }
            Text(String(localized: "“Switch to \(mine)” disconnects \(request.otherNames) first."))
                .typography(.hint)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: Spacing.xs) {
                Spacer(minLength: 0)
                Button {
                    model.overlapRequest = nil
                } label: {
                    Text(String(localized: "Cancel"))
                }
                .buttonStyle(.secondaryCapsule)
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("overlap.cancel")
                Button {
                    model.connectBoth(request)
                } label: {
                    Text(String(localized: "Connect both"))
                }
                .buttonStyle(.secondaryCapsule)
                .accessibilityIdentifier("overlap.both")
                Button {
                    model.switchToOverlapping(request)
                } label: {
                    Text(String(localized: "Switch to \(mine)"))
                }
                .buttonStyle(.primaryCapsule)
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("overlap.switch")
            }
            .padding(.top, 2)
        }
        .padding(Spacing.l)
        .frame(width: 520)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("overlap.sheet")
    }

    /// Who is connected, and that the shared traffic can go through only one of the two tunnels (not which one).
    private var explanation: String {
        let mine = request.profile.name
        let others = request.otherNames
        let sentence =
            request.overlaps.count == 1
            ? String(localized: "\(others) is connected and sends some of the same traffic as \(mine) through its tunnel.")
            : String(localized: "\(others) are connected and send some of the same traffic as \(mine) through their tunnels.")
        return sentence + " " + String(localized: "With both on, that traffic can go through only one of the two tunnels.")
    }
}

/// What one connected profile and the one being connected both take: networks, DNS names, and all traffic.
private struct OverlapTable: View {
    let overlap: ProfileOverlap
    let mine: String
    let captioned: Bool

    private struct Row: Identifiable {
        let id: Int
        var label: String
        var isMono = true
        var theirs: String
        var mine: String
    }

    /// Rows shown before "and N more".
    private static let maxRows = 6

    private var rows: [Row] {
        let summary = overlap.summary
        var rows: [Row] = []
        func add(_ label: String, mono: Bool = true, theirs: String, mine: String) {
            rows.append(Row(id: rows.count, label: label, isMono: mono, theirs: theirs, mine: mine))
        }
        let yes = String(localized: "Yes")
        let none = Self.none
        if summary.firstTakesAllTraffic || summary.secondTakesAllTraffic {
            add(
                String(localized: "All traffic"), mono: false, theirs: summary.secondTakesAllTraffic ? yes : none,
                mine: summary.firstTakesAllTraffic ? yes : none)
        }
        for route in summary.routes { add(route.description, theirs: yes, mine: yes) }
        for domain in summary.domains {
            add("DNS · " + domain, theirs: overlap.theirs.dnsServers.first ?? yes, mine: overlap.mine.dnsServers.first ?? yes)
        }
        return rows
    }

    var body: some View {
        let rows = rows
        let shown = rows.prefix(Self.maxRows)
        let more = rows.count - shown.count
        VStack(alignment: .leading, spacing: Spacing.xxs) {
            if captioned {
                Text(verbatim: overlap.name).typography(.bodyEmphasized).foregroundStyle(Palette.fg)
            }
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: Spacing.s, verticalSpacing: Spacing.xs) {
                GridRow {
                    header(String(localized: "Sent through the tunnel"))
                    header(overlap.name)
                    header(mine)
                    header("")
                }
                ForEach(shown) { row in
                    GridRow {
                        Text(verbatim: row.label)
                            .font(row.isMono ? .system(size: 12.5, design: .monospaced) : .body)
                            .foregroundStyle(Palette.fg)
                            .fixedSize(horizontal: false, vertical: true)
                        Text(verbatim: row.theirs).typography(.body).foregroundStyle(Palette.fg)
                        Text(verbatim: row.mine).typography(.body).foregroundStyle(Palette.fg)
                        HStack(spacing: 4) {
                            StatusIcon(.warning, size: 13)
                            Text(String(localized: "Overlap")).fontWeight(.semibold)
                        }
                        .typography(.body)
                        .foregroundStyle(Palette.amber)
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(Text(verbatim: spoken(row)))
                }
            }
            if more > 0 {
                Text(String(localized: "and \(more) more"))
                    .typography(.hint)
                    .foregroundStyle(Palette.fg2)
            }
        }
        .padding(.vertical, 12)
        .padding(.horizontal, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.fill, in: RoundedRectangle(cornerRadius: Radius.field, style: .continuous))
        .accessibilityElement(children: .contain)
    }

    private func header(_ text: String) -> some View {
        Text(verbatim: text)
            .typography(.hint)
            .fontWeight(.semibold)
            .foregroundStyle(Palette.fg2)
            .lineLimit(1)
            .truncationMode(.tail)
    }

    /// "10.0.0.0/8: Work yes, Lab yes, overlap".
    private func spoken(_ row: Row) -> String {
        func said(_ cell: String) -> String { cell == Self.none ? String(localized: "no") : cell }
        return String(localized: "\(row.label): \(overlap.name) \(said(row.theirs)), \(mine) \(said(row.mine)), overlap")
    }

    /// A table cell for "not in this tunnel".
    private static let none = "—"
}
