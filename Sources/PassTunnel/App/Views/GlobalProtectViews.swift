import AppKit
import PassTunnelCore
import PassTunnelKit
import PassTunnelVPNConfig
import SwiftUI

// Palo Alto GlobalProtect in the app (#233; docs/ARCHITECTURE.md, "Palo Alto GlobalProtect backend"): the
// "Experimental" badge and the "Report how it works…" link (`VPNType.isExperimental`, the one source of the label), the
// HIP notice of a connected profile (`StatusNotice`), and the confirmation of "Trust This Gateway…" (`GatewayTrust`).
// The failure cards are in FailureCards.swift.

// MARK: - Experimental

/// "Experimental": a small capsule beside the name of an experimental VPN type (`VPNType.isExperimental`), in the
/// foreground the caller sets (it follows a selected row's).
struct ExperimentalBadge: View {
    var body: some View {
        Text(ExperimentalLabel.title)
            .font(.system(size: 10.5, weight: .semibold))
            .lineLimit(1)
            .fixedSize()
            .padding(.horizontal, 6)
            .padding(.vertical, 1.5)
            .overlay(Capsule().strokeBorder(lineWidth: 1).opacity(0.55))
            .accessibilityLabel(Text(ExperimentalLabel.title))
    }
}

enum ExperimentalLabel {
    /// The badge's word.
    static var title: String { String(localized: "Experimental") }

    /// The type's name followed by the badge, for an AppKit button title (Add VPN's type question): the badge is
    /// drawn as an image so it can sit in the title, in the label color of the button's state.
    static func attributedTitle(_ name: String, enabled: Bool) -> NSAttributedString {
        let font = NSFont.systemFont(ofSize: NSFont.systemFontSize)
        let color: NSColor = enabled ? .controlTextColor : .disabledControlTextColor
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .center
        let title = NSMutableAttributedString(
            string: name + "  ", attributes: [.font: font, .foregroundColor: color, .paragraphStyle: paragraph])
        let attachment = NSTextAttachment()
        let image = badgeImage(color: enabled ? .secondaryLabelColor : .tertiaryLabelColor)
        attachment.image = image
        attachment.bounds = CGRect(x: 0, y: (font.capHeight - image.size.height) / 2, width: image.size.width, height: image.size.height)
        title.append(NSAttributedString(attachment: attachment))
        title.addAttributes([.paragraphStyle: paragraph], range: NSRange(location: 0, length: title.length))
        return title
    }

    /// The capsule as an image that draws in the current appearance (light or dark).
    static func badgeImage(color: NSColor) -> NSImage {
        let font = NSFont.systemFont(ofSize: 10, weight: .semibold)
        let text = NSAttributedString(string: title, attributes: [.font: font, .foregroundColor: color])
        let textSize = text.size()
        let size = NSSize(width: ceil(textSize.width) + 12, height: ceil(textSize.height) + 3)
        return NSImage(size: size, flipped: false) { rect in
            let path = NSBezierPath(roundedRect: rect.insetBy(dx: 0.5, dy: 0.5), xRadius: rect.height / 2, yRadius: rect.height / 2)
            color.withAlphaComponent(0.7).setStroke()
            path.lineWidth = 1
            path.stroke()
            text.draw(at: NSPoint(x: (rect.width - textSize.width) / 2, y: (rect.height - textSize.height) / 2))
            return true
        }
    }
}

extension AppInfo {
    /// The GlobalProtect report template (docs/ARCHITECTURE.md, "Experimental": `.github/ISSUE_TEMPLATE/
    /// globalprotect_report.md`) of the project's repository.
    static var globalProtectReportURL: URL {
        var components = URLComponents(url: repositoryURL.appendingPathComponent("issues/new"), resolvingAgainstBaseURL: false)
        components?.queryItems = [URLQueryItem(name: "template", value: "globalprotect_report.md")]
        return components?.url ?? repositoryURL
    }
}

extension AppModel {
    /// "Report how it works…": opens the report template of an experimental type in the browser.
    func reportExperimental() {
        NSWorkspace.shared.open(AppInfo.globalProtectReportURL)
    }
}

/// "Report how it works…" as a link (hint size, underlined), for an experimental type's detail header.
struct ExperimentalReportLink: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Button {
            model.reportExperimental()
        } label: {
            Text(String(localized: "Report how it works…")).underline()
        }
        .buttonStyle(.plain)
        .typography(.hint)
        .foregroundStyle(Palette.fg)
        .fixedSize()
        .help(Text(String(localized: "Opens a report form on GitHub in your browser.")))
        .accessibilityIdentifier("profile.reportExperimental")
    }
}

/// The last row of a failure card for an experimental type: that its support is experimental, with "Report how it
/// works…". Nothing for other types.
struct ExperimentalReportRow: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile

    var body: some View {
        if profile.type.isExperimental {
            DiagnosisRow(
                symbol: .info,
                title: Text(String(localized: "\(profile.type.displayName) support is experimental")),
                link: (String(localized: "Report how it works…"), { model.reportExperimental() })
            )
            .accessibilityIdentifier("profile.\(profile.id).failure.report")
        }
    }
}

// MARK: - Notices

extension AppModel {
    /// What the user should know about `p`'s connection that is up (`ConnectionManager.notices`: the gateway asked for
    /// a HIP report); empty otherwise. The session's log is read again only when it changed.
    func notices(_ p: Profile) -> [StatusNotice] {
        if previewStates != nil { return state(p.id).isConnected ? previewNotices[p.id] ?? [] : [] }
        guard p.type == .globalprotect, state(p.id).isConnected else { return [] }
        return NoticeCache.notices(p.id, url: store.logURL(p.id)) { connections.notices(p.id) }
    }
}

/// The notices of each profile, kept while its log file stays the same.
@MainActor
private enum NoticeCache {
    private struct Stamp: Equatable {
        var modified: Date?
        var size: Int?
    }

    private static var cache: [String: (stamp: Stamp, notices: [StatusNotice])] = [:]

    static func notices(_ id: String, url: URL, read: () -> [StatusNotice]) -> [StatusNotice] {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        let stamp = Stamp(modified: attributes?[.modificationDate] as? Date, size: (attributes?[.size] as? NSNumber)?.intValue)
        if let entry = cache[id], entry.stamp == stamp { return entry.notices }
        let notices = read()
        cache[id] = (stamp, notices)
        return notices
    }
}

/// A notice under the detail's status line: the warning glyph and the sentence (`StatusNotice.message`).
struct StatusNoticeRow: View {
    let notice: StatusNotice

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.xs) {
            StatusIcon(.warning, size: 16)
                .frame(width: 20)
                .padding(.top, 1)
            Text(notice.message)
                .typography(.body)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("profile.notice.\(notice.rawValue)")
    }
}

// MARK: - Trust This Gateway

/// The confirmation of "Trust This Gateway…": the gateway and its key, and, when the profile pins no portal key, the
/// portal's key read from the portal now (`GatewayTrust`, `TLSFingerprint.fetchServerKeyPin`), which is trusted with
/// it. Trust is offered only once both keys are shown and while the profile still names the server and pins of the
/// failed sign-in (`AppModel.serverTrustOffer`). `reads`: false in renders, which set the state themselves.
struct GatewayTrustSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let profile: Profile
    @State var trust: GatewayTrust
    var reads = true

    var body: some View {
        let offer = trust.offer
        let current = model.serverTrustOffer(profile) == offer
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text(String(localized: "Trust the gateway \(offer.server)?"))
                .typography(.dialogTitle)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            Text(
                trust.needsPortalKey
                    ? String(localized: "PassTunnel will accept only these two keys when this profile signs in.")
                    : String(localized: "PassTunnel will accept only this key for the gateway when this profile signs in.")
            )
            .typography(.body)
            .foregroundStyle(Palette.fg2)
            .fixedSize(horizontal: false, vertical: true)
            Card(style: .compact) {
                keyRow(title: String(localized: "Gateway \(offer.server)"), pin: offer.pin)
                if !offer.replacing.isEmpty {
                    keyRow(title: String(localized: "Replaces the gateway key trusted now"), pin: offer.replacing, dimmed: true)
                }
                if trust.needsPortalKey { portalRow }
            }
            if trust.needsPortalKey {
                Text(
                    String(
                        localized:
                            "Trusting a gateway’s key turns off the system’s trust for the portal too, so the portal’s key is trusted with it. It was read from the portal just now."
                    )
                )
                .typography(.hint)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
            }
            Text(
                trust.needsPortalKey
                    ? String(localized: "Trust them only if they match the fingerprints your IT team gave you.")
                    : String(localized: "Trust it only if it matches the fingerprint your IT team gave you.")
            )
            .typography(.hint)
            .foregroundStyle(Palette.fg2)
            .fixedSize(horizontal: false, vertical: true)
            if !current {
                Text(ServerTrustOffer.Stale().localizedDescription)
                    .typography(.hint)
                    .foregroundStyle(Palette.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: Spacing.xs) {
                Spacer(minLength: 0)
                Button(String(localized: "Cancel"), role: .cancel) { dismiss() }
                    .buttonStyle(.secondaryCapsule(.compact))
                    .keyboardShortcut(.cancelAction)
                Button(trust.needsPortalKey ? String(localized: "Trust Both Keys") : String(localized: "Trust Gateway")) {
                    model.trustServer(offer, portalPin: trust.portalPin)
                    dismiss()
                }
                .buttonStyle(.primaryCapsule(.compact))
                .keyboardShortcut(.defaultAction)
                .disabled(!trust.canTrust || !current)
                .accessibilityIdentifier("profile.\(profile.id).trustGateway.confirm")
            }
        }
        .padding(Spacing.l)
        .frame(width: 520)
        .task(id: trust.portalKey == .reading) { await readPortalKey() }
    }

    @ViewBuilder private var portalRow: some View {
        switch trust.portalKey {
        case .read(let pin):
            keyRow(title: String(localized: "Portal \(trust.portal)"), pin: pin)
        case .reading:
            VStack(alignment: .leading, spacing: 2) {
                Text(String(localized: "Portal \(trust.portal)")).typography(.bodyEmphasized).foregroundStyle(Palette.fg)
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text(String(localized: "Reading the portal’s key…")).typography(.hint).foregroundStyle(Palette.fg2)
                }
            }
        case .failed(let message):
            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "Portal \(trust.portal)")).typography(.bodyEmphasized).foregroundStyle(Palette.fg)
                Text(message).typography(.hint).foregroundStyle(Palette.red).fixedSize(horizontal: false, vertical: true)
                Button(String(localized: "Try again")) { trust.retry() }
                    .buttonStyle(.secondaryCapsule(.compact))
            }
        case .notNeeded:
            EmptyView()
        }
    }

    private func keyRow(title: String, pin: String, dimmed: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .typography(.bodyEmphasized)
                .foregroundStyle(dimmed ? Palette.fg2 : Palette.fg)
                .lineLimit(2)
                .truncationMode(.middle)
            Text(verbatim: pin)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(dimmed ? Palette.fg2 : Palette.fg)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }

    /// Reads the portal's key while the state asks for it; the answer is kept only for this offer (`GatewayTrust`).
    private func readPortalKey() async {
        guard reads, trust.portalKey == .reading else { return }
        let offer = trust.offer
        do {
            let pin = try await TLSFingerprint.fetchServerKeyPin(host: offer.host, port: offer.port)
            trust.portalKeyRead(pin, for: offer)
        } catch is CancellationError {
            return
        } catch {
            trust.portalKeyFailed(error.localizedDescription, for: offer)
        }
    }
}

/// Wraps a `GatewayTrust` for `.sheet(item:)`.
struct GatewayTrustRequest: Identifiable {
    let id = UUID()
    let trust: GatewayTrust
}
