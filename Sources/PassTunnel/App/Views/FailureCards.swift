import AppKit
import PassTunnelCore
import PassTunnelKit
import PassTunnelVPNConfig
import SwiftUI

// The error states of the main window's detail (docs/APP.md, Main window): under the status line, a card
// that says what happened and what is worth checking, instead of the code cards. Core reports why the connect failed
// (`ConnectionFailure`), the tries of an unreachable server (`UnreachableRetry`) and the network path
// (`NetworkStatus`); the cards word them. A clock that is off has its own banner (ClockBanner.swift).

/// Render overrides for the error states, used while the model shows preview states (`AppModel.previewStates`).
struct FailurePreview {
    var failures: [String: ConnectionFailure] = [:]
    var retries: [String: UnreachableRetry] = [:]
    var network = NetworkStatus.unknown
    /// The clock measurements the banner chooses from.
    var clocks: [ClockOffset] = []
    /// Palo Alto GlobalProtect: the portal's gateways after a failure for want of one, and the gateway whose
    /// certificate was not trusted.
    var gatewayChoices: [String: GatewayChoice] = [:]
    var failedGateways: [String: String] = [:]
}

extension AppModel {
    /// Why the last connect of `id` failed, typed.
    func failure(_ id: String) -> ConnectionFailure? {
        previewStates != nil ? previewFailures.failures[id] : connections.failures[id]
    }

    /// The tries of `id`'s server that did not answer, while there are any.
    func unreachableRetry(_ id: String) -> UnreachableRetry? {
        previewStates != nil ? previewFailures.retries[id] : connections.unreachableRetries[id]
    }

    /// Whether this Mac is online, as the system sees it.
    var networkStatus: NetworkStatus {
        previewStates != nil ? previewFailures.network : connections.networkStatus
    }

    /// The last clock measurement of any profile or the time server, when it is recent and off.
    var clockWarning: ClockOffset? {
        let measurements =
            previewStates != nil
            ? previewFailures.clocks
            : Array(connections.clockOffsets.values) + [connections.timeServerClock].compactMap { $0 }
        return ClockOffset.recentWarning(in: measurements, now: now)
    }

    /// Whether the detail shows a card for the failure, in place of the code cards.
    func showsFailureCard(_ p: Profile, _ status: DisplayStatus) -> Bool {
        guard case .failed(let reason) = status else { return false }
        switch reason {
        case .signInRejected, .serverNotTrusted: return failure(p.id) != nil
        case .unreachable, .hostNotFound, .hostScanRequired, .ssoRequired, .gatewayRequired, .notGlobalProtectServer: return true
        case .message:
            return failure(p.id).map { !MessageCard.lines($0, shown: status.line(at: now)).isEmpty } ?? false
        }
    }

    /// "Trust this server": the offer to keep the key of the Cisco AnyConnect or Palo Alto GlobalProtect server (or
    /// GlobalProtect gateway) whose certificate the last connect of `p` did not trust
    /// (`ConnectionManager.serverTrustOffer`); nil when there is none or the profile changed since.
    func serverTrustOffer(_ p: Profile) -> ServerTrustOffer? {
        if previewStates != nil {
            let stored = profile(p.id) ?? p
            return ServerTrustOffer(stored, pin: failure(p.id)?.serverCert, gateway: previewFailures.failedGateways[p.id])
        }
        return connections.serverTrustOffer(p.id)
    }

    /// Keeps the offer's pin in the profile (only its `server_cert`; for a GlobalProtect gateway `gateway_server_cert`
    /// and, when the profile pinned no portal key, `portalPin` in `server_cert`), once the user confirmed the server and
    /// the pins.
    func trustServer(_ offer: ServerTrustOffer, portalPin: String? = nil) {
        guard previewStates == nil else { return }
        do { try connections.trustServer(offer, portalPin: portalPin) } catch { showError(error) }
        reload()
    }

    /// The gateway (`host:port`) whose certificate the last connect of `p` did not trust; nil for the profile's own
    /// server.
    func failedGateway(_ p: Profile) -> String? {
        if previewStates != nil { return failure(p.id)?.serverCert == nil ? nil : previewFailures.failedGateways[p.id] }
        return connections.failedGateway(p.id)
    }

    /// The portal's gateways after the last connect of `p` failed for want of one (`ConnectionManager.gatewayChoice`);
    /// nil when there is none or the profile names another portal since.
    func gatewayChoice(_ p: Profile) -> GatewayChoice? {
        if previewStates != nil {
            guard let choice = previewFailures.gatewayChoices[p.id], choice.matches(profile(p.id) ?? p) else { return nil }
            return choice
        }
        return connections.gatewayChoice(p.id)
    }

    /// Puts one of the portal's gateways into the profile's `gateway` (only that field).
    func chooseGateway(_ choice: GatewayChoice, label: String) {
        guard previewStates == nil else { return }
        do { try connections.chooseGateway(choice, label: label) } catch { showError(error) }
        reload()
    }

    /// "Copy details": the summary for the user's IT team, on the pasteboard as ordinary text. False when there is
    /// no failure to describe.
    @discardableResult
    func copyFailureDetails(_ p: Profile) -> Bool {
        guard let text = connections.failureDetails(p.id)?.text() else { return false }
        NSPasteboard.general.clearContents()
        return NSPasteboard.general.setString(text, forType: .string)
    }
}

// MARK: - Dispatch

/// The card for the profile's failure: the sign-in the server rejected, the server that does not answer, a name that
/// was not found, or another failure's reason. `server`: where the connect goes ("203.0.113.10:443"; "" when unknown).
struct FailureCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let status: DisplayStatus
    var server = ""

    var body: some View {
        let failure = model.failure(profile.id)
        switch status {
        case .failed(.signInRejected):
            if let failure { RejectedCard(profile: profile, failure: failure) }
        case .failed(.unreachable(let retry)):
            UnreachableCard(profile: profile, failure: failure, retry: retry, server: server)
        case .failed(.hostNotFound):
            MessageCard(profile: profile, failure: failure, shown: status.line(at: model.now), editsAddress: true)
        case .failed(.serverNotTrusted):
            if let failure { ServerTrustCard(profile: profile, failure: failure) }
        case .failed(.hostScanRequired):
            HostScanCard(profile: profile, failure: failure)
        case .failed(.ssoRequired):
            SingleSignOnCard(profile: profile, failure: failure)
        case .failed(.gatewayRequired):
            GatewayChoiceCard(profile: profile, choice: model.gatewayChoice(profile))
        case .failed(.notGlobalProtectServer):
            MessageCard(profile: profile, failure: failure, shown: status.line(at: model.now), editsAddress: true)
        case .failed(.message):
            MessageCard(profile: profile, failure: failure, shown: status.line(at: model.now))
        default:
            EmptyView()
        }
    }
}

// MARK: - Rows

/// A fact in a card: a 16 pt glyph (✓ green, ⚠ amber, ✗ red, ⓘ gray) and a line, with a smaller one under it or a link.
/// The glyph is never the only carrier of the meaning: the words say it too.
struct DiagnosisRow: View {
    let symbol: StatusSymbol
    let title: Text
    var detail: Text?
    var link: (title: String, action: () -> Void)?

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            StatusIcon(symbol, size: 16)
                .frame(width: 18)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 1) {
                title
                    .typography(.body)
                    .foregroundStyle(Palette.fg)
                    .fixedSize(horizontal: false, vertical: true)
                if let detail {
                    detail
                        .typography(.hint)
                        .foregroundStyle(Palette.fg2)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let link {
                    Button(action: link.action) {
                        Text(link.title).underline()
                    }
                    .buttonStyle(.plain)
                    .typography(.hint)
                    .foregroundStyle(Palette.fg)
                }
            }
            // A link stays a control of its own for VoiceOver.
            .accessibilityElement(children: link == nil ? .combine : .contain)
            Spacer(minLength: 0)
        }
    }
}

extension Text {
    /// `sentence` with `part` (an address, the server's reply) set in SF Mono.
    static func mono(_ sentence: String, part: String) -> Text {
        var text = AttributedString(sentence)
        if !part.isEmpty, let range = text.range(of: part) {
            text[range].font = .system(size: 12.5, design: .monospaced)
        }
        return Text(text)
    }
}

/// A card's first paragraph.
private struct Lead: View {
    let text: Text

    var body: some View {
        text
            .typography(.body)
            .foregroundStyle(Palette.fg)
            .lineSpacing(2)
            .fixedSize(horizontal: false, vertical: true)
    }
}

// MARK: - Sign-in rejected

/// "The server answered AUTH_FAILED. PassTunnel stopped instead of retrying, so your account won't get locked." and what
/// is worth checking: whether the code was fresh (from the sign-in that was sent), whether the clock is off (the gateway's
/// time after the rejection, or the time server's when asked with the button), and a changed password.
struct RejectedCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let failure: ConnectionFailure
    @StateObject private var check = ClockCheck()

    var body: some View {
        Card(style: .compact) {
            Lead(text: lead)
            codeRow
            clockRow
            if profile.passwordMode == .keychain {
                DiagnosisRow(
                    symbol: .info, title: Text(String(localized: "Changed your password at work?")),
                    link: (String(localized: "Update it in PassTunnel"), { model.edit(profile) })
                )
                .accessibilityIdentifier("profile.\(profile.id).failure.password")
            }
            ExperimentalReportRow(profile: profile)
            ClockCheckButton(check: check)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("profile.\(profile.id).failure")
    }

    private var lead: Text {
        let stopped = String(localized: "PassTunnel stopped instead of retrying, so your account won’t get locked.")
        guard let reply = failure.reply?.trimmingCharacters(in: .whitespacesAndNewlines), !reply.isEmpty else {
            return Text(String(localized: "The server didn’t accept the sign-in.") + " " + stopped)
        }
        let shown = reply.count > 120 ? String(reply.prefix(120)) + "…" : reply
        return Text.mono(String(localized: "The server answered \(shown).") + " " + stopped, part: shown)
    }

    @ViewBuilder private var codeRow: some View {
        if failure.codeSent, let left = failure.codeSecondsLeft {
            if left > Preferences.freshCodeSeconds {
                DiagnosisRow(
                    symbol: .check, title: Text(String(localized: "The code was fresh")),
                    detail: Text(String(localized: "Sent with \(left) s left")))
            } else {
                DiagnosisRow(
                    symbol: .warning, title: Text(String(localized: "The code was about to expire")),
                    detail: Text(String(localized: "Sent with \(left) s left, so it may have run out on the way.")))
            }
        }
    }

    @ViewBuilder private var clockRow: some View {
        if let clock = failure.clock {
            if clock.isWrong {
                DiagnosisRow(
                    symbol: .warning, title: Text(String(localized: "The clock is off by \(clock.offBy)")),
                    detail: Text(String(localized: "Most likely cause. Fix the clock, then try again.")))
            } else {
                DiagnosisRow(
                    symbol: .check, title: Text(String(localized: "The clock is right")),
                    detail: Text(Self.checked(clock)))
            }
        }
    }

    /// "Within 2 s of time.apple.com".
    private static func checked(_ clock: ClockOffset) -> String {
        let seconds = Int(min(clock.offsetSeconds.magnitude, 1_000_000))
        guard let server = clock.server, !server.isEmpty else { return String(localized: "Within \(seconds) s") }
        return String(localized: "Within \(seconds) s of \(server)")
    }
}

// MARK: - Server unreachable

/// "No answer after 3 tries. Your password and code were not sent." with the network (never whether other sites answer: the
/// app only reads the system's own view), the server that did not answer, and a word about networks that block VPN traffic.
/// "Try now" runs the next try at once; "Copy details" puts the summary for the IT team on the pasteboard.
struct UnreachableCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let failure: ConnectionFailure?
    let retry: UnreachableRetry?
    let server: String
    @State private var copied = false

    var body: some View {
        let network = model.networkStatus
        Card(style: .compact) {
            Lead(text: Text(lead))
            networkRow(network)
            DiagnosisRow(symbol: .rejected, title: Self.title(server), detail: failure?.reason.flatMap { $0.isEmpty ? nil : Text($0) })
            DiagnosisRow(
                symbol: .info, title: Text(String(localized: "On a guest or hotel network?")),
                detail: Text(String(localized: "Some networks block VPN traffic. Try another network or ask your IT team.")))
            ExperimentalReportRow(profile: profile)
            HStack(spacing: Spacing.xs) {
                if let retry {
                    Button {
                        model.connections.retryNow(profile.id)
                    } label: {
                        Text(String(localized: "Try now"))
                    }
                    .buttonStyle(.primaryCapsule(.compact))
                    .disabled(retry.nextTryAt == nil && !retry.waitingForNetwork)
                    .accessibilityIdentifier("profile.\(profile.id).failure.tryNow")
                }
                Button(action: copyDetails) {
                    Text(copied ? String(localized: "Copied ✓") : String(localized: "Copy details"))
                }
                .buttonStyle(.secondaryCapsule(.compact, minWidth: 112))
                .accessibilityIdentifier("profile.\(profile.id).failure.copyDetails")
            }
            .padding(.top, 2)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("profile.\(profile.id).failure")
    }

    /// "No answer after 3 tries. Your password and code were not sent."
    private var lead: String {
        let tries = retry?.tries ?? failure?.tries ?? 1
        let answer = tries > 1 ? String(localized: "No answer after \(tries) tries.") : String(localized: "No answer.")
        guard failure?.credentialsSent != true else { return answer }
        return answer + " " + String(localized: "Your password and code were not sent.")
    }

    /// "This Mac is online · Wi-Fi", or offline; nothing while the system has not said.
    @ViewBuilder private func networkRow(_ network: NetworkStatus) -> some View {
        switch network.online {
        case true?:
            let interface = network.interface.map { " · " + $0.name } ?? ""
            DiagnosisRow(symbol: .check, title: Text(String(localized: "This Mac is online") + interface))
        case false?:
            DiagnosisRow(
                symbol: .rejected, title: Text(String(localized: "This Mac is offline")),
                detail: retry?.waitingForNetwork == true
                    ? Text(String(localized: "The next try starts when the network is back.")) : nil)
        case nil:
            EmptyView()
        }
    }

    /// "203.0.113.10:443 didn’t answer".
    static func title(_ server: String) -> Text {
        server.isEmpty
            ? Text(String(localized: "The server didn’t answer"))
            : Text.mono(String(localized: "\(server) didn’t answer"), part: server)
    }

    private func copyDetails() {
        guard model.copyFailureDetails(profile) else { return }
        copied = true
        Task {
            try? await Task.sleep(nanoseconds: UInt64(Motion.copiedDuration * 1_000_000_000))
            copied = false
        }
    }
}

// MARK: - Other failures

/// A short card for the other failures: the tool's reason, and that the sign-in was not sent when it was not. A name that
/// was not found also offers the profile, where the address is.
struct MessageCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let failure: ConnectionFailure?
    /// What the status line already says.
    let shown: String
    var editsAddress = false

    var body: some View {
        let lines = failure.map { Self.lines($0, shown: shown) } ?? []
        if !lines.isEmpty || editsAddress || profile.type.isExperimental {
            Card(style: .compact) {
                ForEach(lines, id: \.self) { Lead(text: Text(verbatim: $0)) }
                if editsAddress {
                    DiagnosisRow(
                        symbol: .info, title: Text(String(localized: "Is the server’s address right?")),
                        link: (String(localized: "Check it in PassTunnel"), { model.edit(profile) }))
                }
                ExperimentalReportRow(profile: profile)
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("profile.\(profile.id).failure")
        }
    }

    /// The tool's reason, unless the status line says it already, and that nothing was sent.
    static func lines(_ failure: ConnectionFailure, shown: String) -> [String] {
        var lines: [String] = []
        if let reason = failure.reason?.trimmingCharacters(in: .whitespacesAndNewlines), !reason.isEmpty, reason != shown {
            lines.append(reason)
        }
        if !failure.credentialsSent { lines.append(String(localized: "Your password and code were not sent.")) }
        return lines
    }
}

// MARK: - Cisco AnyConnect

/// "Copy details" (`AppModel.copyFailureDetails`), with "Copied ✓" for a moment.
private struct CopyDetailsButton: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    @State private var copied = false

    var body: some View {
        Button(action: copyDetails) {
            Text(copied ? String(localized: "Copied ✓") : String(localized: "Copy details"))
        }
        .buttonStyle(.secondaryCapsule(.compact, minWidth: 112))
        .accessibilityIdentifier("profile.\(profile.id).failure.copyDetails")
    }

    private func copyDetails() {
        guard model.copyFailureDetails(profile) else { return }
        copied = true
        Task {
            try? await Task.sleep(nanoseconds: UInt64(Motion.copiedDuration * 1_000_000_000))
            copied = false
        }
    }
}

/// openconnect did not trust the server's certificate (`DisplayStatus.Failure.serverNotTrusted`): what that means, the
/// key it named (`ConnectionFailure.serverCert`) and "Trust This Server…", which keeps that key in the profile after
/// the user confirmed the server and the key (`AppModel.trustServer`). A profile that had another key pinned is told
/// that the key changed. Once the profile trusts the key, the card says so and Try again uses it.
///
/// Palo Alto GlobalProtect: the same for the portal (or, with Skip portal, the only server); for the gateway the portal
/// sent the sign-in to (`AppModel.failedGateway`) "Trust This Gateway…", whose confirmation (`GatewayTrustSheet`) also
/// reads and shows the portal's key when the profile pins none, and saves the gateway's key only with it.
struct ServerTrustCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let failure: ConnectionFailure
    @State private var confirming: ServerTrustOffer?
    @State private var gatewayTrust: GatewayTrustRequest?

    var body: some View {
        let offer = model.serverTrustOffer(profile)
        let gateway = offer?.gateway ?? model.failedGateway(profile)
        let pin = failure.serverCert.flatMap(OpenConnectPin.normalize) ?? ""
        let pinned = AnyConnectEditing.normalizedPin(gateway == nil ? profile.serverCert : profile.gatewayServerCert)
        let trusted = !pin.isEmpty && pinned == pin
        let changedKey = offer.map { !$0.replacing.isEmpty } ?? (!trusted && !pinned.isEmpty)
        Card(style: .compact) {
            Lead(text: lead(changedKey: changedKey, gateway: gateway))
            if !pin.isEmpty {
                DiagnosisRow(
                    symbol: .info,
                    title: Text(gateway == nil ? String(localized: "The server’s key") : String(localized: "The gateway’s key")),
                    detail: Text.mono(pin, part: pin)
                )
                .textSelection(.enabled)
            }
            if trusted {
                DiagnosisRow(
                    symbol: .check, title: Text(String(localized: "This profile trusts this key now")),
                    detail: Text(String(localized: "Connect again to use it.")))
            } else if changedKey {
                DiagnosisRow(
                    symbol: .warning,
                    title: Text(gateway == nil ? String(localized: "The server’s key changed") : String(localized: "The gateway’s key changed")),
                    detail: Text(
                        String(
                            localized:
                                "If the server got a new key, your IT team can confirm this fingerprint. Otherwise someone may be intercepting the connection."
                        )))
            } else if let gateway {
                DiagnosisRow(
                    symbol: .info, title: Text(String(localized: "Check the fingerprint first")),
                    detail: Text(
                        offer?.needsPortalPin == true
                            ? String(
                                localized:
                                    "Trust the gateway \(gateway) only if this fingerprint matches the one your IT team gave you. The portal’s key is read and shown for you to check too."
                            )
                            : String(localized: "Trust the gateway \(gateway) only if this fingerprint matches the one your IT team gave you.")))
            } else {
                DiagnosisRow(
                    symbol: .info, title: Text(String(localized: "Check the fingerprint first")),
                    detail: Text(String(localized: "Trust the server only if this fingerprint matches the one your IT team gave you.")))
            }
            ExperimentalReportRow(profile: profile)
            HStack(spacing: Spacing.xs) {
                if let offer, !trusted {
                    Button {
                        if let trust = GatewayTrust(offer) {
                            gatewayTrust = GatewayTrustRequest(trust: trust)
                        } else {
                            confirming = offer
                        }
                    } label: {
                        Text(buttonTitle(changedKey: changedKey, gateway: offer.gateway != nil))
                    }
                    .buttonStyle(.primaryCapsule(.compact))
                    .accessibilityIdentifier("profile.\(profile.id).failure.trustServer")
                }
                CopyDetailsButton(profile: profile)
            }
            .padding(.top, 2)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("profile.\(profile.id).failure")
        .alert(
            confirming.map(Self.title) ?? "", isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
            presenting: confirming
        ) { offer in
            Button(offer.replacing.isEmpty ? String(localized: "Trust Server") : String(localized: "Replace Key")) {
                model.trustServer(offer)
            }
            Button(String(localized: "Cancel"), role: .cancel) {}
        } message: { offer in
            Text(verbatim: Self.message(offer))
        }
        .sheet(item: $gatewayTrust) { request in
            GatewayTrustSheet(profile: profile, trust: request.trust).environmentObject(model)
        }
    }

    private func buttonTitle(changedKey: Bool, gateway: Bool) -> String {
        if changedKey { return String(localized: "Trust the New Key…") }
        return gateway ? String(localized: "Trust This Gateway…") : String(localized: "Trust This Server…")
    }

    /// Why it stopped, with openconnect's reason ("signer not found") when it gave one. A gateway's key comes after the
    /// portal took the sign-in, so nothing is said about what was sent.
    private func lead(changedKey: Bool, gateway: String?) -> Text {
        let notSent = failure.credentialsSent ? "" : " " + String(localized: "Your password and code were not sent.")
        let reason = failure.reason?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if let gateway {
            if changedKey {
                return Text.mono(String(localized: "The gateway \(gateway) presented another key than the one this profile trusts."), part: gateway)
            }
            let sentence =
                reason.isEmpty
                ? String(localized: "The portal sent the sign-in on to the gateway \(gateway), whose certificate this Mac doesn’t trust.")
                : String(localized: "The portal sent the sign-in on to the gateway \(gateway), whose certificate this Mac doesn’t trust (\(reason)).")
            return Text.mono(sentence, part: gateway)
        }
        if changedKey {
            return Text(String(localized: "The server presented another key than the one this profile trusts.") + notSent)
        }
        let sentence =
            reason.isEmpty
            ? String(localized: "This Mac doesn’t trust the server’s certificate.")
            : String(localized: "This Mac doesn’t trust the server’s certificate (\(reason)).")
        return Text(sentence + notSent)
    }

    /// "Trust vpn.example.com:8443/engineering?"
    static func title(_ offer: ServerTrustOffer) -> String {
        offer.replacing.isEmpty
            ? String(localized: "Trust \(offer.server)?")
            : String(localized: "Replace the key PassTunnel trusts for \(offer.server)?")
    }

    /// The server and the key, in full, and what trusting it does.
    static func message(_ offer: ServerTrustOffer) -> String {
        var text = String(localized: "PassTunnel will accept only the server key with this fingerprint:") + "\n\n" + offer.pin
        if !offer.replacing.isEmpty {
            text += "\n\n" + String(localized: "It replaces the key the profile trusts now:") + "\n\n" + offer.replacing
        }
        return text + "\n\n" + String(localized: "Trust it only if it matches the fingerprint your IT team gave you.")
    }
}

/// The server asked for a host scan (Cisco Secure Desktop), which PassTunnel never runs (`DisplayStatus.Failure.hostScanRequired`).
struct HostScanCard: View {
    let profile: Profile
    let failure: ConnectionFailure?

    var body: some View {
        Card(style: .compact) {
            Lead(
                text: Text(
                    String(localized: "The server asked for a host scan (Cisco Secure Desktop) before the sign-in. PassTunnel never runs it.")
                        + (failure?.credentialsSent == true ? "" : " " + String(localized: "Your password and code were not sent."))))
            DiagnosisRow(
                symbol: .info, title: Text(String(localized: "Ask your IT team")),
                detail: Text(
                    String(
                        localized:
                            "Your account may be allowed to sign in without the host scan, or the server may offer a group that doesn’t ask for it."
                    )))
            CopyDetailsButton(profile: profile).padding(.top, 2)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("profile.\(profile.id).failure")
    }
}

// MARK: - Palo Alto GlobalProtect

/// The portal or the gateway signs in with single sign-on (SAML), which PassTunnel does not support
/// (`DisplayStatus.Failure.ssoRequired`). At the portal nothing was sent; at a gateway behind a password portal the
/// portal's sign-in was.
struct SingleSignOnCard: View {
    let profile: Profile
    let failure: ConnectionFailure?

    var body: some View {
        Card(style: .compact) {
            Lead(
                text: Text(
                    String(
                        localized:
                            "This server signs in with single sign-on (SAML) in a web page. PassTunnel signs in only with a password and a one-time code."
                    ) + (failure?.credentialsSent == true ? "" : " " + String(localized: "Your password and code were not sent."))))
            DiagnosisRow(
                symbol: .info, title: Text(String(localized: "Ask your IT team")),
                detail: Text(
                    String(
                        localized:
                            "Your account may be allowed to sign in with a password and code, or there may be a gateway you can sign in to directly (Skip portal)."
                    )))
            ExperimentalReportRow(profile: profile)
            CopyDetailsButton(profile: profile).padding(.top, 2)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("profile.\(profile.id).failure")
    }
}

/// The portal lists more than one gateway and the profile names none of them (`DisplayStatus.Failure.gatewayRequired`):
/// the portal's gateways (`GatewayChoice`, its labels as Core read them) under **Choose Gateway**, which puts the one
/// picked into the profile's `gateway` (`AppModel.chooseGateway`); Try again then signs in to it. Without readable
/// labels, the profile's editor and the log.
struct GatewayChoiceCard: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    let choice: GatewayChoice?

    var body: some View {
        let labels = choice?.options(for: profile) ?? []
        let chosen = labels.contains(profile.gateway) && profile.gateway != choice?.gateway ? profile.gateway : nil
        Card(style: .compact) {
            Lead(text: Text(lead))
            if let chosen {
                DiagnosisRow(
                    symbol: .check, title: Text(String(localized: "This profile uses the gateway “\(chosen)” now")),
                    detail: Text(String(localized: "Connect again to use it.")))
            } else if labels.isEmpty {
                DiagnosisRow(
                    symbol: .info, title: Text(String(localized: "The portal’s list couldn’t be read")),
                    detail: Text(String(localized: "Show Log has it. Enter the gateway’s name as the portal lists it in the profile.")),
                    link: (String(localized: "Enter it in PassTunnel"), { model.edit(profile) }))
            } else {
                DiagnosisRow(
                    symbol: .info,
                    title: Text(String(localized: "The portal lists \(labels.count) gateways")),
                    detail: Text(String(localized: "Choose the one your IT team told you to use, or the nearest one.")))
            }
            ExperimentalReportRow(profile: profile)
            HStack(spacing: Spacing.xs) {
                if let choice, !labels.isEmpty {
                    Menu {
                        ForEach(labels, id: \.self) { label in
                            Button {
                                model.chooseGateway(choice, label: label)
                            } label: {
                                if label == profile.gateway {
                                    Label(label, systemImage: "checkmark")
                                } else {
                                    Text(verbatim: label)
                                }
                            }
                        }
                    } label: {
                        Text(chosen == nil ? String(localized: "Choose Gateway") : String(localized: "Change Gateway"))
                    }
                    .menuIndicator(.visible)
                    .fixedSize()
                    .accessibilityIdentifier("profile.\(profile.id).failure.chooseGateway")
                }
                CopyDetailsButton(profile: profile)
            }
            .padding(.top, 2)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("profile.\(profile.id).failure")
    }

    /// Why the sign-in stopped: no gateway named, or one the portal does not list.
    private var lead: String {
        let named = choice?.gateway ?? ""
        let shown = named.count > 64 ? String(named.prefix(64)) + "…" : named
        return named.isEmpty
            ? String(localized: "The portal lists more than one gateway, and this profile doesn’t name one. Choose the gateway to connect to.")
            : String(localized: "The portal doesn’t list the gateway “\(shown)” this profile names. Choose one of its gateways.")
    }
}
