import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// The review of an .ovpn before its profile is added, in the detail of the main window: what the file holds
/// and the lines PassTunnel skips on the left, what the profile still needs on the right, and Add Profile, off with
/// the reason next to it until nothing is missing. A file with a blocking line never gets here: `ImportActions`
/// refuses it with every such line.
struct ImportReviewView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var review: ImportReviewModel
    @FocusState private var focus: Field?
    @State private var codeDropTargeted = false

    enum Field: Hashable { case name, username, password }

    private var report: OVPNImportReport { review.report }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.m) {
                    header
                    // Two columns as designed (about 1 : 1.15) when the detail is wide enough, else one under the
                    // other.
                    ViewThatFits(in: .horizontal) {
                        HStack(alignment: .top, spacing: 14) {
                            foundColumn.frame(minWidth: 250, idealWidth: 300, maxWidth: 460, alignment: .top)
                            needsCard.frame(minWidth: 290, idealWidth: 345, maxWidth: 530, alignment: .top)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        VStack(alignment: .leading, spacing: Spacing.s) {
                            foundColumn
                            needsCard
                        }
                    }
                }
                .padding(.horizontal, Spacing.xl)
                .padding(.top, Spacing.s)
                .padding(.bottom, Spacing.m)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            footer
                .padding(.horizontal, Spacing.xl)
                .padding(.top, Spacing.xs)
                .padding(.bottom, Spacing.m)
        }
        .onAppear { if review.name.isEmpty { focus = .name } }
    }

    // MARK: header

    private var header: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(String(localized: "Review \(review.draft.fileName)"))
                .typography(.reviewTitle)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            Text(verbatim: Self.subtitle(review.draft.source))
                .typography(.body)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// "From Downloads · OpenVPN · name it below" (the folder's name as Finder shows it).
    static func subtitle(_ source: URL) -> String {
        let folder = FileManager.default.displayName(atPath: source.deletingLastPathComponent().path)
        return String(localized: "From \(folder) · OpenVPN · name it below")
    }

    // MARK: found in the file

    private var foundColumn: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Card(style: .compact) {
                SectionLabel(String(localized: "Found in the file"))
                FoundRow(title: String(localized: "Server"), found: !report.servers.isEmpty, detail: serverText)
                FoundRow(title: String(localized: "Certificates"), found: certificates != nil,
                         detail: Text(verbatim: certificates ?? String(localized: "None in the file")))
                FoundRow(title: String(localized: "Sign-in"), found: true, detail: Text(verbatim: signIn))
            }
            if !report.skipped.isEmpty { skippedCard }
        }
    }

    /// "vpn.example.com:1194 · UDP" with the address in SF Mono; "+1 more" with other `remote` lines.
    private var serverText: Text {
        guard let first = report.servers.first else { return Text(String(localized: "No server in the file")) }
        let endpoint = OVPNAnalyzer.Endpoint(host: first.host, port: first.port, tcp: first.tcp,
                                             others: report.servers.count - 1)
        // Protocol names stay untranslated.
        return Text(verbatim: endpoint.server).font(.system(size: 12, design: .monospaced))
            + Text(verbatim: " · \(first.tcp ? "TCP" : "UDP")")
    }

    private var certificates: String? { Self.certificatesText(report.certificates) }

    /// "CA, client certificate and key, inside the file": what identifies the server and this client, and where
    /// it came from. nil when the file has none of them.
    static func certificatesText(_ found: [OVPNImportReport.Certificate]) -> String? {
        var names: [String] = []
        var inside = false
        var embedded = false
        for c in found {
            let name: String
            switch c.name {
            case "ca": name = "CA"
            case "cert": name = String(localized: "client certificate")
            case "key": name = String(localized: "key")
            case "pkcs12": name = String(localized: "PKCS #12 bundle")
            case "tls-auth", "tls-crypt", "tls-crypt-v2": name = String(localized: "TLS key")
            case "secret": name = String(localized: "static key")
            case "peer-fingerprint": name = String(localized: "server fingerprint")
            default: continue
            }
            if !names.contains(name) { names.append(name) }
            if c.file == nil { inside = true } else { embedded = true }
        }
        guard !names.isEmpty else { return nil }
        let list = ListFormatter.localizedString(byJoining: names)
        let text: String
        switch (inside, embedded) {
        case (true, true): text = String(localized: "\(list), inside the file and from files next to it")
        case (false, true): text = String(localized: "\(list), from files next to it")
        default: text = String(localized: "\(list), inside the file")
        }
        return text.prefix(1).uppercased(with: .current) + text.dropFirst()
    }

    private var signIn: String {
        if report.passwordMode == .none { return String(localized: "Certificate only") }
        if review.codeRequired || review.codeSecret != nil {
            return String(localized: "User name and password, plus a one-time code")
        }
        return String(localized: "User name and password")
    }

    private var skippedCard: some View {
        Card(style: .compact) {
            Label {
                Text(String(localized: "\(report.skipped.count) lines will be skipped"))
            } icon: {
                Image(systemName: "exclamationmark.triangle").font(.system(size: 13, weight: .semibold))
            }
            .typography(.bodyEmphasized)
            .foregroundStyle(Palette.amber)
            .accessibilityAddTraits(.isHeader)
            VStack(alignment: .leading, spacing: 0) {
                ForEach(report.skipped, id: \.line) { s in
                    Text(verbatim: s.text)
                        .typography(.log)
                        .foregroundStyle(Palette.fg)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .help(s.reason.message)
                        .accessibilityLabel(Text(String(localized: "line \(s.line): \(s.text)")))
                        .accessibilityHint(Text(verbatim: s.reason.message))
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Palette.fill, in: RoundedRectangle(cornerRadius: Radius.field, style: .continuous))
            Text(verbatim: skipExplanation)
                .typography(.hint)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// Why leaving the lines out is safe: scripts and what serves them, then what the helper runs itself.
    private var skipExplanation: String {
        let reasons = Set(report.skipped.map(\.reason))
        var sentences: [String] = []
        if !reasons.isDisjoint(with: [.program, .scriptSecurity, .dns, .environment]) {
            sentences.append(String(localized: "PassTunnel never runs scripts from a profile. DNS comes from what the server sends instead."))
        }
        if !reasons.isDisjoint(with: [.process, .logging, .management]) {
            sentences.append(String(localized: "PassTunnel runs the connection, its log and its management interface itself."))
        }
        return sentences.joined(separator: " ")
    }

    // MARK: needs you

    private var needsCard: some View {
        Card(style: .compact) {
            HStack(alignment: .firstTextBaseline, spacing: Spacing.xs) {
                SectionLabel(String(localized: "Needs you"))
                Spacer(minLength: Spacing.xs)
                Text(verbatim: missingCount)
                    .typography(.hint)
                    .foregroundStyle(Palette.fg2)
            }
            ReviewRow(String(localized: "Name")) {
                TextField(String(localized: "Name"), text: $review.name, prompt: Text(String(localized: "Name")))
                    .focused($focus, equals: .name)
                    .editorField(focused: focus == .name)
                    .accessibilityIdentifier("import.name")
            }
            if review.signsIn {
                ReviewRow(String(localized: "User name")) {
                    TextField(String(localized: "User name"), text: $review.username,
                              prompt: Text(verbatim: "alice"))
                        .focused($focus, equals: .username)
                        .editorField(focused: focus == .username)
                        .accessibilityIdentifier("import.username")
                }
                ReviewRow(String(localized: "Password")) {
                    SecureField(String(localized: "Password"), text: $review.password)
                        .focused($focus, equals: .password)
                        .editorField(focused: focus == .password)
                        .accessibilityIdentifier("import.password")
                    Text(String(localized: "Saved in Keychain."))
                        .typography(.hint)
                        .foregroundStyle(Palette.fg3)
                }
                ReviewRow(String(localized: "Code secret")) { codeSecretField }
                    .overlay {
                        if codeDropTargeted {
                            RoundedRectangle(cornerRadius: Radius.field, style: .continuous)
                                .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 2, dash: [5, 4]))
                                .padding(-4)
                        }
                    }
                    .onDrop(of: [.fileURL, .image], isTargeted: $codeDropTargeted) { providers in
                        ImportActions.loadImages(from: providers) { item in
                            switch item {
                            case .file(let url): review.scanImage(at: url)
                            case .image(let image): review.scanImage(image)
                            }
                        }
                    }
            }
        }
    }

    /// "1 of 4 missing", "Nothing missing".
    private var missingCount: String {
        let missing = review.missing.count
        guard missing > 0 else { return String(localized: "Nothing missing") }
        return String(localized: "\(missing) of \(review.needs.count) missing")
    }

    @ViewBuilder private var codeSecretField: some View {
        // The buttons follow the field, or go under it when the column is narrow.
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 6) {
                codeSecretBox
                codeSecretButtons
            }
            VStack(alignment: .leading, spacing: 6) {
                codeSecretBox
                HStack(spacing: 6) { codeSecretButtons }
            }
        }
        codeSecretNotes
    }

    @ViewBuilder private var codeSecretButtons: some View {
        Button(String(localized: "Paste")) { review.pasteSecret() }
            .buttonStyle(.secondaryCapsule(.compact))
            .help(String(localized: "Paste the secret, an otpauth:// link or a screenshot of the QR code"))
            .accessibilityIdentifier("import.pasteSecret")
        Button { chooseImage() } label: {
            Image(systemName: "photo").font(.system(size: 13, weight: .medium))
        }
        .buttonStyle(.secondaryCapsule(.compact))
        .help(String(localized: "Choose image…"))
        .accessibilityLabel(String(localized: "Choose image…"))
        .accessibilityIdentifier("import.chooseImage")
    }

    /// Under the field: an error, the secret's summary, or what is missing.
    @ViewBuilder private var codeSecretNotes: some View {
        if let error = review.codeError {
            EditorInlineError(message: error)
        } else if review.codeSecret != nil {
            Text(verbatim: [String(localized: "Secret added · \(review.totp.digits) digits · \(review.totp.period) s"),
                            review.codeSource].filter { !$0.isEmpty }.joined(separator: " · "))
                .typography(.hint)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
            Text(String(localized: "It should match the code in your authenticator app. The secret is saved in the Keychain when you add the profile."))
                .typography(.hint)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
        } else if review.codeRequired {
            Text(String(localized: "Missing. Paste the secret or choose an image of the QR code."))
                .typography(.hint)
                .foregroundStyle(Palette.amber)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Text(String(localized: "Optional. Add it when your VPN asks for a one-time code with the password."))
                .typography(.hint)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// Looks like a field: "Not added" (a dashed amber edge while the server asks for a code), or the secret's
    /// summary with its live code and a button to remove it.
    @ViewBuilder private var codeSecretBox: some View {
        let shape = RoundedRectangle(cornerRadius: Radius.field, style: .continuous)
        let missing = review.codeSecret == nil && review.codeRequired
        HStack(spacing: Spacing.xs) {
            if let secret = review.codeSecret {
                EditorLiveCode(secret: secret, params: review.totp, now: review.previewNow)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button { review.removeSecret() } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(Palette.fg3)
                }
                .buttonStyle(.plain)
                .help(String(localized: "Remove"))
                .accessibilityLabel(String(localized: "Remove the code secret"))
            } else {
                Text(String(localized: "Not added"))
                    .typography(.body)
                    .foregroundStyle(Palette.fg3)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .frame(minHeight: 30)
        .background(Color(nsColor: .textBackgroundColor), in: shape)
        .overlay {
            if missing {
                shape.strokeBorder(Palette.amberRing, style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
            } else {
                shape.strokeBorder(Palette.line, lineWidth: Elevation.hairline)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(String(localized: "Code secret"))
    }

    private func chooseImage() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Choose QR Code Image")
        panel.message = String(localized: "Choose a screenshot or photo of the QR code.")
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        review.scanImage(at: url)
    }

    // MARK: footer

    private var footer: some View {
        HStack(spacing: 10) {
            if let error = review.addError {
                EditorInlineError(message: error)
            } else if let reason = review.blockedReason {
                Text(verbatim: reason)
                    .typography(.hint)
                    .foregroundStyle(Palette.fg2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: Spacing.s)
            Button(String(localized: "Cancel")) { model.importReview = nil }
                .buttonStyle(.secondaryCapsule)
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("import.cancel")
            Button(String(localized: "Add Profile")) { add() }
                .buttonStyle(.primaryCapsule)
                .keyboardShortcut(.defaultAction)
                .disabled(!review.canAdd)
                .accessibilityHint(Text(verbatim: review.blockedReason ?? ""))
                .accessibilityIdentifier("import.add")
        }
    }

    private func add() {
        guard let id = review.add() else { return }
        model.importReview = nil
        ImportActions.imported(id)
    }
}

/// A line of "Found in the file": a green check (or an amber warning when it is missing), the title, and what was
/// found under it.
private struct FoundRow: View {
    let title: String
    let found: Bool
    let detail: Text

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.xs) {
            Image(systemName: found ? "checkmark" : "exclamationmark.triangle")
                .font(.system(size: 12, weight: .bold))
                .foregroundStyle(found ? Palette.green : Palette.amber)
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: title).typography(.body).foregroundStyle(Palette.fg)
                detail
                    .typography(.hint)
                    .foregroundStyle(Palette.fg2)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// A row of "Needs you": the label in `fg2` in a narrow column, the control (and its notes) after it.
private struct ReviewRow<Content: View>: View {
    let label: String
    @ViewBuilder var content: Content

    init(_ label: String, @ViewBuilder content: () -> Content) {
        self.label = label
        self.content = content()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.s) {
            Text(verbatim: label)
                .typography(.body)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
                .frame(width: 104, alignment: .leading)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Spacing.xxs) { content }
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
