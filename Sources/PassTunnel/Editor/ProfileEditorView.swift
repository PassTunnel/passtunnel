import AppKit
import PassTunnelCore
import PassTunnelKit
import PassTunnelVPNConfig
import SwiftUI
import UniformTypeIdentifiers

/// Profile editor sheet. `profileID == nil` creates a new profile of `newType`.
/// Nothing is written until Save; Cancel discards everything.
///
/// Four hairline cards (sign-in, one-time code, code format, switches) with labels in a right-aligned column; the
/// rest of the profile's settings are under "Advanced". Shared by every window that edits profiles.
struct ProfileEditorView: View {
    /// Posted after a successful save; userInfo ["id": String, "profileID": String].
    static let didSave = Notification.Name("PassTunnelProfileSaved")

    typealias Field = EditorModel.Field

    @StateObject private var model: EditorModel
    private let onClose: () -> Void
    @State private var dropTargeted = false
    @State private var showAdvanced = false
    @State private var pendingDelete: Profile?
    @State private var scrollTarget: String?
    /// The cards are taller than the space for them: a hairline then separates them from the footer.
    @State private var contentHeight: CGFloat = 0
    @State private var viewportHeight: CGFloat = 0
    @FocusState private var focus: Field?

    init(profileID: String?, newType: VPNType?, onClose: @escaping () -> Void) {
        _model = StateObject(
            wrappedValue: EditorModel(
                profileID: profileID, newType: newType,
                vault: AppModel.shared?.vault ?? SecretVault()))
        self.onClose = onClose
    }

    /// Used by `EditorPreviewRenderer`.
    init(model: EditorModel, showAdvanced: Bool = false, onClose: @escaping () -> Void = {}) {
        _model = StateObject(wrappedValue: model)
        _showAdvanced = State(initialValue: showAdvanced)
        self.onClose = onClose
    }

    private var p: Profile { model.draft }

    var body: some View {
        VStack(spacing: 0) {
            Text(verbatim: model.title)
                .typography(.sheetTitle)
                .foregroundStyle(Palette.fg)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 26)
                .padding(.top, 22)
                .padding(.bottom, Spacing.s)
                .accessibilityAddTraits(.isHeader)
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: Spacing.s) {
                        signInCard
                        codeCard
                        if model.usesCredentials && p.otpMode != .none { formatCard }
                        switchCard
                        advanced
                    }
                    .padding(.horizontal, 26)
                    .padding(.vertical, 2)
                    .background(GeometryReader { Color.clear.preference(key: ContentHeight.self, value: $0.size.height) })
                }
                .background(GeometryReader { Color.clear.preference(key: ViewportHeight.self, value: $0.size.height) })
                .onPreferenceChange(ContentHeight.self) { contentHeight = $0 }
                .onPreferenceChange(ViewportHeight.self) { viewportHeight = $0 }
                .onChange(of: scrollTarget) { target in
                    guard let target else { return }
                    withAnimation { proxy.scrollTo(target, anchor: .center) }
                    scrollTarget = nil
                }
            }
            footer
                .overlay(alignment: .top) {
                    if contentHeight > viewportHeight + 1 {
                        Rectangle().fill(Palette.line).frame(height: Elevation.hairline)
                    }
                }
        }
        .frame(minWidth: 620, idealWidth: 660, minHeight: 560, idealHeight: 700)
        .onAppear { if model.isNew { focus = .name } }
        .alert(Text("Trust this certificate?"), isPresented: fingerprintAlertShown) {
            Button("Trust Certificate") { model.acceptFetchedFingerprint() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "The gateway \(p.host) presented a certificate with this SHA-256 fingerprint:\n\n\(TLSFingerprint.display(model.fetchedFingerprint ?? ""))\n\nTrust it only if it matches the fingerprint your administrator gave you."
            )
        }
        .profileDeleteConfirmation($pendingDelete) { profile in
            onClose()
            AppModel.shared?.delete(profile)
        }
    }

    // MARK: footer

    private var footer: some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            EditorInlineError(message: model.error(.general))
            HStack(spacing: Spacing.xs) {
                if let original = model.original {
                    Button("Delete Profile…") { pendingDelete = original }
                        .buttonStyle(EditorDestructiveButtonStyle())
                        .accessibilityIdentifier("editor.delete")
                }
                Spacer(minLength: Spacing.s)
                Button("Cancel", role: .cancel) { onClose() }
                    .buttonStyle(.secondaryCapsule(.compact))
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("editor.cancel")
                Button(model.isNew ? LocalizedStringKey("Add Profile") : LocalizedStringKey("Save")) { save() }
                    .buttonStyle(.primaryCapsule(.compact))
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("editor.save")
            }
        }
        .padding(.horizontal, 26)
        .padding(.top, Spacing.s)
        .padding(.bottom, 20)
    }

    /// For a saved profile, the stored secrets are brought in line with "Confirm with Touch ID" first
    /// (`SecretVault.applyProtection`): turning it on encrypts them; lowering it decrypts them, which
    /// asks for Touch ID or the Mac password (otherwise the protection would be one click away).
    private func save() {
        guard model.validateForSave() else { return showFirstError() }
        guard !model.isNew, let original = model.original else { return finishSave() }
        let edited = model.normalized
        Task {
            do {
                try await model.vault.applyProtection(from: original, to: edited)
                finishSave()
            } catch {
                if (error as? PTError) != .userConfirmationCancelled {
                    model.saveErrors[EditorModel.field(for: error)] = error.localizedDescription
                    showFirstError()
                }
            }
        }
    }

    /// Scrolls to the first problem (opening Advanced when it is there) and focuses its field.
    private func showFirstError() {
        guard let field = model.firstErrorField else { return }
        let advanced = model.isAdvanced(field)
        let anchor = field == .totpSecret && advanced ? Self.secretFieldAnchor : Self.anchor(field)
        if advanced && !showAdvanced {
            showAdvanced = true
            DispatchQueue.main.async { scrollTarget = anchor }  // once the rows exist
        } else {
            scrollTarget = anchor
        }
        if field != .general && field != .config && (field != .totpSecret || advanced) { focus = field }
    }

    private func finishSave() {
        if let id = model.save() {
            let info: [String: Any] = ["id": id, "profileID": id]
            NotificationCenter.default.post(name: Self.didSave, object: nil, userInfo: info)
            NotificationCenter.default.post(name: ImportActions.didImport, object: nil, userInfo: info)
            onClose()
        } else {
            showFirstError()
        }
    }

    /// Scroll anchors: one per field, and the secret field under Advanced (its errors show there).
    private static func anchor(_ field: Field) -> String { "field.\(field)" }
    private static let secretFieldAnchor = "advanced.secret"

    // MARK: card 1: sign-in

    private var signInCard: some View {
        EditorCard {
            EditorRow(Text("Name")) {
                TextField("Name", text: $model.draft.name, prompt: Text(verbatim: "Acme VPN"))
                    .focused($focus, equals: .name)
                    .editorField(focused: focus == .name)
                EditorInlineError(message: model.error(.name))
            }
            .id(Self.anchor(.name))

            switch p.type {
            case .openvpn: configurationRow
            case .forti: fortiRows
            case .anyconnect: EmptyView()  // not edited by this version (shown as unsupported)
            }

            if model.usesCredentials {
                EditorRow(Text("User name")) {
                    TextField("User name", text: $model.draft.username, prompt: Text("Ask each time"))
                        .focused($focus, equals: .username)
                        .editorField(focused: focus == .username)
                    EditorInlineError(message: model.error(.username))
                    if p.username.trimmingCharacters(in: .whitespaces).isEmpty {
                        EditorHint("Leave empty to be asked each time you connect.")
                    }
                }
                .id(Self.anchor(.username))
            }

            EditorRow(Text("Password")) { passwordContent }
                .id(Self.anchor(.password))
        }
    }

    @ViewBuilder private var configurationRow: some View {
        EditorRow(Text("Configuration")) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                VStack(alignment: .leading, spacing: 1) {
                    if let name = model.configFileName {
                        Text(verbatim: name)
                            .typography(.body)
                            .foregroundStyle(Palette.fg)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help(Text(verbatim: model.configSummary ?? name))
                        if !model.configServer.isEmpty {
                            Text(verbatim: model.configServer)
                                .typography(.hint)
                                .foregroundStyle(Palette.fg2)
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .textSelection(.enabled)
                        }
                    } else {
                        Text("No configuration chosen").typography(.body).foregroundStyle(Palette.fg2)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text("Configuration"))
                .accessibilityValue(
                    model.configFileName.map {
                        Text(
                            verbatim: [$0, model.configServer]
                                .filter { !$0.isEmpty }.joined(separator: ", "))
                    } ?? Text("No configuration chosen"))
                Button(model.hasConfig || model.configURL != nil ? LocalizedStringKey("Replace…") : LocalizedStringKey("Choose…")) {
                    chooseConfig()
                }
                .buttonStyle(.secondaryCapsule(.compact))
            }
            EditorInlineError(message: model.error(.config))
            if model.configURL != nil && !model.isNew {
                EditorHint("The new configuration replaces the current one when you save.")
            }
        }
        .id(Self.anchor(.config))
    }

    @ViewBuilder private var fortiRows: some View {
        EditorRow(Text("Gateway")) {
            TextField("Gateway", text: $model.draft.host, prompt: Text(verbatim: "vpn.example.com"))
                .focused($focus, equals: .host)
                .editorField(focused: focus == .host)
            EditorInlineError(message: model.error(.host))
        }
        .id(Self.anchor(.host))

        EditorRow(Text("Port")) {
            TextField("Port", value: $model.draft.port, format: .number.grouping(.never), prompt: Text(verbatim: "443"))
                .focused($focus, equals: .port)
                .editorField(focused: focus == .port)
                .frame(width: 90)
            EditorInlineError(message: model.error(.port))
        }
        .id(Self.anchor(.port))

        EditorRow(Text("Trusted certificate")) {
            TextField("Trusted certificate", text: $model.draft.trustedCert, prompt: Text("SHA-256 fingerprint (optional)"))
                .font(.system(.body, design: .monospaced))
                .focused($focus, equals: .trustedCert)
                .editorField(focused: focus == .trustedCert)
            HStack(spacing: Spacing.xs) {
                Button("Fetch Fingerprint") { model.fetchFingerprint() }
                    .buttonStyle(.secondaryCapsule(.compact))
                    .disabled(
                        model.fetchingFingerprint
                            || !FortiConfig.isValidHost(p.host.trimmingCharacters(in: .whitespaces)))
                if model.fetchingFingerprint {
                    ProgressView().controlSize(.small)
                    Text("Connecting to the gateway…").typography(.hint).foregroundStyle(Palette.fg2)
                }
            }
            .padding(.top, 2)
            EditorInlineError(message: model.error(.trustedCert) ?? model.fingerprintError)
            EditorHint("Needed when the gateway’s certificate is not signed by an authority your Mac trusts.")
        }
        .id(Self.anchor(.trustedCert))

        EditorRow(Text("DNS")) {
            Toggle("Use the VPN’s DNS servers", isOn: $model.draft.setDNS).toggleStyle(.checkbox)
        }
        EditorRow(Text("Routes")) {
            Toggle("Add the routes the gateway sends", isOn: $model.draft.setRoutes).toggleStyle(.checkbox)
        }
    }

    /// One secure field for a password kept in the Keychain (no confirm field); otherwise what happens instead.
    /// The mode itself is under Advanced.
    @ViewBuilder private var passwordContent: some View {
        switch p.passwordMode {
        case .keychain:
            SecureField(
                "Password", text: $model.newPassword,
                prompt: model.passwordStored ? Text("Saved in Keychain") : Text("Required")
            )
            .focused($focus, equals: .password)
            .editorField(focused: focus == .password)
            EditorInlineError(message: model.error(.password))
        case .ask:
            VStack(alignment: .leading, spacing: 1) {
                Text("Ask each time").typography(.body).foregroundStyle(Palette.fg)
                EditorHint("PassTunnel asks for the password each time you connect and never stores it.")
            }
            .accessibilityElement(children: .combine)
        case .none:
            VStack(alignment: .leading, spacing: 1) {
                Text("None — certificate only").typography(.body).foregroundStyle(Palette.fg)
                EditorHint("Certificate only: the configuration contains everything needed to sign in.")
            }
            .accessibilityElement(children: .combine)
        }
    }

    private func chooseConfig() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Choose OpenVPN Configuration")
        panel.message = String(
            localized: "Files the configuration refers to (certificates, keys) are embedded automatically when they are in the same folder.")
        panel.allowedContentTypes = ImportActions.ovpnTypes
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        model.chooseConfig(url)
    }

    // MARK: card 2: one-time code

    private var codeCard: some View {
        EditorCard(spacing: 6) {
            EditorRow(Text("One-time code")) { codeSummary }
            if model.usesCredentials {
                EditorRow(nil) {
                    // One row when the three fit (they do not in every language), else the scan on a row of its own.
                    ViewThatFits(in: .horizontal) {
                        HStack(spacing: Spacing.xs) {
                            scanScreenButton
                            imageButtons
                        }
                        VStack(alignment: .leading, spacing: Spacing.xs) {
                            scanScreenButton
                            HStack(spacing: Spacing.xs) { imageButtons }
                        }
                    }
                    if model.scanningScreen {
                        EditorHint("Choose the window or screen that shows the QR code.")
                    }
                    if !model.isAdvanced(.totpSecret) {
                        EditorInlineError(message: model.error(.totpSecret))
                    }
                    if let message = model.scanMessage, model.newTOTPSecret != nil, model.error(.totpSecret) == nil {
                        Label(message, systemImage: "checkmark.circle")
                            .typography(.hint)
                            .foregroundStyle(Palette.fg2)
                    } else if model.newTOTPSecret != nil, p.otpMode == .totp {
                        EditorHint("It should match the code in your authenticator app. The secret is saved in the Keychain when you save.")
                    }
                }
            }
        }
        .overlay {
            if dropTargeted {
                RoundedRectangle(cornerRadius: Radius.compactCard, style: .continuous)
                    .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 2, dash: [5, 4]))
            }
        }
        .onDrop(of: [.fileURL, .image], isTargeted: model.usesCredentials ? $dropTargeted : .constant(false)) { providers in
            guard model.usesCredentials else { return false }
            return ImportActions.loadImages(from: providers) { result in
                switch result {
                case .file(let url): model.scanImage(at: url)
                case .image(let image): model.scanImage(image)
                }
            }
        }
        .id(Self.anchor(.totpSecret))
    }

    /// "Scan QR on screen", hidden on macOS 13: the system's content picker came with macOS 14 (decision D-20).
    @ViewBuilder private var scanScreenButton: some View {
        if #available(macOS 14, *) {
            Button("Scan QR on screen") { model.scanScreen() }
                .buttonStyle(.secondaryCapsule(.compact))
                .disabled(model.scanningScreen)
                .accessibilityIdentifier("editor.scanScreen")
        }
    }

    @ViewBuilder private var imageButtons: some View {
        Button("Choose image…") { chooseQRImage() }
            .buttonStyle(.secondaryCapsule(.compact))
        Button("Paste secret") { model.pasteSecret() }
            .buttonStyle(.secondaryCapsule(.compact))
    }

    /// The secret's summary and live code, or what the profile does instead (asks, none, empty).
    @ViewBuilder private var codeSummary: some View {
        if !model.usesCredentials {
            EditorHint("Certificate-only profiles do not use a one-time code.")
        } else if p.otpMode == .totp && (model.effectiveTOTPSecret != nil || model.storedCodeNeedsConfirmation) {
            HStack(alignment: .center, spacing: 10) {
                Image(systemName: "checkmark.circle")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Palette.green)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text(verbatim: model.secretSummary).typography(.body).foregroundStyle(Palette.fg)
                    if !model.totpSourceLabel.isEmpty {
                        Text(verbatim: model.totpSourceLabel).typography(.hint).foregroundStyle(Palette.fg2)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text("One-time code"))
                .accessibilityValue(
                    Text(
                        verbatim: [model.secretSummary, model.totpSourceLabel]
                            .filter { !$0.isEmpty }.joined(separator: ", ")))
                if let secret = model.effectiveTOTPSecret {
                    EditorLiveCode(secret: secret, params: p.totp, now: model.previewNow)
                } else if let original = model.original {
                    EditorLockedCode(profile: original, params: p.totp, vault: model.vault, now: model.previewNow) { error in
                        model.saveErrors[.totpSecret] = error
                    }
                }
            }
        } else {
            VStack(alignment: .leading, spacing: 1) {
                switch p.otpMode {
                case .totp:
                    Text("Scan the QR code your VPN provider gave you").typography(.body).foregroundStyle(Palette.fg)
                    if #available(macOS 14, *) {
                        EditorHint("Scan it on screen, drop a screenshot here, choose the image, or paste the secret.")
                    } else {
                        EditorHint("Drop a screenshot here, choose the image, or paste the secret.")
                    }
                case .ask:
                    Text("Ask each time").typography(.body).foregroundStyle(Palette.fg)
                    EditorHint("PassTunnel asks for the code each time you connect.")
                case .none:
                    Text("None").typography(.body).foregroundStyle(Palette.fg)
                    EditorHint("Let PassTunnel generate the code, so you never type it again.")
                }
            }
            .accessibilityElement(children: .combine)
        }
    }

    private func chooseQRImage() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Choose QR Code Image")
        panel.message = String(localized: "Choose a screenshot or photo of the QR code.")
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        model.scanImage(at: url)
    }

    // MARK: card 3: code format

    private var formatCard: some View {
        EditorCard(spacing: 6) {
            EditorRow(Text("Code format")) {
                Picker("Code format", selection: formatBinding) {
                    Text("Append").tag(EditorModel.FormatChoice.preset(.append))
                    Text("Prepend").tag(EditorModel.FormatChoice.preset(.prepend))
                    Text(verbatim: "password:code").tag(EditorModel.FormatChoice.preset(.colon))
                    Text(verbatim: "password,code").tag(EditorModel.FormatChoice.preset(.comma))
                    Text("Custom template").tag(EditorModel.FormatChoice.custom)
                    Divider()
                    Text("Sent separately").tag(EditorModel.FormatChoice.separate)
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                if p.otpDelivery == .separate {
                    EditorHint(verbatim: separateExplanation)
                }
            }
            if p.otpDelivery == .combined && model.customTemplate {
                EditorRow(Text("Template")) {
                    TextField("Template", text: $model.draft.otpTemplate, prompt: Text(verbatim: "{password}{otp}"))
                        .font(.system(.body, design: .monospaced))
                        .focused($focus, equals: .template)
                        .editorField(focused: focus == .template)
                    EditorInlineError(message: model.error(.template))
                    EditorHint("Use {password} and {otp}; any other text is sent as typed.")
                }
            }
            if let parts = model.sentParts {
                EditorRow(Text("Server receives"), secondary: true) {
                    EditorServerPreview(
                        username: model.normalized.username, parts: parts.secret,
                        separateCode: parts.separateCode, digits: p.totp.digits,
                        code: previewCode, now: model.previewNow)
                }
            }
        }
        .id(Self.anchor(.template))
    }

    private var formatBinding: Binding<EditorModel.FormatChoice> {
        Binding(get: { model.formatChoice }, set: { model.formatChoice = $0 })
    }

    /// The live code for "Server receives": from the secret entered or saved in the sheet, or the saved encrypted
    /// one while it is unlocked; nil when the code is asked or locked.
    private func previewCode(at date: Date) -> String? {
        guard p.otpMode == .totp else { return nil }
        if let secret = model.effectiveTOTPSecret { return TOTP.code(secret: secret, params: p.totp, at: date) }
        guard let original = model.original, model.storedCodeNeedsConfirmation,
            model.vault.isUnlocked(original.id, .totp),
            let secret = model.vault.available(original.id, .totp).flatMap({ try? TOTP.decodeSecret($0) })
        else {
            return nil
        }
        return TOTP.code(secret: secret, params: p.totp, at: date)
    }

    private var separateExplanation: String {
        switch p.type {
        case .openvpn:
            return String(localized: "The code is sent as the answer to the server’s challenge prompt (static-challenge), not inside the password.")
        case .forti, .anyconnect:
            return String(localized: "The code is sent in the gateway’s own one-time code field, after the password.")
        }
    }

    // MARK: card 4: switches

    private var switchCard: some View {
        EditorCard(spacing: 0, insets: EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0)) {
            if model.normalized.usesStoredSecrets {
                EditorSwitchRow(
                    title: requireAuthTitle, isOn: $model.requireAuthOn, footnote: requireAuthFootnote,
                    identifier: "editor.requireAuth"
                )
                .disabled(p.requireAuth == .off && !model.isPreview && !model.vault.isAvailable)
                switchDivider
            }
            EditorSwitchRow(
                title: String(localized: "Connect at login"), isOn: $model.draft.connectAtLogin,
                footnote: connectAtLoginFootnote, identifier: "editor.connectAtLogin")
            switchDivider
            EditorSwitchRow(
                title: String(localized: "Reconnect automatically if the link drops"),
                isOn: Binding(
                    get: { p.autoReconnect && model.normalized.unattended },
                    set: { model.draft.autoReconnect = $0 }),
                footnote: model.normalized.unattended
                    ? nil
                    : String(
                        localized:
                            "Available only when PassTunnel can connect without asking you: a saved username, the password in the Keychain, and a generated code (or none)."
                    )
            )
            .disabled(!model.normalized.unattended)
        }
    }

    private var switchDivider: some View {
        Rectangle().fill(Palette.line).frame(height: Elevation.hairline).padding(.horizontal, 14)
    }

    /// Why "Connect at login" may not connect by itself: PassTunnel does not open at login, or connecting asks first
    /// (then a notification at login offers the connection instead).
    private var connectAtLoginFootnote: String? {
        guard p.connectAtLogin else { return nil }
        if !model.opensAtLogin {
            return String(localized: "PassTunnel itself does not open at login. Turn on “Open at login, in the menu bar” in Settings → General.")
        }
        let saved = model.normalized
        let asks = !saved.unattended || !SecretVault.protectedKinds(saved).isDisjoint(with: SecretVault.usedKinds(saved))
        return asks
            ? String(localized: "Connecting asks you first, so at login PassTunnel shows a notification you click to connect.")
            : nil
    }

    /// "Require Touch ID before connecting", or the Mac password on a Mac without Touch ID.
    private var requireAuthTitle: String {
        ConfirmationWording.hasTouchID
            ? String(localized: "Require Touch ID before connecting")
            : String(localized: "Require your Mac password before connecting")
    }

    /// What the switch protects, when that is not what its words say.
    private var requireAuthFootnote: String? {
        switch p.requireAuth {
        case .off where !model.isPreview && !model.vault.isAvailable:
            return String(localized: "This Mac has no Secure Enclave, so this protection is not available.")
        case .off:
            return nil
        case .connect where !model.codesAskFirst:
            return String(
                localized:
                    "Set to ask only before connecting: showing, copying or typing the code does not ask. Turn the switch off and on again to ask for the code too."
            )
        case .connect:
            return String(
                localized:
                    "The TOTP secret is encrypted with a key in this Mac’s Secure Enclave. PassTunnel asks for Touch ID or your Mac password before it connects or shows the code."
            )
        case .always:
            return String(
                localized:
                    "The password and the TOTP secret are encrypted. PassTunnel asks for Touch ID or your Mac password before it connects and before it shows, copies or types the code; codes stay hidden until you confirm."
            )
        }
    }

    // MARK: Advanced

    private var advanced: some View {
        DisclosureGroup(isExpanded: $showAdvanced) {
            VStack(alignment: .leading, spacing: Spacing.s) {
                advancedSection(String(localized: "Sign-in")) { advancedSignIn }
                advancedSection(String(localized: "Connection")) { advancedConnection }
                advancedSection(String(localized: "Menu bar")) { advancedMenuBar }
            }
            .padding(.top, Spacing.xs)
        } label: {
            Text("Advanced").typography(.bodyEmphasized).foregroundStyle(Palette.fg)
        }
        .accessibilityIdentifier("editor.advanced")
        .padding(.top, Spacing.xxs)
    }

    private func advancedSection<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel(title).padding(.leading, Spacing.xxs)
            EditorCard { content() }
        }
    }

    @ViewBuilder private var advancedSignIn: some View {
        EditorRow(Text("Type")) {
            if model.allowsTypeChange {
                Picker("Type", selection: Binding(get: { p.type }, set: { model.changeType($0) })) {
                    ForEach(VPNType.connectable, id: \.self) { Text(verbatim: Self.typeName($0)).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
            } else {
                Text(verbatim: Self.typeName(p.type))
                    .typography(.body)
                    .foregroundStyle(Palette.fg)
                    .accessibilityLabel(Text("Type"))
                    .accessibilityValue(Text(verbatim: Self.typeName(p.type)))
            }
        }

        EditorRow(Text("Password")) {
            Picker("Password", selection: $model.draft.passwordMode) {
                ForEach(model.passwordModes, id: \.self) { mode in
                    Text(Self.passwordModeName(mode)).tag(mode)
                }
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .fixedSize()
        }

        if model.usesCredentials {
            EditorRow(Text("One-time code")) {
                Picker("One-time code", selection: $model.draft.otpMode) {
                    Text("None").tag(OTPMode.none)
                    Text("Generate").tag(OTPMode.totp)
                    Text("Ask each time").tag(OTPMode.ask)
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
            }
        }

        if model.usesCredentials && p.otpMode == .totp {
            EditorRow(Text("Secret")) {
                TextField("Secret", text: $model.totpInput, prompt: Text("Paste the secret or an otpauth:// link"))
                    .focused($focus, equals: .totpSecret)
                    .editorField(focused: focus == .totpSecret)
                    .onSubmit { model.applyTOTPInput() }
                    .onChange(of: model.totpInput) { _ in model.applyTOTPInput() }
                if model.isAdvanced(.totpSecret) {
                    EditorInlineError(message: model.error(.totpSecret))
                }
            }
            .id(Self.secretFieldAnchor)

            EditorRow(Text("Digits")) {
                Picker("Digits", selection: $model.draft.totp.digits) {
                    ForEach(6...8, id: \.self) { Text(verbatim: "\($0)").tag($0) }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
            }
            EditorRow(Text("Period")) {
                Picker("Period", selection: $model.draft.totp.period) {
                    ForEach(periodOptions, id: \.self) { Text("\($0) seconds").tag($0) }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
            }
            EditorRow(Text("Algorithm")) {
                Picker("Algorithm", selection: $model.draft.totp.algorithm) {
                    Text(verbatim: "SHA-1").tag(TOTPAlgorithm.sha1)
                    Text(verbatim: "SHA-256").tag(TOTPAlgorithm.sha256)
                    Text(verbatim: "SHA-512").tag(TOTPAlgorithm.sha512)
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                EditorHint("A scanned QR code sets these automatically. Change them only if your provider says so.")
            }
        }
    }

    private var periodOptions: [Int] {
        Array(Set([15, 30, 60, p.totp.period])).sorted()
    }

    @ViewBuilder private var advancedConnection: some View {
        if p.type == .openvpn && model.canRevealConfig {
            EditorRow(Text("Configuration")) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text(verbatim: model.configSummary ?? "")
                        .typography(.body)
                        .foregroundStyle(Palette.fg)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Button("Reveal in Finder") { model.revealConfig() }
                        .buttonStyle(.secondaryCapsule(.compact))
                        .help(Text("Show the copy PassTunnel uses"))
                }
            }
        }

        EditorRow(Text("Session limit")) {
            HStack(spacing: 6) {
                TextField("Session limit", value: $model.draft.sessionLimitMin, format: .number.grouping(.never))
                    .multilineTextAlignment(.trailing)
                    .focused($focus, equals: .sessionLimit)
                    .editorField(focused: focus == .sessionLimit)
                    .frame(width: 80)
                Stepper("Session limit", value: $model.draft.sessionLimitMin, in: 0...10_080, step: 30)
                    .labelsHidden()
                Text("minutes").typography(.body).foregroundStyle(Palette.fg)
            }
            EditorInlineError(message: model.error(.sessionLimit))
            EditorHint("0 means no limit. With a limit, PassTunnel reminds you before the server ends the session.")
        }
        .id(Self.anchor(.sessionLimit))

        EditorRow(Text("Health check")) {
            HStack(spacing: Spacing.xs) {
                TextField("Health check", text: $model.draft.healthHost, prompt: Text("10.0.0.5 or host:port"))
                    .focused($focus, equals: .healthHost)
                    .editorField(focused: focus == .healthHost)
                Button("Test") { model.testHealth() }
                    .buttonStyle(.secondaryCapsule(.compact))
                    .disabled(model.testingHealth || HealthCheck.parse(p.healthHost) == nil)
            }
            if model.testingHealth {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Testing…").typography(.hint).foregroundStyle(Palette.fg2)
                }
            } else if let result = model.healthResult {
                Label(result.text, systemImage: result.ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .typography(.hint)
                    .foregroundStyle(result.ok ? Palette.green : Palette.amber)
            }
            EditorInlineError(message: model.error(.healthHost))
            EditorHint("An address inside the VPN. While connected, PassTunnel checks it every 30 seconds and tells you when it stops answering.")
        }
        .id(Self.anchor(.healthHost))
    }

    @ViewBuilder private var advancedMenuBar: some View {
        EditorRow(Text("Icon")) { EditorIconPicker(icon: $model.draft.icon) }

        EditorRow(Text("Badge")) {
            TextField("Badge", text: badgeBinding, prompt: Text(verbatim: firstLetter))
                .focused($focus, equals: .badge)
                .editorField(focused: focus == .badge)
                .frame(width: 80)
                .help(Text("One or two characters shown in the menu bar. Empty uses the first letter of the name."))
        }

        EditorRow(Text("Menu bar shows")) {
            Picker("Menu bar shows", selection: $model.draft.badgeStyle) {
                Text("Letter").tag(BadgeStyle.letter)
                Text("Icon").tag(BadgeStyle.icon)
                Text("Both").tag(BadgeStyle.both)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
        }

        EditorRow(Text("Preview")) {
            EditorMenuBarPreview(profile: previewProfile, palette: model.palette)
            if p.badgeStyle != .letter && p.icon.isEmpty {
                EditorHint("Choose an icon to show it in the menu bar.")
            }
        }

        EditorRow(nil) {
            Toggle("Always show in the menu bar", isOn: $model.draft.pinned).toggleStyle(.checkbox)
        }
    }

    private var badgeBinding: Binding<String> {
        Binding(get: { p.badge }, set: { model.draft.badge = String($0.prefix(2)) })
    }

    /// Uses the badge placeholder while the name is still empty.
    private var previewProfile: Profile {
        var preview = model.normalized
        if preview.badge.isEmpty && preview.name.isEmpty { preview.badge = firstLetter }
        return preview
    }

    private var firstLetter: String {
        let n = p.name.trimmingCharacters(in: .whitespaces)
        return n.first.map { String($0).uppercased() } ?? "A"
    }

    // MARK: alerts

    private var fingerprintAlertShown: Binding<Bool> {
        Binding(
            get: { model.fetchedFingerprint != nil },
            set: { if !$0 { model.fetchedFingerprint = nil } })
    }

    private struct ContentHeight: PreferenceKey {
        static let defaultValue: CGFloat = 0
        static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
    }

    private struct ViewportHeight: PreferenceKey {
        static let defaultValue: CGFloat = 0
        static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
    }

    // MARK: names

    static func typeName(_ type: VPNType) -> String {
        switch type {
        case .openvpn: return "OpenVPN"  // product names stay untranslated
        case .forti: return "FortiGate SSL VPN"
        case .anyconnect: return "Cisco AnyConnect"
        }
    }

    static func passwordModeName(_ mode: PasswordMode) -> LocalizedStringKey {
        switch mode {
        case .keychain: return "Save in Keychain"
        case .ask: return "Ask each time"
        case .none: return "None — certificate only"
        }
    }
}
