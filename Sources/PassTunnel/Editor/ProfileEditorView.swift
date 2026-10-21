import AppKit
import PassTunnelCore
import PassTunnelShared
import SwiftUI
import UniformTypeIdentifiers

/// Profile editor sheet. `profileID == nil` creates a new profile of `newType`.
/// Nothing is written until Save; Cancel discards everything.
struct ProfileEditorView: View {
    /// Posted after a successful save; userInfo ["id": String, "profileID": String].
    static let didSave = Notification.Name("PassTunnelProfileSaved")

    typealias Field = EditorModel.Field

    @StateObject private var model: EditorModel
    private let onClose: () -> Void
    @State private var dropTargeted = false
    @State private var showAdvanced = false
    @State private var scrollTarget: Field?
    @FocusState private var focus: Field?

    init(profileID: String?, newType: VPNType?, onClose: @escaping () -> Void) {
        _model = StateObject(wrappedValue: EditorModel(profileID: profileID, newType: newType,
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
            header
            Divider()
            ScrollViewReader { proxy in
                Form {
                    generalSection
                    connectionSection
                    signInSection
                    codeSection
                }
                .formStyle(.grouped)
                .onChange(of: scrollTarget) { target in
                    guard let target else { return }
                    withAnimation { proxy.scrollTo(target, anchor: .center) }
                    scrollTarget = nil
                }
            }
            Divider()
            footer
        }
        .frame(minWidth: 540, idealWidth: 580, minHeight: 520, idealHeight: 760)
        .onAppear { if model.isNew { focus = .name } }
        .alert(Text("Trust this certificate?"), isPresented: fingerprintAlertShown) {
            Button("Trust Certificate") { model.acceptFetchedFingerprint() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The gateway \(p.host) presented a certificate with this SHA-256 fingerprint:\n\n\(TLSFingerprint.display(model.fetchedFingerprint ?? ""))\n\nTrust it only if it matches the fingerprint your administrator gave you.")
        }
    }

    // MARK: header / footer

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: p.icon.isEmpty ? (p.type == .forti ? "network" : "lock.shield") : p.icon)
                .font(.system(size: 20))
                .foregroundStyle(Color.accentColor)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: model.title).font(.headline)
                Text(verbatim: Self.typeName(p.type)).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
    }

    private var footer: some View {
        HStack(alignment: .center, spacing: 12) {
            EditorInlineError(message: model.error(.general))
            Spacer()
            Button("Cancel", role: .cancel) { onClose() }
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("editor.cancel")
            Button(model.isNew ? LocalizedStringKey("Add Profile") : LocalizedStringKey("Save")) { save() }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("editor.save")
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
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

    private func showFirstError() {
        scrollTarget = model.firstErrorField
        if let f = model.firstErrorField, f != .general { focus = f }
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

    // MARK: General

    private var generalSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 4) {
                TextField("Name", text: $model.draft.name, prompt: Text(verbatim: "Acme VPN"))
                    .focused($focus, equals: .name)
                EditorInlineError(message: model.error(.name))
            }
            .id(Field.name)

            if model.allowsTypeChange {
                Picker("Type", selection: Binding(get: { p.type }, set: { model.changeType($0) })) {
                    ForEach(VPNType.allCases, id: \.self) { Text(verbatim: Self.typeName($0)).tag($0) }
                }
                .pickerStyle(.segmented)
            } else {
                LabeledContent("Type") { Text(verbatim: Self.typeName(p.type)) }
            }

            LabeledContent("Icon") { EditorIconPicker(icon: $model.draft.icon) }

            TextField("Badge", text: badgeBinding, prompt: Text(verbatim: firstLetter))
                .help(Text("One or two characters shown in the menu bar. Empty uses the first letter of the name."))

            Picker("Menu bar shows", selection: $model.draft.badgeStyle) {
                Text("Letter").tag(BadgeStyle.letter)
                Text("Icon").tag(BadgeStyle.icon)
                Text("Both").tag(BadgeStyle.both)
            }
            .pickerStyle(.segmented)

            LabeledContent("Preview") {
                VStack(alignment: .trailing, spacing: 4) {
                    EditorMenuBarPreview(profile: previewProfile, palette: model.palette)
                    if p.badgeStyle != .letter && p.icon.isEmpty {
                        EditorHint("Choose an icon to show it in the menu bar.")
                    }
                }
            }

            Toggle("Always show in the menu bar", isOn: $model.draft.pinned)
        } header: {
            Text("General")
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

    // MARK: Connection

    private var connectionSection: some View {
        Section {
            switch p.type {
            case .openvpn: openVPNRows
            case .forti: fortiRows
            }

            VStack(alignment: .leading, spacing: 4) {
                LabeledContent("Session limit") {
                    HStack(spacing: 6) {
                        TextField("Session limit", value: $model.draft.sessionLimitMin, format: .number.grouping(.never))
                            .labelsHidden()
                            .multilineTextAlignment(.trailing)
                            .frame(width: 64)
                        Stepper("Session limit", value: $model.draft.sessionLimitMin, in: 0...10_080, step: 30)
                            .labelsHidden()
                        Text("minutes")
                    }
                }
                EditorHint("0 means no limit. With a limit, PassTunnel reminds you before the server ends the session.")
                EditorInlineError(message: model.error(.sessionLimit))
            }
            .id(Field.sessionLimit)

            VStack(alignment: .leading, spacing: 4) {
                LabeledContent("Health check") {
                    HStack(spacing: 6) {
                        TextField("Health check", text: $model.draft.healthHost, prompt: Text("10.0.0.5 or host:port"))
                            .labelsHidden()
                            .focused($focus, equals: .healthHost)
                        Button("Test") { model.testHealth() }
                            .disabled(model.testingHealth || HealthCheck.parse(p.healthHost) == nil)
                    }
                }
                if model.testingHealth {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Testing…").font(.callout).foregroundStyle(.secondary)
                    }
                } else if let result = model.healthResult {
                    Label(result.text, systemImage: result.ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .font(.callout)
                        .foregroundStyle(result.ok ? .green : .orange)
                }
                EditorInlineError(message: model.error(.healthHost))
                EditorHint("An address inside the VPN. While connected, PassTunnel checks it every 30 seconds and tells you when it stops answering.")
            }
            .id(Field.healthHost)

            VStack(alignment: .leading, spacing: 4) {
                Toggle("Reconnect automatically", isOn: Binding(
                    get: { p.autoReconnect && model.normalized.unattended },
                    set: { model.draft.autoReconnect = $0 }))
                    .disabled(!model.normalized.unattended)
                if model.normalized.unattended {
                    EditorHint("Reconnects after an unexpected drop or when the health check keeps failing.")
                } else {
                    EditorHint("Available only when PassTunnel can connect without asking you: a saved username, the password in the Keychain, and a generated code (or none).")
                }
            }
        } header: {
            Text("Connection")
        }
    }

    @ViewBuilder private var openVPNRows: some View {
        VStack(alignment: .leading, spacing: 4) {
            LabeledContent("Configuration") {
                VStack(alignment: .trailing, spacing: 6) {
                    if let summary = model.configSummary {
                        VStack(alignment: .trailing, spacing: 1) {
                            Text(verbatim: summary)
                                .foregroundStyle(.primary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .help(Text(verbatim: summary))
                            if !model.configRemote.isEmpty {
                                Text("Server: \(model.configRemote)")
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                    .textSelection(.enabled)
                            }
                        }
                    }
                    HStack(spacing: 8) {
                        if model.canRevealConfig {
                            Button("Reveal in Finder") { model.revealConfig() }
                                .help(Text("Show the copy PassTunnel uses"))
                        }
                        Button(model.hasConfig || model.configURL != nil ? LocalizedStringKey("Replace…") : LocalizedStringKey("Choose…")) {
                            chooseConfig()
                        }
                    }
                }
            }
            EditorInlineError(message: model.error(.config))
            if model.configURL != nil && !model.isNew {
                EditorHint("The new configuration replaces the current one when you save.")
            }
        }
        .id(Field.config)
    }

    @ViewBuilder private var fortiRows: some View {
        VStack(alignment: .leading, spacing: 4) {
            TextField("Gateway", text: $model.draft.host, prompt: Text(verbatim: "vpn.example.com"))
                .focused($focus, equals: .host)
            EditorInlineError(message: model.error(.host))
        }
        .id(Field.host)

        VStack(alignment: .leading, spacing: 4) {
            TextField("Port", value: $model.draft.port, format: .number.grouping(.never), prompt: Text(verbatim: "443"))
                .focused($focus, equals: .port)
            EditorInlineError(message: model.error(.port))
        }
        .id(Field.port)

        VStack(alignment: .leading, spacing: 4) {
            LabeledContent("Trusted certificate") {
                TextField("Trusted certificate", text: $model.draft.trustedCert, prompt: Text("SHA-256 fingerprint (optional)"))
                    .labelsHidden()
                    .font(.system(.body, design: .monospaced))
                    .multilineTextAlignment(.trailing)
                    .focused($focus, equals: .trustedCert)
            }
            HStack(spacing: 8) {
                Button("Fetch Fingerprint") { model.fetchFingerprint() }
                    .disabled(model.fetchingFingerprint
                              || !FortiConfig.isValidHost(p.host.trimmingCharacters(in: .whitespaces)))
                if model.fetchingFingerprint {
                    ProgressView().controlSize(.small)
                    Text("Connecting to the gateway…").font(.callout).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            EditorInlineError(message: model.error(.trustedCert) ?? model.fingerprintError)
            EditorHint("Needed when the gateway’s certificate is not signed by an authority your Mac trusts.")
        }
        .id(Field.trustedCert)

        Toggle("Use the VPN’s DNS servers", isOn: $model.draft.setDNS)
        Toggle("Add the routes the gateway sends", isOn: $model.draft.setRoutes)
    }

    private func chooseConfig() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Choose OpenVPN Configuration")
        panel.message = String(localized: "Files the configuration refers to (certificates, keys) are embedded automatically when they are in the same folder.")
        panel.allowedContentTypes = ImportActions.ovpnTypes
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        model.chooseConfig(url)
    }

    // MARK: Sign-in

    private var signInSection: some View {
        Section {
            if p.passwordMode != .none { usernameRow }

            VStack(alignment: .leading, spacing: 4) {
                Picker("Password", selection: $model.draft.passwordMode) {
                    ForEach(model.passwordModes, id: \.self) { mode in
                        Text(Self.passwordModeName(mode)).tag(mode)
                    }
                }
                switch p.passwordMode {
                case .none:
                    EditorHint("Certificate only: the configuration contains everything needed to sign in.")
                case .ask:
                    EditorHint("PassTunnel asks for the password each time you connect and never stores it.")
                case .keychain:
                    passwordStatus
                }
            }

            if p.passwordMode == .keychain { passwordRows }
            if model.normalized.usesStoredSecrets { requireAuthRow }
        } header: {
            Text("Sign-in")
        }
    }

    private var usernameRow: some View {
        VStack(alignment: .leading, spacing: 4) {
            TextField("Username", text: $model.draft.username, prompt: Text("Ask each time"))
            if p.username.trimmingCharacters(in: .whitespaces).isEmpty {
                EditorHint("Leave empty to be asked each time you connect.")
            }
        }
    }

    /// One line under the mode picker: what is in the Keychain now.
    @ViewBuilder private var passwordStatus: some View {
        HStack {
            Spacer(minLength: 0)
            if model.passwordStored {
                EditorKeychainBadge()
            } else {
                Label("Not saved yet", systemImage: "key")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private var passwordRows: some View {
        VStack(alignment: .leading, spacing: 4) {
            SecureField("New password",
                        text: $model.newPassword,
                        prompt: model.passwordStored ? Text("Leave empty to keep the saved one") : Text("Required"))
                .focused($focus, equals: .password)
            EditorInlineError(message: model.error(.password))
        }
        .id(Field.password)
        if !model.newPassword.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                SecureField("Confirm password", text: $model.confirmPassword, prompt: Text("Type it again"))
                    .focused($focus, equals: .confirmPassword)
                EditorInlineError(message: model.error(.confirmPassword))
            }
            .id(Field.confirmPassword)
        }
    }

    /// Touch ID (or the Mac password) before the stored password or code is used.
    private var requireAuthRow: some View {
        VStack(alignment: .leading, spacing: 4) {
            Picker(ConfirmationWording.settingName, selection: $model.draft.requireAuth) {
                Text("Off").tag(AuthRequirement.off)
                Text("Before connecting").tag(AuthRequirement.connect)
                Text("Before connecting and showing codes").tag(AuthRequirement.always)
            }
            .accessibilityIdentifier("editor.requireAuth")
            .disabled(p.requireAuth == .off && !model.isPreview && !model.vault.isAvailable)
            switch p.requireAuth {
            case .off where !model.isPreview && !model.vault.isAvailable:
                EditorHint("This Mac has no Secure Enclave, so this protection is not available.")
            case .off:
                EditorHint("Anyone using this Mac while you are logged in can connect with one click.")
            case .connect where model.normalized.passwordMode != .keychain:
                EditorHint("The TOTP secret is encrypted with a key in this Mac’s Secure Enclave. PassTunnel asks for Touch ID or your Mac password before it connects or shows the code.")
            case .connect:
                EditorHint("The password is encrypted with a key in this Mac’s Secure Enclave. PassTunnel asks for Touch ID or your Mac password before it connects. Reconnecting after a drop does not ask again.")
            case .always:
                EditorHint("The password and the TOTP secret are encrypted. PassTunnel asks for Touch ID or your Mac password before it connects and before it shows, copies or types the code; codes stay hidden until you confirm.")
            }
        }
    }

    // MARK: One-time code

    private var codeSection: some View {
        Section {
            if p.passwordMode == .none {
                EditorHint("Certificate-only profiles do not use a one-time code.")
            } else {
                Picker("Code", selection: $model.draft.otpMode) {
                    Text("None").tag(OTPMode.none)
                    Text("Generate").tag(OTPMode.totp)
                    Text("Ask each time").tag(OTPMode.ask)
                }
                .pickerStyle(.segmented)

                switch p.otpMode {
                case .none:
                    EditorHint("No code is needed to sign in.")
                case .ask:
                    EditorHint("PassTunnel asks for the code each time you connect.")
                case .totp:
                    totpRows
                }

                if p.otpMode != .none { deliveryRows }
            }
        } header: {
            VStack(alignment: .leading, spacing: 2) {
                Text("One-time code")
                if p.passwordMode != .none && p.otpMode != .ask {
                    Text("Let PassTunnel generate the code, so you never type it again.")
                        .font(.callout).fontWeight(.regular).foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder private var totpRows: some View {
        Group {
            EditorQRDropZone(isTargeted: dropTargeted,
                             chooseImage: chooseQRImage,
                             pasteImage: { model.scanClipboard() })

            VStack(alignment: .leading, spacing: 4) {
                TextField("Secret", text: $model.totpInput, prompt: Text("Paste the secret or an otpauth:// link"))
                    .focused($focus, equals: .totpSecret)
                    .onSubmit { model.applyTOTPInput() }
                    .onChange(of: model.totpInput) { _ in model.applyTOTPInput() }
                EditorInlineError(message: model.error(.totpSecret))
                if let message = model.scanMessage, model.newTOTPSecret != nil, model.error(.totpSecret) == nil {
                    Label(message, systemImage: "checkmark.circle")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            .id(Field.totpSecret)

            if model.effectiveTOTPSecret != nil || model.storedCodeNeedsConfirmation {
                VStack(alignment: .leading, spacing: 4) {
                    LabeledContent {
                        if let secret = model.effectiveTOTPSecret {
                            EditorLiveCode(secret: secret, params: p.totp)
                        } else if let original = model.original {
                            EditorLockedCode(profile: original, params: p.totp, vault: model.vault) { error in
                                model.saveErrors[.totpSecret] = error
                            }
                        }
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Current code")
                            if !model.totpSourceLabel.isEmpty {
                                Text(verbatim: model.totpSourceLabel).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    if model.newTOTPSecret == nil {
                        EditorKeychainBadge()
                    } else {
                        EditorHint("It should match the code in your authenticator app. The secret is saved in the Keychain when you save.")
                    }
                }
            }

            DisclosureGroup("Advanced", isExpanded: $showAdvanced) {
                Picker("Digits", selection: $model.draft.totp.digits) {
                    ForEach(6...8, id: \.self) { Text(verbatim: "\($0)").tag($0) }
                }
                Picker("Period", selection: $model.draft.totp.period) {
                    ForEach(periodOptions, id: \.self) { Text("\($0) seconds").tag($0) }
                }
                Picker("Algorithm", selection: $model.draft.totp.algorithm) {
                    Text(verbatim: "SHA-1").tag(TOTPAlgorithm.sha1)
                    Text(verbatim: "SHA-256").tag(TOTPAlgorithm.sha256)
                    Text(verbatim: "SHA-512").tag(TOTPAlgorithm.sha512)
                }
                EditorHint("A scanned QR code sets these automatically. Change them only if your provider says so.")
            }
        }
        .onDrop(of: [.fileURL, .image], isTargeted: $dropTargeted) { providers in
            ImportActions.loadImages(from: providers) { result in
                switch result {
                case .file(let url): model.scanImage(at: url)
                case .image(let image): model.scanImage(image)
                }
            }
        }
    }

    private var periodOptions: [Int] {
        Array(Set([15, 30, 60, p.totp.period])).sorted()
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

    @ViewBuilder private var deliveryRows: some View {
        VStack(alignment: .leading, spacing: 4) {
            Picker("Send the code", selection: $model.draft.otpDelivery) {
                Text("With the password").tag(OTPDelivery.combined)
                Text("Separately").tag(OTPDelivery.separate)
            }
            .pickerStyle(.segmented)
            EditorHint(verbatim: deliveryExplanation)
        }

        if p.otpDelivery == .combined {
            VStack(alignment: .leading, spacing: 4) {
                Picker("Format", selection: templateChoiceBinding) {
                    Text("Append (password + code)").tag(EditorModel.TemplateChoice.preset(.append))
                    Text("Prepend (code + password)").tag(EditorModel.TemplateChoice.preset(.prepend))
                    Text("password:code").tag(EditorModel.TemplateChoice.preset(.colon))
                    Text("password,code").tag(EditorModel.TemplateChoice.preset(.comma))
                    Text("Custom…").tag(EditorModel.TemplateChoice.custom)
                }
                if model.customTemplate {
                    LabeledContent("Template") {
                        TextField("Template", text: $model.draft.otpTemplate, prompt: Text(verbatim: "{password}{otp}"))
                            .labelsHidden()
                            .font(.system(.body, design: .monospaced))
                            .multilineTextAlignment(.trailing)
                            .focused($focus, equals: .template)
                    }
                    EditorHint("Use {password} and {otp}; any other text is sent as typed.")
                }
                EditorInlineError(message: model.error(.template))
                if let example = model.templateExample {
                    LabeledContent("Example") {
                        Text(verbatim: example).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    }
                    EditorHint("With the password “secret” and the code “123456”.")
                }
            }
            .id(Field.template)
        }
    }

    private var templateChoiceBinding: Binding<EditorModel.TemplateChoice> {
        Binding(get: { model.templateChoice }, set: { model.templateChoice = $0 })
    }

    private var deliveryExplanation: String {
        switch (p.otpDelivery, p.type) {
        case (.combined, _):
            return String(localized: "The code is joined to the password and sent as one password, in the format below.")
        case (.separate, .openvpn):
            return String(localized: "The code is sent as the answer to the server’s challenge prompt (static-challenge), not inside the password.")
        case (.separate, .forti):
            return String(localized: "The code is sent in the gateway’s own one-time code field, after the password.")
        }
    }

    // MARK: alerts

    private var fingerprintAlertShown: Binding<Bool> {
        Binding(get: { model.fetchedFingerprint != nil },
                set: { if !$0 { model.fetchedFingerprint = nil } })
    }

    // MARK: names

    static func typeName(_ type: VPNType) -> String {
        switch type {
        case .openvpn: return "OpenVPN"   // product names stay untranslated
        case .forti: return "FortiGate SSL VPN"
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
