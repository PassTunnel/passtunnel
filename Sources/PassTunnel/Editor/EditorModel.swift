import AppKit
import Foundation
import PassTunnelCore
import PassTunnelShared

/// State of one editor sheet. Nothing is written to disk or the Keychain until `save()`.
@MainActor
final class EditorModel: ObservableObject {
    enum Field: Hashable {
        case name, config, host, port, trustedCert, sessionLimit, healthHost
        case password, confirmPassword, totpSecret, template, general
    }

    enum TemplateChoice: Hashable {
        case preset(OTPTemplatePreset)
        case custom
    }

    let isNew: Bool
    let store: ProfileStore
    /// Writes secrets encrypted when the profile's "Confirm it’s you" setting protects them.
    let vault: SecretVault
    /// Preview models (renderer) never read or write the store or the Keychain.
    let isPreview: Bool
    let palette: BadgePalette

    @Published var draft: Profile
    /// The stored profile when the sheet opened; Save applies only the differences to it.
    let original: Profile?
    @Published var attemptedSave = false
    @Published var saveErrors: [Field: String] = [:]

    // OpenVPN configuration
    @Published var configURL: URL?          // chosen, not yet copied
    @Published var configRemote = ""
    @Published var hasConfig = false
    @Published var configError: String?

    // Sign-in
    @Published var newPassword = ""
    @Published var confirmPassword = ""
    let passwordStored: Bool

    // One-time code
    @Published var totpInput = ""
    @Published var newTOTPSecret: Data?
    @Published var totpSourceLabel = ""     // "Acme · alice" from a scanned link
    @Published var totpInputError: String?
    @Published var scanMessage: String?
    private var clearingInput = false
    let storedTOTPSecret: Data?
    /// A TOTP secret is saved, encrypted: its code shows only after a confirmation.
    let storedTOTPProtected: Bool
    @Published var customTemplate: Bool

    // Forti fingerprint
    @Published var fetchingFingerprint = false
    @Published var fetchedFingerprint: String?
    @Published var fingerprintError: String?

    // Health check
    @Published var testingHealth = false
    @Published var healthResult: (ok: Bool, text: String)?

    /// True when a new profile was started without a type, so the type can still be picked.
    let allowsTypeChange: Bool

    init(profileID: String?, newType: VPNType?, store: ProfileStore = ProfileStore(), vault: SecretVault) {
        self.store = store
        self.vault = vault
        self.allowsTypeChange = profileID == nil && newType == nil
        self.isPreview = false
        self.palette = Preferences.load(paths: store.paths).badgePalette
        let initial: Profile
        if let id = profileID, let existing = try? store.get(id) {
            isNew = false
            initial = existing
            passwordStored = Secrets.has(id, .password)
            storedTOTPSecret = Secrets.get(id, .totp).flatMap { try? TOTP.decodeSecret($0) }
            storedTOTPProtected = Secrets.isProtected(id, .totp)
        } else {
            isNew = true
            initial = Self.blank(newType ?? .openvpn)
            passwordStored = false
            storedTOTPSecret = nil
            storedTOTPProtected = false
        }
        draft = initial
        original = isNew ? nil : initial
        customTemplate = !Self.isPreset(initial.otpTemplate)
        if isNew, let id = profileID { saveErrors[.general] = PTError.profileNotFound(id).localizedDescription }
        if !isNew { loadExistingConfig() }
        if let id = profileID, let pending = ImportActions.takePendingTOTP(for: id) {
            apply(pending)
        }
    }

    /// For `EditorPreviewRenderer`: a fixed state with no store or Keychain access.
    init(preview profile: Profile, isNew: Bool, passwordStored: Bool = false, storedTOTP: Data? = nil,
         storedTOTPProtected: Bool = false, configRemote: String = "", now: Date? = nil) {
        self.store = ProfileStore(paths: AppPaths(root: FileManager.default.temporaryDirectory
            .appendingPathComponent("PassTunnelPreview-\(UUID().uuidString)")))
        self.vault = SecretVault()
        self.storedTOTPProtected = storedTOTPProtected
        self.isPreview = true
        self.allowsTypeChange = false
        self.palette = .pastel
        self.isNew = isNew
        self.draft = profile
        self.original = isNew ? nil : profile
        self.passwordStored = passwordStored
        self.storedTOTPSecret = storedTOTP
        self.configRemote = configRemote
        self.hasConfig = !configRemote.isEmpty
        self.customTemplate = !Self.isPreset(profile.otpTemplate)
        self.previewNow = now
    }

    /// Fixed "now" for rendered previews (date formatting).
    private var previewNow: Date?

    func changeType(_ type: VPNType) {
        guard allowsTypeChange, type != draft.type else { return }
        draft.type = type
        draft.otpDelivery = type == .forti ? .separate : .combined
        if type == .forti && draft.passwordMode == .none { draft.passwordMode = .keychain }
        configURL = nil
        configError = nil
        configRemote = ""
    }

    static func blank(_ type: VPNType) -> Profile {
        var p = Profile(id: "new-profile", name: "", type: type)
        p.otpDelivery = type == .forti ? .separate : .combined
        return p
    }

    static func isPreset(_ template: String) -> Bool {
        OTPTemplatePreset(rawValue: template) != nil
    }

    var title: String {
        if isNew {
            switch draft.type {
            case .openvpn: return String(localized: "New OpenVPN Profile")
            case .forti: return String(localized: "New FortiGate Profile")
            }
        }
        return String(localized: "Edit “\(draft.name)”")
    }

    // MARK: derived

    var effectiveTOTPSecret: Data? { newTOTPSecret ?? storedTOTPSecret }

    /// Password modes offered for this VPN type ("none" means certificate only: OpenVPN only).
    var passwordModes: [PasswordMode] {
        draft.type == .openvpn ? PasswordMode.allCases : [.keychain, .ask]
    }

    var usesCredentials: Bool { draft.passwordMode != .none }

    /// The saved TOTP secret is encrypted: its code shows only after a confirmation (a secret entered in
    /// this sheet is the user's own input and always shown).
    var storedCodeNeedsConfirmation: Bool { newTOTPSecret == nil && storedTOTPProtected }

    /// "Confirm it’s you" is being turned on where it cannot work (no Secure Enclave).
    var protectionUnavailable: Bool {
        draft.requireAuth != .off && (original?.requireAuth ?? .off) == .off && !isPreview && !vault.isAvailable
    }

    /// The profile as it would be saved (used for `unattended`).
    var normalized: Profile { Self.normalize(draft) }

    static func normalize(_ profile: Profile) -> Profile {
        var p = profile
        p.name = p.name.trimmingCharacters(in: .whitespacesAndNewlines)
        p.username = p.username.trimmingCharacters(in: .whitespacesAndNewlines)
        p.badge = p.badge.trimmingCharacters(in: .whitespacesAndNewlines)
        p.host = p.host.trimmingCharacters(in: .whitespacesAndNewlines)
        p.healthHost = p.healthHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let cert = p.trustedCert.trimmingCharacters(in: .whitespacesAndNewlines)
        p.trustedCert = cert.isEmpty ? "" : (TLSFingerprint.normalize(cert) ?? cert)
        if p.type == .forti && p.passwordMode == .none { p.passwordMode = .keychain }
        if p.passwordMode == .none { p.otpMode = .none }
        if !p.unattended { p.autoReconnect = false }
        return p
    }

    var templateChoice: TemplateChoice {
        get { customTemplate ? .custom : (OTPTemplatePreset(rawValue: draft.otpTemplate).map(TemplateChoice.preset) ?? .custom) }
        set {
            switch newValue {
            case .preset(let preset):
                customTemplate = false
                draft.otpTemplate = preset.rawValue
            case .custom:
                customTemplate = true
            }
        }
    }

    /// Example of what is sent with password "secret" and code "123456", or nil if the template is invalid.
    var templateExample: String? {
        guard (try? OTPComposer.validate(template: draft.otpTemplate)) != nil else { return nil }
        return OTPComposer.compose(password: "secret", otp: "123456", delivery: .combined,
                                   template: draft.otpTemplate, type: draft.type).secret
    }

    // MARK: validation

    /// Inline errors. Format errors show while typing; "required" errors after the first Save attempt.
    var errors: [Field: String] {
        var e: [Field: String] = [:]
        let p = normalized

        if attemptedSave && p.name.isEmpty { e[.name] = PTError.emptyName.localizedDescription }

        switch p.type {
        case .openvpn:
            if let configError { e[.config] = configError }
            else if attemptedSave && !hasConfig && configURL == nil {
                e[.config] = String(localized: "Choose the OpenVPN configuration file (.ovpn).")
            }
        case .forti:
            if p.host.isEmpty {
                if attemptedSave { e[.host] = String(localized: "Enter the gateway address, e.g. vpn.example.com.") }
            } else if !FortiConfig.isValidHost(p.host) {
                e[.host] = String(localized: "Enter a host name or IP address without “https://” or a port.")
            }
            if !(1...65535).contains(p.port) { e[.port] = String(localized: "The port must be between 1 and 65535.") }
            if !p.trustedCert.isEmpty && !FortiConfig.isValidDigest(p.trustedCert) {
                e[.trustedCert] = String(localized: "A trusted certificate is a SHA-256 fingerprint: 64 hexadecimal characters (colons are allowed).")
            }
        }

        if p.sessionLimitMin < 0 { e[.sessionLimit] = String(localized: "The session limit cannot be negative.") }
        if !p.healthHost.isEmpty && HealthCheck.parse(p.healthHost) == nil {
            e[.healthHost] = String(localized: "Use an address (10.0.0.5) or host:port (intranet.example.com:443).")
        }

        if p.passwordMode == .keychain {
            if !newPassword.isEmpty && !confirmPassword.isEmpty && newPassword != confirmPassword {
                e[.confirmPassword] = String(localized: "The passwords do not match.")
            } else if attemptedSave && !newPassword.isEmpty && newPassword != confirmPassword {
                e[.confirmPassword] = String(localized: "Type the password again to confirm it.")
            }
            if attemptedSave && newPassword.isEmpty && !passwordStored {
                e[.password] = String(localized: "Enter the password to save it in the Keychain, or choose “Ask each time”.")
            }
        }

        if p.otpMode == .totp {
            if let totpInputError { e[.totpSecret] = totpInputError }
            else if attemptedSave && effectiveTOTPSecret == nil && !storedTOTPProtected {
                e[.totpSecret] = String(localized: "Scan the QR code or paste the secret to generate codes.")
            }
        }
        if p.otpMode != .none && p.otpDelivery == .combined {
            do { try OTPComposer.validate(template: p.otpTemplate) } catch {
                e[.template] = error.localizedDescription
            }
        }
        if protectionUnavailable && p.usesStoredSecrets { e[.general] = PTError.protectionUnavailable.localizedDescription }
        for (field, message) in saveErrors where e[field] == nil { e[field] = message }
        return e
    }

    func error(_ field: Field) -> String? { errors[field] }

    /// Order used to scroll to the first problem.
    static let fieldOrder: [Field] = [.name, .config, .host, .port, .trustedCert, .sessionLimit, .healthHost,
                                      .password, .confirmPassword, .totpSecret, .template, .general]

    var firstErrorField: Field? {
        let e = errors
        return Self.fieldOrder.first { e[$0] != nil }
    }

    // MARK: OpenVPN configuration

    /// "acme.ovpn · imported 3 Oct" for the stored configuration, or the chosen file's name.
    var configSummary: String? {
        if let url = configURL { return url.lastPathComponent }
        guard hasConfig else { return nil }
        let name = draft.configSourceName
        guard let date = draft.configImportedAt else {
            return name ?? String(localized: "Imported configuration")
        }
        let when = Self.shortDate(date, now: previewNow ?? Date())
        if let name { return String(localized: "\(name) · imported \(when)") }
        return String(localized: "Imported \(when)")
    }

    /// "3 Oct" this year, "3 Oct 2025" otherwise (locale-aware order).
    static func shortDate(_ date: Date, now: Date = Date()) -> String {
        let calendar = Calendar.current
        let sameYear = calendar.component(.year, from: date) == calendar.component(.year, from: now)
        let style = Date.FormatStyle.dateTime.day().month(.abbreviated)
        return sameYear ? date.formatted(style) : date.formatted(style.year())
    }

    /// The stored copy can be revealed once the profile exists.
    var canRevealConfig: Bool { hasConfig && !isNew }

    func revealConfig() {
        guard canRevealConfig, !isPreview else { return }
        NSWorkspace.shared.activateFileViewerSelecting([store.ovpnURL(draft.id)])
    }

    private func loadExistingConfig() {
        let url = store.ovpnURL(draft.id)
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { hasConfig = false; return }
        hasConfig = true
        configRemote = OVPNAnalyzer.analyze(text).remote
    }

    /// Checks a chosen .ovpn now (referenced files, forbidden directives) so problems show
    /// before Save. The file is copied on Save.
    func chooseConfig(_ url: URL) {
        saveErrors[.config] = nil
        do {
            let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
            if let size = attrs?[.size] as? NSNumber, size.intValue > 2 * 1024 * 1024 {
                throw PTError.fileTooLarge(url.lastPathComponent)
            }
            guard let data = try? Data(contentsOf: url),
                  let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
                throw PTError.invalidFile(url.lastPathComponent)
            }
            let prepared = try OVPNInliner.prepare(text, baseDir: url.deletingLastPathComponent())
            let analysis = OVPNAnalyzer.analyze(prepared)
            configURL = url
            configRemote = analysis.remote
            configError = nil
            if isNew {
                draft.passwordMode = analysis.passwordMode
                draft.otpDelivery = analysis.otpDelivery
                if draft.otpMode == .none { draft.otpMode = analysis.otpMode }
                if draft.name.trimmingCharacters(in: .whitespaces).isEmpty {
                    draft.name = url.deletingPathExtension().lastPathComponent
                }
            }
        } catch {
            configURL = nil
            configError = error.localizedDescription
        }
    }

    // MARK: one-time code

    /// Parses the secret field: an otpauth:// link (sets digits/period/algorithm too) or Base32/hex.
    func applyTOTPInput() {
        let text = totpInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if clearingInput && text.isEmpty {
            clearingInput = false
            return
        }
        clearingInput = false
        saveErrors[.totpSecret] = nil
        guard !text.isEmpty else {
            totpInputError = nil
            newTOTPSecret = nil
            totpSourceLabel = ""
            return
        }
        do {
            if text.lowercased().hasPrefix("otpauth") {
                apply(try OTPAuthURI(text))
            } else {
                newTOTPSecret = try TOTP.decodeSecret(text)
                totpSourceLabel = ""
                totpInputError = nil
            }
        } catch {
            newTOTPSecret = nil
            totpInputError = error.localizedDescription
        }
    }

    func apply(_ uri: OTPAuthURI) {
        newTOTPSecret = uri.secret
        draft.totp = uri.params
        draft.otpMode = .totp
        if !totpInput.isEmpty {
            clearingInput = true   // the field's change handler must not drop the scanned secret
            totpInput = ""
        }
        totpInputError = nil
        saveErrors[.totpSecret] = nil
        totpSourceLabel = [uri.issuer, uri.account].filter { !$0.isEmpty }.joined(separator: " · ")
        scanMessage = String(localized: "Code added. Compare it with your authenticator app, then Save.")
    }

    func scanImage(at url: URL) {
        scan { try QRDecoder.otpAuth(inFile: url) }
    }

    func scanImage(_ image: NSImage) {
        guard let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            fail(QRDecoder.Failure.unreadableImage)
            return
        }
        scan { try QRDecoder.otpAuth(in: cg) }
    }

    /// Clipboard: an image (screenshot of a QR code), an image file, or an otpauth link as text.
    func scanClipboard() {
        let pb = NSPasteboard.general
        if let urls = pb.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL],
           let url = urls.first {
            scanImage(at: url)
        } else if let image = NSImage(pasteboard: pb) {
            scanImage(image)
        } else if let text = pb.string(forType: .string), !text.isEmpty {
            totpInput = text.trimmingCharacters(in: .whitespacesAndNewlines)
            applyTOTPInput()
            if totpInputError == nil { scanMessage = String(localized: "Code added. Compare it with your authenticator app, then Save.") }
        } else {
            scanMessage = nil
            totpInputError = String(localized: "The clipboard does not contain an image. Copy a screenshot of the QR code first.")
        }
    }

    private func scan(_ body: () throws -> OTPAuthURI) {
        do { apply(try body()) } catch { fail(error) }
    }

    private func fail(_ error: Error) {
        scanMessage = nil
        totpInputError = error.localizedDescription
    }

    // MARK: Forti fingerprint

    func fetchFingerprint() {
        let host = draft.host.trimmingCharacters(in: .whitespacesAndNewlines)
        let port = draft.port
        fingerprintError = nil
        fetchingFingerprint = true
        Task {
            do {
                fetchedFingerprint = try await TLSFingerprint.fetch(host: host, port: port)
            } catch {
                fingerprintError = error.localizedDescription
            }
            fetchingFingerprint = false
        }
    }

    func acceptFetchedFingerprint() {
        if let fp = fetchedFingerprint { draft.trustedCert = fp }
        fetchedFingerprint = nil
    }

    // MARK: health

    func testHealth() {
        let host = draft.healthHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard HealthCheck.parse(host) != nil else { return }
        testingHealth = true
        healthResult = nil
        Task {
            let result = await Task.detached(priority: .userInitiated) { HealthCheck.check(host) }.value
            healthResult = result.ok
                ? (true, String(localized: "Reachable · \(result.ms) ms"))
                : (false, String(localized: "Not reachable"))
            testingHealth = false
        }
    }

    // MARK: save

    /// Validates without writing (before asking for a confirmation). False shows the errors.
    func validateForSave() -> Bool {
        attemptedSave = true
        saveErrors = [:]
        return errors.isEmpty && !isPreview
    }

    /// Validates, writes the profile and then the Keychain items. Returns the saved id, or nil
    /// (errors are shown inline).
    func save() -> String? {
        attemptedSave = true
        saveErrors = [:]
        guard errors.isEmpty, !isPreview else { return nil }
        var p = normalized
        do {
            if isNew {
                let created = try store.create(name: p.name, type: p.type)
                p.id = created.id
                p.order = created.order
                do {
                    if let url = configURL {
                        let imported = try store.setOVPN(p.id, from: url)
                        p.configSourceName = imported.configSourceName
                        p.configImportedAt = imported.configImportedAt
                    }
                    try store.save(p)
                    try writeSecrets(p)
                } catch {
                    try? store.delete(p.id)
                    throw error
                }
            } else {
                // Only what was changed in the sheet: the CLI, reordering or a connect may have changed
                // other fields while it was open.
                let base = Self.normalize(original ?? p)
                let edited = p
                p = try store.update(p.id) { current in
                    current = try ProfileMerge.merge(original: base, edited: edited, current: current)
                }
                if let url = configURL { try store.setOVPN(p.id, from: url) }
                try writeSecrets(p)
            }
        } catch {
            saveErrors[Self.field(for: error)] = error.localizedDescription
            return nil
        }
        return p.id
    }

    private func writeSecrets(_ p: Profile) throws {
        if p.passwordMode == .keychain {
            if !newPassword.isEmpty { try vault.store(p, .password, newPassword) }
        } else if passwordStored {
            Secrets.delete(p.id, .password)
        }
        if p.otpMode == .totp {
            if let secret = newTOTPSecret { try vault.store(p, .totp, TOTP.base32Encode(secret)) }
        } else if storedTOTPSecret != nil || storedTOTPProtected {
            Secrets.delete(p.id, .totp)
        }
    }

    static func field(for error: Error) -> Field {
        guard let e = error as? PTError else { return .general }
        switch e {
        case .emptyName, .invalidProfileID: return .name
        case .invalidTemplate: return .template
        case .ovpnNotAllowed, .ovpnReferencedFile, .fileTooLarge, .invalidFile: return .config
        case .invalidSecret, .invalidOTPAuthURI, .hotpNotSupported: return .totpSecret
        case .protectedSecretUnreadable(let kind): return kind == .password ? .password : .totpSecret
        case .invalidField(let name):
            switch name {
            case "port": return .port
            case "session_limit_min": return .sessionLimit
            case "totp.digits", "totp.period": return .totpSecret
            default: return .general
            }
        default: return .general
        }
    }
}
