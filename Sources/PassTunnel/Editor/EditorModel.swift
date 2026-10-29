import AppKit
import Foundation
import PassTunnelCore
import PassTunnelKit
import PassTunnelVPNConfig

/// State of one editor sheet. Nothing is written to disk or the Keychain until `save()`.
@MainActor
final class EditorModel: ObservableObject {
    /// `host` is FortiGate's gateway and Cisco AnyConnect's server address (`serverText`).
    enum Field: Hashable {
        case name, config, host, port, trustedCert, authgroup, serverCert, sessionLimit, healthHost
        case username, password, totpSecret, template, badge, general
    }

    /// The "Code format" popup: a template preset, a custom template, or the code sent on its own.
    enum FormatChoice: Hashable {
        case preset(OTPTemplatePreset)
        case custom
        case separate
    }

    let isNew: Bool
    let store: ProfileStore
    /// Writes secrets encrypted when the profile's "Confirm with Touch ID" setting protects them.
    let vault: SecretVault
    /// Preview models (renderer) never read or write the store or the Keychain.
    let isPreview: Bool
    let palette: BadgePalette

    @Published var draft: Profile {
        // A fingerprint fetched, or being fetched, for another server than the one the profile names now is dropped.
        didSet { if fetch.profileChanged(draft) { fetchTask?.cancel() } }
    }
    /// The stored profile when the sheet opened; Save applies only the differences to it.
    let original: Profile?
    @Published var attemptedSave = false
    @Published var saveErrors: [Field: String] = [:]

    // OpenVPN configuration
    @Published var configURL: URL?  // chosen, not yet copied
    @Published var configServer = ""  // "vpn.example.com:1194 · UDP"
    @Published var hasConfig = false
    @Published var configError: String?

    // Sign-in
    @Published var newPassword = ""
    let passwordStored: Bool

    // One-time code
    @Published var totpInput = ""
    @Published var newTOTPSecret: Data?
    @Published var totpSourceLabel = ""  // "Acme · alice" from a scanned link
    /// The secret typed under Advanced is not usable.
    @Published var totpInputError: String?
    /// "Choose image…", "Paste secret" or a drop found no usable code.
    @Published var scanError: String?
    @Published var scanMessage: String?
    /// "Scan QR on screen" is waiting for the system's picker or reading what was picked.
    @Published var scanningScreen = false
    private var clearingInput = false
    let storedTOTPSecret: Data?
    /// A TOTP secret is saved, encrypted: its code shows only after a confirmation.
    let storedTOTPProtected: Bool
    @Published var customTemplate: Bool

    // Cisco AnyConnect: the server address as typed or pasted (`https://vpn.example.com[:port][/group]`), which
    // sets `host`, `port` and `usergroup` whenever it is one (`AnyConnectServer.parse`).
    @Published private(set) var serverText = ""

    // FortiGate's certificate fingerprint, Cisco AnyConnect's key pin ("Fetch Fingerprint")
    /// Bound to the server it reads (`FingerprintFetch`): a result is kept, shown and taken only for the server the
    /// profile names.
    @Published private(set) var fetch = FingerprintFetch()
    private var fetchTask: Task<Void, Never>?
    @Published var fingerprintError: String?

    var fetchingFingerprint: Bool { fetch.isFetching }
    /// The fingerprint read, for the confirmation, while the profile still names the server it was read from.
    var fetchedFingerprint: String? { fetch.value(for: draft) }

    // Health check
    @Published var testingHealth = false
    @Published var healthResult: (ok: Bool, text: String)?

    /// True when a new profile was started without a type, so the type can still be picked.
    let allowsTypeChange: Bool
    /// Why this Mac cannot connect a type (`AppModel.connectRefusal`): the type picker shows it disabled with the note.
    let typeRefusal: (VPNType) -> PTError?
    /// PassTunnel itself opens at login (its login item is on): without it, "Connect at login" has nothing to run it.
    let opensAtLogin: Bool

    init(
        profileID: String?, newType: VPNType?, store: ProfileStore = ProfileStore(), vault: SecretVault,
        typeRefusal: @escaping (VPNType) -> PTError? = { ConnectionManager.connectRefusal($0) }
    ) {
        self.store = store
        self.vault = vault
        self.typeRefusal = typeRefusal
        self.allowsTypeChange = profileID == nil && newType == nil
        self.isPreview = false
        self.palette = Preferences.load(paths: store.paths).badgePalette
        self.opensAtLogin = LoginItem.status == .enabled
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
        serverText = Self.serverText(initial)
        if isNew, let id = profileID { saveErrors[.general] = PTError.profileNotFound(id).localizedDescription }
        if !isNew { loadExistingConfig() }
        if let pending = ImportActions.takePendingTOTP(for: profileID) {
            apply(pending)
            // A new profile started from a scanned code (ImportActions.startProfile) is named after its issuer.
            if isNew && draft.name.isEmpty { draft.name = pending.issuer }
        }
    }

    /// For `EditorPreviewRenderer`: a fixed state with no store or Keychain access.
    init(
        preview profile: Profile, isNew: Bool, passwordStored: Bool = false, storedTOTP: Data? = nil,
        storedTOTPProtected: Bool = false, configServer: String = "", opensAtLogin: Bool = true, now: Date? = nil,
        typeRefusal: @escaping (VPNType) -> PTError? = { _ in nil }, allowsTypeChange: Bool = false
    ) {
        self.store = ProfileStore(
            paths: AppPaths(
                root: FileManager.default.temporaryDirectory
                    .appendingPathComponent("PassTunnelPreview-\(UUID().uuidString)")))
        self.vault = SecretVault()
        self.storedTOTPProtected = storedTOTPProtected
        self.isPreview = true
        self.allowsTypeChange = allowsTypeChange
        self.typeRefusal = typeRefusal
        self.opensAtLogin = opensAtLogin
        self.palette = .pastel
        self.isNew = isNew
        self.draft = profile
        self.original = isNew ? nil : profile
        self.passwordStored = passwordStored
        self.storedTOTPSecret = storedTOTP
        self.configServer = configServer
        self.hasConfig = !configServer.isEmpty
        self.customTemplate = !Self.isPreset(profile.otpTemplate)
        self.serverText = Self.serverText(profile)
        self.previewNow = now
    }

    /// Fixed "now" for rendered previews (date formatting, the live code).
    private(set) var previewNow: Date?

    func changeType(_ type: VPNType) {
        guard allowsTypeChange, type != draft.type, typeRefusal(type) == nil else { return }
        draft.type = type
        draft.otpDelivery = type.defaultOTPDelivery
        if type != .openvpn && draft.passwordMode == .none { draft.passwordMode = .keychain }
        configURL = nil
        configError = nil
        configServer = ""
        serverText = Self.serverText(draft)
    }

    /// The address a Cisco AnyConnect profile's server is shown as (`AnyConnectEditing.serverText`); "" for others.
    static func serverText(_ p: Profile) -> String {
        p.type == .anyconnect ? AnyConnectEditing.serverText(host: p.host, port: p.port, usergroup: p.usergroup) : ""
    }

    /// The Cisco AnyConnect server address typed or pasted: a valid one sets the host, port and user group at once;
    /// an empty one clears them. Anything else leaves them as they were and shows why (`errors`).
    func setServerText(_ text: String) {
        serverText = text
        AnyConnectEditing.applyServer(text, to: &draft)
        fingerprintError = nil
    }

    /// The server address can be used ("Fetch Fingerprint").
    var serverIsValid: Bool { AnyConnectEditing.serverProblem(serverText) == nil }
    static func blank(_ type: VPNType) -> Profile {
        var p = Profile(id: "new-profile", name: "", type: type)
        p.otpDelivery = type.defaultOTPDelivery
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
            case .anyconnect: return String(localized: "New Cisco AnyConnect Profile")
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

    /// "Confirm with Touch ID" is being turned on where it cannot work (no Secure Enclave).
    var protectionUnavailable: Bool {
        draft.requireAuth != .off && (original?.requireAuth ?? .off) == .off && !isPreview && !vault.isAvailable
    }

    /// The editor's one switch for "Confirm with Touch ID" (decision D-4): on asks before connecting and before
    /// showing codes (`always`). A profile set to `connect` (the CLI keeps all three levels) shows as on; turning
    /// the switch off and on again makes it `always`.
    var requireAuthOn: Bool {
        get { draft.requireAuth != .off }
        set { draft.requireAuth = newValue ? .always : .off }
    }

    /// Showing, copying or typing the code asks first: `always`, or `connect` without a saved password (the TOTP
    /// secret is then the one encrypted, see `SecretVault`).
    var codesAskFirst: Bool {
        let p = normalized
        return p.requireAuth == .always || (p.requireAuth == .connect && p.passwordMode != .keychain)
    }

    /// "Secret added · 6 digits · 30 s"
    var secretSummary: String {
        String(localized: "Secret added · \(draft.totp.digits) digits · \(draft.totp.period) s")
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
        if p.type == .anyconnect {
            p.serverCert = AnyConnectEditing.normalizedPin(p.serverCert)
            p.authgroup = AnyConnectEditing.normalizedGroup(p.authgroup)
        }
        if p.type != .openvpn && p.passwordMode == .none { p.passwordMode = .keychain }
        if p.passwordMode == .none { p.otpMode = .none }
        if !p.unattended { p.autoReconnect = false }
        return p
    }

    /// Picking a preset or a custom template sends the code with the password; "Sent separately" keeps the
    /// template for when the user switches back.
    var formatChoice: FormatChoice {
        get {
            if draft.otpDelivery == .separate { return .separate }
            if customTemplate { return .custom }
            return OTPTemplatePreset(rawValue: draft.otpTemplate).map(FormatChoice.preset) ?? .custom
        }
        set {
            switch newValue {
            case .preset(let preset):
                draft.otpDelivery = .combined
                customTemplate = false
                draft.otpTemplate = preset.rawValue
            case .custom:
                draft.otpDelivery = .combined
                customTemplate = true
            case .separate:
                draft.otpDelivery = .separate
            }
        }
    }

    /// What the server receives, in order, for the masked preview; nil while the template is invalid.
    var sentParts: (secret: [OTPComposer.Part], separateCode: Bool)? {
        if draft.otpDelivery == .combined, (try? OTPComposer.validate(template: draft.otpTemplate)) == nil { return nil }
        return OTPComposer.parts(delivery: draft.otpDelivery, template: draft.otpTemplate)
    }

    // MARK: validation

    /// Inline errors. Format errors show while typing; "required" errors after the first Save attempt.
    var errors: [Field: String] {
        var e: [Field: String] = [:]
        let p = normalized

        if attemptedSave && p.name.isEmpty { e[.name] = PTError.emptyName.localizedDescription }

        switch p.type {
        case .openvpn:
            if let configError {
                e[.config] = configError
            } else if attemptedSave && !hasConfig && configURL == nil {
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
        case .anyconnect:
            // Never the text itself: a password pasted into the wrong field must not show up again.
            if let problem = AnyConnectEditing.serverProblem(serverText), problem != .empty || attemptedSave {
                e[.host] = problem.message
            }
            if let message = AnyConnectEditing.groupProblem(p.authgroup) { e[.authgroup] = message }
            if let message = AnyConnectEditing.pinProblem(p.serverCert) { e[.serverCert] = message }
        }

        if p.sessionLimitMin < 0 { e[.sessionLimit] = String(localized: "The session limit cannot be negative.") }
        if !p.healthHost.isEmpty && HealthCheck.parse(p.healthHost) == nil {
            e[.healthHost] = String(localized: "Use an address (10.0.0.5) or host:port (intranet.example.com:443).")
        }

        if p.type == .anyconnect {
            if let message = AnyConnectEditing.usernameProblem(p.username) { e[.username] = message }
        } else if p.passwordMode != .none {
            do { try Profile.checkUsername(p.username, type: p.type) } catch { e[.username] = error.localizedDescription }
        }

        if p.passwordMode == .keychain && attemptedSave && newPassword.isEmpty && !passwordStored {
            e[.password] = String(localized: "Enter the password to save it in the Keychain, or choose “Ask each time” under Advanced.")
        }

        if p.otpMode == .totp {
            if let message = totpInputError ?? scanError {
                e[.totpSecret] = message
            } else if attemptedSave && effectiveTOTPSecret == nil && !storedTOTPProtected {
                e[.totpSecret] = String(localized: "Scan the QR code or paste the secret to generate codes.")
            }
        }
        if p.otpMode != .none && p.otpDelivery == .combined {
            do { try OTPComposer.validate(template: p.otpTemplate) } catch {
                e[.template] = error.localizedDescription
            }
            if e[.template] == nil, p.type == .anyconnect, !Profile.isValidAnyConnectTemplate(p.otpTemplate) {
                e[.template] = String(localized: "The template must be one line of at most 4,095 bytes.")
            }
        }
        if protectionUnavailable && p.usesStoredSecrets { e[.general] = PTError.protectionUnavailable.localizedDescription }
        for (field, message) in saveErrors where e[field] == nil { e[field] = message }
        return e
    }

    func error(_ field: Field) -> String? { errors[field] }

    /// Order used to scroll to the first problem: the cards from the top, then Advanced.
    static let fieldOrder: [Field] = [
        .name, .config, .host, .port, .trustedCert, .authgroup, .serverCert, .username, .password,
        .totpSecret, .template, .general, .sessionLimit, .healthHost
    ]

    var firstErrorField: Field? {
        let e = errors
        return Self.fieldOrder.first { e[$0] != nil }
    }

    /// The field is under Advanced (the secret only when the error is about the text typed there).
    func isAdvanced(_ field: Field) -> Bool {
        switch field {
        case .sessionLimit, .healthHost, .badge: return true
        case .totpSecret: return totpInputError != nil
        default: return false
        }
    }

    // MARK: OpenVPN configuration

    /// The configuration's file name: the chosen file, or the one the stored copy was imported from.
    var configFileName: String? {
        if let url = configURL { return url.lastPathComponent }
        guard hasConfig else { return nil }
        return draft.configSourceName ?? String(localized: "Imported configuration")
    }

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
        configServer = OVPNAnalyzer.endpointDescription(text)
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
                let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1)
            else {
                throw PTError.invalidFile(url.lastPathComponent)
            }
            let inlined = try OVPNInliner.prepare(text, baseDir: url.deletingLastPathComponent())
            // An inline <auth-user-pass> block is not stored with the config: its user name and
            // password go into the fields, and from there into the profile and the Keychain on Save.
            let stripped = OVPNInliner.strippingCredentials(inlined, blocks: [.authUserPass])
            let prepared = stripped.text
            let analysis = OVPNAnalyzer.analyze(prepared)
            configURL = url
            configServer = OVPNAnalyzer.endpointDescription(prepared)
            configError = nil
            if let user = stripped.username, draft.username.trimmingCharacters(in: .whitespaces).isEmpty {
                draft.username = user
            }
            if let password = stripped.password, newPassword.isEmpty {
                draft.passwordMode = .keychain
                newPassword = password
            }
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

    /// Parses the secret field under Advanced: an otpauth:// link (sets digits/period/algorithm too) or
    /// Base32/hex.
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
        scanError = nil
        scanMessage = nil
        do {
            if text.lowercased().hasPrefix("otpauth") {
                apply(try OTPAuthURI(text))
            } else {
                newTOTPSecret = try TOTP.decodeSecret(text)
                draft.otpMode = .totp
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
            clearingInput = true  // the field's change handler must not drop the scanned secret
            totpInput = ""
        }
        totpInputError = nil
        scanError = nil
        saveErrors[.totpSecret] = nil
        totpSourceLabel = [uri.issuer, uri.account].filter { !$0.isEmpty }.joined(separator: " · ")
        scanMessage = String(localized: "Code added. Compare it with your authenticator app, then Save.")
    }

    func scanImage(at url: URL) {
        take { try CodeSecretInput.fromImage(at: url) }
    }

    func scanImage(_ image: NSImage) {
        take { try CodeSecretInput.fromImage(image) }
    }

    /// "Scan QR on screen" (macOS 14 and later): the window or display the user picks (`ScreenQRScanner`). Cancelling
    /// changes nothing.
    func scanScreen() {
        guard #available(macOS 14, *), !isPreview, !scanningScreen else { return }
        scanningScreen = true
        Task {
            defer { scanningScreen = false }
            do {
                if let uri = try await ScreenQRScanner.shared.scan() { apply(uri) }
            } catch {
                fail(error)
            }
        }
    }

    /// "Paste secret": a secret or an otpauth link as text, an image (screenshot of a QR code) or an image file.
    func pasteSecret() {
        take { try CodeSecretInput.fromPasteboard() }
    }

    /// A bare secret (no digits, period or algorithm: the current ones stay).
    private func apply(_ secret: Data) {
        newTOTPSecret = secret
        draft.otpMode = .totp
        if !totpInput.isEmpty {
            clearingInput = true
            totpInput = ""
        }
        totpInputError = nil
        scanError = nil
        saveErrors[.totpSecret] = nil
        totpSourceLabel = ""
        scanMessage = String(localized: "Code added. Compare it with your authenticator app, then Save.")
    }

    /// A link or a secret from `read`; nil from it means the clipboard holds nothing usable.
    private func take(_ read: () throws -> CodeSecretInput?) {
        do {
            switch try read() {
            case .link(let uri)?: apply(uri)
            case .secret(let secret)?: apply(secret)
            case nil: fail(nil)
            }
        } catch {
            fail(error)
        }
    }

    /// nil: the clipboard holds nothing usable.
    private func fail(_ error: Error?) {
        scanMessage = nil
        saveErrors[.totpSecret] = nil
        scanError = error?.localizedDescription ?? CodeSecretInput.nothingToPaste
    }

    // MARK: fingerprint

    /// "Fetch Fingerprint", only when the user clicks it: the server's certificate from a TLS handshake that is then
    /// aborted (`TLSFingerprint`). FortiGate takes the certificate's SHA-256, Cisco AnyConnect its key's pin
    /// (`ServerKeyPin`). The result is shown to confirm before it goes into the field (`acceptFetchedFingerprint`).
    func fetchFingerprint() {
        guard !isPreview, !fetchingFingerprint else { return }
        let host = draft.host.trimmingCharacters(in: .whitespacesAndNewlines)
        let port = draft.port
        let anyConnect = draft.type == .anyconnect
        if anyConnect && !serverIsValid { return }
        fingerprintError = nil
        let destination = fetch.start(for: draft)
        fetchTask = Task {
            do {
                let value =
                    anyConnect
                    ? try await TLSFingerprint.fetchServerKeyPin(host: host, port: port)
                    : try await TLSFingerprint.fetch(host: host, port: port)
                // Kept only for the fetch under way, while the profile still names the server it read.
                fetch.finish(value, for: destination, current: draft)
            } catch {
                if fetch.pending == destination { fingerprintError = error.localizedDescription }
                fetch.fail(for: destination)
            }
        }
    }

    /// Where the fingerprint shown was read ("vpn.example.com:8443/engineering"): the server it was fetched from,
    /// which is the one the profile names (else nothing is shown).
    var fetchedServer: String { fetch.result?.destination.server ?? "" }

    /// "Trust": the fingerprint goes into the field only while the profile still names the server it was read from.
    func acceptFetchedFingerprint() {
        if let fp = fetch.value(for: draft) {
            if draft.type == .anyconnect { draft.serverCert = fp } else { draft.trustedCert = fp }
        }
        fetch.clearResult()
    }

    /// The confirmation was dismissed without trusting.
    func discardFetchedFingerprint() { fetch.clearResult() }

    // MARK: health

    func testHealth() {
        let host = draft.healthHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard HealthCheck.parse(host) != nil else { return }
        testingHealth = true
        healthResult = nil
        Task {
            let result = await Task.detached(priority: .userInitiated) { HealthCheck.check(host) }.value
            healthResult =
                result.ok
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
        case .usernameTooLong: return .username
        case .ovpnNotAllowed, .ovpnReferencedFile, .fileTooLarge, .invalidFile: return .config
        case .invalidSecret, .invalidOTPAuthURI, .hotpNotSupported: return .totpSecret
        case .protectedSecretUnreadable(let kind): return kind == .password ? .password : .totpSecret
        case .invalidField(let name):
            switch name {
            case "port": return .port
            case "host", "usergroup": return .host
            case "authgroup": return .authgroup
            case "server_cert": return .serverCert
            case "username": return .username
            case "otp_template": return .template
            case "health_host": return .healthHost
            case "session_limit_min": return .sessionLimit
            case "totp.digits", "totp.period": return .totpSecret
            default: return .general
            }
        default: return .general
        }
    }
}
