import AppKit
import PassTunnelCore
import PassTunnelKit

/// The import review of an .ovpn (`ImportReviewView`, in the main window): the draft read from the file and
/// what the user adds to it. Nothing is written until `add()` (`ProfileStore.commit`).
@MainActor
final class ImportReviewModel: ObservableObject {
    let draft: ImportDraft
    @Published var name: String
    @Published var username: String
    @Published var password: String
    @Published private(set) var codeSecret: Data?
    @Published private(set) var totp = TOTPParams()
    /// "Acme · alice", from a scanned or pasted link.
    @Published private(set) var codeSource = ""
    @Published private(set) var codeError: String?
    /// Why the profile could not be added (the store or the Keychain refused).
    @Published private(set) var addError: String?
    /// Pins the time of the live code, for renders.
    var previewNow: Date?

    init(draft: ImportDraft) {
        self.draft = draft
        name = draft.suggestedName
        username = draft.report.username ?? ""
        password = draft.report.password ?? ""
    }

    var report: OVPNImportReport { draft.report }
    /// The configuration signs in with a user name and password (`auth-user-pass`), so it can also send a code.
    var signsIn: Bool { report.passwordMode != .none }
    /// The server asks for a one-time code (`static-challenge`): the profile needs the code secret.
    var codeRequired: Bool { report.needs.contains(.codeSecret) }

    /// What the profile needs ("Needs you", 4 in the design: name, user name, password, code secret).
    var needs: [OVPNImportReport.Field] { draft.needs }
    var missing: [OVPNImportReport.Field] {
        draft.missing(name: name, username: username, password: password, codeSecret: codeSecret != nil)
    }
    var canAdd: Bool { missing.isEmpty }

    /// Why Add Profile is off, for the footer: the first thing still missing.
    var blockedReason: String? {
        switch missing.first {
        case nil: return nil
        case .name?: return String(localized: "Add a name to finish.")
        case .username?: return String(localized: "Add the user name to finish.")
        case .password?: return String(localized: "Add the password to finish.")
        case .codeSecret?: return String(localized: "Add the code secret to finish.")
        }
    }

    // MARK: code secret

    func pasteSecret() { take { try CodeSecretInput.fromPasteboard() } }
    func scanImage(at url: URL) { take { try CodeSecretInput.fromImage(at: url) } }
    func scanImage(_ image: NSImage) { take { try CodeSecretInput.fromImage(image) } }

    func removeSecret() {
        codeSecret = nil
        totp = TOTPParams()
        codeSource = ""
        codeError = nil
    }

    /// A secret with the digits, period and algorithm its link brings (a bare secret: the defaults).
    func apply(_ input: CodeSecretInput) {
        switch input {
        case .link(let uri):
            codeSecret = uri.secret
            totp = uri.params
            codeSource = [uri.issuer, uri.account].filter { !$0.isEmpty }.joined(separator: " · ")
        case .secret(let secret):
            codeSecret = secret
            totp = TOTPParams()
            codeSource = ""
        }
        codeError = nil
    }

    private func take(_ read: () throws -> CodeSecretInput?) {
        do {
            guard let input = try read() else {
                codeError = CodeSecretInput.nothingToPaste
                return
            }
            apply(input)
        } catch {
            codeError = error.localizedDescription
        }
    }

    // MARK: adding

    /// Creates the profile with what the review shows. Returns its id, or nil with `addError` set.
    func add(store: ProfileStore = ProfileStore()) -> String? {
        guard canAdd else { return nil }
        do {
            let p = try store.commit(draft, name: name,
                                     username: signsIn ? username : nil,
                                     password: signsIn ? password : nil,
                                     totpSecret: signsIn ? codeSecret : nil, totp: totp)
            addError = nil
            return p.id
        } catch {
            addError = error.localizedDescription
            return nil
        }
    }
}
