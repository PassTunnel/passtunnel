import PassTunnelCore
import SwiftUI

/// Asks only for what the profile needs before connecting; the code is prefilled when a TOTP secret exists.
struct CredentialSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let request: CredentialRequest

    @State private var username = ""
    @State private var password = ""
    @State private var otp = ""
    @State private var prefilledOTP: String?
    @FocusState private var focus: CredentialField?

    private var profile: Profile { request.profile }
    private func needs(_ f: CredentialField) -> Bool { request.needs.contains(f) }

    private var canConnect: Bool {
        (!needs(.username) || !username.trimmingCharacters(in: .whitespaces).isEmpty)
            && (!needs(.password) || !password.isEmpty)
            && (!needs(.otp) || !otp.trimmingCharacters(in: .whitespaces).isEmpty)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                ProfileAvatar(profile: profile, kind: .disconnected, size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(String(localized: "Connect to \(profile.name)"))
                        .font(.headline)
                    Text(String(localized: "Only what is not saved is asked here."))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            .padding([.horizontal, .top], 20)
            .padding(.bottom, 8)

            Form {
                if needs(.username) {
                    TextField(String(localized: "Username"), text: $username)
                        .textContentType(.username)
                        .focused($focus, equals: .username)
                }
                if needs(.password) {
                    SecureField(String(localized: "Password"), text: $password)
                        .textContentType(.password)
                        .focused($focus, equals: .password)
                }
                if needs(.otp) {
                    LabeledContent {
                        HStack(spacing: 6) {
                            TextField(String(localized: "One-time code"), text: $otp, prompt: Text(verbatim: "123456"))
                                .labelsHidden()
                                .font(.system(.body, design: .monospaced))
                                .textContentType(.oneTimeCode)
                                .focused($focus, equals: .otp)
                            if prefilledOTP != nil && otp == prefilledOTP {
                                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                                    if let c = model.code(for: profile, at: ctx.date) {
                                        CountdownRing(remaining: Double(c.remaining), period: Double(profile.totp.period), size: 18, lineWidth: 2)
                                            .onChange(of: c.code) { new in
                                                if otp == prefilledOTP { otp = new; prefilledOTP = new }
                                            }
                                    }
                                }
                            }
                        }
                    } label: {
                        Text(String(localized: "One-time code"))
                    }
                }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .frame(height: CGFloat(request.needs.count) * 36 + 40)

            HStack {
                Spacer()
                Button(String(localized: "Cancel"), role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(String(localized: "Connect")) { submit() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canConnect)
            }
            .padding([.horizontal, .bottom], 20)
        }
        .frame(width: 400)
        .onAppear {
            username = profile.lastUsername
            if let c = model.code(for: profile) {
                otp = c.code
                prefilledOTP = c.code
            }
            focus = request.needs.first { f in
                switch f {
                case .username: return username.isEmpty
                case .password: return true
                case .otp: return otp.isEmpty
                }
            } ?? request.needs.first
        }
    }

    private func submit() {
        guard canConnect else { return }
        var given: [CredentialField: String] = [:]
        if needs(.username) { given[.username] = username.trimmingCharacters(in: .whitespaces) }
        if needs(.password) { given[.password] = password }
        if needs(.otp) {
            // An untouched prefilled code may have rolled over; send the current one.
            if otp == prefilledOTP, let fresh = model.code(for: profile)?.code { given[.otp] = fresh }
            else { given[.otp] = otp.filter { !$0.isWhitespace } }
        }
        dismiss()
        model.connect(profile, given: given)
    }
}
