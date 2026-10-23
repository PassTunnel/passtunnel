import PassTunnelCore
import PassTunnelKit
import SwiftUI

/// First-launch walkthrough: welcome, helper installation, first profile.
struct OnboardingView: View {
    @EnvironmentObject private var model: AppModel
    @State var step: Int = 0
    private let steps = 3

    var body: some View {
        VStack(spacing: 0) {
            Group {
                switch step {
                case 0: WelcomeStep()
                case 1: HelperStep()
                default: FirstProfileStep()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(.horizontal, 40)
            .padding(.top, 32)

            Divider()
            HStack {
                PageDots(count: steps, current: step)
                Spacer()
                if step > 0 {
                    Button(String(localized: "Back")) { withAnimation { step -= 1 } }
                        .accessibilityIdentifier("onboarding.back")
                }
                if step < steps - 1 {
                    Button(step == 1 && model.helperStatus != .enabled ? String(localized: "Later") : String(localized: "Continue")) {
                        withAnimation { step += 1 }
                    }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("onboarding.continue")
                } else {
                    Button(String(localized: "Done")) { model.finishOnboarding() }
                        .keyboardShortcut(.defaultAction)
                        .accessibilityIdentifier("onboarding.done")
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
        }
        .frame(width: 560, height: 520)
    }
}

private struct PageDots: View {
    let count: Int
    let current: Int

    var body: some View {
        HStack(spacing: 6) {
            ForEach(0..<count, id: \.self) { i in
                Capsule()
                    .fill(i == current ? Color.accentColor : Color.secondary.opacity(0.3))
                    .frame(width: i == current ? 18 : 7, height: 7)
            }
        }
        .accessibilityElement()
        .accessibilityLabel(String(localized: "Step \(current + 1) of \(count)"))
    }
}

private struct StepHeader: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(spacing: 8) {
            Text(title)
                .font(.system(size: 24, weight: .bold))
                .multilineTextAlignment(.center)
            Text(subtitle)
                .font(.system(size: 13.5))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 420)
        }
    }
}

// MARK: steps

private struct WelcomeStep: View {
    var body: some View {
        VStack(spacing: 20) {
            Image(nsImage: AppInfo.appIcon)
                .resizable()
                .interpolation(.high)
                .frame(width: 72, height: 72)
                .accessibilityHidden(true)
            StepHeader(title: String(localized: "Never type a one-time code again"),
                       subtitle: String(localized: "PassTunnel connects your VPN and fills in your password and the current one-time code for you."))
            DemoCodeCard()
            VStack(alignment: .leading, spacing: 12) {
                FeatureRow(symbol: "key.fill", tint: .blue,
                           text: String(localized: "Password and authenticator secret stay in your Keychain."))
                FeatureRow(symbol: "bolt.fill", tint: .orange,
                           text: String(localized: "One click, or a shortcut, to connect with a fresh code."))
                FeatureRow(symbol: "menubar.rectangle", tint: .green,
                           text: String(localized: "Status at a glance in the menu bar, with alerts when a VPN drops."))
            }
            .frame(maxWidth: 400, alignment: .leading)
            Spacer(minLength: 0)
        }
    }
}

/// Illustration: a profile card with a live code generated from a fixed demo secret.
struct DemoCodeCard: View {
    @EnvironmentObject private var model: AppModel
    private static let secret = Data("PassTunnelDemoSecret".utf8)

    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.5)) { ctx in
            let date = model.previewNow ?? ctx.date
            let params = TOTPParams()
            let remaining = 30 - date.timeIntervalSince1970.truncatingRemainder(dividingBy: 30)
            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 11, style: .continuous)
                        .fill(Color.green.gradient.opacity(0.22))
                    Image(systemName: "network.badge.shield.half.filled")
                        .font(.system(size: 20, weight: .semibold))
                        .foregroundStyle(.green)
                }
                .frame(width: 42, height: 42)
                VStack(alignment: .leading, spacing: 3) {
                    Text(String(localized: "Work VPN")).font(.system(size: 14, weight: .semibold))
                    Label(String(localized: "Connected"), systemImage: "circle.fill")
                        .labelStyle(DotLabelStyle())
                        .font(.system(size: 11.5))
                        .foregroundStyle(.green)
                }
                Spacer(minLength: 20)
                CodeText(code: TOTP.code(secret: Self.secret, params: params, at: date), fontSize: 26)
                CountdownRing(remaining: remaining, period: 30, size: 24)
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 14)
            .frame(width: 400)
            .background(.background, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Color.primary.opacity(0.1)))
            .shadow(color: .black.opacity(0.12), radius: 14, y: 6)
        }
        .padding(.top, 6)
        .accessibilityHidden(true)
    }
}

private struct FeatureRow: View {
    let symbol: String
    let tint: Color
    let text: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 26, height: 26)
                .background(tint.gradient, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                .accessibilityHidden(true)
            Text(text)
                .font(.system(size: 13))
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct DotLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 5) {
            configuration.icon.font(.system(size: 6))
            configuration.title
        }
    }
}

private struct HelperStep: View {
    @EnvironmentObject private var model: AppModel
    @State private var errorText: String?
    private let timer = Timer.publish(every: 1.5, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 22) {
            ZStack {
                Circle().fill(statusTint.gradient.opacity(0.15)).frame(width: 88, height: 88)
                Image(systemName: symbol)
                    .font(.system(size: 40))
                    .foregroundStyle(statusTint.gradient)
            }
            .padding(.top, 8)
            .accessibilityHidden(true)
            StepHeader(title: String(localized: "Install the helper"),
                       subtitle: String(localized: "Creating a VPN tunnel needs administrator rights. A small helper does that part, and it only runs the signed VPN tools that ship inside PassTunnel."))
            VStack(spacing: 10) {
                switch model.helperStatus {
                case .enabled:
                    Label(String(localized: "The helper is installed and running."), systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .font(.callout.weight(.medium))
                case .requiresApproval:
                    Text(String(localized: "Almost done: turn on PassTunnel in System Settings → General → Login Items."))
                        .font(.callout)
                        .multilineTextAlignment(.center)
                    Button(String(localized: "Open Login Items…")) { HelperInstaller.openSystemSettingsLoginItems() }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .accessibilityIdentifier("onboarding.loginItems")
                case .notRegistered:
                    Button(String(localized: "Install Helper")) { install() }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .accessibilityIdentifier("onboarding.installHelper")
                case .notFound:
                    Text(String(localized: "Move PassTunnel to the Applications folder and open it from there to install the helper."))
                        .font(.callout)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                }
                if let errorText {
                    Text(errorText).font(.caption).foregroundStyle(.red).multilineTextAlignment(.center)
                }
            }
            Spacer(minLength: 0)
        }
        .onReceive(timer) { _ in model.refreshHelperStatus() }
    }

    private var symbol: String {
        model.helperStatus == .enabled ? "checkmark.shield.fill" : "lock.shield.fill"
    }

    private var statusTint: Color {
        switch model.helperStatus {
        case .enabled: return .green
        case .requiresApproval: return .orange
        default: return .accentColor
        }
    }

    private func install() {
        errorText = nil
        do { try HelperInstaller.register() } catch { errorText = error.localizedDescription }
        model.refreshHelperStatus()
        if model.helperStatus == .requiresApproval { HelperInstaller.openSystemSettingsLoginItems() }
    }
}

private struct FirstProfileStep: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 22) {
            StepHeader(title: String(localized: "Add your first VPN"),
                       subtitle: String(localized: "Start from what your IT team gave you. You can add more profiles at any time with the + button."))
                .padding(.top, 10)
            ImportOptionsView()
                .frame(maxWidth: 420)
            Toggle(String(localized: "Start PassTunnel at login"), isOn: startAtLogin)
                .toggleStyle(.checkbox)
                .help(String(localized: "Starts quietly in the menu bar, without opening the window."))
                .frame(maxWidth: 420, alignment: .leading)
            Spacer(minLength: 0)
        }
        // The choice is applied when onboarding closes (Done, or the first import), only once seen here.
        .onAppear { if model.onboardingStartAtLogin == nil { model.onboardingStartAtLogin = true } }
    }

    private var startAtLogin: Binding<Bool> {
        Binding(get: { model.onboardingStartAtLogin ?? true }, set: { model.onboardingStartAtLogin = $0 })
    }
}
