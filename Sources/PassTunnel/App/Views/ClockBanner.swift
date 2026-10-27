import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

// A clock that is off, in the main window: the banner above the detail of any profile while the last measurement
// (under an hour old) says so, and the "Check the clock" button of a rejected sign-in. One-time codes are worked out from
// the time, so every code is wrong until the clock is fixed. The measurements are Core's (`ConnectionManager.clockOffsets`,
// `timeServerClock`); the button asks Apple's time server, which only a click does (decision D-16).

/// Runs the on-request check with the time server (`ConnectionManager.checkClock`); its result reaches the views through
/// the manager (the banner, the failure's clock), this keeps whether it is running and whether it failed.
@MainActor
final class ClockCheck: ObservableObject {
    enum State: Equatable { case idle, checking, failed }

    @Published private(set) var state = State.idle

    func run(_ manager: ConnectionManager) {
        guard state != .checking else { return }
        state = .checking
        Task {
            do {
                _ = try await manager.checkClock()
                state = .idle
            } catch {
                state = .failed
            }
        }
    }
}

/// "Check the clock" and, under it, what the click does or that it did not work.
struct ClockCheckButton: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var check: ClockCheck
    var title = String(localized: "Check the clock")

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            Button {
                check.run(model.connections)
            } label: {
                Text(check.state == .checking ? String(localized: "Checking…") : title)
            }
            .buttonStyle(.secondaryCapsule(.compact))
            .disabled(check.state == .checking)
            .help(Self.disclosure)
            .accessibilityHint(Text(Self.disclosure))
            .accessibilityIdentifier("clock.check")
            Text(
                check.state == .failed
                    ? String(localized: "Couldn’t reach the time server. Check the network, then try again.")
                    : Self.disclosure
            )
            .typography(.hint)
            .foregroundStyle(check.state == .failed ? Palette.red : Palette.fg2)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.top, 2)
    }

    /// What the click sends where.
    static var disclosure: String { String(localized: "Asks Apple’s time server for the time. Nothing about you is sent.") }
}

/// An amber edge, the warning glyph, "This Mac’s clock is 48 s behind. Codes are worked out from the time, so every code will
/// be wrong until it’s fixed." and the buttons that open Date & Time and measure again.
struct ClockBanner: View {
    @EnvironmentObject private var model: AppModel
    let clock: ClockOffset
    @StateObject private var check = ClockCheck()

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: Radius.compactCard, style: .continuous)
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .center, spacing: 10) {
                StatusIcon(.warning, size: 18)
                message
                buttons
            }
            VStack(alignment: .leading, spacing: Spacing.xs) {
                HStack(alignment: .top, spacing: 10) {
                    StatusIcon(.warning, size: 18)
                    message
                }
                buttons
            }
        }
        .padding(.vertical, 10)
        .padding(.leading, 15)
        .padding(.trailing, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.fill, in: shape)
        .overlay(alignment: .leading) { Rectangle().fill(Palette.amberRing).frame(width: 3) }
        .clipShape(shape)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("clock.banner")
    }

    private var message: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(banner)
                .typography(.body)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
            if check.state == .failed {
                Text(String(localized: "Couldn’t reach the time server. Check the network, then try again."))
                    .typography(.hint)
                    .foregroundStyle(Palette.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    /// The headline in semibold, then why it matters.
    private var banner: AttributedString {
        var headline = AttributedString(clock.headline)
        headline.font = .body.weight(.semibold)
        return headline
            + AttributedString(" " + String(localized: "Codes are worked out from the time, so every code will be wrong until it’s fixed."))
    }

    private var buttons: some View {
        HStack(spacing: Spacing.xs) {
            Button {
                Self.openDateAndTime()
            } label: {
                Text(String(localized: "Open Date & Time"))
            }
            .buttonStyle(.secondaryCapsule(.compact))
            .accessibilityIdentifier("clock.openSettings")
            Button {
                check.run(model.connections)
            } label: {
                Text(check.state == .checking ? String(localized: "Checking…") : String(localized: "Check again"))
            }
            .buttonStyle(.secondaryCapsule(.compact))
            .disabled(check.state == .checking)
            .help(ClockCheckButton.disclosure)
            .accessibilityHint(Text(ClockCheckButton.disclosure))
            .accessibilityIdentifier("clock.checkAgain")
        }
    }

    /// System Settings → General → Date & Time.
    static func openDateAndTime() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.Date-Time-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }
}
