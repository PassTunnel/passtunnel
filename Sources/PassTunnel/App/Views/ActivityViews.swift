import AppKit
import PassTunnelCore
import PassTunnelKit
import SwiftUI

// A profile's activity in the redesigned window (docs/APP.md, Redesigned window): the card under the code cards with
// the last six events, and the window "Show all" opens with all of them. The events and their words are
// `ActivityEvent` in Core (it records what the app and the CLI did); the app shows the first three digits of a code
// and never the password.

extension AppModel {
    /// The profile's activity, oldest first, as every process recorded it; from the render overrides while they are
    /// set.
    func activityEvents(_ id: String) -> [ActivityEvent] {
        previewStates == nil ? connections.activity(id) : previewActivity[id] ?? []
    }
}

/// A profile's activity, kept up to date while a view shows it: `ActivityLog` is read again when this app records an
/// event or when the file changes (a session the CLI runs).
@MainActor
final class ActivityFeed: ObservableObject {
    @Published private(set) var events: [ActivityEvent]
    private let model: AppModel
    private let profileID: String
    private var stamp: Stamp?

    private struct Stamp: Equatable {
        var modified: Date?
        var size: Int?
    }

    init(_ model: AppModel, _ profileID: String) {
        self.model = model
        self.profileID = profileID
        events = model.activityEvents(profileID)
        stamp = currentStamp()
    }

    /// Reads the events again when the file changed since the last read, or `force`.
    func refresh(force: Bool = false) {
        let current = currentStamp()
        guard force || current != stamp else { return }
        stamp = current
        let read = model.activityEvents(profileID)
        if read != events { events = read }
    }

    private func currentStamp() -> Stamp? {
        guard model.previewStates == nil,
              let attributes = try? FileManager.default.attributesOfItem(atPath: model.store.activityURL(profileID).path)
        else { return nil }
        return Stamp(modified: attributes[.modificationDate] as? Date, size: (attributes[.size] as? NSNumber)?.intValue)
    }

    /// Keeps `refresh`ing once a second for as long as the calling task runs, for sessions other processes record.
    func follow() async {
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            refresh()
        }
    }
}

extension DisplayStatus {
    /// The tunnel is up (also with a problem), so the last sign-in sent is the one that opened it.
    var isUp: Bool {
        switch self {
        case .connected, .setupIncomplete, .notResponding, .statusUnavailable: return true
        default: return false
        }
    }

    /// When the tunnel came up; nil when it is not up or the time is unknown.
    var connectedSince: Date? {
        switch self {
        case .connected(let c), .setupIncomplete(let c, _), .notResponding(let c), .statusUnavailable(let c): return c.since
        default: return nil
        }
    }
}

extension ActivityEvent.Tone {
    /// Errors red, waits amber, the rest in the text color.
    var color: Color {
        switch self {
        case .neutral: return Palette.fg
        case .wait: return Palette.amber
        case .error: return Palette.red
        }
    }
}

// MARK: - Entry

/// One event: the time (11.5 pt SF Mono, `fg3`) and the sentence in the color of its kind, wrapping rather than
/// truncating. VoiceOver reads it as one element, a hidden password or code as "hidden".
struct ActivityLine: View {
    let event: ActivityEvent
    var selectable = false

    var body: some View {
        let spokenTime = event.at.formatted(date: .omitted, time: .standard)
        let spoken = "\(spokenTime), \(event.spokenSentence(showingCodeDigits: true))"
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(verbatim: ActivityEvent.clockTime(event.at))
                .foregroundStyle(Palette.fg3)
            Text(verbatim: event.sentence(showingCodeDigits: true))
                .foregroundStyle(event.tone.color)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
        .typography(.log)
        .modifier(OptionalTextSelection(enabled: selectable))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: spoken))
    }
}

private struct OptionalTextSelection: ViewModifier {
    let enabled: Bool

    @ViewBuilder
    func body(content: Content) -> some View {
        if enabled { content.textSelection(.enabled) } else { content }
    }
}

// MARK: - Card

/// "ACTIVITY": the last six events of the profile, oldest first, each with its time, and "Show all", which opens the
/// log window. Without events it says "Not connected yet".
struct ActivityCard: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow
    let profile: Profile
    @ObservedObject var feed: ActivityFeed

    /// How many events the card shows.
    static let shown = 6

    var body: some View {
        let events = feed.events.suffix(Self.shown)
        Card {
            HStack {
                SectionLabel(String(localized: "Activity"))
                Spacer(minLength: Spacing.s)
                Button(String(localized: "Show all")) {
                    model.activityLogProfile = profile.id
                    openWindow(id: ActivityLogWindow.id)
                    NSApp.activate(ignoringOtherApps: true)
                }
                .buttonStyle(.smallCapsule)
                .accessibilityHint(Text(verbatim: profile.name))
                .accessibilityIdentifier("profile.\(profile.id).activity.showAll")
            }
            if events.isEmpty {
                Text(String(localized: "Not connected yet"))
                    .typography(.log)
                    .foregroundStyle(Palette.fg3)
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(events.enumerated()), id: \.offset) { _, event in
                        ActivityLine(event: event)
                    }
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("profile.\(profile.id).activity")
    }
}

// MARK: - Window

/// The window "Show all" opens, for the profile in `AppModel.activityLogProfile`: all its events, oldest first under
/// the day they happened, scrolled to the latest; "Errors only" leaves out the rest, "Show raw log" opens the VPN
/// tool's own `vpn.log` as the menu does.
struct ActivityLogWindow: View {
    static let id = "activity-log"

    @EnvironmentObject private var model: AppModel

    var body: some View {
        Group {
            if let profile = model.activityLogProfile.flatMap(model.profile) {
                ActivityLogContent(model: model, profile: profile)
                    .id(profile.id)
                    .navigationTitle(profile.name)
                    .navigationSubtitle(String(localized: "Activity"))
            } else {
                Text(String(localized: "Nothing to show"))
                    .typography(.body)
                    .foregroundStyle(Palette.fg2)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .navigationTitle(String(localized: "Activity"))
            }
        }
        .frame(minWidth: 460, idealWidth: 620, minHeight: 320, idealHeight: 460)
        .background(Palette.background)
    }
}

struct ActivityLogContent: View {
    @EnvironmentObject private var model: AppModel
    let profile: Profile
    @StateObject private var feed: ActivityFeed
    @State private var errorsOnly: Bool

    private static let end = "end"

    /// `errorsOnly`: the filter's start value (renders).
    init(model: AppModel, profile: Profile, errorsOnly: Bool = false) {
        self.profile = profile
        _feed = StateObject(wrappedValue: ActivityFeed(model, profile.id))
        _errorsOnly = State(initialValue: errorsOnly)
    }

    private enum Item {
        case day(String)
        case line(ActivityEvent)
    }

    var body: some View {
        let items = self.items
        let shape = RoundedRectangle(cornerRadius: Radius.compactCard, style: .continuous)
        VStack(alignment: .leading, spacing: Spacing.s) {
            HStack(spacing: Spacing.m) {
                Toggle(String(localized: "Errors only"), isOn: $errorsOnly)
                    .toggleStyle(.checkbox)
                    .accessibilityIdentifier("activity.errorsOnly")
                Spacer(minLength: Spacing.s)
                let hasRawLog = FileManager.default.fileExists(atPath: model.store.logURL(profile.id).path)
                Button(String(localized: "Show raw log")) { model.showLog(profile) }
                    .buttonStyle(.secondaryCapsule(.compact))
                    .disabled(!hasRawLog)
                    .help(hasRawLog ? "" : String(localized: "No log yet"))
                    .accessibilityIdentifier("activity.rawLog")
            }
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        if items.isEmpty {
                            Text(errorsOnly ? String(localized: "No errors") : String(localized: "Not connected yet"))
                                .typography(.log)
                                .foregroundStyle(Palette.fg3)
                        }
                        ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                            switch item {
                            case .day(let title):
                                SectionLabel(title)
                                    .padding(.top, Spacing.xs)
                                    .padding(.bottom, Spacing.xxs)
                            case .line(let event):
                                ActivityLine(event: event, selectable: true)
                            }
                        }
                        Color.clear.frame(height: 1).id(Self.end)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .background(Palette.card, in: shape)
                .edge(shape, Palette.line)
                .onAppear { scrollToEnd(proxy) }
                .onChange(of: feed.events.count) { _ in scrollToEnd(proxy) }
                .onChange(of: errorsOnly) { _ in scrollToEnd(proxy) }
            }
            Text(String(localized: "Passwords are never shown, and only the first three digits of a code."))
                .typography(.hint)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(Spacing.m)
        .onReceive(model.connections.activity) { record in
            if record.profileID == profile.id { feed.refresh(force: true) }
        }
        .task { await feed.follow() }
    }

    /// The events (the errors with "Errors only"), a heading before each day's.
    private var items: [Item] {
        let calendar = Calendar.current
        let events = errorsOnly ? feed.events.filter { $0.tone == .error } : feed.events
        var items: [Item] = []
        var day: Date?
        for event in events {
            if let last = day, calendar.isDate(event.at, inSameDayAs: last) {} else {
                day = event.at
                items.append(.day(Self.dayTitle(event.at, now: model.now)))
            }
            items.append(.line(event))
        }
        return items
    }

    /// "Today", "Yesterday", else "Fri, Oct 23".
    private static func dayTitle(_ date: Date, now: Date) -> String {
        let calendar = Calendar.current
        if calendar.isDate(date, inSameDayAs: now) { return String(localized: "Today") }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now), calendar.isDate(date, inSameDayAs: yesterday) {
            return String(localized: "Yesterday")
        }
        return date.formatted(.dateTime.weekday(.abbreviated).month(.abbreviated).day())
    }

    private func scrollToEnd(_ proxy: ScrollViewProxy) {
        // After the new rows are laid out.
        DispatchQueue.main.async { proxy.scrollTo(Self.end, anchor: .bottom) }
    }
}
