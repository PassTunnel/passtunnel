import AppKit
import Combine
import PassTunnelCore
import SwiftUI

// The Login Items guide (docs/APP.md, Settings → Helper): after PassTunnel opened Login Items for the helper's
// approval, a small floating panel shows the row to turn on, while System Settings is in front. When it shows and
// when it ends is `LoginItemsGuide` (Core); this file only draws and places it. It never reads, scripts or clicks
// anything in System Settings and needs no permission: the frontmost app and the running apps come from
// NSWorkspace, the heading from System Settings' own strings file (`LoginItemsPane`).

extension AppModel {
    /// Opens Login Items for the helper and starts the guide while the helper waits for the approval (never for an
    /// enabled one). Every Open Login Items… for the helper, and the automatic install, go through here.
    func openLoginItemsForHelper() {
        HelperInstaller.openSystemSettingsLoginItems()
        // The status as it is now: a helper turned on since the last refresh gets no guide.
        refreshHelperStatus()
        LoginItemsGuideController.shared.start(for: self)
    }
}

/// Runs the guide: starts it, follows the helper's status, the frontmost app and System Settings, and shows,
/// hides or closes the panel as `LoginItemsGuide` decides.
@MainActor
final class LoginItemsGuideController {
    static let shared = LoginItemsGuideController()

    /// While the guide runs, the helper's status is read this often while System Settings is in front, so the panel
    /// goes as soon as the switch is turned on (the app's own refresh is every 5 s).
    static let refreshInterval: TimeInterval = 1
    /// Distance from the screen's edge.
    static let margin: CGFloat = 20

    private weak var model: AppModel?
    private var guide = LoginItemsGuide()
    private var panel: GuidePanel?
    private var heading: String?
    private var frontmost: String?
    private var placed = false
    private var announced = false
    private var dragStart: (mouse: NSPoint, origin: NSPoint)?
    private var timer: Timer?
    private var bag = Set<AnyCancellable>()

    func start(for model: AppModel) {
        guard guide.start(status: model.helperStatus, removedByUser: model.prefs.helperRemoved) else { return end() }
        self.model = model
        heading = LoginItemsPane.backgroundHeading()
        frontmost = NSWorkspace.shared.frontmostApplication?.bundleIdentifier
        placed = false
        announced = false
        panel?.orderOut(nil)
        panel = nil
        observe(model)
        update()
    }

    /// Ends the guide and removes the panel (the close button, the app quitting, or `LoginItemsGuide` deciding so).
    func end() {
        guide.close()
        timer?.invalidate()
        timer = nil
        bag.removeAll()
        dragStart = nil
        panel?.orderOut(nil)
        panel = nil
    }

    private func observe(_ model: AppModel) {
        bag.removeAll()
        // `@Published` sends before the value changes: read it on the next turn.
        model.$helperStatus.receive(on: DispatchQueue.main).sink { [weak self] _ in self?.update() }.store(in: &bag)
        model.$prefs.receive(on: DispatchQueue.main).sink { [weak self] _ in self?.update() }.store(in: &bag)
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [
            NSWorkspace.didActivateApplicationNotification, NSWorkspace.didLaunchApplicationNotification,
            NSWorkspace.didTerminateApplicationNotification
        ] {
            workspace.publisher(for: name)
                .sink { [weak self] note in
                    guard let self else { return }
                    if name == NSWorkspace.didActivateApplicationNotification,
                        let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
                    {
                        self.frontmost = app.bundleIdentifier
                    }
                    self.update()
                }
                .store(in: &bag)
        }
        NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)
            .sink { [weak self] _ in self?.end() }
            .store(in: &bag)
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: Self.refreshInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
    }

    private func tick() {
        frontmost = NSWorkspace.shared.frontmostApplication?.bundleIdentifier
        if frontmost == LoginItemsGuide.systemSettingsBundleID { model?.refreshHelperStatus() }
        update()
    }

    private func update() {
        guard let model, guide.isActive else { return }
        let running = !NSRunningApplication.runningApplications(withBundleIdentifier: LoginItemsGuide.systemSettingsBundleID)
            .isEmpty
        let situation = LoginItemsGuide.Situation(
            status: model.helperStatus, removedByUser: model.prefs.helperRemoved, frontmost: frontmost,
            systemSettingsRunning: running)
        let shows = guide.shows(situation)
        guard guide.isActive else { return end() }
        if shows { show() } else { panel?.orderOut(nil) }
    }

    private func show() {
        let panel = panel ?? makePanel()
        self.panel = panel
        if !placed {
            place(panel)
            placed = true
        }
        guard !panel.isVisible else { return }
        let animate = !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        panel.alphaValue = animate ? 0 : 1
        panel.orderFrontRegardless()
        if animate {
            NSAnimationContext.runAnimationGroup { context in
                context.duration = Motion.colorChangeDuration
                panel.animator().alphaValue = 1
            }
        }
        if !announced {
            announced = true
            let info: [NSAccessibility.NotificationUserInfoKey: Any] = [
                .announcement: LoginItemsGuideView.announcement(heading: heading),
                .priority: NSAccessibilityPriorityLevel.high.rawValue
            ]
            NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: info)
        }
    }

    private func makePanel() -> GuidePanel {
        let view = LoginItemsGuideView(
            // After the click: the panel is released, and must not be while its button handles the click.
            heading: heading, onClose: { DispatchQueue.main.async { [weak self] in self?.end() } },
            onDrag: { [weak self] ended in self?.drag(ended: ended) })
        return GuidePanel(content: view)
    }

    /// At the leading edge of the screen with the pointer (the one the user just clicked on), centered vertically:
    /// away from the notifications at the top right, and, at System Settings' usual place in the middle of the
    /// screen, beside its window or over its sidebar at most, never over the switches on the right of its list.
    /// Where System Settings' window is is not looked up: that would need the window list. The user can drag the
    /// panel anywhere.
    private func place(_ panel: NSPanel) {
        let mouse = NSEvent.mouseLocation
        guard let screen = NSScreen.screens.first(where: { NSMouseInRect(mouse, $0.frame, false) }) ?? NSScreen.main
        else { return }
        let area = screen.visibleFrame
        let size = panel.frame.size
        panel.setFrameOrigin(NSPoint(x: area.minX + Self.margin, y: (area.midY - size.height / 2).rounded()))
    }

    /// Moves the panel with the pointer (dragging its background).
    private func drag(ended: Bool) {
        guard let panel else { return }
        if ended {
            dragStart = nil
            return
        }
        let mouse = NSEvent.mouseLocation
        guard let start = dragStart else {
            dragStart = (mouse, panel.frame.origin)
            return
        }
        panel.setFrameOrigin(NSPoint(x: start.origin.x + mouse.x - start.mouse.x, y: start.origin.y + mouse.y - start.mouse.y))
    }
}

/// A borderless panel that floats above other apps' windows (System Settings) without becoming key or activating
/// PassTunnel, on every Space and next to full-screen windows; it is never the main window and never counts for
/// the Dock icon (`AppDelegate.updateActivationPolicy` skips panels).
private final class GuidePanel: NSPanel {
    init<Content: View>(content: Content) {
        super.init(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
        isFloatingPanel = true
        level = .floating
        hidesOnDeactivate = false
        becomesKeyOnlyIfNeeded = true
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle]
        isOpaque = false
        backgroundColor = .clear
        hasShadow = true
        isReleasedWhenClosed = false
        animationBehavior = .none
        let host = FirstClickHostingView(rootView: content)
        contentView = host
        setContentSize(host.fittingSize)
    }

    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

/// Takes the first click (the panel is never key), so the close button and dragging work at once.
private final class FirstClickHostingView<Content: View>: NSHostingView<Content> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}

/// The guide's content: what to do, the row as it looks in Login Items (the app icon, "PassTunnel" and its switch
/// drawn on), and that the panel goes by itself. 300 pt wide.
struct LoginItemsGuideView: View {
    /// The heading above the background items in System Settings (`LoginItemsPane`), when known.
    let heading: String?
    var onClose: (() -> Void)?
    /// Dragging the background: false while it moves, true when it ends.
    var onDrag: ((Bool) -> Void)?
    /// The render: the material that stands in for the panel's glass, with its shadow (`RenderSnapshots`).
    var render = false

    static let width: CGFloat = 300

    /// What to do, as the panel says it.
    static func instruction(heading: String?) -> String {
        guard let heading else {
            return String(localized: "In the list of apps that can run in the background, find this row and turn its switch on:")
        }
        return String(localized: "Under “\(heading)”, find this row and turn its switch on:")
    }

    /// What VoiceOver says when the panel appears (it never takes the focus from System Settings).
    static func announcement(heading: String?) -> String {
        guard let heading else { return String(localized: "In System Settings, turn on the switch next to PassTunnel.") }
        return String(localized: "In System Settings, under “\(heading)”, turn on the switch next to PassTunnel.")
    }

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: Radius.panel, style: .continuous)
        VStack(alignment: .leading, spacing: Spacing.s) {
            HStack(alignment: .firstTextBaseline, spacing: Spacing.xs) {
                Text(String(localized: "Turn on the switch next to PassTunnel"))
                    .typography(.sheetTitle)
                    .foregroundStyle(Palette.fg)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 0)
                Button {
                    onClose?()
                } label: {
                    Image(systemName: "xmark")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(Palette.fg2)
                        .frame(width: 20, height: 20)
                        .background(Palette.fill2, in: Circle())
                        .edge(Circle(), Palette.controlEdge)
                }
                .buttonStyle(.plain)
                .contentShape(Circle())
                .accessibilityLabel(String(localized: "Close the guide"))
                .accessibilityIdentifier("loginItemsGuide.close")
            }
            Text(Self.instruction(heading: heading))
                .typography(.hint)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
            LoginItemsRowSample()
            Text(String(localized: "This closes by itself once the helper is on."))
                .typography(.hint)
                .foregroundStyle(Palette.fg2)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(Spacing.m)
        .frame(width: Self.width, alignment: .leading)
        .background { background(shape) }
        .contentShape(shape)
        .gesture(
            DragGesture(minimumDistance: 2)
                .onChanged { _ in onDrag?(false) }
                .onEnded { _ in onDrag?(true) }
        )
        .padding(render ? Spacing.l : 0)
    }

    @ViewBuilder private func background(_ shape: RoundedRectangle) -> some View {
        // Glass as for the menu bar panel; the window draws the shadow. Offscreen, macOS 26's glass does not draw,
        // so the render uses the material of earlier versions with the design's floating shadow.
        if render {
            Color.clear.materialGlass(in: shape, shadow: Elevation.floating)
        } else if #available(macOS 26, *) {
            Color.clear.glassEffect(.regular, in: shape)
        } else {
            Color.clear.background(.regularMaterial, in: shape).edge(shape, Palette.glassEdge, width: Elevation.glassEdge)
        }
    }
}

/// The row as Login Items lists it: the app icon, "PassTunnel", and the switch drawn on, with a ring around it.
/// One image for VoiceOver.
private struct LoginItemsRowSample: View {
    var body: some View {
        HStack(spacing: Spacing.xs) {
            Image(nsImage: AppInfo.appIcon)
                .resizable()
                .interpolation(.high)
                .frame(width: 24, height: 24)
            Text(verbatim: "PassTunnel")
                .typography(.body)
                .foregroundStyle(Palette.fg)
            Spacer(minLength: Spacing.xs)
            SwitchOnSample()
                .padding(4)
                .overlay(Capsule().strokeBorder(Palette.fg2, lineWidth: 1.5))
        }
        .padding(.horizontal, 10)
        .padding(.vertical, Spacing.xs)
        .background(Palette.card, in: RoundedRectangle(cornerRadius: Radius.field, style: .continuous))
        .edge(RoundedRectangle(cornerRadius: Radius.field, style: .continuous), Palette.line)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(String(localized: "Example: PassTunnel, with its switch turned on"))
        .accessibilityAddTraits(.isImage)
    }
}

/// A switch drawn on, as macOS draws one: the accent color, the knob on the right.
private struct SwitchOnSample: View {
    var body: some View {
        Capsule()
            .fill(Color(nsColor: .controlAccentColor))
            .frame(width: 34, height: 20)
            .overlay(alignment: .trailing) {
                Circle()
                    .fill(Color.white)
                    .shadow(color: .black.opacity(0.25), radius: 1, y: 0.5)
                    .padding(2)
            }
            .edge(Capsule(), Palette.controlEdge)
    }
}

/// The guide as it floats over the desktop, for the `login-items-guide` renders (RenderSnapshots).
struct LoginItemsGuidePreview: View {
    let heading: String?

    var body: some View {
        LoginItemsGuideView(heading: heading, render: true)
            .background(Color(nsColor: .underPageBackgroundColor))
    }
}
