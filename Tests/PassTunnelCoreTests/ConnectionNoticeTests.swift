import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// Which connection event gives which notification, and when "Connected to <Profile>" is shown.
final class ConnectionNoticeTests: CoreTestCase {
    private let id = "work"
    private let work = ConnectionNotice.Subject(name: "Work", usesCode: true, address: "10.8.0.6",
                                                server: "vpn.example.com")

    private func notice(_ event: ConnectionEvent, _ s: ConnectionNotice.Subject? = nil,
                        prefs: Preferences = Preferences()) -> ConnectionNotice? {
        ConnectionNotice.forEvent(event, s ?? work, prefs: prefs)
    }

    private var allEvents: [ConnectionEvent] {
        [.dropped(profileID: id, willReconnect: true), .dropped(profileID: id, willReconnect: false),
         .reconnected(profileID: id), .reconnectFailed(profileID: id, reason: "boom"), .unreachable(profileID: id),
         .reachableAgain(profileID: id), .sessionEnding(profileID: id, minutes: 10), .droppedWhileAsleep(profileID: id),
         .destinationChanged(profileID: id, stillConnected: true), .destinationChanged(profileID: id, stillConnected: false)]
    }

    // MARK: drops and reconnects

    func testDropWhileReconnectingSaysSoAndOffersStop() {
        XCTAssertEqual(notice(.dropped(profileID: id, willReconnect: true)),
                       ConnectionNotice(title: "Work dropped", body: "Reconnecting with a fresh code…", profileID: id,
                                        actions: .stop))
        // Without a code there is no fresh code to wait for.
        let plain = ConnectionNotice.Subject(name: "Lab")
        XCTAssertEqual(notice(.dropped(profileID: id, willReconnect: true), plain),
                       ConnectionNotice(title: "Lab dropped", body: "Reconnecting…", profileID: id, actions: .stop))
    }

    func testDropWithoutReconnectOffersConnect() {
        XCTAssertEqual(notice(.dropped(profileID: id, willReconnect: false)),
                       ConnectionNotice(title: "Work dropped", body: "It will not reconnect automatically.", profileID: id,
                                        actions: .connect))
    }

    func testReconnectSaysConnectedWithTheAddressAndServer() {
        XCTAssertEqual(notice(.reconnected(profileID: id)),
                       ConnectionNotice(title: "Connected to Work", body: "10.8.0.6 · vpn.example.com", profileID: id))
    }

    func testConnectedLeavesOutWhatIsUnknown() {
        let noAddress = ConnectionNotice.Subject(name: "Work", server: "vpn.example.com")
        XCTAssertEqual(ConnectionNotice.connected(noAddress, profileID: id).body, "vpn.example.com")
        let noServer = ConnectionNotice.Subject(name: "Work", address: "10.8.0.6")
        XCTAssertEqual(ConnectionNotice.connected(noServer, profileID: id).body, "10.8.0.6")
        let nothing = ConnectionNotice.connected(ConnectionNotice.Subject(name: "Work"), profileID: id)
        XCTAssertEqual(nothing.title, "Connected to Work")
        XCTAssertEqual(nothing.body, "")
        XCTAssertNil(nothing.actions)
        XCTAssertFalse(nothing.connectOnClick)
    }

    func testFailedReconnectGivesTheReasonAndOffersConnect() {
        XCTAssertEqual(notice(.reconnectFailed(profileID: id, reason: "The server did not answer.")),
                       ConnectionNotice(title: "Could not reconnect Work", body: "The server did not answer.", profileID: id,
                                        actions: .connect))
    }

    // MARK: the other events keep their notifications

    func testHealthAndSessionLimit() {
        XCTAssertEqual(notice(.unreachable(profileID: id)),
                       ConnectionNotice(title: "Work is not responding",
                                        body: "The VPN is connected, but the health check host cannot be reached.",
                                        profileID: id))
        XCTAssertEqual(notice(.reachableAgain(profileID: id)),
                       ConnectionNotice(title: "Work is responding again",
                                        body: "The health check host can be reached again.", profileID: id))
        XCTAssertEqual(notice(.sessionEnding(profileID: id, minutes: 10)),
                       ConnectionNotice(title: "Work session is ending",
                                        body: "The session limit is reached in 10 minutes.", profileID: id))
    }

    func testDropWhileAsleepAndChangedDestination() {
        XCTAssertEqual(notice(.droppedWhileAsleep(profileID: id)),
                       ConnectionNotice(title: "“Work” disconnected while the Mac was asleep.", body: "Click to reconnect.",
                                        profileID: id, actions: .connect, connectOnClick: true))
        XCTAssertEqual(notice(.destinationChanged(profileID: id, stillConnected: false)),
                       ConnectionNotice(title: "“Work” was not reconnected",
                                        body: "Its server settings changed after you confirmed the connection. Click to connect and confirm again.",
                                        profileID: id, actions: .connect, connectOnClick: true))
        // Still connected: connecting on click would do nothing, a click shows the profile.
        XCTAssertEqual(notice(.destinationChanged(profileID: id, stillConnected: true)),
                       ConnectionNotice(title: "“Work” server settings changed",
                                        body: "It is still connected to the server you confirmed, which is not responding. Reconnect to confirm the new settings.",
                                        profileID: id))
    }

    func testEveryEventHasANotificationByDefault() {
        for event in allEvents {
            let n = notice(event)
            XCTAssertNotNil(n, "\(event)")
            XCTAssertEqual(n?.profileID, id, "\(event)")
            XCTAssertFalse(n?.title.isEmpty ?? true, "\(event)")
        }
    }

    /// Only a drop while the automatic reconnect runs offers Stop.
    func testOnlyARunningReconnectOffersStop() {
        for event in allEvents {
            XCTAssertEqual(notice(event)?.actions == .stop, event == .dropped(profileID: id, willReconnect: true), "\(event)")
        }
    }

    // MARK: preferences

    func testDropNotificationsFollowTheirSetting() {
        var prefs = Preferences()
        prefs.notifyOnDrop = false
        let off: [ConnectionEvent] = [.dropped(profileID: id, willReconnect: true), .dropped(profileID: id, willReconnect: false),
                                      .reconnected(profileID: id), .reconnectFailed(profileID: id, reason: "boom")]
        for event in allEvents {
            XCTAssertEqual(notice(event, prefs: prefs) == nil, off.contains(event), "\(event)")
        }
    }

    func testHealthNotificationsFollowTheirSetting() {
        var prefs = Preferences()
        prefs.notifyHealth = false
        let off: [ConnectionEvent] = [.unreachable(profileID: id), .reachableAgain(profileID: id)]
        for event in allEvents {
            XCTAssertEqual(notice(event, prefs: prefs) == nil, off.contains(event), "\(event)")
        }
    }

    func testSessionLimitNotificationFollowsItsSetting() {
        var prefs = Preferences()
        prefs.sessionNotifyMin = 0
        for event in allEvents {
            XCTAssertEqual(notice(event, prefs: prefs) == nil, event == .sessionEnding(profileID: id, minutes: 10), "\(event)")
        }
    }

    /// They replace the automatic reconnect the user turned on, so every setting off still shows them.
    func testDropWhileAsleepAndChangedDestinationAreAlwaysShown() {
        var prefs = Preferences()
        prefs.notifyOnDrop = false
        prefs.notifyHealth = false
        prefs.sessionNotifyMin = 0
        let shown = allEvents.filter { notice($0, prefs: prefs) != nil }
        XCTAssertEqual(shown, [.droppedWhileAsleep(profileID: id), .destinationChanged(profileID: id, stillConnected: true),
                               .destinationChanged(profileID: id, stillConnected: false)])
    }

    // MARK: "Connected to"

    func testConnectedIsShownForAutomaticConnectsOrWhenTheWindowIsNotVisible() {
        XCTAssertTrue(ConnectionNotice.announcesConnect(.automatic, mainWindowVisible: true))
        XCTAssertTrue(ConnectionNotice.announcesConnect(.automatic, mainWindowVisible: false))
        XCTAssertTrue(ConnectionNotice.announcesConnect(.user, mainWindowVisible: false))
        XCTAssertFalse(ConnectionNotice.announcesConnect(.user, mainWindowVisible: true), "the window shows it")
    }

    // MARK: connect at login

    func testConnectAtLoginOffersAClickInsteadOfAPrompt() {
        XCTAssertEqual(ConnectionNotice.offeredAtLogin(work, profileID: id),
                       ConnectionNotice(title: "“Work” is set to connect at login", body: "Click to connect.", profileID: id,
                                        actions: .connect, connectOnClick: true))
        // A failure gives the reason; a click shows the profile, Connect tries again.
        XCTAssertEqual(ConnectionNotice.notConnectedAtLogin(work, reason: "This Mac is offline.", profileID: id),
                       ConnectionNotice(title: "Could not connect “Work” at login", body: "This Mac is offline.", profileID: id,
                                        actions: .connect))
    }

    // MARK: subject

    func testSubjectOfAnOpenVPNProfile() throws {
        var p = try store.create(name: "Work", type: .openvpn)
        p.otpMode = .totp
        try store.save(p)
        try Data("client\nremote vpn.example.com 1194\nauth-user-pass\n".utf8).write(to: store.ovpnURL(p.id))
        XCTAssertEqual(ConnectionNotice.Subject(p, state: .connected(ip: "10.8.0.6", since: nil), store: store),
                       ConnectionNotice.Subject(name: "Work", usesCode: true, address: "10.8.0.6", server: "vpn.example.com"))
        // The address only while connected.
        XCTAssertEqual(ConnectionNotice.Subject(p, state: .disconnected, store: store).address, "")
        XCTAssertEqual(ConnectionNotice.Subject(p, state: .connecting("Signing in…"), store: store).address, "")

        // Several servers: named as the confirmation prompt names them.
        try Data("client\nremote vpn.example.com 1194\nremote vpn2.example.com 1194\nauth-user-pass\n".utf8)
            .write(to: store.ovpnURL(p.id))
        XCTAssertEqual(ConnectionNotice.Subject(p, state: .disconnected, store: store).server, "vpn.example.com +1 more")
    }

    func testSubjectOfAFortiProfile() throws {
        var p = try store.create(name: "Lab", type: .forti)
        p.host = "vpn.example.com "
        let s = ConnectionNotice.Subject(p, state: .connected(ip: "10.9.0.2", since: nil), store: store)
        XCTAssertEqual(s, ConnectionNotice.Subject(name: "Lab", usesCode: false, address: "10.9.0.2", server: "vpn.example.com"))
        XCTAssertEqual(ConnectionNotice.connected(s, profileID: p.id).body, "10.9.0.2 · vpn.example.com")
    }
}
