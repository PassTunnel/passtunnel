import XCTest

@testable import PassTunnelShared

/// The system configuration as `OpenVPNDNS` sees it, in memory: the dynamic store's keys, the network
/// preferences and the interfaces. Every write is recorded; writes can be made to fail or not to hold.
final class FakeDNSSystem: OpenVPNDNSSystem {
    /// `Setup:/Network/Service/<id>/DNS`.
    var services: [String: DNSEntity] = [:]
    /// The services of the network preferences and their `DNS` entity (nil: the service has none).
    var preferences: [String: DNSEntity?] = [:]
    var backups: [String: DNSEntity] = [:]
    var tunnels: [String: DNSEntity] = [:]
    var interfaces: Set<String> = []
    var names: [String: String] = [:]
    var storeReadable = true
    var preferencesReadable = true
    /// Writes refused before one is taken.
    var refusedWrites = 0
    /// Writes taken that do not hold (something puts the old value back).
    var lostWrites = 0
    private(set) var writes: [String] = []

    func serviceDNS() -> [String: DNSEntity]? { storeReadable ? services : nil }

    func preferencesDNS(service: String) -> OpenVPNDNS.Preferences {
        guard preferencesReadable else { return .unreadable }
        guard let entry = preferences[service] else { return .none }
        return entry.map(OpenVPNDNS.Preferences.entity) ?? .none
    }

    func setServiceDNS(service: String, _ entity: DNSEntity?) -> Bool {
        writes.append("set \(service) " + (entity.map(Self.describe) ?? "removed"))
        if refusedWrites > 0 {
            refusedWrites -= 1
            return false
        }
        if lostWrites > 0 {
            lostWrites -= 1
            return true
        }
        services[service] = entity
        return true
    }

    func scriptBackups() -> [String: DNSEntity]? { storeReadable ? backups : nil }

    func removeScriptBackup(dev: String) -> Bool {
        writes.append("remove backup \(dev)")
        backups[dev] = nil
        return true
    }

    func tunnelDNS() -> [String: DNSEntity]? { storeReadable ? tunnels : nil }

    func removeTunnelDNS(dev: String) -> Bool {
        writes.append("remove tunnel \(dev)")
        tunnels[dev] = nil
        return true
    }

    func interfaceExists(_ name: String) -> Bool { interfaces.contains(name) }

    func serviceName(_ service: String) -> String? { names[service] }

    static func describe(_ e: DNSEntity) -> String {
        e.keys.sorted().map { key -> String in
            switch e[key]! {
            case .integer(let n): return "\(key)=\(n)"
            case let v: return "\(key)=" + (v.strings?.joined(separator: ",") ?? "?")
            }
        }.joined(separator: " ")
    }
}

final class OpenVPNDNSTests: XCTestCase {
    static let wifi = "8E3F0A1C-0000-4000-8000-00000000A001"
    static let ethernet = "8E3F0A1C-0000-4000-8000-00000000A002"

    /// A full-tunnel session: the VPN's servers and a search domain, no resolve domains.
    static let session = OpenVPNDNSSession(dev: "utun7", servers: ["10.8.0.1", "10.8.0.2"], searchDomains: ["corp.example.com"])

    var system: FakeDNSSystem!

    override func setUp() {
        system = FakeDNSSystem()
        system.names = [Self.wifi: "Wi-Fi", Self.ethernet: "Ethernet"]
        system.preferences = [Self.wifi: [:], Self.ethernet: nil]
    }

    static func strings(_ list: [String]) -> PlistValue { .array(list.map(PlistValue.string)) }

    // MARK: The session's record

    func testSessionFromRecordedVariables() throws {
        let record = """
            dev=utun7
            dns_search_domain_1=corp.example.com
            dns_search_domain_2=corp.example.com
            dns_search_domain_3=lab.example.com
            dns_server_1_address_1=192.0.2.53
            dns_server_1_transport=DoT
            dns_server_2_address_1=192.0.2.54
            dns_server_2_port_1=5353
            dns_server_3_address_1=10.8.0.1
            dns_server_3_address_2=2001:db8::53
            dns_server_3_port_2=53
            dns_server_3_dnssec=no
            dns_server_3_resolve_domain_1=corp.example.com

            """
        let variables = try XCTUnwrap(HelperCore.dnsVariables(record: record))
        let session = try XCTUnwrap(OpenVPNDNSSession(variables: variables))
        XCTAssertEqual(
            session,
            OpenVPNDNSSession(
                dev: "utun7", servers: ["10.8.0.1", "2001:db8::53"], searchDomains: ["corp.example.com", "lab.example.com"],
                matchDomains: ["corp.example.com"]),
            "the first server the script can use (no DoT, only port 53), the search domains once each")
        XCTAssertTrue(session.isSplit)

        let none = try XCTUnwrap(
            OpenVPNDNSSession(variables: ["dev": "utun7", "dns_server_1_address_1": "192.0.2.53", "dns_server_1_dnssec": "yes"]))
        XCTAssertEqual(none.servers, [], "no server the script can use: it sets nothing")
        XCTAssertEqual(OpenVPNDNS.settle(none, live: [], system: system), .done(restored: []))
        XCTAssertNil(OpenVPNDNSSession(variables: ["dev": "utun7/x", "dns_server_1_address_1": "10.8.0.1"]), "no key is built from that")
    }

    // MARK: Full branch

    /// The issue's case: the network went away, the script's dns-down found no primary service and left the
    /// VPN's DNS on Wi-Fi, whose preferences hold no DNS: the key goes.
    func testNetworkAwayLeavesNothingBehind() {
        system.services[Self.wifi] = Self.session.overrideEntity
        XCTAssertEqual(
            OpenVPNDNS.settle(Self.session, live: [], system: system),
            .done(restored: [OpenVPNDNS.Restored(serviceID: Self.wifi, service: "Wi-Fi", settings: ["10.8.0.1", "10.8.0.2"])]))
        XCTAssertNil(system.services[Self.wifi])
        XCTAssertEqual(system.writes, ["set \(Self.wifi) removed"])
        XCTAssertEqual(OpenVPNDNS.settle(Self.session, live: [], system: system), .done(restored: []), "nothing left")
    }

    /// A service whose preferences hold manual servers gets them back, as the preferences hold them.
    func testManualServersComeBack() {
        let manual: DNSEntity = ["ServerAddresses": Self.strings(["192.0.2.1"]), "SearchDomains": Self.strings(["home.example"])]
        system.preferences[Self.wifi] = manual
        system.services[Self.wifi] = Self.session.overrideEntity
        guard case .done(let restored) = OpenVPNDNS.settle(Self.session, live: [], system: system) else { return XCTFail() }
        XCTAssertEqual(restored.map(\.serviceID), [Self.wifi])
        XCTAssertEqual(system.services[Self.wifi], manual)
    }

    /// An empty or inactive entity in the preferences is none: configd publishes no key for it.
    func testWhatThePreferencesHoldIsWhatConfigdPublishes() {
        XCTAssertNil(OpenVPNDNS.normalized([:] as DNSEntity))
        XCTAssertNil(OpenVPNDNS.normalized(["__INACTIVE__": .bool(true), "ServerAddresses": Self.strings(["192.0.2.1"])]))
        XCTAssertEqual(
            OpenVPNDNS.normalized(["ServerAddresses": Self.strings(["192.0.2.1"]), "Sub": .dictionary(["a": .integer(1)])]),
            ["ServerAddresses": Self.strings(["192.0.2.1"])])
        system.preferences[Self.wifi] = ["__INACTIVE__": .bool(true)]
        system.services[Self.wifi] = Self.session.overrideEntity
        _ = OpenVPNDNS.settle(Self.session, live: [], system: system)
        XCTAssertNil(system.services[Self.wifi])
    }

    /// The primary service changed during the session: the script's dns-down looked at Ethernet and left Wi-Fi as
    /// it was. Only Wi-Fi changes.
    func testAnotherPrimaryServiceIsNotTouched() {
        system.preferences[Self.ethernet] = ["ServerAddresses": Self.strings(["192.0.2.1"])]
        system.services = [Self.wifi: Self.session.overrideEntity, Self.ethernet: ["ServerAddresses": Self.strings(["192.0.2.1"])]]
        guard case .done(let restored) = OpenVPNDNS.settle(Self.session, live: [], system: system) else { return XCTFail() }
        XCTAssertEqual(restored.map(\.service), ["Wi-Fi"])
        XCTAssertEqual(system.services[Self.ethernet], ["ServerAddresses": Self.strings(["192.0.2.1"])])
        XCTAssertEqual(system.writes, ["set \(Self.wifi) removed"])
    }

    /// Changed by someone else since the session set it (other servers, one more key, another search order): left.
    func testASettingSomeoneElseChangedIsLeft() {
        var changed = Self.session.overrideEntity
        changed["ServerAddresses"] = Self.strings(["10.8.0.1"])
        var more = Self.session.overrideEntity
        more["DomainName"] = .string("corp.example.com")
        var order = Self.session.overrideEntity
        order["SearchOrder"] = .integer(1)
        for entity in [changed, more, order, ["ServerAddresses": Self.strings(["10.8.0.1", "10.8.0.2"])]] {
            system.services[Self.wifi] = entity
            XCTAssertEqual(OpenVPNDNS.settle(Self.session, live: [], system: system), .done(restored: []))
            XCTAssertEqual(system.services[Self.wifi], entity)
        }
        XCTAssertEqual(system.writes, [])
    }

    /// The preferences hold exactly what the script set (someone configured those servers): nothing to do.
    func testPreferencesThatHoldTheSameAreLeft() {
        system.preferences[Self.wifi] = Self.session.overrideEntity
        system.services[Self.wifi] = Self.session.overrideEntity
        XCTAssertEqual(OpenVPNDNS.settle(Self.session, live: [], system: system), .done(restored: []))
        XCTAssertEqual(system.writes, [])
    }

    /// The script writes an empty search domain list when the server sent none.
    func testOverrideWithoutSearchDomains() {
        let session = OpenVPNDNSSession(dev: "utun7", servers: ["10.8.0.1"])
        system.services[Self.wifi] = ["ServerAddresses": Self.strings(["10.8.0.1"]), "SearchDomains": .array([]), "SearchOrder": .integer(5000)]
        guard case .done(let restored) = OpenVPNDNS.settle(session, live: [], system: system) else { return XCTFail() }
        XCTAssertEqual(restored.count, 1)
        system.services[Self.wifi] = ["ServerAddresses": Self.strings(["10.8.0.1"]), "SearchOrder": .integer(5000)]
        guard case .done(let again) = OpenVPNDNS.settle(session, live: [], system: system) else { return XCTFail() }
        XCTAssertEqual(again.count, 1)
    }

    /// Another running session set the same DNS (two profiles of one VPN): it may be that one's, which its own end
    /// settles. A running session with other DNS does not hold it.
    func testAnotherLiveSessionHoldsTheSameDNS() {
        system.services[Self.wifi] = Self.session.overrideEntity
        system.interfaces = ["utun8"]
        let same = OpenVPNDNSSession(dev: "utun8", servers: Self.session.servers, searchDomains: Self.session.searchDomains)
        XCTAssertEqual(OpenVPNDNS.settle(Self.session, live: [same], system: system), .done(restored: []))
        XCTAssertEqual(system.writes, [])

        let other = OpenVPNDNSSession(dev: "utun8", servers: ["10.9.0.1"])
        guard case .done(let restored) = OpenVPNDNS.settle(Self.session, live: [other], system: system) else { return XCTFail() }
        XCTAssertEqual(restored.map(\.serviceID), [Self.wifi])
    }

    /// The session's DNS was backed up by another running session of the script (its dns-up came while the VPN's DNS
    /// was still on the primary service): it comes back when that one ends, so the record stays (`parked`).
    func testParkedInTheBackupOfARunningSession() {
        system.interfaces = ["utun8"]
        system.backups["utun8"] = Self.session.overrideEntity
        system.services[Self.wifi] = ["ServerAddresses": Self.strings(["10.9.0.1"]), "SearchDomains": .array([]), "SearchOrder": .integer(5000)]
        XCTAssertEqual(OpenVPNDNS.settle(Self.session, live: [], system: system), .parked(restored: []))
        XCTAssertEqual(system.writes, [])
        // That session ended; its script put the backup back.
        system.backups = [:]
        system.interfaces = []
        system.services[Self.wifi] = Self.session.overrideEntity
        guard case .done(let restored) = OpenVPNDNS.settle(Self.session, live: [], system: system) else { return XCTFail() }
        XCTAssertEqual(restored.map(\.serviceID), [Self.wifi])
    }

    /// The session's own backup outlived it (its dns-down never got that far): once its tunnel is gone it goes, as
    /// it would make every later dns-up of the script fail. While a tunnel of that name exists, it stays.
    func testOwnStaleBackupIsRemovedOnceTheTunnelIsGone() {
        system.backups["utun7"] = [:]
        system.interfaces = ["utun7"]
        XCTAssertEqual(OpenVPNDNS.settle(Self.session, live: [], system: system), .done(restored: []))
        XCTAssertEqual(system.writes, [])
        system.interfaces = []
        XCTAssertEqual(OpenVPNDNS.settle(Self.session, live: [], system: system), .done(restored: []))
        XCTAssertEqual(system.writes, ["remove backup utun7"])
    }

    /// A repair that fails is reported with what is left, and the next try does it.
    func testAFailedRepairIsTriedAgain() {
        system.services[Self.wifi] = Self.session.overrideEntity
        let wifi = OpenVPNDNS.Restored(serviceID: Self.wifi, service: "Wi-Fi", settings: Self.session.servers)

        system.refusedWrites = 1
        XCTAssertEqual(
            OpenVPNDNS.settle(Self.session, live: [], system: system),
            .failed(reason: "the system configuration did not take the change", restored: [], left: [wifi]))
        system.lostWrites = 1
        XCTAssertEqual(
            OpenVPNDNS.settle(Self.session, live: [], system: system), .failed(reason: "the change did not hold", restored: [], left: [wifi]))
        system.preferencesReadable = false
        XCTAssertEqual(
            OpenVPNDNS.settle(Self.session, live: [], system: system),
            .failed(reason: "the network preferences cannot be read", restored: [], left: [wifi]))
        system.preferencesReadable = true
        system.storeReadable = false
        XCTAssertEqual(
            OpenVPNDNS.settle(Self.session, live: [], system: system),
            .failed(reason: "the system configuration cannot be read", restored: [], left: []))
        XCTAssertEqual(system.services[Self.wifi], Self.session.overrideEntity, "still there")

        system.storeReadable = true
        XCTAssertEqual(OpenVPNDNS.settle(Self.session, live: [], system: system), .done(restored: [wifi]))
        XCTAssertNil(system.services[Self.wifi])
    }

    // MARK: Split branch

    static let split = OpenVPNDNSSession(dev: "utun7", servers: ["10.8.0.1"], searchDomains: ["corp.example.com"], matchDomains: ["corp.example.com"])
    static let splitKey: DNSEntity = [
        "ServerAddresses": strings(["10.8.0.1"]), "SupplementalMatchDomains": strings(["corp.example.com"]),
        "SupplementalMatchDomainsNoSearch": .integer(1)
    ]

    /// Its own `State:` key goes once the tunnel is gone; the search domains it put on the then primary service go
    /// where the rest of that service's DNS is still what the preferences hold.
    func testSplitDNSAndItsSearchDomains() {
        system.tunnels["utun7"] = Self.splitKey
        system.preferences[Self.ethernet] = ["ServerAddresses": Self.strings(["192.0.2.1"])]
        system.services = [
            Self.wifi: ["SearchDomains": Self.strings(["corp.example.com", "home.example"])],
            Self.ethernet: ["ServerAddresses": Self.strings(["192.0.2.1"]), "SearchDomains": Self.strings(["corp.example.com"])]
        ]
        guard case .done(let restored) = OpenVPNDNS.settle(Self.split, live: [], system: system) else { return XCTFail() }
        XCTAssertEqual(Set(restored.map(\.serviceID)), [Self.wifi, Self.ethernet])
        XCTAssertEqual(restored.first?.settings, ["corp.example.com"])
        XCTAssertNil(system.services[Self.wifi])
        XCTAssertEqual(system.services[Self.ethernet], ["ServerAddresses": Self.strings(["192.0.2.1"])])
        XCTAssertNil(system.tunnels["utun7"])
    }

    func testSplitDNSThatOthersHoldOrChangedIsLeft() {
        // The tunnel is still there (another session has that name now): its key stays.
        system.tunnels["utun7"] = Self.splitKey
        system.interfaces = ["utun7"]
        // Someone changed the servers too; the search domains are not the session's first; a running split session
        // has its search domains there.
        system.services = [
            Self.wifi: ["ServerAddresses": Self.strings(["192.0.2.9"]), "SearchDomains": Self.strings(["corp.example.com"])],
            Self.ethernet: ["SearchDomains": Self.strings(["home.example", "corp.example.com"])]
        ]
        XCTAssertEqual(OpenVPNDNS.settle(Self.split, live: [], system: system), .done(restored: []))
        system.services = [Self.wifi: ["SearchDomains": Self.strings(["corp.example.com", "lab.example.com"])]]
        let other = OpenVPNDNSSession(dev: "utun8", servers: ["10.9.0.1"], searchDomains: ["lab.example.com"], matchDomains: ["lab.example.com"])
        XCTAssertEqual(OpenVPNDNS.settle(Self.split, live: [other], system: system), .done(restored: []))
        XCTAssertEqual(system.writes, [])
        XCTAssertEqual(system.tunnels["utun7"], Self.splitKey)
    }

    // MARK: Left behind

    /// The script's DNS with no session of the script running and no record: reported, never changed.
    func testLeftBehindIsOnlyReported() {
        system.services = [
            Self.wifi: [
                "ServerAddresses": Self.strings(["10.8.0.1"]), "SearchDomains": Self.strings(["corp.example.com"]), "SearchOrder": .integer(5000)
            ],
            Self.ethernet: ["ServerAddresses": Self.strings(["192.0.2.1"])]
        ]
        system.preferences[Self.ethernet] = ["ServerAddresses": Self.strings(["192.0.2.1"])]
        XCTAssertEqual(
            OpenVPNDNS.leftBehind(system: system), [OpenVPNDNS.LeftBehind(serviceID: Self.wifi, service: "Wi-Fi", servers: ["10.8.0.1"])])
        XCTAssertEqual(system.writes, [])

        // A session of the script is redirecting DNS now (its tunnel is there): that is its DNS.
        system.backups["utun3"] = [:]
        system.interfaces = ["utun3"]
        XCTAssertEqual(OpenVPNDNS.leftBehind(system: system), [])
        // A backup whose tunnel is gone holds up nothing.
        system.interfaces = []
        XCTAssertEqual(OpenVPNDNS.leftBehind(system: system)?.count, 1)
        // What the preferences hold is no leftover.
        system.preferences[Self.wifi] = system.services[Self.wifi]!
        XCTAssertEqual(OpenVPNDNS.leftBehind(system: system), [])
        system.storeReadable = false
        XCTAssertNil(OpenVPNDNS.leftBehind(system: system))
    }

    func testScriptOverrideShape() {
        XCTAssertTrue(OpenVPNDNS.isScriptOverride(["ServerAddresses": Self.strings(["10.8.0.1"]), "SearchOrder": .integer(5000)]))
        XCTAssertTrue(Self.session.overrideEntity.keys.count == 3 && OpenVPNDNS.isScriptOverride(Self.session.overrideEntity))
        XCTAssertFalse(OpenVPNDNS.isScriptOverride(["ServerAddresses": Self.strings(["10.8.0.1"])]))
        XCTAssertFalse(OpenVPNDNS.isScriptOverride(["ServerAddresses": .array([]), "SearchOrder": .integer(5000)]))
        XCTAssertFalse(
            OpenVPNDNS.isScriptOverride(["ServerAddresses": Self.strings(["10.8.0.1"]), "SearchOrder": .integer(5000), "DomainName": .string("x")]))
        XCTAssertFalse(OpenVPNDNS.isScriptOverride(["ServerAddresses": Self.strings(["10.8.0.1"]), "SearchOrder": .integer(1)]))
    }

    func testNamesAndKeys() {
        XCTAssertTrue(OpenVPNDNS.isDeviceName("utun12"))
        for bad in ["", "utun/1", "utun 1", "utun.1", String(repeating: "a", count: 16)] { XCTAssertFalse(OpenVPNDNS.isDeviceName(bad), bad) }
        XCTAssertTrue(OpenVPNDNS.isServiceID(Self.wifi))
        for bad in ["", "a/b", "a b", "..", "*", String(repeating: "a", count: 65)] { XCTAssertFalse(OpenVPNDNS.isServiceID(bad), bad) }
        system.services["a/b"] = Self.session.overrideEntity
        XCTAssertEqual(OpenVPNDNS.settle(Self.session, live: [], system: system), .done(restored: []), "a key no service ID names")
        XCTAssertEqual(OpenVPNDNS.name(of: Self.ethernet, system: system), "Ethernet")
        system.names[Self.ethernet] = "My “Office”\nLAN"
        XCTAssertEqual(OpenVPNDNS.name(of: Self.ethernet, system: system), "My  Office  LAN")
        system.names[Self.ethernet] = nil
        XCTAssertEqual(OpenVPNDNS.name(of: Self.ethernet, system: system), Self.ethernet)
    }

    // MARK: The Mac

    #if os(macOS)
    /// Reads only: the dynamic store and the network preferences of the Mac the tests run on, never written.
    func testMacSystemReadsTheStoreAndThePreferences() throws {
        let mac = MacOpenVPNDNSSystem(name: "PassTunnel tests")
        let services = try XCTUnwrap(mac.serviceDNS())
        XCTAssertNotNil(mac.scriptBackups())
        XCTAssertNotNil(mac.tunnelDNS())
        for (id, _) in services {
            XCTAssertTrue(OpenVPNDNS.isServiceID(id))
            XCTAssertNotEqual(mac.preferencesDNS(service: id), .unreadable, id)
        }
        XCTAssertEqual(mac.preferencesDNS(service: "00000000-0000-4000-8000-000000000000"), .none)
        XCTAssertEqual(mac.preferencesDNS(service: "a/b"), .unreadable, "never a path of another key")
        XCTAssertTrue(mac.interfaceExists("lo0"))
        XCTAssertFalse(mac.interfaceExists("utun999"))
        XCTAssertNotNil(OpenVPNDNS.leftBehind(system: mac))

        let entity: DNSEntity = [
            "ServerAddresses": Self.strings(["10.8.0.1"]), "SearchOrder": .integer(5000), "Weight": .real(0.5), "On": .bool(true),
            "Sub": .dictionary(["Data": .data(Data([1, 2])), "When": .date(Date(timeIntervalSince1970: 1))])
        ]
        XCTAssertEqual(MacOpenVPNDNSSystem.entity(MacOpenVPNDNSSystem.propertyList(.dictionary(entity))), entity)
    }
    #endif

    // MARK: Log lines

    func testNotesRoundTrip() {
        let notes = [
            OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: ["10.8.0.1", "2001:db8::53"]),
            OpenVPNDNS.Note(.notRestored, service: "USB 10/100 LAN", settings: ["10.8.0.1"], reason: "the change did not hold"),
            OpenVPNDNS.Note(.notRestored, service: "Wi-Fi", settings: ["corp.example.com"]),
            OpenVPNDNS.Note(.leftBehind, service: "Wi-Fi, 2", settings: ["10.8.0.1"])
        ]
        for note in notes {
            XCTAssertTrue(note.line.hasPrefix("PassTunnel helper: "), "never read as a failed start")
            XCTAssertFalse(note.line.contains("\n"))
            XCTAssertEqual(OpenVPNDNS.Note(line: note.line), note, note.line)
        }
        XCTAssertEqual(
            notes[0].line, "PassTunnel helper: restored the DNS of “Wi-Fi”, which still used the VPN's 10.8.0.1, 2001:db8::53")
        let log = "2026-11-22 11:12:01 SIGTERM received\n" + notes.map(\.line).joined(separator: "\n") + "\nPassTunnel helper: something else\n"
        XCTAssertEqual(OpenVPNDNS.Note.all(in: log), notes)
        for other in [
            "PassTunnel: restored the DNS of “Wi-Fi”, which still used the VPN's 10.8.0.1",
            "PassTunnel helper: restored the DNS of “”, which still used the VPN's 10.8.0.1",
            "PassTunnel helper: restored the DNS of “Wi-Fi”, which still used the VPN's ",
            "PassTunnel helper: the DNS of “Wi-Fi” still uses 10.8.0.1"
        ] {
            XCTAssertNil(OpenVPNDNS.Note(line: other), other)
        }
        XCTAssertEqual(OpenVPNDNS.Note(.restored, service: "x", settings: ["10.8.0.1", "a b", "$(id)"]).settings, ["10.8.0.1"])
    }
}
