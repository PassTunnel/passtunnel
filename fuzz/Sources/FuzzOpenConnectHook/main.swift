import Foundation
import FuzzSupport
import PassTunnelShared

// Fuzzes openconnect's hook, the part that runs as root on the server's values: the environment check
// (`OpenConnectNetwork`), the plan built from it (`OpenConnectPlan`), the session's record
// (`OpenConnectRecord`) and the report lines (`VPNHook`).
//
// Input: one byte of flags, then the environment as `NAME=VALUE` entries separated by NUL (as `environ`
// holds them). Flags: bit 0 Linux, bit 1 set_routes, bit 2 set_dns, bits 3–4 the default gateways (none,
// IPv4, both, one on the tunnel's own interface), bit 5 the rest is a record instead of an environment.
//
// Properties: nothing crashes or hangs; a refusal's description and failure line are one line of printable
// ASCII; an accepted network written back as variables parses to the same network, and every value in it
// passes its rule again; every change of a plan parses back from its text and never routes the default
// route; the record of a set-up reads back the same and reverts in reverse order; the report line is one
// line and parses back; a record that parses prints back byte for byte.
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    let bytes = [UInt8](fuzzData(data, size))
    guard let flags = bytes.first else { return 0 }
    let rest = Array(bytes.dropFirst())
    if flags & 0x20 != 0 {
        checkRecord(rest)
        return 0
    }
    let platform: OpenConnectNetwork.Platform = flags & 1 != 0 ? .linux : .macOS
    let policy = OpenConnectPolicy(uid: 501, profileID: "acme", setRoutes: flags & 2 != 0, setDNS: flags & 4 != 0)
    let v4 = OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "en0")
    let v6 = OpenConnectPlan.Gateway(address: IPAddress("fe80::1"), interface: "en0")
    let underlay: OpenConnectPlan.Underlay
    switch flags >> 3 & 3 {
    case 0: underlay = .init()
    case 1: underlay = .init(ipv4: v4)
    case 2: underlay = .init(ipv4: v4, ipv6: v6)
    default: underlay = .init(ipv4: OpenConnectPlan.Gateway(address: nil, interface: platform == .macOS ? "utun5" : "tun0"))
    }

    let entries = rest.split(separator: 0, omittingEmptySubsequences: true).map(Array.init)
    let event: OpenConnectNetwork.Event
    do {
        event = try OpenConnectNetwork.parse(.init(entries: entries), platform: platform)
    } catch {
        checkLine(VPNHook.failureLine(String(describing: error)))
        precondition(String(describing: error).utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7F }, "a refusal that is not printable")
        return 0
    }
    guard let network = event.network else { return 0 }
    checkNetwork(network, event: event, platform: platform)

    let plan: OpenConnectPlan
    do {
        plan = try OpenConnectPlan.connect(network, policy: policy, underlay: underlay)
    } catch {
        checkLine(VPNHook.failureLine(String(describing: error)))
        return 0
    }
    var record = OpenConnectRecord(interface: network.interface)!
    for change in plan.changes {
        let text = change.text
        precondition(OpenConnectPlan.Change(text: text) == change, "a change does not parse back")
        precondition(text.utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7F }, "a change that is not one line")
        if case .route(let route) = change {
            precondition(route.network.prefixLength > 0, "a plan that routes the default route")
            if case .interface(let name) = route.via { precondition(name == network.interface) }
            if case .reject = route.via { precondition(plan.blocked.contains(route.network.family)) }
            precondition(policy.setRoutes, "a route without set_routes")
        }
        if case .dns = change { precondition(policy.setDNS, "DNS without set_dns") }
        try! record.append(.begin(change))
        try! record.append(.owned(change))
    }
    try! record.append(.status(.up))
    precondition(record.toRevert == plan.changes.reversed(), "a revert that is not newest first")
    if let text = try? record.text() {
        precondition(OpenConnectRecord.parse(text) == record, "the record does not read back")
    }
    precondition(OpenConnectPlan.matches(network, policy: policy, underlay: underlay, record: record), "a set-up that does not match itself")
    let refresh = OpenConnectPlan.refresh(network, policy: policy, underlay: underlay, record: record)
    precondition(refresh.remove.isEmpty && refresh.add.isEmpty, "a refresh that changes nothing changed something")

    let report = VPNHook.Report(plan)
    checkLine(report.line)
    precondition(VPNHook.Report.parse(report.line[...]) == report, "the report line does not parse back")
    return 0
}

/// One line of printable ASCII and its line break.
func checkLine(_ line: String) {
    let utf8 = Array(line.utf8)
    precondition(utf8.last == 0x0A && utf8.dropLast().allSatisfy { $0 >= 0x20 && $0 < 0x7F }, "a report that is not one line")
    precondition(line.hasPrefix(VPNHook.linePrefix))
}

func checkNetwork(_ n: OpenConnectNetwork, event: OpenConnectNetwork.Event, platform: OpenConnectNetwork.Platform) {
    precondition(OpenConnectNetwork.isTunnelInterface(n.interface, platform: platform))
    precondition(OpenConnectNetwork.mtuRange.contains(n.mtu))
    precondition(n.ipv4 != nil || n.ipv6 != nil)
    precondition(n.ipv6 == nil || n.mtu >= OpenConnectNetwork.minIPv6MTU)
    for address in [n.gateway] + [n.ipv4?.address, n.ipv6?.address].compactMap({ $0 }) + n.dnsServers {
        precondition(IPAddress(address.description) == address, "an address that does not validate again")
    }
    for domain in n.defaultDomains + n.splitDNSDomains {
        precondition(DomainName.normalize(domain) == domain, "a domain that does not validate again")
    }
    precondition(n.dnsServers.count <= OpenConnectNetwork.maxDNSServers)
    precondition(n.defaultDomains.count <= OpenConnectNetwork.maxDomains && n.splitDNSDomains.count <= OpenConnectNetwork.maxDomains)
    for list in [n.ipv4Includes, n.ipv4Excludes, n.ipv6Includes, n.ipv6Excludes] {
        precondition(list.count <= OpenConnectNetwork.maxSplitRoutes)
        for net in list { precondition(IPNetwork(net.description) == net, "a network that does not validate again") }
    }
    let again = try? OpenConnectNetwork.parse(.init(n.environment(reason: event.reason)), platform: platform)
    precondition(again == event, "the network written back does not parse to itself")
}

func checkRecord(_ bytes: [UInt8]) {
    let text = String(decoding: bytes, as: UTF8.self)
    guard let record = OpenConnectRecord.parse(text) else { return }
    precondition(Array((try! record.text()).utf8) == bytes, "a record that does not print back byte for byte")
    let compact = record.compacted()
    precondition(OpenConnectRecord.parse(try! compact.text()) == compact, "a compacted record does not read back")
    precondition(compact.toRevert == record.toRevert && compact.applied == record.applied && compact.status == record.status)
}

runFuzzer(LLVMFuzzerTestOneInput)
