import XCTest

@testable import PassTunnelShared

final class SmokeTests: XCTestCase {
    func testIdentifiers() { XCTAssertEqual(PT.keychainService, "PassTunnel") }
}
