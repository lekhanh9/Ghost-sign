import XCTest
@testable import GhostSign
import GhostCode

final class GhostSignTests: XCTestCase {
    func testInitialization() throws {
        let auth = AppleAuth()
        XCTAssertNotNil(auth)
    }

    func testBridgeSignerInitialization() throws {
        let bridge = BridgeSigner()
        XCTAssertNotNil(bridge)
    }
}
