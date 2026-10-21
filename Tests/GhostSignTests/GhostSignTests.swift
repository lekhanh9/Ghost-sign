import XCTest
@testable import GhostSign

final class GhostSignTests: XCTestCase {
    func testInitialization() throws {
        let auth = AppleAuth()
        XCTAssertNotNil(auth)
    }
}
