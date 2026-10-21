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

    func testAnisetteHeadersGeneration() throws {
        let anisette = AnisetteData(
            machineID: "test-machine",
            oneTimePassword: "test-otp",
            localUserID: "test-user",
            routingInfo: "17106176",
            deviceID: "test-device"
        )

        let headers = anisette.toHTTPHeaders()
        XCTAssertEqual(headers["X-Apple-I-MD-M"], "test-machine")
        XCTAssertEqual(headers["X-Apple-I-MD"], "test-otp")
        XCTAssertEqual(headers["X-Apple-I-MD-LU"], "test-user")
        XCTAssertEqual(headers["X-Apple-I-MD-RINFO"], "17106176")
        XCTAssertEqual(headers["X-Mme-Device-Id"], "test-device")
    }

    func testAuthSessionValidity() throws {
        let session = AuthSession(
            dsid: "12345678",
            authToken: "auth-token-xyz",
            idmsToken: "idms-token-abc",
            sessionKey: Data(repeating: 0x01, count: 32),
            anisetteData: AnisetteData(),
            creationDate: Date(),
            expirationDate: Date().addingTimeInterval(3600)
        )

        XCTAssertTrue(session.isValid)
        XCTAssertFalse(session.isExpired)

        let expiredSession = AuthSession(
            dsid: "12345678",
            authToken: "auth-token-xyz",
            idmsToken: "idms-token-abc",
            sessionKey: Data(repeating: 0x01, count: 32),
            anisetteData: AnisetteData(),
            creationDate: Date().addingTimeInterval(-7200),
            expirationDate: Date().addingTimeInterval(-3600)
        )

        XCTAssertFalse(expiredSession.isValid)
        XCTAssertTrue(expiredSession.isExpired)
    }

    func testAppleAuthLogin() async throws {
        let auth = AppleAuth()
        let result = try await auth.startLogin(appleID: "developer@example.com", password: "SecretPassword123!")

        switch result {
        case .authenticated(let session):
            XCTAssertFalse(session.dsid.isEmpty)
            XCTAssertFalse(session.authToken.isEmpty)
            XCTAssertFalse(session.idmsToken.isEmpty)
            XCTAssertEqual(session.sessionKey.count, 32)
        case .requires2FA:
            XCTFail("Did not expect 2FA for mock test")
        }
    }

    func testAppleAuthSubmit2FACode() async throws {
        let auth = AppleAuth()
        let context = TwoFactorContext(
            appleID: "developer@example.com",
            dsid: "12345678",
            idmsToken: "dummy-idms",
            sessionKey: Data(repeating: 0x01, count: 32),
            spdData: Data(),
            anisetteData: AnisetteData()
        )

        let session = try await auth.submit2FACode(code: "123456", context: context)
        XCTAssertEqual(session.dsid, "12345678")
        XCTAssertFalse(session.authToken.isEmpty)
    }

    func testAppleAuthEmptyCredentialsThrow() async {
        let auth = AppleAuth()
        do {
            _ = try await auth.startLogin(appleID: "", password: "")
            XCTFail("Expected empty credentials to throw")
        } catch let error as AppleAuthError {
            guard case .invalidCredentials = error else {
                XCTFail("Unexpected error type: \(error)")
                return
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}
