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

    func testBigUIntArithmeticAndModExp() throws {
        let a = BigUInt(123456789)
        let b = BigUInt(987654321)
        let sum = a + b
        XCTAssertEqual(sum.description, BigUInt(1111111110).description)

        let diff = b - a
        XCTAssertEqual(diff.description, BigUInt(864197532).description)

        let prod = a * b
        XCTAssertTrue(prod > a)
        XCTAssertTrue(prod > b)

        // Test modular exponentiation: 2^10 mod 1000 = 1024 mod 1000 = 24
        let base = BigUInt(2)
        let exp = BigUInt(10)
        let modulus = BigUInt(1000)
        let result = base.power(exp, modulus: modulus)
        XCTAssertEqual(result, BigUInt(24))
    }

    func testSRPClientGenerationAndKeyDerivation() throws {
        let srp = SRPClient()
        let publicKeyA = srp.startAuthentication()
        XCTAssertEqual(publicKeyA.count, 256)
        XCTAssertFalse(publicKeyA.allSatisfy { $0 == 0 })

        let salt = Data(repeating: 0x5A, count: 16)
        let s2kKey = srp.derivePasswordKey(
            password: "MySecurePassword123!",
            salt: salt,
            iterations: 100,
            isS2KFO: false
        )
        XCTAssertNotNil(s2kKey)
        XCTAssertEqual(s2kKey?.count, 32)

        let s2kFOKey = srp.derivePasswordKey(
            password: "MySecurePassword123!",
            salt: salt,
            iterations: 100,
            isS2KFO: true
        )
        XCTAssertNotNil(s2kFOKey)
        XCTAssertEqual(s2kFOKey?.count, 32)
        XCTAssertNotEqual(s2kKey, s2kFOKey)
    }

    func testSRPChallengeProcessing() throws {
        let client = SRPClient()
        let clientA = client.startAuthentication()
        XCTAssertEqual(clientA.count, 256)

        let salt = Data(repeating: 0x12, count: 16)
        let dummyServerB = Data(repeating: 0x34, count: 256)

        guard let passwordKey = client.derivePasswordKey(
            password: "SuperSecretPassword!",
            salt: salt,
            iterations: 50,
            isS2KFO: false
        ) else {
            XCTFail("Failed to derive password key")
            return
        }

        let proofM1 = client.processChallenge(
            username: "tester@example.com",
            derivedPasswordKey: passwordKey,
            salt: salt,
            serverPublicKey: dummyServerB
        )

        XCTAssertNotNil(proofM1)
        XCTAssertEqual(proofM1?.count, 32)
        XCTAssertNotNil(client.sessionKey())
        XCTAssertEqual(client.sessionKey()?.count, 32)
    }

    func testGSAClientClientDictionary() throws {
        let client = GSAClient()
        let anisette = AnisetteData(
            machineID: "mach-1",
            oneTimePassword: "otp-1",
            localUserID: "user-1",
            routingInfo: "17106176",
            deviceID: "dev-1"
        )

        let dict = client.makeClientDictionary(anisette: anisette)
        XCTAssertEqual(dict["X-Apple-I-MD-M"] as? String, "mach-1")
        XCTAssertEqual(dict["X-Apple-I-MD"] as? String, "otp-1")
        XCTAssertEqual(dict["X-Apple-I-MD-LU"] as? String, "user-1")
        XCTAssertEqual(dict["bootstrap"] as? Bool, true)
    }

    func testRawIdentityDerPemConversion() throws {
        let rawCert = Data([0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x01])
        let rawKey = Data([0x30, 0x82, 0x02, 0x00, 0x02, 0x01, 0x00])

        let certPEM = RawIdentity.derToPEM(der: rawCert, type: "CERTIFICATE")
        XCTAssertTrue(certPEM.contains("-----BEGIN CERTIFICATE-----"))
        XCTAssertTrue(certPEM.contains("-----END CERTIFICATE-----"))

        let roundtripCert = RawIdentity.pemToDER(pem: certPEM)
        XCTAssertEqual(roundtripCert, rawCert)

        let identity = RawIdentity(
            certificateDER: rawCert,
            privateKeyDER: rawKey,
            certificatePEM: certPEM,
            privateKeyPEM: RawIdentity.derToPEM(der: rawKey, type: "RSA PRIVATE KEY")
        )
        XCTAssertEqual(identity.certificateDER, rawCert)
        XCTAssertEqual(identity.privateKeyDER, rawKey)
    }

    func testFetchCertificateRawInMemoryExtraction() throws {
        let auth = AppleAuth()
        let rawCert = Data([0x30, 0x05, 0x02, 0x01, 0x01, 0x00, 0x00])
        let rawKey = Data([0x30, 0x05, 0x02, 0x01, 0x00, 0x00, 0x00])

        let pemPayload = """
        -----BEGIN CERTIFICATE-----
        MAUCAQEAAA==
        -----END CERTIFICATE-----
        -----BEGIN RSA PRIVATE KEY-----
        MAUCAQAAAA==
        -----END RSA PRIVATE KEY-----
        """

        let identity = try auth.fetchCertificate(p12Data: Data(pemPayload.utf8), password: "")
        XCTAssertEqual(identity.certificateDER, rawCert)
        XCTAssertEqual(identity.privateKeyDER, rawKey)
    }

    func testBridgeSignerWithRawIdentity() throws {
        let bridge = BridgeSigner()
        XCTAssertNotNil(bridge)
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
