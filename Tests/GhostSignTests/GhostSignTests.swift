import XCTest
@testable import GhostSign
import GhostCode
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class GhostSignTests: XCTestCase {
    func testInitialization() throws {
        let auth = AppleAuth()
        XCTAssertNotNil(auth)
    }

    private func makeAnisetteProvider(
        handler: @escaping (URLRequest) throws -> (HTTPURLResponse, Data)
    ) -> RemoteAnisetteProvider {
        MockURLProtocol.requestHandler = handler
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return RemoteAnisetteProvider(
            serverURL: URL(string: "https://anisette.example.com")!,
            urlSession: URLSession(configuration: config)
        )
    }

    func testRemoteAnisetteProviderUsesServerHeadersVerbatim() async throws {
        let payload = """
        {
          "X-Apple-I-MD": "otp-value",
          "X-Apple-I-MD-M": "machine-value",
          "X-MMe-Client-Info": "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
          "X-Mme-Device-Id": "DEVICE-ID-1",
          "User-Agent": "AuthKit/1 (Macintosh; OS X 13.1)"
        }
        """

        let provider = makeAnisetteProvider { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(payload.utf8))
        }

        let anisette = try await provider.fetchAnisetteData()
        XCTAssertEqual(anisette.oneTimePassword, "otp-value")
        XCTAssertEqual(anisette.machineID, "machine-value")
        XCTAssertEqual(anisette.clientInfo, "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>")
        XCTAssertEqual(anisette.deviceID, "DEVICE-ID-1")
        XCTAssertEqual(anisette.userAgent, "AuthKit/1 (Macintosh; OS X 13.1)")
    }

    func testRemoteAnisetteProviderMatchesHeaderCasingAndOmitsMissingUserAgent() async throws {
        let payload = """
        {
          "X-Apple-I-MD-M": "machine-value",
          "X-Mme-Client-Info": "<Mac> client-info",
          "X-Mme-Device-Id": "DEVICE-ID-2"
        }
        """

        let provider = makeAnisetteProvider { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(payload.utf8))
        }

        let anisette = try await provider.fetchAnisetteData()
        XCTAssertEqual(anisette.clientInfo, "<Mac> client-info")
        XCTAssertEqual(anisette.userAgent, "")
    }

    func testRemoteAnisetteProviderRequiresClientInfo() async throws {
        let payload = """
        {
          "X-Apple-I-MD": "otp-value",
          "X-Apple-I-MD-M": "machine-value"
        }
        """

        let provider = makeAnisetteProvider { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(payload.utf8))
        }

        do {
            _ = try await provider.fetchAnisetteData()
            XCTFail("Expected missingHeader error")
        } catch let error as AnisetteError {
            guard case .missingHeader = error else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
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

    func testBridgeSignerWithDeveloperPortalAssets() throws {
        let bridge = BridgeSigner()
        let cert = DeveloperCertificate(certificateId: "CERT123", name: "Dev Cert", certContent: Data([0x30, 0x05, 0x02, 0x01, 0x01, 0x00, 0x00]))
        let profile = DeveloperProvisioningProfile(provisioningProfileId: "PROF123", encodedProfile: Data("Fake Profile".utf8))
        XCTAssertNotNil(cert)
        XCTAssertNotNil(profile)
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

    func testFileStorageManagerSaveAndLoadUnencryptedIdentity() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let storage = FileStorageManager(baseDirectory: tempDir)

        let mockP12 = Data([0x30, 0x82, 0x01, 0x23, 0x45, 0x67, 0x89])
        let savedURL = try storage.saveIdentity(p12Data: mockP12, filename: "test.p12")
        XCTAssertTrue(FileManager.default.fileExists(atPath: savedURL.path))

        let loaded = try storage.loadIdentity(from: savedURL)
        XCTAssertEqual(loaded, mockP12)

        try storage.clearAll()
    }

    func testFileStorageManagerAESGCMEncryptionAtRest() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let storage = FileStorageManager(baseDirectory: tempDir)

        let mockP12 = Data("Sensitive PKCS#12 Identity Data for Sideloading".utf8)
        let key = FileStorageManager.generateKey()

        let savedURL = try storage.saveIdentity(p12Data: mockP12, filename: "encrypted_identity.p12", encryptionKey: key)

        // Raw file on disk must be encrypted and NOT equal to plain text
        let rawDiskData = try Data(contentsOf: savedURL)
        XCTAssertNotEqual(rawDiskData, mockP12)

        // Decryption with the proper key must recover original data
        let decrypted = try storage.loadIdentity(from: savedURL, decryptionKey: key)
        XCTAssertEqual(decrypted, mockP12)

        // Decryption with a wrong key must throw
        let wrongKey = FileStorageManager.generateKey()
        XCTAssertThrowsError(try storage.loadIdentity(from: savedURL, decryptionKey: wrongKey))

        try storage.clearAll()
    }

    func testFileStorageManagerProvisioningProfileSaveAndLoad() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let storage = FileStorageManager(baseDirectory: tempDir)

        let mockProfile = Data("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist><dict><key>AppIDName</key><string>GhostApp</string></dict></plist>".utf8)
        let key = FileStorageManager.deriveKey(from: "my-passphrase-123")

        let savedURL = try storage.saveProvisioningProfile(data: mockProfile, filename: "test.mobileprovision", encryptionKey: key)
        XCTAssertTrue(FileManager.default.fileExists(atPath: savedURL.path))

        let loaded = try storage.loadProvisioningProfile(from: savedURL, decryptionKey: key)
        XCTAssertEqual(loaded, mockProfile)

        let profiles = try storage.listStoredProfiles()
        XCTAssertEqual(profiles.count, 1)
        XCTAssertEqual(profiles.first?.lastPathComponent, "test.mobileprovision")

        try storage.clearAll()
    }

    func testFileStorageManagerPEMIdentityExtraction() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let storage = FileStorageManager(baseDirectory: tempDir)

        let rawCert = Data([0x30, 0x05, 0x02, 0x01, 0x01, 0x00, 0x00])
        let rawKey = Data([0x30, 0x05, 0x02, 0x01, 0x00, 0x00, 0x00])
        let identity = RawIdentity(certificateDER: rawCert, privateKeyDER: rawKey)

        let key = FileStorageManager.generateKey()
        let pemURL = try storage.saveRawIdentityAsPEM(identity: identity, filename: "identity.pem", encryptionKey: key)

        let loadedData = try storage.loadIdentity(from: pemURL, decryptionKey: key)
        guard let pemString = String(data: loadedData, encoding: .utf8) else {
            XCTFail("Failed to convert decrypted data to UTF-8")
            return
        }

        let parsed = RawIdentity.parsePEMIdentity(pemString: pemString)
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.certificateDER, rawCert)
        XCTAssertEqual(parsed?.privateKeyDER, rawKey)

        try storage.clearAll()
    }

    func testFileStorageManagerListingAndDeletion() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let storage = FileStorageManager(baseDirectory: tempDir)

        let p12URL = try storage.saveIdentity(p12Data: Data([0x01, 0x02]), filename: "app1.p12")
        let profURL = try storage.saveProvisioningProfile(data: Data([0x03, 0x04]), filename: "app1.mobileprovision")

        var identities = try storage.listStoredIdentities()
        var profiles = try storage.listStoredProfiles()
        XCTAssertEqual(identities.count, 1)
        XCTAssertEqual(profiles.count, 1)

        try storage.deleteItem(at: p12URL)
        identities = try storage.listStoredIdentities()
        XCTAssertEqual(identities.count, 0)

        try storage.deleteItem(at: profURL)
        profiles = try storage.listStoredProfiles()
        XCTAssertEqual(profiles.count, 0)

        try storage.clearAll()
    }

    func testConstantsValuesAndFormatting() {
        XCTAssertEqual(Constants.GrandSlam.service, "iCloud")
        XCTAssertEqual(Constants.GrandSlam.authApp, "com.apple.gs.xcode.auth")
        XCTAssertEqual(Constants.DeveloperServices.protocolVersion, "QH65B2")
        XCTAssertEqual(Constants.DeveloperServices.clientID, "XABBG36SBA")

        XCTAssertEqual(Constants.ResultCodes.success, 0)
        XCTAssertEqual(Constants.ResultCodes.invalidCertificateRequest, 3250)
        XCTAssertEqual(Constants.ResultCodes.deviceAlreadyRegistered, 35)
        XCTAssertEqual(Constants.ResultCodes.maximumAppIDLimitReached, 37)
        XCTAssertEqual(Constants.ResultCodes.maximumCertificatesReachedAlternate, 7460)
        XCTAssertEqual(Constants.ResultCodes.profileNotFoundAlternate, 8201)
        XCTAssertEqual(Constants.ResultCodes.profileNotFound, 9115)
        XCTAssertEqual(Constants.ResultCodes.sessionExpired, -22406)

        XCTAssertEqual(Constants.HTTPStatusCodes.ok, 200)
        XCTAssertEqual(Constants.HTTPStatusCodes.unauthorized, 401)
        XCTAssertEqual(Constants.HTTPStatusCodes.notFound, 404)
        XCTAssertFalse(Constants.HTTPStatusCodes.localizedDescription(for: 401).isEmpty)
        XCTAssertFalse(Constants.HTTPStatusCodes.localizedDescription(for: 500).isEmpty)

        XCTAssertEqual(Constants.Storage.defaultBaseDirectoryName, "GhostSign")
        XCTAssertEqual(Constants.Storage.identitiesDirectoryName, "Identities")
        XCTAssertEqual(Constants.Storage.profilesDirectoryName, "Profiles")
    }

    func testProvisioningProfileParsingAndMatching() throws {
        let profilePlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Name</key>
            <string>ContraStore Dev Profile</string>
            <key>TeamIdentifier</key>
            <array>
                <string>ABC123TEAM</string>
            </array>
            <key>TeamName</key>
            <string>Contra Team</string>
            <key>UUID</key>
            <string>12345678-ABCD-1234-ABCD-1234567890AB</string>
            <key>Entitlements</key>
            <dict>
                <key>application-identifier</key>
                <string>ABC123TEAM.com.contra.store</string>
                <key>com.apple.developer.team-identifier</key>
                <string>ABC123TEAM</string>
                <key>get-task-allow</key>
                <true/>
                <key>keychain-access-groups</key>
                <array>
                    <string>ABC123TEAM.*</string>
                </array>
            </dict>
        </dict>
        </plist>
        """

        let profile = try ProvisioningProfile(data: Data(profilePlist.utf8))
        XCTAssertEqual(profile.name, "ContraStore Dev Profile")
        XCTAssertEqual(profile.teamIdentifier, "ABC123TEAM")
        XCTAssertEqual(profile.bundleIdentifier, "com.contra.store")
        XCTAssertTrue(profile.matches(bundleIdentifier: "com.contra.store"))
        XCTAssertFalse(profile.matches(bundleIdentifier: "com.other.app"))

        let wildcardProfilePlist = profilePlist.replacingOccurrences(of: "com.contra.store", with: "com.contra.*")
        let wildcardProfile = try ProvisioningProfile(data: Data(wildcardProfilePlist.utf8))
        XCTAssertTrue(wildcardProfile.matches(bundleIdentifier: "com.contra.store"))
        XCTAssertTrue(wildcardProfile.matches(bundleIdentifier: "com.contra.widget"))
        XCTAssertFalse(wildcardProfile.matches(bundleIdentifier: "com.other.app"))
    }

    func testAppBundleDiscoveryAndEntitlementsRewriting() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let appDir = tempDir.appendingPathComponent("TestApp.app")
        let pluginsDir = appDir.appendingPathComponent("PlugIns")
        let extDir = pluginsDir.appendingPathComponent("TestWidget.appex")
        try FileManager.default.createDirectory(at: extDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Main app Info.plist
        let appPlist: [String: Any] = [
            "CFBundleIdentifier": "com.test.app",
            "CFBundleExecutable": "TestApp",
            "CFBundleDisplayName": "Test App",
            "CFBundleShortVersionString": "2.0",
            "CFBundleVersion": "200"
        ]
        let appPlistData = try PropertyListSerialization.data(fromPropertyList: appPlist, format: .xml, options: 0)
        try appPlistData.write(to: appDir.appendingPathComponent("Info.plist"))
        try Data("binary".utf8).write(to: appDir.appendingPathComponent("TestApp"))

        // Extension Info.plist
        let extPlist: [String: Any] = [
            "CFBundleIdentifier": "com.test.app.widget",
            "CFBundleExecutable": "TestWidget",
            "CFBundleDisplayName": "Test Widget"
        ]
        let extPlistData = try PropertyListSerialization.data(fromPropertyList: extPlist, format: .xml, options: 0)
        try extPlistData.write(to: extDir.appendingPathComponent("Info.plist"))
        try Data("binary".utf8).write(to: extDir.appendingPathComponent("TestWidget"))

        // Validate AppBundle discovery
        guard let bundle = AppBundle(fileURL: appDir) else {
            XCTFail("Failed to load AppBundle")
            return
        }
        XCTAssertEqual(bundle.bundleIdentifier, "com.test.app")
        XCTAssertEqual(bundle.name, "Test App")
        XCTAssertEqual(bundle.executableName, "TestApp")
        XCTAssertEqual(bundle.appExtensions.count, 1)
        XCTAssertEqual(bundle.appExtensions.first?.bundleIdentifier, "com.test.app.widget")

        // Test EntitlementModifier keychain rewriting
        let profilePlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Name</key>
            <string>Test Profile</string>
            <key>TeamIdentifier</key>
            <array>
                <string>NEWTEAM123</string>
            </array>
            <key>UUID</key>
            <string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string>
            <key>Entitlements</key>
            <dict>
                <key>application-identifier</key>
                <string>NEWTEAM123.com.test.app</string>
                <key>com.apple.developer.team-identifier</key>
                <string>NEWTEAM123</string>
                <key>get-task-allow</key>
                <true/>
            </dict>
        </dict>
        </plist>
        """
        let profile = try ProvisioningProfile(data: Data(profilePlist.utf8))
        let ents = EntitlementModifier.makeEntitlements(for: bundle, profile: profile)
        XCTAssertEqual(ents["application-identifier"] as? String, "NEWTEAM123.com.test.app")
        XCTAssertEqual(ents["com.apple.developer.team-identifier"] as? String, "NEWTEAM123")
        XCTAssertEqual(ents["get-task-allow"] as? Bool, true)

        // Ad-hoc mode
        let adHocEnts = EntitlementModifier.makeEntitlements(for: bundle, profile: nil)
        XCTAssertEqual(adHocEnts["application-identifier"] as? String, "com.test.app")
        XCTAssertEqual(adHocEnts["get-task-allow"] as? Bool, true)

        // Dump info test
        let info = bundle.dumpInfo()
        XCTAssertTrue(info.contains("com.test.app"))
        XCTAssertTrue(info.contains("TestWidget"))
    }

    func testAdHocProfileGeneration() throws {
        let adHoc = ProvisioningProfile.createAdHoc(bundleIdentifier: "com.SideStore.SideStore")
        XCTAssertEqual(adHoc.bundleIdentifier, "com.SideStore.SideStore")
        XCTAssertTrue(adHoc.matches(bundleIdentifier: "com.SideStore.SideStore"))
        XCTAssertFalse(adHoc.data.isEmpty)

        // Verify XML can be parsed by any AltStore/SideStore reader
        let parsed = try ProvisioningProfile(data: adHoc.data)
        XCTAssertEqual(parsed.bundleIdentifier, "com.SideStore.SideStore")
        XCTAssertEqual(parsed.teamIdentifier, "ADHOC12345")
        XCTAssertEqual(parsed.entitlements["get-task-allow"] as? Bool, true)
    }

    func testDeveloperAppGroupModel() throws {
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>name</key>
            <string>SideStore App Group</string>
            <key>identifier</key>
            <string>group.com.SideStore.SideStore</string>
            <key>applicationGroup</key>
            <string>GRP123456</string>
        </dict>
        </plist>
        """
        let group = try PropertyListDecoder().decode(DeveloperAppGroup.self, from: Data(plist.utf8))
        XCTAssertEqual(group.name, "SideStore App Group")
        XCTAssertEqual(group.identifier, "group.com.SideStore.SideStore")
        XCTAssertEqual(group.applicationGroup, "GRP123456")
    }

    func testSessionManagerPersistenceAndEncryption() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let anisette = AnisetteData(
            machineID: "test-machine",
            oneTimePassword: "test-otp",
            localUserID: "test-lu",
            routingInfo: "17106176",
            deviceID: "DEVICE-123",
            clientInfo: "<MacBookPro16,1> <macOS;14.0;23A344>",
            userAgent: "AuthKit/1 (Macintosh; OS X 14.0)"
        )

        let session = AuthSession(
            dsid: "1234567890",
            authToken: "GS_TOKEN_ABCXYZ",
            idmsToken: "IDMS_TOKEN_123",
            sessionKey: Data([1, 2, 3, 4, 5, 6, 7, 8]),
            anisetteData: anisette,
            expirationDate: Date().addingTimeInterval(3600),
            teamID: "TEAM123456"
        )

        // 1. Auto machine encryption mode (no password)
        let savedURL = try SessionManager.save(session, identifier: "dev", directory: tempDir)
        XCTAssertTrue(FileManager.default.fileExists(atPath: savedURL.path))

        let loaded = try SessionManager.load(identifier: "dev", from: savedURL)
        XCTAssertEqual(loaded.dsid, "1234567890")
        XCTAssertEqual(loaded.authToken, "GS_TOKEN_ABCXYZ")
        XCTAssertEqual(loaded.idmsToken, "IDMS_TOKEN_123")
        XCTAssertEqual(loaded.teamID, "TEAM123456")
        XCTAssertEqual(loaded.anisetteData.machineID, "test-machine")
        XCTAssertEqual(loaded.anisetteData.oneTimePassword, "test-otp")
        XCTAssertFalse(loaded.isExpired)

        // 2. Custom password encryption mode
        let pwdURL = try SessionManager.save(session, identifier: "secure", directory: tempDir, password: "SecretPassword123")
        let loadedWithPwd = try SessionManager.load(from: pwdURL, password: "SecretPassword123")
        XCTAssertEqual(loadedWithPwd.dsid, "1234567890")

        // 3. Failed password decryption
        XCTAssertThrowsError(try SessionManager.load(from: pwdURL, password: "WrongPassword"))

        // 4. Listing sessions
        let sessionsList = SessionManager.listSessions(in: tempDir)
        XCTAssertEqual(sessionsList.count, 2)

        // 5. Deletion
        try SessionManager.deleteSession(identifier: "dev", at: savedURL)
        XCTAssertFalse(SessionManager.hasSession(identifier: "dev", in: tempDir))
    }

    func testDynamicAnisetteHeadersGeneration() throws {
        let anisette = AnisetteData(
            machineID: "machine-1",
            oneTimePassword: "otp-999",
            localUserID: "lu-1",
            routingInfo: "17106176",
            deviceID: "dev-id",
            serialNumber: "SERIAL123",
            clientInfo: "<iPhone14,2> <iOS;17.0;21A329>",
            userAgent: "Xcode/15.4"
        )

        let headers = anisette.toHTTPHeaders()
        XCTAssertEqual(headers["X-Apple-I-MD"], "otp-999")
        XCTAssertEqual(headers["X-Apple-I-MD-M"], "machine-1")
        XCTAssertEqual(headers["X-Apple-I-MD-LU"], "lu-1")
        XCTAssertEqual(headers["X-Apple-I-MD-RINFO"], "17106176")
        XCTAssertEqual(headers["X-Mme-Device-Id"], "dev-id")
        XCTAssertEqual(headers["X-Apple-I-SRL-NO"], "SERIAL123")
        XCTAssertEqual(headers["X-MMe-Client-Info"], "<iPhone14,2> <iOS;17.0;21A329>")
        XCTAssertEqual(headers["X-Apple-I-Client-Info"], "<iPhone14,2> <iOS;17.0;21A329>")
        XCTAssertEqual(headers["User-Agent"], "Xcode/15.4")
        XCTAssertFalse(headers["X-Apple-I-Client-Time"]?.isEmpty ?? true)
    }
}
