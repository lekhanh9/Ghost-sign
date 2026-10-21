//
//  DeveloperPortalClientTests.swift
//  GhostSignTests
//
//  Created for Ghost-Sign Milestone 2.
//

import XCTest
@testable import GhostSign
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - MockURLProtocol

final class MockURLProtocol: URLProtocol {
    nonisolated(unsafe) static var requestHandler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool {
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }

    override func startLoading() {
        guard let handler = Self.requestHandler else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "MockURLProtocol", code: -1, userInfo: [NSLocalizedDescriptionKey: "No handler registered"]))
            return
        }

        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

// MARK: - DeveloperPortalClientTests

final class DeveloperPortalClientTests: XCTestCase {

    override func setUp() {
        super.setUp()
        MockURLProtocol.requestHandler = nil
    }

    override func tearDown() {
        MockURLProtocol.requestHandler = nil
        super.tearDown()
    }

    private func makeClient(
        handler: @escaping (URLRequest) throws -> (HTTPURLResponse, Data)
    ) -> DeveloperPortalClient {
        MockURLProtocol.requestHandler = handler
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]

        let session = AuthSession(
            dsid: "99887766",
            authToken: "mock-xcode-auth-token-12345",
            idmsToken: "mock-idms-token",
            sessionKey: Data(repeating: 0x42, count: 32),
            anisetteData: AnisetteData(
                machineID: "mock-machine-id",
                oneTimePassword: "mock-otp",
                localUserID: "mock-user",
                routingInfo: "17106176",
                deviceID: "mock-device-id"
            )
        )

        return DeveloperPortalClient(session: session, sessionConfiguration: config)
    }

    // MARK: - Tests: Teams

    func testListTeamsSuccess() async throws {
        let xmlPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>resultCode</key>
            <integer>0</integer>
            <key>teams</key>
            <array>
                <dict>
                    <key>teamId</key>
                    <string>TEAM123456</string>
                    <key>name</key>
                    <string>Jane Doe (Personal Team)</string>
                    <key>type</key>
                    <string>Individual</string>
                    <key>status</key>
                    <string>active</string>
                    <key>memberships</key>
                    <array>
                        <dict>
                            <key>name</key>
                            <string>Free</string>
                            <key>status</key>
                            <string>active</string>
                        </dict>
                    </array>
                </dict>
            </array>
        </dict>
        </plist>
        """

        let client = makeClient { request in
            XCTAssertTrue(request.url?.absoluteString.contains("listTeams.action") == true)
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-Apple-GS-Token"), "mock-xcode-auth-token-12345")
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-Apple-I-Identity-Id"), "99887766")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(xmlPlist.utf8))
        }

        let teams = try await client.listTeams()
        XCTAssertEqual(teams.count, 1)
        XCTAssertEqual(teams[0].teamId, "TEAM123456")
        XCTAssertEqual(teams[0].name, "Jane Doe (Personal Team)")
        XCTAssertTrue(teams[0].isFreeAccount)
        XCTAssertEqual(teams[0].teamType, .free)
    }

    // MARK: - Tests: Devices

    func testListDevicesSuccess() async throws {
        let xmlPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>resultCode</key>
            <integer>0</integer>
            <key>devices</key>
            <array>
                <dict>
                    <key>deviceId</key>
                    <string>DEV123</string>
                    <key>deviceNumber</key>
                    <string>00008101-001234567890ABCD</string>
                    <key>name</key>
                    <string>iPhone 15 Pro</string>
                    <key>deviceClass</key>
                    <string>iphone</string>
                    <key>status</key>
                    <string>c</string>
                </dict>
            </array>
        </dict>
        </plist>
        """

        let client = makeClient { request in
            XCTAssertTrue(request.url?.absoluteString.contains("ios/listDevices.action") == true)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(xmlPlist.utf8))
        }

        let devices = try await client.listDevices(teamId: "TEAM123456")
        XCTAssertEqual(devices.count, 1)
        XCTAssertEqual(devices[0].deviceId, "DEV123")
        XCTAssertEqual(devices[0].deviceNumber, "00008101-001234567890ABCD")
        XCTAssertEqual(devices[0].name, "iPhone 15 Pro")
        XCTAssertTrue(devices[0].isActive)
    }

    func testAddDeviceAlreadyRegistered() async throws {
        let xmlPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>resultCode</key>
            <integer>35</integer>
            <key>userString</key>
            <string>A device with this UDID is already registered to this team.</string>
        </dict>
        </plist>
        """

        let client = makeClient { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(xmlPlist.utf8))
        }

        do {
            _ = try await client.addDevice(name: "Test iPhone", udid: "00008101-001234567890ABCD", teamId: "TEAM123456")
            XCTFail("Expected deviceAlreadyRegistered error")
        } catch let error as DeveloperPortalError {
            XCTAssertEqual(error, .deviceAlreadyRegistered)
        }
    }

    // MARK: - Tests: App IDs

    func testListAppIdsSuccess() async throws {
        let xmlPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>resultCode</key>
            <integer>0</integer>
            <key>appIds</key>
            <array>
                <dict>
                    <key>appIdId</key>
                    <string>APPID789</string>
                    <key>identifier</key>
                    <string>com.example.ghostsign</string>
                    <key>name</key>
                    <string>GhostSign App</string>
                    <key>prefix</key>
                    <string>TEAM123456</string>
                    <key>isWildCard</key>
                    <false/>
                </dict>
            </array>
        </dict>
        </plist>
        """

        let client = makeClient { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(xmlPlist.utf8))
        }

        let appIds = try await client.listAppIds(teamId: "TEAM123456")
        XCTAssertEqual(appIds.count, 1)
        XCTAssertEqual(appIds[0].identifier, "com.example.ghostsign")
        XCTAssertEqual(appIds[0].appIdId, "APPID789")
    }

    func testAddAppIdMaximumLimitReached() async throws {
        let xmlPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>resultCode</key>
            <integer>37</integer>
            <key>userString</key>
            <string>You cannot create more than 10 App IDs within 7 days.</string>
        </dict>
        </plist>
        """

        let client = makeClient { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(xmlPlist.utf8))
        }

        do {
            _ = try await client.addAppId(name: "Test", identifier: "com.test.app", teamId: "TEAM123456")
            XCTFail("Expected maximumAppIDLimitReached error")
        } catch let error as DeveloperPortalError {
            XCTAssertEqual(error, .maximumAppIDLimitReached)
        }
    }

    // MARK: - Tests: Certificates (Raw In-Memory Extraction)

    func testSubmitCSRAndExtractRawCertificateData() async throws {
        let fakeCertDER = Data([0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x01, 0x03])
        let base64Cert = fakeCertDER.base64EncodedString()

        let xmlPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>resultCode</key>
            <integer>0</integer>
            <key>certRequest</key>
            <dict>
                <key>certificateId</key>
                <string>CERT123</string>
                <key>name</key>
                <string>Apple Development: Jane Doe (XYZ1234567)</string>
                <key>status</key>
                <string>active</string>
                <key>serialNumber</key>
                <string>1234567890ABCDEF</string>
                <key>certContent</key>
                <data>\(base64Cert)</data>
            </dict>
        </dict>
        </plist>
        """

        let client = makeClient { request in
            XCTAssertTrue(request.url?.absoluteString.contains("ios/submitDevelopmentCSR.action") == true)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(xmlPlist.utf8))
        }

        let cert = try await client.addCertificate(csrPEM: "-----BEGIN CERTIFICATE REQUEST-----\nMOCK\n-----END CERTIFICATE REQUEST-----", teamId: "TEAM123456")

        XCTAssertEqual(cert.certificateId, "CERT123")
        XCTAssertEqual(cert.certContent, fakeCertDER)
        // Zero Keychain involvement: raw DER data is preserved directly in memory
        XCTAssertEqual(cert.certContent.count, fakeCertDER.count)
    }

    // MARK: - Tests: Provisioning Profiles (Raw In-Memory Extraction)

    func testCreateProvisioningProfileSuccess() async throws {
        let fakeProfileData = Data("Fake PKCS#7 Signed Mobileprovision Container".utf8)
        let base64Profile = fakeProfileData.base64EncodedString()

        let xmlPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>resultCode</key>
            <integer>0</integer>
            <key>provisioningProfile</key>
            <dict>
                <key>provisioningProfileId</key>
                <string>PROF456</string>
                <key>name</key>
                <string>iOS Team Provisioning Profile: com.example.ghostsign</string>
                <key>status</key>
                <string>active</string>
                <key>encodedProfile</key>
                <data>\(base64Profile)</data>
            </dict>
        </dict>
        </plist>
        """

        let client = makeClient { request in
            let urlString = request.url?.absoluteString ?? ""
            if urlString.contains("ios/listDevices.action") {
                let devicesPlist = """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0">
                <dict>
                    <key>resultCode</key>
                    <integer>0</integer>
                    <key>devices</key>
                    <array>
                        <dict>
                            <key>deviceId</key>
                            <string>DEV123</string>
                            <key>deviceNumber</key>
                            <string>00008101-001234567890ABCD</string>
                            <key>name</key>
                            <string>iPhone</string>
                        </dict>
                    </array>
                </dict>
                </plist>
                """
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (response, Data(devicesPlist.utf8))
            } else if urlString.contains("ios/createProvisioningProfile.action") {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (response, Data(xmlPlist.utf8))
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
            return (response, Data())
        }

        let profile = try await client.createProvisioningProfile(
            name: "iOS Team Provisioning Profile",
            bundleId: "APPID789",
            certificateId: "CERT123",
            deviceUDIDs: ["00008101-001234567890ABCD"],
            teamId: "TEAM123456"
        )

        XCTAssertEqual(profile.provisioningProfileId, "PROF456")
        XCTAssertEqual(profile.encodedProfile, fakeProfileData)
    }

    func testDownloadTeamProvisioningProfileSuccess() async throws {
        let fakeProfileData = Data("Fake Ephemeral Xcode Team Mobileprovision".utf8)
        let base64Profile = fakeProfileData.base64EncodedString()

        let xmlPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>resultCode</key>
            <integer>0</integer>
            <key>provisioningProfile</key>
            <dict>
                <key>provisioningProfileId</key>
                <string>TEAMPROF789</string>
                <key>name</key>
                <string>iOS Team Provisioning Profile: com.example.ghostsign</string>
                <key>status</key>
                <string>active</string>
                <key>encodedProfile</key>
                <data>\(base64Profile)</data>
            </dict>
        </dict>
        </plist>
        """

        let client = makeClient { request in
            XCTAssertTrue(request.url?.absoluteString.contains("ios/downloadTeamProvisioningProfile.action") == true)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(xmlPlist.utf8))
        }

        let profile = try await client.downloadTeamProvisioningProfile(appIdId: "APPID789", teamId: "TEAM123456")
        XCTAssertEqual(profile.provisioningProfileId, "TEAMPROF789")
        XCTAssertEqual(profile.encodedProfile, fakeProfileData)
    }

    // MARK: - Tests: Authentication & Network Errors

    func testUnauthenticatedErrorMapped() async throws {
        let xmlPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>resultCode</key>
            <integer>-22406</integer>
            <key>userString</key>
            <string>Your session has expired. Please log in.</string>
        </dict>
        </plist>
        """

        let client = makeClient { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 401, httpVersion: nil, headerFields: nil)!
            return (response, Data(xmlPlist.utf8))
        }

        do {
            _ = try await client.listTeams()
            XCTFail("Expected unauthenticated error")
        } catch let error as DeveloperPortalError {
            guard case .unauthenticated = error else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
    }

    // MARK: - Tests: End-to-End SideStore Sandbox Storage Flow (No Keychain)

    func testSideStoreSandboxStorageWithDownloadedAssets() async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let storage = FileStorageManager(baseDirectory: tempDir)
        let encryptionKey = FileStorageManager.generateKey()

        let fakeCertDER = Data([0x30, 0x82, 0x01, 0x55, 0x02, 0x01, 0x01])
        let fakeProfileData = Data("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist><dict><key>AppIDName</key><string>GhostApp</string></dict></plist>".utf8)

        // 1. Save certificate DER & profile encrypted in sandbox Documents
        let savedCertURL = try storage.saveIdentity(p12Data: fakeCertDER, filename: "apple_dev.cer", encryptionKey: encryptionKey)
        let savedProfileURL = try storage.saveProvisioningProfile(data: fakeProfileData, filename: "embedded.mobileprovision", encryptionKey: encryptionKey)

        XCTAssertTrue(FileManager.default.fileExists(atPath: savedCertURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: savedProfileURL.path))

        // 2. Load and decrypt in memory (zero Keychain)
        let loadedCert = try storage.loadIdentity(from: savedCertURL, decryptionKey: encryptionKey)
        let loadedProfile = try storage.loadProvisioningProfile(from: savedProfileURL, decryptionKey: encryptionKey)

        XCTAssertEqual(loadedCert, fakeCertDER)
        XCTAssertEqual(loadedProfile, fakeProfileData)

        try storage.clearAll()
    }
}
