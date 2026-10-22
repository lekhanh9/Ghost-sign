import XCTest
@testable import GhostSign
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class AppleClientConfigurationTests: XCTestCase {
    func testDefaultsMatchExistingSpoofedIdentity() {
        let configuration = AppleClientConfiguration()
        XCTAssertEqual(configuration.userAgent, GhostSignConstants.GrandSlam.userAgent)
        XCTAssertEqual(configuration.clientInfo, AppleClientConfiguration.defaultClientInfo)
    }

    func testBlankValuesFallBackToDefaults() {
        let configuration = AppleClientConfiguration(userAgent: "   ", clientInfo: "\n\t")
        XCTAssertEqual(configuration.userAgent, AppleClientConfiguration.defaultUserAgent)
        XCTAssertEqual(configuration.clientInfo, AppleClientConfiguration.defaultClientInfo)
    }

    func testHeaderInjectionCharactersAreStripped() {
        let configuration = AppleClientConfiguration(
            userAgent: "Agent\r\nX-Evil: yes",
            clientInfo: "Info\nInjected"
        )
        XCTAssertEqual(configuration.userAgent, "AgentX-Evil: yes")
        XCTAssertEqual(configuration.clientInfo, "InfoInjected")
    }

    func testApplyingOverridesAnisetteIdentity() {
        let anisette = AnisetteData(
            machineID: "machine",
            oneTimePassword: "otp",
            localUserID: "user",
            routingInfo: "17106176",
            deviceID: "device",
            clientInfo: "server-client-info",
            userAgent: "server-user-agent"
        )
        let configuration = AppleClientConfiguration(
            userAgent: "CustomAgent",
            clientInfo: "CustomClientInfo"
        )

        let configured = configuration.applying(to: anisette)
        XCTAssertEqual(configured.userAgent, "CustomAgent")
        XCTAssertEqual(configured.clientInfo, "CustomClientInfo")
        XCTAssertEqual(configured.machineID, "machine")
        XCTAssertEqual(configured.oneTimePassword, "otp")
    }

    func testRemoteProviderUsesConfiguredIdentity() async throws {
        let originalHandler = MockURLProtocol.requestHandler
        defer { MockURLProtocol.requestHandler = originalHandler }

        let payload = """
        {
            "X-Apple-I-MD-M": "machine",
            "X-Apple-I-MD": "otp",
            "X-Apple-I-MD-LU": "user",
            "X-Mme-Device-Id": "device",
            "X-MMe-Client-Info": "server-client-info"
        }
        """
        MockURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(payload.utf8))
        }

        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        let provider = RemoteAnisetteProvider(
            serverURL: URL(string: "https://anisette.example.test/")!,
            clientConfiguration: AppleClientConfiguration(
                userAgent: "CustomAgent",
                clientInfo: "CustomClientInfo"
            ),
            urlSession: URLSession(configuration: config)
        )

        let anisette = try await provider.fetchAnisetteData()
        XCTAssertEqual(anisette.machineID, "machine")
        XCTAssertEqual(anisette.userAgent, "CustomAgent")
        XCTAssertEqual(anisette.clientInfo, "CustomClientInfo")
    }
}
