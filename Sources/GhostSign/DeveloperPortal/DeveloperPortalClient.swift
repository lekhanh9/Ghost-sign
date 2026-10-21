//
//  DeveloperPortalClient.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Asynchronous API client for communicating with Apple Developer Services 2 (QH65B2).
/// Follows SideSign's architecture: credentials, certificates, and profiles are maintained
/// in memory as raw Data buffers without storing into Apple Keychain.
public final class DeveloperPortalClient: @unchecked Sendable {
    public let session: AuthSession
    public let urlSession: URLSession

    private let baseURL = "https://developerservices2.apple.com/services/QH65B2"
    private let clientID = "XABBG36SBA"
    private let protocolVersion = "QH65B2"
    private let xcodeVersion = "15.4 (15F31d)"
    private let userAgent = "Xcode"
    private let appInfo = "com.apple.gs.xcode.auth"

    public init(session: AuthSession, sessionConfiguration: URLSessionConfiguration = .default) {
        self.session = session
        self.urlSession = URLSession(configuration: sessionConfiguration)
    }

    public init(session: AuthSession, urlSession: URLSession) {
        self.session = session
        self.urlSession = urlSession
    }

    // MARK: - Generic Network Dispatcher

    private func performRequest<T: Decodable>(
        action: String,
        parameters: [String: Any] = [:],
        teamId: String? = nil,
        context: String? = nil,
        customErrorMapper: ((Int, String) -> DeveloperPortalError?)? = nil
    ) async throws -> T {
        let urlString = "\(baseURL)/\(action)?clientId=\(clientID)"
        guard let url = URL(string: urlString) else {
            throw DeveloperPortalError.portalError(code: -1, message: "Invalid endpoint URL: \(urlString)")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Accept")
        request.setValue("en-us", forHTTPHeaderField: "Accept-Language")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(appInfo, forHTTPHeaderField: "X-Apple-App-Info")
        request.setValue(xcodeVersion, forHTTPHeaderField: "X-Xcode-Version")
        request.setValue(session.dsid, forHTTPHeaderField: "X-Apple-I-Identity-Id")
        request.setValue(session.authToken, forHTTPHeaderField: "X-Apple-GS-Token")

        // Attach Anisette device attestation headers
        for (header, value) in session.anisetteData.toHTTPHeaders() {
            request.setValue(value, forHTTPHeaderField: header)
        }

        var bodyDict: [String: Any] = [
            "clientId": clientID,
            "protocolVersion": protocolVersion,
            "requestId": UUID().uuidString.uppercased()
        ]
        if let teamId = teamId {
            bodyDict["teamId"] = teamId
        }
        for (key, value) in parameters {
            bodyDict[key] = value
        }

        do {
            request.httpBody = try PropertyListSerialization.data(fromPropertyList: bodyDict, format: .xml, options: 0)
        } catch {
            throw DeveloperPortalError.invalidResponseFormat("Failed to serialize request plist: \(error.localizedDescription)")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw DeveloperPortalError.networkError(error as NSError)
        }

        // Handle non-2xx HTTP responses
        if let httpResponse = response as? HTTPURLResponse, !(200...299).contains(httpResponse.statusCode) {
            if let status = try? PropertyListDecoder().decode(DeveloperPortalStatusResponse.self, from: data) {
                let code = status.resultCode ?? httpResponse.statusCode
                let msg = status.effectiveErrorMessage
                if code == -22406 || httpResponse.statusCode == 401 {
                    throw DeveloperPortalError.unauthenticated(msg)
                }
                if let custom = customErrorMapper?(code, msg) {
                    throw custom
                }
                throw DeveloperPortalResultCodeMapper.map(code: code, message: msg, context: context)
            }
            if httpResponse.statusCode == 401 {
                throw DeveloperPortalError.unauthenticated("HTTP 401 Unauthorized")
            }
            let code = URLError.Code(rawValue: httpResponse.statusCode) ?? .badServerResponse
            throw DeveloperPortalError.networkError(URLError(code))
        }

        // Check Apple status envelope for application-level error codes
        if let status = try? PropertyListDecoder().decode(DeveloperPortalStatusResponse.self, from: data), !status.isSuccess {
            let code = status.resultCode ?? -1
            let msg = status.effectiveErrorMessage
            if let custom = customErrorMapper?(code, msg) {
                throw custom
            }
            throw DeveloperPortalResultCodeMapper.map(code: code, message: msg, context: context)
        }

        // Decode target response model
        do {
            return try PropertyListDecoder().decode(T.self, from: data)
        } catch {
            throw DeveloperPortalError.decodingError(error as NSError)
        }
    }

    // MARK: - Public Operations

    /// Retrieves developer teams associated with the authenticated Apple ID.
    public func listTeams() async throws -> [DeveloperTeam] {
        let response: ListTeamsResponse = try await performRequest(
            action: "listTeams.action",
            context: "teams"
        )
        guard let teams = response.teams, !teams.isEmpty else {
            return response.teams ?? []
        }
        return teams
    }

    /// Queries registered hardware test devices for a developer team.
    public func listDevices(teamId: String) async throws -> [DeveloperDevice] {
        let response: ListDevicesResponse = try await performRequest(
            action: "ios/listDevices.action",
            teamId: teamId,
            context: "device"
        )
        return response.devices ?? []
    }

    /// Registers a new hardware test device with the developer team.
    public func addDevice(name: String, udid: String, teamId: String) async throws -> DeveloperDevice {
        let response: DeviceResponse = try await performRequest(
            action: "ios/addDevice.action",
            parameters: [
                "name": name,
                "deviceNumber": udid,
                "DTDK_Platform": "ios"
            ],
            teamId: teamId,
            context: "device",
            customErrorMapper: { code, msg in
                if code == 35 {
                    let lower = msg.lowercased()
                    if lower.contains("maximum") || lower.contains("limit") {
                        return .maximumDevicesReached
                    }
                    return .deviceAlreadyRegistered
                }
                return nil
            }
        )
        guard let device = response.device else {
            throw DeveloperPortalError.portalError(code: -1, message: "Response missing device dictionary")
        }
        return device
    }

    /// Queries registered App IDs (bundle identifiers) under the developer team.
    public func listAppIds(teamId: String) async throws -> [DeveloperAppId] {
        let response: ListAppIdsResponse = try await performRequest(
            action: "ios/listAppIds.action",
            teamId: teamId,
            context: "appId"
        )
        return response.appIds ?? []
    }

    /// Registers a new App ID bundle identifier under the developer team.
    public func addAppId(name: String, identifier: String, teamId: String) async throws -> DeveloperAppId {
        let response: AppIdResponse = try await performRequest(
            action: "ios/addAppId.action",
            parameters: [
                "name": name,
                "identifier": identifier
            ],
            teamId: teamId,
            context: "appId",
            customErrorMapper: { code, _ in
                if code == 35 {
                    return .bundleIdentifierUnavailable
                } else if code == 37 {
                    return .maximumAppIDLimitReached
                }
                return nil
            }
        )
        guard let appId = response.appId else {
            throw DeveloperPortalError.portalError(code: -1, message: "Response missing appId dictionary")
        }
        return appId
    }

    /// Queries active development certificates for the developer team.
    public func listCertificates(teamId: String) async throws -> [DeveloperCertificate] {
        let response: ListCertificatesResponse = try await performRequest(
            action: "ios/listAllDevelopmentCerts.action",
            teamId: teamId,
            context: "certificate"
        )
        return response.certificates ?? []
    }

    /// Submits a PKCS#10 Certificate Signing Request (CSR) PEM and downloads the issued Apple Development Certificate.
    public func addCertificate(csrPEM: String, teamId: String) async throws -> DeveloperCertificate {
        let response: CertificateResponse = try await performRequest(
            action: "ios/submitDevelopmentCSR.action",
            parameters: [
                "csrContent": csrPEM,
                "machineName": "GhostSign",
                "machineId": UUID().uuidString.uppercased()
            ],
            teamId: teamId,
            context: "certificate",
            customErrorMapper: { code, _ in
                if code == 3250 {
                    return .invalidCertificateRequest
                } else if code == 35 || code == 7460 {
                    return .maximumCertificatesReached
                }
                return nil
            }
        )
        guard let cert = response.effectiveCertificate else {
            throw DeveloperPortalError.certificateNotFound
        }
        return cert
    }

    /// Queries all provisioning profiles registered under the developer team.
    public func listProvisioningProfiles(teamId: String) async throws -> [DeveloperProvisioningProfile] {
        let response: ListProvisioningProfilesResponse = try await performRequest(
            action: "ios/listProvisioningProfiles.action",
            parameters: ["includeTeamProfiles": true],
            teamId: teamId,
            context: "profile"
        )
        return response.provisioningProfiles ?? []
    }

    /// Generates a new development provisioning profile matching the App ID, certificate, and device UDIDs.
    public func createProvisioningProfile(
        name: String,
        bundleId: String,
        certificateId: String,
        deviceUDIDs: [String],
        teamId: String
    ) async throws -> DeveloperProvisioningProfile {
        var resolvedAppIdId = bundleId
        if bundleId.contains(".") {
            let appIds = try await listAppIds(teamId: teamId)
            if let matched = appIds.first(where: { $0.identifier == bundleId }) {
                resolvedAppIdId = matched.appIdId
            }
        }

        var resolvedDeviceIds = deviceUDIDs
        if !deviceUDIDs.isEmpty {
            let devices = try await listDevices(teamId: teamId)
            let pairs = devices.compactMap { d -> (String, String)? in
                guard let devId = d.deviceId else { return nil }
                return (d.deviceNumber, devId)
            }
            let deviceMap = Dictionary(pairs, uniquingKeysWith: { first, _ in first })
            resolvedDeviceIds = deviceUDIDs.map { deviceMap[$0] ?? $0 }
        }

        var params: [String: Any] = [
            "provisioningProfileName": name,
            "appIdId": resolvedAppIdId,
            "distributionType": "limited",
            "certificateIds": [certificateId]
        ]
        if !resolvedDeviceIds.isEmpty {
            params["deviceIds"] = resolvedDeviceIds
        }

        let response: ProvisioningProfileResponse = try await performRequest(
            action: "ios/createProvisioningProfile.action",
            parameters: params,
            teamId: teamId,
            context: "profile"
        )
        guard let profile = response.provisioningProfile else {
            throw DeveloperPortalError.profileNotFound
        }
        return profile
    }

    /// Downloads the on-the-fly ephemeral Xcode Team Provisioning Profile for an App ID.
    public func downloadTeamProvisioningProfile(appIdId: String, teamId: String) async throws -> DeveloperProvisioningProfile {
        var resolvedAppIdId = appIdId
        if appIdId.contains(".") {
            let appIds = try await listAppIds(teamId: teamId)
            if let matched = appIds.first(where: { $0.identifier == appIdId }) {
                resolvedAppIdId = matched.appIdId
            }
        }

        let response: ProvisioningProfileResponse = try await performRequest(
            action: "ios/downloadTeamProvisioningProfile.action",
            parameters: ["appIdId": resolvedAppIdId],
            teamId: teamId,
            context: "profile",
            customErrorMapper: { code, _ in
                if code == 8201 || code == 9115 {
                    return .profileNotFound
                }
                return nil
            }
        )
        guard let profile = response.provisioningProfile else {
            throw DeveloperPortalError.profileNotFound
        }
        return profile
    }
}
