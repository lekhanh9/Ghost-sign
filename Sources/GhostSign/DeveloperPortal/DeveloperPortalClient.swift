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

    private let baseURL = Constants.DeveloperServices.defaultBaseURL
    private let clientID = Constants.DeveloperServices.clientID
    private let protocolVersion = Constants.DeveloperServices.protocolVersion
    private let xcodeVersion = Constants.DeveloperServices.xcodeVersion
    private let userAgent = Constants.DeveloperServices.userAgent
    private let appInfo = Constants.DeveloperServices.appInfo

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
        request.setValue(appInfo, forHTTPHeaderField: Constants.AnisetteHeaders.appInfo)
        request.setValue(xcodeVersion, forHTTPHeaderField: Constants.AnisetteHeaders.xcodeVersion)
        request.setValue(session.dsid, forHTTPHeaderField: Constants.AnisetteHeaders.identityId)
        request.setValue(session.authToken, forHTTPHeaderField: Constants.AnisetteHeaders.gsToken)

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
            action: Constants.URLs.listTeams,
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
            action: Constants.URLs.listDevices,
            teamId: teamId,
            context: "device"
        )
        return response.devices ?? []
    }

    /// Registers a new hardware test device with the developer team.
    public func addDevice(name: String, udid: String, teamId: String) async throws -> DeveloperDevice {
        let response: DeviceResponse = try await performRequest(
            action: Constants.URLs.addDevice,
            parameters: [
                "name": name,
                "deviceNumber": udid,
                "DTDK_Platform": "ios"
            ],
            teamId: teamId,
            context: "device",
            customErrorMapper: { code, msg in
                if code == Constants.ResultCodes.deviceAlreadyRegistered {
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
            action: Constants.URLs.listAppIDs,
            teamId: teamId,
            context: "appId"
        )
        return response.appIds ?? []
    }

    /// Registers a new App ID bundle identifier under the developer team.
    public func addAppId(name: String, identifier: String, teamId: String) async throws -> DeveloperAppId {
        let response: AppIdResponse = try await performRequest(
            action: Constants.URLs.addAppID,
            parameters: [
                "name": name,
                "identifier": identifier
            ],
            teamId: teamId,
            context: "appId",
            customErrorMapper: { code, _ in
                if code == Constants.ResultCodes.bundleIdentifierUnavailable {
                    return .bundleIdentifierUnavailable
                } else if code == Constants.ResultCodes.maximumAppIDLimitReached {
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
            action: Constants.URLs.listCertificates,
            teamId: teamId,
            context: "certificate"
        )
        return response.certificates ?? []
    }

    /// Submits a PKCS#10 Certificate Signing Request (CSR) PEM and downloads the issued Apple Development Certificate.
    public func addCertificate(csrPEM: String, teamId: String) async throws -> DeveloperCertificate {
        let response: CertificateResponse = try await performRequest(
            action: Constants.URLs.submitDevelopmentCSR,
            parameters: [
                "csrContent": csrPEM,
                "machineName": "GhostSign",
                "machineId": UUID().uuidString.uppercased()
            ],
            teamId: teamId,
            context: "certificate",
            customErrorMapper: { code, _ in
                if code == Constants.ResultCodes.invalidCertificateRequest {
                    return .invalidCertificateRequest
                } else if code == Constants.ResultCodes.maximumCertificatesReached || code == Constants.ResultCodes.maximumCertificatesReachedAlternate {
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

    /// Submits a PKCS#10 Certificate Signing Request (CSR) DER bytes directly, converting to PEM internally.
    public func addCertificate(csrDER: Data, teamId: String) async throws -> DeveloperCertificate {
        let pem = PEMDERCodec.derToPEM(der: csrDER, type: .certificateRequest)
        return try await addCertificate(csrPEM: pem, teamId: teamId)
    }

    /// Convenience alias for addCertificate(csrPEM:teamId:).
    public func submitDevelopmentCSR(teamId: String, csrPEM: String) async throws -> DeveloperCertificate {
        try await addCertificate(csrPEM: csrPEM, teamId: teamId)
    }

    /// Convenience alias for addCertificate(csrDER:teamId:).
    public func submitDevelopmentCSR(teamId: String, csrDER: Data) async throws -> DeveloperCertificate {
        try await addCertificate(csrDER: csrDER, teamId: teamId)
    }

    /// Queries active development certificates for the developer team (alias for listCertificates).
    public func listAllDevelopmentCerts(teamId: String) async throws -> [DeveloperCertificate] {
        try await listCertificates(teamId: teamId)
    }

    /// Queries all provisioning profiles registered under the developer team.
    public func listProvisioningProfiles(teamId: String) async throws -> [DeveloperProvisioningProfile] {
        let response: ListProvisioningProfilesResponse = try await performRequest(
            action: Constants.URLs.listProvisioningProfiles,
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
            action: Constants.URLs.createProvisioningProfile,
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
            action: Constants.URLs.downloadTeamProfile,
            parameters: ["appIdId": resolvedAppIdId],
            teamId: teamId,
            context: "profile",
            customErrorMapper: { code, _ in
                if code == Constants.ResultCodes.profileNotFoundAlternate || code == Constants.ResultCodes.profileNotFound {
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

    /// Deletes an App ID bundle identifier from the developer team.
    @discardableResult
    public func deleteAppId(appIdId: String, teamId: String) async throws -> Bool {
        let _: DeveloperPortalStatusResponse = try await performRequest(
            action: Constants.URLs.deleteAppID,
            parameters: ["appIdId": appIdId],
            teamId: teamId,
            context: "appId"
        )
        return true
    }

    /// Removes a registered hardware device from the developer team.
    @discardableResult
    public func deleteDevice(deviceId: String, teamId: String) async throws -> Bool {
        let _: DeveloperPortalStatusResponse = try await performRequest(
            action: Constants.URLs.deleteDevice,
            parameters: ["deviceId": deviceId],
            teamId: teamId,
            context: "device"
        )
        return true
    }

    /// Downloads a specific manual provisioning profile by its profile ID.
    public func downloadProvisioningProfile(profileId: String, teamId: String) async throws -> DeveloperProvisioningProfile {
        let response: ProvisioningProfileResponse = try await performRequest(
            action: Constants.URLs.downloadProfile,
            parameters: ["provisioningProfileId": profileId],
            teamId: teamId,
            context: "profile"
        )
        guard let profile = response.provisioningProfile else {
            throw DeveloperPortalError.profileNotFound
        }
        return profile
    }

    /// Deletes a provisioning profile from the developer portal.
    @discardableResult
    public func deleteProvisioningProfile(profileId: String, teamId: String) async throws -> Bool {
        let _: DeveloperPortalStatusResponse = try await performRequest(
            action: Constants.URLs.deleteProvisioningProfile,
            parameters: ["provisioningProfileId": profileId],
            teamId: teamId,
            context: "profile"
        )
        return true
    }
}
